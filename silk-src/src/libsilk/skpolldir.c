/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
**
** SiLK 3.22.0
**
** Copyright 2023 Carnegie Mellon University.
**
** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
** INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
** UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
** AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
** PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
** THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
** INFRINGEMENT.
**
** Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
** contact permission@sei.cmu.edu for full terms.
**
** [DISTRIBUTION STATEMENT A] This material has been approved for public
** release and unlimited distribution.  Please see Copyright notice for
** non-US Government use and distribution.
**
** GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
**
** Contract No.: FA8702-15-D-0002
** Contractor Name: Carnegie Mellon University
** Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
**
** The Government's rights to use, modify, reproduce, release, perform,
** display, or disclose this software are restricted by paragraph (b)(2) of
** the Rights in Noncommercial Computer Software and Noncommercial Computer
** Software Documentation clause contained in the above identified
** contract. No restrictions apply after the expiration date shown
** above. Any reproduction of the software or portions thereof marked with
** this legend must also reproduce the markings.
**
** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
** Trademark Office by Carnegie Mellon University.
**
** This Software includes and/or makes use of Third-Party Software each
** subject to its own license.
**
** DM23-0973
**
** @OPENSOURCE_LICENSE_END@
*/

/*
**  Library for polling directories for new files
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skpolldir.c 806cac94b1d1 2023-09-11 19:50:13Z mthomas $");

#include <silk/skdeque.h>
#include <silk/redblack.h>
#include <silk/skvector.h>
#include <silk/skdllist.h>
#include <silk/skpolldir.h>
#include <silk/sktimer.h>
#include <silk/sklog.h>
#include <silk/utils.h>

#ifdef SKPOLLDIR_TRACE_LEVEL
#define TRACEMSG_LEVEL SKPOLLDIR_TRACE_LEVEL
/*
 *    Messages at various tracing levels
 *
 *    1 - Startup, Shutdown, Dir-Scan begin/end, Mark+Sweep begin/end
 *
 *    2 - Number of files found during Dir-Scan, Number of deleted files found
 *    while trying to GetNextFile() if non-zero
 *
 *    3 - The names of deleted files found during GetNextFile()
 *
 *    4 - Names of files when first noticed, when size changes before queuing,
 *    when first enqueued, when the file is no longer present, when file is
 *    returned from GetNextFile()
 *
 *    5 - Names of ignored files and previously queued files (on every
 *    directory poll), Result of every skDequePopBack() in GetNextFile()
 */
#endif
#define TRACEMSG(tm_lvl, tm_msg)  TRACEMSG_TO_TRACEMSGLVL(tm_lvl, tm_msg)
#include <silk/sktracemsg.h>
#if TRACEMSG_LEVEL >= 2
#define SKPOLLDIR_FILE_COUNT 1
#endif


/* LOCAL DEFINES AND TYPEDEFS */

/*
 *    Define SKPOLLDIR_USE_INODE to zero not to have the inode be included in
 *    the key for the red-black tree.
 *
 *    The inode provides a very small speed increase during a directory-scan.
 */
/* #define SKPOLLDIR_USE_INODE 0 */
#ifndef SKPOLLDIR_USE_INODE
#define SKPOLLDIR_USE_INODE 1
#endif

/*
 *    Define SKPOLLDIR_TIMING to a non-zero value to time the
 *    directory-scan and mark-and-sweep operations.  Messages are
 *    written at --log-level=debug.
 */
/* #define SKPOLLDIR_TIMING 1 */
#ifndef SKPOLLDIR_TIMING
#define SKPOLLDIR_TIMING 0
#endif


/* The type of skPollDir_t objects */
typedef struct sk_polldir_st {
    /** name of directory to poll */
    char            *directory;
    /** the position of the basename in the complete file paths
     * returned to caller */
    size_t           filename_offset;
    /** a red-black is used to keep track of files that exist in the
     * directoy.  it holds pd_dirent_t objects */
    struct rbtree   *tree;
    /** once a file in the dirctory is quiescent, it is added to this
     * queue until requested by the caller.  the queue holds
     * pd_qentry_t objects */
    skDeque_t        queue;
    /** when the timer fires, it is time to poll the directory again */
    skTimer_t        timer;
    /** this is max number of seconds the NextFile() function will
     * wait for a file.  if 0, wait forever. */
    uint32_t         wait_next_file;
    /** current error.  this can be set while polling the directory or
     * when skPollDirStop() is called.  */
    skPollDirErr_t   error;
    /* if there is a system error during polling, this holds the
     * errno */
    int              sys_errno;
    unsigned         stopped : 1;
} sk_polldir_t;


/* A file entry; these are stored in the red-black tree for all files
 * that exist in the directory.  */
typedef struct pd_dirent_st {
    /* basename of the file */
    char        *name;
    /* size of the file; used to check for constant file size */
    off_t        size;
#if SKPOLLDIR_USE_INODE
    /* the inode of the file */
    ino_t        inode;
#endif
    /* true if the file existed during the most recent scan */
    unsigned int seen   : 1;
    /* true if the file has been added to the deque */
    unsigned int queued : 1;
} pd_dirent_t;


/* The file entry for items stored in the deque. */
typedef struct pd_qentry_st {
    /* basename of the file */
    char       *qe_name;
} pd_qentry_t;


/* LOCAL VARIABLE DEFINITIONS */

/* variables and mutex to handle maximum file handle usage */
static pthread_mutex_t skp_fh_sem_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  skp_fh_sem_cond  = PTHREAD_COND_INITIALIZER;
static int skp_fh_max = SKPOLLDIR_DEFAULT_MAX_FILEHANDLES;
static int skp_fh_left = SKPOLLDIR_DEFAULT_MAX_FILEHANDLES;


/* FUNCTION DEFINITIONS */


/* Acquire the file handle semaphore */
static void
skp_fh_sem_aquire(
    void)
{
    pthread_mutex_lock(&skp_fh_sem_mutex);
    while (skp_fh_left <= 0) {
        pthread_cond_wait(&skp_fh_sem_cond, &skp_fh_sem_mutex);
    }
    --skp_fh_left;
    pthread_mutex_unlock(&skp_fh_sem_mutex);
}

/* release the file handle semaphore */
static void
skp_fh_sem_release(
    void)
{
    pthread_mutex_lock(&skp_fh_sem_mutex);
    ++skp_fh_left;
    pthread_cond_signal(&skp_fh_sem_cond);
    pthread_mutex_unlock(&skp_fh_sem_mutex);
}

/* Change the maximum number of filehandles we can use. */
int
skPollDirSetMaximumFileHandles(
    int                 max_fh)
{
    if (max_fh < 1) {
        return -1;
    }

    pthread_mutex_lock(&skp_fh_sem_mutex);
    skp_fh_left += max_fh - skp_fh_max;
    skp_fh_max = max_fh;
    pthread_mutex_unlock(&skp_fh_sem_mutex);

    return 0;
}

/* Allocates and returns pd_qentry_t to hold 'filename'. */
static pd_qentry_t *
pd_qentry_new(
    const sk_polldir_t  UNUSED(*pd),
    const char                 *filename)
{
    pd_qentry_t *qe = (pd_qentry_t *)malloc(sizeof(*qe));
    if (!qe) {
        return NULL;
    }

    qe->qe_name = strdup(filename);
    if (!qe->qe_name) {
        free(qe);
        return NULL;
    }
    return qe;
}

/* Frees a pd_qentry_t and its path. */
static void
pd_qentry_free(
    pd_qentry_t    *qe)
{
    free(qe->qe_name);
    free(qe);
}


/* Comparison function for pd_dirent_t items (used by red black tree) */
static int
compare(
    const void         *va,
    const void         *vb,
    const void  UNUSED(*unused))
{
    const pd_dirent_t *a = (const pd_dirent_t *)va;
    const pd_dirent_t *b = (const pd_dirent_t *)vb;

#if !SKPOLLDIR_USE_INODE
    return strcmp(a->name, b->name);
#else  /* SKPOLLDIR_USE_INODE */
    return ((a->inode == b->inode)
            ? strcmp(a->name, b->name)
            : ((a->inode < b->inode) ? -1 : 1));
#endif /* #else of #if !SKPOLLDIR_USE_INODE */
}


/* Walk through the tree removing files that were not seen.  Marks
 * files that were not removed as unseen in preperation for the next
 * pass. */
static void
remove_unseen(
    sk_polldir_t       *pd)
{
    RBLIST *list;
    pd_dirent_t *x;
    sk_vector_t *dellist;
    int rv;
    size_t i;
#if SKPOLLDIR_TIMING
    clock_t t1, t2 = 0, t3 = 0;
#endif
#if TRACEMSG_LEVEL >= 1
    size_t seen = 0;
#endif

    TRACEMSG(1, ("polldir %p: Starting mark and sweep", pd));
#if SKPOLLDIR_TIMING
    t1 = clock();
#endif

    dellist = skVectorNew(sizeof(pd_dirent_t *));
    list = rbopenlist(pd->tree);
    if (NULL == dellist || NULL == list) {
        pd->error = PDERR_MEMORY;
        goto end;
    }

    /* Loop through all files */
    while ((x = (pd_dirent_t *)rbreadlist(list))) {
        if (x->seen) {
            /* Seen.  Reset to zero for next pass. */
            x->seen = 0;
#if TRACEMSG_LEVEL >= 1
            ++seen;
#endif
        } else {
            TRACEMSG(4, (("polldir %p: File '%s' was not noticed."
                          " Removing from consideration."),
                         pd, x->name));

            /* Not seen.  Add to delete list. */
            rv = skVectorAppendValue(dellist, &x);
            if (-1 == rv) {
                pd->error = PDERR_MEMORY;
                goto end;
            }
        }
    }

#if SKPOLLDIR_TIMING
    t2 = clock();
#endif

    /* Remove items in the delete list */
    for (i = 0; i < skVectorGetCount(dellist); ++i) {
        skVectorGetValue(&x, dellist, i);
        rbdelete(x, pd->tree);
        free(x->name);
        free(x);
    }

  end:
#if SKPOLLDIR_TIMING
    t3 = clock();
#endif
    TRACEMSG(1, (("polldir %p: Finished mark and sweep."
                  " Kept %" SK_PRIuZ " nodes. Removed %" SK_PRIuZ " nodes"),
                 pd, seen, skVectorGetCount(dellist)));

#if SKPOLLDIR_TIMING
    DEBUGMSG(("polldir %p: Mark and sweep required %f seconds:"
              " rbtree scan %f secs; node delete %f secs"),
             pd, ((double)(t3 - t1) / CLOCKS_PER_SEC),
             ((double)(t2 - t1) / CLOCKS_PER_SEC),
             ((double)(t3 - t2) / CLOCKS_PER_SEC));
#endif
    if (list) {
        rbcloselist(list);
    }
    if (dellist) {
        skVectorDestroy(dellist);
    }
}


/* Free all pd_dirent_t structures in the tree. */
static void
free_tree_nodes(
    sk_polldir_t       *pd)
{
    RBLIST *list;
    pd_dirent_t *x;

    list = rbopenlist(pd->tree);
    if (list == NULL) {
        pd->error = PDERR_MEMORY;
        goto end;
    }

    while ((x = (pd_dirent_t *)rbreadlist(list))) {
        free(x->name);
        free(x);
    }

  end:
    rbcloselist(list);
}

/* Actually poll the directory.  This is the function that the
 * skTimer_t will call. */
static skTimerRepeat_t
pollDir(
    void               *vpd)
{
    /*
     *    Things to try in order to improve performance:
     *
     *    Use inode to improve comparison times when accessing the
     *    red-black tree.
     *
     *    Make the readdir loop shorter so that its job is to filter
     *    out files that begin with '.' or where the 'd_type' is
     *    unwanted; all other files it puts into a temporary Deque
     *    (the scan_deque).  Provide a second thread that reads file
     *    names from scan_deque and stat()s the files, updates the
     *    red-black tree, etc.
     *
     *    If we add scan_deque, allow multiple threads to process its
     *    entries.  To do this, we would need a mutex around the call
     *    to rbsearch().  Alternately, we could change to rbsearch()
     *    to rbfind(), and add any new files to another structure.
     *    Existing nodes in the red-black tree could have their 'seen'
     *    bit flipped since that does not affect the red-black tree
     *    directly.  Once all files in scan_deque have been handled,
     *    the new files then added to the red-black tree.  We could
     *    also remove unseen elements before adding the new entries,
     *    which might slightly improvement performance.
     *
     *    The scan_deque could also allow for multiple readers of the
     *    directory.
     *
     *    It may be possible to avoid the scan_deque and have use
     *    readdir_r() to put the directory entries directly into the
     *    threads that process the entries.
     */

    sk_polldir_t *pd = (sk_polldir_t *)vpd;
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    int rv;
    char path[PATH_MAX];
    pd_dirent_t *node, *found;
    pd_qentry_t *item;
    skDQErr_t err;
#if SKPOLLDIR_TIMING
    clock_t t1, t2 = 0;
#endif
#ifdef SKPOLLDIR_FILE_COUNT
    unsigned int non_file = 0, dot_file = 0, ignore_stat = 0;
    unsigned int new_file = 0, size_change = 0, added = 0, existing = 0;
#endif

    if (pd->stopped) {
        goto unblock_and_end_timer;
    }

    skp_fh_sem_aquire();
    TRACEMSG(1, ("polldir %p: Starting directory scan of '%s'",
                 pd, pd->directory));

#if SKPOLLDIR_TIMING
    t1 = clock();
#endif

    node = NULL;
    dir = opendir(pd->directory);
    if (NULL == dir) {
        pd->error = PDERR_SYSTEM;
        pd->sys_errno = errno;
        goto cleanup_and_exit;
    }

    path[sizeof(path) - 1] = '\0';
    rv = snprintf(path, sizeof(path), "%s/", pd->directory);
    assert((size_t)rv == pd->filename_offset);

    /* Loop over all files in the directory */
    while (!pd->stopped
           && PDERR_NONE == pd->error
           && (entry = readdir(dir)))
    {
#ifdef SK_HAVE_STRUCT_DIRENT_D_TYPE
        switch (entry->d_type) {
          case DT_UNKNOWN:
          case DT_REG:
          case DT_LNK:
            break;
          default:
#ifdef SKPOLLDIR_FILE_COUNT
            ++non_file;
#endif
            TRACEMSG(5, ("polldir %p: File '%s' was ignored (non-file [%d])",
                         pd, entry->d_name, entry->d_type));
            continue;
        }
#endif  /* SK_HAVE_STRUCT_DIRENT_D_TYPE */

        /* Ignore dot files. */
        if (entry->d_name[0] == '.') {
#ifdef SKPOLLDIR_FILE_COUNT
            ++dot_file;
#endif
            TRACEMSG(5, ("polldir %p: File '%s' was ignored (dotfile)",
                         pd, entry->d_name));
            continue;
        }

        assert(strlen(entry->d_name) + pd->filename_offset < sizeof(path));
        strcpy(path + pd->filename_offset, entry->d_name);

        /* Ignore files that are empty, or that aren't either regular
         * files or symbolic links. */
        rv = stat(path, &st);
        if (-1 == rv
            || !(st.st_mode & (S_IFREG | S_IFLNK))
            || (0 == st.st_size))
        {
#ifdef SKPOLLDIR_FILE_COUNT
            ++ignore_stat;
#endif
            TRACEMSG(5, ("polldir %p: File '%s' was ignored (%s)",
                         pd, entry->d_name,
                         ((-1 == rv)
                          ? strerror(errno)
                          : ((0 == st.st_size) ? "zero-bytes" : "non-file"))));
            continue;
        }

        /* Allocate an entry, if one doesn't already exist. */
        if (node == NULL) {
            node = (pd_dirent_t*)malloc(sizeof(pd_dirent_t));
            if (NULL == node) {
                TRACEMSG(1, ("polldir %p: Node allocation error for '%s'",
                             pd, entry->d_name));
                pd->error = PDERR_MEMORY;
                continue;
            }
            node->queued = 0;
        }

        if (pd->stopped) {
            break;
        }

        node->name = entry->d_name;
#if SKPOLLDIR_USE_INODE
        node->inode = st.st_ino;
#endif

        /* Find or insert the entry into the tree.  */
        found = (pd_dirent_t *)rbsearch(node, pd->tree);

        if (found == node) {
            /* New node has been added to the tree */
#ifdef SKPOLLDIR_FILE_COUNT
            ++new_file;
#endif
            TRACEMSG(4, (("polldir %p: File '%s' noticed with size %" PRId64
                          " for the first time"),
                         pd, node->name, st.st_size));

            found->size = st.st_size;

            /* Make the name persistent */
            found->name = strdup(found->name);
            if (NULL == found->name) {
                TRACEMSG(1, ("polldir %p: Name allocation error for '%s'",
                             pd, node->name));
                pd->error = PDERR_MEMORY;
                continue;
            }

            /* Allocate a new node on the next run through the loop. */
            node = NULL;

        } else if (!found->queued) {
            /* Node already existed but not yet queued. */
            if (st.st_size != found->size) {
                /* file size still changing */
#ifdef SKPOLLDIR_FILE_COUNT
                ++size_change;
#endif
                TRACEMSG(4, (("polldir %p: File '%s' was noticed with size %"
                              PRId64 "; different from previous %" PRId64),
                            pd, node->name, st.st_size, found->size));
                found->size = st.st_size;
            } else {
                /* Size has stabalized, add to queue */
#ifdef SKPOLLDIR_FILE_COUNT
                ++added;
#endif
                TRACEMSG(4, (("polldir %p: File '%s' was noticed with size %"
                              PRId64 "; size is stable.  Queuing"),
                             pd, node->name, st.st_size));
                found->queued = 1;

                item = pd_qentry_new(pd, node->name);
                if (NULL == item) {
                    TRACEMSG(1, ("polldir %p: Entry allocation error for '%s'",
                                 pd, node->name));
                    pd->error = PDERR_MEMORY;
                    continue;
                }

                err = skDequePushFront(pd->queue, item);
                if (err != SKDQ_SUCCESS) {
                    TRACEMSG(1, ("polldir %p: Deque allocation error for '%s'",
                                 pd, node->name));
                    pd_qentry_free(item);
                    pd->error = PDERR_MEMORY;
                    continue;
                }
            }
#ifdef SKPOLLDIR_FILE_COUNT
        } else {
            ++existing;
            TRACEMSG(5, (("polldir %p: File '%s' with size %" PRId64
                          "; prevously queued with size %" PRId64),
                         pd, node->name, st.st_size, found->size));
#endif  /* SKPOLLDIR_FILE_COUNT */
        }

        /* Mark this file as seen this time around */
        found->seen = 1;
    }
    closedir(dir);

  cleanup_and_exit:
#if SKPOLLDIR_TIMING
    t2 = clock();
#endif
    skp_fh_sem_release();

    TRACEMSG(1, ("polldir %p: Finished directory scan of '%s'",
                 pd, pd->directory));
    TRACEMSG(2, (("polldir %p: Ignored %u, First-seen %u, Size-change %u,"
                  " Stable-size %u, Prev-Queued %u, Total-Seen %u"),
                 pd, (non_file + dot_file + ignore_stat),
                 new_file, size_change, added, existing,
                 (new_file + size_change + added + existing)));

#if SKPOLLDIR_TIMING
    DEBUGMSG("polldir %p: Directory scan required %f seconds",
             pd, ((double)(t2 - t1) / CLOCKS_PER_SEC));
#endif

    /* Free node, if left over. */
    if (node) {
        free(node);
    }

    /* Remove entries we did not see, and re-mark tree as unseen. */
    if (!pd->stopped && PDERR_NONE == pd->error) {
        remove_unseen(pd);
    }

    /* Repeat if no error */
    if (!pd->stopped && PDERR_NONE == pd->error) {
        return SK_TIMER_REPEAT;
    }

  unblock_and_end_timer:
    /* Ensure that pd->error is set to an error code before unblocking Deque
     * in case GetNextFile() is waiting */
    if (pd->stopped && PDERR_NONE == pd->error) {
        pd->error = PDERR_STOPPED;
    }

    skDequeUnblock(pd->queue);

    return SK_TIMER_END;
}


void
skPollDirStop(
    sk_polldir_t       *pd)
{
    assert(pd);

    pd->stopped = 1;

    TRACEMSG(1, ("polldir %p: Being told to stop", pd));

    /* Stop the timer */
    if (pd->timer) {
        skTimerDestroy(pd->timer);
        pd->timer = NULL;
    }

    /* Unblock the queue */
    pd->error = PDERR_STOPPED;
    skDequeUnblock(pd->queue);
}


/* Destroy a polldir object */
void
skPollDirDestroy(
    sk_polldir_t       *pd)
{
    pd_qentry_t *item;

    if (NULL == pd) {
        TRACEMSG(1, ("polldir %p: Attempting to destroy NULL polldir", pd));
        return;
    }
    skPollDirStop(pd);

    TRACEMSG(1, ("polldir %p: Being destroyed", pd));

    /* Empty and destroy the tree */
    if (pd->tree) {
        free_tree_nodes(pd);
        rbdestroy(pd->tree);
        pd->tree = NULL;
    }

    /* Free the directory name */
    if (pd->directory) {
        free(pd->directory);
        pd->directory = NULL;
    }

    /* Empty and destoy the queue */
    if (pd->queue) {
        while (skDequePopFrontNB(pd->queue, (void **)&item) == SKDQ_SUCCESS) {
            pd_qentry_free(item);
        }

        skDequeDestroy(pd->queue);
        pd->queue = NULL;
    }

    /* Finally, free the polldir object */
    free(pd);
}


/* Create a directory polling object. */
sk_polldir_t *
skPollDirCreate(
    const char         *directory,
    uint32_t            poll_interval)
{
    sk_polldir_t *pd;
    int           rv;

    assert(directory);

    if (!skDirExists(directory)) {
        return NULL;
    }

    pd = (sk_polldir_t*)calloc(1, sizeof(sk_polldir_t));
    if (NULL == pd) {
        return NULL;
    }

    pd->queue = skDequeCreate();
    if (NULL == pd->queue) {
        goto err;
    }
    pd->directory = strdup(directory);
    if (NULL == pd->directory) {
        goto err;
    }
    pd->filename_offset = strlen(directory) + 1;
    if (pd->filename_offset >= PATH_MAX) {
        goto err;
    }

    pd->tree = rbinit(compare, NULL);
    if (NULL == pd->tree) {
        goto err;
    }

    TRACEMSG(1, ("polldir %p: Created to scan '%s' every %" PRIu32 " seconds",
                 pd, directory, poll_interval));

    /* Initial population of tree */
    pollDir(pd);

    /* Start timer */
    rv = skTimerCreate(&pd->timer, poll_interval, pollDir, pd);
    if (0 != rv) {
        goto err;
    }

    return pd;

  err:
    /* Clean up after any errors */
    skPollDirDestroy(pd);
    return NULL;
}


/* Puts a file back on the queue. 'filename' is the basename */
skPollDirErr_t
skPollDirPutBackFile(
    sk_polldir_t       *pd,
    const char         *filename)
{
    pd_qentry_t *item;
    skDQErr_t err;

    assert(pd);
    assert(filename);

    if (pd->filename_offset + strlen(filename) >= PATH_MAX) {
        return PDERR_MEMORY;
    }

    item = pd_qentry_new(pd, filename);
    if (NULL == item) {
        return PDERR_MEMORY;
    }

    err = skDequePushFront(pd->queue, item);
    if (err != SKDQ_SUCCESS) {
        pd_qentry_free(item);
        return PDERR_MEMORY;
    }

    return PDERR_NONE;
}


/* Get the next added entry to a directory. */
skPollDirErr_t
skPollDirGetNextFile(
    sk_polldir_t       *pd,
    char               *path,
    char              **filename)
{
    char pathname[PATH_MAX];
    ssize_t sz;
    pd_qentry_t *item = NULL;
    skDQErr_t err;
#ifdef SKPOLLDIR_FILE_COUNT
    unsigned int deleted = 0;
#endif

    assert(pd);
    assert(path);

    if (pd->stopped) {
        return PDERR_STOPPED;
    }

    /* NOTE: For a timed-wait, if the deque contains the names of files that
     * have been removed, the total time this function waits may be longer
     * than pd->wait_next_file. */

    /* exit from this 'for' by returning */
    for (;;) {
        item = NULL;
        if (pd->wait_next_file) {
            err = skDequePopBackTimed(pd->queue, (void **)&item,
                                      pd->wait_next_file);
        } else {
            err = skDequePopBack(pd->queue, (void **)&item);
        }
        TRACEMSG(5, ("polldir %p: Deque return value is %d", pd, (int)err));
        if (SKDQ_SUCCESS != err) {
            /* error code from Deque */
            if (PDERR_NONE == pd->error) {
                if (err == SKDQ_TIMEDOUT) {
                    return PDERR_TIMEDOUT;
                }
                if (err == SKDQ_UNBLOCKED) {
                    DEBUGMSG("Deque was UNBLOCKED but polldir not stopped");
                    return PDERR_STOPPED;
                }
                /* This should not happen */
                CRITMSG(("%s:%d Invalid error condition in polldir;"
                         " deque returned %d"),
                        __FILE__, __LINE__, err);
                skAbort();
            }
            if (item) {
                pd_qentry_free(item);
            }
            if (PDERR_SYSTEM == pd->error) {
                errno = pd->sys_errno;
            }
            return pd->error;
        }

        pathname[sizeof(pathname) - 1] = '\0';
        sz = snprintf(pathname, sizeof(pathname), "%s/%s",
                      pd->directory, item->qe_name);
        if ((size_t)sz >= sizeof(pathname)) {
            INFOMSG(
                "Complete pathname for file '%s' is too long. Ignoring entry",
                item->qe_name);
            pd_qentry_free(item);
            item = NULL;
            continue;
        }
        if (!skFileExists(pathname)) {
#ifdef SKPOLLDIR_FILE_COUNT
            ++deleted;
#endif
            TRACEMSG(3, ("polldir %p: File '%s' was deleted before it"
                         " could be delivered",
                         pd, item->qe_name));
            pd_qentry_free(item);
            item = NULL;
            continue;
        }

        /* check for stopped */
        if (pd->stopped) {
            pd_qentry_free(item);
            return PDERR_STOPPED;
        }

        /* File exists; return it. */
        strcpy(path, pathname);
        if (filename) {
            *filename = path + pd->filename_offset;
        }

#ifdef SKPOLLDIR_FILE_COUNT
        if (deleted) {
            TRACEMSG(2, (("polldir %p: Noticed %u deleted files"
                          " before finding existing file"),
                         pd, deleted));
        }
#endif
        TRACEMSG(4, ("polldir %p: File '%s' was delivered",
                     pd, item->qe_name));

        pd_qentry_free(item);
        return PDERR_NONE;
    }
}


/* Get the directory being polled by a polldir object. */
const char *
skPollDirGetDir(
    sk_polldir_t       *pd)
{
    assert(pd);
    return pd->directory;
}


void
skPollDirSetFileTimeout(
    sk_polldir_t       *pd,
    uint32_t            timeout_seconds)
{
    assert(pd);
    pd->wait_next_file = timeout_seconds;
}


/* Return a string describing an error */
const char *
skPollDirStrError(
    skPollDirErr_t      err)
{
    switch (err) {
      case PDERR_NONE:
        return "No error";
      case PDERR_STOPPED:
        return "Polldir stopped";
      case PDERR_MEMORY:
        return "Memory allocation error";
      case PDERR_SYSTEM:
        return "System error";
      case PDERR_TIMEDOUT:
        return "Polldir timed out";
    }

    return "Invalid error identifier"; /* NOTREACHED */
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
