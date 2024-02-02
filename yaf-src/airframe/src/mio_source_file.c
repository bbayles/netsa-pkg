/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  mio_source_file.c
 *  Multiple I/O regular file source, from single file, glob, or directory.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 2.15.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2313
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */

#define _AIRFRAME_SOURCE_
#include <airframe/mio_source_file.h>
#include <airframe/mio_stdio.h>
#include "mio_internal.h"

typedef struct _MIOSourceFileEntry {
    char  *path;
    char  *lpath;
} MIOSourceFileEntry;

typedef struct _MIOSourceFileContext {
    GQueue        *queue;
    GStringChunk  *pathchunk;
    GString       *scratch;
    char          *lpath;
} MIOSourceFileContext;

static MIOSourceFileContext *
mio_source_file_context(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    MIOSourceFileContext *fx = (MIOSourceFileContext *)source->ctx;

    if (!fx) {
        /* create file context on first call */
        fx = g_new0(MIOSourceFileContext, 1);
        fx->queue = g_queue_new();
        source->ctx = fx;
    } else if (!(*flags & MIO_F_OPT_DAEMON) && g_queue_is_empty(fx->queue)) {
        /* queue exists and is empty; not in daemon mode so terminate. */
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_NOINPUT,
                    "End of input");
        *flags |= MIO_F_CTL_TERMINATE;
        return NULL;
    }

    return fx;
}


static void
mio_source_file_context_reset(
    MIOSourceFileContext  *fx)
{
    if (fx->pathchunk) {g_string_chunk_free(fx->pathchunk);}
    fx->pathchunk = g_string_chunk_new(16384);
}


static MIOSourceFileEntry *
mio_source_file_entry_new(
    MIOSourceFileContext  *fx,
    const char            *path,
    uint32_t               flags)
{
    MIOSourceFileEntry *fent;

    if (flags & MIO_F_OPT_LOCK) {
        /* Generate lock path */
        if (!fx->scratch) {(fx->scratch) = g_string_new(NULL);}
        g_string_printf(fx->scratch, "%s.lock", path);

        /* Skip files locked at queue time */
        if (g_file_test(fx->scratch->str, G_FILE_TEST_IS_REGULAR)) {
            return NULL;
        }
    }

    /* No lock contention right now; create the entry. */
    fent = g_slice_new0(MIOSourceFileEntry);
    fent->path = g_string_chunk_insert(fx->pathchunk, path);
    if (flags & MIO_F_OPT_LOCK) {
        fent->lpath = g_string_chunk_insert(fx->pathchunk, fx->scratch->str);
    }

    return fent;
}


static gboolean
mio_source_next_file_queue(
    MIOSource             *source,
    MIOSourceFileContext  *fx,
    uint32_t              *flags,
    GError               **err)
{
    int fd;
    MIOSourceFileEntry *fent;

    for (;;) {
        /* Attempt to dequeue a file entry */
        if (!(fent = g_queue_pop_tail(fx->queue))) {
            /* Queue is empty. We're done. */
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_NOINPUT,
                        "End of input");
            *flags |= MIO_F_CTL_POLL;
            return FALSE;
        }

        /* Attempt lock */
        if (fent->lpath) {
            fd = open(fent->lpath, O_WRONLY | O_CREAT | O_EXCL, 0664);
            if (fd < 0) {
                g_slice_free(MIOSourceFileEntry, fent);
                continue;
            }
            close(fd);
        }

        /* Verify existence */
        if (!g_file_test(fent->path, G_FILE_TEST_IS_REGULAR)) {
            /* file not here; unlock it */
            if (fent->lpath) {unlink(fent->lpath);}
            g_slice_free(MIOSourceFileEntry, fent);
            continue;
        }

        /* We own the file. Store paths from the queue entry */
        source->name = fent->path;
        fx->lpath = fent->lpath;

        /* Now open the file as necessary */
        if (source->vsp_type != MIO_T_NULL) {
            /* Not a null type source. Open the file. */
            fd = open(fent->path, O_RDONLY, 0664);
            if (fd < 0) {
                /* File open failed. Unlock and return error. */
                g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IO,
                            "Couldn't open file %s for reading: %s",
                            fent->path, strerror(errno));
                *flags |= MIO_F_CTL_ERROR;
                if (fent->lpath) {unlink(fent->lpath);}
                g_slice_free(MIOSourceFileEntry, fent);
                return FALSE;
            }

            /* Determine how to store opened file */
            if (source->vsp_type == MIO_T_FP) {
                /* As file handle. fdopen should never fail here. */
                source->vsp = fdopen(fd, "r");
                g_assert(source->vsp);
            } else {
                /* As file descriptor. Yay Casting! */
                source->vsp = GINT_TO_POINTER(fd);
            }
        }
        g_slice_free(MIOSourceFileEntry, fent);

        /* Done */
        return TRUE;
    }
}


gboolean
mio_source_next_file_dir(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    MIOSourceFileContext *fx = NULL;
    MIOSourceFileEntry   *fent = NULL;
    uint32_t              fcount = 0, dnamlen = 0;
    DIR *dir = NULL;
    struct dirent        *dirent = NULL;

    /* Handle queue empty boundary conditions for non-daemon mode. */
    if (!(fx = mio_source_file_context(source, flags, err))) {return FALSE;}

    /* Valid queue. Ensure there's something in it. */
    if (g_queue_is_empty(fx->queue)) {
        /* Reset file context */
        mio_source_file_context_reset(fx);

        /* Open directory */
        if (!(dir = opendir(source->spec))) {
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IO,
                        "Could not open directory %s: %s",
                        source->spec, strerror(errno));
            *flags |= MIO_F_CTL_ERROR;
            return FALSE;
        }

        /* Iterate over directory entries, enqueueing. */
        while ((dirent = readdir(dir))) {
            dnamlen = strlen(dirent->d_name);

            /* Skip lockfiles */
            if (!strcmp(".lock", &(dirent->d_name[dnamlen]))) {
                continue;
            }

            /* Skip non-regular files */
#if HAVE_STRUCT_DIRENT_D_TYPE
            if (dirent->d_type != DT_REG) {
                continue;
            }
#endif
            /* Create a new file entry; skip on lock contention. */
            if (!(fent = mio_source_file_entry_new(fx, dirent->d_name,
                                                   *flags)))
            {
                continue;
            }

            /* Enqueue new entry */
            g_queue_push_head(fx->queue, fent);
            ++fcount;
        }

        /* Close directory */
        if (closedir(dir) < 0) {
            g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IO,
                        "Could not close directory %s: %s",
                        source->spec, strerror(errno));
            *flags |= MIO_F_CTL_ERROR;
            return FALSE;
        }
    }

    /* Filled queue if possible. Dequeue and open next file. */
    return mio_source_next_file_queue(source, fx, flags, err);
}


gboolean
mio_source_next_file_glob(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    MIOSourceFileContext *fx = NULL;
    MIOSourceFileEntry   *fent = NULL;
    glob_t gbuf;
    size_t i;
    int    grc;

    /* Handle queue empty boundary conditions for non-daemon mode. */
    if (!(fx = mio_source_file_context(source, flags, err))) {return FALSE;}

    /* Valid queue. Ensure there's something in it. */
    if (g_queue_is_empty(fx->queue)) {
        /* Reset file context */
        mio_source_file_context_reset(fx);

        /* Evaluate glob expression */
        grc = glob(source->spec, 0, NULL, &gbuf);
        if (grc == GLOB_NOSPACE) {
            g_error("Out of memory: glob allocation failure");
        }
#ifdef GLOB_NOMATCH
        /* HaX0riffic! Simulate behavior without NOMATCH where we have it. */
        else if (grc == GLOB_NOMATCH) {
            gbuf.gl_pathc = 0;
            gbuf.gl_pathv = NULL;
        }
#endif /* ifdef GLOB_NOMATCH */

        /* Iterate over glob paths, enqueueing. */
        for (i = 0; i < gbuf.gl_pathc; i++) {
            /* Skip non-regular files */
            if (!g_file_test(gbuf.gl_pathv[i], G_FILE_TEST_IS_REGULAR)) {
                continue;
            }

            /* Skip lockfiles */
            if (!strcmp(".lock", gbuf.gl_pathv[i]
                        + strlen(gbuf.gl_pathv[i]) - 5))
            {
                continue;
            }

            /* Create a new file entry; skip on lock contention. */
            if (!(fent = mio_source_file_entry_new(fx, gbuf.gl_pathv[i],
                                                   *flags)))
            {
                continue;
            }

            /* Enqueue new entry */
            g_queue_push_head(fx->queue, fent);
        }

        /* Free glob buffer */
        globfree(&gbuf);
    }

    /* Filled queue if possible. Dequeue and open next file. */
    return mio_source_next_file_queue(source, fx, flags, err);
}


gboolean
mio_source_next_file_single(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    MIOSourceFileContext *fx = NULL;
    MIOSourceFileEntry   *fent = NULL;

    /* Handle queue empty boundary conditions for non-daemon mode. */
    if (!(fx = mio_source_file_context(source, flags, err))) {return FALSE;}

    /* Valid queue. Ensure there's something in it. */
    if (g_queue_is_empty(fx->queue)) {
        /* Reset file context */
        mio_source_file_context_reset(fx);

        /* Add single entry */
        if ((fent = mio_source_file_entry_new(fx, source->spec, *flags))) {
            g_queue_push_head(fx->queue, fent);
        }
    }

    /* Filled queue if possible. Dequeue and open next file. */
    return mio_source_next_file_queue(source, fx, flags, err);
}


#define MIO_CLOSE_FILE_ERROR(_action_)                                     \
    {                                                                      \
        ok = FALSE;                                                        \
        if (!errstr) errstr = g_string_new ("I/O error on close:");        \
        g_string_append_printf(errstr, "\nfailed to %s %s: %s",            \
                               (_action_), source->name, strerror(errno)); \
    }

gboolean
mio_source_close_file(
    MIOSource  *source,
    uint32_t   *flags,
    GError    **err)
{
    MIOSourceFileContext *fx = (MIOSourceFileContext *)source->ctx;
    MIOSourceFileConfig  *cfg = (MIOSourceFileConfig *)source->cfg;
    char *ddir = NULL, *dbase = NULL;
    gboolean              ok = TRUE;
    GString              *errstr = NULL;

    /* Close file pointer or file descriptor as necessary */
    if (source->vsp_type == MIO_T_FP) {
        if (fclose((FILE *)source->vsp) < 0) {
            MIO_CLOSE_FILE_ERROR("close");
        }
    } else if (source->vsp_type == MIO_T_FD) {
        if (close(GPOINTER_TO_INT(source->vsp)) < 0) {
            MIO_CLOSE_FILE_ERROR("close");
        }
    }

    /* Determine move destination directory */
    if (*flags & MIO_F_CTL_ERROR) {
        /* Error. Move to fail directory. */
        ddir = cfg->faildir;
    } else if (*flags & MIO_F_CTL_TRANSIENT) {
        /* Transient error. Do not move. */
        ddir = NULL;
    } else {
        /* No error. Move to next directory. */
        ddir = cfg->nextdir;
    }

    /* Do move or delete */
    if (ddir) {
        if (*ddir) {
            /* Create scratch string if necessary */
            if (!fx->scratch) {fx->scratch = g_string_new(NULL);}
            /* Calculate move destination path */
            dbase = g_path_get_basename(source->name);
            g_string_printf(fx->scratch, "%s/%s", ddir, dbase);
            g_free(dbase);
            /* Do link */
            if (link(source->name, fx->scratch->str) < 0) {
                MIO_CLOSE_FILE_ERROR("move");
            }
        }

        /* Do delete */
        if (unlink(source->name) < 0) {
            MIO_CLOSE_FILE_ERROR("delete");
        }
    }

    /* Unlock file */
    if (fx->lpath) {unlink(fx->lpath);}

    /* Clear file */
    fx->lpath = NULL;
    source->name = NULL;
    source->vsp = NULL;

    /* Handle error */
    if (!ok) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_IO, "%s", errstr->str);
        g_string_free(errstr, TRUE);
        *flags |= MIO_F_CTL_ERROR;
    }

    /* all done */
    return ok;
}


void
mio_source_free_file(
    MIOSource  *source)
{
    MIOSourceFileContext *fx = (MIOSourceFileContext *)source->ctx;

    if (source->spec) {g_free(source->spec);}

    if (fx) {
        if (fx->queue) {
            MIOSourceFileEntry *fent;
            while ((fent = g_queue_pop_tail(fx->queue))) {
                g_slice_free(MIOSourceFileEntry, fent);
            }
            g_queue_free(fx->queue);
        }
        if (fx->pathchunk) {g_string_chunk_free(fx->pathchunk);}
        if (fx->scratch) {g_string_free(fx->scratch, TRUE);}
        g_free(fx);
    }
}


static gboolean
mio_source_init_file_inner(
    MIOSource    *source,
    const char   *spec,
    MIOType       vsp_type,
    void         *cfg,
    MIOSourceFn   next_source,
    GError      **err)
{
    /* choose default type */
    if (vsp_type == MIO_T_ANY) {vsp_type = MIO_T_FP;}

    /* initialize file source */
    source->spec = g_strdup(spec);
    source->name = NULL;
    source->vsp_type = vsp_type;
    source->vsp = NULL;
    source->ctx = NULL;
    source->cfg = cfg;
    source->next_source = next_source;
    source->close_source = mio_source_close_file;
    source->free_source = mio_source_free_file;
    source->opened = FALSE;
    source->active = FALSE;

    /* Ensure type is valid */
    if (!(vsp_type == MIO_T_NULL ||
          vsp_type == MIO_T_FD ||
          vsp_type == MIO_T_FP))
    {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Cannot open file source: type mismatch");
        return FALSE;
    }

    return TRUE;
}


gboolean
mio_source_init_file_dir(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* check that specifier exists */
    if (!spec || !strlen(spec)) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Source specifier is empty");
        return FALSE;
    }

    /* check that specifier is an accessible directory */
    if (!g_file_test(spec, G_FILE_TEST_IS_DIR)) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Source specifier %s is not a directory", spec);
        return FALSE;
    }

    /* initialize source */
    return mio_source_init_file_inner(source, spec, vsp_type, cfg,
                                      mio_source_next_file_dir, err);
}


gboolean
mio_source_init_file_glob(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* check that specifier exists */
    if (!spec || !strlen(spec)) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Source specifier is empty");
        return FALSE;
    }

    /* failover to single */
    if (!strchr(spec, '*') && !strchr(spec, '?') && !strchr(spec, '[')) {
        return mio_source_init_file_single(source, spec, vsp_type, cfg, err);
    }

    /* initialize source */
    return mio_source_init_file_inner(source, spec, vsp_type, cfg,
                                      mio_source_next_file_glob, err);
}


gboolean
mio_source_init_file_single(
    MIOSource   *source,
    const char  *spec,
    MIOType      vsp_type,
    void        *cfg,
    GError     **err)
{
    /* check that specifier exists */
    if (!spec || !strlen(spec)) {
        g_set_error(err, MIO_ERROR_DOMAIN, MIO_ERROR_ARGUMENT,
                    "Source specifier is empty");
        return FALSE;
    }

    /* failover to stdin */
    if (!strcmp(spec, "-")) {
        return mio_source_init_stdin(source, spec, vsp_type, cfg, err);
    }

    /* initialize source */
    return mio_source_init_file_inner(source, spec, vsp_type, cfg,
                                      mio_source_next_file_single, err);
}
