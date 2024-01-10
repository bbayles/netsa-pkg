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
**  skthread.c
**
**    Common thread routines, useful for debugging.
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skthread.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/skthread.h>

/* LOCAL DEFINES AND TYPEDEFS */

#ifndef SKTHREAD_LOG_IDS
#define SKTHREAD_LOG_IDS    0
#endif

typedef struct skthread_data_st {
    const char *name;
    void *(*fn)(void *);
    void *arg;
} skthread_data_t;


/* EXPORTED VARIABLE DEFINITIONS */

/* Used as a flag so we warn on too many read locks only once.  */
int skthread_too_many_readlocks = 0;


/* LOCAL VARIABLE DEFINITIONS */

static int initialized = 0;
static pthread_key_t skthread_name_key;
static pthread_key_t skthread_id_key;

/* mutex for protecting next_thread_id */
static pthread_mutex_t mutex;
static uint32_t next_thread_id = 0;


/* FUNCTION DEFINITIONS */

/*
 *    Set the thread's name and id.
 *
 *    Set the thread's name to the specified argument.  For the ID,
 *    allocate a uint32_t, set that value to the next unused thread
 *    ID, and set the thread's ID to that value.
 */
static void
skthread_set_name_id(
    const char         *name)
{
    uint32_t *id = (uint32_t*)malloc(sizeof(uint32_t));
    if (id != NULL) {
        pthread_mutex_lock(&mutex);
        *id = next_thread_id++;
        pthread_mutex_unlock(&mutex);

        pthread_setspecific(skthread_id_key, id);
#if SKTHREAD_LOG_IDS
        skAppPrintErr("Thread ID:%" PRIu32 " ('%s') started", *id, name);
#endif
    }
    pthread_setspecific(skthread_name_key, name);
}

/*
 *    Free the id for the current thread.
 */
static void
skthread_free_id(
    void               *id)
{
    if (id) {
#if SKTHREAD_LOG_IDS
        skAppPrintErr("Thread ID:%" PRIu32 " ended", *(uint32_t*)id);
#endif  /* SKTHREAD_LOG_IDS */
        free(id);
    }
}

/* initialize skthread code.  called once by main thread */
int
skthread_init(
    const char         *name)
{
    if (initialized) {
        return 0;
    }
    if (pthread_mutex_init(&mutex, NULL) != 0) {
        return -1;
    }
    if (pthread_key_create(&skthread_name_key, NULL) != 0) {
        return -1;
    }
    if (pthread_key_create(&skthread_id_key, skthread_free_id) != 0) {
        return -1;
    }
    skthread_set_name_id(name);

    initialized = 1;
    return 0;
}

/* teardown skthread code.  called once by main thread */
void
skthread_teardown(
    void)
{
    void *val;
    if (!initialized) {
        return;
    }
    initialized = 0;
    val = pthread_getspecific(skthread_id_key);
    pthread_setspecific(skthread_id_key, NULL);
    pthread_key_delete(skthread_id_key);
    pthread_key_delete(skthread_name_key);
    skthread_free_id(val);
}

/* return thread's name */
const char *
skthread_name(
    void)
{
    if (initialized) {
        const char *rv = (const char *)pthread_getspecific(skthread_name_key);
        if (rv != NULL) {
            return rv;
        }
    }
    return "unknown";
}

/* return thread's ID */
uint32_t
skthread_id(
    void)
{
    if (initialized) {
        uint32_t *id = (uint32_t *)pthread_getspecific(skthread_id_key);
        if (id != NULL) {
            return *id;
        }
    }
    return SKTHREAD_UNKNOWN_ID;
}


/*
 *    Thread entry function.
 *
 *    Wrapper function that is invoked by the pthread_create() call in
 *    skthread_create_helper() function.
 *
 *    Sets the thread's name, the thread's ID, sets the thread's
 *    signal mask to ignore all signals, then invokes the caller's
 *    function with the caller's argument.
 *
 *    The 'vdata' parameter contains the thread's name, the caller's
 *    function and argument.
 */
static void *
skthread_create_init(
    void               *vdata)
{
    skthread_data_t *data = (skthread_data_t *)vdata;
    void *(*fn)(void *) = data->fn;
    void *arg = data->arg;

    /* ignore all signals */
    skthread_ignore_signals();

    if (initialized) {
        skthread_set_name_id(data->name);
    }
    free(data);

    return fn(arg);
}


/*
 *    Helper function that implements common parts of
 *    skthread_create() and skthread_create_detached().
 */
static int
skthread_create_helper(
    const char         *name,
    pthread_t          *thread,
    void             *(*fn)(void *),
    void               *arg,
    pthread_attr_t     *attr)
{
    skthread_data_t *data;
    int rv;

    data = (skthread_data_t *)malloc(sizeof(*data));
    if (NULL == data) {
        return errno;
    }
    data->name = name;
    data->fn = fn;
    data->arg = arg;

    rv = pthread_create(thread, attr, skthread_create_init, data);
    if (rv != 0) {
        free(data);
    }
    return rv;
}

int
skthread_create(
    const char         *name,
    pthread_t          *thread,
    void             *(*fn)(void *),
    void               *arg)
{
    return skthread_create_helper(name, thread, fn, arg, NULL);
}


int
skthread_create_detached(
    const char         *name,
    pthread_t          *thread,
    void             *(*fn)(void *),
    void               *arg)
{
    pthread_attr_t attr;
    int rv;

    rv = pthread_attr_init(&attr);
    if (rv != 0) {
        return rv;
    }
    rv = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    assert(rv == 0);

    rv = skthread_create_helper(name, thread, fn, arg, &attr);
    pthread_attr_destroy(&attr);

    return rv;
}


void
skthread_ignore_signals(
    void)
{
    sigset_t sigs;

    sigfillset(&sigs);
    sigdelset(&sigs, SIGABRT);
    sigdelset(&sigs, SIGBUS);
    sigdelset(&sigs, SIGILL);
    sigdelset(&sigs, SIGSEGV);

#ifdef SIGEMT
    sigdelset(&sigs, SIGEMT);
#endif
#ifdef SIGIOT
    sigdelset(&sigs, SIGIOT);
#endif
#ifdef SIGSYS
    sigdelset(&sigs, SIGSYS);
#endif

    pthread_sigmask(SIG_SETMASK, &sigs, NULL);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
