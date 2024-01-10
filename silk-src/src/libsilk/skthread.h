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
**  skthread.h
**
**    Common thread routines.
**
*/
#ifndef _SKTHREAD_H
#define _SKTHREAD_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKTHREAD_H, "$SiLK: skthread.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/sklog.h>


#define SKTHREAD_UNKNOWN_ID UINT32_MAX


/**
 *    Intitialize the skthread module.  This function is expected be
 *    called by the program's primary thread, and the function must be
 *    called before calling skthread_create() or
 *    skthread_create_detached().
 *
 *    Set the name of the current thread to `name', which must be a
 *    string that is valid for the lifetime of the thread.  Set the ID
 *    of the current thread to 0.
 *
 *    This function is a no-op if it has been called previously and
 *    succeeded.
 *
 *    Return 0 on success, -1 on failure.
 */
int
skthread_init(
    const char         *name);

/**
 *    Teardown function for the skthread module.  This function is
 *    expected be called by the program's primary thread, and the
 *    function should be called once all other threads have exited.
 */
void
skthread_teardown(
    void);

/**
 *    Spawn a simple thread and invoke the function 'fn' with the
 *    argument 'arg'.  Call skthread_ignore_signals() within the
 *    context of the new thread.
 *
 *    Set the thread's name to 'name', which must be a string that is
 *    valid for the lifetime of the thread.  Set the thread's ID to
 *    the next unused integer value.
 *
 *    Return 0 on success, errno on failure.
 */
int
skthread_create(
    const char         *name,
    pthread_t          *thread,
    void             *(*fn)(void *),
    void               *arg);

/**
 *    Similar to skthread_create(), except the thread is created with
 *    the detached attribute set.
 */
int
skthread_create_detached(
    const char         *name,
    pthread_t          *thread,
    void             *(*fn)(void *),
    void               *arg);

/**
 *    Return the name of the calling thread that was specified with
 *    skthread_init(), skthread_create(), or
 *    skthread_create_detached().
 *
 *    Return the string "unknown" if a name was not set for the
 *    calling thread.
 */
const char *
skthread_name(
    void);

/**
 *    Return the id of the calling thread.
 *
 *    Return the value SKTHREAD_UNKNOWN_ID if an id was not set for
 *    the calling thread.
 */
uint32_t
skthread_id(
    void);

/**
 *    Tell the current thread to ignore all signals except those
 *    indicating a failure (SIGABRT, SIGBUS, SIGSEGV, ...).
 */
void
skthread_ignore_signals(
    void);



/*
 *    Thread debug logging.
 *
 *    Wrappers around DEBUGMSG() that prepend the message with the
 *    current file name, line number, thread name, and thread id.
 */
#define SKTHREAD_DEBUG_PREFIX(m_fmt)                            \
    "%s:%d <%s:%" PRIu32 "> " m_fmt,                            \
        __FILE__, __LINE__, skthread_name(), skthread_id()

#define SKTHREAD_DEBUG_PRINT1(m_fmt)            \
    DEBUGMSG(SKTHREAD_DEBUG_PREFIX(m_fmt))
#define SKTHREAD_DEBUG_PRINT2(m_fmt, m_a2)              \
    DEBUGMSG(SKTHREAD_DEBUG_PREFIX(m_fmt), (m_a2))
#define SKTHREAD_DEBUG_PRINT3(m_fmt, m_a2, m_a3)                \
    DEBUGMSG(SKTHREAD_DEBUG_PREFIX(m_fmt), (m_a2), (m_a3))
#define SKTHREAD_DEBUG_PRINT4(m_fmt, m_a2, m_a3, m_a4)                  \
    DEBUGMSG(SKTHREAD_DEBUG_PREFIX(m_fmt), (m_a2), (m_a3), (m_a4))


/*
 *    Use the above wrappers over DEBUGMSG() when SKTHREAD_DEBUG_MUTEX
 *    is defined and has a value greater than 0.
 */
#if  defined(SKTHREAD_DEBUG_MUTEX) && SKTHREAD_DEBUG_MUTEX > 0
#define SKT_D2(x, y)        SKTHREAD_DEBUG_PRINT2(x, y)
#define SKT_D3(x, y, z)     SKTHREAD_DEBUG_PRINT3(x, y, z)
#define SKT_D4(x, y, z, zz) SKTHREAD_DEBUG_PRINT4(x, y, z, zz)
#else
#define SKT_D2(x, y)
#define SKT_D3(x, y, z)
#define SKT_D4(x, y, z, zz)
#endif


/*
 *    Wrappers around pthread mutex / condition functions
 */

/* Wrapper around pthread_mutex_init() */
#define MUTEX_INIT(m_mutex)         pthread_mutex_init((m_mutex), NULL)

/* Wrapper around pthread_mutex_destroy() */
#define MUTEX_DESTROY(m_mutex)      pthread_mutex_destroy((m_mutex))

/* Wrapper around pthread_cond_init() */
#define MUTEX_COND_INIT(m_cond)     pthread_cond_init((m_cond), NULL)

/* Wrapper around pthread_cond_destroy() */
#define MUTEX_COND_DESTROY(m_cond)  pthread_cond_destroy((m_cond))

/* Wrapper around pthread_mutex_lock() */
#define MUTEX_LOCK(m_mutex)                             \
    do {                                                \
        SKT_D2("MUTEX LOCKING %p", (void *)(m_mutex));  \
        pthread_mutex_lock(m_mutex);                    \
        SKT_D2("MUTEX IN LOCK %p", (void *)(m_mutex));  \
    } while (0)

/* Wrapper around pthread_mutex_unlock() */
#define MUTEX_UNLOCK(m_mutex)                                   \
    do {                                                        \
        SKT_D2("MUTEX UNLOCKING %p", (void *)(m_mutex));        \
        pthread_mutex_unlock(m_mutex);                          \
    } while (0)

/* Wrapper around pthread_cond_wait() */
#define MUTEX_WAIT(m_cond, m_mutex)                     \
    do {                                                \
        SKT_D3("MUTEX WAIT %p (Unlocked %p)",           \
               (void *)(m_cond), (void *)(m_mutex));    \
        pthread_cond_wait((m_cond), (m_mutex));         \
        SKT_D3("MUTEX RESUME %p (Locked %p)",           \
               (void *)(m_cond), (void *)(m_mutex));    \
    } while (0)

/* Wrapper around pthread_cond_timedwait(); result of call is stored
 * in memory location referenced by 'm_retval'. */
#define MUTEX_TIMEDWAIT(m_cond, m_mutex, m_timespec, m_retval)  \
    do {                                                        \
        SKT_D3("MUTEX WAIT %p (Unlocked %p)",                   \
               (void *)(m_cond), (void *)(m_mutex));            \
        *(m_retval) = (pthread_cond_timedwait(                  \
                           (m_cond), (m_mutex), (m_timespec))); \
        SKT_D4("MUTEX RESUME %p (Locked %p) (%s)",              \
               (void *)(m_cond), (void *)(m_mutex),             \
               (0 == *(m_retval)) ? "Signaled" : "Timed-out");  \
    } while (0)

/* Wrapper around pthread_cond_signal() */
#define MUTEX_SIGNAL(m_cond)                                    \
    do {                                                        \
        SKT_D2("SIGNALING %p", (void *)(m_cond));               \
        pthread_cond_signal(m_cond);                            \
    } while (0)

/* Wrapper around pthread_cond_broadcast() */
#define MUTEX_BROADCAST(m_cond)                                 \
    do {                                                        \
        SKT_D2("BROADCASTING %p", (void *)(m_cond));            \
        pthread_cond_broadcast(m_cond);                         \
    } while (0)

#if defined(SKTHREAD_DEBUG_MUTEX) && SKTHREAD_DEBUG_MUTEX > 0
#define ASSERT_MUTEX_LOCKED(m_mutex)                            \
    if (pthread_mutex_trylock((m_mutex)) == EBUSY) { } else {   \
        SKT_D2("Unexpectedly found %p to be unlocked",          \
               (void *)(m_mutex));                              \
        skAbort();                                              \
    }
#else
#define ASSERT_MUTEX_LOCKED(m_mutex)                    \
    assert(pthread_mutex_trylock((m_mutex)) == EBUSY)
#endif



/*
 *    Read / Write Lock Macros
 */

#ifdef SK_HAVE_PTHREAD_RWLOCK
#  define RWMUTEX pthread_rwlock_t

extern int skthread_too_many_readlocks;

#  define RW_MUTEX_INIT(m_mutex)    pthread_rwlock_init((m_mutex), NULL)

#  define RW_MUTEX_DESTROY(m_mutex)                             \
    do {                                                        \
        SKT_D2("RW MUTEX DESTROY %p", (void *)(m_mutex));       \
        pthread_rwlock_destroy((m_mutex));                      \
    } while (0)

#  define READ_LOCK(m_mutex)                                            \
    do {                                                                \
        SKT_D2("READ MUTEX LOCKING %p", (void *)(m_mutex));             \
        while (pthread_rwlock_rdlock(m_mutex) == EAGAIN) {              \
            if (!skthread_too_many_readlocks) {                         \
                skthread_too_many_readlocks = 1;                        \
                WARNINGMSG(("WARNING: Too many read locks; "            \
                            "spinlocking enabled to compensate"));      \
            }                                                           \
        }                                                               \
        SKT_D2("READ MUTEX IN LOCK %p", (void *)(m_mutex));             \
    } while (0)

#  define WRITE_LOCK(m_mutex)                                   \
    do {                                                        \
        SKT_D2("WRITE MUTEX LOCKING %p", (void *)(m_mutex));    \
        pthread_rwlock_wrlock(m_mutex);                         \
        SKT_D2("WRITE MUTEX IN LOCK %p", (void *)(m_mutex));    \
    } while (0)

#  define RW_MUTEX_UNLOCK(m_mutex)                              \
    do {                                                        \
        SKT_D2("RW MUTEX UNLOCKING %p", (void *)(m_mutex));     \
        pthread_rwlock_unlock(m_mutex);                         \
    } while (0)

#if defined(SKTHREAD_DEBUG_MUTEX) && SKTHREAD_DEBUG_MUTEX > 0

#  define ASSERT_RW_MUTEX_LOCKED(m_mutex)                               \
    do {                                                                \
        int wrlock_ret = pthread_rwlock_trywrlock(m_mutex);             \
        if (EBUSY == wrlock_ret || EDEADLK == wrlock_ret) { } else {    \
            SKT_D2("Unexpectedly found %p to be unlocked",              \
                   (void *)(m_mutex));                                  \
            skAbort();                                                  \
        }                                                               \
    } while (0)

#  define ASSERT_RW_MUTEX_WRITE_LOCKED(m_mutex)                         \
    do {                                                                \
        int rdlock_ret = pthread_rwlock_tryrdlock(m_mutex);             \
        if (EBUSY == rdlock_ret || EDEADLK == rdlock_ret) { } else {    \
            SKT_D2("Expected %p to be write locked but got a read lock", \
                   (void *)(m_mutex));                                  \
            skAbort();                                                  \
        }                                                               \
    } while (0)

#elif !defined(NDEBUG)

#  define ASSERT_RW_MUTEX_LOCKED(m_mutex)                       \
    do {                                                        \
        int wrlock_ret = pthread_rwlock_trywrlock(m_mutex);     \
        assert(EBUSY == wrlock_ret || EDEADLK == wrlock_ret);   \
    } while (0)

#  define ASSERT_RW_MUTEX_WRITE_LOCKED(m_mutex)                 \
    do {                                                        \
        int rdlock_ret = pthread_rwlock_tryrdlock(m_mutex);     \
        assert(EBUSY == rdlock_ret || EDEADLK == rdlock_ret);   \
    } while (0)

#else
/* no-ops */
#  define ASSERT_RW_MUTEX_LOCKED(m_mutex)
#  define ASSERT_RW_MUTEX_WRITE_LOCKED(m_mutex)
#endif  /* NDEBUG */

#else  /* #ifdef SK_HAVE_PTHREAD_RWLOCK */

/*
 *    No support for read/write locks; use ordinary locks
 */

#  define RWMUTEX                   pthread_mutex_t
#  define RW_MUTEX_INIT             MUTEX_INIT
#  define RW_MUTEX_DESTROY          MUTEX_DESTROY
#  define READ_LOCK                 MUTEX_LOCK
#  define WRITE_LOCK                MUTEX_LOCK
#  define RW_MUTEX_UNLOCK           MUTEX_UNLOCK
#  define ASSERT_RW_MUTEX_LOCKED(m_mutex)       ASSERT_MUTEX_LOCKED(m_mutex)
#  define ASSERT_RW_MUTEX_WRITE_LOCKED(m_mutex) ASSERT_MUTEX_LOCKED(m_mutex)

#endif  /* #else of #ifdef SK_HAVE_PTHREAD_RWLOCK */


#ifdef __cplusplus
}
#endif
#endif /* _SKTHREAD_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
