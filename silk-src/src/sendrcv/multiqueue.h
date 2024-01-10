/*
** Copyright (C) 2007-2023 by Carnegie Mellon University.
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
**  multiqueue.h
**
**    Creates queue sets.
**
*/
#ifndef _MULTIQUEUE_H
#define _MULTIQUEUE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_MULTIQUEUE_H, "$SiLK: multiqueue.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
 *    Multiqueues are sets of subqueues that can work together as a
 *    single queue.  Subqueues can be added to and moved between
 *    multiqueues at runtime.
 */


/* Type of a multiqueue */
typedef struct mq_multi_st mq_multi_t;

/* Type of a multiqueue subqueue */
typedef struct mq_queue_st mq_queue_t;

typedef enum mq_err_en {
    MQ_NOERROR = 0,
    MQ_DISABLED,
    MQ_SHUTDOWN,
    MQ_MEMERROR,
    MQ_ILLEGAL
} mq_err_t;

typedef enum mq_function_en {
    MQ_ADD    = 1,
    MQ_REMOVE = (1 << 1) ,
    MQ_BOTH   = MQ_ADD | MQ_REMOVE
} mq_function_t;


/**
 *    Create an unfair multiqueue.
 *
 *    An unfair multiqueue will drain all data from its first subqueue
 *    before draining elements from subsequent subqueues.
 *
 *    The 'free_fn' is a function that is used to free elements in the
 *    multiqueue's subqueues upon destruction of the multiqueue.  It
 *    may be NULL.
 */
mq_multi_t *
mqCreateUnfair(
    void              (*free_fn)(void *));

/**
 *    Create an fair multiqueue.
 *
 *    An fair multiqueue will drain data from its subqueues in a
 *    round-robin fashion.
 *
 *    The 'free_fn' is a function that is used to free elements in the
 *    multiqueue's subqueues upon destruction of the multiqueue.  It
 *    may be NULL.
 */
mq_multi_t *
mqCreateFair(
    void              (*free_fn)(void *));

/**
 *    Shutdown a multiqueue.
 *
 *    Shutting down a multiqueue unblocks all operations on that
 *    multiqueue, and makes the multiqueue unusable.  Generally a
 *    prelude to destroying a multiqueue.
 */
void
mqShutdown(
    mq_multi_t         *q);

/**
 *    Disable a part of functionality of a multiqueue.
 *
 *    One can disable either the ability to add or remove elements
 *    from a multiqueue.  Disabling adding also disables addding to
 *    the multiqueue's subqueues and adding new queues to the
 *    multiqueue.  Disabling removing will unblock Get calls on that
 *    multiqueue (but not its subqueues).  Multiqueue functionality
 *    can be reinstated using mqEnable().
 */
mq_err_t
mqDisable(
    mq_multi_t         *q,
    mq_function_t       which);

/**
 *    Re-enable a part of functionality of a multiqueue.
 *
 *    Re-enables functionality of a multiqueue that has been
 *    previously disabled.
 */
mq_err_t
mqEnable(
    mq_multi_t         *q,
    mq_function_t       which);

/**
 *    Destroy a multiqueue and all owned subqueues.
 *
 *    If the multiqueue was created with a non-null free_fn, this
 *    function will also call that free_fn on all elements in the
 *    multiqueue's subqueues.
 */
void
mqDestroy(
    mq_multi_t         *q);

/**
 *    Get an element from a multiqueue.
 *
 *    This will block if the multiqueue is empty.  Returns MQ_NOERROR
 *    on success.  Returns MQ_SHUTDOWN or MQ_DISABLED if the
 *    multiqueue was shutdown or disabled.
 */
mq_err_t
mqGet(
    mq_multi_t         *q,
    void              **data);

/**
 *    Put an element back on a multiqueue, such that it will be the
 *    next element returned by an mqGet() call.
 */
mq_err_t
mqPushBack(
    mq_multi_t         *q,
    void               *data);

/**
 *    Create and add a subqueue to a multiqueue.
 */
mq_queue_t *
mqCreateQueue(
    mq_multi_t         *q);

/**
 *    Destroy a subqueue.
 */
void
mqDestroyQueue(
    mq_queue_t         *sq);

/**
 *    Add an element to a subqueue.
 */
mq_err_t
mqQueueAdd(
    mq_queue_t         *sq,
    void               *data);

/**
 *    Get an element from a subqueue.
 */
mq_err_t
mqQueueGet(
    mq_queue_t         *sq,
    void              **data);

/**
 *    Put an element back on a subqueue such that mqQueueGet() will
 *    return that element.
 */
mq_err_t
mqQueuePushBack(
    mq_queue_t         *sq,
    void               *data);

/**
 *    Move a subqueue to a particular multiqueue.
 */
mq_err_t
mqQueueMove(
    mq_multi_t         *q,
    mq_queue_t         *sq);

/**
 *    Disable a part of functionality of a subqueue.
 *
 *    One can disable either the ability to add or remove elements
 *    from a subqueue.  Disabling removing will unblock Get calls on
 *    that subqueue.  Subqueue functionality can be reinstated using
 *    mqQueueEnable().
 */
mq_err_t
mqQueueDisable(
    mq_queue_t         *q,
    mq_function_t       which);

/**
 *    Re-enable a part of functionality of a subqueue.
 *
 *    Re-enables functionality of a subqueue that has been previously
 *    disabled.
 */
mq_err_t
mqQueueEnable(
    mq_queue_t         *q,
    mq_function_t       which);

#ifdef __cplusplus
}
#endif
#endif /* _MULTIQUEUE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
