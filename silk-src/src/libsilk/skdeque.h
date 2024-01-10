/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
**  skdeque.h
**
**    Methods for working with thread-safe double-ended queues
**
*/
#ifndef _SKDEQUE_H
#define _SKDEQUE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKDEQUE_H, "$SiLK: skdeque.h 5cd70d1ab29e 2023-07-14 14:06:27Z mthomas $");

/**
 *  @file
 *
 *    Implementation of a thread-safe, double-ended queue.
 *
 *    This file is part of libsilk-thrd.
 *
 *
 *  A deque maintains a list of void pointers.  It does not know the
 *  contents of these pointers, and as such the deque knows nothing
 *  about the memory management behind them.  A deque never attempts to
 *  copy or free anything behind the pointer.  It is the caller's
 *  responsibility to ensure that an object in a deque is not
 *  free()'ed until the object has been popped from the deque.
 *
 *
 *  Within this header file, the item most-recently pushed is
 *  considered to be "last", and "behind" all the other items, and the
 *  item which would be returned by a pop is considered to be "first",
 *  and "in front of" all the other items.
 */

/**
 *    The type of deques.
 *
 *    Unlike most SiLK types, the pointer is part of the typedef.
 */
typedef struct sk_deque_st *skDeque_t;


/**
 *    The type of return values from the skDeque functions.
 */
typedef enum {
    /** success */
    SKDQ_SUCCESS = 0,
    /** deque is empty */
    SKDQ_EMPTY = -1,
    /** unspecified error */
    SKDQ_ERROR = -2,
    /** deque was destroyed */
    SKDQ_DESTROYED = -3,
    /** deque was unblocked */
    SKDQ_UNBLOCKED = -4,
    /** deque pop timed out */
    SKDQ_TIMEDOUT = -5
} skDQErr_t;

/*** Deque creation functions ***/

/*
 * For all creation functions, a NULL return value indicates an error
 * condition.
 */

/**
 *    Creates a deque.  Returns NULL on memory allocation error.  To free the
 *    deque, use skDequeDestroy().
 */
skDeque_t
skDequeCreate(
    void);


/**
 *    Creates a copy (another reference) to a deque.  Operations on both
 *    deques will affect each other.  Returns NULL on error.  To free the
 *    copy, use skDequeDestroy().
 */
skDeque_t
skDequeCopy(
    skDeque_t           deque);

/**
 *    Creates a new pseudo-deque which acts like a deque with all the elements
 *    of q1 in front of q2.  q1 and q2 continue behaving normally.  Returns
 *    NULL on error.  To free the deque, use skDequeDestroy().
 */
skDeque_t
skDequeCreateMerged(
    skDeque_t           q1,
    skDeque_t           q2);


/*** Deque destruction ***/

/**
 *    Destroys a reference to a deque created by skDequeCreate(),
 *    skDequeCopy(), or skDequeCreateMerged().  If this is the last reference,
 *    also frees the deque.  Returns SKDQ_ERROR if 'deque' is NULL.
 *
 *    This function does not free the data stored in the deque.  The caller is
 *    responsible for freeing that data.
 */
skDQErr_t
skDequeDestroy(
    skDeque_t           deque);


/*** Deque information functions ***/

/**
 *    Returns the status of a deque: SKDQ_EMPTY if empty, SKDQ_SUCCESS if
 *    non-empty, or SKDQ_ERROR if 'deque' is NULL.
 */
skDQErr_t
skDequeStatus(
    skDeque_t           deque);

/**
 *    Returns the size of a deque.  Undefined on a bad (destroyed or
 *    error-ridden) deque.
 */
uint32_t
skDequeSize(
    skDeque_t           deque);

/**
 *    Peeks at the first element: Returns the first element of 'deque' without
 *    removing it, or SKDQ_EMPTY if the deque is empty.  This function does
 *    not remove items from the deque.  The caller must not free() an item
 *    until it has been popped.
 */
skDQErr_t
skDequeFront(
    skDeque_t           deque,
    void              **item);

/**
 *    Peeks at the last element: Like skDequeFront(), but returns the last
 *    element of 'deque'.
 */
skDQErr_t
skDequeBack(
    skDeque_t           deque,
    void              **item);


/*** Deque data manipulation functions ***/

/**
 *    Pops an element from the front of 'deque' and returns SKDQ_SUCCESS.  If
 *    'deque' is empty, blocks until an item is available or skDequeUnblock()
 *    is called; in the latter case, the function returns SKDQ_UNBLOCKED.
 *
 *    Returns SKDQ_DESTROYED if skDequeDestroy() has been called on 'deque'
 *    while waiting for an element.
 *
 *    It is the responsibility of the program using the deque to free any
 *    elements popped from it.
 */
skDQErr_t
skDequePopFront(
    skDeque_t           deque,
    void              **item);

/**
 *    Like skDequePopFront(), but does not block and returns SKDQ_EMPTY if
 *    'deque' is currently empty.
 */
skDQErr_t
skDequePopFrontNB(
    skDeque_t           deque,
    void              **item);

/**
 *    Like skDequePopFront() except, when 'deque' is empty, waits 'seconds'
 *    seconds for an item to appear in 'deque'.  If 'deque' is still empty
 *    after 'seconds' seconds, returns SKDQ_EMPTY.  If 'seconds' is 0, this is
 *    equivalent to skDequePopFront().
 */
skDQErr_t
skDequePopFrontTimed(
    skDeque_t           deque,
    void              **item,
    uint32_t            seconds);

/**
 *    Like skDequePopFront(), but returns the last element of 'deque'.
 */
skDQErr_t
skDequePopBack(
    skDeque_t           deque,
    void              **item);

/**
 *    Like skDequePopFrontNB(), but returns the last element of 'deque'.
 */
skDQErr_t
skDequePopBackNB(
    skDeque_t           deque,
    void              **item);

/**
 *    Like skDequePopFrontTimed(), but returns the last element of 'deque'.
 */
skDQErr_t
skDequePopBackTimed(
    skDeque_t           deque,
    void              **item,
    uint32_t            seconds);

/**
 *    Unblocks threads blocked on dequeue pops (each of which will return
 *    SKDQ_UNBLOCKED).  They will remain unblocked, ignoring blocking pops,
 *    until re-blocked.
 */
skDQErr_t
skDequeUnblock(
    skDeque_t           deque);

/**
 *    Enables blocking behavior on a deque unblocked by skDequeUnblock().
 *    Deques are created in a blockable state.
 */
skDQErr_t
skDequeBlock(
    skDeque_t           deque);

/**
 *    Pushes 'item' onto the front of 'deque' and returns SKDQ_SUCCESS.
 *    Returns SKDQ_ERROR on memory allocation error.
 *
 *    Deques maintain the item pointer only.  In order for the item to be of
 *    any use when it is later popped, it must survive its stay in the queue
 *    (not be freed).
 */
skDQErr_t
skDequePushFront(
    skDeque_t           deque,
    void               *item);

/**
 *    Like skDequePushFront(), but pushes 'item' onto the end of 'deque'.
 */
skDQErr_t
skDequePushBack(
    skDeque_t           deque,
    void               *item);

#ifdef __cplusplus
}
#endif
#endif /* _SKDEQUE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
