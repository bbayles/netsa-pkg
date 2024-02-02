/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  ring.c
 *  General ring array implementation
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

#define _YAF_SOURCE_
#include <yaf/ring.h>

struct rgaRing_st {
    size_t     elt_sz;
    size_t     cap;
    size_t     count;
    size_t     peak;
    size_t     hrsv;
    size_t     trsv;
    uint8_t   *base;
    uint8_t   *end;
    uint8_t   *head;
    uint8_t   *tail;
#if YAF_RING_THREAD
    GMutex    *mtx;
    GCond     *cnd_zero;
    GCond     *cnd_full;
    uint32_t   interrupt;
#endif /* if YAF_RING_THREAD */
};

/**
 * rgaAlloc
 *
 *
 *
 */
rgaRing_t *
rgaAlloc(
    size_t   elt_sz,
    size_t   cap)
{
    rgaRing_t *ring = NULL;
    size_t     alignedEltSize = elt_sz;

#if HAVE_ALIGNED_ACCESS_REQUIRED
    alignedEltSize += (elt_sz % (sizeof(uint64_t)));
#endif
    /* allocate the structure */
    ring = g_slice_new0(rgaRing_t);

    /* allocate the buffer */
    ring->base = g_slice_alloc0(alignedEltSize * cap);

    /* note last element in array */
    ring->end = ring->base + (alignedEltSize * (cap - 1));

    /* set head and tail pointers to start of ring */
    ring->head = ring->tail = ring->base;

    /* stash element size and capacity */
    ring->elt_sz = alignedEltSize;
    ring->cap = cap;

    /* All done. */
    return ring;
}


#if YAF_RING_THREAD
/**
 * rgaAllocThreaded
 *
 *
 *
 */
rgaRing_t *
rgaAllocThreaded(
    size_t   elt_sz,
    size_t   cap)
{
    rgaRing_t *ring = rgaAlloc(elt_sz, cap);

    /* allocate mutex and conditions */
    ring->mtx = g_mutex_new();
    ring->cnd_zero = g_cond_new();
    ring->cnd_full = g_cond_new();

    return ring;
}


#endif /* if YAF_RING_THREAD */

/**
 * rgaFree
 *
 *
 *
 */
void
rgaFree(
    rgaRing_t  *ring)
{
    size_t base_sz;

    base_sz = ring->elt_sz * ring->cap;

#if YAF_RING_THREAD
    /* free conditions and mutex if present */
    if (ring->cnd_zero) {
        g_cond_free(ring->cnd_zero);
    }

    if (ring->cnd_full) {
        g_cond_free(ring->cnd_full);
    }

    if (ring->mtx) {
        g_mutex_free(ring->mtx);
    }
#endif /* if YAF_RING_THREAD */

    /* free buffer */
    g_slice_free1(base_sz, ring->base);

    /* free structure */
    g_slice_free(rgaRing_t, ring);
}


/**
 * rgaNextHead
 *
 *
 *
 */
uint8_t *
rgaNextHead(
    rgaRing_t  *ring)
{
    uint8_t *head;

    /* return null if buffer full */
    if (ring->count >= (ring->cap - ring->trsv)) {
        return NULL;
    }

    /* get head pointer */
    head = ring->head;

    /* advance head pointer and wrap */
    ring->head += ring->elt_sz;
    if (ring->head > ring->end) {
        ring->head = ring->base;
    }

    /* keep count and peak */
    ++(ring->count);
    if (ring->count > ring->peak) {
        ring->peak = ring->count;
    }

    /* return head pointer */
    return head;
}


#if YAF_RING_THREAD
/**
 * rgaNextHead
 *
 *
 *
 */
uint8_t *
rgaNextHead(
    rgaRing_t  *ring)
{
    uint8_t *head = NULL;

    g_mutex_lock(ring->mtx);
    while (!ring->interrupt && ((head = rgaNextHead(ring)) == NULL)) {
        g_cond_wait(ring->cnd_full, ring->mtx);
    }
    if (ring->interrupt) {
        head = NULL;
        goto end;
    }
    if (++(ring->hrsv) > ring->cap) {
        ring->hrsv = ring->cap;
    }
    g_cond_signal(ring->cnd_zero);
  end:
    g_mutex_unlock(ring->mtx);
    return head;
}


#endif /* if YAF_RING_THREAD */

#if YAF_RING_THREAD
/**
 * rgaReleaseHead
 *
 *
 *
 */
void
rgaReleaseHead(
    rgaRing_t  *ring,
    size_t      rsv)
{
    g_mutex_lock(ring->mtx);
    if (rsv > ring->hrsv) {
        rsv = ring->hrsv;
    }
    ring->hrsv -= rsv;
    g_cond_signal(ring->cnd_full);
    g_mutex_unlock(ring->mtx);
}


#endif /* if YAF_RING_THREAD */

/**
 * rgaNextTail
 *
 *
 *
 */
uint8_t *
rgaNextTail(
    rgaRing_t  *ring)
{
    uint8_t *tail;

    /* return null if buffer empty */
    if (ring->count <= ring->hrsv) {
        return NULL;
    }

    /* get tail pointer */
    tail = ring->tail;

    /* advance tail pointer and wrap */
    ring->tail += ring->elt_sz;
    if (ring->tail > ring->end) {
        ring->tail = ring->base;
    }

    /* keep count */
    --(ring->count);

    /* return tail pointer */
    return tail;
}


#if YAF_RING_THREAD
/**
 * rgaWaitTail
 *
 *
 *
 */
uint8_t *
rgaWaitTail(
    rgaRing_t  *ring)
{
    uint8_t *tail = NULL;

    g_mutex_lock(ring->mtx);
    while (!ring->interrupt && ((tail = rgaNextTail(ring)) == NULL)) {
        g_cond_wait(ring->cnd_zero, ring->mtx);
    }
    if (ring->interrupt) {
        tail = NULL;
        goto end;
    }
    if (++(ring->trsv) >= ring->cap) {
        ring->trsv = ring->cap;
    }
    g_cond_signal(ring->cnd_full);
  end:
    g_mutex_unlock(ring->mtx);
    return tail;
}


#endif /* if YAF_RING_THREAD */

#if YAF_RING_THREAD
/**
 * rgaReleaseTail
 *
 *
 *
 */
void
rgaReleaseTail(
    rgaRing_t  *ring,
    size_t      rsv)
{
    g_mutex_lock(ring->mtx);
    if (rsv > ring->trsv) {
        rsv = ring->trsv;
    }
    ring->trsv -= rsv;
    g_cond_signal(ring->cnd_zero);
    g_mutex_unlock(ring->mtx);
}


#endif /* if YAF_RING_THREAD */

#if YAF_RING_THREAD
/**
 * rgaSetInterrupt
 *
 *
 *
 */
void
rgaSetInterrupt(
    rgaRing_t  *ring)
{
    g_mutex_lock(ring->mtx);
    ++(ring->interrupt);
    g_cond_broadcast(ring->cnd_zero);
    g_cond_broadcast(ring->cnd_full);
    g_mutex_unlock(ring->mtx);
}


#endif /* if YAF_RING_THREAD */

#if YAF_RING_THREAD
/**
 * rgaClearInterrupt
 *
 *
 *
 */
void
rgaClearInterrupt(
    rgaRing_t  *ring)
{
    g_mutex_lock(ring->mtx);
    --(ring->interrupt);
    g_mutex_unlock(ring->mtx);
}


#endif /* if YAF_RING_THREAD */

/**
 * rgaCount
 *
 *
 *
 */
size_t
rgaCount(
    rgaRing_t  *ring)
{
    return ring->count;
}


/**
 * rgaPeak
 *
 *
 *
 */
size_t
rgaPeak(
    rgaRing_t  *ring)
{
    return ring->peak;
}
