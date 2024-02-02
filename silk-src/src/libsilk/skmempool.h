/*
** Copyright (C) 2010-2023 by Carnegie Mellon University.
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
**  skmempool.h
**
**    Memory Pool Allocator
**
*/
#ifndef _SKMEMPOOL_H
#define _SKMEMPOOL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKMEMPOOL_H, "$SiLK: skmempool.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/**
 *  @file
 *
 *    Implementation of a memory pool.
 *
 *    This file is part of libsilk.
 *
 *
 *
 *    The memory pool is an efficient way to allocate elements that
 *    all have the same size, the 'element_size'.  When you create the
 *    pool, you specify the number of bytes per element and the number
 *    of elements the pool should allocate at once (internally the
 *    pool calls this a block), that is, the 'elements_per_block'.
 *
 *    The 'elements_per_block' should be large enough to avoid a lot
 *    of calls to malloc()---that is why use are using the memory
 *    pool---but not so large that there is a lot of wasted space.
 *
 *    To use the memory pool, you request an element from the pool and
 *    the pool returns an element to you (the memory in the element is
 *    cleared).  Behind the scenes, the pool may reuse memory or
 *    allocate fresh memory.
 *
 *    When you are finished with the element, return it to the pool
 *    and the pool will reuse it on subsequent requests for memory.
 *    Never "return" memory to a pool that you have created via other
 *    means, and ensure that you return memory to the pool where it
 *    was allocated.
 *
 *    Internally, the pool never uses realloc(), so all existing
 *    pointers remain valid until the pool is destroyed.
 *
 *    The memory used by the pool never decreases; that is, allocated
 *    memory is never freed until the pool is destroyed.
 *
 */


/**
 *    The type of a memory pool.
 */
typedef struct sk_mempool_st sk_mempool_t;


/**
 *    Creates a new memory pool to hand out memory in 'element_size'
 *    pieces.  This should be the size of the item you are creating.
 *    The element_size should be specified with sizeof() to ensure
 *    that structures are properly aligned.
 *
 *    Due to the way the pool maintains freed data, the smallest
 *    element_size that can be used is sizeof(void*).  If a smaller
 *    element size is specified by the caller, internally the memory
 *    pool will use sizeof(void*).
 *
 *    When the pool requires memory, it allocates blocks of memory,
 *    where each block of memory holds 'elements_per_block' items.
 *
 *    This call only allocates the pool itself; this call does not
 *    allocate any elements.
 *
 *    A pointer to the new memory pool is put into the location
 *    specified by 'pool' and 0 is returned.  Returns -1 if either
 *    size value is 0, if the product of the sizes is larger than
 *    UINT32_MAX, or if pool cannot be created due to lack of memory.
 */
int
skMemoryPoolCreate(
    sk_mempool_t      **pool,
    size_t              element_size,
    size_t              elements_per_block);


/**
 *    Destroys the memory pool at the location specify by '*pool'.
 *    The pool and all the elements it has created are destroyed.  If
 *    'pool' or the location it points to is NULL, no action is taken.
 */
void
skMemoryPoolDestroy(
    sk_mempool_t      **pool);


/**
 *    Return a true value if the element 'elem' appears to be from the
 *    memory pool 'pool', or a false value otherwise.
 */
int
skMemoryPoolOwnsElement(
    const sk_mempool_t *pool,
    const void         *elem);


/**
 *    Returns the element 'elem' to the memory pool 'pool'.
 *
 *    Be careful to only return memory to the pool that has been
 *    allocated using skMemPoolElementNew() for that particular pool.
 */
void
skMemPoolElementFree(
    sk_mempool_t       *pool,
    void               *elem);


/**
 *    Returns element_size bytes of cleared memory from the pool
 *    'pool', where the element size was specified when the pool was
 *    created.  Returns NULL if memory cannot be allocated.
 */
void *
skMemPoolElementNew(
    sk_mempool_t       *pool);

#ifdef __cplusplus
}
#endif
#endif /* _SKMEMPOOL_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
