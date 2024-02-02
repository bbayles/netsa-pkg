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
**  Memory Pool Allocator
**
**    Mark Thomas
**    January 2010
**
**    The memory pool contains a linked list of blocks.  Each block
**    contains a pointer to the next block and then space for
**    'elements_per_block' elements that are each 'element_size'
**    bytes.
**
**    When memory is initially requested by the caller, a new block is
**    created and elements and handed out from that block.  To make
**    allocation quick, a pointer to the next available entry in the
**    current block is maintained.
**
**    As the caller returns elements to the pool, the first
**    sizeof(void*) bytes of each element are used to create a linked
**    list of freed elements.
**
**    When the caller requests memory and the linked list of freed
**    elements is non-empty, one of those elements is returned.
**
**
**    Additional ideas for enhancement:
**
**    Add a debugging state where each "element" in the block has
**    number of flag bytes before the element we had to the caller.
**    These flag bytes can be used to see whether an element has been
**    allocated or freed.  By using an unusual value for the flag
**    bits, such as 0xaaaaaaaa and 0x55555555, we may be able to
**    determine when an element is writing outside its bounds.
**
**    Use the valgrind API specified to teach valgrind about the
**    memory pool.  See
**    http://valgrind.org/docs/manual/mc-manual.html#mc-manual.mempools
**
**    It would be nice if there were some way to free blocks when all
**    the elements in a block have been freed.  I suppose each block
**    could have a counter associated with it that specifies the
**    number of allocated elements.  However, to maintain the counter,
**    the skMemPoolElementFree() function would have to determine
**    which block owns the memory being freed, which is some extra
**    overhead.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skmempool.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skmempool.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/*
 *    Using a memory pool can make it difficult for tools like
 *    valgrind to determine if you are writing outside an
 *    element---since you may be outside the element but still inside
 *    the larger block.
 *
 *    When the MEMORY_POOL_DISABLE macro is true, elements will be
 *    allocated and freed individually which will help valgrind
 *    determine what is happening.
 */
/* #define MEMORY_POOL_DISABLE 1 */
#ifndef MEMORY_POOL_DISABLE
#  define MEMORY_POOL_DISABLE 0
#endif


/*
 *    This adds an extra check to every skMemPoolElementFree() call to
 *    check whether the element was allocated from the pool.  If an
 *    element is not from the pool, the program aborts.
 */
/* #define MEMORY_POOL_CHECK_FREE 1 */
#ifndef MEMORY_POOL_CHECK_FREE
#  define MEMORY_POOL_CHECK_FREE 0
#endif


/* forward declarations */
typedef struct sk_mempool_block_st    sk_mempool_block_t;
typedef struct sk_mempool_element_st  sk_mempool_element_t;


/* the memory pool */
struct sk_mempool_st {
    /* a linked list of blocks that have been allocated */
    sk_mempool_block_t     *block_list;
    /* pointer into current block. this is the element to return on
     * next request (unless freed_elements are available) */
    uint8_t                *next_block_element;
    /* a linked list of elements that have been freed */
    sk_mempool_element_t   *freed_elements;
    /* number of elements still available in current block */
    size_t                  block_elems_avail;
    /* element size as set by the user */
    size_t                  element_size;
    /* number of elements the pool should allocate in a block whenever
     * a new block of elements are needed.  Set by user. */
    size_t                  elements_per_block;
};


/*
 *    A block is just a pointer to the next block and the large data
 *    block of elements.
 *
 * typedef sk_mempool_block_t;
 */
struct sk_mempool_block_st {
    /* ensure the element_data is aligned on an 8-byte boundary */
    union mempool_block_align_un {
        sk_mempool_block_t     *p;
        uint64_t                aligner;
    }                       next;
    uint8_t                 element_data[1];
};


/*
 *    When elements are returned to the pool, they are cast to this
 *    type so we can maintain a linked list of them.
 *
 * typedef sk_mempool_element_t;
 */
struct sk_mempool_element_st {
    void     *next;
};


/* FUNCTION DEFINITIONS */

/* creates a new memory pool */
int
skMemoryPoolCreate(
    sk_mempool_t      **pool,
    size_t              element_size,
    size_t              elements_per_block)
{
    sk_mempool_t *p;

    assert(pool);

    /* verify that values are non-zero */
    if (element_size == 0 || elements_per_block == 0) {
        return -1;
    }

    /* a linked list of freed elements is maintained, so each element
     * must be at least as large a pointer */
    if (element_size < sizeof(sk_mempool_element_t)) {
        element_size = sizeof(sk_mempool_element_t);
    }

    /* verify the values won't cause overflow */
    if ((UINT32_MAX - sizeof(sk_mempool_block_t)) / element_size
        < elements_per_block)
    {
        return -1;
    }

    /* allocate and initialize */
    p = (sk_mempool_t*)calloc(1, sizeof(sk_mempool_t));
    if (p == NULL) {
        return -1;
    }

    p->element_size = element_size;
    p->elements_per_block = elements_per_block;

    *pool = p;
    return 0;
}


/* destroys the pool */
void
skMemoryPoolDestroy(
    sk_mempool_t      **pool)
{
    uint8_t *block;
    sk_mempool_t *p;

    if (pool == NULL || *pool == NULL) {
        return;
    }
    p = *pool;
    *pool = NULL;

    /* free all the blocks */
    while (p->block_list) {
        block = (uint8_t*)p->block_list;
        p->block_list = p->block_list->next.p;
        free(block);
    }

    /* clear object for a bit of extra sanity checking */
    memset(p, 0, sizeof(sk_mempool_t));
    free(p);
}


#if 0
/* frees everything except the pool itself.  not sure how useful this
 * is, so I'll leave it commented out for now */
void
skMemoryPoolFreeAll(
    sk_mempool_t       *pool)
{
    uint8_t *block;
    sk_mempool_t *p;

    assert(pool);

    /* free all the blocks */
    while (p->block_list) {
        block = (uint8_t*)p->block_list;
        p->block_list = p->block_list->next.p;
        free(block);
    }

    p->block_list = NULL;
    p->freed_elements = NULL;
    p->next_block_element = NULL;
    p->block_elems_avail = 0;
}
#endif  /* 0 */


/* check whether 'p' owns 'elem'. */
int
skMemoryPoolOwnsElement(
    const sk_mempool_t *p,
    const void         *elem)
{
    sk_mempool_block_t *block;
    uint8_t *e = (uint8_t*)elem;
    size_t block_size;

    assert(p);
    assert(elem);

    block_size = p->element_size * p->elements_per_block;

    for (block = p->block_list; block != NULL; block = block->next.p) {
        if ((block->element_data <= e)
            && (e < (block->element_data + block_size)))
        {
            /* found */
            return 1;
        }
    }
    return 0;
}


/* adds the element 'e' back into the pool 'p' */
#if MEMORY_POOL_DISABLE
void
skMemPoolElementFree(
    sk_mempool_t    UNUSED(*p),
    void                   *elem)
{
    assert(p);
    assert(elem);
    free(elem);
}
#else  /* MEMORY_POOL_DISABLE */
void
skMemPoolElementFree(
    sk_mempool_t       *p,
    void               *elem)
{
    assert(p);
    assert(elem);

#if MEMORY_POOL_CHECK_FREE
    if (!skMemoryPoolOwnsElement(p, elem)) {
        skAppPrintErr("Element %p not member of pool %p",
                      elem, p);
        skAbort();
    }
#endif  /* MEMORY_POOL_CHECK_FREE */

    /* copy value in freed_elements into the element */
#ifdef SK_HAVE_ALIGNED_ACCESS_REQUIRED
    memcpy(elem, &p->freed_elements, sizeof(void*));
#else
    ((sk_mempool_element_t*)elem)->next = p->freed_elements;
#endif

    p->freed_elements = (sk_mempool_element_t*)elem;
}
#endif  /* MEMORY_POOL_DISABLE */


/* "allocates" memory for a new element */
#if  MEMORY_POOL_DISABLE
void *
skMemPoolElementNew(
    sk_mempool_t       *p)
{
    assert(p);
    return calloc(1, p->element_size);
}
#else  /* MEMORY_POOL_DISABLE */
void *
skMemPoolElementNew(
    sk_mempool_t       *p)
{
    sk_mempool_block_t *new_block;
    void *e;

    assert(p);

    /* return a value from the linked list of freed elements */
    if (p->freed_elements) {
        e = (void*)p->freed_elements;
#ifdef SK_HAVE_ALIGNED_ACCESS_REQUIRED
        memcpy(&p->freed_elements, e, sizeof(void*));
#else
        p->freed_elements = (sk_mempool_element_t*)p->freed_elements->next;
#endif
        goto END;
    }

    /* return a value from current block */
    if (p->next_block_element) {
        e = (void*)p->next_block_element;
        --p->block_elems_avail;
        if (p->block_elems_avail > 0) {
            p->next_block_element += p->element_size;
        } else {
            p->next_block_element = NULL;
        }
        goto END;
    }

    /* must allocate a new block.  add additional space to the front
     * of the block to maintain a linked list of blocks. */
    new_block = ((sk_mempool_block_t*)
                 malloc((p->element_size * p->elements_per_block)
                        + offsetof(sk_mempool_block_t, element_data)));
    if (new_block == NULL) {
        return NULL;
    }

    /* update the linked list of blocks */
    new_block->next.p = p->block_list;
    p->block_list = new_block;

    /* element to return is the first in the data section */
    e = (void*)new_block->element_data;

    /* set next_block_element, skipping the first in the data section
     * which is the element being returned */
    p->next_block_element = (uint8_t*)e + p->element_size;
    p->block_elems_avail = p->elements_per_block - 1;

  END:
    memset(e, 0, p->element_size);
    return (void*)e;
}
#endif  /* MEMORY_POOL_DISABLE */


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
