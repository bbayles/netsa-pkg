/*
** Copyright (C) 2001-2023 by Carnegie Mellon University.
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
**  skheap.c
**
**    Implementation of a heap data structure.
**
**    A heap data structure is an ordinary binary tree with two
**    properties: The shape property and the heap property.
**
**    The shape property states that the tree is perfectly balanced
**    and that the elements at the bottom level are pushed as far to
**    the left as possible; the tree has no holes and there are leaf
**    elements on at most two levels of the tree.
**
**    The heap property simply states that every element of the tree
**    is larger than any of its descendants if they exist.  In
**    particular, the largest element of the heap is the root
**    element. Of course the opposite ordering also defines a heap.
**    Depending on the ordering, a heap is called a max-heap or a
**    min-heap respectively.
**
**    This implementation uses 0 as the root of the heap; for any node
**    n, its parent node is (n-1)/2, and its children are 2n+1 and
**    2n+2
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skheap.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skheap.h>


/* TYPEDEFS AND DEFINES */

/*
 *    How much larger to make the data array when an attempt is made
 *    to insert an entry to a full heap.  A value of 0.50 represents a
 *    50% increase for each realloc.  A value of 1.0 means the heap
 *    array is doubled each time.
 */
#define HEAP_RESIZE_FACTOR  1.0


/*
 *  node = HEAP_NODE(heap, idx);
 *
 *    Return a pointer to the entry at position 'idx' in data array.
 */
#define HEAP_NODE(hn_heap, hn_idx)                              \
    ((hn_heap)->data + ((hn_idx) * (hn_heap->entry_size)))


/*
 *  HEAP_COPY_INTO(heap, dst_index, src_node);
 *
 *    Copy the node at 'src_node' into the data array at position
 *    'dst_index'.
 */
#define HEAP_COPY_INTO(hci_heap, hci_idx, hci_src_node)         \
    memcpy(HEAP_NODE((hci_heap), (hci_idx)), (hci_src_node),    \
           (hci_heap)->entry_size)


/*
 *  HEAP_COPY_OUT(heap, src_index, dst_node);
 *
 *    Copy the entry at position 'src_index' in the data array to the
 *    node 'dst_node'.
 */
#define HEAP_COPY_OUT(hco_heap, hco_idx, hco_dst_node)          \
    memcpy((hco_dst_node), HEAP_NODE((hco_heap), (hco_idx)),    \
           (hco_heap)->entry_size)


/*
 *  HEAP_COPY_INTERNAL(heap, dst_index, src_index);
 *
 *    Copy the entry at position 'src_index' in the data array to the
 *    entry at position 'dst_index' in the data array.
 */
#define HEAP_COPY_INTERNAL(hc_heap, hc_idx_dst, hc_idx_src)     \
    memcpy(HEAP_NODE((hc_heap), (hc_idx_dst)),                  \
           HEAP_NODE((hc_heap), (hc_idx_src)),                  \
           (hc_heap)->entry_size)



/* The heap data structure */
struct skheap_st {
    uint8_t        *data;
    uint8_t        *scratch;
    void           *cmp_data;
    skheapcmp2fn_t  cmpfun;
    uint32_t        max_entries;
    uint32_t        num_entries;
    uint32_t        entry_size;
    /* whether heap is using user-defined data */
    unsigned        user_data :1;
};


/* The interator over the heap */
struct skheapiterator_st {
    const skheap_t *heap;
    uint32_t        position;
    unsigned        reverse :1;
    unsigned        no_more_entries :1;
};


/* FUNCTION DEFINITONS */

/*
 *  status = heapGrow(heap);
 *
 *    Grow the data array in the heap.  Return SKHEAP_OK for success;
 *    SKHEAP_ERR_FULL for failure.
 */
static int
heapGrow(
    skheap_t           *heap)
{
    double factor = HEAP_RESIZE_FACTOR;
    size_t target_entries;
    void *new_data;

    assert(heap);

    /*
     * Determine new target size.  Find value such that
     *
     * ((((heap->max_entries * (1.0 + factor)) + 1) * heap->entry_size)
     *  < SIZE_MAX)
     *
     * where the +1 is for the scratch buffer.
     */
    while (((double)(SIZE_MAX - heap->entry_size) / (1.0 + factor))
           <= ((heap->max_entries + 1) * heap->entry_size))
    {
        factor /= 2.0;
    }
    target_entries = (size_t)(heap->max_entries * (1.0 + factor) + 1);

    /* Resize the heap to target_entries, adjust target_entries if
     * resize fails */
    while (target_entries > heap->max_entries) {
        new_data = realloc(heap->data, target_entries * heap->entry_size);
        if (new_data) {
            heap->data = (uint8_t*)new_data;
            heap->max_entries = target_entries - 1;
            heap->scratch = HEAP_NODE(heap, heap->max_entries);
            return SKHEAP_OK;
        }
        factor /= 2.0;
        target_entries = (size_t)(heap->max_entries * (1.0 + factor));
    }

    return SKHEAP_ERR_FULL;
}


/*
 *  heapSiftup(heap, start_idx, last_idx, new_node);
 *
 *      Given that 'start_idx' is empty and 'new_node' is to be
 *      inserted, either insert 'new_node' at 'start_idx' and return,
 *      or move one of the children of 'start_idx' into its position
 *      and then repeat with that child.  Assume that 'last_idx' is
 *      the largest valid index in the heap..
 */
static void
heapSiftup(
    skheap_t           *heap,
    uint32_t            start_idx,
    uint32_t            last_idx,
    const skheapnode_t  new_node)
{
    uint32_t child_idx;
    uint8_t *child_node;

    /* continue as long as at least one child of 'start_idx' is in scope */
    while ((child_idx = 1+2*start_idx) <= last_idx) {
        child_node = HEAP_NODE(heap, child_idx);
        /* child is set to left hand child. find the larger child if
         * both are in scope */
        if ((child_idx < last_idx)
            && ((*heap->cmpfun)(child_node, child_node + heap->entry_size,
                                heap->cmp_data) < 0))
        {
            /* right hand child is larger */
            child_idx++;
            child_node += heap->entry_size;
        }
        /* compare the child to new_node */
        if ((*heap->cmpfun)(new_node, child_node, heap->cmp_data) >= 0) {
            /* new_node is larger; we're done */
            break;
        }
        /* move child into parent's position */
        HEAP_COPY_INTO(heap, start_idx, child_node);
        start_idx = child_idx;
    }
    /* insert new_node */
    HEAP_COPY_INTO(heap, start_idx, new_node);
}


/* Create a new heap. */
skheap_t *
skHeapCreate(
    skheapcmpfn_t       cmpfun,
    uint32_t            init_count,
    uint32_t            entry_size,
    skheapnode_t       *data)
{
    return skHeapCreate2((skheapcmp2fn_t)cmpfun, init_count, entry_size,
                         data, NULL);
}


/* Create a new heap. */
skheap_t *
skHeapCreate2(
    skheapcmp2fn_t      cmpfun,
    uint32_t            init_count,
    uint32_t            entry_size,
    skheapnode_t       *data,
    void               *cmp_data)
{
    skheap_t *heap;

    if (init_count < 1) {
        return NULL;
    }
    if (NULL == cmpfun) {
        return NULL;
    }

    heap = (skheap_t*)calloc(1, sizeof(skheap_t));
    if (NULL == heap) {
        return NULL;
    }

    heap->max_entries = init_count;
    heap->entry_size = entry_size;
    heap->cmpfun = cmpfun;
    heap->cmp_data = cmp_data;

    if (data) {
        heap->user_data = 1;
        heap->data = (uint8_t*)data;
        heap->scratch = (uint8_t*)malloc(entry_size);
        if (NULL == heap->scratch) {
            free(heap);
            return NULL;
        }
    } else {
        /* allocate an extra space and use that as our scratch
         * space */
        heap->data = (uint8_t*)calloc(1 + init_count, entry_size);
        if (NULL == heap->data) {
            free(heap);
            return NULL;
        }
        heap->scratch = HEAP_NODE(heap, init_count);
    }

    return heap;
}


/* Set number of entries to 0. */
void
skHeapEmpty(
    skheap_t           *heap)
{
    assert(NULL != heap);
    heap->num_entries = 0;
}


/* Destroy the heap. */
void
skHeapFree(
    skheap_t           *heap)
{
    if (NULL == heap) {
        return;
    }

    if (heap->user_data) {
        if (NULL != heap->scratch) {
            free(heap->scratch);
            heap->scratch = NULL;
        }
    } else if (NULL != heap->data) {
        free(heap->data);
        heap->data = NULL;
        heap->scratch = NULL;
    }

    free(heap);
    heap = NULL;
}


/* Get capacity */
uint32_t
skHeapGetCapacity(
    const skheap_t     *heap)
{
    assert(NULL != heap);
    return heap->max_entries;
}


/* Get entry size */
uint32_t
skHeapGetEntrySize(
    const skheap_t     *heap)
{
    assert(NULL != heap);
    return heap->entry_size;
}


/* Remove top node from the 'heap', and copy into 'top_node' */
int
skHeapExtractTop(
    skheap_t           *heap,
    skheapnode_t        top_node)
{
    assert(NULL != heap);
    if (heap->num_entries < 1) {
        return SKHEAP_ERR_EMPTY;
    }

    /* fill 'top_node' if given */
    if (NULL != top_node) {
        HEAP_COPY_OUT(heap, 0, top_node);
    }

    --heap->num_entries;
    if (heap->num_entries) {
        /* treat position 0 as empty, and decide where to insert the
         * node that currently lives at the highest index. */
        heapSiftup(heap, 0, heap->num_entries-1,
                   HEAP_NODE(heap, heap->num_entries));
    }

    return SKHEAP_OK;
}


/* Get current number of entries */
uint32_t
skHeapGetNumberEntries(
    const skheap_t     *heap)
{
    assert(NULL != heap);
    return heap->num_entries;
}


/* Add 'new_node' to 'heap' */
int
skHeapInsert(
    skheap_t           *heap,
    const skheapnode_t  new_node)
{
    uint32_t parent;
    uint32_t child;

    assert(NULL != heap);

    if (heap->num_entries >= heap->max_entries) {
        if (heap->user_data) {
            return SKHEAP_ERR_FULL;
        }
        /* else grow the heap */
        if (heapGrow(heap)) {
            return SKHEAP_ERR_FULL;
        }
    }

    /* start at the leaf-node and work towards the root.  Compare the
     * node's parent with the new_node.  If cmpfun()>=0, insert the
     * new_node at that position, else move the node's parent to the
     * node's position and move to the node's parent. */
    for (child = heap->num_entries; child > 0; child = parent) {
        parent = (child - 1) >> 1;
        if ((*heap->cmpfun)(HEAP_NODE(heap, parent), new_node, heap->cmp_data)
            >= 0)
        {
            /* parent is larger */
            break;
        }
        HEAP_COPY_INTERNAL(heap, child, parent);
    }
    HEAP_COPY_INTO(heap, child, new_node);
    ++heap->num_entries;

    return SKHEAP_OK;
}


/* Create a new iterator to visit nodes in the heap. */
skheapiterator_t *
skHeapIteratorCreate(
    const skheap_t     *heap,
    int                 direction)
{
    skheapiterator_t *iter;

    assert(NULL != heap);

    iter = (skheapiterator_t*)calloc(1, sizeof(skheapiterator_t));
    if (NULL == iter) {
        return NULL;
    }

    iter->heap = heap;
    if (direction < 0) {
        iter->position = heap->num_entries - 1;
        iter->reverse = 1;
    }

    /* if the heap is empty, set 'no_more_entries' to true */
    if (0 == heap->num_entries) {
        iter->position = 0;
        iter->no_more_entries = 1;
    }

    return iter;
}


/* Destroy memory associate with the iterator. */
void
skHeapIteratorFree(
    skheapiterator_t   *iter)
{
    if (NULL == iter) {
        return;
    }

    free(iter);
    iter = NULL;
}


/* Move iterator to the next node. */
int
skHeapIteratorNext(
    skheapiterator_t   *iter,
    skheapnode_t       *heap_node)
{
    assert(NULL != iter);
    assert(NULL != heap_node);

    if (iter->no_more_entries) {
        return SKHEAP_NO_MORE_ENTRIES;
    }

    *heap_node = HEAP_NODE(iter->heap, iter->position);

    /* move iterator to next entry */
    if (iter->reverse) {
        if (0 == iter->position) {
            iter->no_more_entries = 1;
        } else {
            --iter->position;
        }
    } else {
        ++iter->position;
        if (iter->heap->num_entries == iter->position) {
            iter->no_more_entries = 1;
        }
    }

    return SKHEAP_OK;
}


/* Copy top of heap to 'top_node'.  Do not modify heap. */
int
skHeapPeekTop(
    const skheap_t     *heap,
    skheapnode_t       *top_node)
{
    assert(NULL != heap);
    assert(NULL != top_node);

    if (heap->num_entries < 1) {
        return SKHEAP_ERR_EMPTY;
    }

    *top_node = HEAP_NODE(heap, 0);
    return SKHEAP_OK;
}


/* Extract top element and replace with 'new_node' */
int
skHeapReplaceTop(
    skheap_t           *heap,
    const skheapnode_t  new_node,
    skheapnode_t        top_node)
{
    assert(NULL != heap);

    if (heap->num_entries < 1) {
        return SKHEAP_ERR_EMPTY;
    }

    /* fill 'top_node' if given */
    if (NULL != top_node) {
        HEAP_COPY_OUT(heap, 0, top_node);
    }

    /* treat position 0 as empty, and decide where to insert
     * new_node. */
    heapSiftup(heap, 0, heap->num_entries-1, new_node);

    return SKHEAP_OK;
}


/* Sort the nodes in the heap. */
int
skHeapSortEntries(
    skheap_t           *heap)
{
    uint32_t i;
    uint32_t j;

    assert(NULL != heap);

    if (heap->num_entries <= 1) {
        return SKHEAP_OK;
    }

    /* we can get the data array in the heap into sorted order by
     * removing the entries one at a time, but we need a place to
     * store them as we remove them.  since the heap is getting
     * smaller as the entries are removed, we store the entries at the
     * end of the heap data array.  Once all entries have been
     * "removed", we can simply reverse the heap data array.  */

    for (i = heap->num_entries - 1; i > 0; --i) {
        HEAP_COPY_OUT(heap, 0, heap->scratch);
        heapSiftup(heap, 0, i-1, HEAP_NODE(heap, i));
        HEAP_COPY_INTO(heap, i, heap->scratch);
    }

    /* reverse the nodes in data[] */
    for (i = 0, j = heap->num_entries - 1; i < j; ++i, --j) {
        HEAP_COPY_OUT(heap, i, heap->scratch);
        HEAP_COPY_INTERNAL(heap, i, j);
        HEAP_COPY_INTO(heap, j, heap->scratch);
    }

    return SKHEAP_OK;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
