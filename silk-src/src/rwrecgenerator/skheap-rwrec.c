/*
** Copyright (C) 2011-2023 by Carnegie Mellon University.
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
**  A heap (priority queue) for rwRec pointers
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skheap-rwrec.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "skheap-rwrec.h"

/* LOCAL DEFINES AND TYPEDEFS */

/* Means of getting the correct sktime_t from the record. */
#define GET_TIME(rec) rwRecGetEndTime(rec)

/* How much larger (multiplicative) to attempt to realloc heap upon
   heap growth.  (Must be positive.) */
#define RESIZE_FACTOR 1.0       /* Double the size on growth */

struct skrwrecheap_st {
    rwRec  **data;
    size_t   max_entries;
    size_t   num_entries;
};


/* FUNCTION DEFINITIONS */

skrwrecheap_t *
skRwrecHeapCreate(
    size_t              initial_entries)
{
    skrwrecheap_t *heap;

    heap = (skrwrecheap_t*)calloc(1, sizeof(skrwrecheap_t));
    if (heap == NULL) {
        return NULL;
    }

    if (initial_entries == 0) {
        initial_entries = 1;
    }
    heap->data = (rwRec**)malloc(initial_entries * sizeof(rwRec *));
    if (heap->data == NULL) {
        free(heap);
        return NULL;
    }
    heap->max_entries = initial_entries;

    return heap;
}


void
skRwrecHeapDestroy(
    skrwrecheap_t      *heap)
{
    free(heap->data);
    free(heap);
}

static int
skRwrecHeapResize(
    skrwrecheap_t      *heap,
    size_t              num_entries)
{
    rwRec **new_data;

    assert(heap);

    new_data = (rwRec**)realloc(heap->data, sizeof(rwRec *) * num_entries);
    if (new_data == NULL) {
        return -1;
    }
    heap->data = new_data;
    heap->max_entries = num_entries;
    if (num_entries < heap->num_entries) {
        heap->num_entries = num_entries;
    }

    return 0;
}


/* Grow the heap.  Return the change in size of the heap. */
static size_t
skRwrecHeapGrow(
    skrwrecheap_t      *heap)
{
    size_t target_size;
    size_t target_growth;
    double factor = RESIZE_FACTOR;
    int rv = 0;

    assert(heap);

    /* Determine new target size, adjust for possible overflow */
    target_size = (size_t)((double)heap->max_entries * (1.0 + factor));
    while (target_size < heap->max_entries) {
        factor /= 2.0;
        target_size = (size_t)((double)heap->max_entries * (1.0 + factor));
    }

    /* Resize the heap to target_size, adjust target_size if resize
       fails */
    while (target_size > heap->max_entries) {
        target_growth = target_size - heap->max_entries;
        rv = skRwrecHeapResize(heap, target_size);
        if (rv == 0) {
            return target_growth;
        }
        factor /= 2.0;
        target_size = (size_t)((double)heap->max_entries * (1.0 + factor));
    }

    return 0;
}


int
skRwrecHeapInsert(
    skrwrecheap_t      *heap,
    rwRec              *rec)
{
    size_t parent;
    size_t child;
    sktime_t rec_time;
    rwRec **data;

    assert(heap);
    assert(rec);

    /* If the heap is full, resize */
    if (heap->num_entries == heap->max_entries
        && !skRwrecHeapGrow(heap))
    {
        return -1;
    }

    rec_time = GET_TIME(rec);
    data = heap->data;
    for (child = heap->num_entries; child > 0; child = parent) {
        parent = (child - 1) >> 1;
        if (GET_TIME(data[parent]) <= rec_time) {
            break;
        }
        data[child] = data[parent];
    }
    data[child] = rec;
    ++heap->num_entries;

    return 0;
}


const rwRec *
skRwrecHeapPeek(
    skrwrecheap_t      *heap)
{
    assert(heap);

    if (heap->num_entries) {
        return heap->data[0];
    }
    return NULL;
}


rwRec *
skRwrecHeapPop(
    skrwrecheap_t      *heap)
{
    size_t parent;
    size_t child;
    sktime_t rec_time, c1, c2;
    rwRec *retval;
    rwRec **data;

    assert(heap);

    if (heap->num_entries < 1) {
        return NULL;
    }
    retval = heap->data[0];

    --heap->num_entries;
    if (heap->num_entries) {
        data = heap->data;
        rec_time = GET_TIME(data[heap->num_entries]);
        parent = 0;             /* The empty slot */
        child = 1;              /* Children of empty slot */
        while (child < heap->num_entries) {
            /* Expanded the possibilities out for speed.  We minimize
               the number of times we have to call GET_TIME. */
            if (child + 1 == heap->num_entries) {
                /* Only one child */
                if (GET_TIME(data[child]) < rec_time) {
                    data[parent] = data[child];
                    parent = child;
                } else {
                    break;
                }
            } else {
                /* Two children */
                c1 = GET_TIME(data[child]);
                c2 = GET_TIME(data[child + 1]);
                if ((c1 <= c2)) {
                    /* Child 1 is smaller than (or equal to) child 2 */
                    if (c1 < rec_time) {
                        data[parent] = data[child];
                        parent = child;
                    } else {
                        break;
                    }
                } else if (c2 < rec_time) {
                    /* Child 2 is smaller than child 1 */
                    data[parent] = data[child + 1];
                    parent = child + 1;
                } else {
                    break;
                }
            }
            child = (parent << 1) + 1;
        }

        data[parent] = data[heap->num_entries];
    }

    return retval;
}


size_t
skRwrecHeapCountEntries(
    const skrwrecheap_t    *heap)
{
    assert(heap);
    return heap->num_entries;
}

size_t
skRwrecHeapGetCapacity(
    const skrwrecheap_t    *heap)
{
    assert(heap);
    return heap->max_entries;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
