/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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
**  A simple vector (grow-able array) type.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skvector.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skvector.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* vector type */
struct sk_vector_st {
    uint8_t    *list;
    size_t      element_size;
    size_t      capacity;
    size_t      count;
    size_t      max_capacity;
};


/* get address of the item at position 'pos' in the vector 'v' */
#define VA_PTR(v, pos) \
    (&((v)->list[(pos)*(v)->element_size]))

/* mem-copy the contents of 'elem' to position 'pos' in the vector 'v' */
#define VA_SET(elem, v, pos)  \
    memcpy(VA_PTR(v, pos), (elem), (v)->element_size)

/* mem-copy the contents of position 'pos' in the vector 'v' to 'elem' */
#define VA_GET(elem, v, pos)  \
    memcpy((elem), VA_PTR(v, pos), (v)->element_size)

/* if caller does not set initial capacity, use this value */
#define SKVECTOR_INIT_CAPACITY 16


/* LOCAL VARIABLES */

/* Factors by which to grow the array.  We multiply the current size
 * of the array by each of these sizes until the allocations succeeds
 * or we reach the growth factor of 0. */
static const double growth_factor[] = {
    2.0,
    1.5,
    1.25,
    1.1,
    0.0 /* sentinel */
};


/*
 *  status = skVectorAlloc(v, new_cap);
 *
 *    Grow or shink the element list in 'v' to hold 'new_cap'
 *    elements.
 */
static int
skVectorAlloc(
    sk_vector_t        *v,
    size_t              new_cap)
{
    size_t old_cap;
    uint8_t *old_list;

    assert(v);
    assert(new_cap);

    /* store current values in case the realloc fails */
    old_cap = v->capacity;
    old_list = v->list;

    if (new_cap > v->max_capacity) {
        new_cap = v->max_capacity;
    }

    /* Allocate memory to grow or shink */
    v->capacity = new_cap;
    if (old_cap == 0) {
        /* malloc new memory */
        v->list = (uint8_t*)malloc((size_t)(v->capacity * v->element_size));
    } else {
        /* realloc */
        v->list = ((uint8_t*)
                   realloc(v->list, (size_t)(v->capacity * v->element_size)));
    }

    /* handle failure */
    if (!v->list) {
        v->capacity = old_cap;
        v->list = old_list;
        return -1;
    }

    return 0;
}


/*
 *  status = skVectorGrow(v);
 *
 *    Grow the vector to hold more elements.  If the current capacity
 *    is zero, grow to SKVECTOR_INIT_CAPACITY elements; otherwise grow
 *    the current capacity using the global growth_factor array.
 */
static int
skVectorGrow(
    sk_vector_t        *v)
{
    double dbl_cap;
    size_t cap;
    int i;

    assert(v);

    /* initial allocation */
    if (v->capacity == 0) {
        return skVectorAlloc(v, SKVECTOR_INIT_CAPACITY);
    }

    /* grow the array */
    for (i = 0; growth_factor[i] > 0.0; ++i) {
        dbl_cap = growth_factor[i] * (double)v->capacity;
        if (dbl_cap > v->max_capacity) {
            cap = v->max_capacity;
        } else if (dbl_cap <= v->capacity) {
            cap = v->capacity + SKVECTOR_INIT_CAPACITY;
        } else {
            cap = (size_t)dbl_cap;
        }
        if (0 == skVectorAlloc(v, cap)) {
            return 0;
        }
    }

    return -1;
}


sk_vector_t *
skVectorNew(
    size_t              element_size)
{
    sk_vector_t *v;

    if (element_size == 0) {
        return NULL;
    }

    v = (sk_vector_t*)calloc(1, sizeof(sk_vector_t));
    if (!v) {
        return NULL;
    }
    v->element_size = element_size;
    v->max_capacity = (size_t)(0.9 * (double)SIZE_MAX / element_size);

    return v;
}


sk_vector_t *
skVectorClone(
    const sk_vector_t  *v)
{
    sk_vector_t *nv;
    int          rv;

    nv = skVectorNew(v->element_size);
    if (nv == NULL) {
        return NULL;
    }

    rv = skVectorAlloc(nv, v->count);
    if (0 != rv) {
        skVectorDestroy(nv);
        return NULL;
    }

    memcpy(nv->list, v->list, (v->count * v->element_size));
    nv->count = v->count;

    return(nv);
}


sk_vector_t *
skVectorNewFromArray(
    size_t              element_size,
    const void         *array,
    size_t              count)
{
    sk_vector_t *v;

    /* create the new vector */
    v = skVectorNew(element_size);
    if (v == NULL) {
        return NULL;
    }

    /* make certain we have data with which to fill it */
    if (array == NULL || count == 0) {
        return v;
    }

    if (0 != skVectorAlloc(v, count)) {
        skVectorDestroy(v);
        return NULL;
    }

    v->count = count;
    memcpy(v->list, array, (v->count * v->element_size));
    return v;
}


void
skVectorDestroy(
    sk_vector_t        *v)
{
    if (v) {
        if (v->list) {
            free(v->list);
            v->list = NULL;
        }
        v->capacity = 0;
        v->count = 0;
        free(v);
    }
}


int
skVectorSetCapacity(
    sk_vector_t        *v,
    size_t              capacity)
{
    assert(v);

    /* Nothing to do when desired capacity is our capacity */
    if (capacity == v->capacity) {
        return 0;
    }

    /* free the data if capacity is 0 */
    if (capacity == 0) {
        free(v->list);
        v->list = NULL;
        v->capacity = 0;
        v->count = 0;
        return 0;
    }

    /* must realloc or malloc */
    if (skVectorAlloc(v, capacity)) {
        return -1;
    }
    if (v->count > v->capacity) {
        v->count = v->capacity;
    }
    return 0;
}


void
skVectorClear(
    sk_vector_t        *v)
{
    if (v) {
        v->count = 0;
    }
}


size_t
skVectorGetElementSize(
    const sk_vector_t  *v)
{
    assert(v);
    return v->element_size;
}


size_t
skVectorGetCapacity(
    const sk_vector_t  *v)
{
    assert(v);
    return v->capacity;
}


size_t
skVectorGetCount(
    const sk_vector_t  *v)
{
    assert(v);
    return v->count;
}


int
skVectorAppendValue(
    sk_vector_t        *v,
    const void         *value)
{
    assert(v);

    if (v->capacity == v->count) {
        if (skVectorGrow(v) != 0) {
            return -1;
        }
    }
    VA_SET(value, v, v->count);
    ++v->count;
    return 0;
}


int
skVectorAppendVector(
    sk_vector_t        *dst,
    const sk_vector_t  *src)
{
    size_t total;

    assert(dst);
    assert(src);
    assert(dst->element_size == src->element_size);

    /* is there space in 'dst' for all the elements from 'src'? */
    if ((dst->max_capacity - dst->count) < src->count) {
        return -1;
    }
    total = dst->count + src->count;

    if (dst->capacity < total) {
        if (0 != skVectorAlloc(dst, total)) {
            return -1;
        }
    }
    memcpy(VA_PTR(dst, dst->count), src->list, src->element_size * src->count);
    dst->count += src->count;

    return 0;
}

int
skVectorAppendFromArray(
    sk_vector_t        *v,
    const void         *array,
    size_t              count)
{
    size_t total;

    assert(v);
    assert(array);

    /* is there space in 'v' for 'count' elements? */
    if ((v->max_capacity - v->count) < count) {
        return -1;
    }
    total = v->count + count;

    if (v->capacity < total) {
        if (0 != skVectorAlloc(v, total)) {
            return -1;
        }
    }
    memcpy(VA_PTR(v, v->count), array, v->element_size * count);
    v->count += count;

    return 0;
}


int
skVectorGetValue(
    void               *out_element,
    const sk_vector_t  *v,
    size_t              position)
{
    assert(v);
    if (position >= v->count) {
        return -1;
    }
    VA_GET(out_element, v, position);
    return 0;
}


void *
skVectorGetValuePointer(
    const sk_vector_t  *v,
    size_t              position)
{
    assert(v);
    if (position >= v->count) {
        return NULL;
    }
    return (void*)VA_PTR(v, position);
}


int
skVectorSetValue(
    sk_vector_t        *v,
    size_t              position,
    const void         *value)
{
    assert(v);
    if (position >= v->capacity) {
        return -1;
    }

    if (position >= v->count) {
        /* clear memory from current count to new position */
        memset(VA_PTR(v, v->count), 0,
               ((size_t)(position - v->count) * v->element_size));
        v->count = position+1;
    }
    VA_SET(value, v, position);

    return 0;
}


int
skVectorInsertValue(
    sk_vector_t        *v,
    size_t              position,
    const void         *value)
{
    assert(v);

    if (position >= v->count) {
        return skVectorSetValue(v, position, value);
    }
    if (v->capacity == v->count) {
        if (skVectorGrow(v) != 0) {
            return -1;
        }
    }
    memmove(VA_PTR(v, position + 1), VA_PTR(v, position),
            v->element_size * (v->count - position));
    VA_SET(value, v, position);
    ++v->count;
    return 0;
}


int
skVectorRemoveValue(
    sk_vector_t        *v,
    size_t              position,
    void               *out_element)
{
    assert(v);
    if (position >= v->count) {
        return -1;
    }
    if (out_element) {
        VA_GET(out_element, v, position);
    }
    --v->count;
    if (position != v->count) {
        memmove(VA_PTR(v, position), VA_PTR(v, position + 1),
                v->element_size * (v->count - position));
    }
    return 0;
}


#if 0
/* DO NOT PROVIDE THIS SINCE CURRENTLY WE DO NOT NEED IT */

/**
 *    Copies the data from 'new_value' to vector 'v' at 'position'
 *    similar to skVectorSetValue() except it first copies the value
 *    being replaced to the location referenced by 'replaced_element'
 *    when 'replaced_element' is not NULL and 'position' is less than
 *    skVectorGetCount().  The value at 'replaced_element' is left
 *    unchanged when 'position' is not less than skVectorGetCount().
 *
 *    Returns 0 on success.  Returns -1 if 'position' is not less than
 *    skVectorGetCapacity(v).
 *
 *    Since SiLK x.y.z.
 */
int
skVectorReplaceValue(
    sk_vector_t        *v,
    size_t              position,
    const void         *new_value,
    void               *replaced_element);

int
skVectorReplaceValue(
    sk_vector_t        *v,
    size_t              position,
    const void         *new_value,
    void               *out_element)
{
    if (out_element && position < v->count) {
        VA_GET(out_element, v, position);
    }
    return skVectorSetValue(v, position, new_value);
}
#endif  /* 0 */


size_t
skVectorGetMultipleValues(
    void               *out_array,
    const sk_vector_t  *v,
    size_t              start_position,
    size_t              num_elements)
{
    uint8_t *p;

    assert(v);
    assert(out_array);

    if (start_position >= v->count) {
        return 0;
    }
    if ((v->count - start_position) < num_elements) {
        num_elements = (v->count - start_position);
    }
    p = VA_PTR(v, start_position);
    memcpy(out_array, p, (num_elements * v->element_size));
    return num_elements;
}


void
skVectorToArray(
    void               *out_array,
    const sk_vector_t  *v)
{
    assert(v);
    assert(out_array);

    if (v->count) {
        memcpy(out_array, v->list, (v->count * v->element_size));
   }
}


void *
skVectorToArrayAlloc(
    const sk_vector_t  *v)
{
    void *array;

    assert(v);

    if (0 == v->count) {
        return NULL;
    }

    array = malloc(v->count * v->element_size);
    if (NULL == array) {
        return NULL;
    }
    memcpy(array, v->list, (v->count * v->element_size));
    return array;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
