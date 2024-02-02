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
#ifndef _SKHEAP_RWREC_H
#define _SKHEAP_RWREC_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKHEAP_RWREC_H, "$SiLK: skheap-rwrec.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  skheap-rwrec.h
**
**  A heap (priority queue) for rwRec pointers
**
**
*/

#include <silk/rwrec.h>

/* The Heap object */
typedef struct skrwrecheap_st skrwrecheap_t;

/* Returns a new heap with space for initial_entries.  Returns NULL on
 * memory allocation faulure. */
skrwrecheap_t *
skRwrecHeapCreate(
    size_t              initial_entries);

/* Destroy the heap (does not destroy the rwRecs in the heap */
void
skRwrecHeapDestroy(
    skrwrecheap_t      *heap);

/* Adds an rwRec to the heap.  Returns 0 on success, -1 on memory
 * allocation failure. */
int
skRwrecHeapInsert(
    skrwrecheap_t      *heap,
    rwRec              *rec);

/* Returns a pointer to the top entry on the heap, NULL if the heap is
 * empty */
const rwRec *
skRwrecHeapPeek(
    skrwrecheap_t      *heap);

/* Removes the top entry on the heap, returns that item.  Returns NULL
 * if the heap is empty.  */
rwRec *
skRwrecHeapPop(
    skrwrecheap_t      *heap);

/* Return the number of entries in the heap. */
size_t
skRwrecHeapCountEntries(
    const skrwrecheap_t    *heap);

/* Return the capacity of the heap */
size_t
skRwrecHeapGetCapacity(
    const skrwrecheap_t    *heap);

#ifdef __cplusplus
}
#endif
#endif /* _SKHEAP_RWREC_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
