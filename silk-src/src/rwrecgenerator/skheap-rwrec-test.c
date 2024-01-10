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
**  skheap-rwrec-test.c
**
**     Test the skheap-rwrec code.
**
**  Michael Duggan
**  May 2011
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skheap-rwrec-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skstream.h>
#include <silk/utils.h>
#include "skheap-rwrec.h"

int main(int UNUSED(argc), char **argv)
{
#define DATA_SIZE 30
    skrwrecheap_t *heap;
    int data[DATA_SIZE] = {
        201, 34, 202, 56, 203,  2,
        204, 65, 205,  3, 206,  5,
        207,  8, 208, 74, 209, 32,
        210, 78, 211, 79, 212, 80,
        213,  5, 214,  5, 215,  1};
    rwRec recs[DATA_SIZE];
    const rwRec *last, *cur;
    int rv;
    int i;

    /* register the application */
    skAppRegister(argv[0]);

    memset(recs, 0, sizeof(recs));
    for (i = 0; i < DATA_SIZE; i++) {
        rwRecSetElapsed(&recs[i], data[i]);
        rwRecSetProto(&recs[i], data[i]);
    }

    heap = skRwrecHeapCreate(1);
    if (heap == NULL) {
        skAppPrintErr("Failed to create heap");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < DATA_SIZE; i++) {
        rv = skRwrecHeapInsert(heap, &recs[i]);
        if (rv != 0) {
            skAppPrintErr("Failed to insert element");
            exit(EXIT_FAILURE);
        }
    }

    last = skRwrecHeapPeek(heap);
    if (last == NULL) {
        skAppPrintErr("Heap unexpectedly empty");
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < DATA_SIZE; i++) {
        cur = skRwrecHeapPop(heap);
        if (cur == NULL) {
            skAppPrintErr("Heap unexpectedly empty");
            exit(EXIT_FAILURE);
        }
        if (i != 0 && cur == last) {
            skAppPrintErr("Unexpected duplicate");
            exit(EXIT_FAILURE);
        }
        if (rwRecGetProto(cur) < rwRecGetProto(last)) {
            skAppPrintErr("Incorrect ordering");
            exit(EXIT_FAILURE);
        }
        printf("%" PRIu32 "\n", rwRecGetProto(cur));
        last = cur;
    }
    if (skRwrecHeapPeek(heap) != NULL) {
        skAppPrintErr("Heap unexpectedly non-empty");
        exit(EXIT_FAILURE);
    }
    if (skRwrecHeapPop(heap) != NULL) {
        skAppPrintErr("Heap unexpectedly non-empty");
        exit(EXIT_FAILURE);
    }

    printf("Success!\n");

    return EXIT_SUCCESS;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
