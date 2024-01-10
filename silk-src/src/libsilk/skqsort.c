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
**   qsort()
**
**   A la Bentley and McIlroy in Software - Practice and Experience,
**   Vol. 23 (11) 1249-1265. Nov. 1993
**
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skqsort.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>


typedef long WORD;
#define W               sizeof(WORD)    /* must be a power of 2 */

/* The kind of swapping is given by a variable, swaptype, with value 0
 * for single-word swaps, 1 for general swapping by words, and 2 for
 * swapping by bytes.  */
#define SWAPINIT(a, es)                                                 \
    swaptype = ((((char*)a-(char*)0) | es) % W) ? 2 : (es > W) ? 1 : 0

#define exch(a, b, t)   (t = a, a = b, b = t)

/* choose between function call and in-line exchange */
#define swap(a, b)                                      \
    ((swaptype != 0)                                    \
     ? swapfunc((char*)(a), (char*)(b), es, swaptype)   \
     : (void)exch(*(WORD*)(a), *(WORD*)(b), t))

/* swap sequences of records */
#define vecswap(a, b, n)                                        \
    if (n > 0) swapfunc((char*)(a), (char*)(b), n, swaptype)

#define min(a, b)       a <= b ? a : b

/* return median value of 'a', 'b', and 'c'. */
static char *
med3(
    char               *a,
    char               *b,
    char               *c,
    int               (*cmp)(const void *, const void *, void *),
    void               *thunk)
{
    return ((cmp(a, b, thunk) < 0)
            ? ((cmp(b, c, thunk) < 0) ? b : ((cmp(a, c, thunk) < 0) ? c : a))
            : ((cmp(b, c, thunk) > 0) ? b : ((cmp(a, c, thunk) > 0) ? c : a)));
}


static void
swapfunc(
    char               *a,
    char               *b,
    size_t              n,
    int                 swaptype)
{
    if (swaptype <= 1) {
        WORD t;
        for ( ; n > 0; a += W, b += W, n -= W) {
            exch(*(WORD*)a, *(WORD*)b, t);
        }
    } else {
        char t;
        for ( ; n > 0; a += 1, b += 1, n -= 1) {
            exch(*a, *b, t);
        }
    }
}


void
skQSort_r(
    void               *a,
    size_t              n,
    size_t              es,
    int               (*cmp)(const void *, const void *, void *),
    void               *thunk)
{
    char *pa, *pb, *pc, *pd, *pl, *pm, *pn;
    int r, swaptype;
    WORD t;
    size_t s;

  loop:
    SWAPINIT(a, es);
    if (n < 7) {
        /* use insertion sort on smallest arrays */
        for (pm = (char*)a + es; pm < (char*)a + n*es; pm += es)
            for (pl = pm; pl > (char*)a && cmp(pl-es, pl, thunk) > 0; pl -= es)
                swap(pl, pl-es);
        return;
    }

    /* determine the pivot, pm */
    pm = (char*)a + (n/2)*es;           /* small arrays middle element */
    if (n > 7) {
        pl = (char*)a;
        pn = (char*)a + (n - 1)*es;
        if (n > 40) {
            /* big arays.  Pseudomedian of 9 */
            s = (n / 8) * es;
            pl = med3(pl, pl + s, pl + 2 * s, cmp, thunk);
            pm = med3(pm - s, pm, pm + s, cmp, thunk);
            pn = med3(pn - 2 * s, pn - s, pn, cmp, thunk);
        }
        pm = med3(pl, pm, pn, cmp, thunk);      /* mid-size, med of 3 */
    }
    /* put pivot into position 0 */
    swap(a, pm);

    pa = pb = (char*)a + es;
    pc = pd = (char*)a + (n - 1) * es;
    for (;;) {
        while (pb <= pc && (r = cmp(pb, a, thunk)) <= 0) {
            if (r == 0) {
                swap(pa, pb);
                pa += es;
            }
            pb += es;
        }
        while (pc >= pb && (r = cmp(pc, a, thunk)) >= 0) {
            if (r == 0) {
                swap(pc, pd);
                pd -= es;
            }
            pc -= es;
        }
        if (pb > pc) {
            break;
        }
        swap(pb, pc);
        pb += es;
        pc -= es;
    }

    pn = (char*)a + n * es;
    s = min(pa - (char*)a, pb - pa);
    vecswap(a, pb - s, s);
    s = min((size_t)(pd - pc), pn - pd - es);
    vecswap(pb, pn - s, s);
    if ((s = pb - pa) > es) {
        skQSort_r(a, s/es, es, cmp, thunk);
    }
    if ((s = pd - pc) > es) {
        /* iterate rather than recurse */
        /* skQSort(pn - s, s/es, es, cmp, thunk); */
        a = pn - s;
        n = s / es;
        goto loop;
    }
}


void
skQSort(
    void               *a,
    size_t              n,
    size_t              es,
    int               (*cmp)(const void *, const void *))
{
    skQSort_r(a, n, es,(int (*)(const void *, const void *, void *))cmp, NULL);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
