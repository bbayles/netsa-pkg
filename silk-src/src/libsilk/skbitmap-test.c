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
**  Test functions for skbitmap.c
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skbitmap-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skipaddr.h>
#include <silk/utils.h>


#define TEST(s)    fprintf(stderr, s "...");
#define RESULT(b)                                               \
    if ((b)) {                                                  \
        fprintf(stderr, "ok\n");                                \
    } else {                                                    \
        fprintf(stderr,                                         \
                ("failed at %s:%d "                             \
                 "(rv=%d, i=%u, j=%u, sz=%u p=%u q=%u)\n"),     \
                __FILE__, __LINE__, rv, i, j, sz, p, q);        \
        exit(EXIT_FAILURE);                                     \
    }

#define CHECK_MAP(bmap, pos, val)                       \
    for (sz = 0; sz < (BITMAP_SIZE >> 5); ++sz) {       \
        if (sz == (pos >> 5)) {                         \
            if (bmap->map[sz] != (val)) {               \
                RESULT(0);                              \
            }                                           \
        } else if (bmap->map[sz] != 0) {                \
            RESULT(0);                                  \
        }                                               \
    }


static void
bitmap_test(
    void)
{
#define BITMAP_SIZE   160
    sk_bitmap_t *bmap;
    sk_bitmap_t *bmap2;
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t p = 0;
    uint32_t q = 0;
    int rv;
    uint32_t sz;
    sk_bitmap_t bitmap;
    sk_bitmap_iter_t iter;
    uint32_t bitarray[8];
    uint32_t vals[] = {
        32, 63, 65, 96,
        98, 99, 100, 102,
        105, 106, 120, 121,
        126, 127, 128, 159
    };

    TEST("skBitmapCreate");
    rv = skBitmapCreate(&bmap, BITMAP_SIZE);
    CHECK_MAP(bmap, (BITMAP_SIZE * 2), 0);
    RESULT(rv == 0 && bmap != NULL);

    TEST("skBitmapGetSize");
    sz = skBitmapGetSize(bmap);
    RESULT(sz == BITMAP_SIZE);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 0);

    i = 96;

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, i);
    RESULT(rv == 0);

    TEST("skBitmapSetBit");
    skBitmapSetBit(bmap, i);
    CHECK_MAP(bmap, i, 1);
    RESULT(1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, i);
    RESULT(rv == 1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    j = 127;

    TEST("skBitmapCreate");
    rv = skBitmapCreate(&bmap2, BITMAP_SIZE);
    CHECK_MAP(bmap2, (BITMAP_SIZE * 2), 0);
    RESULT(rv == 0 && bmap2 != NULL);

    TEST("skBitmapGetSize");
    sz = skBitmapGetSize(bmap2);
    RESULT(sz == BITMAP_SIZE);

    TEST("skBitmapSetBit");
    skBitmapSetBit(bmap2, j);
    CHECK_MAP(bmap2, j, 1u << 31);
    RESULT(1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap2, j);
    RESULT(rv == 1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap2);
    RESULT(sz == 1);

    TEST("skBitmapUnion");
    rv = skBitmapUnion(bmap2, bmap);
    CHECK_MAP(bmap2, j, ((1u << 31) | 1u));
    RESULT(rv == 0);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap2);
    RESULT(sz == 2);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap2, i);
    RESULT(rv == 1);

    TEST("skBitmapIntersection");
    rv = skBitmapIntersection(bmap2, bmap);
    CHECK_MAP(bmap2, j, 1);
    RESULT(rv == 0);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap2);
    RESULT(sz == 1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap2, i);
    RESULT(rv == 1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap2, j);
    RESULT(rv == 0);

    TEST("skBitmapComplement");
    skBitmapComplement(bmap2);
    for (sz = 0; sz < (BITMAP_SIZE >> 5); ++sz) {
        if (sz == (i >> 5)) {
            if (bmap2->map[sz] != ~(1u << (i & 0x1F))) {
                RESULT(0);
            }
        } else if (bmap2->map[sz] != 0xFFFFFFFF) {
            RESULT(0);
        }
    }
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap2);
    RESULT(sz == (BITMAP_SIZE - 1));

    TEST("skBitmapDestroy");
    skBitmapDestroy(&bmap2);
    RESULT(bmap2 == NULL);

    j = 97;

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, j);
    RESULT(rv == 0);

    TEST("skBitmapClearBit");
    skBitmapClearBit(bmap, j);
    CHECK_MAP(bmap, i, 1);
    RESULT(1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, j);
    RESULT(rv == 0);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, i);
    RESULT(rv == 1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapSetBit");
    skBitmapSetBit(bmap, j);
    CHECK_MAP(bmap, i, 0x3);
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 2);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, j);
    RESULT(rv == 1);

    TEST("skBitmapClearBit");
    skBitmapClearBit(bmap, i);
    CHECK_MAP(bmap, i, 0x2);
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapClearAllBits");
    skBitmapClearAllBits(bmap);
    CHECK_MAP(bmap, (BITMAP_SIZE * 2), 0);
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 0);

    TEST("skBitmapCountConsecutive");
    for (p = 0, q = BITMAP_SIZE; p < BITMAP_SIZE; p += 32, q -= 32) {
        sz = skBitmapCountConsecutive(bmap, p, 0);
        if (sz != q) {
            RESULT(sz == q);
        }
    }
    RESULT(1);

    TEST("skBitmapGetSize");
    sz = skBitmapGetSize(bmap);
    RESULT(sz == BITMAP_SIZE);

    i = 95;

    TEST("skBitmapSetBit");
    skBitmapSetBit(bmap, i);
    CHECK_MAP(bmap, i, (1u << 31));
    RESULT(1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, i);
    RESULT(rv == 1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, j);
    RESULT(rv == 0);

    TEST("skBitmapClearBit");
    skBitmapClearBit(bmap, j);
    CHECK_MAP(bmap, i, (1u << 31));
    RESULT(1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, j);
    RESULT(rv == 0);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, i);
    RESULT(rv == 1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapClearBit");
    skBitmapClearBit(bmap, i);
    CHECK_MAP(bmap, (BITMAP_SIZE * 2), 0);
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 0);

    i = 0;

    TEST("skBitmapSetBit");
    skBitmapSetBit(bmap, i);
    CHECK_MAP(bmap, i, 1);
    RESULT(1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, i);
    RESULT(rv == 1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, j);
    RESULT(rv == 0);

    TEST("skBitmapClearBit");
    skBitmapClearBit(bmap, j);
    CHECK_MAP(bmap, i, 1);
    RESULT(1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, j);
    RESULT(rv == 0);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, i);
    RESULT(rv == 1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapClearBit");
    skBitmapClearBit(bmap, i);
    CHECK_MAP(bmap, (BITMAP_SIZE * 2), 0);
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 0);

    i = BITMAP_SIZE - 1;

    TEST("skBitmapSetBit");
    skBitmapSetBit(bmap, i);
    CHECK_MAP(bmap, i, (1u << (i & 0x1f)));
    RESULT(1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, i);
    RESULT(rv == 1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, j);
    RESULT(rv == 0);

    TEST("skBitmapClearBit");
    skBitmapClearBit(bmap, j);
    CHECK_MAP(bmap, i, (1u << (i & 0x1f)));
    RESULT(1);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, j);
    RESULT(rv == 0);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, i);
    RESULT(rv == 1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapClearBit");
    skBitmapClearBit(bmap, i);
    CHECK_MAP(bmap, (BITMAP_SIZE * 2), 0);
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 0);

    TEST("skBitmapDestroy");
    skBitmapDestroy(&bmap);
    RESULT(bmap == NULL);

    TEST("skBitmapDestroy");
    skBitmapDestroy(&bmap);
    RESULT(bmap == NULL);

    bmap = NULL;
    TEST("skBitmapCreate");
    rv = skBitmapCreate(&bmap, BITMAP_SIZE);
    RESULT(rv == 0 && bmap != NULL);

    TEST("skBitmapSetAllBits");
    skBitmapSetAllBits(bmap);
    for (sz = 0; sz < (BITMAP_SIZE >> 5); ++sz) {
        if (bmap->map[sz] != UINT32_MAX) {
            RESULT(0);
        }
    }
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == BITMAP_SIZE);

    TEST("skBitmapRangeCountHigh");
    for (p = BITMAP_SIZE - 34, q = 34; p < BITMAP_SIZE; ++p, --q) {
        sz = skBitmapRangeCountHigh(bmap, p, BITMAP_SIZE - 1);
        if (q != sz) {
            RESULT(q == sz);
        }
    }
    RESULT(1);

    TEST("skBitmapRangeCountHigh");
    q = 5;
    for (p = 62; p < 96; ++p) {
        sz = skBitmapRangeCountHigh(bmap, p, p + q - 1);
        if (sz != q) {
            RESULT(q == sz);
        }
    }
    RESULT(1);

    TEST("skBitmapRangeCountHigh");
    q = 33;
    for (p = 62; p < 96; ++p) {
        sz = skBitmapRangeCountHigh(bmap, p, p + q - 1);
        if (sz != q) {
            RESULT(q == sz);
        }
    }
    RESULT(1);

    TEST("skBitmapClearAllBits");
    skBitmapClearAllBits(bmap);
    CHECK_MAP(bmap, (BITMAP_SIZE * 2), 0);
    RESULT(1);

    p = 0;
    q = BITMAP_SIZE - 1;

    TEST("skBitmapRangeSet");
    skBitmapRangeSet(bmap, q, q);
    CHECK_MAP(bmap, q, 1u << (q & 0x1f));
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapRangeSet");
    skBitmapRangeSet(bmap, p, p);
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 2);

    TEST("skBitmapCountConsecutive");
    sz = skBitmapCountConsecutive(bmap, p, 1);
    if (sz != 1) {
        RESULT(0);
    }
    sz = skBitmapCountConsecutive(bmap, q, 1);
    if (sz != 1) {
        RESULT(0);
    }
    sz = skBitmapCountConsecutive(bmap, p, 0);
    if (sz != 0) {
        RESULT(0);
    }
    sz = skBitmapCountConsecutive(bmap, q, 0);
    if (sz != 0) {
        RESULT(0);
    }
    sz = skBitmapCountConsecutive(bmap, p+1, 0);
    if (sz != q - p - 1) {
        RESULT(0);
    }
    RESULT(1);

    TEST("skBitmapRangeClear");
    skBitmapRangeClear(bmap, q, q);
    CHECK_MAP(bmap, p, 1u << (p & 0x1f));
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapRangeClear");
    skBitmapRangeClear(bmap, p, p);
    CHECK_MAP(bmap, BITMAP_SIZE * 2, 0);
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 0);

    TEST("skBitmapRangeSet");
    j = 62;
    skBitmapRangeSet(bmap, j, j+1);
    CHECK_MAP(bmap, j, (3u << (j & 0x1f)));
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 2);

    TEST("skBitmapCountConsecutive");
    sz = skBitmapCountConsecutive(bmap, j, 1);
    RESULT(sz == 2);

    TEST("skBitmapRangeSet");
    j = 61;
    skBitmapRangeSet(bmap, j, j+3);
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 4);

    TEST("skBitmapCountConsecutive");
    sz = skBitmapCountConsecutive(bmap, j, 1);
    RESULT(sz == 4);

    TEST("skBitmapRangeSet");
    j = 64;
    skBitmapRangeSet(bmap, j, j+1);
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 5);

    TEST("skBitmapCountConsecutive");
    sz = skBitmapCountConsecutive(bmap, j, 2);
    RESULT(sz == 2);

    TEST("skBitmapCountConsecutive");
    sz = skBitmapCountConsecutive(bmap, 61, 1);
    RESULT(sz == 5);

    TEST("skBitmapRangeClear");
    j = 62;
    skBitmapRangeClear(bmap, j, j+1);
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 3);

    TEST("skBitmapRangeClear");
    j = 61;
    skBitmapRangeClear(bmap, j, j+3);
    CHECK_MAP(bmap, (j + 4), (1u << ((j + 4) & 0x1f)));
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapRangeClear");
    j = 64;
    skBitmapRangeClear(bmap, j, j+1);
    CHECK_MAP(bmap, (BITMAP_SIZE * 2), 0);
    RESULT(1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 0);

    TEST("skBitmapDestroy");
    skBitmapDestroy(&bmap);
    RESULT(bmap == NULL);

    bmap = NULL;
    TEST("skBitmapCreate");
    rv = skBitmapCreate(&bmap, 0);
    RESULT(rv == -1 && bmap == NULL);

    TEST("skBitmapCreate");
    rv = skBitmapCreate(&bmap, BITMAP_SIZE);
    CHECK_MAP(bmap, (BITMAP_SIZE * 2), 0);
    RESULT(rv == 0 && bmap != NULL);

    TEST("skBitmapGetSize");
    sz = skBitmapGetSize(bmap);
    RESULT(sz == BITMAP_SIZE);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 0);

    for (i = 0; i < sizeof(vals)/sizeof(uint32_t); ++i) {
        TEST("skBitmapSetBit");
        skBitmapSetBit(bmap, vals[i]);
        RESULT(1 == skBitmapGetBit(bmap, vals[i]));
    }

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == sizeof(vals)/sizeof(uint32_t));

    TEST("skBitmapIteratorBind");
    skBitmapIteratorBind(bmap, &iter);
    RESULT(1);

    for (i = 0; i < sizeof(vals)/sizeof(uint32_t); ++i) {
        j = 0xFFFF;
        TEST("skBitmapIteratorNext");
        rv = skBitmapIteratorNext(&iter, &j);
        RESULT(rv == SK_ITERATOR_OK && j == vals[i]);
    }

    j = 0xFFFF;
    TEST("skBitmapIteratorNext");
    rv = skBitmapIteratorNext(&iter, &j);
    RESULT(rv == SK_ITERATOR_NO_MORE_ENTRIES && j == 0xFFFF);

    TEST("skBitmapIteratorReset");
    skBitmapIteratorReset(&iter);
    RESULT(1);

    TEST("skBitmapClearAllBits");
    skBitmapClearAllBits(bmap);
    CHECK_MAP(bmap, (BITMAP_SIZE * 2), 0);
    RESULT(1);

    j = 0xFFFF;
    TEST("skBitmapIteratorNext");
    rv = skBitmapIteratorNext(&iter, &j);
    RESULT(rv == SK_ITERATOR_NO_MORE_ENTRIES && j == 0xFFFF);

    TEST("skBitmapIteratorReset");
    skBitmapIteratorReset(&iter);
    RESULT(1);

    i = 0;
    TEST("skBitmapSetBit");
    skBitmapSetBit(bmap, i);
    RESULT(1 == skBitmapGetBit(bmap, i));

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    j = 0xFFFF;
    TEST("skBitmapIteratorNext");
    rv = skBitmapIteratorNext(&iter, &j);
    RESULT(rv == SK_ITERATOR_OK && j == i);

    j = 0xFFFF;
    TEST("skBitmapIteratorNext");
    rv = skBitmapIteratorNext(&iter, &j);
    RESULT(rv == SK_ITERATOR_NO_MORE_ENTRIES && j == 0xFFFF);

    TEST("skBitmapIteratorReset");
    skBitmapIteratorReset(&iter);
    RESULT(1);

    TEST("skBitmapClearAllBits");
    skBitmapClearAllBits(bmap);
    CHECK_MAP(bmap, (BITMAP_SIZE * 2), 0);
    RESULT(1);

    i = BITMAP_SIZE - 1;
    TEST("skBitmapSetBit");
    skBitmapSetBit(bmap, i);
    RESULT(1 == skBitmapGetBit(bmap, i));

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    j = 0xFFFF;
    TEST("skBitmapIteratorNext");
    rv = skBitmapIteratorNext(&iter, &j);
    RESULT(rv == SK_ITERATOR_OK && j == i);

    j = 0xFFFF;
    TEST("skBitmapIteratorNext");
    rv = skBitmapIteratorNext(&iter, &j);
    RESULT(rv == SK_ITERATOR_NO_MORE_ENTRIES && j == 0xFFFF);

    TEST("skBitmapIteratorReset");
    skBitmapIteratorReset(&iter);
    RESULT(1);

    TEST("skBitmapDestroy");
    skBitmapDestroy(&bmap);
    RESULT(bmap == NULL);


    /* ==== */
    bmap = &bitmap;

    TEST("skBitmapBind");
    rv = skBitmapBind(bmap, BITMAP_SIZE, bitarray, sizeof(bitarray));
    RESULT(rv == 0);

    TEST("skBitmapGetSize");
    sz = skBitmapGetSize(bmap);
    RESULT(sz == BITMAP_SIZE);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 0);

    TEST("skBitmapBind");
    rv = skBitmapBind(bmap, 255, bitarray, sizeof(bitarray));
    RESULT(rv == 0);

    i = 256;
    j = 255;

    TEST("skBitmapBind");
    rv = skBitmapBind(bmap, i, bitarray, sizeof(bitarray));
    RESULT(rv == 0);

    TEST("skBitmapSetBit");
    skBitmapSetBit(bmap, j);
    RESULT(bitarray[7] == 0x80000000);

    TEST("skBitmapGetBit");
    rv = skBitmapGetBit(bmap, j);
    RESULT(rv == 1);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 1);

    TEST("skBitmapClearBit");
    skBitmapClearBit(bmap, j);
    RESULT(bitarray[7] == 0);

    TEST("skBitmapGetHighCount");
    sz = skBitmapGetHighCount(bmap);
    RESULT(sz == 0);

    TEST("skBitmapBind");
    rv = skBitmapBind(bmap, 257, bitarray, sizeof(bitarray));
    RESULT(rv == -1);
}


#define FINAL_VALUE 0x88008800

#define BAD_PARSE 0x44 /* 68 */


static void
ipwild_test_helper_v4(
    const char         *str,
    const uint32_t     *vals,
    uint32_t            range_start,
    uint32_t            range_length,
    uint32_t            range_step)
{
    skIPWildcard_t ipwild;
    skIPWildcardIterator_t iter;
    skipaddr_t ipaddr;
    uint32_t ipv4;
    uint32_t range_ip = 0;
    unsigned int i;
    int rv;

    fprintf(stderr, "Testing IPWildcard '%s' ...", str);

    rv = skStringParseIPWildcard(&ipwild, str);
    if (rv) {
        if (vals[0] == BAD_PARSE) {
            if (vals[1] == (uint32_t)rv) {
                fprintf(stderr, "ok\n");
            } else {
                fprintf(stderr, "expected %d got %d .. ok\n",
                        (int32_t)vals[1], rv);
            }
            return;
        }
        fprintf(stderr, "parsing failed (ip='%s', rv=%d): %s\n",
                str, rv, skStringParseStrerror(rv));
        exit(EXIT_FAILURE);
    }
    if (vals[0] == BAD_PARSE) {
        fprintf(stderr, "parsing succeeded but expected failure ip='%s'\n",
                str);
        exit(EXIT_FAILURE);
    }

    if (range_length) {
        range_ip = range_start;
    }

    i = 0;
    skIPWildcardIteratorBind(&iter, &ipwild);
    while (SK_ITERATOR_OK == skIPWildcardIteratorNext(&iter, &ipaddr)) {
        ipv4 = skipaddrGetV4(&ipaddr);
        /* printf("0x%x\n", ipv4); */

        if (range_length) {
            if (i == range_length) {
                fprintf(stderr,
                        "out of values before iterator iter_ip=0x%x i=%u\n",
                        ipv4, i);
                exit(EXIT_FAILURE);
            }
            if (ipv4 != range_ip) {
                fprintf(stderr,
                        "iterator mismatch iter_ip=0x%x val_ip=0x%x, i=%u\n",
                        ipv4, range_ip, i);
                exit(EXIT_FAILURE);
            }
            range_ip += range_step;
        } else {
            if (vals[i] == FINAL_VALUE) {
                fprintf(stderr,
                        "out of values before iterator iter_ip=0x%x i=%u\n",
                        ipv4, i);
                exit(EXIT_FAILURE);
            } else if (ipv4 != vals[i]) {
                fprintf(stderr,
                        "iterator mismatch iter_ip=0x%x val_ip=0x%x, i=%u\n",
                        ipv4, vals[i], i);
                exit(EXIT_FAILURE);
            }
        }
        ++i;
    }

    if (range_length) {
        if (i != range_length) {
            fprintf(stderr, "out of iterator before values val_ip=0x%x i=%u\n",
                    range_ip, i);
            exit(EXIT_FAILURE);
        }
    } else if (vals[i] != FINAL_VALUE) {
        fprintf(stderr, "out of iterator before values val_ip=0x%x i=%u\n",
                vals[i], i);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "ok\n");
}


static void
ipwild_test_v4(
    void)
{
    const char *ipstr;
    uint32_t val[1<<16];
    int v = 0;

    ipstr = "0.0.0.0";
    val[v++] = 0;
    val[v++] = FINAL_VALUE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
    v = 0;

    ipstr = "255.255.255.255";
    val[v++] = UINT32_MAX;
    val[v++] = FINAL_VALUE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
    v = 0;

    ipstr = "     255.255.255.255";
    val[v++] = UINT32_MAX;
    val[v++] = FINAL_VALUE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
    v = 0;

    ipstr = "255.255.255.255     ";
    val[v++] = UINT32_MAX;
    val[v++] = FINAL_VALUE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
    v = 0;

    ipstr = "   255.255.255.255  ";
    val[v++] = UINT32_MAX;
    val[v++] = FINAL_VALUE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
    v = 0;

    ipstr = "0.0.0.0/31";
    val[v++] = 0;
    val[v++] = 1;
    val[v++] = FINAL_VALUE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
    v = 0;

    ipstr = "255.255.255.254-255";
    val[v++] = UINT32_MAX-1;
    val[v++] = UINT32_MAX;
    val[v++] = FINAL_VALUE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
    v = 0;

    ipstr = "3,2,1.4.5.6";
    val[v++] = 0x1040506;
    val[v++] = 0x2040506;
    val[v++] = 0x3040506;
    val[v++] = FINAL_VALUE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
    v = 0;

    ipstr = "0.0.0.1,31,51,71,91,101,121,141,161,181,211,231,251";
    val[v++] = 1;
    val[v++] = 31;
    val[v++] = 51;
    val[v++] = 71;
    val[v++] = 91;
    val[v++] = 101;
    val[v++] = 121;
    val[v++] = 141;
    val[v++] = 161;
    val[v++] = 181;
    val[v++] = 211;
    val[v++] = 231;
    val[v++] = 251;
    val[v++] = FINAL_VALUE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
    v = 0;

    ipstr = "0,255.0,255.0,255.0,255";
    val[v++] = 0x00000000;
    val[v++] = 0x000000ff;
    val[v++] = 0x0000ff00;
    val[v++] = 0x0000ffff;
    val[v++] = 0x00ff0000;
    val[v++] = 0x00ff00ff;
    val[v++] = 0x00ffff00;
    val[v++] = 0x00ffffff;
    val[v++] = 0xff000000;
    val[v++] = 0xff0000ff;
    val[v++] = 0xff00ff00;
    val[v++] = 0xff00ffff;
    val[v++] = 0xffff0000;
    val[v++] = 0xffff00ff;
    val[v++] = 0xffffff00;
    val[v++] = 0xffffffff;
    val[v++] = FINAL_VALUE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
    v = 0;

    ipstr = "1.1.128.0/22";
    val[0] = 0;
    ipwild_test_helper_v4(ipstr, val, ((1 << 24) | (1 << 16) | (128 << 8)),
                          1 << 10, 1);
    v = 0;

    ipstr = "128.x.0.0";
    val[0] = 0;
    ipwild_test_helper_v4(ipstr, val, (128u << 24), 256, (1 << 16));
    v = 0;

    ipstr = "128.0-255.0.0";
    val[0] = 0;
    ipwild_test_helper_v4(ipstr, val, (128u << 24), 256, (1 << 16));
    v = 0;

    ipstr = "128.0,128-255,1-127.0.0";
    val[0] = 0;
    ipwild_test_helper_v4(ipstr, val, (128u << 24), 256, (1 << 16));
    v = 0;

    ipstr = "128.0,128,129-253,255-255,254,1-127.0.0";
    val[0] = 0;
    ipwild_test_helper_v4(ipstr, val, (128u << 24), 256, (1 << 16));
    v = 0;

    ipstr = "128.0,128-255,1-127.0.0  ";
    val[0] = 0;
    ipwild_test_helper_v4(ipstr, val, (128u << 24), 256, (1 << 16));
    v = 0;

    ipstr = "  128.0,128-255,1-127.0.0  ";
    val[0] = 0;
    ipwild_test_helper_v4(ipstr, val, (128u << 24), 256, (1 << 16));
    v = 0;

    ipstr = "  128.0,128-255,,1-127.0.0  ";
    val[0] = 0;
    ipwild_test_helper_v4(ipstr, val, (128u << 24), 256, (1 << 16));
    v = 0;

    /* the following should all fail */
    val[v++] = BAD_PARSE;
    val[v++] = 0;
    val[v++] = FINAL_VALUE;

    ipstr = "0.0.0.0/33";
    val[1] = SKUTILS_ERR_MAXIMUM;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0.2-0";
    val[1] = SKUTILS_ERR_BAD_RANGE;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0.256";
    val[1] = SKUTILS_ERR_MAXIMUM;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.256.0";
    val[1] = SKUTILS_ERR_MAXIMUM;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0256.0";
    val[1] = SKUTILS_ERR_MAXIMUM;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.256.0.0";
    val[1] = SKUTILS_ERR_MAXIMUM;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0.0.0";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.x.0/31";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.x.0:0";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0,1.0/31";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0-1.0/31";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0-1-.0";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0--1.0";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0.0 junk";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.-0-1.0";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.-1.0";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0..0";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = ".0.0.0.0";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);

    ipstr = "0.0.0.0.";
    val[1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v4(ipstr, val, 0, 0, 0);
}


#if SK_ENABLE_IPV6

static const char *
v6tostring(
    uint8_t            *ip)
{
    static char buf[50];
    char *cp;
    int i;

    cp = buf;
    for (i = 0; i < 16; ++i) {
        if (!(i & 0x01) && i > 0) { *cp = ':'; ++cp; }
        cp += snprintf(cp, (sizeof(buf) - (cp - buf)), "%02x", ip[i]);
        if ((size_t)(cp - buf) > sizeof(buf)) {
            skAbort();
        }
    }

    return buf;
}


static void four32tov6(uint32_t v[4], uint8_t *ipv6)
{
    int j, k;

    for (j = 0, k = 0; j < 16; j += 4, ++k) {
        uint32_t tmp32 = htonl(v[k]);
        memcpy(&ipv6[j], &tmp32, 4);
    }
}


static void
ipwild_test_helper_v6(
    const char         *str,
    uint32_t            vals[][4],
    uint32_t            range_start[4],
    uint32_t            range_step[4],
    int64_t             range_length)
{
    skIPWildcard_t ipwild;
    skIPWildcardIterator_t iter;
    skipaddr_t ipaddr;
    uint8_t step_ipv6[16];
    uint8_t tmp_ipv6[16];
    uint8_t ipv6[16];
    uint32_t carry;
    int64_t i;
    int j;
    int rv;

    tmp_ipv6[0] = '\0';

    fprintf(stderr, "Testing IPWildcard '%s' ...", str);

    rv = skStringParseIPWildcard(&ipwild, str);
    if (rv) {
        if (vals[0][0] == BAD_PARSE) {
            if (rv == (int8_t)(vals[0][1])) {
                fprintf(stderr, "ok\n");
            } else {
                fprintf(stderr, "expected %d got %d .. ok\n",
                        (int8_t)vals[0][1], rv);
            }
            return;
        }
        fprintf(stderr, "parsing failed (ip='%s', rv=%d): %s\n",
                str, rv, skStringParseStrerror(rv));
        exit(EXIT_FAILURE);
    }
    if (vals[0][0] == BAD_PARSE) {
        fprintf(stderr, "parsing succeeded but expected failure ip='%s'\n",
                str);
        exit(EXIT_FAILURE);
    }

    if (range_length) {
        four32tov6(range_start, tmp_ipv6);
    }

    i = 0;
    skIPWildcardIteratorBind(&iter, &ipwild);
    while (SK_ITERATOR_OK == skIPWildcardIteratorNext(&iter, &ipaddr)) {
        skipaddrGetV6(&ipaddr, ipv6);
        if (range_length) {
            if (i == range_length) {
                fprintf(stderr, ("out of values before iterator i=%" PRId64
                                 " iter_ip=%s\n"),
                        i, v6tostring(ipv6));
                exit(EXIT_FAILURE);
            }
            if (0 != memcmp(ipv6, tmp_ipv6, sizeof(ipv6))) {
                fprintf(stderr, "iterator mismatch i=%" PRId64 " iter_ip=%s",
                        i, v6tostring(ipv6));
                fprintf(stderr, ", val_ip=%s\n",
                        v6tostring(tmp_ipv6));
                exit(EXIT_FAILURE);
            }
            carry = 0;
            four32tov6(range_step, step_ipv6);
            for (j = 15; j >= 0; --j) {
                uint32_t sum = carry + tmp_ipv6[j] + step_ipv6[j];
                if (sum >= 256) {
                    carry = 1;
                    sum -= 256;
                    assert(sum < 256);
                } else {
                    carry = 0;
                }
                tmp_ipv6[j] = sum;
            }
        } else {
            if (vals[i][0] == FINAL_VALUE) {
                fprintf(stderr, ("out of values before iterator "
                                 "i=%" PRId64 " iter_ip=%s \n"),
                        i, v6tostring(ipv6));
                exit(EXIT_FAILURE);
            }
            four32tov6(vals[i], tmp_ipv6);
            if (0 != memcmp(ipv6, tmp_ipv6, sizeof(ipv6))) {
                fprintf(stderr, "iterator mismatch i=%" PRId64 " iter_ip=%s",
                        i, v6tostring(ipv6));
                fprintf(stderr, ", val_ip=%s\n",
                        v6tostring(tmp_ipv6));
                exit(EXIT_FAILURE);
            }
        }

        /* see if ipaddr is in wildcard */
        if (!skIPWildcardCheckIp(&ipwild, &ipaddr)) {
            fprintf(stderr, "check-ip fails to find ip i=%" PRId64 " ip=%s\n",
                    i, v6tostring(ipaddr.ip_ip.ipu_ipv6));
            exit(EXIT_FAILURE);
        }

        ++i;
    }

    if (0 == i) {
        fprintf(stderr, "iterator returned no addresses");
        exit(EXIT_FAILURE);
    }
    if (range_length) {
        if (i != range_length) {
            fprintf(stderr, ("out of iterator before values i=%" PRId64
                             " val_ip=%s\n"),
                    i, v6tostring(tmp_ipv6));
            exit(EXIT_FAILURE);
        }
    } else if (vals[i][0] != FINAL_VALUE) {
        fprintf(stderr, ("out of iterator before values i=%" PRId64
                         " val_ip=%s\n"),
                i, v6tostring(tmp_ipv6));
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "ok\n");
}



static void
ipwild_test_v6(
    void)
{
    const char *ipstr;
    uint32_t val[1<<16][4];
    uint32_t range_start[4] = {0, 0, 0, 0};
    uint32_t range_step[4] = {0, 0, 0, 1};
    int v = 0;

    ipstr = "0:0:0:0:0:0:0:0";
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "::";
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "::0.0.0.0";
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "1:2:3:4:5:6:7:8";
    val[v][0] = 0x00010002;
    val[v][1] = 0x00030004;
    val[v][2] = 0x00050006;
    val[v][3] = 0x00070008;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "1:203:405:607:809:a0b:c0d:e0f";
    val[v][0] = 0x00010203;
    val[v][1] = 0x04050607;
    val[v][2] = 0x08090a0b;
    val[v][3] = 0x0c0d0e0f;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "1:203:405:607:809:a0b:12.13.14.15";
    val[v][0] = 0x00010203;
    val[v][1] = 0x04050607;
    val[v][2] = 0x08090a0b;
    val[v][3] = 0x0c0d0e0f;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "::FFFF";
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0xffff;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "::FFFF:FFFF";
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0xffffffff;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "::0.0.255.255";
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0xffff;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "::255.255.255.255";
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0xffffffff;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "FFFF::";
    val[v][0] = 0xffff0000;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "0,FFFF::0,FFFF";
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0;
    ++v;
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0xffff;
    ++v;
    val[v][0] = 0xffff0000;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0;
    ++v;
    val[v][0] = 0xffff0000;
    val[v][1] = 0;
    val[v][2] = 0;
    val[v][3] = 0xffff;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "::FFFF:0,10.0.0.0,10";
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0xffff;
    val[v][3] = 0;
    ++v;
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0xffff;
    val[v][3] = 0x0a;
    ++v;
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0xffff;
    val[v][3] = 0x0a000000;
    ++v;
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0xffff;
    val[v][3] = 0x0a00000a;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "::FFFF:0.0,160.0,160.0";
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0xffff;
    val[v][3] = 0;
    ++v;
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0xffff;
    val[v][3] = 0xa000;
    ++v;
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0xffff;
    val[v][3] = 0x00a00000;
    ++v;
    val[v][0] = 0;
    val[v][1] = 0;
    val[v][2] = 0xffff;
    val[v][3] = 0x00a0a000;
    ++v;
    val[v][0] = FINAL_VALUE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);
    v = 0;

    ipstr = "1-FF::/16";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1,2::/16";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1::2::3";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = ":1::";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = ":1:2:3:4:5:6:7:8";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1:2:3:4:5:6:7:8:";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1:2:3:4:5:6:7.8.9:10";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1:2:3:4:5:6:7:8.9.10.11";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = ":";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1:2:3:4:5:6:7";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_SHORT;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1:2:3:4:5:6:7/16";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);


    ipstr = "FFFFF::";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_MAXIMUM;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "::FFFFF";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_MAXIMUM;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1:FFFFF::7:8";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_MAXIMUM;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1:AAAA-FFFF0::";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_MAXIMUM;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "FFFFF-AAAA::";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_MAXIMUM;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "FFFF-AAAA::";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_RANGE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "2-1::";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_RANGE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1:FFFF-0::";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_RANGE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1::FFFF-AAAA";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_RANGE;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = ":::";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1:2:3:$::";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "1.2.3.4:ffff::";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_BAD_CHAR;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "x";
    val[0][0] = BAD_PARSE;
    val[0][1] = SKUTILS_ERR_SHORT;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 0);

    ipstr = "0:0:0:0:0:0:0:0/127";
    val[0][0] = 0;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 2);
    v = 0;

    ipstr = "::/127";
    val[0][0] = 0;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 2);
    v = 0;

    ipstr = "0:0:0:0:0:0:0:0/110";
    val[0][0] = 0;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 18));
    v = 0;

#if 0
    ipstr = "0:0:0:0:0:0:0:0/95";
    val[0][0] = 0;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1ULL << 33));
    v = 0;
#endif

    ipstr = "0:ffff::0/127";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 2);
    v = 0;

    ipstr = "0:ffff::0.0.0.0,1";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 2);
    v = 0;

    ipstr = "0:ffff::0.0.0.0-10";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, 11);
    v = 0;

    ipstr = "0:ffff::0.0.0.x";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 8));
    v = 0;

    ipstr = "::ffff:0:0:0:0:0:0/110";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 18));
    v = 0;

    ipstr = "0:ffff::/112";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0:x";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0:x";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0:0-ffff";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0.0.x.x";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0.0.0-255.128-254,0-126,255,127";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0.0.128-254,0-126,255,127.x";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0.0.0.0/112";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0.0,1.x.x";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 17));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0:0-10,10-20,24,23,22,21,25-ffff";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff::x";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0:aaab-ffff,aaaa-aaaa,0-aaa9";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0:ff00/120";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    range_start[1] = 0;
    range_start[2] = 0;
    range_start[3] = 0xff00;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 8));
    v = 0;

    ipstr = "0:ffff:0:0:0:0:0:ffff/120";
    val[0][0] = 0;
    range_start[0] = 0xffff;
    range_start[1] = 0;
    range_start[2] = 0;
    range_start[3] = 0xff00;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 8));
    v = 0;

    ipstr = "::ff00:0/104";
    val[0][0] = 0;
    range_start[0] = 0;
    range_start[1] = 0;
    range_start[2] = 0;
    range_start[3] = 0xff000000;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 24));
    v = 0;

    ipstr = "::x";
    val[0][0] = 0;
    range_start[0] = 0;
    range_start[1] = 0;
    range_start[2] = 0;
    range_start[3] = 0;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "x::";
    val[0][0] = 0;
    range_start[0] = 0;
    range_step[0] = 0x00010000;
    range_step[1] = 0;
    range_step[2] = 0;
    range_step[3] = 0;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;

    ipstr = "x::10.10.10.10";
    val[0][0] = 0;
    range_start[0] = 0;
    range_start[3] = 0x0a0a0a0a;
    range_step[0] = 0x00010000;
    range_step[1] = 0;
    range_step[2] = 0;
    range_step[3] = 0;
    ipwild_test_helper_v6(ipstr, val, range_start, range_step, (1 << 16));
    v = 0;
}

#endif /*  SK_ENABLE_IPV6 */



int main(int UNUSED(argc), char **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);

    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);

    bitmap_test();
    ipwild_test_v4();
#if SK_ENABLE_IPV6
    ipwild_test_v6();
#endif /* SK_ENABLE_IPV6 */

    skAppUnregister();

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
