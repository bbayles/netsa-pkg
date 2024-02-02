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
**  skbitmap.c
**
**    Bitmap creatation and deletion.
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skbitmap.c c3cb530920e1 2023-04-26 14:50:25Z mthomas $");

#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/*
 *    Return number of 32bit words needed to hold a bitmap with
 *    'num_bits' elements.  Need to add 1 if number of bits is not an
 *    even multiple of 32.
 */
#define BITMAP_GET_WORD_COUNT(num_bits)         \
    (((num_bits) >> 5) + !!((num_bits) & 0x1F))


/* FUNCTION DEFINITIONS */

/*
 *    Return the number of trailing zeros in 'v'.  Note: This function
 *    assumes 'v' is non-zero; it will return 31 if 'v' is 0.
 */
static uint8_t
bitmapCountTrailingZeros(
    uint32_t            v)
{
    uint8_t c = 1;
    if ((v & 0xffff) == 0) {
        v >>= 16;
        c += 16;
    }
    if ((v & 0xff) == 0) {
        v >>= 8;
        c += 8;
    }
    if ((v & 0xf) == 0) {
        v >>= 4;
        c += 4;
    }
    if ((v & 0x3) == 0) {
        v >>= 2;
        c += 2;
    }
    return c - (uint8_t)(v & 0x1);
}


int
skBitmapBind(
    sk_bitmap_t        *bitmap,
    uint32_t            num_bits,
    uint32_t           *bitarray,
    size_t              sizeof_bitarray)
{
    uint32_t word_count = BITMAP_GET_WORD_COUNT(num_bits);

    if ( !(bitmap && num_bits && bitarray && sizeof_bitarray)) {
        return -1;
    }

    if (sizeof_bitarray < (word_count * sizeof(uint32_t))) {
        return -1;
    }

    memset(bitarray, 0, sizeof_bitarray);
    bitmap->map = bitarray;
    bitmap->num_bits = num_bits;
    bitmap->count = 0;

    return 0;
}


int
skBitmapCreate(
    sk_bitmap_t       **bitmap_out,
    uint32_t            num_bits)
{
    uint32_t word_count = BITMAP_GET_WORD_COUNT(num_bits);

    assert(bitmap_out);

    if (num_bits == 0) {
        *bitmap_out = NULL;
        return -1;
    }

    *bitmap_out = (sk_bitmap_t*)calloc(1, sizeof(sk_bitmap_t));
    if (*bitmap_out == NULL) {
        return -1;
    }

    (*bitmap_out)->map = (uint32_t*)calloc(word_count, sizeof(uint32_t));
    if (NULL == (*bitmap_out)->map) {
        free(*bitmap_out);
        *bitmap_out = NULL;
        return -1;
    }

    (*bitmap_out)->num_bits = num_bits;

    return 0;
}


void
skBitmapDestroy(
    sk_bitmap_t       **bitmap)
{
    if (!bitmap || !*bitmap) {
        return;
    }

    free((*bitmap)->map);
    (*bitmap)->map = NULL;
    free(*bitmap);
    *bitmap = NULL;
}


void
skBitmapClearAllBits(
    sk_bitmap_t        *bitmap)
{
    uint32_t word_count;

    assert(bitmap);

    word_count = BITMAP_GET_WORD_COUNT(bitmap->num_bits);

    memset(bitmap->map, 0, word_count * sizeof(uint32_t));
    bitmap->count = 0;
}


void
skBitmapSetAllBits(
    sk_bitmap_t        *bitmap)
{
    uint32_t word_count;

    assert(bitmap);

    word_count = BITMAP_GET_WORD_COUNT(bitmap->num_bits);

    if ((bitmap->num_bits & 0x1F) != 0) {
        /* last word is not fully used. handle it specially so we
         * don't set bits that are not in use */
        --word_count;
        SET_MASKED_BITS(bitmap->map[word_count], UINT32_MAX,
                        0, (bitmap->num_bits & 0x1F));
    }
    memset(bitmap->map, 0xFF, word_count * sizeof(uint32_t));
    bitmap->count = bitmap->num_bits;
}


uint32_t
skBitmapGetSizeF(
    const sk_bitmap_t  *bitmap)
{
    assert(bitmap);

    return skBitmapGetSizeFast(bitmap);
}


uint32_t
skBitmapGetHighCountF(
    const sk_bitmap_t  *bitmap)
{
#ifndef NDEBUG
    uint32_t count = 0;
#endif
    uint32_t i;
    uint32_t bits;

    assert(bitmap);

    /* check that bitmap->count is corrrect */
    for (i=BITMAP_GET_WORD_COUNT(bitmap->num_bits)-1; i < (uint32_t)-1; --i) {
        BITS_IN_WORD32(&bits, bitmap->map[i]);
#ifndef NDEBUG
        count += bits;
#endif
    }
    assert(count == bitmap->count);

    return skBitmapGetHighCountFast(bitmap);
}


int
skBitmapGetBitF(
    const sk_bitmap_t  *bitmap,
    uint32_t            pos)
{
    assert(bitmap);
    assert(pos < bitmap->num_bits);

    return skBitmapGetBitFast(bitmap, pos);
}


void
skBitmapSetBitF(
    sk_bitmap_t        *bitmap,
    uint32_t            pos)
{
    assert(bitmap);
    assert(pos < bitmap->num_bits);

    skBitmapSetBitFast(bitmap, pos);
}


void
skBitmapClearBitF(
    sk_bitmap_t        *bitmap,
    uint32_t            pos)
{
    assert(bitmap);
    assert(pos < bitmap->num_bits);

    skBitmapClearBitFast(bitmap, pos);
}


void
skBitmapComplement(
    sk_bitmap_t        *bitmap)
{
    uint32_t i;
    uint32_t bits;

    assert(bitmap);

    bitmap->count = 0;

    i = BITMAP_GET_WORD_COUNT(bitmap->num_bits) - 1;

    if (bitmap->num_bits & 0x1F) {
        /* last word is not fully used.  handle it specially so we
         * don't complement bits that are not in use */
        bitmap->map[i] = GET_MASKED_BITS(~bitmap->map[i], 0,
                                         (bitmap->num_bits & 0x1F));
        BITS_IN_WORD32(&bits, bitmap->map[i]);
        bitmap->count += bits;
        --i;
    }
    for ( ; i < (uint32_t)-1; --i) {
        bitmap->map[i] = ~bitmap->map[i];
        BITS_IN_WORD32(&bits, bitmap->map[i]);
        bitmap->count += bits;
    }
}


int
skBitmapIntersection(
    sk_bitmap_t        *dest,
    const sk_bitmap_t  *src)
{
    uint32_t i;
    uint32_t bits;

    assert(dest);
    assert(src);

    if (dest->num_bits != src->num_bits) {
        return -1;
    }

    dest->count = 0;
    for (i = BITMAP_GET_WORD_COUNT(src->num_bits) - 1; i < (uint32_t)-1; --i) {
        dest->map[i] &= src->map[i];
        BITS_IN_WORD32(&bits, dest->map[i]);
        dest->count += bits;
    }
    return 0;
}


int
skBitmapUnion(
    sk_bitmap_t        *dest,
    const sk_bitmap_t  *src)
{
    uint32_t i;
    uint32_t bits;

    assert(dest);
    assert(src);

    if (dest->num_bits != src->num_bits) {
        return -1;
    }

    dest->count = 0;
    for (i = BITMAP_GET_WORD_COUNT(src->num_bits) - 1; i < (uint32_t)-1; --i) {
        dest->map[i] |= src->map[i];
        BITS_IN_WORD32(&bits, dest->map[i]);
        dest->count += bits;
    }
    return 0;
}


uint32_t
skBitmapCountConsecutive(
    const sk_bitmap_t  *bitmap,
    uint32_t            begin_pos,
    uint32_t            state)
{
    uint32_t count = 0;
    uint32_t value;
    uint32_t limit;
    uint32_t i;

    assert(bitmap);
    if (begin_pos >= bitmap->num_bits) {
        return UINT32_MAX;
    }

    i = _BMAP_INDEX(begin_pos);
    limit = _BMAP_INDEX(bitmap->num_bits - 1);

    if (i == limit) {
        /* look at a single word */
        value = GET_MASKED_BITS((state ? ~bitmap->map[i] : bitmap->map[i]),
                                begin_pos & 0x1F, bitmap->num_bits-begin_pos);
        if (value) {
            return bitmapCountTrailingZeros(value);
        }
        return bitmap->num_bits - begin_pos;
    }

    if (begin_pos & 0x1F) {
        /* first bit is not least significant bit */
        value = GET_MASKED_BITS((state ? ~(bitmap->map[i]) : bitmap->map[i]),
                                begin_pos & 0x1F, 32 - (begin_pos & 0x1F));
        if (value) {
            return bitmapCountTrailingZeros(value);
        }
        count += 32 - (begin_pos & 0x1F);
        ++i;
    }

    if ((bitmap->num_bits & 0x1F) == 0) {
        /* no need to handle final word specially */
        ++limit;
    }

    if (state) {
        for (; i < limit; ++i) {
            if (UINT32_MAX == bitmap->map[i]) {
                count += 32;
            } else {
                return count + bitmapCountTrailingZeros(~bitmap->map[i]);
            }
        }
    } else {
        for (; i < limit; ++i) {
            if (0 == bitmap->map[i]) {
                count += 32;
            } else {
                return count + bitmapCountTrailingZeros(bitmap->map[i]);
            }
        }
    }

    if (bitmap->num_bits & 0x1F) {
        /* handle final partially filled word */
        value = GET_MASKED_BITS((state ? ~(bitmap->map[i]) : bitmap->map[i]),
                                0, (bitmap->num_bits & 0x1F));
        if (value) {
            return count + bitmapCountTrailingZeros(value);
        }
        count += (bitmap->num_bits & 0x1F);
    }

    return count;
}


int
skBitmapRangeSet(
    sk_bitmap_t        *bitmap,
    uint32_t            begin_pos,
    uint32_t            end_pos)
{
    uint32_t prev;
    uint32_t bits;
    uint32_t i;

    assert(bitmap);
    if (begin_pos > end_pos || end_pos >= bitmap->num_bits) {
        return -1;
    }

    i = _BMAP_INDEX(begin_pos);
    if (i == _BMAP_INDEX(end_pos)) {
        /* range is in a single word */
        prev = bitmap->map[i];
        SET_MASKED_BITS(bitmap->map[i], UINT32_MAX,
                        begin_pos & 0x1F, 1 + end_pos - begin_pos);
        BITS_IN_WORD32(&bits, prev ^ bitmap->map[i]);
        bitmap->count += bits;
        return 0;
    }

    prev = bitmap->map[i];
    SET_MASKED_BITS(bitmap->map[i], UINT32_MAX, begin_pos & 0x1F,
                    32 - (begin_pos & 0x1F));
    BITS_IN_WORD32(&bits, prev ^ bitmap->map[i]);
    bitmap->count += bits;

    for (++i; i < _BMAP_INDEX(end_pos); ++i) {
        BITS_IN_WORD32(&bits, bitmap->map[i]);
        bitmap->count += 32 - bits;
        bitmap->map[i] = UINT32_MAX;
    }

    prev = bitmap->map[i];
    SET_MASKED_BITS(bitmap->map[i], UINT32_MAX, 0, 1 + (end_pos & 0x1F));
    BITS_IN_WORD32(&bits, prev ^ bitmap->map[i]);
    bitmap->count += bits;
    return 0;
}


int
skBitmapRangeClear(
    sk_bitmap_t        *bitmap,
    uint32_t            begin_pos,
    uint32_t            end_pos)
{
    uint32_t prev;
    uint32_t bits;
    uint32_t i;

    assert(bitmap);
    if (begin_pos > end_pos || end_pos >= bitmap->num_bits) {
        return -1;
    }

    i = _BMAP_INDEX(begin_pos);
    if (i == _BMAP_INDEX(end_pos)) {
        /* range is in a single word */
        prev = bitmap->map[i];
        SET_MASKED_BITS(bitmap->map[i], 0,
                        begin_pos & 0x1F, 1 + end_pos - begin_pos);
        BITS_IN_WORD32(&bits, prev ^ bitmap->map[i]);
        bitmap->count -= bits;
        return 0;
    }

    prev = bitmap->map[i];
    SET_MASKED_BITS(bitmap->map[i], 0, begin_pos & 0x1F,
                    32 - (begin_pos & 0x1F));
    BITS_IN_WORD32(&bits, prev ^ bitmap->map[i]);
    bitmap->count -= bits;

    for (++i; i < _BMAP_INDEX(end_pos); ++i) {
        BITS_IN_WORD32(&bits, bitmap->map[i]);
        bitmap->count -= bits;
        bitmap->map[i] = 0;
    }

    prev = bitmap->map[i];
    SET_MASKED_BITS(bitmap->map[i], 0, 0, 1 + (end_pos & 0x1F));
    BITS_IN_WORD32(&bits, prev ^ bitmap->map[i]);
    bitmap->count -= bits;
    return 0;
}


uint32_t
skBitmapRangeCountHigh(
    sk_bitmap_t        *bitmap,
    uint32_t            begin_pos,
    uint32_t            end_pos)
{
    uint32_t value;
    uint32_t bits1;
    uint32_t bits2;
    uint32_t i;

    assert(bitmap);
    if (begin_pos > end_pos || end_pos >= bitmap->num_bits) {
        return UINT32_MAX;
    }

    i = _BMAP_INDEX(begin_pos);
    if (i == _BMAP_INDEX(end_pos)) {
        /* range is in a single word */
        value = GET_MASKED_BITS(bitmap->map[i], begin_pos & 0x1F,
                                1 + end_pos - begin_pos);
        BITS_IN_WORD32(&bits1, value);
        return bits1;
    }

    value = GET_MASKED_BITS(bitmap->map[i], begin_pos & 0x1F,
                            32 - (begin_pos & 0x1F));
    BITS_IN_WORD32(&bits1, value);
    value = GET_MASKED_BITS(bitmap->map[_BMAP_INDEX(end_pos)],
                            0, 1 + (end_pos & 0x1F));
    BITS_IN_WORD32(&bits2, value);

    return (bits1 + bits2 + 32 * (_BMAP_INDEX(end_pos) - i - 1));
}


void
skBitmapIteratorBind(
    const sk_bitmap_t  *bitmap,
    sk_bitmap_iter_t   *iter)
{
    assert(bitmap);
    assert(iter);

    memset(iter, 0, sizeof(sk_bitmap_iter_t));
    iter->bitmap = bitmap;
    skBitmapIteratorReset(iter);
}


int
skBitmapIteratorNext(
    sk_bitmap_iter_t   *iter,
    uint32_t           *pos)
{
    uint32_t word_count;

    assert(iter);
    assert(pos);

    word_count = BITMAP_GET_WORD_COUNT(iter->bitmap->num_bits);
    if (word_count == iter->map_idx) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }

    if (iter->bitmap->map[iter->map_idx] >> iter->pos) {
        /* find next bit in current word */
        iter->pos += bitmapCountTrailingZeros(iter->bitmap->map[iter->map_idx]
                                              >> iter->pos);
        *pos = ((iter->map_idx << 5) | iter->pos);
        if (iter->pos < 31) {
            ++iter->pos;
        } else {
            ++iter->map_idx;
            iter->pos = 0;
        }
        return SK_ITERATOR_OK;
    }

    /* find next word with bits */
    for (++iter->map_idx; iter->map_idx < word_count; ++iter->map_idx) {
        if (iter->bitmap->map[iter->map_idx]) {
            iter->pos
                = bitmapCountTrailingZeros(iter->bitmap->map[iter->map_idx]);
            *pos = ((iter->map_idx << 5) | iter->pos);
            if (iter->pos < 31) {
                ++iter->pos;
            } else {
                ++iter->map_idx;
                iter->pos = 0;
            }
            return SK_ITERATOR_OK;
        }
    }

    return SK_ITERATOR_NO_MORE_ENTRIES;
}


void
skBitmapIteratorReset(
    sk_bitmap_iter_t   *iter)
{
    assert(iter);

    iter->map_idx = 0;
    iter->pos = 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
