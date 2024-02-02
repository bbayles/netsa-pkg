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
**  utils.h
**
**    A collection of utility routines.
**
**    Suresh L Konda
*/
#ifndef _UTILS_H
#define _UTILS_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_UTILS_H, "$SiLK: utils.h 35b901fd2f56 2023-03-10 19:46:07Z mthomas $");

#include <silk/silk_types.h>

#ifdef SK_HAVE_GETOPT_LONG_ONLY
#include <getopt.h>
#else
#include <silk/gnu_getopt.h>
#endif

/**
 *  @file
 *
 *    A collection of utility functions for registring an application,
 *    registering options, providing common options, parsing option
 *    strings, printing error messages, opening and closing file, et
 *    cetera.
 *
 *    This file is part of libsilk.
 */


/**
 *    Where to create temp files by default.  This can be overridden
 *    by the --temp-dir switch (assuming skOptionsTempDirRegister() is
 *    in use), or environment variable named in SK_TEMPDIR_ENVAR1 or
 *    the environment variable named in SK_TEMPDIR_ENVAR2.
 *
 *    If this is not defined, no default exists.
 */
#define SK_TEMPDIR_DEFAULT "/tmp"

/**
 *    Name of primary environment variable that holds name of temp
 *    directory.  This is consulted when the --temp-dir switch is not
 *    given.
 */
#define SK_TEMPDIR_ENVAR1 "SILK_TMPDIR"

/**
 *    Name of alternate environment variable that holds name of temp
 *    directory.  Used when the --temp-dir switch is not given and the
 *    variable named by SK_TMPDIR_ENVAR1 is not set.
 */
#define SK_TEMPDIR_ENVAR2 "TMPDIR"



typedef enum {
    /* Command was successful */
    SKUTILS_OK = 0,

    /* Input to function is null or invalid (e.g., 0 length bitmap) */
    SKUTILS_ERR_INVALID = -1,

    /* Input to function was empty (or contained only whitespace) */
    SKUTILS_ERR_EMPTY = -2,

    /* Unexpected/Bad character or number is unparseable */
    SKUTILS_ERR_BAD_CHAR = -3,

    /* Value overflows the parser */
    SKUTILS_ERR_OVERFLOW = -4,

    /* Value underflows the parser */
    SKUTILS_ERR_UNDERFLOW = -5,

    /* Range is invalid (min > max) */
    SKUTILS_ERR_BAD_RANGE = -6,

    /* Unexpected end-of-input */
    SKUTILS_ERR_SHORT = -7,

    /* Too many fields provided */
    SKUTILS_ERR_TOO_MANY_FIELDS = -8,

    /* Out of memory */
    SKUTILS_ERR_ALLOC = -9,

    /* Miscellaneous error */
    SKUTILS_ERR_OTHER = -10,

    /* Value is below the minimum */
    SKUTILS_ERR_MINIMUM = -11,

    /* Value is above the maximum */
    SKUTILS_ERR_MAXIMUM = -12,

    /* Host name or port could not be resolved */
    SKUTILS_ERR_RESOLVE = -13
} silk_utils_errcode_t;



/*
**
**  sku-compat.c
**
*/

/* silk.h will #define intmax_t sk_intmax_t if required */
typedef int64_t sk_intmax_t;

/* silk.h will #define imaxdiv_t sk_imaxdiv_t if required */
typedef struct sk_imaxdiv_st {
    sk_intmax_t quot; /* Quotient  */
    sk_intmax_t rem;  /* Remainder */
} sk_imaxdiv_t;

/* silk.h will #define imaxdiv sk_imaxdiv if required */
/**
 *    Do the integer division of 'numer' by 'denom'; return a
 *    structure that contains the 'quot' (quotient) and the 'rem'
 *    (remainder).
 *
 *    Conforming to C99.
 */
sk_imaxdiv_t
sk_imaxdiv(
    sk_intmax_t         numer,
    sk_intmax_t         denom);


/* silk.h will #define memccpy sk_memccpy if required */
/**
 *    Copy bytes from 'src' to 'dst' stopping after the first
 *    occurance of 'c' or when 'len' octets have been copied,
 *    whichever comes first.  If 'c' was not found, NULL is returned;
 *    else return value pointing to character after 'c' in 'dst'.
 *
 *    Conforming to C99.
 */
void *
sk_memccpy(
    void               *dst,
    const void         *src,
    int                 c,
    size_t              len);


/* silk.h will #define setenv sk_setenv if required */
/**
 *    Set environment variable 'name' to 'value', unless 'name' already
 *    exists in the environment and 'overwrite' is 0.
 *
 *    Return 0 on success.  Return -1 and set errno on memory
 *    allocation error or if 'name' contains a '=' character.  Assumes
 *    'name' and 'value' are not NULL.
 *
 *    Conforming to POSIX.1-2001
 */
int
sk_setenv(
    const char         *name,
    const char         *value,
    int                 overwrite);


/* silk.h will #define strsep sk_strsep if required */
/**
 *    Locate in *stringp first occurrence of any member of 'delim'.
 *    Change that character to '\0', modify '*stringp' to point to the
 *    following character, and return the original value of *stringp.
 *
 *    Return NULL if *stringp is NULL or when **stringp is '\0'; i.e.,
 *    when the end of the string is reached.
 *
 *    Empty field is determined by testing the returned value to '\0'.
 *
 *    Comforming to BSD 4.4
 */
char *
sk_strsep(
    char              **stringp,
    const char         *delim);


/* silk.h will #define timegm sk_timegm if required */
/**
 *    Do the reverse of gmtime(): Take a time structure and return
 *    seconds since the epoch in the UTC timezone.
 *
 *    No standard; common on Open Source systems.
 */
time_t
sk_timegm(
    struct tm          *tm);


#if 0
/**
 *    Replacement for snprintf() that always NUL terminates the string.
 */
int
sk_snprintf(
    char               *str,
    size_t              size,
    const char         *format,
    ...);


/**
 *    Replacement for vsnprintf() that always NUL terminates the string.
 */
int
sk_vsnprintf(
    char               *str,
    size_t              size,
    const char         *format,
    va_list             args);
#endif



/*
**
**  skbitmap.c
**
*/


/* typedef struct sk_bitmap_st sk_bitmap_t; // silk_types.h */
struct sk_bitmap_st {
    uint32_t   *map;
    uint32_t    num_bits;
    uint32_t    count;
};


/**
 *    Type for iterating over the entries in an sk_bitmap_t.
 */
typedef struct sk_bitmap_iter_st {
    const sk_bitmap_t  *bitmap;
    uint32_t            map_idx;
    uint8_t             pos;
} sk_bitmap_iter_t;


/* Internal macros.  Not for public use. */
#define _BMAP_INDEX(p)      ((p) >> 5)
#define _BMAP_OFFSET(p)     (1u << ((p) & 0x1F))
#define _BMAP_IS_SET(b, p)  ((b)->map[_BMAP_INDEX(p)] & _BMAP_OFFSET(p))



/**
 *    Create a new empty bitmap capable of holding 'num_bits' bits.
 *    All bits in the map are set to 0/LOW/OFF.  Return the bitmap in
 *    the location given by 'bitmap_out'.  Returns 0 if successful; -1
 *    for a memory allocation error or if 'num_bits' is zero.
 *
 *    Bits in an sk_bitmap_t are numbered from 0 to num_bits-1.
 *
 *    See also skBitmapBind().
 */
int
skBitmapCreate(
    sk_bitmap_t       **bitmap_out,
    uint32_t            num_bits);


/**
 *    Bind 'bitmap' to an existing array of uint32_t, 'bitarray', and
 *    clear the bitmap.  'num_bits' is number of bits you want to the
 *    bitmap to hold.  'sizeof_bitarray' should be the value of
 *    sizeof(bitarray).
 *
 *    This function can be used to create bitmaps on the stack without
 *    having to use the allocation code in skBitmapCreate().  These
 *    bitmaps should NOT be skBitmapDestroy()'ed.
 */
int
skBitmapBind(
    sk_bitmap_t        *bitmap,
    uint32_t            num_bits,
    uint32_t           *bitarray,
    size_t              sizeof_bitarray);


/**
 *    Destroy the bitmap at location given by 'bitmap' that was
 *    created by skBitmapCreate().  Do not call this function when you
 *    have used skBitmapBind().
 *
 *    The 'bitmap' paramter may be NULL or it may reference a NULL
 *    value.
 */
void
skBitmapDestroy(
    sk_bitmap_t       **bitmap);


/**
 *    Turn OFF all the bits in 'bitmap' and set the high-bit count to
 *    zero.
 */
void
skBitmapClearAllBits(
    sk_bitmap_t        *bitmap);


/**
 *    Turn ON all the bits in 'bitmap' and set the high-bit count to
 *    the number of bits in the bitmap.
 */
void
skBitmapSetAllBits(
    sk_bitmap_t        *bitmap);


/**
 *    Return the number of bits that 'bitmap' can hold.
 */
uint32_t
skBitmapGetSizeF(
    const sk_bitmap_t  *bitmap);
#define skBitmapGetSizeFast(bmap_size_fast)     \
    ((bmap_size_fast)->num_bits)
#ifdef SKBITMAP_DEBUG
#  define skBitmapGetSize(bitmap) skBitmapGetSizeF(bitmap)
#else
#  define skBitmapGetSize(bitmap) skBitmapGetSizeFast(bitmap)
#endif


/**
 *    Return the number of bits in 'bitmap' that are ON.
 */
uint32_t
skBitmapGetHighCountF(
    const sk_bitmap_t  *bitmap);
#define skBitmapGetHighCountFast(bmap_high_fast)        \
    ((bmap_high_fast)->count)
#ifdef SKBITMAP_DEBUG
#  define skBitmapGetHighCount(bitmap) skBitmapGetHighCountF(bitmap)
#else
#  define skBitmapGetHighCount(bitmap) skBitmapGetHighCountFast(bitmap)
#endif


/**
 *    Return 1 if the bit at position 'pos' in 'bitmap' is ON; return
 *    0 if it is OFF.  Valid values for 'pos' are 0 through one less
 *    than the number of bits in the bitmap.  Return -1 if 'pos' is
 *    larger than the size of the bitmap.
 */
int
skBitmapGetBitF(
    const sk_bitmap_t  *bitmap,
    uint32_t            pos);
#define skBitmapGetBitFast(bmap_get_fast, pos_get_fast)         \
    ((((uint32_t)(pos_get_fast)) >= (bmap_get_fast)->num_bits)  \
     ? -1                                                       \
     : !!_BMAP_IS_SET((bmap_get_fast), (pos_get_fast)))
#ifdef SKBITMAP_DEBUG
#  define skBitmapGetBit(bitmap, pos) skBitmapGetBitF(bitmap, pos)
#else
#  define skBitmapGetBit(bitmap, pos) skBitmapGetBitFast(bitmap, pos)
#endif


/**
 *    Turn ON the bit at position 'pos' in 'bitmap'.  Adjust the
 *    bitmap's high-bit counter.  Valid values for 'pos' are 0 through
 *    one less than the number of bits in the bitmap.
 */
void
skBitmapSetBitF(
    sk_bitmap_t        *bitmap,
    uint32_t            pos);
#define skBitmapSetBitFast(bmap_set_fast, pos_set_fast)                 \
    if ((((uint32_t)(pos_set_fast)) >= (bmap_set_fast)->num_bits)       \
        || _BMAP_IS_SET((bmap_set_fast), (pos_set_fast)))               \
    { /* no-op */ } else {                                              \
        (bmap_set_fast)->map[_BMAP_INDEX(pos_set_fast)]                 \
            |= _BMAP_OFFSET(pos_set_fast);                              \
        ++(bmap_set_fast)->count;                                       \
    }
#ifdef SKBITMAP_DEBUG
#  define skBitmapSetBit(bitmap, pos) skBitmapSetBitF(bitmap, pos)
#else
#  define skBitmapSetBit(bitmap, pos) skBitmapSetBitFast(bitmap, pos)
#endif


/**
 *    Turn OFF the bit at position 'pos' in 'bitmap'.  Adjust the
 *    bitmap's high-bit counter.  Valid values for 'pos' are 0 through
 *    one less than the number of bits in the bitmap.
 */
void
skBitmapClearBitF(
    sk_bitmap_t        *bitmap,
    uint32_t            pos);
#define skBitmapClearBitFast(bmap_clear_fast, pos_clear_fast)   \
    if (((pos_clear_fast) >= (bmap_clear_fast)->num_bits)       \
        || !_BMAP_IS_SET((bmap_clear_fast),(pos_clear_fast)))   \
    { /* no-op */ } else {                                      \
        (bmap_clear_fast)->map[_BMAP_INDEX(pos_clear_fast)]     \
            &= ~(_BMAP_OFFSET(pos_clear_fast));                 \
        --(bmap_clear_fast)->count;                             \
    }
#ifdef SKBITMAP_DEBUG
#  define skBitmapClearBit(bitmap, pos) skBitmapClearBitF(bitmap, pos)
#else
#  define skBitmapClearBit(bitmap, pos) skBitmapClearBitFast(bitmap, pos)
#endif


/**
 *    Modify 'bitmap' in place to hold its complement.
 */
void
skBitmapComplement(
    sk_bitmap_t        *bitmap);


/**
 *    Compute the intersection of 'dest' and 'src', placing the result
 *    in 'dest'.  The bitmaps must be of the same size.  If they are
 *    not of the same size, returns -1, else returns 0.
 */
int
skBitmapIntersection(
    sk_bitmap_t        *dest,
    const sk_bitmap_t  *src);


/**
 *    Compute the union of 'dest' and 'src', placing the result in
 *    'dest'.  The bitmaps must be of the same size.  If they are not
 *    of the same size, returns -1, else returns 0.
 */
int
skBitmapUnion(
    sk_bitmap_t        *dest,
    const sk_bitmap_t  *src);


/**
 *    Return the number of bits, starting at 'begin_pos', that have
 *    the value 'state', which should be 0 or 1.  Return UINT32_MAX if
 *    'begin_pos' is larger than the size of the bitmap.
 */
uint32_t
skBitmapCountConsecutive(
    const sk_bitmap_t  *bitmap,
    uint32_t            begin_pos,
    uint32_t            state);


/**
 *    Turn ON all bits in the bitmap from 'begin_pos' to 'end_pos'
 *    inclusive.  Valid values for 'begin_pos' and 'end_pos' are 0
 *    through one less than the number of bits in the bitmap.  Return
 *    -1 if 'end_pos' is less than 'begin_pos' or if either value is
 *    larger than the size of the bitmap.  Return 0 otherwise.
 */
int
skBitmapRangeSet(
    sk_bitmap_t        *bitmap,
    uint32_t            begin_pos,
    uint32_t            end_pos);


/**
 *    Turn OFF all bits in the bitmap from 'begin_pos' to 'end_pos'
 *    inclusive.  Valid values for 'begin_pos' and 'end_pos' are 0
 *    through one less than the number of bits in the bitmap.  Return
 *    -1 if 'end_pos' is less than 'begin_pos' or if either value is
 *    larger than the size of the bitmap.  Return 0 otherwise.
 */
int
skBitmapRangeClear(
    sk_bitmap_t        *bitmap,
    uint32_t            begin_pos,
    uint32_t            end_pos);


/**
 *    Return a count of the number of bits between 'begin_pos' and
 *    'end_pos' inclusive that are currently ON.  Valid values for
 *    'begin_pos' and 'end_pos' are 0 through one less than the number
 *    of bits in the bitmap.  Return UINT32_MAX if 'end_pos' is less
 *    than 'begin_pos' or if either value is larger than the size of
 *    the bitmap.
 */
uint32_t
skBitmapRangeCountHigh(
    sk_bitmap_t        *bitmap,
    uint32_t            begin_pos,
    uint32_t            end_pos);


/**
 *    Bind the bitmap iterator 'iter' to iterate over the high bits in
 *    the bitmap 'bitmap'.  It is possible to set/unset bits in the
 *    bitmap as the iterator moves through it and have the iterator
 *    visit/skip those bits---as long as the bit position changed is
 *    greater than the iterator's current position.
 */
void
skBitmapIteratorBind(
    const sk_bitmap_t  *bitmap,
    sk_bitmap_iter_t   *iter);

/**
 *    Set 'pos' to the next high bit in the bitmap that is bound to
 *    the iterator 'iter' and return SK_ITERATOR_OK.  If the iterator
 *    has visited all the high bits in the bitmap, leave the value in
 *    'pos' unchanged and return SK_ITERATOR_NO_MORE_ENTRIES.
 */
int
skBitmapIteratorNext(
    sk_bitmap_iter_t   *iter,
    uint32_t           *pos);


/**
 *    Allow the bitmap iterator 'iter' to iterate over the bitmap
 *    again.
 */
void
skBitmapIteratorReset(
    sk_bitmap_iter_t   *iter);


/**
 *  BITS_IN_WORD32(&countptr, word);
 *  BITS_IN_WORD64(&countptr, word);
 *
 *    Set the value pointed at by 'countptr' to the number of bits
 *    that are high in the value 'word', where 'word' is either 32 or
 *    64 bits.
 *
 * Fast method of computing the number of bits in a 32-bit word.  From
 * http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
 */
#define BITS_IN_WORD32(countptr, word)                                  \
    do {                                                                \
        uint32_t vv = (word) - (((word) >> 1) & 0x55555555);            \
        vv = (vv & 0x33333333) + ((vv >> 2) & 0x33333333);              \
        *(countptr) = (((vv + (vv >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24; \
    } while(0)

#define BITS_IN_WORD64(countptr, word)                                  \
    do {                                                                \
        uint64_t vv = ((uint64_t)(word)                                 \
                       - ((uint64_t)((word) >> 1)                       \
                          & UINT64_C(0x5555555555555555)));             \
        vv = ((vv & UINT64_C(0x3333333333333333))                       \
              + ((vv >> 2) & UINT64_C(0x3333333333333333)));            \
        *(countptr) = (((uint64_t)((vv + (vv >> 4))                     \
                                   & UINT64_C(0x0f0f0f0f0f0f0f0f))      \
                        * UINT64_C(0x0101010101010101)) >> 56);         \
    } while(0)

#define BITS_IN_WORD(countptr, word)    BITS_IN_WORD32(countptr, word)


/**
 *  _BITMASK32(s);
 *  _BITMASK64(s);
 *
 *    Private macro used by GET_MASKED_BITS and SET_MASKED_BITS.  This
 *    returns a 32-bit (or 64-bit) integer with the first `s'
 *    least-significant bits turned on.
 */
#define _BITMASK32(s)                                   \
    (((s) >= 32) ? UINT32_MAX : ~(UINT32_MAX << (s)))

#define _BITMASK64(s)                                   \
    (((s) >= 64) ? UINT64_MAX : ~(UINT64_MAX << (s)))

#define _BITMASK(s)  _BITMASK32(s)


/*
 *  GET_MASKED_BITS32(x, o, s)
 *  GET_MASKED_BITS64(x, o, s)
 *
 *    Given an integer value 'x', return an integer created by
 *    shifting 'x' to the right by offset 'o' bits and returning the
 *    least significant 's' bits.  Works on any size 'x' up to maximum
 *    specified in the macro's name.
 *
 *    GET_MASKED_BITS32(x, 2, 5) would return the value represented by
 *    the middle 5 bits of a single byte, as shown here:
 *
 *    76543210
 *    .xxxxx..
 *
 *    with the value shifted to the right.  The possible values
 *    returned range from 0---if NONE of the bits are set---through
 *    31---if ALL of the bits are set.
 */
#define GET_MASKED_BITS32(x, o, s) (((x) >> (o)) & _BITMASK32((s)))

#define GET_MASKED_BITS64(x, o, s) (((x) >> (o)) & _BITMASK64((s)))

#define GET_MASKED_BITS(x, o, s)   GET_MASKED_BITS32(x, o, s)


/**
 *  SET_MASKED_BITS32(x, v, o, s)
 *  SET_MASKED_BITS64(x, v, o, s)
 *
 *    Modify the integer variable 'x' by clearing the bits from 'o' to
 *    'o'+'s'-1, and replacing those bits by shifting the value 'v' to
 *    the left 'o' bits.
 *
 *    Bits are numbered with the least significant bit being 0.
 *
 *    For example, with x=0 and v<=31, the call
 *
 *    SET_MASKED_BITS32(x, v, 1, 5)
 *
 *    will result in 'x' being set to 2*'v', with a possible range of
 *    resulting values for 'x' of 2 to 62.
 *
 *    This is the setting equivalent to GET_MASKED_BITS32().
 */
#define SET_MASKED_BITS32(x, v, o, s)                   \
    do {                                                \
        (x) = (((x) & (~(_BITMASK32(s) << (o))))        \
               | (((v) & _BITMASK32(s)) << (o)));       \
    } while(0)

#define SET_MASKED_BITS64(x, v, o, s)                   \
    do {                                                \
        (x) = (((x) & (~(_BITMASK64(s) << (o))))        \
               | (((v) & _BITMASK64(s)) << (o)));       \
    } while(0)

#define SET_MASKED_BITS(x, v, o, s)  SET_MASKED_BITS32(x, v, o, s)


/**
 *  BITMAP_DECLARE(var_name, size);
 *
 *    Declares the bitmap 'var_name' that will hold size bits numbered
 *    from 0 to size-1.
 */
#define BITMAP_DECLARE(name, size)                                      \
    uint32_t name[((size) >> 5) + ((((size) & 0x1F) == 0) ? 0 : 1)]

/**
 *  BITMAP_INIT(name);
 *
 *    Clears all the bits in the bitmap named 'name'.  This macro must
 *    appear in the same scope as the BITMAP_DECLARE() macro.
 */
#define BITMAP_INIT(name) memset(&name, 0, sizeof(name))

/**
 *  BITMAP_SETBIT(name, pos);
 *  BITMAP_CLEARBIT(name, pos);
 *  is_set = BITMAP_GETBIT(name, pos);
 *
 *    Set, clear, or get the bit as position 'pos' in bitmap 'name'.
 */
#define BITMAP_SETBIT(name, pos)                        \
    ((name)[_BMAP_INDEX(pos)] |= _BMAP_OFFSET(pos))
#define BITMAP_CLEARBIT(name, pos)                      \
    ((name)[_BMAP_INDEX(pos)] &= ~_BMAP_OFFSET(pos))
#define BITMAP_GETBIT(name, pos)                                \
    (((name)[_BMAP_INDEX(pos)] & _BMAP_OFFSET(pos)) ? 1 : 0)


/*
**
**    sku-app.c
**
*/

/**
 *    The null message function.  Does nothing and returns zero.
 */
int
skMsgNone(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);

/**
 *    The null message function.  Does nothing and returns zero.
 */
int
skMsgNoneV(
    const char         *fmt,
    va_list             args)
    SK_CHECK_PRINTF(1, 0);

/**
 *    Register the application.  Other functions below assume you've
 *    passed argv[0] as the value of 'name'.
 */
void
skAppRegister(
    const char         *name);

/**
 *    Destroy all data structures and free all memory associated with
 *    this application.
 */
void
skAppUnregister(
    void);

/**
 *    Return the name that was used to register the application.  This
 *    is the value that was passed to skAppRegister().  The return
 *    value should be considered read-only.
 */
const char *
skAppRegisteredName(
    void);

/**
 *    Return a short name for the application.  This is the basename
 *    of the registered name.  The return value should be considered
 *    read-only.
 */
const char *
skAppName(
    void);

/**
 *    Return the full path to application.  This will consult the PATH
 *    envar and cgetcwd() to find the complete path to the
 *    application.  The return value should be considered read-only.
 */
const char *
skAppFullPathname(
    void);

/**
 *    Return the application's directory's parent directory in 'buf',
 *    a character array of 'buf_len' bytes. e.g., if the rwfilter
 *    application lives in "/usr/local/bin/rwfilter", this function
 *    puts "/usr/local" into buf.  Return value is a pointer to 'buf',
 *    or NULL on error.
 */
char *
skAppDirParentDir(
    char               *buf,
    size_t              buf_len);

/**
 *    Print short usage information---telling the user to use the
 *    ``--help'' option---to stderr and exit the application with a
 *    FAILURE exit status.
 */
void
skAppUsage(
    void)
    NORETURN;

/**
 *    Print, to the 'fh' file handle, the current application's name,
 *    the 'usage_msg', each option in 'app_options' and its 'app_help'
 *    string.  Returns control to the application.
 */
void
skAppStandardUsage(
    FILE                   *fh,
    const char             *usage_msg,
    const struct option    *app_options,
    const char            **app_help);

/**
 *    Structure used to verify that a SiLK library was compiled with
 *    the same set of features that were used to build the
 *    application.
 */
typedef struct silk_features_st {
    uint64_t struct_version;
    uint8_t  big_endian;
    uint8_t  enable_ipv6;
    uint8_t  enable_gnutls;
    uint8_t  enable_ipfix;
    uint8_t  enable_localtime;
} silk_features_t;

#define SILK_FEATURES_DEFINE_STRUCT(var_name)   \
    const silk_features_t var_name = {          \
        2,                                      \
        SK_BIG_ENDIAN,                          \
        SK_ENABLE_IPV6,                         \
        SK_ENABLE_GNUTLS,                       \
        SK_ENABLE_IPFIX,                        \
        SK_ENABLE_LOCALTIME                     \
    }

/**
 *    Verify that the features that were compiled into the application
 *    agree with those that were compiled into the libsilk library.
 *
 *    Currently 'future_use' is unused, but is included for possible
 *    future expansion.
 */
void
skAppVerifyFeatures(
    const silk_features_t  *features,
    void                   *future_use);

/**
 *    Sets the error stream to 'f' for any messages printed with
 *    skAppPrintErrV() or skAppUsage().  When 'f' is NULL, calling
 *    skAppPrintErr(), skAppPrintErrV(), and skAppUsage() will result
 *    in no output being generated.
 *
 *    Returns the previous value of the error-stream.
 */
FILE *
skAppSetErrStream(
    FILE               *f);

/**
 *    Sets the function that skAppPrintErr() will call to print its
 *    arguments.  If 'fn' is NULL, resets skAppPrintErr() to use its
 *    default function, which is skAppPrintErrV().  To disable
 *    printing of errors, pass 'skMsgNoneV' to this function.
 */
void
skAppSetFuncPrintErr(
    sk_msg_vargs_fn_t   fn);

/**
 *    Sets the function that skAppPrintSyserror() will call to print
 *    its arguments.  If 'fn' is NULL, resets skAppPrintSyserror() to
 *    use its default function, which is skAppPrintSyserrorV().  To
 *    disable printing of errors, pass 'skMsgNoneV' to this function.
 */
void
skAppSetFuncPrintSyserror(
    sk_msg_vargs_fn_t   fn);

/**
 *    Sets the function that skAppPrintAbortMsg(),
 *    skAppPrintBadCaseMsg(), and skAppPrintOutOfMemoryMsgFunction()
 *    will call to print their arguments.  If 'fn' is NULL, resets the
 *    functions to use the default function, which is skAppPrintErr().
 *    To disable printing of errors, pass 'skMsgNone' to this
 *    function.
 */
void
skAppSetFuncPrintFatalErr(
    sk_msg_fn_t         fn);

/**
 *    Prints the application name, a colon, the result of formatting
 *    the arguments using v*printf(), and a newline to the stream set
 *    by skAppSetErrStream(), which defaults to stderr.
 *
 *    This is the default function used by skAppPrintErr() to print
 *    error messages.
 */
int
skAppPrintErrV(
    const char         *fmt,
    va_list             args);

/**
 *    Prints the application name, a colon, the result of formatting
 *    the arguments using v*printf(), the result of calling
 *    strerror(), and a newline to the stream set by
 *    skAppSetErrStream(), which defaults to stderr.
 *
 *    This is the default function used by skAppPrintSyserror() to
 *    print system error messages.
 */
int
skAppPrintSyserrorV(
    const char         *fmt,
    va_list             args);


#ifdef TEST_PRINTF_FORMATS
#define skAppPrintErr printf
#else
/**
 *    Calls the function set by skAppSetFuncPrintErr()---which has the
 *    default value skAppPrintErrV()---to format and print the
 *    arguments using the given format 'fmt'.
 */
int
skAppPrintErr(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
#endif


#ifdef TEST_PRINTF_FORMATS
#define skAppPrintSyserror printf
#else
/**
 *    Calls the function set by skAppSetFuncPrintSyserror()---which
 *    has the default value skAppPrintSyserrorV()---to format and
 *    print the arguments using the given format 'fmt'.
 */
int
skAppPrintSyserror(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);
#endif


/**
 *    Prints a message to the standard error.  This function appends a
 *    final newline to the output.  This function may used by
 *    TRACEMSG(), see sktracemsg.h.
 */
int
skTraceMsg(
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(1, 2);


/**
 *    Install the function 'sig_handler' to be called whenever the
 *    application receives a SIGINT, SIGTERM, SIGQUIT, or SIGPIPE.
 *
 *    The parameter passed to 'sig_handler' will be the received
 *    signal.
 *
 *    Return 0 on success, or -1 if the handler cannot be installed.
 */
int
skAppSetSignalHandler(
    void              (*sig_handler)(int signal));


/**
 *    Use skAbort() to call this function.
 *
 *    skAbort() is a macro defined in silk.h that calls this function
 *    with the current function name (if the compiler supports it),
 *    filename, and line number macros.  Once this function returns,
 *    the skAbort() macro calls abort().
 *
 *    This function will call the function specified by
 *    skAppSetFuncPrintFatalErr() to print a message containing the
 *    specified 'func_name', 'file_name' and 'line_number' values.
 *    This function will return.  It is the caller's responsibility to
 *    call abort().
 */
void
skAppPrintAbortMsg(
    const char         *func_name,
    const char         *file_name,
    int                 line_number);


/**
 *    Use skAbortBadCase(case_expr) to call this function.
 *
 *    skAbortBadCase() is a macro defined in silk.h that calls this
 *    function with the current function name (if the compiler
 *    supports it), filename, line number macros, the value of
 *    'case_expr' as an int64_t and the stringification of
 *    'case_expr'.  Once this function returns, the skAbortBadCase()
 *    macro calls abort().
 *
 *    This function will call the function specified by
 *    skAppSetFuncPrintFatalErr() to print an appropriate message
 *    regarding switch(value_expr) getting an unexpected value.  This
 *    function will return.  It is the caller's responsibility to call
 *    abort().
 */
void
skAppPrintBadCaseMsg(
    const char         *func_name,
    const char         *file_name,
    int                 line_number,
    int64_t             value,
    const char         *value_expr);


#ifdef SK_HAVE_C99___FUNC__
#define skAppPrintOutOfMemory(oom_string)                                  \
    skAppPrintOutOfMemoryMsgFunction(__func__, __FILE__, __LINE__, oom_string)
#else
#define skAppPrintOutOfMemory(oom_string)                                  \
    skAppPrintOutOfMemoryMsgFunction(NULL, __FILE__, __LINE__, oom_string)
#endif


/**
 *    Use skAppPrintOutOfMemory("object_name") to call this function.
 *
 *    skAppPrintOutOfMemory() is a macro defined above that calls this
 *    function with the current function name (if the compiler
 *    supports it), filename, line number macros, the value for
 *    'object_name'.
 *
 *    This function will call the function specified by
 *    skAppSetFuncPrintFatalErr() to print a message about being out
 *    of memory and unable to allocate 'object_name'.  'object_name'
 *    may be NULL.  This function will return.  It is the caller's
 *    responsibility to exit the program.
 */
void
skAppPrintOutOfMemoryMsgFunction(
    const char         *func_name,
    const char         *file_name,
    int                 line_number,
    const char         *object_name);


/*
**
**    sku-options.c
**
*/

/*
 *    Values to specify for the 'has_arg' member of struct option when
 *    calling skOptionsRegister().
 */
#define NO_ARG          0
#define REQUIRED_ARG    1
#define OPTIONAL_ARG    2


/**
 *    Macro that converts the preceeding values to a string; used when
 *    printing usage (--help) information.  The paraemter to the macro
 *    is a struct option.
 */
#define SK_OPTION_HAS_ARG(struct_option_st)             \
    (((struct_option_st).has_arg == REQUIRED_ARG)       \
     ? "Req Arg"                                        \
     : (((struct_option_st).has_arg == OPTIONAL_ARG)    \
        ? "Opt Arg"                                     \
        : (((struct_option_st).has_arg == NO_ARG)       \
           ? "No Arg"                                   \
           : "BAD 'has_arg' VALUE")))

/**
 *    Callback data type for the options handler function.
 */
typedef void   *clientData;

/**
 *    Signature of the options handler callback function to pass to
 *    skOptionsRegister().  An options handler function is invoked by
 *    skOptionsParse() for each command line switch.
 *
 *    'cData' is user callback data that was supplied to
 *    'skOptionsRegister().  The 'optIndex' parameter is set to the
 *    value of the 'val' member of the struct option structure for the
 *    option.  'optArg' is the user's argument to the command line
 *    switch, or NULL if the user provided no switch.
 *
 *    The options handler should return 0 on success, or non-zero if
 *    there was a problem processing the option.  A non-zero return
 *    value causes options parsing to stop.
 */
typedef int (*optHandler)(
    clientData  cData,
    int         optIndex,
    char       *optArg);

/**
 *    Signature of callback functions invoked when the --help or
 *    --version switches are seen.
 */
typedef void  (*usage_fn_t)(
    void);

/**
 *    Register command line switches (options) with the global options
 *    handler.  The paramter 'options' specifies the switches to
 *    register as an array of:
 *
 *        struct option {
 *            char   *name;
 *            int     has_arg;
 *            int    *flag;
 *            int     val;
 *        };
 *
 *    where 'name' is the switch name (without the preceeding
 *    hyphens), 'has_arg' is one of NO_ARG, REQUIRED_ARG, OPTIONAL_ARG
 *    depending on whether the switch requires an argument, 'flag'
 *    should always be 0, and 'val' is a user-supplied value that gets
 *    passed as the 'optIndex' parameter of the options handler
 *    callback.
 *
 *    Processing of the 'options' array stops once a NULL value for
 *    'name' is found or once 'max_options' elements of the 'options'
 *    array have been processed, whichever occurs first.  A
 *    'max_options' value of 0 is equivalent to no limit.
 *
 *    The 'handler' function is the callback function to invoke when
 *    the option is seen on the command line.
 *
 *    The 'cData' parameter is a caller maintained pointer will be
 *    supplied to the handler function.  skOptionsRegisterCount() does
 *    not use this value.  It may be NULL.
 */
int
skOptionsRegisterCount(
    const struct option    *options,
    size_t                  max_options,
    optHandler              handler,
    clientData              cData);

/**
 *    A wrapper for skOptionsRegisterCount() that calls that function
 *    with 0 for the 'max_options' parameter.
 */
int
skOptionsRegister(
    const struct option    *options,
    optHandler              handler,
    clientData              cData);

/**
 *    Prepare the application to process options.
 *
 *    Application writers do not need to call this function as it is
 *    called by skAppRegister().
 */
void
skOptionsSetup(
    void);

/**
 *    Free all memory associated with options processing.
 *
 *    Application writers do not need to call this function as it is
 *    called by skAppUnregister().
 */
void
skOptionsTeardown(
    void);

/**
 *    Register the function 'help_fn' as the function the appliction
 *    will invoke when the user runs the application with the --help
 *    option.  If not specified, no output is produced by --help.
 *
 *    This function should print its results to the stdout.
 *
 *    It is recommended that this function print a brief summary of
 *    the purpose of the application, and then print every switch the
 *    function accepts.  The skAppStandardUsage() function can be used
 *    to print much of this information.
 */
void
skOptionsSetUsageCallback(
    usage_fn_t          help_fn);

/**
 *    Register the function 'version_fn' as the function the
 *    application will invoke when the user runs the application with
 *    the --version option.  If not specified, information about the
 *    version of libsilk that the application is using will be
 *    printed.
 *
 *    This function should print its results to the stdout.
 *
 *    It is recommended that this function print information about how
 *    the application was compiled and the license(s) that the
 *    application is released under.
 */
void
skOptionsSetVersionCallback(
    usage_fn_t          version_fn);

/**
 *    Print usage information about the default options that all
 *    applications support (namely --help and --version) to the named
 *    file handle.
 */
void
skOptionsDefaultUsage(
    FILE               *fh);


#ifndef SK_SUPPORT_CONF_FILE
#  define SK_SUPPORT_CONF_FILE 0
#endif
#if  SK_SUPPORT_CONF_FILE
/**
 * optionsHandleConfFile:
 *
 *     Loads a configuration file.  The configuration file consists of
 *     a series of newline-terminated lines.  A line consisting of
 *     only whitespace, or whose first non-whitespace character is a
 *     `#' character is ignored.  All other lines should consist of a
 *     single option name followed by the option's value (if any),
 *     separated by whitespace.  Whitespace at the beginning and end
 *     of the line is ignored.
 *
 * BUGS:
 *     If you intersperse switches (options) and arguments, arguments
 *     before the configuration file is parsed will not be seen.
 *
 *  Return:
 *      0 if ok. -1 else
 */
int
optionsHandleConfFile(
    char               *filename);
#endif  /* SK_SUPPORT_CONF_FILE */


/**
 *  skOptionsParse:
 *      Adjust the global options array to allow for the help
 *      option. If help is selected by the user, call the stashed
 *      usageFunction.  Parse input options given a set of
 *      pre-registered options and their handlers.  For each
 *      legitimate option, call the handler.
 *  SideEffects:
 *      The individual handlers update whatever datastruture they wish
 *      to via the clientData argument to the handler.
 *  Return:
 *      optind which points at the first non-option argument passed if
 *      all is OK.  If not OK, the return -1 for error.
 */
int
skOptionsParse(
    int                 argc,
    char              **argv);


/**
 *    Verify that the directory in 'dirname' exists, that the length
 *    is shorter than PATH_MAX, and that we have a full path to the
 *    directory.  If so, return 0; otherwise, print an error that the
 *    option named by 'option_name' was bad and return -1.
 */
int
skOptionsCheckDirectory(
    const char         *dirname,
    const char         *option_name);


/**
 *    Return the length of the shortest unique prefix required to
 *    match the option whose complete name is 'option_name'.  Return
 *    -1 if option_name is NULL, empty, or if no options have the name
 *    'option_name'.
 */
int
skOptionsGetShortestPrefix(
    const char         *option_name);


/**
 *    Registers a --temp-directory switch for the application.  Use
 *    skOptionsTempDirUsage() to print the usage for this switch.
 *
 *    The parameter 'var_location' must be specified.  The variable at
 *    that location will be set to the location the user provides in
 *    the --temp-directory switch.
 *
 *    The variable at 'var_location' is only modified if the user
 *    specifies the --temp-directory switch,
 */
int
skOptionsTempDirRegister(
    const char        **var_location);

/**
 *    Print the usage information for the --temp-directory switch.
 */
void
skOptionsTempDirUsage(
    FILE               *fh);


/**
 *    Registers an --ip-format switch for the application that allows
 *    the user to specify how IP addresses will be displayed.
 *
 *    The parameter 'var_location' must be specified.  The variable at
 *    that location will be set to the value the user specifies in the
 *    various switches.  This value will be one of the values defined
 *    in skipaddr_flags_t (see silk_types.h).
 *
 *    Use skOptionsIPFormatUsage() to print the usage for these
 *    switches.
 *
 *    The 'settings' parameter registers additional switches.
 *
 *    When SK_OPTION_IP_FORMAT_INTEGER_IPS is specified, an
 *    --integer-ips switch is also registered.
 *
 *    When SK_OPTION_IP_FORMAT_ZERO_PAD_IPS is specified, a
 *    --zero-pad-ips switch is also registered.
 *
 *    When SK_OPTION_IP_FORMAT_UNMAP_V6 is specified, unmap-v6
 *    (SKIPADDR_UNMAP_V6) is automatically added to the default IP
 *    format and to the result of parsing the --ip-format switch
 *    unless that format specifies map-v4 explicitly or the output
 *    format is decimal or hexadecimal.
 *
 *    The variable at 'var_location' is only modified if the user
 *    specifies the --ip-format switch.
 *
 *    If the SILK_IP_FORMAT environment variable is set, the value in
 *    'var_location' is initialized with the result of parsing that
 *    variable's value as if it was an argument to the --ip-format
 *    switch.
 *
 *    The 'settings' parameter was added in SiLK 3.15.0.
 */
int
skOptionsIPFormatRegister(
    uint32_t           *var_location,
    uint32_t            settings);

/**
 *    Print the usage information for the switches registered by
 *    skOptionsIPFormatRegister() to the stream 'fp'.
 */
void
skOptionsIPFormatUsage(
    FILE               *fp);

/**
 *    A bit to include in the 'settings' argument to
 *    skOptionsIPFormatRegister() that indicates an --integer-ips
 *    switch should be included.  Since SiLK 3.15.0.
 */
#define SK_OPTION_IP_FORMAT_INTEGER_IPS     (1u << 0)

/**
 *    A bit to include in the 'settings' argument to
 *    skOptionsIPFormatRegister() that indicates an --zero-pad-ips
 *    switch should be included.  Since SiLK 3.15.0.
 */
#define SK_OPTION_IP_FORMAT_ZERO_PAD_IPS    (1u << 1)

/**
 *    A bit to include in the 'settings' argument to
 *    skOptionsIPFormatRegister() that causes SKIPADDR_UNMAP_V6
 *    (unmap-v6) to be automatically added to the default IP format
 *    and to the result of parsing the --ip-format switch unless that
 *    format specifies map-v4 explicitly or the output format is
 *    decimal or hexadecimal.  Since SiLK 3.17.0.
 */
#define SK_OPTION_IP_FORMAT_UNMAP_V6        (1u << 2)


/**
 *    Registers a --timestamp-format switch for the application that
 *    allows the user to specify how timestamps will be displayed.
 *
 *    The parameter 'var_location' must be specified.  The variable at
 *    that location will be set to the value the user specifies in the
 *    various switches.  This value includes one or more of the values
 *    defined in sktimestamp_flags_t.
 *
 *    Use skOptionsIPFormatUsage() to print the usage for these
 *    switches.
 *
 *    The 'settings' changes the behavior of the --timestamp-format
 *    switch or registers additional switches.
 *
 *    When SK_OPTION_TIMESTAMP_NEVER_MSEC is specified, the parameter
 *    in 'var_location' always has the SKTIMESTAMP_NOMSEC bit set and
 *    --timestamp-format does not support 'no-msec'.
 *
 *    When SK_OPTION_TIMESTAMP_ALWAYS_MSEC is specified, the parameter
 *    in 'var_location' never has the SKTIMESTAMP_NOMSEC bit set and
 *    --timestamp-format does not support 'no-msec'.
 *
 *    When SK_OPTION_TIMESTAMP_OPTION_LEGACY is specified, a
 *    --legacy-timestamps switch is also registered.
 *
 *    When SK_OPTION_TIMESTAMP_OPTION_EPOCH is specified, an
 *    --epoch-timestamps switch is also registered.
 *
 *    When SK_OPTION_TIMESTAMP_OPTION_EPOCH_NAME is specified, the
 *    first string in the variable options is used as the name of a
 *    switch that has the same effect as '--epoch-timestamps'.
 *
 *    If the SILK_TIMESTAMP_FORMAT environment variable is set, the
 *    value in 'var_location' is initialized with the result of
 *    parsing that variable's value as if it was an argument to the
 *    --timestamp-format switch.
 *
 *    Since SiLK 3.11.0.
 */
int
skOptionsTimestampFormatRegister(
    uint32_t           *var_location,
    uint32_t            settings,
    ...);

/**
 *    Print the usage information for the switches registered by
 *    skOptionsTimestampFormatRegister() to the stream 'fp'.
 *
 *    Since SiLK 3.11.0.
 */
void
skOptionsTimestampFormatUsage(
    FILE               *fp);


/**
 *    A bit to include in the 'settings' argument to
 *    skOptionsTimestampFormatRegister() that indicates the
 *    application does not support fractional seconds.  The
 *    SKTIMESTAMP_NOMSEC flag is always set on the result, and
 *    "no-msec" is not allowed in --timestamp-format.
 */
#define SK_OPTION_TIMESTAMP_NEVER_MSEC          (1u << 0)

/**
 *    A bit to include in the 'settings' argument to
 *    skOptionsTimestampFormatRegister() that indicates the
 *    application only supports fractional seconds.  The "no-msec"
 *    is not allowed in --timestamp-format.
 */
#define SK_OPTION_TIMESTAMP_ALWAYS_MSEC         (1u << 1)

/**
 *    A bit to include in the 'settings' argument to
 *    skOptionsTimestampFormatRegister() that indicates an
 *    --epoch-time switch should be included.
 */
#define SK_OPTION_TIMESTAMP_OPTION_EPOCH        (1u << 2)

/**
 *    Similar to SK_OPTION_TIMESTAMP_OPTION_EPOCH except this
 *    indicates the name for the switch is included as one of the
 *    var-args values.  This takes precedence when
 *    SK_OPTION_TIMESTAMP_OPTION_EPOCH is also specified.
 */
#define SK_OPTION_TIMESTAMP_OPTION_EPOCH_NAME   (1u << 3)

/**
 *    A bit to include in the 'settings' argument to
 *    skOptionsTimestampFormatRegister() that indicates a
 *    --legacy-timestamps switch should be included.
 */
#define SK_OPTION_TIMESTAMP_OPTION_LEGACY       (1u << 4)



/*
**
**    skoptionsctx.c
**
*/

/**
 *    The sk_options_ctx_t structure provides a way to process
 *    non-switches command line arguments, such as input file names.
 *
 *    The sk_options_ctx_t also allows an application to register
 *    common options.
 *
 *    The normal usage pattern is:
 *
 *        skOptionsCtxCreate()
 *        skOptionsCtxOptionsRegister()
 *        skOptionsCtxOptionsParse()
 *        // use one of these two while() loops
 *        while (0==skOptionsCtxNextSilkFile()) {
 *            // process file
 *        }
 *        while (0==skOptionsCtxNextArgument()) {
 *            // process argument
 *        }
 *        skOptionsCtxDestroy()
 *
 *    TO DO: Should support for --output-path and --pager be added
 *    here as well?
 */
typedef struct sk_options_ctx_st sk_options_ctx_t;

/*
 *    The following are values to be ORed together to form the 'flags'
 *    argument to skOptionsCtxCreate().
 */
#define SK_OPTIONS_CTX_PRINT_FILENAMES  (1u <<  0)
#define SK_OPTIONS_CTX_COPY_INPUT       (1u <<  1)
#define SK_OPTIONS_CTX_ALLOW_STDIN      (1u <<  2)
#define SK_OPTIONS_CTX_XARGS            (1u <<  3)
#define SK_OPTIONS_CTX_INPUT_SILK_FLOW  (1u <<  4)
#define SK_OPTIONS_CTX_INPUT_BINARY     (1u <<  5)
#define SK_OPTIONS_CTX_INPUT_PIPE       (1u << 30)
#define SK_OPTIONS_CTX_SWITCHES_ONLY    (1u << 31)


/**
 *    When the --copy-input switch has been used, this function will
 *    close the copy input destination.  Return 0 if the --copy-input
 *    switch was not used, or the status of closing the stream.
 */
int
skOptionsCtxCopyStreamClose(
    sk_options_ctx_t   *arg_ctx,
    sk_msg_fn_t         err_fn);

/**
 *    When the --copy-input switch has been used, this function will
 *    return 1.  Otherwise, the function will return 0.
 */
int
skOptionsCtxCopyStreamIsActive(
    const sk_options_ctx_t *arg_ctx);

/**
 *    When the --copy-input switch has been used, this function will
 *    return 1 if the stream is bound to the standard output.  Return
 *    1 if the --copy-input stream is not used or is not bound to
 *    stdout.
 */
int
skOptionsCtxCopyStreamIsStdout(
    const sk_options_ctx_t *arg_ctx);

/**
 *    Return the number of unprocessed arguments specified on the
 *    command line.
 */
int
skOptionsCtxCountArgs(
    const sk_options_ctx_t *arg_ctx);

/**
 *    Create the options context object.  Return 0 on success or
 *    non-zero on allocation error or for inconsistent 'flags' values.
 *
 *    'flags' is an OR of:
 *
 *    SK_OPTIONS_CTX_PRINT_FILENAMES -- Cause a --print-filenames
 *    switch to be registered and, when the switch is specified, have
 *    skOptionsCtxNextSilkFile() print the filenames as the files are
 *    opened.
 *
 *    SK_OPTIONS_CTX_COPY_INPUT -- Cause a --copy-input switch to be
 *    registered and, when the switch is specified, have
 *    skOptionsCtxNextSilkFile() copy their records to the named file.
 *
 *    SK_OPTIONS_CTX_ALLOW_STDIN -- Have the application default to
 *    reading from the standard input when no other input is
 *    specified.
 *
 *    SK_OPTIONS_CTX_XARGS -- Cause a --xargs switch to be registered
 *    and, when the switch is specified, read the names of the input
 *    files from the named stream (or from the standard input when no
 *    argument is give to the switch).
 *
 *    SK_OPTIONS_CTX_INPUT_SILK_FLOW -- Whether the input to the
 *    application is SiLK Flow records.  When set, prevents the
 *    application from reading from standard input when standard input
 *    is connected to a terminal.  Implies SK_OPTIONS_CTX_INPUT_BINARY
 *
 *    SK_OPTIONS_CTX_INPUT_BINARY -- Whether the input to the
 *    application is binary.  When set, prevents the application from
 *    reading from standard input when standard input is connected to
 *    a terminal.
 *
 *    SK_OPTIONS_CTX_INPUT_PIPE -- Cause an --input-pipe switch to be
 *    registered and, when the switch is specified, read input from
 *    the file, stream, or pipe.
 *
 *    SK_OPTIONS_CTX_SWITCHES_ONLY -- Cause the application to
 *    complain when any non-switched argument appears on the command
 *    line.
 */
int
skOptionsCtxCreate(
    sk_options_ctx_t  **arg_ctx,
    unsigned int        flags);

/**
 *    Destroy the options context object.  If the copy-input stream
 *    has not been closed yet, this function closes it.  Returns the
 *    status of closing the copy-input stream, or 0.  Does nothing and
 *    returns 0 if 'arg_ctx' or the location it points to is NULL.
 */
int
skOptionsCtxDestroy(
    sk_options_ctx_t  **arg_ctx);

/**
 *    When --print-filenames has been specified, return the file
 *    handle to which the file names are being printed.  If
 *    --print-filenames has not been specified, this function returns
 *    NULL.
 */
FILE *
skOptionsCtxGetPrintFilenames(
    const sk_options_ctx_t *arg_ctx);

/**
 *    Set the value in 'arg' to point to the next input.  Return 0 if
 *    there is more input, 1 if there is no more input, or -1 when
 *    getting input from --xargs and there is a read error.  The
 *    caller should not modify the value in 'arg'; calling this
 *    function may invalidate any previous 'arg' value.
 *
 *    Depending on the value of 'flags' when the context was created,
 *    the next argument may be (1)the value specified to the
 *    --input-pipe switch, (2)a name read from --xargs, (3)a file
 *    listed on the command line, (4)the value "-" for the standard
 *    input.
 */
int
skOptionsCtxNextArgument(
    sk_options_ctx_t   *arg_ctx,
    char              **arg);

/**
 *    A wrapper for skOptionsCtxNextArgument() that treats the string
 *    as a file name and attempts to open it as a SiLK Flow file.
 *    Return 0 on success, 1 if no more files, or -1 on error.  When
 *    'err_fn' is specified, any error opening a file is reported
 *    using that function.
 *
 *    If the skOptionsCtxSetOpenCallback() function was used to set a
 *    callback function, that function will be called with the stream
 *    as an argument.  If the callback returns 0, the stream is
 *    returned to the caller.  If the callback returns 1, the stream
 *    is skipped.  If the callback returns -1, the processing of all
 *    input stops.
 *
 *    The function will print the name of the file if
 *    --print-filenames was specified.  Will set the SiLK flow records
 *    to be copied to the --copy-input stream.
 */
int
skOptionsCtxNextSilkFile(
    sk_options_ctx_t   *arg_ctx,
    skstream_t        **stream,
    sk_msg_fn_t         err_fn);

typedef int (*sk_options_ctx_open_cb_t)(
    skstream_t *stream);


/**
 *    Specify a callback for skOptionsCtxNextSilkFile().
 */
void
skOptionsCtxSetOpenCallback(
    sk_options_ctx_t           *arg_ctx,
    sk_options_ctx_open_cb_t    open_callback_fn);

/**
 *    Call skOptionsParse() and arrange for any non-switched arguments
 *    to be handled by the options context.  Return 0 on success, or
 *    non-zero on options parsing error or if input files/streams are
 *    required and are not available.
 */
int
skOptionsCtxOptionsParse(
    sk_options_ctx_t   *arg_ctx,
    int                 argc,
    char              **argv);

/**
 *    Depending on the value of 'flags' specified when the context was
 *    created, register options with the global options handler.
 */
int
skOptionsCtxOptionsRegister(
    const sk_options_ctx_t *arg_ctx);

/**
 *    Print usage information according to flags specified when the
 *    context was created.
 */
void
skOptionsCtxOptionsUsage(
    const sk_options_ctx_t *arg_ctx,
    FILE                   *fh);

/**
 *    Open the --copy-input stream and/or --xargs stream as
 *    appropriate.  If an error occurs, print the error using the
 *    'err_fn' if it in not NULL.
 */
int
skOptionsCtxOpenStreams(
    sk_options_ctx_t   *arg_ctx,
    sk_msg_fn_t         err_fn);


/*
**
**    skqsort.c
**
*/

/**
 *    Perform a quicksort on the elements in 'buffer', where each
 *    element is 'element_size' octets and 'buffer' contains
 *    'number_elements' such elements.
 *
 *    The elements in 'buffer' will be sorted in assending order
 *    according to the comparison function 'cmp'.  'cmp' will be
 *    handed pointers to two elements in the buffer, and it must
 *    return a value less than, equal to, or greater than zero if the
 *    first element is less than, equal to, or greater than the
 *    second.
 */
void
skQSort(
    void               *buffer,
    size_t              number_elements,
    size_t              element_size,
    int               (*cmp)(const void *a, const void *b));

/**
 *    Perform the same quicksort operation as skQSort().  This
 *    function takes a context object 'thunk' which the function
 *    passes as the third argument to the comparison function 'cmp'.
 */
void
skQSort_r(
    void               *buffer,
    size_t              number_elements,
    size_t              element_size,
    int               (*cmp)(const void *a, const void *b, void *thunk),
    void               *thunk);


/*
**
**    skoptions-notes.c
**
*/


int
skOptionsNotesRegister(
    int                *note_strip);

void
skOptionsNotesTeardown(
    void);

void
skOptionsNotesUsage(
    FILE               *fh);

int
skOptionsNotesAddToStream(
    skstream_t         *stream);



/*
**
**    sku-times.c
**
*/


/**
 *    Flags that can be use to specify how a timestamp will be
 *    printed.
 */
typedef enum {
    /** Do not include fractional seconds when printing the time */
    SKTIMESTAMP_NOMSEC   = (1u << 0),
    /** Print as MM/DD/YYYY HH:MM:SS[.sss] */
    SKTIMESTAMP_MMDDYYYY = (1u << 1),
    /** Print as seconds since the UNIX epoch */
    SKTIMESTAMP_EPOCH    = (1u << 2),
    /** Print as YYYY-MM-DD HH:MM:SS[.sss] */
    SKTIMESTAMP_ISO      = (1u << 3),
    /** Print the time as UTC (assuming TZ=0) */
    SKTIMESTAMP_UTC      = (1u << 4),
    /** Print the time in the local timezone */
    SKTIMESTAMP_LOCAL    = (1u << 5)
} sktimestamp_flags_t;

/**
 *    Fill 'outbuf' with an ASCII version of the time 't' and return a
 *    pointer to 'output'.  This function assumes that 'outbuf' is at
 *    least SKTIMESTAMP_STRLEN characters long.  SKTIMESTAMP_STRLEN is
 *    defined in silk_types.h.
 *
 *    By default, the timestamp will be in the form:
 *
 *        "YYYY/MM/DDTHH:MM:SS.sss"
 *
 *    where "sss" == milliseconds, the "T" is a literal 'T'.
 *
 *    The parameter 'timestamp_flags' can be used to change the
 *    printed time, where the flags are a bitwise OR of the
 *    sktimestamp_flags_t values.
 *
 *    The following fields for 'timestamp_flags' are mutually
 *    exclusive; if more than one is set, the time is printed in the
 *    default form (and the SKTIMESTAMP_NOMSEC bit is ignored):
 *
 *        SKTIMESTAMP_EPOCH prints the value as the number of seconds
 *        since the UNIX epoch.  The timezone bits are ignored.
 *
 *            "SSSSSSSSSS[.sss]"
 *
 *        SKTIMESTAMP_MMDDYYYY causes the time to be printed as:
 *
 *            "MM/DD/YYYY HH:MM:SS[.sss]"
 *
 *        SKTIMESTAMP_ISO causes the time to be printed as
 *
 *            "YYYY-MM-DD HH:MM:SS[.sss]"
 *
 *    The following bit operates independently of any other bits:
 *
 *        SKTIMESTAMP_NOMSEC suppresses the printing of the
 *        milliseconds.  The milliseconds value is dropped and the
 *        remaining value is NOT rounded.
 *
 *    The 'timestamp_flags' value can affect the timezone used when
 *    printing the time.  If neither (or both) of the following bits
 *    are set, the time is printed in UTC unless SiLK was configured
 *    with --enable-local-timezone, in which case the local timezone
 *    is used.
 *
 *        SKTIMESTAMP_UTC causes the value to be printed in UTC,
 *        regardless of whether SiLK was configured with the
 *        --enable-local-timezone switch.
 *
 *        SKTIMESTAMP_LOCAL causes the value to be printed in the
 *        local timezone, regardless of whether SiLK was configured
 *        with the --enable-local-timezone switch.
 */
char *
sktimestamp_r(
    char               *outbuf,
    sktime_t            t,
    unsigned int        timestamp_flags);


/**
 *    Similar to sktimestamp_r(), except returns the value in a static
 *    buffer.
 */
char *
sktimestamp(
    sktime_t            t,
    unsigned int        timestamp_flags);


/**
 *    Return the maximum day in a given month/year
 *
 *    NOTE:  Months are in the 1..12 range and NOT 0..11
 *
 */
int
skGetMaxDayInMonth(
    int                 yr,
    int                 mo);


/**
 *    Return an sktime set to the current UTC time to millisecond
 *    precision.
 */
sktime_t
sktimeNow(
    void);


/**
 *    Given a value containing seconds since the UNIX epoch (such as a
 *    time_t) and a millisecond count, return an sktime_t.  The second
 *    parameter can be any value containing milliseconds.  There is no
 *    restriction on the range of its value.
 */
#define sktimeCreate(sktc_seconds, sktc_milliseconds)                   \
    ((sktime_t)(INT64_C(1000) * (sktc_seconds) + (sktc_milliseconds)))


/**
 *    Given a pointer to a struct timeval, return an sktime_t
 */
#define sktimeCreateFromTimeval(sktc_tv)                                \
    sktimeCreate((sktc_tv)->tv_sec, ((sktc_tv)->tv_usec / 1000))


/**
 *    Given an sktime_t value, fill the locations referenced by
 *    'seconds' and 'milliseconds' with the number of seconds and
 *    milliseconds that the sktime_t value represents.
 */
#define sktimeGetParts(sktgp_time, sktgp_seconds, sktgp_milliseconds)   \
    do {                                                                \
        imaxdiv_t sktgp_d = imaxdiv((sktgp_time), INT64_C(1000));       \
        *(sktgp_seconds) = sktgp_d.quot;                                \
        *(sktgp_milliseconds) = sktgp_d.rem;                            \
    } while (0)


/**
 *    Given an sktime_t, return the number of seconds since the UNIX
 *    epoch as an integer.
 */
#define sktimeGetSeconds(sktgs_time)            \
    ((sktgs_time) / INT64_C(1000))


/**
 *    Given an sktime_t, return fractional seconds as an integer.
 */
#define sktimeGetMilliseconds(sktgm_time)       \
    ((sktgm_time) % INT64_C(1000))


/*
**
**    sku-bigsockbuf.c
**
*/

/**
 *    There is no portable way to determine the max send and receive
 *    buffers that can be set for a socket, so guess then decrement
 *    that guess by 2K until the call succeeds.  If n > 1MB then the
 *    decrement by .5MB instead.
 *
 *    Returns size or -1 for error
 */
int
skGrowSocketBuffer(
    int                 sock,
    int                 direction,
    int                 size);


/*
**
**    sku-filesys.c
**
*/

/**
 *    Strip directory prefix from the file path fp.  Returns a pointer
 *    to a static string buffer.
 */
char *
skBasename(
    const char         *fp);


/**
 *    Thread safe version of skBasename()
 */
char *
skBasename_r(
    char               *dest,
    const char         *src,
    size_t              dest_size);


/**
 *    Strip file name suffix from the file path fp.  Returns a pointer
 *    to a static string buffer.
 */
char *
skDirname(
    const char         *fp);


/**
 *    Thread safe version of skDirname()
 */
char *
skDirname_r(
    char               *dest,
    const char         *src,
    size_t              dest_size);


/**
 *    Returns 1 if the FILE* fd is a tty, 0 otherwise
 */
#define FILEIsATty(fd)          isatty(fileno(fd))


/**
 *    Return 1 if 'path_name' exists and is a FIFO.
 *
 *    Return 0 and set errno if calling stat() on 'path_name' fails.
 *
 *    Return 0 when stat() succeeds but 'path_name' is not a FIFO.
 *
 *    See also skFileExists().
 */
int
isFIFO(
    const char         *path_name);


/**
 *    Return 1 if 'path_name' exists and is a directory.
 *
 *    Return 0 and set errno if calling stat() on 'path_name' fails.
 *
 *    Return 0 when stat() succeeds but 'path_name' is not a
 *    directory.
 */
int
skDirExists(
    const char         *path_name);


/**
 *    Return 1 if 'path_name' exists and is either a regular file or a
 *    FIFO.
 *
 *    Return 0 and set errno if calling stat() on 'path_name' fails.
 *
 *    Return 0 when stat() succeeds but 'path_name' is neither a
 *    regular file nor a FIFO.
 *
 *    See also skDirExists() and isFIFO().
 */
int
skFileExists(
    const char         *path_name);


/**
 *    Return the size of 'path_name' if it exists.
 *
 *    Return 0 if 'path_name' exists and is an empty file.
 *
 *    Return 0 and set errno if calling stat() on 'path_name' fails.
 *
 *    See also skFileExists().
 */
off_t
skFileSize(
    const char         *path_name);


/**
 *    Perform a locking operation on the opened file represented by
 *    the file descriptor 'fd'.  'type' is the type of lock, it should
 *    be one of F_RDLCK for a read lock, F_WRLCK for a write lock, or
 *    F_UNLCK to unlock a previously locked file.  'cmd' should be one
 *    of F_SETLKW to wait indefinitely for a lock, or F_SETLK to
 *    return immediately.  Return 0 if successful, -1 otherwise.  Use
 *    errno to determine the error.
 */
int
skFileSetLock(
    int                 fd,
    short               type,
    int                 cmd);


/**
 *    Find the given file 'base_name' in one of several places:
 *
 *    -- If 'base_name' begins with a slash (/), copy it to 'buf'.
 *    -- See if the environment variable named by the cpp macro
 *       ENV_SILK_PATH (normally SILK_PATH) is defined.  If so, check
 *       for the file in:
 *         * $SILK_PATH/share/silk/file_name
 *         * $SILK_PATH/share/file_name
 *         * $SILK_PATH/file_name (for historical resaons)
 *    -- Take the full path to the application (/yadda/yadda/bin/app),
 *       lop off the app's immediate parent directory---which leaves
 *       /yadda/yadda---and check for the file in the:
 *         * "/share/silk" subdir (/yadda/yadda/share/silk/file_name)
 *         * "/share" subdir (/yadda/yadda/share/file_name)
 *
 *    If found---and if the total path is less than 'bufsize-1'
 *    characters---fills 'buf' with a full path to the file and
 *    returns a pointer to 'buf'.
 *
 *    If not found or if 'buf' is too small to hold the full path;
 *    returns NULL and leaves 'buf' in an unknown state.
 */
char *
skFindFile(
    const char         *base_name,
    char               *buf,
    size_t              bufsize,
    int                 verbose);


/**
 *    Attempt to find the named plug-in, 'dlPath', in one of several
 *    places.  If the function searches and finds the plug-in, it
 *    copies that location to the character array 'path'--whose
 *    caller-allocated size if 'path_len'---and returns 'path';
 *    otherwise return NULL.  This routine checks:
 *
 *    -- If 'dlPath' contains a slash, assume the path to plug-in is
 *       correct and return NULL.
 *    -- See if the environment variable named by the cpp macro
 *       ENV_SILK_PATH (normally SILK_PATH) is defined.  If so, check
 *       for the plug-in in the subdirectories of $SILK_PATH specified
 *       in the SILK_SUBDIR_PLUGINS macro, namely:
 *         * $SILK_PATH/lib/silk/dlPath
 *         * $SILK_PATH/share/lib/dlPath
 *         * $SILK_PATH/lib/dlPath
 *    -- Take the full path to the application "/yadda/yadda/bin/app",
 *       lop off the app's immediate parent directory--which leaves
 *       "/yadda/yadda", and check the SILK_SUBDIR_PLUGINS
 *       subdirectories:
 *         * "/lib/silk" subdir (/yadda/yadda/lib/silk/dlPath)
 *         * "/share/lib" subdir (/yadda/yadda/share/lib/dlPath)
 *         * "/lib" subdir (/yadda/yadda/lib/dlPath)
 *
 *    If 'verbose_prefix' is not NULL, the function uses
 *    skAppPrintErr() to print every pathname it checks, prefixing the
 *    pathname with the string in 'verbose_prefix'.
 *
 *    Return NULL if 'dlPath' was not found of if the search was not
 *    performed; otherwise return a char* which is the buffer passed
 *    into the subroutine.
 */
char *
skFindPluginPath(
    const char         *dlPath,
    char               *path,
    size_t              path_len,
    const char         *verbose_prefix);


/**
 *    Return values for the skFileptrOpen() function.  To get an error
 *    message for these values, pass the value to the
 *    skFileptrStrerror() function.
 */
typedef enum sk_fileptr_status_en {
    SK_FILEPTR_OK = 0,
    SK_FILEPTR_PAGER_IGNORED = 1,
    SK_FILEPTR_ERR_ERRNO = -1,
    SK_FILEPTR_ERR_POPEN = -2,
    SK_FILEPTR_ERR_WRITE_STDIN = -3,
    SK_FILEPTR_ERR_READ_STDOUT = -4,
    SK_FILEPTR_ERR_READ_STDERR = -5,
    SK_FILEPTR_ERR_TOO_LONG = -6,
    SK_FILEPTR_ERR_INVALID = -7
} sk_fileptr_status_t;


/**
 *    Values for the 'of_file_type' member of the sk_fileptr_t
 *    structure.
 */
typedef enum sk_fileptr_type_en {
    SK_FILEPTR_IS_STDIO, SK_FILEPTR_IS_FILE, SK_FILEPTR_IS_PROCESS
} sk_fileptr_type_t;


/**
 *    Structure to pass to skFileptrOpen() and skFileptrClose().  For
 *    skFileptrOpen(), the 'of_name' member must be non-NULL.  For
 *    skFileptrClose(), the 'of_fp' parameter should be non-NULL.
 */
typedef struct sk_fileptr_st {
    const char         *of_name;
    FILE               *of_fp;
    sk_fileptr_type_t of_type;
} sk_fileptr_t;

/**
 *    Open a file, process, or stream for reading, writing, or
 *    appending.  How the file or stream is opened is determined by
 *    the 'io_mode' parameter, which should be one of SK_IO_READ,
 *    SK_IO_WRITE, or SK_IO_APPEND.
 *
 *    The 'of_name' member of the 'file' structure must be non-NULL;
 *    if it is NULL, SK_FILEPTR_ERR_INVALID is returned.
 *
 *    When 'of_name' is '-' or the strings 'stdin', 'stdout', or
 *    'stderr', the 'of_fp' member is set to the appropriate standard
 *    stream and the 'of_type' value is set to SK_FILEPTR_IS_STDIO.
 *
 *    When 'of_name' ends in '.gz', skFileptrOpen() attempts to invoke
 *    the 'gzip' command to read from or write to the file.  On
 *    success, the 'of_fp' member is set the to process file handle
 *    and the 'of_type' member is set to SK_FILEPTR_IS_PROCESS.
 *
 *    Otherwise, the 'of_name' value is opened as a standard file,
 *    'of_fp' is set the file handle, and the 'of_type' member is set
 *    to SK_FILEPTR_IS_FILE.
 *
 *    The return status of this function is one of the values in the
 *    sk_fileptr_status_t enumeration.
 */
int
skFileptrOpen(
    sk_fileptr_t       *file,
    skstream_mode_t     io_mode);

/**
 *    Close the file, process, or stream specified in the 'of_fp'
 *    member of 'file'.  If 'of_fp' in NULL, return 0.  When 'of_fp'
 *    represents a standard output or standard error, the stream is
 *    flushed but not closed.
 *
 *    If 'err_fn' is non-NULL, it is used to report any errors in
 *    closing the file or process.
 */
int
skFileptrClose(
    sk_fileptr_t       *file,
    sk_msg_fn_t         err_fn);

/**
 *    Return a textual description of the return status from
 *    skFileptrOpen().  The parameter 'errnum' should be one of the
 *    values in the sk_fileptr_status_t enumeration.
 */
const char *
skFileptrStrerror(
    int                 errnum);

/**
 *    Set 'file' to the pager process when it is appropriate to do so.
 *
 *    The function returns SK_FILEPTR_PAGER_IGNORED when the 'of_fp'
 *    member of 'file' has a non-NULL value other than stdout, or when
 *    the standard output is not a terminal.
 *
 *    If 'pager' is NULL, the function attempts to find the pager from
 *    the environment by checking the environment variables SILK_PAGER
 *    and PAGER.  When the function determines that pager is NULL or
 *    the empty string, the function returns
 *    SK_FILEPTR_PAGER_IGNORED.
 *
 *    Finally, the function will attempt to open the pager.  If that
 *    fails, SK_FILEPTR_ERR_POPEN is returned.
 *
 *    If opening the pager succeeds, the members of 'file' are updated
 *    to hold the name of the pager and the FILE* for the pager
 *    process.
 *
 *    Use skFileptrClose() to close the pager.
 */
int
skFileptrOpenPager(
    sk_fileptr_t       *file,
    const char         *pager);


/**
 *    DEPRECATED.  Replaced by skFileptrOpen().
 *
 *    Removed in SiLK 4.0.0.
 *
 *    Open 'file' as a pipe or as a regular file depending on whether
 *    it is a gzipped file or not.  A file is considered gzipped if
 *    its name contains the string ".gz\0" or ".gz.".
 *
 *    The name of the file is given in the C-string 'file'; 'mode'
 *    determines whether to open 'file' for reading (mode==0) or
 *    writing (mode==1).
 *
 *    The file pointer to the newly opened file is put into 'fp'.  The
 *    value pointed to by 'isPipe' is set to 0 if fopen() was used to
 *    open the file, or 1 if popen() was used.  The caller is
 *    responsible for calling fclose() or pclose() as appropriate.
 *
 *    The function returns 0 on success, or 1 on failure.
 */
int
skOpenFile(
    const char         *FName,
    int                 mode,
    FILE              **fp,
    int                *isPipe)
    SK_GCC_DEPRECATED;


/**
 *    Make the complete directory path to 'directory', including
 *    parent(s) if required.  A return status of 0 indicates that
 *    'directory' exists---either this function created it or it
 *    existed prior to invoking this function.
 *
 *    A return status of 1 indicates a failure to create 'directory'
 *    or its parent(s), or that 'directory' already exists and it is
 *    not a directory.  On failure, any parent directories that were
 *    created by this function will not be removed.  This function
 *    sets errno on failure.
 */
int
skMakeDir(
    const char         *directory);


/**
 *    Copy the file 'src_path' to 'dest_path'.  'dest_path' may be a
 *    file or a directory.  Overwrite the destination file if it
 *    already exists.  Return 0 on success, or errno on failure.
 */
int
skCopyFile(
    const char         *src_path,
    const char         *dest_path);


/**
 *    Move the file at 'src_path' to 'dest_path'.  'dest_path' may be
 *    a file or a directory.  Overwrite the destination file if it
 *    already exists.  Return 0 on success, or errno on failure.
 */
int
skMoveFile(
    const char         *src_path,
    const char         *dest_path);


/**
 *    Return the location of the temporary directory.
 *
 *    If a temporary directory is not specified or if the specified
 *    location does not exist, return NULL.  In addition, if 'err_fn'
 *    is specified, print an error message using that function.
 *
 *    If 'user_temp_dir' is specified, that location is used.
 *    Otherwise, locations specified by the SILK_TMPDIR and TMPDIR
 *    environment variables are checked, in that order.  Finally, the
 *    DEFAULT_TEMP_DIR is used if defined.
 */
const char *
skTempDir(
    const char         *user_temp_dir,
    sk_msg_fn_t         err_fn);


/**
 *    DEPRECATED.  Replaced by skFileptrOpenPager().
 *
 *    Removed in SiLK 4.0.0.
 *
 *    Attempts to redirect the '*output_stream' to the paging program
 *    '*pager.'
 *
 *    If output changed so that it goes to a pager, 1 is returned; if
 *    the output is unchanged, 0 is returned.  If an error occurred in
 *    invoking the pager, -1 is returned.
 *
 *    If the '*output_stream' is NULL, it is assumed that the output
 *    was being sent to stdout.  If the '*output_stream' is not stdout
 *    or not a terminal, no paging is preformed and 0 is returned.
 *
 *    If '*pager' is NULL, the environment variable SILK_PAGER is
 *    checked for the paging program; if that is NULL, the PAGER
 *    environment variable is checked.  If that is also NULL, no
 *    paging is performed and 0 is returned.
 *
 *    If there was a problem invoking the pager, an error is printed
 *    and -1 is returned.
 *
 *    If the pager was started, the *output_stream value is set to the
 *    pager stream, and *pager is set to the name of the pager (if the
 *    user's environment was consulted), and 1 is returned.  To close
 *    the pager, use the skClosePager() function, or call pclose() on
 *    the *output_stream.
 *
 *    Due to the race condition of checking the status of the child
 *    process, it is possible for 1 to be returned even though the
 *    pager has exited.  In this case the tool's output will be lost.
 */
int
skOpenPagerWhenStdoutTty(
    FILE              **output_stream,
    char              **pager)
    SK_GCC_DEPRECATED;


/**
 *    DEPRECATED.
 *
 *    Removed in SiLK 4.0.0.
 *
 *    If skOpenPagerWhenStdoutTty() returns a positive value, use this
 *    function to close the pager stream.  Prints an error if the
 *    close fails.
 */
void
skClosePager(
    FILE               *output_stream,
    const char         *pager)
    SK_GCC_DEPRECATED;


/**
 *    Fill 'out_buffer' with the next non-blank, non-comment line read
 *    from 'stream'.  The caller should supply 'out_buffer' and pass
 *    its size in the 'buf_size' variable.  The return value is the
 *    number of lines that were read to get a valid line.
 *
 *    The final newline will be removed; if comment_start is provided,
 *    it will also be removed from line.
 *
 *    If a line longer than buf_size is found, out_buffer will be set
 *    to the empty string but the return value will be positive.
 *
 *    At end of file, 0 is returned and out_buffer is the empty
 *    string.
 */
int
skGetLine(
    char               *out_buffer,
    size_t              buf_size,
    FILE               *stream,
    const char         *comment_start);


/**
 *  Reads 'count' bytes from the file descriptor 'fd' into the buffer
 *  'buf'.  The return value is the number of bytes actually read.
 *  Will return less than 'count' if an end-of-file situation is
 *  reached.  In an error condition, returns -1.  More information
 *  about the error can be derived from 'errno'.
 */
ssize_t
skreadn(
    int                 fd,
    void               *buf,
    size_t              count);

/**
 *  Writes 'count' bytes from the buffer 'buf' to the file descriptor
 *  'fd'.  The return value is the number of bytes actually written.
 *  If the underlying `write' call returns zero, this function will
 *  return a value less than 'count'.  It is unknown if this actually
 *  occurs in any real-life conditions.  In an error condition,
 *  returns -1.  More information about the error can be derived from
 *  'errno'.
 */
ssize_t
skwriten(
    int                 fd,
    const void         *buf,
    size_t              count);


/**
 *    Verify that the command string specified in 'cmd_string'
 *    contains only the conversions specified in 'conversion_chars'.
 *
 *    Specifically, search 'cmd_string' for the character '%', and
 *    verify that the character that follows '%' is either another '%'
 *    or one of the characters specified in 'conversion_chars'.  In
 *    addition, verify that the command does not contain a single '%'
 *    at the end of the string.
 *
 *    If 'cmd_string' is the empty string or does not contain any
 *    invalid conversions, return 0.
 *
 *    If 'cmd_string' is not valid, return the offset into
 *    'cmd_string' of the invalid character that followed '%'.
 */
size_t
skSubcommandStringCheck(
    const char         *cmd_string,
    const char         *conversion_chars);

/**
 *    Allocate and return a new string that contains 'cmd_string' with
 *    any %-conversions expanded.
 *
 *    Specifically, create a new string and copy 'cmd_string' into it,
 *    where the string "%%" is replaced with a single '%' and where
 *    any other occurence of '%' and a character by is replaced by
 *    finding the offset of that character in 'conversion_chars' and
 *    using that offset as the index into the variable argument list
 *    to get the string to use in place of that conversion.  If the
 *    conversion character is not present in 'conversion_chars' or is
 *    the '\0' character, return NULL.
 *
 *    Return the new string.  Return NULL on an allocation error or an
 *    invalid conversion.  The caller is responsible for freeing the
 *    returned string.
 */
char *
skSubcommandStringFill(
    const char         *cmd_string,
    const char         *conversion_chars,
    ...);

/**
 *    Execute 'cmd_array[0]' in a subprocess with the remaining
 *    members of 'cmd_array[]' as the arguments to the program.  The
 *    final member of cmd_array[] must be NULL.  The value in
 *    'cmd_array[0]' should be the full path to the program since this
 *    function does not search for the command in PATH.
 *
 *    See also skSubcommandExecuteShell().
 *
 *    This function calls fork() twice to ensure that the parent
 *    process does not wait for the subprocess to terminate.
 *
 *    Return the process id of the first child if the parent
 *    successfully forks and waits for that child.
 *
 *    Return -1 if there is an allocate error or if the parent is
 *    unable to fork().  Return -2 if the wait() call fails.  In all
 *    cases, errno is set.
 *
 *    The child and grandchild only call a non-reentrant function on
 *    error: when either the child process is unable to fork() or
 *    grandchild process encounters an error in the execve() call.  In
 *    these cases, an error is reported by calling skAppPrintErr().
 */
long int
skSubcommandExecute(
    char * const        cmd_array[]);

/**
 *    Execute 'cmd_string' in a subprocess.
 *
 *    This is identical to skSubcommandExecute() execept the command
 *    'cmd_string' is invoked as the argument to "/bin/sh -c" in the
 *    grandchild process.
 */
long int
skSubcommandExecuteShell(
    const char         *cmd_string);



/*
**
**    sku-ips.c
**
*/


/**
 *    Return the log2 of 'value' as an integer.  This is the position
 *    of the most significant bit in 'value', assuming the MSB is
 *    number 63 and the LSB is 0.  Returns -1 if 'value' is 0.
 */
int
skIntegerLog2(
    uint64_t            value);


/**
 *    Compute the largest CIDR block that begins at 'start_addr' and
 *    contains no IPs larger than 'end_addr', and return the CIDR
 *    designation for that block.  For example:
 *
 *        skCIDRComputePrefix(10.0.0.2, 10.0.0.5, NULL) => 31
 *
 *    When 'new_start_addr' is not NULL, it's value is set to 0 if the
 *    CIDR block completely contains all IPs between 'start_addr' and
 *    'end_addr' inclusive.  Otherwise, its value is set to the IP that
 *    follows that block covered by the CIDR block.
 *
 *    Returns -1 if 'end_addr' < 'start_addr'.
 *
 *    This function allows one to print all CIDR blocks from 'start'
 *    to 'end' using:
 *
 *        do {
 *            cidr_prefix = skCIDRComputePrefix(&start, &end, &new_start);
 *            printf("%s/%d", skipaddrString(buf, start, 0), cidr_prefix);
 *            skipaddrCopy(&start, &new_start);
 *        } while (!skipaddrIsZero(&start));
 *
 *    Continuing the above example:
 *
 *        skCIDRComputePrefix(10.0.0.2, 10.0.0.5, &new) => 31, new => 10.0.0.4
 *        skCIDRComputePrefix(10.0.0.4, 10.0.0.5, &new) => 31, new => 0
 *
 *    which means that the IP range 10.0.0.2--10.0.0.5 is contained by
 *    the two CIDR blocks:
 *
 *        10.0.0.2/31
 *        10.0.0.4/31
 */
int
skCIDRComputePrefix(
    const skipaddr_t   *start_addr,
    const skipaddr_t   *end_addr,
    skipaddr_t         *new_start_addr);

/**
 *    Older interface to skCIDRComputePrefix() that uses integers for
 *    the IP addresses.
 */
int
skComputeCIDR(
    uint32_t            start_ip,
    uint32_t            end_ip,
    uint32_t           *new_start_ip);


/**
 *    Compute the minimum and maximum IPs that are represented by
 *    'ipaddr' when the CIDR mask 'cidr' is applied to it.  Return -1
 *    if 'cidr' is too large for the type of IP address.
 *
 *    Either of the output values, 'min_ip' or 'max_ip', may point to
 *    the same memory as 'ipaddr'.
 *
 *    See also skCIDRComputeEnd().
 */
int
skCIDR2IPRange(
    const skipaddr_t   *ipaddr,
    uint32_t            cidr,
    skipaddr_t         *min_ip,
    skipaddr_t         *max_ip);


/**
 *    Compute the minimum IP that is covered by the CIDR block
 *    'ipaddr'/'cidr' and fill 'min_ip' with that value.  Return -1 if
 *    'cidr' is too marge for the type of IP address.
 *
 *    'min_ip' may point to the same memory as 'ipaddr'.
 *
 *    See also skCIDR2IPRange().
 */
int
skCIDRComputeStart(
    const skipaddr_t   *ipaddr,
    uint32_t            cidr,
    skipaddr_t         *min_ip);


/**
 *    Compute the maximum IP that is covered by the CIDR block
 *    'ipaddr'/'cidr' and fill 'max_ip' with that value.  Return -1 if
 *    'cidr' is too marge for the type of IP address.
 *
 *    'max_ip' may point to the same memory as 'ipaddr'.
 *
 *    See also skCIDR2IPRange().
 */
int
skCIDRComputeEnd(
    const skipaddr_t   *ipaddr,
    uint32_t            cidr,
    skipaddr_t         *max_ip);


/**
 *    Parse the string 'policy_name' and set 'ipv6_policy' to the
 *    parsed value.  Return 0 on success.
 *
 *    If 'policy_name' is not a valid policy, return -1.  In addition,
 *    if 'option_name' is non-NULL, print an error message that the
 *    'policy_name' was invalid.
 */
int
skIPv6PolicyParse(
    sk_ipv6policy_t    *ipv6_policy,
    const char         *policy_name,
    const char         *option_name);


/**
 *    Add an option that will allow the user to determine how IPv6
 *    flow records are handled.  This function will also check the
 *    environment variabled namd by SILK_IPV6_POLICY_ENVAR for a
 *    policy to follow.  After skOptionsParse() sucessfully returns, the
 *    variable pointed to by 'ipv6_policy' will contain the IPv6
 *    policy to follow.
 *
 *    Before calling this function, the caller should set the variable
 *    that ipv6_policy points at to the application's default IPv6
 *    policy.
 *
 *    If IPv6 support is not enabled, the ipv6_policy is set to ignore
 *    IPv6 flows, the environment is not checked, and no option is
 *    registered
 */
int
skIPv6PolicyOptionsRegister(
    sk_ipv6policy_t    *ipv6_policy);


/**
 *    Print the help text for the --ipv6-policy switch to the named
 *    file handle.  Uses the default policy that was set when
 *    skIPv6PolicyOptionsRegister() was called.
 */
void
skIPv6PolicyUsage(
    FILE               *fh);


/* typedef struct skIPWildcard_st skIPWildcard_t; // silk_types.h */
struct skIPWildcard_st {
    /*
     *    m_blocks[] contains a bitmap for each octet of an IPv4
     *    address (IPv6:hexadectet).  If the bit is enabled, that
     *    value should be returned for that octet/hexadectet.
     *
     *    m_min[] and m_max[] are the minimum and maximum values in
     *    the bitmap for the octet/hexadectet.
     *
     *    num_blocks is 4 for an IPv4 address, 8 for an IPv6 address.
     *
     *    m_blocks[0], m_min[0], m_max[0] represent the values for the
     *    most significant octet/hexadectet.
     */
#if !SK_ENABLE_IPV6
    uint32_t            m_blocks[4][256/32];
    uint16_t            m_min[4];
    uint16_t            m_max[4];
#else
    uint32_t            m_blocks[8][65536/32];
    uint16_t            m_min[8];
    uint16_t            m_max[8];
#endif
    uint8_t             num_blocks;
};

typedef struct skIPWildcardIterator_st {
    const skIPWildcard_t   *ipwild;
    uint16_t                i_block[8];
    unsigned                no_more_entries :1;
    unsigned                force_ipv6      :1;
    unsigned                force_ipv4      :1;
} skIPWildcardIterator_t;


#define _IPWILD_BLOCK_IS_SET(ipwild, block, val)                        \
    ((ipwild)->m_blocks[(block)][_BMAP_INDEX(val)] & _BMAP_OFFSET(val))

#define _IPWILD_IPv4_IS_SET(ipwild, ipaddr)                             \
    (_IPWILD_BLOCK_IS_SET((ipwild), 0, 0xFF&(skipaddrGetV4(ipaddr) >> 24))&& \
     _IPWILD_BLOCK_IS_SET((ipwild), 1, 0xFF&(skipaddrGetV4(ipaddr) >> 16))&& \
     _IPWILD_BLOCK_IS_SET((ipwild), 2, 0xFF&(skipaddrGetV4(ipaddr) >>  8))&& \
     _IPWILD_BLOCK_IS_SET((ipwild), 3, 0xFF&(skipaddrGetV4(ipaddr))))


/**
 *    Zero all values in the skIPWildcard_t 'ipwild'.
 */
void
skIPWildcardClear(
    skIPWildcard_t     *ipwild);



#if !SK_ENABLE_IPV6
#  define skIPWildcardIsV6(ipwild)   0
#  define skIPWildcardCheckIp(ipwild, ipaddr) \
    _IPWILD_IPv4_IS_SET(ipwild, ipaddr)
#else
#  define skIPWildcardIsV6(ipwild) (8 == (ipwild)->num_blocks)
/**
 *    Return 1 if 'ip' is represented in by 'ipwild'; 0 otherwise.
 */
int
skIPWildcardCheckIp(
    const skIPWildcard_t   *ipwild,
    const skipaddr_t       *ip);
#endif


/**
 *    Bind the iterator 'iter' to iterate over the entries in the
 *    skIPWildcard_t 'ipwild'.  Use skIPWildcardIteratorNext() or
 *    skIPWildcardIteratorNextCidr() to get the entries.
 *
 *    When iterating over the IPs, the addresses will be returned in
 *    the form in which they were specified when 'ipwild' was
 *    created---that is, as either IPv4 or as IPv6.  To force an
 *    IPWildcard of IPv4 addresses to be returned as IPv6 addresses
 *    (in the ::ffff:0:0/96 subnet), use skIPWildcardIteratorBindV6().
 *
 *    Return 0 unless 'ipwild' is NULL.
 */
int
skIPWildcardIteratorBind(
    skIPWildcardIterator_t *iter,
    const skIPWildcard_t   *ipwild);


#if SK_ENABLE_IPV6
/**
 *    Bind the iterator 'iter' to iterate over the entries in the
 *    skIPWildcard_t 'ipwild'.  Similar to skIPWildcardIteratorBind(),
 *    but instructs the iterator to return IPv6 addresses even when
 *    the 'ipwild' contains IPv4 addresses.  The IPv4 addresses are
 *    mapped into the ::ffff:0:0/96 subnet.
 */
int
skIPWildcardIteratorBindV6(
    skIPWildcardIterator_t *iter,
    const skIPWildcard_t   *ipwild);

/**
 *    Bind the iterator 'iter' to iterate over the entries in the
 *    skIPWildcard_t 'ipwild'.  Similar to skIPWildcardIteratorBind(),
 *    but instructs the iterator to only visit IPv6 addresses within
 *    the ::ffff:0:0/96 subnet and return them as IPv4 addresses.
 *
 *    Since SiLK 3.9.0.
 */
int
skIPWildcardIteratorBindV4(
    skIPWildcardIterator_t *out_iter,
    const skIPWildcard_t   *ipwild);
#else  /* SK_ENABLE_IPV6 */
#define skIPWildcardIteratorBindV4 skIPWildcardIteratorBind
#endif  /* SK_ENABLE_IPV6 */


/**
 *    Fill 'out_ip' with the next IP address represented by the
 *    IPWildcard that is bound to the iterator 'iter'.  Return
 *    SK_ITERATOR_OK if 'out_ip' was filled with an IP address, or
 *    SK_ITERATOR_NO_MORE_ENTRIES otherwise.
 *
 *    This function can be intermingled with calls to
 *    skIPWildcardIteratorNextCidr(), which returns the CIDR blocks in
 *    the IPWildcard.
 */
skIteratorStatus_t
skIPWildcardIteratorNext(
    skIPWildcardIterator_t *iter,
    skipaddr_t             *out_ip);


/**
 *    Fill 'out_min_ip' and 'out_prefix' with the next CIDR block
 *    (subnet) represented by the IPWildcard that is bound to the
 *    iterator 'iter'.  Return SK_ITERATOR_OK if 'out_min_ip' was
 *    filled with an IP address, or SK_ITERATOR_NO_MORE_ENTRIES
 *    otherwise.
 *
 *    This function can be intermingled with calls to
 *    skIPWildcardIteratorNext(), which returns the individual IPs in
 *    the IPWildcard.
 */
skIteratorStatus_t
skIPWildcardIteratorNextCidr(
    skIPWildcardIterator_t *iter,
    skipaddr_t             *out_min_ip,
    uint32_t               *out_prefix);


/**
 *    Allow 'iter' to iterate again over the entries in the IPWildcard
 *    that is bound to it.
 */
void
skIPWildcardIteratorReset(
    skIPWildcardIterator_t *iter);


/*
**
**    sku-string.c
**
*/

/**
 *    Fill 'outbuf' with a string representation of the IP address in
 *    'ip'.  The size of 'outbuf' must be at least SKIPADDR_STRLEN bytes
 *    in length.  The function returns a pointer to 'outbuf'.
 *
 *    The form of the string will depend on the values in 'ip_flags',
 *    which should contain values from the skipaddr_flags_t
 *    enumeration.  Both skipaddr_flags_t and SKIPADDR_STRLEN are
 *    defined in silk_types.h.
 *
 *    The strlen() of the returned string depends on the values in
 *    'ip_flags'.  For help in setting the column width of the output,
 *    use skipaddrStringMaxlen() to get the length of the longest
 *    possible string.
 *
 *    Use skipaddrCidrString() for when a CIDR prefix (netblock)
 *    length follows the IP address.
 */
char *
skipaddrString(
    char               *outbuf,
    const skipaddr_t   *ip,
    uint32_t            ip_flags);

/**
 *    Fill 'outbuf' with a string representation of the CIDR block
 *    (netblock) denoted by the IP address in 'ip' and length in
 *    'prefix'.  The size of 'outbuf' must be at least
 *    SKIPADDR_CIDR_STRLEN bytes in length.  The function returns a
 *    pointer to 'outbuf'.
 *
 *    If the 'ip_flags' changes the displayed IP address between IPv4
 *    and IPv6 then the displayed 'prefix' is adjusted as well.
 *
 *    Note: The function assumes the proper mask has already been
 *    applied to the 'ip' (that is, that the bits below the 'prefix'
 *    are zero).
 *
 *    The form of the string will depend on the values in 'ip_flags',
 *    which should contain values from the skipaddr_flags_t
 *    enumeration.  Both skipaddr_flags_t and SKIPADDR_CIDR_STRLEN are
 *    defined in silk_types.h.
 *
 *    When 'ip_flags' contains SKIPADDR_ZEROPAD, the CIDR prefix value
 *    is also zero-padded.  The SKIPADDR_HEXADECIMAL setting does does
 *    affect the CIDR prefix, which is always displayed in decimal.
 *
 *    The strlen() of the returned string depends on the values in
 *    'ip_flags'.  For help in setting the column width of the output,
 *    use skipaddrCidrStringMaxlen() to get the length of the longest
 *    possible string.
 *
 *    See also skipaddrString().
 *
 *    Since SiLK 3.18.0.
 */
char *
skipaddrCidrString(
    char               *outbuf,
    const skipaddr_t   *ip,
    uint32_t            prefix,
    uint32_t            ip_flags);


/**
 *    Return the length of longest string expected to be returned by
 *    skipaddrString() when 'ip_flags' represent the flags value
 *    passed to that function and 'allow_ipv6' is 0 when only IPv4
 *    addresses are passed to skipaddrString() and non-zero otherwise.
 *
 *    The return value should only ever be used to set a column width.
 *    Always use a buffer having at least SKIPADDR_STRLEN characters
 *    as the 'outbuf' parameter.
 *
 *    This function ignores the SKIPADDR_UNMAP_V6 flag since the
 *    function does not know whether all IP addresses in this column
 *    fall into the ::ffff:0:0/96 netblock.  If the caller knows this,
 *    the caller may safely reduce the returned length by 22.  (The
 *    caller may reduce the length by 24 for SKIPADDR_CANONICAL,
 *    SKIPADDR_NO_MIXED, and SKIPADDR_HEXADECIMAL, and 22 for
 *    SKIPADDR_DECIMAL).
 *
 *    See also skipaddrCidrStringMaxlen().
 */
int
skipaddrStringMaxlen(
    unsigned int        allow_ipv6,
    uint32_t            ip_flags);


/**
 *    Return the length of longest string expected to be returned by
 *    skipaddrCidrString() when 'ip_flags' represent the flags value
 *    passed to that function and 'allow_ipv6' is 0 when only IPv4
 *    addresses are passed to skipaddrCidrString() and non-zero
 *    otherwise.
 *
 *    The return value should only ever be used to set a column width.
 *    Always use a buffer having at least SKIPADDR_CIDR_STRLEN
 *    characters as the 'outbuf' parameter.
 *
 *    This function treats SKIPADDR_UNMAP_V6 in the same way as
 *    skipaddrStringMaxlen(), which see.  When the input is known to
 *    contain only IPs in the ::ffff:0:0/96 netblock, the width may be
 *    reduced by 23 (or 25).
 *
 *    See also skipaddrStringMaxlen().
 *
 *    Since SiLK 3.18.0.
 */
int
skipaddrCidrStringMaxlen(
    unsigned int        allow_ipv6,
    uint32_t            ip_flags);


/**
 *    DEPRECATED.  Use skipaddrString() instead.
 *
 *    Converts the integer form of an IPv4 IP address to the dotted-quad
 *    version.  ip is taken to be in native byte order; returns a
 *    pointer to a static string buffer.
 *
 *    Returns NULL on error.
 *
 *    Replace with:
 *
 *    skipaddr_t ipaddr;
 *    char outbuf[SKIPADDR_STRLEN];
 *    skipaddrSetV4(&ipaddr, &ip);
 *    skipaddrString(outbuf, &ipaddr, 0);
 */
char *
num2dot(
    uint32_t            ip);


/**
 *    DEPRECATED.  Use skipaddrString() instead.
 *
 *    Like num2dot(), but will zero-pad the octects: num2dot0(0) will
 *    return "000.000.000.000".
 *
 *    Replace with:
 *
 *    skipaddr_t ipaddr;
 *    char outbuf[SKIPADDR_STRLEN];
 *    skipaddrSetV4(&ipaddr, &ip);
 *    skipaddrString(outbuf, &ipaddr, SKIPADDR_ZEROPAD);
 */
char *
num2dot0(
    uint32_t            ip)
    SK_GCC_DEPRECATED;


/**
 *    DEPRECATED.  Use skipaddrString() instead.
 *
 *    Thread safe version of num2dot().  The 'outbuf' should be at
 *    least SKIPADDR_STRLEN characters long.
 *
 *    Replace with:
 *
 *    skipaddr_t ipaddr;
 *    char outbuf[SKIPADDR_STRLEN];
 *    skipaddrSetV4(&ipaddr, &ip);
 *    skipaddrString(outbuf, &ipaddr, 0);
 */
char *
num2dot_r(
    uint32_t            ip,
    char               *outbuf);


/**
 *    DEPRECATED.  Use skipaddrString() instead.
 *
 *    Thread safe version of num2dot0().  The 'outbuf' must be at
 *    least SKIPADDR_STRLEN characters long.
 *
 *    Replace with:
 *
 *    skipaddr_t ipaddr;
 *    char outbuf[SKIPADDR_STRLEN];
 *    skipaddrSetV4(&ipaddr, &ip);
 *    skipaddrString(outbuf, &ipaddr, SKIPADDR_ZEROPAD);
 */
char *
num2dot0_r(
    uint32_t            ip,
    char               *outbuf)
    SK_GCC_DEPRECATED;


/**
 *    A value that may be included in the 'print_flags' value of
 *    skTCPFlagsString() and skTCPStateString() that causes the
 *    returned string to contain spaces for bits that are not set.
 */
#define SK_PADDED_FLAGS (1u << 0)


/**
 *    The minimum size of the buffer to pass to skTCPFlagsString().
 */
#define SK_TCPFLAGS_STRLEN 9

/**
 *    Fill a buffer with a string representation of the TCP flags
 *    (tcpControlBits) value 'tcp_flags'.  If all flags are on, the
 *    resulting string is "FSRPAUEC".  The 'outbuf' is expected to be
 *    at least SK_TCPFLAGS_STRLEN long.
 *
 *    If 'print_flags' is SK_PADDED_FLAGS, a space ' ' appears in
 *    place of the character if the TCP flag is off, and the
 *    representation of a particular TCP bit always appears in the
 *    same column.
 */
char *
skTCPFlagsString(
    uint8_t             tcp_flags,
    char               *outbuf,
    unsigned int        print_flags);


/**
 *    The minimum size of the buffer to pass to skTCPStateString().
 */
#define SK_TCP_STATE_STRLEN 9

/**
 *    Fill a buffer with a string representation of a SiLK atttributes
 *    (TCP state) value.  If all state flags are on, the resulting
 *    string is "TCFS".  The 'outbuf' is expected to be at least
 *    SK_TCP_STATE_STRLEN long.
 *
 *    If 'print_flags' is SK_PADDED_FLAGS, a space ' ' appears in
 *    place of the character if the state flag is off, the
 *    representation of a particular attribute bit always appears in
 *    the same column, and four space characters are appended to the
 *    string to the result is always 8 characters.
 */
char *
skTCPStateString(
    uint8_t             state,
    char               *outbuf,
    unsigned int        print_flags);


/**
 *    DEPRECATED.  Replaced by skTCPFlagsString().
 *
 *    Removed in SiLK 4.0.0.
 *
 *    Return an 8 character string denoting which TCP flags are set.
 *    If all flags are on, FSRPAUEC is returned.  For any flag that is
 *    off, a space (' ') appears in place of the character.  Returns a
 *    pointer to a static buffer.
 */
char *
tcpflags_string(
    uint8_t             flags)
    SK_GCC_DEPRECATED;


/**
 *    DEPRECATED.  Replaced by skTCPFlagsString().
 *
 *    Removed in SiLK 4.0.0.
 *
 *    Thread-safe version of tcpflags_string().  The 'outbuf' should
 *    be at least SK_TCPFLAGS_STRLEN characters long.
 */
char *
tcpflags_string_r(
    uint8_t             flags,
    char               *outbuf)
    SK_GCC_DEPRECATED;


/**
 *    Strips all leading and trailing whitespace from 'line'.
 *    Modifies line in place.
 */
int
skStrip(
    char               *line);


/**
 *    Converts uppercase letters in 'cp' to lowercase.  Modifies the
 *    string in place.
 */
void
skToLower(
    char               *cp);


/**
 *    Converts lowercase letters in 'cp' to uppercase.  Modifies the
 *    string in place.
 */
void
skToUpper(
    char               *cp);


/**
 *    Return a string describing the last error that occurred when
 *    invoking the skStringParse* functions.
 *
 *    The 'errcode' value is expected to be an silk_utils_errcode_t.
 */
const char *
skStringParseStrerror(
    int                 errcode);


/**
 *    Given a C-string containing a list---i.e., comma or hyphen
 *    delimited set---of non-negative integers, e.g., "4,3,2-6",
 *    allocate and return, via the 'number_list' parameter, an array
 *    whose values are the numbers the list contains, breaking ranges
 *    into a list of numbers.  If duplicates appear in the input, they
 *    will appear in the return value.  Order is maintained.  Thus
 *    given the C-string 'input' of "4,3,2-6", the function will set
 *    *number_list to a newly allocated array containing
 *    {4,3,2,3,4,5,6}.  The number of entries in the array is returned
 *    in '*number_count'.  The list of number is limited by the
 *    'min_val' and 'max_val' parameters; a 'max_val' of 0 means no
 *    maximum.  The maximum size of the array to be returned is given
 *    by 'max_number_count'; when this value is 0 and max_value is not
 *    zero, it is set to the number of possible values (1+max-min);
 *    when max_number_count is 0 and max_value is 0, it is set to a
 *    large (2^24) number of entries.  In all cases, the function
 *    tries to keep the returned array as small as possible.  On
 *    success, 0 is returned.
 *
 *    INPUT:
 *      number_list -- the address in which to return the array
 *      number_count -- the address in which to store the
 *          number valid elements in the returned array.
 *      input -- the string buffer to be parsed
 *      min_value -- the minimum allowed value in user input
 *      max_value -- the maximum allowed value in user input.  When
 *          max_value is 0, there is no maximum.
 *      max_number_count -- the maximum number of entries the array
 *          returned in 'number_list' is allowed to have.
 *
 *    The caller should free() the returned array when finished
 *    processing.
 *
 *    On error, a silk_utils_errcode_t value is returned.
 */
int
skStringParseNumberList(
    uint32_t          **number_list,
    uint32_t           *number_count,
    const char         *input,
    uint32_t            min_val,
    uint32_t            max_val,
    uint32_t            max_number_count);


/**
 *    Similar to skStringParseNumberList(), except that instead of
 *    returning an array, bits are set in the sk_bitmap_t 'out_bitmap'
 *    which the caller must have previously created.
 *
 *    The input may have values from 0 to skBitmapGetSize(out_bitmap)-1.
 *
 *    This function does NOT clear the bits in 'out_bitmap' prior to
 *    setting the bits based on 'input.  When re-using a bitmap, the
 *    caller should first call skBitmapClearAllBits().
 *
 *    If an error occurs, a silk_utils_errcode_t value is returned and
 *    the bitmap will be left in an unknown state.
 */
int
skStringParseNumberListToBitmap(
    sk_bitmap_t        *out_bitmap,
    const char         *input);


/**
 *    Parses a C-string containing an IPv4 or IPv6 address in the
 *    "canonical" presentation form and sets the value pointed to by
 *    'out_val' to the result.
 *
 *    In addition, a single integer value will be parsed as IPv4
 *    address.
 *
 *    Returns 0 and puts the result into 'out_val' if parsing was
 *    successful and the 'ip_string' only contained the IP address and
 *    optional leading and/or trailing whitespace.
 *
 *    Returns a positive value and puts the result into 'out_val' if
 *    parsing was successful and 'ip_string' contains additional,
 *    non-whitespace text.  The return value is the number of
 *    characters that were parsed as part of the IP address and any
 *    leading whitespace.  That is, the return value is the position
 *    in 'ip_string' where the trailing text begins.  Whitespace
 *    between the IP address and the trailing text is not parsed.
 *
 *    Returns one of the silk_utils_errcode_t values on error.
 *
 *    This routine will not parse IPs in CIDR notation; or rather, it
 *    will parse the IP portion, but the return value will be the
 *    position of the '/' character.  To correctly parse IPs in CIDR
 *    notation, use skStringParseCIDR() or skStringParseIPWildcard().
 */
int
skStringParseIP(
    skipaddr_t         *out_val,
    const char         *ip_string);


/**
 *    Takes a C-string containing an IPv4 or IPv6 address and fills
 *    'ipwild' with the result.
 *
 *    Returns 0 and puts result into 'ipwild' if parsing was
 *    successful and 'ip_string' contained only the IP address and
 *    optional leading or trailing whitespace.
 *
 *    Returns one of the silk_utils_errcode_t values on error.
 *
 *    The 'ip_string' can be in CIDR notation such as "1.2.3.0/24" or
 *    "ff80::/16"; in the canonical form "1.2.3.4" or
 *    "::ffff:0102:0304", an integer 16909056, an integer with a CIDR
 *    designation 16909056/24, or in SiLK wildcard notation: a IP in
 *    the canonical form with an 'x' respresenting an entire octet
 *    "1.2.3.x" in IPv4 or entire hexadectet in IPv6
 *    "1:2:3:4:5:6:7.x", or a dotted quad with lists or ranges in any
 *    or all octets or hexadectets "1.2,3.4,5.6,7", "1.2.3.0-255",
 *    "::2-4", "1-2:3-4:5-6:7-8:9-a:b-c:d-e:0-ffff".
 *
 *    Note that wildcard characters (',','-','x') and CIDR notation
 *    cannot be combined in a single address.
 *
 *    See also skStringParseCIDR().
 */
int
skStringParseIPWildcard(
    skIPWildcard_t     *ipwild,
    const char         *ip_string);


/**
 *    Parses a C-string containing an IPv4 or IPv6 address in the
 *    "canonical" presentation form with an optional CIDR designation.
 *    Sets the values pointed to by 'out_val' and 'out_cidr' to the
 *    parsed IP address and the CIDR designation.  If no CIDR
 *    designation is present in 'ip_string', 'out_cidr' is set to the
 *    complete IP length: 32 for IPv4, 128 for IPv6.
 *
 *    In addition, a single integer value will be parsed as IPv4
 *    address, with an optional CIDR designation.
 *
 *    Returns 0 and puts the result into 'out_val' if parsing was
 *    successful and the 'ip_string' only contained the IP address,
 *    the CIDR designation, and optional leading and/or trailing
 *    whitespace.
 *
 *    Returns one of the silk_utils_errcode_t values on error.
 *
 *    If the CIDR mask is too large for the type of IP,
 *    SKUTILS_ERR_MAXIMUM is returned.
 *
 *    It is an error for 'ip_string' to contain any text other than
 *    the IP string, CIDR designation, and leading or trailing
 *    whitespace.  SKUTILS_ERR_BAD_CHAR will be returned.
 *
 *    This routine will not parse the SiLK IP Wildcard notation; use
 *    skStringParseIPWildcard() for that.
 */
int
skStringParseCIDR(
    skipaddr_t         *out_val,
    uint32_t           *out_cidr,
    const char         *ip_string);


/* typedef union sk_sockaddr_un sk_sockaddr_t;              // silk_types.h */
/* typedef struct sk_sockaddr_array_st sk_sockaddr_array_t; // silk_types.h */

/**
 *    Constant returned by skSockaddrArrayGetHostname() when the
 *    string that created the sk_sockaddr_array_t---that is, the
 *    string passed to skStringParseHostPortPair()---did not contain a
 *    hostname or host address.
 */
extern const char *sk_sockaddr_array_anyhostname;

/* It seems that solaris does not define SUN_LEN (yet) */
#ifndef SUN_LEN
#define SUN_LEN(su)                                                     \
    (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

/* AF_UNIX seems to be defined everywhere, but the standard may change
 * to AF_LOCAL in the future. */
#ifndef AF_UNIX
#define AF_UNIX AF_LOCAL
#endif

/**
 *    Return the size of sk_sockaddr_t object, suitable for passing
 *    as the addrlen in functions such as connect(2) and bind(2).
 *
 *    Prior to SiLK 3.16.0, this was called skSockaddrLen().
 */
#if 0
size_t
skSockaddrGetLen(
    const sk_sockaddr_t    *s);
#endif  /* 0 */
#define skSockaddrGetLen(s)                                             \
    (((s)->sa.sa_family == AF_INET) ? sizeof((s)->v4) :                 \
     (((s)->sa.sa_family == AF_INET6) ? sizeof((s)->v6) :               \
      (((s)->sa.sa_family == AF_UNIX) ? SUN_LEN(&(s)->un) : 0)))

/**
 *    DEPRECATED.  Replaced by skSockaddrGetLen().
 *
 *    Removed in SiLK 4.0.0.
 */
size_t
skSockaddrLen(
    const sk_sockaddr_t    *s)
    SK_GCC_DEPRECATED;


/**
 *    Return the port portion of a sk_sockaddr_t object, as an integer
 *    in host-byte-order.  Return -1 for sockaddr types without
 *    ports.
 *
 *    Prior to SiLK 3.16.0, this was called skSockaddrPort().
 */
#if 0
int
skSockaddrGetPort(
    const sk_sockaddr_t    *s);
#endif  /* 0 */
#define skSockaddrGetPort(s)                                            \
    (((s)->sa.sa_family == AF_INET) ? ntohs((s)->v4.sin_port) :         \
     (((s)->sa.sa_family == AF_INET6) ? ntohs((s)->v6.sin6_port) : -1))

/**
 *    DEPRECATED.  Replaced by skSockaddrGetPort().
 *
 *    Removed in SiLK 4.0.0.
 */
int
skSockaddrPort(
    const sk_sockaddr_t    *s)
    SK_GCC_DEPRECATED;


/**
 *    Destroy a sk_sockaddr_array_t structure previously created by
 *    skStringParseHostPortPair().  Do nothing if the argument is
 *    NULL.
 */
#if 0
void
skSockaddrArrayDestroy(
    sk_sockaddr_array_t    *s);
#endif  /* 0 */
#define skSockaddrArrayDestroy(s)               \
    do {                                        \
        if (s) {                                \
            free((s)->name);                    \
            free((s)->host_port_pair);          \
            free((s)->addrs);                   \
            free(s);                            \
        }                                       \
    } while (0)


/**
 *    Return the hostname or host address portion of a
 *    sk_sockaddr_array_t structure as a C character array.  That is,
 *    return the host or IP address portion of the 'host_port'
 *    parameter of skStringParseHostPortPair().
 *
 *    If no hostname was specified when the sk_sockaddr_array_t was
 *    created, return the string specified by the global
 *    sk_sockaddr_array_anyhostname constant---the string "*".
 *
 *    To determine whether a hostname was provided to
 *    skStringParseHostPortPair(), the caller may compare the result
 *    of this macro with the sk_sockaddr_array_anyhostname constant.
 *
 *    Prior to SiLK 3.16.0, this was called skSockaddrArrayNameSafe().
 */
#if 0
const char *
skSockaddrArrayGetHostname(
    const sk_sockaddr_array_t  *s);
#endif  /* 0 */
#define skSockaddrArrayGetHostname(s)                           \
    ((s)->name ? (s)->name : sk_sockaddr_array_anyhostname)

/*
 *    DEPRECATED.  Replaced by skSockaddrArrayGetHostname().
 *
 *    Removed in SiLK 4.0.0.
 */
const char *
skSockaddrArrayNameSafe(
    const sk_sockaddr_array_t  *s)
    SK_GCC_DEPRECATED;


/**
 *    DEPRECATED.  Replaced by skSockaddrArrayGetHostname().  If need
 *    to know whether value is NULL, compare result of
 *    skSockaddrArrayGetHostname() to sk_sockaddr_array_anyhostname.
 *
 *    Removed in SiLK 4.0.0.
 *
 *    Returns the name of a sk_sockaddr_array_t structure.
 *    Specifically, returns the host or IP address portion of the
 *    'host_port' parameter of skStringParseHostPortPair().  May
 *    return NULL.  See also skSockaddrArrayNameSafe() and
 *    skSockaddrString().
 */
const char *
skSockaddrArrayName(
    const sk_sockaddr_array_t  *s)
    SK_GCC_DEPRECATED;


/**
 *    Return the host-port pair string that created the
 *    sk_sockaddr_array_t structure.  The return value is nearly the
 *    string that was passed to skStringParseHostPortPair() except the
 *    string uses a "*" or "[*]" to represent the host when no
 *    host-name/-address was provided to skStringParseHostPortPair()
 *    and the HOST_PROHIBITED flag was not set.
 *
 *    Since SiLK 4.0.0.
 */
#if 0
const char *
skSockaddrArrayGetHostPortPair(
    const sk_sockaddr_array_t  *s);
#endif  /* 0 */
#define skSockaddrArrayGetHostPortPair(s)   ((s)->host_port_pair)


/**
 *    Return the number of addresses in a sk_sockaddr_array_t
 *    structure.
 *
 *    Prior to SiLK 3.16.0, this was called skSockaddrArraySize().
 */
#if 0
uint32_t
skSockaddrArrayGetSize(
    const sk_sockaddr_array_t  *s);
#endif  /* 0 */
#define skSockaddrArrayGetSize(s)           ((s)->num_addrs)

/*
 *    DEPRECATED.  Replaced by skSockaddrArrayGetSize().
 *
 *    Removed in SiLK 4.0.0.
 */
uint32_t
skSockaddrArraySize(
    const sk_sockaddr_array_t  *s)
    SK_GCC_DEPRECATED;


/**
 *    Return the address (sk_sockaddr_t *) at position 'n' in the
 *    sk_sockaddr_array_t structure 's'.  The first address is at
 *    position 0.  The value 'n' must be less than
 *    skSockaddrArrayGetSize(s), otherwise the return value is
 *    indeterminate.
 */
#if 0
const sk_sockaddr_t *
skSockaddrArrayGet(
    const sk_sockaddr_array_t  *s,
    uint32_t                    n);
#endif  /* 0 */
#define skSockaddrArrayGet(s, n)            (&((s)->addrs[n]))


/**
 *    Ignore the port value when comparing two sk_sockaddr_t objects
 *    with skSockaddrCompare() or skSockaddrArrayMatches().
 */
#define SK_SOCKADDRCOMP_NOPORT       (1u << 0)

/**
 *    Ignore the address when comparing two sk_sockaddr_t objects
 *    with skSockaddrCompare() or skSockaddrArrayMatches().
 */
#define SK_SOCKADDRCOMP_NOADDR       (1u << 1)

/**
 *    Treat IPv4 and IPv6 addresses as different when comparing two
 *    sk_sockaddr_t objects with skSockaddrCompare() or
 *    skSockaddrArrayMatches().
 */
#define SK_SOCKADDRCOMP_NOT_V4_AS_V6 (1u << 2)


/**
 *    Fill 'outbuf' with a string representing the IP address in
 *    'addr' and any non-zero port number.  The IP address and port
 *    are separated by a colon, ':'.  If the address in 'addr' is
 *    INADDR_ANY, the address is represented by an asterisk '*'.  When
 *    the address is IPv6 and the port is non-zero, the address is
 *    enclosed in square brackets, '[',']'.  When 'addr' contains a
 *    Unix domain socket, write the path to 'outbuf'.
 *
 *    Return the number of bytes written to 'outbuf', not including
 *    the terminating NUL.
 *
 *    Write no more than 'size' bytes to 'outbuf'.  If 'outbuf' is not
 *    large enough to hold the string, return the number of bytes that
 *    would have written if 'outbuf' had been large enough to hold the
 *    entire string, not including the terminating NUL.
 */
ssize_t
skSockaddrString(
    char                   *outbuf,
    size_t                  size,
    const sk_sockaddr_t    *addr);

/**
 *    Compare two sk_sockaddr_t objects.
 *
 *    Return -1 if a is "less than" b, 1 if a is "greater than" b,
 *    and 0 if the two are equal.
 *
 *    The 'flags' parameter may contain any of the following bits:
 *
 *    SK_SOCKADDRCOMP_NOPORT -- ignore the port portions when
 *    comparing
 *
 *    SK_SOCKADDRCOMP_NOADDR -- ignore the address potions when
 *    comparing
 *
 *    SK_SOCKADDRCOMP_NOT_V4_AS_V6 -- do not map IPv4 addresses into
 *    the ::ffff:0:0/96 IPv6 netblock when comparing an AF_INET and an
 *    AF_INET6 sk_sockaddr_t.
 */
int
skSockaddrCompare(
    const sk_sockaddr_t    *a,
    const sk_sockaddr_t    *b,
    unsigned int            flags);

/**
 *    Determine whether 'array' contains 'addr', according to
 *    'flags'.  Return 1 if true, 0 if false.
 *
 *    Addresses are compared using the skSockaddrCompare() function.
 *    The 'flags' argument will be passed to that function.
 *
 *    Return value will be 0 if either 'array' or 'addr' are NULL.
 */
int
skSockaddrArrayContains(
    const sk_sockaddr_array_t  *array,
    const sk_sockaddr_t        *addr,
    unsigned int                flags);

/**
 *    Determine whether two sk_sockaddr_array_t objects are
 *    identical, according to 'flags'.
 *
 *    Two sk_sockaddr_array_t objects are considered equal if they
 *    have the same number of addresses, and each address in 'a' is
 *    contained in 'b'.  Two NULL arrays are considered equal.  It is
 *    assumed that the two arrays contain no duplicate addresses.
 *    Addresses are compared with the skSockaddrCompare() function,
 *    which will use the 'flags' argument.
 */
int
skSockaddrArrayEqual(
    const sk_sockaddr_array_t  *a,
    const sk_sockaddr_array_t  *b,
    unsigned int                flags);


/**
 *    Decide whether two sk_sockaddr_array_t objects match.  Return
 *    1 if they match, 0 otherwise.
 *
 *    Two sk_sockaddr_array_t objects are considered to match if any
 *    of their sk_sockaddr_t elements match as determined by
 *    skSockaddrCompare().  The 'flags' argument will be passed to the
 *    skSockaddrCompare() function.
 *
 *    An empty array matches nothing, not even another empty array.
 */
int
skSockaddrArrayMatches(
    const sk_sockaddr_array_t  *a,
    const sk_sockaddr_array_t  *b,
    unsigned int                flags);


/* Flags which can be passed to skStringParseHostPortPair() */
#define PORT_REQUIRED    (1u << 0)
#define PORT_PROHIBITED  (1u << 1)
#define HOST_REQUIRED    (1u << 2)
#define HOST_PROHIBITED  (1u << 3)
#define IPV6_REQUIRED    (1u << 4)
#define IPV6_PROHIBITED  (1u << 5)


/**
 *    Parse a host:port pair, or a host, or a port number.
 *
 *    Allocate a new sk_sockaddr_array_t object, store the resulting
 *    set of addresses and ports as 'sk_sockaddr_t' objects in the
 *    sk_sockaddr_array_t object, and store the array in the location
 *    referenced by 'sockaddr'.
 *
 *    The number of sk_sockaddr_t's in the sk_sockaddr_array_t is
 *    given by skSockaddrArraySize().  The caller may obtain an
 *    individual sk_sockaddr_t by calling skSockaddrArrayGet().  The
 *    caller must destroy the array by calling
 *    skSockaddrArrayDestroy().
 *
 *    The host portion of 'host_port' may be a dotted decimal IPv4
 *    address, a hex string IPv6 address, or a hostname.  The host may
 *    be enclosed in '[' and ']', and it must be so enclosed when an
 *    IPv6 hex string includes a port number, for example "[::]:80"
 *
 *    The flags are a bitwise combination of
 *    {PORT,HOST,IPV6}_{REQUIRED,PROHIBITED}.  Four of these flags
 *    specify whether the host portion and/or port portion of the
 *    host_port string is required or prohibited.  By default there
 *    are no requirements/prohibitions on the content of 'host_port'.
 *    The other two flags specify whether IPv6 addresses should be
 *    resolved, or whether only IPv6 addresses should be resolved.
 *    The default is to resolve to both IPv6 and IPv4 addresses.
 */
int
skStringParseHostPortPair(
    sk_sockaddr_array_t   **sockaddr,
    const char             *host_port,
    uint8_t                 flags);


/**
 *    skStringParseDatetime() sets the lower three bits of its
 *    'out_flags' parameter to this value when only a year was parsed.
 *    The 'out_flags' value should never contain this value.
 */
#define SK_PARSED_DATETIME_YEAR             1

/**
 *    skStringParseDatetime() sets the lower three bits of its
 *    'out_flags' parameter to this value when a year and month were
 *    parsed.  The 'out_flags' value should never contain this value.
 */
#define SK_PARSED_DATETIME_MONTH            2

/**
 *    skStringParseDatetime() sets the lower three bits of its
 *    'out_flags' parameter to this value when a year, month, and day
 *    were parsed or when an epoch time was parsed and the value is a
 *    multiple of 86400.
 */
#define SK_PARSED_DATETIME_DAY              3

/**
 *    skStringParseDatetime() sets the lower three bits of its
 *    'out_flags' parameter to this value when a year, month, day, and
 *    hour were parsed or when an epoch time was parsed and the value
 *    is a multiple of 3600.
 */
#define SK_PARSED_DATETIME_HOUR             4

/**
 *    skStringParseDatetime() sets the lower three bits of its
 *    'out_flags' parameter to this value when a year, month, day,
 *    hour, and minute were parsed or when an epoch time was parsed
 *    and the value is a multiple of 60.
 */
#define SK_PARSED_DATETIME_MINUTE           5

/**
 *    skStringParseDatetime() sets the lower three bits of its
 *    'out_flags' parameter to this value when a year, month, day,
 *    hour, minute, and second were parsed or when an epoch time was
 *    parsed and no fractional seconds value was present.
 */
#define SK_PARSED_DATETIME_SECOND           6

/**
 *    skStringParseDatetime() sets the lower three bits of its
 *    'out_flags' parameter to this value when a year, month, day,
 *    hour, minute, second, and fractional second were parsed or when
 *    an epoch time was parsed and a fractional seconds value was
 *    present.
 */
#define SK_PARSED_DATETIME_FRACSEC          7

/**
 *    A mask to apply to the 'out_flags' value set by
 *    skStringParseDatetime() to determine the precision.
 */
#define SK_PARSED_DATETIME_MASK_PRECISION   0x7

/**
 *    Return the precision portion of the 'out_flags' value that is
 *    set by calling skStringParseDatetime().
 */
#define SK_PARSED_DATETIME_GET_PRECISION(pdgp_flags)    \
    (SK_PARSED_DATETIME_MASK_PRECISION & (pdgp_flags))

/**
 *    skStringParseDatetime() sets this bit in its 'out_flags'
 *    parameter when the parsed string contained seconds since the
 *    UNIX epoch.
 */
#define SK_PARSED_DATETIME_EPOCH            0x8

/**
 *    Attempt to parse the 'time_string' as a date in the form
 *    YYYY/MM/DD[:HH[:MM[:SS[.sss]]]] and set *time_val to that time in
 *    milliseconds since the UNIX epoch.  Assume the time in UTC
 *    unless SiLK was configured with the --enable-local-timezone
 *    switch, in which case the time is assumed to be in the local
 *    timezone.
 *
 *    A fractional seconds value with more precision that milliseconds
 *    is truncated.  NOTE: Prior to SiLK 3.10.0, fractional seconds
 *    were rounded to the nearest millisecond value.
 *
 *    When the input string contains only digits and decimal points
 *    (".") and is at least eight characters in length, parse the
 *    value before the decimal point as seconds since the UNIX epoch,
 *    and the value after the decimal point as fractional seconds.
 *    Return an error if more than one decimal point is present.
 *
 *    If the 'out_flags' parameter is non-null, set the location it
 *    references with SK_PARSED_DATETIME_* values to indicate what was
 *    parsed.
 *
 *    The SK_PARSED_DATEDTIME_EPOCH bit of 'out_flags' is set when the
 *    value parsed was in epoch seconds.  The lower three bits are
 *    still set to reflect the precision of the value.
 *
 *    Note that skStringParseDatetime() will return SKUTILS_ERR_SHORT
 *    if the time_string is not an epoch time and does not contain at
 *    least Day precision.
 *
 *    Return 0 on success.  Returns a silk_utils_errcode_t value on an
 *    error; error conditions include an empty string, malformed date,
 *    or extra text after the date.  Returns SKUTILS_ERR_SHORT if the
 *    date does not have at least day precision.
 */
int
skStringParseDatetime(
    sktime_t           *time_val,
    const char         *time_string,
    unsigned int       *out_flags);


/**
 *    Attempt to parse 'datetime_range' as a datetime or a range of
 *    datetimes.  When two hyphen-separated datetimes are found, store
 *    the first in 'start' and the second in 'end'.  When only one
 *    datetime is found, store that time in 'start' and set 'end' to
 *    INT64_MAX.
 *
 *    This function uses skStringParseDatetime() internally, and the
 *    'start_flags' and 'end_flags' values are set by that function
 *    when parsing the starting datetime and ending datetime,
 *    respectively.  See skStringParseDatetime() for more information.
 *
 *    Return 0 when the datetimes are parsed correctly.
 *
 *    Return an silk_utils_errcode_t value on error, including
 *    SKUTILS_ERR_SHORT if the either date does not have at least day
 *    precision, and SKUTILS_ERR_BAD_RANGE if the end-date is earlier
 *    than the start-date.
 */
int
skStringParseDatetimeRange(
    sktime_t           *start,
    sktime_t           *end,
    const char         *datetime_range,
    unsigned int       *start_flags,
    unsigned int       *end_flags);


/**
 *    Take a calendar time 't' and a 'precision' and put into
 *    'ceiling_time' the latest-possible (largest) calendar time
 *    greater than or equal to 't' such that the value specified by
 *    'precision' is not modified.  't' and 'ceiling_time' may point
 *    to the same memory.  See skStringParseDatetime() for a
 *    description the precision.
 *
 *    skStringParseDatetime() parses a string to the earliest-possible
 *    calendar time that meets the constraints parsed.  For example,
 *    "1990/12/25:05" is taken to mean "1990/12/25:05:00:00.000".
 *    Passing that value and its precision---which would be
 *    SK_PARSED_DATETIME_HOUR---to skDatetimeCeiling() would result in
 *    the calendar time for "1990/12/25:05:59:59.999".
 *
 *    skDatetimeCeiling() is commonly used to calculate the endpoint
 *    for a range of dates parsed by skStringParseDatetimeRange().
 *    For example, "2004/12/25-2004/12/26:3" should represent
 *    everything between "2004/12/25:00:00:00.000" and
 *    "2004/12/26:03:59:59.999".
 *
 *    The time is assumed to be in UTC unless SiLK was configured with
 *    the --enable-local-timezone switch.  The timezone is only a
 *    factor for times that are coarser than hour precision.
 *
 *    skDatetimeCeiling() ignores whether SK_PARSED_DATETIME_EPOCH is
 *    set in the 'precision' parameter.
 *
 *    Return 0 on success.  Return -1 if the system time conversion
 *    functions return an error, if 'precision' is 0, or if
 *    'precision' is an unexpected value.
 */
int
skDatetimeCeiling(
    sktime_t           *ceiling_time,
    const sktime_t     *t,
    unsigned int        precision);


/**
 *    Take a calendar time 't' and a 'precision' and put into
 *    'floor_time' the earliest-possible (lowest) timestamp less than
 *    or equal to 't' such that the value specified by 'precision' is
 *    not modified.  't' and 'floor_time' may point to the same
 *    memory.  See skStringParseDatetime() for a description the
 *    precision.
 *
 *    One use of skDatetimeFloor() is to clear the minutes and seconds
 *    fields from a calendar time.
 *
 *    The time is assumed to be in UTC unless SiLK was configured with
 *    the --enable-local-timezone switch.  The timezone is only a
 *    factor for times that are coarser than hour precision.
 *
 *    skDatetimeFloor() ignores whether SK_PARSED_DATETIME_EPOCH is
 *    set in the 'precision' parameter.
 *
 *    Return 0 on success.  Return -1 if the system time conversion
 *    functions return an error, if 'precision' is 0, or if
 *    'precision' is an unexpected value.
 *
 *    Since SiLK 3.11.0.
 */
int
skDatetimeFloor(
    sktime_t           *floor_time,
    const sktime_t     *t,
    unsigned int        precision);


/**
 *    A wrapper over skStringParseUint64() that uses unsiged 32-bit
 *    numbers unstead of 64-bit numbers.
 */
int
skStringParseUint32(
    uint32_t           *result_val,
    const char         *int_string,
    uint32_t            min_val,
    uint32_t            max_val);


/**
 *    Attempts to parse the C string 'int_string' as an unsigned
 *    64-bit decimal integer, and puts the result into the referent of
 *    'result_val'.  Ignores any whitespace before and after the
 *    number.
 *
 *    In addition, the function verifies that the value is between
 *    'min_val' and 'max_val' inclusive.  A 'max_val' of 0 is
 *    equivalent to UINT64_MAX; i.e., the largest value that will fit
 *    in a 64bit value.
 *
 *    Returns 0 and fills 'result_val' when 'int_string' contains only
 *    a number and leading or trailing whitespace and the number is
 *    parsable and the resulting value is within the limits.
 *
 *    Returns a positive value and fills 'result_val' when
 *    'int_string' contains a value within the limits and contains
 *    additional non-whitespace text after a parsed number.  The
 *    return value is the number of characters parsed in 'int_string'.
 *    For example, an 'int_string' of either "7x" or "7 x" causes the
 *    function to set the referent of 'result_val' to 7 and return 1.
 *
 *    Fills 'result_val' and returns either SKUTILS_ERR_MINIMUM or
 *    SKUTILS_ERR_MAXIMUM when the value is successfully parsed but is
 *    not within the limits.  When the value falls outside the
 *    possible range of the function, 'result_val' is unchanged and
 *    SKUTILS_ERR_OVERFLOW is returned.
 *
 *    Returns a silk_utils_errcode_t value on any other error and
 *    leaves 'result_val' unchanged.
 */
int
skStringParseUint64(
    uint64_t           *result_val,
    const char         *int_string,
    uint64_t            min_val,
    uint64_t            max_val);



/**
 *    Options flags to pass to skStringParseHumanUint64()
 */
typedef enum {
    /** Use 1024 for k, etc.  This is the default unless
     * SK_HUMAN_LOWER_SI is specified. */
    SK_HUMAN_LOWER_TRADITIONAL = 0,

    /** Use 1000 instead of 1024 for k, etc. */
    SK_HUMAN_LOWER_SI = 1,

    /** Use 1024 for K, etc.  This is the default unless
     * SK_HUMAN_UPPER_SI is specified. */
    SK_HUMAN_UPPER_TRADITIONAL = 0,

    /** Use 1000 instead of 1024 for K, etc. */
    SK_HUMAN_UPPER_SI = 2,

    /** Do not allow whitespace between the number and the suffix---the
     * position of the suffix will be the function's return value.
     * This is the default unless SK_HUMAN_MID_WS is specified. */
    SK_HUMAN_MID_NO_WS = 0,

    /** Ignore whitespace between the number and the suffix */
    SK_HUMAN_MID_WS = 4,

    /** Parse trailing whitespace.  This is the default unless
     * SK_HUMAN_END_NO_WS is specified. */
    SK_HUMAN_END_WS = 0,

    /** Do not parse trailing whitespace.  The position of the first
     * whitespace chacter is the function's return value. */
    SK_HUMAN_END_NO_WS = 8
} skHumanFlags_t;

/**
 *    Default settings from skStringParseHumanUint64()
 */
#define SK_HUMAN_NORMAL                                         \
    (SK_HUMAN_LOWER_TRADITIONAL | SK_HUMAN_UPPER_TRADITIONAL    \
     | SK_HUMAN_MID_NO_WS | SK_HUMAN_END_WS)

/**
 *    Attempts to parse the C string 'int_string' as an unsigned
 *    64-bit integer, ignoring leading whitespace.  In addition,
 *    handles human suffixes such as k, m, g, and t.  Puts the result
 *    into location pointed to by 'result_val'.
 *
 *    Returns a value >= 0 the string was parsable.  Returns 0 when
 *    nothing other than parsed whitespace was present.  A positive
 *    return value is the index into 'int_string' of the first
 *    non-parsed character following the successfully parsed number;
 *    e.g; "1x" would set *result_val to 1 and return 2.
 *
 *    Returns an silk_utils_errcode_t value on error.  Note that "NaN"
 *    returns SKUTILS_ERR_BAD_CHAR.
 *
 *    The 'parse_flags' value is made by or-ing flags from
 *    skHumanFlags_t together.  See their descriptions above.
 */
int
skStringParseHumanUint64(
    uint64_t           *result_val,
    const char         *int_string,
    unsigned int        parse_flags);


/* Following are used by skStringParseRange64() and
 * skStringParseRange32() */

/**
 *    Allow a fully specified range "3-5", a single value "3"
 *    (range_upper is set to range_lower), or an open-ended range "3-"
 *    (range_upper is set to max_val).
 */
#define SKUTILS_RANGE_SINGLE_OPEN   0

/**
 *    Allow a fully specified range "3-5" or an open-ended range "3-";
 *    i.e., the argument must contain a hyphen.  A single value is not
 *    allowed.
 */
#define SKUTILS_RANGE_NO_SINGLE     (1u << 0)

/**
 *    Allow a fully specified range "3-5" or a single value "3"
 *    (range_upper is set to range_lower).
 */
#define SKUTILS_RANGE_NO_OPEN       (1u << 1)

/**
 *    Only support a fully specified range "3-5"; i.e., the range must
 *    have both bounds.
 */
#define SKUTILS_RANGE_ONLY_RANGE    (SKUTILS_RANGE_NO_SINGLE \
                                     | SKUTILS_RANGE_NO_OPEN)

/**
 *    When a single value "3" is parsed, set range_upper to max_val as
 *    if an open-ended range had been specified.
 */
#define SKUTILS_RANGE_MAX_SINGLE    (1u << 2)

/**
 *    Attempts to parse the C-string 'range_string' as a range of two
 *    32-bit integers; that is, as a 32-bit integer representing the
 *    lower bound of the range, a hyphen '-', and the upper bound of
 *    the range.  The function sets 'range_lower' to the lower bound,
 *    and 'range_upper' to the upper bound.
 *
 *    The function also verifies that the bounds on the range fall
 *    between 'min_val' and 'max_val' inclusive.  A 'max_val' of 0 is
 *    equivalent to UINT32_MAX.
 *
 *    If flags does not contain 'SKUTILS_RANGE_NO_SINGLE', this
 *    function will also parse a single value, similar to
 *    skStringParseUint32().  When this occurs, both 'range_lower' and
 *    'range_upper' are set to the single value.  There is no way for
 *    the caller to tell whether the function parsed a single value
 *    '4' or a range where the bounds are identical '4-4'.
 *    SKUTILS_ERR_SHORT is returned when a single value is present and
 *    SKUTILS_RANGE_NO_SINGLE is specified.
 *
 *    If flags does not contain 'SKUTILS_RANGE_NO_OPEN', the upper
 *    bound of the range is optional.  That is, a 'range_string' of
 *    '5-' will result in the upper bound being set to 'max_val', or
 *    UINT32_MAX if 'max_val' is 0.  SKUTILS_ERR_SHORT is returned
 *    when an open-ended range is given and SKUTILS_RANGE_NO_OPEN is
 *    specified.
 *
 *    If flags contains 'SKUTILS_RANGE_MAX_SINGLE', the function sets
 *    range_upper to 'max_val' (or to UINT32_MAX if 'max_val' is 0)
 *    when a single value is parsed (as for an open-ended range).
 *
 *    Whitespace around the range will be ignored.  Whitespace within
 *    the range will result in SKUTILS_ERR_BAD_CHAR being returned.
 *
 *    Returns 0 on success, or a silk_utils_errcode_t value on error.
 */
int
skStringParseRange32(
    uint32_t           *range_lower,
    uint32_t           *range_upper,
    const char         *range_string,
    uint32_t            min_val,
    uint32_t            max_val,
    unsigned int        flags);


/**
 *    As skStringParseRange32(), except that it attempts to parse the
 *    C-string 'range_string' as two unsigned 64-bit integers and a
 *    'max_val' of 0 represents UINT64_MAX.
 */
int
skStringParseRange64(
    uint64_t           *range_lower,
    uint64_t           *range_upper,
    const char         *range_string,
    uint64_t            min_val,
    uint64_t            max_val,
    unsigned int        flags);


/**
 *    Attempts to parse the C string 'dbl_string' as a floating point
 *    value (double).  In addition, verifies that the value is between
 *    'min_val' and 'max_val' inclusive.  A 'max_val' of 0 is
 *    equivalent to HUGE_VAL.  Puts the result into location pointed
 *    to by 'result_val'.  Ignores any whitespace around the number.
 *
 *    Returns 0 and fills 'result_val' when 'dbl_string' contains only
 *    a number and whitespace and the number is parsable and the
 *    resulting value is within the limits.
 *
 *    Returns a positive value and fills 'result_val' when
 *    'dbl_string' contains a value within the limits and contains
 *    additional non-whitespace text.  The return value is the number
 *    of characters parsed, not including whitespace between the
 *    number and the additional text; e.g; "1.1 x" would set
 *    *result_val to 1.1 and return 3.
 *
 *    Returns an silk_utils_errcode_t value on error.  Note that "NaN"
 *    returns SKUTILS_ERR_BAD_CHAR.
 */
int
skStringParseDouble(
    double             *result_val,
    const char         *dbl_string,
    double              min_val,
    double              max_val);


/**
 *    As skStringParseRange32(), except that it attempts to parse the
 *    C-string 'range_string' as two double values and a 'max_val' of
 *    0 represents HUGE_VAL.
 */
int
skStringParseDoubleRange(
    double             *range_lower,
    double             *range_upper,
    const char         *range_string,
    double              min_val,
    double              max_val,
    unsigned int        flags);




/* TCP FLAGS HANDLING */

/**
 *    Sets any high-flags in 'flags' to high in 'var'.  Other high-flags
 *    in 'var' are not affected.
 */
#define TCP_FLAG_SET_FLAG( var, flags ) ((var) |= (flags))

/**
 *    Returns 1 if the high-flags in 'flags' are also high in 'var';
 *    returns 0 otherwise.
 */
#define TCP_FLAG_TEST( var, flags ) ( (((flag) & (var)) != 0) ? 1 : 0 )

/**
 *    Returns 1 if, for all high-flags in 'mask', the only high-bits
 *    in 'var' are thost that are set in 'high'; return 0 otherwise.
 *    See skStringParseTCPFlagsHighMask() for details.
 */
#define TCP_FLAG_TEST_HIGH_MASK( var, high, mask ) \
    ( (((var) & (mask)) == ((high) & (mask))) ? 1 : 0 )



/**
 *    Parses the C-string 'flag_string' as a block of TCP flags and
 *    puts the value into the memory pointed at by 'result'.  Flag
 *    strings can only contain the following characters:
 *
 *        F f (FIN)
 *        S s (SYN)
 *        R r (RESET)
 *        P p (PUSH)
 *        A a (ACK)
 *        U u (URGENT)
 *        E e (ECE)
 *        C c (CWR)
 *
 *    As of SiLK 3.20.0, the character "-" sets all flag bits high.
 *
 *    Returns 0 when 'flag_string' contains valid TCP flag characters
 *    and whitespace.  Returns 0 and sets 'result' to 0 if the string
 *    is empty or contains only whitespace.
 *
 *    Otherwise, a silk_utils_errcode_t value is returned.
 */
int
skStringParseTCPFlags(
    uint8_t            *result,
    const char         *flag_string);


/**
 *    Parses 'flag_string' as a HIGH/MASK pair of blocks of TCP flags.
 *    Both the HIGH and MASK portions of the string are flag strings,
 *    and are interpreted by skStringParseTCPFlags().
 *
 *    In a HIGH/MASK pair, the TCP flags listed in HIGH must be set;
 *    flags listed in MASK but not in HIGH must be low; flags not
 *    listed in MASK can have any value.  It is an error if a flag is
 *    listed in HIGH but not in MASK; that is, HIGH must be a subset
 *    of MASK.  For example: "AS/ASFR" means ACK,SYN must be high,
 *    FIN,RST must be low, and the other flags--PSH,URG,ECE,CWR--may
 *    have any value.
 *
 *    If successful, returns 0.  Otherwise, an silk_utils_errcode_t
 *    value is returned.
 *
 *    The inputs 'high' and 'mask' are overwritten with the bitmap of
 *    the flags set.
 *
 *    It is an error for any trailing text (other than whitespace) to
 *    follow the MASK.  Returns SKUTILS_ERR_SHORT if MASK has no
 *    value; returns SKUTILS_ERR_BAD_RANGE if HIGH is not a subset of
 *    MASK.
 */
int
skStringParseTCPFlagsHighMask(
    uint8_t            *high,
    uint8_t            *mask,
    const char         *flag_string);


/*
 * flag definitions.
 */
#define CWR_FLAG (1u << 7)      /* 128 */
#define ECE_FLAG (1u << 6)      /*  64 */
#define URG_FLAG (1u << 5)      /*  32 */
#define ACK_FLAG (1u << 4)      /*  16 */
#define PSH_FLAG (1u << 3)      /*   8 */
#define RST_FLAG (1u << 2)      /*   4 */
#define SYN_FLAG (1u << 1)      /*   2 */
#define FIN_FLAG (1u << 0)      /*   1 */


/**
 *    Parses the C-string 'flag_string' as a block of TCP state flags
 *    and puts the value into the memory pointed at by 'result'.  Flag
 *    strings can only contain the following characters:
 *
 *        T t (SK_TCPSTATE_TIMEOUT_KILLED)
 *        C c (SK_TCPSTATE_TIMEOUT_STARTED)
 *        F f (SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK)
 *        S s (SK_TCPSTATE_UNIFORM_PACKET_SIZE)
 *
 *    As of SiLK 3.20.0, the character "-" sets all TCP state flag
 *    bits high.
 *
 *    Returns 0 when 'flag_string' contains valid TCP state flag
 *    characters and whitespace.  Returns 0 and sets 'result' to 0 if
 *    the string is empty or contains only whitespace.
 *
 *    Otherwise, a silk_utils_errcode_t value is returned.
 */
int
skStringParseTCPState(
    uint8_t            *result,
    const char         *flag_string);


/**
 *    Parses 'flag_string' as a HIGH/MASK pair of blocks of TCP state
 *    flags.  Both the HIGH and MASK portions of the string are flag
 *    strings, and are interpreted by skStringParseTCPState().
 *
 *    In a HIGH/MASK pair, the TCP state flags listed in HIGH must be
 *    set; flags listed in MASK but not in HIGH must be low; flags not
 *    listed in MASK can have any value.  It is an error if a flag is
 *    listed in HIGH but not in MASK; that is, HIGH must be a subset
 *    of MASK.
 *
 *    If successful, returns 0.  Otherwise, an silk_utils_errcode_t
 *    value is returned.
 *
 *    The inputs 'high' and 'mask' are overwritten with the bitmap of
 *    the flags set.
 *
 *    It is an error for any trailing text (other than whitespace) to
 *    follow the MASK.  Returns SKUTILS_ERR_SHORT if MASK has no
 *    value; returns SKUTILS_ERR_BAD_RANGE if HIGH is not a subset of
 *    MASK.
 */
int
skStringParseTCPStateHighMask(
    uint8_t            *high,
    uint8_t            *mask,
    const char         *flag_string);


/**
 *    Return the name of the signal that has the specified value.  The
 *    returned string does not include the "SIG" prefix.  For example,
 *    calling this function with the value 9 returns "KILL".
 *
 *    If 'signal_number' is not recognized as a signal, the return
 *    value is "?".
 */
const char *
skSignalToName(
    int                 signal_num);


/**
 *    Parse 'signal_name' as either the name of a signal or the number
 *    of a signal.  The leading "SIG" on 'signal_name' is optional.
 *
 *    If the first non-whitespace chacter in 'signal_name' is a digit,
 *    the return value is similar to that for skStringParseUint32().
 *
 *    The function returns 0 if 'signal_name' only contains a signal
 *    name and optional leading and/or trailing whitespace.
 *
 *    A return value greater than 0 indicates that a signal name was
 *    parsed, but that additional text appears in the string.  The
 *    return value indicates the number of character that were parsed.
 *
 *    On error, the function returns one of the following values:
 *    SKUTILS_ERR_INVALID if an input value is NULL; SKUTILS_ERR_EMPTY
 *    if 'signal_name' contains only whitespace, or
 *    SKUTILS_ERR_BAD_CHAR if the string does not contain a valid
 *    signal name.
 */
int
skStringParseSignal(
    int                *signal_num,
    const char         *signal_name);


#ifdef __cplusplus
}
#endif
#endif /* _UTILS_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
