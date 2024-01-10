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
**  skunique.c
**
**    This is an attempt to make the bulk of rwuniq into a stand-alone
**    library.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skunique.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/hashlib.h>
#include <silk/rwascii.h>
#include <silk/rwrec.h>
#include <silk/skheap.h>
#include <silk/skstream.h>
#include <silk/sktempfile.h>
#include <silk/skvector.h>
#include <silk/utils.h>
#include "skunique.h"

#ifdef SKUNIQUE_TRACE_LEVEL
#define TRACEMSG_LEVEL 1
#endif
#define TRACEMSG(x)  TRACEMSG_TO_TRACEMSGLVL(1, x)
#include <silk/sktracemsg.h>


#ifndef SKUNIQ_USE_MEMCPY
#ifdef SK_HAVE_ALIGNED_ACCESS_REQUIRED
#define SKUNIQ_USE_MEMCPY 1
#else
#define SKUNIQ_USE_MEMCPY 0
#endif
#endif


#define HASH_MAX_NODE_BYTES  (HASHLIB_MAX_KEY_WIDTH + HASHLIB_MAX_VALUE_WIDTH)

#define HASH_INITIAL_SIZE    500000

#define MAX_MERGE_FILES 1024

#define COMP_FUNC_CAST(cfc_func)                                \
    (int (*)(const void*, const void*, void*))(cfc_func)


/* Print debugging messages when this environment variable is set to a
 * positive integer. */
#define SKUNIQUE_DEBUG_ENVAR "SILK_UNIQUE_DEBUG"

/*
 *  UNIQUE_DEBUG(ud_uniq, (ud_msg, ...));
 *
 *    Print a message when the print_debug member of the unique object
 *    'ud_uniq' is active.  The message and any arguments it requires
 *    must be wrapped in parentheses.
 *
 *    UNIQUE_DEBUG(uniq, ("one is %d and two is %d", 1, 2));
 */
#define UNIQUE_DEBUG(ud_uniq, ud_msg)                   \
    if (!(ud_uniq)->print_debug) { /*no-op*/ } else {   \
        skAppPrintErr ud_msg;                           \
    }


/*
 *    Return the name of the current temporary file used for output on
 *    the sk_unique_t object 'm_uniq'.
 */
#define UNIQUE_TMPNAME_OUT(m_uniq)                                      \
    uniqBasename(skTempFileGetName((m_uniq)->tmpctx, (m_uniq)->temp_idx))

/*
 *    Given the number 'm_idx' which is an index into the fps[] array
 *    on the structure 'sk_sort_unique_t', 'uniqiter_temp_dist_t', or
 *    'uniqiter_temp_values_t' pointed to by 'm_uniq', return the
 *    absolute number identifier for that temporary file.
 */
#define UNIQUE_TMPNUM_READ(m_uniq, m_idx)       \
    ((m_uniq)->temp_idx_base + (m_idx))



/* FUNCTION DEFINITIONS */


/* **************************************************************** */

/*    FIELD LIST */

/* **************************************************************** */


/* Maximum number of fields that may be specified. */
#define FIELDLIST_MAX_NUM_FIELDS    (HASHLIB_MAX_KEY_WIDTH >> 1)

#define COMPARE(cmp_a, cmp_b)                                   \
    (((cmp_a) < (cmp_b)) ? -1 : (((cmp_a) > (cmp_b)) ? 1 : 0))

#define WARN_OVERFLOW(wo_max, wo_a, wo_b)                       \
    if (wo_max - wo_b >= wo_a) { /* ok */ } else {              \
        skAppPrintErr("Overflow at %s:%d", __FILE__, __LINE__); \
    }

#if !SKUNIQ_USE_MEMCPY

#define CMP_INT_PTRS(cmp_out, cmp_type, cmp_a, cmp_b)                   \
    {                                                                   \
        cmp_out = COMPARE(*(cmp_type *)(cmp_a), *(cmp_type *)(cmp_b));  \
    }

#define MERGE_INT_PTRS(mrg_max, mrg_type, mrg_a, mrg_b)                 \
    {                                                                   \
        WARN_OVERFLOW(mrg_max, *(mrg_type*)(mrg_a), *(mrg_type*)(mrg_b)); \
        *(mrg_type*)(mrg_a) += *(mrg_type*)(mrg_b);                     \
    }

#define ADD_TO_INT_PTR(mrg_type, mrg_ptr, mrg_val)      \
    {                                                   \
        *((mrg_type*)(mrg_ptr)) += mrg_val;             \
    }

#define MIN_UPDATE_FROM_INT(mrg_type, mrg_inout_ptr, mrg_other_val)     \
    {                                                                   \
        mrg_type *mufi_a = (mrg_type*)(mrg_inout_ptr);                  \
        if (((mrg_type)(mrg_other_val)) < *mufi_a) {                    \
            *mufi_a = (mrg_other_val);                                  \
        }                                                               \
    }

#define MIN_MERGE_INT_PTRS(mrg_type, mrg_inout_ptr, mrg_other_ptr)      \
    {                                                                   \
        mrg_type *mmip_b = (mrg_type*)(mrg_other_ptr);                  \
        MIN_UPDATE_FROM_INT(mrg_type, mrg_inout_ptr, *mmip_b);          \
    }

#define MAX_UPDATE_FROM_INT(mrg_type, mrg_inout_ptr, mrg_other_val)     \
    {                                                                   \
        mrg_type *mufi_a = (mrg_type*)(mrg_inout_ptr);                  \
        if (((mrg_type)(mrg_other_val)) > *mufi_a) {                    \
            *mufi_a = (mrg_other_val);                                  \
        }                                                               \
    }

#define MAX_MERGE_INT_PTRS(mrg_type, mrg_inout_ptr, mrg_other_ptr)      \
    {                                                                   \
        mrg_type *mmip_b = (mrg_type*)(mrg_other_ptr);                  \
        MAX_UPDATE_FROM_INT(mrg_type, mrg_inout_ptr, *mmip_b);          \
    }

#else  /* #if !SKUNIQ_USE_MEMCPY */

#define CMP_INT_PTRS(cmp_out, cmp_type, cmp_a, cmp_b)   \
    {                                                   \
        cmp_type cip_val_a;                             \
        cmp_type cip_val_b;                             \
                                                        \
        memcpy(&cip_val_a, (cmp_a), sizeof(cmp_type));  \
        memcpy(&cip_val_b, (cmp_b), sizeof(cmp_type));  \
                                                        \
        cmp_out = COMPARE(cip_val_a, cip_val_b);        \
    }

#define MERGE_INT_PTRS(mrg_max, mrg_type, mrg_a, mrg_b) \
    {                                                   \
        mrg_type mip_val_a;                             \
        mrg_type mip_val_b;                             \
                                                        \
        memcpy(&mip_val_a, (mrg_a), sizeof(mrg_type));  \
        memcpy(&mip_val_b, (mrg_b), sizeof(mrg_type));  \
                                                        \
        WARN_OVERFLOW(mrg_max, mip_val_a, mip_val_b);   \
        mip_val_a += mip_val_b;                         \
        memcpy((mrg_a), &mip_val_a, sizeof(mrg_type));  \
    }

#define ADD_TO_INT_PTR(mrg_type, mrg_ptr, mrg_val)              \
    {                                                           \
        mrg_type atip_val_a;                                    \
                                                                \
        memcpy(&atip_val_a, (mrg_ptr), sizeof(mrg_type));       \
        atip_val_a += mrg_val;                                  \
        memcpy((mrg_ptr), &atip_val_a, sizeof(mrg_type));       \
    }

#define MIN_UPDATE_FROM_INT(mrg_type, mrg_inout_ptr, mrg_other_val)     \
    {                                                                   \
        mrg_type mufi_a;                                                \
        memcpy(&mufi_a, (mrg_inout_ptr), sizeof(mrg_type));             \
        if (((mrg_type)(mrg_other_val)) < mufi_a) {                     \
            mufi_a = (mrg_other_val);                                   \
            memcpy((mrg_inout_ptr), &mufi_a, sizeof(mrg_type));         \
        }                                                               \
    }

#define MIN_MERGE_INT_PTRS(mrg_type, mrg_inout_ptr, mrg_other_ptr)      \
    {                                                                   \
        mrg_type mmip_b;                                                \
        memcpy(&mmip_b, (mrg_other_ptr), sizeof(mrg_type));             \
        MIN_UPDATE_FROM_INT(mrg_type, mrg_inout_ptr, mmip_b);           \
    }

#define MAX_UPDATE_FROM_INT(mrg_type, mrg_inout_ptr, mrg_other_val)     \
    {                                                                   \
        mrg_type mufi_a;                                                \
        memcpy(&mufi_a, (mrg_inout_ptr), sizeof(mrg_type));             \
        if (((mrg_type)(mrg_other_val)) > mufi_a) {                     \
            mufi_a = (mrg_other_val);                                   \
            memcpy((mrg_inout_ptr), &mufi_a, sizeof(mrg_type));         \
        }                                                               \
    }

#define MAX_MERGE_INT_PTRS(mrg_type, mrg_inout_ptr, mrg_other_ptr)      \
    {                                                                   \
        mrg_type mmip_b;                                                \
        memcpy(&mmip_b, (mrg_other_ptr), sizeof(mrg_type));             \
        MAX_UPDATE_FROM_INT(mrg_type, mrg_inout_ptr, mmip_b);           \
    }

#endif  /* #else of #if !SKUNIQ_USE_MEMCPY */

/* typedef struct sk_fieldentry_st sk_fieldentry_t; */
struct sk_fieldentry_st {
    sk_fieldlist_rec_to_bin_fn_t    rec_to_bin;
    sk_fieldlist_bin_cmp_fn_t       bin_compare;
    sk_fieldlist_rec_to_bin_fn_t    add_rec_to_bin;
    sk_fieldlist_bin_merge_fn_t     bin_merge;
    sk_fieldlist_output_fn_t        bin_output;

    int                             id;

    /* the byte-offset where this field begins in the binary key used
     * for binning. */
    size_t                          offset;
    size_t                          octets;
    void                           *context;

    uint8_t                        *initial_value;

    sk_fieldlist_t                 *parent_list;
};


/* typedef struct sk_fieldlist_st struct sk_fieldlist_t; */
struct sk_fieldlist_st {
    sk_fieldentry_t    fields[FIELDLIST_MAX_NUM_FIELDS];
    size_t             num_fields;
    size_t             total_octets;
};


/*  compare arbitrary buffers of size len */
int
skFieldCompareMemcmp(
    const void         *a,
    const void         *b,
    void               *len)
{
    /* FIXME.  size_t or unit32_t? */
    return memcmp(a, b, *(size_t*)len);
}


/*  compare buffers containing uint8_t */
int
skFieldCompareUint8(
    const void         *a,
    const void         *b,
    void        UNUSED(*ctx))
{
    return COMPARE(*(uint8_t*)a, *(uint8_t*)b);
}

/*  merge buffers containing uint8_t */
void
skFieldMergeUint8(
    void               *a,
    const void         *b,
    void        UNUSED(*ctx))
{
    WARN_OVERFLOW(UINT8_MAX, *(uint8_t*)a, *(uint8_t*)b);
    *(uint8_t*)a += *(uint8_t*)b;
}


/*  compare buffers containing uint16_t */
int
skFieldCompareUint16(
    const void         *a,
    const void         *b,
    void        UNUSED(*ctx))
{
    int rv;
    CMP_INT_PTRS(rv, uint16_t, a, b);
    return rv;
}

/*  merge buffers containing uint16_t */
void
skFieldMergeUint16(
    void               *a,
    const void         *b,
    void        UNUSED(*ctx))
{
    MERGE_INT_PTRS(UINT16_MAX, uint16_t, a, b);
}


/*  compare buffers containing uint32_t */
int
skFieldCompareUint32(
    const void         *a,
    const void         *b,
    void        UNUSED(*ctx))
{
    int rv;
    CMP_INT_PTRS(rv, uint32_t, a, b);
    return rv;
}

/*  merge buffers containing uint32_t */
void
skFieldMergeUint32(
    void               *a,
    const void         *b,
    void        UNUSED(*ctx))
{
    MERGE_INT_PTRS(UINT32_MAX, uint32_t, a, b);
}


/*  compare buffers containing uint64_t */
int
skFieldCompareUint64(
    const void         *a,
    const void         *b,
    void        UNUSED(*ctx))
{
    int rv;
    CMP_INT_PTRS(rv, uint64_t, a, b);
    return rv;
}

/*  merge buffers containing uint64_t */
void
skFieldMergeUint64(
    void               *a,
    const void         *b,
    void        UNUSED(*ctx))
{
    MERGE_INT_PTRS(UINT64_MAX, uint64_t, a, b);
}

/*  create a new field list */
int
skFieldListCreate(
    sk_fieldlist_t    **field_list)
{
    sk_fieldlist_t *fl;

    fl = (sk_fieldlist_t*)calloc(1, sizeof(sk_fieldlist_t));
    if (NULL == fl) {
        return -1;
    }

    *field_list = fl;
    return 0;
}

/*  destroy a field list */
void
skFieldListDestroy(
    sk_fieldlist_t    **field_list)
{
    sk_fieldlist_t *fl;
    sk_fieldentry_t *field;
    size_t i;

    if (NULL == field_list || NULL == *field_list) {
        return;
    }

    fl = *field_list;
    *field_list = NULL;

    for (i = 0, field = fl->fields; i < fl->num_fields; ++i, ++field) {
        if (field->initial_value) {
            free(field->initial_value);
        }
    }

    free(fl);
}


/*  add an arbitrary field to a field list */
sk_fieldentry_t *
skFieldListAddField(
    sk_fieldlist_t                 *field_list,
    const sk_fieldlist_entrydata_t *regdata,
    void                           *ctx)
{
    sk_fieldentry_t *field = NULL;
    size_t i;

    if (NULL == field_list || NULL == regdata) {
        return NULL;
    }
    if (FIELDLIST_MAX_NUM_FIELDS == field_list->num_fields) {
        return NULL;
    }

    field = &field_list->fields[field_list->num_fields];
    ++field_list->num_fields;

    memset(field, 0, sizeof(sk_fieldentry_t));
    field->offset = field_list->total_octets;
    field->context = ctx;
    field->parent_list = field_list;
    field->id = SK_FIELD_CALLER;

    field->octets = regdata->bin_octets;
    field->rec_to_bin = regdata->rec_to_bin;
    field->bin_compare = regdata->bin_compare;
    field->add_rec_to_bin = regdata->add_rec_to_bin;
    field->bin_merge = regdata->bin_merge;
    field->bin_output = regdata->bin_output;
    if (regdata->initial_value) {
        /* only create space for value if it contains non-NUL */
        for (i = 0; i < field->octets; ++i) {
            if ('\0' != regdata->initial_value[i]) {
                field->initial_value = (uint8_t*)malloc(field->octets);
                if (NULL == field->initial_value) {
                    --field_list->num_fields;
                    return NULL;
                }
                memcpy(field->initial_value, regdata->initial_value,
                       field->octets);
                break;
            }
        }
    }

    field_list->total_octets += field->octets;

    return field;
}


/*  add a defined field to a field list */
sk_fieldentry_t *
skFieldListAddKnownField(
    sk_fieldlist_t     *field_list,
    int                 field_id,
    void               *ctx)
{
    sk_fieldentry_t *field = NULL;
    int bin_octets = 0;

    if (NULL == field_list) {
        return NULL;
    }
    if (FIELDLIST_MAX_NUM_FIELDS == field_list->num_fields) {
        return NULL;
    }

    switch (field_id) {
      case SK_FIELD_SIPv4:
      case SK_FIELD_DIPv4:
      case SK_FIELD_NHIPv4:
      case SK_FIELD_PACKETS:
      case SK_FIELD_BYTES:
      case SK_FIELD_STARTTIME:
      case SK_FIELD_ELAPSED:
      case SK_FIELD_ELAPSED_MSEC:
      case SK_FIELD_ENDTIME:
      case SK_FIELD_SUM_ELAPSED:
      case SK_FIELD_MIN_STARTTIME:
      case SK_FIELD_MAX_ENDTIME:
        bin_octets = 4;
        break;

      case SK_FIELD_SPORT:
      case SK_FIELD_DPORT:
      case SK_FIELD_SID:
      case SK_FIELD_INPUT:
      case SK_FIELD_OUTPUT:
      case SK_FIELD_APPLICATION:
        bin_octets = 2;
        break;

      case SK_FIELD_PROTO:
      case SK_FIELD_FLAGS:
      case SK_FIELD_INIT_FLAGS:
      case SK_FIELD_REST_FLAGS:
      case SK_FIELD_TCP_STATE:
      case SK_FIELD_FTYPE_CLASS:
      case SK_FIELD_FTYPE_TYPE:
      case SK_FIELD_ICMP_TYPE:
      case SK_FIELD_ICMP_CODE:
        bin_octets = 1;
        break;

      case SK_FIELD_RECORDS:
      case SK_FIELD_SUM_PACKETS:
      case SK_FIELD_SUM_BYTES:
      case SK_FIELD_SUM_ELAPSED_MSEC:
      case SK_FIELD_STARTTIME_MSEC:
      case SK_FIELD_ENDTIME_MSEC:
      case SK_FIELD_MIN_STARTTIME_MSEC:
      case SK_FIELD_MAX_ENDTIME_MSEC:
        bin_octets = 8;
        break;

      case SK_FIELD_SIPv6:
      case SK_FIELD_DIPv6:
      case SK_FIELD_NHIPv6:
        bin_octets = 16;
        break;

      case SK_FIELD_CALLER:
        break;
    }

    if (bin_octets == 0) {
        skAppPrintErr("Unknown field id %d", field_id);
        return NULL;
    }

    field = &field_list->fields[field_list->num_fields];
    ++field_list->num_fields;

    memset(field, 0, sizeof(sk_fieldentry_t));
    field->offset = field_list->total_octets;
    field->octets = bin_octets;
    field->parent_list = field_list;
    field->id = field_id;
    field->context = ctx;

    field_list->total_octets += bin_octets;

    return field;
}


/*  return context for a field */
void *
skFieldListEntryGetContext(
    const sk_fieldentry_t  *field)
{
    assert(field);
    return field->context;
}


/*  return integer identifier for a field */
uint32_t
skFieldListEntryGetId(
    const sk_fieldentry_t  *field)
{
    assert(field);
    return field->id;
}


/*  return (binary) length for a field */
size_t
skFieldListEntryGetBinOctets(
    const sk_fieldentry_t  *field)
{
    assert(field);
    return field->octets;
}


/*  return (binary) size of all fields in 'field_list' */
size_t
skFieldListGetBufferSize(
    const sk_fieldlist_t   *field_list)
{
    assert(field_list);
    return field_list->total_octets;
}


/*  return number of fields in the field_list */
size_t
skFieldListGetFieldCount(
    const sk_fieldlist_t   *field_list)
{
    assert(field_list);
    return field_list->num_fields;
}


/*  get pointer to a specific field in an encoded buffer */
#define FIELD_PTR(all_fields_buffer, flent)     \
    ((all_fields_buffer) + (flent)->offset)

#if !SKUNIQ_USE_MEMCPY

#define REC_TO_KEY_SZ(rtk_type, rtk_val, rtk_buf, rtk_flent)    \
    { *((rtk_type*)FIELD_PTR(rtk_buf, rtk_flent)) = rtk_val; }

#else

#define REC_TO_KEY_SZ(rtk_type, rtk_val, rtk_buf, rtk_flent)    \
    {                                                           \
        rtk_type rtk_tmp = rtk_val;                             \
        memcpy(FIELD_PTR(rtk_buf, rtk_flent), &rtk_tmp,         \
               sizeof(rtk_type));                               \
    }

#endif


#define REC_TO_KEY_64(val, all_fields_buffer, flent)            \
    REC_TO_KEY_SZ(uint64_t, val, all_fields_buffer, flent)

#define REC_TO_KEY_32(val, all_fields_buffer, flent)              \
    REC_TO_KEY_SZ(uint32_t, val, all_fields_buffer, flent)

#define REC_TO_KEY_16(val, all_fields_buffer, flent)              \
    REC_TO_KEY_SZ(uint16_t, val, all_fields_buffer, flent)

#define REC_TO_KEY_08(val, all_fields_buffer, flent)      \
    { *(FIELD_PTR(all_fields_buffer, flent)) = val; }



/*  get the binary value for each field in 'field_list' and set that
 *  value in 'all_fields_buffer' */
void
skFieldListRecToBinary(
    const sk_fieldlist_t   *field_list,
    const rwRec            *rwrec,
    uint8_t                *bin_buffer)
{
    const rwRec *rec_ipv4 = NULL;
    const sk_fieldentry_t *f;
    size_t i;

#if !SK_ENABLE_IPV6
#define  FIELDLIST_RWREC_TO_IPV4                \
    rec_ipv4 = rwrec
#else

    const rwRec *rec_ipv6 = NULL;
    rwRec rec_tmp;

    /* ensure we have an IPv4 record when extracting IPv4
     * addresses. If record is IPv6 and cannot be converted to IPv4,
     * use 0 as the IP address. */
#define  FIELDLIST_RWREC_TO_IPV4                \
    if (rec_ipv4) { /* no-op */ }               \
    else if (!rwRecIsIPv6(rwrec)) {             \
        rec_ipv4 = rwrec;                       \
    } else {                                    \
        rec_ipv4 = &rec_tmp;                    \
        RWREC_COPY(&rec_tmp, rwrec);            \
        if (rwRecConvertToIPv4(&rec_tmp)) {     \
            RWREC_CLEAR(&rec_tmp);              \
        }                                       \
    }

    /* ensure we have an IPv6 record when extracting IPv6 addresses */
#define  FIELDLIST_RWREC_TO_IPV6                \
    if (rec_ipv6) { /* no-op */ }               \
    else if (rwRecIsIPv6(rwrec)) {              \
        rec_ipv6 = rwrec;                       \
    } else {                                    \
        rec_ipv6 = &rec_tmp;                    \
        RWREC_COPY(&rec_tmp, rwrec);            \
        rwRecConvertToIPv6(&rec_tmp);           \
    }
#endif  /* #else of #if !SK_ENABLE_IPV6 */


    for (i = 0, f = field_list->fields; i < field_list->num_fields; ++i, ++f) {
        if (f->rec_to_bin) {
            f->rec_to_bin(rwrec, FIELD_PTR(bin_buffer, f), f->context);
        } else {
            switch (f->id) {
#if SK_ENABLE_IPV6
              case SK_FIELD_SIPv6:
                FIELDLIST_RWREC_TO_IPV6;
                rwRecMemGetSIPv6(rec_ipv6, FIELD_PTR(bin_buffer, f));
                break;
              case SK_FIELD_DIPv6:
                FIELDLIST_RWREC_TO_IPV6;
                rwRecMemGetDIPv6(rec_ipv6, FIELD_PTR(bin_buffer, f));
                break;
              case SK_FIELD_NHIPv6:
                FIELDLIST_RWREC_TO_IPV6;
                rwRecMemGetNhIPv6(rec_ipv6, FIELD_PTR(bin_buffer, f));
                break;
#endif  /* SK_ENABLE_IPV6 */

              case SK_FIELD_SIPv4:
                FIELDLIST_RWREC_TO_IPV4;
                REC_TO_KEY_32(rwRecGetSIPv4(rec_ipv4), bin_buffer, f);
                break;
              case SK_FIELD_DIPv4:
                FIELDLIST_RWREC_TO_IPV4;
                REC_TO_KEY_32(rwRecGetDIPv4(rec_ipv4), bin_buffer, f);
                break;
              case SK_FIELD_NHIPv4:
                FIELDLIST_RWREC_TO_IPV4;
                REC_TO_KEY_32(rwRecGetNhIPv4(rec_ipv4), bin_buffer, f);
                break;
              case SK_FIELD_SPORT:
                REC_TO_KEY_16(rwRecGetSPort(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_DPORT:
                REC_TO_KEY_16(rwRecGetDPort(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_ICMP_TYPE:
                if (rwRecIsICMP(rwrec)) {
                    REC_TO_KEY_08(rwRecGetIcmpType(rwrec), bin_buffer, f);
                } else {
                    REC_TO_KEY_08(0, bin_buffer, f);
                }
                break;
              case SK_FIELD_ICMP_CODE:
                if (rwRecIsICMP(rwrec)) {
                    REC_TO_KEY_08(rwRecGetIcmpCode(rwrec), bin_buffer, f);
                } else {
                    REC_TO_KEY_08(0, bin_buffer, f);
                }
                break;
              case SK_FIELD_PROTO:
                REC_TO_KEY_08(rwRecGetProto(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_PACKETS:
                REC_TO_KEY_32(rwRecGetPkts(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_BYTES:
                REC_TO_KEY_32(rwRecGetBytes(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_FLAGS:
                REC_TO_KEY_08(rwRecGetFlags(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_SID:
                REC_TO_KEY_16(rwRecGetSensor(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_INPUT:
                REC_TO_KEY_16(rwRecGetInput(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_OUTPUT:
                REC_TO_KEY_16(rwRecGetOutput(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_INIT_FLAGS:
                REC_TO_KEY_08(rwRecGetInitFlags(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_REST_FLAGS:
                REC_TO_KEY_08(rwRecGetRestFlags(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_TCP_STATE:
                REC_TO_KEY_08(
                    (rwRecGetTcpState(rwrec) & SK_TCPSTATE_ATTRIBUTE_MASK),
                    bin_buffer, f);
                break;
              case SK_FIELD_APPLICATION:
                REC_TO_KEY_16(rwRecGetApplication(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_FTYPE_CLASS:
              case SK_FIELD_FTYPE_TYPE:
                REC_TO_KEY_08(rwRecGetFlowType(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_STARTTIME:
                REC_TO_KEY_32(rwRecGetStartSeconds(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_ELAPSED:
                REC_TO_KEY_32(rwRecGetElapsedSeconds(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_ENDTIME:
                REC_TO_KEY_32(rwRecGetEndSeconds(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_STARTTIME_MSEC:
                REC_TO_KEY_64(rwRecGetStartTime(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_ELAPSED_MSEC:
                REC_TO_KEY_32(rwRecGetElapsed(rwrec), bin_buffer, f);
                break;
              case SK_FIELD_ENDTIME_MSEC:
                REC_TO_KEY_64(rwRecGetEndTime(rwrec), bin_buffer, f);
                break;
              default:
                break;
            }
        }
    }
}


/*  add the binary value for each field in 'field_list' to the values
 *  in 'all_fields_buffer' */
void
skFieldListAddRecToBuffer(
    const sk_fieldlist_t   *field_list,
    const rwRec            *rwrec,
    uint8_t                *summed)
{
    const sk_fieldentry_t *f;
    size_t i;

    for (i = 0, f = field_list->fields; i < field_list->num_fields; ++i, ++f) {
        if (f->add_rec_to_bin) {
            f->add_rec_to_bin(rwrec, FIELD_PTR(summed, f), f->context);
        } else {
            switch (f->id) {
              case SK_FIELD_RECORDS:
                ADD_TO_INT_PTR(uint64_t, FIELD_PTR(summed, f), 1);
                break;

              case SK_FIELD_SUM_BYTES:
                ADD_TO_INT_PTR(uint64_t, FIELD_PTR(summed, f),
                               rwRecGetBytes(rwrec));
                break;

              case SK_FIELD_SUM_PACKETS:
                ADD_TO_INT_PTR(uint64_t, FIELD_PTR(summed, f),
                               rwRecGetPkts(rwrec));
                break;

              case SK_FIELD_SUM_ELAPSED:
                ADD_TO_INT_PTR(uint32_t, FIELD_PTR(summed, f),
                               rwRecGetElapsedSeconds(rwrec));
                break;

              case SK_FIELD_SUM_ELAPSED_MSEC:
                ADD_TO_INT_PTR(uint64_t, FIELD_PTR(summed, f),
                               rwRecGetElapsed(rwrec));
                break;

              case SK_FIELD_MIN_STARTTIME:
                MIN_UPDATE_FROM_INT(uint32_t, FIELD_PTR(summed, f),
                                    rwRecGetStartSeconds(rwrec));
                break;

              case SK_FIELD_MAX_ENDTIME:
                MAX_UPDATE_FROM_INT(uint32_t, FIELD_PTR(summed, f),
                                    rwRecGetEndSeconds(rwrec));
                break;

              case SK_FIELD_MIN_STARTTIME_MSEC:
                MIN_UPDATE_FROM_INT(uint64_t, FIELD_PTR(summed, f),
                                    rwRecGetStartTime(rwrec));
                break;

              case SK_FIELD_MAX_ENDTIME_MSEC:
                MAX_UPDATE_FROM_INT(uint64_t, FIELD_PTR(summed, f),
                                    rwRecGetEndSeconds(rwrec));
                break;

              case SK_FIELD_CALLER:
                break;

              default:
                break;
            }
        }
    }
}


/*  set 'all_fields_buffer' to the initial value for each field in the
 *  field list. */
void
skFieldListInitializeBuffer(
    const sk_fieldlist_t   *field_list,
    uint8_t                *all_fields_buffer)
{
    const sk_fieldentry_t *f;
    size_t i;

    memset(all_fields_buffer, 0, field_list->total_octets);
    for (i = 0, f = field_list->fields; i < field_list->num_fields; ++i, ++f) {
        if (f->initial_value) {
            memcpy(FIELD_PTR(all_fields_buffer, f), f->initial_value,
                   f->octets);
        } else {
            switch (f->id) {
              case SK_FIELD_MIN_STARTTIME:
              case SK_FIELD_MIN_STARTTIME_MSEC:
                memset(FIELD_PTR(all_fields_buffer, f), 0xFF, f->octets);
                break;
              default:
                break;
            }
        }
    }
}


/*  merge (e.g., add) two buffers for a field list */
void
skFieldListMergeBuffers(
    const sk_fieldlist_t   *field_list,
    uint8_t                *all_fields_buffer1,
    const uint8_t          *all_fields_buffer2)
{
    const sk_fieldentry_t *f;
    size_t i;

    for (i = 0, f = field_list->fields; i < field_list->num_fields; ++i, ++f) {
        if (f->bin_merge) {
            f->bin_merge(FIELD_PTR(all_fields_buffer1, f),
                         FIELD_PTR(all_fields_buffer2, f),
                         f->context);
        } else {
            switch (f->id) {
              case SK_FIELD_SUM_ELAPSED:
                MERGE_INT_PTRS(UINT32_MAX, uint32_t,
                               FIELD_PTR(all_fields_buffer1, f),
                               FIELD_PTR(all_fields_buffer2, f));
                break;

              case SK_FIELD_RECORDS:
              case SK_FIELD_SUM_PACKETS:
              case SK_FIELD_SUM_BYTES:
              case SK_FIELD_SUM_ELAPSED_MSEC:
                MERGE_INT_PTRS(UINT64_MAX, uint64_t,
                               FIELD_PTR(all_fields_buffer1, f),
                               FIELD_PTR(all_fields_buffer2, f));
                break;

              case SK_FIELD_MIN_STARTTIME:
                MIN_MERGE_INT_PTRS(uint32_t, FIELD_PTR(all_fields_buffer1, f),
                                   FIELD_PTR(all_fields_buffer2, f));
                break;

              case SK_FIELD_MAX_ENDTIME:
                MAX_MERGE_INT_PTRS(uint32_t, FIELD_PTR(all_fields_buffer1, f),
                                   FIELD_PTR(all_fields_buffer2, f));
                break;

              case SK_FIELD_MIN_STARTTIME_MSEC:
                MIN_MERGE_INT_PTRS(uint64_t, FIELD_PTR(all_fields_buffer1, f),
                                   FIELD_PTR(all_fields_buffer2, f));
                break;

              case SK_FIELD_MAX_ENDTIME_MSEC:
                MAX_MERGE_INT_PTRS(uint64_t, FIELD_PTR(all_fields_buffer1, f),
                                   FIELD_PTR(all_fields_buffer2, f));
                break;

              default:
                break;
            }
        }
    }
}


/*  compare two field buffers, return -1, 0, 1, if
 *  'all_fields_buffer1' is <, ==, > 'all_fields_buffer2' */
int
skFieldListCompareBuffers(
    const uint8_t          *all_fields_buffer1,
    const uint8_t          *all_fields_buffer2,
    const sk_fieldlist_t   *field_list)
{
    const sk_fieldentry_t *f;
    size_t i;
    int rv = 0;

    for (i = 0, f = field_list->fields;
         rv == 0 && i < field_list->num_fields;
         ++i, ++f)
    {
        if (f->bin_compare) {
            rv = f->bin_compare(FIELD_PTR(all_fields_buffer1, f),
                                FIELD_PTR(all_fields_buffer2, f),
                                f->context);
        } else {
            switch (f->id) {
              case SK_FIELD_SIPv6:
              case SK_FIELD_DIPv6:
              case SK_FIELD_NHIPv6:
                rv = memcmp(FIELD_PTR(all_fields_buffer1, f),
                            FIELD_PTR(all_fields_buffer2, f),
                            f->octets);
                break;

              case SK_FIELD_SIPv4:
              case SK_FIELD_DIPv4:
              case SK_FIELD_NHIPv4:
              case SK_FIELD_PACKETS:
              case SK_FIELD_BYTES:
              case SK_FIELD_STARTTIME:
              case SK_FIELD_ELAPSED:
              case SK_FIELD_ELAPSED_MSEC:
              case SK_FIELD_ENDTIME:
              case SK_FIELD_SUM_ELAPSED:
              case SK_FIELD_MIN_STARTTIME:
              case SK_FIELD_MAX_ENDTIME:
                CMP_INT_PTRS(rv, uint32_t, FIELD_PTR(all_fields_buffer1, f),
                             FIELD_PTR(all_fields_buffer2, f));
                break;

              case SK_FIELD_SPORT:
              case SK_FIELD_DPORT:
              case SK_FIELD_SID:
              case SK_FIELD_INPUT:
              case SK_FIELD_OUTPUT:
              case SK_FIELD_APPLICATION:
                CMP_INT_PTRS(rv, uint16_t, FIELD_PTR(all_fields_buffer1, f),
                             FIELD_PTR(all_fields_buffer2, f));
                break;

              case SK_FIELD_PROTO:
              case SK_FIELD_FLAGS:
              case SK_FIELD_INIT_FLAGS:
              case SK_FIELD_REST_FLAGS:
              case SK_FIELD_TCP_STATE:
              case SK_FIELD_FTYPE_CLASS:
              case SK_FIELD_FTYPE_TYPE:
              case SK_FIELD_ICMP_TYPE:
              case SK_FIELD_ICMP_CODE:
                rv = COMPARE(*(FIELD_PTR(all_fields_buffer1, f)),
                             *(FIELD_PTR(all_fields_buffer2, f)));
                break;

              case SK_FIELD_RECORDS:
              case SK_FIELD_SUM_PACKETS:
              case SK_FIELD_SUM_BYTES:
              case SK_FIELD_SUM_ELAPSED_MSEC:
              case SK_FIELD_STARTTIME_MSEC:
              case SK_FIELD_ENDTIME_MSEC:
              case SK_FIELD_MIN_STARTTIME_MSEC:
              case SK_FIELD_MAX_ENDTIME_MSEC:
                CMP_INT_PTRS(rv, uint64_t, FIELD_PTR(all_fields_buffer1, f),
                             FIELD_PTR(all_fields_buffer2, f));
                break;

              default:
                rv = memcmp(FIELD_PTR(all_fields_buffer1, f),
                            FIELD_PTR(all_fields_buffer2, f),
                            f->octets);
                break;
            }
        }
    }

    return rv;
}


/*  Call the comparison function for a single field entry, where
 *  'field_buffer1' and 'field_buffer2' are pointing at the values
 *  specific to that field. */
int
skFieldListEntryCompareBuffers(
    const uint8_t          *field_buffer1,
    const uint8_t          *field_buffer2,
    const sk_fieldentry_t  *field_entry)
{
    int rv;

    if (field_entry->bin_compare) {
        rv = field_entry->bin_compare(field_buffer1, field_buffer2,
                                      field_entry->context);
    } else {
        switch (field_entry->id) {
          case SK_FIELD_SIPv6:
          case SK_FIELD_DIPv6:
          case SK_FIELD_NHIPv6:
            rv = memcmp(field_buffer1, field_buffer2, field_entry->octets);
            break;

          case SK_FIELD_SIPv4:
          case SK_FIELD_DIPv4:
          case SK_FIELD_NHIPv4:
          case SK_FIELD_PACKETS:
          case SK_FIELD_BYTES:
          case SK_FIELD_STARTTIME:
          case SK_FIELD_ELAPSED:
          case SK_FIELD_ELAPSED_MSEC:
          case SK_FIELD_ENDTIME:
          case SK_FIELD_SUM_ELAPSED:
          case SK_FIELD_MIN_STARTTIME:
          case SK_FIELD_MAX_ENDTIME:
            CMP_INT_PTRS(rv, uint32_t, field_buffer1, field_buffer2);
            break;

          case SK_FIELD_SPORT:
          case SK_FIELD_DPORT:
          case SK_FIELD_SID:
          case SK_FIELD_INPUT:
          case SK_FIELD_OUTPUT:
          case SK_FIELD_APPLICATION:
            CMP_INT_PTRS(rv, uint16_t, field_buffer1, field_buffer2);
            break;

          case SK_FIELD_PROTO:
          case SK_FIELD_FLAGS:
          case SK_FIELD_INIT_FLAGS:
          case SK_FIELD_REST_FLAGS:
          case SK_FIELD_TCP_STATE:
          case SK_FIELD_FTYPE_CLASS:
          case SK_FIELD_FTYPE_TYPE:
          case SK_FIELD_ICMP_TYPE:
          case SK_FIELD_ICMP_CODE:
            rv = COMPARE(*field_buffer1, *field_buffer2);
            break;

          case SK_FIELD_RECORDS:
          case SK_FIELD_SUM_PACKETS:
          case SK_FIELD_SUM_BYTES:
          case SK_FIELD_SUM_ELAPSED_MSEC:
          case SK_FIELD_STARTTIME_MSEC:
          case SK_FIELD_ENDTIME_MSEC:
          case SK_FIELD_MIN_STARTTIME_MSEC:
          case SK_FIELD_MAX_ENDTIME_MSEC:
            CMP_INT_PTRS(rv, uint64_t, field_buffer1, field_buffer2);
            break;

          default:
            rv = memcmp(field_buffer1, field_buffer2, field_entry->octets);
            break;
        }
    }
    return rv;
}


/*  call the output callback for each field */
void
skFieldListOutputBuffer(
    const sk_fieldlist_t   *field_list,
    const uint8_t          *all_fields_buffer);


/* Do we still need the field iterators (as public)? */

/*  bind an iterator to a field list */
void
skFieldListIteratorBind(
    const sk_fieldlist_t       *field_list,
    sk_fieldlist_iterator_t    *iter)
{
    assert(field_list);
    assert(iter);

    memset(iter, 0, sizeof(sk_fieldlist_iterator_t));
    iter->field_list = field_list;
    iter->field_idx = 0;
}

/*  reset the fieldlist iterator */
void
skFieldListIteratorReset(
    sk_fieldlist_iterator_t    *iter)
{
    assert(iter);
    iter->field_idx = 0;
}

/*  get next field-entry from an iterator */
sk_fieldentry_t *
skFieldListIteratorNext(
    sk_fieldlist_iterator_t    *iter)
{
    const sk_fieldentry_t *f = NULL;

    assert(iter);
    if (iter->field_idx < iter->field_list->num_fields) {
        f = &iter->field_list->fields[iter->field_idx];
        ++iter->field_idx;
    }
    return (sk_fieldentry_t*)f;
}


/*  copy the value associated with 'field_id' from 'all_fields_buffer'
 *  and into 'one_field_buf' */
void
skFieldListExtractFromBuffer(
    const sk_fieldlist_t    UNUSED(*field_list),
    const uint8_t                  *all_fields_buffer,
    sk_fieldentry_t                *field_id,
    uint8_t                        *one_field_buf)
{
    assert(field_id->parent_list == field_list);
    memcpy(one_field_buf, FIELD_PTR(all_fields_buffer, field_id),
           field_id->octets);
}



/* **************************************************************** */

/*    HASH SET */

/* **************************************************************** */

/* LOCAL DEFINES AND TYPEDEFS */

typedef struct HashSet_st {
    HashTable   *table;
    uint8_t      is_sorted;
    uint8_t      key_width;
    uint8_t      mod_key;
} HashSet;

typedef struct hashset_iter {
    HASH_ITER    table_iter;
    uint8_t      key[HASHLIB_MAX_KEY_WIDTH];
    uint8_t      val;
} hashset_iter;


/* LOCAL VARIABLE DEFINITIONS */

/* position of least significant bit, as in 1<<N */
static const uint8_t lowest_bit_in_val[] = {
    /*   0- 15 */  8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  16- 31 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  32- 47 */  5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  48- 63 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  64- 79 */  6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  80- 95 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /*  96-111 */  5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 112-127 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 128-143 */  7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 144-159 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 160-175 */  5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 176-191 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 192-207 */  6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 208-223 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 224-239 */  5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    /* 240-255 */  4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
};

#ifndef NDEBUG
/* number of high bits in each value */
static const uint8_t bits_in_value[] = {
    /*   0- 15 */  0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    /*  16- 31 */  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /*  32- 47 */  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /*  48- 63 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /*  64- 79 */  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /*  80- 95 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /*  96-111 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 112-127 */  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 128-143 */  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /* 144-159 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 160-175 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 176-191 */  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 192-207 */  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 208-223 */  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 224-239 */  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 240-255 */  4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};
#endif  /* NDEBUG */


/*
 *  hashset = hashset_create_set(key_width, estimated_count, load_factor);
 *
 *    Create a hashlib hash table that supports storing a bit for each
 *    key.  'key_width' is the number of octets in each key.
 *    'estimated_count' is the number of entries in the hash table.
 *    'load_factor' is the load factor to use for the hashlib table.
 *    Return the new hashset, or NULL on error.
 */
static HashSet *
hashset_create_set(
    uint8_t             key_width,
    uint32_t            estimated_count,
    uint8_t             load_factor)
{
    uint8_t no_value = 0;
    HashSet *hash_set;

    hash_set = (HashSet*)calloc(1, sizeof(HashSet));
    if (NULL == hash_set) {
        return NULL;
    }
    hash_set->key_width = key_width;
    hash_set->mod_key = key_width - 1;
    hash_set->table = hashlib_create_table(key_width, 1, HTT_INPLACE,
                                           &no_value, NULL, 0,
                                           estimated_count, load_factor);
    if (hash_set->table == NULL) {
        free(hash_set);
        return NULL;
    }
    return hash_set;
}


/*
 *  status = hashset_insert(hashset, key);
 *
 *    Set the bit for 'key' in 'hashset'.  Return OK on success.
 *    Return ERR_NOMOREENTRIES or ERR_NOMOREBLOCKS on memory
 *    allocation error.
 */
static int
hashset_insert(
    HashSet            *set_ptr,
    const uint8_t      *key_ptr)
{
    uint8_t tmp_key[HASHLIB_MAX_KEY_WIDTH];
    uint8_t *value_ptr;
    uint8_t bit;
    int rv;

    /* make a new key, masking off the lowest three bits */
    memcpy(tmp_key, key_ptr, set_ptr->key_width);
    tmp_key[set_ptr->mod_key] &= 0xF8;

    /* determine which bit to check/set */
    bit = 1 << (key_ptr[set_ptr->mod_key] & 0x7);

    rv = hashlib_insert(set_ptr->table, tmp_key, &value_ptr);
    switch (rv) {
      case OK_DUPLICATE:
        if (0 == (*value_ptr & bit)) {
            rv = OK;
        }
        /* FALLTHROUGH */
      case OK:
        *value_ptr |= bit;
        break;
    }
    return rv;
}


#if 0                           /* currently unused; #if 0 to avoid warning */
/*
 *  status = hashset_lookup(hashset, key);
 *
 *    Return OK if 'key' is set in 'hashset', or ERR_NOTFOUND if it is
 *    not.
 */
static int
hashset_lookup(
    const HashSet      *set_ptr,
    const uint8_t      *key_ptr)
{
    uint8_t tmp_key[HASHLIB_MAX_KEY_WIDTH];
    uint8_t *value_ptr;
    uint8_t bit;
    int rv;

    /* make a new key, masking off the lowest three bits */
    memcpy(tmp_key, key_ptr, set_ptr->key_width);
    tmp_key[set_ptr->mod_key] &= 0xF8;

    /* determine which bit to check/set */
    bit = 1 << (key_ptr[set_ptr->mod_key] & 0x7);

    rv = hashlib_lookup(set_ptr->table, tmp_key, &value_ptr);
    if (rv == OK && (*value_ptr & bit)) {
        return OK;
    }
    return ERR_NOTFOUND;
}
#endif  /* 0 */


/*
 *  iter = hashset_create_iterator(hashset);
 *
 *    Create an iterator to loop over the bits that are set in
 *    'hashset'.
 */
static hashset_iter
hashset_create_iterator(
    const HashSet      *set_ptr)
{
    hashset_iter iter;

    memset(&iter, 0, sizeof(iter));
    iter.table_iter = hashlib_create_iterator(set_ptr->table);
    return iter;
}


/*
 *  status = hashset_sort_entries(hashset);
 *
 *    Sort the entries in 'hashset'.  This makes the 'hashset'
 *    immutable.
 */
static int
hashset_sort_entries(
    HashSet            *set_ptr)
{
    set_ptr->is_sorted = 1;
    return hashlib_sort_entries(set_ptr->table);
}


/*
 *  status = hashset_iterate(hashset, iter, &key);
 *
 *    Modify 'key' to point to the next key that is set in 'hashset'.
 *    Return OK on success, or ERR_NOMOREENTRIES if 'iter' has visited
 *    all the netries in the 'hashset'.
 */
static int
hashset_iterate(
    const HashSet      *set_ptr,
    hashset_iter       *iter,
    uint8_t           **key_pptr)
{
    uint8_t *hash_key;
    uint8_t *hash_value;
    int rv;

    if (iter->val == 0) {
        /* need to get a key/value pair, which we stash on the iterator */
        rv = hashlib_iterate(set_ptr->table, &iter->table_iter,
                             &hash_key, &hash_value);
        if (rv != OK) {
            return rv;
        }
        memcpy(&iter->key, hash_key, set_ptr->key_width);
        iter->val = hash_value[0];
    }

    /* each key/value pair from the hash table may represent up to 8
     * distinct values.  set the 3 least significant bits of the key
     * we return to the caller based on which bit(s) are set on the
     * value, then clear that bit on the cached value so we don't
     * return it again. */

    switch (lowest_bit_in_val[iter->val]) {
      case 0:
        iter->key[set_ptr->mod_key] = (iter->key[set_ptr->mod_key] & 0xF8);
        iter->val &= 0xFE;
        break;
      case 1:
        iter->key[set_ptr->mod_key] = (iter->key[set_ptr->mod_key] & 0xF8) | 1;
        iter->val &= 0xFD;
        break;
      case 2:
        iter->key[set_ptr->mod_key] = (iter->key[set_ptr->mod_key] & 0xF8) | 2;
        iter->val &= 0xFB;
        break;
      case 3:
        iter->key[set_ptr->mod_key] = (iter->key[set_ptr->mod_key] & 0xF8) | 3;
        iter->val &= 0xF7;
        break;
      case 4:
        iter->key[set_ptr->mod_key] = (iter->key[set_ptr->mod_key] & 0xF8) | 4;
        iter->val &= 0xEF;
        break;
      case 5:
        iter->key[set_ptr->mod_key] = (iter->key[set_ptr->mod_key] & 0xF8) | 5;
        iter->val &= 0xDF;
        break;
      case 6:
        iter->key[set_ptr->mod_key] = (iter->key[set_ptr->mod_key] & 0xF8) | 6;
        iter->val &= 0xBF;
        break;
      case 7:
        iter->key[set_ptr->mod_key] = (iter->key[set_ptr->mod_key] & 0xF8) | 7;
        iter->val &= 0x7F;
        break;
      default:
        skAbortBadCase(lowest_bit_in_val[iter->val]);
    }

    *key_pptr = iter->key;
    return OK;
}


/*
 *  hashset_free_table(hashset);
 *
 *    Free the memory associated with the 'hashset'.
 */
static void
hashset_free_table(
    HashSet            *set_ptr)
{
    if (set_ptr) {
        if (set_ptr->table) {
            hashlib_free_table(set_ptr->table);
            set_ptr->table = NULL;
        }
        free(set_ptr);
    }
}


#ifndef NDEBUG                  /* used only in assert() */
/*
 *  count = hashset_count_entries(hashset);
 *
 *    Count the number the bits that are set in the 'hashset'.
 */
static uint32_t
hashset_count_entries(
    const HashSet      *set_ptr)
{
    HASH_ITER iter;
    uint8_t *key_ptr;
    uint8_t *val_ptr;
    uint32_t count = 0;

    iter = hashlib_create_iterator(set_ptr->table);

    while (hashlib_iterate(set_ptr->table, &iter, &key_ptr, &val_ptr) == OK) {
        count += bits_in_value[*val_ptr];
    }

    return count;
}
#endif /* !NDEBUG */



/* **************************************************************** */

/*    SHORT LIST */

/* **************************************************************** */

#define SK_SHORT_LIST_MAX_ELEMENTS  32

#define SK_SHORT_LIST_ELEM(sle_list, sle_pos)                   \
    ((void*)(((uint8_t*)(sle_list)->sl_data)                    \
             + (sle_pos) * (sle_list)->sl_element_size))

enum sk_short_list_en {
    SK_SHORT_LIST_OK = 0,
    SK_SHORT_LIST_OK_DUPLICATE = 1,
    SK_SHORT_LIST_ERR_ALLOC = -1,
    SK_SHORT_LIST_ERR_FULL = -2
};


typedef struct sk_short_list_st {
    /* size of elements, as specified by user */
    uint32_t    sl_element_size;
    /* number of current elements */
    uint32_t    sl_element_count;
    /* comarison function */
    int        (*sl_compare_fn)(const void *, const void *, void *);
    void        *sl_compare_data;
    /* data[] is a variable sized array; use a uint64_t to ensure data
     * is properly aligned to hold uint64_t's. */
    uint64_t    sl_data[1];
} sk_short_list_t;


/*
 *  status = skShortListCreate(&list, element_size, cmp_func, cmp_func_data);
 *
 *    Create a new short-list object at the address specified in
 *    'list', where the size of each element is 'element_size'.  The
 *    list object will use 'cmp_func' to compare keys.  Return 0 on
 *    success, or -1 on failure.
 */
static int
skShortListCreate(
    sk_short_list_t   **list,
    size_t              element_size,
    int               (*compare_function)(const void *, const void *, void *),
    void               *compare_user_data);

/*
 *  skShortListDestroy(&list);
 *
 *    Destroy the short-list object at 'list'.  Does nothing if 'list'
 *    or the object that 'list' refers to is NULL.
 */
static void
skShortListDestroy(
    sk_short_list_t   **list);

/*
 *  count = skShortListCountEntries(list);
 *
 *    Count the number of entries in list.
 */
static uint32_t
skShortListCountEntries(
    const sk_short_list_t  *list);

/*
 *  object = skShortListGetElement(list, position);
 *
 *    Get the object in 'list' at 'position'.  Return NULL if there is
 *    no object at 'position'.  The caller must treat the returned
 *    value as immutable.
 */
static const void *
skShortListGetElement(
    const sk_short_list_t  *list,
    uint32_t                position);

/*
 *  skShortListRemoveAll(list);
 *
 *    Remove all the entries in 'list'.
 */
static void
skShortListRemoveAll(
    sk_short_list_t    *list);

/*
 *  status = skShortListInsert(list, object);
 *
 *    Add 'object' to the short-list 'list'.  Return SK_SHORT_LIST_OK
 *    if 'object' is a new entry in 'list'.  Return
 *    SK_SHORT_LIST_OK_DUPLICATE if 'object' already existed in
 *    'list'.  Return SK_SHORT_LIST_ERR_FULL if there is no room in
 *    'list' for the entry.
 */
static int
skShortListInsert(
    sk_short_list_t    *list,
    const void         *element);


/*  create a short-list */
static int
skShortListCreate(
    sk_short_list_t   **list,
    size_t              element_size,
    int               (*compare_function)(const void *, const void *, void *),
    void               *compare_user_data)
{
    assert(list);

    if (0 == element_size) {
        return -1;
    }
    *list = ((sk_short_list_t*)
             malloc(offsetof(sk_short_list_t, sl_data)
                    + (element_size * SK_SHORT_LIST_MAX_ELEMENTS)));
    if (NULL == *list) {
        return SK_SHORT_LIST_ERR_ALLOC;
    }
    (*list)->sl_element_size = element_size;
    (*list)->sl_element_count = 0;
    (*list)->sl_compare_fn = compare_function;
    (*list)->sl_compare_data = compare_user_data;
    return 0;
}


/*  destroy a short-list */
static void
skShortListDestroy(
    sk_short_list_t   **list)
{
    if (list && *list) {
        free(*list);
        *list = NULL;
    }
}


/*  count number of entries in the short-list */
static uint32_t
skShortListCountEntries(
    const sk_short_list_t  *list)
{
    return list->sl_element_count;
}


/*  get object at 'position' in 'list' */
static const void *
skShortListGetElement(
    const sk_short_list_t  *list,
    uint32_t                position)
{
    assert(list);
    if (position >= list->sl_element_count) {
        return NULL;
    }
    return SK_SHORT_LIST_ELEM(list, position);
}


/*  remove all the entries in 'list' */
static void
skShortListRemoveAll(
    sk_short_list_t    *list)
{
    assert(list);
    list->sl_element_count = 0;
}


/*  add 'element' to 'list' */
static int
skShortListInsert(
    sk_short_list_t    *list,
    const void         *element)
{
    int cmp;
    int top = list->sl_element_count - 1;
    int bot = 0;
    int pos;

    assert(list);
    assert(element);

    /* binary search */
    while (top >= bot) {
        pos = (bot + top) >> 1;
        cmp = list->sl_compare_fn(element, SK_SHORT_LIST_ELEM(list, pos),
                                  list->sl_compare_data);
        if (cmp < 0) {
            top = pos - 1;
        } else if (cmp > 0) {
            bot = pos + 1;
        } else {
            return SK_SHORT_LIST_OK_DUPLICATE;
        }
    }

    if (list->sl_element_count == SK_SHORT_LIST_MAX_ELEMENTS) {
        return SK_SHORT_LIST_ERR_FULL;
    }

    if (bot < (int)list->sl_element_count) {
        /* must move elements */
        memmove(SK_SHORT_LIST_ELEM(list, bot+1), SK_SHORT_LIST_ELEM(list, bot),
                (list->sl_element_count - bot) * list->sl_element_size);
    }
    memcpy(SK_SHORT_LIST_ELEM(list, bot), element, list->sl_element_size);
    ++list->sl_element_count;
    return SK_SHORT_LIST_OK;
}



/* **************************************************************** */

/*    SKUNIQUE WRAPPER AROUND FIELD LIST */

/* **************************************************************** */

/* structure for field info; used by sk_unique_t and sk_sort_unique_t */
typedef struct sk_uniq_field_info_st {
    const sk_fieldlist_t   *key_fields;
    const sk_fieldlist_t   *value_fields;
    const sk_fieldlist_t   *distinct_fields;

    uint8_t                 key_num_fields;
    uint8_t                 key_octets;

    uint8_t                 value_num_fields;
    uint8_t                 value_octets;

    uint8_t                 distinct_num_fields;
    uint8_t                 distinct_octets;
} sk_uniq_field_info_t;


#define KEY_ONLY            1
#define VALUE_ONLY          2
#define DISTINCT_ONLY       4
#define KEY_VALUE           (KEY_ONLY | VALUE_ONLY)
#define KEY_DISTINCT        (KEY_ONLY | DISTINCT_ONLY)
#define VALUE_DISTINCT      (VALUE_ONLY | DISTINCT_ONLY)
#define KEY_VALUE_DISTINCT  (KEY_ONLY | VALUE_ONLY | DISTINCT_ONLY)


static struct allowed_fieldid_st {
    sk_fieldid_t    fieldid;
    uint8_t         kvd;
} allowed_fieldid[] = {
    {SK_FIELD_SIPv4,                KEY_DISTINCT},
    {SK_FIELD_DIPv4,                KEY_DISTINCT},
    {SK_FIELD_SPORT,                KEY_DISTINCT},
    {SK_FIELD_DPORT,                KEY_DISTINCT},
    {SK_FIELD_PROTO,                KEY_DISTINCT},
    {SK_FIELD_PACKETS,              KEY_DISTINCT},
    {SK_FIELD_BYTES,                KEY_DISTINCT},
    {SK_FIELD_FLAGS,                KEY_DISTINCT},
    {SK_FIELD_STARTTIME,            KEY_DISTINCT},
    {SK_FIELD_ELAPSED,              KEY_DISTINCT},
    {SK_FIELD_ENDTIME,              KEY_DISTINCT},
    {SK_FIELD_SID,                  KEY_DISTINCT},
    {SK_FIELD_INPUT,                KEY_DISTINCT},
    {SK_FIELD_OUTPUT,               KEY_DISTINCT},
    {SK_FIELD_NHIPv4,               KEY_DISTINCT},
    {SK_FIELD_INIT_FLAGS,           KEY_DISTINCT},
    {SK_FIELD_REST_FLAGS,           KEY_DISTINCT},
    {SK_FIELD_TCP_STATE,            KEY_DISTINCT},
    {SK_FIELD_APPLICATION,          KEY_DISTINCT},
    {SK_FIELD_FTYPE_CLASS,          KEY_DISTINCT},
    {SK_FIELD_FTYPE_TYPE,           KEY_DISTINCT},
    {SK_FIELD_STARTTIME_MSEC,       KEY_DISTINCT},
    {SK_FIELD_ENDTIME_MSEC,         KEY_DISTINCT},
    {SK_FIELD_ELAPSED_MSEC,         KEY_DISTINCT},
    {SK_FIELD_ICMP_TYPE,            KEY_DISTINCT},
    {SK_FIELD_ICMP_CODE,            KEY_DISTINCT},
    {SK_FIELD_SIPv6,                KEY_DISTINCT},
    {SK_FIELD_DIPv6,                KEY_DISTINCT},
    {SK_FIELD_NHIPv6,               KEY_DISTINCT},
    {SK_FIELD_RECORDS,              VALUE_ONLY},
    {SK_FIELD_SUM_PACKETS,          VALUE_ONLY},
    {SK_FIELD_SUM_BYTES,            VALUE_ONLY},
    {SK_FIELD_SUM_ELAPSED,          VALUE_ONLY},
    {SK_FIELD_SUM_ELAPSED_MSEC,     VALUE_ONLY},
    {SK_FIELD_MIN_STARTTIME,        VALUE_ONLY},
    {SK_FIELD_MAX_ENDTIME,          VALUE_ONLY},
    {SK_FIELD_MIN_STARTTIME_MSEC,   VALUE_ONLY},
    {SK_FIELD_MAX_ENDTIME_MSEC,     VALUE_ONLY},

    {SK_FIELD_CALLER,               KEY_VALUE_DISTINCT}
};


/*
 *  status = uniqCheckFields(uniq_fields);
 *
 *    Verify that the fields for a unique object make sense.  The
 *    fields are given in 'uniq_fields'.  Return 0 if the fields are
 *    valid.  Return -1 if they are invalid and print an error.
 *
 *    For the fields to make sense, there must be more or more key
 *    fields and at least one distinct field or one aggregate value
 *    field.
 */
static int
uniqCheckFields(
    sk_uniq_field_info_t   *field_info)
{
#define SAFE_SET(variable, value)               \
    {                                           \
        size_t sz = (value);                    \
        if (sz > UINT8_MAX) {                   \
            skAppPrintErr("Overflow");          \
            return -1;                          \
        }                                       \
        variable = (uint8_t)value;              \
    }

    sk_fieldlist_iterator_t fl_iter;
    sk_fieldlist_iterator_t fl_iter2;
    sk_fieldentry_t *field;
    sk_fieldentry_t *field2;
    size_t num_allowed;
    uint8_t field_type;
    uint32_t field_id;
    size_t i;

    assert(field_info);

    num_allowed = sizeof(allowed_fieldid)/sizeof(struct allowed_fieldid_st);

    /* must have at least one key field */
    if (NULL == field_info->key_fields) {
        skAppPrintErr("No key fields were specified");
        return -1;
    }
    /* must have at least one value or one distinct field */
    if (NULL == field_info->value_fields
        && NULL == field_info->distinct_fields)
    {
        skAppPrintErr("Neither value nor distinct fields were specified");
        return -1;
    }

    /* handle key fields */
    skFieldListIteratorBind(field_info->key_fields, &fl_iter);
    while (NULL != (field = skFieldListIteratorNext(&fl_iter))) {
        field_type = 0;
        field_id = skFieldListEntryGetId(field);
        for (i = 0; i < num_allowed; ++i) {
            if (field_id == (uint32_t)allowed_fieldid[i].fieldid) {
                field_type = allowed_fieldid[i].kvd;
                break;
            }
        }
        if (field_type == 0) {
            skAppPrintErr("Unknown field %d", field->id);
            return -1;
        }
        if (!(field_type & KEY_ONLY)) {
            skAppPrintErr("Field %d is not allowed in the key", field->id);
            return -1;
        }
    }
    SAFE_SET(field_info->key_num_fields,
             skFieldListGetFieldCount(field_info->key_fields));
    SAFE_SET(field_info->key_octets,
             skFieldListGetBufferSize(field_info->key_fields));
    if (field_info->key_num_fields == 0 || field_info->key_octets == 0) {
        skAppPrintErr("No key fields were specified");
        return -1;
    }

    /* handle value fields */
    if (field_info->value_fields) {
        skFieldListIteratorBind(field_info->value_fields, &fl_iter);
        while (NULL != (field = skFieldListIteratorNext(&fl_iter))) {
            field_type = 0;
            field_id = skFieldListEntryGetId(field);
            for (i = 0; i < num_allowed; ++i) {
                if (field_id == (uint32_t)allowed_fieldid[i].fieldid) {
                    field_type = allowed_fieldid[i].kvd;
                    break;
                }
            }
            if (field_type == 0) {
                skAppPrintErr("Unknown field %d", field->id);
                return -1;
            }
            if (!(field_type & VALUE_ONLY)) {
                skAppPrintErr("Field %d is not allowed in the value",
                              field->id);
                return -1;
            }
        }

        SAFE_SET(field_info->value_num_fields,
                 skFieldListGetFieldCount(field_info->value_fields));
        SAFE_SET(field_info->value_octets,
                 skFieldListGetBufferSize(field_info->value_fields));
    }

    /* handle distinct fields */
    if (field_info->distinct_fields) {
        skFieldListIteratorBind(field_info->distinct_fields, &fl_iter);
        while (NULL != (field = skFieldListIteratorNext(&fl_iter))) {
            field_type = 0;
            field_id = skFieldListEntryGetId(field);
            for (i = 0; i < num_allowed; ++i) {
                if (field_id == (uint32_t)allowed_fieldid[i].fieldid) {
                    field_type = allowed_fieldid[i].kvd;
                    break;
                }
            }
            if (field_type == 0) {
                skAppPrintErr("Unknown field %d", field->id);
                return -1;
            }
            if (!(field_type & DISTINCT_ONLY)) {
                skAppPrintErr("Field %d is not allowed in the distinct",
                              field->id);
                return -1;
            }

            /* ensure distinct field is not part of key */
            if (SK_FIELD_CALLER == field_id) {
                void *field_ctx = skFieldListEntryGetContext(field);
                skFieldListIteratorBind(field_info->key_fields, &fl_iter2);
                while (NULL != (field2 = skFieldListIteratorNext(&fl_iter2))) {
                    if (skFieldListEntryGetId(field2) == SK_FIELD_CALLER) {
                        if (skFieldListEntryGetContext(field2) == field_ctx) {
                            skAppPrintErr("Will not count distinct"
                                          " value that is also part of key");
                            return -1;
                        }
                    }
                }
            } else {
                skFieldListIteratorBind(field_info->key_fields, &fl_iter2);
                while (NULL != (field2 = skFieldListIteratorNext(&fl_iter2))) {
                    if (skFieldListEntryGetId(field2) == field_id) {
                        skAppPrintErr("Will not count distinct"
                                      " value that is also part of key");
                        return -1;
                    }
                }
            }
        }

        SAFE_SET(field_info->distinct_num_fields,
                 skFieldListGetFieldCount(field_info->distinct_fields));
        SAFE_SET(field_info->distinct_octets,
                 skFieldListGetBufferSize(field_info->distinct_fields));
    }

    /* ensure either values or distincts are specified */
    if (((field_info->value_num_fields + field_info->distinct_num_fields) == 0)
        || ((field_info->value_octets + field_info->distinct_octets) == 0))
    {
        skAppPrintErr("No value or distinct fields were specified");
        return -1;
    }

    return 0;
}



/* **************************************************************** */

/*    SKUNIQUE INTERNAL SUPPORT FOR DISTINCT FIELDS */

/* **************************************************************** */

#define DISTINCT_PTR(d_buffer, d_array, d_index)        \
    ((d_buffer) + (d_array)[(d_index)].dv_offset)

typedef enum {
    /* compute the dintinct count by keeping track of each value we
     * see.  DISTINCT_BITMAP is used for values up to 8bits;
     * DISTINCT_SHORTLIST is used for larger values where we have seen
     * no more than 32 distinct values.  Once the DISTINCT_SHORTLIST
     * is full, it is converted to a DISTINCT_HASHSET. */
    DISTINCT_BITMAP,
    DISTINCT_SHORTLIST,
    DISTINCT_HASHSET
} distinct_type_t;


/*    The data structure holding the distinct values */
typedef union distinct_tracker_un {
    sk_short_list_t    *dv_shortlist;
    HashSet            *dv_hashset;
    sk_bitmap_t        *dv_bitmap;
} distinct_tracker_t;

typedef struct distinct_value_st {
    /*    count of distinct elements */
    uint64_t            dv_count;
    /*    data structure holding the distinct elements */
    distinct_tracker_t  dv_v;
    /*    the type of data structure in 'dv_v' */
    distinct_type_t     dv_type;
    /*    the octet length of an element */
    uint8_t             dv_octets;
    /*    the offset of this field in the buffer that is filled for a
     *    single record or for a single bin's results */
    uint8_t             dv_offset;
} distinct_value_t;


static int
uniqDistinctShortlistCmp(
    const void         *field_buffer1,
    const void         *field_buffer2,
    void               *v_fieldlen)
{
    const uint8_t *len = (uint8_t*)v_fieldlen;

    return memcmp(field_buffer1, field_buffer2, *len);
}

/*
 *  uniqDistinctFree(field_info, distincts);
 *
 *    Free all memory that was allocated by uniqDistinctAlloc() or
 *    uniqDistinctAllocMerging().
 */
static void
uniqDistinctFree(
    const sk_uniq_field_info_t *field_info,
    distinct_value_t           *distincts)
{
    distinct_value_t *dist;
    uint8_t i;

    if (NULL == distincts) {
        return;
    }

    for (i = 0; i < field_info->distinct_num_fields; ++i) {
        dist = &distincts[i];
        switch (dist->dv_type) {
          case DISTINCT_BITMAP:
            skBitmapDestroy(&dist->dv_v.dv_bitmap);
            break;
          case DISTINCT_SHORTLIST:
            skShortListDestroy(&dist->dv_v.dv_shortlist);
            break;
          case DISTINCT_HASHSET:
            hashset_free_table(dist->dv_v.dv_hashset);
            dist->dv_v.dv_hashset = NULL;
            break;
        }
    }
    free(distincts);
}


/*
 *  ok = uniqDistinctAllocMerging(field_info, &distincts);
 *
 *    Allocate the 'distincts' and initalize it with the length and
 *    offsets of each distinct field but do not create the data
 *    structures used to count them.  This function is used when
 *    merging the distinct counts from temporary files.
 *
 *    See also uniqDistinctAlloc().
 *
 *    Use uniqDistinctFree() to deallocate this data structure.
 *
 *    Return 0 on success, or -1 on failure.
 */
static int
uniqDistinctAllocMerging(
    const sk_uniq_field_info_t     *field_info,
    distinct_value_t              **new_distincts)
{
    sk_fieldlist_iterator_t fl_iter;
    sk_fieldentry_t *field;
    distinct_value_t *distincts;
    distinct_value_t *dist;
    uint8_t total_octets = 0;

    assert(field_info);
    assert(new_distincts);

    if (0 == field_info->distinct_num_fields) {
        *new_distincts = NULL;
        return 0;
    }

    distincts = (distinct_value_t*)calloc(field_info->distinct_num_fields,
                                          sizeof(distinct_value_t));
    if (NULL == distincts) {
        TRACEMSG(("%s:%d: Error allocating distinct field_info",
                  __FILE__, __LINE__));
        *new_distincts = NULL;
        return -1;
    }

    dist = distincts;

    /* determine how each field maps into the single buffer */
    skFieldListIteratorBind(field_info->distinct_fields, &fl_iter);
    while (NULL != (field = skFieldListIteratorNext(&fl_iter))) {
        dist->dv_octets = skFieldListEntryGetBinOctets(field);
        dist->dv_offset = total_octets;
        total_octets += dist->dv_octets;
        dist->dv_type = DISTINCT_BITMAP;

        ++dist;
        assert(dist <= distincts + field_info->distinct_num_fields);
    }
    assert(total_octets < HASHLIB_MAX_KEY_WIDTH);

    *new_distincts = distincts;
    return 0;
}


/*
 *  ok = uniqDistinctAlloc(field_info, &distincts);
 *
 *    Create the data structures required by 'field_info' to count
 *    distinct values and fill 'distincts' with the structures.
 *
 *    To allocate the distincts structure but not the data structures
 *    used for counting distinct items, use
 *    uniqDistinctAllocMerging().
 *
 *    Use uniqDistinctFree() to deallocate this data structure.
 *
 *    Return 0 on success, or -1 on failure.
 */
static int
uniqDistinctAlloc(
    const sk_uniq_field_info_t     *field_info,
    distinct_value_t              **new_distincts)
{
    sk_fieldlist_iterator_t fl_iter;
    sk_fieldentry_t *field;
    distinct_value_t *distincts;
    distinct_value_t *dist;

    assert(field_info);
    assert(new_distincts);

    if (0 == field_info->distinct_num_fields) {
        *new_distincts = NULL;
        return 0;
    }
    if (uniqDistinctAllocMerging(field_info, &distincts)) {
        *new_distincts = NULL;
        return -1;
    }

    dist = distincts;

    /* create the data structures */
    skFieldListIteratorBind(field_info->distinct_fields, &fl_iter);
    while (NULL != (field = skFieldListIteratorNext(&fl_iter))) {
        if (dist->dv_octets == 1) {
            dist->dv_type = DISTINCT_BITMAP;
            if (skBitmapCreate(&dist->dv_v.dv_bitmap,
                               1 << (dist->dv_octets * CHAR_BIT)))
            {
                TRACEMSG(("%s:%d: Error allocating bitmap",
                          __FILE__, __LINE__));
                dist->dv_v.dv_bitmap = NULL;
                goto ERROR;
            }
        } else {
            dist->dv_type = DISTINCT_SHORTLIST;
            if (skShortListCreate(
                    &dist->dv_v.dv_shortlist, dist->dv_octets,
                    uniqDistinctShortlistCmp, (void*)&dist->dv_octets))
            {
                TRACEMSG(("%s:%d: Error allocating short list",
                          __FILE__, __LINE__));
                dist->dv_v.dv_shortlist = NULL;
                goto ERROR;
            }
        }
        ++dist;
        assert(dist <= distincts + field_info->distinct_num_fields);
    }

    *new_distincts = distincts;
    return 0;

  ERROR:
    uniqDistinctFree(field_info, distincts);
    *new_distincts = NULL;
    return -1;
}


/*
 *  status = uniqDistinctShortListToHashSet(dist);
 *
 *    Convert the distinct count at 'dist' from using a short-list to
 *    count entries to the hash-set.  Return 0 on success, or -1 if
 *    there is a memory allocation failure.
 */
static int
uniqDistinctShortListToHashSet(
    distinct_value_t   *dist)
{
    HashSet *hashset = NULL;
    uint32_t i;
    int rv;

    assert(DISTINCT_SHORTLIST == dist->dv_type);

    hashset = hashset_create_set(dist->dv_octets,
                                 256, DEFAULT_LOAD_FACTOR);
    if (NULL == hashset) {
        TRACEMSG(("%s:%d: Error allocating hashset", __FILE__, __LINE__));
        goto ERROR;
    }

    for (i = skShortListCountEntries(dist->dv_v.dv_shortlist); i > 0; ) {
        --i;
        rv = hashset_insert(
            hashset,
            (uint8_t*)skShortListGetElement(dist->dv_v.dv_shortlist, i));
        switch (rv) {
          case OK:
            break;
          case OK_DUPLICATE:
            /* this is okay, but unexpected */
            break;
          default:
            TRACEMSG(("%s:%d: Error inserting value into hashset",
                      __FILE__, __LINE__));
            goto ERROR;
        }
    }

    skShortListDestroy(&dist->dv_v.dv_shortlist);
    dist->dv_v.dv_hashset = hashset;
    dist->dv_type = DISTINCT_HASHSET;
    return 0;

  ERROR:
    hashset_free_table(hashset);
    return -1;
}


/*
 *  status = uniqDistinctIncrement(uniq_fields, distincts, key);
 *
 *    Increment the distinct counters given 'key'.  Return 0 on
 *    success or -1 on memory allocation failure.
 */
static int
uniqDistinctIncrement(
    const sk_uniq_field_info_t *field_info,
    distinct_value_t           *distincts,
    const uint8_t              *key)
{
    distinct_value_t *dist;
    uint8_t i;
    int rv;

    for (i = 0; i < field_info->distinct_num_fields; ++i) {
        dist = &distincts[i];
        switch (dist->dv_type) {
          case DISTINCT_BITMAP:
            skBitmapSetBit(dist->dv_v.dv_bitmap,
                           *(uint8_t*)DISTINCT_PTR(key, distincts, i));
            dist->dv_count = skBitmapGetHighCount(dist->dv_v.dv_bitmap);
            break;
          case DISTINCT_SHORTLIST:
            rv = skShortListInsert(dist->dv_v.dv_shortlist,
                                   (void*)DISTINCT_PTR(key,distincts,i));
            switch (rv) {
              case SK_SHORT_LIST_OK:
                ++dist->dv_count;
                break;
              case SK_SHORT_LIST_OK_DUPLICATE:
                break;
              case SK_SHORT_LIST_ERR_FULL:
                if (uniqDistinctShortListToHashSet(dist)) {
                    return -1;
                }
                rv = hashset_insert(dist->dv_v.dv_hashset,
                                    DISTINCT_PTR(key,distincts,i));
                switch (rv) {
                  case OK:
                    ++dist->dv_count;
                    break;
                  case OK_DUPLICATE:
                    break;
                  default:
                    TRACEMSG(("%s:%d: Error inserting value into hashset",
                              __FILE__, __LINE__));
                    return -1;
                }
                break;
              default:
                skAbortBadCase(rv);
            }
            break;
          case DISTINCT_HASHSET:
            rv = hashset_insert(dist->dv_v.dv_hashset,
                                DISTINCT_PTR(key, distincts, i));
            switch (rv) {
              case OK:
                ++dist->dv_count;
                break;
              case OK_DUPLICATE:
                break;
              default:
                TRACEMSG(("%s:%d: Error inserting value into hashset",
                          __FILE__, __LINE__));
                return -1;
            }
            break;
        }
    }

    return 0;
}


/*
 *  uniqDistinctSetOutputBuf(uniq_fields, distincts, out_buf);
 *
 *    For all the distinct fields, fill the buffer at 'out_buf' to
 *    contain the number of distinct values.
 */
static void
uniqDistinctSetOutputBuf(
    const sk_uniq_field_info_t *field_info,
    const distinct_value_t     *distincts,
    uint8_t                    *out_buf)
{
    const distinct_value_t *dist;
    uint8_t i;

    for (i = 0; i < field_info->distinct_num_fields; ++i) {
        dist = &distincts[i];
        switch (dist->dv_octets) {
          case 1:
            *((uint8_t*)DISTINCT_PTR(out_buf, distincts, i))
                = (uint8_t)(dist->dv_count);
            break;

          case 3:
          case 5:
          case 6:
          case 7:
            {
                union array_uint64_t {
                    uint64_t  u64;
                    uint8_t   ar[8];
                } array_uint64;
                array_uint64.u64 = dist->dv_count;
#if SK_BIG_ENDIAN
                memcpy(DISTINCT_PTR(out_buf, distincts, i),
                       &array_uint64.ar[8-dist->dv_octets], dist->dv_octets);
#else
                memcpy(DISTINCT_PTR(out_buf, distincts, i),
                       &array_uint64.ar[0], dist->dv_octets);
#endif  /* #else of #if SK_BIG_ENDIAN */
            }
            break;

#if !SKUNIQ_USE_MEMCPY
          case 2:
            *((uint16_t*)DISTINCT_PTR(out_buf, distincts, i))
                = (uint16_t)(dist->dv_count);
            break;
          case 4:
            *((uint32_t*)DISTINCT_PTR(out_buf, distincts, i))
                = (uint32_t)(dist->dv_count);
            break;
          case 8:
            *((uint64_t*)DISTINCT_PTR(out_buf, distincts, i))
                = dist->dv_count;
            break;
          default:
            *((uint64_t*)DISTINCT_PTR(out_buf, distincts, i))
                = dist->dv_count;
            break;
#else  /* SKUNIQ_USE_MEMCPY */
          case 2:
            {
                uint16_t val16 = (uint16_t)(dist->dv_count);
                memcpy(DISTINCT_PTR(out_buf, distincts, i),
                       &val16, sizeof(val16));
            }
            break;
          case 4:
            {
                uint32_t val32 = (uint32_t)(dist->dv_count);
                memcpy(DISTINCT_PTR(out_buf, distincts, i),
                       &val32, sizeof(val32));
            }
            break;
          case 8:
            memcpy(DISTINCT_PTR(out_buf, distincts, i),
                   &dist->dv_count, sizeof(uint64_t));
            break;
          default:
            memcpy(DISTINCT_PTR(out_buf, distincts, i),
                   &dist->dv_count, sizeof(uint64_t));
            break;
#endif  /* #else of #if !SKUNIQ_USE_MEMCPY */
        }
    }
}


/*
 *  status = uniqDistinctReset(uniq_fields, distincts);
 *
 *    Reset the distinct counters and clear all entries from the data
 *    structure (this recreates the hashset data structure).  Return 0
 *    on success, or -1 on memory allocation error.
 */
static int
uniqDistinctReset(
    const sk_uniq_field_info_t *field_info,
    distinct_value_t           *distincts)
{
    distinct_value_t *dist;
    uint8_t i;

    for (i = 0; i < field_info->distinct_num_fields; ++i) {
        dist = &distincts[i];
        switch (dist->dv_type) {
          case DISTINCT_BITMAP:
            skBitmapClearAllBits(dist->dv_v.dv_bitmap);
            break;
          case DISTINCT_SHORTLIST:
            skShortListRemoveAll(dist->dv_v.dv_shortlist);
            break;
          case DISTINCT_HASHSET:
            hashset_free_table(dist->dv_v.dv_hashset);
            dist->dv_v.dv_hashset = hashset_create_set(dist->dv_octets, 256,
                                                       DEFAULT_LOAD_FACTOR);
            if (NULL == dist->dv_v.dv_hashset) {
                TRACEMSG(("%s:%d: Error allocating hashset",
                          __FILE__, __LINE__));
                return -1;
            }
            break;
        }
        dist->dv_count = 0;
    }
    return 0;
}



/* **************************************************************** */

/*    SKUNIQUE INTERNAL WRAPPERS FOR OPEN, READ AND WRITE OF TEMP FILES */

/* **************************************************************** */

/*
 *    Return a pointer into the string 'name' that either points at
 *    the first character after the final '/' or to the first
 *    character of 'name'.
 */
static const char *
uniqBasename(
    const char         *name)
{
    const char *base;

    if (name) {
        base = strrchr(name, '/');
        if (base) {
            return base + 1;
        }
    }
    return name;
}


/*
 *    Return the basename of the path to specified in 'stream'.
 */
static const char *
uniqTempName(
    const skstream_t   *stream)
{
    return uniqBasename(skStreamGetPathname(stream));
}


/*
 *    Create and return a new temporary file, putting the index of the
 *    file in 'temp_idx'.  Exit the application on failure.
 */
static skstream_t *
uniqTempCreate(
    sk_tempfilectx_t   *tmpctx,
    int                *temp_idx)
{
    skstream_t *stream;

    stream = skTempFileCreateStream(tmpctx, temp_idx);
    if (NULL == stream) {
        skAppPrintSyserror("Error creating new temporary file");
        exit(EXIT_FAILURE);
    }
    return stream;
}

/*
 *    Re-open the existing temporary file indexed by 'temp_idx'.
 *    Return the new stream.  Return NULL if we could not open the
 *    stream due to out-of-memory or out-of-file-handles error.  Exit
 *    the application on any other error.
 */
static skstream_t *
uniqTempReopen(
    sk_tempfilectx_t   *tmpctx,
    int                 temp_idx)
{
    skstream_t *stream;

    stream = skTempFileOpenStream(tmpctx, temp_idx);
    if (NULL == stream) {
        if ((errno != EMFILE) && (errno != ENOMEM)) {
            skAppPrintSyserror(("Error opening existing temporary file '%s'"),
                               skTempFileGetName(tmpctx, temp_idx));
            exit(EXIT_FAILURE);
        }
    }
    return stream;
}

/*
 *    Close a temporary file.  Exit the application if stream was open
 *    for write and closing fails.  Do nothing if stream is NULL.
 */
static void
uniqTempClose(
    skstream_t         *stream)
{
    char errbuf[2 * PATH_MAX];
    ssize_t rv;

    rv = skStreamClose(stream);
    switch (rv) {
      case SKSTREAM_OK:
      case SKSTREAM_ERR_NOT_OPEN:
      case SKSTREAM_ERR_CLOSED:
        skStreamDestroy(&stream);
        return;
      case SKSTREAM_ERR_NULL_ARGUMENT:
        return;
    }

    skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
    skAppPrintErr("Error closing temporary file: %s", errbuf);
    if (skStreamGetMode(stream) == SK_IO_WRITE) {
        exit(EXIT_FAILURE);
    }
    skStreamDestroy(&stream);
}

/*
 *    Read 'str_size' bytes from 'str_stream' into 'str_buf'.  Return
 *    'str_size' on success or 0 for other condition (end-of-file,
 *    short read, error).
 */
#define uniqTempRead(str_stream, str_buf, str_size)                     \
    uniqTempReadHelper(str_stream, str_buf, str_size, __FILE__, __LINE__)

static ssize_t
uniqTempReadHelper(
    skstream_t         *stream,
    void               *buf,
    size_t              size,
    const char         *file_name,
    int                 file_line)
{
    ssize_t rv;

    rv = skStreamRead(stream, buf, size);
    if (rv == (ssize_t)size) {
        return rv;
    }
#if TRACEMSG_LEVEL == 0
    (void)file_name;
    (void)file_line;
#else
    if (rv == 0) {
        TRACEMSG(("%s:%d: Failed to read %" SK_PRIuZ " bytes: EOF on '%s'",
                  file_name, file_line, size, uniqTempName(stream)));
    } else if (rv > 0) {
        TRACEMSG(("%s:%d: Failed to read %" SK_PRIuZ " bytes:"
                  " Short read of %" SK_PRIdZ " on '%s'",
                  file_name, file_line, size, rv, uniqTempName(stream)));
    } else {
        char errbuf[2 * PATH_MAX];

        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        TRACEMSG(("%s:%d: Failed to read %" SK_PRIuZ " bytes: %s",
                  file_name, file_line, size, errbuf));
    }
#endif  /* #else of #if TRACEMSG_LEVEL == 0 */
    return 0;
}


/*
 *    Write 'stw_size' bytes from 'stw_buf' to 'stw_stream'.  Return
 *    'stw_size' on success and exit the appliation on error or short
 *    write.
 */
#define uniqTempWrite(stw_stream, stw_buf, stw_size)                    \
    uniqTempWriteHelper(stw_stream, stw_buf, stw_size, __FILE__, __LINE__)

static void
uniqTempWriteHelper(
    skstream_t         *stream,
    const void         *buf,
    size_t              size,
    const char         *file_name,
    int                 file_line)
{
    char errbuf[2 * PATH_MAX];
    ssize_t rv;

    rv = skStreamWrite(stream, buf, size);
    if (rv == (ssize_t)size) {
        return;
    }
    skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));

#if TRACEMSG_LEVEL == 0
    (void)file_name;
    (void)file_line;
#else
    if (rv >= 0) {
        TRACEMSG(("%s:%d: Failed to write %" SK_PRIuZ " bytes:"
                  " Short write of %" SK_PRIdZ " on '%s'",
                  file_name, file_line, size, rv, uniqTempName(stream)));
    } else {
        TRACEMSG(("%s:%d: Failed to write %" SK_PRIuZ " bytes: %s",
                  file_name, file_line, size, errbuf));
    }
#endif  /* #else of #if TRACEMSG_LEVEL == 0 */

    if (rv >= 0) {
        snprintf(errbuf, sizeof(errbuf),
                 "Short write of %" SK_PRIdZ " bytes to '%s'",
                 rv, uniqTempName(stream));
    }
    skAppPrintErr("Cannot write to temporary file: %s", errbuf);
    exit(EXIT_FAILURE);
}



/* **************************************************************** */

/*    SKUNIQUE INTERNAL SUPPORT FOR MERGING DISTINCT FILES   */

/* **************************************************************** */

/*
 *    The following data structure and functions allow merging of
 *    distinct values that have been written to temporary files.  This
 *    code may be used by either unsorted input data, presorted input
 *    data, or when computing the number of distinct values across all
 *    bins.
 */

/*
 *    distinct_merge_data_t is used when merging distinct values that
 *    have been written to temporary files.  It contains the current
 *    distinct value that was read from every open file.
 */
struct distinct_merge_data_st {
    uint8_t      value[MAX_MERGE_FILES][HASHLIB_MAX_KEY_WIDTH];
    uint8_t      octets;
};
typedef struct distinct_merge_data_st distinct_merge_data_t;

/*
 *    distinct_merge_t is used to process distinct values that have
 *    been written to temporary files.
 */
struct distinct_merge_st {
    uint64_t                num_distinct[MAX_MERGE_FILES];
    skstream_t             *fps[MAX_MERGE_FILES];
    skstream_t             *dist_fp;
    distinct_merge_data_t  *merge_data;
    skheap_t               *heap;
    uint16_t                active[MAX_MERGE_FILES];
    /* index of first temp file opened for this round of merging;
     * used when reporting temp file indexes */
    int                     temp_idx_base;
    uint16_t                max_fps;
    uint16_t                num_active;
    uint8_t                 octet_len;
    uint8_t                 read_to_end_of_file;
    uint8_t                 write_to_temp;
    uint8_t                 print_debug;
};
typedef struct distinct_merge_st distinct_merge_t;


#if TRACEMSG_LEVEL == 0

/*
 *    Function that is used to output log messages enabled by the
 *    SILK_UNIQUE_DEBUG environment variable.
 *
 *    If SKUNIQUE_TRACE_LEVEL or TRACEMSG_LEVEL is non-zero, a
 *    different definition of this funciton is used, which is defined
 *    below.
 */
static void
uniqDistmergeDebug(
    const distinct_merge_t *merge,
    const char             *fmt,
    ...)
    SK_CHECK_PRINTF(2, 3);

static void
uniqDistmergeDebug(
    const distinct_merge_t *merge,
    const char             *fmt,
    ...)
{
    va_list args;

    va_start(args, fmt);
    if (merge && merge->print_debug) {
        fprintf(stderr, "%s: " SKUNIQUE_DEBUG_ENVAR ": ", skAppName());
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    }
    va_end(args);
}

#else  /* TRACEMSG_LEVEL > 0 */

/*
 *    When SKUNIQUE_TRACE_LEVEL or TRACEMSG_LEVEL is non-zero, the
 *    code behaves as though SILK_UNIQUE_DEBUG is enabled and this
 *    function is used to to trace the code.
 */
#define uniqDistmergeDebug(...)                         \
    uniqDistmergeDebugHelper(__LINE__, __VA_ARGS__)

static void
uniqDistmergeDebugHelper(
    int                     lineno,
    const distinct_merge_t *merge,
    const char             *fmt,
    ...)
    SK_CHECK_PRINTF(3, 4);

static void
uniqDistmergeDebugHelper(
    int                     lineno,
    const distinct_merge_t *merge,
    const char             *fmt,
    ...)
{
    va_list args;

    SK_UNUSED_PARAM(merge);

    va_start(args, fmt);
    fprintf(stderr, __FILE__ ":%d: ", lineno);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}
#endif  /* #else of TRACEMSG_LEVEL == 0 */


/*
 *    Comparison function used by the heap on the distinct_merge_t
 *    data structure.
 *
 *    The values in 'b' and 'a' (note the order) are integer indexes
 *    into an array of distinct values.
 *
 *    The context value in 'v_dist_merge' is a distinct_merge_t object
 *    that holds a pointer to a distinct_merge_data_t object that
 *    holds the values.
 */
static int
uniqDistmergeCmp(
    const skheapnode_t  b,
    const skheapnode_t  a,
    void               *v_dist_merge)
{
    distinct_merge_data_t *merge_data;
    const uint8_t *dist_a;
    const uint8_t *dist_b;

    assert(v_dist_merge);
    assert(((distinct_merge_t *)v_dist_merge)->merge_data);

    merge_data = ((distinct_merge_t *)v_dist_merge)->merge_data;

    dist_a = merge_data->value[*(uint16_t*)a];
    dist_b = merge_data->value[*(uint16_t*)b];

    return memcmp(dist_a, dist_b, merge_data->octets);
}


/*
 *    Merge a single distinct field and return the number of distinct
 *    values seen for that field, or UINT64_MAX on error.
 *
 *    The fps[] array of the 'merge' object must contain open file
 *    handles to the files containing the distinct values; the
 *    active[] array must specify which indexes from 'fps' are to be
 *    used; the num_active member must specify the number of entries
 *    in 'active'; the num_distinct[] array must specify the number of
 *    distinct values to read from each file or the
 *    'read_to_end_of_file' value may be specified to indicate that
 *    the function should only stop reading once the end of the files
 *    has been reached; the 'octet_len' member must specify the octet
 *    length of this distinct field; the 'write_to_temp' member
 *    specifies that the distinct values should be written to the
 *    'dist_fp' member.
 */
static uint64_t
uniqDistmergeMergeOne(
    distinct_merge_t   *merge)
{
    uint8_t lowest_distinct[HASHLIB_MAX_KEY_WIDTH];
    uint64_t distinct_count;
    uint32_t heap_count;
    uint16_t *top_heap;
    uint16_t lowest;
    ssize_t last_errno;
    distinct_merge_data_t merge_data;
    uint16_t i;

    assert(merge);
    assert(merge->heap);
    assert(0 == skHeapGetNumberEntries(merge->heap));

    /* Should only be called when distinct fields are present */
    assert(!merge->write_to_temp || merge->dist_fp);

    merge_data.octets = merge->octet_len;
    merge->merge_data = &merge_data;

    if (merge->read_to_end_of_file) {
        /* set all num_distinct counts to the maximum */
        memset(merge->num_distinct, 0xff, sizeof(merge->num_distinct));
    }

    /* holds the number of distinct values found for this distinct
     * field across all open files */
    distinct_count = 0;

    /* for each file: read the first distinct value and store the
     * index in dist_heap */
    for (i = 0; i < merge->num_active; ++i) {
        lowest = merge->active[i];
        if (0 == merge->num_distinct[lowest]) {
            /* do nothing */
        } else if (uniqTempRead(merge->fps[lowest],
                                merge_data.value[lowest], merge_data.octets))
        {
            skHeapInsert(merge->heap, &lowest);
            --merge->num_distinct[lowest];
        } else {
            last_errno = skStreamGetLastErrno(merge->fps[lowest]);
            if (last_errno != 0 || !merge->read_to_end_of_file) {
                goto READ_ERROR;
            }
            uniqDistmergeDebug(merge, "Ignoring empty temporary file #%u '%s'",
                               UNIQUE_TMPNUM_READ(merge, i),
                               uniqTempName(merge->fps[lowest]));
        }
    }

    /* get the file index that has the lowest distinct value */
    if (skHeapPeekTop(merge->heap, (skheapnode_t*)&top_heap)
        == SKHEAP_ERR_EMPTY)
    {
        /* strange, but okay? */
        return distinct_count;
    }
    lowest = *top_heap;

    heap_count = skHeapGetNumberEntries(merge->heap);
    assert(heap_count > 0);

    /* process all the distinct values */
    while (heap_count > 1) {
        if (merge->write_to_temp) {
            uniqTempWrite(merge->dist_fp,
                          &merge_data.value[lowest], merge_data.octets);
        }
        ++distinct_count;

        memcpy(lowest_distinct, merge_data.value[lowest], merge_data.octets);

        do {
            /* replace the distinct_value we just read */
            if (0 == merge->num_distinct[lowest]) {
                /* no more distinct values from this file */
                skHeapExtractTop(merge->heap, NULL);
                --heap_count;
                if (0 == heap_count) {
                    break;
                }
            } else if (uniqTempRead(merge->fps[lowest],
                                    merge_data.value[lowest],
                                    merge_data.octets))
            {
                --merge->num_distinct[lowest];
                skHeapReplaceTop(merge->heap, &lowest, NULL);
                /* distinct values in each file must be sorted and
                 * unique */
                assert(memcmp(lowest_distinct, merge_data.value[lowest],
                              merge->octet_len) < 0);
            } else {
                last_errno = skStreamGetLastErrno(merge->fps[lowest]);
                if (last_errno != 0 || !merge->read_to_end_of_file) {
                    goto READ_ERROR;
                }
                /* done with this file */
                skHeapExtractTop(merge->heap, NULL);
                --heap_count;
                uniqDistmergeDebug(
                    merge, "Finished reading file #%u, %u files remain",
                    UNIQUE_TMPNUM_READ(merge, lowest), heap_count);
                if (0 == heap_count) {
                    break;
                }
            }

            /* get the new value at the top of the heap */
            skHeapPeekTop(merge->heap, (skheapnode_t*)&top_heap);
            lowest = *top_heap;
            /* ignore value if it matches the lowest_distinct */
        } while (memcmp(lowest_distinct, merge_data.value[lowest],
                        merge_data.octets) == 0);
    }

    if (skHeapExtractTop(merge->heap, (skheapnode_t)&lowest)
        == SKHEAP_ERR_EMPTY)
    {
        return distinct_count;
    }
    assert(skHeapGetNumberEntries(merge->heap) == 0);

    /* process the remaining values in this single file */
    for (;;) {
        if (merge->write_to_temp) {
            uniqTempWrite(merge->dist_fp,
                          &merge_data.value[lowest], merge->octet_len);
        }
        ++distinct_count;

        if (0 == merge->num_distinct[lowest]) {
            /* no more distinct values */
            break;
        } else if (uniqTempRead(merge->fps[lowest], merge_data.value[lowest],
                                merge_data.octets))
        {
            --merge->num_distinct[lowest];
        } else {
            last_errno = skStreamGetLastErrno(merge->fps[lowest]);
            if (last_errno != 0 || !merge->read_to_end_of_file) {
                goto READ_ERROR;
            }
            uniqDistmergeDebug(merge,
                               "Finished reading file #%u, 0 files remain",
                               UNIQUE_TMPNUM_READ(merge, lowest));
            break;
        }
    }

    return distinct_count;

  READ_ERROR:
    uniqDistmergeDebug(merge, "Cannot read from temporary file #%u",
                       UNIQUE_TMPNUM_READ(merge, lowest));
    skAppPrintErr("Cannot read distinct values from temporary file: %s",
                  (last_errno ? strerror(last_errno) : "EOF"));
    return UINT64_MAX;
}



/* **************************************************************** */

/*    SKUNIQUE INTERNAL SUPPORT FOR DISTINCT COUNT ACROSS ALL BINS   */

/* **************************************************************** */

/*
 *    total_dist_t is used to count the number of distinct values for
 *    one field across all bins.  It is used by rwstats when the
 *    primary value field is a distinct count.
 *
 *    FIXME: It would be nice if we could use a bitmap for 2-byte
 *    values instead of the short-list/hashset hybrid, but that means
 *    changing some of the the uniqDistinct* calls to special-case the
 *    total-distinct case.
 */
struct total_distinct_st {
    /*      information about this single field */
    sk_uniq_field_info_t    td_fi;
    /*      the count of distinct items */
    uint64_t                td_count;
    /*      data structure holding the distinct values */
    distinct_value_t       *td_distincts;
    /*      the temp file context to use if all distinct values cannot
     *      be stored in memory */
    sk_tempfilectx_t       *td_tmpctx;
    /*      the open temporary file */
    skstream_t             *td_tmp_fp;
    /*      index of the temp file */
    int                     td_tmp_idx;
    /*      octet length of this distinct field */
    uint8_t                 td_octets;
    /*      whether any temp files have been written to */
    uint8_t                 td_uses_temp;
    /*      whether the count has already been computed */
    uint8_t                 td_have_count;
};
typedef struct total_distinct_st total_distinct_t;


/*
 *    Write the current distinct values to the tempoary file, close
 *    the temporary file, and empty the distinct data structure.  For
 *    the hashset, recreates the hash.
 */
static int
uniqTotalDistinctToTemp(
    total_distinct_t   *totdis)
{
    distinct_value_t *dist;
    hashset_iter h_iter;
    uint8_t *hash_key;
    uint16_t j;

    assert(totdis);
    assert(totdis->td_tmp_fp);

    dist = totdis->td_distincts;

    TRACEMSG(("%s:%d: Writing %" PRIu64 " total distinct values to TD#%d...",
              __FILE__, __LINE__, totdis->td_distincts->dv_count,
              totdis->td_tmp_idx));

    /* write each value into the distinct file */
    switch (dist->dv_type) {
      case DISTINCT_BITMAP:
        skAppPrintErr("Should never need to write total dist bitmap to file");
        skAbort();

      case DISTINCT_SHORTLIST:
        assert(skShortListCountEntries(dist->dv_v.dv_shortlist)
               == dist->dv_count);
        for (j = 0; j < dist->dv_count; ++j) {
            uniqTempWrite(totdis->td_tmp_fp,
                          skShortListGetElement(dist->dv_v.dv_shortlist, j),
                          dist->dv_octets);
        }
        skShortListRemoveAll(dist->dv_v.dv_shortlist);
        break;

      case DISTINCT_HASHSET:
        assert(hashset_count_entries(dist->dv_v.dv_hashset) == dist->dv_count);
        hashset_sort_entries(dist->dv_v.dv_hashset);
        h_iter = hashset_create_iterator(dist->dv_v.dv_hashset);
        while (OK == hashset_iterate(dist->dv_v.dv_hashset, &h_iter,&hash_key))
        {
            uniqTempWrite(totdis->td_tmp_fp, hash_key, dist->dv_octets);
        }
        hashset_free_table(dist->dv_v.dv_hashset);
        dist->dv_v.dv_hashset = hashset_create_set(dist->dv_octets, 256,
                                                   DEFAULT_LOAD_FACTOR);
        if (NULL == dist->dv_v.dv_hashset) {
            TRACEMSG(("%s:%d: Error allocating hashset",
                      __FILE__, __LINE__));
            return -1;
        }
        break;
    }

    /* close the temporary file */
    TRACEMSG((("%s:%d: Finished writing TD#%d '%s'"),
              __FILE__, __LINE__, totdis->td_tmp_idx,
              uniqBasename(skStreamGetPathname(totdis->td_tmp_fp))));
    uniqTempClose(totdis->td_tmp_fp);
    totdis->td_tmp_fp = NULL;
    totdis->td_uses_temp = 1;

    /* reset count */
    dist->dv_count = 0;

    return 0;
}


/*
 *    Return the number of distinct values seen.
 *
 *    The uniqTotalDistinctPrepareOutput() function must be called
 *    before calling this function.
 *
 *    If temporary files are in use, this function reads the distinct
 *    values from the files to compute the number of distinct values.
 */
static uint64_t
uniqTotalDistinctGetCount(
    total_distinct_t   *totdis)
{
    distinct_merge_t dist_merge;

    /* indexes at which to start and stop the merge */
    int tmp_idx_a;
    int tmp_idx_b;

    /* number of distinct values */
    uint64_t distinct_count;

    uint16_t i;
    int j;

    if (totdis->td_have_count) {
        return totdis->td_count;
    }
    if (!totdis->td_uses_temp) {
        skAppPrintErr("uniqTotalDistinctPrepareOutput was not called");
        skAbort();
    }

    assert(totdis->td_tmp_idx > 0);

    memset(&dist_merge, 0, sizeof(dist_merge));
    dist_merge.read_to_end_of_file = 1;
    dist_merge.octet_len = totdis->td_octets;
    dist_merge.write_to_temp = 1;

    /* create a heap to manage merging of the distinct values */
    dist_merge.heap = skHeapCreate2(uniqDistmergeCmp, MAX_MERGE_FILES,
                                    sizeof(uint16_t), NULL, &dist_merge);
    if (NULL == dist_merge.heap) {
        skAppPrintOutOfMemory("heap");
        goto ERROR;
    }

    tmp_idx_a = 0;

    /* This loop repeats until we have processed all of the temp files
     * that hold the total distinct values. */
    do {
        dist_merge.temp_idx_base = tmp_idx_a;
        dist_merge.num_active = 0;
        distinct_count = 0;

        /* may not process more than MAX_MERGE_FILES files */
        tmp_idx_b = tmp_idx_a + MAX_MERGE_FILES - 1;
        if (totdis->td_tmp_idx < tmp_idx_b) {
            /* number of temp files is less than MAX_MERGE_FILES */
            tmp_idx_b = totdis->td_tmp_idx;
        }
        TRACEMSG((("%s:%d: Attempting to open total distinct temporary"
                   " files TD#%d through TD#%d"),
                  __FILE__, __LINE__, tmp_idx_a, tmp_idx_b));

        /* open an intermediate temp file.  The processing writes
         * distinct values here if all existing temporary files cannot
         * be processed at once. */
        totdis->td_tmp_fp = uniqTempCreate(totdis->td_tmpctx,
                                           &totdis->td_tmp_idx);

        /* Open each total distinct temp file */
        for (j = tmp_idx_a, i = 0; j <= tmp_idx_b; ++j, ++i) {
            dist_merge.fps[i] = uniqTempReopen(totdis->td_tmpctx, j);
            if (NULL == dist_merge.fps[i]) {
                if (i < 2) {
                    skAppPrintErr("Unable to open multiple temporary files");
                    return -1;
                }
                /* We cannot open any more temp files; we'll need
                 * to catch file 'j' the next time around. */
                tmp_idx_b = j - 1;
                TRACEMSG((("%s:%d: File limit hit [%s]---merging"
                           " TD#%d through TD#%d into TD#%d..."),
                          __FILE__, __LINE__, strerror(errno),
                          tmp_idx_a, tmp_idx_b, totdis->td_tmp_idx));
                break;
            }
            dist_merge.active[dist_merge.num_active++] = i;
        }

        TRACEMSG(("%s:%d: Opened %d total distinct temporary files",
                 __FILE__, __LINE__, i));

        /* We may close the intermediate temp file if we have opened
         * all existing temporary files. */
        if (tmp_idx_b == totdis->td_tmp_idx - 1) {
            TRACEMSG(("%s:%d: Successfully opened all%s"
                      " total distinct temporary files",
                      __FILE__, __LINE__,
                      ((tmp_idx_a > 0) ? " remaining" : "")));
            uniqTempClose(totdis->td_tmp_fp);
            totdis->td_tmp_fp = NULL;
            dist_merge.write_to_temp = 0;
        }

        dist_merge.dist_fp = totdis->td_tmp_fp;

        /* process the files */
        distinct_count = uniqDistmergeMergeOne(&dist_merge);

        /* Close and destroy all the temp files that we processed this
         * time. */
        for (j = tmp_idx_a, i = 0; j <= tmp_idx_b; ++j, ++i) {
            uniqTempClose(dist_merge.fps[i]);
            skTempFileRemove(totdis->td_tmpctx, j);
        }
        memset(dist_merge.fps, 0, sizeof(dist_merge.fps));

        /* return if there was an error */
        if (UINT64_MAX == distinct_count) {
            goto ERROR;
        }

        /* Close the intermediate temp file(s). */
        if (totdis->td_tmp_fp) {
            TRACEMSG(("%s:%d: Finished writing TD#%d '%s'",
                      __FILE__, __LINE__, totdis->td_tmp_idx,
                      uniqBasename(skStreamGetPathname(totdis->td_tmp_fp))));
            uniqTempClose(totdis->td_tmp_fp);
            totdis->td_tmp_fp = NULL;
        }

        /* start the next merge with the next temp file */
        tmp_idx_a = tmp_idx_b + 1;
    } while (dist_merge.write_to_temp);

    skHeapFree(dist_merge.heap);

    totdis->td_count = distinct_count;

    totdis->td_have_count = 1;
    return totdis->td_count;

  ERROR:
    skHeapFree(dist_merge.heap);
    return SIZE_MAX;
}


/*
 *    Insert the value of the distinct field on 'rwrec' into the
 *    distinct data structure.  If memory is exhausted, write the
 *    values in the data structure to disk and create an empty data
 *    structure.
 */
static int
uniqTotalDistinctIncrement(
    total_distinct_t   *totdis,
    const rwRec        *rwrec)
{
    uint8_t field_buf[HASHLIB_MAX_KEY_WIDTH];

    assert(rwrec);
    assert(totdis);
    assert(0 == totdis->td_have_count);

    if (0 == totdis->td_fi.distinct_num_fields) {
        /* nothing to do */
        return 0;
    }
    skFieldListRecToBinary(totdis->td_fi.distinct_fields, rwrec, field_buf);
    if (uniqDistinctIncrement(&totdis->td_fi, totdis->td_distincts, field_buf)
        == 0)
    {
        /* success */
        return 0;
    }

    if (uniqTotalDistinctToTemp(totdis)) {
        return -1;
    }

    /* open a new file */
    totdis->td_tmp_fp = uniqTempCreate(totdis->td_tmpctx, &totdis->td_tmp_idx);

    /* insert the value */
    if (uniqDistinctIncrement(&totdis->td_fi, totdis->td_distincts, field_buf)
        != 0)
    {
        skAppPrintSyserror("Unable to increment into empty data structure");
        return -1;
    }

    return 0;
}


/*
 *    Initialize the 'totdis' data strucure to process the first
 *    distinct field specified in the field info structure
 *    'field_info'.  Create a temporary file to hold the distinct
 *    values if the data structure overflows.  Return an error if no
 *    distinct fields have been specified in 'field_info' or if there
 *    is an allocation error.
 */
static int
uniqTotalDistinctPrepareInput(
    total_distinct_t           *totdis,
    const sk_uniq_field_info_t *field_info,
    const char                 *temp_dir)
{
    sk_fieldlist_t *dist_list = NULL;
    sk_tempfilectx_t *tmpctx = NULL;

    if (NULL == field_info->distinct_fields
        || 0 == field_info->distinct_num_fields)
    {
        skAppPrintErr("No distinct fields have been specified");
        return -1;
    }

    memset(totdis, 0, sizeof(*totdis));
    if (skFieldListCreate(&dist_list)) {
        return -1;
    }

    memcpy(&dist_list->fields[0], &field_info->distinct_fields->fields[0],
           sizeof(sk_fieldentry_t));
    dist_list->fields[0].parent_list = dist_list;
    dist_list->fields[0].offset = 0;
    dist_list->num_fields = 1;
    dist_list->total_octets = dist_list->fields[0].octets;

    if (dist_list->total_octets > 1) {
        /* initialize a separate temp file context */
        if (skTempFileInitialize(&tmpctx, temp_dir, NULL, &skAppPrintErr)) {
            skFieldListDestroy(&dist_list);
            return -1;
        }
        /* open a temp file */
        totdis->td_tmp_fp = uniqTempCreate(tmpctx, &totdis->td_tmp_idx);
    }

    totdis->td_fi.distinct_num_fields = 1;
    totdis->td_fi.distinct_octets = dist_list->total_octets;
    totdis->td_fi.distinct_fields = dist_list;

    totdis->td_octets = dist_list->total_octets;
    totdis->td_tmpctx = tmpctx;

    return uniqDistinctAlloc(&totdis->td_fi, &totdis->td_distincts);
}


/*
 *    Tell 'totdis' that there is no more input data.  If temporary
 *    files have been used, this function writes the current in-memory
 *    values to a temporary file.  If no temporary files have been
 *    written to, this function simply counts the number of unique
 *    values specified in the data structure.
 */
static int
uniqTotalDistinctPrepareOutput(
    total_distinct_t   *totdis)
{
    if (NULL == totdis || 0 == totdis->td_fi.distinct_num_fields) {
        /* not being used */
        return 0;
    }

    if (!totdis->td_uses_temp) {
        assert(0 == totdis->td_tmp_idx);
        totdis->td_have_count = 1;
        totdis->td_count = totdis->td_distincts->dv_count;

        /* close the temporary file */
        uniqTempClose(totdis->td_tmp_fp);
        totdis->td_tmp_fp = NULL;
    } else {
        assert(totdis->td_tmp_idx > 0);
        assert(totdis->td_tmp_fp);

        /* write the current contents of the data structure */
        if (uniqTotalDistinctToTemp(totdis)) {
            return -1;
        }
    }

    /* done with the data structure */
    uniqDistinctFree(&totdis->td_fi, totdis->td_distincts);
    totdis->td_distincts = NULL;

    return 0;
}


/*
 *    Free any memory associated with the total distinct data
 *    structure 'totdis'.  This function does not free 'totdis'
 *    itself.
 */
static void
uniqTotalDistinctDestroy(
    total_distinct_t   *totdis)
{
    sk_fieldlist_t *fl;

    if (NULL == totdis) {
        return;
    }
    uniqDistinctFree(&totdis->td_fi, totdis->td_distincts);
    fl = (sk_fieldlist_t *)totdis->td_fi.distinct_fields;
    totdis->td_fi.distinct_fields = NULL;
    uniqTempClose(totdis->td_tmp_fp);
    skTempFileTeardown(&totdis->td_tmpctx);
    skFieldListDestroy(&fl);
}



/* **************************************************************** */

/*    SKUNIQUE INTERNAL SUPPORT WRITING KEY,VALUE TO TEMPORARY FILE */

/* **************************************************************** */

/*
 *  uniqTempWriteTriple(field_info, fp, dist_fp,key_buf, value_buf, distincts);
 *
 *    Write the values from 'key_buffer', 'value_buffer', and the
 *    distinct fields in 'distincts' (if any) to the file handles 'fp'
 *    and 'dist_fp'.  Return on success; exit on failure.
 *
 *    When there are no distinct fields, data is written to 'fp' only,
 *    and it is written as follows:
 *
 *      the key_buffer
 *      the value_buffer
 *
 *    When there are distinct fields but 'distincts' is NULL, data is
 *    written to 'fp' only, and it is written as follows:
 *
 *      the key_buffer
 *      the value_buffer
 *      a 0 (in 8 bytes) for each distinct field
 *
 *    When there are distinct fields and 'distincts' is not NULL, data
 *    is written to 'fp' as follows:
 *
 *      the key_buffer
 *      the value_buffer
 *      for each distinct field
 *          number of distinct values
 *
 *    And data is written to 'dist_fp' as follows:
 *
 *      for each distinct field
 *          distinct value 1, distinct value 2, ...
 */
static void
uniqTempWriteTriple(
    const sk_uniq_field_info_t *field_info,
    skstream_t                 *fp,
    skstream_t                 *dist_fp,
    const uint8_t              *key_buffer,
    const uint8_t              *value_buffer,
    const distinct_value_t     *dist)
{
    sk_bitmap_iter_t b_iter;
    hashset_iter h_iter;
    uint8_t *hash_key;
    uint16_t i;
    uint16_t j;
    uint32_t tmp32;
    uint8_t val8;

    /* write keys and values */
    uniqTempWrite(fp, key_buffer, field_info->key_octets);
    if (field_info->value_octets) {
        uniqTempWrite(fp, value_buffer, field_info->value_octets);
    }

    if (0 == field_info->distinct_num_fields) {
        return;
    }
    if (NULL == dist) {
        /* write a count of 0 for each distinct value into the main
         * file */
        uint64_t count = 0;
        for (i = 0; i < field_info->distinct_num_fields; ++i) {
            uniqTempWrite(fp, &count, sizeof(uint64_t));
        }
        return;
    }

    /* handle all the distinct fields */
    for (i = 0; i < field_info->distinct_num_fields; ++i, ++dist) {
        /* write the count into the main file */
        uniqTempWrite(fp, &dist->dv_count, sizeof(uint64_t));
        /* write each value into the distinct file */
        switch (dist->dv_type) {
          case DISTINCT_BITMAP:
            assert(skBitmapGetHighCount(dist->dv_v.dv_bitmap)
                   == dist->dv_count);
            skBitmapIteratorBind(dist->dv_v.dv_bitmap, &b_iter);
            assert(1 == dist->dv_octets);
            while (SK_ITERATOR_OK == skBitmapIteratorNext(&b_iter, &tmp32)) {
                val8 = (uint8_t)tmp32;
                uniqTempWrite(dist_fp, &val8, sizeof(uint8_t));
            }
            break;

          case DISTINCT_SHORTLIST:
            assert(skShortListCountEntries(dist->dv_v.dv_shortlist)
                   == dist->dv_count);
            for (j = 0; j < dist->dv_count; ++j) {
                uniqTempWrite(
                    dist_fp, skShortListGetElement(dist->dv_v.dv_shortlist, j),
                    dist->dv_octets);
            }
            break;

          case DISTINCT_HASHSET:
            assert(hashset_count_entries(dist->dv_v.dv_hashset)
                   == dist->dv_count);
            hashset_sort_entries(dist->dv_v.dv_hashset);
            h_iter = hashset_create_iterator(dist->dv_v.dv_hashset);
            while (OK == hashset_iterate(dist->dv_v.dv_hashset,
                                         &h_iter, &hash_key))
            {
                uniqTempWrite(dist_fp, hash_key, dist->dv_octets);
            }
            break;
        }
    }
}


/* **************************************************************** */

/*    SKUNIQUE USER API FOR RANDOM INPUT */

/* **************************************************************** */

/* structure for binning records */

/* typedef struct sk_unique_st sk_unique_t; */
struct sk_unique_st {
    /* information about the fields */
    sk_uniq_field_info_t    fi;

    /* where to write temporary files */
    char                   *temp_dir;

    /* the hash table */
    HashTable              *ht;

    /* the temp file context */
    sk_tempfilectx_t       *tmpctx;

    /* pointer to the current intermediate temporary file; it's index
     * is given by the 'temp_idx' member */
    skstream_t             *temp_fp;

    /* when distinct fields are being computed, temporary files always
     * appear in pairs, and this is the pointer to an intermediate
     * temp file used to hold distinct values; its index is given by
     * the 'max_temp_idx' member */
    skstream_t             *dist_fp;

    /* when computing the number of distinct values for one field
     * across all bins */
    total_distinct_t        total_dist;

    /* when creating the hash table, the estimated number of entries
     * for the table */
    uint64_t                ht_estimated;

    /* index of the intermediate temp file member 'temp_fp'. if temp
     * files have been written, its value is one more than the temp
     * file most recently written. */
    int                     temp_idx;

    /* index of highest used temporary file; this is the same as
     * 'temp_idx' when distinct files are not in use; when distinct
     * files are in use, this is one more than 'temp_idx' and the
     * index of 'dist_fp'. */
    int                     max_temp_idx;

    uint32_t                hash_value_octets;

    /* whether the output should be sorted */
    unsigned                sort_output :1;

    /* whether PrepareForInput()/PrepareForOutput() have been called */
    unsigned                ready_for_input:1;
    unsigned                ready_for_output:1;

    /* whether to print debugging information */
    unsigned                print_debug:1;

    /* whether the total_dist object is to be used */
    unsigned                use_total_distinct:1;
};


#if TRACEMSG_LEVEL == 0

/*
 *    Function that is used to output log messages enabled by the
 *    SILK_UNIQUE_DEBUG environment variable.
 *
 *    If SKUNIQUE_TRACE_LEVEL or TRACEMSG_LEVEL is non-zero, a
 *    different definition of this funciton is used, which is defined
 *    below.
 */
static void
uniqDebug(
    const sk_unique_t  *uniq,
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(2, 3);

static void
uniqDebug(
    const sk_unique_t  *uniq,
    const char         *fmt,
    ...)
{
    va_list args;

    va_start(args, fmt);
    if (uniq && uniq->print_debug) {
        fprintf(stderr, "%s: " SKUNIQUE_DEBUG_ENVAR ": ", skAppName());
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    }
    va_end(args);
}

#else  /* TRACEMSG_LEVEL > 0 */

/*
 *    When SKUNIQUE_TRACE_LEVEL or TRACEMSG_LEVEL is non-zero, the
 *    code behaves as though SILK_UNIQUE_DEBUG is enabled and this
 *    function is used to to trace the code.
 */
#define uniqDebug(...)  uniqDebugHelper(__LINE__, __VA_ARGS__)

static void
uniqDebugHelper(
    int                 lineno,
    const sk_unique_t  *uniq,
    const char         *fmt,
    ...)
    SK_CHECK_PRINTF(3, 4);

static void
uniqDebugHelper(
    int                 lineno,
    const sk_unique_t  *uniq,
    const char         *fmt,
    ...)
{
    va_list args;

    SK_UNUSED_PARAM(uniq);

    va_start(args, fmt);
    fprintf(stderr, __FILE__ ":%d: ", lineno);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}
#endif  /* #else of TRACEMSG_LEVEL == 0 */


/*
 *  status = uniqueCreateHashTable(uniq);
 *
 *    Create a hashlib hash table using the field information on
 *    'uniq'.  Return 0 on success, or -1 on failure.
 */
static int
uniqueCreateHashTable(
    sk_unique_t        *uniq)
{
    uint8_t no_val[HASHLIB_MAX_VALUE_WIDTH];

    memset(no_val, 0, sizeof(no_val));

    uniq->ht = hashlib_create_table(uniq->fi.key_octets,
                                    uniq->hash_value_octets,
                                    HTT_INPLACE,
                                    no_val,
                                    NULL,
                                    0,
                                    uniq->ht_estimated,
                                    DEFAULT_LOAD_FACTOR);
    if (NULL == uniq->ht) {
        skAppPrintOutOfMemory("hash table");
        return -1;
    }
    return 0;
}


/*
 *  uniqueDestroyHashTable(uniq);
 *
 *    Destroy the hashlib hash table stored on 'uniq'.
 */
static void
uniqueDestroyHashTable(
    sk_unique_t        *uniq)
{
    distinct_value_t *distincts;
    uint8_t *hash_key;
    uint8_t *hash_val;
    HASH_ITER ithash;

    if (NULL == uniq->ht) {
        return;
    }
#if 0 && defined(HASHLIB_RECORD_STATS)
    hashlib_print_stats(stderr, uniq->ht);
#endif
    if (0 == uniq->fi.distinct_num_fields) {
        hashlib_free_table(uniq->ht);
        uniq->ht = NULL;
        return;
    }

    /* must loop through table and free the distincts */
    ithash = hashlib_create_iterator(uniq->ht);
    while (hashlib_iterate(uniq->ht, &ithash, &hash_key, &hash_val)
           != ERR_NOMOREENTRIES)
    {
        memcpy(&distincts, hash_val + uniq->fi.value_octets, sizeof(void*));
        uniqDistinctFree(&uniq->fi, distincts);
    }

    hashlib_free_table(uniq->ht);
    uniq->ht = NULL;
    return;
}


/*
 *  uniqueDumpHashToTemp(uniq);
 *
 *    Write the entries in the current hash table to the current
 *    temporary file on 'uniq, destroy the hash table, and open a new
 *    temporary file.  The entries are written in sorted order, where
 *    the sort algorithm will depend on whether the user requested
 *    sorted output.  Return 0 on success, exit on failure.
 */
static void
uniqueDumpHashToTemp(
    sk_unique_t        *uniq)
{
    distinct_value_t *distincts;
    uint8_t *hash_key;
    uint8_t *hash_val;
    uint64_t entry_count;
    HASH_ITER ithash;

    assert(uniq);
    assert(uniq->temp_fp);
    assert(0 == uniq->fi.distinct_num_fields || uniq->dist_fp);

    /* sort the hash entries using skFieldListCompareBuffers.  To sort
     * using memcmp(), we would need to ensure we use memcmp() when
     * reading/merging the values back out of the temp files. */
    hashlib_sort_entries_usercmp(uniq->ht,
                                 COMP_FUNC_CAST(skFieldListCompareBuffers),
                                 (void*)uniq->fi.key_fields);

    /* use the table's current entry count to set the initial entry
     * for when the table is re-created */
    entry_count = hashlib_count_entries(uniq->ht);
    if (uniq->ht_estimated < (entry_count >> 1)) {
        uniq->ht_estimated = entry_count >> 1;
    }

    /* create an iterator for the hash table */
    ithash = hashlib_create_iterator(uniq->ht);

    if (0 == uniq->fi.distinct_num_fields) {
        uniqDebug(uniq, "Writing %" PRIu64 " key/value paris to #%d...",
                  entry_count, uniq->temp_idx);

        /* iterate over the hash entries */
        while (hashlib_iterate(uniq->ht, &ithash, &hash_key, &hash_val)
               != ERR_NOMOREENTRIES)
        {
            uniqTempWriteTriple(&uniq->fi, uniq->temp_fp, NULL,
                                hash_key, hash_val, NULL);
        }
        /* destroy the hash table */
        uniqueDestroyHashTable(uniq);

        /* close the temp file and open a new file */
        uniqDebug(uniq, "Finished writing #%d '%s'",
                  uniq->temp_idx, UNIQUE_TMPNAME_OUT(uniq));
        uniqTempClose(uniq->temp_fp);
        uniq->temp_fp = uniqTempCreate(uniq->tmpctx, &uniq->max_temp_idx);
        uniq->temp_idx = uniq->max_temp_idx;

    } else {
        uniqDebug(uniq, ("Writing %" PRIu64
                         " key/value/distinct triples to #%d, #%d..."),
                  entry_count, uniq->temp_idx, uniq->max_temp_idx);

        while (hashlib_iterate(uniq->ht, &ithash, &hash_key, &hash_val)
               != ERR_NOMOREENTRIES)
        {
            memcpy(&distincts, hash_val + uniq->fi.value_octets, sizeof(void*));
            uniqTempWriteTriple(&uniq->fi, uniq->temp_fp, uniq->dist_fp,
                                hash_key, hash_val, distincts);
        }
        uniqueDestroyHashTable(uniq);

        /* close the temp files and open a new files */
        uniqDebug(uniq, "Finished writing #%d '%s', #%d '%s'",
                  uniq->temp_idx, UNIQUE_TMPNAME_OUT(uniq), uniq->max_temp_idx,
                  uniqBasename(skStreamGetPathname(uniq->dist_fp)));
        uniqTempClose(uniq->temp_fp);
        uniq->temp_fp = NULL;
        uniqTempClose(uniq->dist_fp);
        uniq->dist_fp = NULL;
        uniq->temp_fp = uniqTempCreate(uniq->tmpctx, &uniq->max_temp_idx);
        uniq->temp_idx = uniq->max_temp_idx;
        uniq->dist_fp = uniqTempCreate(uniq->tmpctx, &uniq->max_temp_idx);
    }
}


/*  create a new unique object */
int
skUniqueCreate(
    sk_unique_t       **uniq)
{
    sk_unique_t *u;
    const char *env_value;
    uint32_t debug_lvl;

    u = (sk_unique_t*)calloc(1, sizeof(sk_unique_t));
    if (NULL == u) {
        *uniq = NULL;
        return -1;
    }

    u->ht_estimated = HASH_INITIAL_SIZE;
    u->temp_idx = -1;
    u->max_temp_idx = -1;

    env_value = getenv(SKUNIQUE_DEBUG_ENVAR);
    if (env_value && 0 == skStringParseUint32(&debug_lvl, env_value, 1, 0)) {
        u->print_debug = 1;
    }

    *uniq = u;
    return 0;
}


/*  destroy a unique object; cleans up any temporary files; etc. */
void
skUniqueDestroy(
    sk_unique_t       **uniq)
{
    sk_unique_t *u;

    if (NULL == uniq || NULL == *uniq) {
        return;
    }

    u = *uniq;
    *uniq = NULL;

    if (u->temp_fp) {
        uniqTempClose(u->temp_fp);
        u->temp_fp = NULL;
    }
    if (u->dist_fp) {
        uniqTempClose(u->dist_fp);
        u->dist_fp = NULL;
    }
    uniqTotalDistinctDestroy(&u->total_dist);
    skTempFileTeardown(&u->tmpctx);
    u->temp_idx = -1;
    uniqueDestroyHashTable(u);
    free(u->temp_dir);

    free(u);
}


/*  specify that output from 'uniq' should be sorted */
int
skUniqueSetSortedOutput(
    sk_unique_t        *uniq)
{
    assert(uniq);

    if (uniq->ready_for_input) {
        skAppPrintErr("May not call skUniqueSetSortedOutput"
                      " after calling skUniquePrepareForInput");
        return -1;
    }
    uniq->sort_output = 1;
    return 0;
}


/*  specify the temporary directory. */
void
skUniqueSetTempDirectory(
    sk_unique_t        *uniq,
    const char         *temp_dir)
{
    assert(uniq);

    if (uniq->ready_for_input) {
        skAppPrintErr("May not call skUniqueSetTempDirectory"
                      " after calling skUniquePrepareForInput");
        return;
    }

    if (uniq->temp_dir) {
        free(uniq->temp_dir);
        uniq->temp_dir = NULL;
    }
    if (temp_dir) {
        uniq->temp_dir = strdup(temp_dir);
    }
}


/*  set the fields that 'uniq' will use. */
int
skUniqueSetFields(
    sk_unique_t            *uniq,
    const sk_fieldlist_t   *key_fields,
    const sk_fieldlist_t   *distinct_fields,
    const sk_fieldlist_t   *agg_value_fields)
{
    assert(uniq);

    if (uniq->ready_for_input) {
        skAppPrintErr("May not call skUniqueSetFields"
                      " after calling skUniquePrepareForInput");
        return -1;
    }

    memset(&uniq->fi, 0, sizeof(sk_uniq_field_info_t));
    uniq->fi.key_fields = key_fields;
    uniq->fi.distinct_fields = distinct_fields;
    uniq->fi.value_fields = agg_value_fields;

    return 0;
}


/*  count distincts across all bins for first distinct field */
int
skUniqueEnableTotalDistinct(
    sk_unique_t        *uniq)
{
    assert(uniq);

    if (uniq->ready_for_input) {
        skAppPrintErr("May not call skUniqueEnableTotalDistinct"
                      " after calling skUniquePrepareForInput");
        return -1;
    }
    uniq->use_total_distinct = 1;
    return 0;
}


/*  return the number of distincts for first distinct field across all
 *  bins */
uint64_t
skUniqueGetTotalDistinctCount(
    sk_unique_t        *uniq)
{
    if (!uniq->ready_for_output) {
        skAppPrintErr("May not call skUniqueGetTotalDistinctCount"
                      " before calling skUniquePrepareForOutput");
        return UINT64_MAX;
    }
    return uniqTotalDistinctGetCount(&uniq->total_dist);
}


/*  tell the unique object that initialization is complete.  return an
 *  error if the object is not completely specified. */
int
skUniquePrepareForInput(
    sk_unique_t        *uniq)
{
    assert(uniq);

    if (uniq->ready_for_input) {
        return 0;
    }

    if (uniqCheckFields(&uniq->fi)) {
        return -1;
    }

    /* initialize the total distinct object */
    if (uniq->use_total_distinct) {
        if (uniqTotalDistinctPrepareInput(
                &uniq->total_dist, &uniq->fi, uniq->temp_dir))
        {
            return -1;
        }
    }

    /* set sizes for the hash table */
    SAFE_SET(uniq->hash_value_octets,
             (uniq->fi.value_octets
              + (uniq->fi.distinct_num_fields ? sizeof(void*) : 0)));

    /* create the hash table */
    if (uniqueCreateHashTable(uniq)) {
        return -1;
    }

    /* initialize temp file context on the unique object */
    if (skTempFileInitialize(&uniq->tmpctx, uniq->temp_dir,
                             NULL, &skAppPrintErr))
    {
        return -1;
    }

    /* open an intermediate file */
    uniq->temp_fp = uniqTempCreate(uniq->tmpctx, &uniq->max_temp_idx);
    uniq->temp_idx = uniq->max_temp_idx;
    if (uniq->fi.distinct_num_fields) {
        uniq->dist_fp = uniqTempCreate(uniq->tmpctx, &uniq->max_temp_idx);
    }

    uniq->ready_for_input = 1;
    return 0;
}


/*  add a flow record to a unique object */
int
skUniqueAddRecord(
    sk_unique_t        *uniq,
    const rwRec        *rwrec)
{
    distinct_value_t *distincts = NULL;
    uint8_t field_buf[HASHLIB_MAX_KEY_WIDTH];
    uint8_t *hash_val;
    uint32_t memory_error = 0;
    int rv;

    assert(uniq);
    assert(uniq->ht);
    assert(rwrec);
    assert(uniq->ready_for_input);

    if (uniqTotalDistinctIncrement(&uniq->total_dist, rwrec)) {
        return -1;
    }

    for (;;) {
        skFieldListRecToBinary(uniq->fi.key_fields, rwrec, field_buf);

        /* the 'insert' will set 'hash_val' to the memory to use to
         * store the values. either fresh memory or the existing
         * value(s). */
        rv = hashlib_insert(uniq->ht, field_buf, &hash_val);
        switch (rv) {
          case OK:
            /* new key; don't increment value until we are sure we can
             * allocate the space for the distinct fields */
            skFieldListInitializeBuffer(uniq->fi.value_fields, hash_val);
            if (uniq->fi.distinct_num_fields) {
                skFieldListRecToBinary(uniq->fi.distinct_fields, rwrec,
                                       field_buf);
                if (uniqDistinctAlloc(&uniq->fi, &distincts)) {
                    memory_error |= 2;
                    break;
                }
                if (uniqDistinctIncrement(&uniq->fi, distincts, field_buf)) {
                    memory_error |= 4;
                    break;
                }
                memcpy(hash_val + uniq->fi.value_octets, &distincts,
                       sizeof(void*));
            }
            skFieldListAddRecToBuffer(uniq->fi.value_fields, rwrec, hash_val);
            return 0;

          case OK_DUPLICATE:
            /* existing key; merge the distinct fields first, then
             * merge the value */
            if (uniq->fi.distinct_num_fields) {
                memcpy(&distincts, hash_val + uniq->fi.value_octets,
                       sizeof(void*));
                skFieldListRecToBinary(uniq->fi.distinct_fields, rwrec,
                                       field_buf);
                if (uniqDistinctIncrement(&uniq->fi, distincts, field_buf)) {
                    memory_error |= 8;
                    break;
                }
            }
            skFieldListAddRecToBuffer(uniq->fi.value_fields, rwrec, hash_val);
            return 0;

          case ERR_OUTOFMEMORY:
          case ERR_NOMOREBLOCKS:
            memory_error |= 1;
            break;

          default:
            skAppPrintErr("Unexpected return code '%d' from hash table insert",
                          rv);
            return -1;
        }

        /* ran out of memory somewhere */
        TRACEMSG((("%s:%d: Memory error code is %" PRIu32),
                  __FILE__, __LINE__, memory_error));

        if (memory_error > (1u << 31)) {
            /* this is our second memory error */
            if (OK != rv) {
                skAppPrintErr(("Unexpected return code '%d'"
                               " from hash table insert on new hash table"),
                              rv);
            } else {
                skAppPrintErr(("Error allocating memory after writing"
                               " hash table to temporary file"));
            }
            return -1;
        }
        memory_error |= (1u << 31);

        /*
         *  If (memory_error & 8) then there is a partially updated
         *  distinct count.  This should not matter as long as we can
         *  write the current values to disk and then reset
         *  everything.  At worst, the distinct value for this key
         *  will appear in two separate temporary files, but that
         *  should be resolved then the distinct values from the two
         *  files for this key are merged.
         */

        /* out of memory */
        uniqueDumpHashToTemp(uniq);

        /* re-create the hash table */
        if (uniqueCreateHashTable(uniq)) {
            return -1;
        }
    }

    return 0;                   /* NOTREACHED */
}


/*  get ready to return records to the caller. */
int
skUniquePrepareForOutput(
    sk_unique_t        *uniq)
{
    if (uniq->ready_for_output) {
        return 0;
    }
    if (!uniq->ready_for_input) {
        skAppPrintErr("May not call skUniquePrepareForOutput"
                      " before calling skUniquePrepareForInput");
        return -1;
    }

    if (uniq->temp_idx > 0) {
        /* dump the current/final hash entries to a file */
        uniqueDumpHashToTemp(uniq);
    } else if (uniq->sort_output) {
        /* need to sort using the skFieldListCompareBuffers function */
        hashlib_sort_entries_usercmp(uniq->ht,
                                     COMP_FUNC_CAST(skFieldListCompareBuffers),
                                     (void*)uniq->fi.key_fields);
    }

    if (uniqTotalDistinctPrepareOutput(&uniq->total_dist)) {
        return -1;
    }

    uniqDebug(uniq, "Preparing for output");

    uniq->ready_for_output = 1;
    return 0;
}


/****************************************************************
 * Iterator for handling one hash table, no distinct counts
 ***************************************************************/

/*
 *    A simple iterator over the items in the hash table.
 */

typedef struct uniqiter_simple_st {
    sk_uniqiter_next_fn_t   next_fn;
    sk_uniqiter_free_fn_t   free_fn;
    sk_unique_t            *uniq;
    HASH_ITER               ithash;
} uniqiter_simple_t;


/*
 *  status = uniqIterSimpleNext(iter, &key, &distinct, &value);
 *
 *    Implementation for skUniqueIteratorNext().
 */
static int
uniqIterSimpleNext(
    sk_unique_iterator_t           *v_iter,
    uint8_t                       **key_fields_buffer,
    uint8_t                UNUSED(**distinct_fields_buffer),
    uint8_t                       **value_fields_buffer)
{
    uniqiter_simple_t *iter = (uniqiter_simple_t*)v_iter;

    if (hashlib_iterate(iter->uniq->ht, &iter->ithash,
                        key_fields_buffer, value_fields_buffer)
        == ERR_NOMOREENTRIES)
    {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    return SK_ITERATOR_OK;
}


/*
 *  uniqIterSimpleDestroy(&iter);
 *
 *    Implementation for skUniqueIteratorDestroy().
 */
static void
uniqIterSimpleDestroy(
    sk_unique_iterator_t  **v_iter)
{
    uniqiter_simple_t *iter;

    if (v_iter && *v_iter) {
        iter = *(uniqiter_simple_t**)v_iter;
        memset(iter, 0, sizeof(uniqiter_simple_t));
        free(iter);
        *v_iter = NULL;
    }
}


/*
 *  status = uniqIterSimpleCreate(uniq, &iter);
 *
 *    Helper function for skUniqueIteratorCreate().
 */
static int
uniqIterSimpleCreate(
    sk_unique_t            *uniq,
    sk_unique_iterator_t  **new_iter)
{
    uniqiter_simple_t *iter;

    iter = (uniqiter_simple_t*)calloc(1, sizeof(uniqiter_simple_t));
    if (NULL == iter) {
        skAppPrintOutOfMemory("unique iterator");
        return -1;
    }

    iter->uniq = uniq;
    iter->next_fn = uniqIterSimpleNext;
    iter->free_fn = uniqIterSimpleDestroy;
    iter->ithash = hashlib_create_iterator(iter->uniq->ht);

    uniqDebug(iter->uniq, "Created simple iterator; num entries = %" PRIu64,
              hashlib_count_entries(iter->uniq->ht));

    *new_iter = (sk_unique_iterator_t*)iter;
    return 0;
}



/****************************************************************
 * Iterator for handling distinct values in one hash table
 ***************************************************************/

/*
 *    An iterator over the items in the hash table that calls a
 *    function to get the distinct count for every distinct field.
 */

typedef struct uniqiter_distinct_st {
    sk_uniqiter_next_fn_t   next_fn;
    sk_uniqiter_free_fn_t   free_fn;
    sk_unique_t            *uniq;
    HASH_ITER               ithash;
    uint8_t                 returned_buf[HASH_MAX_NODE_BYTES];
} uniqiter_distinct_t;


/*
 *  status = uniqIterDistinctNext();
 *
 *    Implementation for skUniqueIteratorNext(iter, &key, &distinct, &value).
 */
static int
uniqIterDistinctNext(
    sk_unique_iterator_t   *v_iter,
    uint8_t               **key_fields_buffer,
    uint8_t               **distinct_fields_buffer,
    uint8_t               **value_fields_buffer)
{
    uniqiter_distinct_t *iter = (uniqiter_distinct_t*)v_iter;
    distinct_value_t *distincts;

    if (hashlib_iterate(iter->uniq->ht, &iter->ithash,
                        key_fields_buffer, value_fields_buffer)
        == ERR_NOMOREENTRIES)
    {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }

    memcpy(&distincts, *value_fields_buffer + iter->uniq->fi.value_octets,
           sizeof(void*));
    uniqDistinctSetOutputBuf(&iter->uniq->fi, distincts, iter->returned_buf);
    *distinct_fields_buffer = iter->returned_buf;
    return SK_ITERATOR_OK;
}


/*
 *  uniqIterDistinctDestroy(&iter);
 *
 *    Implementation for skUniqueIteratorDestroy().
 */
static void
uniqIterDistinctDestroy(
    sk_unique_iterator_t  **v_iter)
{
    uniqiter_distinct_t *iter;

    if (v_iter && *v_iter) {
        iter = *(uniqiter_distinct_t**)v_iter;
        memset(iter, 0, sizeof(uniqiter_distinct_t));
        free(iter);
        *v_iter = NULL;
    }
}


/*
 *  status = uniqIterDistinctCreate(uniq, &iter);
 *
 *    Helper function for skUniqueIteratorCreate().
 */
static int
uniqIterDistinctCreate(
    sk_unique_t            *uniq,
    sk_unique_iterator_t  **new_iter)
{
    uniqiter_distinct_t *iter;

    assert(uniq);
    assert(uniq->fi.distinct_num_fields > 0);

    iter = (uniqiter_distinct_t*)calloc(1, sizeof(uniqiter_distinct_t));
    if (NULL == iter) {
        skAppPrintOutOfMemory("unique iterator");
        return -1;
    }

    iter->uniq = uniq;
    iter->next_fn = uniqIterDistinctNext;
    iter->free_fn = uniqIterDistinctDestroy;
    iter->ithash = hashlib_create_iterator(iter->uniq->ht);

    uniqDebug(iter->uniq,
              "Created simple-distinct iterator; num entries = %" PRIu64,
              hashlib_count_entries(iter->uniq->ht));

    *new_iter = (sk_unique_iterator_t*)iter;
    return 0;
}


/****************************************************************
 * Iterator for handling temporary files without distinct values
 ***************************************************************/

/*
 *    The iterator merge-sorts the keys in the temporary files and
 *    merges the values when keys are identical.
 *
 *    The first call to the iterator opens all temporary files.  If
 *    there are more temporary files than file handles, the files are
 *    merged until the iterator is able to have an open file handle to
 *    every temporary file.
 */

typedef struct uniqiter_temp_values_st {
    sk_uniqiter_next_fn_t   next_fn;
    sk_uniqiter_free_fn_t   free_fn;
    sk_unique_t            *uniq;
    skheap_t               *heap;
    uint8_t                 key[MAX_MERGE_FILES][HASHLIB_MAX_KEY_WIDTH];
    skstream_t             *fps[MAX_MERGE_FILES];
    uint8_t                 returned_buf[HASH_MAX_NODE_BYTES];
    int                     temp_idx_base;
    uint16_t                max_fps;
    /* ENSURE EVERYTHING ABOVE HERE MATCHES uniqiter_temp_dist_t */
} uniqiter_temp_values_t;


static int
uniqIterTempValuesKeyCmp(
    const skheapnode_t  b,
    const skheapnode_t  a,
    void               *v_iter);

static int
uniqIterTempValuesMergeValues(
    uniqiter_temp_values_t *iter,
    uint16_t                lowest,
    uint8_t                *cached_key,
    uint8_t                *merged_values);

static int
uniqIterTempValuesOpenAll(
    uniqiter_temp_values_t *iter);


/*
 *  status = uniqIterTempValuesNext(iter, &key, &distinct, &value);
 *
 *    Implementation for skUniqueIteratorNext() when using temporary
 *    files that do not have distinct values.
 */
static int
uniqIterTempValuesNext(
    sk_unique_iterator_t   *v_iter,
    uint8_t               **key_fields_buffer,
    uint8_t               **distinct_fields_buffer,
    uint8_t               **value_fields_buffer)
{
    uniqiter_temp_values_t *iter = (uniqiter_temp_values_t*)v_iter;
    uint16_t lowest;
    uint16_t *top_heap;
    uint8_t cached_key[HASHLIB_MAX_KEY_WIDTH];
    uint8_t merged_values[HASHLIB_MAX_VALUE_WIDTH];

    SK_UNUSED_PARAM(distinct_fields_buffer);

    assert(iter);

    /* should only be called with value fields and no distinct fields */
    assert(0 == iter->uniq->fi.distinct_num_fields);
    assert(iter->uniq->fi.value_octets > 0);

    /* get the index of the file with the lowest key; which is at
     * the top of the heap */
    if (SKHEAP_OK != skHeapPeekTop(iter->heap, (skheapnode_t*)&top_heap)) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    lowest = *top_heap;

    if (uniqIterTempValuesMergeValues(iter, lowest, cached_key, merged_values))
    {
        /* error reading from files */
        skHeapEmpty(iter->heap);
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }

    /* set user's pointers to the buffers on the iterator, and write
     * the key, values, and distincts into those buffers */
    *key_fields_buffer = iter->returned_buf;
    memcpy(*key_fields_buffer, cached_key, iter->uniq->fi.key_octets);

    *value_fields_buffer = iter->returned_buf + iter->uniq->fi.key_octets;
    memcpy(*value_fields_buffer,merged_values,iter->uniq->fi.value_octets);

    return SK_ITERATOR_OK;
}


/*
 *  uniqIterTempValuesDestroy(iter);
 *
 *    Implementation for skUniqueIteratorDestroy().
 */
static void
uniqIterTempValuesDestroy(
    sk_unique_iterator_t  **v_iter)
{
    uniqiter_temp_values_t *iter;
    size_t i;

    if (v_iter && *v_iter) {
        iter = *(uniqiter_temp_values_t**)v_iter;

        for (i = 0; i < iter->max_fps; ++i) {
            uniqTempClose(iter->fps[i]);
        }
        memset(iter->fps, 0, sizeof(iter->fps));

        skHeapFree(iter->heap);
        free(iter);
        *v_iter = NULL;
    }
}


/*
 *  status = uniqIterTempValuesCreate(uniq, &iter);
 *
 *    Helper function for skUniqueIteratorCreate().
 */
static int
uniqIterTempValuesCreate(
    sk_unique_t            *uniq,
    sk_unique_iterator_t  **new_iter)
{
    uniqiter_temp_values_t *iter;

    assert(uniq);
    assert(new_iter);

    /* should only be called with value fields and no distinct fields */
    assert(0 == uniq->fi.distinct_num_fields);
    assert(uniq->fi.value_octets > 0);

    iter = (uniqiter_temp_values_t *)calloc(1,sizeof(uniqiter_temp_values_t));
    if (NULL == iter) {
        skAppPrintOutOfMemory("unique iterator");
        goto ERROR;
    }

    iter->heap = skHeapCreate2(uniqIterTempValuesKeyCmp, MAX_MERGE_FILES,
                               sizeof(uint16_t), NULL, iter);
    if (NULL == iter->heap) {
        skAppPrintOutOfMemory("unique iterator");
        goto ERROR;
    }

    iter->uniq = uniq;
    iter->next_fn = uniqIterTempValuesNext;
    iter->free_fn = uniqIterTempValuesDestroy;

    /* open all temp files---this also merges temp files if there
     * are not enough file handles to open all temp files */
    if (uniqIterTempValuesOpenAll(iter)) {
        goto ERROR;
    }
    if (skHeapGetNumberEntries(iter->heap) == 0) {
        skAppPrintErr("Could not read records from any temporary files");
        goto ERROR;
    }

    uniqDebug(iter->uniq, "Created tempfile iterator; open files = %" PRIu32,
              skHeapGetNumberEntries(iter->heap));

    *new_iter = (sk_unique_iterator_t*)iter;
    return 0;

  ERROR:
    uniqIterTempValuesDestroy((sk_unique_iterator_t**)&iter);
    skAppPrintErr("Error creating unique iterator");
    return -1;
}


/*
 *    Helper function to merge the aggregate values from multiple
 *    temporary files into a single value for a single key.
 *
 *    This function may only be used when no distinct fields are
 *    present.
 *
 *    Fill 'cached_key' with the key for the file whose index is in
 *    'lowest'.
 *
 *    Initialize the buffer in 'merged_values' to hold the merging
 *    (e.g., the sum) of the aggregate value fields.
 *
 *    Across all the temporary files open on 'iter', read the values
 *    for keys that match 'cached_key' and add that value to
 *    'merged_values'.
 *
 *    Return 0 on success or -1 on read failure.
 */
static int
uniqIterTempValuesMergeValues(
    uniqiter_temp_values_t *iter,
    uint16_t                lowest,
    uint8_t                *cached_key,
    uint8_t                *merged_values)
{
    uint8_t buf[4096];
    uint16_t *top_heap;
    uint32_t heap_count;
    int last_errno;

    /* should only be called with value fields and no distinct fields */
    assert(0 == iter->uniq->fi.distinct_num_fields);
    assert(0 < iter->uniq->fi.value_octets);

    /* lowest should be the file index at the top of the heap */
    assert(SKHEAP_OK == skHeapPeekTop(iter->heap, (skheapnode_t*)&top_heap));
    assert(lowest == *top_heap);

    heap_count = skHeapGetNumberEntries(iter->heap);

    memcpy(cached_key, iter->key[lowest], iter->uniq->fi.key_octets);

    skFieldListInitializeBuffer(iter->uniq->fi.value_fields, merged_values);

    /* repeat as long as the key of the item at top of the heap
     * matches the cached_key */
    do {
        /* read the value and merge it into the current value */
        if (!uniqTempRead(iter->fps[lowest], buf, iter->uniq->fi.value_octets))
        {
            last_errno = skStreamGetLastErrno(iter->fps[lowest]);
            uniqDebug(iter->uniq, "Cannot read from temporary file #%u",
                      UNIQUE_TMPNUM_READ(iter, lowest));
            skAppPrintErr(
                "Cannot read value field from temporary file: %s",
                (last_errno ? strerror(last_errno) : "EOF"));
            return -1;
        }
        skFieldListMergeBuffers(
            iter->uniq->fi.value_fields, merged_values, buf);

        /* replace the key for the value we just processed */
        if (uniqTempRead(iter->fps[lowest], iter->key[lowest],
                         iter->uniq->fi.key_octets))
        {
            /* read succeeded. insert the new entry into the
             * heap. */
            skHeapReplaceTop(iter->heap, &lowest, NULL);
            /* keys within a file should always be unique and sorted
             * when no distinct fields are present */
            assert(skFieldListCompareBuffers(cached_key, iter->key[lowest],
                                             iter->uniq->fi.key_fields) < 0);
        } else {
            /* read failed or no more data for this file; remove it
             * from the heap */
            uniqDebug(iter->uniq, "Finished reading file #%u, %u files remain",
                      UNIQUE_TMPNUM_READ(iter, lowest),
                      skHeapGetNumberEntries(iter->heap) - 1);
            skHeapExtractTop(iter->heap, NULL);
            --heap_count;
            if (0 == heap_count) {
                break;
            }
        }

        /* get the new value at the top of the heap; if its key
         * matches cached_key, add its values to merged_values. */
        skHeapPeekTop(iter->heap, (skheapnode_t*)&top_heap);
        lowest = *top_heap;

    } while (skFieldListCompareBuffers(
                 cached_key, iter->key[lowest], iter->uniq->fi.key_fields)==0);

    return 0;
}


/*
 *  status = uniqIterTempValuesKeyCmp(b, a, v_iter);
 *
 *    Comparison callback function used by the heap.
 *
 *    The values in 'b' and 'a' are integer indexes into an array of
 *    keys.  The function calls the field comparison function to
 *    compare the keys and returns the result.
 *
 *    The context value in 'v_iter' is the uniqiter_temp_values_t or
 *    uniqiter_temp_dist_t object that holds the keys and the fields
 *    describing the sort order.
 *
 *    Note the order of arguments is 'b', 'a'.
 */
static int
uniqIterTempValuesKeyCmp(
    const skheapnode_t  b,
    const skheapnode_t  a,
    void               *v_iter)
{
    uniqiter_temp_values_t *iter = (uniqiter_temp_values_t *)v_iter;

    return skFieldListCompareBuffers(iter->key[*(uint16_t*)a],
                                     iter->key[*(uint16_t*)b],
                                     iter->uniq->fi.key_fields);
}


/*
 *  count = uniqIterTempValuesOpenAll(iter);
 *
 *    Open all temporary files created while reading records, put the
 *    file handles in the 'fp' member of 'iter', read the first key
 *    from each file into the 'key' member of 'iter', insert the keys
 *    into the heap on 'iter', and return the number of files opened.
 *
 *    If it is impossible to open all files due to a lack of file
 *    handles, the existing temporary files will be merged into new
 *    temporary files, and then another attempt will be made to open
 *    all files.
 *
 *    This function will only return when it is possible to return a
 *    file handle to every existing temporary file.  If it is unable
 *    to create a new temporary file, it returns -1.
 */
static int
uniqIterTempValuesOpenAll(
    uniqiter_temp_values_t *iter)
{
    uint16_t i;
    int j;
    int tmp_idx_a;
    int tmp_idx_b;
    uint16_t *top_heap;
    uint16_t lowest;
    uint8_t cached_key[HASHLIB_MAX_KEY_WIDTH];
    uint8_t merged_values[HASHLIB_MAX_VALUE_WIDTH];
    ssize_t rv;

    /* recall that uniq->temp_idx is the intermediate temp file; which
     * is open but unused when this function is called.  for this
     * function to be called, temp files #0 and #1 must be in use */
    assert(iter->uniq->temp_idx >= 2);
    assert(iter->uniq->temp_fp);

    /* should only be called with value fields and no distinct fields */
    assert(0 == iter->uniq->fi.distinct_num_fields);
    assert(0 < iter->uniq->fi.value_octets);

    /* index at which to start the merge */
    tmp_idx_a = 0;

    /* This loop repeats as long as we haven't opened all of the temp
     * files generated while reading the flows. */
    for (;;) {
        assert(skHeapGetNumberEntries(iter->heap) == 0);

        /* the index of the first temporary file being processed */
        iter->temp_idx_base = tmp_idx_a;

        /* determine the index at which to stop the merge */
        tmp_idx_b = tmp_idx_a + MAX_MERGE_FILES - 1;
        if (iter->uniq->temp_idx <= tmp_idx_b) {
            /* fewer than MAX_MERGE_FILES files */
            tmp_idx_b = iter->uniq->temp_idx - 1;
        }

        uniqDebug(iter->uniq,
                  "Attempting to open temporary files #%d through #%d",
                  tmp_idx_a, tmp_idx_b);

        /* Open up to MAX_MERGE files */
        for (j = tmp_idx_a, i = 0; j <= tmp_idx_b; ++j, ++i) {
            iter->fps[i] = uniqTempReopen(iter->uniq->tmpctx, j);
            if (NULL == iter->fps[i]) {
                if (skHeapGetNumberEntries(iter->heap) < 2) {
                    skAppPrintErr("Unable to open multiple temporary files");
                    return -1;
                }
                /* We cannot open any more temp files; we'll need to
                 * catch file 'j' the next time around. */
                tmp_idx_b = j - 1;
                uniqDebug(iter->uniq,
                          ("File limit hit [%s]---merging"
                           " #%d through #%d into #%d..."),
                          strerror(errno), tmp_idx_a, tmp_idx_b,
                          iter->uniq->temp_idx);
                break;
            }

            /* Read the first key from the file and add the file's
             * index to the heap */
            if (uniqTempRead(iter->fps[i], iter->key[i],
                             iter->uniq->fi.key_octets))
            {
                skHeapInsert(iter->heap, &i);
            } else if (0 == skStreamGetLastErrno(iter->fps[i])) {
                uniqDebug(iter->uniq,
                          "Ignoring empty temporary file #%u '%s'",
                          j, skTempFileGetName(iter->uniq->tmpctx, j));
                uniqTempClose(iter->fps[i]);
                iter->fps[i] = NULL;
            } else {
                skAppPrintErr(
                    "Cannot read first key from temporary file '%s': %s",
                    skTempFileGetName(iter->uniq->tmpctx, j),
                    strerror(skStreamGetLastErrno(iter->fps[i])));
                return -1;
            }
        }

        uniqDebug(iter->uniq, "Opened %" PRIu32 " temporary files",
                  skHeapGetNumberEntries(iter->heap));

        /* Check to see if we've opened all temp files.  If so,
         * return */
        if (tmp_idx_b == iter->uniq->temp_idx - 1) {
            uniqDebug(iter->uniq,
                      "Successfully opened all%s temporary files",
                      ((tmp_idx_a > 0) ? " remaining" : ""));
            iter->max_fps = i;
            return 0;
        }
        /* Else, we could not open all temp files, so merge all opened
         * temp files into the intermediate file */

        /* exit this while() loop once all records for all opened
         * files have been read or until there is only one file
         * remaining */
        while (skHeapGetNumberEntries(iter->heap) > 1) {
            /* get the index of the file with the lowest key */
            skHeapPeekTop(iter->heap, (skheapnode_t*)&top_heap);
            lowest = *top_heap;

            /* for all files that match the lowest key key, merge
             * their values into 'merged_values' */
            if (uniqIterTempValuesMergeValues(
                    iter, lowest, cached_key, merged_values))
            {
                return -1;
            }

            /* write the lowest key/value pair to the intermediate
             * temp file */
            uniqTempWrite(iter->uniq->temp_fp, cached_key,
                          iter->uniq->fi.key_octets);
            uniqTempWrite(iter->uniq->temp_fp, merged_values,
                          iter->uniq->fi.value_octets);
        }

        /* copy the data from the remaining file as blocks */
        if (skHeapExtractTop(iter->heap, (skheapnode_t)&lowest) == SKHEAP_OK) {
            uint8_t buf[4096];

            assert(skHeapGetNumberEntries(iter->heap) == 0);

            /* write the key that's in memory */
            uniqTempWrite(iter->uniq->temp_fp, iter->key[lowest],
                          iter->uniq->fi.key_octets);

            /* inline the body of uniqTempRead() since that function
             * does not support partial reads */
            while ((rv =skStreamRead(iter->fps[lowest], buf, sizeof(buf))) > 0)
            {
                uniqTempWrite(iter->uniq->temp_fp, buf, rv);
            }
            if (-1 == rv) {
                char errbuf[2 * PATH_MAX];

                skStreamLastErrMessage(
                    iter->fps[lowest], rv, errbuf, sizeof(errbuf));
                TRACEMSG(("%s:%d: Failed to read %" SK_PRIuZ " bytes: %s",
                          __FILE__, __LINE__, sizeof(buf), errbuf));
                skAppPrintErr("Cannot read from temporary file: %s", errbuf);
                return -1;
            }
            uniqDebug(iter->uniq, "Finished reading file #%u, 0 files remain",
                      UNIQUE_TMPNUM_READ(iter, lowest));
        }
        assert(skHeapGetNumberEntries(iter->heap) == 0);

        /* Close and remove all the temp files that we processed this
         * time. */
        for (j = tmp_idx_a, i = 0; j <= tmp_idx_b; ++j, ++i) {
            uniqTempClose(iter->fps[i]);
            skTempFileRemove(iter->uniq->tmpctx, j);
        }
        memset(iter->fps, 0, sizeof(iter->fps));

        /* Close the intermediate temp file and open a new one. */
        uniqDebug(iter->uniq, "Finished writing #%d '%s'",
                  iter->uniq->temp_idx, UNIQUE_TMPNAME_OUT(iter->uniq));
        uniqTempClose(iter->uniq->temp_fp);
        iter->uniq->temp_fp = uniqTempCreate(iter->uniq->tmpctx,
                                             &iter->uniq->max_temp_idx);
        iter->uniq->temp_idx = iter->uniq->max_temp_idx;

        /* Start the next merge with the next input temp file */
        tmp_idx_a = tmp_idx_b + 1;
    }

    return -1;    /* NOTREACHED */
}


/****************************************************************
 * Iterator for handling temporary files with distinct values
 ***************************************************************/

/*
 *    There are two structures used when handling temporary files
 *    depending on whether there are distinct fields to handle.  the
 *    two structures have the same initial members can be cast to one
 *    another.
 *
 *    The callback function that implements skUniqueIteratorNext() is
 *    different depending on whether distinct fields are present.
 */

/* has support for distinct fields */
typedef struct uniqiter_temp_dist_st {
    /* function pointer used by skUniqueIteratorNext() */
    sk_uniqiter_next_fn_t   next_fn;

    /* function pointer used by skUniqueIteratorDestroy() */
    sk_uniqiter_free_fn_t   free_fn;

    /* the object to iterate over */
    sk_unique_t        *uniq;

    /* heap the stores the indexes used by the 'fps' and 'key'
     * members. comparison function uses the 'key' member of this
     * structure and returns the keys in ascending order */
    skheap_t           *heap;

    /* for each file in 'fps', the file's current key */
    uint8_t             key[MAX_MERGE_FILES >> 1][HASHLIB_MAX_KEY_WIDTH];

    /* temporary key/value files that are currently open; number of
     * valid files specified by the 'open_count' member */
    skstream_t         *fps[MAX_MERGE_FILES >> 1];

    /* buffer used to hold the values the are returned to the caller
     * by skUniqueIteratorNext(). */
    uint8_t             returned_buf[HASH_MAX_NODE_BYTES];

    /* */
    distinct_merge_t    dist_merge;

    /* index of first temp file opened for this round of merging; used
     * when reporting temp file indexes */
    int                 temp_idx_base;

    /* number of open files: number of valid entries in fps[] */
    uint16_t            max_fps;

    /* lengths and offsets of each distinct field */
    distinct_value_t   *distincts;

} uniqiter_temp_dist_t;


static int
uniqIterTempDistMergeOne(
    uniqiter_temp_dist_t   *iter,
    uint8_t                 merged_values[]);

static int
uniqIterTempDistMergeValuesDist(
    uniqiter_temp_dist_t   *iter,
    uint8_t                 merged_values[]);

static int
uniqIterTempDistOpenAll(
    uniqiter_temp_dist_t   *iter);

static int
uniqIterTempDistKeyCmp(
    const skheapnode_t  b,
    const skheapnode_t  a,
    void               *v_iter);


/*
 *  status = uniqIterTempDistNext(iter, &key, &distinct, &value);
 *
 *    Implementation for skUniqueIteratorNext() when using temporary
 *    files that do have distinct values.
 */
static int
uniqIterTempDistNext(
    sk_unique_iterator_t   *v_iter,
    uint8_t               **key_fields_buffer,
    uint8_t               **distinct_fields_buffer,
    uint8_t               **value_fields_buffer)
{
    uniqiter_temp_dist_t *iter = (uniqiter_temp_dist_t*)v_iter;
    uint16_t lowest;
    uint16_t *top_heap;
    uint8_t cached_key[HASHLIB_MAX_KEY_WIDTH];
    uint8_t merged_values[HASHLIB_MAX_VALUE_WIDTH];
    uint16_t i;
    int rv;

    assert(iter);

    /* should only be called when distinct fields are present */
    assert(iter->uniq->fi.distinct_num_fields > 0);

    /* should not be writing to tempoary files */
    assert(0 == iter->dist_merge.write_to_temp);

    /* get the index of the file with the lowest key; which is at
     * the top of the heap; cache this low key */
    if (SKHEAP_OK != skHeapPeekTop(iter->heap, (skheapnode_t*)&top_heap)) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    lowest = *top_heap;
    memcpy(cached_key, iter->key[lowest], iter->uniq->fi.key_octets);

    /* store the id of each file whose current key matches the
     * cached_key into the active[] array on iter->dist_merge and
     * remove the items from heap as they are added to active[] */
    iter->dist_merge.active[0] = lowest;
    iter->dist_merge.num_active = 1;

    /* avoid a needless pop/push on the heap when only one file
     * remains */
    if (skHeapGetNumberEntries(iter->heap) == 1) {
        if (uniqIterTempDistMergeOne(iter, merged_values)) {
            skHeapEmpty(iter->heap);
            return SK_ITERATOR_NO_MORE_ENTRIES;
        }

        /* replace the key for the record we just processed */
        if (!uniqTempRead(iter->fps[lowest], iter->key[lowest],
                          iter->uniq->fi.key_octets))
        {
            /* read failed and no more data for this file; remove it
             * from the heap */
            uniqDebug(iter->uniq,
                      "Finished reading files #%u, #%u; 0 files remain",
                      UNIQUE_TMPNUM_READ(iter, lowest),
                      UNIQUE_TMPNUM_READ(iter, lowest + 1));
            skHeapExtractTop(iter->heap, NULL);
        }
        goto END;
    }

    skHeapExtractTop(iter->heap, NULL);
    while (skHeapPeekTop(iter->heap, (skheapnode_t*)&top_heap) == SKHEAP_OK
           && 0 == (skFieldListCompareBuffers(
                        cached_key, iter->key[*top_heap],
                        iter->uniq->fi.key_fields)))
    {
        iter->dist_merge.active[iter->dist_merge.num_active++] = *top_heap;
        skHeapExtractTop(iter->heap, NULL);
    }

    if (1 == iter->dist_merge.num_active) {
        /* nothing to merge when the key occurs in one file */
        rv = uniqIterTempDistMergeOne(iter, merged_values);
    } else {
        rv = uniqIterTempDistMergeValuesDist(iter, merged_values);
    }
    if (rv) {
        skHeapEmpty(iter->heap);
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }

    /* for each element in iter->dist_merge.active[], read its next key and
     * insert it into the heap containing the keys */
    for (i = 0; i < iter->dist_merge.num_active; ++i) {
        lowest = iter->dist_merge.active[i];
        if (uniqTempRead(iter->fps[lowest], iter->key[lowest],
                         iter->uniq->fi.key_octets))
        {
            /* read succeeded. insert the new entry into the heap */
            skHeapInsert(iter->heap, &lowest);
            /* keys within a file should always be sorted; duplicate
             * keys may appear if the distinct data structure ran out
             * of memory */
            assert(skFieldListCompareBuffers(cached_key, iter->key[lowest],
                                             iter->uniq->fi.key_fields) <= 0);
        } else {
            /* read failed and no more data for this file */
            uniqDebug(iter->uniq,
                      "Finished reading files #%u, #%u; %d files remain",
                      UNIQUE_TMPNUM_READ(iter, iter->dist_merge.active[i]),
                      UNIQUE_TMPNUM_READ(iter, iter->dist_merge.active[i] + 1),
                      (2 * (skHeapGetNumberEntries(iter->heap)
                            + iter->dist_merge.num_active - i - 1)));
        }
    }

  END:
    /* set user's pointers to the buffers on the iterator, and write
     * the key, values, and distincts into those buffers */
    *key_fields_buffer = iter->returned_buf;
    memcpy(*key_fields_buffer, cached_key, iter->uniq->fi.key_octets);

    *value_fields_buffer = iter->returned_buf + iter->uniq->fi.key_octets;
    memcpy(*value_fields_buffer, merged_values, iter->uniq->fi.value_octets);

    *distinct_fields_buffer = (iter->returned_buf + iter->uniq->fi.key_octets
                               + iter->uniq->fi.value_octets);
    uniqDistinctSetOutputBuf(&iter->uniq->fi, iter->distincts,
                             *distinct_fields_buffer);

    return SK_ITERATOR_OK;
}


/*
 *  uniqIterTempDistDestroy(iter);
 *
 *    Implementation for skUniqueIteratorDestroy().
 */
static void
uniqIterTempDistDestroy(
    sk_unique_iterator_t  **v_iter)
{
    uniqiter_temp_dist_t *iter;
    size_t i;

    if (v_iter && *v_iter) {
        iter = *(uniqiter_temp_dist_t**)v_iter;

        for (i = 0; i < iter->max_fps; ++i) {
            uniqTempClose(iter->fps[i]);
        }
        memset(iter->fps, 0, sizeof(iter->fps));

        for (i = 0; i < iter->dist_merge.max_fps; ++i) {
            uniqTempClose(iter->dist_merge.fps[i]);
        }
        memset(iter->dist_merge.fps, 0, sizeof(iter->dist_merge.fps));

        uniqDistinctFree(&iter->uniq->fi, iter->distincts);
        skHeapFree(iter->dist_merge.heap);
        skHeapFree(iter->heap);

        free(iter);
        *v_iter = NULL;
    }
}


/*
 *  status = uniqIterTempDistCreate(uniq, &iter);
 *
 *    Helper function for skUniqueIteratorCreate().
 */
static int
uniqIterTempDistCreate(
    sk_unique_t            *uniq,
    sk_unique_iterator_t  **new_iter)
{
    uniqiter_temp_dist_t *iter;

    assert(uniq);
    assert(new_iter);

    /* should only be called when distinct fields are present */
    assert(uniq->fi.distinct_num_fields > 0);

    iter = (uniqiter_temp_dist_t*)calloc(1, sizeof(uniqiter_temp_dist_t));
    if (NULL == iter) {
        goto ERROR;
    }

    iter->heap = skHeapCreate2(uniqIterTempDistKeyCmp, MAX_MERGE_FILES,
                               sizeof(uint16_t), NULL, iter);
    if (NULL == iter->heap) {
        goto ERROR;
    }

    iter->uniq = uniq;
    iter->next_fn = uniqIterTempDistNext;
    iter->free_fn = uniqIterTempDistDestroy;

    /* create the heap that operates over the distinct fields */
    iter->dist_merge.heap = skHeapCreate2(uniqDistmergeCmp,
                                          MAX_MERGE_FILES >> 1,
                                          sizeof(uint16_t),
                                          NULL, &iter->dist_merge);
    if (NULL == iter->dist_merge.heap) {
        goto ERROR;
    }
    if (uniqDistinctAllocMerging(&uniq->fi, &iter->distincts)) {
        goto ERROR;
    }

    iter->dist_merge.print_debug = uniq->print_debug;
    iter->dist_merge.write_to_temp = 0;

    /* open all temp files---this also merges temp files if there
     * are not enough file handles to open all temp files */
    if (uniqIterTempDistOpenAll(iter)) {
        goto ERROR;
    }

    if (skHeapGetNumberEntries(iter->heap) == 0) {
        skAppPrintErr("Could not read records from any temporary files");
        goto ERROR;
    }

    iter->dist_merge.write_to_temp = 0;

    uniqDebug(iter->uniq, ("Created tempfile-distinct iterator;"
                           " processing %" PRIu32 " temporary file pairs"),
              skHeapGetNumberEntries(iter->heap));

    *new_iter = (sk_unique_iterator_t*)iter;
    return 0;

  ERROR:
    uniqIterTempDistDestroy((sk_unique_iterator_t**)&iter);
    if (iter) {
        skHeapFree(iter->dist_merge.heap);
        skHeapFree(iter->heap);
        free(iter);
    }
    skAppPrintErr("Error allocating unique iterator");
    return -1;
}


/*
 *  status = uniqIterTempDistKeyCmp(b, a, v_iter);
 *
 *    Comparison callback function used by the heap.
 *
 *    The values in 'b' and 'a' are integer indexes into an array of
 *    keys.  The function calls the field comparison function to
 *    compare the keys and returns the result.
 *
 *    The context value in 'v_iter' is the uniqiter_temp_values_t or
 *    uniqiter_temp_dist_t object that holds the keys and the fields
 *    describing the sort order.
 *
 *    Note the order of arguments is 'b', 'a'.
 */
static int
uniqIterTempDistKeyCmp(
    const skheapnode_t  b,
    const skheapnode_t  a,
    void               *v_iter)
{
    uniqiter_temp_dist_t *iter = (uniqiter_temp_dist_t *)v_iter;

    return skFieldListCompareBuffers(iter->key[*(uint16_t*)a],
                                     iter->key[*(uint16_t*)b],
                                     iter->uniq->fi.key_fields);
}


/*
 *  status = uniqIterTempDistMergeOne(iter, merged_values);
 *
 *    Read the values and distincts from the file in the iter->fps[]
 *    array at position 'fps_index'.
 *
 *    If 'write_to_temp' is non-zero, the value and distinct data is
 *    written to the current temporary file.  If 'write_to_temp' is
 *    zero, the value is stored in 'merged_values' and the distinct
 *    counts are stored on the 'distinct' member of the 'uniq' object.
 *
 *    Return 0 on success, or -1 on read or write error.
 */
static int
uniqIterTempDistMergeOne(
    uniqiter_temp_dist_t   *iter,
    uint8_t                 merged_values[])
{
    distinct_value_t *dist;
    uint8_t buf[4096];
    size_t to_read;
    size_t exp_len;
    uint16_t fps_index;
    uint64_t dist_count;
    uint16_t i;
    int last_errno;

    /* Should only be called when distinct fields are present */
    assert(0 != iter->uniq->fi.distinct_num_fields);

    assert(1 == iter->dist_merge.num_active);
    assert(0 == iter->dist_merge.write_to_temp
           || (iter->uniq->temp_fp && iter->uniq->dist_fp));

    fps_index = iter->dist_merge.active[0];

    if (iter->uniq->fi.value_octets) {
        /* read the value */
        if (!uniqTempRead(iter->fps[fps_index], buf,
                          iter->uniq->fi.value_octets))
        {
            last_errno = skStreamGetLastErrno(iter->fps[fps_index]);
            skAppPrintErr(
                "Cannot read value field from temporary file: %s",
                (last_errno ? strerror(last_errno) : "EOF"));
            return -1;
        }
        if (!iter->dist_merge.write_to_temp) {
            /* store value in the 'merged_values[]' buffer */
            skFieldListInitializeBuffer(
                iter->uniq->fi.value_fields, merged_values);
            skFieldListMergeBuffers(
                iter->uniq->fi.value_fields, merged_values, buf);
        } else {
            uniqTempWrite(iter->uniq->temp_fp, buf,
                          iter->uniq->fi.value_octets);
        }
    }

    /* handle the distinct fields */
    for (i = 0; i < iter->uniq->fi.distinct_num_fields; ++i) {
        dist = &iter->distincts[i];
        /* read the number of distinct values */
        if (!uniqTempRead(iter->fps[fps_index], &dist_count, sizeof(uint64_t)))
        {
            last_errno = skStreamGetLastErrno(iter->fps[fps_index]);
            skAppPrintErr(
                "Cannot read distinct count from temporary file: %s",
                (last_errno ? strerror(last_errno) : "EOF"));
            return -1;
        }

        /* determine the number of bytes to read */
        assert(dist->dv_octets > 0);
        to_read = dist->dv_octets * dist_count;

        if (!iter->dist_merge.write_to_temp) {
            /* no need to read the data, just skip over it by using
             * 'NULL' as the buffer */
            if (!uniqTempRead(iter->dist_merge.fps[fps_index], NULL, to_read)){
                last_errno = (skStreamGetLastErrno(
                                  iter->dist_merge.fps[fps_index]));
                skAppPrintErr(
                    "Cannot read distinct values from temporary file: %s",
                    (last_errno ? strerror(last_errno) : "EOF"));
                return -1;
            }
        } else {
            /* write the number of distinct values */
            uniqTempWrite(iter->uniq->temp_fp, &dist_count, sizeof(uint64_t));

            /* read and write the bytes */
            while (to_read) {
                exp_len = ((to_read < sizeof(buf)) ? to_read : sizeof(buf));
                if (!uniqTempRead(
                        iter->dist_merge.fps[fps_index], buf, exp_len))
                {
                    last_errno
                        = skStreamGetLastErrno(iter->dist_merge.fps[fps_index]);
                    skAppPrintErr(
                        "Cannot read distinct values from temporary file: %s",
                        (last_errno ? strerror(last_errno) : "EOF"));
                    return -1;
                }
                uniqTempWrite(iter->uniq->dist_fp, buf, exp_len);
                to_read -= exp_len;
            }
        }
        dist->dv_count = dist_count;
    }

    return 0;
}


/*
 *    Helper function used when merging files.
 *
 *    Process the set of file ids specified in the 'active' array on
 *    the 'dist_merge' member of the iterator 'iter'.  These files
 *    are known to have the same key, and the read position in each
 *    file is just after the key.
 *
 *    Read and merge the values and distinct fields from the files for
 *    this single key.  Update the 'disticts' value with the count of
 *    items and perhaps write the result to the new temporary file.
 */
static int
uniqIterTempDistMergeValuesDist(
    uniqiter_temp_dist_t   *iter,
    uint8_t                 merged_values[])
{
    uint8_t buf[4096];
    uint16_t fps_index;
    uint16_t i;
    uint16_t j;
    int last_errno;

    /* Should only be called when distinct fields are present */
    assert(0 != iter->uniq->fi.distinct_num_fields);

    assert(iter->dist_merge.num_active > 1);
    assert(0 == iter->dist_merge.write_to_temp
           || (iter->uniq->temp_fp && iter->uniq->dist_fp));
    assert(0 == iter->dist_merge.write_to_temp
           || (iter->uniq->dist_fp == iter->dist_merge.dist_fp));

    if (iter->uniq->fi.value_octets) {
        /* initialize the merged_values buffer.  for each file, read
         * the value and add it to the merged_values buffer. */

        skFieldListInitializeBuffer(iter->uniq->fi.value_fields,merged_values);

        for (j = 0; j < iter->dist_merge.num_active; ++j) {
            fps_index = iter->dist_merge.active[j];
            if (!uniqTempRead(iter->fps[fps_index], buf,
                              iter->uniq->fi.value_octets))
            {
                last_errno = skStreamGetLastErrno(iter->fps[fps_index]);
                uniqDebug(iter->uniq, "Cannot read from temporary file #%u",
                          UNIQUE_TMPNUM_READ(iter, fps_index));
                skAppPrintErr(
                    "Cannot read value field from temporary file: %s",
                    (last_errno ? strerror(last_errno) : "EOF"));
                return -1;
            }
            skFieldListMergeBuffers(
                iter->uniq->fi.value_fields, merged_values, buf);
        }

        if (iter->dist_merge.write_to_temp) {
            /* write the merged value to the temporary file */
            uniqTempWrite(iter->uniq->temp_fp, merged_values,
                          iter->uniq->fi.value_octets);
        }
    }

    /* process each distinct field */
    for (i = 0; i < iter->uniq->fi.distinct_num_fields; ++i) {
        assert(0 == skHeapGetNumberEntries(iter->dist_merge.heap));

        iter->dist_merge.octet_len = iter->distincts[i].dv_octets;

        /* for each file: read the number of distinct entries */
        for (j = 0; j < iter->dist_merge.num_active; ++j) {
            fps_index = iter->dist_merge.active[j];
            if (!uniqTempRead(iter->fps[fps_index],
                              &iter->dist_merge.num_distinct[fps_index],
                              sizeof(uint64_t)))
            {
                last_errno = skStreamGetLastErrno(iter->fps[fps_index]);
                uniqDebug(iter->uniq, "Cannot read from temporary file #%u",
                          UNIQUE_TMPNUM_READ(iter, fps_index));
                skAppPrintErr(
                    "Cannot read distinct count from temporary file: %s",
                    (last_errno ? strerror(last_errno) : "EOF"));
                return -1;
            }
        }

        iter->distincts[i].dv_count = uniqDistmergeMergeOne(&iter->dist_merge);
    }

    if (iter->dist_merge.write_to_temp) {
        /* write the distinct count to the main temporary file */
        for (i = 0; i < iter->uniq->fi.distinct_num_fields; ++i) {
            uniqTempWrite(iter->uniq->temp_fp, &iter->distincts[i].dv_count,
                          sizeof(iter->distincts[i].dv_count));
        }
    }

    return 0;
}


/*
 *  count = uniqIterTempDistOpenAll(iter);
 *
 *    Open all temporary files created while reading records,
 *    put the file handles in the 'fp' member of 'iter', and return
 *    the number of files opened.
 *
 *    If it is impossible to open all files due to a lack of file
 *    handles, the existing temporary files will be merged into new
 *    temporary files, and then another attempt will be made to open
 *    all files.
 *
 *    This function will only return when it is possible to return a
 *    file handle to every existing temporary file.  If it is unable
 *    to create a new temporary file, it returns -1.
 */
static int
uniqIterTempDistOpenAll(
    uniqiter_temp_dist_t   *iter)
{
#ifndef NDEBUG
    uint8_t cached_key[HASHLIB_MAX_KEY_WIDTH];
#endif
    uint16_t i;
    int j;
    int tmp_idx_a;
    int tmp_idx_b;
    int last_errno;
    uint16_t *top_heap;
    uint16_t lowest;
    uint8_t merged_values[HASHLIB_MAX_VALUE_WIDTH];
    ssize_t rv;

    /* recall that uniq->temp_idx is the intermediate temp file; which
     * is open but unused when this function is called.  for this
     * function to be called, temp files #0 and #1 must be in use */
    assert(iter->uniq->temp_idx >= 2);
    assert(iter->uniq->temp_fp);

    /* should only be called when distinct fields are present */
    assert(iter->uniq->fi.distinct_num_fields > 0);
    assert(iter->uniq->temp_fp && iter->uniq->dist_fp);

    /* index at which to start the merge */
    tmp_idx_a = 0;

    /* This loop repeats as long as we haven't opened all of the temp
     * files generated while reading the flows. */
    for (;;) {
        assert(skHeapGetNumberEntries(iter->heap) == 0);

        iter->dist_merge.dist_fp = iter->uniq->dist_fp;

        /* the index of the first temporary file being processed */
        iter->temp_idx_base = tmp_idx_a;

        /* determine the index at which to stop the merge */
        tmp_idx_b = tmp_idx_a + MAX_MERGE_FILES - 1;
        if (iter->uniq->temp_idx <= tmp_idx_b) {
            /* fewer than MAX_MERGE_FILES files */
            tmp_idx_b = iter->uniq->temp_idx - 1;
        }
        assert((tmp_idx_a & 0x1) == 0);
        assert((tmp_idx_b & 0x1) == 1);

        uniqDebug(iter->uniq,
                  "Attempting to open temporary files #%d through #%d",
                  tmp_idx_a, tmp_idx_b);

        /* Open up to MAX_MERGE files; the files are opened in pairs
         * where the second file of the pair contains the distinct
         * counts */
        for (j = tmp_idx_a, i = 0; j <= tmp_idx_b; j += 2, ++i) {
            iter->fps[i] = uniqTempReopen(iter->uniq->tmpctx, j);
            if (NULL == iter->fps[i]) {
                if (skHeapGetNumberEntries(iter->heap) < 2) {
                    skAppPrintErr("Unable to open multiple temporary files");
                    return -1;
                }
                /* We cannot open any more temp files; we'll need to
                 * catch file 'j' the next time around. */
                tmp_idx_b = j - 1;
                uniqDebug(iter->uniq,
                          ("File limit hit [%s]---merging"
                           " #%d through #%d into #%d, #%d..."),
                          strerror(errno), tmp_idx_a, tmp_idx_b,
                          iter->uniq->temp_idx, iter->uniq->max_temp_idx);
                break;
            }

            /* Read the first key from the file */
            if (!uniqTempRead(iter->fps[i], iter->key[i],
                              iter->uniq->fi.key_octets))
            {
                last_errno = skStreamGetLastErrno(iter->fps[i]);
                if (0 != last_errno) {
                    skAppPrintErr(
                        "Cannot read first key from temporary file '%s': %s",
                        skTempFileGetName(iter->uniq->tmpctx, j),
                        strerror(last_errno));
                    return -1;
                }
                uniqDebug(iter->uniq,
                          "Ignoring empty temporary file #%u '%s'",
                          j, skTempFileGetName(iter->uniq->tmpctx, j));
                uniqTempClose(iter->fps[i]);
                iter->fps[i] = NULL;
                continue;
            }

            /* open the corresponding distinct file */
            iter->dist_merge.fps[i] = uniqTempReopen(iter->uniq->tmpctx, j+ 1);
            if (NULL == iter->dist_merge.fps[i]) {
                if (skHeapGetNumberEntries(iter->heap) < 2) {
                    skAppPrintErr("Unable to open multiple temporary files");
                    return -1;
                }
                tmp_idx_b = j - 1;
                uniqDebug(iter->uniq,
                          ("File limit hit [%s]---merging"
                           " #%d through #%d into #%d, #%d..."),
                          strerror(errno), tmp_idx_a, tmp_idx_b,
                          iter->uniq->temp_idx, iter->uniq->max_temp_idx);
                uniqTempClose(iter->fps[i]);
                iter->fps[i] = NULL;
                break;
            }

            skHeapInsert(iter->heap, &i);
        }

        uniqDebug(iter->uniq, "Opened %" PRIu32 " temporary file pairs",
                  skHeapGetNumberEntries(iter->heap));

        /* Check to see if we've opened all temp files.  If so,
         * return */
        if (tmp_idx_b == iter->uniq->temp_idx - 1) {
            uniqDebug(iter->uniq,
                      "Successfully opened all%s temporary files",
                      ((tmp_idx_a > 0) ? " remaining" : ""));
            iter->dist_merge.max_fps = iter->max_fps = i;
            return 0;
        }
        /* Else, we could not open all temp files, so merge all opened
         * temp files into the intermediate file */

        iter->dist_merge.write_to_temp = 1;

        /* exit this while() loop once all data for all opened files
         * have been read or until there is only one file remaining */
        while (skHeapGetNumberEntries(iter->heap) > 1) {
            /* get the index of the file with the lowest key */
            skHeapExtractTop(iter->heap, (skheapnode_t)&lowest);

            /* write the key to the temp file */
            uniqTempWrite(iter->uniq->temp_fp, iter->key[lowest],
                          iter->uniq->fi.key_octets);
#ifndef NDEBUG
            /* cache the key */
            memcpy(cached_key, iter->key[lowest], iter->uniq->fi.key_octets);
#endif

            /* pop items from the heap that match the lowest key and
             * store the ids in the active[] array */
            iter->dist_merge.active[0] = lowest;
            iter->dist_merge.num_active = 1;
            while (skHeapPeekTop(iter->heap, (skheapnode_t*)&top_heap)
                   == SKHEAP_OK
                   && (skFieldListCompareBuffers(
                           iter->key[lowest], iter->key[*top_heap],
                           iter->uniq->fi.key_fields) == 0))
            {
                iter->dist_merge.active[iter->dist_merge.num_active++]
                    = *top_heap;
                skHeapExtractTop(iter->heap, NULL);
            }

            if (1 == iter->dist_merge.num_active) {
                /* if the lowest key only appears in one file, there
                 * no need to merge, just copy the bytes from source
                 * to the dest */
                rv = uniqIterTempDistMergeOne(iter, merged_values);
            } else {
                rv = uniqIterTempDistMergeValuesDist(iter, merged_values);
            }
            if (rv) {
                return -1;
            }

            /* for each element in dist_merge.active[], read its next
             * key and insert it into the heap */
            for (i = 0; i < iter->dist_merge.num_active; ++i) {
                if (uniqTempRead(iter->fps[iter->dist_merge.active[i]],
                                 iter->key[iter->dist_merge.active[i]],
                                 iter->uniq->fi.key_octets))
                {
                    /* read succeeded. insert the new entry into the
                     * heap. */
                    skHeapInsert(iter->heap, &iter->dist_merge.active[i]);
                    /* keys within a file should always be sorted;
                     * duplicate keys may appear if the distinct data
                     * structure ran out of memory */
                    assert(skFieldListCompareBuffers(
                               cached_key, iter->key[lowest],
                               iter->uniq->fi.key_fields) <= 0);
                } else {
                    uniqDebug(
                        iter->uniq,
                        "Finished reading files #%u, #%u; %d files remain",
                        UNIQUE_TMPNUM_READ(iter, iter->dist_merge.active[i]),
                        UNIQUE_TMPNUM_READ(iter, iter->dist_merge.active[i]+1),
                        (2 * (skHeapGetNumberEntries(iter->heap)
                              + iter->dist_merge.num_active - i - 1)));
                }
            }
        }

        /* handle the final file */
        if (skHeapExtractTop(iter->heap, (skheapnode_t)&lowest) == SKHEAP_OK) {
            assert(skHeapGetNumberEntries(iter->heap) == 0);

            iter->dist_merge.active[0] = lowest;
            iter->dist_merge.num_active = 1;
            do {
                /* write the key to the output file */
                uniqTempWrite(iter->uniq->temp_fp, iter->key[lowest],
                              iter->uniq->fi.key_octets);
                /* handle the values and distincts */
                if (uniqIterTempDistMergeOne(iter, merged_values)) {
                    return -1;
                }
                /* read the next key */
            } while (uniqTempRead(iter->fps[lowest], iter->key[lowest],
                                  iter->uniq->fi.key_octets));
            /* read failed and no more data for this file */
            uniqDebug(iter->uniq,
                      "Finished reading files #%u, #%u; 0 files remain",
                      UNIQUE_TMPNUM_READ(iter, lowest),
                      UNIQUE_TMPNUM_READ(iter, lowest + 1));
        }
        assert(skHeapGetNumberEntries(iter->heap) == 0);

        /* Close and remove all the temp files that we processed this
         * time. */
        for (j = tmp_idx_a, i = 0; j <= tmp_idx_b; j += 2, ++i) {
            uniqTempClose(iter->fps[i]);
            uniqTempClose(iter->dist_merge.fps[i]);
            skTempFileRemove(iter->uniq->tmpctx, j);
            skTempFileRemove(iter->uniq->tmpctx, j + 1);
        }
        memset(iter->fps, 0, sizeof(iter->fps));
        memset(iter->dist_merge.fps, 0, sizeof(iter->dist_merge.fps));

        /* Close the intermediate temp file and open a new one. */
        uniqDebug(iter->uniq, "Finished writing #%d '%s', #%d '%s'",
                  iter->uniq->temp_idx, UNIQUE_TMPNAME_OUT(iter->uniq),
                  iter->uniq->max_temp_idx,
                  uniqBasename(skTempFileGetName(iter->uniq->tmpctx,
                                                 iter->uniq->max_temp_idx)));
        uniqTempClose(iter->uniq->temp_fp);
        iter->uniq->temp_fp = uniqTempCreate(iter->uniq->tmpctx,
                                             &iter->uniq->max_temp_idx);
        iter->uniq->temp_idx = iter->uniq->max_temp_idx;

        /* Close and open the temp file for distinct counts */
        uniqTempClose(iter->uniq->dist_fp);
        iter->uniq->dist_fp = uniqTempCreate(iter->uniq->tmpctx,
                                             &iter->uniq->max_temp_idx);

        /* Start the next merge with the next input temp file */
        tmp_idx_a = tmp_idx_b + 1;
    }

    return -1;    /* NOTREACHED */
}



/****************************************************************
 * Public Interface for Iterating over the bins
 ***************************************************************/

/*  create iterator to get bins from the unique object; calls one of
 *  the helper functions above */
int
skUniqueIteratorCreate(
    sk_unique_t            *uniq,
    sk_unique_iterator_t  **new_iter)
{
    uniqDebug(uniq, "Initializing iterator");

    if (!uniq->ready_for_output) {
        skAppPrintErr("May not call skUniqueIteratorCreate"
                      " before calling skUniquePrepareForOutput");
        return -1;
    }
    if (uniq->temp_idx > 0) {
        if (uniq->fi.distinct_num_fields) {
            return uniqIterTempDistCreate(uniq, new_iter);
        }
        return uniqIterTempValuesCreate(uniq, new_iter);
    }

    if (uniq->fi.distinct_num_fields) {
        return uniqIterDistinctCreate(uniq, new_iter);
    }

    return uniqIterSimpleCreate(uniq, new_iter);
}


#if 0
/*
 *    Destroy the interator.
 *
 *    Implemented as a macro in skunique.h that invokes the function
 *    pointer specified in the free_fn member of 'iter'.
 */
void
skUniqueIteratorDestroy(
    sk_unique_iterator_t  **iter);

/*
 *    Get the next set of values for the keys, values, and distinct
 *    counts.
 *
 *    Implemented as a macro in skunique.h that invokes the function
 *    pointer specified in the next_fn member of 'iter'.
 */
int
skUniqueIteratorNext(
    sk_unique_iterator_t   *iter,
    uint8_t               **key_fields_buffer,
    uint8_t               **distinct_fields_buffer,
    uint8_t               **agg_value_fields_buffer);

/*
 *    Reset the iterator so it can be used again.
 *
 *    Implemented as a macro in skunique.h that invokes the function
 *    pointer specified in the rest_fn member of 'iter'.
 */
int
skUniqueIteratorReset(
    sk_unique_iterator_t   *iter);
#endif  /* 0 */



/* **************************************************************** */

/*    SKUNIQUE USER API FOR HANDLING FILES OF PRESORTED INPUT */

/* **************************************************************** */

/* structure for binning records */
/* typedef struct sk_sort_unique_st sk_sort_unique_t; */
struct sk_sort_unique_st {
    sk_uniq_field_info_t    fi;

    int                   (*post_open_fn)(skstream_t *);
    int                   (*read_rec_fn)(skstream_t *, rwRec *);

    /* vector containing the names of files to process */
    sk_vector_t            *files;

    /* where to write temporary files */
    char                   *temp_dir;

    /* the skstream_t that are being read; there are SiLK Flow files
     * for the initial pass; if temporary files are created, this
     * array holds the temporary files during the file-merging */
    skstream_t             *fps[MAX_MERGE_FILES];

    /* array of records, one for each open file */
    rwRec                  *rec;

    /* memory to hold the key for each open file; this is allocated as
     * one large block; the 'key' member points into this buffer. */
    uint8_t                *key_data;

    /* array of keys, one for each open file, holds pointers into
     * 'key_data' */
    uint8_t               **key;

    /* maintains sorted keys */
    skheap_t               *heap;

    /* array holding information required to count distinct fields */
    distinct_value_t       *distincts;

    /* the temp file context */
    sk_tempfilectx_t       *tmpctx;

    /* pointer to the current intermediate temp file; its index is
     * given by the 'temp_idx' member */
    skstream_t             *temp_fp;

    /* when distinct fields are being computed, temporary files always
     * appear in pairs, and this is the pointer to an intermediate
     * temp file used to hold distinct values; its index is given by
     * the 'max_temp_idx' member */
    skstream_t             *dist_fp;

    /* when computing the number of distinct values for one field
     * across all bins */
    total_distinct_t        total_dist;

    /* index of the intermediate temp file member 'temp_fp'. if temp
     * files have been written, its value is one more than the temp
     * file most recently written. */
    int                     temp_idx;

    /* index of highest used temporary file; this is the same as
     * 'temp_idx' when distinct files are not in use; when distinct
     * files are in use, this is one more than 'temp_idx' and the
     * index of 'dist_fp'. */
    int                     max_temp_idx;

    /* when merging temporary files, the index of the first temporary
     * file that is being merged */
    int                     temp_idx_base;

    /* current position in the 'files' vector */
    int                     files_position;

    /* flag to detect recursive calls to skPresortedUniqueProcess() */
    unsigned                processing : 1;

    /* whether to print debugging information */
    unsigned                print_debug:1;

    /* whether the total_dist object is to be used */
    unsigned                use_total_distinct:1;
};


#if TRACEMSG_LEVEL == 0

/*
 *    Function that is used to output log messages enabled by the
 *    SILK_UNIQUE_DEBUG environment variable.
 *
 *    If SKUNIQUE_TRACE_LEVEL or TRACEMSG_LEVEL is non-zero, a
 *    different definition of this funciton is used, which is defined
 *    below.
 */
static void
sortuniqDebug(
    const sk_sort_unique_t *uniq,
    const char             *fmt,
    ...)
    SK_CHECK_PRINTF(2, 3);

static void
sortuniqDebug(
    const sk_sort_unique_t *uniq,
    const char             *fmt,
    ...)
{
    va_list args;

    va_start(args, fmt);
    if (uniq && uniq->print_debug) {
        fprintf(stderr, "%s: " SKUNIQUE_DEBUG_ENVAR ": ", skAppName());
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    }
    va_end(args);
}

#else  /* TRACEMSG_LEVEL > 0 */

/*
 *    When SKUNIQUE_TRACE_LEVEL or TRACEMSG_LEVEL is non-zero, the
 *    code behaves as though SILK_UNIQUE_DEBUG is enabled and this
 *    function is used to to trace the code.
 */
#define sortuniqDebug(...)  sortuniqDebugHelper(__LINE__, __VA_ARGS__)

static void
sortuniqDebugHelper(
    int                     lineno,
    const sk_sort_unique_t *uniq,
    const char             *fmt,
    ...)
    SK_CHECK_PRINTF(3, 4);

static void
sortuniqDebugHelper(
    int                     lineno,
    const sk_sort_unique_t *uniq,
    const char             *fmt,
    ...)
{
    va_list args;

    SK_UNUSED_PARAM(uniq);

    va_start(args, fmt);
    fprintf(stderr, __FILE__ ":%d: ", lineno);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}
#endif  /* #else of TRACEMSG_LEVEL == 0 */


/*
 *  status = sortuniqOpenNextInput(uniq, &stream);
 *
 *    Get the name of the next SiLK Flow record file to open, and set
 *    'stream' to that stream.
 *
 *    Return 0 on success.  Return 1 if no more files to open.  Return
 *    -2 if the file cannot be opened due to lack of memory or file
 *    handles.  Return -1 on other error.
 */
static int
sortuniqOpenNextInput(
    sk_sort_unique_t   *uniq,
    skstream_t        **out_stream)
{
    skstream_t *stream = NULL;
    const char *filename;
    int rv;

    do {
        rv = skVectorGetValue(&filename, uniq->files,
                              uniq->files_position);
        if (rv != 0) {
            /* no more files */
            return 1;
        }
        ++uniq->files_position;

        errno = 0;
        rv = skStreamOpenSilkFlow(&stream, filename, SK_IO_READ);
        if (rv) {
            if (errno == EMFILE || errno == ENOMEM) {
                rv = -2;
                /* decrement counter to try this file next time */
                --uniq->files_position;
                sortuniqDebug(uniq, "Unable to open '%s': %s",
                              filename, strerror(errno));
            } else {
                skStreamPrintLastErr(stream, rv, skAppPrintErr);
                rv = -1;
            }
            skStreamDestroy(&stream);
            return rv;
        }

        /* call the user's PostOpenFn if they provided one. */
        if (uniq->post_open_fn) {
            rv = uniq->post_open_fn(stream);
            if (rv == 1 || rv == -1) {
                sortuniqDebug(uniq, "Caller's post_open_fn returned %d", rv);
                skStreamDestroy(&stream);
                return rv;
            }
            if (rv != 0) {
                sortuniqDebug(uniq, "Caller's post_open_fn returned %d", rv);
                skStreamDestroy(&stream);
            }
        }
    } while (0 != rv);

    *out_stream = stream;
    return 0;
}


/*
 *  ok = sortuniqFillRecordAndKey(uniq, idx);
 *
 *    Read a record from a stream and compute the key for that record.
 *    The stream to read and the destinations for the record and key
 *    are determined by the index 'idx'.
 *
 *    Return 1 if a record was read; 0 otherwise.
 */
static int
sortuniqFillRecordAndKey(
    sk_sort_unique_t   *uniq,
    uint16_t            idx)
{
    int rv;

    rv = uniq->read_rec_fn(uniq->fps[idx], &uniq->rec[idx]);
    if (rv) {
        if (rv != SKSTREAM_ERR_EOF) {
            skStreamPrintLastErr(uniq->fps[idx], rv, skAppPrintErr);
        }
        return 0;
    }

    skFieldListRecToBinary(uniq->fi.key_fields, &uniq->rec[idx],
                           uniq->key[idx]);

    if (uniqTotalDistinctIncrement(&uniq->total_dist, &uniq->rec[idx])) {
        return 0;
    }

    return 1;
}


/*
 *  status = sortuniqHeapKeysCmp(b, a, v_uniq);
 *
 *    Comparison callback function used by the heap when processing
 *    presorted-data.
 *
 *    The values in 'b' and 'a' are integer indexes into an array of
 *    keys.  The function calls the field comparison function to
 *    compare the keys and returns the result.
 *
 *    The context value in 'v_uniq' is the sk_sort_unique_t object
 *    that holds the keys and the fields describing the sort order.
 *
 *    Note the order of arguments is 'b', 'a'.
 */
static int
sortuniqHeapKeysCmp(
    const skheapnode_t  b,
    const skheapnode_t  a,
    void               *v_uniq)
{
    sk_sort_unique_t *uniq = (sk_sort_unique_t*)v_uniq;

    return skFieldListCompareBuffers(uniq->key[*(uint16_t*)a],
                                     uniq->key[*(uint16_t*)b],
                                     uniq->fi.key_fields);
}


/*
 *    Helper function for skPresortedUniqueProcess() that process SiLK
 *    Flow input files files when distinct counts are not being
 *    computed.
 *
 *    Use the open SiLK streams in the fps[] array on the 'uniq'
 *    object and merge the values when the keys are identical.
 *
 *    If the 'output_fn' is not-NULL, send the key and merged values
 *    to that function.  When the 'output_fn' is NULL, the merged
 *    values are written to a temporary file.
 *
 *    This function returns once all the data in the open files has
 *    been read.
 */
static int
sortuniqReadSilkNodist(
    sk_sort_unique_t       *uniq,
    sk_unique_output_fn_t   output_fn,
    void                   *callback_data)
{
    uint16_t *top_heap;
    uint16_t lowest;
    uint8_t cached_key[HASHLIB_MAX_KEY_WIDTH];
    uint8_t distinct_buffer[HASHLIB_MAX_KEY_WIDTH];
    uint8_t merged_values[HASHLIB_MAX_VALUE_WIDTH];
    uint32_t heap_count;
    int rv;

    /* should only be called with value fields and no distinct fields */
    assert(0 == uniq->fi.distinct_num_fields);
    assert(0 < uniq->fi.value_octets);

    heap_count = skHeapGetNumberEntries(uniq->heap);
    if (0 == heap_count) {
        return 0;
    }

    /* get the index of the file with the lowest key; which is at
     * the top of the heap */
    skHeapPeekTop(uniq->heap, (skheapnode_t*)&top_heap);
    lowest = *top_heap;

    /* exit this do...while() once all records for all opened SiLK
     * input files have been read */
    do {
        /* cache this low key and initialze values and distincts */
        memcpy(cached_key, uniq->key[lowest], uniq->fi.key_octets);
        skFieldListInitializeBuffer(uniq->fi.value_fields, merged_values);

        /* loop over all files until we get a key that does not
         * match the cached_key */
        do {
            /* add the values and distincts */
            skFieldListAddRecToBuffer(
                uniq->fi.value_fields, &uniq->rec[lowest], merged_values);

            /* replace the record we just processed */
            if (sortuniqFillRecordAndKey(uniq, lowest)) {
                /* read succeeded. insert it into the heap */
                skHeapReplaceTop(uniq->heap, &lowest, NULL);
            } else {
                /* read failed and no more data for this file; remove
                 * the file's index from the heap; exit the loop if
                 * the heap is empty */
                --heap_count;
                sortuniqDebug(uniq,
                              ("Finished reading records from file #%u,"
                               " %u files remain"),
                              lowest, heap_count);
                skHeapExtractTop(uniq->heap, NULL);
                assert(skHeapGetNumberEntries(uniq->heap) == heap_count);
                if (0 == heap_count) {
                    break;
                }
            }

            /* get the new value at the top of the heap and see if it
             * matches the cached_key */
            skHeapPeekTop(uniq->heap, (skheapnode_t*)&top_heap);
            lowest = *top_heap;
        } while (skFieldListCompareBuffers(
                     cached_key, uniq->key[lowest], uniq->fi.key_fields)
                 == 0);

        /* output this key and its values. */
        if (output_fn) {
            rv = output_fn(cached_key, distinct_buffer, merged_values,
                           callback_data);
            if (rv != 0) {
                sortuniqDebug(uniq, "output_fn returned non-zero %d", rv);
                return -1;
            }
        } else {
            uniqTempWriteTriple(&uniq->fi, uniq->temp_fp, NULL,
                                cached_key, merged_values, uniq->distincts);
        }
    } while (heap_count > 0);

    return 0;
}


/*
 *    Helper function for skPresortedUniqueProcess() that process SiLK
 *    Flow input files files when distinct counts are being computed.
 *
 *    Use the open SiLK streams in the fps[] array on the 'uniq'
 *    object and merge the values and distinct counts when the keys
 *    are identical.
 *
 *    The merged values and distinct counts are written to temporary
 *    files.
 *
 *    This function returns once all the data in the open files has
 *    been read.
 */
static int
sortuniqReadSilkDist(
    sk_sort_unique_t       *uniq)
{
    uint16_t *top_heap;
    uint16_t lowest;
    uint8_t cached_key[HASHLIB_MAX_KEY_WIDTH];
    uint8_t distinct_buffer[HASHLIB_MAX_KEY_WIDTH];
    uint8_t merged_values[HASHLIB_MAX_VALUE_WIDTH];
    uint32_t heap_count;

    /* Should only be called when distinct fields are present */
    assert(0 != uniq->fi.distinct_num_fields);
    assert(uniq->temp_fp && uniq->dist_fp);

    heap_count = skHeapGetNumberEntries(uniq->heap);
    if (0 == heap_count) {
        /* probably should be an error */
        return 0;
    }

    /* get the index of the file with the lowest key; which is at
     * the top of the heap */
    skHeapPeekTop(uniq->heap, (skheapnode_t*)&top_heap);
    lowest = *top_heap;

    /* exit this do...while() once all records for all opened files
     * have been read */
    do {
        /* cache this low key */
        memcpy(cached_key, uniq->key[lowest], uniq->fi.key_octets);

        /* reset the values and distincts */
        skFieldListInitializeBuffer(uniq->fi.value_fields, merged_values);
        if (uniqDistinctReset(&uniq->fi, uniq->distincts)) {
            skAppPrintOutOfMemory("table for distinct values");
            return -1;
        }

        /* loop over all SiLK input files until we get a key that does
         * not match the cached_key */
        do {
            /* add the distinct value to the data structure */
            skFieldListRecToBinary(
                uniq->fi.distinct_fields, &uniq->rec[lowest], distinct_buffer);
            if (uniqDistinctIncrement(
                    &uniq->fi, uniq->distincts, distinct_buffer))
            {
                /* increment of the distinct values failed; write the
                 * current values to disk */
                sortuniqDebug(uniq, ("Writing 1 key/value/distinct triple"
                                     " to #%d, #%d..."),
                              uniq->temp_idx, uniq->max_temp_idx);
                uniqTempWriteTriple(
                    &uniq->fi, uniq->temp_fp, uniq->dist_fp,
                    cached_key, merged_values, uniq->distincts);

                /* close and create new temporary files.  the merging
                 * code assumes keys are not duplicated within a
                 * single temporary file */
                sortuniqDebug(uniq, "Finished writing #%d '%s', #%d '%s'",
                              uniq->temp_idx, UNIQUE_TMPNAME_OUT(uniq),
                              uniq->max_temp_idx,
                              uniqBasename(skStreamGetPathname(uniq->dist_fp)));

                uniqTempClose(uniq->temp_fp);
                uniq->temp_fp = uniqTempCreate(uniq->tmpctx,
                                               &uniq->max_temp_idx);
                uniq->temp_idx = uniq->max_temp_idx;

                uniqTempClose(uniq->dist_fp);
                uniq->dist_fp = uniqTempCreate(uniq->tmpctx,
                                               &uniq->max_temp_idx);

                /* reset the values and distincts */
                skFieldListInitializeBuffer(
                    uniq->fi.value_fields, merged_values);
                if (uniqDistinctReset(&uniq->fi, uniq->distincts)) {
                    skAppPrintOutOfMemory("table for distinct values");
                    return -1;
                }
            }

            /* add the value */
            skFieldListAddRecToBuffer(
                uniq->fi.value_fields, &uniq->rec[lowest], merged_values);

            /* replace the record we just processed */
            if (sortuniqFillRecordAndKey(uniq, lowest)) {
                /* read succeeded. insert it into the heap */
                skHeapReplaceTop(uniq->heap, &lowest, NULL);
            } else {
                /* read failed and no more data for this file;
                 * remove it from the heap */
                --heap_count;
                sortuniqDebug(uniq,
                              ("Finished reading records from file #%u,"
                               " %" PRIu32 " files remain"),
                              lowest, heap_count);
                skHeapExtractTop(uniq->heap, NULL);
                assert(skHeapGetNumberEntries(uniq->heap) == heap_count);
                if (0 == heap_count) {
                    break;
                }
            }

            /* get the new index at top of heap and see if the file's
             * key matches the cached_key */
            skHeapPeekTop(uniq->heap, (skheapnode_t*)&top_heap);
            lowest = *top_heap;
        } while (skFieldListCompareBuffers(
                     cached_key, uniq->key[lowest], uniq->fi.key_fields)
                 == 0);

        /* write the current values to the disk. */
        uniqTempWriteTriple(&uniq->fi, uniq->temp_fp, uniq->dist_fp,
                            cached_key, merged_values, uniq->distincts);
    } while (heap_count > 0);

    return 0;
}


/*
 *    Helper function for sortuniqMergeFilesDist() to get a value and
 *    distinct counts from a single file for a single unique key.
 *
 *    The key being merged is specified in 'cached_key'.
 *
 *    The index of the file to be read is specified in 'fps_index'.
 *    This is an index into the uniq->fps[] array.
 *
 *    If the 'output_fn' is not-NULL, send the key, merged values, and
 *    distinct counts to that function.  When the 'output_fn' is NULL,
 *    the merged values are written to another temporary file.
 *
 *    This function returns once entries for the 'cached_key' have
 *    been processed.
 *
 *    See also sortuniqMergeValuesDist().
 */
static int
sortuniqMergeSingleFile(
    sk_sort_unique_t       *uniq,
    const uint8_t           cached_key[],
    distinct_merge_t       *dist_merge,
    sk_unique_output_fn_t   output_fn,
    void                   *callback_data)
{
    distinct_value_t *dist;
    uint8_t distinct_buffer[HASHLIB_MAX_KEY_WIDTH];
    uint8_t merged_values[HASHLIB_MAX_VALUE_WIDTH];
    uint16_t fps_index;
    uint8_t buf[4096];
    size_t to_read;
    size_t exp_len;
    uint64_t dist_count;
    int last_errno;
    uint16_t i;
    ssize_t rv;

    /* Should only be called when distinct fields are present */
    assert(0 != uniq->fi.distinct_num_fields);
    assert(output_fn || (uniq->temp_fp && uniq->dist_fp));
    assert((1 == dist_merge->write_to_temp && (uniq->temp_fp && uniq->dist_fp))
           || (0 == dist_merge->write_to_temp && output_fn));
    assert(1 == dist_merge->num_active);

    fps_index = dist_merge->active[0];

    /* handle the values field */
    if (uniq->fi.value_octets) {
        if (!uniqTempRead(uniq->fps[fps_index], buf, uniq->fi.value_octets)) {
            last_errno = skStreamGetLastErrno(uniq->fps[fps_index]);
            skAppPrintErr("Cannot read value field from temporary file: %s",
                          (last_errno ? strerror(last_errno) : "EOF"));
            return -1;
        }
        if (output_fn) {
            skFieldListInitializeBuffer(uniq->fi.value_fields, merged_values);
            skFieldListMergeBuffers(uniq->fi.value_fields, merged_values, buf);
        } else {
            uniqTempWrite(uniq->temp_fp, buf, uniq->fi.value_octets);
        }
    }

    /* handle the distinct fields */
    for (i = 0; i < uniq->fi.distinct_num_fields; ++i) {
        dist = &uniq->distincts[i];
        /* read the number of distinct values */
        if (!uniqTempRead(uniq->fps[fps_index], &dist_count, sizeof(uint64_t)))
        {
            last_errno = skStreamGetLastErrno(uniq->fps[fps_index]);
            skAppPrintErr("Cannot read distinct count from temporary file: %s",
                          (last_errno ? strerror(last_errno) : "EOF"));
            return -1;
        }

        /* determine the number of bytes to read */
        assert(dist->dv_octets > 0);
        to_read = dist->dv_octets * dist_count;

        if (output_fn) {
            dist->dv_count = dist_count;

            /* no need to read the data, just skip over it by using
             * 'NULL' as the buffer */
            if (!uniqTempRead(dist_merge->fps[fps_index], NULL, to_read)) {
                last_errno = skStreamGetLastErrno(dist_merge->fps[fps_index]);
                skAppPrintErr(
                    "Cannot read distinct values from temporary file: %s",
                    (last_errno ? strerror(last_errno) : "EOF"));
                return -1;
            }
        } else {
            /* write the number of distinct values */
            uniqTempWrite(uniq->temp_fp, &dist_count, sizeof(uint64_t));

            /* read and write the bytes */
            while (to_read) {
                exp_len = ((to_read < sizeof(buf)) ? to_read : sizeof(buf));
                if (!uniqTempRead(dist_merge->fps[fps_index], buf, exp_len)) {
                    last_errno
                        = skStreamGetLastErrno(dist_merge->fps[fps_index]);
                    skAppPrintErr(
                        "Cannot read distinct values from temporary file: %s",
                        (last_errno ? strerror(last_errno) : "EOF"));
                    return -1;
                }
                uniqTempWrite(uniq->dist_fp, buf, exp_len);
                to_read -= exp_len;
            }
        }
    }

    if (output_fn) {
        uniqDistinctSetOutputBuf(&uniq->fi, uniq->distincts, distinct_buffer);
        rv = output_fn(cached_key, distinct_buffer, merged_values,
                       callback_data);
        if (rv != 0) {
            sortuniqDebug(uniq, "output_fn returned non-zero %" SK_PRIdZ, rv);
            return -1;
        }
    }

    return 0;
}


/*
 *    Helper function for sortuniqMergeFilesDist() to merge values and
 *    distinct counts from multiple input files for a single unique
 *    key.
 *
 *    The key being merged is specified in 'cached_key'.
 *
 *    The index of the files to be merged are specified in 'file_ids',
 *    an array of length 'file_ids_len'.  These values are indexes
 *    into the uniq->fps[] array.
 *
 *    If the 'output_fn' is not-NULL, send the key, merged values, and
 *    distinct counts to that function.  When the 'output_fn' is NULL,
 *    the merged values are written to another temporary file.
 *
 *    This function returns once entries for the 'cached_key' have
 *    been processed.
 *
 *    See also sortuniqMergeSingleFile().
 */
static int
sortuniqMergeValuesDist(
    sk_sort_unique_t       *uniq,
    const uint8_t           cached_key[],
    distinct_merge_t       *dist_merge,
    sk_unique_output_fn_t   output_fn,
    void                   *callback_data)
{
    uint8_t buf[4096];
    uint8_t distinct_buffer[HASHLIB_MAX_KEY_WIDTH];
    uint8_t merged_values[HASHLIB_MAX_VALUE_WIDTH];
    uint16_t fps_index;
    uint16_t i;
    uint16_t j;
    int last_errno;
    int rv;

    /* Should only be called when distinct fields are present */
    assert(0 != uniq->fi.distinct_num_fields);
    assert(output_fn || (uniq->temp_fp && uniq->dist_fp));
    assert((1 == dist_merge->write_to_temp && (uniq->temp_fp && uniq->dist_fp))
           || (0 == dist_merge->write_to_temp && output_fn));

    if (uniq->fi.value_octets) {
        /* initialize the merged_values buffer.  for each file, read
         * the value and add it to the merged_values buffer. */

        /* initialize the merge_values buffer */
        skFieldListInitializeBuffer(uniq->fi.value_fields, merged_values);

        /* read and merge all values */
        for (j = 0; j < dist_merge->num_active; ++j) {
            fps_index = dist_merge->active[j];
            if (!uniqTempRead(uniq->fps[fps_index], buf, uniq->fi.value_octets))
            {
                last_errno = skStreamGetLastErrno(uniq->fps[fps_index]);
                sortuniqDebug(uniq, "Cannot read from temporary file #%u",
                              UNIQUE_TMPNUM_READ(uniq, fps_index));
                skAppPrintErr(
                    "Cannot read values field from temporary file: %s",
                    (last_errno ? strerror(last_errno) : "EOF"));
                return -1;
            }
            skFieldListMergeBuffers(
                uniq->fi.value_fields, merged_values, buf);
        }

        if (!output_fn) {
            /* write the merged value to the temporary file */
            uniqTempWrite(uniq->temp_fp, merged_values, uniq->fi.value_octets);
        }
    }

    /* process each distinct field */
    for (i = 0; i < uniq->fi.distinct_num_fields; ++i) {
        dist_merge->octet_len = uniq->distincts[i].dv_octets;

        /* for each file: read the number of distinct entries */
        for (j = 0; j < dist_merge->num_active; ++j) {
            fps_index = dist_merge->active[j];
            if (!uniqTempRead(uniq->fps[fps_index],
                              &dist_merge->num_distinct[fps_index],
                              sizeof(uint64_t)))
            {
                last_errno = skStreamGetLastErrno(uniq->fps[fps_index]);
                sortuniqDebug(uniq, "Cannot read from temporary file #%u",
                              UNIQUE_TMPNUM_READ(uniq, fps_index));
                skAppPrintErr(
                    "Cannot read distinct count from temporary file: %s",
                    (last_errno ? strerror(last_errno) : "EOF"));
                return -1;
            }
        }

        uniq->distincts[i].dv_count = uniqDistmergeMergeOne(dist_merge);
    }

    if (!output_fn) {
        /* write the distinct count to the main temporary file */
        for (i = 0; i < uniq->fi.distinct_num_fields; ++i) {
            uniqTempWrite(uniq->temp_fp, &uniq->distincts[i].dv_count,
                          sizeof(uniq->distincts[i].dv_count));
        }
    } else {
        uniqDistinctSetOutputBuf(&uniq->fi, uniq->distincts, distinct_buffer);
        rv = output_fn(cached_key, distinct_buffer, merged_values,
                       callback_data);
        if (rv != 0) {
            sortuniqDebug(uniq, "output_fn returned non-zero %d", rv);
            return -1;
        }
    }

    return 0;
}


/*
 *    Helper function for skPresortedUniqueProcess() that merges
 *    temporary files when distinct counts are being computed.
 *
 *    Use the open file handles in the fps[] array on the 'uniq'
 *    object and merge the values and distinct counts when the keys
 *    are identical.
 *
 *    If the 'output_fn' is not-NULL, send the key, merged values, and
 *    distinct counts to that function.  When the 'output_fn' is NULL,
 *    the merged values are written to another temporary file.
 *
 *    This function returns once all the data in the open files has
 *    been read.
 */
static int
sortuniqMergeFilesDist(
    sk_sort_unique_t       *uniq,
    distinct_merge_t       *dist_merge,
    sk_unique_output_fn_t   output_fn,
    void                   *callback_data)
{
    uint16_t *top_heap;
    uint16_t lowest;
    uint16_t i;
    int rv = -1;

    /* Should only be called when distinct fields are present */
    assert(0 != uniq->fi.distinct_num_fields);
    assert(output_fn || (uniq->temp_fp && uniq->dist_fp));
    assert((1 == dist_merge->write_to_temp && (uniq->temp_fp && uniq->dist_fp))
           || (0 == dist_merge->write_to_temp && output_fn));

    /* check for the same key in multiple input files */
    while (skHeapGetNumberEntries(uniq->heap) > 1) {
        /* get the file with the lowest key */
        skHeapExtractTop(uniq->heap, (skheapnode_t)&lowest);

        /* store the id of each file whose current key matches the
         * lowest key into the dist_merge->active[] array; remove the
         * items from heap as they are added to active[] */
        dist_merge->active[0] = lowest;
        dist_merge->num_active = 1;

        while (skHeapPeekTop(uniq->heap, (skheapnode_t*)&top_heap)
               == SKHEAP_OK
               && 0 == (skFieldListCompareBuffers(
                            uniq->key[lowest], uniq->key[*top_heap],
                            uniq->fi.key_fields)))
        {
            dist_merge->active[dist_merge->num_active++] = *top_heap;
            skHeapExtractTop(uniq->heap, NULL);
        }
        if (dist_merge->write_to_temp) {
            /* write the key to the temporary file */
            uniqTempWrite(
                uniq->temp_fp, uniq->key[lowest], uniq->fi.key_octets);
        }

        if (1 == dist_merge->num_active) {
            /* if the lowest key only appears in one file, there no
             * need to merge, just copy the bytes from source to the
             * dest */
            rv = sortuniqMergeSingleFile(uniq, uniq->key[lowest], dist_merge,
                                         output_fn, callback_data);
        } else {
            rv = sortuniqMergeValuesDist(uniq, uniq->key[lowest], dist_merge,
                                         output_fn, callback_data);
        }
        if (rv) {
            return -1;
        }

        /* for each element in dist_merge->active[], read its next key and
         * insert it into the heap */
        for (i = 0; i < dist_merge->num_active; ++i) {
            if (uniqTempRead(uniq->fps[dist_merge->active[i]],
                             uniq->key[dist_merge->active[i]],
                             uniq->fi.key_octets))
            {
                /* read succeeded. insert the new entry into the heap */
                skHeapInsert(uniq->heap, &dist_merge->active[i]);
            } else {
                /* read failed and no more data for this file */
                sortuniqDebug(
                    uniq, "Finished reading files #%u, #%u; %d files remain",
                    UNIQUE_TMPNUM_READ(uniq, dist_merge->active[i]),
                    UNIQUE_TMPNUM_READ(uniq, dist_merge->active[i] + 1),
                    (2 * (skHeapGetNumberEntries(uniq->heap)
                          + dist_merge->num_active - i - 1)));
            }
        }
    }

    /* handle the final file */
    if (skHeapExtractTop(uniq->heap, (skheapnode_t)&lowest) == SKHEAP_OK) {
        assert(skHeapGetNumberEntries(uniq->heap) == 0);

        dist_merge->active[0] = lowest;
        dist_merge->num_active = 1;

        do {
            if (dist_merge->write_to_temp) {
                uniqTempWrite(
                    uniq->temp_fp, uniq->key[lowest], uniq->fi.key_octets);
            }
            if (sortuniqMergeSingleFile(uniq, uniq->key[lowest], dist_merge,
                                        output_fn, callback_data))
            {
                return -1;
            }
        } while (uniqTempRead(uniq->fps[lowest], uniq->key[lowest],
                              uniq->fi.key_octets));
        /* read failed and no more data for this file */
        sortuniqDebug(
            uniq, "Finished reading files #%u, #%u; 0 files remain",
            UNIQUE_TMPNUM_READ(uniq, lowest),
            UNIQUE_TMPNUM_READ(uniq, lowest + 1));
    }
    assert(skHeapGetNumberEntries(uniq->heap) == 0);

    return 0;
}


/*
 *    The output function for presorted input when temporary files
 *    have been written and distinct files are being used.
 */
static int
sortuniqHandleTempDist(
    sk_sort_unique_t       *uniq,
    sk_unique_output_fn_t   output_fn,
    void                   *callback_data)
{
    int tmp_idx_a;
    int tmp_idx_b;
    uint16_t i;
    int j;
    distinct_merge_t dist_merge;
    int rv = -1;

    /* Should only be called when distinct fields are present */
    assert(0 != uniq->fi.distinct_num_fields);
    assert(output_fn);

    memset(&dist_merge, 0, sizeof(dist_merge));
    dist_merge.write_to_temp = 1;

    /* create the heap that operates over the distinct fields */
    dist_merge.heap = skHeapCreate2(uniqDistmergeCmp, MAX_MERGE_FILES,
                                    sizeof(uint16_t), NULL, &dist_merge);
    if (NULL == dist_merge.heap) {
        skAppPrintOutOfMemory("distinct heap");
        return -1;
    }

    /* index at which to start the merge */
    tmp_idx_a = 0;

    /* This loop repeats as long as we haven't opened all of the temp
     * files generated while reading the flows. */
    do {
        assert(skHeapGetNumberEntries(uniq->heap) == 0);

        /* the index of the first temporary file being processed */
        uniq->temp_idx_base = tmp_idx_a;

        /* determine the index at which to stop the merge */
        tmp_idx_b = tmp_idx_a + MAX_MERGE_FILES - 1;
        if (uniq->max_temp_idx < tmp_idx_b) {
            /* number of temp files is less than MAX_MERGE */
            tmp_idx_b = uniq->max_temp_idx;
        }
        assert((tmp_idx_a & 0x1) == 0);
        assert((tmp_idx_b & 0x1) == 1);

        sortuniqDebug(uniq,
                      "Attempting to open temporary files #%d through #%d",
                      tmp_idx_a, tmp_idx_b);

        /* open intermediate temp files */
        uniq->temp_fp = uniqTempCreate(uniq->tmpctx, &uniq->max_temp_idx);
        uniq->temp_idx = uniq->max_temp_idx;

        uniq->dist_fp = uniqTempCreate(uniq->tmpctx, &uniq->max_temp_idx);
        dist_merge.dist_fp = uniq->dist_fp;

        /* Open up to MAX_MERGE files; the files are opened in pairs
         * where the second file of the pair contains the distinct
         * counts */
        for (j = tmp_idx_a, i = 0; j <= tmp_idx_b; j += 2, ++i) {
            uniq->fps[i] = uniqTempReopen(uniq->tmpctx, j);
            if (uniq->fps[i] == NULL) {
                if (skHeapGetNumberEntries(uniq->heap) < 2) {
                    skAppPrintErr("Unable to open multiple temporary files");
                    return -1;
                }
                /* We cannot open any more temp files; we'll need to
                 * catch file 'j' the next time around. */
                tmp_idx_b = j - 1;
                sortuniqDebug(uniq,
                              ("File limit hit [%s]---merging"
                               " #%d through #%d into #%d, #%d..."),
                              strerror(errno), tmp_idx_a, tmp_idx_b,
                              uniq->temp_idx, uniq->max_temp_idx);
                break;
            }

            /* Read the first key from the file */
            if (!uniqTempRead(uniq->fps[i], uniq->key[i],
                              uniq->fi.key_octets))
            {
                if (0 != skStreamGetLastErrno(uniq->fps[i])) {
                    skAppPrintErr(
                        "Cannot read first key from temporary file '%s'; %s",
                        skTempFileGetName(uniq->tmpctx, j),
                        strerror(skStreamGetLastErrno(uniq->fps[i])));
                    return -1;
                }
                sortuniqDebug(uniq, "Ignoring empty temporary file '%s'",
                              skTempFileGetName(uniq->tmpctx, j));
                uniqTempClose(uniq->fps[i]);
                uniq->fps[i] = NULL;
                continue;
            }

            /* open the corresponding distinct file */
            dist_merge.fps[i] = uniqTempReopen(uniq->tmpctx, j + 1);
            if (NULL == dist_merge.fps[i]) {
                if (skHeapGetNumberEntries(uniq->heap) < 2) {
                    skAppPrintErr("Unable to open multiple temporary files");
                    return -1;
                }
                /* We cannot open any more temp files; we'll need to
                 * catch file 'j' the next time around. */
                tmp_idx_b = j - 1;
                sortuniqDebug(uniq,
                              ("File limit hit [%s]---merging"
                               " #%d through #%d into #%d, #%d..."),
                              strerror(errno), tmp_idx_a, tmp_idx_b,
                              uniq->temp_idx, uniq->max_temp_idx);
                uniqTempClose(uniq->fps[i]);
                uniq->fps[i] = NULL;
                break;
            }

            skHeapInsert(uniq->heap, &i);
        }

        sortuniqDebug(uniq, "Opened %" PRIu32 " temporary file pairs",
                      skHeapGetNumberEntries(uniq->heap));

        /* Check to see if we've opened all temp files.  If so, close
         * the intermediate file. */
        if (tmp_idx_b == uniq->temp_idx - 1) {
            /* no longer need the intermediate temp file */
            sortuniqDebug(uniq, "Successfully opened all%s temporary files",
                          ((tmp_idx_a > 0) ? " remaining" : ""));

            uniqTempClose(uniq->temp_fp);
            uniqTempClose(uniq->dist_fp);
            uniq->temp_fp = NULL;
            uniq->dist_fp = NULL;

            dist_merge.write_to_temp = 0;
        }

        /* process this set of files */
        if (uniq->temp_fp) {
            rv = sortuniqMergeFilesDist(uniq, &dist_merge, NULL, NULL);
        } else {
            rv = sortuniqMergeFilesDist(uniq, &dist_merge,
                                        output_fn, callback_data);
        }
        /* return on error below after closing files */

        /* Close and remove all the temp files that we processed this
         * time. */
        for (j = tmp_idx_a, i = 0; j <= tmp_idx_b; j += 2, ++i) {
            uniqTempClose(uniq->fps[i]);
            uniqTempClose(dist_merge.fps[i]);
            skTempFileRemove(uniq->tmpctx, j);
            skTempFileRemove(uniq->tmpctx, j + 1);
        }
        memset(uniq->fps, 0, sizeof(uniq->fps));
        memset(dist_merge.fps, 0, sizeof(dist_merge.fps));

        if (rv) {
            skHeapFree(dist_merge.heap);
            return rv;
        }

        if (uniq->temp_fp) {
            /* Close the intermediate temp files. */
            sortuniqDebug(uniq, "Finished writing #%d '%s', #%d '%s'",
                          uniq->temp_idx, UNIQUE_TMPNAME_OUT(uniq),
                          uniq->max_temp_idx,
                          uniqBasename(skStreamGetPathname(uniq->dist_fp)));

            uniqTempClose(uniq->temp_fp);
            uniq->temp_fp = NULL;
            uniqTempClose(uniq->dist_fp);
            uniq->dist_fp = NULL;
        }

        /* start the next merge with the next temp file */
        tmp_idx_a = tmp_idx_b + 1;
    } while (dist_merge.write_to_temp);

    skHeapFree(dist_merge.heap);
    return 0;
}


/*
 *    Helper function for skPresortedUniqueProcess() that merges
 *    temporary files when distinct counts are not being computed.
 *
 *    Use the open file handles in the fps[] array on the 'uniq'
 *    object and merge the values the keys are identical.
 *
 *    If the 'output_fn' is not-NULL, send the key and merged values
 *    to that function.  When the 'output_fn' is NULL, the merged
 *    values are written to another temporary file.
 *
 *    This function returns once all the data in the open files has
 *    been read.
 */
static int
sortuniqMergeFilesNodist(
    sk_sort_unique_t       *uniq,
    sk_unique_output_fn_t   output_fn,
    void                   *callback_data)
{
    uint8_t buf[4096];
    uint16_t *top_heap;
    uint16_t lowest;
    uint8_t cached_key[HASHLIB_MAX_KEY_WIDTH];
    uint8_t distinct_buffer[HASHLIB_MAX_KEY_WIDTH];
    uint8_t merged_values[HASHLIB_MAX_VALUE_WIDTH];
    uint32_t heap_count;
    int last_errno;
    int rv;

    /* should only be called with value fields and no distinct fields */
    assert(0 == uniq->fi.distinct_num_fields);
    assert(0 < uniq->fi.value_octets);

    /* either writing to the temp file or to the output function */
    assert(output_fn || uniq->temp_fp);

    heap_count = skHeapGetNumberEntries(uniq->heap);
    if (0 == heap_count) {
        return 0;
    }

    /* get the index of the file with the lowest key; which is at
     * the top of the heap */
    skHeapPeekTop(uniq->heap, (skheapnode_t*)&top_heap);
    lowest = *top_heap;

    /* exit this do...while() once all records for all opened files
     * have been read */
    do {
        /* cache this low key, initialize the values */
        memcpy(cached_key, uniq->key[lowest], uniq->fi.key_octets);
        skFieldListInitializeBuffer(uniq->fi.value_fields, merged_values);

        /* loop over all files until we get a key that does not
         * match the cached_key */
        do {
            /* read the value from the file and merge it */
            if (!uniqTempRead(uniq->fps[lowest], buf, uniq->fi.value_octets)) {
                last_errno = skStreamGetLastErrno(uniq->fps[lowest]);
                sortuniqDebug(uniq, "Cannot read from temporary file #%u",
                              UNIQUE_TMPNUM_READ(uniq, lowest));
                skAppPrintErr(
                    "Cannot read value field from temporary file: %s",
                    (last_errno ? strerror(last_errno) : "EOF"));
                return -1;
            }
            skFieldListMergeBuffers(
                uniq->fi.value_fields, merged_values, buf);

            /* replace the key for the value we just processed */
            if (uniqTempRead(uniq->fps[lowest], uniq->key[lowest],
                             uniq->fi.key_octets))
            {
                /* insert the new key into the heap; get the new
                 * lowest key */
                skHeapReplaceTop(uniq->heap, &lowest, NULL);
            } else {
                /* read failed.  there is no more data for this file;
                 * remove it from the heap; get the new top of the
                 * heap, or end the while if no more files */
                --heap_count;
                sortuniqDebug(uniq,
                              ("Finished reading records from file #%u,"
                               " %" PRIu32 " files remain"),
                              UNIQUE_TMPNUM_READ(uniq, lowest), heap_count);
                skHeapExtractTop(uniq->heap, NULL);
                assert(skHeapGetNumberEntries(uniq->heap) == heap_count);
                if (0 == heap_count) {
                    break;
                }
            }
            skHeapPeekTop(uniq->heap, (skheapnode_t*)&top_heap);
            lowest = *top_heap;

        } while (skFieldListCompareBuffers(
                     cached_key, uniq->key[lowest], uniq->fi.key_fields)
                 == 0);

        /* write the key and value */
        if (output_fn) {
            rv = output_fn(cached_key, distinct_buffer, merged_values,
                           callback_data);
            if (rv != 0) {
                sortuniqDebug(uniq, "output_fn returned non-zero %d", rv);
                return -1;
            }
        } else {
            uniqTempWriteTriple(&uniq->fi, uniq->temp_fp, NULL,
                                cached_key, merged_values, uniq->distincts);
        }
    } while (heap_count > 0);

    return 0;
}


/*
 *    The output function for presorted input when temporary files
 *    have been written and distinct files are not in use.
 */
static int
sortuniqHandleTempNodist(
    sk_sort_unique_t       *uniq,
    sk_unique_output_fn_t   output_fn,
    void                   *callback_data)
{
    int tmp_idx_a;
    int tmp_idx_b;
    uint16_t i;
    int j;
    int opened_all_temps;
    int rv = -1;

    assert(uniq);
    assert(output_fn);

    /* should only be called with value fields and no distinct fields */
    assert(0 == uniq->fi.distinct_num_fields);
    assert(0 < uniq->fi.value_octets);
    assert(output_fn);

    /* for this function to be called, temp files #0 and #1 must be in
     * use */
    assert(uniq->temp_idx >= 1);

    /* index at which to start the merge */
    tmp_idx_a = 0;

    opened_all_temps = 0;

    /* This loop repeats as long as we haven't opened all of the temp
     * files generated while reading the flows. */
    do {
        assert(skHeapGetNumberEntries(uniq->heap) == 0);

        /* the index of the first temporary file being processed */
        uniq->temp_idx_base = tmp_idx_a;

        /* determine the index at which to stop the merge */
        tmp_idx_b = tmp_idx_a + MAX_MERGE_FILES - 1;
        if (uniq->max_temp_idx < tmp_idx_b) {
            /* number of temp files is less than MAX_MERGE */
            tmp_idx_b = uniq->max_temp_idx;
        }

        sortuniqDebug(uniq,
                      "Attempting to open temporary files #%d through #%d",
                      tmp_idx_a, tmp_idx_b);

        /* open an intermediate temp file.  The merge-sort will have
         * to write nodes here if there are not enough file handles
         * available to open all the temporary files we wrote while
         * reading the data. */
        uniq->temp_fp = uniqTempCreate(uniq->tmpctx, &uniq->max_temp_idx);
        uniq->temp_idx = uniq->max_temp_idx;

        /* Open up to MAX_MERGE files */
        for (j = tmp_idx_a, i = 0; j <= tmp_idx_b; ++j, ++i) {
            uniq->fps[i] = uniqTempReopen(uniq->tmpctx, j);
            if (NULL == uniq->fps[i]) {
                if (skHeapGetNumberEntries(uniq->heap) < 2) {
                    skAppPrintErr("Unable to open multiple temporary files");
                    return -1;
                }
                /* We cannot open any more temp files; we'll need to
                 * catch file 'j' the next time around. */
                tmp_idx_b = j - 1;
                sortuniqDebug(uniq,
                              ("File limit hit [%s]---merging"
                               " #%d through #%d into #%d..."),
                              strerror(errno), tmp_idx_a, tmp_idx_b,
                              uniq->temp_idx);
                break;
            }

            /* Read the first key from the file and add the file's
             * index to the heap */
            if (uniqTempRead(uniq->fps[i], uniq->key[i], uniq->fi.key_octets)){
                skHeapInsert(uniq->heap, &i);
            } else if (0 == skStreamGetLastErrno(uniq->fps[i])) {
                sortuniqDebug(uniq, "Ignoring empty temporary file #%u '%s'",
                              j, skTempFileGetName(uniq->tmpctx, j));
                uniqTempClose(uniq->fps[i]);
                uniq->fps[i] = NULL;
            } else {
                skAppPrintErr(
                    "Cannot read first key from temporary file '%s': %s",
                    skTempFileGetName(uniq->tmpctx, j),
                    strerror(skStreamGetLastErrno(uniq->fps[i])));
                return -1;
            }
        }

        sortuniqDebug(uniq, "Opened %" PRIu32 " temporary files",
                      skHeapGetNumberEntries(uniq->heap));

        /* Check to see if we've opened all temp files.  If so, close
         * the intermediate file. */
        if (tmp_idx_b == uniq->temp_idx - 1) {
            /* no longer need the intermediate temp file */
            sortuniqDebug(uniq, "Successfully opened all%s temporary files",
                          ((tmp_idx_a > 0) ? " remaining" : ""));
            uniqTempClose(uniq->temp_fp);
            uniq->temp_fp = NULL;
            opened_all_temps = 1;
        }

        if (uniq->temp_fp) {
            rv = sortuniqMergeFilesNodist(uniq, NULL, NULL);
        } else {
            rv = sortuniqMergeFilesNodist(uniq, output_fn, callback_data);
        }
        /* return on error after closing temporary files */

        /* Close and remove all the temp files that we processed this
         * time. */
        for (j = tmp_idx_a, i = 0; j <= tmp_idx_b; ++j, ++i) {
            uniqTempClose(uniq->fps[i]);
            skTempFileRemove(uniq->tmpctx, j);
        }
        memset(uniq->fps, 0, sizeof(uniq->fps));

        if (rv) {
            return rv;
        }

        /* Close the intermediate temp file if using it */
        if (uniq->temp_fp) {
            sortuniqDebug(uniq, "Finished writing #%d '%s'",
                          uniq->temp_idx, UNIQUE_TMPNAME_OUT(uniq));
            uniqTempClose(uniq->temp_fp);
            uniq->temp_fp = NULL;
        }

        /* start the next merge with the next temp file */
        tmp_idx_a = tmp_idx_b + 1;
    } while (!opened_all_temps);

    return 0;
}


/*  create an object to bin fields where the data is coming from files
 *  that have been sorted using the same keys as specified in the
 *  'uniq' object. */
int
skPresortedUniqueCreate(
    sk_sort_unique_t  **uniq)
{
    sk_sort_unique_t *u;
    const char *env_value;
    uint32_t debug_lvl;

    *uniq = NULL;

    u = (sk_sort_unique_t*)calloc(1, sizeof(sk_sort_unique_t));
    if (NULL == u) {
        return -1;
    }
    u->files = skVectorNew(sizeof(char*));
    if (NULL == u->files) {
        free(u);
        return -1;
    }

    u->read_rec_fn = &skStreamReadRecord;

    env_value = getenv(SKUNIQUE_DEBUG_ENVAR);
    if (env_value && 0 == skStringParseUint32(&debug_lvl, env_value, 1, 0)) {
        u->print_debug = 1;
    }

    u->temp_idx = -1;
    u->max_temp_idx = -1;

    *uniq = u;
    return 0;
}


/*  destroy the unique object */
void
skPresortedUniqueDestroy(
    sk_sort_unique_t  **uniq)
{
    sk_sort_unique_t *u;
    char *filename;
    size_t i;

    if (NULL == uniq || NULL == *uniq) {
        return;
    }

    u = *uniq;
    *uniq = NULL;

    if (u->temp_fp) {
        uniqTempClose(u->temp_fp);
        u->temp_fp = NULL;
    }
    if (u->dist_fp) {
        uniqTempClose(u->dist_fp);
        u->dist_fp = NULL;
    }
    skTempFileTeardown(&u->tmpctx);
    free(u->temp_dir);

    if (u->files) {
        for (i = 0; 0 == skVectorGetValue(&filename, u->files, i); ++i) {
            free(filename);
        }
        skVectorDestroy(u->files);
    }

    free(u->rec);
    free(u->key);
    free(u->key_data);
    skHeapFree(u->heap);
    uniqTotalDistinctDestroy(&u->total_dist);
    uniqDistinctFree(&u->fi, u->distincts);

    free(u);
}


/*  tell the unique object to process the records in 'filename' */
int
skPresortedUniqueAddInputFile(
    sk_sort_unique_t   *uniq,
    const char         *filename)
{
    char *copy;

    assert(uniq);
    assert(filename);

    if (uniq->processing) {
        return -1;
    }

    copy = strdup(filename);
    if (NULL == copy) {
        return -1;
    }
    if (skVectorAppendValue(uniq->files, &copy)) {
        free(copy);
        return -1;
    }

    return 0;
}


/*  set the temporary directory used by 'uniq' to 'temp_dir' */
void
skPresortedUniqueSetTempDirectory(
    sk_sort_unique_t   *uniq,
    const char         *temp_dir)
{
    if (uniq->temp_dir) {
        free(uniq->temp_dir);
        uniq->temp_dir = NULL;
    }
    if (temp_dir) {
        uniq->temp_dir = strdup(temp_dir);
    }
}


/*  set a function that gets called when the 'uniq' object opens a
 *  file that was specified in skPresortedUniqueAddInputFile(). */
int
skPresortedUniqueSetPostOpenFn(
    sk_sort_unique_t   *uniq,
    int               (*stream_post_open)(skstream_t *))
{
    assert(uniq);

    if (uniq->processing) {
        return -1;
    }

    uniq->post_open_fn = stream_post_open;
    return 0;
}


/*  set a function to read a record from an input stream */
int
skPresortedUniqueSetReadFn(
    sk_sort_unique_t   *uniq,
    int               (*stream_read)(skstream_t *, rwRec *))
{
    assert(uniq);

    if (uniq->processing) {
        return -1;
    }

    if (NULL == stream_read) {
        uniq->read_rec_fn = &skStreamReadRecord;
    } else {
        uniq->read_rec_fn = stream_read;
    }
    return 0;
}


/*  set the key, distinct, and value fields for 'uniq' */
int
skPresortedUniqueSetFields(
    sk_sort_unique_t       *uniq,
    const sk_fieldlist_t   *key_fields,
    const sk_fieldlist_t   *distinct_fields,
    const sk_fieldlist_t   *agg_value_fields)
{
    assert(uniq);

    if (uniq->processing) {
        return -1;
    }

    memset(&uniq->fi, 0, sizeof(sk_uniq_field_info_t));
    uniq->fi.key_fields = key_fields;
    uniq->fi.value_fields = agg_value_fields;
    uniq->fi.distinct_fields = distinct_fields;

    return 0;
}


/*  count distincts across all bins for first distinct field */
int
skPresortedUniqueEnableTotalDistinct(
    sk_sort_unique_t   *uniq)
{
    assert(uniq);

    if (uniq->processing) {
        skAppPrintErr("May not call skPresortedUniqueEnableTotalDistinct"
                      " after calling skPresortedUniqueProcess");
        return -1;
    }
    uniq->use_total_distinct = 1;
    return 0;
}


/*  return the number of distincts for first distinct field across all
 *  bins */
uint64_t
skPresortedUniqueGetTotalDistinctCount(
    sk_sort_unique_t   *uniq)
{
    return uniqTotalDistinctGetCount(&uniq->total_dist);
}


/*  set callback function that 'uniq' will call once it determines
 *  that a bin is complete */
int
skPresortedUniqueProcess(
    sk_sort_unique_t       *uniq,
    sk_unique_output_fn_t   output_fn,
    void                   *callback_data)
{
    uint16_t open_count;
    uint16_t i;
    int no_more_inputs = 0;
    int rv = -1;

    assert(uniq);
    assert(output_fn);

    /* no recursive processing */
    if (uniq->processing) {
        return -1;
    }
    uniq->processing = 1;

    if (uniqCheckFields(&uniq->fi)) {
        return -1;
    }

    /* initialize the total distinct object */
    if (uniq->use_total_distinct) {
        if (uniqTotalDistinctPrepareInput(
                &uniq->total_dist, &uniq->fi, uniq->temp_dir))
        {
            return -1;
        }
    }

    if (skTempFileInitialize(&uniq->tmpctx, uniq->temp_dir,
                             NULL, skAppPrintErr))
    {
        return -1;
    }

    /* set up distinct fields */
    if (uniq->fi.distinct_num_fields) {
        if (uniqDistinctAlloc(&uniq->fi, &uniq->distincts)) {
            skAppPrintOutOfMemory("distinct counts");
            return -1;
        }
    }

    /* This outer loop is over the SiLK Flow input files and it
     * repeats as long as we haven't read all the records from all the
     * input files */
    do {
        /* open an intermediate temp file that we will use if there
         * are not enough file handles available to open all the input
         * files. */
        uniq->temp_fp = uniqTempCreate(uniq->tmpctx, &uniq->max_temp_idx);
        uniq->temp_idx = uniq->max_temp_idx;
        if (uniq->fi.distinct_num_fields) {
            uniq->dist_fp = uniqTempCreate(uniq->tmpctx, &uniq->max_temp_idx);
        }

        /* Attempt to open up to MAX_MERGE_FILES SILK input files,
         * though any open may fail due to lack of resources (EMFILE
         * or ENOMEM) */
        for (open_count = 0; open_count < MAX_MERGE_FILES; ++open_count) {
            rv = sortuniqOpenNextInput(uniq, &uniq->fps[open_count]);
            if (rv != 0) {
                break;
            }
        }
        switch (rv) {
          case 1:
            /* successfully opened all (remaining) input files */
            sortuniqDebug(uniq, "Opened all%s input files",
                          (uniq->rec ? " remaining" : ""));
            no_more_inputs = 1;
            break;
          case -1:
            /* unexpected error opening a file */
            return -1;
          case -2:
            /* ran out of memory or file descriptors */
            sortuniqDebug(uniq, ("Unable to open all inputs"
                                 "---out of memory or file handles"));
            break;
          case 0:
            if (open_count != MAX_MERGE_FILES) {
                /* no other way that rv == 0 */
                sortuniqDebug(uniq, ("rv == 0 but open_count == %d;"
                                     " max_merge == %d. Abort"),
                              open_count, MAX_MERGE_FILES);
                skAbort();
            }
            /* ran out of pointers for this run */
            sortuniqDebug(uniq, ("Unable to open all inputs"
                                 "---max_merge (%d) limit reached"),
                          MAX_MERGE_FILES);
            break;
          default:
            /* unexpected error */
            sortuniqDebug(uniq, "Got unexpected rv value = %d", rv);
            skAbortBadCase(rv);
        }

        /* if this is the first iteration, allocate space for the
         * records and keys we will use while processing the files */
        if (NULL == uniq->rec) {
            uint8_t *n;
            uniq->rec = (rwRec*)malloc(MAX_MERGE_FILES * sizeof(rwRec));
            if (NULL == uniq->rec) {
                skAppPrintErr("Error allocating space for %u records",
                              MAX_MERGE_FILES);
                return -1;
            }
            uniq->key_data = ((uint8_t*)
                              malloc(MAX_MERGE_FILES * uniq->fi.key_octets));
            if (NULL == uniq->key_data) {
                skAppPrintErr("Error allocating space for %u keys",
                              MAX_MERGE_FILES);
                return -1;
            }
            uniq->key = (uint8_t**)malloc(MAX_MERGE_FILES * sizeof(uint8_t*));
            if (NULL == uniq->key) {
                skAppPrintErr("Error allocating space for %u key pointers",
                              MAX_MERGE_FILES);
                return -1;
            }
            for (i = 0, n = uniq->key_data;
                 i < MAX_MERGE_FILES;
                 ++i, n += uniq->fi.key_octets)
            {
                uniq->key[i] = n;
            }
            uniq->heap = skHeapCreate2(sortuniqHeapKeysCmp, MAX_MERGE_FILES,
                                       sizeof(uint16_t), NULL, uniq);
            if (NULL == uniq->heap) {
                skAppPrintErr("Error allocating space for %u heap entries",
                              MAX_MERGE_FILES);
                return -1;
            }
        }

        /* Read the first record from each file into the rec[] array;
         * generate and store the key in the key[] array.  Insert the
         * index into the heap. */
        for (i = 0; i < open_count; ++i) {
            if (sortuniqFillRecordAndKey(uniq, i)) {
                skHeapInsert(uniq->heap, &i);
            }
        }

        /* process this set of files */
        if (uniq->fi.distinct_num_fields) {
            sortuniqDebug(uniq, ("Merging %" PRIu32 " presorted input files"
                                 " into temporary files #%d, #%d..."),
                          skHeapGetNumberEntries(uniq->heap),
                          uniq->temp_idx, uniq->max_temp_idx);
            rv = sortuniqReadSilkDist(uniq);
        } else if (no_more_inputs && uniq->temp_idx == 0) {
            /* opened everything in one pass; no longer need the
             * intermediate temp file */
            sortuniqDebug(uniq, "Merging %" PRIu32 " presorted input files",
                          skHeapGetNumberEntries(uniq->heap));
            uniqTempClose(uniq->temp_fp);
            uniq->temp_fp = NULL;
            uniq->temp_idx = -1;
            uniq->max_temp_idx = -1;
            rv = sortuniqReadSilkNodist(uniq, output_fn, callback_data);
        } else {
            sortuniqDebug(uniq, ("Merging %" PRIu32 " presorted input files"
                                 " into temporary file #%d..."),
                          skHeapGetNumberEntries(uniq->heap), uniq->temp_idx);
            rv = sortuniqReadSilkNodist(uniq, NULL, NULL);
        }
        if (rv) {
            return rv;
        }

        /* Close the input files that we processed this time. */
        for (i = 0; i < open_count; ++i) {
            skStreamDestroy(&uniq->fps[i]);
        }

        /* Close the intermediate temp file(s) if using them. */
        if (uniq->dist_fp) {
            sortuniqDebug(uniq, "Finished writing #%d '%s', #%d '%s'",
                          uniq->temp_idx, UNIQUE_TMPNAME_OUT(uniq),
                          uniq->max_temp_idx,
                          uniqBasename(skStreamGetPathname(uniq->dist_fp)));
            uniqTempClose(uniq->temp_fp);
            uniq->temp_fp = NULL;
            uniqTempClose(uniq->dist_fp);
            uniq->dist_fp = NULL;
        } else if (uniq->temp_fp) {
            sortuniqDebug(uniq, "Finished writing #%d '%s'",
                          uniq->temp_idx, UNIQUE_TMPNAME_OUT(uniq));
            uniqTempClose(uniq->temp_fp);
            uniq->temp_fp = NULL;
        }

    } while (!no_more_inputs);

    /* we are finished processing records; free the 'rec' array */
    free(uniq->rec);
    uniq->rec = NULL;

    /* close the total distinct file and data structure */
    if (uniqTotalDistinctPrepareOutput(&uniq->total_dist)) {
        return -1;
    }

    /* If any temporary files were written, we now have to merge them.
     * Otherwise, we didn't write any temporary files, and we are
     * done. */
    if (uniq->temp_idx < 0) {
        /* no temporary files were written */
        return 0;
    }

    sortuniqDebug(uniq, "Finished reading SiLK Flow records");

    if (uniq->fi.distinct_num_fields) {
        rv = sortuniqHandleTempDist(uniq, output_fn, callback_data);
    } else {
        rv = sortuniqHandleTempNodist(uniq, output_fn, callback_data);
    }

    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
