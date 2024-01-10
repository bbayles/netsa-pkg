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
**  skunqiue.h
**
**    A library used by rwuniq and rwstats to bin records by a key and
**    compute aggregate values (e.g., sum of bytes) for each bin.
**
*/
#ifndef _SKUNIQUE_H
#define _SKUNIQUE_H 1
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKUNIQUE_H, "$SiLK: skunique.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>


/* LOCAL DEFINES AND TYPEDEFS */

/*
 *    The sk_fieldid_t enumeration lists all the fields that can be added
 *    to an sk_fieldlist_t.  This lists includes key-fields (the
 *    fields on rwRecs) and value fields (such as sum of bytes).  The
 *    SK_FIELD_CALLER allows the caller to create arbitrary fields.
 *
 *    The definition of the enumeration is below.
 */
/* typedef enum sk_fieldid_en sk_fieldid_t; */

/*
 *    The sk_fieldlist_t holds a list of fields.  Use the
 *    skFieldList*() functions to create and modify the
 *    sk_fieldlist_t.  With the exception of SK_FIELD_CALLER, a field
 *    is added to sk_fieldlist_t by specifying a sk_fieldid_t.  To add
 *    an SK_FIELD_CALLER, the caller must fill-in the
 *    sk_fieldlist_entrydata_t structure with the required lengths and
 *    function pointers.
 */
typedef struct sk_fieldlist_st sk_fieldlist_t;

/*
 *    When a field is added to field list, the caller gets a
 *    sk_fieldentry_t has a handle to that field in that particular
 *    field_list.
 */
typedef struct sk_fieldentry_st sk_fieldentry_t;

/*
 *    The sk_fieldlist_iterator_t supports iterating over entries in
 *    an sk_fieldlist_t.
 */
typedef struct sk_fieldlist_iterator_st sk_fieldlist_iterator_t;


/*
 *    The following specify the signature of the callback functions
 *    the must be specified when adding an SK_FIELD_CALLER field to an
 *    sk_fieldlist_t.
 */

/*
 *    Callback for adding/converting a record to a binary value.
 *
 *    -- if we want this to work with the existing plug-in API, do we
 *       need to include the "extra" value here?
 */
typedef void (*sk_fieldlist_rec_to_bin_fn_t)(
    const rwRec        *rec,
    uint8_t            *dest,
    void               *ctx);

/*    Callback for comparing two binary values */
typedef int (*sk_fieldlist_bin_cmp_fn_t)(
    const uint8_t      *bin1,
    const uint8_t      *bin2,
    void               *ctx);

/*    Callback for initializing a binary value */
typedef void (*sk_fieldlist_bin_init_fn_t)(
    uint8_t            *bin,
    void               *ctx);

/*    Callback for merging (for example, adding) two binary
 *    values--used for aggregate values (and maybe distinct
 *    fields?) */
typedef void (*sk_fieldlist_bin_merge_fn_t)(
    uint8_t            *bin1,
    const uint8_t      *bin2,
    void               *ctx);

/*    Currently unused.  I think this is here for consistency with
 *    skplugin.h
 */
typedef void (*sk_fieldlist_output_fn_t)(
    const uint8_t      *bin,
    void               *ctx);

/*
 *    The sk_fieldlist_entrydata_t structure is used when the caller
 *    wants to create a custom field.  This structure holds pointers
 *    to the above callback functions.
 *
 *    In addition, 'bin_octets' specifies the length of the custom
 *    field, and 'initial_value' specifies the value that the field
 *    should be initialized to.  If 'initial_value' is not provided,
 *    the field is memset() to 0.
 */
typedef struct sk_fieldlist_entrydata_st {
    sk_fieldlist_rec_to_bin_fn_t    rec_to_bin;
    sk_fieldlist_bin_cmp_fn_t       bin_compare;
    sk_fieldlist_rec_to_bin_fn_t    add_rec_to_bin;
    sk_fieldlist_bin_merge_fn_t     bin_merge;
    sk_fieldlist_output_fn_t        bin_output;
    const uint8_t                  *initial_value;
    size_t                          bin_octets;
} sk_fieldlist_entrydata_t;


/*
 *  ok = skFieldListCreate(&field_list);
 *
 *    Create a new field list at the location specified by
 *    'field_list'.  Return 0 on success, or -1 on failure.
 */
int
skFieldListCreate(
    sk_fieldlist_t    **field_list);

/*
 *  skFieldListDestroy(&field_list);
 *
 *    Destroy the field list at location 'field_list' and set the
 *    pointer to NULL.  Function is a no-op if the argument is NULL or
 *    if it references a NULL address.
 */
void
skFieldListDestroy(
    sk_fieldlist_t    **field_list);

/*
 *  entry = skFieldListAddField(field_list, regdata, ctx);
 *
 *    Add a custom field to 'field_list', where the structure
 *    'regdata' specifies the behavior of the field.  'ctx' is a
 *    user-defined context that will be passed to the comparison
 *    functions.  Returns a handle to the new field, or NULL if there
 *    is an error.
 */
sk_fieldentry_t *
skFieldListAddField(
    sk_fieldlist_t                 *field_list,
    const sk_fieldlist_entrydata_t *regdata,
    void                           *ctx);

/*
 *  entry = skFieldListAddKnownField(field_list, field_id, ctx);
 *
 *    Add a known sk_fieldid_t to 'field_list'.  'ctx' is a
 *    user-defined context that will be passed to the comparison
 *    functions.
 */
sk_fieldentry_t *
skFieldListAddKnownField(
    sk_fieldlist_t     *field_list,
    int                 field_id,
    void               *ctx);

/*
 *  count = skFieldListGetFieldCount(field_list);
 *
 *    Return the number of fields that 'field_list' contains.
 */
size_t
skFieldListGetFieldCount(
    const sk_fieldlist_t   *field_list);

/*
 *  size = skFieldListGetBufferSize(field_list);
 *
 *    Return the number of octets required to hold all the fields in
 *    'field_list.
 */
size_t
skFieldListGetBufferSize(
    const sk_fieldlist_t   *field_list);

/*
 *  skFieldListInitializeBuffer(field_list, all_fields_buffer);
 *
 *    Set 'all_fields_buffer' to the initial value for each field in
 *    the 'field_list'.
 */
void
skFieldListInitializeBuffer(
    const sk_fieldlist_t   *field_list,
    uint8_t                *all_fields_buffer);

/*
 *  skFieldListMergeBuffers(field_list, all_fields_buffer1,all_fields_buffer2);
 *
 *    Given two buffers for the 'field_list', call the merge function
 *    to merge (e.g., add) the buffers.  The value in
 *    'all_fields_buffer2' will be added to the value in
 *    'all_fields_buffer1'.
 */
void
skFieldListMergeBuffers(
    const sk_fieldlist_t   *field_list,
    uint8_t                *all_fields_buffer1,
    const uint8_t          *all_fields_buffer2);

/*
 *  cmp=skFieldListCompareBuffers(all_fields_buf1,all_fields_buf2,field_list);
 *
 *    Compare two buffers for 'field_list', and return -1, 0, 1, if
 *    'all_fields_buf1' is <, ==, > 'all_fields_buf2'.
 *
 *    Note that the field list is the final parameter, allowing it be
 *    be easily used directly with skQSort_r().
 *
 *    See also skFieldListEntryCompareBuffers()
 */
int
skFieldListCompareBuffers(
    const uint8_t          *all_fields_buffer1,
    const uint8_t          *all_fields_buffer2,
    const sk_fieldlist_t   *field_list);

/*
 *  skFieldListRecToBinary(field_list, rwrec, all_fields_buffer);
 *
 *    For each field in 'field_list', get the binary value of that
 *    field from 'rwrec' and set the corresponding value in the
 *    'all_fields_buffer'.
 */
void
skFieldListRecToBinary(
    const sk_fieldlist_t   *field_list,
    const rwRec            *rwrec,
    uint8_t                *all_fields_buffer);

/*
 *  skFieldListAddRecToBinary(field_list, rwrec, all_fields_buffer);
 *
 *    For each field in 'field_list', get the binary value of that
 *    field from 'rwrec' and merge (e.g., add) that value to the
 *    corresponding value in the 'all_fields_buffer'.
 */
void
skFieldListAddRecToBuffer(
    const sk_fieldlist_t   *field_list,
    const rwRec            *rwrec,
    uint8_t                *all_fields_buffer);

/*
 *  skFieldListAddRecToBinary(field_list, rwrec, all_fields_buffer);
 *
 *    For each field in 'field_list', call the output callback
 *    function for each field.
 */
void
skFieldListOutputBuffer(
    const sk_fieldlist_t   *field_list,
    const uint8_t          *all_fields_buffer);


/*
 *    The following functions work with the handle that was returned
 *    by the call to skFieldListAddKnownField() and
 *    skFieldListAddField().
 */

/*
 *  ctx = skFieldListEntryGetContext(field);
 *
 *    Return the context object that was specified when 'field' was
 *    created.
 */
void *
skFieldListEntryGetContext(
    const sk_fieldentry_t  *field);

/*
 *  field_id = skFieldListEntryGetId(field);
 *
 *    Return the sk_fieldid_t value for 'field'.
 */
uint32_t
skFieldListEntryGetId(
    const sk_fieldentry_t  *field);

/*
 *  size = skFieldListEntryGetBinOctets(field);
 *
 *    Return the number of octets required to hold 'field'.
 */
size_t
skFieldListEntryGetBinOctets(
    const sk_fieldentry_t  *field);

/*
 *  skFieldListExtractFromBuffer(field_list,all_fields_buf,field,one_field_buf);
 *
 *    Copy the value associated with 'field' from the 'all_fields_buf'
 *    into the 'one_field_buf'.  It is the caller's responsibility to
 *    ensure that 'one_field_buf' is large enough to hold the value.
 */
void
skFieldListExtractFromBuffer(
    const sk_fieldlist_t   *field_list,
    const uint8_t          *all_fields_buffer,
    sk_fieldentry_t        *field_entry,
    uint8_t                *one_field_buf);

/*
 *  cmp = skFieldListEntryCompareBuffers(field_buf1, field_buf2, field_entry);
 *
 *    Compare two buffers for a single 'field_entry', and return -1,
 *    0, 1, if 'field_buf1' is <, ==, > 'field_buf2'.
 *
 *    The function assumes 'field_buf1' and 'field_buf2' are pointing
 *    at the start of the bytes for 'field_entry'
 *
 *    Note that the field entry is the final parameter, allowing it be
 *    be easily used directly with skQSort_r().
 *
 *    See also skFieldListCompareBuffers()
 */
int
skFieldListEntryCompareBuffers(
    const uint8_t          *field_buffer1,
    const uint8_t          *field_buffer2,
    const sk_fieldentry_t  *field_entry);



/*
 *    The following support iteration over the fields in a field_list.
 */

/* Do we still need the structure of the field iterator as public? */
/* typedef struct sk_fieldlist_iterator_st sk_fieldlist_iterator_t; */
struct sk_fieldlist_iterator_st {
    const sk_fieldlist_t   *field_list;
    size_t                  field_idx;
};


/*
 *  skFieldListIteratorBind(field_list, *iter);
 *
 *    Bind the field list iterator 'iter' to 'field_list'.  This
 *    function also calls skFieldListIteratorReset() to prepare the
 *    iterator for visiting each field.
 */
void
skFieldListIteratorBind(
    const sk_fieldlist_t       *field_list,
    sk_fieldlist_iterator_t    *iter);

/*
 *  skFieldListIteratorReset(iter);
 *
 *    Reset the field list iterator 'iter' so it may iteratate over
 *    the list of fields again.
 */
void
skFieldListIteratorReset(
    sk_fieldlist_iterator_t    *iter);

/*
 *  field = skFieldListIteratorNext(iter);
 *
 *    Return a handle to the next field in the field_list.  Return
 *    NULL once the iterator 'iter' has visited every field in the
 *    field list.
 */
sk_fieldentry_t *
skFieldListIteratorNext(
    sk_fieldlist_iterator_t    *iter);


/*
 *    The following are pre-defined functions provided for the
 *    caller's convenience when filling-in the
 *    sk_fieldlist_entrydata_t structure.
 */

/*
 *  cmp = skFieldCompareMemcmp(a, b, &len);
 *
 *    Comparison function the caller may use.  This function performs
 *    memcmp() on the values 'a' and 'b'.  The number of bytes in the
 *    'a' and 'b' should be passed in as the context.
 */
int
skFieldCompareMemcmp(
    const void         *a,
    const void         *b,
    void               *len);

/*
 *  cmp = skFieldCompareUintXX(a, b);
 *
 *    Comparison function the caller may use.  These functions
 *    compares 'a' and 'b' as containing unsigned uintXX_t's in native
 *    byte order.  The context is ignored.
 */
int
skFieldCompareUint8(
    const void         *a,
    const void         *b,
    void               *ctx);
int
skFieldCompareUint16(
    const void         *a,
    const void         *b,
    void               *ctx);
int
skFieldCompareUint32(
    const void         *a,
    const void         *b,
    void               *ctx);
int
skFieldCompareUint64(
    const void         *a,
    const void         *b,
    void               *ctx);

/*
 *  skFieldMergeUintXX(a, b);
 *
 *    Merging functions the caller may use.  These functions treat 'a'
 *    and 'b' as containing unsigned uintXX_t's in native byte order.
 *    The two values are summed and the result it put into 'a'.  The
 *    context is ignored.
 */
void
skFieldMergeUint8(
    void               *a,
    const void         *b,
    void               *ctx);
void
skFieldMergeUint16(
    void               *a,
    const void         *b,
    void               *ctx);
void
skFieldMergeUint32(
    void               *a,
    const void         *b,
    void               *ctx);
void
skFieldMergeUint64(
    void               *a,
    const void         *b,
    void               *ctx);


/*
 *    As noted above, the sk_fieldid_t enumeration lists all the
 *    fields that can be added to an sk_fieldlist_t.
 */
typedef enum sk_fieldid_en {
    /* the following correspond to values in rwascii.h */
    SK_FIELD_SIPv4,             /*  0 */
    SK_FIELD_DIPv4,
    SK_FIELD_SPORT,
    SK_FIELD_DPORT,

    SK_FIELD_PROTO,             /*  4 */
    SK_FIELD_PACKETS,
    SK_FIELD_BYTES,
    SK_FIELD_FLAGS,

    SK_FIELD_STARTTIME,         /*  8 */
    SK_FIELD_ELAPSED,
    SK_FIELD_ENDTIME,
    SK_FIELD_SID,

    SK_FIELD_INPUT,             /* 12 */
    SK_FIELD_OUTPUT,
    SK_FIELD_NHIPv4,
    SK_FIELD_INIT_FLAGS,

    SK_FIELD_REST_FLAGS,        /* 16 */
    SK_FIELD_TCP_STATE,
    SK_FIELD_APPLICATION,
    SK_FIELD_FTYPE_CLASS,

    SK_FIELD_FTYPE_TYPE,        /* 20 */
    SK_FIELD_STARTTIME_MSEC,
    SK_FIELD_ENDTIME_MSEC,
    SK_FIELD_ELAPSED_MSEC,

    SK_FIELD_ICMP_TYPE,         /* 24 */
    SK_FIELD_ICMP_CODE,
    /* the above correspond to values in rwascii.h */

    SK_FIELD_SIPv6,
    SK_FIELD_DIPv6,

    SK_FIELD_NHIPv6,            /* 28 */
    SK_FIELD_RECORDS,
    SK_FIELD_SUM_PACKETS,
    SK_FIELD_SUM_BYTES,

    SK_FIELD_SUM_ELAPSED,       /* 32 */
    SK_FIELD_SUM_ELAPSED_MSEC,
    SK_FIELD_MIN_STARTTIME,
    SK_FIELD_MAX_ENDTIME,

    SK_FIELD_MIN_STARTTIME_MSEC,/* 36 */
    SK_FIELD_MAX_ENDTIME_MSEC,
    SK_FIELD_CALLER
} sk_fieldid_t;



/* ************************************************************ */
/* ************************************************************ */

/*
 *    The sk_unique_t structure supports binning records, computing
 *    some value for all the records in a bin, and looping over the
 *    bins.
 *
 *    sk_unique_t was designed with batch processing in mind, such as
 *    that done by rwuniq and rwstats.  As currently written, you
 *    cannot use skUniqueIteratorCreate() until after you call
 *    skUniquePrepareForOutput(), and you cannot skUniqueAddRecord()
 *    once you call skUniquePrepareForOutput().  Things that occur in
 *    skUniquePrepareForOutput() are:
 *
 *        Dumping last batch of records to disk if we have already
 *        created temporary files.  To address this, we could have the
 *        sk_unique_t object return an error if the hash tables are
 *        too large to fit into memory.
 *
 *        Sorting the keys of the table when sorted output is
 *        requested.  To avoid this issue, do not request sorted
 *        output.
 *
 *        Sorting the keys of the table when any distinct field is
 *        present.  This may be a little more difficult to address in
 *        environments such as the Analysis Pipeline.
 *
 *    sk_unique_t handles data in random or in presorted order.  The
 *    sk_sort_unique_t structure defined later in this file operates
 *    specifically on presorted input.
 *
 *    The general processing loop for sk_unique_t is:
 *
 *      skUniqueCreate(&u);
 *      skUniqueSetFields(u, key, distinct, value);
 *      skUniqueSetTempDirectory(u);  //optional
 *      skUniqueSetSortedOutput(u);   //optional
 *      skUniquePrepareForInput(u);
 *      foreach (input_file) {
 *          skStreamOpenSilkFlow(stream, input_file[i]);
 *          while (skStreamReadRecord(stream, rec)) {
 *            skUniqueAddRecord(rec);
 *          }
 *      }
 *      skUniquePrepareForOutput(u);
 *      skUniqueIteratorCreate(u, &iter);
 *      while (skUniqueIteratorNext(iter, &key_buf, &dist_buf, &val_buf)) {
 *        // print result
 *      }
 *      skUniqueIteratorDestroy(&iter);
 *      skUniqueDestroy(&u);
 */
typedef struct sk_unique_st sk_unique_t;

/*
 *    The sk_unique_iterator_t structure supports iterating over the
 *    bins once records have been added.  The internal structure of
 *    the iterator will differ depending on various settings of the
 *    sk_unique_t structure the iterator is bound to.  These
 *    differences should not concern the caller.
 */
typedef struct sk_unique_iterator_st sk_unique_iterator_t;

/*
 *  ok = skUniqueCreate(&uniq);
 *
 *    Create a new unique object and store its address in the
 *    parameter 'uniq'.  Return -1 if the unique object cannot be
 *    created.
 */
int
skUniqueCreate(
    sk_unique_t       **uniq);

/*
 *  skUniqueDestroy(&uniq);
 *
 *    Destroy the unique object whose address is specified in 'uniq'.
 *    Remove any temporary files.  This function may be called with a
 *    NULL pointer.
 */
void
skUniqueDestroy(
    sk_unique_t       **uniq);

/*
 *  ok = skUniqueSetSortedOutput(uniq);
 *
 *    Specify that the unique object 'uniq' should present its results
 *    in sorted order.  This function must be called before calling
 *    skUniquePrepareForInput(); otherwise, the function returns -1.
 */
int
skUniqueSetSortedOutput(
    sk_unique_t        *uniq);

/*
 *  skUniqueSetTempDirectory(uniq, temp_dir);
 *
 *    Specify that the unique object 'uniq' should use the directory
 *    'temp_dir' to store temporary files.  This function is a no-op
 *    if it is called after skUniquePrepareForInput() has been called.
 *    This function makes a copy of the parameter 'temp_dir'.
 */
void
skUniqueSetTempDirectory(
    sk_unique_t        *uniq,
    const char         *temp_dir);

/*
 *  ok = skUniqueSetFields(uniq, keys, distincts, values);
 *
 *    Specify the fields that the unique object 'uniq' should use.  It
 *    is an error to call this function after
 *    skUniquePrepareForInput() has been called.
 *
 *    'keys' is a field list containing the fields to bin by.  It must
 *    contain at least one field.
 *
 *    'distincts' is a field list containing the fields where the
 *    caller wishes to get a count of distinct values per key.  It may
 *    be NULL or contain no fields, subject to the additional
 *    constraints given below.  The keys specified in 'distincts' may
 *    not be present in 'keys'.
 *
 *    'values' is a field list containing the fields where the caller
 *    wishes to compute an aggregate value per key.  It may be NULL or
 *    contain no fields, subject to the additional containsts given
 *    below.
 *
 *    If this function is called multiple times, the previous field
 *    values will be lost.
 *
 *    There are additional constaints, which will be checked when
 *    skUniquePrepareForInput() is called:
 *
 *    The length of 'keys' and 'distincts' must total to no more than
 *    HASHLIB_MAX_KEY_WIDTH bytes.
 *
 *    The length of 'values' must be no more than
 *    HASHLIB_MAX_VALUE_WIDTH bytes.
 *
 *    At least one 'values' or one 'distincts' field must be specified.
 */
int
skUniqueSetFields(
    sk_unique_t            *uniq,
    const sk_fieldlist_t   *key_fields,
    const sk_fieldlist_t   *distinct_fields,
    const sk_fieldlist_t   *agg_value_fields);


/*
 *  ok = skUniqueEnableTotalDistinct(uniq);
 *
 *    Tell the unique object 'uniq' that it should compute the number
 *    of distinct values for the first distinct field across all
 *    records.
 *
 *    The caller may use skUniqueGetTotalDistinctCount() to get the
 *    distinct count after skUniquePrepareForOutput() has been called.
 *
 *    Return an error if this function is called after
 *    skUniquePrepareForInput() has been called.
 */
int
skUniqueEnableTotalDistinct(
    sk_unique_t        *uniq);

/*
 *  ok = skUniquePrepareForInput(uniq);
 *
 *    Tell the unique object 'uniq' that initialization is complete,
 *    and that the caller is now ready to begin adding records to the
 *    unique object.
 *
 *    Return an error if the object is not completely specified or if
 *    there are field errors as specified in skUniqueSetFields().
 */
int
skUniquePrepareForInput(
    sk_unique_t        *uniq);

/*
 *  ok = skUniquePrepareForOutput(uniq);
 *
 *    Tell the unique object 'uniq' that all records have been added,
 *    and the unqiue object can now do whatever it needs to do before
 *    the caller requests get the binned records.
 *
 *    Return 0 on success.  Return -1 if skUniquePrepareForInput() has
 *    not yet been called.
 *
 *    This function may write data to a temporary file; it will return
 *    -1 if there is an error writing the file.
 *
 *    It is an error to call skUniqueAddRecord() after this function
 *    has been called.
 */
int
skUniquePrepareForOutput(
    sk_unique_t        *uniq);

/*
 *  ok = skUniqueAddRecord(uniq, rwrec);
 *
 *    Add the SiLK Flow record 'rwrec' to the unique object 'uniq'.
 *    This function should only be called after a call to
 *    skUniquePrepareForInput().
 *
 *    This function will call skFieldListRecToBinary() for the key
 *    fields (and the distinct fields, if any).  This function will
 *    call skFieldListAddRecToBuffer() for the value fields, if any.
 *
 *    Return 0 on success.  Return -1 on error.  Error conditions
 *    include calling this function before calling
 *    skUniquePrepareForInput(), being unable to write a temporary
 *    file, or being unable to create a new hash table after writing
 *    the current hash table to disk.
 */
int
skUniqueAddRecord(
    sk_unique_t        *uniq,
    const rwRec        *rwrec);

/*
 *  count = skUniqueGetTotalDistinctCount(uniq);
 *
 *    Return the number of distinct values seen for the first
 *    distinct_field across all flow records.
 *
 *    Return UINT64_MAX if this function is called before calling
 *    skUniquePrepareForOutput().
 */
uint64_t
skUniqueGetTotalDistinctCount(
    sk_unique_t        *uniq);

/*
 *  ok = skUniqueIteratorCreate(uniq, &iter);
 *
 *    Create a new iterator that can be used to get the bins from the
 *    unique object, 'uniq'.  The iterator is stored in the location
 *    pointed to by 'iter'.
 *
 *    It is an error to call this function before calling
 *    skUniquePrepareForOutput().
 *
 *    Return 0 on success, or -1 if there is an error allocating
 *    memory for the iterator.  This function may affect temporary
 *    files; it will return -1 if there is an error reading or writing
 *    the temporary files.
 */
int
skUniqueIteratorCreate(
    sk_unique_t            *uniq,
    sk_unique_iterator_t  **iter);

/*
 *  skUniqueIteratorDestroy(&iter);
 *
 *    Destroy the iterator pointed to by 'iter' and set 'iter' to
 *    NULL.  The function is a no-op if iter or *iter is NULL.
 */
#define skUniqueIteratorDestroy(uniqit_iter)    \
    if (*(uniqit_iter)) {                       \
        (*(uniqit_iter))->free_fn(uniqit_iter); \
    }

/*
 *  ok = skUniqueIteratorNext(iter, &key_fields_buf, &distinct_fields_buf, &value_fields_buf);
 *
 *    Set the pointers referenced by 'key_fields_buf',
 *    'distinct_fields_buf', and 'value_fields_buf' to the location of
 *    the buffers holding values associated with the current row.  The
 *    value remain valid until the next call to this function.
 *
 *    Return SK_ITERATOR_OK if there was another row of data; return
 *    SK_ITERATOR_NO_MORE_ENTRIES when all rows have been visited.
 */
#define skUniqueIteratorNext(uniqit_iter, uniqit_key, uniqit_dis, uniqit_val) \
    ((uniqit_iter)->next_fn((uniqit_iter), (uniqit_key),                \
                            (uniqit_dis), (uniqit_val)))


/*
 *    PRIVATE.  For internal use only.
 *
 *    Specify the signature for the function to destroy an iterator.
 */
typedef void (*sk_uniqiter_free_fn_t)(
    sk_unique_iterator_t          **iter);

/*
 *    PRIVATE.  For internal use only.
 *
 *    Specify the signature for the function to get values for the
 *    current row from the iterator.
 *
 *    int skUniqueIteratorNext(
 *        sk_unique_iterator_t           *iter,
 *        uint8_t                       **key_fields_buffer,
 *        uint8_t                       **distinct_fields_buffer,
 *        uint8_t                       **agg_value_fields_buffer);
 */
typedef int (*sk_uniqiter_next_fn_t)(
    sk_unique_iterator_t           *iter,
    uint8_t                       **key_fields_buffer,
    uint8_t                       **distinct_fields_buffer,
    uint8_t                       **value_fields_buffer);

/*
 *    PRIVATE.  For internal use only.
 *
 *    typedef struct sk_unique_iterator_st sk_unique_iterator_t;
 *
 *    The internal structure of the iterator is made available to
 *    avoid an extra function call when iterating over the elements of
 *    an sk_unique_t.
 */
struct sk_unique_iterator_st {
    sk_uniqiter_next_fn_t   next_fn;
    sk_uniqiter_free_fn_t   free_fn;
};



/* ************************************************************ */
/* ************************************************************ */

/*
 *    The sk_sort_unique_t structure is similar to sk_unique_t;
 *    however, sk_sort_unique_t is specifically designed to handle
 *    pre-sorted input.
 *
 *    For some types of calculations (particularly summing the number
 *    of packets or bytes), knowing that the data is presorted allows
 *    fast calculations since there is no need to create a hash table.
 *    When computing a count of distinct values, using sk_unique_t can
 *    be faster than using sk_sort_unique_t, since sk_sort_unique_t
 *    will still create a hash table to count the distinct values.
 *
 *    The processing of sk_sort_unique_t is very different from that
 *    for sk_unique_t.  sk_sort_unique_t processing is callback based,
 *    as specified here:
 *
 *      skPresortedUniqueCreate(&u);
 *      skPresortedUniqueSetFields(u, key, distinct, value);
 *      skPresortedUniqueSetTempDirectory(u);        //optional
 *      skPresortedUniqueSetPostOpenFn(u, open_cb);  //optional
 *      skPresortedUniqueSetReadFn(u, read_cb);      //optional
 *      foreach (input_file) {
 *        skPresortedUniqueAddInputFile(rec, input_file[i]);
 *      }
 *      skPresortedUniqueProcess(u, output_cb);
 *      skPresortedUniqueDestroy(&u);
 *
 *    where the 'output_cb' callback is called for each unique bin.
 *
 */
typedef struct sk_sort_unique_st sk_sort_unique_t;

/*
 *  ok = skPresortedUniqueCreate(&ps_uniq);
 *
 *    Create a new unique object and store its address in the parameter
 *    'ps_uniq'.  Return -1 if the unique object cannot be created.
 */
int
skPresortedUniqueCreate(
    sk_sort_unique_t  **ps_uniq);

/*
 *  skPresortedUniqueDestroy(&ps_uniq);
 *
 *    Destroy the unique object whose address is specified in 'ps_uniq'.
 *    Remove any temporary files.  This function may be called with a
 *    NULL pointer.
 */
void
skPresortedUniqueDestroy(
    sk_sort_unique_t  **ps_uniq);

/*
 *  skPresortedUniqueSetTempDirectory(ps_uniq, temp_dir);
 *
 *    Specify that the unique object 'ps_uniq' should use the
 *    directory 'temp_dir' to store temporary files.  This function
 *    makes a copy of the parameter 'temp_dir'.
 */
void
skPresortedUniqueSetTempDirectory(
    sk_sort_unique_t   *ps_uniq,
    const char         *temp_dir);

/*
 *  ok = skPresortedUniqueSetFields(ps_uniq, keys, distincts, values);
 *
 *    Specify the fields that the unique object 'ps_uniq' should use.
 *    It is an error to call this function once
 *    skPresortedUniqueProcess() has been called.
 *
 *    'keys' is a field list containing the fields to bin by.  It must
 *    contain at least one field.
 *
 *    'distincts' is a field list containing the fields where the
 *    caller wishes to get a count of distinct values per key.  It may
 *    be NULL or contain no fields, subject to the additional
 *    constraints given below.  The keys specified in 'distincts' may
 *    not be present in 'keys'.
 *
 *    'values' is a field list containing the fields where the caller
 *    wishes to compute an aggregate value per key.  It may be NULL or
 *    contain no fields, subject to the additional containsts given
 *    below.
 *
 *    If this function is called multiple times, the previous field
 *    values will be lost.
 *
 *    There are additional constaints, which will be checked when
 *    skPresortedUniqueProcess() is called:
 *
 *    The length of 'keys' and 'distincts' must total to no more than
 *    HASHLIB_MAX_KEY_WIDTH bytes.
 *
 *    The length of 'values' must be no more than
 *    HASHLIB_MAX_VALUE_WIDTH bytes.
 *
 *    At least one 'values' or one 'distincts' field must be specified.
 */
int
skPresortedUniqueSetFields(
    sk_sort_unique_t       *ps_uniq,
    const sk_fieldlist_t   *key_fields,
    const sk_fieldlist_t   *distinct_fields,
    const sk_fieldlist_t   *agg_value_fields);

/*
 *  ok = skPresortedUniqueEnableTotalDistinct(uniq);
 *
 *    Tell the unique object 'ps_uniq' that it should compute the
 *    number of distinct values for the first distinct field across
 *    all records.
 *
 *    The caller may use skPresortedUniqueGetTotalDistinctCount() to
 *    get the distinct count once skPresortedUniqueProcess() has
 *    returned.
 *
 *    Return an error if this function is called after
 *    skPresortedUniqueProcess() has been called.
 */
int
skPresortedUniqueEnableTotalDistinct(
    sk_sort_unique_t   *ps_uniq);

/*
 *  count = skPresortedUniqueGetTotalDistinctCount(ps_uniq);
 *
 *    Return the number of distinct values seen for the first distinct
 *    field across all flow records.  This should be called once
 *    skPresortedUniqueProcess() has returned.
 */
uint64_t
skPresortedUniqueGetTotalDistinctCount(
    sk_sort_unique_t   *ps_uniq);

/*
 *  ok = skPresortedUniqueAddInputFile(ps_uniq, filename);
 *
 *    Specify that 'ps_uniq' should process the SiLK Flow records in
 *    'filename'.  'ps_uniq' will assume the records in 'filename'
 *    have been sorted using the same key as specified in the call to
 *    skPresortedUniqueSetFields().
 *
 *    This function makes a copy of name of the filename and adds the
 *    copy to a list of inputs.  The function does no other processing
 *    of the file.  The function returns 0 on success, or -1 if there
 *    was an error allocating memory.
 *
 *    It is an error to call this function once
 *    skPresortedUniqueProcess() has been called.
 */
int
skPresortedUniqueAddInputFile(
    sk_sort_unique_t   *ps_uniq,
    const char         *filename);

/*
 *  ok = int skPresortedUniqueSetPostOpenFn(ps_uniq, post_open_func);
 *
 *    Specify that the 'post_open_func' callback should be invoked
 *    each time a new input file is opened.  The callback is passed a
 *    reference to the newly opened stream, an skstream_t*.
 *
 *    If 'post_open_func' is NULL, any previously set callback will be
 *    cleared.
 *
 *    It is an error to call this function once
 *    skPresortedUniqueProcess() has been called.
 */
int
skPresortedUniqueSetPostOpenFn(
    sk_sort_unique_t   *ps_uniq,
    int               (*stream_post_open)(skstream_t *));

/*
 *  ok = skPresortedUniqueSetReadFn(ps_uniq, read_rec_func);
 *
 *    Specify that the 'read_rec_func' should be called to read a
 *    record from an open skstream_t.  If this function is not called,
 *    or if the 'read_rec_func' is NULL, the ps_uniq object uses
 *    skStreamReadRecord() to get a record from the stream.
 *
 *    It is an error to call this function once
 *    skPresortedUniqueProcess() has been called.
 */
int
skPresortedUniqueSetReadFn(
    sk_sort_unique_t   *ps_uniq,
    int               (*stream_read)(skstream_t *, rwRec *));

/*
 *    The sk_unique_output_fn_t specifies the signature of the
 *    callback function that the skPresortedUniqueProcess() function
 *    will invoke for each unique bin that it finds.
 *
 *    This function should print the result or do whatever other
 *    processing is required.
 *
 *    The 'key_fields_buffer', 'distinct_fields_buffer', and
 *    'value_fields_buffer' will contain the buffers for the
 *    key_fields, distinct_fields, and value_fields specified to
 *    skPresortedUniqueSetFields().  Those buffers are valid until the
 *    function returns.  If distinct_fields or value_fields were not
 *    specified, the corresponding buffer will be NULL.
 *
 *    The 'callback_data' parameter is a user-specified value passed
 *    to the skPresortedUniqueProcess() function.  It may be NULL.
 *    The callback does not automatically get a handle to the
 *    'sk_sort_unique_t' object; the caller may wish to specify that
 *    object as (part of) the callback_data.
 */
typedef int (*sk_unique_output_fn_t)(
    const uint8_t                  *key_fields_buffer,
    const uint8_t                  *distinct_fields_buffer,
    const uint8_t                  *value_fields_buffer,
    void                           *callback_data);

/*
 *  ok = skPresortedUniqueProcess(ps_uniq, output_fn, callback_data);
 *
 *    Tell 'ps_uniq' that it should process the input files that were
 *    specified in the calls to skPresortedUniqueAddInputFile().
 *
 *    The input files are opened with skStreamOpenSilkFlow().  If
 *    specified, the 'post_open_func' callback is invoked on the file.
 *    Records are read from the files using the 'read_rec_func'
 *    callback, or skStreamReadRecord() if that callback is NULL.
 *
 *    When 'ps_uniq' determines that a bin is complete, it will invoke
 *    the 'output_fn' specified here.  Note that the buffers that
 *    skPresortedUniqueProcess() hands to the callback are valid until
 *    the callback returns.  If the 'output_fn' returns a non-zero
 *    value, processing stops.
 *
 *    The 'callback_data' parameter is an user-specified value that
 *    gets passed to each invocation of the 'output_fn'; this
 *    parameter may be NULL.
 *
 *    The function returns 0 once all records have read, or -1 if
 *    there is an error during processing.
 */
int
skPresortedUniqueProcess(
    sk_sort_unique_t       *ps_uniq,
    sk_unique_output_fn_t   output_fn,
    void                   *callback_data);

#ifdef __cplusplus
}
#endif
#endif  /* _SKUNIQUE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
