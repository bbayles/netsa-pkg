/*
** Copyright (C) 2016-2023 by Carnegie Mellon University.
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
#ifndef _SKAGGBAG_H
#define _SKAGGBAG_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKAGGBAG_H, "$SiLK: skaggbag.h 6a1929dbf54d 2023-09-13 14:12:09Z mthomas $");

#include <silk/silk_types.h>
#include <silk/skstream.h>


/*
 *  skaggbag.h
 *
 *    The API to AggBag, a container and associated file format that
 *    contains a Bag-like data structure (see skbag.h) where the key
 *    and counter are aggregates of multiple fields.
 *
 *    Since SiLK 3.15.0.
 *
 *
 *    To create an AggBag, use skAggBagCreate().  Specify the type of
 *    the fields that comprise the key and counter by calling
 *    skAggBagSetKeyFields() and skAggBagSetCounterFields(),
 *    respectively.
 *
 *    To insert data into the AggBag, first call
 *    skAggBagInitializeKey() and skAggBagInitializeCounter().  These
 *    functions initialize an sk_aggbag_aggregate_t and an
 *    sk_aggbag_field_t.  sk_aggbag_aggregate_t is is an object holds
 *    the values prior to inserting them into the AggBag.
 *    sk_aggbag_field_t is an iterator over the fields that comprise a
 *    key or a counter.  For each field, call
 *    skAggBagAggregateSetDatetime(), skAggBagAggregateSetIPAddress(),
 *    or skAggBagAggregateSetUnsigned() to set its value, then call
 *    skAggBagFieldIterNext() to move the iterator to the next field.
 *    Once all key fields and counter fields have been specified, call
 *    skAggBagKeyCounterSet() to insert the key and counter.
 *
 *    skAggBagKeyCounterAdd(), skAggBagKeyCounterRemove(), and
 *    skAggBagKeyCounterSubtract() may be used to manipulate the
 *    counter values for a key.  Use skAggBagKeyCounterGet() to get a
 *    counter for a specified key.
 *
 *    Once processing is compete, use skAggBagSave() or
 *    skAggBagWrite() to store the AggBag to disk, and
 *    skAggBagDestroy() to free the memory used by the AggBag.
 *
 *
 *    For processing an existing AggBag, first use skAggBagLoad() or
 *    skAggBagRead() to read the AggBag from disk.  Use
 *    skAggBagIteratorBind() to bind an iterator to the contents of
 *    the AggBag, and skAggBagIteratorNext() to copy the key and
 *    counter from the AggBag into the iterator.  Use
 *    skAggBagFieldIterGetType() to get the type of the field, and
 *    then the one of the functions skAggBagAggregateGetDatetime(),
 *    skAggBagAggregateGetIPAddress(), or
 *    skAggBagAggregateGetUnsigned() to retrieve the value for each
 *    field in the key or counter.  Use skAggBagFieldIterNext() to
 *    visit each field in the key and counter.  Once all keys and
 *    counters have been visited, call skAggBagIteratorFree() to free
 *    the iterator and skAggBagDestroy() to destroy the AggBag.
 *
 *
 *  Mark Thomas
 *  December 2016
 *
 */

/**
 *    sk_aggbag_t is the AggBag data structure.
 */
typedef struct sk_aggbag_st sk_aggbag_t;

/**
 *    sk_aggbag_aggregate_t is a structure to hold the key or counter
 *    prior to inserting them into the AggBag or when reading from an
 *    AggBag.  An sk_aggbag_field_t is usually paired with the
 *    sk_aggbag_aggregate_t to visit each of the individual fields in
 *    the key or the counter.
 */
typedef struct sk_aggbag_aggregate_st sk_aggbag_aggregate_t;

/**
 *    sk_aggbag_field_t is an iterator over the individual fields that
 *    comprise a key or a counter.  It is usually paired with an
 *    sk_aggbag_aggregate_t that holds the values.
 */
typedef struct sk_aggbag_field_st sk_aggbag_field_t;



/**
 *    sk_aggbag_options_t is used for specifying features of the
 *    output stream when writing an Aggregate Bag to a file.
 */
struct sk_aggbag_options_st {
    /**
     *  type of input to the application, where a non-zero value
     *  indicates application uses existing SiLK files (either AggBags
     *  or Flow files).  A non-zero value provides the --notes-strip
     *  option to the application. */
    unsigned int        existing_silk_files;
    /**
     *  when 0, do not strip invocations from the AggBag; when 1,
     *  strip invocations from output */
    unsigned int        invocation_strip;
    /**
     *  when 0, do not strip annoations (notes) from the AggBag; when
     *  1, strip annotations from output */
    int                 note_strip;
    /**
     *  the command line: number of arguments */
    unsigned int        argc;
    /**
     *  the command line: the arguments */
    char              **argv;
    /**
     *  the version of records to write */
    uint16_t            record_version;
    /**
     *  the type of compression to use */
    sk_compmethod_t     comp_method;
};
typedef struct sk_aggbag_options_st sk_aggbag_options_t;


/**
 *    sk_aggbag_iter_t is used for iterating over the keys and
 *    counters that an AggBag contains.  The caller is expected to use
 *    the SK_AGGBAG_ITER_INITIALIZER macro when initializing an
 *    sk_aggbag_iter_t on the stack.
 *
 *    Use skAggBagIteratorBind() to bind the iterator to an AggBag,
 *    skAggBagIteratorNext() to visit each key and counter, and
 *    skAggBagIteratorFree() when done.
 */
typedef struct sk_aggbag_iter_st sk_aggbag_iter_t;

/**
 *    sk_aggbag_type_iter_t is a structure used when iterating over
 *    the types of fields that the AggBag code supports.
 *
 *    Use skAggBagFieldTypeIteratorBind() to initialize it and
 *    skAggBagFieldTypeIteratorNext() to visit each type.
 */
typedef struct sk_aggbag_type_iter_st sk_aggbag_type_iter_t;

/**
 *    sk_aggbag_type_t specifies the field types that the AggBag code
 *    supports.
 */
typedef enum sk_aggbag_type_en {
    SKAGGBAG_FIELD_SIPv4 = 0,
    SKAGGBAG_FIELD_DIPv4,
    SKAGGBAG_FIELD_SPORT,
    SKAGGBAG_FIELD_DPORT,
    SKAGGBAG_FIELD_PROTO = 4,
    SKAGGBAG_FIELD_PACKETS,
    SKAGGBAG_FIELD_BYTES,
    SKAGGBAG_FIELD_FLAGS,
    SKAGGBAG_FIELD_STARTTIME = 8,
    SKAGGBAG_FIELD_ELAPSED,
    SKAGGBAG_FIELD_ENDTIME,
    SKAGGBAG_FIELD_SID,
    SKAGGBAG_FIELD_INPUT = 12,
    SKAGGBAG_FIELD_OUTPUT,
    SKAGGBAG_FIELD_NHIPv4,
    SKAGGBAG_FIELD_INIT_FLAGS,
    SKAGGBAG_FIELD_REST_FLAGS = 16,
    SKAGGBAG_FIELD_TCP_STATE,
    SKAGGBAG_FIELD_APPLICATION,
    SKAGGBAG_FIELD_FTYPE_CLASS,
    SKAGGBAG_FIELD_FTYPE_TYPE = 20,
    /*
     *  SKAGGBAG_FIELD_STARTTIME_MSEC = 21,
     *  SKAGGBAG_FIELD_ENDTIME_MSEC,
     *  SKAGGBAG_FIELD_ELAPSED_MSEC,
     */
    SKAGGBAG_FIELD_ICMP_TYPE = 24,
    SKAGGBAG_FIELD_ICMP_CODE = 25,
    /* the above correspond to values in rwascii.h */

    SKAGGBAG_FIELD_SIPv6,
    SKAGGBAG_FIELD_DIPv6,
    SKAGGBAG_FIELD_NHIPv6 = 28,

    SKAGGBAG_FIELD_ANY_IPv4,
    SKAGGBAG_FIELD_ANY_IPv6,
    SKAGGBAG_FIELD_ANY_PORT,
    SKAGGBAG_FIELD_ANY_SNMP = 32,
    SKAGGBAG_FIELD_ANY_TIME,

    SKAGGBAG_FIELD_CUSTOM_KEY,

    SKAGGBAG_FIELD_SIP_COUNTRY,
    SKAGGBAG_FIELD_DIP_COUNTRY = 36,
    SKAGGBAG_FIELD_ANY_COUNTRY,

    SKAGGBAG_FIELD_SIP_PMAP,
    SKAGGBAG_FIELD_DIP_PMAP,
    SKAGGBAG_FIELD_ANY_IP_PMAP = 40,

    SKAGGBAG_FIELD_SPORT_PMAP,
    SKAGGBAG_FIELD_DPORT_PMAP,
    SKAGGBAG_FIELD_ANY_PORT_PMAP = 43,

    SKAGGBAG_FIELD_RECORDS = 0xc000, /* 49152 */
    SKAGGBAG_FIELD_SUM_PACKETS,
    SKAGGBAG_FIELD_SUM_BYTES,
    SKAGGBAG_FIELD_SUM_ELAPSED,
    SKAGGBAG_FIELD_CUSTOM_COUNTER = 0xc004, /* 49156 */

    SKAGGBAG_FIELD_INVALID = 65534
} sk_aggbag_type_t;


/**
 *    An initializer to use when creating an sk_aggbag_iter_t on the
 *    stack.
 */
#define SK_AGGBAG_ITER_INITIALIZER                              \
    { NULL, {NULL, {0}}, {NULL, {0}}, {NULL, 0}, {NULL, 0}}

/**
 *    Specify SK_AGGBAG_KEY as the value of the 'key_counter_flag'
 *    parameter to skAggBagFieldTypeIteratorBind() to visit the field
 *    types that represent keys.
 */
#define SK_AGGBAG_KEY       1

/**
 *    Specify SK_AGGBAG_COUNTER as the value of the 'key_counter_flag'
 *    parameter to skAggBagFieldTypeIteratorBind() to visit the field
 *    types that represent counters.
 */
#define SK_AGGBAG_COUNTER   2

/**
 *    The maximum number of octets an aggregate key or counter value
 *    may occupy.
 */
#define SKAGGBAG_AGGREGATE_MAXLEN  UINT16_MAX

/**
 *    Specifies the possible actions to take when dividing one AggBag by
 *    another and the divisor has a counter whose value is zero.
 *
 *    Since SiLK 3.22.0.
 */
typedef enum sk_aggbag_div_zero_action_en {
    /**
     *    Causes the operation to return SKAGGBAG_E_DIVIDE_BY_ZERO
     */
    SKAGGBAG_DIV_ZERO_ERROR,
    /**
     *    Causes the operation either to remove the key from the AggBag or to
     *    set all counters for the current key to zero, in effect removing the
     *    key when the AggBag is saved.
     */
    SKAGGBAG_DIV_ZERO_DELETE,
    /**
     *    Causes the operation to set the quotient for the affected counter to
     *    the specified value.
     */
    SKAGGBAG_DIV_ZERO_VALUE,
    /**
     *    Causes the operation to leave the dividend unchanged.
     */
    SKAGGBAG_DIV_ZERO_NOCHANGE
} sk_aggbag_div_zero_action_t;

/**
 *    Specifies the specific action to take  when dividing one AggBag by
 *    another and the divisor has a counter whose value is zero.
 *
 *    Since SiLK 3.22.0.
 */
typedef struct sk_aggbag_div_zero_st {
    /** The action to take */
    sk_aggbag_div_zero_action_t action;
    /** The value to use when 'action' is SKAGGBAG_DIV_ZERO_VALUE. */
    uint64_t                    value;
} sk_aggbag_div_zero_t;



/**
 *    Add the AggBag 'ab_addend' to the AggBag 'ab_augend'.
 *
 *    For each key in 'ab_addend', add the value for the key's counter
 *    to its value in 'ab_augend', creating new entries for keys that
 *    are not present.
 */
int
skAggBagAddAggBag(
    sk_aggbag_t        *ab_augend,
    const sk_aggbag_t  *ab_addend);


/**
 *    Get the value of the field at position 'field' in the key
 *    specified by 'agg' and set the referent of 'time_value' to that
 *    value.
 *
 *    Return SKAGGBAG_OK on success.  Return
 *    SKAGGBAG_E_FIELD_TYPE_MISMATCH if the value at position 'field'
 *    is not a Time.
 *
 *    To set the value, use skAggBagAggregateSetDatetime().  See also
 *    skAggBagAggregateGetIPAddress() and
 *    skAggBagAggregateGetUnsigned().
 */
int
skAggBagAggregateGetDatetime(
    const sk_aggbag_aggregate_t    *agg,
    const sk_aggbag_field_t        *field,
    sktime_t                       *time_value);


/**
 *    Get the value of the field at position 'field' in the key
 *    specified by 'agg' and set the referent of 'ip_value' to that
 *    value.
 *
 *    Return SKAGGBAG_OK on success.  Return
 *    SKAGGBAG_E_FIELD_TYPE_MISMATCH if the value at position 'field'
 *    is not an IP address.
 *
 *    To set the value, use skAggBagAggregateSetIPAddress().  See also
 *    skAggBagAggregateGetDatetime() and
 *    skAggBagAggregateGetUnsigned().
 */
int
skAggBagAggregateGetIPAddress(
    const sk_aggbag_aggregate_t    *agg,
    const sk_aggbag_field_t        *field,
    skipaddr_t                     *ip_value);


/**
 *    Get the value of the field at position 'field' in the key or
 *    counter specified by 'agg' and set the referent of
 *    'unsigned_value' to that value.
 *
 *    Return SKAGGBAG_OK on success.  Return
 *    SKAGGBAG_E_FIELD_TYPE_MISMATCH if the value at position 'field'
 *    is an IP address or a Time.
 *
 *    To set the value, use skAggBagAggregateSetUnsigned().  See also
 *    skAggBagAggregateGetDatetime() and
 *    skAggBagAggregateGetIPAddress().
 */
int
skAggBagAggregateGetUnsigned(
    const sk_aggbag_aggregate_t    *agg,
    const sk_aggbag_field_t        *field,
    uint64_t                       *unsigned_value);


/**
 *    Set the value of the field at position 'field' in the key
 *    specified by 'agg' to the value in 'time_value'.
 *
 *    Return SKAGGBAG_OK on success.  Return
 *    SKAGGBAG_E_FIELD_TYPE_MISMATCH if the value at position 'field'
 *    is not a Time.
 *
 *    To get the value, use skAggBagAggregateGetDatetime().  See also
 *    skAggBagAggregateSetIPAddress() and
 *    skAggBagAggregateSetUnsigned().
 */
int
skAggBagAggregateSetDatetime(
    sk_aggbag_aggregate_t      *agg,
    const sk_aggbag_field_t    *field,
    sktime_t                    time_value);

/**
 *    Set the value of the field at position 'field' in the key
 *    specified by 'agg' to the value in 'ip_value'.
 *
 *    Return SKAGGBAG_OK on success.  Return
 *    SKAGGBAG_E_FIELD_TYPE_MISMATCH if the value at position 'field'
 *    is not an IP address.
 *
 *    To get the value, use skAggBagAggregateGetIPAddress().  See also
 *    skAggBagAggregateSetDatetime() and
 *    skAggBagAggregateSetUnsigned().
 */
int
skAggBagAggregateSetIPAddress(
    sk_aggbag_aggregate_t      *agg,
    const sk_aggbag_field_t    *field,
    const skipaddr_t           *ip_value);

/**
 *    Set the value of the field at position 'field' in the key or
 *    counter specified by 'agg' to the value in 'unsigned_value'.
 *
 *    Return SKAGGBAG_OK on success.  Return
 *    SKAGGBAG_E_FIELD_TYPE_MISMATCH if the value at position 'field'
 *    is an IP address or a Time.
 *
 *    To get the value, use skAggBagAggregateGetUnsigned().  See also
 *    skAggBagAggregateSetDatetime() and
 *    skAggBagAggregateSetIPAddress().
 */
int
skAggBagAggregateSetUnsigned(
    sk_aggbag_aggregate_t      *agg,
    const sk_aggbag_field_t    *field,
    uint64_t                    unsigned_value);


/**
 *    Create a new AggBag data structure and store it in the referent
 *    of 'ab'.  Before the AggBag can be used, the caller must call
 *    skAggBagSetKeyFields() and skAggBagSetCounterFields() to set the
 *    key fields and counter fields of the AggBag.
 *
 *    The caller must use skAggBagDestroy() to destroy the AggBag once
 *    processing is complete.
 */
int
skAggBagCreate(
    sk_aggbag_t       **ab);


/**
 *    Free all memory associated with an AggBag data structure in the
 *    referent of 'ab' that was allocated via skAggBagCreate(),
 *    skAggBagRead(), or skAggBagLoad().  Do nothing if 'ab' or its
 *    referent is NULL.
 */
void
skAggBagDestroy(
    sk_aggbag_t       **ab);


/**
 *    Divide the AggBag 'ab_dividend' by the AggBag 'ab_divisor'.
 *
 *    For each key in 'ab_dividend', divide the key's counters by those for
 *    the key in 'ab_divisor'.  If 'ab_divisor' does not contain that key or
 *    one of the counters in 'ab_divisor' is zero, follow the action specified
 *    by 'div_zero'.
 *
 *    Since SiLK 3.22.0.
 */
int
skAggBagDivideAggBag(
    sk_aggbag_t                *ab_dividend,
    const sk_aggbag_t          *ab_divisor,
    const sk_aggbag_div_zero_t *div_zero);


/**
 *    Return the type of the current field at position 'field_iter'.
 *    Return SKAGGBAG_FIELD_INVALID if 'field_iter' is NULL or if it
 *    is not positioned on a valid key field or counter field.
 */
sk_aggbag_type_t
skAggBagFieldIterGetType(
    const sk_aggbag_field_t    *field_iter);


/**
 *    Set 'field_iter' to the next field that comprises the key or the
 *    counter and return SK_ITERATOR_OK if a field exists or return
 *    SK_ITERATOR_NO_MORE_ENTRIES if all fields have been visited.
 */
int
skAggBagFieldIterNext(
    sk_aggbag_field_t  *field_iter);


/**
 *    Reset the iterator 'field_iter' that supports iterating over the
 *    fields that comprise the key or counter.  This function sets the
 *    iterator to point at the first field in the key or counter.
 *
 *    Since SiLK 3.17.0.
 */
void
skAggBagFieldIterReset(
    sk_aggbag_field_t  *field_iter);


/**
 *    Return a description of the field type 'field_type'.  The returned value
 *    is a constant string that the caller must not modify.  Return NULL if
 *    the field type is not known.
 *
 *    Since SiLK 3.22.0.
 */
const char *
skAggBagFieldTypeGetDescription(
    sk_aggbag_type_t    field_type);

/**
 *    Return the key and counter disposition of the field type 'field_type'.
 *    That is, returns SK_AGGBAG_KEY if 'field_type' is a key or
 *    SK_AGGBAG_COUNTER if 'field_type' is a counter.  Returns 0 if
 *    'field_type' is not a known field type.
 *
 *    This function may also return (SK_AGGBAG_KEY|SK_AGGBAG_COUNTER) if a
 *    field may be either a key or a counter, though no fields in SiLK 3.22.0
 *    support that.
 *
 *    Since SiLK 3.22.0.
 */
unsigned int
skAggBagFieldTypeGetDisposition(
    sk_aggbag_type_t    field_type);

/**
 *    Return the name associated with the field type 'field_type'.  The
 *    returned value is a constant string that the caller must not modify.
 *    Return NULL if the field type is not known.
 */
const char *
skAggBagFieldTypeGetName(
    sk_aggbag_type_t    field_type);

/**
 *    Bind the iterator 'type_iter' to visit each type of key field or
 *    counter field that the AggBag code supports.  The
 *    'key_counter_flag' parameter must be either SK_AGGBAG_KEY or
 *    SK_AGGBAG_COUNTER to specify which field types to visit.
 *
 *    The caller should create the iterator on the stack and pass its
 *    address to this function.
 *
 *    Do nothing if 'type_iter' is NULL or 'key_counter_flag' is an
 *    invalid value.
 */
void
skAggBagFieldTypeIteratorBind(
    sk_aggbag_type_iter_t  *type_iter,
    unsigned int            key_counter_flag);

/**
 *    Move the type iterator 'type_iter' to the first/next type, set
 *    the referent of 'field_type' to that type and return the name of
 *    the type.  Set the referent of 'field_type' to
 *    SKAGGBAG_FIELD_INVALID and return NULL when all types have been
 *    visitied.
 *
 *    To use this function, the iterator must first be bound via
 *    skAggBagFieldTypeIteratorBind().
 */
const char *
skAggBagFieldTypeIteratorNext(
    sk_aggbag_type_iter_t  *type_iter,
    sk_aggbag_type_t       *field_type);

/**
 *    Move the field type iterator 'type_iter' to the beginning of the
 *    AggBag so that skAggBagIteratorNext() returns the first key and
 *    counter pair in the AggBag.  Do nothing if 'iter' is NULL.
 */
void
skAggBagFieldTypeIteratorReset(
    sk_aggbag_type_iter_t  *type_iter);


/**
 *    Set all values in 'counter' to 0 and initialize
 *    'counter_field_iter' to iterate over the fields that comprise
 *    the aggregate counter in 'ab'.  The parameters 'counter' or
 *    'counter_field_iter' may be NULL.
 *
 *    After calling this function, the iterator is pointed at the
 *    first field in the counter, and one may set the value of that
 *    field using one of the skAggBagAggregateSetFOO() functions.
 *    Calling skAggBagFieldIterNext() moves the iterator to the second
 *    field in the counter and returns SK_ITERATOR_OK or returns
 *    SK_ITERATOR_NO_MORE_ENTRIES if the counter contains a single
 *    field.
 *
 *    This function does not modify 'counter' and 'counter_field_iter'
 *    if 'ab' is NULL.
 *
 *    Use skAggBagInitializeKey() to initialize the key.
 */
void
skAggBagInitializeCounter(
    const sk_aggbag_t      *ab,
    sk_aggbag_aggregate_t  *counter,
    sk_aggbag_field_t      *counter_field_iter);


/**
 *    Set all values in 'key' to 0 and initialize 'key_field_iter' to
 *    iterate over the fields that comprise the aggregate key in 'ab'.
 *    The parameters 'key' or 'key_field_iter' may be NULL.
 *
 *    After calling this function, the iterator is pointed at the
 *    first field in the key, and one may set the value of that field
 *    using one of the skAggBagAggregateSetFOO() functions.  Calling
 *    skAggBagFieldIterNext() moves the iterator to the second field in
 *    the key and returns SK_ITERATOR_OK or returns
 *    SK_ITERATOR_NO_MORE_ENTRIES if the key contains a single field.
 *
 *    This function does not modify 'key' and 'key_field_iter' if 'ab'
 *    is NULL.
 *
 *    Use skAggBagInitializeCounter() to initialize the counter.
 */
void
skAggBagInitializeKey(
    const sk_aggbag_t      *ab,
    sk_aggbag_aggregate_t  *key,
    sk_aggbag_field_t      *key_field_iter);


/**
 *    Bind the iterator 'iter' to visit the contents of the AggBag
 *    data structure 'ab'.  The caller should create the iterator on
 *    the stack, initialize it with the SK_AGGBAG_ITER_INITIALIZER,
 *    and pass its address to this function.
 *
 *    The caller may use skAggBagIteratorNext() to move the first/next
 *    key and counter pair in the AggBag.
 *
 *    Once the contents have been visited or the caller has finished
 *    with the iterator, the caller must use skAggBagIteratorFree() to
 *    free the memory allocated by this function.
 *
 *    Do nothing if 'iter' or 'ab' are NULL.
 */
void
skAggBagIteratorBind(
    sk_aggbag_iter_t       *iter,
    const sk_aggbag_t      *ab);

/**
 *    Free the memory used by the AggBag contents iterator 'iter' that
 *    was allocated by skAggBagIteratorBind().  For this function to
 *    work correctly on an iterator that was not bound, the 'iter'
 *    should be allocated on the stack and initialized with
 *    SK_AGGBAG_ITER_INITIALIZER.  Do nothing if 'iter' is NULL.
 */
void
skAggBagIteratorFree(
    sk_aggbag_iter_t   *iter);

/**
 *    Move the AggBag contents iterator 'iter' to the first or next
 *    key and counter pair in the AggBag.  Return SK_ITERATOR_OK if
 *    the move was successful or SK_ITERATOR_NO_MORE_ENTRIES if all
 *    key/counter pairs have been visited.  Do nothing if 'iter' is
 *    NULL.
 *
 *    To use this function, the iterator must first be bound to an
 *    AggBag via skAggBagIteratorBind().
 */
int
skAggBagIteratorNext(
    sk_aggbag_iter_t   *iter);

/**
 *    Move the AggBag contents iterator 'iter' to the beginning of the
 *    AggBag so that skAggBagIteratorNext() returns the first key and
 *    counter pair in the AggBag.  Do nothing if 'iter' is NULL.
 */
void
skAggBagIteratorReset(
    sk_aggbag_iter_t   *iter);


/**
 *    In the AggBag 'ab', add to each counter associated with 'key' the values
 *    in 'counter'.  If 'key' does not exist in 'ab', insert it into 'ab' and
 *    set its values to those in 'counter'.  Set a counter to the maximum
 *    supported by the AggBag if the computed sum would exceed the maximum.
 *
 *    If 'new_counter' is not NULL, the new value of the counter is copied
 *    into that location.  'new_counter' is unchanged when this function turns
 *    a value other than SKAGGBAG_OK.
 *
 *    Return SKAGGBAG_E_UNDEFINED_KEY or SKAGGBAG_E_UNDEFINED_COUNTER if 'ab'
 *    has not had its key or counter fields defined.
 *
 *    Return SKAGGBAG_E_FIELDS_DIFFER_KEY or SKAGGBAG_E_FIELDS_DIFFER_COUNTER
 *    when 'ab' has different fields that 'key' or 'counter'.
 *
 *    Return SKAGGBAG_E_NULL_PARM when any required function parameter is
 *    NULL.
 */
int
skAggBagKeyCounterAdd(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    sk_aggbag_aggregate_t          *new_counter);

/**
 *    In the AggBag 'ab', divide the counters associated with 'key' by the
 *    values in 'counter'.  If 'key' does not exist in 'ab', take no action
 *    and return SKAGGBAG_OK.  Quotients are rounded to the nearest integer
 *    (0.5 always rounds up). and quotients less than 0.5 become zero.
 *
 *    If a value in 'counter' is zero, use 'div_zero' as the resolution: Leave
 *    the counter in 'ab' unchanged when the action is
 *    SKAGGBAG_DIV_ZERO_NOCHANGE; set the counter in 'ab' to the specified
 *    value when the action is SKAGGBAG_DIV_ZERO_VALUE; remove 'key' from 'ab'
 *    when the action is SKAGGBAG_DIV_ZERO_DELETE, and return
 *    SKAGGBAG_E_DIVIDE_BY_ZERO when the action is SKAGGBAG_DIV_ZERO_ERROR.
 *
 *    If 'new_counter' is not NULL, the new value of the counter is copied
 *    into that location.  When 'key' is removed from 'ab' because of division
 *    by zero, all values in 'new_counter' are set to 0.  'new_counter' is
 *    unchanged when this function turns a value other than SKAGGBAG_OK.
 *
 *    Since SiLK 3.22.0.
 */
int
skAggBagKeyCounterDivide(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    const sk_aggbag_div_zero_t     *div_zero,
    sk_aggbag_aggregate_t          *new_counter);

/**
 *    Fill 'counter' with the value that 'key' has in the AggBag 'ab'.
 *
 *    If 'key' is not in 'ab', set fields in 'counter' to 0 and return
 *    not found.  Otherwise, return SKAGGBAG_OK.
 */
int
skAggBagKeyCounterGet(
    const sk_aggbag_t              *ab,
    const sk_aggbag_aggregate_t    *key,
    sk_aggbag_aggregate_t          *counter);

/**
 *    Remove the counter associated with 'key' from the AggBag 'ab'.
 */
int
skAggBagKeyCounterRemove(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key);

/**
 *    In the AggBag 'ab', set the counter associated with 'key' to the
 *    value 'counter', overwriting the current counter value, if any.
 *    If 'counter' is non-zero, create 'key' if it does not already
 *    exist in 'bag'.  If 'counter' is 0, remove 'key' if it exists in
 *    'bag'; otherwise, do nothing.
 */
int
skAggBagKeyCounterSet(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter);

/**
 *    In the AggBag 'ab', subtract from the counters associated with 'key' the
 *    values in 'counter'.  If 'key' is not in 'ab', take no action and return
 *    SKAGGBAG_OK.  Set a counter to zero if the computed difference would
 *    result in negative number.
 *
 *    If 'new_counter' is not NULL, the new value of the counter is copied
 *    into that location.  'new_counter' is unchanged when 'key' is not in
 *    'ab' or when this function turns a value other than SKAGGBAG_OK.
 *
 *    Return SKAGGBAG_E_UNDEFINED_KEY or SKAGGBAG_E_UNDEFINED_COUNTER if 'ab'
 *    has not had its key or counter fields defined.
 *
 *    Return SKAGGBAG_E_FIELDS_DIFFER_KEY or SKAGGBAG_E_FIELDS_DIFFER_COUNTER
 *    when 'ab' has different fields that 'key' or 'counter'.
 *
 *    Return SKAGGBAG_E_NULL_PARM when any required function parameter is
 *    NULL.
 */
int
skAggBagKeyCounterSubtract(
    sk_aggbag_t                    *ab,
    const sk_aggbag_aggregate_t    *key,
    const sk_aggbag_aggregate_t    *counter,
    sk_aggbag_aggregate_t          *new_counter);


/**
 *    Read a serialized AggBag from the file specified by 'filename'
 *    into a newly created AggBag structure and set the referent of
 *    'ab' to its location.  This function is a wrapper around
 *    skBagRead().
 *
 *    The caller must use skAggBagDestroy() to free the AggBag once it
 *    is no longer needed.
 */
int
skAggBagLoad(
    sk_aggbag_t           **ab,
    const char             *filename);

/**
 *    Bind 'ab_opts' to the AggBag 'ab'.  'ab_opts' specify how the
 *    AggBag will be written to disk.  If no options are bound to an
 *    AggBag, the AggBag uses default values when writing the AggBag.
 *
 *    The AggBag 'ab' does not copy the 'ab_options'; it simply
 *    maintains a pointer to them, and it references the options when
 *    a call to skAggBagSave() or skAggBagWrite() is made.
 */
void
skAggBagOptionsBind(
    sk_aggbag_t                *ab,
    const sk_aggbag_options_t  *ab_opts);

/**
 *    Register options that affect how binary AggBags are written.
 *    The 'ab_opts' parameter is required; it is initialized to the
 *    default values.
 *
 *    Prior to calling this function, the caller should set the
 *    'existing_silk_files' member of the structure to either 0 or 1.
 *    The value 1 indicates the application works with existing
 *    AggBags (e.g., rwaggbagtool) or existing SiLK Flow files
 *    (rwaggbag); the value 0 indicates the application creates new
 *    AggBags (e.g., rwaggbagbuild).  If the value is non-zero, the
 *    --notes-strip option is provided.
 */
int
skAggBagOptionsRegister(
    sk_aggbag_options_t    *ab_opts);

/**
 *    Free any memory or internal state used by the AggBag options.
 */
void
skAggBagOptionsTeardown(
    void);

/**
 *    Print usage information for the command line switches registered
 *    by skAggBagOptionsRegister() to the specified file handle.
 */
void
skAggBagOptionsUsage(
    FILE               *fh);

/**
 *    Read a serialized AggBag from the input stream 'stream' into a
 *    newly created AggBag structure and set the referent of 'ab' to
 *    its location.
 *
 *    The caller must use skAggBagDestroy() to free the AggBag once it
 *    is no longer needed.
 *
 *
 *    See also skBagLoad().
 */
int
skAggBagRead(
    sk_aggbag_t           **ab,
    skstream_t             *stream);

/**
 *    Serialize the AggBag structure 'ab' to the file specified by
 *    'filename'.  This function is a wrapper around skBagWrite().
 */
int
skAggBagSave(
    const sk_aggbag_t      *ab,
    const char             *filename);


/**
 *    Set the key fields of the AggBag 'ab' to the list of
 *    'field_count' values in in 'fields'.
 */
int
skAggBagSetKeyFields(
    sk_aggbag_t            *ab,
    unsigned int            field_count,
    const sk_aggbag_type_t  fields[]);

/**
 *    Set the counter fields of the AggBag 'ab' to the list of
 *    'field_count' values in in 'fields'.
 */
int
skAggBagSetCounterFields(
    sk_aggbag_t            *ab,
    unsigned int            field_count,
    const sk_aggbag_type_t  fields[]);


/**
 *    Return a static string that describes the error associated with
 *    the error code 'err_code.
 */
const char *
skAggBagStrerror(
    int                 err_code);


/**
 *    Subtract the AggBag 'ab_subtrahend' from the AggBag 'ab_minuend'.
 *
 *    For each key common to 'ab_subtrahend' and 'ab_minuend',
 *    subtract the value of the key's counter in 'ab_subtrahend' from
 *    the value of the key's counter in 'ab_minuend'.  Remove a key
 *    from 'ab_minuend' if that key's counter is less than or equal to
 *    the key's counter in 'ab_subtrahend'.
 */
int
skAggBagSubtractAggBag(
    sk_aggbag_t        *ab_minuend,
    const sk_aggbag_t  *ab_subtrahend);


/**
 *    Serialize the AggBag structure 'ab' to the output stream
 *    'stream'.  The caller may set the compression method of 'stream'
 *    before calling this function.
 *
 *
 *    See also skBagSave().
 */
int
skAggBagWrite(
    const sk_aggbag_t      *ab,
    skstream_t             *stream);


/*
 *    Definifition of the type for sk_aggbag_aggregate_t so that the
 *    aggregate may be created on the stack.  The caller must treat
 *    the internals of this type as opaque.
 */
struct sk_aggbag_aggregate_st {
    const void         *opaque;
    uint8_t             data[SKAGGBAG_AGGREGATE_MAXLEN];
};

/*
 *    Definifition of the type for sk_aggbag_field_t so that the field
 *    iterator may be created on the stack.  The caller must treat the
 *    internals of this type as opaque.
 */
struct sk_aggbag_field_st {
    const void         *opaque;
    size_t              pos;
};

/*
 *    Definifition of the type for sk_aggbag_iter_t so that the AggBag
 *    content iterator may be created on the stack.  The caller must
 *    treat the internals of this type as opaque.
 *
 *    When creating an sk_aggbag_iter_t on the stack, the caller is
 *    expected to initialize it to SK_AGGBAG_ITER_INITIALIZER.
 */
struct sk_aggbag_iter_st {
    const void              *opaque;
    sk_aggbag_aggregate_t    key;
    sk_aggbag_aggregate_t    counter;
    sk_aggbag_field_t        key_field_iter;
    sk_aggbag_field_t        counter_field_iter;
};


/*
 *    Definifition of the type for sk_aggbag_type_iter_t so that the
 *    type iterator may be created on the stack.  The caller must
 *    treat the internals of this type as opaque.
 */
struct sk_aggbag_type_iter_st {
    sk_aggbag_type_t    pos;
    unsigned int        key_counter_flag;
};


typedef enum sk_aggbag_retval_en {
    /**
     *    Command succeeded
     */
    SKAGGBAG_OK,
    /**
     *    Memory allocation failed
     */
    SKAGGBAG_E_ALLOC,
    /**
     *    NULL or invalid parameter passed to function
     */
    SKAGGBAG_E_NULL_PARM,
    /**
     *    Aggregate Bag's fields are immutable
     */
    SKAGGBAG_E_FIXED_FIELDS,
    /**
     *    Aggregate Bag's key fields are undefined
     */
    SKAGGBAG_E_UNDEFINED_KEY,
    /**
     *    Aggregate Bag's counter fields are undefined
     */
    SKAGGBAG_E_UNDEFINED_COUNTER,
    /**
     *    Field has the incorrect type (key vs counter)
     */
    SKAGGBAG_E_FIELD_CLASS,
    /**
     *    Sets of key fields do not match
     */
    SKAGGBAG_E_FIELDS_DIFFER_KEY,
    /**
     *    Sets of counter fields do not match
     */
    SKAGGBAG_E_FIELDS_DIFFER_COUNTER,
    /**
     *    Incorrect get or set function called for field type
     */
    SKAGGBAG_E_GET_SET_MISMATCH,
    /**
     *    Iterator points to an invalid field
     */
    SKAGGBAG_E_BAD_INDEX,
    /**
     *    Error while reading an Aggregate Bag from a stream or file
     */
    SKAGGBAG_E_READ,
    /**
     *    Error while writing an Aggregate Bag to a stream or file
     */
    SKAGGBAG_E_WRITE,
    /**
     *    File header contains an unexpected value
     */
    SKAGGBAG_E_HEADER,
    /**
     *    Unexpected error during insert
     */
    SKAGGBAG_E_INSERT,
    /**
     *    SiLK is compiled without IPv6 support
     */
    SKAGGBAG_E_UNSUPPORTED_IPV6,
    /**
     *    Aggregate Bag divisor has a value of 0 or is absent
     *
     *    Since SiLK 3.22.0.
     */
    SKAGGBAG_E_DIVIDE_BY_ZERO
} sk_aggbag_retval_t;


#ifdef __cplusplus
}
#endif
#endif /* _SKAGGBAG_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
