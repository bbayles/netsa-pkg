/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
**  skbag.h
**
**    The Bag API maps keys to counters.
**
**    For keys of 32-bits or less, the data structure is a tree whose
**    depth depends on the number of octets in the key.  A key's value
**    is encoded into the tree's structure.  At the leaves, the tree
**    contains blocks of counters to hold the counter associated with
**    a key.
**
**    The API defined in this file is current as of SiLK 3.0.
**
**    As of SiLK 3.0, some older functions and types have been
**    deprecated.  Those functions and types are declared in the
**    header file silk/bagtree.h.
**
**    Original implementation:
**      Christopher Lee
**      2004-11-04
**
**
*/
#ifndef _SKBAG_H
#define _SKBAG_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKBAG_H, "$SiLK: skbag.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>

/**
 *  @file
 *
 *    A mapping from a key to a counter.  The key can be a 8, 16, or
 *    32 bit integer or an IPv4 or IPv6 address.  The counter is an
 *    unsigned 64 bit value.
 *
 *    This file is part of libsilk.
 */


/* DEFINES AND TYPEDEFS */

/**
 *    The Bag object maps keys to counters
 */
typedef struct skBag_st skBag_t;


/**
 *    Nearly every Bag function returns one of the following values to
 *    denote the status of invoking the function.
 */
typedef enum skBagErr_en {
    /** Success */
    SKBAG_OK = 0,
    /** Memory allocation error */
    SKBAG_ERR_MEMORY = 1,
    /** No more entries in bag */
    SKBAG_ERR_KEY_NOT_FOUND = 2,
    /** Invalid argument to function */
    SKBAG_ERR_INPUT = 3,
    /** Overflow/Underflow in counter */
    SKBAG_ERR_OP_BOUNDS = 4,
    /** Error writing to stream */
    SKBAG_ERR_OUTPUT = 5,
    /** Error reading from stream */
    SKBAG_ERR_READ = 6,
    /** File header values incompatible with this compile of SiLK */
    SKBAG_ERR_HEADER = 7,
    /** Key out of range for bag and auto-conversion disabled */
    SKBAG_ERR_KEY_RANGE = 8,
    /** Bag modified during iteration */
    SKBAG_ERR_MODIFIED = 9
} skBagErr_t;


/**
 *    The following structure is used to iterate over the key/counter
 *    pairs in a Bag.
 */
typedef struct skBagIterator_st skBagIterator_t;


/**
 *    The Bag API supports adding keys and counters whose types are
 *    one of an enumerated set of values.  When setting or getting a
 *    key or counter, the caller must specify the type of key or
 *    counter the caller is providing or wants to receive.
 *
 *    When getting a key or counter, the caller may specify the
 *    special ANY type to have the Bag return the "natural" type for
 *    the data structure; the Bag sets the type to the type of
 *    value returned.
 *
 *    The following enumerations list the types for keys and
 *    counters.
 */
typedef enum skBagKeyType_en {
    SKBAG_KEY_ANY     = 0,
    SKBAG_KEY_U8      = 1,
    SKBAG_KEY_U16     = 2,
    SKBAG_KEY_U32     = 4,
    SKBAG_KEY_IPADDR  = 16
} skBagKeyType_t;

typedef enum skBagCounterType_en {
    SKBAG_COUNTER_ANY     = 0,
    SKBAG_COUNTER_U64     = 8
} skBagCounterType_t;


/**
 *    The following types specify how keys and counters are to be
 *    provided to and received from the Bag, as of SiLK 3.0.
 */
typedef struct skBagTypedKey_st {
    skBagKeyType_t              type;
    union skBagTypedKey_un {
        uint8_t     u8;
        uint16_t    u16;
        uint32_t    u32;
        uint64_t    u64; /* unsupported */
        skipaddr_t  addr;
    }                           val;
} skBagTypedKey_t;

typedef struct skBagTypedCounter_st {
    skBagCounterType_t          type;
    union skBagTypedCounter_un {
        uint64_t    u64;
    }                           val;
} skBagTypedCounter_t;


/*
 *    The older SiLK 2.x Bag API (see bagtree.h) used a fixed size for
 *    the key and counter stored in the bag.  Those types are defined
 *    here.
 */

typedef uint32_t skBagKey_t;
typedef uint64_t skBagCounter_t;


/*
 *    The following specify the numeric range of counters in a Bag.
 *
 *    Note that the maximum counter in SiLK 3.0 is less than that in
 *    SiLK 2.0.
 *
 *    Although SKBAG_COUNTER_MIN is 0, setting the counter of a key is
 *    0 effectively removes the key from the bag.
 */

#define SKBAG_COUNTER_MIN   UINT64_C(0)
#define SKBAG_COUNTER_MAX   (UINT64_MAX - UINT64_C(1))


/*
 *    The following specify the numeric range of keys in a Bag that
 *    does not hold IPv6 addresses.
 */

#define SKBAG_KEY_MIN       UINT32_C(0)
#define SKBAG_KEY_MAX       UINT32_MAX


/**
 *    The Bag data-structure maintains a key-type and counter-type
 *    that specify what the key and counter represent.  For example, a
 *    Bag could map each source-port value to the number of flows seen
 *    for that port.
 *
 *    The following enumeration lists those types.
 */
typedef enum skBagFieldType_en {
    /* the following correspond to values in rwascii.h */
    SKBAG_FIELD_SIPv4 = 0,
    SKBAG_FIELD_DIPv4,
    SKBAG_FIELD_SPORT,
    SKBAG_FIELD_DPORT,
    SKBAG_FIELD_PROTO = 4,
    SKBAG_FIELD_PACKETS,
    SKBAG_FIELD_BYTES,
    SKBAG_FIELD_FLAGS,
    SKBAG_FIELD_STARTTIME = 8,
    SKBAG_FIELD_ELAPSED,
    SKBAG_FIELD_ENDTIME,
    SKBAG_FIELD_SID,
    SKBAG_FIELD_INPUT = 12,
    SKBAG_FIELD_OUTPUT,
    SKBAG_FIELD_NHIPv4,
    SKBAG_FIELD_INIT_FLAGS,
    SKBAG_FIELD_REST_FLAGS = 16,
    SKBAG_FIELD_TCP_STATE,
    SKBAG_FIELD_APPLICATION,
    SKBAG_FIELD_FTYPE_CLASS,
    SKBAG_FIELD_FTYPE_TYPE = 20,
    /*
     *  SKBAG_FIELD_STARTTIME_MSEC = 21,
     *  SKBAG_FIELD_ENDTIME_MSEC,
     *  SKBAG_FIELD_ELAPSED_MSEC,
     */
    SKBAG_FIELD_ICMP_TYPE_CODE = 24,
    /* the above correspond to values in rwascii.h */

    SKBAG_FIELD_SIPv6,
    SKBAG_FIELD_DIPv6,
    SKBAG_FIELD_NHIPv6,
    SKBAG_FIELD_RECORDS = 28,
    SKBAG_FIELD_SUM_PACKETS,
    SKBAG_FIELD_SUM_BYTES,
    SKBAG_FIELD_SUM_ELAPSED,

    SKBAG_FIELD_ANY_IPv4 = 32,
    SKBAG_FIELD_ANY_IPv6,
    SKBAG_FIELD_ANY_PORT,
    SKBAG_FIELD_ANY_SNMP,
    SKBAG_FIELD_ANY_TIME = 36,

    SKBAG_FIELD_SIP_COUNTRY,
    SKBAG_FIELD_DIP_COUNTRY,
    SKBAG_FIELD_ANY_COUNTRY,

    SKBAG_FIELD_SIP_PMAP = 40,
    SKBAG_FIELD_DIP_PMAP,
    SKBAG_FIELD_ANY_IP_PMAP,

    SKBAG_FIELD_SPORT_PMAP,
    SKBAG_FIELD_DPORT_PMAP = 44,
    SKBAG_FIELD_ANY_PORT_PMAP = 45,

    SKBAG_FIELD_CUSTOM = 255
} skBagFieldType_t;


/**
 *    The following structure is used to iterate over the field types
 *    listed above.
 *
 *    The structure is defined here so that the iterator may be
 *    created on the stack.  However, the structure is subject to
 *    change and the caller should treat the interals of this
 *    structure as opaque.
 */
typedef struct skBagFieldTypeIterator_st {
    skBagFieldType_t    val;
    uint8_t             no_more_entries;
} skBagFieldTypeIterator_t;


/**
 *    In skBagCounterFieldName(), skBagFieldTypeAsString(), and
 *    skBagKeyFieldName(), using a character buffer of at least this
 *    size is guaranteed to hold all the possible field type strings.
 */
#define SKBAG_MAX_FIELD_BUFLEN  32


/**
 *    Value returned by skBagFieldTypeGetLength() when the field type
 *    is SKBAG_FIELD_CUSTOM.
 */
#define SKBAG_OCTETS_CUSTOM         (SIZE_MAX-1)


/**
 *    Value returned by skBagFieldTypeGetLength() when the field type
 *    is not recognized.
 */
#define SKBAG_OCTETS_UNKNOWN        SIZE_MAX


/**
 *    In skBagCreateTyped() and skBagModify(), the value to use for
 *    'key_octets' or 'counter_octets' that indicates the size should
 *    be the default size for the 'key_type' or 'counter_type',
 *    respectively.
 */
#define SKBAG_OCTETS_FIELD_DEFAULT  0


/**
 *    In skBagModify(), the value to use for 'key_octets' or
 *    'counter_octets' that indicates the size should remain
 *    unchagned.
 */
#define SKBAG_OCTETS_NO_CHANGE      (SIZE_MAX-2)


/**
 *    The signature of a callback used by skBagAddBag() when adding
 *    two counters causes an overflow.
 *
 *    The value in 'key' is the key where the overflow is occuring,
 *    'in_out_counter' is the current value of the counter in the
 *    destination bag, 'in_counter' is the current value in the source
 *    bag, and 'cb_data' is the caller-supplied parameter to
 *    skBagAddBag().
 *
 *    The callback should modify 'in_out_counter' to the value the
 *    caller wants to insert into the destination bag for 'key'.  If
 *    the callback returns any value other than SKBAG_OK,
 *    skBagAddBag() stops processing and returns that value.
 */
typedef skBagErr_t
(*skBagBoundsCallback_t)(
    const skBagTypedKey_t      *key,
    skBagTypedCounter_t        *in_out_counter,
    const skBagTypedCounter_t  *in_counter,
    void                       *cb_data);


/**
 *    The signature of a callback used by skBagProcessStreamTyped()
 *    when reading a bag from a stream.  This callback is invoked
 *    after the stream's header has been read and before processing
 *    any entries in the bag.
 *
 *    If this function returns a value other than SKBAG_OK, processing
 *    of the bag stops.
 *
 *    The 'fake_bag' argument is partially constructed bag that may
 *    be used to query the type and/or size of the key and counter in
 *    the bag that is being read.  This parameter must be considered
 *    read-only.
 *
 *    The 'cb_data' parameter is provided for the caller to use.  It
 *    is the parameter specified to skBagProcessStream().
 */
typedef skBagErr_t
(*skBagStreamInitFunc_t)(
    const skBag_t          *fake_bag,
    void                   *cb_data);


/**
 *    The signature of a callback used by skBagProcessStreamTyped()
 *    when reading a bag from a stream.  This callback is invoked for
 *    each entry (that is, each key/counter pair) read from the bag.
 *
 *    The 'fake_bag' argument is partially constructed bag that may be
 *    used to query the type and/or size of the key and counter in the
 *    bag that is being read.  This parameter must be considered
 *    read-only.
 *
 *    The 'key' parameter is a pointer to the current key.  If the bag
 *    contains IPv6 addresses, the type of the key is
 *    SKBAG_KEY_IPADDR.  Otherwise, the type of the key is
 *    SKBAG_KEY_U32.
 *
 *    The 'counter' paramter is a pointer to the current counter.
 *
 *    The 'cb_data' parameter is provided for the caller to use.  It
 *    is the parameter specified to skBagProcessStream().
 */
typedef skBagErr_t
(*skBagStreamEntryFunc_t)(
    const skBag_t              *fake_bag,
    const skBagTypedKey_t      *key,
    const skBagTypedCounter_t  *counter,
    void                       *cb_data);


/**
 *    Some features of the Bag are implemented as macros, and those
 *    macros use the following variables.  The variables are not
 *    considered part of the supported API, and they are not for
 *    public use.
 */
extern const skBagTypedCounter_t *skbag_counter_zero;
extern const skBagTypedCounter_t *skbag_counter_incr;


/* FUNCTION DECLARATIONS */

/**
 *    Add the key/counter pairs of the in-memory bag 'src_bag' to the
 *    in-memory bag 'dest_bag', in effect 'dest_bag' += 'src_bag'.
 *
 *    The key_type, counter_type, key_octets, and counter_octets of
 *    'dest_bag' may change as a result of this operation.
 *
 *    The 'bounds_cb' callback may be NULL.  When it is specified, it
 *    is invoked whenever summing two counters causes an overflow
 *    (that is, when skBagCounterAdd() returns SKBAG_ERR_OP_BOUNDS).
 *    The callback is invoked with the key, the counter from
 *    'dest_bag', the counter from 'src_bag', and the 'cb_data'.  The
 *    callback should modify the counter from 'dest_bag' to the value
 *    the caller wants to insert into 'dest_bag' and return SKBAG_OK,
 *    and the function then attempts to set the key in 'dest_bag'
 *    to that value.  If the insert succeeds, processing continues;
 *    otherwise the result of the attempt to set the key is
 *    returned.  If 'bounds_cb' returns a value other than SKBAG_OK,
 *    that value is returned.
 *
 *    Return SKBAG_OK on success.  Return SKBAG_ERR_INPUT if
 *    'dest_bag' or 'src_bag' is NULL.  Return SKBAG_ERR_KEY_RANGE if
 *    the key octet width in 'src' is larger than that in 'dest' and
 *    auto-conversion is disabled in 'dest'.  Return SKBAG_ERR_MEMORY
 *    if a key cannot be inserted into 'dest_bag'.  Return
 *    SKBAG_ERR_OP_BOUNDS if adding two counters causes an overflow
 *    and the 'bounds_cb' callback parameter is NULL.
 */
skBagErr_t
skBagAddBag(
    skBag_t                *dest,
    const skBag_t          *src,
    skBagBoundsCallback_t   bounds_cb,
    void                   *cb_data);


/**
 *    Read a serialized Bag from the input stream 'stream' and add
 *    its key/counter pairs to the existing Bag 'bag'.  New keys are
 *    created if required; existing keys have their values
 *    summed.
 *
 *    Return SKBAG_ERR_INPUT if 'bag' or 'stream_in' is NULL.  Return
 *    SKBAG_ERR_OP_BOUNDS if summing counters results in an overflow.
 *    Return SKBAG_ERR_KEY_RANGE if auto-conversion is disabled on
 *    'bag' (see skBagAutoConvertDisable()) and the key size in 'bag'
 *    is smaller than the key size of the bag in 'stream_in'.
 */
skBagErr_t
skBagAddFromStream(
    skBag_t            *bag,
    skstream_t         *stream_in);


/**
 *    Prevent auto-conversion of keys from happening on 'bag'.
 *
 *    By default, attempting to insert a key whose octet width is
 *    larger than the Bag current supports promotes the keys in the
 *    Bag to hold the larger key.  Such an auto-conversion may occur
 *    when inserting an IPv6 address into a uint32_t Bag, or when
 *    inserting a uint32_t key into an uint8_t Bag.  This function
 *    disables this conversion.  An attempt to insert an unsupported
 *    key size into such a Bag returns SKBAG_ERR_KEY_RANGE.
 *
 *    See also skBagAutoConvertEnable() and
 *    skBagAutoConvertIsEnabled().
 */
void
skBagAutoConvertDisable(
    skBag_t            *bag);


/**
 *    Allow an attempt to insert a key whose octet width is larger
 *    than 'bag' currently support to succeed, promoting the keys in
 *    'bag' to the wider size.  This behavior is the default.
 *
 *    See also skBagAutoConvertDisable() and
 *    skBagAutoConvertIsEnabled().
 */
void
skBagAutoConvertEnable(
    skBag_t            *bag);


/**
 *    Return 1 if 'bag' automatically converts its keys' octet width
 *    to a larger size when an attempt is made to insert a larger key.
 *
 *    See also skBagAutoConvertDisable() and
 *    skBagAutoConvertEnable().
 */
int
skBagAutoConvertIsEnabled(
    const skBag_t      *bag);


/**
 *    Make a new bag that is a deep copy of src, and set the referent
 *    of 'dest' to it.
 */
skBagErr_t
skBagCopy(
    skBag_t           **dest,
    const skBag_t      *src);


/**
 *    Return the number of unique keys in 'bag'.
 */
uint64_t
skBagCountKeys(
    const skBag_t      *bag);


/**
 *    In 'bag', add to the counter associated with 'key' the value
 *    'counter_add'.  If 'key' does not exist in 'bag', insert it into
 *    'bag' and set its value to 'counter_add'.
 *
 *    If 'key' is larger than the maximum key currently supported by
 *    'bag', 'bag' is converted to a size capable of holding 'key'
 *    unless auto-conversion is disabled for 'bag'; see
 *    skBagAutoConvertEnable(), skBagAutoConvertDisable(), and
 *    skBagAutoConvertIsEnabled().
 *
 *    If 'new_counter' is not NULL, the new value of the counter is
 *    copied into that location.  'new_counter' is unchanged when this
 *    function turns a value other than SKBAG_OK.
 *
 *    Return SKBAG_OK on success.  Return SKBAG_ERR_MEMORY if the
 *    attempt to insert the key fails because of an allocation error.
 *    Return SKBAG_ERR_KEY_RANGE if the value in 'key' is larger than
 *    the octet width in 'bag' and auto-conversion is disabled in
 *    'bag'.  If the addition would cause the counter to overflow, the
 *    current value in 'bag' remains unchanged and SKBAG_ERR_OP_BOUNDS
 *    is returned.  Return SKBAG_ERR_INPUT if any input parameter
 *    (other than 'new_counter') is NULL, if the type of 'key' is
 *    SKBAG_KEY_ANY, if the type of 'counter' is SKBAG_COUNTER_ANY, or
 *    if 'counter' is larger than SKBAG_COUNTER_MAX.
 *
 *    See also skBagCounterSet() and skBagCounterSubtract().  The
 *    convenience wrapper skBagCounterIncrement() may be used to add 1
 *    to a key's counter.  Use skBagCounterGet() to get a key's
 *    counter.
 */
skBagErr_t
skBagCounterAdd(
    skBag_t                    *bag,
    const skBagTypedKey_t      *key,
    const skBagTypedCounter_t  *counter_add,
    skBagTypedCounter_t        *new_counter);


/**
 *    In 'bag', decrement the counter associated with 'key' by one.
 *    This is no-op if 'key' does not exist in 'bag'; that is, unlike
 *    skBagCounterSubtract(), this macro returns SKBAG_OK if 'key' is
 *    not in 'bag'.
 */
#define skBagCounterDecrement(dec_bag, dec_key)         \
    ((skBagCounterSubtract((dec_bag), (dec_key),        \
                           skbag_counter_incr, NULL)    \
      == SKBAG_ERR_INPUT)                               \
     ? SKBAG_ERR_INPUT : SKBAG_OK)


/**
 *    Return the number of octets the counter of 'bag' occupies
 *    for the in-core representation of 'bag'.
 */
size_t
skBagCounterFieldLength(
    const skBag_t      *bag);


/**
 *    Return the type of counter that 'bag' contains, and, if 'buf' is
 *    not NULL, fill 'buf' with a string representation of that type.
 *    The caller must specify the size of 'buf' in 'buflen'.  If 'buf'
 *    is too small to hold the string representation, 'buf' is filled
 *    with as much of the name as possible.
 *
 *    See also skBagCounterFieldType(), skBagKeyFieldName(), and
 *    skBagKeyFieldType().
 */
skBagFieldType_t
skBagCounterFieldName(
    const skBag_t      *bag,
    char               *buf,
    size_t              buflen);


/**
 *    Return the type of counter that 'bag' contains.
 *
 *    See also skBagCounterFieldName(), skBagKeyFieldType(), and
 *    skBagKeyFieldName().
 */
skBagFieldType_t
skBagCounterFieldType(
    const skBag_t      *bag);


/**
 *    Fill 'counter' with the value associated with 'key' in 'bag'.
 *    If 'key' is not in bag, set 'counter' to 0.  Return SKBAG_OK and
 *    set 'counter' to 0 when 'key' is outside the range supported by
 *    'bag'.
 *
 *    Return SKBAG_OK on success, or SKBAG_ERR_INPUT when any input
 *    parameter is NULL or when the type of 'key' or 'counter' is not
 *    recognized.
 *
 *    Use skBagCounterSet() to set a key's counter.  See also
 *    skBagCounterAdd() and skBagCounterSubtract().
 */
skBagErr_t
skBagCounterGet(
    const skBag_t          *bag,
    const skBagTypedKey_t  *key,
    skBagTypedCounter_t    *counter);


/**
 *    In 'bag', increment the counter associated with 'key' by one.
 *    Create the key and set its counter to 1 if the key does not
 *    exist in the bag.
 *
 *    This is a convenience wrapper around skBagCounterAdd(), which
 *    see for additional information.
 */
#define skBagCounterIncrement(inc_bag, inc_key)                      \
    skBagCounterAdd((inc_bag), (inc_key), skbag_counter_incr, NULL)


/**
 *    In 'bag', set the counter associated with 'key' to the value
 *    'counter'.  If 'counter' is non-zero, create 'key' if it does
 *    not already exist in 'bag'.  If 'counter' is 0, remove 'key' if
 *    it exists in 'bag'; otherwise, do nothing.
 *
 *    If 'key' is larger than the maximum key currently supported by
 *    'bag', 'bag' is converted to a size capable of holding 'key'
 *    unless auto-conversion in 'bag' is disabled; see
 *    skBagAutoConvertEnable(), skBagAutoConvertDisable(), and
 *    skBagAutoConvertIsEnabled().
 *
 *    Return SKBAG_OK on success.  Return SKBAG_ERR_MEMORY if there is
 *    an allocation error when inserting the 'key'.  Unless 'counter'
 *    is 0, return SKBAG_ERR_KEY_RANGE if the value in 'key' is larger
 *    than the octet width in 'bag' and auto-conversion is disabled in
 *    'bag'.  Return SKBAG_ERR_INPUT if any input parameter is NULL,
 *    if the type of 'key' is SKBAG_KEY_ANY, if the type of 'counter'
 *    is SKBAG_COUNTER_ANY, or if 'counter' is larger than
 *    SKBAG_COUNTER_MAX.
 *
 *    See also skBagCounterAdd() and skBagCounterSubtract().  Use
 *    skBagCounterGet() to get a key's counter.
 */
skBagErr_t
skBagCounterSet(
    skBag_t                    *bag,
    const skBagTypedKey_t      *key,
    const skBagTypedCounter_t  *counter);


/**
 *    In 'bag', subtract from the counter associated with 'key' the
 *    value 'counter_sub'.  When 'counter_sub' is non-zero, 'key' must
 *    exist in 'bag'; if it does not, SKBAG_ERR_OP_BOUNDS is returned.
 *    SKBAG_ERR_OP_BOUNDS is also returned when 'key' is outside the
 *    range of keys supported by 'bag'.
 *
 *    When 'counter_sub' is 0, return SKBAG_OK regardless of whether
 *    'key' is in 'bag' and, if 'new_counter' is not NULL, set it to
 *    the counter for 'key' if 'key' is in 'bag' or 0 otherwise.
 *
 *    If 'new_counter' is not NULL, the new value of the counter is
 *    copied into that location.  'new_counter' is unchanged when this
 *    function turns a value other than SKBAG_OK.
 *
 *    Return SKBAG_OK on success.  If the subtraction would cause the
 *    counter to become negative or if 'key' does not exist in 'bag',
 *    the counter in 'bag' is unchanged and SKBAG_ERR_OP_BOUNDS is
 *    returned.  Return SKBAG_ERR_INPUT if any input parameter is
 *    NULL, if the type of 'key' is SKBAG_KEY_ANY, if the type of
 *    'counter' is SKBAG_COUNTER_ANY, or if 'counter' is larger than
 *    SKBAG_COUNTER_MAX.
 *
 *    See also skBagCounterSet() and skBagCounterAdd().  The
 *    convenience wrapper skBagCounterDecrement() may be used to
 *    subtract 1 from a key's counter.  Use skBagCounterGet() to
 *    get a key's counter.
 */
skBagErr_t
skBagCounterSubtract(
    skBag_t                    *bag,
    const skBagTypedKey_t      *key,
    const skBagTypedCounter_t  *counter_sub,
    skBagTypedCounter_t        *new_counter);


/**
 *    Allocate memory for a new Bag and set the referent of 'bag' to
 *    it.  The type of the key and counter are set to
 *    SKBAG_FIELD_CUSTOM.  The bag is created with a 4 octet key and
 *    an 8 octet counter.
 *
 *    See also skBagCreateTyped().
 */
skBagErr_t
skBagCreate(
    skBag_t           **bag);


/**
 *    Allocate memory for a new Bag to hold a specific type of key and
 *    counter, each having the specified number of octets.  Set the
 *    referent of 'bag' to the newly allocated bag.
 *
 *    When 'key_type' is SKBAG_FIELD_CUSTOM, the value in 'key_octets'
 *    must be one of the supported key lengths.  Currently, the
 *    supported values for 'key_octets' are 1,2,4,16.  Note that
 *    'key_octets' of 8 is not supported.
 *
 *    When 'key_type' is not SKBAG_FIELD_CUSTOM, the value in
 *    'key_octets' must be a supported key length or the value may be
 *    SKBAG_OCTETS_FIELD_DEFAULT, indicating the bag should use the
 *    size returned by skBagFieldTypeGetLength('key_type').  If that
 *    function returns a length of 8, the bag uses a length of 4
 *    instead.
 *
 *    When 'counter_type' is SKBAG_FIELD_CUSTOM, the value in
 *    'counter_octets' must be specified as 8, as currently that is
 *    the only supported value for 'counter_octets'.
 *
 *    When 'counter_type' is not SKBAG_FIELD_CUSTOM, 'counter_octets'
 *    value must be either 8 or SKBAG_OCTETS_FIELD_DEFAULT.  The bag
 *    will use a 'counter_octets' value of 8.
 *
 *    The function returns SKBAG_OK on success.  It returns
 *    SKBAG_ERR_MEMORY if the bag cannot be allocated.  A return value
 *    of SKBAG_ERR_INPUT indicates the 'bag' parameter was NULL, the
 *    'key_type' or 'counter_type' was not recognized, or the
 *    'key_octets' or 'counter_octets' are not a supported value.
 */
skBagErr_t
skBagCreateTyped(
    skBag_t           **bag,
    skBagFieldType_t    key_type,
    skBagFieldType_t    counter_type,
    size_t              key_octets,
    size_t              counter_octets);


/**
 *    Free all memory associated with the Bag pointed to by 'bag' and
 *    set '*bag' to NULL.  This function does nothing when 'bag' is
 *    NULL or the memory that 'bag' points to is NULL.
 */
void
skBagDestroy(
    skBag_t           **bag);


/**
 *    Fill 'buf' with a string representation of the field-type
 *    'field'.  The caller must specify the size of 'buf' in 'buflen'.
 *    Return the value 'buf' when 'field' is a valid field type and
 *    'buflen' is large enough to hold the complete type name.
 *    Otherwise leave 'buf' unchanged and return NULL.
 */
char *
skBagFieldTypeAsString(
    skBagFieldType_t    field,
    char               *buf,
    size_t              buflen);


/**
 *    Return the standard number of octets required to hold the
 *    field-type 'field'.  Return SKBAG_OCTETS_CUSTOM if the field
 *    type is SKBAG_FIELD_CUSTOM.  Return SKBAG_OCTETS_UNKNOWN if
 *    'field' is not recognized.
 */
size_t
skBagFieldTypeGetLength(
    skBagFieldType_t    field);


/**
 *    Bind the iterator 'ft_iter' to iterate over the skBagFieldType_t
 *    values that this bag library supports.  Return SKBAG_OK unless
 *    'ft_iter' is NULL.
 */
skBagErr_t
skBagFieldTypeIteratorBind(
    skBagFieldTypeIterator_t   *ft_iter);


/**
 *    Move the iterator to the next skBagFieldType_t value.  Return
 *    SKBAG_OK on success; return SKBAG_ERR_KEY_NOT_FOUND if there are
 *    no more field types to vist; return SKBAG_ERR_INPUT if 'iter' is
 *    NULL.
 *
 *    If 'field_id' is not NULL, fill it with the skBagFieldType_t
 *    value.  If 'field_octets' is not NULL, fill it with the number
 *    of octets normally used by that field.  If 'field_name' is not
 *    NULL and 'field_name_len' is large enough to hold the entire
 *    field name, fill 'field_name' with the string representation of
 *    the type.
 */
skBagErr_t
skBagFieldTypeIteratorNext(
    skBagFieldTypeIterator_t   *iter,
    skBagFieldType_t           *field_id,
    size_t                     *field_octets,
    char                       *field_name,
    size_t                      field_name_len);


/**
 *    Reset 'iter' so it will revisit the skBagFieldType_t values.
 */
skBagErr_t
skBagFieldTypeIteratorReset(
    skBagFieldTypeIterator_t   *iter);


/**
 *    Find the field-type whose name is the string 'type_name'.  If
 *    'type_name' is not a valid field-type name, return
 *    SKBAG_ERR_INPUT; otherwise return SKBAG_OK.
 *
 *    If the argument 'field_type' is not NULL, fill its referent with
 *    the ID corresponding to 'name'.  If the argument 'field_octets'
 *    is not NULL, fill its referent with the number of octets that
 *    field normally occupies---that is, the result of calling
 *    skBagFieldTypeGetLength() on the field.
 */
skBagErr_t
skBagFieldTypeLookup(
    const char         *type_name,
    skBagFieldType_t   *field_type,
    size_t             *field_length);


/**
 *    Return the field type that should be used when two bags are
 *    merged.
 *
 *    This function assumes the bags are being added or subtracted.
 */
skBagFieldType_t
skBagFieldTypeMerge(
    skBagFieldType_t    field_type1,
    skBagFieldType_t    field_type2);


/**
 *    Create a new iterator to iterate over the bag 'bag' and store
 *    the iterator in the referent of 'iter'.  The iterator is
 *    initialized so that the first call to skBagIteratorNextTyped()
 *    returns the counter associated with the first key.
 *
 *    If the key size of the bag changes during iteration,
 *    SKBAG_ERR_MODIFIED is returned.  At that point, the
 *    iterator may be destroyed or reset.
 *
 *    If keys are added or removed during iteration, the entries may
 *    or may not be visited by the iterator.
 *
 *    The iterator visits the entries in 'bag' in order from the
 *    smallest key to the largest key.
 *
 *    Once iteration is complete, the caller must destroy the iterator
 *    by calling skBagIteratorDestroy().
 */
skBagErr_t
skBagIteratorCreate(
    const skBag_t      *bag,
    skBagIterator_t   **iter);


/**
 *    Similar to skBagIteratorCreate(), but the iterator does not make
 *    any guarantees on the order in which the iterator visits the
 *    entries.
 */
skBagErr_t
skBagIteratorCreateUnsorted(
    const skBag_t      *bag,
    skBagIterator_t   **iter);


/**
 *    Deallocate all memory associated with the bag iterator 'iter'.
 *    The function returns SKBAG_ERR_INPUT if the 'iter' parameter is
 *    NULL.
 */
skBagErr_t
skBagIteratorDestroy(
    skBagIterator_t    *iter);


/**
 *    Get the next key/counter pair associated with the given
 *    iterator, 'iter', store them in the referents of
 *    'key' and 'counter', respectively, and return SKBAG_OK.
 *
 *    The 'type' field of 'key' and 'counter' structures determine how
 *    the key and counter are returned.  If the key's type is
 *    SKBAG_KEY_ANY, 'key' is filled with an SKBAG_KEY_IPADDR for a
 *    bag containing IPv6 addresses and an SKBAG_KEY_U32 otherwise.
 *    'counter' is always filled with an SKBAG_COUNTER_U64.
 *
 *    If the range of keys does not fit into the specified type of
 *    'key', the iterator returns SKBAG_ERR_KEY_NOT_FOUND once all
 *    values that fit into 'key' have been visited.  When
 *    iterating over a Bag that contains IPv6 data and the key type is
 *    an integer, addresses in the ::ffff:0:0/96 block are
 *    converted to IPv4 addresses, and then those addresses are
 *    converted to native integers and returned by this function.  All
 *    other IPv6 addresses are ignored.
 *
 *    If the iterator has visited all entries, the 'key' and 'counter'
 *    values are unchanged and the function returns
 *    SKBAG_ERR_KEY_NOT_FOUND.  The function returns SKBAG_ERR_INPUT
 *    if any of the input parameters are NULL or if the type field of
 *    'key' or 'counter' is not recognized.  Return SKBAG_ERR_MODIFIED
 *    if the Bag's key size has changed; when this happens, the
 *    iterator must be reset or destroyed.
 */
skBagErr_t
skBagIteratorNextTyped(
    skBagIterator_t        *iter,
    skBagTypedKey_t        *key,
    skBagTypedCounter_t    *counter);


/**
 *    Reset the iterator at 'iter' so the next call to
 *    skBagIteratorNextTyped() returns the counter associated with
 *    the first key.
 */
skBagErr_t
skBagIteratorReset(
    skBagIterator_t    *iter);


/**
 *    Return the number octets the key of 'bag' occupies for the
 *    in-core representation of 'bag'.
 */
size_t
skBagKeyFieldLength(
    const skBag_t      *bag);


/**
 *    Return the type of key that 'bag' contains, and, if 'buf' is not
 *    NULL, fill 'buf' with a string representation of that type.  The
 *    caller must specify the size of 'buf' in 'buflen'.  If 'buf' is
 *    too small to hold the string representation, 'buf' is filled
 *    with as much of the name as possible.
 *
 *    See also skBagKeyFieldType(), skBagCounterFieldName(), and
 *    skBagCounterFieldType().
 */
skBagFieldType_t
skBagKeyFieldName(
    const skBag_t      *bag,
    char               *buf,
    size_t              buflen);


/**
 *    Return the type of key that 'bag' contains.
 *
 *    See also skBagKeyFieldName(), skBagCounterFieldType(), and
 *    skBagCounterFieldName().
 */
skBagFieldType_t
skBagKeyFieldType(
    const skBag_t      *bag);


/**
 *    Remove 'key' from the bag 'bag'.  Return SKBAG_OK on success.
 *    Return SKBAG_OK if 'key' is not in 'bag'.
 */
#define skBagKeyRemove(rm_bag, rm_key)                          \
    skBagCounterSet((rm_bag), (rm_key), skbag_counter_zero)


/**
 *    Read a serialized Bag from the file specified by 'filename' into
 *    a newly created bag and set the referent of 'bag' to its
 *    location.  This function is a wrapper around skBagRead().
 *
 *    Return SKBAG_OK on success.  Return SKBAG_ERR_INPUT and do not
 *    create the bag if any input parameter is NULL.  Return
 *    SKBAG_ERR_READ, print an error, and do not create the bag if
 *    'filename' cannot be opened.  Otherwise, return the error code
 *    specified by skBagRead().
 */
skBagErr_t
skBagLoad(
    skBag_t           **bag,
    const char         *filename);


/**
 *    Modify the type or length of the key or counter for the existing
 *    bag 'bag'.
 *
 *    When 'key_octets' and/or 'counter_octets' is
 *    SKBAG_OCTETS_NO_CHANGE, the size of the key and/or counter is
 *    not modified.  Otherwise, the 'key_octets' and/or
 *    'counter_octets' values are handled as they are in
 *    skBagCreateTyped().
 *
 *    When 'key_octets' and/or 'counter_octets' specifies a size
 *    smaller than that bag's current key/counter lengths,
 *    keys/counters whose value is outside the range of the new
 *    key/counter are removed from the bag.
 *
 *    Return SKBAG_OK on success.  Return SKBAG_ERR_INPUT when 'bag'
 *    is NULL or when the other parameters are not recognized or have
 *    illegal values.
 *
 */
skBagErr_t
skBagModify(
    skBag_t            *bag,
    skBagFieldType_t    key_type,
    skBagFieldType_t    counter_type,
    size_t              key_octets,
    size_t              counter_octets);


/**
 *    Print to the stream 'stream' meta-data on how the bag 'bag' is
 *    performing.
 */
skBagErr_t
skBagPrintTreeStats(
    const skBag_t      *bag,
    skstream_t         *stream_out);


/**
 *    Read a Bag from the 'stream'.  For each key/counter pair in the
 *    Bag, the function invokes the callback function 'cb_entry_func'
 *    with the key, the counter, and the 'cb_data'.  Processing
 *    continues until the stream is exhausted or until 'cb_entry_func'
 *    returns a value other than 'SKBAG_OK'.
 *
 *    The 'cb_init_func' callback may be NULL.  If it is not NULL, the
 *    callback is invoked after the stream's header has been read and
 *    before processing any entries in the bag.  The callback is
 *    invoked with a partially constructed bag that may be used to
 *    determine the contents of 'stream'.  If the 'cb_init_func'
 *    callback returns a value other than SKBAG_OK, processing of the
 *    bag stops.
 *
 *    Return SKBAG_ERR_INPUT if the 'stream' or 'cb_entry_func' input
 *    parameters are NULL.  Return SKBAG_ERR_READ (and print an error)
 *    if there is an error reading 'bag' from 'stream'.  Return
 *    SKBAG_ERR_HEADER (and print an error) if 'stream' does not
 *    contain a Bag file, if the Bag file version is unsupported, or
 *    if the file contains key or counter types or octet lengths that
 *    are not supported by the library.  Otherwise, the return status
 *    of this function is the return status of 'cb_entry_func'.
 */
skBagErr_t
skBagProcessStreamTyped(
    skstream_t             *stream_in,
    void                   *cb_data,
    skBagStreamInitFunc_t   cb_init_func,
    skBagStreamEntryFunc_t  cb_entry_func);


/**
 *    Read a serialized Bag from the input stream 'stream' into a
 *    newly created Bag and set 'bag' to its location.
 *
 *    Return SKBAG_OK on success.  Return SKBAG_ERR_INPUT and do not
 *    create the bag if any input parameter is NULL.  Return
 *    SKBAG_ERR_HEADER, print an error, and do not create the bag if
 *    'stream' does not contain a Bag file, if the bag file version is
 *    unsupported, or if the file contains key or counter types or
 *    octet lengths that are not supported by the library.  Return
 *    SKBAG_ERR_MEMORY if there is an error creating the bag or adding
 *    entries to it; in the latter case, the bag is returned.  Return
 *    SKBAG_ERR_READ (and print an error) if there is an error reading
 *    from 'stream'; the bag may or may not be created depending on
 *    when the error occurred.
 *
 *    See also skBagLoad().
 */
skBagErr_t
skBagRead(
    skBag_t           **bag,
    skstream_t         *stream_in);


/**
 *    Serialize the Bag 'bag' to the file specified by 'filename'.
 *    This function is a wrapper around skBagWrite().
 *
 *    Return SKBAG_OK on success.  Return SKBAG_ERR_INPUT if any
 *    parameter is NULL.  Return SKBAG_ERR_OUTPUT (and print an error)
 *    if 'filename' cannot be opened for writing.  May also return the
 *    error codes specified by skBagWrite().
 */
skBagErr_t
skBagSave(
    const skBag_t      *bag,
    const char         *filename);


/**
 *    Return a static string describing the skBagErr_t value 'code'.
 */
const char *
skBagStrerror(
    skBagErr_t          err_code);


/**
 *    Serialize the bag 'bag' to the output stream 'stream'.  The
 *    caller may set the compression method of 'stream' before calling
 *    this function.
 *
 *    Return SKBAG_OK on success.  Return SKBAG_ERR_INPUT if any input
 *    parameter is NULL.  Return SKBAG_ERR_OUTPUT if there is an error
 *    writing 'bag' to 'stream'.
 *
 *    See also skBagSave().
 */
skBagErr_t
skBagWrite(
    const skBag_t      *bag,
    skstream_t         *stream_out);

#ifdef __cplusplus
}
#endif
#endif /* _SKBAG_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
