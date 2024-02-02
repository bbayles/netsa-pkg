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
**  silk_types.h
**
**    A place to gather commonly used defines, typedefs, and enumerations.
**
*/

#ifndef _SILK_TYPES_H
#define _SILK_TYPES_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SILK_TYPES_H, "$SiLK: silk_types.h 05d39531ae59 2023-05-17 15:23:40Z mthomas $");

/**
 *  @file
 *
 *    The typedefs and some common macros used throughout the SiLK
 *    code base.
 *
 *    This file is part of libsilk.
 */


/* *****  IP ADDRESS / SOCKADDR  ********************************** */

/**
 *    The IP address structure.  Most code should use skipaddr_t
 *    instead of skIPUnion_t.  Users should not deference directly,
 *    use the macros specified in skipaddr.h to get/set the value.
 */
typedef union skipunion_un {
    uint32_t    ipu_ipv4;
#if SK_ENABLE_IPV6
    uint8_t     ipu_ipv6[16];
#endif
} skIPUnion_t;

/**
 *    An IP address structure that knows the version of IP address it
 *    contains.  Do not deference directly, instead use the macros
 *    specified in skipaddr.h to get/set the value
 */
typedef struct skipaddr_st {
    skIPUnion_t ip_ip;
#if SK_ENABLE_IPV6
    unsigned    ip_is_v6 :1;
#endif
} skipaddr_t;

/**
 *    Flags that determine the string representation of an IP as
 *    returned by skipaddrString() and other functions declared in
 *    utils.h
 */
typedef enum {
    /**
     *  Canonical format: dotted quad for IPv4 and colon-separated
     *  hexadecimal for IPv6.  This format calls the inet_ntop(3)
     *  function which uses a mixture of IPv4 and IPV6 addresss for
     *  IPv6 addresses that occur in the ::ffff:0:0/96 and ::/96
     *  netblocks (except ::/127), such as ::192.0.2.1 and
     *  ::ffff:192.0.2.1.
     *
     *  The maximum length of this string is 15 for IPv4, 39 for IPv6,
     *  18 for IPv4/CIDR, 43 for IPv6/CIDR.
     *
     *  May be used with SKIPADDR_ZEROPAD and either SKIPADDR_MAP_V4
     *  or SKIPADDR_UNMAP_V6.
     */
    SKIPADDR_CANONICAL = 0,
    /**
     *  Value as an integer number, printed as decimal.
     *
     *  The maximum length of this string is 10 for IPv4, 39 for IPv6,
     *  13 for IPv4/CIDR, 43 for IPv6/CIDR.
     *
     *  May be used with SKIPADDR_ZEROPAD and either SKIPADDR_MAP_V4
     *  or SKIPADDR_UNMAP_V6.
     */
    SKIPADDR_DECIMAL = 1u,
    /**
     *  Value as an integer number, printed as hexadecimal.
     *
     *  The maximum length of this string is 8 for IPv4, 32 for IPv6,
     *  11 for IPv4/CIDR, 36 for IPv6/CIDR.
     *
     *  May be used with SKIPADDR_ZEROPAD and either
     *  SKIPADDR_MAP_V4 or SKIPADDR_UNMAP_V6.
     */
    SKIPADDR_HEXADECIMAL = 2u,
    /**
     *  Print IPv4 addresses in the canonical form.  Print IPv6 in the
     *  canonical form but use only hexadecimal numbers and never a
     *  mixture of IPv4 and IPv6.  That is, prints ::c000:201 instead
     *  of ::192.0.2.1.
     *
     *  May be used with SKIPADDR_ZEROPAD and either SKIPADDR_MAP_V4
     *  or SKIPADDR_UNMAP_V6.
     *
     *  Since SiLK 3.17.0.
     */
    SKIPADDR_NO_MIXED = 3u,
    /**
     *  Apply any other formatting, and then pad with zeros to expand
     *  the string to the maximum width: Each IPv4 octet has three
     *  characters, each IPv6 hexadectet has 4 characters, decimal and
     *  hexadecimal numbers have leading zeros.  Useful for string
     *  comparisons.
     *
     *  May be used with any other skipaddr_flags_t.
     */
    SKIPADDR_ZEROPAD = (1u << 7),
    /**
     *  Map each IPv4 address into the IPv6 ::ffff:0:0/96 netblock and
     *  then apply other formatting.  Has no effect on IPv6 addresses.
     *
     *  May be used with any other skipaddr_flags_t except
     *  SKIPADDR_UNMAP_V6.
     *
     *  Since SiLK 3.17.0.
     */
    SKIPADDR_MAP_V4 = (1u << 8),
    /**
     *  For each IPv4-mapped IPv6 address (i.e., IPv6 addresses in the
     *  ::ffff:0:0/96 netblock), convert the address to IPv4 and then
     *  apply other formatting.  Has no effect on IPv4 addresses or on
     *  IPv6 addresses outside of the ::ffff:0:0/96 netblock.
     *
     *  May be used with any other skipaddr_flags_t except
     *  SKIPADDR_MAP_V4 and SKIPADDR_FORCE_IPV6.
     *
     *  Since SiLK 3.17.0.
     */
    SKIPADDR_UNMAP_V6 = (1u << 9),
    /**
     *  Map each IPv4 address into the IPv6 ::ffff:0:0/96 netblock and
     *  then apply the SKIPADDR_NO_MIXED format.
     *
     *  May be used with SKIPADDR_ZEROPAD.
     */
    SKIPADDR_FORCE_IPV6 = (SKIPADDR_MAP_V4 | SKIPADDR_NO_MIXED)
} skipaddr_flags_t;

/**
 *    Minimum required size of character buffer that holds the printed
 *    representation of an IP address.  skipaddrString() expects (and
 *    assumes) a buffer of at least this size.
 *
 *    The length is taken from INET6_ADDRSTRLEN used by inet_ntop(),
 *    which can return "0000:0000:0000:0000:0000:ffff:000.000.000.000"
 */
#define SKIPADDR_STRLEN     46
#define SK_NUM2DOT_STRLEN   SKIPADDR_STRLEN

/**
 *    Minimum required size of character buffer that holds the printed
 *    representation of an IP address, a slash ('/'), and a CIDR
 *    prefix (netblock) designation.  skipaddrCidrString() expects
 *    (and assumes) a buffer of at least this size.
 *
 *    Since SiLK 3.18.0.
 */
#define SKIPADDR_CIDR_STRLEN    (SKIPADDR_STRLEN + 4)

/**
 *    How to handle IPv6 Flow records.
 */
typedef enum sk_ipv6policy_en {
    /** completely ignore IPv6 flows */
    SK_IPV6POLICY_IGNORE = -2,
    /** convert IPv6 flows to IPv4 if possible, else ignore */
    SK_IPV6POLICY_ASV4 = -1,
    /** mix IPv4 and IPv6 flows in the result--this is the default */
    SK_IPV6POLICY_MIX = 0,
    /** force IPv4 flows to be converted to IPv6 */
    SK_IPV6POLICY_FORCE = 1,
    /** only return IPv6 flows that were marked as IPv6 */
    SK_IPV6POLICY_ONLY = 2
} sk_ipv6policy_t;

/**
 *    A special structure of IP Addresses.  It is defined in utils.h
 */
typedef struct skIPWildcard_st skIPWildcard_t;


/**
 *    A union that encompasses the various struct sockaddr types.
 *    Macros and functions for manipulating these are in utils.h.
 */
typedef union sk_sockaddr_un {
    struct sockaddr     sa;
    struct sockaddr_in  v4;
    struct sockaddr_in6 v6;
    struct sockaddr_un  un;
} sk_sockaddr_t;

/**
 *    The sk_sockaddr_array_t structure represents multiple
 *    representations of an address and/or port.  Macros and functions
 *    for manipulating these are in utils.h.
 */
typedef struct sk_sockaddr_array_st {
    /* the host-name/-address or NULL for INADDR_ANY */
    char           *name;
    /* the host:port pair; uses '*' for INADDR_ANY */
    char           *host_port_pair;
    /* array of sockets */
    sk_sockaddr_t  *addrs;
    /* number of entries in 'addrs' */
    uint32_t        num_addrs;
} sk_sockaddr_array_t;


/* *****  TIME  *************************************************** */

/**
 *    sktime_t is milliseconds since the UNIX epoch.  Macros and
 *    functions for manipulating these are in utils.h.
 *
 *    Value is signed, like time_t.
 */
typedef int64_t sktime_t;

/**
 *    Minimum size of buffer to pass to sktimestamp_r().
 */
#define SKTIMESTAMP_STRLEN 64


/* *****  FLOW RECORDS (RWREC)  *********************************** */

/**
 *    The generic SiLK Flow record returned from ANY file format
 *    containing packed SiLK Flow records.  It is defined in rwrec.h
 */
typedef struct rwGenericRec_V5_st rwGenericRec_V5;
typedef rwGenericRec_V5 rwRec;

/**
 *    The maximum size of a SiLK Flow record.
 */
#define SK_MAX_RECORD_SIZE 104

/**
 *    Number of possible SNMP interface index values
 */
#define SK_SNMP_INDEX_LIMIT   65536



/* *****  STREAM / FILE FORMATS  ********************************** */

/**
 *    Interface to a file containing SiLK Data---flow records or
 *    IPsets, etc---is an skstream_t.  See skstream.h.
 */
typedef struct skstream_st skstream_t;

/**
 *    Type to hold the ID of the various SiLK file formats.  The
 *    format IDs begin with FT_ and are listed in silk_files.h.
 */
typedef uint8_t  sk_file_format_t;
typedef sk_file_format_t fileFormat_t       SK_GCC_DEPRECATED;

/**
 *    The value for an invalid or unrecognized file format.
 *
 *    Since SiLK 3.13.0.
 */
#define SK_INVALID_FILE_FORMAT      ((sk_file_format_t)0xFF)

/**
 *    The strlen() of the names of file formats will be this size or
 *    less.
 */
#define SK_MAX_STRLEN_FILE_FORMAT   32

/**
 *    A version of the file format.
 */
typedef uint8_t  sk_file_version_t;
typedef sk_file_version_t fileVersion_t     SK_GCC_DEPRECATED;

/**
 *    Value meaning that any file version is valid
 */
#define SK_RECORD_VERSION_ANY       ((sk_file_version_t)0xFF)

/**
 *    The compression method used to write the data section of a file.
 *    The known compression methods are listed in silk_files.h.
 */
typedef uint8_t sk_compmethod_t;

/**
 *    The value for an invalid or unrecognized compression method
 */
#define SK_INVALID_COMPMETHOD       ((sk_compmethod_t)0xFF)

/**
 *    Values that specify how a stream/file is to be opened.
 */
typedef enum {
    SK_IO_READ = 1,
    SK_IO_WRITE = 2,
    SK_IO_APPEND = 4
} skstream_mode_t;

/**
 *    What type of content the stream contains
 */
typedef enum {
    /** stream contains line-oriented text */
    SK_CONTENT_TEXT = (1 << 0),
    /** stream contains a SiLK file header and SiLK Flow data */
    SK_CONTENT_SILK_FLOW = (1 << 1),
    /** stream contains a SiLK file header and data (non-Flow data) */
    SK_CONTENT_SILK = (1 << 2),
    /** stream contains binary data other than SiLK */
    SK_CONTENT_OTHERBINARY = (1 << 3)
} skcontent_t;



/* *****  CLASS / TYPE / SENSORS  ********************************* */

/* Most of the functions for manipulating these are declared in
 * sksite.h */

/**
 *    Type to hold a class ID.  A class is not actually stored in
 *    packed records (see sk_flowtype_id_t).
 */
typedef uint8_t sk_class_id_t;
typedef sk_class_id_t classID_t             SK_GCC_DEPRECATED;

/**
 *    The maximum number of classes that may be allocated.  (All valid
 *    class IDs must be less than this number.)
 */
#define SK_MAX_NUM_CLASSES          ((sk_class_id_t)32)

/**
 *    The value for an invalid or unrecognized class.
 */
#define SK_INVALID_CLASS            ((sk_class_id_t)0xFF)

/**
 *    A flowtype is a class/type pair.  It has a unique name and
 *    unique ID.
 */
typedef uint8_t  sk_flowtype_id_t;
typedef sk_flowtype_id_t flowtypeID_t       SK_GCC_DEPRECATED;

/**
 *    The maximum number of flowtypes that may be allocated.  (All
 *    valid flowtype IDs must be less than this number.)
 */
#define SK_MAX_NUM_FLOWTYPES        ((sk_flowtype_id_t)0xFF)

/**
 *    The value for an invalid or unrecognized flow-type value
 */
#define SK_INVALID_FLOWTYPE         ((sk_flowtype_id_t)0xFF)

/**
 *    The strlen() of the names of flowtypes, classes, and types will
 *    be this size or less.  Add 1 to allow for the NUL byte.
 */
#define SK_MAX_STRLEN_FLOWTYPE      32

/**
 *    Type to hold a sensor ID.  Usually, a sensor is a router or
 *    other flow collector.
 */
typedef uint16_t sk_sensor_id_t;
typedef sk_sensor_id_t sensorID_t           SK_GCC_DEPRECATED;

/**
 *    The maximum number of sensors that may be allocated.  (All valid
 *    sensor IDs must be less than this number.)
 */
#define SK_MAX_NUM_SENSORS          ((sk_sensor_id_t)0xFFFF)

/**
 *    The value for an invalid or unrecognized sensor.
 */
#define SK_INVALID_SENSOR           ((sk_sensor_id_t)0xFFFF)

/**
 *    The maximum length of a sensor name, not including the final
 *    NUL.
 */
#define SK_MAX_STRLEN_SENSOR        64

/**
 *    Type to hold a sensor group ID.  This is not actually stored in
 *    packed records.
 */
typedef uint16_t sk_sensorgroup_id_t;
typedef sk_sensorgroup_id_t sensorgroupID_t SK_GCC_DEPRECATED;

/**
 *    The maximum number of sensorgroups that may be allocated.  (All
 *    valid sensorgroup IDs must be less than this number.)
 */
#define SK_MAX_NUM_SENSORGROUPS     ((sk_sensorgroup_id_t)0xFFFF)

/**
 *    The value for an invalid or unrecognized sensor.
 */
#define SK_INVALID_SENSORGROUP      ((sk_sensorgroup_id_t)0xFFFF)



/* *****  BITMPAP / LINKED-LIST / VECTOR  ************************* */

/**
 *    Bitmap of integers.  It is defined in utils.h.
 */
typedef struct sk_bitmap_st sk_bitmap_t;


/**
 *    Signature of a doubly-linked list.  See skdllist.h.
 */
struct sk_dllist_st;
typedef struct sk_dllist_st      sk_dllist_t;

/**
 *    Signature of an iterator for a doubly linked list
 */
struct sk_dll_iter_st;
typedef struct sk_dll_iter_st sk_dll_iter_t;
struct sk_dll_iter_st {
    void           *data;
    sk_dll_iter_t  *link[2];
};

/**
 *    A stringmap maps strings to integer IDs.  It is used for parsing
 *    the user's argument to --fields.  See skstringmap.h.
 */
typedef sk_dllist_t sk_stringmap_t;

/**
 *    Growable array.  See skvector.h.
 */
typedef struct sk_vector_st sk_vector_t;



/* *****  IPSET  ************************************************** */

/**
 *    Data structure to hold a set of IP addresses.  See skipset.h.
 */
typedef struct skipset_st skipset_t;



/* *****  MISCELLANEOUS  ****************************************** */

/**
 *    An enumeration type for endianess.
 */
typedef enum silk_endian_en {
    SILK_ENDIAN_BIG,
    SILK_ENDIAN_LITTLE,
    SILK_ENDIAN_NATIVE,
    SILK_ENDIAN_ANY
} silk_endian_t;


/**
 *    The status of an iterator.
 */
typedef enum skIteratorStatus_en {
    /** More entries */
    SK_ITERATOR_OK=0,
    /** No more entries */
    SK_ITERATOR_NO_MORE_ENTRIES
} skIteratorStatus_t;

/**
 *    The type of message functions.  These should use the same
 *    semantics as printf.
 */
typedef int (*sk_msg_fn_t)(const char *, ...)
    SK_CHECK_TYPEDEF_PRINTF(1, 2);

/**
 *    The type of message functions with the arguments expanded to a
 *    variable argument list.
 */
typedef int (*sk_msg_vargs_fn_t)(const char *, va_list)
    SK_CHECK_TYPEDEF_PRINTF(1, 0);

#ifdef __cplusplus
}
#endif
#endif /* _SILK_TYPES_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
