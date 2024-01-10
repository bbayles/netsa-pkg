/*
** Copyright (C) 2008-2023 by Carnegie Mellon University.
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
**  skipset.c
**
**    IPset data structure for SiLK-3.
**
**    Mark Thomas
**    February 2011
*/
#ifndef _SKIPSET_H
#define _SKIPSET_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKIPSET_H, "$SiLK: skipset.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>
#include <silk/skheader.h>

/**
 *  @file
 *
 *    Implementation of a  data structure for maintaining IP
 *    addresses.
 *
 *    This file is part of libsilk.
 *
 *    The implementation uses a Radix Tree (aka Patricia Trie) to keep
 *    IP addresses and their prefixes.  The implementation can support
 *    IPv4 or IPv6 addresses, though each instance of an IPset can
 *    only hold one type of IP address.
 *
 *    This structure is a replacement for the skIPTree_t data
 *    structure defined in iptree.c.
 */


/**
 *    Most function in this file return one of these values.
 */
typedef enum skipset_return_en {
    /** Success */
    SKIPSET_OK = 0,
    /** Unable to allocate memory */
    SKIPSET_ERR_ALLOC = 1,
    /** Empty/Invalid/NULL input value */
    SKIPSET_ERR_BADINPUT = 2,
    /** Error in reading from/writing to stream */
    SKIPSET_ERR_FILEIO = 3,
    /** Input is not an IPset */
    SKIPSET_ERR_FILETYPE = 4,
    /** Header values on IPset are incompatible with this compile of SiLK */
    SKIPSET_ERR_FILEHEADER = 5,
    /** IPset is empty */
    SKIPSET_ERR_EMPTY = 6,
    /** Error opening file */
    SKIPSET_ERR_OPEN = 7,
    /** IPset does not allow IPv6 addresses */
    SKIPSET_ERR_IPV6 = 8,
    /** IPset version unsupported by this SiLK release */
    SKIPSET_ERR_FILEVERSION = 9,
    /** Prefix value out of range */
    SKIPSET_ERR_PREFIX = 10,
    /** Value not found in IPset */
    SKIPSET_ERR_NOTFOUND = 11,
    /** Function requires a 'clean' IPset, see skIPSetClean() */
    SKIPSET_ERR_REQUIRE_CLEAN = 12,
    /** IPset state is inconsistent (corrupt file?) */
    SKIPSET_ERR_CORRUPT = 13,
    /** Part of netblock exists in IPset */
    SKIPSET_ERR_SUBSET = 14,
    /** Internal use */
    SKIPSET_ERR_MULTILEAF = 15
} skipset_return_t;


/**
 *    The type of an IPset.
 */
/* typedef struct skipset_st skipset_t;   // silk_types.h */

typedef struct skSetStream_st skSetStream_t;

/**
 *    Structure used for specifying the options used when writing an
 *    IPset to a file.
 */
typedef struct skipset_options_st {
    /** type of input to the application, where a non-zero value
     * indicates application uses existing SiLK files (either IPsets
     * or Flow files).  A non-zero value provides the --notes-strip
     * option to the application. */
    int                 existing_silk_files;
    /** when 0, do not strip invocations from the IPset; when 1, strip
     * invocations from output */
    int                 invocation_strip;
    /** when 0, do not strip annoations (notes) from the IPset; when 1,
     * strip annotations from output */
    int                 note_strip;
    /** command line: number of arguments */
    int                 argc;
    /** command line: the arguments */
    char              **argv;
    /** version of records to write */
    uint16_t            record_version;
    /** type of compression to use for output */
    sk_compmethod_t     comp_method;
} skipset_options_t;


/**
 *    Type of callback function used when walking over the elements of
 *    an IPset.  See skIPSetWalk().
 */
typedef int (*skipset_walk_fn_t)(
    skipaddr_t         *ip,
    uint32_t            prefix,
    void               *cb_ctx);


/**
 *    skIPTree_t was the IPset structure used prior to SiLK 3.
 */
typedef struct skIPTree_st skIPTree_t;

/**
 *    The skipset_iterator_t is for iterating over the elements of an
 *    IPset.  See skIPSetIteratorBind().
 *
 *    The structure is public so it may be created on the stack, but
 *    the caller should consider the structure opaque.
 */
struct skipset_iterator_st {
    union iter_un {
        struct v2_st {
            const skIPTree_t   *tree;
            uint32_t            base_ip;
            uint32_t            count;
            uint32_t            trail_zero;
            uint32_t            top_16;
            uint16_t            mid_11;
            uint16_t            bot_5;
        }                               v2;
        struct v3_st {
            uint64_t            data[4];
            uint32_t            cur;
        }                               v3;
    }                               it;
    const skipset_t    *ipset;
    sk_ipv6policy_t     v6policy;
    unsigned            cidr_blocks :1;
    unsigned            is_iptree   :1;
};
typedef struct skipset_iterator_st skipset_iterator_t;


/**
 *    By default, attempting to insert an IPv6 addresses into an
 *    IPv4-only IPset will auto-convert the IPset so that it can hold
 *    IPv6 addresses.  This function prevents that auto-conversion
 *    from happening on 'ipset'.  An attempt to insert an IPv6 address
 *    into such an IPset will return SKIPSET_ERR_IPV6.
 *
 *    This function has no effect when used on an IPset that already
 *    holds IPv6 addresses.
 *
 *    See also skIPSetAutoConvertEnable() and
 *    skIPSetAutoConvertIsEnabled().
 */
void
skIPSetAutoConvertDisable(
    skipset_t          *ipset);


/**
 *    Allow an attempt to insert an IPv6 address into 'ipset', where
 *    'ipset' currently only holds IPv4 addresses, to automatically
 *    convert the 'ipset' to an IPv6 IPset.  This behavior is the
 *    default.
 *
 *    See also skIPSetAutoConvertDisable() and
 *    skIPSetAutoConvertIsEnabled().
 */
void
skIPSetAutoConvertEnable(
    skipset_t          *ipset);


/**
 *    Return 1 if 'ipset' will automatically convert itself from an
 *    IPv4 IPset to an IPv6 IPset when an attempt is made to insert an
 *    IPv6 address.
 *
 *    See also skIPSetAutoConvertDisable() and
 *    skIPSetAutoConvertEnable().
 */
int
skIPSetAutoConvertIsEnabled(
    const skipset_t    *ipset);


/**
 *    Return 1 if 'ip' is present in 'ipset'; return 0 otherwise.
 *
 *    If 'ip' and 'ipset' have different IP versions (IPv4 vs IPv6),
 *    this function will attempt to convert 'ip' to the form used in
 *    'ipset'.  If the conversion cannot be performed, 0 is returned.
 */
int
skIPSetCheckAddress(
    const skipset_t    *ipset,
    const skipaddr_t   *ip);


/**
 *    Return 1 if the IPsets 'ipset1' and 'ipset2' have any IPs in
 *    common; otherwise, return 0.
 */
int
skIPSetCheckIPSet(
    const skipset_t    *ipset1,
    const skipset_t    *ipset2);


/**
 *    Return 1 if the IPset 'ipset' and IPWildcard 'ipwild' have any
 *    IPs in common; otherwise, return 0.
 */
int
skIPSetCheckIPWildcard(
    const skipset_t        *ipset,
    const skIPWildcard_t   *ipwild);


/**
 *    Return 1 if the IPset 'ipset' contains the...
 *
 *    ... source IP address of the SiLK Flow record 'rwrec' when
 *    'src_dst_nh' is 1
 *
 *    ... destination IP address of the SiLK Flow record 'rwrec' when
 *    'src_dst_nh' is 2
 *
 *    ... next hop IP address of the SiLK Flow record 'rwrec' when
 *    'src_dst_nh' is 4
 *
 *    Any other value for 'src_dst_nh' is a fatal error.
 */
int
skIPSetCheckRecord(
    const skipset_t    *ipset,
    const rwRec        *rwrec,
    int                 src_dst_nh);


/**
 *    Return 1 if the IPset 'ipset' contains the source IP address of
 *    the SiLK Flow record 'rwrec'; otherwise, return 0.
 */
#define skIPSetCheckRecordSIP(ipset, rwrec)     \
    skIPSetCheckRecord((ipset), (rwrec), 1)


/**
 *    Return 1 if the IPset 'ipset' contains the destination IP
 *    address of the SiLK Flow record 'rwrec'; otherwise, return 0.
 */
#define skIPSetCheckRecordDIP(ipset, rwrec)     \
    skIPSetCheckRecord((ipset), (rwrec), 2)


/**
 *    Return 1 if the IPset 'ipset' contains the next hop IP address
 *    of the SiLK Flow record 'rwrec'; otherwise, return 0.
 */
#define skIPSetCheckRecordNhIP(ipset, rwrec)     \
    skIPSetCheckRecord((ipset), (rwrec), 4)


/**
 *    Combine adjacent CIDR blocks into a larger blocks and make
 *    certain the IPs in 'ipset' use a contiguous region of memory.
 *    Return SKIPSET_ERR_BADINPUT when 'ipset' is NULL; return
 *    SKIPSET_OK otherwise.
 */
int
skIPSetClean(
    skipset_t          *ipset);


/**
 *    Return 1 if the IPset 'ipset' contains IPv6 addresses (other
 *    than IPv6-encoded-IPv4 addresses---i.e., ::ffff:0:0/96); return
 *    0 otherwise.
 *
 *    See also skIPSetIsV6().
 */
int
skIPSetContainsV6(
    const skipset_t    *ipset);


/**
 *    Change the form of IP addresses that are stored in the IPset
 *    'ipset'.
 *
 *    When 'target_ip_version' is 6, 'ipset' is modified to hold
 *    IPv6 addresses.  An IPset that already holds IPv6 addresses will
 *    not be modified.
 *
 *    When 'target_ip_version' is 4 and 'ipset' holds only
 *    IPv6-encoded-IPv4 addresses, 'ipset' is modified to hold
 *    IPv4 addresses.  If 'ipset' holds addresses that cannot be
 *    converted to IPv4 (i.e., if skIPSetContainsV6() returns true),
 *    the function returns SKIPSET_ERR_IPV6.  An IPset that already
 *    holds IPv4 addresses will not be modified.
 *
 *    Any other value for 'target_ip_version' results in a return
 *    value of SKIPSET_ERR_BADINPUT, and no changes will be made to
 *    'ipset'.
 */
int
skIPSetConvert(
    skipset_t          *ipset,
    int                 target_ip_version);


/**
 *    Count the number of IPs in the IPset 'ipset'.  Return the
 *    count and, when 'count' is specified, store the count in that
 *    memory location.  If 'ipset' contains more than UINT64_MAX IPv6
 *    addresses, the return value is UINT64_MAX.
 *
 *    See also skIPSetCountIPsString() and
 *    skIPSetProcessStreamCountIPs().
 */
uint64_t
skIPSetCountIPs(
    const skipset_t    *ipset,
    double             *count);


/**
 *    Count the number of IPs in the IPset 'ipset', fills 'buf' with
 *    the base-10 representation of the count, and return 'buf'.
 *
 *    The caller must pass the size of 'buf' in the 'buflen'
 *    parameter.  If 'buflen' is not large enough to hold the number
 *    of IPs in the IPset, the function returns NULL.  (A 'buflen' of
 *    40 or greater will be sufficient for an IPv6 IPset.)
 *
 *    See also skIPSetCountIPs() and skIPSetProcessStreamCountIPs().
 */
char *
skIPSetCountIPsString(
    const skipset_t    *ipset,
    char               *buf,
    size_t              buflen);


/**
 *    Allocate and initialize a new IPset at the location referenced
 *    specified by 'ipset'.  The set is initially empty.
 *
 *    Assuming IPv6 support is enabled in SiLK, the default behavior
 *    is for an IPset to be initialized to store IPv4 addresses and to
 *    convert itself to hold IPv6 addresses once an IPv6 address is
 *    inserted.  When the 'support_ipv6' parameter is non-zero, the
 *    IPset is initialized to store IPv6 addresses which eliminates
 *    the need for the IPset to convert itself to the IPv6 format.
 *    (See also skIPSetAutoConvertDisable().)
 *
 *    Return SKIPSET_OK on success.  Return SKIPSET_ERR_ALLOC on an
 *    allocation failure, SKIPSET_ERR_BADINPUT if the 'ipset'
 *    parameter was NULL, or SKIPSET_ERR_IPV6 if 'support_ipv6' is
 *    non-zero and SiLK was configured without IPv6 support.  Leave
 *    the memory referenced by 'ipset' unchanged when an error code is
 *    returned.
 *
 *    skIPSetDestroy() is the corresponding free function.
 */
int
skIPSetCreate(
    skipset_t         **ipset,
    int                 support_ipv6);


/**
 *    Deallocate all memory associated with IPset stored in '*ipset'.
 *    On completion, set *ipset to NULL.  If 'ipset' or '*ipset' are
 *    NULL, no action is taken.
 */
void
skIPSetDestroy(
    skipset_t         **ipset);


/**
 *    Add the CIDR block represented by 'ip'/'prefix' to the binary
 *    IPSet 'ipset'.
 *
 *    If 'prefix' is 0, the function inserts the single IP address
 *    'ip'.  If 'prefix' is too large for the given IP,
 *    SKIPSET_ERR_PREFIX is returned.
 *
 *    The 'ip' is converted to the appropriate form (IPv4 or
 *    IPv6) to match the 'ipset'.  For an IPv4 address and an IPv6
 *    set, the IPv4 address is mapped into the ::ffff:0:0/96 subnet on
 *    the IPset.
 *
 *    For an IPv4 set, an IPv6 address in the ::ffff:0:0/96 subnet
 *    will be treated as an IPv6-encoded IPv4 address and IPv4 address
 *    will be added.  Any other IPv6 address will cause 'ipset' to be
 *    automatically converted to an IPv6 IPset UNLESS the
 *    skIPSetAutoConvertDisable() function has been called on 'ipset'.
 *    When auto-conversion is disabled, the address will be rejected
 *    and the function will return SKIPSET_ERR_IPV6.
 *
 *    Return SKIPSET_OK for success, or SKIPSET_ERR_ALLOC if there is
 *    not enough memory to allocate space for the new IP address
 *    block.
 *
 *    Note that little effort is made to combine CIDR blocks into
 *    larger CIDR blocks as the blocks are inserted.  To ensure that
 *    the data structure is as compact as possible, you may wish to
 *    call skIPSetClean() after inserting a series of IP addresses.
 */
int
skIPSetInsertAddress(
    skipset_t          *ipset,
    const skipaddr_t   *ip,
    uint32_t            prefix);


/**
 *    Add all the addresses in the IPWildcard 'ipwild' to the IPset
 *    'ipset'.  Returns the same results as skIPSetInsertAddress().
 */
int
skIPSetInsertIPWildcard(
    skipset_t              *ipset,
    const skIPWildcard_t   *ipwild);


/**
 *    Insert all IPs from 'ipaddr_start' to 'ipaddr_end' inclusive to
 *    the IPset 'ipset'.  In addition to the return values specified
 *    in 'skIPSetInsertAddress()', this function will return
 *    SKIPSET_ERR_BADINPUT if 'ipaddr_start' is greater than
 *    'ipaddr_end'.
 */
int
skIPSetInsertRange(
    skipset_t          *ipset,
    const skipaddr_t   *ipaddr_start,
    const skipaddr_t   *ipaddr_end);


/**
 *    Perform an intersection of 'result_ipset' and 'ipset', with the
 *    result in the 'result_ipset'; i.e., turn off all addresses in
 *    'result_ipset' that are off in 'ipset'.
 */
int
skIPSetIntersect(
    skipset_t          *result_ipset,
    const skipset_t    *ipset);


/**
 *    Return 1 if the IPset 'ipset' is currently configued to store
 *    IPv6 addresses; return 0 otherwise.
 *
 *    To determine whether it is possible to store an IPv6 address in
 *    the IPset 's', use
 *
 *        (skIPSetIsV6(s) || skIPSetAutoConvertIsEnabled(s))
 *
 *    See also skIPSetContainsV6().
 */
int
skIPSetIsV6(
    const skipset_t    *ipset);


/**
 *    Bind the IPset iterator 'iter' to iterate over the contents of
 *    the IPSet 'ipset'.
 *
 *    This function requires that the IPset is clean; that is, when
 *    there has been any modification to the IPset, a call to
 *    skIPSetClean() must precede the call to this function.
 *
 *    If 'cidr_blocks' is 0, the skIPSetIteratorNext() function
 *    visits each individual IP.  If 'cidr_blocks' is 1,
 *    skIPSetIteratorNext() visits CIDR blocks.  Any other value
 *    for 'cidr_blocks' is illegal.
 *
 *    The 'v6_policy' parameter may be used to force
 *    skIPSetIteratorNext() to return an IPv4 or an IPv6 address.
 *    When either 'v6_policy' is SK_IPV6POLICY_ONLY and 'ipset' is an
 *    IPv4 IPset or 'v6_policy' is SK_IPV6POLICY_IGNORE and 'ipset' is
 *    an IPv6 IPset, no addresses are returned and every call to
 *    skIPSetIteratorNext() will return SK_ITERATOR_NO_MORE_ENTRIES.
 *    When 'v6_policy' is SK_IPV6POLICY_FORCE, IPv6 addresses are
 *    always returned by skIPSetIteratorNext(); if the 'ipset' is an
 *    IPv4 IPset, the IP addresses are mapped into the ::ffff:0:0/96
 *    prefix.  When 'v6_policy' is SK_IPV6POLICY_ASV4, IPv4 addresses
 *    are always returned by skIPSetIteratorNext(); when the 'ipset'
 *    is IPv6, addresses in the ::ffff:0:0/96 prefix are mapped to
 *    IPv4 and all other IPv6 addresses are ignored.  When the policy
 *    is SK_IPV6POLICY_MIX, an IPv4 address is always returned when
 *    iterating over an IPv4 IPset and an IPv6 addresses is always
 *    returned when iterating over an IPv6 IPset.  When SiLK is not
 *    compiled with support for IPv6, every call to
 *    skIPSetIteratorNext() returns SK_ITERATOR_NO_MORE_ENTRIES when
 *    the 'v6_policy' is SK_IPV6POLICY_FORCE or SK_IPV6POLICY_ONLY.
 *
 *    This function returns SKIPSET_OK on success,
 *    SKIPSET_ERR_BADINPUT if either 'iter' or 'ipset' is NULL, or
 *    SKIPSET_ERR_REQUIRE_CLEAN if the 'ipset' is not clean.
 */
int
skIPSetIteratorBind(
    skipset_iterator_t *iter,
    const skipset_t    *ipset,
    uint32_t            cidr_blocks,
    sk_ipv6policy_t     v6_policy);


/**
 *    If there are more entries in the IPSet, this function puts the
 *    next IP Address and its CIDR prefix into the locations
 *    referenced by 'ipaddr' and 'prefix', respectively, and returns
 *    SK_ITERATOR_OK.  Otherwise, neither 'ipaddr' nor 'prefix' are
 *    modified and SK_ITERATOR_NO_MORE_ENTRIES is returned.
 */
int
skIPSetIteratorNext(
    skipset_iterator_t *iter,
    skipaddr_t         *ipaddr,
    uint32_t           *prefix);


/**
 *    Reset the iterator 'iter' to begin looping through the entries
 *    in the IPSet again.
 */
void
skIPSetIteratorReset(
    skipset_iterator_t *iter);


/**
 *    Create a new IPset at the location pointed at by 'ipset' and
 *    fill it with the data that the function reads from 'filename'.
 *
 *    This function is similar to skIPSetRead(), except that this
 *    function creates the stream from the specified filename.
 *
 *    Return SKIPSET_ERR_OPEN if there is a problem opening the file.
 *    Otherwise, return the result of skIPSetRead().
 */
int
skIPSetLoad(
    skipset_t         **ipset,
    const char         *filename);


/**
 *    Modify in place the specified 'ipset' so it contains at most 1
 *    IP address for every net-block of bitmask length 'prefix'.  When
 *    the 'ipset' has any IP active within each 'prefix'-sized block,
 *    all IPs in that block are turned off except for the IP at the
 *    start of the block. The allowable values for 'prefix' are 1 to
 *    the maximum prefix size for the 'ipset'.
 *
 *    See also skIPSetMaskAndFill().
 *
 *    Specify mask==16 with an IPset containing these IPs:
 *        10.0.0.23
 *        10.0.1.0/24
 *        10.7.1.0/24
 *        20.20.0.243
 *        32.32.0.0/15
 *    produces an IPset containing these IPs:
 *        10.0.0.0
 *        10.7.0.0
 *        20.20.0.0
 *        32.32.0.0
 *        32.33.0.0
 *
 *    Return SKIPSET_OK on success.  Return SKIPSET_ERR_PREFIX if
 *    the 'prefix' value is 0 or too large for the 'ipset'.  Return
 *    SKIPSET_ERR_ALLOC if memory cannot be allocated.
 */
int
skIPSetMask(
    skipset_t          *ipset,
    uint32_t            prefix);


/**
 *    Modify in place the specified 'ipset' so net-blocks of size
 *    'prefix' are completely full when any IP in that block is
 *    active. The allowable values for 'prefix' are 1 to the maximum
 *    prefix size for the 'ipset'.
 *
 *    See also skIPSetMask().
 *
 *    Specify mask==16 with an IPset containing these IPs:
 *        10.0.0.23
 *        10.0.1.0/24
 *        10.7.1.0/24
 *        20.20.0.243
 *        32.32.0.0/15
 *    produces an IPset with these blocks:
 *        10.0.0.0/16
 *        10.7.0.0/16
 *        20.20.0.0/16
 *        32.32.0.0/15
 *
 *    When the prefix of a net-block is smaller than 'prefix', that
 *    block is not modified.
 *
 *    Return SKIPSET_OK on success.  Return SKIPSET_ERR_PREFIX if
 *    the 'prefix' value is 0 or too large for the 'ipset'.
 */
int
skIPSetMaskAndFill(
    skipset_t          *ipset,
    uint32_t            prefix);


/**
 *    Bind 'set_options' to the 'ipset'.  'set_options' specify how
 *    the IPset will be written to disk.  If no options are bound to
 *    an IPset, the IPset will use default values when writing the
 *    IPset.
 *
 *    The 'ipset' does not copy the 'set_options'; it simply maintains
 *    a pointer to them, and it will reference the options when a call
 *    to skIPSetSave() or skIPSetWrite() is made.
 */
void
skIPSetOptionsBind(
    skipset_t                  *ipset,
    const skipset_options_t    *set_options);


/**
 *    Register options that affect how binary IPsets are written.  The
 *    'ipset_opts' parameter is required; it will be initialized to
 *    the default values.
 *
 *    The caller should set the 'existing_silk_files' to 1 if the
 *    application works with existing IPsets (e.g., rwsettool) or
 *    existing SiLK Flow files (rwset), or 0 if the application is
 *    creating new IPsets (e.g., rwsetbuild).  If the value is
 *    non-zero, the --notes-strip option is provided.
 *
 *    It is an error to call both this function and
 *    skIPSetOptionsRegisterRecordVersion().
 */
int
skIPSetOptionsRegister(
    skipset_options_t  *ipset_opts);

/**
 *    Similar to skIPSetOptionsRegister(), but this function is to be
 *    used by applications outside the rwset*-family.  This function
 *    registers a single option to specify the version of IPset files
 *    written.  The name of the option is given by 'option_name'; the
 *    function uses "record-version" when 'option_name' is NULL.
 *
 *    It is an error to call both this function and
 *    skIPSetOptionsRegister().
 *
 *    Since SiLK 3.11.0.
 */
int
skIPSetOptionsRegisterRecordVersion(
    skipset_options_t  *ipset_opts,
    const char         *option_name);

/**
 *    Free any memory or internal state used by the IPset options.
 */
void
skIPSetOptionsTeardown(
    void);

/**
 *    Print usage information to the specified file handle.  This
 *    function should be paired with usage of
 *    skIPSetOptionsRegister().
 */
void
skIPSetOptionsUsage(
    FILE               *fh);

/**
 *    Print usage information to the specified file handle.  This
 *    function should be paired with usage of
 *    skIPSetOptionsRegisterRecordVersion().
 *
 *    Since SiLK 3.11.0.
 */
void
skIPSetOptionsUsageRecordVersion(
    FILE               *fh);


/**
 *    Print, to the stream 'stream', a textual representation of the
 *    IPset given by 'ipset'.  The parameter 'ip_format' decribes how
 *    to print the ipset (see utils.h).  If 'as_cidr' is non-zero, the
 *    output will be in CIDR notation.
 */
void
skIPSetPrint(
    const skipset_t    *ipset,
    skstream_t         *stream,
    skipaddr_flags_t    ip_format,
    int                 as_cidr);


/**
 *    skipset_procstream_parm_t specifies the callback function and
 *    settings to use when processing a stream as an IPset.
 */
struct skipset_procstream_parm_st {
    /* the function to invoke on each entry in the IPset */
    skipset_walk_fn_t       cb_entry_func;
    /* a user-controlled context value that is passed to
     * 'cb_entry_func' for eeach entry */
    void                   *cb_entry_func_ctx;
    /* if one, 'cb_entry_func' is presented entries as CIDR blocks. if
     * zero, 'cb_entry_func' is called for each individual IP */
    uint32_t                visit_cidr;
    /* the IPv6 policy to follow */
    sk_ipv6policy_t         v6_policy;
};
typedef struct skipset_procstream_parm_st skipset_procstream_parm_t;

/**
 *    The signature of a callback used by skIPSetProcessStream() when
 *    reading an IPset from a stream.  This callback is invoked after
 *    the stream's header has been read and before processing any
 *    entries in the IPset.
 *
 *    If this function returns a value other than SKIPSET_OK,
 *    processing of the IPset stops.
 *
 *    The 'fake_ipset' argument is an empty IPset that must be
 *    considered read-only. The caller may determine whether the
 *    stream is capable of containing IPv6 addresses by calling
 *    skIPSetIsV6().  Note: It is possible for an IPv6 IPset to only
 *    contain IPv4 addresses.
 *
 *    The file's header is available in the 'hdr' parameter.
 *
 *    The 'cb_init_func_ctx' parameter is provided for the caller to
 *    use.  It is the parameter specified to skIPSetProcessStream().
 *
 *    The 'proc_stream_settings' paraemeter is the same one passed to
 *    skIPSetProcessStream().  The user may change the settings as she
 *    wishes.
 */
typedef int
(*skipset_procstream_init_t)(
    const skipset_t            *fake_ipset,
    const sk_file_header_t     *hdr,
    void                       *cb_init_func_ctx,
    skipset_procstream_parm_t  *proc_stream_settings);


/**
 *    Read an IPset from the 'stream' and invoke a callback function
 *    for each IP and netblock (CIDR) prefix pair without reading the
 *    entire IPset into memory.
 *
 *    The callback function to invoke for each entry has the signature
 *    specified by skipset_walk_fn_t.  The callback is given an IP,
 *    its netblock prefix, and a caller-provided context pointer.  The
 *    callback and its context are specified with the 'cb_entry_func'
 *    and 'cb_entry_func_ctx' members of the 'proc_stream_settings'
 *    parameter, respectively.  Processing of entries continues until
 *    the stream is exhausted or until 'cb_entry_func' returns a value
 *    other than 'SKIPSET_OK'.
 *
 *    The 'cidr_blocks' and 'v6_policy' members of the
 *    'proc_stream_settings' parameter determine the type of addresses
 *    that are passed to the 'cb_entry_func'.  See skIPSetWalk() for
 *    an explanation.
 *
 *    The 'cb_init_func' callback may be NULL.  If it is not NULL, the
 *    callback is invoked after the stream's header has been read and
 *    before processing any entries in the IPset. The callback is
 *    invoked with an empty IPset that may be used to determine
 *    whether the IPset in 'stream' is capable of containing IPv6
 *    addresses.  The callback function is also given the file's
 *    header and the 'cb_init_func_ctx' and 'proc_stream_settings'
 *    parameters.  The callback may change the values in the
 *    'proc_stream_settings'---for example, to choose the entry
 *    callback function to use based on the types of IPs in
 *    'stream'. If the 'cb_init_func' callback returns a value other
 *    than SKIPSET_OK, processing of the IPset stops and this function
 *    returns that value.
 *
 *    When this function is first called, either 'cb_init_func' or a
 *    'cb_entry_func' callback must be provided.  If not,
 *    SKIPSET_ERR_BADINPUT is returned.  However, if 'cb_entry_func'
 *    is NULL after calling 'cb_init_func', no further action is taken
 *    on 'stream' and this function returns SKIPSET_OK.
 *
 *    The function returns SKIPSET_ERR_BADINPUT if the 'stream' or
 *    'proc_stream_settings' parameters are NULL.  It may return any
 *    of the values specified for skIPSetRead() when it encounters one
 *    of those errors.  Otherwise, the return status of this function
 *    will be the return status of 'cb_init_func' or 'cb_entry_func'.
 *
 *    Since SiLK 3.11.0.
 */
int
skIPSetProcessStream(
    skstream_t                 *stream,
    skipset_procstream_init_t   cb_init_func,
    void                       *cb_init_func_ctx,
    skipset_procstream_parm_t  *proc_stream_settings);


/**
 *    Read an IPset from 'stream', count the number of IPs in the
 *    IPset, and write the base-10 representation of that number as a
 *    string to 'buf', a buffer of size 'buflen'.  See
 *    skIPSetCountIPsString() for information on the suggested minimum
 *    size for 'buf'.
 *
 *    Return SKIPSET_OK on success or the error code returned by
 *    skIPSetProcessStream() if an IPset cannot be read from 'stream'.
 *    If 'buf' is too small to hold the number of IPs, return
 *    SKIPSET_ERR_BADINPUT.
 *
 *    Since SiLK 3.14.0.
 */
int
skIPSetProcessStreamCountIPs(
    skstream_t         *stream,
    char               *buf,
    size_t              buflen);


/**
 *    Allocate a new IPset at the location pointed at by 'ipset' and
 *    fill it with the data that the function reads from the stream
 *    'stream'.  'stream' should be bound to a file and open.
 *
 *    The skIPSetLoad() function is a wrapper around this function.
 *
 *    On failure, 'ipset' is set to NULL.
 *
 *    Return SKIPSET_OK on success.  Otherwise, return
 *    SKIPSET_ERR_BADINPUT if either input parameter is NULL,
 *    SKIPSET_ERR_FILETYPE if the input is not an IPset stream,
 *    SKIPSET_ERR_FILEVERSION if the IPset file version is newer than
 *    supported by this release of SiLK, SKIPSET_ERR_FILEHEADER on
 *    other header errors reading the header (this may include if the
 *    stream's header includes features not available in this compile
 *    of SiLK---such as file compression or an attempt to read an IPv6
 *    IPset in an IPv4-only compile of SiLK), SKIPSET_ERR_FILEIO on
 *    other read error (including if the input is not a SiLK file), or
 *    SKIPSET_ERR_CORRUPT if the file was read correctly but the data
 *    appears invalid (for example, positional indexes are out of
 *    range).
 */
int
skIPSetRead(
    skipset_t         **ipset,
    skstream_t         *stream);


/**
 *    Remove the CIDR block represented by 'ip'/'prefix' from the
 *    binary IPSet 'ipset'.
 *
 *    If 'prefix' is 0, the function removes the single IP address
 *    'ip'.  If 'prefix' is too large for the given IP,
 *    SKIPSET_ERR_PREFIX is returned.
 *
 *    The 'ip' is converted to the appropriate form (IPv4 or
 *    IPv6) to match the 'ipset'.  For an IPv4 address and an IPv6
 *    set, the IPv4 address is mapped into the ::ffff:0:0/96 subnet on
 *    the IPset.
 *
 *    For an IPv4 set, an IPv6 address in the ::ffff:0:0/96 subnet
 *    will be treated as an IPv6-encoded IPv4 address and IPv4 address
 *    will be removed.  Any other IPv6 address is considered not be a
 *    member of the IPset and SKIPSET_OK is returned.
 *
 *    Return SKIPSET_OK for success.  This function may require
 *    memory allocation: Since the IPset stores CIDR blocks
 *    interanlly, the removal of a single IP from a CIDR block
 *    requires more entries.  If memory allocation fails,
 *    SKIPSET_ERR_ALLOC is returned.
 */
int
skIPSetRemoveAddress(
    skipset_t          *ipset,
    const skipaddr_t   *ip,
    uint32_t            prefix);


/**
 *    Remove all IPs from the IPset.
 */
int
skIPSetRemoveAll(
    skipset_t          *ipset);


/**
 *    Remove from 'ipset' all IPs in the IPWildcard 'ipwild'.  Return
 *    SKIPSET_OK on success.  May also return SKIPSET_ERR_ALLOC as
 *    described in skIPSetRemoveAddress().
 */
int
skIPSetRemoveIPWildcard(
    skipset_t              *ipset,
    const skIPWildcard_t   *ipwild);


/**
 *    Write the IPset at 'ipset' to 'filename'.
 *
 *    This function is similar to skIPSetWrite(), except this
 *    function writes directly to a file using the default compression
 *    method.
 *
 */
int
skIPSetSave(
    const skipset_t    *ipset,
    const char         *filename);


/**
 *    Return a text string describing 'err_code'.
 */
const char *
skIPSetStrerror(
    int                 error_code);


/**
 *    Subtract 'ipset' from 'result_ipset'.  That is, remove all
 *    addresses from 'result_ipset' that are specified in 'ipset'.
 */
int
skIPSetSubtract(
    skipset_t          *result_ipset,
    const skipset_t    *ipset);


/**
 *    Add the addresses in 'ipset' to 'result_ipset'.  Returns 0 on
 *    success, or 1 on memory allocation error.
 */
int
skIPSetUnion(
    skipset_t          *result_ipset,
    const skipset_t    *ipset);


/**
 *    Call the specified 'callback' function on the contents of the
 *    specified 'ipset'.
 *
 *    If 'cidr_blocks' is 0, the 'callback' is called on each
 *    individual IP in the 'ipset'.  If 'cidr_blocks' is 1, blocks of
 *    IP addresses are passed to the 'callback'.
 *
 *    The 'v6_policy' parameter may be used to force the IP addresses
 *    to be passed to callback as IPv4 or IPv6 addresses.  When either
 *    'v6_policy' is SK_IPV6POLICY_ONLY and 'ipset' is an IPv4 IPset
 *    or 'v6_policy' is SK_IPV6POLICY_IGNORE and 'ipset' is an IPv6
 *    IPset, no addresses are visited and skIPSetWalk() immediately
 *    returns SKIPSET_OK.  When 'v6_policy' is SK_IPV6POLICY_FORCE,
 *    IPv6 addresses are always passed to the 'callback' function; if
 *    the 'ipset' is an IPv4 IPset, the IP addresses are mapped into
 *    the ::ffff:0:0/96 prefix.  When 'v6_policy' is
 *    SK_IPV6POLICY_ASV4, IPv4 addresses are always passed to the
 *    'callback' function; when the 'ipset' is IPv6, addresses in the
 *    ::ffff:0:0/96 prefix are mapped to IPv4 and all other IPv6
 *    addresses are ignored.  When the policy is SK_IPV6POLICY_MIX, an
 *    IPv4 IPset always passes IPv4 addresses to the 'callback'
 *    function and an IPv6 IPset always passes IPv6 addresses to the
 *    'callback' function.  When SiLK is not compiled with support for
 *    IPv6, skIPSetWalk() returns immediately when the 'v6_policy' is
 *    SK_IPV6POLICY_FORCE or SK_IPV6POLICY_ONLY.
 *
 *    The 'cb_ctx' parameter is passed unchanged to 'callback'
 *    function.
 *
 *    If the 'callback' function returns a non-zero value, the
 *    function stops walking through the IPset, and the return value
 *    from 'callback' becomes the return value of this function.
 *
 *    It is not safe to modify the 'ipset' while walking over its
 *    entries.
 *
 *    See also skIPSetIteratorBind() and skIPSetIteratorNext().
 */
int
skIPSetWalk(
    const skipset_t    *ipset,
    uint32_t            cidr_blocks,
    sk_ipv6policy_t     v6_policy,
    skipset_walk_fn_t   callback,
    void               *cb_ctx);


/**
 *   Write the IPset at 'ipset' the output stream 'stream'.  'stream'
 *   should be bound to a file and open.  The caller may add headers
 *   to the file and set the compression method of the stream before
 *   calling this function.  If not set, the default compression
 *   method is used.
 *
 *   The skIPSetSave() function is a wrapper around this function.
 */
int
skIPSetWrite(
    const skipset_t    *ipset,
    skstream_t         *stream);


/**
 *    This is meant as a debugging function only.  It prints all
 *    entries in the radix tree starting at 'node_idx'.
 */
void
skIPSetDebugPrint(
    const skipset_t    *ipset);

#ifdef __cplusplus
}
#endif
#endif /* _SKIPSET_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
