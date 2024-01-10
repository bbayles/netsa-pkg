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
**  skipaddr.h
**
**    Macros and function declarations for handling IP addresses
**    (skipaddr_t and skIPUnion_t).
**
*/
#ifndef _SKIPADDR_H
#define _SKIPADDR_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKIPADDR_H, "$SiLK: skipaddr.h 27ca2e40f216 2023-05-16 21:15:20Z mthomas $");

#include <silk/silk_types.h>

/*
**  For reference.  Defined in silk_types.h
**
**    typedef union skipunion_un {
**        uint32_t    ipu_ipv4;
**    #if SK_ENABLE_IPV6
**        uint8_t     ipu_ipv6[16];
**    #endif
**    } skIPUnion_t;
**
**
**    typedef struct skipaddr_st {
**        skIPUnion_t ip_ip;
**    #if SK_ENABLE_IPV6
**        unsigned    ip_is_v6 :1;
**    #endif
**    } skipaddr_t;
*/


/*
 *  is_zero = SK_IPV6_IS_ZERO(ipv6);
 *
 *    Return true if the specified ipv6 address is zero, where ipv6
 *    was defined as:
 *
 *    uint8_t ipv6[16];
 */
#define SK_IPV6_IS_ZERO(v6_byte_array)                                  \
    (0 == memcmp((v6_byte_array), sk_ipv6_zero, SK_IPV6_ZERO_LEN))
#define SK_IPV6_ZERO_LEN 16
extern const uint8_t sk_ipv6_zero[SK_IPV6_ZERO_LEN];


/*
 *  is_v4_in_v6 = SK_IPV6_IS_V4INV6(ipv6);
 *
 *    Return true if the specified ipv6 address represents an
 *    IPv6-encoded-IPv4 address, where ipv6 was defined as:
 *
 *    uint8_t ipv6[16];
 */
#define SK_IPV6_IS_V4INV6(v6_byte_array)                                   \
    (0 == memcmp((v6_byte_array), sk_ipv6_v4inv6, SK_IPV6_V4INV6_LEN))
#define SK_IPV6_V4INV6_LEN 12
extern const uint8_t sk_ipv6_v4inv6[SK_IPV6_V4INV6_LEN];


/* ****  skIPUnion_t  **** */

/* Macros dealing with skIPUnion_t's are typically for use by other
 * SiLK macros and functions.  These macros are subject to change at
 * any time. */

/* Get and Set the V4 part of the address structure */
#define skIPUnionGetV4(ipu)                     \
    ((ipu)->ipu_ipv4)

#define skIPUnionSetV4(ipu, in_vp)              \
    memcpy(&((ipu)->ipu_ipv4), (in_vp), 4)

#define skIPUnionApplyMaskV4(ipu, v4_mask)              \
    do { ((ipu)->ipu_ipv4) &= (v4_mask); } while(0)

/* Get the 'cidr' most significant bits of the V4 address */
#define skIPUnionGetCIDRV4(ipu, cidr)                   \
    (((cidr) >= 32)                                     \
     ? ((ipu)->ipu_ipv4)                                \
     : (((ipu)->ipu_ipv4) & ~(UINT32_MAX >> cidr)))

/* Set the V4 address to its 'cidr' most significant bits.  Assumes
 * the following: 0 <= 'cidr' < 32 */
#define skIPUnionApplyCIDRV4(ipu, cidr)                                 \
    do { (((ipu)->ipu_ipv4) &= ~(UINT32_MAX >> cidr)); } while(0)

#if SK_ENABLE_IPV6

/* Get and Set the V6 parts of the address structure */
#define skIPUnionGetV6(ipu, out_vp)             \
    memcpy((out_vp), (ipu)->ipu_ipv6, 16)

#define skIPUnionSetV6(ipu, in_vp)              \
    memcpy((ipu)->ipu_ipv6, (in_vp), 16)

/* Convert a pointer to a native uint32_t to an IPv6 byte array  */
#define skIPUnionU32ToV6(src_u32, dst_v6)                               \
    do {                                                                \
        uint32_t ipu32tov6 = htonl(*(src_u32));                         \
        memcpy((dst_v6), sk_ipv6_v4inv6, SK_IPV6_V4INV6_LEN);           \
        memcpy(((uint8_t*)(dst_v6)+SK_IPV6_V4INV6_LEN), &ipu32tov6, 4); \
    } while(0)

/* Write the V4 address into a V6 location. The two parameters can
 * point to the same skIPUnion_t. */
#define skIPUnionGetV4AsV6(ipu, ipv6)           \
    skIPUnionU32ToV6(&((ipu)->ipu_ipv4), ipv6)

/* Convert a V4 skIPUnion_t to an V6 skIPUnion_t. The two parameters
 * can point to the same skIPUnion_t. */
#define skIPUnion4to6(src_ipu, dst_ipu)                                 \
    skIPUnionU32ToV6(&((src_ipu)->ipu_ipv4), (dst_ipu)->ipu_ipv6)

#define skIPUnionApplyMaskV6(ipu, v6_mask)                              \
    do {                                                                \
        int ipuam;                                                      \
        for (ipuam = 0; ipuam < 16; ++ipuam) {                          \
            (ipu)->ipu_ipv6[ipuam] &= ((int8_t*)(v6_mask))[ipuam];      \
        }                                                               \
    } while(0)


/* Get the 'cidr' most significant bits of the V6 address */
#define skIPUnionGetCIDRV6(ipu, out_vp, cidr)                           \
    if ((cidr) >= 128) {                                                \
        skIPUnionGetV6((ipu), (out_vp));                                \
    } else {                                                            \
        int ipugc6 = (cidr) >> 3;                                       \
        memcpy((out_vp), (ipu)->ipu_ipv6, ipugc6);                      \
        ((uint8_t*)(out_vp))[ipugc6] = ((ipu)->ipu_ipv6[ipugc6]         \
                                        & ~(0xFF >> (0x7 & (cidr))));   \
        memset(&((uint8_t*)(out_vp))[ipugc6+1], 0, 15 - ipugc6);        \
    }

/* Set the V6 address to its 'cidr' most significant bits.  assumes
 * the following: 0 <= cidr < 128 */
#define skIPUnionApplyCIDRV6(ipu, cidr)                         \
    do {                                                        \
        int ipugc6 = (cidr) >> 3;                               \
        (ipu)->ipu_ipv6[ipugc6] &= ~(0xFF >> (0x7 & (cidr)));   \
        memset(&(ipu)->ipu_ipv6[ipugc6+1], 0, 15 - ipugc6);     \
    } while(0)
#endif  /* #if SK_ENABLE_IPV6 */


/* ****  skipaddr_t  **** */

/**
 *  is_v6 = skipaddrIsV6(ipaddr).
 *
 *    Return 1 if the skipaddr_t 'ipaddr' is an IPv6 address.  Return
 *    0 otherwise.
 */
#if 0
int
skipaddrIsV6(
    const skipaddr_t   *ipaddr);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#  define skipaddrIsV6(addr)   0
#else
#  define skipaddrIsV6(addr)   ((addr)->ip_is_v6)
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  skipaddrSetVersion(addr, is_v6);
 *
 *    If 'is_v6' is non-zero, specify that the skipaddr_t 'addr'
 *    contains an IPv6 address.  This does not modify the
 *    representation of the IP address.  See also skipaddrV4toV6().
 */
#if 0
void
skipaddrSetVersion(
    skipaddr_t         *ipaddr,
    int                 is_v6);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#  define skipaddrSetVersion(addr, is_v6)
#else
#  define skipaddrSetVersion(addr, is_v6)     \
    do { (addr)->ip_is_v6 = !!(is_v6); } while(0)
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  skipaddrCopy(dst, src);
 *
 *    Copy the skipaddr_t pointed at by 'src' to the location of the
 *    skipaddr_t pointed at by 'dst'.
 */
#if 0
void
skipaddrCopy(
    skipaddr_t         *dst,
    const skipaddr_t   *src);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#  define skipaddrCopy(dst, src)                                        \
    do {                                                                \
        skIPUnionGetV4(&(dst)->ip_ip) = skIPUnionGetV4(&(src)->ip_ip);  \
    } while(0)
#else
#  define skipaddrCopy(dst, src)   memcpy((dst), (src), sizeof(skipaddr_t))
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  skipaddrClear(addr);
 *
 *    Set all bits in the skipaddr_t pointed at by 'addr' to 0.  This
 *    causes 'addr' to represent the IPv4 address 0.0.0.0.
 */
#if 0
void
skipaddrClear(
    skipaddr_t         *ipaddr);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#  define skipaddrClear(addr)                           \
    do { skIPUnionGetV4(&(addr)->ip_ip) = 0; } while(0)
#else
#  define skipaddrClear(addr)   memset((addr), 0, sizeof(skipaddr_t))
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  ipv4 = skipaddrGetV4(addr);
 *
 *    Treat the skipaddr_t 'addr' as containing an IPv4 address and
 *    return that value in native (host) byte order.  To properly
 *    handle the cases where 'addr' contains an IPv6 address, use
 *    skipaddrGetAsV4().
 */
#if 0
uint32_t
skipaddrGetV4(
    const skipaddr_t   *addr);
#endif  /* 0 */
#define skipaddrGetV4(addr)    (skIPUnionGetV4(&((addr)->ip_ip)))


/**
 *  is_v4_mapped_v6 = skipaddrIsV4MappedV6(addr);
 *
 *    Return true if 'addr' is an IPv6 address and is in the
 *    ::ffff:0:0/96 netblock.  That is, whether 'addr' is an
 *    IPv4-mapped IPv6 address.
 *
 *    Return false if 'addr' is an IPv4 address.
 *
 *    If the IPv4 address is wanted, use skipaddrGetAsV4() which
 *    extracts the IPv4 address and returns 0 if successful or returns
 *    -1 if the address is not IPv4 nor an IPv4-mapped IPv6 address.
 *
 *    Since SiLK 3.17.0.
 */
#if 0
int
skipaddrIsV4MappedV6(
    const skipaddr_t   *ipaddr);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#  define skipaddrIsV4MappedV6(addr)    0
#else
#  define skipaddrIsV4MappedV6(addr)                                    \
    ((addr)->ip_is_v6 && SK_IPV6_IS_V4INV6((addr)->ip_ip.ipu_ipv6))
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  ok = skipaddrGetAsV4(addr, &ipv4);
 *
 *    If the skipaddr_t 'addr' contains an IPv4 address or an
 *    IPv4-mapped IPv6 address (i.e., an address in the ::ffff:0:0/96
 *    netblock), set the value pointed at by the uint32_t 'ipv4' to
 *    the IPv4 address (in native (host) byte order) and return 0.
 *    Otherwise leave the value pointed at by 'ipv4' unchanged and
 *    return -1.
 *
 *    If 'addr' is known to be IPv4, consider using skipaddrGetV4().
 *
 *    If 'addr' is known to be IPv6 and the IPv4-mapped address is not
 *    needed, you may check whether this function would return 0 by
 *    using skipaddrIsV4MappedV6().
 */
#if !SK_ENABLE_IPV6
/* use comma expression so expression evaluates to 0 */
#  define skipaddrGetAsV4(addr, ipv4_ptr)       \
    ((*(ipv4_ptr) = skipaddrGetV4(addr)), 0)
#else
int
skipaddrGetAsV4(
    const skipaddr_t   *addr,
    uint32_t           *ipv4);
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  skipaddrSetV4(addr, src);
 *
 *    Copy the uint32_t refereneced by 'src' into the skipaddr_t
 *    'addr' and set the 'addr' as containing an IPv4 address.  'src'
 *    should be in native (host) byte order.
 */
#if 0
void
skipaddrSetV4(
    skipaddr_t         *addr,
    uint32_t            src);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#  define skipaddrSetV4(addr, in_vp)            \
    skIPUnionSetV4(&((addr)->ip_ip), in_vp)
#else
#define skipaddrSetV4(addr, in_vp)                      \
    do {                                                \
        skipaddrClear(addr);                            \
        skIPUnionSetV4(&((addr)->ip_ip), (in_vp));      \
    } while(0)
#endif  /* #else of #if !SK_ENABLE_IPV6 */


#if SK_ENABLE_IPV6

/**
 *  skipaddrGetV6(addr, dst);
 *
 *    Treat 'addr' as containing an IPv6 address and copy that value
 *    into the uint8_t[16] refereneced by 'dst'.  To properly handle
 *    the cases where 'addr' contains an IPv4 address, use
 *    skipaddrGetAsV6().
 */
#if 0
void
skipaddrGetV6(
    const skipaddr_t   *addr,
    uint8_t             dst[16]);
#endif  /* 0 */
#define skipaddrGetV6(addr, out_vp)             \
    skIPUnionGetV6(&((addr)->ip_ip), (out_vp))


/**
 *  skipaddrGetAsV6(addr, dst);
 *
 *    Copy an IPv6 representation of the skipaddr_t 'addr' to the
 *    uint8_t[16] referenced by 'dst'.  If 'addr' contains an IPv4
 *    address, the result contains an IPv4-mapped IPv6 address (that
 *    is, an IPv6 address in the ::ffff:0:0/96 netblock).
 *
 *    If 'addr' is known to be IPv6, consider using skipaddrGetV6().
 */
#if 0
void
skipaddrGetAsV6(
    const skipaddr_t   *addr,
    uint8_t             dst[16]);
#endif  /* 0 */
#define skipaddrGetAsV6(addr, out_vp)                   \
    if (skipaddrIsV6(addr)) {                           \
        skIPUnionGetV6(&((addr)->ip_ip), (out_vp));     \
    } else {                                            \
        skIPUnionGetV4AsV6(&((addr)->ip_ip), (out_vp)); \
    }


/**
 *  skipaddrSetV6(addr, src);
 *
 *    Copy the uint8_t[16] refereneced by 'src' into the skipaddr_t
 *    'addr' and set the 'addr' as containing an IPv6 address.
 */
#if 0
void
skipaddrSetV6(
    skipaddr_t         *addr,
    uint8_t             src[16]);
#endif  /* 0 */
#define skipaddrSetV6(addr, in_vp)                      \
    do {                                                \
        skIPUnionSetV6(&((addr)->ip_ip), (in_vp));      \
        (addr)->ip_is_v6 = 1;                           \
    } while(0)


/**
 *  skipaddrSetV6FromUint32(addr, src);
 *
 *    Treat the uint32_t refereneced by 'src' as an IPv4 address in
 *    native (host) byte order, convert it to an IPv6 address, and
 *    store the result in skipaddr_t 'addr'.
 */
#if 0
void
skipaddrSetV6FromUint32(
    skipaddr_t         *addr,
    const uint32_t     *src);
#endif  /* 0 */
#define skipaddrSetV6FromUint32(addr, in_vp)            \
    do {                                                \
        uint8_t v6fromu32[16];                          \
        skIPUnionU32ToV6((in_vp), v6fromu32);           \
        skIPUnionSetV6(&((addr)->ip_ip), v6fromu32);    \
        (addr)->ip_is_v6 = 1;                           \
    } while(0)

/**
 *  skipaddrV4toV6(srcaddr, dstaddr);
 *
 *    Assume the skipaddr_t 'srcaddr' contains an IPv4 address,
 *    convert that address to an IPv4-mapped IPv6 address (that is, an
 *    address in the ::ffff:0:0/96 netblock), and store the result in
 *    the skipaddr_t 'dstaddr'. 'srcaddr' and 'dstaddr' may point to
 *    the same skipaddr_t.
 */
#if 0
void
skipaddrV4toV6(
    const skipaddr_t   *srcaddr,
    skipaddr_t         *dstaddr);
#endif  /* 0 */
#define skipaddrV4toV6(srcaddr, dstaddr)                                \
    do {                                                                \
        skIPUnion4to6(&((srcaddr)->ip_ip), &((dstaddr)->ip_ip));        \
        (dstaddr)->ip_is_v6 = 1;                                        \
    } while(0)


/**
 *  ok = skipaddrV6toV4(srcaddr, dstaddr);
 *
 *    Assume the skipaddr_t 'srcaddr' contains an IPv6 address. If
 *    that address is an IPv4-mapped IPv6 address (that is, an address
 *    in the ::ffff:0:0/96 netblock), convert the address to IPv4,
 *    store the result in the skipaddr_t 'dstaddr', and return 0.
 *    Otherwise, return -1 and leave 'dstaddr' unchanged. 'srcaddr'
 *    and 'dstaddr' may point to the same skipaddr_t.
 */
int
skipaddrV6toV4(
    const skipaddr_t   *srcaddr,
    skipaddr_t         *dstaddr);
#endif  /* #if SK_ENABLE_IPV6 */


/**
 *  cmp = skipaddrCompare(addr1, addr2);
 *
 *    Compare the value of the skipaddr_t objects 'addr1' and 'addr2'.
 *
 *    Return 0 if 'addr1' is equal to 'addr2'; return a value less
 *    than 0 if 'addr1' is less than 'addr2'; return a value greater
 *    than 0 if 'addr1' is greater than 'addr2'.
 *
 *    When IPv6 is enabled and either address is IPv6, the comparison
 *    is done as if both addresses were IPv6 by mapping an IPv4
 *    address to the ::ffff:0:0/96 netblock.
 */
#if !SK_ENABLE_IPV6
#  define skipaddrCompare(addr1, addr2)                         \
    (((addr1)->ip_ip.ipu_ipv4 < (addr2)->ip_ip.ipu_ipv4)        \
     ? -1                                                       \
     : (((addr1)->ip_ip.ipu_ipv4 > (addr2)->ip_ip.ipu_ipv4)     \
        ? 1                                                     \
        : 0))
#else
int
skipaddrCompare(
    const skipaddr_t   *addr1,
    const skipaddr_t   *addr2);
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  skipaddrMask(ipaddr, mask_ip);
 *
 *    Apply the bit-mask in the skipaddr_t 'mask_ip' to the skipaddr_t
 *    'ipaddr'.
 *
 *    When both addresses are either IPv4 or IPv6, applying the mask
 *    is straightforward.
 *
 *    When 'ipaddr' is IPv6 and 'mask_ip' is IPv4, the function
 *    converts 'mask_ip' to an IPv4-mapped IPv6 (i.e., an address in
 *    the ::ffff:0:0/96 netblock) and then applies the mask.  The
 *    result is an IPv6 address.
 *
 *    When 'ipaddr' is IPv4 and 'mask_ip' is IPv6, the function
 *    converts 'ipaddr' to an IPv4-mapped IPv6 address and performs
 *    the mask.  If the result is still an IPv4-mapped IPv6 address,
 *    the function converts the result back to IPv4; otherwise the
 *    result remains an IPv6 address.
 */
#if !SK_ENABLE_IPV6
#  define skipaddrMask(ipaddr, mask_ip)                         \
    do {                                                        \
        (ipaddr)->ip_ip.ipu_ipv4 &= (mask_ip)->ip_ip.ipu_ipv4;  \
    } while(0)
#else
void
skipaddrMask(
    skipaddr_t         *ipaddr,
    const skipaddr_t   *mask_ip);
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  skipaddrApplyCIDR(ipaddr, cidr_prefix);
 *
 *    Apply the numeric CIDR prefix 'cidr_prefix' to the skipaddr_t
 *    'ipaddr', zeroing all but the most significant 'cidr_prefix'
 *    bits.
 *
 *    If a CIDR prefix too large for the address is given, it will be
 *    ignored.
 */
#if 0
void
skipaddrApplyCIDR(
    skipaddr_t         *ipaddr,
    uint32_t            cidr_prefix);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#  define skipaddrApplyCIDR(ipaddr, cidr)               \
    if ((cidr) >= 32) { /* no-op */ } else {            \
        skIPUnionApplyCIDRV4(&(ipaddr)->ip_ip, cidr);   \
    }
#else
#  define skipaddrApplyCIDR(ipaddr, cidr)                       \
    if (skipaddrIsV6(ipaddr)) {                                 \
        if ((cidr) < 128) {                                     \
            skIPUnionApplyCIDRV6(&((ipaddr)->ip_ip), cidr);     \
        }                                                       \
    } else {                                                    \
        if ((cidr) < 32) {                                      \
            skIPUnionApplyCIDRV4(&((ipaddr)->ip_ip), cidr);     \
        }                                                       \
    }
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  skipaddrIncrement(ipaddr);
 *
 *    Add one to the integer representation of the IP address in the
 *    skipaddr_t 'ipaddr'.  If overflow occurs, wrap the value back to
 *    0.
 */
#if 0
void
skipaddrIncrement(
    skipaddr_t         *ipaddr);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#define skipaddrIncrement(addr)                 \
    ((void)(++(addr)->ip_ip.ipu_ipv4))
#else
#define skipaddrIncrement(addr)                                         \
    if (!skipaddrIsV6(addr)) {                                          \
        ++(addr)->ip_ip.ipu_ipv4;                                       \
    } else {                                                            \
        int incr_idx;                                                   \
        for (incr_idx = 15; incr_idx >= 0; --incr_idx) {                \
            if (UINT8_MAX != (addr)->ip_ip.ipu_ipv6[incr_idx]) {        \
                ++(addr)->ip_ip.ipu_ipv6[incr_idx];                     \
                break;                                                  \
            }                                                           \
            (addr)->ip_ip.ipu_ipv6[incr_idx] = 0;                       \
        }                                                               \
    }
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  skipaddrDecrement(ipaddr);
 *
 *    Subtract one from the integer representation of the IP address
 *    in the skipaddr_t 'ipaddr'.  If underflow occurs, wrap the value
 *    back to the maximum.
 */
#if 0
void
skipaddrDecrement(
    skipaddr_t         *ipaddr);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#define skipaddrDecrement(addr)                 \
    ((void)(--(addr)->ip_ip.ipu_ipv4))
#else
#define skipaddrDecrement(addr)                                         \
    if (!skipaddrIsV6(addr)) {                                          \
        --(addr)->ip_ip.ipu_ipv4;                                       \
    } else {                                                            \
        int decr_idx;                                                   \
        for (decr_idx = 15; decr_idx >= 0; --decr_idx) {                \
            if (0 != (addr)->ip_ip.ipu_ipv6[decr_idx]) {                \
                --(addr)->ip_ip.ipu_ipv6[decr_idx];                     \
                break;                                                  \
            }                                                           \
            (addr)->ip_ip.ipu_ipv6[decr_idx] = UINT8_MAX;               \
        }                                                               \
    }
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  is_zero = skipaddrIsZero(ipaddr);
 *
 *    Return 1 if the IP address in the skipaddr_t 'ipaddr' contains
 *    no high bits.  Return 0 otherwise.
 *
 *    skipaddrIsZero(skipaddrClear(ipaddr)) returns 1.
 */
#if 0
int
skipaddrIsZero(
    const skipaddr_t   *ipaddr);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#  define skipaddrIsZero(addr) (0 == (addr)->ip_ip.ipu_ipv4)
#else
#  define skipaddrIsZero(addr)                                          \
    (skipaddrIsV6(addr)                                                 \
     ? SK_IPV6_IS_ZERO((addr)->ip_ip.ipu_ipv6)                          \
     : (0 == (addr)->ip_ip.ipu_ipv4))
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/* ****  skcidr_t  **** */

/**
 *    skcidr_t represents a CIDR block or net-block.  The structure
 *    holds an IP address and the number of subnet bits.
 */
typedef union skcidr_un {
    struct cidr_un_v4 {
        /* whether this value contains an IPv6 mask */
        uint8_t  is_ipv6;
        /* length of the subnet (in bits). */
        uint8_t  cidr_length;
        /* placeholders for alignment */
        uint8_t  unused2;
        uint8_t  unused3;
        /* the base IP of the CIDR block */
        uint32_t ip;
        /* pre-computed mask where the upper length bits are high */
        uint32_t mask;
    } v4;
#if SK_ENABLE_IPV6
    struct cidr_un_v6 {
        /* whether this value contains an IPv6 mask */
        uint8_t  is_ipv6;
        /* length of the subnet (in bits). */
        uint8_t  cidr_length;
        /* number of bytes to memcmp() when comparing IP to CIDR */
        uint8_t  byte_length;
        /* pre-computed mask to use when comparing the
         * "ip[byte_length-1]" byte */
        uint8_t  mask;
        /* the base IP of the CIDR block */
        uint8_t  ip[16];
    } v6;
#endif  /* #if SK_ENABLE_IPV6 */
} skcidr_t;


/**
 *  in_cidr = skcidrCheckIP(cidr, ipaddr);
 *
 *    Return a true value if 'ipaddr' is contained in the CIDR block
 *    represented by 'cidr'.  Return false otherwise.
 *
 *    When 'cidr' is IPv6 and 'ipaddr' is IPv4, the function maps 'ipaddr' to
 *    ::ffff:0:0/96 prior to the check.
 *
 *    When 'cidr' is IPv4 and 'ipaddr' is IPv6, an 'ipaddr' in the
 *    ::ffff:0:0/96 netblock is mapped to IPv4 prior to the check and the
 *    function returns false for all other IPv6 addresses.
 */
#if !SK_ENABLE_IPV6
#define skcidrCheckIP(cidr, ipaddr)                             \
    ((skipaddrGetV4(ipaddr) & cidr->v4.mask) == (cidr)->v4.ip)
#else
int
skcidrCheckIP(
    const skcidr_t     *cidr,
    const skipaddr_t   *ipaddr);
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  skcidrClear(cidr);
 *
 *    Set all bits in the skcidr_t pointed at by 'cidr' to 0.
 */
#if 0
void
skcidrClear(
    skcidr_t           *cidr);
#endif  /* 0 */
#define skcidrClear(cidr)           memset(cidr, 0, sizeof(skcidr_t))


/**
 *  skcidrGetIPAddr(cidr, ipaddr);
 *
 *    Fill 'ipaddr' with the IP address contained by 'cidr'; that is,
 *    with the first IP address in the CIDR block represented by
 *    'cidr'.
 */
void
skcidrGetIPAddr(
    const skcidr_t     *cidr,
    skipaddr_t         *ipaddr);


/**
 *  len = skcidrGetLength(cidr);
 *
 *    Return the length of the subnet represented by 'cidr'.
 */
#if 0
uint8_t
skcidrGetLength(
    const skcidr_t     *cidr);
#endif  /* 0 */
#define skcidrGetLength(cidr)       ((cidr)->v4.cidr_length)


/**
 *  skcidrIsV6(cidr);
 *
 *    Return 1 if the skcidr_t pointed at by 'cidr' contains IPv6
 *    data.  Return 0 otherwise.
 */
#if 0
int
skcidrIsV6(
    const skcidr_t     *cidr);
#endif  /* 0 */
#if !SK_ENABLE_IPV6
#  define skcidrIsV6(cidr)          (0)
#else
#  define skcidrIsV6(cidr)          ((cidr)->v4.is_ipv6)
#endif  /* #else of #if !SK_ENABLE_IPV6 */


/**
 *  ok = skcidrSetFromIPAddr(cidr, ipaddr, length);
 *
 *    Set 'cidr' to the CIDR block that represents a subnet of
 *    'length' bits that has the IP in 'ipaddr' as its base.  Return
 *    -1 if 'length' is too long for the given 'ipaddr'.  Return 0
 *    otherwise.
 */
int
skcidrSetFromIPAddr(
    skcidr_t           *cidr,
    const skipaddr_t   *ipaddr,
    uint32_t            cidr_len);


/**
 *  ok = skcidrSetV4(cidr, ipv4, length);
 *
 *    Similar to skcidrSetFromIPAddr(), except use an integer
 *    representation of an IPv4 address.
 */
int
skcidrSetV4(
    skcidr_t           *cidr,
    uint32_t            ipv4,
    uint32_t            cidr_len);

#if SK_ENABLE_IPV6
/**
 *  ok = skcidrSetV6(cidr, ipv6, length);
 *
 *    Similar to skcidrSetFromIPAddr(), except use an array
 *    representation of an IPv6 address.
 */
int
skcidrSetV6(
    skcidr_t           *cidr,
    const uint8_t      *ipv6,
    uint32_t            cidr_len);
#endif  /* #if SK_ENABLE_IPV6 */


/**
 *  ok = skipaddrToSockaddr(dest_sockaddr, len, src_ipaddr);
 *
 *    Clear 'dest_sockaddr', and then set the family and address of
 *    'dest_sockaddr' from 'src_ipaddr' where 'len' is the length of
 *    'dest_sockaddr'.  Return -1 if 'len' is too small, 0 otherwise.
 */
int
skipaddrToSockaddr(
    struct sockaddr    *dest_sockaddr,
    size_t              len,
    const skipaddr_t   *src_ipaddr);

/**
 *  ok = skipaddrFromSockaddr(dest_ipaddr, src)
 *
 *    Set 'dest_ipaddr' to the address in 'src_sockaddr'.  Return -1
 *    if 'src_sockaddr' does not represent an IP address, 0 otherwise.
 */
int
skipaddrFromSockaddr(
    skipaddr_t             *dest_ipaddr,
    const struct sockaddr  *src_sockaddr);


#ifdef __cplusplus
}
#endif
#endif /* _SKIPADDR_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
