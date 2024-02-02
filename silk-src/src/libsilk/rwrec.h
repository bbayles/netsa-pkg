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
**  rwrec.h
**
**    The SiLK Flow record (rwRec) definition and functions/macros for
**    manipulating it.
**
*/
#ifndef _RWREC_H
#define _RWREC_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWREC_H, "$SiLK: rwrec.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>

#ifndef RWREC_OPAQUE
#  define RWREC_OPAQUE 0
#  include <silk/skipaddr.h>
#endif


/*
 * The following documents macros defined in this file that work to
 * access and manipulate the data in an rwRec.  Although these are
 * macros, they have been documented as functions in order to convey
 * the expected types of the arguments.
 *
 * ****  Convenience macros  ****
 *
 *   void RWREC_CLEAR(rwRec *r);
 *    Zero out the record, and set Sensor ID and Flowtype to invalid
 *    values.
 *
 *   void RWREC_COPY(rwRec *dst, const rwRec *src);
 *    Copy the rwRec from 'src' to 'dst'.
 *
 *   int rwRecIsICMP(const rwRec *r);
 *    Returns non-zero if the record is an ICMP record, zero otherwise.
 *
 *   int rwRecIsWeb(const rwRec *r);
 *    Returns non-zero if the record can be represented using the SiLK
 *    web-specific file formats, zero otherwise.
 *
 *
 * **** More macros ****
 *
 * Function versions of all of the following macros exist.  Simply
 * change the "rwRec" prefix of the macro to "rwrec_" to use the
 * function version.
 *
 * ***  Whether a record is IPv6  ***
 *
 * int      rwRecIsIPv6(const rwRec *r);
 *
 * ***  Set record as IPv4 or IPv6  ***
 *
 * void     rwRecSetIPv6(rwRec *r);
 * void     rwRecSetIPv4(rwRec *r);
 *
 * It is important to note that the above two macros do not do any
 * conversions on the contained IP addresses.  They are primarily to
 * be used when creating a new rwRec from scratch.  See the following
 * for conversion.
 *
 * ***  Convert record to IPv4 or IPv6  ***
 *
 * int      rwRecConvertToIPv4(rwRec *r);
 * void     rwRecConvertToIPv6(rwRec *r);
 *
 * These macros convert an rwRec to IPv4 or IPv6.  The latter always
 * succeeds.  The former will return -1 if unable to convert due to
 * the existence of IPv6 addresses that cannot be represented as IPv4
 * (and return zero on success).
 *
 * ****  rwRec accessor macros ****
 *
 * Most of the following accessor macros come in five standard
 * variations:
 *
 *   <fieldtype> rwRecGet<field>(const reRec *r)
 *    Gets the value of the field directly
 *
 *   void rwRecSet<field>(rwRec *r, <fieldtype> in_v)
 *    Sets the value of the field to 'in_v'
 *
 *   void rwRecMemGet<field>(const rwRec *r, <fieldtype> *out_vp)
 *    Copies the value of the field to location out_vp
 *
 *   void rwRecMemSet<field>(rwRec *r, const <fieldtype> *in_vp)
 *    Copies the value in location in_vp into the field
 *
 *   int rwRecMemCmp<field>(const rwRec *r, const <fieldtype> *vp)
 *    Compares the field to the value in location vp, returning a
 *    negative integer if the field is less than vp, 0 if equal, and a
 *    positive integer if greater than vp.
 *
 * For the rwRecMem{Get,Set,Cmp}<field>() macros, we use of
 * <fieldtype> in the comment to explain the size of the data
 * involved.  With the exception of those dealing the skipaddr_t
 * objects, the actual functions use void pointers; as a result, those
 * macros do not require the value pointer to be aligned.  The macros
 * that handle values larger than uint8_t use memcpy() or memcmp() to
 * copy or compare the values.
 *
 * ** IP Address Macros **
 *
 * For handling IP addresses, there are three sets of macros: one for
 * IPv4 addresses: one for IPv6 addresses, and one for skipaddr_t
 * objects, which can represent either an IPv4 address or and IPv6
 * object.
 *
 * In addition to the Get, Set, and Comparison macros, the follow
 * macro exists in IPv4, IPv6, and skipaddr_t varieties:
 *
 *   void rwRecApplyMask<field>(rwRec *r, const <fieldtype> mask);
 *    Modify the rwRec's <field> IP addresses by applying the
 *    specified mask (using a bit-wise AND) to that IP address.
 *
 * All of the macros that deal with IPv4 addresses assume that you
 * know the rwRec holds IPv4 addresses.  No conversion of the rwRec or
 * of the address occurs.
 *
 * Using the Get macros for IPv6 on an rwRec that contains V4 data
 * will return a properly encoded IPv4-in-IPv6 address.  All other
 * macros for IPv6 assume you know that the rwRec holds IPv6
 * addresses.  For IPv6, the rwRecGet<field>() and rwRecSet<field>()
 * macros do not exist; you must use the rwRecMemGet<field>() and
 * rwRecMemSet<field>() versions.
 *
 * Since an skipaddr_t can hold an IPv4 or an IPv6 address, the macros
 * that use skipaddr_t objects will correctly handle with rwRecs that
 * hold IPv4 or IPv6 data.  Setting or masking an IPv4 rwRec with an
 * IPv6 skipaddr_t may convert the record to IPv6.  The comparison
 * macros will operate in IPv6 space if either argument involves IPv6.
 * Unlike all other rwRecMem{Get,Set,Cmp}<field>() macros, the
 * functions that work with skipaddr_t pointers require the skipaddr_t
 * to be properly aligned.
 *
 * The IPv4 macros include an extra DEPRECATED macro:
 *
 *   uint32_t rwRecGetMask<field>v4(rwRec *r, uint32_t mask)
 *    Gets the value of the field with the given bit-mask applied
 *
 * ***  Source IPv4 Address (sIP)  ***
 *
 * uint32_t rwRecGetSIPv4(const rwRec *r);
 * void     rwRecSetSIPv4(rwRec *r, uint32_t in_v);
 * void     rwRecMemGetSIPv4(const rwRec *r, uint32_t *out_vp);
 * void     rwRecMemSetSIPv4(rwRec *r, const uint32_t *in_vp);
 * int      rwRecMemCmpSIPv4(const rwRec *r, const uint32_t *vp);
 * void     rwRecApplyMaskSIPv4(rwRec *r, uint32_t mask);
 * uint32_t rwRecGetMaskSIPv4(const rwRec *r, uint32_t mask);
 *
 * ***  Source IPv6 Address (sIP)  ***
 *
 * void     rwRecMemGetSIPv6(const rwRec *r, uint8_t[16] out_vp);
 * void     rwRecMemSetSIPv6(rwRec *r, const uint8_t[16] in_vp);
 * int      rwRecMemCmpSIPv6(const rwRec *r, const uint8_t[16] vp);
 * void     rwRecApplyMaskSIPv6(rwRec *r, const uint8_t[16] mask);
 *
 * ***  Source IP Address (sIP) as skipaddr_t  ***
 *
 * void     rwRecMemGetSIP(const rwRec *r, skipaddr_t *out_addr);
 * void     rwRecMemSetSIP(rwRec *r, const skipaddr_t *in_addr);
 * int      rwRecMemCmpSIP(const rwRec *r, const skipaddr_t *addr);
 * void     rwRecApplyMaskSIP(rwRec *r, const skipaddr_t *mask);
 *
 * ***  Destination IP Address (dIP)  ***
 *
 * uint32_t rwRecGetDIPv4(const rwRec *r);
 * void     rwRecSetDIPv4(rwRec *r, uint32_t in_v);
 * void     rwRecMemGetDIPv4(const rwRec *r, uint32_t *out_vp);
 * void     rwRecMemSetDIPv4(rwRec *r, const uint32_t *in_vp);
 * int      rwRecMemCmpDIPv4(const rwRec *r, const uint32_t *vp);
 * void     rwRecApplyMaskDIPv4(rwRec *r, uint32_t mask);
 * uint32_t rwRecGetMaskDIPv4(const rwRec *r, uint32_t mask);
 *
 * ***  Destination IPv6 Address (dIP)  ***
 *
 * void     rwRecMemGetDIPv6(const rwRec *r, uint8_t[16] out_vp);
 * void     rwRecMemSetDIPv6(rwRec *r, const uint8_t[16] in_vp);
 * int      rwRecMemCmpDIPv6(const rwRec *r, const uint8_t[16] vp);
 * void     rwRecApplyMaskDIPv6(rwRec *r, const uint8_t[16] mask);
 *
 * ***  Destination IP Address (dIP) as skipaddr_t  ***
 *
 * void     rwRecMemGetDIP(const rwRec *r, skipaddr_t *out_addr);
 * void     rwRecMemSetDIP(rwRec *r, const skipaddr_t *in_addr);
 * int      rwRecMemCmpDIP(const rwRec *r, const skipaddr_t *addr);
 * void     rwRecApplyMaskDIP(rwRec *r, const skipaddr_t *mask);
 *
 * ***  Next Hop IP Address  ***
 *
 * uint32_t rwRecGetNhIPv4(const rwRec *r);
 * void     rwRecSetNhIPv4(rwRec *r, uint32_t in_v);
 * void     rwRecMemGetNhIPv4(const rwRec *r, uint32_t *out_vp);
 * void     rwRecMemSetNhIPv4(rwRec *r, const uint32_t *in_vp);
 * int      rwRecMemCmpNhIPv4(const rwRec *r, const uint32_t *vp);
 * void     rwRecApplyMaskNhIPv4(rwRec *r, uint32_t mask);
 * uint32_t rwRecGetMaskNhIPv4(const rwRec *r, uint32_t mask);
 *
 * ***  Next Hop IPv6 Address (nhIP)  ***
 *
 * void     rwRecMemGetNhIPv6(const rwRec *r, uint8_t[16] out_vp);
 * void     rwRecMemSetNhIPv6(rwRec *r, const uint8_t[16] in_vp);
 * int      rwRecMemCmpNhIPv6(const rwRec *r, const uint8_t[16] vp);
 * void     rwRecApplyMaskNhIPv6(rwRec *r, const uint8_t[16] mask);
 *
 * ***  Next Hop IP Address (nhIP) as skipaddr_t  ***
 *
 * void     rwRecMemGetNhIP(const rwRec *r, skipaddr_t *out_addr);
 * void     rwRecMemSetNhIP(rwRec *r, const skipaddr_t *in_addr);
 * int      rwRecMemCmpNhIP(const rwRec *r, const skipaddr_t *addr);
 * void     rwRecApplyMaskNhIP(rwRec *r, const skipaddr_t *mask);
 *
 * ***  Source Port (sPort)  ***
 *
 * uint16_t rwRecGetSPort(const rwRec *r);
 * void     rwRecSetSPort(rwRec *r, uint16_t in_v);
 * void     rwRecMemGetSPort(const rwRec *r, uint16_t *out_vp);
 * void     rwRecMemSetSPort(rwRec *r, const uint16_t *in_vp);
 * int      rwRecMemCmpSPort(const rwRec *r, const uint16_t *vp);
 *
 * ***  Destination Port (dPort)  ***
 *
 * uint16_t rwRecGetDPort(const rwRec *r);
 * void     rwRecSetDPort(rwRec *r, uint16_t in_v);
 * void     rwRecMemGetDPort(const rwRec *r, uint16_t *out_vp);
 * void     rwRecMemSetDPort(rwRec *r, const uint16_t *in_vp);
 * int      rwRecMemCmpDPort(const rwRec *r, const uint16_t *vp);
 *
 * ***  Protocol  ***
 *
 * uint8_t  rwRecGetProto(const rwRec *r);
 * void     rwRecSetProto(rwRec *r, uint8_t in_v);
 * void     rwRecMemGetProto(const rwRec *r, uint8_t *out_vp);
 * void     rwRecMemSetProto(rwRec *r, const uint8_t *in_vp);
 * int      rwRecMemCmpProto(const rwRec *r, const uint8_t *vp);
 *
 * ***  Packet Count (pkts)  ***
 *
 * uint32_t rwRecGetPkts(const rwRec *r);
 * void     rwRecSetPkts(rwRec *r, uint32_t in_v);
 * void     rwRecMemGetPkts(const rwRec *r, uint32_t *out_vp);
 * void     rwRecMemSetPkts(rwRec *r, const uint32_t *in_vp);
 * int      rwRecMemCmpPkts(const rwRec *r, const uint32_t *vp);
 *
 * ***  Byte count  ***
 *
 * uint32_t rwRecGetBytes(const rwRec *r);
 * void     rwRecSetBytes(rwRec *r, uint32_t in_v);
 * void     rwRecMemGetBytes(const rwRec *r, uint32_t *out_vp);
 * void     rwRecMemSetBytes(rwRec *r, const uint32_t *in_vp);
 * int      rwRecMemCmpBytes(const rwRec *r, const uint32_t *vp);
 *
 * ***  Bitwise OR of TCP Flags on ALL packets in flow  ***
 *
 * uint8_t  rwRecGetFlags(const rwRec *r);
 * void     rwRecSetFlags(rwRec *r, uint8_t in_v);
 * void     rwRecMemGetFlags(const rwRec *r, uint8_t *out_vp);
 * void     rwRecMemSetFlags(rwRec *r, const uint8_t *in_vp);
 * int      rwRecMemCmpFlags(const rwRec *r, const uint8_t *vp);
 *
 * ***  TCP Flags seen on initial packet of flow  ***
 *
 * uint8_t  rwRecGetInitFlags(const rwRec *r);
 * void     rwRecSetInitFlags(rwRec *r, uint8_t in_v);
 * void     rwRecMemGetInitFlags(const rwRec *r, uint8_t *out_vp);
 * void     rwRecMemSetInitFlags(rwRec *r, const uint8_t *in_vp);
 * int      rwRecMemCmpInitFlags(const rwRec *r, const uint8_t *vp);
 *
 * ***  Bitwise OR of TCP Flags on all packets in session except first  ***
 *
 * uint8_t  rwRecGetRestFlags(const rwRec *r);
 * void     rwRecSetRestFlags(rwRec *r, uint8_t in_v);
 * void     rwRecMemGetRestFlags(const rwRec *r, uint8_t *out_vp);
 * void     rwRecMemSetRestFlags(rwRec *r, const uint8_t *in_vp);
 * int      rwRecMemCmpRestFlags(const rwRec *r, const uint8_t *vp);
 *
 * ***  Start Time as milliseconds since UNIX epoch (sTime)  ***
 *
 * sktime_t rwRecGetStartTime(const rwRec *r);
 * void     rwRecSetStartTime(rwRec *r, sktime_t in_v);
 * void     rwRecMemGetStartTime(const rwRec *r, sktime_t *out_vp);
 * void     rwRecMemSetStartTime(rwRec *r, const sktime_t *in_vp);
 * int      rwRecMemCmpStartTime(const rwRec *r, const sktime_t *vp);
 *
 * uint32_t rwRecGetStartSeconds(const rwRec *r);
 * void     rwRecMemGetStartSeconds(const rwRec *r, uint32_t *out_vp);
 *
 * ***  End Time is derived from the sTime and duration (eTime)  ***
 *
 * sktime_t rwRecGetEndTime(const rwRec *r);
 * void     rwRecMemGetEndTime(const rwRec *r, sktime_t *out_vp);
 *
 * uint32_t rwRecGetEndSeconds(const rwRec *r);
 * void     rwRecMemGetEndSeconds(const rwRec *r, uint32_t *out_vp);
 *
 * There are no setter macros for end time, because end time is
 * derived from start time and duration (elapsed time).
 *
 * ***  Elapsed (duration) of the flow, in milliseconds  ***
 *
 * uint32_t rwRecGetElapsed(const rwRec *r);
 * void     rwRecSetElapsed(rwRec *r, uint32_t in_v);
 * void     rwRecMemGetElapsed(const rwRec *r, uint32_t *out_vp);
 * void     rwRecMemSetElapsed(rwRec *r, const uint32_t *in_vp);
 * int      rwRecMemCmpElapsed(const rwRec *r, const uint32_t *vp);
 *
 * uint32_t rwRecGetElapsedSeconds(const rwRec *r);
 * void     rwRecMemGetElapsedSeconds(const rwRec *r, uint32_t *out_vp);
 *
 * ***  Sensor ID (sID)  ***
 *
 * sensorID_t rwRecGetSensor(const rwRec *r);
 * void     rwRecSetSensor(rwRec *r, sensorID_t in_v);
 * void     rwRecMemGetSensor(const rwRec *r, sensorID_t *out_vp);
 * void     rwRecMemSetSensor(rwRec *r, const sensorID_t *in_vp);
 * int      rwRecMemCmpSensor(const rwRec *r, const sensorID_t *vp);
 *
 * ***  FlowType holds Class and Type  ***
 *
 * flowtypeID_t rwRecGetFlowType(const rwRec *r);
 * void     rwRecSetFlowType(rwRec *r, flowtypeID_t in_v);
 * void     rwRecMemGetFlowType(const rwRec *r, flowtypeID_t *out_vp);
 * void     rwRecMemSetFlowType(rwRec *r, const flowtypeID_t *in_vp);
 * int      rwRecMemCmpFlowType(const rwRec *r, const flowtypeID_t *vp);
 *
 * ***  SNMP Input Value (Router incoming/ingress interface/vlanId) ***
 *
 * uint16_t rwRecGetInput(const rwRec *r);
 * void     rwRecSetInput(rwRec *r, uint16_t in_v);
 * void     rwRecMemGetInput(const rwRec *r, uint16_t *out_vp);
 * void     rwRecMemSetInput(rwRec *r, const uint16_t *in_vp);
 * int      rwRecMemCmpInput(const rwRec *r, const uint16_t *vp);
 *
 * ***  SNMP Output Value (Router outgoing/egress interface/postVlanId) ***
 *
 * uint16_t rwRecGetOutput(const rwRec *r);
 * void     rwRecSetOutput(rwRec *r, uint16_t in_v);
 * void     rwRecMemGetOutput(const rwRec *r, uint16_t *out_vp);
 * void     rwRecMemSetOutput(rwRec *r, const uint16_t *in_vp);
 * int      rwRecMemCmpOutput(const rwRec *r, const uint16_t *vp);
 *
 * ***  TCP State (the Attributes field)  ***
 *
 * uint8_t  rwRecGetTcpState(const rwRec *r);
 * void     rwRecSetTcpState(rwRec *r, uint8_t in_v);
 * void     rwRecMemGetTcpState(const rwRec *r, uint8_t *out_vp);
 * void     rwRecMemSetTcpState(rwRec *r, const uint8_t *in_vp);
 * int      rwRecMemCmpTcpState(const rwRec *r, const uint8_t *vp);
 *
 * The TCP state field is a bit field which states certain miscellaneous
 * information about the flow record.  The following constants are
 * defined which represent this information:
 *
 * #define SK_TCPSTATE_EXPANDED              0x01
 *  Expanded TCP-flags: This bit must be set if and only if the flow
 *  is TCP and the init_flags and rest_flags fields are set.
 *
 * #define SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK  0x08
 *  Flow received packets following the FIN packet that were not ACK or
 *  RST packets.
 *
 * #define SK_TCPSTATE_UNIFORM_PACKET_SIZE   0x10
 *  Flow has packets all of the same size
 *
 * #define SK_TCPSTATE_TIMEOUT_KILLED        0x20
 *  Flow ends prematurely due to a timeout by the collector.
 *
 * #define SK_TCPSTATE_TIMEOUT_STARTED       0x40
 *  Flow is a continuation of a previous flow that was killed
 *  prematurely due to a timeout by the collector.
 *
 * Note: the most significant bit of tcp_state (0x80) is used as a flag
 * to mark a record as having IPv6 addresses.  The rwRecSetIPv4() and
 * rwRecSetIPv6() macros should be used to modify this bit.
 *
 * Be careful when setting the TCP state.  You usually want get the
 * current TCP state, add or remove specific bits by masking, then set it
 * with the resulting value.
 *
 * ***  Application  ***
 *
 * uint16_t rwRecGetApplication(const rwRec *r);
 * void     rwRecSetApplication(rwRec *r, uint16_t in_v);
 * void     rwRecMemGetApplication(const rwRec *r, uint16_t *out_vp);
 * void     rwRecMemSetApplication(rwRec *r, const uint16_t *in_vp);
 * int      rwRecMemCmpApplication(const rwRec *r, const uint16_t *vp);
 *
 * The application field can be set by the yaf flow generation
 * software when it is configured with the "applabel" feature.  This
 * feature causes yaf to inspect the packets in the flow and guess as
 * to the type of application (HTTP, SMTP, SSH, etc) the packets
 * represent.  The value for the field is the standard service port
 * for that service (80, 25, 22, etc).
 *
 * ***  Memo  ***
 *
 * uint16_t rwRecGetMemo(const rwRec *r);
 * void     rwRecSetMemo(rwRec *r, uint16_t in_v);
 * void     rwRecMemGetMemo(const rwRec *r, uint16_t *out_vp);
 * void     rwRecMemSetMemo(rwRec *r, const uint16_t *in_vp);
 * int      rwRecMemCmpMemo(const rwRec *r, const uint16_t *vp);
 *
 * Currently unused.
 *
 * ***  ICMP Type and Code is derived from the DPort  ***
 *
 * uint8_t  rwRecGetIcmpType(const rwRec *r);
 * void     rwRecSetIcmpType(rwRec *r, uint8_t in_v);
 * void     rwRecMemGetIcmpType(const rwRec *r, uint8_t *out_vp);
 *
 * uint8_t  rwRecGetIcmpCode(const rwRec *r);
 * void     rwRecSetIcmpCode(rwRec *r, uint8_t in_v);
 * void     rwRecMemGetIcmpCode(const rwRec *r, uint8_t *out_vp);
 *
 * uint16_t rwRecGetIcmpTypeAndCode(const rwRec *r);
 * void     rwRecSetIcmpTypeAndCode(rwRec *r, uint16_t in_v);
 * void     rwRecMemGetIcmpTypeAndCode(const rwRec *r, uint16_t *out_vp);
 * void     rwRecMemSetIcmpTypeAndCode(rwRec *r, const uint16_t *in_vp);
 * int      rwRecMemCmpIcmpTypeAndCode(const rwRec *r, const uint16_t *vp);
 *
 * Since the ICMP Type and Code are stored in the dport field, modifying
 * these will modify the return value of rwRecGetDPort() and friends.
 */


#define SK_WEBPORT_CHECK(p) ((p) == 80 || (p) == 443 || (p) == 8080)
/*
 *    Return a true value if port 'p' is a "web" port; false otherwise
 */

#define RWREC_CLEAR(rec)                                     \
    do {                                                     \
        memset((rec), 0, sizeof(rwRec));                     \
        rwRecSetSensor((rec), SK_INVALID_SENSOR);            \
        rwRecSetFlowType((rec), SK_INVALID_FLOWTYPE);        \
    } while(0)
/*
 *    Zero out the record, and set Sensor ID and Flowtype to invalid
 *    values.
 */


#define RWREC_COPY(dst, src)                    \
    memcpy((dst), (src), sizeof(rwRec))
/*
 *    Copy the rwRec from 'src' to 'dst'.
 */


/*
 *  This is the generic SiLK Flow record returned from ANY file format
 *  containing packed SiLK Flow records.
 *
 *  typedef struct rwGenericRec_V5_st rwGenericRec_V5_t; // silk_types.h
 *  typedef rwGenericRec_V5_t rwRec;                     // silk_types.h
 */
struct rwGenericRec_V5_st {
#if RWREC_OPAQUE && !defined(RWREC_DEFINE_BODY)
#if SK_ENABLE_IPV6
    uint8_t         ar[88];
#else
    uint8_t         ar[52];
#endif
#else
    int64_t         sTime;       /*  0- 7  Flow start time in milliseconds
                                  *        since UNIX epoch */

    uint32_t        elapsed;     /*  8-11  Duration of flow in millisecs */

    uint16_t        sPort;       /* 12-13  Source port */
    uint16_t        dPort;       /* 14-15  Destination port */

    uint8_t         proto;       /* 16     IP protocol */
    sk_flowtype_id_t flow_type;  /* 17     Class & Type info */
    sk_sensor_id_t  sID;         /* 18-19  Sensor ID */

    uint8_t         flags;       /* 20     OR of all flags (Netflow flags) */
    uint8_t         init_flags;  /* 21     TCP flags in first packet
                                  *        or blank for "legacy" data */
    uint8_t         rest_flags;  /* 22     TCP flags on non-initial packet
                                  *        or blank for "legacy" data */
    uint8_t         tcp_state;   /* 23     TCP state machine info (below) */

    uint16_t        application; /* 24-25  "Service" port set by collector */
    uint16_t        memo;        /* 26-27  Application specific field */

    uint16_t        input;       /* 28-29  Router incoming SNMP interface */
    uint16_t        output;      /* 30-31  Router outgoing SNMP interface */

    uint32_t        pkts;        /* 32-35  Count of packets */
    uint32_t        bytes;       /* 36-39  Count of bytes */

    skIPUnion_t     sIP;         /* 40-43  (or 40-55 if IPv6) Source IP */
    skIPUnion_t     dIP;         /* 44-47  (or 56-71 if IPv6) Destination IP */
    skIPUnion_t     nhIP;        /* 48-51  (or 72-87 if IPv6) Routr NextHop IP*/
#endif  /* RWREC_OPAQUE && !defined(RWREC_DEFINE_BODY) */
};


/*
**  Values for tcp_state value in rwGeneric and packed formats
*/

/* No additional TCP-state machine information is available */
#define SK_TCPSTATE_NO_INFO               0x00

/* Expanded TCP-flags: This bit must be set if and only if the flow is
 * TCP and the init_flags and rest_flags fields are valid.  */
#define SK_TCPSTATE_EXPANDED              0x01

/* Unused SK_TCPSTATE_  0x02 */
/* Unused SK_TCPSTATE_  0x04 */

/* Flow received packets following the FIN packet that were not ACK or
 * RST packets. */
#define SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK  0x08

/* Flow has packets all of the same size */
#define SK_TCPSTATE_UNIFORM_PACKET_SIZE   0x10

/* Flow ends prematurely due to a timeout by the collector. */
#define SK_TCPSTATE_TIMEOUT_KILLED        0x20

/* Flow is a continuation of a previous flow that was killed
 * prematurely due to a timeout by the collector. */
#define SK_TCPSTATE_TIMEOUT_STARTED       0x40

/* Define a mask that returns the defined bits in tcpstate.  This is
 * used internally by rwRecGetTcpState(), rwRecSetTcpState() */
#define SK_TCPSTATE_MASK                  0x79

/* Define a mask that returns the attribute bits in tcpstate. */
#define SK_TCPSTATE_ATTRIBUTE_MASK        0x78

/* Note: the most significant bit of tcp_state (0x80) is used as a
 * flag to mark a record as having IPv6 addresses. */


/* the sizeof the fields in an rwRec */
#define RWREC_SIZEOF_SIPv4        4
#define RWREC_SIZEOF_DIPv4        4
#define RWREC_SIZEOF_NHIPv4       4
#define RWREC_SIZEOF_SPORT        2
#define RWREC_SIZEOF_DPORT        2
#define RWREC_SIZEOF_INPUT        2
#define RWREC_SIZEOF_OUTPUT       2
#define RWREC_SIZEOF_STIME        8
#define RWREC_SIZEOF_ELAPSED      4
#define RWREC_SIZEOF_PKTS         4
#define RWREC_SIZEOF_BYTES        4
#define RWREC_SIZEOF_PROTO        1
#define RWREC_SIZEOF_FLOW_TYPE    1
#define RWREC_SIZEOF_SID          2
#define RWREC_SIZEOF_FLAGS        1
#define RWREC_SIZEOF_INIT_FLAGS   1
#define RWREC_SIZEOF_REST_FLAGS   1
#define RWREC_SIZEOF_TCP_STATE    1
#define RWREC_SIZEOF_APPLICATION  2
#define RWREC_SIZEOF_MEMO         2
#define RWREC_SIZEOF_SIPv6       16
#define RWREC_SIZEOF_DIPv6       16
#define RWREC_SIZEOF_NHIPv6      16

#if !SK_ENABLE_IPV6
#  define RWREC_SIZEOF_SIP  RWREC_SIZEOF_SIPv4
#  define RWREC_SIZEOF_DIP  RWREC_SIZEOF_DIPv4
#  define RWREC_SIZEOF_NHIP RWREC_SIZEOF_NHIPv4
#else
#  define RWREC_SIZEOF_SIP  RWREC_SIZEOF_SIPv6
#  define RWREC_SIZEOF_DIP  RWREC_SIZEOF_DIPv6
#  define RWREC_SIZEOF_NHIP RWREC_SIZEOF_NHIPv6
#endif /* SK_ENABLE_IPV6 */


/* Helper macros */
#if 0
#  define MEMCPY8(dst, src)   { *((uint8_t*)(dst))  = *((uint8_t*)(src)); }
#  define MEMCPY16(dst, src)  { *((uint16_t*)(dst)) = *((uint16_t*)(src)); }
#  define MEMCPY32(dst, src)  { *((uint32_t*)(dst)) = *((uint32_t*)(src)); }
#else
#  define MEMCPY8(dst, src)   memcpy((dst), (src), sizeof(uint8_t))
#  define MEMCPY16(dst, src)  memcpy((dst), (src), sizeof(uint16_t))
#  define MEMCPY32(dst, src)  memcpy((dst), (src), sizeof(uint32_t))
#endif


/***  Whether record is ICMP  ***/

#define rwRecIsICMP(r)                                                  \
    ((IPPROTO_ICMP == rwRecGetProto(r))                                 \
     || (rwRecIsIPv6(r) && (IPPROTO_ICMPV6 == rwRecGetProto(r))))


/***  Whether record is WEB/HTTP  ***/

#define rwRecIsWeb(r)                                   \
    ((IPPROTO_TCP == rwRecGetProto(r))                  \
     && (SK_WEBPORT_CHECK(rwRecGetSPort(r))             \
         || SK_WEBPORT_CHECK(rwRecGetDPort(r))))


/***  Whether record is IPv6  ***/

#if !SK_ENABLE_IPV6
#  define rwRecIsIPv6(r)  0
#else

int  rwrec_IsIPv6(const rwRec *r);
void rwrec_SetIPv6(rwRec *r);
void rwrec_SetIPv4(rwRec *r);

#define _recIsIPv6(r)                           \
    (((r)->tcp_state & 0x80) ? 1 : 0)
#define _recSetIPv6(r)                          \
    { (r)->tcp_state |= 0x80; }
#define _recSetIPv4(r)                          \
    { (r)->tcp_state &= 0x7F; }

#if RWREC_OPAQUE
#  define rwRecIsIPv6(r)    rwrec_IsIPv6(r)
#  define rwRecSetIPv6(r)   rwrec_SetIPv6(r)
#  define rwRecSetIPv4(r)   rwrec_SetIPv4(r)
#else
#  define rwRecIsIPv6(r)    _recIsIPv6(r)
#  define rwRecSetIPv6(r)   _recSetIPv6(r)
#  define rwRecSetIPv4(r)   _recSetIPv4(r)
#endif /* RWREC_OPAQUE */

#endif  /* SK_ENABLE_IPV6 */


/***  Convert a Record to IPv6 or IPv4  ***/

#if SK_ENABLE_IPV6

void rwrec_ConvertToIPv6(rwRec *r);
int  rwrec_ConvertToIPv4(rwRec *r);

#define _recConvertToIPv6(r)                    \
    {                                           \
        skIPUnion4to6(&(r)->sIP, &(r)->sIP);    \
        skIPUnion4to6(&(r)->dIP, &(r)->dIP);    \
        skIPUnion4to6(&(r)->nhIP, &(r)->nhIP);  \
        _recSetIPv6(r);                         \
    }

#if RWREC_OPAQUE
#  define rwRecConvertToIPv6(r)   rwrec_ConvertToIPv6(r)
#  define rwRecConvertToIPv4(r)   rwrec_ConvertToIPv4(r)
#else
#  define rwRecConvertToIPv6(r)   _recConvertToIPv6(r)
#  define rwRecConvertToIPv4(r)   rwrec_ConvertToIPv4(r)
#endif /* RWREC_OPAQUE */

#endif  /* SK_ENABLE_IPV6 */


/***  Source IPv4 Address (sIP)  ***/

uint32_t rwrec_GetSIPv4(const rwRec *r);
void     rwrec_SetSIPv4(rwRec *r, uint32_t in_v);
void     rwrec_MemGetSIPv4(const rwRec *r, void *out_vp);
void     rwrec_MemSetSIPv4(rwRec *r, const void *in_vp);
int      rwrec_MemCmpSIPv4(const rwRec *r, const void *vp);
uint32_t rwrec_GetMaskSIPv4(const rwRec *r, uint32_t mask);
void     rwrec_ApplyMaskSIPv4(rwRec *r, uint32_t mask);

#define _recGetSIPv4(r)                         \
    ((r)->sIP.ipu_ipv4)
#define _recSetSIPv4(r, in_v)                   \
    { ((r)->sIP.ipu_ipv4) = (in_v); }
#define _recMemGetSIPv4(r, out_vp)                              \
    memcpy((out_vp), &((r)->sIP.ipu_ipv4), RWREC_SIZEOF_SIPv4)
#define _recMemSetSIPv4(r, in_vp)                               \
    memcpy(&((r)->sIP.ipu_ipv4), (in_vp), RWREC_SIZEOF_SIPv4)
#define _recMemCmpSIPv4(r, vp)                          \
    memcmp(&((r)->sIP.ipu_ipv4), (vp), RWREC_SIZEOF_SIPv4)
#define _recGetMaskSIPv4(r, mask)               \
    (((r)->sIP.ipu_ipv4) & mask)
#define _recApplyMaskSIPv4(r, mask)             \
    skIPUnionApplyMaskV4(&((r)->sIP), (mask))

#if RWREC_OPAQUE
#  define rwRecGetSIPv4(r)              rwrec_GetSIPv4(r)
#  define rwRecSetSIPv4(r, in_v)        rwrec_SetSIPv4(r, in_v)
#  define rwRecMemGetSIPv4(r, out_vp)   rwrec_MemGetSIPv4(r, out_vp)
#  define rwRecMemSetSIPv4(r, in_vp)    rwrec_MemSetSIPv4(r, in_vp)
#  define rwRecMemCmpSIPv4(r, vp)       rwrec_MemCmpSIPv4(r, vp)
#  define rwRecGetMaskSIPv4(r, mask)    rwrec_GetMaskSIPv4(r, mask)
#  define rwRecApplyMaskSIPv4(r, mask)  rwrec_ApplyMaskSIPv4(r, mask)
#else
#  define rwRecGetSIPv4(r)              _recGetSIPv4(r)
#  define rwRecSetSIPv4(r, in_v)        _recSetSIPv4(r, in_v)
#  define rwRecMemGetSIPv4(r, out_vp)   _recMemGetSIPv4(r, out_vp)
#  define rwRecMemSetSIPv4(r, in_vp)    _recMemSetSIPv4(r, in_vp)
#  define rwRecMemCmpSIPv4(r, vp)       _recMemCmpSIPv4(r, vp)
#  define rwRecGetMaskSIPv4(r, mask)    _recGetMaskSIPv4(r, mask)
#  define rwRecApplyMaskSIPv4(r, mask)  _recApplyMaskSIPv4(r, mask)
#endif /* RWREC_OPAQUE */


/***  Source IPv6 Address (sIP)  ***/

#if SK_ENABLE_IPV6

void     rwrec_MemGetSIPv6(const rwRec *r, void *out_vp);
void     rwrec_MemSetSIPv6(rwRec *r, const void *in_vp);
int      rwrec_MemCmpSIPv6(const rwRec *r, const void *vp);
void     rwrec_ApplyMaskSIPv6(rwRec *r, const void *mask_vp);

#define _recMemGetSIPv6(r, out_vp)                      \
    if (_recIsIPv6(r)) {                                \
        skIPUnionGetV6(&((r)->sIP), (out_vp));          \
    } else {                                            \
        skIPUnionGetV4AsV6(&((r)->sIP), (out_vp));      \
    }
#define _recMemSetSIPv6(r, in_vp)                               \
    memcpy(&((r)->sIP.ipu_ipv6), (in_vp), RWREC_SIZEOF_SIPv6)
#define _recMemCmpSIPv6(r, vp)                                  \
    memcmp(&((r)->sIP.ipu_ipv6), (vp), RWREC_SIZEOF_SIPv6)
#define _recApplyMaskSIPv6(r, mask)             \
    skIPUnionApplyMaskV6(&((r)->sIP), (mask))

#if RWREC_OPAQUE
#  define rwRecMemGetSIPv6(r, out_vp)   rwrec_MemGetSIPv6(r, out_vp)
#  define rwRecMemSetSIPv6(r, in_vp)    rwrec_MemSetSIPv6(r, in_vp)
#  define rwRecMemCmpSIPv6(r, vp)       rwrec_MemCmpSIPv6(r, vp)
#  define rwRecApplyMaskSIPv6(r, mask)  rwrec_ApplyMaskSIPv6(r, mask)
#else
#  define rwRecMemGetSIPv6(r, out_vp)   _recMemGetSIPv6(r, out_vp)
#  define rwRecMemSetSIPv6(r, in_vp)    _recMemSetSIPv6(r, in_vp)
#  define rwRecMemCmpSIPv6(r, vp)       _recMemCmpSIPv6(r, vp)
#  define rwRecApplyMaskSIPv6(r, mask)  _recApplyMaskSIPv6(r, mask)
#endif /* RWREC_OPAQUE */

#endif  /* SK_ENABLE_IPV6 */


/***  Source IP Address (sIP) as skipaddr_t  ***/

void     rwrec_MemGetSIP(const rwRec *r, skipaddr_t *out_addr);
void     rwrec_MemSetSIP(rwRec *r, const skipaddr_t *in_addr);
int      rwrec_MemCmpSIP(const rwRec *r, const skipaddr_t *addr);
void     rwrec_ApplyMaskSIP(rwRec *r, const skipaddr_t *mask_addr);

#if !SK_ENABLE_IPV6
#define _recMemGetSIP _recMemGetSIPv4
#define _recMemSetSIP _recMemSetSIPv4
#define _recMemCmpSIP(r, addr)                          \
    _recMemCmpSIPv4((r), &((addr)->ip_ip.ipu_ipv4))
#define _recApplyMaskSIP(r, addr)                       \
    _recApplyMaskSIPv4((r), (addr)->ip_ip.ipu_ipv4)
#else
#define _recMemGetSIP(r, out_addr)                              \
    do {                                                        \
        memcpy(out_addr, &((r)->sIP), sizeof(skIPUnion_t));     \
        skipaddrSetVersion((out_addr), _recIsIPv6(r));          \
    } while(0)
#define _recMemSetSIP(r, in_addr)                                       \
    do {                                                                \
        if (skipaddrIsV6(in_addr) == _recIsIPv6(r)) {                   \
            /* both are either V4 or V6 */                              \
            memcpy(&((r)->sIP), (in_addr), sizeof(skIPUnion_t));        \
        } else if (_recIsIPv6(r)) {                                     \
            /* convert V4 IP to V6 */                                   \
            skIPUnion4to6(&((in_addr)->ip_ip), &((r)->sIP));            \
        } else {                                                        \
            /* must convert record to V6 */                             \
            _recConvertToIPv6(r);                                       \
            memcpy(&((r)->sIP), (in_addr), sizeof(skIPUnion_t));        \
        }                                                               \
    } while(0)
#define _recMemCmpSIP(r, addr)      rwrec_MemCmpSIP(r, addr)
#define _recApplyMaskSIP(r, addr)   rwrec_ApplyMaskSIP(r, addr)
#endif /* SK_ENABLE_IPV6 */

#if RWREC_OPAQUE
#  define rwRecMemGetSIP(r, out_addr)   rwrec_MemGetSIP(r, out_addr)
#  define rwRecMemSetSIP(r, in_addr)    rwrec_MemSetSIP(r, in_addr)
#  define rwRecMemCmpSIP(r, addr)       rwrec_MemCmpSIP(r, addr)
#  define rwRecApplyMaskSIP(r, addr)    rwrec_ApplyMaskSIP(r, addr)
#else
#  define rwRecMemGetSIP(r, out_addr)   _recMemGetSIP(r, out_addr)
#  define rwRecMemSetSIP(r, in_addr)    _recMemSetSIP(r, in_addr)
#  define rwRecMemCmpSIP(r, addr)       _recMemCmpSIP(r, addr)
#  define rwRecApplyMaskSIP(r, addr)    _recApplyMaskSIP(r, addr)
#endif /* RWREC_OPAQUE */


/***  Destination IP Address (dIP)  ***/

uint32_t rwrec_GetDIPv4(const rwRec *r);
void     rwrec_SetDIPv4(rwRec *r, uint32_t in_v);
void     rwrec_MemGetDIPv4(const rwRec *r, void *out_vp);
void     rwrec_MemSetDIPv4(rwRec *r, const void *in_vp);
int      rwrec_MemCmpDIPv4(const rwRec *r, const void *vp);
uint32_t rwrec_GetMaskDIPv4(const rwRec *r, uint32_t mask);
void     rwrec_ApplyMaskDIPv4(rwRec *r, uint32_t mask);

#define _recGetDIPv4(r)                         \
    ((r)->dIP.ipu_ipv4)
#define _recSetDIPv4(r, in_v)                   \
    { ((r)->dIP.ipu_ipv4) = (in_v); }
#define _recMemGetDIPv4(r, out_vp)                              \
    memcpy((out_vp), &((r)->dIP.ipu_ipv4), RWREC_SIZEOF_DIPv4)
#define _recMemSetDIPv4(r, in_vp)                               \
    memcpy(&((r)->dIP.ipu_ipv4), (in_vp), RWREC_SIZEOF_DIPv4)
#define _recMemCmpDIPv4(r, vp)                          \
    memcmp(&((r)->dIP.ipu_ipv4), (vp), RWREC_SIZEOF_DIPv4)
#define _recGetMaskDIPv4(r, mask)               \
    (((r)->dIP.ipu_ipv4) & mask)
#define _recApplyMaskDIPv4(r, mask)             \
    skIPUnionApplyMaskV4(&((r)->dIP), (mask))


#if RWREC_OPAQUE
#  define rwRecGetDIPv4(r)              rwrec_GetDIPv4(r)
#  define rwRecSetDIPv4(r, in_v)        rwrec_SetDIPv4(r, in_v)
#  define rwRecMemGetDIPv4(r, out_vp)   rwrec_MemGetDIPv4(r, out_vp)
#  define rwRecMemSetDIPv4(r, in_vp)    rwrec_MemSetDIPv4(r, in_vp)
#  define rwRecMemCmpDIPv4(r, vp)       rwrec_MemCmpDIPv4(r, vp)
#  define rwRecGetMaskDIPv4(r, mask)    rwrec_GetMaskDIPv4(r, mask)
#  define rwRecApplyMaskDIPv4(r, mask)  rwrec_ApplyMaskDIPv4(r, mask)
#else
#  define rwRecGetDIPv4(r)              _recGetDIPv4(r)
#  define rwRecSetDIPv4(r, in_v)        _recSetDIPv4(r, in_v)
#  define rwRecMemGetDIPv4(r, out_vp)   _recMemGetDIPv4(r, out_vp)
#  define rwRecMemSetDIPv4(r, in_vp)    _recMemSetDIPv4(r, in_vp)
#  define rwRecMemCmpDIPv4(r, vp)       _recMemCmpDIPv4(r, vp)
#  define rwRecGetMaskDIPv4(r, mask)    _recGetMaskDIPv4(r, mask)
#  define rwRecApplyMaskDIPv4(r, mask)  _recApplyMaskDIPv4(r, mask)
#endif /* RWREC_OPAQUE */


/***  Destination IPv6 Address (dIP)  ***/

#if SK_ENABLE_IPV6

void     rwrec_MemGetDIPv6(const rwRec *r, void *out_vp);
void     rwrec_MemSetDIPv6(rwRec *r, const void *in_vp);
int      rwrec_MemCmpDIPv6(const rwRec *r, const void *vp);
void     rwrec_ApplyMaskDIPv6(rwRec *r, const void *mask_vp);

#define _recMemGetDIPv6(r, out_vp)                      \
    if (_recIsIPv6(r)) {                                \
        skIPUnionGetV6(&((r)->dIP), (out_vp));          \
    } else {                                            \
        skIPUnionGetV4AsV6(&((r)->dIP), (out_vp));      \
    }
#define _recMemSetDIPv6(r, in_vp)                               \
    memcpy(&((r)->dIP.ipu_ipv6), (in_vp), RWREC_SIZEOF_DIPv6)
#define _recMemCmpDIPv6(r, vp)                                  \
    memcmp(&((r)->dIP.ipu_ipv6), (vp), RWREC_SIZEOF_DIPv6)
#define _recApplyMaskDIPv6(r, mask)             \
    skIPUnionApplyMaskV6(&((r)->dIP), (mask))

#if RWREC_OPAQUE
#  define rwRecMemGetDIPv6(r, out_vp)   rwrec_MemGetDIPv6(r, out_vp)
#  define rwRecMemSetDIPv6(r, in_vp)    rwrec_MemSetDIPv6(r, in_vp)
#  define rwRecMemCmpDIPv6(r, vp)       rwrec_MemCmpDIPv6(r, vp)
#  define rwRecApplyMaskDIPv6(r, mask)  rwrec_ApplyMaskDIPv6(r, mask)
#else
#  define rwRecMemGetDIPv6(r, out_vp)   _recMemGetDIPv6(r, out_vp)
#  define rwRecMemSetDIPv6(r, in_vp)    _recMemSetDIPv6(r, in_vp)
#  define rwRecMemCmpDIPv6(r, vp)       _recMemCmpDIPv6(r, vp)
#  define rwRecApplyMaskDIPv6(r, mask)  _recApplyMaskDIPv6(r, mask)
#endif /* RWREC_OPAQUE */

#endif  /* SK_ENABLE_IPV6 */


/***  Destination IP Address (dIP) as skipaddr_t  ***/

void     rwrec_MemGetDIP(const rwRec *r, skipaddr_t *out_addr);
void     rwrec_MemSetDIP(rwRec *r, const skipaddr_t *in_addr);
int      rwrec_MemCmpDIP(const rwRec *r, const skipaddr_t *addr);
void     rwrec_ApplyMaskDIP(rwRec *r, const skipaddr_t *mask_addr);

#if !SK_ENABLE_IPV6
#define _recMemGetDIP _recMemGetDIPv4
#define _recMemSetDIP _recMemSetDIPv4
#define _recMemCmpDIP(r, addr)                          \
    _recMemCmpDIPv4((r), &((addr)->ip_ip.ipu_ipv4))
#define _recApplyMaskDIP(r, addr)                       \
    _recApplyMaskDIPv4((r), (addr)->ip_ip.ipu_ipv4)
#else
#define _recMemGetDIP(r, out_addr)                              \
    do {                                                        \
        memcpy(out_addr, &((r)->dIP), sizeof(skIPUnion_t));     \
        skipaddrSetVersion((out_addr), _recIsIPv6(r));          \
    } while(0)
#define _recMemSetDIP(r, in_addr)                                       \
    do {                                                                \
        if (skipaddrIsV6(in_addr) == _recIsIPv6(r)) {                   \
            /* both are either V4 or V6 */                              \
            memcpy(&((r)->dIP), (in_addr), sizeof(skIPUnion_t));        \
        } else if (_recIsIPv6(r)) {                                     \
            /* convert V4 IP to V6 */                                   \
            skIPUnion4to6(&((in_addr)->ip_ip), &((r)->dIP));            \
        } else {                                                        \
            /* must convert record to V6 */                             \
            _recConvertToIPv6(r);                                       \
            memcpy(&((r)->dIP), (in_addr), sizeof(skIPUnion_t));        \
        }                                                               \
    } while(0)
#define _recMemCmpDIP(r, addr)      rwrec_MemCmpDIP(r, addr)
#define _recApplyMaskDIP(r, addr)   rwrec_ApplyMaskDIP(r, addr)
#endif /* SK_ENABLE_IPV6 */

#if RWREC_OPAQUE
#  define rwRecMemGetDIP(r, out_addr)   rwrec_MemGetDIP(r, out_addr)
#  define rwRecMemSetDIP(r, in_addr)    rwrec_MemSetDIP(r, in_addr)
#  define rwRecMemCmpDIP(r, addr)       rwrec_MemCmpDIP(r, addr)
#  define rwRecApplyMaskDIP(r, addr)    rwrec_ApplyMaskDIP(r, addr)
#else
#  define rwRecMemGetDIP(r, out_addr)   _recMemGetDIP(r, out_addr)
#  define rwRecMemSetDIP(r, in_addr)    _recMemSetDIP(r, in_addr)
#  define rwRecMemCmpDIP(r, addr)       _recMemCmpDIP(r, addr)
#  define rwRecApplyMaskDIP(r, addr)    _recApplyMaskDIP(r, addr)
#endif /* RWREC_OPAQUE */


/***  Next Hop IP (nhIP) Address  ***/

uint32_t rwrec_GetNhIPv4(const rwRec *r);
void     rwrec_SetNhIPv4(rwRec *r, uint32_t in_v);
void     rwrec_MemGetNhIPv4(const rwRec *r, void *out_vp);
void     rwrec_MemSetNhIPv4(rwRec *r, const void *in_vp);
int      rwrec_MemCmpNhIPv4(const rwRec *r, const void *vp);
uint32_t rwrec_GetMaskNhIPv4(const rwRec *r, uint32_t mask);
void     rwrec_ApplyMaskNhIPv4(rwRec *r, uint32_t mask);

#define _recGetNhIPv4(r)                        \
    ((r)->nhIP.ipu_ipv4)
#define _recSetNhIPv4(r, in_v)                  \
    { ((r)->nhIP.ipu_ipv4) = (in_v); }
#define _recMemGetNhIPv4(r, out_vp)                             \
    memcpy((out_vp), &((r)->nhIP.ipu_ipv4), RWREC_SIZEOF_NHIPv4)
#define _recMemSetNhIPv4(r, in_vp)                              \
    memcpy(&((r)->nhIP.ipu_ipv4), (in_vp), RWREC_SIZEOF_NHIPv4)
#define _recMemCmpNhIPv4(r, vp)                         \
    memcmp(&((r)->nhIP.ipu_ipv4), (vp), RWREC_SIZEOF_NHIPv4)
#define _recGetMaskNhIPv4(r, mask)              \
    (((r)->nhIP.ipu_ipv4) & mask)
#define _recApplyMaskNhIPv4(r, mask)            \
    skIPUnionApplyMaskV4(&((r)->nhIP), (mask))


#if RWREC_OPAQUE
#  define rwRecGetNhIPv4(r)             rwrec_GetNhIPv4(r)
#  define rwRecSetNhIPv4(r, in_v)       rwrec_SetNhIPv4(r, in_v)
#  define rwRecMemGetNhIPv4(r, out_vp)  rwrec_MemGetNhIPv4(r, out_vp)
#  define rwRecMemSetNhIPv4(r, in_vp)   rwrec_MemSetNhIPv4(r, in_vp)
#  define rwRecMemCmpNhIPv4(r, vp)      rwrec_MemCmpNhIPv4(r, vp)
#  define rwRecGetMaskNhIPv4(r, mask)   rwrec_GetMaskNhIPv4(r, mask)
#  define rwRecApplyMaskNhIPv4(r, mask) rwrec_ApplyMaskNhIPv4(r, mask)
#else
#  define rwRecGetNhIPv4(r)             _recGetNhIPv4(r)
#  define rwRecSetNhIPv4(r, in_v)       _recSetNhIPv4(r, in_v)
#  define rwRecMemGetNhIPv4(r, out_vp)  _recMemGetNhIPv4(r, out_vp)
#  define rwRecMemSetNhIPv4(r, in_vp)   _recMemSetNhIPv4(r, in_vp)
#  define rwRecMemCmpNhIPv4(r, vp)      _recMemCmpNhIPv4(r, vp)
#  define rwRecGetMaskNhIPv4(r, mask)   _recGetMaskNhIPv4(r, mask)
#  define rwRecApplyMaskNhIPv4(r, mask) _recApplyMaskNhIPv4(r, mask)
#endif /* RWREC_OPAQUE */


/***  Next Hop IPv6 Address (nhIP)  ***/

#if SK_ENABLE_IPV6

void     rwrec_MemGetNhIPv6(const rwRec *r, void *out_vp);
void     rwrec_MemSetNhIPv6(rwRec *r, const void *in_vp);
int      rwrec_MemCmpNhIPv6(const rwRec *r, const void *vp);
void     rwrec_ApplyMaskNhIPv6(rwRec *r, const void *mask_vp);

#define _recMemGetNhIPv6(r, out_vp)                     \
    if (_recIsIPv6(r)) {                                \
        skIPUnionGetV6(&((r)->nhIP), (out_vp));         \
    } else {                                            \
        skIPUnionGetV4AsV6(&((r)->nhIP), (out_vp));     \
    }
#define _recMemSetNhIPv6(r, in_vp)                              \
    memcpy(&((r)->nhIP.ipu_ipv6), (in_vp), RWREC_SIZEOF_NHIPv6)
#define _recMemCmpNhIPv6(r, vp)                                 \
    memcmp(&((r)->nhIP.ipu_ipv6), (vp), RWREC_SIZEOF_NHIPv6)
#define _recApplyMaskNhIPv6(r, mask)            \
    skIPUnionApplyMaskV6(&((r)->nhIP), (mask))

#if RWREC_OPAQUE
#  define rwRecMemGetNhIPv6(r, out_vp)   rwrec_MemGetNhIPv6(r, out_vp)
#  define rwRecMemSetNhIPv6(r, in_vp)    rwrec_MemSetNhIPv6(r, in_vp)
#  define rwRecMemCmpNhIPv6(r, vp)       rwrec_MemCmpNhIPv6(r, vp)
#  define rwRecApplyMaskNhIPv6(r, mask)  rwrec_ApplyMaskNhIPv6(r, mask)
#else
#  define rwRecMemGetNhIPv6(r, out_vp)   _recMemGetNhIPv6(r, out_vp)
#  define rwRecMemSetNhIPv6(r, in_vp)    _recMemSetNhIPv6(r, in_vp)
#  define rwRecMemCmpNhIPv6(r, vp)       _recMemCmpNhIPv6(r, vp)
#  define rwRecApplyMaskNhIPv6(r, mask)  _recApplyMaskNhIPv6(r, mask)
#endif /* RWREC_OPAQUE */

#endif /* SK_ENABLE_IPV6 */


/***  Next Hop IP Address (nhIP) as skipaddr_t  ***/

void     rwrec_MemGetNhIP(const rwRec *r, skipaddr_t *out_addr);
void     rwrec_MemSetNhIP(rwRec *r, const skipaddr_t *in_addr);
int      rwrec_MemCmpNhIP(const rwRec *r, const skipaddr_t *addr);
void     rwrec_ApplyMaskNhIP(rwRec *r, const skipaddr_t *mask_addr);

#if !SK_ENABLE_IPV6
#define _recMemGetNhIP    _recMemGetNhIPv4
#define _recMemSetNhIP    _recMemSetNhIPv4
#define _recMemCmpNhIP(r, addr)                         \
    _recMemCmpNhIPv4((r), &((addr)->ip_ip.ipu_ipv4))
#define _recApplyMaskNhIP(r, addr)                      \
    _recApplyMaskNhIPv4((r), (addr)->ip_ip.ipu_ipv4)
#else
#define _recMemGetNhIP(r, out_addr)                             \
    do {                                                        \
        memcpy(out_addr, &((r)->nhIP), sizeof(skIPUnion_t));    \
        skipaddrSetVersion((out_addr), _recIsIPv6(r));          \
    } while(0)
#define _recMemSetNhIP(r, in_addr)                                      \
    do {                                                                \
        if (skipaddrIsV6(in_addr) == _recIsIPv6(r)) {                   \
            /* both are either V4 or V6 */                              \
            memcpy(&((r)->nhIP), (in_addr), sizeof(skIPUnion_t));       \
        } else if (_recIsIPv6(r)) {                                     \
            /* convert V4 IP to V6 */                                   \
            skIPUnion4to6(&((in_addr)->ip_ip), &((r)->nhIP));           \
        } else {                                                        \
            /* must convert record to V6 */                             \
            _recConvertToIPv6(r);                                       \
            memcpy(&((r)->nhIP), (in_addr), sizeof(skIPUnion_t));       \
        }                                                               \
    } while(0)
#define _recMemCmpNhIP(r, addr)     rwrec_MemCmpNhIP(r, addr)
#define _recApplyMaskNhIP(r, addr)  rwrec_ApplyMaskNhIP(r, addr)
#endif /* SK_ENABLE_IPV6 */

#if RWREC_OPAQUE
#  define rwRecMemGetNhIP(r, out_addr)  rwrec_MemGetNhIP(r, out_addr)
#  define rwRecMemSetNhIP(r, in_addr)   rwrec_MemSetNhIP(r, in_addr)
#  define rwRecMemCmpNhIP(r, addr)      rwrec_MemCmpNhIP(r, addr)
#  define rwRecApplyMaskNhIP(r, addr)   rwrec_ApplyMaskNhIP(r, addr)
#else
#  define rwRecMemGetNhIP(r, out_addr)  _recMemGetNhIP(r, out_addr)
#  define rwRecMemSetNhIP(r, in_addr)   _recMemSetNhIP(r, in_addr)
#  define rwRecMemCmpNhIP(r, addr)      _recMemCmpNhIP(r, addr)
#  define rwRecApplyMaskNhIP(r, addr)   _recApplyMaskNhIP(r, addr)
#endif /* RWREC_OPAQUE */


/***  Source Port (sPort)  ***/

uint16_t rwrec_GetSPort(const rwRec *r);
void     rwrec_SetSPort(rwRec *r, uint16_t in_v);
void     rwrec_MemGetSPort(const rwRec *r, void *out_vp);
void     rwrec_MemSetSPort(rwRec *r, const void *in_vp);
int      rwrec_MemCmpSPort(const rwRec *r, const void *vp);

#define _recGetSPort(r)                         \
    ((r)->sPort)
#define _recSetSPort(r, in_v)                   \
    { ((r)->sPort) = (in_v); }
#define _recMemGetSPort(r, out_vp)                      \
    memcpy((out_vp), &((r)->sPort), RWREC_SIZEOF_SPORT)
#define _recMemSetSPort(r, in_vp)                       \
    memcpy(&((r)->sPort), (in_vp), RWREC_SIZEOF_SPORT)
#define _recMemCmpSPort(r, vp)                          \
    memcmp(&((r)->sPort), (vp), RWREC_SIZEOF_SPORT)

#if RWREC_OPAQUE
#  define rwRecGetSPort(r)  rwrec_GetSPort(r)
#  define rwRecSetSPort(r, in_v)  rwrec_SetSPort(r, in_v)
#  define rwRecMemGetSPort(r, out_vp)  rwrec_MemGetSPort(r, out_vp)
#  define rwRecMemSetSPort(r, in_vp)  rwrec_MemSetSPort(r, in_vp)
#  define rwRecMemCmpSPort(r, vp)  rwrec_MemCmpSPort(r, vp)
#else
#  define rwRecGetSPort(r)  _recGetSPort(r)
#  define rwRecSetSPort(r, in_v)  _recSetSPort(r, in_v)
#  define rwRecMemGetSPort(r, out_vp)  _recMemGetSPort(r, out_vp)
#  define rwRecMemSetSPort(r, in_vp)  _recMemSetSPort(r, in_vp)
#  define rwRecMemCmpSPort(r, vp)  _recMemCmpSPort(r, vp)
#endif /* RWREC_OPAQUE */


/***  Destination Port (dPort)  ***/

uint16_t rwrec_GetDPort(const rwRec *r);
void     rwrec_SetDPort(rwRec *r, uint16_t in_v);
void     rwrec_MemGetDPort(const rwRec *r, void *out_vp);
void     rwrec_MemSetDPort(rwRec *r, const void *in_vp);
int      rwrec_MemCmpDPort(const rwRec *r, const void *vp);

#define _recGetDPort(r)                         \
    ((r)->dPort)
#define _recSetDPort(r, in_v)                   \
    { ((r)->dPort) = (in_v); }
#define _recMemGetDPort(r, out_vp)                      \
    memcpy((out_vp), &((r)->dPort), RWREC_SIZEOF_DPORT)
#define _recMemSetDPort(r, in_vp)                       \
    memcpy(&((r)->dPort), (in_vp), RWREC_SIZEOF_DPORT)
#define _recMemCmpDPort(r, vp)                          \
    memcmp(&((r)->dPort), (vp), RWREC_SIZEOF_DPORT)

#if RWREC_OPAQUE
#  define rwRecGetDPort(r)  rwrec_GetDPort(r)
#  define rwRecSetDPort(r, in_v)  rwrec_SetDPort(r, in_v)
#  define rwRecMemGetDPort(r, out_vp)  rwrec_MemGetDPort(r, out_vp)
#  define rwRecMemSetDPort(r, in_vp)  rwrec_MemSetDPort(r, in_vp)
#  define rwRecMemCmpDPort(r, vp)  rwrec_MemCmpDPort(r, vp)
#else
#  define rwRecGetDPort(r)  _recGetDPort(r)
#  define rwRecSetDPort(r, in_v)  _recSetDPort(r, in_v)
#  define rwRecMemGetDPort(r, out_vp)  _recMemGetDPort(r, out_vp)
#  define rwRecMemSetDPort(r, in_vp)  _recMemSetDPort(r, in_vp)
#  define rwRecMemCmpDPort(r, vp)  _recMemCmpDPort(r, vp)
#endif /* RWREC_OPAQUE */


/***  Protocol  ***/

uint8_t  rwrec_GetProto(const rwRec *r);
void     rwrec_SetProto(rwRec *r, uint8_t in_v);
void     rwrec_MemGetProto(const rwRec *r, void *out_vp);
void     rwrec_MemSetProto(rwRec *r, const void *in_vp);
int      rwrec_MemCmpProto(const rwRec *r, const void *vp);

#define _recGetProto(r)                         \
    ((r)->proto)
#define _recSetProto(r, in_v)                   \
    { ((r)->proto) = (in_v); }
#define _recMemGetProto(r, out_vp)                      \
    memcpy((out_vp), &((r)->proto), RWREC_SIZEOF_PROTO)
#define _recMemSetProto(r, in_vp)                       \
    memcpy(&((r)->proto), (in_vp), RWREC_SIZEOF_PROTO)
#define _recMemCmpProto(r, vp)                          \
    memcmp(&((r)->proto), (vp), RWREC_SIZEOF_PROTO)

#if RWREC_OPAQUE
#  define rwRecGetProto(r)  rwrec_GetProto(r)
#  define rwRecSetProto(r, in_v)  rwrec_SetProto(r, in_v)
#  define rwRecMemGetProto(r, out_vp)  rwrec_MemGetProto(r, out_vp)
#  define rwRecMemSetProto(r, in_vp)  rwrec_MemSetProto(r, in_vp)
#  define rwRecMemCmpProto(r, vp)  rwrec_MemCmpProto(r, vp)
#else
#  define rwRecGetProto(r)  _recGetProto(r)
#  define rwRecSetProto(r, in_v)  _recSetProto(r, in_v)
#  define rwRecMemGetProto(r, out_vp)  _recMemGetProto(r, out_vp)
#  define rwRecMemSetProto(r, in_vp)  _recMemSetProto(r, in_vp)
#  define rwRecMemCmpProto(r, vp)  _recMemCmpProto(r, vp)
#endif /* RWREC_OPAQUE */


/***  Packet Count (pkts)  ***/

uint32_t rwrec_GetPkts(const rwRec *r);
void     rwrec_SetPkts(rwRec *r, uint32_t in_v);
void     rwrec_MemGetPkts(const rwRec *r, void *out_vp);
void     rwrec_MemSetPkts(rwRec *r, const void *in_vp);
int      rwrec_MemCmpPkts(const rwRec *r, const void *vp);

#define _recGetPkts(r)                          \
    ((r)->pkts)
#define _recSetPkts(r, in_v)                    \
    { ((r)->pkts) = (in_v); }
#define _recMemGetPkts(r, out_vp)                       \
    memcpy((out_vp), &((r)->pkts), RWREC_SIZEOF_PKTS)
#define _recMemSetPkts(r, in_vp)                        \
    memcpy(&((r)->pkts), (in_vp), RWREC_SIZEOF_PKTS)
#define _recMemCmpPkts(r, vp)                           \
    memcmp(&((r)->pkts), (vp), RWREC_SIZEOF_PKTS)

#if RWREC_OPAQUE
#  define rwRecGetPkts(r)  rwrec_GetPkts(r)
#  define rwRecSetPkts(r, in_v)  rwrec_SetPkts(r, in_v)
#  define rwRecMemGetPkts(r, out_vp)  rwrec_MemGetPkts(r, out_vp)
#  define rwRecMemSetPkts(r, in_vp)  rwrec_MemSetPkts(r, in_vp)
#  define rwRecMemCmpPkts(r, vp)  rwrec_MemCmpPkts(r, vp)
#else
#  define rwRecGetPkts(r)  _recGetPkts(r)
#  define rwRecSetPkts(r, in_v)  _recSetPkts(r, in_v)
#  define rwRecMemGetPkts(r, out_vp)  _recMemGetPkts(r, out_vp)
#  define rwRecMemSetPkts(r, in_vp)  _recMemSetPkts(r, in_vp)
#  define rwRecMemCmpPkts(r, vp)  _recMemCmpPkts(r, vp)
#endif /* RWREC_OPAQUE */


/***  Byte count  ***/

uint32_t rwrec_GetBytes(const rwRec *r);
void     rwrec_SetBytes(rwRec *r, uint32_t in_v);
void     rwrec_MemGetBytes(const rwRec *r, void *out_vp);
void     rwrec_MemSetBytes(rwRec *r, const void *in_vp);
int      rwrec_MemCmpBytes(const rwRec *r, const void *vp);

#define _recGetBytes(r)                         \
    ((r)->bytes)
#define _recSetBytes(r, in_v)                   \
    { ((r)->bytes) = (in_v); }
#define _recMemGetBytes(r, out_vp)                      \
    memcpy((out_vp), &((r)->bytes), RWREC_SIZEOF_BYTES)
#define _recMemSetBytes(r, in_vp)                       \
    memcpy(&((r)->bytes), (in_vp), RWREC_SIZEOF_BYTES)
#define _recMemCmpBytes(r, vp)                          \
    memcmp(&((r)->bytes), (vp), RWREC_SIZEOF_BYTES)

#if RWREC_OPAQUE
#  define rwRecGetBytes(r)  rwrec_GetBytes(r)
#  define rwRecSetBytes(r, in_v)  rwrec_SetBytes(r, in_v)
#  define rwRecMemGetBytes(r, out_vp)  rwrec_MemGetBytes(r, out_vp)
#  define rwRecMemSetBytes(r, in_vp)  rwrec_MemSetBytes(r, in_vp)
#  define rwRecMemCmpBytes(r, vp)  rwrec_MemCmpBytes(r, vp)
#else
#  define rwRecGetBytes(r)  _recGetBytes(r)
#  define rwRecSetBytes(r, in_v)  _recSetBytes(r, in_v)
#  define rwRecMemGetBytes(r, out_vp)  _recMemGetBytes(r, out_vp)
#  define rwRecMemSetBytes(r, in_vp)  _recMemSetBytes(r, in_vp)
#  define rwRecMemCmpBytes(r, vp)  _recMemCmpBytes(r, vp)
#endif /* RWREC_OPAQUE */


/***  Bitwise OR of TCP Flags on ALL packets in flow  ***/

uint8_t  rwrec_GetFlags(const rwRec *r);
void     rwrec_SetFlags(rwRec *r, uint8_t in_v);
void     rwrec_MemGetFlags(const rwRec *r, void *out_vp);
void     rwrec_MemSetFlags(rwRec *r, const void *in_vp);
int      rwrec_MemCmpFlags(const rwRec *r, const void *vp);

#define _recGetFlags(r)                         \
    ((r)->flags)
#define _recSetFlags(r, in_v)                   \
    { ((r)->flags) = (in_v); }
#define _recMemGetFlags(r, out_vp)                      \
    memcpy((out_vp), &((r)->flags), RWREC_SIZEOF_FLAGS)
#define _recMemSetFlags(r, in_vp)                       \
    memcpy(&((r)->flags), (in_vp), RWREC_SIZEOF_FLAGS)
#define _recMemCmpFlags(r, vp)                          \
    memcmp(&((r)->flags), (vp), RWREC_SIZEOF_FLAGS)

#if RWREC_OPAQUE
#  define rwRecGetFlags(r)  rwrec_GetFlags(r)
#  define rwRecSetFlags(r, in_v)  rwrec_SetFlags(r, in_v)
#  define rwRecMemGetFlags(r, out_vp)  rwrec_MemGetFlags(r, out_vp)
#  define rwRecMemSetFlags(r, in_vp)  rwrec_MemSetFlags(r, in_vp)
#  define rwRecMemCmpFlags(r, vp)  rwrec_MemCmpFlags(r, vp)
#else
#  define rwRecGetFlags(r)  _recGetFlags(r)
#  define rwRecSetFlags(r, in_v)  _recSetFlags(r, in_v)
#  define rwRecMemGetFlags(r, out_vp)  _recMemGetFlags(r, out_vp)
#  define rwRecMemSetFlags(r, in_vp)  _recMemSetFlags(r, in_vp)
#  define rwRecMemCmpFlags(r, vp)  _recMemCmpFlags(r, vp)
#endif /* RWREC_OPAQUE */


/***  TCP Flags seen on initial packet of flow  ***/

uint8_t  rwrec_GetInitFlags(const rwRec *r);
void     rwrec_SetInitFlags(rwRec *r, uint8_t in_v);
void     rwrec_MemGetInitFlags(const rwRec *r, void *out_vp);
void     rwrec_MemSetInitFlags(rwRec *r, const void *in_vp);
int      rwrec_MemCmpInitFlags(const rwRec *r, const void *vp);

#define _recGetInitFlags(r)                     \
    ((r)->init_flags)
#define _recSetInitFlags(r, in_v)               \
    { ((r)->init_flags) = (in_v); }
#define _recMemGetInitFlags(r, out_vp)                                  \
    memcpy((out_vp), &((r)->init_flags), RWREC_SIZEOF_INIT_FLAGS)
#define _recMemSetInitFlags(r, in_vp)                                   \
    memcpy(&((r)->init_flags), (in_vp), RWREC_SIZEOF_INIT_FLAGS)
#define _recMemCmpInitFlags(r, vp)                              \
    memcmp(&((r)->init_flags), (vp), RWREC_SIZEOF_INIT_FLAGS)

#if RWREC_OPAQUE
#  define rwRecGetInitFlags(r)  rwrec_GetInitFlags(r)
#  define rwRecSetInitFlags(r, in_v)  rwrec_SetInitFlags(r, in_v)
#  define rwRecMemGetInitFlags(r, out_vp)  rwrec_MemGetInitFlags(r, out_vp)
#  define rwRecMemSetInitFlags(r, in_vp)  rwrec_MemSetInitFlags(r, in_vp)
#  define rwRecMemCmpInitFlags(r, vp)  rwrec_MemCmpInitFlags(r, vp)
#else
#  define rwRecGetInitFlags(r)  _recGetInitFlags(r)
#  define rwRecSetInitFlags(r, in_v)  _recSetInitFlags(r, in_v)
#  define rwRecMemGetInitFlags(r, out_vp)  _recMemGetInitFlags(r, out_vp)
#  define rwRecMemSetInitFlags(r, in_vp)  _recMemSetInitFlags(r, in_vp)
#  define rwRecMemCmpInitFlags(r, vp)  _recMemCmpInitFlags(r, vp)
#endif /* RWREC_OPAQUE */


/***  Bitwise OR of TCP Flags on all packets in session except first  ***/

uint8_t  rwrec_GetRestFlags(const rwRec *r);
void     rwrec_SetRestFlags(rwRec *r, uint8_t in_v);
void     rwrec_MemGetRestFlags(const rwRec *r, void *out_vp);
void     rwrec_MemSetRestFlags(rwRec *r, const void *in_vp);
int      rwrec_MemCmpRestFlags(const rwRec *r, const void *vp);

#define _recGetRestFlags(r)                     \
    ((r)->rest_flags)
#define _recSetRestFlags(r, in_v)               \
    { ((r)->rest_flags) = (in_v); }
#define _recMemGetRestFlags(r, out_vp)                                  \
    memcpy((out_vp), &((r)->rest_flags), RWREC_SIZEOF_REST_FLAGS)
#define _recMemSetRestFlags(r, in_vp)                                   \
    memcpy(&((r)->rest_flags), (in_vp), RWREC_SIZEOF_REST_FLAGS)
#define _recMemCmpRestFlags(r, vp)                              \
    memcmp(&((r)->rest_flags), (vp), RWREC_SIZEOF_REST_FLAGS)

#if RWREC_OPAQUE
#  define rwRecGetRestFlags(r)  rwrec_GetRestFlags(r)
#  define rwRecSetRestFlags(r, in_v)  rwrec_SetRestFlags(r, in_v)
#  define rwRecMemGetRestFlags(r, out_vp)  rwrec_MemGetRestFlags(r, out_vp)
#  define rwRecMemSetRestFlags(r, in_vp)  rwrec_MemSetRestFlags(r, in_vp)
#  define rwRecMemCmpRestFlags(r, vp)  rwrec_MemCmpRestFlags(r, vp)
#else
#  define rwRecGetRestFlags(r)  _recGetRestFlags(r)
#  define rwRecSetRestFlags(r, in_v)  _recSetRestFlags(r, in_v)
#  define rwRecMemGetRestFlags(r, out_vp)  _recMemGetRestFlags(r, out_vp)
#  define rwRecMemSetRestFlags(r, in_vp)  _recMemSetRestFlags(r, in_vp)
#  define rwRecMemCmpRestFlags(r, vp)  _recMemCmpRestFlags(r, vp)
#endif /* RWREC_OPAQUE */


/***  Start Time as milliseconds since UNIX epoch (sTime)  ***/

sktime_t rwrec_GetStartTime(const rwRec *r);
void     rwrec_SetStartTime(rwRec *r, sktime_t in_v);
void     rwrec_MemGetStartTime(const rwRec *r, void *out_vp);
void     rwrec_MemSetStartTime(rwRec *r, const void *in_vp);
int      rwrec_MemCmpStartTime(const rwRec *r, const void *vp);
uint32_t rwrec_GetStartSeconds(const rwRec *r);
void     rwrec_MemGetStartSeconds(const rwRec *r, void *out_vp);

#define _recGetStartTime(r)                     \
    ((r)->sTime)
#define _recSetStartTime(r, in_v)               \
    { ((r)->sTime = (in_v)); }
#define _recMemGetStartTime(r, out_vp)                  \
    memcpy((out_vp), &((r)->sTime), RWREC_SIZEOF_STIME)
#define _recMemSetStartTime(r, in_vp)                   \
    memcpy(&((r)->sTime), (in_vp), RWREC_SIZEOF_STIME)
#define _recMemCmpStartTime(r, vp)                      \
    memcmp(&((r)->sTime), (vp), RWREC_SIZEOF_STIME)

#define _recGetStartSeconds(r)                  \
    ((uint32_t)((r)->sTime / 1000))
#define _recMemGetStartSeconds(r, out_vp) {     \
        uint32_t _t = _recGetStartSeconds(r);   \
        memcpy((out_vp), &_t, sizeof(_t));      \
    }

#if RWREC_OPAQUE
#  define rwRecGetStartTime(r)  rwrec_GetStartTime(r)
#  define rwRecSetStartTime(r, in_v)  rwrec_SetStartTime(r, in_v)
#  define rwRecMemGetStartTime(r, out_vp)  rwrec_MemGetStartTime(r, out_vp)
#  define rwRecMemSetStartTime(r, in_vp)  rwrec_MemSetStartTime(r, in_vp)
#  define rwRecMemCmpStartTime(r, vp)  rwrec_MemCmpStartTime(r, vp)
#  define rwRecGetStartSeconds(r)  rwrec_GetStartSeconds(r)
#  define rwRecMemGetStartSeconds(r, out_vp)    \
    rwrec_MemGetStartSeconds(r, out_vp)
#else
#  define rwRecGetStartTime(r)  _recGetStartTime(r)
#  define rwRecSetStartTime(r, in_v)  _recSetStartTime(r, in_v)
#  define rwRecMemGetStartTime(r, out_vp)  _recMemGetStartTime(r, out_vp)
#  define rwRecMemSetStartTime(r, in_vp)  _recMemSetStartTime(r, in_vp)
#  define rwRecMemCmpStartTime(r, vp)  _recMemCmpStartTime(r, vp)
#  define rwRecGetStartSeconds(r)  _recGetStartSeconds(r)
#  define rwRecMemGetStartSeconds(r, out_vp)  _recMemGetStartSeconds(r, out_vp)
#endif /* RWREC_OPAQUE */


/***  Elapsed (duration) of the flow, in milliseconds  ***/

uint32_t rwrec_GetElapsed(const rwRec *r);
void     rwrec_SetElapsed(rwRec *r, sktime_t in_v);
void     rwrec_MemGetElapsed(const rwRec *r, void *out_vp);
void     rwrec_MemSetElapsed(rwRec *r, const void *in_vp);
int      rwrec_MemCmpElapsed(const rwRec *r, const void *vp);
uint32_t rwrec_GetElapsedSeconds(const rwRec *r);
void     rwrec_MemGetElapsedSeconds(const rwRec *r, void *out_vp);

#define _recGetElapsed(r)                       \
    ((r)->elapsed)
#define _recSetElapsed(r, in_v)                 \
    { (r)->elapsed = (uint32_t)(in_v); }
#define _recMemGetElapsed(r, out_vp)                            \
    memcpy((out_vp), &((r)->elapsed), RWREC_SIZEOF_ELAPSED)
#define _recMemSetElapsed(r, in_vp)                             \
    memcpy(&((r)->elapsed), (in_vp), RWREC_SIZEOF_ELAPSED)
#define _recMemCmpElapsed(r, vp)                                \
    memcmp(&((r)->elapsed), (vp), RWREC_SIZEOF_ELAPSED)

#define _recGetElapsedSeconds(r)                \
    ((uint32_t)((r)->elapsed / 1000))
#define _recMemGetElapsedSeconds(r, out_vp) {   \
        uint32_t _t = _recGetElapsedSeconds(r); \
        memcpy((out_vp), &_t, sizeof(_t));      \
    }

#if RWREC_OPAQUE
#  define rwRecGetElapsed(r)  rwrec_GetElapsed(r)
#  define rwRecSetElapsed(r, in_v)  rwrec_SetElapsed(r, in_v)
#  define rwRecMemGetElapsed(r, out_vp)  rwrec_MemGetElapsed(r, out_vp)
#  define rwRecMemSetElapsed(r, in_vp)  rwrec_MemSetElapsed(r, in_vp)
#  define rwRecMemCmpElapsed(r, vp)  rwrec_MemCmpElapsed(r, vp)
#  define rwRecGetElapsedSeconds(r)  rwrec_GetElapsedSeconds(r)
#  define rwRecMemGetElapsedSeconds(r, out_vp)  \
    rwrec_MemGetElapsedSeconds(r, out_vp)
#else
#  define rwRecGetElapsed(r)  _recGetElapsed(r)
#  define rwRecSetElapsed(r, in_v)  _recSetElapsed(r, in_v)
#  define rwRecMemGetElapsed(r, out_vp)  _recMemGetElapsed(r, out_vp)
#  define rwRecMemSetElapsed(r, in_vp)  _recMemSetElapsed(r, in_vp)
#  define rwRecMemCmpElapsed(r, vp)  _recMemCmpElapsed(r, vp)
#  define rwRecGetElapsedSeconds(r)  _recGetElapsedSeconds(r)
#  define rwRecMemGetElapsedSeconds(r, out_vp)  \
    _recMemGetElapsedSeconds(r, out_vp)
#endif /* RWREC_OPAQUE */



/***  End Time is derived from the sTime and duration (eTime)  ***/

/* No Set macros/functions since this is a derived field */

sktime_t rwrec_GetEndTime(const rwRec *r);
void     rwrec_MemGetEndTime(const rwRec *r, void *out_vp);
uint32_t rwrec_GetEndSeconds(const rwRec *r);
void     rwrec_MemGetEndSeconds(const rwRec *r, void *out_vp);

#define _recGetEndTime(r)                               \
    ((sktime_t)_recGetStartTime(r) + _recGetElapsed(r))
#define _recMemGetEndTime(r, out_vp) {          \
        sktime_t _t = _recGetEndTime(r);        \
        memcpy((out_vp), &_t, sizeof(_t));      \
    }
#define _recGetEndSeconds(r)                    \
    ((uint32_t)(_recGetEndTime(r) / 1000))
#define _recMemGetEndSeconds(r, out_vp) {       \
        uint32_t _t = rwRecGetEndSeconds(r);    \
        memcpy((out_vp), &_t, sizeof(_t));      \
    }

#if RWREC_OPAQUE
#  define rwRecGetEndTime(r)  rwrec_GetEndTime(r)
#  define rwRecMemGetEndTime(r, out_vp)  rwrec_MemGetEndTime(r, out_vp)
#  define rwRecGetEndSeconds(r)  rwrec_GetEndSeconds(r)
#  define rwRecMemGetEndSeconds(r, out_vp)  rwrec_MemGetEndSeconds(r, out_vp)
#else
#  define rwRecGetEndTime(r)  _recGetEndTime(r)
#  define rwRecMemGetEndTime(r, out_vp)  _recMemGetEndTime(r, out_vp)
#  define rwRecGetEndSeconds(r)  _recGetEndSeconds(r)
#  define rwRecMemGetEndSeconds(r, out_vp)  _recMemGetEndSeconds(r, out_vp)
#endif /* RWREC_OPAQUE */


/***  Sensor ID (sID)  ***/

sk_sensor_id_t  rwrec_GetSensor(const rwRec *r);
void            rwrec_SetSensor(rwRec *r, sk_sensor_id_t in_v);
void            rwrec_MemGetSensor(const rwRec *r, void *out_vp);
void            rwrec_MemSetSensor(rwRec *r, const void *in_vp);
int             rwrec_MemCmpSensor(const rwRec *r, const void *vp);

#define _recGetSensor(r)                        \
    ((r)->sID)
#define _recSetSensor(r, in_v)                  \
    { ((r)->sID) = (in_v); }
#define _recMemGetSensor(r, out_vp)                     \
    memcpy((out_vp), &((r)->sID), RWREC_SIZEOF_SID)
#define _recMemSetSensor(r, in_vp)                      \
    memcpy(&((r)->sID), (in_vp), RWREC_SIZEOF_SID)
#define _recMemCmpSensor(r, vp)                 \
    memcmp(&((r)->sID), (vp), RWREC_SIZEOF_SID)

#if RWREC_OPAQUE
#  define rwRecGetSensor(r)  rwrec_GetSensor(r)
#  define rwRecSetSensor(r, in_v)  rwrec_SetSensor(r, in_v)
#  define rwRecMemGetSensor(r, out_vp)  rwrec_MemGetSensor(r, out_vp)
#  define rwRecMemSetSensor(r, in_vp)  rwrec_MemSetSensor(r, in_vp)
#  define rwRecMemCmpSensor(r, vp)  rwrec_MemCmpSensor(r, vp)
#else
#  define rwRecGetSensor(r)  _recGetSensor(r)
#  define rwRecSetSensor(r, in_v)  _recSetSensor(r, in_v)
#  define rwRecMemGetSensor(r, out_vp)  _recMemGetSensor(r, out_vp)
#  define rwRecMemSetSensor(r, in_vp)  _recMemSetSensor(r, in_vp)
#  define rwRecMemCmpSensor(r, vp)  _recMemCmpSensor(r, vp)
#endif /* RWREC_OPAQUE */


/***  FlowType holds Class and Type  ***/

sk_flowtype_id_t    rwrec_GetFlowType(const rwRec *r);
void                rwrec_SetFlowType(rwRec *r, sk_flowtype_id_t in_v);
void                rwrec_MemGetFlowType(const rwRec *r, void *out_vp);
void                rwrec_MemSetFlowType(rwRec *r, const void *in_vp);
int                 rwrec_MemCmpFlowType(const rwRec *r, const void *vp);

#define _recGetFlowType(r)                      \
    ((r)->flow_type)
#define _recSetFlowType(r, in_v)                \
    { ((r)->flow_type) = (in_v); }
#define _recMemGetFlowType(r, out_vp)                           \
    memcpy((out_vp), &((r)->flow_type), RWREC_SIZEOF_FLOW_TYPE)
#define _recMemSetFlowType(r, in_vp)                            \
    memcpy(&((r)->flow_type), (in_vp), RWREC_SIZEOF_FLOW_TYPE)
#define _recMemCmpFlowType(r, vp)                               \
    memcmp(&((r)->flow_type), (vp), RWREC_SIZEOF_FLOW_TYPE)

#if RWREC_OPAQUE
#  define rwRecGetFlowType(r)  rwrec_GetFlowType(r)
#  define rwRecSetFlowType(r, in_v)  rwrec_SetFlowType(r, in_v)
#  define rwRecMemGetFlowType(r, out_vp)  rwrec_MemGetFlowType(r, out_vp)
#  define rwRecMemSetFlowType(r, in_vp)  rwrec_MemSetFlowType(r, in_vp)
#  define rwRecMemCmpFlowType(r, vp)  rwrec_MemCmpFlowType(r, vp)
#else
#  define rwRecGetFlowType(r)  _recGetFlowType(r)
#  define rwRecSetFlowType(r, in_v)  _recSetFlowType(r, in_v)
#  define rwRecMemGetFlowType(r, out_vp)  _recMemGetFlowType(r, out_vp)
#  define rwRecMemSetFlowType(r, in_vp)  _recMemSetFlowType(r, in_vp)
#  define rwRecMemCmpFlowType(r, vp)  _recMemCmpFlowType(r, vp)
#endif /* RWREC_OPAQUE */


/***  SNMP Input Value (Router incoming/ingress interface)  ***/

uint16_t rwrec_GetInput(const rwRec *r);
void     rwrec_SetInput(rwRec *r, uint16_t in_v);
void     rwrec_MemGetInput(const rwRec *r, void *out_vp);
void     rwrec_MemSetInput(rwRec *r, const void *in_vp);
int      rwrec_MemCmpInput(const rwRec *r, const void *vp);

#define _recGetInput(r)                         \
    ((r)->input)
#define _recSetInput(r, in_v)                   \
    { ((r)->input) = (in_v); }
#define _recMemGetInput(r, out_vp)                      \
    memcpy((out_vp), &((r)->input), RWREC_SIZEOF_INPUT)
#define _recMemSetInput(r, in_vp)                       \
    memcpy(&((r)->input), (in_vp), RWREC_SIZEOF_INPUT)
#define _recMemCmpInput(r, vp)                          \
    memcmp(&((r)->input), (vp), RWREC_SIZEOF_INPUT)

#if RWREC_OPAQUE
#  define rwRecGetInput(r)  rwrec_GetInput(r)
#  define rwRecSetInput(r, in_v)  rwrec_SetInput(r, in_v)
#  define rwRecMemGetInput(r, out_vp)  rwrec_MemGetInput(r, out_vp)
#  define rwRecMemSetInput(r, in_vp)  rwrec_MemSetInput(r, in_vp)
#  define rwRecMemCmpInput(r, vp)  rwrec_MemCmpInput(r, vp)
#else
#  define rwRecGetInput(r)  _recGetInput(r)
#  define rwRecSetInput(r, in_v)  _recSetInput(r, in_v)
#  define rwRecMemGetInput(r, out_vp)  _recMemGetInput(r, out_vp)
#  define rwRecMemSetInput(r, in_vp)  _recMemSetInput(r, in_vp)
#  define rwRecMemCmpInput(r, vp)  _recMemCmpInput(r, vp)
#endif /* RWREC_OPAQUE */


/***  SNMP Output Value  (Router outgoing/egress interface)  ***/

uint16_t rwrec_GetOutput(const rwRec *r);
void     rwrec_SetOutput(rwRec *r, uint16_t in_v);
void     rwrec_MemGetOutput(const rwRec *r, void *out_vp);
void     rwrec_MemSetOutput(rwRec *r, const void *in_vp);
int      rwrec_MemCmpOutput(const rwRec *r, const void *vp);

#define _recGetOutput(r)                        \
    ((r)->output)
#define _recSetOutput(r, in_v)                  \
    { ((r)->output) = (in_v); }
#define _recMemGetOutput(r, out_vp)                             \
    memcpy((out_vp), &((r)->output), RWREC_SIZEOF_OUTPUT)
#define _recMemSetOutput(r, in_vp)                              \
    memcpy(&((r)->output), (in_vp), RWREC_SIZEOF_OUTPUT)
#define _recMemCmpOutput(r, vp)                         \
    memcmp(&((r)->output), (vp), RWREC_SIZEOF_OUTPUT)

#if RWREC_OPAQUE
#  define rwRecGetOutput(r)  rwrec_GetOutput(r)
#  define rwRecSetOutput(r, in_v)  rwrec_SetOutput(r, in_v)
#  define rwRecMemGetOutput(r, out_vp)  rwrec_MemGetOutput(r, out_vp)
#  define rwRecMemSetOutput(r, in_vp)  rwrec_MemSetOutput(r, in_vp)
#  define rwRecMemCmpOutput(r, vp)  rwrec_MemCmpOutput(r, vp)
#else
#  define rwRecGetOutput(r)  _recGetOutput(r)
#  define rwRecSetOutput(r, in_v)  _recSetOutput(r, in_v)
#  define rwRecMemGetOutput(r, out_vp)  _recMemGetOutput(r, out_vp)
#  define rwRecMemSetOutput(r, in_vp)  _recMemSetOutput(r, in_vp)
#  define rwRecMemCmpOutput(r, vp)  _recMemCmpOutput(r, vp)
#endif /* RWREC_OPAQUE */


/***  TCP State  ***/

uint8_t  rwrec_GetTcpState(const rwRec *r);
void     rwrec_SetTcpState(rwRec *r, uint8_t in_v);
void     rwrec_MemGetTcpState(const rwRec *r, void *out_vp);
void     rwrec_MemSetTcpState(rwRec *r, const void *in_vp);
int      rwrec_MemCmpTcpState(const rwRec *r, const void *vp);

#define _recGetTcpState(r)                              \
    ((uint8_t)((r)->tcp_state & SK_TCPSTATE_MASK))
#define _recSetTcpState(r, in_v)                                       \
    { ((r)->tcp_state)                                                 \
            = ((r)->tcp_state & 0x80) | (SK_TCPSTATE_MASK & (in_v)); }
#define _recMemGetTcpState(r, out_vp)                   \
    { *((uint8_t*)(out_vp)) = _recGetTcpState(r); }
#define _recMemSetTcpState(r, in_vp)            \
    _recSetTcpState((r), *((uint8_t*)(in_vp)))
#define _recMemCmpTcpState(r, vp)                               \
    ((int)(_recGetTcpState(r)                                   \
           - (uint8_t)(SK_TCPSTATE_MASK & *((uint8_t*)(vp)))))

#if RWREC_OPAQUE
#  define rwRecGetTcpState(r)  rwrec_GetTcpState(r)
#  define rwRecSetTcpState(r, in_v)  rwrec_SetTcpState(r, in_v)
#  define rwRecMemGetTcpState(r, out_vp)  rwrec_MemGetTcpState(r, out_vp)
#  define rwRecMemSetTcpState(r, in_vp)  rwrec_MemSetTcpState(r, in_vp)
#  define rwRecMemCmpTcpState(r, vp)  rwrec_MemCmpTcpState(r, vp)
#else
#  define rwRecGetTcpState(r)  _recGetTcpState(r)
#  define rwRecSetTcpState(r, in_v)  _recSetTcpState(r, in_v)
#  define rwRecMemGetTcpState(r, out_vp)  _recMemGetTcpState(r, out_vp)
#  define rwRecMemSetTcpState(r, in_vp)  _recMemSetTcpState(r, in_vp)
#  define rwRecMemCmpTcpState(r, vp)  _recMemCmpTcpState(r, vp)
#endif /* RWREC_OPAQUE */


/***  Application  ***/

uint16_t rwrec_GetApplication(const rwRec *r);
void     rwrec_SetApplication(rwRec *r, uint16_t in_v);
void     rwrec_MemGetApplication(const rwRec *r, void *out_vp);
void     rwrec_MemSetApplication(rwRec *r, const void *in_vp);
int      rwrec_MemCmpApplication(const rwRec *r, const void *vp);

#define _recGetApplication(r)                   \
    ((r)->application)
#define _recSetApplication(r, in_v)             \
    { ((r)->application) = (in_v); }
#define _recMemGetApplication(r, out_vp)                                \
    memcpy((out_vp), &((r)->application), RWREC_SIZEOF_APPLICATION)
#define _recMemSetApplication(r, in_vp)                                 \
    memcpy(&((r)->application), (in_vp), RWREC_SIZEOF_APPLICATION)
#define _recMemCmpApplication(r, vp)                            \
    memcmp(&((r)->application), (vp), RWREC_SIZEOF_APPLICATION)

#if RWREC_OPAQUE
#  define rwRecGetApplication(r)  rwrec_GetApplication(r)
#  define rwRecSetApplication(r, in_v)  rwrec_SetApplication(r, in_v)
#  define rwRecMemGetApplication(r, out_vp)  rwrec_MemGetApplication(r, out_vp)
#  define rwRecMemSetApplication(r, in_vp)  rwrec_MemSetApplication(r, in_vp)
#  define rwRecMemCmpApplication(r, vp)  rwrec_MemCmpApplication(r, vp)
#else
#  define rwRecGetApplication(r)  _recGetApplication(r)
#  define rwRecSetApplication(r, in_v)  _recSetApplication(r, in_v)
#  define rwRecMemGetApplication(r, out_vp)  _recMemGetApplication(r, out_vp)
#  define rwRecMemSetApplication(r, in_vp)  _recMemSetApplication(r, in_vp)
#  define rwRecMemCmpApplication(r, vp)  _recMemCmpApplication(r, vp)
#endif /* RWREC_OPAQUE */


/***  Memo  ***/

uint16_t rwrec_GetMemo(const rwRec *r);
void     rwrec_SetMemo(rwRec *r, uint16_t in_v);
void     rwrec_MemGetMemo(const rwRec *r, void *out_vp);
void     rwrec_MemSetMemo(rwRec *r, const void *in_vp);
int      rwrec_MemCmpMemo(const rwRec *r, const void *vp);

#define _recGetMemo(r)                          \
    ((r)->memo)
#define _recSetMemo(r, in_v)                    \
    { ((r)->memo) = (in_v); }
#define _recMemGetMemo(r, out_vp)                       \
    memcpy((out_vp), &((r)->memo), RWREC_SIZEOF_MEMO)
#define _recMemSetMemo(r, in_vp)                        \
    memcpy(&((r)->memo), (in_vp), RWREC_SIZEOF_MEMO)
#define _recMemCmpMemo(r, vp)                           \
    memcmp(&((r)->memo), (vp), RWREC_SIZEOF_MEMO)

#if RWREC_OPAQUE
#  define rwRecGetMemo(r)  rwrec_GetMemo(r)
#  define rwRecSetMemo(r, in_v)  rwrec_SetMemo(r, in_v)
#  define rwRecMemGetMemo(r, out_vp)  rwrec_MemGetMemo(r, out_vp)
#  define rwRecMemSetMemo(r, in_vp)  rwrec_MemSetMemo(r, in_vp)
#  define rwRecMemCmpMemo(r, vp)  rwrec_MemCmpMemo(r, vp)
#else
#  define rwRecGetMemo(r)  _recGetMemo(r)
#  define rwRecSetMemo(r, in_v)  _recSetMemo(r, in_v)
#  define rwRecMemGetMemo(r, out_vp)  _recMemGetMemo(r, out_vp)
#  define rwRecMemSetMemo(r, in_vp)  _recMemSetMemo(r, in_vp)
#  define rwRecMemCmpMemo(r, vp)  _recMemCmpMemo(r, vp)
#endif /* RWREC_OPAQUE */


/***  ICMP Type and Code is derived from the DPort  ***/

/*
 *    In NetFlow, Cisco has traditionally encoded the ICMP type and
 *    code in the destination port field as (type << 8 | code).
 *    The following macros assume this Cisco-encoding.
 *
 *    Due to various issues, sometimes the ICMP type and code is
 *    encoded in the source port instead of the destination port.  As
 *    of SiLK-3.4.0, libsilk (skstream.c) handles these incorrect
 *    encodings when the record is read and modifies the record to use
 *    the traditional Cisco encoding.
 *
 *    The following functions/macros do not check the protocol.
 */
uint8_t  rwrec_GetIcmpType(const rwRec *r);
void     rwrec_SetIcmpType(rwRec *r, uint8_t in_v);
void     rwrec_MemGetIcmpType(const rwRec *r, void *out_vp);
uint8_t  rwrec_GetIcmpCode(const rwRec *r);
void     rwrec_SetIcmpCode(rwRec *r, uint8_t in_v);
void     rwrec_MemGetIcmpCode(const rwRec *r, void *out_vp);

uint16_t rwrec_GetIcmpTypeAndCode(const rwRec *r);
void     rwrec_SetIcmpTypeAndCode(rwRec *r, uint16_t in_v);
void     rwrec_MemGetIcmpTypeAndCode(const rwRec *r, void *out_vp);
void     rwrec_MemSetIcmpTypeAndCode(rwRec *r, const void *in_vp);
int      rwrec_MemCmpIcmpTypeAndCode(const rwRec *r, const void *vp);

#define _recGetIcmpTypeAndCode(r)  _recGetDPort(r)
#define _recSetIcmpTypeAndCode(r, in_v)  _recSetDPort(r, in_v)
#define _recMemGetIcmpTypeAndCode(r, out_vp)  _recMemGetDPort(r, out_vp)
#define _recMemSetIcmpTypeAndCode(r, in_vp)  _recMemSetDPort(r, in_vp)
#define _recMemCmpIcmpTypeAndCode(r, vp)  _recMemCmpDPort(r, vp)

#define _recGetIcmpType(r)                                      \
    ((uint8_t)(0xFF & (_recGetIcmpTypeAndCode(r) >> 8)))
#define _recSetIcmpType(r, in_v)                                        \
    _recSetIcmpTypeAndCode(r, ((_recGetIcmpTypeAndCode(r) & 0x00FF)     \
                               | (((in_v) & 0xFF) << 8)))
#define _recMemGetIcmpType(r, out_vp)           \
    { *out_vp = _recGetIcmpType(r); }

#define _recGetIcmpCode(r)                              \
    ((uint8_t)(0xFF & _recGetIcmpTypeAndCode(r)))
#define _recSetIcmpCode(r, in_v)                                        \
    _recSetIcmpTypeAndCode(r, ((_recGetIcmpTypeAndCode(r) & 0xFF00)     \
                               | ((in_v) & 0xFF)))
#define _recMemGetIcmpCode(r, out_vp)           \
    { *out_vp = _recGetIcmpCode(r); }

#if RWREC_OPAQUE
#  define rwRecGetIcmpType(r)  rwrec_GetIcmpType(r)
#  define rwRecSetIcmpType(r, in_v)  rwrec_SetIcmpType(r, in_v)
#  define rwRecMemGetIcmpType(r, out_vp)  rwrec_MemGetIcmpType(r, out_vp)

#  define rwRecGetIcmpCode(r)  rwrec_GetIcmpCode(r)
#  define rwRecSetIcmpCode(r, in_v)  rwrec_SetIcmpCode(r, in_v)
#  define rwRecMemGetIcmpCode(r, out_vp)  rwrec_MemGetIcmpCode(r, out_vp)

#  define rwRecGetIcmpTypeAndCode(r)  rwrec_GetIcmpTypeAndCode(r)
#  define rwRecSetIcmpTypeAndCode(r, in_v)  rwrec_SetIcmpTypeAndCode(r, in_v)
#  define rwRecMemGetIcmpTypeAndCode(r, out_vp) \
    rwrec_MemGetIcmpTypeAndCode(r, out_vp)
#  define rwRecMemSetIcmpTypeAndCode(r, in_vp)  \
    rwrec_MemSetIcmpTypeAndCode(r, in_vp)
#  define rwRecMemCmpIcmpTypeAndCode(r, vp)     \
    rwrec_MemCmpIcmpTypeAndCode(r, vp)
#else /* RWREC_OPAQUE */
#  define rwRecGetIcmpType(r)  _recGetIcmpType(r)
#  define rwRecSetIcmpType(r, in_v)  _recSetIcmpType(r, in_v)
#  define rwRecMemGetIcmpType(r, out_vp)  _recMemGetIcmpType(r, out_vp)

#  define rwRecGetIcmpCode(r)  _recGetIcmpCode(r)
#  define rwRecSetIcmpCode(r, in_v)  _recSetIcmpCode(r, in_v)
#  define rwRecMemGetIcmpCode(r, out_vp)  _recMemGetIcmpCode(r, out_vp)

#  define rwRecGetIcmpTypeAndCode(r)  _recGetIcmpTypeAndCode(r)
#  define rwRecSetIcmpTypeAndCode(r, in_v)  _recSetIcmpTypeAndCode(r, in_v)
#  define rwRecMemGetIcmpTypeAndCode(r, out_vp) \
    _recMemGetIcmpTypeAndCode(r, out_vp)
#  define rwRecMemSetIcmpTypeAndCode(r, in_vp)  \
    _recMemSetIcmpTypeAndCode(r, in_vp)
#  define rwRecMemCmpIcmpTypeAndCode(r, vp)     \
    _recMemCmpIcmpTypeAndCode(r, vp)
#endif /* RWREC_OPAQUE */


#ifdef __cplusplus
}
#endif
#endif /* _RWREC_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
