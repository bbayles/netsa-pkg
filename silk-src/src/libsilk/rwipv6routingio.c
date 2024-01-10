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
**  rwipv6routingio.c
**
**    Routines to pack/unpack FT_RWIPV6ROUTING records.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwipv6routingio.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "skstream_priv.h"


/* Version to use when SK_RECORD_VERSION_ANY is specified */
#define DEFAULT_RECORD_VERSION 1


/* LOCAL FUNCTION PROTOTYPES */

static int
ipv6routingioRecordUnpack_V1(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar);


static const uint8_t IP4in6_prefix[12] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};


/* ********************************************************************* */

/*
**  RWIPV6ROUTING VERSION 3
**
**    int64_t       sTime;       //  0- 7  Flow start time as milliseconds
**                               //        since UNIX epoch
**
**    uint32_t      elapsed;     //  8-11  Duration of flow in milliseconds
**                               //        (Allows for a 49 day flow)
**
**    uint16_t      sPort;       // 12-13  Source port
**    uint16_t      dPort;       // 14-15  Destination port
**
**    uint8_t       proto;       // 16     IP protocol
**    uint8_t       flow_type;   // 17     Class & Type info
**    uint16_t      sID;         // 18-19  Sensor ID
**
**    uint8_t       flags;       // 20     OR of all flags (Netflow flags)
**    uint8_t       init_flags;  // 21     TCP flags in first packet
**                               //        or blank for "legacy" data
**    uint8_t       rest_flags;  // 22     TCP flags on non-initial packet
**                               //        or blank for "legacy" data
**    uint8_t       tcp_state;   // 23     TCP state machine info (below)
**
**    uint16_t      application; // 24-25  Indication of type of traffic
**    uint16_t      memo;        // 26-27  Application specific field
**
**    uint32_t      input;       // 28-31  Router incoming SNMP interface
**
**    uint64_t      pkts;        // 32-39  Count of packets
**
**    uint64_t      bytes;       // 40-47  Count of bytes
**
**    uint8_t[16]   sIP;         // 48-63  (IPv4 in 60-63) Source IP
**    uint8_t[16]   dIP;         // 64-79  (IPv4 in 76-79) Destination IP
**    uint8_t[16]   nhIP;        // 80-95  (IPv4 in 92-95) Router Next Hop IP
**
**    uint32_t      output;      // 96-99  Router outgoing SNMP interface
**
**
**  100 bytes on disk.
*/

#define RECLEN_RWIPV6ROUTING_V3 100


/*
 *    Byte swap the RWIPV6ROUTING v1 record 'ar' in place.
 */
#define ipv6routingioRecordSwap_V3(ar)                                  \
    {                                                                   \
        SWAP_DATA64((ar) +  0);   /* sTime */                           \
        SWAP_DATA32((ar) +  8);   /* elapsed */                         \
        SWAP_DATA16((ar) + 12);   /* sPort */                           \
        SWAP_DATA16((ar) + 14);   /* dPort */                           \
        /* Two single bytes: (16)proto, (17)flow_type */                \
        SWAP_DATA16((ar) + 18);   /* sID */                             \
        /* Four single bytes: (20)flags, (21)init_flags,                \
         *                    (22)rest_flags, (23)tcp_state */          \
        SWAP_DATA16((ar) + 24);   /* application */                     \
        SWAP_DATA16((ar) + 26);   /* memo */                            \
        SWAP_DATA32((ar) + 28);   /* input */                           \
        SWAP_DATA64((ar) + 32);   /* pkts */                            \
        SWAP_DATA64((ar) + 40);   /* bytes */                           \
        /* 48 bytes of sIP, dIP, nhIP always in network byte order */   \
        SWAP_DATA32((ar) + 96);   /* output */                          \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
ipv6routingioRecordUnpack_V3(
    skstream_t         *stream,
    rwRec              *rwrec,
    uint8_t            *ar)
{
    uint32_t u32;
    uint64_t u64;

#if !SK_ENABLE_IPV6
    if (ar[23] & 0x80) {
        /* Record is IPv6 */
        return SKSTREAM_ERR_UNSUPPORT_IPV6;
    }
#endif

    /* swap if required */
    if (stream->swapFlag) {
        ipv6routingioRecordSwap_V3(ar);
    }

    rwRecMemSetStartTime(rwrec, &ar[0]);
    rwRecMemSetElapsed(rwrec, &ar[8]);
    rwRecMemSetSPort(rwrec, &ar[12]);
    rwRecMemSetDPort(rwrec, &ar[14]);
    rwRecMemSetProto(rwrec, &ar[16]);
    rwRecMemSetFlowType(rwrec, &ar[17]);
    rwRecMemSetSensor(rwrec, &ar[18]);
    rwRecMemSetFlags(rwrec, &ar[20]);
    rwRecMemSetInitFlags(rwrec, &ar[21]);
    rwRecMemSetRestFlags(rwrec, &ar[22]);
    rwRecMemSetTcpState(rwrec, &ar[23]);
    rwRecMemSetApplication(rwrec, &ar[24]);
    rwRecMemSetMemo(rwrec, &ar[26]);

    /* Input; set to UINT16_MAX if too large */
    memcpy(&u32, &ar[28], sizeof(u32));
    if (u32 > UINT16_MAX) {
        rwRecSetInput(rwrec, UINT16_MAX);
    } else {
        rwRecSetInput(rwrec, (uint16_t)u32);
    }

    /* Packets; set to UINT32_MAX if too large */
    memcpy(&u64, &ar[32], sizeof(u64));
    if (u64 > UINT32_MAX) {
        rwRecSetPkts(rwrec, UINT32_MAX);
    } else {
        rwRecSetPkts(rwrec, (uint32_t)u64);
    }

    /* Bytes; set to UINT32_MAX if too large */
    memcpy(&u64, &ar[40], sizeof(u64));
    if (u64 > UINT32_MAX) {
        rwRecSetBytes(rwrec, UINT32_MAX);
    } else {
        rwRecSetBytes(rwrec, (uint32_t)u64);
    }

    /* Output; set to UINT16_MAX if too large */
    memcpy(&u32, &ar[96], sizeof(u32));
    if (u32 > UINT16_MAX) {
        rwRecSetOutput(rwrec, UINT16_MAX);
    } else {
        rwRecSetOutput(rwrec, (uint16_t)u32);
    }

#if SK_ENABLE_IPV6
    if (ar[23] & 0x80) {
        /* Record is IPv6 */
        rwRecSetIPv6(rwrec);
        rwRecMemSetSIPv6(rwrec, &ar[48]);
        rwRecMemSetDIPv6(rwrec, &ar[64]);
        rwRecMemSetNhIPv6(rwrec, &ar[80]);
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        /* Record is IPv4, but data encoded as IPv6 */
        uint32_t ip;

        /* sIP */
        memcpy(&ip, &ar[60], sizeof(ip));
        rwRecSetSIPv4(rwrec, ntohl(ip));

        /* dIP */
        memcpy(&ip, &ar[76], sizeof(ip));
        rwRecSetDIPv4(rwrec, ntohl(ip));

        /* nhIP */
        memcpy(&ip, &ar[92], sizeof(ip));
        rwRecSetNhIPv4(rwrec, ntohl(ip));
    }

    /*
     * No need for this; file format is post SiLK-3.6.0
     * RWREC_MAYBE_CLEAR_TCPSTATE_EXPANDED(rwrec);
     */

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
ipv6routingioRecordPack_V3(
    skstream_t         *stream,
    const rwRec        *rwrec,
    uint8_t            *ar)
{
    uint32_t u32;
    uint64_t u64;

    rwRecMemGetStartTime(rwrec, &ar[0]);
    rwRecMemGetElapsed(rwrec, &ar[8]);
    rwRecMemGetSPort(rwrec, &ar[12]);
    rwRecMemGetDPort(rwrec, &ar[14]);
    rwRecMemGetProto(rwrec, &ar[16]);
    rwRecMemGetFlowType(rwrec, &ar[17]);
    rwRecMemGetSensor(rwrec, &ar[18]);
    rwRecMemGetFlags(rwrec, &ar[20]);
    rwRecMemGetInitFlags(rwrec, &ar[21]);
    rwRecMemGetRestFlags(rwrec, &ar[22]);
    rwRecMemGetTcpState(rwrec, &ar[23]);
    rwRecMemGetApplication(rwrec, &ar[24]);
    rwRecMemGetMemo(rwrec, &ar[26]);

    u32 = rwRecGetInput(rwrec);
    memcpy(&ar[28], &u32, sizeof(u32));

    u64 = rwRecGetPkts(rwrec);
    memcpy(&ar[32], &u64, sizeof(u64));

    u64 = rwRecGetBytes(rwrec);
    memcpy(&ar[40], &u64, sizeof(u64));

    u32 = rwRecGetOutput(rwrec);
    memcpy(&ar[96], &u32, sizeof(u32));

    if (rwRecIsIPv6(rwrec)) {
        /* Record is IPv6 */
#if !SK_ENABLE_IPV6
        return SKSTREAM_ERR_UNSUPPORT_IPV6;
#else
        ar[23] |= 0x80;
        rwRecMemGetSIPv6(rwrec, &ar[48]);
        rwRecMemGetDIPv6(rwrec, &ar[64]);
        rwRecMemGetNhIPv6(rwrec, &ar[80]);
#endif  /* SK_ENABLE_IPV6 */
    } else {
        /* Record is IPv4, but encode as IPv6 */
        uint32_t ip;

        /* sIP */
        ip = htonl(rwRecGetSIPv4(rwrec));
        memcpy(&ar[48], IP4in6_prefix, sizeof(IP4in6_prefix));
        memcpy(&ar[60], &ip, sizeof(ip));

        /* dIP */
        ip = htonl(rwRecGetDIPv4(rwrec));
        memcpy(&ar[64], IP4in6_prefix, sizeof(IP4in6_prefix));
        memcpy(&ar[76], &ip, sizeof(ip));

        /* nhIP */
        ip = htonl(rwRecGetNhIPv4(rwrec));
        memcpy(&ar[80], IP4in6_prefix, sizeof(IP4in6_prefix));
        memcpy(&ar[92], &ip, sizeof(ip));
    }

    /* swap if required */
    if (stream->swapFlag) {
        ipv6routingioRecordSwap_V3(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWIPV6ROUTING VERSION 2
**
**    FT_RWIPV6ROUTING version 2 is identical to V1, expect must clear
**    the application field when unpacking.  Packing functions for V1
**    and V2 are identical.
*/

static int
ipv6routingioRecordUnpack_V2(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    int rv;

    rv = ipv6routingioRecordUnpack_V1(stream, rwrec, ar);
    rwRecSetApplication(rwrec, 0);
    return rv;
}


/* ********************************************************************* */

/*
**  RWIPV6ROUTING VERSION 1
**
**    int64_t       sTime;       //  0- 7  Flow start time as milliseconds
**                               //        since UNIX epoch
**
**    uint32_t      elapsed;     //  8-11  Duration of flow in milliseconds
**                               //        (Allows for a 49 day flow)
**
**    uint16_t      sPort;       // 12-13  Source port
**    uint16_t      dPort;       // 14-15  Destination port
**
**    uint8_t       proto;       // 16     IP protocol
**    uint8_t       flow_type;   // 17     Class & Type info
**    uint16_t      sID;         // 18-19  Sensor ID
**
**    uint8_t       flags;       // 20     OR of all flags (Netflow flags)
**    uint8_t       init_flags;  // 21     TCP flags in first packet
**                               //        or blank for "legacy" data
**    uint8_t       rest_flags;  // 22     TCP flags on non-initial packet
**                               //        or blank for "legacy" data
**    uint8_t       tcp_state;   // 23     TCP state machine info (below)
**
**    uint16_t      application; // 24-25  Indication of type of traffic
**    uint16_t      memo;        // 26-27  Application specific field
**
**    uint16_t      input;       // 28-29  Router incoming SNMP interface
**    uint16_t      output;      // 30-31  Router outgoing SNMP interface
**
**    uint32_t      pkts;        // 32-35  Count of packets
**    uint32_t      bytes;       // 36-39  Count of bytes
**
**    uint8_t[16]   sIP;         // 40-55  Source IP
**    uint8_t[16]   dIP;         // 56-71  Destination IP
**    uint8_t[16]   nhIP;        // 72-87  Router Next Hop IP
**
**
**  88 bytes on disk.
*/

#define RECLEN_RWIPV6ROUTING_V1 88


/*
 *    Byte swap the RWIPV6ROUTING v1 record 'ar' in place.
 */
#define ipv6routingioRecordSwap_V1(ar)                                  \
    {                                                                   \
        SWAP_DATA64((ar) +  0);   /* sTime */                           \
        SWAP_DATA32((ar) +  8);   /* elapsed */                         \
        SWAP_DATA16((ar) + 12);   /* sPort */                           \
        SWAP_DATA16((ar) + 14);   /* dPort */                           \
        /* Two single bytes: (16)proto, (17)flow_type */                \
        SWAP_DATA16((ar) + 18);   /* sID */                             \
        /* Four single bytes: (20)flags, (21)init_flags,                \
         *                    (22)rest_flags, (23)tcp_state */          \
        SWAP_DATA16((ar) + 24);   /* application */                     \
        SWAP_DATA16((ar) + 26);   /* memo */                            \
        SWAP_DATA16((ar) + 28);   /* input */                           \
        SWAP_DATA16((ar) + 30);   /* output */                          \
        SWAP_DATA32((ar) + 32);   /* pkts */                            \
        SWAP_DATA32((ar) + 36);   /* bytes */                           \
        /* 48 bytes of sIP, dIP, nhIP always in network byte order */   \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
ipv6routingioRecordUnpack_V1(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t ip;

    /* swap if required */
    if (stream->swapFlag) {
        ipv6routingioRecordSwap_V1(ar);
    }

    rwRecMemSetStartTime(rwrec, &ar[0]);
    rwRecMemSetElapsed(rwrec, &ar[8]);
    rwRecMemSetSPort(rwrec, &ar[12]);
    rwRecMemSetDPort(rwrec, &ar[14]);
    rwRecMemSetProto(rwrec, &ar[16]);
    rwRecMemSetFlowType(rwrec, &ar[17]);
    rwRecMemSetSensor(rwrec, &ar[18]);
    rwRecMemSetFlags(rwrec, &ar[20]);
    rwRecMemSetInitFlags(rwrec, &ar[21]);
    rwRecMemSetRestFlags(rwrec, &ar[22]);
    rwRecMemSetTcpState(rwrec, &ar[23]);
    rwRecMemSetApplication(rwrec, &ar[24]);
    rwRecMemSetMemo(rwrec, &ar[26]);
    rwRecMemSetInput(rwrec, &ar[28]);
    rwRecMemSetOutput(rwrec, &ar[30]);
    rwRecMemSetPkts(rwrec, &ar[32]);
    rwRecMemSetBytes(rwrec, &ar[36]);

    if (ar[23] & 0x80) {
        /* Record is IPv6 */
#if !SK_ENABLE_IPV6
        return SKSTREAM_ERR_UNSUPPORT_IPV6;
#else
        rwRecSetIPv6(rwrec);
        rwRecMemSetSIPv6(rwrec, &ar[40]);
        rwRecMemSetDIPv6(rwrec, &ar[56]);
        rwRecMemSetNhIPv6(rwrec, &ar[72]);
#endif /* SK_ENABLE_IPV6 */
    } else {
        /* Record is IPv4 */

        /* sIP */
        memcpy(&ip, &ar[52], sizeof(ip));
        rwRecSetSIPv4(rwrec, ntohl(ip));

        /* dIP */
        memcpy(&ip, &ar[68], sizeof(ip));
        rwRecSetDIPv4(rwrec, ntohl(ip));

        /* nhIP */
        memcpy(&ip, &ar[84], sizeof(ip));
        rwRecSetNhIPv4(rwrec, ntohl(ip));
    }

    RWREC_MAYBE_CLEAR_TCPSTATE_EXPANDED(rwrec);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
ipv6routingioRecordPack_V1(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    uint32_t ip;

    rwRecMemGetStartTime(rwrec, &ar[0]);
    rwRecMemGetElapsed(rwrec, &ar[8]);
    rwRecMemGetSPort(rwrec, &ar[12]);
    rwRecMemGetDPort(rwrec, &ar[14]);
    rwRecMemGetProto(rwrec, &ar[16]);
    rwRecMemGetFlowType(rwrec, &ar[17]);
    rwRecMemGetSensor(rwrec, &ar[18]);
    rwRecMemGetFlags(rwrec, &ar[20]);
    rwRecMemGetInitFlags(rwrec, &ar[21]);
    rwRecMemGetRestFlags(rwrec, &ar[22]);
    rwRecMemGetTcpState(rwrec, &ar[23]);
    rwRecMemGetApplication(rwrec, &ar[24]);
    rwRecMemGetMemo(rwrec, &ar[26]);
    rwRecMemGetInput(rwrec, &ar[28]);
    rwRecMemGetOutput(rwrec, &ar[30]);
    rwRecMemGetPkts(rwrec, &ar[32]);
    rwRecMemGetBytes(rwrec, &ar[36]);

    if (rwRecIsIPv6(rwrec)) {
        /* Record is IPv6 */
#if !SK_ENABLE_IPV6
        return SKSTREAM_ERR_UNSUPPORT_IPV6;
#else
        ar[23] |= 0x80;
        rwRecMemGetSIPv6(rwrec, &ar[40]);
        rwRecMemGetDIPv6(rwrec, &ar[56]);
        rwRecMemGetNhIPv6(rwrec, &ar[72]);
#endif /* SK_ENABLE_IPV6 */
    } else {
        /* Record is IPv4, but encode as IPv6 */

        /* sIP */
        ip = htonl(rwRecGetSIPv4(rwrec));
        memcpy(&ar[40], IP4in6_prefix, sizeof(IP4in6_prefix));
        memcpy(&ar[52], &ip, sizeof(ip));

        /* dIP */
        ip = htonl(rwRecGetDIPv4(rwrec));
        memcpy(&ar[56], IP4in6_prefix, sizeof(IP4in6_prefix));
        memcpy(&ar[68], &ip, sizeof(ip));

        /* nhIP */
        ip = htonl(rwRecGetNhIPv4(rwrec));
        memcpy(&ar[72], IP4in6_prefix, sizeof(IP4in6_prefix));
        memcpy(&ar[84], &ip, sizeof(ip));
    }

    /* swap if required */
    if (stream->swapFlag) {
        ipv6routingioRecordSwap_V1(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
 *  Return length of record of specified version, or 0 if no such
 *  version exists.  See skstream_priv.h for details.
 */
uint16_t
ipv6routingioGetRecLen(
    sk_file_version_t   vers)
{
    switch (vers) {
      case 1:
      case 2:
        return RECLEN_RWIPV6ROUTING_V1;
      case 3:
        return RECLEN_RWIPV6ROUTING_V3;
      default:
        return 0;
    }
}


/*
 *  status = ipv6routingioPrepare(stream);
 *
 *    Sets the record version to the default if it is unspecified,
 *    checks that the record format supports the requested record
 *    version, sets the record length, and sets the pack and unpack
 *    functions for this record format and version.
 */
int
ipv6routingioPrepare(
    skstream_t         *stream)
{
#define FILE_FORMAT "FT_RWIPV6ROUTING"
    sk_file_header_t *hdr = stream->silk_hdr;
    int rv = SKSTREAM_OK; /* return value */

    /* Set version if none was selected by caller */
    if ((stream->io_mode == SK_IO_WRITE)
        && (skHeaderGetRecordVersion(hdr) == SK_RECORD_VERSION_ANY))
    {
        skHeaderSetRecordVersion(hdr, DEFAULT_RECORD_VERSION);
    }

    /* version check; set values based on version */
    switch (skHeaderGetRecordVersion(hdr)) {
      case 3:
        stream->rwUnpackFn = &ipv6routingioRecordUnpack_V3;
        stream->rwPackFn   = &ipv6routingioRecordPack_V3;
        break;
      case 2:
        stream->rwUnpackFn = &ipv6routingioRecordUnpack_V2;
        stream->rwPackFn   = &ipv6routingioRecordPack_V1;
        break;
      case 1:
        stream->rwUnpackFn = &ipv6routingioRecordUnpack_V1;
        stream->rwPackFn   = &ipv6routingioRecordPack_V1;
        break;
      case 0:
      default:
        rv = SKSTREAM_ERR_UNSUPPORT_VERSION;
        goto END;
    }

    stream->recLen = ipv6routingioGetRecLen(skHeaderGetRecordVersion(hdr));

    /* verify lengths */
    if (stream->recLen == 0) {
        skAppPrintErr("Record length not set for %s version %u",
                      FILE_FORMAT, (unsigned)skHeaderGetRecordVersion(hdr));
        skAbort();
    }
    if (stream->recLen != skHeaderGetRecordLength(hdr)) {
        if (0 == skHeaderGetRecordLength(hdr)) {
            skHeaderSetRecordLength(hdr, stream->recLen);
        } else {
            skAppPrintErr(("Record length mismatch for %s version %u\n"
                           "\tcode = %" PRIu16 " bytes;  header = %lu bytes"),
                          FILE_FORMAT, (unsigned)skHeaderGetRecordVersion(hdr),
                          stream->recLen,
                          (unsigned long)skHeaderGetRecordLength(hdr));
            skAbort();
        }
    }

  END:
    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
