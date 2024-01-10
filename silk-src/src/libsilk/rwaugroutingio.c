/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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
** rwaugroutingio.c
**
**      routines to do io stuff with augrouting records.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwaugroutingio.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/* #define RWPACK_BYTES_PACKETS          1 */
#define RWPACK_FLAGS_TIMES_VOLUMES    1
#define RWPACK_PROTO_FLAGS            1
/* #define RWPACK_SBB_PEF                1 */
#define RWPACK_TIME_BYTES_PKTS_FLAGS  1
#define RWPACK_TIMES_FLAGS_PROTO      1
#include "skstream_priv.h"
#include "rwpack.c"


/* Version to use when SK_RECORD_VERSION_ANY is specified */
#define DEFAULT_RECORD_VERSION 4


/* ********************************************************************* */

/*
**  RWAUGROUTING VERSION 5
**
**  in the following: EXPANDED == ((tcp_state & SK_TCPSTATE_EXPANDED) ? 1 : 0)
**
**    uint32_t      rflag_stime;     //  0- 3
**    // uint32_t     rest_flags: 8; //        is_tcp==0: Empty; else
**                                   //          EXPANDED==0:Empty
**                                   //          EXPANDED==1:TCPflags/!1st pkt
**    // uint32_t     is_tcp    : 1; //        1 if FLOW is TCP; 0 otherwise
**    // uint32_t     unused    : 1; //        Reserved
**    // uint32_t     stime     :22; //        Start time:msec offset from hour
**
**    uint8_t       proto_iflags;    //  4     is_tcp==0: Protocol; else:
**                                   //          EXPANDED==0:TCPflags/ALL pkts
**                                   //          EXPANDED==1:TCPflags/1st pkt
**    uint8_t       tcp_state;       //  5     TCP state machine info
**    uint16_t      application;     //  6- 7  Indication of type of traffic
**
**    uint16_t      sPort;           //  8- 9  Source port
**    uint16_t      dPort;           // 10-11  Destination port
**
**    uint32_t      elapsed;         // 12-15  Duration of the flow
**
**    uint32_t      pkts;            // 16-19  Count of packets
**    uint32_t      bytes;           // 20-23  Count of bytes
**
**    uint32_t      sIP;             // 24-27  Source IP
**    uint32_t      dIP;             // 28-31  Destination IP
**
**    uint32_t      nhIP;            // 32-35  Router Next Hop IP
**
**    uint16_t      input;           // 36-37  Router incoming SNMP interface
**    uint16_t      output;          // 38-39  Router outgoing SNMP interface
**
**
**  40 bytes on disk.
*/

#define RECLEN_RWAUGROUTING_V5 40


/*
 *    Byte swap the RWAUGROUTING v5 record 'ar' in place.
 */
#define augroutingioRecordSwap_V5(ar)                           \
    {                                                           \
        SWAP_DATA32((ar) +  0);   /* rflag_stime */             \
        /* two single bytes (4)proto_iflags, (5)tcp_state */    \
        SWAP_DATA16((ar) +  6);   /* application */             \
        SWAP_DATA16((ar) +  8);   /* sPort */                   \
        SWAP_DATA16((ar) + 10);   /* dPort */                   \
        SWAP_DATA32((ar) + 12);   /* elapsed */                 \
        SWAP_DATA32((ar) + 16);   /* pkts */                    \
        SWAP_DATA32((ar) + 20);   /* bytes */                   \
        SWAP_DATA32((ar) + 24);   /* sIP */                     \
        SWAP_DATA32((ar) + 28);   /* dIP */                     \
        SWAP_DATA32((ar) + 32);   /* nhIP */                    \
        SWAP_DATA16((ar) + 36);   /* input */                   \
        SWAP_DATA16((ar) + 38);   /* output */                  \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
augroutingioRecordUnpack_V5(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    /* swap if required */
    if (stream->swapFlag) {
        augroutingioRecordSwap_V5(ar);
    }

    /* Start time, TCP flags, Protocol, TCP State */
    rwpackUnpackTimesFlagsProto(rwrec, ar, stream->hdr_starttime);

    /* application */
    rwRecMemSetApplication(rwrec, &ar[ 6]);

    /* sPort, dPort */
    rwRecMemSetSPort(rwrec, &ar[ 8]);
    rwRecMemSetDPort(rwrec, &ar[10]);

    /* Elapsed */
    rwRecMemSetElapsed(rwrec, &ar[12]);

    /* packets, bytes */
    rwRecMemSetPkts(rwrec,  &ar[16]);
    rwRecMemSetBytes(rwrec, &ar[20]);

    /* sIP, dIP */
    rwRecMemSetSIPv4(rwrec, &ar[24]);
    rwRecMemSetDIPv4(rwrec, &ar[28]);

    /* nhIP */
    rwRecMemSetNhIPv4(rwrec, &ar[32]);

    /* input, output */
    rwRecMemSetInput(rwrec,  &ar[36]);
    rwRecMemSetOutput(rwrec, &ar[38]);

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
augroutingioRecordPack_V5(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv;

    /* Start time, TCP Flags, Protocol, TCP State */
    rv = rwpackPackTimesFlagsProto(rwrec, ar, stream->hdr_starttime);
    if (rv) {
        return rv;
    }

    /* application */
    rwRecMemGetApplication(rwrec, &ar[6]);

    /* sPort, dPort */
    rwRecMemGetSPort(rwrec, &ar[ 8]);
    rwRecMemGetDPort(rwrec, &ar[10]);

    /* Elapsed */
    rwRecMemGetElapsed(rwrec, &ar[12]);

    /* packets, bytes */
    rwRecMemGetPkts(rwrec,  &ar[16]);
    rwRecMemGetBytes(rwrec, &ar[20]);

    /* sIP, dIP */
    rwRecMemGetSIPv4(rwrec, &ar[24]);
    rwRecMemGetDIPv4(rwrec, &ar[28]);

    /* nhIP */
    rwRecMemGetNhIPv4(rwrec, &ar[32]);

    /* input, output */
    rwRecMemGetInput(rwrec,  &ar[36]);
    rwRecMemGetOutput(rwrec, &ar[38]);

    /* swap if required */
    if (stream->swapFlag) {
        augroutingioRecordSwap_V5(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWAUGROUTING VERSION 4
**
**  in the following: EXPANDED == ((tcp_state & SK_TCPSTATE_EXPANDED) ? 1 : 0)
**
**    uint32_t      stime_bb1;       //  0- 3
**    // uint32_t     stime     :22  //        Start time:msec offset from hour
**    // uint32_t     bPPkt1    :10; //        Whole bytes-per-packet (hi 10)
**
**    uint32_t      bb2_elapsed;     //  4- 7
**    // uint32_t     bPPkt2    : 4; //        Whole bytes-per-packet (low 4)
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**    // uint32_t     elapsed   :22; //        Duration of flow in msec
**
**    uint32_t      pro_flg_pkts;    //  8-11
**    // uint32_t     prot_flags: 8; //        is_tcp==0: IP protocol
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:TCPflags/All pkts
**                                   //          EXPANDED==1:TCPflags/1st pkt
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**    // uint32_t     is_tcp    : 1; //        1 if flow is TCP; 0 otherwise
**    // uint32_t     padding   : 2; //
**    // uint32_t     pkts      :20; //        Count of packets
**
**    uint8_t       tcp_state;       // 12     TCP state machine info
**    uint8_t       rest_flags;      // 13     is_tcp==0: Flow's reported flags
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:Empty
**                                   //          EXPANDED==1:TCPflags/!1st pkt
**    uint16_t      application;     // 14-15  Type of traffic
**
**    uint16_t      sPort;           // 16-17  Source port
**    uint16_t      dPort;           // 18-19  Destination port
**
**    uint16_t      input;           // 20-21  Router incoming SNMP interface
**    uint16_t      output;          // 22-23  Router outgoing SNMP interface
**
**    uint32_t      sIP;             // 24-27  Source IP
**    uint32_t      dIP;             // 28-31  Destination IP
**
**    uint32_t      nhIP;            // 32-35  Router Next Hop IP
**
**
**  36 bytes on disk.
*/

#define RECLEN_RWAUGROUTING_V4 36


/*
 *    Byte swap the RWAUGROUTING v4 record 'ar' in place.
 */
#define augroutingioRecordSwap_V4(ar)                           \
    {                                                           \
        SWAP_DATA32((ar) +  0);   /* stime_bb1 */               \
        SWAP_DATA32((ar) +  4);   /* bb2_elapsed */             \
        SWAP_DATA32((ar) +  8);   /* pro_flg_pkts */            \
        /* two single bytes (12)tcp_state, (13)rest_flags */    \
        SWAP_DATA16((ar) + 14);   /* application */             \
        SWAP_DATA16((ar) + 16);   /* sPort */                   \
        SWAP_DATA16((ar) + 18);   /* dPort */                   \
        SWAP_DATA16((ar) + 20);   /* input */                   \
        SWAP_DATA16((ar) + 22);   /* output */                  \
        SWAP_DATA32((ar) + 24);   /* sIP */                     \
        SWAP_DATA32((ar) + 28);   /* dIP */                     \
        SWAP_DATA32((ar) + 32);   /* nhIP */                    \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
augroutingioRecordUnpack_V4(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    /* swap if required */
    if (stream->swapFlag) {
        augroutingioRecordSwap_V4(ar);
    }

    /* sTime, elapsed, pkts, bytes, proto, tcp-flags, state, application */
    rwpackUnpackFlagsTimesVolumes(rwrec, ar, stream->hdr_starttime, 16, 0);

    /* sPort, dPort */
    rwRecMemSetSPort(rwrec, &ar[16]);
    rwRecMemSetDPort(rwrec, &ar[18]);

    /* input, output */
    rwRecMemSetInput(rwrec, &ar[20]);
    rwRecMemSetOutput(rwrec, &ar[22]);

    /* sIP, dIP, nhIP */
    rwRecMemSetSIPv4(rwrec, &ar[24]);
    rwRecMemSetDIPv4(rwrec, &ar[28]);
    rwRecMemSetNhIPv4(rwrec, &ar[32]);

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
augroutingioRecordPack_V4(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */

    /* sTime, elapsed, pkts, bytes, proto, tcp-flags, state, application */
    rv = rwpackPackFlagsTimesVolumes(ar, rwrec, stream->hdr_starttime, 16);
    if (rv) {
        return rv;
    }

    /* sPort, dPort */
    rwRecMemGetSPort(rwrec, &ar[16]);
    rwRecMemGetDPort(rwrec, &ar[18]);

    /* input, output */
    rwRecMemGetInput(rwrec, &ar[20]);
    rwRecMemGetOutput(rwrec, &ar[22]);

    /* sIP, dIP, nhIP */
    rwRecMemGetSIPv4(rwrec, &ar[24]);
    rwRecMemGetDIPv4(rwrec, &ar[28]);
    rwRecMemGetNhIPv4(rwrec, &ar[32]);

    /* swap if required */
    if (stream->swapFlag) {
        augroutingioRecordSwap_V4(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWAUGROUTING VERSION 1
**  RWAUGROUTING VERSION 2
**  RWAUGROUTING VERSION 3
**
**  in the following: EXPANDED == ((tcp_state & SK_TCPSTATE_EXPANDED) ? 1 : 0)
**
**    uint32_t      sIP;             //  0- 3  Source IP
**    uint32_t      dIP;             //  4- 7  Destination IP
**
**    uint16_t      sPort;           //  8- 9  Source port
**    uint16_t      dPort;           // 10-11  Destination port
**
**    uint32_t      pkts_stime;      // 12-15
**    // uint32_t     pkts      :20; //        Count of packets
**    // uint32_t     sTime     :12; //        Start time--offset from hour
**
**    uint32_t      bbe;             // 16-19
**    // uint32_t     bPPkt     :14; //        Whole bytes-per-packet
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**    // uint32_t     elapsed   :12; //        Duration of flow
**
**    uint32_t      msec_flags       // 20-23
**    // uint32_t     sTime_msec:10; //        Fractional sTime (millisec)
**    // uint32_t     elaps_msec:10; //        Fractional elapsed (millisec)
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**    // uint32_t     is_tcp    : 1; //        1 if flow is TCP; 0 otherwise
**    // uint32_t     padding   : 2; //        padding/reserved
**    // uint32_t     prot_flags: 8; //        is_tcp==0: IP protocol
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:TCPflags/All pkts
**                                   //          EXPANDED==1:TCPflags/1st pkt
**
**    uint16_t      application;     // 24-25  Type of traffic
**
**    uint8_t       tcp_state;       // 26     TCP state machine info
**    uint8_t       rest_flags;      // 27     is_tcp==0: Flow's reported flags
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:Empty
**                                   //          EXPANDED==1:TCPflags/!1st pkt
**
**    uint32_t      nhIP;            // 28-31  Router Next Hop IP
**
**    uint16_t      input;           // 32-33  Router incoming SNMP interface
**    uint16_t      output;          // 34-35  Router outgoing SNMP interface
**
**
**  36 bytes on disk.
*/

#define RECLEN_RWAUGROUTING_V1 36
#define RECLEN_RWAUGROUTING_V2 36
#define RECLEN_RWAUGROUTING_V3 36


/*
 *    Byte swap the RWAUGROUTING v1 record 'ar' in place.
 */
#define augroutingioRecordSwap_V1(ar)                           \
    {                                                           \
        SWAP_DATA32((ar) +  0);   /* sIP */                     \
        SWAP_DATA32((ar) +  4);   /* dIP */                     \
        SWAP_DATA16((ar) +  8);   /* sPort */                   \
        SWAP_DATA16((ar) + 10);   /* dPort */                   \
        SWAP_DATA32((ar) + 12);   /* pkts_stime */              \
        SWAP_DATA32((ar) + 16);   /* bbe */                     \
        SWAP_DATA32((ar) + 20);   /* msec_flags */              \
        SWAP_DATA16((ar) + 24);   /* application */             \
        /* Two single bytes: (26)tcp_state, (27)rest_flags */   \
        SWAP_DATA32((ar) + 28);   /* nhIP */                    \
        SWAP_DATA16((ar) + 32);   /* input */                   \
        SWAP_DATA16((ar) + 34);   /* output */                  \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
augroutingioRecordUnpack_V1(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t msec_flags;
    uint8_t is_tcp, prot_flags;

    /* swap if required */
    if (stream->swapFlag) {
        augroutingioRecordSwap_V1(ar);
    }

    /* sIP, dIP, sPort, dPort */
    rwRecMemSetSIPv4(rwrec, &ar[0]);
    rwRecMemSetDIPv4(rwrec, &ar[4]);
    rwRecMemSetSPort(rwrec, &ar[8]);
    rwRecMemSetDPort(rwrec, &ar[10]);

    /* msec times, proto or flags */
    memcpy(&msec_flags, &ar[20],  4);

    /* application */
    rwRecMemSetApplication(rwrec, &ar[24]);

    /* sTime, pkts, bytes, elapsed, proto, tcp-flags, bpp */
    rwpackUnpackTimeBytesPktsFlags(rwrec, stream->hdr_starttime,
                                   (uint32_t*)&ar[12], (uint32_t*)&ar[16],
                                   &msec_flags);

    /* extra TCP information */
    is_tcp = (uint8_t)GET_MASKED_BITS(msec_flags, 10, 1);
    prot_flags = (uint8_t)GET_MASKED_BITS(msec_flags, 0, 8);
    rwpackUnpackProtoFlags(rwrec, is_tcp, prot_flags, ar[26], ar[27]);

    /* next hop, input & output interfaces */
    rwRecMemSetNhIPv4(rwrec, &ar[28]);
    rwRecMemSetInput(rwrec, &ar[32]);
    rwRecMemSetOutput(rwrec, &ar[34]);

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
augroutingioRecordPack_V1(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */
    uint32_t msec_flags;
    uint8_t is_tcp, prot_flags;

    /* sTime, pkts, bytes, elapsed, proto, tcp-flags, bpp */
    rv = rwpackPackTimeBytesPktsFlags((uint32_t*)&ar[12], (uint32_t*)&ar[16],
                                      &msec_flags,
                                      rwrec, stream->hdr_starttime);
    if (rv) {
        return rv;
    }

    rwpackPackProtoFlags(&is_tcp, &prot_flags, &ar[26], &ar[27], rwrec);

    /* msec_flags: sTime_msec:10; elaps_msec:10; pflag:1;
     *             is_tcp:1; pad:2; prot_flags:8; */
    /* overwrite the least significant 11 bits */
    msec_flags = ((msec_flags & (MASKARRAY_21 << 11))
                  | (is_tcp ? (1 << 10) : 0)
                  | prot_flags);

    /* sIP, dIP, sPort, dPort */
    rwRecMemGetSIPv4(rwrec, &ar[0]);
    rwRecMemGetDIPv4(rwrec, &ar[4]);
    rwRecMemGetSPort(rwrec, &ar[8]);
    rwRecMemGetDPort(rwrec, &ar[10]);

    /* msec_flags */
    memcpy(&ar[20], &msec_flags, 4);

    /* application */
    rwRecMemGetApplication(rwrec, &ar[24]);

    /* next hop, input & output interfaces */
    rwRecMemGetNhIPv4(rwrec, &ar[28]);
    rwRecMemGetInput(rwrec, &ar[32]);
    rwRecMemGetOutput(rwrec, &ar[34]);

    /* swap if required */
    if (stream->swapFlag) {
        augroutingioRecordSwap_V1(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
 *  Return length of record of specified version, or 0 if no such
 *  version exists.  See skstream_priv.h for details.
 */
uint16_t
augroutingioGetRecLen(
    sk_file_version_t   vers)
{
    switch (vers) {
      case 1:
        return RECLEN_RWAUGROUTING_V1;
      case 2:
        return RECLEN_RWAUGROUTING_V2;
      case 3:
        return RECLEN_RWAUGROUTING_V3;
      case 4:
        return RECLEN_RWAUGROUTING_V4;
      case 5:
        return RECLEN_RWAUGROUTING_V5;
      default:
        return 0;
    }
}


/*
 *  status = augroutingioPrepare(&stream);
 *
 *    Sets the record version to the default if it is unspecified,
 *    checks that the record format supports the requested record
 *    version, sets the record length, and sets the pack and unpack
 *    functions for this record format and version.
 */
int
augroutingioPrepare(
    skstream_t         *stream)
{
#define FILE_FORMAT "FT_RWAUGROUTING"
    sk_file_header_t *hdr = stream->silk_hdr;
    int rv = SKSTREAM_OK; /* return value */

    assert(skHeaderGetFileFormat(hdr) == FT_RWAUGROUTING);

    /* Set version if none was selected by caller */
    if ((stream->io_mode == SK_IO_WRITE)
        && (skHeaderGetRecordVersion(hdr) == SK_RECORD_VERSION_ANY))
    {
        skHeaderSetRecordVersion(hdr, DEFAULT_RECORD_VERSION);
    }

    /* version check; set values based on version */
    switch (skHeaderGetRecordVersion(hdr)) {
      case 5:
        stream->rwUnpackFn = &augroutingioRecordUnpack_V5;
        stream->rwPackFn   = &augroutingioRecordPack_V5;
        break;
      case 4:
        stream->rwUnpackFn = &augroutingioRecordUnpack_V4;
        stream->rwPackFn   = &augroutingioRecordPack_V4;
        break;
      case 3:
      case 2:
      case 1:
        /* V1 and V2 differ only in the padding of the header */
        /* V2 and V3 differ only in that V3 supports compression on
         * read and write; V2 supports compression only on read */
        stream->rwUnpackFn = &augroutingioRecordUnpack_V1;
        stream->rwPackFn   = &augroutingioRecordPack_V1;
        break;
      case 0:
      default:
        rv = SKSTREAM_ERR_UNSUPPORT_VERSION;
        goto END;
    }

    stream->recLen = augroutingioGetRecLen(skHeaderGetRecordVersion(hdr));

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
