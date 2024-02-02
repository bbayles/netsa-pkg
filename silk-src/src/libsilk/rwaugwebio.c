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
** rwaugwebio.c
**
** Suresh L Konda
**      routines to do io stuff with augweb records.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwaugwebio.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

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
**  RWAUGWEB VERSION 5
**
**  in the following: EXPANDED == ((tcp_state & SK_TCPSTATE_EXPANDED) ? 1 : 0)
**
**    uint32_t      rflag_stime;     //  0- 3
**    // uint32_t     rest_flags: 8; //        EXPANDED==0:Empty
**                                   //        EXPANDED==1:TCPflags/!1st pkt
**    // uint32_t     is_tcp    : 1; //        always 1 since all flows TCP
**    // uint32_t     src_is_srv: 1; //        1 if sIP is http server
**    // uint32_t     stime     :22; //        Start time:msec offset from hour
**
**    uint8_t       proto_iflags;    //  4     EXPANDED==0:TCPflags/ALL pkts
**                                   //        EXPANDED==1:TCPflags/1st pkt
**    uint8_t       tcp_state;       //  5     TCP state machine info
**    uint16_t      application;     //  6- 7  Indication of type of traffic
**
**    uint32_t      srvport_elapsed; //  8-11
**    // uint32_t      srv_port : 2; //        Server port: 0=80; 1=443; 2=8080
**    // uint32_t      elapsed  :30; //        Duration of the flow
**
**    uint32_t      pkts;            // 12-15  Count of packets
**    uint32_t      bytes;           // 16-19  Count of bytes
**
**    uint32_t      sIP;             // 20-23  Source IP
**    uint32_t      dIP;             // 24-27  Destination IP
**
**    uint16_t      clnt_port;       // 28-29  Client(non-server) port
**
**
**  30 bytes on disk.
*/

#define RECLEN_RWAUGWEB_V5 30


/*
 *    Byte swap the RWAUGWEB v5 record 'ar' in place.
 */
#define augwebioRecordSwap_V5(ar)                               \
    {                                                           \
        SWAP_DATA32((ar) +  0);   /* rflag_stime */             \
        /* two single bytes (4)proto_iflags, (5)tcp_state */    \
        SWAP_DATA16((ar) +  6);   /* application */             \
        SWAP_DATA32((ar) +  8);   /* srvport_elapsed */         \
        SWAP_DATA32((ar) + 12);   /* pkts */                    \
        SWAP_DATA32((ar) + 16);   /* bytes */                   \
        SWAP_DATA32((ar) + 20);   /* sIP */                     \
        SWAP_DATA32((ar) + 24);   /* dIP */                     \
        SWAP_DATA16((ar) + 28);   /* clnt_port */               \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
augwebioRecordUnpack_V5(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t rflag_stime;
    uint32_t srvport_elapsed;
    uint32_t srv_port;

    /* swap if required */
    if (stream->swapFlag) {
        augwebioRecordSwap_V5(ar);
    }

    /* Get a copy of rflag_stime to check the src_is_srv bit below */
    memcpy(&rflag_stime, &ar[0], sizeof(rflag_stime));

    /* Start time, TCP flags, Protocol, TCP State */
    rwpackUnpackTimesFlagsProto(rwrec, ar, stream->hdr_starttime);

    /* application */
    rwRecMemSetApplication(rwrec, &ar[ 6]);

    /* Elapsed */
    memcpy(&srvport_elapsed,  &ar[ 8], sizeof(srvport_elapsed));
    rwRecSetElapsed(rwrec, GET_MASKED_BITS(srvport_elapsed, 0, 30));

    /* packets, bytes */
    rwRecMemSetPkts(rwrec,  &ar[12]);
    rwRecMemSetBytes(rwrec, &ar[16]);

    /* sIP, dIP */
    rwRecMemSetSIPv4(rwrec, &ar[20]);
    rwRecMemSetDIPv4(rwrec, &ar[24]);

    /* set the ports based on who was the server */
    srv_port = GET_MASKED_BITS(srvport_elapsed, 30, 2);
    if (GET_MASKED_BITS(rflag_stime, 22, 1)) {
        /* source IP/Port is server; dest is client */
        rwRecSetSPort(rwrec, SK_WEBPORT_EXPAND(srv_port));
        rwRecMemSetDPort(rwrec, &ar[28]);
    } else {
        /* dest IP/Port is server; source is client */
        rwRecMemSetSPort(rwrec, &ar[28]);
        rwRecSetDPort(rwrec, SK_WEBPORT_EXPAND(srv_port));
    }

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
augwebioRecordPack_V5(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    uint32_t rflag_stime;
    uint32_t srvport_elapsed;
    uint32_t src_is_srv;
    int rv;

    /* verify protocol is TCP.  Should we also check that the port is
     * one of those we encode---i.e., should we do the entire
     * rwRecIsWeb() check here, or do we assume the caller knows what
     * they are doing in choosing this file type? */
    if (rwRecGetProto(rwrec) != IPPROTO_TCP) {
        return SKSTREAM_ERR_PROTO_MISMATCH;
    }

    /* Elapsed */
    srvport_elapsed = rwRecGetElapsed(rwrec);
    if (srvport_elapsed & 0xc0000000) {
        return SKSTREAM_ERR_ELPSD_OVRFLO;
    }

    /* Start time, TCP Flags, Protocol, TCP State */
    rv = rwpackPackTimesFlagsProto(rwrec, ar, stream->hdr_starttime);
    if (rv) {
        return rv;
    }

    /* application */
    rwRecMemGetApplication(rwrec, &ar[6]);

    /* sPort, dPort, src_is_srv bit in 'rflag_stime', srv_port bits in
     * 'srvport_elapsed' */
    src_is_srv = SK_WEBPORT_CHECK(rwRecGetSPort(rwrec));
    if (src_is_srv) {
        /* source is server; put dPort into clnt_port */
        srvport_elapsed |= (SK_WEBPORT_ENCODE(rwRecGetSPort(rwrec)) << 30);
        rwRecMemGetDPort(rwrec, &ar[28]);

        /* Set the src_is_srv bit in the 'rflag_stime' */
        memcpy(&rflag_stime, &ar[0], sizeof(rflag_stime));
        rflag_stime |= (1 << 22);
        memcpy(&ar[0], &rflag_stime, sizeof(rflag_stime));

    } else {
        /* destination is server; put sPort into clnt_port; get dPort
         * as srv_port */
        srvport_elapsed |= (SK_WEBPORT_ENCODE(rwRecGetDPort(rwrec)) << 30);
        rwRecMemGetSPort(rwrec, &ar[28]);
    }

    /* Elapsed */
    memcpy(&ar[ 8], &srvport_elapsed, sizeof(srvport_elapsed));

    /* packets, bytes */
    rwRecMemGetPkts(rwrec,  &ar[12]);
    rwRecMemGetBytes(rwrec, &ar[16]);

    /* sIP, dIP */
    rwRecMemGetSIPv4(rwrec, &ar[20]);
    rwRecMemGetDIPv4(rwrec, &ar[24]);

    /* swap if required */
    if (stream->swapFlag) {
        augwebioRecordSwap_V5(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWAUGWEB VERSION 4
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
**    uint32_t      srv_flg_pkts;    //  8-11
**    // uint32_t     a_1_flags: 8;  //        EXPANDED==0:TCPflags/All pkts
**                                   //        EXPANDED==1:TCPflags/1st pkt
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**    // uint32_t     src_is_srv: 1; //        1 if sIP is http server
**    // uint32_t     srv_port  : 2; //        server port: 0=80; 1=443; 2=8080
**    // uint32_t     pkts      :20; //        Count of packets
**
**    uint8_t       tcp_state;       // 12     TCP state machine info
**    uint8_t       rest_flags;      // 13     is_tcp==0: Flow's reported flags
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:Empty
**                                   //          EXPANDED==1:TCPflags/!1st pkt
**    uint16_t      application;     // 14-15  Type of traffic
**
**    uint32_t      sIP;             // 16-19  Source IP
**    uint32_t      dIP;             // 20-23  Destination IP
**
**    uint16_t      clnt_port;       // 24-25  Client(non-server) port
**
**
**  26 bytes on disk.
*/

#define RECLEN_RWAUGWEB_V4 26


/*
 *    Byte swap the RWAUGWEB v4 record 'ar' in place.
 */
#define augwebioRecordSwap_V4(ar)                               \
    {                                                           \
        SWAP_DATA32((ar) +  0);   /* stime_bb1 */               \
        SWAP_DATA32((ar) +  4);   /* bb2_elapsed */             \
        SWAP_DATA32((ar) +  8);   /* srv_flg_pkts */            \
        /* two single bytes (12)tcp_state, (13)rest_flags */    \
        SWAP_DATA16((ar) + 14);   /* application */             \
        SWAP_DATA32((ar) + 16);   /* sIP */                     \
        SWAP_DATA32((ar) + 20);   /* dIP */                     \
        SWAP_DATA16((ar) + 24);   /* clnt_port */               \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
augwebioRecordUnpack_V4(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t srv_flg_pkts;
    uint32_t srv_port;

    /* swap if required */
    if (stream->swapFlag) {
        augwebioRecordSwap_V4(ar);
    }

    /* sTime, elapsed, pkts, bytes, proto, tcp-flags, state, application */
    rwpackUnpackFlagsTimesVolumes(rwrec, ar, stream->hdr_starttime, 16, 1);

    /* sIP, dIP */
    rwRecMemSetSIPv4(rwrec, &ar[16]);
    rwRecMemSetDIPv4(rwrec, &ar[20]);

    /* get the encoded server-side port */
    memcpy(&srv_flg_pkts, &ar[8], sizeof(srv_flg_pkts));
    srv_port = GET_MASKED_BITS(srv_flg_pkts, 20, 2);

    /* set the ports based on who was the server */
    if (GET_MASKED_BITS(srv_flg_pkts, 22, 1)) {
        /* source IP/Port is server; dest is client */
        rwRecSetSPort(rwrec, SK_WEBPORT_EXPAND(srv_port));
        rwRecMemSetDPort(rwrec, &ar[24]);
    } else {
        /* dest IP/Port is server; source is client */
        rwRecMemSetSPort(rwrec, &ar[24]);
        rwRecSetDPort(rwrec, SK_WEBPORT_EXPAND(srv_port));
    }

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
augwebioRecordPack_V4(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    uint32_t srv_flg_pkts;
    uint32_t src_is_srv;
    uint16_t srv_port;
    int rv = SKSTREAM_OK; /* return value */

    /* verify protocol is TCP.  Should we also check that the port is
     * one of those we encode---i.e., should we do the entire
     * rwRecIsWeb() check here, or do we assume the caller knows what
     * they are doing in choosing this file type? */
    if (rwRecGetProto(rwrec) != IPPROTO_TCP) {
        return SKSTREAM_ERR_PROTO_MISMATCH;
    }

    /* sTime, elapsed, pkts, bytes, proto, tcp-flags, state, application */
    rv = rwpackPackFlagsTimesVolumes(ar, rwrec, stream->hdr_starttime, 16);
    if (rv) {
        return rv;
    }

    /* sIP, dIP */
    rwRecMemGetSIPv4(rwrec, &ar[16]);
    rwRecMemGetDIPv4(rwrec, &ar[20]);

    /* pack the client-side port */
    srv_port = rwRecGetSPort(rwrec);
    src_is_srv = SK_WEBPORT_CHECK(srv_port);
    if (src_is_srv) {
        /* source is server; put dPort into clnt_port */
        rwRecMemGetDPort(rwrec, &ar[24]);
    } else {
        /* destination is server; put sPort into clnt_port; get dPort
         * as srv_port */
        memcpy(&ar[24], &srv_port, sizeof(srv_port));
        srv_port = rwRecGetDPort(rwrec);
    }

    /* pack the web-specific values */
    memcpy(&srv_flg_pkts, &ar[8], sizeof(srv_flg_pkts));
    srv_flg_pkts = ((srv_flg_pkts & ~(MASKARRAY_03 << 20))
                    | (SK_WEBPORT_ENCODE(srv_port) << 20)
                    | (src_is_srv ? (1 << 22) : 0));
    memcpy(&ar[8], &srv_flg_pkts, sizeof(srv_flg_pkts));

    /* swap if required */
    if (stream->swapFlag) {
        augwebioRecordSwap_V4(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWAUGWEB VERSION 1
**  RWAUGWEB VERSION 2
**  RWAUGWEB VERSION 3
**
**  in the following: EXPANDED == ((tcp_state & SK_TCPSTATE_EXPANDED) ? 1 : 0)
**
**    uint32_t      sIP;             //  0- 3  Source IP
**    uint32_t      dIP;             //  4- 7  Destination IP
**
**    uint32_t      pkts_stime;      //  8-11
**    // uint32_t     pkts      :20; //        Count of packets
**    // uint32_t     sTime     :12; //        Start time--offset from hour
**
**    uint32_t      bbe;             // 12-15
**    // uint32_t     bPPkt     :14; //        Whole bytes-per-packet
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**    // uint32_t     elapsed   :12; //        Duration of flow
**
**    uint32_t      msec_prt_flags   // 16-19
**    // uint32_t     sTime_msec:10; //        Fractional sTime (millisec)
**    // uint32_t     elaps_msec:10; //        Fractional elapsed (millisec)
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**    // uint32_t     srcIsSrv  : 1; //        1 if srv_port is src; 0 if dest
**    // uint32_t     srv_port  : 2; //        server port: 0=80; 1=443; 2=8080
**    // uint32_t     a_1_flags : 8; //        EXPANDED==0: TCP flags/All pkts
**                                   //        EXPANDED==1: TCP flags/1st pkt
**
**    uint16_t      clnt_port;       // 20-21  Non-Web Port
**
**    uint16_t      application;     // 22-23  Type of traffic
**
**    uint8_t       tcp_state;       // 24     TCP state machine info
**    uint8_t       rest_flags;      // 25     EXPANDED==0: Empty
**                                   //        EXPANDED==1: TCPflags/rest pkts
**
**
**  26 bytes on disk.
*/

#define RECLEN_RWAUGWEB_V1 26
#define RECLEN_RWAUGWEB_V2 26
#define RECLEN_RWAUGWEB_V3 26


/*
 *    Byte swap the RWAUGWEB v1 record 'ar' in place.
 */
#define augwebioRecordSwap_V1(ar)                               \
    {                                                           \
        SWAP_DATA32((ar) +  0);   /* sIP */                     \
        SWAP_DATA32((ar) +  4);   /* dIP */                     \
        SWAP_DATA32((ar) +  8);   /* pkts_stime */              \
        SWAP_DATA32((ar) + 12);   /* bbe */                     \
        SWAP_DATA32((ar) + 16);   /* msec_prt_flags */          \
        SWAP_DATA16((ar) + 20);   /* client port */             \
        SWAP_DATA16((ar) + 22);   /* application */             \
        /* Two single bytes: (24)tcp_state, (25)rest_flags */   \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
augwebioRecordUnpack_V1(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t msec_prt_flags;
    uint16_t clnt_port, srv_port;
    uint8_t src_is_server, a_1_flags;

    /* swap if required */
    if (stream->swapFlag) {
        augwebioRecordSwap_V1(ar);
    }

    /* sIP, dIP */
    rwRecMemSetSIPv4(rwrec, &ar[0]);
    rwRecMemSetDIPv4(rwrec, &ar[4]);

    /* fractional-times, server-port, flags */
    memcpy(&msec_prt_flags, &ar[16], 4);

    /* client (non-web) port */
    memcpy(&clnt_port, &ar[20], 2);

    /* application */
    rwRecMemSetApplication(rwrec, &ar[22]);

    /* msec_prt_flags: sTime_msec:10; elaps_msec:10; pflag:1;
     *                 srcIsSrv:1; srv_port:2; a_1_flags:8; */
    src_is_server = GET_MASKED_BITS(msec_prt_flags, 10, 1);
    srv_port = (uint16_t)GET_MASKED_BITS(msec_prt_flags, 8, 2);
    a_1_flags = (uint8_t)GET_MASKED_BITS(msec_prt_flags, 0, 8);

    /* unpack server port */
    srv_port = SK_WEBPORT_EXPAND(srv_port);

    /* set source and destination ports */
    if (src_is_server) {
        rwRecMemSetSPort(rwrec, &srv_port);
        rwRecMemSetDPort(rwrec, &clnt_port);
    } else {
        rwRecMemSetDPort(rwrec, &srv_port);
        rwRecMemSetSPort(rwrec, &clnt_port);
    }

    /* proto is fixed.  Must make certain this is set before
     * calling rwpackUnpackTimeBytesPktsFlags(). */
    rwRecSetProto(rwrec, IPPROTO_TCP);

    /* sTime, pkts, bytes, elapsed, proto, tcp-flags, bpp */
    rwpackUnpackTimeBytesPktsFlags(rwrec, stream->hdr_starttime,
                                   (uint32_t*)&ar[8], (uint32_t*)&ar[12],
                                   &msec_prt_flags);

    /* extra TCP information */
    rwpackUnpackProtoFlags(rwrec, 1, a_1_flags, ar[24], ar[25]);

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
augwebioRecordPack_V1(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */
    uint32_t msec_prt_flags;
    uint8_t is_tcp, a_1_flags;
    unsigned int src_is_server;

    /* verify protocol is TCP.  Should we also check that the port is
     * one of those we encode---i.e., should we do the entire
     * rwRecIsWeb() check here, or do we assume the caller knows what
     * they are doing in choosing this file type? */
    if (rwRecGetProto(rwrec) != IPPROTO_TCP) {
        return SKSTREAM_ERR_PROTO_MISMATCH;
    }

    /* sTime, pkts, bytes, elapsed, proto, tcp-flags, bpp */
    rv = rwpackPackTimeBytesPktsFlags((uint32_t*)&ar[8], (uint32_t*)&ar[12],
                                      &msec_prt_flags,
                                      rwrec, stream->hdr_starttime);
    if (rv) {
        return rv;
    }

    rwpackPackProtoFlags(&is_tcp, &a_1_flags, &ar[24], &ar[25], rwrec);

    /* Is the source port the server's port? */
    src_is_server = SK_WEBPORT_CHECK(rwRecGetSPort(rwrec));

    /* msec_prt_flags: sTime_msec:10; elaps_msec:10; pflag:1;
     *                 srcIsSrv:1; srv_port:2; a_1_flags:8; */
    /* overwrite the least significant 11 bits so that we get the
     * initial tcp flags if tcp_state!=0. */
    msec_prt_flags = ((msec_prt_flags & (MASKARRAY_21 << 11))
                      | ((src_is_server == 0) ? 0 : (1 << 10))
                      | (SK_WEBPORT_ENCODE(src_is_server
                                           ? rwRecGetSPort(rwrec)
                                           : rwRecGetDPort(rwrec)) << 8)
                      | a_1_flags);

    /* sIP, dIP */
    rwRecMemGetSIPv4(rwrec, &ar[0]);
    rwRecMemGetDIPv4(rwrec, &ar[4]);

    /* fractional-times, server-port, tcp-flags */
    memcpy(&ar[16], &msec_prt_flags, 4);

    /* client (non-web) port */
    if (src_is_server) {
        rwRecMemGetDPort(rwrec, &ar[20]);
    } else {
        rwRecMemGetSPort(rwrec, &ar[20]);
    }

    /* application */
    rwRecMemGetApplication(rwrec, &ar[22]);

    /* swap if required */
    if (stream->swapFlag) {
        augwebioRecordSwap_V1(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
 *  Return length of record of specified version, or 0 if no such
 *  version exists.  See skstream_priv.h for details.
 */
uint16_t
augwebioGetRecLen(
    sk_file_version_t   vers)
{
    switch (vers) {
      case 1:
        return RECLEN_RWAUGWEB_V1;
      case 2:
        return RECLEN_RWAUGWEB_V2;
      case 3:
        return RECLEN_RWAUGWEB_V3;
      case 4:
        return RECLEN_RWAUGWEB_V4;
      case 5:
        return RECLEN_RWAUGWEB_V5;
      default:
        return 0;
    }
}


/*
 *  status = augwebioPrepare(&stream);
 *
 *    Sets the record version to the default if it is unspecified,
 *    checks that the record format supports the requested record
 *    version, sets the record length, and sets the pack and unpack
 *    functions for this record format and version.
 */
int
augwebioPrepare(
    skstream_t         *stream)
{
#define FILE_FORMAT "FT_RWAUGWEB"
    sk_file_header_t *hdr = stream->silk_hdr;
    int rv = SKSTREAM_OK; /* return value */

    assert(skHeaderGetFileFormat(hdr) == FT_RWAUGWEB);

    /* Set version if none was selected by caller */
    if ((stream->io_mode == SK_IO_WRITE)
        && (skHeaderGetRecordVersion(hdr) == SK_RECORD_VERSION_ANY))
    {
        skHeaderSetRecordVersion(hdr, DEFAULT_RECORD_VERSION);
    }

    /* version check; set values based on version */
    switch (skHeaderGetRecordVersion(hdr)) {
      case 5:
        stream->rwUnpackFn = &augwebioRecordUnpack_V5;
        stream->rwPackFn   = &augwebioRecordPack_V5;
        break;
      case 4:
        stream->rwUnpackFn = &augwebioRecordUnpack_V4;
        stream->rwPackFn   = &augwebioRecordPack_V4;
        break;
      case 3:
      case 2:
      case 1:
        /* V1 and V2 differ only in the padding of the header */
        /* V2 and V3 differ only in that V3 supports compression on
         * read and write; V2 supports compression only on read */
        stream->rwUnpackFn = &augwebioRecordUnpack_V1;
        stream->rwPackFn   = &augwebioRecordPack_V1;
        break;
      case 0:
      default:
        rv = SKSTREAM_ERR_UNSUPPORT_VERSION;
        goto END;
    }

    stream->recLen = augwebioGetRecLen(skHeaderGetRecordVersion(hdr));

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
