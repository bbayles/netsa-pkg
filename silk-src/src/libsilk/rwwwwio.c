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
** rwwwwio.c
**
**      routines to do io stuff with web records.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwwwwio.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/* #define RWPACK_BYTES_PACKETS          1 */
#define RWPACK_FLAGS_TIMES_VOLUMES    1
/* #define RWPACK_PROTO_FLAGS            1 */
#define RWPACK_SBB_PEF                1
#define RWPACK_TIME_BYTES_PKTS_FLAGS  1
/* #define RWPACK_TIMES_FLAGS_PROTO      1 */
#include "skstream_priv.h"
#include "rwpack.c"


/* Version to use when SK_RECORD_VERSION_ANY is specified */
#define DEFAULT_RECORD_VERSION 5


/* ********************************************************************* */

/*
**  RWWWW VERSION 5
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
**    // uint32_t     flags     : 8; //        TCPflags/All pkts
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**    // uint32_t     src_is_srv: 1; //        1 if sIP is http server
**    // uint32_t     srv_port  : 2; //        server port: 0=80; 1=443; 2=8080
**    // uint32_t     pkts      :20; //        Count of packets
**
**    uint32_t      sIP;             // 12-15  Source IP
**    uint32_t      dIP;             // 16-19  Destination IP
**
**    uint16_t      clnt_port;       // 20-21  Client(non-server) port
**
**
**  22 bytes on disk.
*/

#define RECLEN_RWWWW_V5 22


/*
 *    Byte swap the RWWWW v5 record 'ar' in place.
 */
#define wwwioRecordSwap_V5(ar)                          \
    {                                                   \
        SWAP_DATA32((ar) +  0);   /* stime_bb1 */       \
        SWAP_DATA32((ar) +  4);   /* bb2_elapsed */     \
        SWAP_DATA32((ar) +  8);   /* srv_flg_pkts */    \
        SWAP_DATA32((ar) + 12);   /* sIP */             \
        SWAP_DATA32((ar) + 16);   /* dIP */             \
        SWAP_DATA16((ar) + 20);   /* client port */     \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
wwwioRecordUnpack_V5(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t srv_flg_pkts;
    uint32_t srv_port;

    /* swap if required */
    if (stream->swapFlag) {
        wwwioRecordSwap_V5(ar);
    }

    /* sTime, elapsed, pkts, bytes, proto, tcp-flags */
    rwpackUnpackFlagsTimesVolumes(rwrec, ar, stream->hdr_starttime, 12, 1);

    /* sIP, dIP */
    rwRecMemSetSIPv4(rwrec, &ar[12]);
    rwRecMemSetDIPv4(rwrec, &ar[16]);

    /* get the encoded server-side port */
    memcpy(&srv_flg_pkts, &ar[8], sizeof(srv_flg_pkts));
    srv_port = GET_MASKED_BITS(srv_flg_pkts, 20, 2);

    /* set the ports based on who was the server */
    if (GET_MASKED_BITS(srv_flg_pkts, 22, 1)) {
        /* source IP/Port is server; dest is client */
        rwRecSetSPort(rwrec, SK_WEBPORT_EXPAND(srv_port));
        rwRecMemSetDPort(rwrec, &ar[20]);
    } else {
        /* dest IP/Port is server; source is client */
        rwRecMemSetSPort(rwrec, &ar[20]);
        rwRecSetDPort(rwrec, SK_WEBPORT_EXPAND(srv_port));
    }

    /* sensor, flow_type from file header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
wwwioRecordPack_V5(
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

    /* sTime, elapsed, pkts, bytes, proto, tcp-flags */
    rv = rwpackPackFlagsTimesVolumes(ar, rwrec, stream->hdr_starttime, 12);
    if (rv) {
        return rv;
    }

    /* sIP, dIP */
    rwRecMemGetSIPv4(rwrec, &ar[12]);
    rwRecMemGetDIPv4(rwrec, &ar[16]);

    /* pack the client-side port */
    srv_port = rwRecGetSPort(rwrec);
    src_is_srv = SK_WEBPORT_CHECK(srv_port);
    if (src_is_srv) {
        /* source is server; put dPort into clnt_port */
        rwRecMemGetDPort(rwrec, &ar[20]);
    } else {
        /* destination is server; put sPort into clnt_port; get dPort
         * as srv_port */
        memcpy(&ar[20], &srv_port, sizeof(srv_port));
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
        wwwioRecordSwap_V5(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWWWW VERSION 3
**  RWWWW VERSION 4
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
**    // uint32_t     flags;    : 8; //        TCP flags
**
**    uint16_t      clnt_port;       // 20-21  Non-Web Port
**
**
**  22 bytes on disk.
*/

#define RECLEN_RWWWW_V3 22
#define RECLEN_RWWWW_V4 22


/*
 *    Byte swap the RWWWW v3 record 'ar' in place.
 */
#define wwwioRecordSwap_V3(ar)                          \
    {                                                   \
        SWAP_DATA32((ar) +  0);   /* sIP */             \
        SWAP_DATA32((ar) +  4);   /* dIP */             \
        SWAP_DATA32((ar) +  8);   /* pkts_stime */      \
        SWAP_DATA32((ar) + 12);   /* bbe */             \
        SWAP_DATA32((ar) + 16);   /* msec_prt_flags */  \
        SWAP_DATA16((ar) + 20);   /* client port */     \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
wwwioRecordUnpack_V3(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t msec_prt_flags;
    uint16_t clnt_port, srv_port;
    uint8_t src_is_server;

    /* swap if required */
    if (stream->swapFlag) {
        wwwioRecordSwap_V3(ar);
    }

    /* sIP, dIP */
    rwRecMemSetSIPv4(rwrec, &ar[0]);
    rwRecMemSetDIPv4(rwrec, &ar[4]);

    /* fractional-times, server-port, flags */
    memcpy(&msec_prt_flags, &ar[16], 4);

    /* msec_prt_flags: sTime_msec:10; elaps_msec:10; pflag:1;
     *                 srcIsSrv:1; srv_port:2; prot_flags:8; */
    src_is_server = GET_MASKED_BITS(msec_prt_flags, 10, 1);
    srv_port = (uint16_t)GET_MASKED_BITS(msec_prt_flags, 8, 2);

    /* unpack server port */
    srv_port = SK_WEBPORT_EXPAND(srv_port);

    /* client (non-web) port */
    memcpy(&clnt_port, &ar[20], 2);

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

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
wwwioRecordPack_V3(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */
    uint32_t msec_prt_flags;
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

    /* Is the source port the server's port? */
    src_is_server = SK_WEBPORT_CHECK(rwRecGetSPort(rwrec));

    /* msec_prt_flags: sTime_msec:10; elaps_msec:10; pflag:1;
     *                 srcIsSrv:1; srv_port:2; prot_flags:8;
     *
     * Add our bits to msec_prt_flags, but make certain that the
     * values this function expects to be zero really are zero. */
    msec_prt_flags = ((msec_prt_flags & (~(MASKARRAY_03 << 8)))
                      | ((src_is_server == 0) ? 0 : (1 << 10))
                      | (SK_WEBPORT_ENCODE(src_is_server
                                           ? rwRecGetSPort(rwrec)
                                           : rwRecGetDPort(rwrec)) << 8));

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

    /* swap if required */
    if (stream->swapFlag) {
        wwwioRecordSwap_V3(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWWWW VERSION 1
**  RWWWW VERSION 2
**
**    uint32_t      sIP;             //  0- 3  Source IP
**    uint32_t      dIP;             //  4- 7  Destination IP
**
**    uint32_t      pef;             //  8-11
**    // uint32_t     pkts      :20; //        Count of packets
**    // uint32_t     elapsed   :11; //        Duration of flow
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**
**    uint32_t      sbb;             // 12-15
**    // uint32_t     sTime     :12; //        Start time--offset from hour
**    // uint32_t     bPPkt     :14; //        Whole bytes-per-packet
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**
**    uint16_t      clnt_port;       // 16-17  Non-Web Port
**
**    uint8_t       wrf;             // 18
**    // uint8_t      srcIsSrv  : 1; //        1 if srvPort is src; 0 if dest
**    // uint8_t      pad       : 1; //        padding/reserved
**    // uint8_t      flags     : 6; //        OR of all TCP flags on all pkts
**
**    uint8_t       wPort;           // 19
**    // uint8_t      srvPort   : 2; //        server port: 0=80; 1=443; 2=8080
**    // uint8_t      pad       : 6; //        padding/reserved
**
**
**  20 bytes on disk.
*/

#define RECLEN_RWWWW_V1 20
#define RECLEN_RWWWW_V2 20


/*
 *    Byte swap the RWWWW v{1,2} record 'ar' in place.
 */
#define wwwioRecordSwap_V1(ar)                          \
    {                                                   \
        SWAP_DATA32((ar) +  0);   /* sIP */             \
        SWAP_DATA32((ar) +  4);   /* dIP */             \
        SWAP_DATA32((ar) +  8);   /* pef */             \
        SWAP_DATA32((ar) + 12);   /* sbb */             \
        SWAP_DATA16((ar) + 16);   /* non-web port */    \
        /* Two single bytes: (18)wrf (19)webPort */     \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
wwwioRecordUnpack_V1(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint16_t clnt_port, srv_port;
    int src_is_server;

    /* swap if required */
    if (stream->swapFlag) {
        wwwioRecordSwap_V1(ar);
    }

    /* sIP, dIP */
    rwRecMemSetSIPv4(rwrec, &ar[0]);
    rwRecMemSetDIPv4(rwrec, &ar[4]);

    /* pkts, elapsed, sTime, bytes, bpp */
    rwpackUnpackSbbPef(rwrec, stream->hdr_starttime,
                       (uint32_t*)&ar[12], (uint32_t*)&ar[8]);

    /* client (non-web) port */
    memcpy(&clnt_port, &ar[16], 2);

    /* which side is the server?  flags */
    src_is_server = ar[18] & 0x80;
    rwRecSetFlags(rwrec, (uint8_t)(ar[18] & MASKARRAY_06));

    /* server (web) port */
    srv_port = (ar[19] >> 6) & MASKARRAY_02;
    srv_port = SK_WEBPORT_EXPAND(srv_port);

    if (src_is_server) {
        rwRecMemSetSPort(rwrec, &srv_port);
        rwRecMemSetDPort(rwrec, &clnt_port);
    } else {
        rwRecMemSetDPort(rwrec, &srv_port);
        rwRecMemSetSPort(rwrec, &clnt_port);
    }

    /* proto is fixed */
    rwRecSetProto(rwrec, IPPROTO_TCP);

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
wwwioRecordPack_V1(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */
    int src_is_server;

    /* Check sizes of fields we've expanded in later versions */
    /* Nothing to check for rwwww */

    /* verify protocol is TCP.  Should we also check that the port is
     * one of those we encode---i.e., should we do the entire
     * rwRecIsWeb() check here, or do we assume the caller knows what
     * they are doing in choosing this file type? */
    if (rwRecGetProto(rwrec) != IPPROTO_TCP) {
        return SKSTREAM_ERR_PROTO_MISMATCH;
    }

    /* pkts, elapsed, sTime, bytes, bpp */
    rv = rwpackPackSbbPef((uint32_t*)&ar[12], (uint32_t*)&ar[8],
                          rwrec, stream->hdr_starttime);
    if (rv) {
        return rv;
    }

    /* sIP, dIP */
    rwRecMemGetSIPv4(rwrec, &ar[0]);
    rwRecMemGetDIPv4(rwrec, &ar[4]);

    /* client (non-web) port */
    src_is_server = SK_WEBPORT_CHECK(rwRecGetSPort(rwrec));
    if (src_is_server) {
        rwRecMemGetDPort(rwrec, &ar[16]);
    } else {
        rwRecMemGetSPort(rwrec, &ar[16]);
    }

    /* rwf: uint8_t wsPort:1; uint8_t reserved:1; uint8_t flags:6 */
    ar[18] = (uint8_t)((src_is_server ? 0x80 : 0)
                       | (rwRecGetFlags(rwrec) & MASKARRAY_06));

    /* server port */
    ar[19] = (uint8_t)(SK_WEBPORT_ENCODE(src_is_server
                                         ? rwRecGetSPort(rwrec)
                                         : rwRecGetDPort(rwrec)) << 6);

    /* swap if required */
    if (stream->swapFlag) {
        wwwioRecordSwap_V1(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
 *  Return length of record of specified version, or 0 if no such
 *  version exists.  See skstream_priv.h for details.
 */
uint16_t
wwwioGetRecLen(
    sk_file_version_t   vers)
{
    switch (vers) {
      case 1:
        return RECLEN_RWWWW_V1;
      case 2:
        return RECLEN_RWWWW_V2;
      case 3:
        return RECLEN_RWWWW_V3;
      case 4:
        return RECLEN_RWWWW_V4;
      case 5:
        return RECLEN_RWWWW_V5;
      default:
        return 0;
    }
}


/*
 *  status = wwwioPrepare(&stream);
 *
 *    Sets the record version to the default if it is unspecified,
 *    checks that the record format supports the requested record
 *    version, sets the record length, and sets the pack and unpack
 *    functions for this record format and version.
 */
int
wwwioPrepare(
    skstream_t         *stream)
{
#define FILE_FORMAT "FT_RWWWW"
    sk_file_header_t *hdr = stream->silk_hdr;
    int rv = SKSTREAM_OK; /* return value */

    assert(skHeaderGetFileFormat(hdr) == FT_RWWWW);

    /* Set version if none was selected by caller */
    if ((stream->io_mode == SK_IO_WRITE)
        && (skHeaderGetRecordVersion(hdr) == SK_RECORD_VERSION_ANY))
    {
        skHeaderSetRecordVersion(hdr, DEFAULT_RECORD_VERSION);
    }

    /* version check; set values based on version */
    switch (skHeaderGetRecordVersion(hdr)) {
      case 5:
        stream->rwUnpackFn = &wwwioRecordUnpack_V5;
        stream->rwPackFn   = &wwwioRecordPack_V5;
        break;
      case 4:
      case 3:
        /* V3 and V4 differ only in that V4 supports compression on
         * read and write; V3 supports compression only on read */
        stream->rwUnpackFn = &wwwioRecordUnpack_V3;
        stream->rwPackFn   = &wwwioRecordPack_V3;
        break;
      case 2:
      case 1:
        /* V1 and V2 differ only in the padding of the header */
        stream->rwUnpackFn = &wwwioRecordUnpack_V1;
        stream->rwPackFn   = &wwwioRecordPack_V1;
        break;
      case 0:
      default:
        rv = SKSTREAM_ERR_UNSUPPORT_VERSION;
        goto END;
    }

    stream->recLen = wwwioGetRecLen(skHeaderGetRecordVersion(hdr));

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
