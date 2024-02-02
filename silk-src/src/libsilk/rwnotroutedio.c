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
** rwnotroutedio.c
**
** Suresh L Konda
**      routines to do io stuff with notrouted records.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwnotroutedio.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

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
**  RWNOTROUTED VERSION 5
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
**                                   //        is_tcp==1: TCPflags/All pkts
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**    // uint32_t     is_tcp    : 1; //        1 if flow is TCP; 0 otherwise
**    // uint32_t     padding   : 2; //
**    // uint32_t     pkts      :20; //        Count of packets
**
**    uint16_t      sPort;           // 12-13  Source port
**    uint16_t      dPort;           // 14-15  Destination port
**
**    uint32_t      sIP;             // 16-19  Source IP
**    uint32_t      dIP;             // 20-23  Destination IP
**
**    uint16_t      input;           // 24-25  Router incoming SNMP interface
**
**
**  26 bytes on disk.
*/

#define RECLEN_RWNOTROUTED_V5 26


/*
 *    Byte swap the RWNOTROUTED v5 record 'ar' in place.
 */
#define notroutedioRecordSwap_V5(ar)                    \
    {                                                   \
        SWAP_DATA32((ar) +  0);   /* stime_bb1 */       \
        SWAP_DATA32((ar) +  4);   /* bb2_elapsed */     \
        SWAP_DATA32((ar) +  8);   /* pro_flg_pkts */    \
        SWAP_DATA16((ar) + 12);   /* sPort */           \
        SWAP_DATA16((ar) + 14);   /* dPort */           \
        SWAP_DATA32((ar) + 16);   /* sIP */             \
        SWAP_DATA32((ar) + 20);   /* dIP */             \
        SWAP_DATA16((ar) + 24);   /* input */           \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
notroutedioRecordUnpack_V5(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    /* swap if required */
    if (stream->swapFlag) {
        notroutedioRecordSwap_V5(ar);
    }

    /* sTime, elapsed, pkts, bytes, proto, tcp-flags */
    rwpackUnpackFlagsTimesVolumes(rwrec, ar, stream->hdr_starttime, 12, 0);

    /* sPort, dPort */
    rwRecMemSetSPort(rwrec, &ar[12]);
    rwRecMemSetDPort(rwrec, &ar[14]);

    /*, sIP, dIP */
    rwRecMemSetSIPv4(rwrec, &ar[16]);
    rwRecMemSetDIPv4(rwrec, &ar[20]);

    /* input */
    rwRecMemSetInput(rwrec, &ar[24]);

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
notroutedioRecordPack_V5(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */

    /* sTime, elapsed, pkts, bytes, proto, tcp-flags */
    rv = rwpackPackFlagsTimesVolumes(ar, rwrec, stream->hdr_starttime, 12);
    if (rv) {
        return rv;
    }

    /* sPort, dPort */
    rwRecMemGetSPort(rwrec, &ar[12]);
    rwRecMemGetDPort(rwrec, &ar[14]);

    /* sIP, dIP */
    rwRecMemGetSIPv4(rwrec, &ar[16]);
    rwRecMemGetDIPv4(rwrec, &ar[20]);

    /* input */
    rwRecMemGetInput(rwrec, &ar[24]);

    /* swap if required */
    if (stream->swapFlag) {
        notroutedioRecordSwap_V5(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWNOTROUTED VERSION 3
**  RWNOTROUTED VERSION 4
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
**                                   //        is_tcp==1: TCP flags
**
**    uint16_t      input;           // 24-25  Router incoming SNMP interface
**
**
**  26 bytes on disk.
*/

#define RECLEN_RWNOTROUTED_V3 26
#define RECLEN_RWNOTROUTED_V4 26


/*
 *    Byte swap the RWNOTROUTED v3 record 'ar' in place.
 */
#define notroutedioRecordSwap_V3(ar)                    \
    {                                                   \
        SWAP_DATA32((ar) +  0);   /* sIP */             \
        SWAP_DATA32((ar) +  4);   /* dIP */             \
        SWAP_DATA16((ar) +  8);   /* sPort */           \
        SWAP_DATA16((ar) + 10);   /* dPort */           \
        SWAP_DATA32((ar) + 12);   /* pkts_stime */      \
        SWAP_DATA32((ar) + 16);   /* bbe */             \
        SWAP_DATA32((ar) + 20);   /* msec_flags */      \
        SWAP_DATA16((ar) + 24);   /* input */           \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
notroutedioRecordUnpack_V3(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    /* swap if required */
    if (stream->swapFlag) {
        notroutedioRecordSwap_V3(ar);
    }

    /* sIP, dIP, sPort, dPort */
    rwRecMemSetSIPv4(rwrec, &ar[0]);
    rwRecMemSetDIPv4(rwrec, &ar[4]);
    rwRecMemSetSPort(rwrec, &ar[8]);
    rwRecMemSetDPort(rwrec, &ar[10]);

    /* input interface */
    rwRecMemSetInput(rwrec, &ar[24]);

    /* sTime, pkts, bytes, elapsed, proto, tcp-flags, bpp */
    rwpackUnpackTimeBytesPktsFlags(rwrec, stream->hdr_starttime,
                                   (uint32_t*)&ar[12], (uint32_t*)&ar[16],
                                   (uint32_t*)&ar[20]);

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
notroutedioRecordPack_V3(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */

    /* sTime, pkts, bytes, elapsed, proto, tcp-flags, bpp */
    rv = rwpackPackTimeBytesPktsFlags((uint32_t*)&ar[12], (uint32_t*)&ar[16],
                                      (uint32_t*)&ar[20],
                                      rwrec, stream->hdr_starttime);
    if (rv) {
        return rv;
    }

    /* sIP, dIP, sPort, dPort */
    rwRecMemGetSIPv4(rwrec, &ar[0]);
    rwRecMemGetDIPv4(rwrec, &ar[4]);
    rwRecMemGetSPort(rwrec, &ar[8]);
    rwRecMemGetDPort(rwrec, &ar[10]);

    /* input interfaces */
    rwRecMemGetInput(rwrec, &ar[24]);

    /* swap if required */
    if (stream->swapFlag) {
        notroutedioRecordSwap_V3(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWNOTROUTED VERSION 1
**  RWNOTROUTED VERSION 2
**
**    uint32_t      sIP;             //  0- 3  Source IP
**    uint32_t      dIP;             //  4- 7  Destination IP
**
**    uint16_t      sPort;           //  8- 9  Source port
**    uint16_t      dPort;           // 10-11  Destination port
**
**    uint32_t      pef;             // 12-15
**    // uint32_t     pkts      :20; //        Count of packets
**    // uint32_t     elapsed   :11; //        Duration of flow
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**
**    uint32_t      sbb;             // 16-19
**    // uint32_t     sTime     :12; //        Start time--offset from hour
**    // uint32_t     bPPkt     :14; //        Whole bytes-per-packet
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**
**    uint8_t       proto;           // 20     IP protocol
**    uint8_t       flags;           // 21     OR of all TCP flags on all pkts
**    uint8_t       input;           // 22     Router incoming SNMP interface
**
**
**  23 bytes on disk.
*/

#define RECLEN_RWNOTROUTED_V1 23
#define RECLEN_RWNOTROUTED_V2 23


/*
 *    Byte swap the RWNOTROUTED v1 record 'ar' in place.
 */
#define notroutedioRecordSwap_V1(ar)                                    \
    {                                                                   \
        SWAP_DATA32((ar) +  0);   /* sIP */                             \
        SWAP_DATA32((ar) +  4);   /* dIP */                             \
        SWAP_DATA16((ar) +  8);   /* sPort */                           \
        SWAP_DATA16((ar) + 10);   /* dPort */                           \
        SWAP_DATA32((ar) + 12);   /* pef */                             \
        SWAP_DATA32((ar) + 16);   /* sbb */                             \
        /* Three single bytes: (20)proto, (21)flags, (22)input */       \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
notroutedioRecordUnpack_V1(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    /* swap if required */
    if (stream->swapFlag) {
        notroutedioRecordSwap_V1(ar);
    }

    /* sIP, dIP, sPort, dPort */
    rwRecMemSetSIPv4(rwrec, &ar[0]);
    rwRecMemSetDIPv4(rwrec, &ar[4]);
    rwRecMemSetSPort(rwrec, &ar[8]);
    rwRecMemSetDPort(rwrec, &ar[10]);

    /* pkts, elapsed, sTime, bytes, bpp */
    rwpackUnpackSbbPef(rwrec, stream->hdr_starttime,
                       (uint32_t*)&ar[16], (uint32_t*)&ar[12]);

    /* proto, flags, input interface */
    rwRecSetProto(rwrec, ar[20]);
    rwRecSetFlags(rwrec, ar[21]);
    rwRecSetInput(rwrec, ar[22]);

    /* sensor, flow_type from file name/header */
    rwRecSetSensor(rwrec, stream->hdr_sensor);
    rwRecSetFlowType(rwrec, stream->hdr_flowtype);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
notroutedioRecordPack_V1(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */

    /* Check sizes of fields we've expanded in later versions */
    if (rwRecGetInput(rwrec) > 255) {
        return SKSTREAM_ERR_SNMP_OVRFLO;
    }

    /* pkts, elapsed, sTime, bytes, bpp */
    rv = rwpackPackSbbPef((uint32_t*)&ar[16], (uint32_t*)&ar[12],
                          rwrec, stream->hdr_starttime);
    if (rv) {
        return rv;
    }

    /* sIP, dIP, sPort, dPort */
    rwRecMemGetSIPv4(rwrec, &ar[0]);
    rwRecMemGetDIPv4(rwrec, &ar[4]);
    rwRecMemGetSPort(rwrec, &ar[8]);
    rwRecMemGetDPort(rwrec, &ar[10]);

    /* proto, flags, input interface */
    ar[20] = rwRecGetProto(rwrec);
    ar[21] = rwRecGetFlags(rwrec);
    ar[22] = (uint8_t)rwRecGetInput(rwrec);

    /* swap if required */
    if (stream->swapFlag) {
        notroutedioRecordSwap_V1(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
 *  Return length of record of specified version, or 0 if no such
 *  version exists.  See skstream_priv.h for details.
 */
uint16_t
notroutedioGetRecLen(
    sk_file_version_t   vers)
{
    switch (vers) {
      case 1:
        return RECLEN_RWNOTROUTED_V1;
      case 2:
        return RECLEN_RWNOTROUTED_V2;
      case 3:
        return RECLEN_RWNOTROUTED_V3;
      case 4:
        return RECLEN_RWNOTROUTED_V4;
      case 5:
        return RECLEN_RWNOTROUTED_V5;
      default:
        return 0;
    }
}


/*
 *  status = notroutedioPrepare(&stream);
 *
 *    Sets the record version to the default if it is unspecified,
 *    checks that the record format supports the requested record
 *    version, sets the record length, and sets the pack and unpack
 *    functions for this record format and version.
 */
int
notroutedioPrepare(
    skstream_t         *stream)
{
#define FILE_FORMAT "FT_RWNOTROUTED"
    sk_file_header_t *hdr = stream->silk_hdr;
    int rv = SKSTREAM_OK; /* return value */

    assert(skHeaderGetFileFormat(hdr) == FT_RWNOTROUTED);

    /* Set version if none was selected by caller */
    if ((stream->io_mode == SK_IO_WRITE)
        && (skHeaderGetRecordVersion(hdr) == SK_RECORD_VERSION_ANY))
    {
        skHeaderSetRecordVersion(hdr, DEFAULT_RECORD_VERSION);
    }

    /* version check; set values based on version */
    switch (skHeaderGetRecordVersion(hdr)) {
      case 5:
        stream->rwUnpackFn = &notroutedioRecordUnpack_V5;
        stream->rwPackFn   = &notroutedioRecordPack_V5;
        break;
      case 4:
      case 3:
        /* V3 and V4 differ only in that V4 supports compression on
         * read and write; V3 supports compression only on read */
        stream->rwUnpackFn = &notroutedioRecordUnpack_V3;
        stream->rwPackFn   = &notroutedioRecordPack_V3;
        break;
      case 2:
      case 1:
        /* V1 and V2 differ only in the padding of the header */
        stream->rwUnpackFn = &notroutedioRecordUnpack_V1;
        stream->rwPackFn   = &notroutedioRecordPack_V1;
        break;
      case 0:
      default:
        rv = SKSTREAM_ERR_UNSUPPORT_VERSION;
        goto END;
    }

    stream->recLen = notroutedioGetRecLen(skHeaderGetRecordVersion(hdr));

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
