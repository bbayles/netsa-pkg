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
** rwfilterio.c
**
** Suresh L Konda
**      routines to do io stuff with filter records.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwfilterio.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#define RWPACK_BYTES_PACKETS          1
/* #define RWPACK_FLAGS_TIMES_VOLUMES    1 */
#define RWPACK_PROTO_FLAGS            1
/* #define RWPACK_SBB_PEF                1 */
/* #define RWPACK_TIME_BYTES_PKTS_FLAGS  1 */
/* #define RWPACK_TIMES_FLAGS_PROTO      1 */
#include "skstream_priv.h"
#include "rwpack.c"


/* Version to use when SK_RECORD_VERSION_ANY is specified */
#define DEFAULT_RECORD_VERSION 5


/* ********************************************************************* */

/*
**  RWFILTER VERSION 4
**  RWFILTER VERSION 5
**
**  in the following: EXPANDED == ((tcp_state & SK_TCPSTATE_EXPANDED) ? 1 : 0)
**
**    uint32_t      sIP;             //  0- 3  Source IP
**    uint32_t      dIP;             //  4- 7  Destination IP
**
**    uint16_t      sPort;           //  8- 9  Source port
**    uint16_t      dPort;           // 10-11  Destination port
**
**    uint32_t      nhIP;            // 12-15  Router Next Hop IP
**    uint16_t      input;           // 16-17  Router incoming SNMP interface
**    uint16_t      output;          // 18-19  Router outgoing SNMP interface
**
**    uint32_t      sTime;           // 20-23  Start time of flow-epoch secs
**    uint32_t      elapsed;         // 24-27  Duration of flow
**
**    uint32_t      pkts_stimems;    // 28-31
**    // uint32_t     pkts      :20; //        Count of packets
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**    // uint32_t     is_tcp    : 1; //        1 if flow is TCP; 0 otherwise
**    // uint32_t     sTime_msec:10; //        Fractional sTime (millisec)
**
**    uint32_t      bb_elapsems;      // 32-35
**    // uint32_t     bPPkt     :14; //        Whole bytes-per-packet
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**    // uint32_t     padding   : 2; //        padding/reserved
**    // uint32_t     elaps_msec:10; //        Fractional elapsed (millisec)
**
**    uint16_t      sID;             // 36-37  Sensor ID
**
**    uint8_t       flowtype;        // 38     flow type (class&type)
**    uint8_t       prot_flags;      // 39     is_tcp==0: IP protocol
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:TCPflags/all pkts
**                                   //          EXPANDED==1:TCPflags/1st pkt
**
**    uint16_t      application;     // 40-41  Generator of traffic
**
**    uint8_t       tcp_state;       // 42     TCP state machine info
**    uint8_t       rest_flags;      // 43     is_tcp==0: Flow's reported flags
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:Empty
**                                   //          EXPANDED==1:TCPflags/!1st pkt
**
**
**  44 bytes on disk.
*/

#define RECLEN_RWFILTER_V4  44
#define RECLEN_RWFILTER_V5  44


/*
 *    Byte swap the RWFILTER v4 record 'ar' in place.
 */
#define filterioRecordSwap_V4(ar)                               \
    {                                                           \
        SWAP_DATA32((ar) +  0);   /* sIP */                     \
        SWAP_DATA32((ar) +  4);   /* dIP */                     \
        SWAP_DATA16((ar) +  8);   /* sPort */                   \
        SWAP_DATA16((ar) + 10);   /* dPort */                   \
        SWAP_DATA32((ar) + 12);   /* nhIP */                    \
        SWAP_DATA16((ar) + 16);   /* input */                   \
        SWAP_DATA16((ar) + 18);   /* output */                  \
        SWAP_DATA32((ar) + 20);   /* sTime */                   \
        SWAP_DATA32((ar) + 24);   /* elapsed */                 \
        SWAP_DATA32((ar) + 28);   /* pkts_stimems */            \
        SWAP_DATA32((ar) + 32);   /* bb_elapsems */             \
        SWAP_DATA16((ar) + 36);   /* sID */                     \
        /* Two single bytes: (38)flowtype, (39)prot_flags */    \
        SWAP_DATA16((ar) + 40);   /* application */             \
        /* Two single bytes: (42)tcp_state, (43)rest_flags */   \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
filterioRecordUnpack_V4(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t pkts_stimems, bb_elapsems;
    uint32_t pkts, bpp, pflag;
    uint32_t sTime, elapsed;
    uint8_t is_tcp;

    /* swap if required */
    if (stream->swapFlag) {
        filterioRecordSwap_V4(ar);
    }

    /* sIP, dIP, sPort, dPort, nhIP, input, output */
    rwRecMemSetSIPv4(rwrec, &ar[0]);
    rwRecMemSetDIPv4(rwrec, &ar[4]);
    rwRecMemSetSPort(rwrec, &ar[8]);
    rwRecMemSetDPort(rwrec, &ar[10]);
    rwRecMemSetNhIPv4(rwrec, &ar[12]);
    rwRecMemSetInput(rwrec, &ar[16]);
    rwRecMemSetOutput(rwrec, &ar[18]);

    /* sTime, elapsed */
    memcpy(&sTime, &ar[20], 4);
    memcpy(&elapsed, &ar[24], 4);

    /* pkts_stimems, bb_elapsems, sensorID */
    memcpy(&pkts_stimems, &ar[28],  4);
    memcpy(&bb_elapsems, &ar[32],  4);
    rwRecMemSetSensor(rwrec, &ar[36]);

    /* flow type, application */
    rwRecSetFlowType(rwrec, ar[38]);
    rwRecMemSetApplication(rwrec, &ar[40]);

    /* unpack 'pkts_stimems': pkts:20; pflag:1; pad:1; sTime_msec:10; */
    pkts = GET_MASKED_BITS(pkts_stimems, 12, 20);
    pflag = GET_MASKED_BITS(pkts_stimems, 11, 1);
    is_tcp = (uint8_t)GET_MASKED_BITS(pkts_stimems, 10, 1);

    rwRecSetStartTime(rwrec,sktimeCreate(sTime,
                                         GET_MASKED_BITS(pkts_stimems, 0, 10)));

    /* protocol, tcp-flags */
    rwpackUnpackProtoFlags(rwrec, is_tcp, ar[39], ar[42], ar[43]);

    /* unpack 'bb_elapsems': bpp:20 (bPPkt:14; bPPFrac:6); pad:2;
     * elapsed_msec:10; */
    bpp = GET_MASKED_BITS(bb_elapsems, 12, 20);

    rwRecSetElapsed(rwrec, (1000 * elapsed
                            + GET_MASKED_BITS(bb_elapsems, 0, 10)));

    /* pkts, bytes, bpp */
    rwpackUnpackBytesPackets(rwrec, bpp, pkts, pflag);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
filterioRecordPack_V4(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */
    uint32_t pkts_stimems, bb_elapsems;
    uint32_t pflag = 0;
    uint8_t is_tcp;

    rv = rwpackPackBytesPackets(&bb_elapsems, &pkts_stimems, &pflag, rwrec);
    if (rv) {
        return rv;
    }

    /* protocol, tcp-flags */
    rwpackPackProtoFlags(&is_tcp, &ar[39], &ar[42], &ar[43], rwrec);

    /* pkts_stimems has 'pkts' in the least significant bits---move it
     * over and insert the remaining values. */
    /* pkts_stimems: pkts:20, pflag:1; is_tcp:1; sTime_msec:10 */
    pkts_stimems = ((pkts_stimems << 12)
                    | ((pflag == 0) ? 0 : (1 << 11))
                    | ((is_tcp == 0) ? 0 : (1 << 10))
                    | (rwRecGetStartMSec(rwrec) & MASKARRAY_10));

    /* bb_elapsems has 'bpp' in the least significant bits; move it
     * over and add elapsed_msec */
    bb_elapsems = ((bb_elapsems << 12)
                   | (rwRecGetElapsedMSec(rwrec) & MASKARRAY_10));

    /* sIP, dIP, sPort, dPort, nhIP, input, output, sTime */
    rwRecMemGetSIPv4(rwrec, &ar[0]);
    rwRecMemGetDIPv4(rwrec, &ar[4]);
    rwRecMemGetSPort(rwrec, &ar[8]);
    rwRecMemGetDPort(rwrec, &ar[10]);
    rwRecMemGetNhIPv4(rwrec, &ar[12]);
    rwRecMemGetInput(rwrec, &ar[16]);
    rwRecMemGetOutput(rwrec, &ar[18]);
    rwRecMemGetStartSeconds(rwrec, &ar[20]);
    rwRecMemGetElapsedSeconds(rwrec, &ar[24]);

    /* pkts_stimems, bb_elapsems, sID, flow-type, application */
    memcpy(&ar[28], &pkts_stimems, 4);
    memcpy(&ar[32], &bb_elapsems, 4);
    rwRecMemGetSensor(rwrec, &ar[36]);

    /* flow type, application */
    ar[38] = rwRecGetFlowType(rwrec);
    rwRecMemGetApplication(rwrec, &ar[40]);

    /* swap if required */
    if (stream->swapFlag) {
        filterioRecordSwap_V4(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWFILTER VERSION 3
**
**    uint32_t      sIP;             //  0- 3  Source IP
**    uint32_t      dIP;             //  4- 7  Destination IP
**
**    uint16_t      sPort;           //  8- 9  Source port
**    uint16_t      dPort;           // 10-11  Destination port
**
**    uint32_t      nhIP;            // 12-15  Router Next Hop IP
**    uint16_t      input;           // 16-17  Router incoming SNMP interface
**    uint16_t      output;          // 18-19  Router outgoing SNMP interface
**
**    uint32_t      sTime;           // 20-23  Start time of flow-epoch secs
**    uint32_t      elapsed;         // 24-27  Duration of flow
**
**    uint32_t      pkts_ftype       // 28-31
**    // uint32_t     pkts      :20; //        Count of packets
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**    // uint32_t     pad       : 3; //        padding/reserved
**    // uint32_t     flowtype  : 8; //        flow type (class&type)
**
**    uint32_t      bpp;             // 32-35
**    // uint32_t     bPPkt     :14; //        Whole bytes-per-packet
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**    // uint32_t     pad       :12; //        padding/reserved
**
**    uint16_t      sID;             // 36-37  Sensor ID
**
**    uint8_t       proto;           // 38     IP protocol
**    uint8_t       flags;           // 39     OR of all TCP flags on all pkts
**
**
**  40 bytes on disk.
*/

#define RECLEN_RWFILTER_V3  40


/*
 *    Byte swap the RWFILTER v3 record 'ar' in place.
 */
#define filterioRecordSwap_V3(ar)                       \
    {                                                   \
        SWAP_DATA32((ar) +  0);   /* sIP */             \
        SWAP_DATA32((ar) +  4);   /* dIP */             \
        SWAP_DATA16((ar) +  8);   /* sPort */           \
        SWAP_DATA16((ar) + 10);   /* dPort */           \
        SWAP_DATA32((ar) + 12);   /* nhIP */            \
        SWAP_DATA16((ar) + 16);   /* input */           \
        SWAP_DATA16((ar) + 18);   /* output */          \
        SWAP_DATA32((ar) + 20);   /* sTime */           \
        SWAP_DATA32((ar) + 24);   /* elapsed */         \
        SWAP_DATA32((ar) + 28);   /* pkts_ftype */      \
        SWAP_DATA32((ar) + 32);   /* bpp */             \
        SWAP_DATA16((ar) + 36);   /* sID */             \
        /* Two single bytes: (38)proto, (39)flags */    \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
filterioRecordUnpack_V3(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t tmp32, bpp;
    uint32_t pkts, pflag;

    /* swap if required */
    if (stream->swapFlag) {
        filterioRecordSwap_V3(ar);
    }

    /* sIP, dIP, sPort, dPort, nhIP, input, output */
    rwRecMemSetSIPv4(rwrec, &ar[0]);
    rwRecMemSetDIPv4(rwrec, &ar[4]);
    rwRecMemSetSPort(rwrec, &ar[8]);
    rwRecMemSetDPort(rwrec, &ar[10]);
    rwRecMemSetNhIPv4(rwrec, &ar[12]);
    rwRecMemSetInput(rwrec, &ar[16]);
    rwRecMemSetOutput(rwrec, &ar[18]);

    /* sTime, elapsed */
    memcpy(&tmp32, &ar[20], 4);
    rwRecSetStartTime(rwrec, sktimeCreate(tmp32, 0));
    memcpy(&tmp32, &ar[24], 4);
    rwRecSetElapsed(rwrec, (uint32_t)1000 * tmp32);

    /* pkts_ftype, bpp, sensorID */
    memcpy(&tmp32, &ar[28],  4);
    memcpy(&bpp, &ar[32],  4);
    rwRecMemSetSensor(rwrec, &ar[36]);

    /* protocol, tcp-flags */
    rwRecSetProto(rwrec, ar[38]);
    rwRecSetFlags(rwrec, ar[39]);

    /* unpack 'pkts_ftype': pkts:20; pflag:1; pad:3; flowtype:8; */
    pkts = GET_MASKED_BITS(tmp32, 12, 20);
    pflag = GET_MASKED_BITS(tmp32, 11, 1);
    rwRecSetFlowType(rwrec, GET_MASKED_BITS(tmp32, 0, 8));

    /* 'bpp' has bytes-per-packet in most significant bits; move to
     * least significant bits which is where the unpack function below
     * expects them. */
    bpp = bpp >> 12;

    /* pkts, bytes, bpp */
    rwpackUnpackBytesPackets(rwrec, bpp, pkts, pflag);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
filterioRecordPack_V3(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */
    uint32_t tmp32, bpp;
    uint32_t pflag = 0;

    /* sIP, dIP, sPort, dPort, nhIP, input, output */
    rwRecMemGetSIPv4(rwrec, &ar[0]);
    rwRecMemGetDIPv4(rwrec, &ar[4]);
    rwRecMemGetSPort(rwrec, &ar[8]);
    rwRecMemGetDPort(rwrec, &ar[10]);
    rwRecMemGetNhIPv4(rwrec, &ar[12]);
    rwRecMemGetInput(rwrec, &ar[16]);
    rwRecMemGetOutput(rwrec, &ar[18]);

    /* sTime, elapsed */
    tmp32 = (uint32_t)(rwRecGetStartTime(rwrec) / 1000);
    memcpy(&ar[20], &tmp32, 4);
    tmp32 = (uint32_t)(rwRecGetElapsed(rwrec) / 1000);
    memcpy(&ar[24], &tmp32, 4);

    rv = rwpackPackBytesPackets(&bpp, &tmp32, &pflag, rwrec);
    if (rv) {
        return rv;
    }

    /* pkts_ftype has 'pkts' in the least significant bits; move it
     * over and add the 'pflag' and flow type */
    /* pkts_ftype: pkts:20, pflag:1; pad:3; flowType:8 */
    tmp32 = ((tmp32 << 12)
             | ((pflag == 0) ? 0 : (1 << 11))
             | rwRecGetFlowType(rwrec));

    /* 'bpp' has bytes-per-pkt in the least significant bits; move it
     * over to the most significant bits */
    bpp = (bpp << 12);

    /* pkts_ftype, bpp, sID, protocol, tcp-flags */
    memcpy(&ar[28], &tmp32, 4);
    memcpy(&ar[32], &bpp, 4);
    rwRecMemGetSensor(rwrec, &ar[36]);
    ar[38] = rwRecGetProto(rwrec);
    ar[39] = rwRecGetFlags(rwrec);

    /* swap if required */
    if (stream->swapFlag) {
        filterioRecordSwap_V3(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWFILTER VERSION 2
**
**    Only the final 12 bits of the final four bytes differ from
**    VERSION 1: the sID is moved all the way to the right and is now
**    8 bits wide, with 4 bits of padding.
**
**    uint32_t      sIP;             //  0- 3  Source IP
**    uint32_t      dIP;             //  4- 7  Destination IP
**
**    uint16_t      sPort;           //  8- 9  Source port
**    uint16_t      dPort;           // 10-11  Destination port
**
**    uint8_t       proto;           // 12     IP protocol
**    uint8_t       flags;           // 13     OR of all TCP flags on all pkts
**    uint8_t       input;           // 14     Router incoming SNMP interface
**    uint8_t       output;          // 15     Router outgoing SNMP interface
**
**    uint32_t      nhIP;            // 16-19  Router Next Hop IP
**    uint32_t      sTime;           // 20-23  Start time of flow-epoch secs
**
**    uint32_t      pef;             // 24-27
**    // uint32_t     pkts      :20; //        Count of packets
**    // uint32_t     elapsed   :11; //        Duration of flow
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**
**    uint32_t      bbs;             // 28-31
**    // uint32_t     bPPkt     :14; //        Whole bytes-per-packet
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**    // uint32_t     pad       : 4; //        Padding
**    // uint32_t     sensorID  : 8; //        Sensor ID
**
**
**  32 bytes on disk.
*/

#define RECLEN_RWFILTER_V2  32


/* ********************************************************************* */

/*
**  RWFILTER VERSION 1
**
**    uint32_t      sIP;             //  0- 3  Source IP
**    uint32_t      dIP;             //  4- 7  Destination IP
**
**    uint16_t      sPort;           //  8- 9  Source port
**    uint16_t      dPort;           // 10-11  Destination port
**
**    uint8_t       proto;           // 12     IP protocol
**    uint8_t       flags;           // 13     OR of all TCP flags on all pkts
**    uint8_t       input;           // 14     Router incoming SNMP interface
**    uint8_t       output;          // 15     Router outgoing SNMP interface
**
**    uint32_t      nhIP;            // 16-19  Router Next Hop IP
**    uint32_t      sTime;           // 20-23  Start time of flow-epoch secs
**
**    uint32_t      pef;             // 24-27
**    // uint32_t     pkts      :20; //        Count of packets
**    // uint32_t     elapsed   :11; //        Duration of flow
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**
**    uint32_t      bbs;             // 28-31
**    // uint32_t     bPPkt     :14; //        Whole bytes-per-packet
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**    // uint32_t     sensorID  : 6; //        Sensor ID
**    // uint32_t     pad       : 6; //        Padding
**
**
**  32 bytes on disk.
*/

#define RECLEN_RWFILTER_V1  32


/*
 *    Byte swap the RWFILTER v{1,2} record 'ar' in place.
 */
#define filterioRecordSwap_V1V2(ar)                                     \
    {                                                                   \
        SWAP_DATA32((ar) +  0);   /* sIP */                             \
        SWAP_DATA32((ar) +  4);   /* dIP */                             \
        SWAP_DATA16((ar) +  8);   /* sPort */                           \
        SWAP_DATA16((ar) + 10);   /* dPort */                           \
        /* Four single bytes: (12)proto, (13)flags, (14)input, (15)output */ \
        SWAP_DATA32((ar) + 16);   /* nhIP */                            \
        SWAP_DATA32((ar) + 20);   /* sTime */                           \
        SWAP_DATA32((ar) + 24);   /* pef */                             \
        SWAP_DATA32((ar) + 28);   /* bpp/sensorId */                    \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
filterioRecordUnpack_V1V2(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t pef, sbb;
    uint32_t bpp, pkts, pflag;
    uint32_t sTime;

    /* swap if required */
    if (stream->swapFlag) {
        filterioRecordSwap_V1V2(ar);
    }

    /* sIP, dIP, sPort, dPort */
    rwRecMemSetSIPv4(rwrec, &ar[0]);
    rwRecMemSetDIPv4(rwrec, &ar[4]);
    rwRecMemSetSPort(rwrec, &ar[8]);
    rwRecMemSetDPort(rwrec, &ar[10]);

    /* proto, flags, input, output */
    rwRecSetProto(rwrec, ar[12]);
    rwRecSetFlags(rwrec, ar[13]);
    rwRecSetInput(rwrec, ar[14]);
    rwRecSetOutput(rwrec, ar[15]);

    /* nhIP */
    rwRecMemSetNhIPv4(rwrec, &ar[16]);

    /* sTime */
    memcpy(&sTime, &ar[20], 4);
    rwRecSetStartTime(rwrec, sktimeCreate(sTime, 0));

    /* pef: uint32_t pkts:20; uint32_t elapsed :11; uint32_t pflag:1; */
    memcpy(&pef, &ar[24], 4);
    pkts = pef >> 12;
    rwRecSetElapsed(rwrec, (1000 * ((pef >> 1) & MASKARRAY_11)));
    pflag = pef & MASKARRAY_01;

    /* bytes, bpp (ignoring sensor in last 12 bits of sbb) */
    memcpy(&sbb, &ar[28], 4);
    bpp = (sbb >> 12) & MASKARRAY_20;

    rwpackUnpackBytesPackets(rwrec, bpp, pkts, pflag);

    if (skHeaderGetRecordVersion(stream->silk_hdr) == 1) {
        /* handle sensor: sbb is (bPPkt:14; bPPFrac:6; sID:6; pad:6) */
        rwRecSetSensor(rwrec, (uint8_t)((sbb >> 6) & MASKARRAY_06));
    } else {
        assert(skHeaderGetRecordVersion(stream->silk_hdr) == 2);
        /* handle sensor: sbb is (bPPkt:14; bPPFrac:6; pad: 4; sID:8) */
        rwRecSetSensor(rwrec, (sk_sensor_id_t)(sbb & MASKARRAY_08));
    }

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
filterioRecordPack_V1V2(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    int rv = SKSTREAM_OK; /* return value */
    uint32_t bbs;
    uint32_t pef;
    uint32_t pflag;
    uint32_t sTime;

    /* Check sizes of fields we've expanded in later versions */
    if (rwRecGetInput(rwrec) > 255 || rwRecGetOutput(rwrec) > 255) {
        rv = SKSTREAM_ERR_SNMP_OVRFLO;
        goto END;
    }
    if (rwRecGetSensor(rwrec) > 255) {
        rv = SKSTREAM_ERR_SENSORID_OVRFLO;
        goto END;
    }
    if (rwRecGetElapsedSeconds(rwrec) >= MAX_ELAPSED_TIME_OLD) {
        rv = SKSTREAM_ERR_ELPSD_OVRFLO;
        goto END;
    }

    /* bytes-per-packet, packets, packets-flag */
    rv = rwpackPackBytesPackets(&bbs, &pef, &pflag, rwrec);
    if (rv) { goto END; }

    /* The bbs value we have has the bytes-per-packet in the least
     * significant bits.  Move it to the most significant bits, and
     * add the sensor id. */
    /* bbs: uint32_t bPPkt:14;  uint32_t bPPFrac:6; pad:4; sID:8 */
    bbs = ((bbs << 12) | (rwRecGetSensor(rwrec) & MASKARRAY_08));

    if (skHeaderGetRecordVersion(stream->silk_hdr) == 1) {
        /* For v1 of FT_RWFILTER files, only 6 bits allowed of sensor
         * is allowed.  Check that our value fits */
        if (rwRecGetSensor(rwrec) > MASKARRAY_06) {
            rv = SKSTREAM_ERR_SENSORID_OVRFLO;
            goto END;
        }

        /* To convert from version 2 to version 1, shrink the sID to six
         * bits and shift it six bits to the left. */
        bbs = ((bbs & 0xFFFFF000) /* top 20 bits are the same */
               | ((bbs & MASKARRAY_06) << 6));
    }

    /* The pef value we have has the packets value in the least
     * significant bits.  Move it to the most significant bits and add
     * the elapsed time and pflag. */
    /* pef: uint32_t pkts:20; uint32_t elapsed:11; uint32_t pflag:1; */
    pef = ((pef << 12) | (rwRecGetElapsedSeconds(rwrec) << 1) | pflag);

    /* sIP, dIP, sPort, dPort */
    rwRecMemGetSIPv4(rwrec, &ar[0]);
    rwRecMemGetDIPv4(rwrec, &ar[4]);
    rwRecMemGetSPort(rwrec, &ar[8]);
    rwRecMemGetDPort(rwrec, &ar[10]);

    /* proto, flags, input, output */
    ar[12] = rwRecGetProto(rwrec);
    ar[13] = rwRecGetFlags(rwrec);
    ar[14] = (uint8_t)rwRecGetInput(rwrec);
    ar[15] = (uint8_t)rwRecGetOutput(rwrec);

    /* nhIP */
    rwRecMemGetNhIPv4(rwrec, &ar[16]);

    /* sTime */
    sTime = (uint32_t)(rwRecGetStartTime(rwrec) / 1000);
    memcpy(&ar[20], &sTime, 4);

    /* pef, bbs  */
    memcpy(&ar[24], &pef, 4);
    memcpy(&ar[28], &bbs, 4);

    /* swap if required */
    if (stream->swapFlag) {
        filterioRecordSwap_V1V2(ar);
    }

  END:
    return rv;
}


/* ********************************************************************* */

/*
 *  Return length of record of specified version, or 0 if no such
 *  version exists.  See skstream_priv.h for details.
 */
uint16_t
filterioGetRecLen(
    sk_file_version_t   vers)
{
    switch (vers) {
      case 1:
        return RECLEN_RWFILTER_V1;
      case 2:
        return RECLEN_RWFILTER_V2;
      case 3:
        return RECLEN_RWFILTER_V3;
      case 4:
        return RECLEN_RWFILTER_V4;
      case 5:
        return RECLEN_RWFILTER_V5;
      default:
        return 0;
    }
}


/*
 *  status = filterioPrepare(&stream);
 *
 *    Sets the record version to the default if it is unspecified,
 *    checks that the record format supports the requested record
 *    version, sets the record length, and sets the pack and unpack
 *    functions for this record format and version.
 */
int
filterioPrepare(
    skstream_t         *stream)
{
#define FILE_FORMAT "FT_RWFILTER"
    sk_file_header_t *hdr = stream->silk_hdr;
    int rv = SKSTREAM_OK; /* return value */

    assert(skHeaderGetFileFormat(hdr) == FT_RWFILTER);

    /* Set version if none was selected by caller */
    if ((stream->io_mode == SK_IO_WRITE)
        && (skHeaderGetRecordVersion(hdr) == SK_RECORD_VERSION_ANY))
    {
        skHeaderSetRecordVersion(hdr, DEFAULT_RECORD_VERSION);
    }

    /* version check; set values based on version */
    switch (skHeaderGetRecordVersion(hdr)) {
      case 5:
      case 4:
        /* V4 and V5 differ only in that V5 supports compression on
         * read and write; V4 supports compression only on read */
        stream->rwUnpackFn = &filterioRecordUnpack_V4;
        stream->rwPackFn   = &filterioRecordPack_V4;
        break;
      case 3:
        stream->rwUnpackFn = &filterioRecordUnpack_V3;
        stream->rwPackFn   = &filterioRecordPack_V3;
        break;
      case 2:
      case 1:
        stream->rwUnpackFn = &filterioRecordUnpack_V1V2;
        stream->rwPackFn   = &filterioRecordPack_V1V2;
        break;
      case 0:
        /* no longer supported */
      default:
        rv = SKSTREAM_ERR_UNSUPPORT_VERSION;
        goto END;
    }

    stream->recLen = filterioGetRecLen(skHeaderGetRecordVersion(hdr));

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
