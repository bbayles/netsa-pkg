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
** rwgenericio.c
**
** Suresh L Konda
**      routines to do io stuff with generic records.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwgenericio.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "skstream_priv.h"


/* Version to use when SK_RECORD_VERSION_ANY is specified */
#define DEFAULT_RECORD_VERSION 5


/* ********************************************************************* */

/*
**  RWGENERIC VERSION 5
**
**    int64_t       sTime;           //  0- 7  Flow start time as milliseconds
**                                   //        since UNIX epoch
**
**    uint32_t      elapsed;         //  8-11  Duration of flow in milliseconds
**                                   //        (Allows for a 49 day flow)
**
**    uint16_t      sPort;           // 12-13  Source port
**    uint16_t      dPort;           // 14-15  Destination port
**
**    uint8_t       proto;           // 16     IP protocol
**    uint8_t       flow_type;       // 17     Class & Type info
**    uint16_t      sID;             // 18-19  Sensor ID
**
**    uint8_t       flags;           // 20     OR of all flags (Netflow flags)
**    uint8_t       init_flags;      // 21     TCP flags in first packet
**                                   //        or blank for "legacy" data
**    uint8_t       rest_flags;      // 22     TCP flags on non-initial packet
**                                   //        or blank for "legacy" data
**    uint8_t       tcp_state;       // 23     TCP state machine info (below)
**
**    uint16_t      application;     // 24-25  Indication of type of traffic
**    uint16_t      memo;            // 26-27  Application specific field
**
**    uint16_t      input;           // 28-29  Router incoming SNMP interface
**    uint16_t      output;          // 30-31  Router outgoing SNMP interface
**
**    uint32_t      pkts;            // 32-35  Count of packets
**    uint32_t      bytes;           // 36-39  Count of bytes
**
**    uint32_t      sIP;             // 40-43  Source IP
**    uint32_t      dIP;             // 44-47  Destination IP
**    uint32_t      nhIP;            // 48-51  Router Next Hop IP
**
**
**  52 bytes on disk.
*/

#define RECLEN_RWGENERIC_V5 52


/*
 *    Byte swap the RWGENERIC v5 record 'ar' in place.
 */
#define genericioRecordSwap_V5(ar)                              \
    {                                                           \
        SWAP_DATA64((ar) +  0);   /* sTime */                   \
        SWAP_DATA32((ar) +  8);   /* elapsed */                 \
        SWAP_DATA16((ar) + 12);   /* sPort */                   \
        SWAP_DATA16((ar) + 14);   /* dPort */                   \
        /* Two single bytes: (16)proto, (17)flow_type */        \
        SWAP_DATA16((ar) + 18);   /* sID */                     \
        /* Four single bytes: (20)flags, (21)init_flags,        \
         *                    (22)rest_flags, (23)tcp_state */  \
        SWAP_DATA16((ar) + 24);   /* application */             \
        SWAP_DATA16((ar) + 26);   /* memo */                    \
        SWAP_DATA16((ar) + 28);   /* input */                   \
        SWAP_DATA16((ar) + 30);   /* output */                  \
        SWAP_DATA32((ar) + 32);   /* pkts */                    \
        SWAP_DATA32((ar) + 36);   /* bytes */                   \
        SWAP_DATA32((ar) + 40);   /* sIP */                     \
        SWAP_DATA32((ar) + 44);   /* dIP */                     \
        SWAP_DATA32((ar) + 48);   /* nhIP */                    \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
genericioRecordUnpack_V5(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    /* swap if required */
    if (stream->swapFlag) {
        genericioRecordSwap_V5(ar);
    }

#if  !SK_ENABLE_IPV6
    memcpy(rwrec, ar, RECLEN_RWGENERIC_V5);
#else
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
    rwRecMemSetSIPv4(rwrec, &ar[40]);
    rwRecMemSetDIPv4(rwrec, &ar[44]);
    rwRecMemSetNhIPv4(rwrec, &ar[48]);
#endif

    RWREC_MAYBE_CLEAR_TCPSTATE_EXPANDED(rwrec);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
genericioRecordPack_V5(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
#if  !SK_ENABLE_IPV6
    memcpy(ar, rwrec, RECLEN_RWGENERIC_V5);
#else
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
    rwRecMemGetSIPv4(rwrec, &ar[40]);
    rwRecMemGetDIPv4(rwrec, &ar[44]);
    rwRecMemGetNhIPv4(rwrec, &ar[48]);
#endif
    /* swap if required */
    if (stream->swapFlag) {
        genericioRecordSwap_V5(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWGENERIC VERSION 3
**  RWGENERIC VERSION 4
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
**    uint32_t      pkts;            // 28-31  Count of packets
**    uint32_t      bytes;           // 32-35  Count of bytes
**
**    uint8_t       proto;           // 36     IP protocol
**    uint8_t       flow_type;       // 37     Class & Type info
**    uint16_t      sID;             // 38-39  Sensor ID
**
**    uint8_t       flags;           // 40     OR of all flags (Netflow flags)
**    uint8_t       init_flags;      // 41     TCP flags in first packet
**                                   //        or blank for "legacy" data
**    uint8_t       rest_flags;      // 42     TCP flags on non-initial packet
**                                   //        or blank for "legacy" data
**    uint8_t       tcp_state;       // 43     TCP state machine information
**
**    uint32_t      bpp;             // 44-47  Bytes-per-Packet
**
**    uint16_t      sTime_msec;      // 48-49  Start time fraction (millisec)
**    uint16_t      elapsed_msec;    // 50-51  Elapsed time fraction (millisec)
**
**    uint16_t      application;     // 52-53  Type of traffic
**    uint8_t[2]                     // 54-55  PADDING
**
**  56 bytes on disk.
*/

#define RECLEN_RWGENERIC_V3 56
#define RECLEN_RWGENERIC_V4 RECLEN_RWGENERIC_V3


/*
 *    Byte swap the RWGENERIC v3 record 'ar' in place.
 */
#define genericioRecordSwap_V3(ar)                              \
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
        SWAP_DATA32((ar) + 28);   /* pkts */                    \
        SWAP_DATA32((ar) + 32);   /* bytes */                   \
        /* Two single bytes: (36)proto, (37)flow_type */        \
        SWAP_DATA16((ar) + 38);   /* sID */                     \
        /* Four single bytes: (40)flags, (41)init_flags,        \
         *                    (42)rest_flags, (43)tcp_state */  \
        SWAP_DATA32((ar) + 44);   /* bpp */                     \
        SWAP_DATA16((ar) + 48);   /* sTime_msec */              \
        SWAP_DATA16((ar) + 50);   /* elapsed_msec */            \
        SWAP_DATA16((ar) + 52);   /* application */             \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
genericioRecordUnpack_V3(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t quot;
    uint16_t rem;

    /* swap if required */
    if (stream->swapFlag) {
        genericioRecordSwap_V3(ar);
    }

    /* sIP, dIP, sPort, dPort, nhIP, input, output */
    rwRecMemSetSIPv4(rwrec, &ar[0]);
    rwRecMemSetDIPv4(rwrec, &ar[4]);
    rwRecMemSetSPort(rwrec, &ar[8]);
    rwRecMemSetDPort(rwrec, &ar[10]);
    rwRecMemSetNhIPv4(rwrec, &ar[12]);
    rwRecMemSetInput(rwrec, &ar[16]);
    rwRecMemSetOutput(rwrec, &ar[18]);

    /* sTime, sTime_msec */
    memcpy(&quot, &ar[20], 4);
    memcpy(&rem, &ar[48], 2);
    rwRecSetStartTime(rwrec, sktimeCreate(quot, rem));

    /* elapsed, elapsed_msec */
    memcpy(&quot, &ar[24], 4);
    memcpy(&rem, &ar[50], 2);
    rwRecSetElapsed(rwrec, (1000 * quot + rem));

    /* pkts, bytes */
    rwRecMemSetPkts(rwrec, &ar[28]);
    rwRecMemSetBytes(rwrec, &ar[32]);

    /* proto, flowtype, sensor, flags, init_flags, rest_flags, tcp_state */
    rwRecMemSetProto(rwrec, &ar[36]);
    rwRecMemSetFlowType(rwrec, &ar[37]);
    rwRecMemSetSensor(rwrec, &ar[38]);
    rwRecMemSetFlags(rwrec, &ar[40]);
    rwRecMemSetInitFlags(rwrec, &ar[41]);
    rwRecMemSetRestFlags(rwrec, &ar[42]);
    rwRecMemSetTcpState(rwrec, &ar[43]);

    /* bpp field no longer exists */
    /* sTime_msec (above), elapsed_msec (above) */

    /* application */
    rwRecMemSetApplication(rwrec, &ar[52]);

    RWREC_MAYBE_CLEAR_TCPSTATE_EXPANDED(rwrec);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
genericioRecordPack_V3(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    imaxdiv_t idiv;
    uint32_t quot;
    uint16_t rem;

    /* sIP, dIP, sPort, dPort, nhIP, input, output */
    rwRecMemGetSIPv4(rwrec, &ar[0]);
    rwRecMemGetDIPv4(rwrec, &ar[4]);
    rwRecMemGetSPort(rwrec, &ar[8]);
    rwRecMemGetDPort(rwrec, &ar[10]);
    rwRecMemGetNhIPv4(rwrec, &ar[12]);
    rwRecMemGetInput(rwrec, &ar[16]);
    rwRecMemGetOutput(rwrec, &ar[18]);

    /* sTime, sTime_msec */
    idiv = imaxdiv(rwRecGetStartTime(rwrec), 1000);
    quot = (uint32_t)idiv.quot;
    rem = (uint16_t)idiv.rem;
    memcpy(&ar[20], &quot, 4);
    memcpy(&ar[48], &rem, 2);

    /* elapsed, elapsed_msec */
    idiv = imaxdiv(rwRecGetElapsed(rwrec), 1000);
    quot = (uint32_t)idiv.quot;
    rem = (uint16_t)idiv.rem;
    memcpy(&ar[24], &quot, 4);
    memcpy(&ar[50], &rem, 2);

    /* pkts, bytes */
    rwRecMemGetPkts(rwrec, &ar[28]);
    rwRecMemGetBytes(rwrec, &ar[32]);

    /* proto, flowtype, sensor, flags, init_flags, rest_flags, tcp_state */
    rwRecMemGetProto(rwrec, &ar[36]);
    rwRecMemGetFlowType(rwrec, &ar[37]);
    rwRecMemGetSensor(rwrec, &ar[38]);
    rwRecMemGetFlags(rwrec, &ar[40]);
    rwRecMemGetInitFlags(rwrec, &ar[41]);
    rwRecMemGetRestFlags(rwrec, &ar[42]);
    rwRecMemGetTcpState(rwrec, &ar[43]);

    /* bpp field no longer exists */
    memset(&ar[44], 0, 4);

    /* sTime_msec (above), elapsed_msec (above) */

    /* application */
    rwRecMemGetApplication(rwrec, &ar[52]);

    /* padding */
    memset(&ar[54], 0, 2);

    /* swap if required */
    if (stream->swapFlag) {
        genericioRecordSwap_V3(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWGENERIC VERSION 2
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
**    uint32_t      pkts;            // 28-31  Count of packets
**    uint32_t      bytes;           // 32-35  Count of bytes
**
**    uint8_t       proto;           // 36     IP protocol
**    uint8_t       flow_type;       // 37     Class & Type info
**    uint16_t      sID;             // 38-39  Sensor ID
**
**    uint8_t       flags;           // 40     OR of all flags (Netflow flags)
**    uint8_t       init_flags;      // 41     TCP flags in first packet
**                                   //        or blank for "legacy" data
**    uint8_t       rest_flags;      // 42     TCP flags on non-initial packet
**                                   //        or blank for "legacy" data
**    uint8_t       tcp_state;       // 43     TCP state machine information
**
**    uint32_t      bpp;             // 44-47  Bytes-per-Packet
**
**
**  48 bytes on disk.
*/

#define RECLEN_RWGENERIC_V2 48


/*
 *    Byte swap the RWGENERIC v2 record 'ar' in place.
 */
#define genericioRecordSwap_V2(ar)                              \
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
        SWAP_DATA32((ar) + 28);   /* pkts */                    \
        SWAP_DATA32((ar) + 32);   /* bytes */                   \
        /* Two single bytes: (36)proto, (37)flow_type */        \
        SWAP_DATA16((ar) + 38);   /* sID */                     \
        /* Four single bytes: (40)flags, (41)init_flags,        \
         *                    (42)rest_flags, (43)tcp_state */  \
        SWAP_DATA32((ar) + 44);   /* bpp */                     \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
genericioRecordUnpack_V2(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t tmp32;

    /* swap if required */
    if (stream->swapFlag) {
        genericioRecordSwap_V2(ar);
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
    rwRecSetElapsed(rwrec, (1000 * tmp32));

    /* pkts, bytes */
    rwRecMemSetPkts(rwrec, &ar[28]);
    rwRecMemSetBytes(rwrec, &ar[32]);

    /* proto, flow_type, sID, flags, init_flags, rest_flags, tcp_state */
    rwRecMemSetProto(rwrec, &ar[36]);
    rwRecMemSetFlowType(rwrec, &ar[37]);
    rwRecMemSetSensor(rwrec, &ar[38]);
    rwRecMemSetFlags(rwrec, &ar[40]);
    rwRecMemSetInitFlags(rwrec, &ar[41]);
    rwRecMemSetRestFlags(rwrec, &ar[42]);
    rwRecMemSetTcpState(rwrec, &ar[43]);

    /* bpp field no longer exists */

    RWREC_MAYBE_CLEAR_TCPSTATE_EXPANDED(rwrec);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
genericioRecordPack_V2(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    uint32_t tmp32;

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
    tmp32 = rwRecGetElapsed(rwrec) / 1000;
    memcpy(&ar[24], &tmp32, 4);

    /* pkts, bytes */
    rwRecMemGetPkts(rwrec, &ar[28]);
    rwRecMemGetBytes(rwrec, &ar[32]);

    /* proto, flow_type, sID, flags, init_flags, rest_flags, tcp_state */
    rwRecMemGetProto(rwrec, &ar[36]);
    rwRecMemGetFlowType(rwrec, &ar[37]);
    rwRecMemGetSensor(rwrec, &ar[38]);
    rwRecMemGetFlags(rwrec, &ar[40]);
    rwRecMemGetInitFlags(rwrec, &ar[41]);
    rwRecMemGetRestFlags(rwrec, &ar[42]);
    rwRecMemGetTcpState(rwrec, &ar[43]);

    /* bpp field no longer exists */
    memset(&ar[44], 0, 4);

    /* swap if required */
    if (stream->swapFlag) {
        genericioRecordSwap_V2(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
**  RWGENERIC VERSION 0
**  RWGENERIC VERSION 1
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
**    uint32_t      pkts;            // 24-27  Count of packets
**    uint32_t      bytes;           // 28-31  Count of bytes
**    uint32_t      elapsed;         // 32-35  Duration of flow
**
**    uint8_t       sID;             // 36     Sensor ID
**    uint8_t       padding[3];      // 37-39  Padding
**
**  40 bytes on disk with padding (VERSION 0)
**  37 bytes on disk without padding (VERSION 1)
*/

#define RECLEN_RWGENERIC_V0 40
#define RECLEN_RWGENERIC_V1 37


/*
 *    Byte swap the RWGENERIC v1 record 'ar' in place.
 */
#define genericioRecordSwap_V1(ar)                                      \
    {                                                                   \
        SWAP_DATA32((ar) +  0);   /* sIP */                             \
        SWAP_DATA32((ar) +  4);   /* dIP */                             \
        SWAP_DATA16((ar) +  8);   /* sPort */                           \
        SWAP_DATA16((ar) + 10);   /* dPort */                           \
        /* Four single bytes: (12)proto, (13)flags, (14)input, (15)output */ \
        SWAP_DATA32((ar) + 16);   /* nhIP */                            \
        SWAP_DATA32((ar) + 20);   /* sTime */                           \
        SWAP_DATA32((ar) + 24);   /* pkts */                            \
        SWAP_DATA32((ar) + 28);   /* bytes */                           \
        SWAP_DATA32((ar) + 32);   /* elapsed */                         \
        /* One single bytes: (36)sensorId */                            \
    }


/*
 *  Unpack the array of bytes 'ar' into a record 'rwrec'
 */
static int
genericioRecordUnpack_V1(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec,
    uint8_t            *ar)
{
    uint32_t tmp32;

    /* swap if required */
    if (stream->swapFlag) {
        genericioRecordSwap_V1(ar);
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
    memcpy(&tmp32, &ar[20], 4);
    rwRecSetStartTime(rwrec, sktimeCreate(tmp32, 0));

    /* pkts, bytes */
    rwRecMemSetPkts(rwrec, &ar[24]);
    rwRecMemSetBytes(rwrec, &ar[28]);

    /* elapsed */
    memcpy(&tmp32, &ar[32], 4);
    rwRecSetElapsed(rwrec, (1000 * tmp32));

    /* sID */
    rwRecSetSensor(rwrec, ar[36]);

    return SKSTREAM_OK;
}


/*
 *  Pack the record 'rwrec' into an array of bytes 'ar'
 */
static int
genericioRecordPack_V1(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar)
{
    uint32_t tmp32;

    /* Check sizes of fields we've expanded in later versions */
    if (rwRecGetInput(rwrec) > 255 || rwRecGetOutput(rwrec) > 255) {
        return SKSTREAM_ERR_SNMP_OVRFLO;
    }
    /* Check sizes of fields we've expanded in later versions */
    if (rwRecGetSensor(rwrec) > 255) {
        return SKSTREAM_ERR_SENSORID_OVRFLO;
    }

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
    tmp32 = (uint32_t)(rwRecGetStartTime(rwrec) / 1000);
    memcpy(&ar[20], &tmp32, 4);

    /* pkts, bytes */
    rwRecMemGetPkts(rwrec, &ar[24]);
    rwRecMemGetBytes(rwrec, &ar[28]);

    /* elapsed */
    tmp32 = rwRecGetElapsed(rwrec) / 1000;
    memcpy(&ar[32], &tmp32, 4);

    /* sID */
    ar[36] = (uint8_t)rwRecGetSensor(rwrec);

    /* clear padding if present (for consistent output) */
    if (stream->recLen == 40) {
        memset(&ar[37], 0, 3);
    }

    /* swap if required */
    if (stream->swapFlag) {
        genericioRecordSwap_V1(ar);
    }

    return SKSTREAM_OK;
}


/* ********************************************************************* */

/*
 *  Return length of record of specified version, or 0 if no such
 *  version exists.  See skstream_priv.h for details.
 */
uint16_t
genericioGetRecLen(
    sk_file_version_t   vers)
{
    switch (vers) {
      case 0:
        return RECLEN_RWGENERIC_V0;
      case 1:
        return RECLEN_RWGENERIC_V1;
      case 2:
        return RECLEN_RWGENERIC_V2;
      case 3:
        return RECLEN_RWGENERIC_V3;
      case 4:
        return RECLEN_RWGENERIC_V4;
      case 5:
        return RECLEN_RWGENERIC_V5;
      default:
        return 0;
    }
}


/*
 *  status = genericioPrepare(&stream);
 *
 *    Sets the record version to the default if it is unspecified,
 *    checks that the record format supports the requested record
 *    version, sets the record length, and sets the pack and unpack
 *    functions for this record format and version.
 */
int
genericioPrepare(
    skstream_t         *stream)
{
#define FILE_FORMAT "FT_RWGENERIC"
    sk_file_header_t *hdr = stream->silk_hdr;
    int rv = SKSTREAM_OK; /* return value */

    assert(skHeaderGetFileFormat(hdr) == FT_RWGENERIC);

    /* Set version if none was selected by caller */
    if ((stream->io_mode == SK_IO_WRITE)
        && (skHeaderGetRecordVersion(hdr) == SK_RECORD_VERSION_ANY))
    {
        skHeaderSetRecordVersion(hdr, DEFAULT_RECORD_VERSION);
    }

    /* version check; set values based on version */
    switch (skHeaderGetRecordVersion(hdr)) {
      case 5:
        stream->rwUnpackFn = &genericioRecordUnpack_V5;
        stream->rwPackFn   = &genericioRecordPack_V5;
        break;
      case 4:
      case 3:
        /* V3 and V4 differ only in that V4 supports compression on
         * read and write; V3 supports compression only on read */
        stream->rwUnpackFn = &genericioRecordUnpack_V3;
        stream->rwPackFn   = &genericioRecordPack_V3;
        break;
      case 2:
        stream->rwUnpackFn = &genericioRecordUnpack_V2;
        stream->rwPackFn   = &genericioRecordPack_V2;
        break;
      case 1:
      case 0:
        /* Version 0 and Version 1 records are nearly the same; the
         * on-disk Version 0 records included the 3 bytes of in-core
         * padding; the on-disk Version 1 records do not include these
         * 3 bytes. */
        stream->rwUnpackFn = &genericioRecordUnpack_V1;
        stream->rwPackFn   = &genericioRecordPack_V1;
        break;
      default:
        rv = SKSTREAM_ERR_UNSUPPORT_VERSION;
        goto END;
    }

    stream->recLen = genericioGetRecLen(skHeaderGetRecordVersion(hdr));

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
