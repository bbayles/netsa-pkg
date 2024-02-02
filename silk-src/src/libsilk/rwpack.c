/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
**  Functions to support binary output: opening binary SiLK files for
**  writing or appending.
**
*/


#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWPACK_C, "$SiLK: rwpack.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#ifndef RWPACK_BYTES_PACKETS
#if defined(RWPACK_FLAGS_TIMES_VOLUMES) || defined(RWPACK_SBB_PEF)
#define RWPACK_BYTES_PACKETS 1
#endif
#endif
#include "skstream_priv.h"


#ifdef RWPACK_BYTES_PACKETS
/*  Convert bytes and packets fields in 'rwrec' to the values used in
 *  rwfilter output files and in the packed file formats.  See
 *  skstream_priv.h. */
static int
rwpackPackBytesPackets(
    uint32_t               *bpp_out,
    uint32_t               *pkts_out,
    uint32_t               *pflag_out,
    const rwGenericRec_V5  *rwrec)
{
    imaxdiv_t bpp;
    uint32_t packets;
    uint32_t bytes;

    assert(bpp_out);
    assert(pkts_out);
    assert(pflag_out);
    assert(rwrec);

    packets = rwRecGetPkts(rwrec);
    bytes = rwRecGetBytes(rwrec);

    /* Check for 0 value in 'pkts' field */
    if (packets == 0) {
        return SKSTREAM_ERR_PKTS_ZERO;
    }

    /* Verify that there are more bytes than packets */
    if (packets > bytes) {
        return SKSTREAM_ERR_PKTS_GT_BYTES;
    }

    /* Set packets field; check for overflow */
    if (packets < MAX_PKTS) {
        *pkts_out = packets;
        *pflag_out = 0;
    } else {
        *pkts_out = packets / PKTS_DIVISOR;
        if (*pkts_out >= MAX_PKTS) {
            /* Double overflow in pkts */
            return SKSTREAM_ERR_PKTS_OVRFLO;
        }
        /* pktsFlag */
        *pflag_out = 1;
    }

    /* calculate the bytes-per-packet ratio */
    bpp = imaxdiv(bytes, packets);

    if (bpp.quot > MASKARRAY_14) {
        return SKSTREAM_ERR_BPP_OVRFLO;
    }

    /* compute new value */
    *bpp_out = (((uint32_t)bpp.quot) << 6) |
                ((uint32_t)(bpp.rem * BPP_PRECN / packets));

    return SKSTREAM_OK;
}


/*  Fill in the bytes and packets fields in rwrec by expanding the
 *  values that were read from disk.  See skstream_priv.h for details. */
static void
rwpackUnpackBytesPackets(
    rwGenericRec_V5    *rwrec,
    uint32_t            bpp,
    uint32_t            pkts,
    uint32_t            pflag)
{
    uint32_t bytes;
    int bPPkt, bPPFrac;
    div_t i;

    if (pflag) {
        pkts *= PKTS_DIVISOR;
    }

    /* Unpack the bpp value:  bPPkt:14; bPPFrac:6; */
    bPPkt = GET_MASKED_BITS(bpp, 6, 14);
    bPPFrac = GET_MASKED_BITS(bpp, 0, 6);

    /* convert fraction to whole number */
    i = div((bPPFrac * pkts), BPP_PRECN);

    bytes = ((bPPkt * pkts) + i.quot + ((i.rem >= BPP_PRECN_DIV_2) ? 1 : 0));

    rwRecSetPkts(rwrec, pkts);
    rwRecSetBytes(rwrec, bytes);
}
#endif  /* RWPACK_BYTES_PACKETS */


#ifdef RWPACK_PROTO_FLAGS
/* Pack the protocol, flags, and TCP state fields.  See skstream_priv.h */
static void
rwpackPackProtoFlags(
    uint8_t                *is_tcp_out,
    uint8_t                *prot_flags_out,
    uint8_t                *tcp_state_out,
    uint8_t                *rest_flags_out,
    const rwGenericRec_V5  *rwrec)
{
    *tcp_state_out = rwRecGetTcpState(rwrec);
    if (rwRecGetProto(rwrec) != IPPROTO_TCP) {
        /* Flow is not TCP, so there is no additional TCP info.  Set
         * '*rest_flags_out' to value of rwrec->flags. */
        *is_tcp_out = 0;
        *prot_flags_out = rwRecGetProto(rwrec);
        *rest_flags_out = rwRecGetFlags(rwrec);
    } else {
        /* Flow is TCP */
        *is_tcp_out = 1;
        if (*tcp_state_out & SK_TCPSTATE_EXPANDED) {
            /* There is additional TCP info.  Put the initial TCP
             * flags into the '*prot_flags_out' value. */
            *prot_flags_out = rwRecGetInitFlags(rwrec);
            *rest_flags_out = rwRecGetRestFlags(rwrec);
        } else {
            /* There is no additional TCP info. */
            *prot_flags_out = rwRecGetFlags(rwrec);
            *rest_flags_out = 0;
        }
    }
}


/* Fill in the protocol, flags, and TCP state fields on the rwrec.  See
 * skstream_priv.h */
static void
rwpackUnpackProtoFlags(
    rwGenericRec_V5    *rwrec,
    uint8_t             is_tcp,
    uint8_t             prot_flags,
    uint8_t             tcp_state,
    uint8_t             rest_flags)
{
    /* For some record types (e.g., RWWWW), proto is fixed at 6(TCP)
     * and there may be another value in the 'is_tcp' bit; ignore the
     * 'is_tcp' bit if the protocol is already set to TCP. */
    rwRecSetTcpState(rwrec, tcp_state);
    if ((rwRecGetProto(rwrec) == IPPROTO_TCP) || (is_tcp == 1)) {
        /* Flow is TCP */
        rwRecSetProto(rwrec, IPPROTO_TCP);
        if (tcp_state & SK_TCPSTATE_EXPANDED) {
            /* We have additional flow information; value in
             * prot_flags are the flags on the first packet. */
            rwRecSetInitFlags(rwrec, prot_flags);
            rwRecSetRestFlags(rwrec, rest_flags);
            rwRecSetFlags(rwrec, (uint8_t)(prot_flags | rest_flags));
        } else {
            /* We don't have additional TCP info; 'prot_flags' holds
             * the flags. */
            rwRecSetFlags(rwrec, prot_flags);
        }
    } else {
        /* Flow is not TCP so there can be no additional TCP info.
         * 'prot_flags' holds the protocol.  Although 'flags' has no
         * real meaning here, the 'rest_flags' value has the value
         * that we got from the flow collector, so set 'rwrec->flags'
         * to that value. */
        rwRecSetProto(rwrec, prot_flags);
        rwRecSetFlags(rwrec, rest_flags);
    }
}
#endif  /* RWPACK_PROTO_FLAGS */


#ifdef RWPACK_SBB_PEF
/*  Compute the 'sbb' and 'pef' fields used in packed file formats.
 *  See skstream_priv.h. */
static int
rwpackPackSbbPef(
    uint32_t               *sbb_out,
    uint32_t               *pef_out,
    const rwGenericRec_V5  *rwrec,
    sktime_t                file_start_time)
{
    int rv = SKSTREAM_OK; /* return value */
    sktime_t start_time;
    uint32_t elapsed;
    uint32_t pkts, bpp, pflag;

    elapsed = (rwRecGetElapsed(rwrec) / 1000);
    if (elapsed >= MAX_ELAPSED_TIME_OLD) {
        rv = SKSTREAM_ERR_ELPSD_OVRFLO;
        goto END;
    }

    start_time = rwRecGetStartTime(rwrec);
    if (start_time < file_start_time) {
        rv = SKSTREAM_ERR_STIME_UNDRFLO;
        goto END;
    }
    /* convert start time to seconds in the hour */
    start_time = (start_time - file_start_time) / 1000;
    if (start_time >= MAX_START_TIME) {
        rv = SKSTREAM_ERR_STIME_OVRFLO;
        goto END;
    }

    rv = rwpackPackBytesPackets(&bpp, &pkts, &pflag, rwrec);
    if (rv) { goto END; }

    /* sbb: uint32_t sTime:12;  uint32_t bPPkt:14;  uint32_t bPPFrac:6; */
    *sbb_out = (((MASKARRAY_12 & (uint32_t)start_time) << 20)
                | (bpp & MASKARRAY_20));

    /* pef: uint32_t pkts:20; uint32_t elapsed :11; uint32_t pktsFlag:1; */
    *pef_out = ((pkts << 12) | (elapsed << 1) | pflag);

  END:
    return rv;
}


/* Set values in rwrec by expanding the 'sbb' and 'pef' fields that
 * exist in the packed file formats.  See skstream_priv.h for details. */
static void
rwpackUnpackSbbPef(
    rwGenericRec_V5    *rwrec,
    sktime_t            file_start_time,
    const uint32_t     *sbb,
    const uint32_t     *pef)
{
    uint32_t pkts, pktsFlag, bpp, start_time;

    /* pef: uint32_t pkts:20; uint32_t elapsed :11; uint32_t pktsFlag:1; */
    pkts = *pef >> 12;
    rwRecSetElapsed(rwrec, (1000 * ((*pef >> 1) & MASKARRAY_11)));
    pktsFlag = *pef & MASKARRAY_01;

    /* sbb: uint32_t start_time:12; uint32_t bpp:20 */
    bpp = *sbb & MASKARRAY_20;
    start_time = (*sbb >> 20);
    rwRecSetStartTime(rwrec, file_start_time + sktimeCreate(start_time, 0));

    rwpackUnpackBytesPackets(rwrec, bpp, pkts, pktsFlag);
}
#endif  /* RWPACK_SBB_PEF */


#ifdef RWPACK_TIME_BYTES_PKTS_FLAGS
static int
rwpackPackTimeBytesPktsFlags(
    uint32_t               *pkts_stime_out,
    uint32_t               *bbe_out,
    uint32_t               *msec_flags_out,
    const rwGenericRec_V5  *rwrec,
    sktime_t                file_start_time)
{
    int rv = SKSTREAM_OK; /* return value */
    sktime_t start_time;
    uint32_t pkts, bpp, pflag, is_tcp;
    uint8_t prot_flags;
    imaxdiv_t stime_div;
    imaxdiv_t elapsed_div;

    elapsed_div = imaxdiv(rwRecGetElapsed(rwrec), 1000);

    if (elapsed_div.quot >= MAX_ELAPSED_TIME) {
        rv = SKSTREAM_ERR_ELPSD_OVRFLO;
        goto END;
    }

    start_time = rwRecGetStartTime(rwrec);
    if (start_time < file_start_time) {
        rv = SKSTREAM_ERR_STIME_UNDRFLO;
        goto END;
    }
    start_time -= file_start_time;
    stime_div = imaxdiv(start_time, 1000);
    if (stime_div.quot >= MAX_START_TIME) {
        rv = SKSTREAM_ERR_STIME_OVRFLO;
        goto END;
    }

    rv = rwpackPackBytesPackets(&bpp, &pkts, &pflag, rwrec);
    if (rv) { goto END; }

    /* pkts_stime: pkts:20; sTime: 12; */
    *pkts_stime_out = ((pkts << 12)
                       | (MASKARRAY_12 & (uint32_t)stime_div.quot));

    /* bbe: bpp: 20; elapsed: 12 */
    *bbe_out = ((bpp << 12)
                | (MASKARRAY_12 & (uint32_t)elapsed_div.quot));

    /* set is_tcp bit and prot_flags */
    if (rwRecGetProto(rwrec) == IPPROTO_TCP) {
        is_tcp = 1;
        prot_flags = rwRecGetFlags(rwrec);
    } else {
        is_tcp = 0;
        prot_flags = rwRecGetProto(rwrec);
    }

    /* msec_flags: sTime_msec:10; elaps_msec:10; pflag:1;
     *             is_tcp:1; pad:2; prot_flags:8;*/
    *msec_flags_out = (((MASKARRAY_10 & (uint32_t)stime_div.rem) << 22)
                       | ((MASKARRAY_10 & (uint32_t)elapsed_div.rem) << 12)
                       | (pflag ? (1 << 11) : 0)
                       | (is_tcp ? (1 << 10) : 0)
                       | prot_flags);

  END:
    return rv;
}


static void
rwpackUnpackTimeBytesPktsFlags(
    rwGenericRec_V5    *rwrec,
    sktime_t            file_start_time,
    const uint32_t     *pkts_stime,
    const uint32_t     *bbe,
    const uint32_t     *msec_flags)
{
    uint32_t pkts, bpp, is_tcp, pflag;
    uint8_t prot_flags;

    /* pkts_stime: pkts:20; sTime: 12; */
    /* msec_flags: sTime_msec:10; elaps_msec:10; pflag:1;
     *             is_tcp:1; pad:2, prot_flags:8;          */
    pkts = GET_MASKED_BITS(*pkts_stime, 12, 20);

    rwRecSetStartTime(rwrec,
                      (file_start_time
                       + sktimeCreate(GET_MASKED_BITS(*pkts_stime, 0, 12),
                                      GET_MASKED_BITS(*msec_flags, 22, 10))));

    /* bbe: bpp: 20; elapsed: 12 */
    bpp = GET_MASKED_BITS(*bbe, 12, 20);

    rwRecSetElapsed(rwrec, (1000u * GET_MASKED_BITS(*bbe, 0, 12)
                            + GET_MASKED_BITS(*msec_flags, 12, 10)));

    /* msec_flags: sTime_msec:10; elaps_msec:10; pflag:1;
     *             is_tcp:1; pad:2, prot_flags:8;          */
    pflag = GET_MASKED_BITS(*msec_flags, 11, 1);
    is_tcp = GET_MASKED_BITS(*msec_flags, 10, 1);
    prot_flags = (uint8_t)GET_MASKED_BITS(*msec_flags, 0, 8);

    if (rwRecGetProto(rwrec) == IPPROTO_TCP) {
        /* caller has forced record to be TCP */
        rwRecSetFlags(rwrec, prot_flags);
    } else if (is_tcp == 0) {
        /* flow is not TCP */
        rwRecSetProto(rwrec, prot_flags);
    } else {
        /* flow is TCP */
        rwRecSetProto(rwrec, IPPROTO_TCP);
        rwRecSetFlags(rwrec, prot_flags);
    }

    /* unpack the bpp value into bytes and packets */
    rwpackUnpackBytesPackets(rwrec, bpp, pkts, pflag);
}
#endif  /* RWPACK_TIME_BYTES_PKTS_FLAGS */


#ifdef RWPACK_FLAGS_TIMES_VOLUMES
static int
rwpackPackFlagsTimesVolumes(
    uint8_t                *ar,
    const rwGenericRec_V5  *rwrec,
    sktime_t                file_start_time,
    size_t                  len)
{
    uint32_t bpp, tmp, pkts, pflag;
    uint8_t tcp_state;
    sktime_t start_time;
    int rv = SKSTREAM_OK;

    if (rwRecGetElapsed(rwrec) >= 1000u * MAX_ELAPSED_TIME) {
        rv = SKSTREAM_ERR_ELPSD_OVRFLO;
        goto END;
    }

    start_time = rwRecGetStartTime(rwrec);
    if (start_time < file_start_time) {
        rv = SKSTREAM_ERR_STIME_UNDRFLO;
        goto END;
    }
    start_time -= file_start_time;
    if (start_time >= sktimeCreate(MAX_START_TIME, 0)) {
        rv = SKSTREAM_ERR_STIME_OVRFLO;
        goto END;
    }

    rv = rwpackPackBytesPackets(&bpp, &pkts, &pflag, rwrec);
    if (rv) { goto END; }

/*
**    uint32_t      stime_bb1;       //  0- 3
**    // uint32_t     stime     :22  //        Start time:msec offset from hour
**    // uint32_t     bPPkt1    :10; //        Whole bytes-per-packet (hi 10)
*/
    tmp = (((MASKARRAY_22 & (uint32_t)start_time) << 10)
           | (GET_MASKED_BITS(bpp, 10, 10)));
    memcpy(&ar[0], &tmp, sizeof(tmp));

/*
**    uint32_t      bb2_elapsed;     //  4- 7
**    // uint32_t     bPPkt2    : 4; //        Whole bytes-per-packet (low 4)
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**    // uint32_t     elapsed   :22; //        Duration of flow in msec
**
*/
    tmp = ((GET_MASKED_BITS(bpp, 0, 10) << 22)
           | (MASKARRAY_22 & rwRecGetElapsed(rwrec)));
    memcpy(&ar[4], &tmp, sizeof(tmp));

/*
**    uint8_t      tcp_state;        // 12     TCP state machine info
**    uint8_t      rest_flags;       // 13     is_tcp==0: Flow's reported flags
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:Empty
**                                   //          EXPANDED==1:TCPflags/!1st pkt
**    uint16_t     application;      // 14-15  Type of traffic
*/
    if (len == 12) {
        tcp_state = 0;
    } else if (len == 16) {
        tcp_state = rwRecGetTcpState(rwrec);
        ar[12] = tcp_state;
        if (rwRecGetProto(rwrec) != IPPROTO_TCP) {
            /* when not TCP, holds whatever flags value we have */
            ar[13] = rwRecGetFlags(rwrec);
        } else if (tcp_state & SK_TCPSTATE_EXPANDED) {
            /* when TCP and extended data, hold the rest flags */
            ar[13] = rwRecGetRestFlags(rwrec);
        } else {
            /* when TCP but no extended data, is empty */
            ar[13] = 0;
        }
        rwRecMemGetApplication(rwrec, &ar[14]);
    } else {
        skAppPrintErr(("Bad length (%lu) to rwpackPackFlagsTimesVolumes"
                       " at %s:%d"),
                      (unsigned long)len, __FILE__, __LINE__);
        skAbort();
    }

/*
**    uint32_t      pro_flg_pkts;    //  8-11
**    // uint32_t     prot_flags: 8; //        is_tcp==0: IP protocol
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:TCPflags/All pkts
**                                   //          EXPANDED==1:TCPflags/1st pkt
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**    // uint32_t     is_tcp    : 1; //        1 if flow is TCP; 0 otherwise
**    // uint32_t     padding   : 2; //
**    // uint32_t     pkts      :20; //        Count of packets
*/
    tmp = ((pflag << 23)
           | (MASKARRAY_20 & pkts));
    if (rwRecGetProto(rwrec) != IPPROTO_TCP) {
        tmp |= (rwRecGetProto(rwrec) << 24);
    } else {
        if (tcp_state & SK_TCPSTATE_EXPANDED) {
            tmp |= ((rwRecGetInitFlags(rwrec) << 24)
                    | (1 << 22));
        } else {
            tmp |= ((rwRecGetFlags(rwrec) << 24)
                    | (1 << 22));
        }
    }
    memcpy(&ar[8], &tmp, sizeof(tmp));

  END:
    return rv;
}


static void
rwpackUnpackFlagsTimesVolumes(
    rwGenericRec_V5    *rwrec,
    const uint8_t      *ar,
    sktime_t            file_start_time,
    size_t              len,
    int                 is_tcp)
{
    uint32_t bpp, tmp, pkts, pflag;
    uint8_t tcp_state, rest_flags;

/*
**    uint8_t      tcp_state;        // 12     TCP state machine info
**    uint8_t      rest_flags;       // 13     is_tcp==0: Flow's reported flags
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:Empty
**                                   //          EXPANDED==1:TCPflags/!1st pkt
**    uint16_t     application;      // 14-15  Type of traffic
*/
    if (len == 12) {
        tcp_state = 0;
        rest_flags = 0;
    } else if (len == 16) {
        tcp_state = ar[12];
        rest_flags = ar[13];
        rwRecSetTcpState(rwrec, tcp_state);
        rwRecMemSetApplication(rwrec, &ar[14]);
    } else {
        skAppPrintErr(("Bad length (%lu) to rwpackUnpackFlagsTimesVolumes"
                       " at %s:%d"),
                      (unsigned long)len, __FILE__, __LINE__);
        skAbort();
    }

/*
**    uint32_t      pro_flg_pkts;    //  8-11
**    // uint32_t     prot_flags: 8; //        is_tcp==0: IP protocol
**                                   //        is_tcp==1 &&
**                                   //          EXPANDED==0:TCPflags/All pkts
**                                   //          EXPANDED==1:TCPflags/1st pkt
**    // uint32_t     pflag     : 1; //        'pkts' requires multiplier?
**    // uint32_t     is_tcp    : 1; //        1 if flow is TCP; 0 otherwise
**    // uint32_t     padding   : 2; //
**    // uint32_t     pkts      :20; //        Count of packets
*/
    memcpy(&tmp, &ar[8], sizeof(tmp));
    pkts = GET_MASKED_BITS(tmp, 0, 20);
    pflag = GET_MASKED_BITS(tmp, 23, 1);
    if (!is_tcp) {
        is_tcp = GET_MASKED_BITS(tmp, 22, 1);
    }
    if (!is_tcp) {
        rwRecSetProto(rwrec, GET_MASKED_BITS(tmp, 24, 8));
        rwRecSetFlags(rwrec, rest_flags);
    } else {
        rwRecSetProto(rwrec, IPPROTO_TCP);
        if (tcp_state & SK_TCPSTATE_EXPANDED) {
            rwRecSetRestFlags(rwrec, rest_flags);
            rwRecSetInitFlags(rwrec, GET_MASKED_BITS(tmp, 24, 8));
        }
        rwRecSetFlags(rwrec, (GET_MASKED_BITS(tmp, 24, 8)
                              | rest_flags));
    }

/*
**    uint32_t      bb2_elapsed;     //  4- 7
**    // uint32_t     bPPkt2    : 4; //        Whole bytes-per-packet (low 4)
**    // uint32_t     bPPFrac   : 6; //        Fractional bytes-per-packet
**    // uint32_t     elapsed   :22; //        Duration of flow in msec
**
*/
    memcpy(&tmp, &ar[4], sizeof(tmp));
    rwRecSetElapsed(rwrec, GET_MASKED_BITS(tmp, 0, 22));


/*
**    uint32_t      stime_bb1;       //  0- 3
**    // uint32_t     stime     :22  //        Start time:msec offset from hour
**    // uint32_t     bPPkt1    :10; //        Whole bytes-per-packet (hi 10)
*/
    memcpy(&bpp, &ar[0], sizeof(bpp));
    rwRecSetStartTime(rwrec, file_start_time + GET_MASKED_BITS(bpp, 10, 22));

    bpp = ((GET_MASKED_BITS(bpp, 0, 10) << 10)
           | GET_MASKED_BITS(tmp, 22, 10));

    rwpackUnpackBytesPackets(rwrec, bpp, pkts, pflag);
}
#endif  /* RWPACK_FLAGS_TIMES_VOLUMES */


#ifdef RWPACK_TIMES_FLAGS_PROTO
static int
rwpackPackTimesFlagsProto(
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar,
    sktime_t                file_start_time)
{
    sktime_t start_time;
    uint32_t tmp;
    int rv = SKSTREAM_OK; /* return value */

    start_time = rwRecGetStartTime(rwrec);
    if (start_time < file_start_time) {
        rv = SKSTREAM_ERR_STIME_UNDRFLO;
        goto END;
    }
    start_time -= file_start_time;
    if (start_time >= sktimeCreate(MAX_START_TIME, 0)) {
        rv = SKSTREAM_ERR_STIME_OVRFLO;
        goto END;
    }

/*
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
*/

    /* Start time, Protocol, TCP Flags */
    if (IPPROTO_TCP != rwRecGetProto(rwrec)) {
        /* First 4 bytes only contains stime */
        assert((MASKARRAY_22 & (uint32_t)start_time) == start_time);
        tmp = (uint32_t)start_time;
        memcpy(&ar[ 0], &tmp, sizeof(tmp));
        rwRecMemGetProto(rwrec, &ar[ 4]);

    } else if (rwRecGetTcpState(rwrec) & SK_TCPSTATE_EXPANDED) {
        tmp = ((rwRecGetRestFlags(rwrec) << 24)
               | (1 << 23)
               | (MASKARRAY_22 & (uint32_t)start_time));
        memcpy(&ar[ 0], &tmp, sizeof(tmp));
        rwRecMemGetInitFlags(rwrec, &ar[ 4]);

    } else {
        tmp = ((1 << 23)
               | (MASKARRAY_22 & (uint32_t)start_time));
        memcpy(&ar[ 0], &tmp, sizeof(tmp));
        rwRecMemGetFlags(rwrec, &ar[ 4]);
    }

    rwRecMemGetTcpState(rwrec, &ar[ 5]);

  END:
    return rv;
}


static void
rwpackUnpackTimesFlagsProto(
    rwGenericRec_V5    *rwrec,
    const uint8_t      *ar,
    sktime_t            file_start_time)
{
    uint32_t tmp;

/*
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
*/

    memcpy(&tmp, &ar[0], sizeof(tmp));
    rwRecSetStartTime(rwrec, (file_start_time
                              + (sktime_t)GET_MASKED_BITS(tmp, 0, 22)));

    if (0 == GET_MASKED_BITS(tmp, 23, 1)) {
        /* Not TCP; protocol is in the 'proto_iflags' field */
        rwRecMemSetProto(rwrec, &ar[4]);

    } else if (ar[5] & SK_TCPSTATE_EXPANDED) {
        /* Is TCP and have initial-flags and session-flags */
        rwRecSetProto(rwrec, IPPROTO_TCP);
        rwRecSetRestFlags(rwrec, GET_MASKED_BITS(tmp, 24, 8));
        rwRecMemSetInitFlags(rwrec, &ar[4]);
        rwRecSetFlags(rwrec,
                      (rwRecGetInitFlags(rwrec) | rwRecGetRestFlags(rwrec)));
    } else {
        /* Is TCP; only have combined TCP flags */
        rwRecSetProto(rwrec, IPPROTO_TCP);
        rwRecMemSetFlags(rwrec, &ar[4]);
    }

    rwRecMemSetTcpState(rwrec, &ar[5]);
}
#endif  /* RWPACK_TIMES_FLAGS_PROTO */


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
