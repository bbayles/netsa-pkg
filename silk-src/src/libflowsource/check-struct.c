/*
** Copyright (C) 2008-2023 by Carnegie Mellon University.
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
 *    Verify that the IPFIX data structure looks sound.
 *
 *
 *    This file is included by skipfix.c (part of libflowsource) and
 *    it is also compiled as a stand-alone file to create the
 *    check-struct applaition.
 *
 *    The skiCheckDataStructure() function is defined when
 *    SKIPFIX_SOURCE is defined; otherwise the main() function is
 *    defined.
 */

#include <silk/silk.h>

RCSIDENTVAR(rcs_CHECK_STRUCT_C, "$SiLK: check-struct.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");


/*
 *    Print to the named file handle information about the internal
 *    data structures.  This can be used for debugging to ensure that
 *    the data model does not contain holes or mis-aligned members.
 */
void
skiCheckDataStructure(
    FILE               *fh);


#ifdef SKIPFIX_SOURCE
/*
 *    Add to 'session' a new template specified by 'spec'.  Use
 *    'spec_flags' when appending the spec to the tempate.  Return the
 *    new template or return NULL on error.
 */
static fbTemplate_t *
checkDataStructPrepTemplate(
    fbInfoElementSpec_t spec[],
    uint32_t            spec_flags,
    fbSession_t        *session)
{
    fbInfoModel_t *model;
    fbTemplate_t *tmpl;
    GError *err = NULL;
    uint16_t tid;

    model = fbSessionGetInfoModel(session);

    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, spec, spec_flags, &err)) {
        g_clear_error(&err);
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
    tid = fbSessionAddTemplate(session, TRUE, FB_TID_AUTO, tmpl, &err);
    if (0 == tid) {
        g_clear_error(&err);
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
    tmpl = fbSessionGetTemplate(session, TRUE, tid, &err);
    if (NULL == tmpl) {
        g_clear_error(&err);
        return NULL;
    }
    return tmpl;
}

/*
 *    Check that the byte offset, the length, and the name of the
 *    'tmpl_idx'th item in the template 'tmpl' are equal the
 *    'elem_off', 'elem_size', and 'elem_name' parameters,
 *    respectively, where those parameters represent the location,
 *    size, and name of a member of a C structure.  'struct_pos'
 *    represents the byte offset of the previous element in the
 *    structure.
 *
 *    Increment 'tmpl_idx' by 1 and increment 'struct_pos' by
 *    'elem_size'.
 */
static void
checkDataStructDoElement(
    FILE               *fh,
    fbTemplate_t       *tmpl,
    uint32_t           *tmpl_idx,
    size_t             *struct_pos,
    size_t              elem_off,
    size_t              elem_size,
    const char         *elem_name)
{
    const char *alerr;
    const char *ie_ok;
    const char *hole;
    size_t end;
    const fbTemplateField_t *ie;

    ie = fbTemplateGetFieldByPosition(tmpl, *tmpl_idx);
    ++*tmpl_idx;

    hole = ((*struct_pos != elem_off) ? "hole" : "");
    *struct_pos += elem_size;

    alerr = (((elem_off % elem_size) != 0) ? "alerr" : "");
    if (NULL == ie) {
        ie_ok = "absent";
    } else if (0 != strcmp(elem_name, fbTemplateFieldGetName(ie))) {
        if (elem_size != fbTemplateFieldGetLen(ie)) {
            ie_ok = "nm,len";
        } else {
            ie_ok = "name";
        }
    } else if (elem_size != fbTemplateFieldGetLen(ie)) {
        ie_ok = "length";
    } else {
        ie_ok = "";
    }
    end = elem_off + elem_size - 1;

    fprintf(fh, "%5" SK_PRIuZ "|%5" SK_PRIuZ "|%5" SK_PRIuZ "|%5s|%5s|%6s|%s\n",
            elem_off, end, elem_size, alerr, hole, ie_ok, elem_name);
}

/* Check the alignment of the C structures and their templates. */
void
skiCheckDataStructure(
    FILE               *fh)
{
    fbInfoModel_t *model;
    fbSession_t *session;
    fbTemplate_t *tmpl;
    uint32_t flags;
    uint32_t idx;
    size_t pos;

#define RESET_COUNTERS()                        \
    { pos = 0; idx = 0; }

#define PRINT_TITLE(s_)                                                 \
    fprintf(fh, "===> %s\n%5s|%5s|%5s|%5s|%5s|%6s|%s\n", #s_,           \
            "begin", "end", "size", "alerr", "hole", "IE", "member")

#define PRINT_OFFSET(pos_, s_, mem_)                                    \
    {                                                                   \
        s_ x;                                                           \
        size_t off_ = offsetof(s_, mem_);                               \
        size_t sz_ = sizeof(x.mem_);                                    \
        checkDataStructDoElement(fh, tmpl, &idx, &pos, off_, sz_, #mem_); \
    }

    skIPFIXSourcesSetup();

    model = skiInfoModel();
    session = fbSessionAlloc(model);

    tmpl = checkDataStructPrepTemplate(ski_fixrec_spec, sampler_flags,session);
    if (!tmpl) { goto END; }
    RESET_COUNTERS();
    PRINT_TITLE(ski_fixrec_t);
    PRINT_OFFSET(pos, ski_fixrec_t, sourceTransportPort);
    PRINT_OFFSET(pos, ski_fixrec_t, destinationTransportPort);
    PRINT_OFFSET(pos, ski_fixrec_t, protocolIdentifier);
    PRINT_OFFSET(pos, ski_fixrec_t, tcpControlBits);
    PRINT_OFFSET(pos, ski_fixrec_t, initialTCPFlags);
    PRINT_OFFSET(pos, ski_fixrec_t, unionTCPFlags);
    PRINT_OFFSET(pos, ski_fixrec_t, ingressInterface);
    PRINT_OFFSET(pos, ski_fixrec_t, egressInterface);
    PRINT_OFFSET(pos, ski_fixrec_t, packetDeltaCount);
    PRINT_OFFSET(pos, ski_fixrec_t, octetDeltaCount);
    PRINT_OFFSET(pos, ski_fixrec_t, packetTotalCount);
    PRINT_OFFSET(pos, ski_fixrec_t, octetTotalCount);
    PRINT_OFFSET(pos, ski_fixrec_t, initiatorPackets);
    PRINT_OFFSET(pos, ski_fixrec_t, initiatorOctets);
    PRINT_OFFSET(pos, ski_fixrec_t, responderPackets);
    PRINT_OFFSET(pos, ski_fixrec_t, responderOctets);
    PRINT_OFFSET(pos, ski_fixrec_t, flowAttributes);
    PRINT_OFFSET(pos, ski_fixrec_t, silkAppLabel);
    PRINT_OFFSET(pos, ski_fixrec_t, silkFlowSensor);
    PRINT_OFFSET(pos, ski_fixrec_t, silkFlowType);
    PRINT_OFFSET(pos, ski_fixrec_t, silkTCPState);
    PRINT_OFFSET(pos, ski_fixrec_t, vlanId);
    PRINT_OFFSET(pos, ski_fixrec_t, postVlanId);
    PRINT_OFFSET(pos, ski_fixrec_t, firewallEvent);
    PRINT_OFFSET(pos, ski_fixrec_t, NF_F_FW_EVENT);
    PRINT_OFFSET(pos, ski_fixrec_t, NF_F_FW_EXT_EVENT);
    PRINT_OFFSET(pos, ski_fixrec_t, icmpTypeCodeIPv4);
    PRINT_OFFSET(pos, ski_fixrec_t, icmpTypeIPv4);
    PRINT_OFFSET(pos, ski_fixrec_t, icmpCodeIPv4);
    PRINT_OFFSET(pos, ski_fixrec_t, icmpTypeCodeIPv6);
    PRINT_OFFSET(pos, ski_fixrec_t, icmpTypeIPv6);
    PRINT_OFFSET(pos, ski_fixrec_t, icmpCodeIPv6);
    PRINT_OFFSET(pos, ski_fixrec_t, flowStartMilliseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowEndMilliseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, systemInitTimeMilliseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowStartSysUpTime);
    PRINT_OFFSET(pos, ski_fixrec_t, flowEndSysUpTime);
    PRINT_OFFSET(pos, ski_fixrec_t, flowStartMicroseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowEndMicroseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowStartNanoseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowEndNanoseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowStartSeconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowEndSeconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowStartDeltaMicroseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowEndDeltaMicroseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowDurationMicroseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, flowDurationMilliseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, collectionTimeMilliseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, observationTimeMilliseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, observationTimeMicroseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, observationTimeNanoseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, observationTimeSeconds);
    PRINT_OFFSET(pos, ski_fixrec_t, sourceIPv4Address);
    PRINT_OFFSET(pos, ski_fixrec_t, destinationIPv4Address);
    PRINT_OFFSET(pos, ski_fixrec_t, ipNextHopIPv4Address);
    PRINT_OFFSET(pos, ski_fixrec_t, sourceIPv6Address);
    PRINT_OFFSET(pos, ski_fixrec_t, destinationIPv6Address);
    PRINT_OFFSET(pos, ski_fixrec_t, ipNextHopIPv6Address);
    PRINT_OFFSET(pos, ski_fixrec_t, postPacketDeltaCount);
    PRINT_OFFSET(pos, ski_fixrec_t, postOctetDeltaCount);
    PRINT_OFFSET(pos, ski_fixrec_t, postPacketTotalCount);
    PRINT_OFFSET(pos, ski_fixrec_t, postOctetTotalCount);
    PRINT_OFFSET(pos, ski_fixrec_t, flowEndReason);
    PRINT_OFFSET(pos, ski_fixrec_t, reverseTcpControlBits);
    PRINT_OFFSET(pos, ski_fixrec_t, reverseInitialTCPFlags);
    PRINT_OFFSET(pos, ski_fixrec_t, reverseUnionTCPFlags);
    PRINT_OFFSET(pos, ski_fixrec_t, reverseFlowDeltaMilliseconds);
    PRINT_OFFSET(pos, ski_fixrec_t, reversePacketDeltaCount);
    PRINT_OFFSET(pos, ski_fixrec_t, reverseOctetDeltaCount);
    PRINT_OFFSET(pos, ski_fixrec_t, reversePacketTotalCount);
    PRINT_OFFSET(pos, ski_fixrec_t, reverseOctetTotalCount);
    PRINT_OFFSET(pos, ski_fixrec_t, reverseVlanId);
    PRINT_OFFSET(pos, ski_fixrec_t, reversePostVlanId);
    PRINT_OFFSET(pos, ski_fixrec_t, reverseFlowAttributes);
#if SKI_FIXREC_PADDING != 0
    PRINT_OFFSET(pos, ski_fixrec_t, paddingOctets);
#endif
    PRINT_OFFSET(pos, ski_fixrec_t, stml);

    tmpl = checkDataStructPrepTemplate(ski_yafstats_spec, 0, session);
    if (!tmpl) { goto END; }
    RESET_COUNTERS();
    PRINT_TITLE(ski_yafstats_t);
    PRINT_OFFSET(pos, ski_yafstats_t, systemInitTimeMilliseconds);
    PRINT_OFFSET(pos, ski_yafstats_t, exportedFlowRecordTotalCount);
    PRINT_OFFSET(pos, ski_yafstats_t, packetTotalCount);
    PRINT_OFFSET(pos, ski_yafstats_t, droppedPacketTotalCount);
    PRINT_OFFSET(pos, ski_yafstats_t, ignoredPacketTotalCount);
    PRINT_OFFSET(pos, ski_yafstats_t, notSentPacketTotalCount);
    PRINT_OFFSET(pos, ski_yafstats_t, expiredFragmentCount);
#if 0
    PRINT_OFFSET(pos, ski_yafstats_t, assembledFragmentCount);
    PRINT_OFFSET(pos, ski_yafstats_t, flowTableFlushEventCount);
    PRINT_OFFSET(pos, ski_yafstats_t, flowTablePeakCount);
    PRINT_OFFSET(pos, ski_yafstats_t, exporterIPv4Address);
    PRINT_OFFSET(pos, ski_yafstats_t, exportingProcessId);
    PRINT_OFFSET(pos, ski_yafstats_t, meanFlowRate);
    PRINT_OFFSET(pos, ski_yafstats_t, meanPacketRate);
#endif  /* 0 */
#if SKI_YAFSTATS_PADDING != 0
    PRINT_OFFSET(pos, ski_yafstats_t, paddingOctets);
#endif

    tmpl = checkDataStructPrepTemplate(ski_nf9sampling_spec, sampler_flags,
                                       session);
    if (!tmpl) { goto END; }
    RESET_COUNTERS();
    PRINT_TITLE(ski_nf9sampling_t);
    PRINT_OFFSET(pos, ski_nf9sampling_t, samplingInterval);
    PRINT_OFFSET(pos, ski_nf9sampling_t, samplerRandomInterval);
    PRINT_OFFSET(pos, ski_nf9sampling_t, samplingAlgorithm);
    PRINT_OFFSET(pos, ski_nf9sampling_t, samplerMode);
    PRINT_OFFSET(pos, ski_nf9sampling_t, samplerId);
#if SKI_NF9SAMPLING_PADDING != 0
    PRINT_OFFSET(pos, ski_nf9sampling_t, paddingOctets);
#endif

    tmpl = checkDataStructPrepTemplate(ski_ignore_spec, 0, session);
    if (!tmpl) { goto END; }
    RESET_COUNTERS();
    PRINT_TITLE(ski_ignore_t);
    PRINT_OFFSET(pos, ski_ignore_t, systemInitTimeMilliseconds);

    tmpl = checkDataStructPrepTemplate(ski_tombstone_spec, 0, session);
    if (!tmpl) { goto END; }
    RESET_COUNTERS();
    PRINT_TITLE(ski_tombstone_t);
    PRINT_OFFSET(pos, ski_tombstone_t, observationDomainId);
    PRINT_OFFSET(pos, ski_tombstone_t, exportingProcessId);
    PRINT_OFFSET(pos, ski_tombstone_t, exporterConfiguredId);
    PRINT_OFFSET(pos, ski_tombstone_t, exporterUniqueId);
    PRINT_OFFSET(pos, ski_tombstone_t, paddingOctets);
    PRINT_OFFSET(pos, ski_tombstone_t, tombstoneId);
    PRINT_OFFSET(pos, ski_tombstone_t, observationTimeSeconds);
#if SKIPFIX_ENABLE_TOMBSTONE_TIMES
    PRINT_OFFSET(pos, ski_tombstone_t, stl);
#if FIXBUF_CHECK_VERSION(2,3,0)
    PRINT_OFFSET(pos, ski_tombstone_t, tombstoneAccessList);
#endif
#endif  /* SKIPFIX_ENABLE_TOMBSTONE_TIMES */

    tmpl = checkDataStructPrepTemplate(ski_tombstone_access_spec, 0, session);
    if (!tmpl) { goto END; }
    RESET_COUNTERS();
    PRINT_TITLE(ski_tombstone_access_t);
    PRINT_OFFSET(pos, ski_tombstone_access_t, certToolId);
    PRINT_OFFSET(pos, ski_tombstone_access_t, exportingProcessId);
    PRINT_OFFSET(pos, ski_tombstone_access_t, observationTimeSeconds);

    flags = (YAFREC_DELTA | YAFREC_IP_BOTH | YAFREC_BI | YAFREC_STML);
    tmpl = checkDataStructPrepTemplate(ski_yafrec_spec, flags, session);
    if (!tmpl) { goto END; }
    RESET_COUNTERS();
    PRINT_TITLE(ski_yafrec_t);
    PRINT_OFFSET(pos, ski_yafrec_t, sourceTransportPort);
    PRINT_OFFSET(pos, ski_yafrec_t, destinationTransportPort);
    PRINT_OFFSET(pos, ski_yafrec_t, protocolIdentifier);
    PRINT_OFFSET(pos, ski_yafrec_t, tcpControlBits);
    PRINT_OFFSET(pos, ski_yafrec_t, initialTCPFlags);
    PRINT_OFFSET(pos, ski_yafrec_t, unionTCPFlags);
    PRINT_OFFSET(pos, ski_yafrec_t, ingressInterface);
    PRINT_OFFSET(pos, ski_yafrec_t, egressInterface);
    PRINT_OFFSET(pos, ski_yafrec_t, packetDeltaCount);
    PRINT_OFFSET(pos, ski_yafrec_t, octetDeltaCount);
    PRINT_OFFSET(pos, ski_yafrec_t, flowAttributes);
    PRINT_OFFSET(pos, ski_yafrec_t, silkAppLabel);
    PRINT_OFFSET(pos, ski_yafrec_t, silkFlowSensor);
    PRINT_OFFSET(pos, ski_yafrec_t, silkFlowType);
    PRINT_OFFSET(pos, ski_yafrec_t, silkTCPState);
    PRINT_OFFSET(pos, ski_yafrec_t, flowStartMilliseconds);
    PRINT_OFFSET(pos, ski_yafrec_t, flowEndMilliseconds);
    PRINT_OFFSET(pos, ski_yafrec_t, vlanId);
    PRINT_OFFSET(pos, ski_yafrec_t, postVlanId);
    PRINT_OFFSET(pos, ski_yafrec_t, icmpTypeCode);
    PRINT_OFFSET(pos, ski_yafrec_t, flowEndReason);
    PRINT_OFFSET(pos, ski_yafrec_t, ipClassOfService);
    PRINT_OFFSET(pos, ski_yafrec_t, sourceIPv4Address);
    PRINT_OFFSET(pos, ski_yafrec_t, destinationIPv4Address);
    PRINT_OFFSET(pos, ski_yafrec_t, ipNextHopIPv4Address);
    PRINT_OFFSET(pos, ski_yafrec_t, paddingOctets_1);
    PRINT_OFFSET(pos, ski_yafrec_t, sourceIPv6Address);
    PRINT_OFFSET(pos, ski_yafrec_t, destinationIPv6Address);
    PRINT_OFFSET(pos, ski_yafrec_t, ipNextHopIPv6Address);
    PRINT_OFFSET(pos, ski_yafrec_t, reversePacketDeltaCount);
    PRINT_OFFSET(pos, ski_yafrec_t, reverseOctetDeltaCount);
    PRINT_OFFSET(pos, ski_yafrec_t, reverseFlowDeltaMilliseconds);
    PRINT_OFFSET(pos, ski_yafrec_t, reverseVlanId);
    PRINT_OFFSET(pos, ski_yafrec_t, reversePostVlanId);
    PRINT_OFFSET(pos, ski_yafrec_t, reverseFlowAttributes);
    PRINT_OFFSET(pos, ski_yafrec_t, reverseTcpControlBits);
    PRINT_OFFSET(pos, ski_yafrec_t, reverseInitialTCPFlags);
    PRINT_OFFSET(pos, ski_yafrec_t, reverseUnionTCPFlags);
    PRINT_OFFSET(pos, ski_yafrec_t, reverseIpClassOfService);
    PRINT_OFFSET(pos, ski_yafrec_t, paddingOctets_2);
    PRINT_OFFSET(pos, ski_yafrec_t, stml);

    flags = (NF9REC_INITIATOR | NF9REC_SYSUP | NF9REC_IP6);
    tmpl = checkDataStructPrepTemplate(ski_nf9rec_spec, flags, session);
    if (!tmpl) { goto END; }
    RESET_COUNTERS();
    PRINT_TITLE(ski_nf9rec_t);
    PRINT_OFFSET(pos, ski_nf9rec_t, sourceTransportPort);
    PRINT_OFFSET(pos, ski_nf9rec_t, destinationTransportPort);
    PRINT_OFFSET(pos, ski_nf9rec_t, protocolIdentifier);
    PRINT_OFFSET(pos, ski_nf9rec_t, tcpControlBits);
    PRINT_OFFSET(pos, ski_nf9rec_t, flowEndReason);
    PRINT_OFFSET(pos, ski_nf9rec_t, ipClassOfService);
    PRINT_OFFSET(pos, ski_nf9rec_t, ingressInterface);
    PRINT_OFFSET(pos, ski_nf9rec_t, egressInterface);
    PRINT_OFFSET(pos, ski_nf9rec_t, packetDeltaCount);
    PRINT_OFFSET(pos, ski_nf9rec_t, octetDeltaCount);
    PRINT_OFFSET(pos, ski_nf9rec_t, postPacketDeltaCount);
    PRINT_OFFSET(pos, ski_nf9rec_t, postOctetDeltaCount);
    PRINT_OFFSET(pos, ski_nf9rec_t, t.sysup.systemInitTimeMilliseconds);
    PRINT_OFFSET(pos, ski_nf9rec_t, t.sysup.flowStartSysUpTime);
    PRINT_OFFSET(pos, ski_nf9rec_t, t.sysup.flowEndSysUpTime);
    PRINT_OFFSET(pos, ski_nf9rec_t, vlanId);
    PRINT_OFFSET(pos, ski_nf9rec_t, postVlanId);
    PRINT_OFFSET(pos, ski_nf9rec_t, icmpTypeCode);
    PRINT_OFFSET(pos, ski_nf9rec_t, icmpType);
    PRINT_OFFSET(pos, ski_nf9rec_t, icmpCode);
    PRINT_OFFSET(pos, ski_nf9rec_t, addr.ip6.sourceIPv6Address);
    PRINT_OFFSET(pos, ski_nf9rec_t, addr.ip6.destinationIPv6Address);
    PRINT_OFFSET(pos, ski_nf9rec_t, addr.ip6.ipNextHopIPv6Address);
    PRINT_OFFSET(pos, ski_nf9rec_t, paddingOctets);
    PRINT_OFFSET(pos, ski_nf9rec_t, firewallEvent);
    PRINT_OFFSET(pos, ski_nf9rec_t, NF_F_FW_EVENT);
    PRINT_OFFSET(pos, ski_nf9rec_t, NF_F_FW_EXT_EVENT);

#if 0
    /* need to find a better way to handle optional IEs */
    flags = (NF9REC_DELTA | NF9REC_MILLI | NF9REC_IP4);
    tmpl = checkDataStructPrepTemplate(ski_nf9rec_spec, flags, session);
    if (!tmpl) { goto END; }
    RESET_COUNTERS();
    PRINT_TITLE(ski_nf9rec_t);
    PRINT_OFFSET(pos, ski_nf9rec_t, sourceTransportPort);
    PRINT_OFFSET(pos, ski_nf9rec_t, destinationTransportPort);
    PRINT_OFFSET(pos, ski_nf9rec_t, protocolIdentifier);
    PRINT_OFFSET(pos, ski_nf9rec_t, tcpControlBits);
    PRINT_OFFSET(pos, ski_nf9rec_t, flowEndReason);
    PRINT_OFFSET(pos, ski_nf9rec_t, ipClassOfService);
    PRINT_OFFSET(pos, ski_nf9rec_t, ingressInterface);
    PRINT_OFFSET(pos, ski_nf9rec_t, egressInterface);
    PRINT_OFFSET(pos, ski_nf9rec_t, packetDeltaCount);
    PRINT_OFFSET(pos, ski_nf9rec_t, octetDeltaCount);
    /* name and length of the next does not match */
    PRINT_OFFSET(pos, ski_nf9rec_t, reversePacketDeltaCount);
    PRINT_OFFSET(pos, ski_nf9rec_t, t.milli.flowStartMilliseconds);
    PRINT_OFFSET(pos, ski_nf9rec_t, t.milli.flowEndMilliseconds);
    PRINT_OFFSET(pos, ski_nf9rec_t, vlanId);
    PRINT_OFFSET(pos, ski_nf9rec_t, postVlanId);
    PRINT_OFFSET(pos, ski_nf9rec_t, icmpTypeCode);
    PRINT_OFFSET(pos, ski_nf9rec_t, icmpType);
    PRINT_OFFSET(pos, ski_nf9rec_t, icmpCode);
    PRINT_OFFSET(pos, ski_nf9rec_t, addr.ip4.sourceIPv4Address);
    PRINT_OFFSET(pos, ski_nf9rec_t, addr.ip4.destinationIPv4Address);
    PRINT_OFFSET(pos, ski_nf9rec_t, addr.ip4.ipNextHopIPv4Address);
    /* length of the next does not match */
    PRINT_OFFSET(pos, ski_nf9rec_t, paddingOctets);
    PRINT_OFFSET(pos, ski_nf9rec_t, firewallEvent);
    PRINT_OFFSET(pos, ski_nf9rec_t, NF_F_FW_EVENT);
    PRINT_OFFSET(pos, ski_nf9rec_t, NF_F_FW_EXT_EVENT);
#endif  /* 0 */

  END:
    fbSessionFree(session);
    skiInfoModelFree();
    skiTeardown();
}


#else  /* #ifdef SKIPFIX_SOURCE */

#include "ipfixsource.h"

int main(int argc, char **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    SK_UNUSED_PARAM(argc);

    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);

    skiCheckDataStructure(stderr);

    skAppUnregister();
    return 0;
}

#endif  /* #else of #ifdef SKIPFIX_SOURCE */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
