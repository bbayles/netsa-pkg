/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yfpp0f.h
 *  Definition of the YAF interface to the passive OS fingerprinting
 *  mechanism ported from p0f.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio, Emily Sarneso
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 2.15.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2313
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */


#ifndef YFPP0F_H_
#define YFPP0F_H_

#include <p0f/public.h>

/** list of different modes that the p0f
fingerprinter can operate in */
enum YFP_FIND_MODES {SYN = 0, SYNACK = 1, RST = 2, OPEN = 3};


/** structure returned from yfpPacketParse used to send into yfpFindMatch */
struct packetDecodeDetails_st {
    uint16_t        tot;
    uint8_t         df;
    uint8_t         ttl;
    uint16_t        wss;
    uint32_t        srcIp;
    uint32_t        dstIp;
    uint16_t        srcPort;
    uint16_t        dstPort;
    uint8_t         tcpOptCount;
    uint8_t         tcpOptions[MAXOPT];
    uint16_t        maxSegSize;
    uint16_t        windowScale;
    uint32_t        tcpTimeStamp;
    uint8_t         tos;
    uint32_t        quirks;
    uint32_t        synAckQuirks;
    uint32_t        rstQuirks;
    uint32_t        openQuirks;
    uint8_t         ecn;
    uint8_t        *pkt;
    uint8_t         pktLen;
    uint8_t        *payload;
    struct timeval  packetTimeStamp;
};



/**
 * yfpLoadConfig
 *
 * Loads the appropriate p0f signature definition file
 *
 *
 * @param dirname directory of the p0f database files
 * @param err glib error structure filed in on error
 *
 * @return TRUE on success, FALSE on error
 */
gboolean yfpLoadConfig(char *dirname,
    GError **err);


/**
 * yfpPacketParse
 *
 * This parses the IP & TCP layer of the packet header, it is pulling out
 * details to be used in the OS fingerprinting, and looks at various things
 * in the header that YAF doesn't otherwise care about
 *
 * @param pkt pointer to the packet data (after layer 2 removal)
 * @param pktLen length of the data in pkt
 * @param packetDetails this is the result of the parsed packet, noting all
 *                      the quirks etc used to find a rule match
 * @param err a glib error structure returned filled in on failure
 *
 * @return FALSE on error, TRUE on success
 */
gboolean yfpPacketParse (uint8_t *pkt,
    size_t pktLen,
    struct packetDecodeDetails_st *packetDetails,
    GError **err);


/**
 * yfpSynFindMatch
 *
 * called from the outside to do a finger print search on Syn packets
 *
 * @param packetDetails the decoded packet details, from the yfpPacketParse
 *        function
 * @param tryFuzzy flag to determine whether or not to use a fuzzy match
 * @param fuzzyMatch output flag, TRUE if the match was made fuzzy, FALSE for
 *        deterministic
 * @param osName pointer into a constant string, (in the matching database,)
 *        of the operating system name of the match
 * @param osDetails pointer into a constant string, (in the matching database,)
 *        of the details of the OS match (version number, comments, etc.)
 * @param osFingerPrint pointer
 * @param on error, set with a useful descriptive text string of the error that
 *        occured
 *
 * @return TRUE on success, FALSE on error
 *
 */
gboolean yfpSynFindMatch (struct packetDecodeDetails_st *packetDetails,
    gboolean tryFuzzy,
    gboolean *fuzzyMatch,
    const char **osName,
    const char **osDetails,
    char **osFingerPrint,
    GError **err);



#endif
