/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafp0f.c
 *  yaf portion of the p0f OS fingerprinting engine
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
 *
 *  Copyright (C) 2000-2006 Michal Zalewski <lcamtuf@coredump.cx>
 *  GNU Lesser Public License (LPGL)
 *  Rights pursuant to Version 2.1, February 1999
 *
 *  ------------------------------------------------------------------------
 */



/** regular yaf include statements */
#define _YAF_SOURCE_
#include <yaf/yafcore.h>
#include <yaf/autoinc.h>
#include <airframe/airutil.h>

/** p0f include statements */
#if YAF_ENABLE_P0F
#include "p0ftcp.h"
#include "yfp0f.h"

/** definition of the access structure for
the signature database for each of the different
modes */
#define YFP_HASH_DEPTH 16
#define SIGMAX 100
typedef struct fp_database fp_db;

/** logging and error convience macros, carryover from p0f rewriting */
#define debug(x...) g_warning(x)
#define fatal(_kind,x...) g_set_error(err,YAF_ERROR_DOMAIN, _kind, x)

/* local prototypes */

static fp_db* yfpAllocFPDatabase(enum YFP_FIND_MODES findMode);

static fp_db * yfpSYNDatabase = NULL;

static char * ypCreateSignature(
    fp_db *fp_db2,
    uint8_t ttl,
    uint16_t tot,
    uint8_t df,
    uint8_t* op,
    uint8_t ocnt,
    uint16_t mss,
    uint16_t wss,
    uint8_t wsc,
    uint32_t tstamp,
    uint32_t quirks);

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
gboolean
yfpLoadConfig(char *dirname,
    GError **err) {

    char *internDirname;
    char *synConfigFile;

    if (NULL == dirname) {
        internDirname = YAF_CONF_DIR;
    } else {
        internDirname = dirname;
    }

    synConfigFile = g_strconcat(internDirname, "/p0f.fp", NULL);
    yfpSYNDatabase = yfpAllocFPDatabase(SYN);
    load_config(yfpSYNDatabase, (uint8_t *)synConfigFile, 1);
    g_free(synConfigFile);

    return TRUE;
}

/**
 * yfpAllocFPDatabase
 *
 * @return pointer to fp_database
 *
 *
 */
static fp_db * yfpAllocFPDatabase(
    enum YFP_FIND_MODES findMode
)
{
    fp_db *newDB = NULL;

    newDB = g_slice_new0(fp_db);

    switch (findMode){
    case (SYN):
        break;
    case (SYNACK):
        newDB->ack_mode = 1;
        break;
    case (RST):
        newDB->rst_mode = 1;
        break;
    case (OPEN):
        newDB->open_mode = 1;
        break;
    }

    return newDB;

}



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
gboolean
yfpPacketParse (
    uint8_t *pkt,
    size_t pktLen,
    struct packetDecodeDetails_st *packetDetails,
    GError **err) {


    struct ip_header *iph = NULL;
    struct tcp_header *tcph = NULL;
    uint8_t *opt_ptr = NULL;
    int32_t ilen;
    uint32_t quirks = 0;
    int32_t tcpOptLen = 0;
    uint8_t *payloadPtr = NULL;

    /** parse the packet once, but store various additional quirks if
    later on, trying against more then the standard SYN database is
    desirable */
/*    uint32_t synAckQuirks = 0;*/
    uint32_t rstQuirks = 0;
    uint32_t openQuirks = 0;

    /* track tcp options */
    uint8_t tcpOpts[MAXOPT];
    uint8_t tcpOptCount = 0;

    uint16_t maxSegSize = 0;
    uint16_t winScale = 0;
    uint32_t *tempTs32;

    /* clear out the timestamp by default, just in case it
    isn't set otherwise */
    memset(&(packetDetails->tcpTimeStamp), 0,
           sizeof(packetDetails->tcpTimeStamp));

    /** yaf's decoder has already validated that this is pointing to an
        IP header, at a minimum we're beyond layer 2 encapsulation */
    if (pktLen < sizeof(struct ip_header)){
        return FALSE;
    }

    iph = (struct ip_header *)pkt;

    /** check to make sure this is an IPv4 packet and a TCP packet as well */
    if ( ((iph->ihl & 0x40) != 0x40) || iph->proto != IPPROTO_TCP) {
        fatal(YAF_ERROR_PACKET_PAYLOAD,
              "Non-IP packet received. Bad header length");
        return FALSE;
    }
    /** get a pointer to the IP options area */
    opt_ptr = (uint8_t *)iph + g_htons(iph->tot_len);


    /** get the IP header length (in 32-bit words) */
    ilen = iph->ihl & 15;

    /** check to make sure we have a valid IPv4 minimum header size */
    if (5 > ilen) {
        fatal(YAF_ERROR_PACKET_PAYLOAD,
              "Packet payload is not IPv4, only IPv4 is fingerprinted.");
        return FALSE;
    }

    /** check for IP options included in the header, and flag it */
    if (5 < ilen) {
        quirks |= QUIRK_IPOPT;
    }
    /** get a pointer to the TCP header */
    tcph = (struct tcp_header*)((uint8_t*)iph + (ilen << 2));

    /** check to make sure enough was captured to include the TCP header */
    if (((uint8_t*)(tcph+1) - pkt) > pktLen) {
        fatal(YAF_ERROR_PACKET_PAYLOAD,
              "Packet payload is not TCP, only TCP IPv4 is fingerprinted.");
        return FALSE;
    }
    /** capture some details in the TCP header and note them for later */
    if (tcph->flags & TH_ACK) {
        rstQuirks |= QUIRK_RSTACK;
    }
    if (tcph->seq == tcph->ack) {
        quirks |= QUIRK_SEQEQ;
    }
    if (!tcph->seq) {
        quirks |= QUIRK_SEQ0;
    }
    if (tcph->flags & ~(TH_SYN|TH_ACK|TH_RST|TH_ECE|TH_CWR)) {
        quirks |= QUIRK_FLAGS;
    }
    if (tcph->flags & TH_PUSH) {
        openQuirks |= QUIRK_FLAGS;
    }

    /** determine the size of the TCP options section */
    tcpOptLen = ((tcph->doff)<<2) - sizeof(struct tcp_header);

    /** check to see if the TCP options have been captured in
    the packet data */
    if ( (pkt - ((uint8_t*)tcph) + tcpOptLen) < pktLen) {
        openQuirks |= QUIRK_DATA;
    }
    /** figure out where the payloadPtr should be */
    payloadPtr = ((uint8_t*)tcph) + (tcph->doff << 2);
    payloadPtr = ((payloadPtr - pkt) < pktLen)  ? payloadPtr : NULL;


    opt_ptr = (uint8_t*)(tcph+1);
    while (tcpOptLen) {
        tcpOptLen--;

        switch(*(opt_ptr++)) {
            case TCPOPT_EOL:
                tcpOpts[tcpOptCount] = TCPOPT_EOL;
                tcpOptCount++;
                if (tcpOptLen) {
                    quirks |= QUIRK_PAST;
                }
                goto endParsing;
                break;
            case TCPOPT_NOP:
                tcpOpts[tcpOptCount] = TCPOPT_NOP;
                tcpOptCount++;
                break;
            case TCPOPT_SACKOK:
                tcpOpts[tcpOptCount] = TCPOPT_SACKOK;
                tcpOptCount++;
                /* skip over the sack payload */
                tcpOptLen--;
                opt_ptr++;
                break;
            case TCPOPT_MAXSEG:
                if (opt_ptr + 3 > (pkt+pktLen)) {
                    quirks |= QUIRK_BROKEN;
                    goto endParsing;
                }
                tcpOpts[tcpOptCount] = TCPOPT_MAXSEG;
                tcpOptCount++;
                maxSegSize = g_ntohs(*(unsigned short *)(opt_ptr+1));
                tcpOptLen -= 3;
                opt_ptr += 3;
                break;
            case TCPOPT_WSCALE:
                if (opt_ptr + 2 > (pkt+pktLen)) {
                    quirks |= QUIRK_BROKEN;
                    goto endParsing;
                }
                tcpOpts[tcpOptCount] = TCPOPT_WSCALE;
                tcpOptCount++;
                winScale = *(opt_ptr+1);
                tcpOptLen -= 2;
                opt_ptr += 2;
                break;
            case TCPOPT_TIMESTAMP:
                if (opt_ptr + 9 > (pkt+pktLen)) {
                    quirks |= QUIRK_BROKEN;
                    goto endParsing;
                }
                /* check the second stamp out to check if its zero */
                tempTs32 = (uint32_t *)(opt_ptr+5);
                if (*tempTs32) {
                    quirks |= QUIRK_T2;
                }
                memcpy(&(packetDetails->tcpTimeStamp), opt_ptr+1, 4);
                packetDetails->tcpTimeStamp =
                    g_ntohl(packetDetails->tcpTimeStamp);
                tcpOpts[tcpOptCount] = TCPOPT_TIMESTAMP;
                tcpOptCount++;
                tcpOptLen -= 9;
                opt_ptr += 9;
                break;
            default:
                if ((opt_ptr+1) > (pkt+pktLen)) {
                    goto endParsing;
                }
                opt_ptr++;
                tcpOptLen--;
        }
        /* if we already have all the options we can handle, stop
        looking for more*/
        if (tcpOptCount >= MAXOPT-1) {
            quirks |= QUIRK_BROKEN;
            goto endParsing;
        }
        /* check to make sure opt_ptr hasn't run off the end of the
        packet capture */
        if (tcpOptLen > 0) {
            if (opt_ptr >= (pkt+pktLen)) {
                quirks |= QUIRK_BROKEN;
                goto endParsing;
            }
        }
    }
endParsing:

    /* check for more flags in the TCP header */
    if (tcph->ack) {
        quirks |= QUIRK_ACK;
    }
    if (tcph->urg) {
        quirks |= QUIRK_URG;
    }
    if (tcph->_x2) {
        quirks |= QUIRK_X2;
    }
    if (!iph->id)  {
        quirks |= QUIRK_ZEROID;
    }

    /** copy all the details into the packetDetails structure
    for later use */
    packetDetails->tot              = g_ntohs(iph->tot_len);
    packetDetails->df               = (g_ntohs(iph->off) & IP_DF) != 0;
    packetDetails->ttl              = iph->ttl;
    packetDetails->wss              = g_ntohs(tcph->win);
    packetDetails->srcIp            = iph->saddr;
    packetDetails->dstIp            = iph->daddr;
    packetDetails->srcPort          = g_ntohs(tcph->sport);
    packetDetails->dstPort          = g_ntohs(tcph->dport);
    packetDetails->tcpOptCount      = tcpOptCount;
    if (tcpOptCount > 0){
        memcpy(packetDetails->tcpOptions, tcpOpts, tcpOptCount);
    }
    packetDetails->maxSegSize       = maxSegSize;
    packetDetails->windowScale      = winScale;
    /* packetDetails->tcpTimeStamp is already set in the code */
    packetDetails->tos              = iph->tos;
    packetDetails->quirks           = quirks;
    /* Don't need the rest right now */
/*    packetDetails->synAckQuirks     = synAckQuirks;
    packetDetails->rstQuirks        = rstQuirks;
    packetDetails->openQuirks       = openQuirks;
    packetDetails->ecn              = tcph->flags & (TH_ECE|TH_CWR);
    packetDetails->pkt              = g_slice_alloc(YFP_IPTCPHEADER_SIZE);
    memcpy(packetDetails->pkt, pkt, pktLen);
    packetDetails->pktLen           = pktLen;
    packetDetails->payload          = packetDetails->pkt + (payloadPtr - pkt);*/

    /*debug*/
/*    g_debug("tot: %d", packetDetails->tot);
    g_debug("df: %d", packetDetails->df);
    g_debug("ttl: %d", packetDetails->ttl);
    g_debug("wss: %d", packetDetails->wss);
    g_debug("srcIP: %lu", packetDetails->srcIp);
    g_debug("dstIP: %lu", packetDetails->dstIp);
    g_debug("srcPort: %d", packetDetails->srcPort);
    g_debug("dstPort: %d", packetDetails->dstPort);
    g_debug("tcpOptCt: %d", packetDetails->tcpOptCount);
    g_debug("maxSegSize: %d", packetDetails->maxSegSize);
    g_debug("windowScale: %d", packetDetails->windowScale);
    g_debug("tos: %d", packetDetails->tos);
    g_debug("quirks: %d", packetDetails->quirks);
    g_debug("synackquirks: %d", packetDetails->synAckQuirks);
    g_debug("rstQuirks: %d", packetDetails->rstQuirks);
    g_debug("openQuirks: %d", packetDetails->openQuirks);
    g_debug("pktLen is %d", packetDetails->pktLen);*/

    /* FIX_ME
    this should be the time stamp retrieved from the PCAP library or
    its equivalent, but that doesn't make it in this far, the question
    remains if it is useful to pass around */
    /*memcpy(&(packetDetails->packetTimeStamp), &pts, sizeof(struct timeval));*/
    memset(&(packetDetails->packetTimeStamp), 0, sizeof(struct timeval));

    return TRUE;
}




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
 * @param on error, set with a useful descriptive text string of the error that
 *        occured
 *
 * @return TRUE on success, FALSE on error
 *
 */
gboolean
yfpSynFindMatch (struct packetDecodeDetails_st *packetDetails,
    gboolean tryFuzzy,
    gboolean *fuzzyMatch,
    const char **osName,
    const char **osDetails,
    char **osFingerPrint,
    GError **err)
{
    uint8_t use_fuzzy = 0;
    uint8_t nat = 0;
    uint8_t dfout = 0;
    const struct fp_entry *p;

    p = lookup_match(yfpSYNDatabase, packetDetails->tot,
                     packetDetails->df,
                     packetDetails->ttl, packetDetails->wss,
                     packetDetails->tcpOptCount,
                     packetDetails->tcpOptions,
                     packetDetails->maxSegSize,
                     packetDetails->windowScale,
                     packetDetails->tcpTimeStamp,
                     packetDetails->tos, packetDetails->quirks,
                     use_fuzzy, &nat, &dfout);
    if (p){
        *osFingerPrint = ypCreateSignature(yfpSYNDatabase, p->ttl,
                                           p->size, p->df, p->opt,
                                           p->optcnt, p->mss, p->wsize,
                                           p->wsc, p->zero_stamp, p->quirks);
        *osName = (char *)p->os;
        *osDetails = (char*)p->desc;
    }

    return TRUE;
}

/**
 * ypCreateSignature
 *
 * This function is basically copied from libp0f's displaySignature function.
 *
 **/

static char * ypCreateSignature(
    fp_db* fp_db2,
    uint8_t ttl,
    uint16_t tot,
    uint8_t df,
    uint8_t* op,
    uint8_t ocnt,
    uint16_t mss,
    uint16_t wss,
    uint8_t wsc,
    uint32_t tstamp,
    uint32_t quirks)
{
    uint32_t j;
    uint8_t d = 0;
    char fp[SIGMAX];
    char fp2[SIGMAX];
    uint8_t length = 0;
    char *fingerPrint = NULL;

    if (mss && wss && !(wss % mss)) {
        sprintf(fp2, "S%d", wss/mss);
    } else if (wss && !(wss % 1460)) {
        sprintf(fp2, "S%d", wss/1460);
    } else if (mss && wss && !(wss % (mss+40))) {
        sprintf(fp2, "T%d", wss/(mss+40));
    } else if (wss && !(wss % 1500)) {
        sprintf(fp2, "T%d", wss/1500);
    } else if (wss == 12345) {
        sprintf(fp2, "*(12345)");
    } else {
        sprintf(fp2, "%d", wss);
    }

    strcpy(fp, fp2);

    if (!fp_db2->open_mode) {
        if (tot < PACKET_BIG) {
            sprintf(fp2, ":%d:%d:%d:",ttl,df,tot);
        } else {
            sprintf(fp2, ":%d:%d:*(%d):",ttl,df,tot);
        }
    } else {
        sprintf(fp2, ":%d:%d:*:",ttl,df);
    }

    strcat(fp, fp2);
    length = strlen(fp);

    for ( j = 0 ; j < ocnt ; j++ ) {
        switch (op[j]) {
        case TCPOPT_NOP:
            *(fp + length++) = 'N'; d=1;
            break;
        case TCPOPT_WSCALE:
            sprintf(fp2, "W%d", wsc); d=1;
            strcpy((fp + length), fp2);
            length += (strlen(fp2));
            break;
        case TCPOPT_MAXSEG:
            sprintf(fp2, "M%d", mss); d=1;
            strcpy((fp + length), fp2);
            length += (strlen(fp2));
            break;
        case TCPOPT_TIMESTAMP:
            *(fp + length++) = 'T';
            if (!tstamp){
                *(fp + length++) = '0';
            }
            d=1; break;
        case TCPOPT_SACKOK:
            *(fp + length++) = 'S'; d=1;
            break;
        case TCPOPT_EOL:
            *(fp + length++) = 'E'; d=1;
            break;
        default: sprintf(fp2, "?%d", op[j]); d=1;
            strcpy((fp + length), fp2);
            length += strlen(fp2);
            break;
        }

        if (j != ocnt-1) {
            *(fp + length++) = ',';
        }
    }


    if (!d) {
        *(fp + length++) = '.';
    }

    *(fp + length++) = ':';

    if (!quirks) *(fp + length++) = '.'; else {
        if (quirks & QUIRK_RSTACK) *(fp + length++) = 'K';
        if (quirks & QUIRK_SEQEQ) *(fp + length++) = 'Q';
        if (quirks & QUIRK_SEQ0) *(fp + length++) = '0';
        if (quirks & QUIRK_PAST) *(fp + length++) = 'P';
        if (quirks & QUIRK_ZEROID) *(fp + length++) = 'Z';
        if (quirks & QUIRK_IPOPT) *(fp + length++) = 'I';
        if (quirks & QUIRK_URG) *(fp + length++) = 'U';
        if (quirks & QUIRK_X2) *(fp + length++) = 'X';
        if (quirks & QUIRK_ACK) *(fp + length++) = 'A';
        if (quirks & QUIRK_T2) *(fp + length++) = 'T';
        if (quirks & QUIRK_FLAGS) *(fp + length++) = 'F';
        if (quirks & QUIRK_DATA) *(fp + length++) = 'D';
        if (quirks & QUIRK_BROKEN) *(fp + length++) = '!';
    }

    if (length > 0){
        *(fp + length++) = '\0';
        fingerPrint = g_malloc(length);
        strncpy(fingerPrint, fp, length);
    }

    return fingerPrint;
}
#endif
