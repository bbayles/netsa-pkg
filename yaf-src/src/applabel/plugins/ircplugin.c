/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  ircplugin.c
 *
 *  this provides IRC payload packet recognition for use within YAF
 *  It is based on RFC 2812 and some random limited packet capture.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio
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

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <pcre.h>
#include <payloadScanner.h>

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#define IRCDEBUG 0
#define IRC_PORT 194

YC_SCANNER_PROTOTYPE(ircplugin_LTX_ycIrcScanScan);

/**
 * the compiled regular expressions, and related
 * flags
 *
 */
static pcre        *ircMsgRegex = NULL;
/*static pcre *ircJoinRegex = NULL;*/
static pcre        *ircRegex = NULL;
static pcre        *ircDPIRegex = NULL;
static unsigned int pcreInitialized = 0;



/**
 * static local functions
 *
 */
static uint16_t
ycIrcScanInit(
    void);

#if IRCDEBUG
static int
ycDebugBinPrintf(
    uint8_t   *data,
    uint16_t   size);

#endif /* if IRCDEBUG */

/**
 * ircplugin_LTX_ycIrcScanScan
 *
 * scans a given payload to see if it conforms to our idea of what IRC traffic
 * looks like.
 *
 *
 * name abomination has been achieved by combining multiple naming standards
 * until the prefix to
 * the function name is ircplugin_LTX_ycIrcScanScan --- it's a feature
 *
 * @param argc NOT USED
 * @param argv NOT USED
 * @param payload pointer to the payload data
 * @param payloadSize the size of the payload parameter
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 0 for no match IRC_PORT_NUMBER (194) for a match
 *
 */
uint16_t
ircplugin_LTX_ycIrcScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    int rc;
#define NUM_CAPT_VECTS 60
    int vects[NUM_CAPT_VECTS];

    if (0 == pcreInitialized) {
        if (0 == ycIrcScanInit()) {
            return 0;
        }
    }

    rc = pcre_exec(ircMsgRegex, NULL, (char *)payload, payloadSize,
                   0, 0, vects, NUM_CAPT_VECTS);

    /*if (rc <= 0) {
     *  rc = pcre_exec(ircJoinRegex, NULL, (char *)payload, payloadSize,
     *                 0, 0, vects, NUM_CAPT_VECTS);
     *                 }*/
    if (rc <= 0) {
        rc = pcre_exec(ircRegex, NULL, (char *)payload, payloadSize,
                       0, 0, vects, NUM_CAPT_VECTS);
    }

    /** at some point in the future, this is the place to extract protocol
     *  information like message targets and join targets, etc.*/

#if YAF_ENABLE_HOOKS

    if (rc > 0 && ircDPIRegex) {
        yfHookScanPayload(flow, payload, payloadSize, ircDPIRegex, 0,
                          202, IRC_PORT);
    }

#endif /* if YAF_ENABLE_HOOKS */

    if (rc > 0) {
        return IRC_PORT;
    }

    return 0;
}


/**
 * ycIrcScanInit
 *
 * this initializes the PCRE expressions needed to search the payload for
 * IRC
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is complete correctly, 0 otherwise
 */
static
uint16_t
ycIrcScanInit(
    void)
{
    const char *errorString;
    int         errorPos;

    const char  ircMsgRegexString[] = "^(?:(:[^: \\n\\r]+)(?:\\ ))?"
        "(PRIVMSG|NOTICE) \\ "
        "([^: \\n\\r]+|:.*) (?:\\ )"
        "([^: \\n\\r]+\\ |:.*)";
    /*const char ircJoinRegexString[] = "^(?:(:[^\\: \\n\\r]+)(?:\\ ))?"
     * "((JOIN) \\ [^: \\n\\r]+\\ |:.*)\\s";*/
    const char ircRegexString[] = "^((?:(:[^: \\n\\r]+)(?:\\ ))?"
        "(PASS|OPER|QUIT|SQUIT|NICK"
        "|MODE|USER|SERVICE|JOIN|NAMES|INVITE"
        "|PART|TOPIC|LIST|KICK|PRIVMSG|NOTICE"
        "|MOTD|STATS|CONNECT|INFO|LUSERS|LINKS"
        "|TRACE|VERSION|TIME|ADMIN|SERVLIST"
        "|SQUERY|WHO|WHOWAS|WHOIS|KILL|PING"
        "|PONG|ERROR|AWAY|DIE|SUMMON|REHASH"
        "|RESTART|USERS|USERHOST)[ a-zA-Z0-9$#.:*\"]*)"
        "(?:[\\r\\n])";

    const char ircDPIRegexString[] = "((\\d{3}|PASS|OPER|QUIT|SQUIT|NICK"
        "|MODE|USER|SERVICE|JOIN|NAMES|INVITE"
        "|PART|TOPIC|LIST|KICK|PRIVMSG"
        "|MOTD|STATS|CONNECT|INFO|LUSERS|LINKS"
        "|TRACE|VERSION|TIME|ADMIN|SERVLIST"
        "|SQUERY|WHO|WHOWAS|WHOIS|KILL|PING"
        "|PONG|ERROR|AWAY|DIE|SUMMON|REHASH"
        "|RESTART|USERS|USERHOST|PROTOCTL) "
        "[-a-zA-Z0-9$#.:*\" ]*)(?:[\\r\\n])";

    ircRegex = pcre_compile(ircRegexString, PCRE_EXTENDED | PCRE_ANCHORED,
                            &errorString, &errorPos, NULL);
    ircMsgRegex = pcre_compile(ircMsgRegexString, PCRE_EXTENDED | PCRE_ANCHORED,
                               &errorString, &errorPos, NULL);
    /*ircJoinRegex =
     * pcre_compile(ircJoinRegexString,PCRE_EXTENDED|PCRE_ANCHORED,
     * &errorString, &errorPos, NULL);*/
    ircDPIRegex = pcre_compile(ircDPIRegexString, PCRE_MULTILINE,
                               &errorString, &errorPos, NULL);

    if (NULL != ircRegex && NULL != ircMsgRegex) {
        pcreInitialized = 1;
    }

    return pcreInitialized;
}


#if IRCDEBUG
static
int
ycDebugBinPrintf(
    uint8_t   *data,
    uint16_t   size)
{
    uint16_t loop;
    int      numPrinted = 0;

    if (0 == size) {
        return 0;
    }

    for (loop = 0; loop < size; loop++) {
        if (isprint(*(data + loop)) && !iscntrl(*(data + loop))) {
            printf("%c", *(data + loop));
        } else {
            printf(".");
        }
        if ('\n' == *(data + loop) || '\r' == *(data + loop)
            || '\0' == *(data + loop))
        {
            break;
        }
        numPrinted++;
    }

    return numPrinted;
}


#endif /* if IRCDEBUG */
