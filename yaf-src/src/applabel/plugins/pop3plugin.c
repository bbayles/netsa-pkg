/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  pop3plugin.c
 *
 *  this provides POP3 payload packet recognition for use within YAF
 *  It is based on RFC 1939 and some random limited packet capture.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Dan Ruef, Emily Ecoff
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
#include <payloadScanner.h>
#include <pcre.h>

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#define POP3DEBUG 0
#define POP3_PORT 110

YC_SCANNER_PROTOTYPE(pop3plugin_LTX_ycPop3ScanScan);

/**
 * the compiled regular expressions, and related
 * flags
 *
 */
static pcre        *pop3RegexApplabel = NULL;
#if YAF_ENABLE_HOOKS
static pcre        *pop3RegexRequest  = NULL;
static pcre        *pop3RegexResponse = NULL;
#endif

/* 1 if initialized; -1 if initialization failed */
static int pcreInitialized = 0;


/**
 * static local functions
 *
 */

static uint16_t
ycPop3ScanInit(
    void);

#if POP3DEBUG
static int
ycDebugBinPrintf(
    uint8_t   *data,
    uint16_t   size);
#endif /* if POP3DEBUG */

/**
 * pop3plugin_LTX_ycPop3ScanScan
 *
 * scans a given payload to see if it conforms to our idea of what POP3 traffic
 * looks like.
 *
 *
 *
 * @param argc NOT USED
 * @param argv NOT USED
 * @param payload pointer to the payload data
 * @param payloadSize the size of the payload parameter
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 0 for no match POP3_PORT_NUMBER (110) for a match
 *
 */
uint16_t
pop3plugin_LTX_ycPop3ScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    int      rc;
#define NUM_CAPT_VECTS 60
    int      vects[NUM_CAPT_VECTS];

    if (1 != pcreInitialized) {
        if (-1 == pcreInitialized || 0 == ycPop3ScanInit()) {
            return 0;
        }
    }

    rc = pcre_exec(pop3RegexApplabel, NULL, (char *)payload, payloadSize, 0,
                   0, vects, NUM_CAPT_VECTS);
    if (rc <= 0) {
        return 0;
    }

#if YAF_ENABLE_HOOKS
    if (rc == 2) {
        /* server side */
        yfHookScanPayload(flow, payload, payloadSize, pop3RegexResponse, 0,
                          111, POP3_PORT);
    } else {
        /* client side */
        yfHookScanPayload(flow, payload, payloadSize, pop3RegexRequest, 0,
                          110, POP3_PORT);
    }
#endif /* if YAF_ENABLE_HOOKS */

    return POP3_PORT;
}


/**
 * ycPop3ScanInit
 *
 * this initializes the PCRE expressions needed to search the payload for
 * POP3
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is complete correctly, 0 otherwise
 */
static uint16_t
ycPop3ScanInit(
    void)
{
#if YAF_ENABLE_HOOKS
    /* capture everything the client says */
    const char  pop3StringRequest[] =  "(?im)^[ \\t]*([!-~][ !-~]+)";

    /* capture the first line of each response */
    const char  pop3StringResponse[] = "(?m)^((?:\\+OK|-ERR)[ -~]*)";
#endif
    const char *errorString;
    int         errorPos;

    /* used to determine if this connection looks like POP3; capture the
     * response to distinguish the server from the client */
    const char  pop3StringApplabel[] =
        "(?i)^\\s*(?:(?:CAPA\\b|AUTH\\s(?:KERBEROS_V|GSSAPI|SKEY)|"
        "UIDL\\b|APOP\\s|USER\\s)|(\\+OK\\b|-ERR\\b))";

    pcreInitialized = 1;

    pop3RegexApplabel = pcre_compile(
        pop3StringApplabel, 0, &errorString, &errorPos, NULL);
    if (!pop3RegexApplabel) {
        /* g_debug("Failed to compile '%s'; %s at position %d", */
        /*         pop3StringApplabel, errorString, errorPos); */
        pcreInitialized = -1;
    }

#if YAF_ENABLE_HOOKS
    pop3RegexRequest = pcre_compile(
        pop3StringRequest, 0, &errorString, &errorPos, NULL);
    pop3RegexResponse = pcre_compile(
        pop3StringResponse, 0, &errorString, &errorPos, NULL);

    if (!pop3RegexRequest || !pop3RegexResponse) {
        pcreInitialized = -1;
    }

#if 0
    if (!pop3RegexRequest) {
        g_debug("Failed to compile '%s'; %s at position %d",
                pop3StringRequest, errorString, errorPos);
    }
    if (!pop3RegexResponse) {
        g_debug("Failed to compile '%s'; %s at position %d",
                pop3StringResponse, errorString, errorPos);
    }
#endif  /* 0 */
#endif  /* YAF_ENABLE_HOOKS */

    return (1 == pcreInitialized);
}


#if POP3DEBUG
static int
ycDebugBinPrintf(
    uint8_t   *data,
    uint16_t   size)
{
    uint16_t loop;
    int      numPrinted = 0;

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
#endif /* if POP3DEBUG */
