/**
 * @INTERNAL
 *
 * @file pop3plugin.c
 *
 * this provides POP3 payload packet recognition for use within YAF
 * It is based on RFC 1939 and some random limited packet capture.
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2007-2023 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Dan Ruef, Emily Ecoff
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the YAF system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
 ** Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
 **
 ** NO WARRANTY
 **
 ** ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
 ** PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
 ** PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
 ** "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
 ** KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
 ** MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
 ** OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
 ** SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
 ** TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
 ** WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
 ** LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
 ** CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
 ** CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
 ** DELIVERABLES UNDER THIS LICENSE.
 **
 ** Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
 ** Mellon University, its trustees, officers, employees, and agents from
 ** all claims or demands made against them (and any related losses,
 ** expenses, or attorney's fees) arising out of, or relating to Licensee's
 ** and/or its sub licensees' negligent use or willful misuse of or
 ** negligent conduct or willful misconduct regarding the Software,
 ** facilities, or other rights or assistance granted by Carnegie Mellon
 ** University under this License, including, but not limited to, any
 ** claims of product liability, personal injury, death, damage to
 ** property, or violation of any laws or regulations.
 **
 ** Carnegie Mellon University Software Engineering Institute authored
 ** documents are sponsored by the U.S. Department of Defense under
 ** Contract FA8721-05-C-0003. Carnegie Mellon University retains
 ** copyrights in all material produced under this contract. The U.S.
 ** Government retains a non-exclusive, royalty-free license to publish or
 ** reproduce these documents, or allow others to do so, for U.S.
 ** Government purposes only pursuant to the copyright license under the
 ** contract clause at 252.227.7013.
 **
 ** @OPENSOURCE_HEADER_END@
 ** ------------------------------------------------------------------------
 *
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
#   define NUM_CAPT_VECTS 60
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
