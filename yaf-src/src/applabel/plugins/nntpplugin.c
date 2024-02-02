/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  nntpplugin.c
 *
 *  this provides NNTP payload packet recognition for use within YAF
 *  It is based on RFC 977 and some random limited packet capture.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Ecoff
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

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#include <pcre.h>


#define NNTP_PORT 119

YC_SCANNER_PROTOTYPE(nntpplugin_LTX_ycNNTPScanScan);

/**
 * the compiled regular expressions, and related
 * flags
 *
 */
static pcre        *nntpCommandRegex = NULL;
static pcre        *nntpResponseRegex = NULL;
static unsigned int pcreInitialized = 0;


/**
 * static local functions
 *
 */
static uint16_t
ycNNTPScanInit(
    void);

/*static int ycDebugBinPrintf(uint8_t *data, uint16_t size);*/


/**
 * nntpplugin_LTX_ycNNTPScanScan
 *
 * scans a given payload to see if it conforms to our idea of what NNTP traffic
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
 * @return 0 for no match NNTP_PORT_NUMBER (119) for a match
 *
 */
uint16_t
nntpplugin_LTX_ycNNTPScanScan(
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
        if (0 == ycNNTPScanInit()) {
            return 0;
        }
    }

    rc = pcre_exec(nntpCommandRegex, NULL, (char *)payload, payloadSize,
                   0, 0, vects, NUM_CAPT_VECTS);

    if (rc <= 0) {
        rc = pcre_exec(nntpResponseRegex, NULL, (char *)payload,
                       payloadSize, 0, 0, vects, NUM_CAPT_VECTS);
    }

    /** at some point in the future, this is the place to extract protocol
     *  information like message targets and join targets, etc.*/
#if YAF_ENABLE_HOOKS
    if (rc > 0) {
        yfHookScanPayload(flow, payload, payloadSize, nntpCommandRegex, 0,
                          173, NNTP_PORT);
        yfHookScanPayload(flow, payload, payloadSize, nntpResponseRegex, 0,
                          172, NNTP_PORT);
    }
#endif /* if YAF_ENABLE_HOOKS */

    if (rc > 0) {
        return NNTP_PORT;
    }

    return 0;
}


/**
 * ycNNTPScanInit
 *
 * this initializes the PCRE expressions needed to search the payload for
 * NNTP
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is complete correctly, 0 otherwise
 */
static
uint16_t
ycNNTPScanInit(
    void)
{
    const char *errorString;
    int         errorPos;
    const char  nntpResponseRegexString[] =
        "(([1-5]([0-4]|[8-9])[0-9] )+"
        ".* (text follows)?[\\r\\n]?"
        "(.* \\r\\n)?)\\b";
    const char nntpCommandRegexString[] =
        "^((ARTICLE|GROUP|HELP|IHAVE|LAST"
        "|LIST|NEWGROUPS|NEWNEWS|NEXT|POST|QUIT"
        "|SLAVE|STAT|MODE) ?[ a-zA-Z0-9.]*)[ \\r\\n]";

    nntpCommandRegex = pcre_compile(nntpCommandRegexString, 0, &errorString,
                                    &errorPos, NULL);
    nntpResponseRegex = pcre_compile(nntpResponseRegexString,
                                     PCRE_EXTENDED | PCRE_ANCHORED,
                                     &errorString, &errorPos, NULL);

    if (NULL != nntpCommandRegex && NULL != nntpResponseRegex) {
        pcreInitialized = 1;
    }

    return pcreInitialized;
}


#if 0
static int
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
            || '\0' == (data + loop))
        {
            break;
        }
        numPrinted++;
    }

    return numPrinted;
}
#endif /* 0 */
