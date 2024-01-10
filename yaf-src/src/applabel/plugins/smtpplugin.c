/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  smtpplugin.c
 *
 *  this is a protocol classifier for the simple mail transport protocol (SMTP)
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
#include <payloadScanner.h>
#include <pcre.h>

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#define SMTP_PORT_NUMBER 25

/*  Size for PCRE capture vector. */
#define NUM_CAPT_VECTS 60

/*  Max number of separate emails; note that these fill space in the DPI
 *  array that could be used by other DPI info. */
#define SMTP_MAX_EMAILS 5

/*  If the <CRLF>.<CRLF> to close a message is within this number of bytes of
 *  the payloadSize, assume the only remaining SMTP command from the client is
 *  "QUIT<CRLF>". */
#define YF_BYTES_AFTER_DOT  12

YC_SCANNER_PROTOTYPE(smtpplugin_LTX_ycSMTPScanScan);

static pcre        *smtpRegexApplabel = NULL;

#if YAF_ENABLE_HOOKS
static pcre        *smtpRegexBdatLast = NULL;
static pcre        *smtpRegexBlankLine = NULL;
static pcre        *smtpRegexDataBdat = NULL;
static pcre        *smtpRegexEndData = NULL;

static pcre        *smtpRegexEnhanced = NULL;
static pcre        *smtpRegexFilename = NULL;
static pcre        *smtpRegexFrom = NULL;
static pcre        *smtpRegexHeader = NULL;
static pcre        *smtpRegexHello = NULL;
static pcre        *smtpRegexResponse = NULL;
static pcre        *smtpRegexSize = NULL;
static pcre        *smtpRegexStartTLS = NULL;
static pcre        *smtpRegexSubject = NULL;
static pcre        *smtpRegexTo = NULL;
static pcre        *smtpRegexURL = NULL;
#endif  /* YAF_ENABLE_HOOKS */

static unsigned int pcreInitialized = 0;

static uint16_t
ycSMTPScanInit(
    void);

/**
 * smtpplugin_LTX_ycSMTPScanScan
 *
 * returns SMTP_PORT_NUMBER if the passed in payload matches a service location
 * protocol packet
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * @return SMTP_PORT_NUMBER otherwise 0
 */
uint16_t
smtpplugin_LTX_ycSMTPScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    int rc;
    int vects[NUM_CAPT_VECTS];

    if (0 == pcreInitialized) {
        if (0 == ycSMTPScanInit()) {
            return 0;
        }
    }

    rc = pcre_exec(smtpRegexApplabel, NULL, (char *)payload, payloadSize,
                   0, 0, vects, NUM_CAPT_VECTS);

#if YAF_ENABLE_HOOKS
    /* If pcre_exec() returns 1 this is the client-side of the conversation
     * and if 2 it is the server-side. */
    if (rc == 1) {
        /*
         * To limit the regexes to searching only the relative parts of the
         * payload, we first find the positions of those relative parts, while
         * being aware multiple messages may be sent during a single
         * connection.
         *
         * msgSplits[i] is start of the area where STMP commands are allowed
         * and also marks the end of message i-1.
         * msgData[i] is boundary between STMP commands and the message.
         * msgBegin[i] equals msgData[i] unless DATA/BDAT was not seen, in
         * which case it equals msgSplit[i].
         * hdrEnd[i] is the blank line beween the msg's header and body.
         */
        uint32_t msgSplits[1 + SMTP_MAX_EMAILS];
        uint32_t msgData[SMTP_MAX_EMAILS];
        uint32_t msgBegin[SMTP_MAX_EMAILS];
        uint32_t hdrEnd[SMTP_MAX_EMAILS];
        int msgIndex = 0;
        int tmprc;
        int i;

        msgSplits[0] = 0;

        for (;;) {
            /* look for DATA or BDAT */
            tmprc = pcre_exec(smtpRegexDataBdat, NULL, (char *)payload,
                              payloadSize, msgSplits[msgIndex],
                              0, vects, NUM_CAPT_VECTS);
            if (tmprc <= 0) {
                /* DATA/BDAT not found; if there are more than
                 * YF_BYTES_AFTER_DOT bytes of payload after the end of the
                 * last message, assume the payload contains the start of
                 * another "MAIL FROM:..." */
                if (payloadSize - msgSplits[msgIndex] > YF_BYTES_AFTER_DOT) {
                    msgData[msgIndex] = payloadSize;
                    msgBegin[msgIndex] = msgSplits[msgIndex];
                    hdrEnd[msgIndex] = payloadSize;
                    msgSplits[++msgIndex] = payloadSize;
                }
                break;
            }

            msgData[msgIndex] = msgBegin[msgIndex] = vects[1];
            /* assume email message goes to end of payload */
            msgSplits[msgIndex + 1] = payloadSize;

            if (tmprc == 2) {
                /* saw "BDAT <LENGTH>(| +LAST)"; if the character before
                 * vects[3] is not 'T', search for the last BDAT blob */
                if ('T' != payload[vects[3] - 1]) {
                    tmprc = pcre_exec(smtpRegexBdatLast, NULL, (char *)payload,
                                      payloadSize, msgData[msgIndex], 0,
                                      vects, NUM_CAPT_VECTS);
                }

                if (tmprc > 1) {
                    /* parse the length of the last BDAT blob to find the end
                     * of the message */
                    unsigned long len;
                    char *ep = (char *)payload;

                    errno = 0;
                    len = strtoul((char *)payload + vects[2], &ep, 10);
                    if (len > 0 || (0 == errno && ep != (char *)payload)) {
                        msgSplits[msgIndex + 1] =
                            MIN(vects[1] + len, payloadSize);
                    }
                }
            } else {
                /* saw DATA; search for <CRLF>.<CRLF> to find the end of
                 * msg */
                tmprc = pcre_exec(smtpRegexEndData, NULL, (char *)payload,
                                  payloadSize, msgData[msgIndex], 0,
                                  vects, NUM_CAPT_VECTS);
                if (tmprc > 0) {
                    msgSplits[msgIndex + 1] = vects[1];
                }
            }

            /* find the separator between headers and body; if not found, set
             * it to the next message split */
            tmprc = pcre_exec(smtpRegexBlankLine, NULL, (char *)payload,
                              msgSplits[msgIndex + 1], msgData[msgIndex], 0,
                              vects, NUM_CAPT_VECTS);
            if (tmprc > 0) {
                hdrEnd[msgIndex] = vects[1];
            } else {
                hdrEnd[msgIndex] = msgSplits[msgIndex + 1];
            }

            ++msgIndex;
            if (msgIndex >= SMTP_MAX_EMAILS ||
                msgSplits[msgIndex] >= payloadSize)
            {
                break;
            }
        }

        /* Capture headers in order of importance since we may run out of room
         * in the DPI array */

        /* Check for hello, from, to, and subject in each message */
        for (i = 0; i < msgIndex && msgSplits[i] < payloadSize; ++i) {
            /* store the end of the message as a separator if it not at or
             * near the end of the payload */
            if (msgSplits[i+1] + YF_BYTES_AFTER_DOT < payloadSize) {
                yfHookScanPayload(flow, payload, 2, NULL, msgSplits[i+1], 38,
                                  SMTP_PORT_NUMBER);
            }

            yfHookScanPayload(flow, payload, msgData[i], smtpRegexHello,
                              msgSplits[i], 26, SMTP_PORT_NUMBER);
            yfHookScanPayload(flow, payload, msgData[i], smtpRegexFrom,
                              msgSplits[i], 33, SMTP_PORT_NUMBER);
            yfHookScanPayload(flow, payload, msgData[i], smtpRegexTo,
                              msgSplits[i], 32, SMTP_PORT_NUMBER);
            yfHookScanPayload(flow, payload, hdrEnd[i], smtpRegexSubject,
                              msgBegin[i], 31, SMTP_PORT_NUMBER);
        }

        /* get filenames and urls throughout the payload */
        yfHookScanPayload(flow, payload, payloadSize,
                         smtpRegexFilename, 0, 34, SMTP_PORT_NUMBER);
        yfHookScanPayload(flow, payload, payloadSize,
                         smtpRegexURL, 0, 35, SMTP_PORT_NUMBER);

        /* look for starttls, msg size, and headers per message */
        for (i = 0; i < msgIndex && msgSplits[i] < payloadSize; ++i) {
            yfHookScanPayload(flow, payload, msgData[i], smtpRegexStartTLS,
                             msgSplits[i], 29, SMTP_PORT_NUMBER);
            yfHookScanPayload(flow, payload, msgData[i], smtpRegexSize,
                             msgSplits[i], 28, SMTP_PORT_NUMBER);
            yfHookScanPayload(flow, payload, hdrEnd[i], smtpRegexHeader,
                             msgBegin[i], 36, SMTP_PORT_NUMBER);
        }
    } else if (rc > 0 || flow->appLabel == SMTP_PORT_NUMBER) {
        yfHookScanPayload(flow, payload, payloadSize, smtpRegexResponse, 0, 30,
                          SMTP_PORT_NUMBER);
        yfHookScanPayload(flow, payload, payloadSize, smtpRegexEnhanced, 0, 27,
                          SMTP_PORT_NUMBER);
    }
#endif /* if YAF_ENABLE_HOOKS */

    if (rc > 0 || flow->appLabel == SMTP_PORT_NUMBER) {
        return SMTP_PORT_NUMBER;
    }

    return 0;
}


static pcre *
ydPcreCompile(
    const char  *regex,
    int          options)
{
    const char *errorString;
    int         errorOffset;
    pcre       *compiled;

    compiled = pcre_compile(regex, options, &errorString, &errorOffset, NULL);
    if (NULL == compiled) {
        g_error("Compiling regular expression returned error %s"
                " at offset %d of \"%s\"",
                errorString, errorOffset, regex);
    }

    return compiled;
}


/**
 * ycSMTPScanInit
 *
 * this initializes the PCRE expressions needed to search the payload for SMTP
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is complete correctly, 0 otherwise
 */
static
uint16_t
ycSMTPScanInit(
    void)
{
#if YAF_ENABLE_HOOKS
    /* many of these regexes use "[\\t -~]" to denote printable ASCII with
     * whitespace and "[!-~]" for printable ASCII without whitespace */

    /* this matches an email address */
#define EMAIL_ADDR  ""                          \
        "(?:@[-A-Z0-9.](?:,@[-A-Z0-9.])*:)?"    \
        "(?:[!#-'*+\\-./0-9=?@A-Z^_`a-z{|}~]+|" \
        "\"(?:[ !#-\\[\\]-~]+|\\\\[ -~])*\")"

    /* a regex to use in mail headers (fields) that matches a single
     * whitespace character on a line or a complete folded header */
#define FOLD_SPACE  "(?:[ \\t]|\\r\\n[ \\t])"

    /* a regex to match a single char in a field-name. RFC2822 2.2: field-name
     * is any ASCII from decimal 33(!) to 126(~) inclusive except 58(:) */
#define FIELD_NAME  "[!-9;-~]"
    /* a regex to use in fields that matches a complete folder header or a
     * single character in a field-body: printable ascii, space, tab */
#define FIELD_BODY  "(?:[\\t -~]|\\r\\n[ \\t])"

    const char  smtpStringDataBdat[] =
        "(?im)^(?:DATA|BDAT +(\\d+(?:| +LAST)))\\r\\n";
    const char  smtpStringBdatLast[] =
        "(?im)^BDAT +(\\d+) +LAST\\r\\n";
    const char  smtpStringEndData[] = "\\r\\n\\.\\r\\n";
    const char  smtpStringBlankLine[] = "\\r\\n\\r\\n";

    const char  smtpStringHello[] =
        "(?im)^((?:HELO|EHLO)(?: [!-~]+)*)\\r\\n";
    const char  smtpStringSize[] = "(?im)^MAIL FROM:.+ SIZE=(\\d+)\\s";
    const char  smtpStringStartTLS[] = "(?im)^STARTTLS\\r\\n";
    /* limit responses to the 220 welcome banner and error codes */
    const char  smtpStringResponse[] =
        "(?m)^((?:220|[45][0-5][0-9])[- ][\\t -~]*)\\r\\n";

    const char  smtpStringTo[] =
        "(?im)^RCPT TO: ?<?(" EMAIL_ADDR ")>?(?: |\\r\\n)";
    const char  smtpStringFrom[] =
        "(?im)^MAIL FROM: ?<?(" EMAIL_ADDR ")>?(?: |\\r\\n)";

    const char  smtpStringHeader[] =
        "(?m)^(" FIELD_NAME "+:" FIELD_BODY "+)";
    const char  smtpStringSubject[] =
        "(?im)^Subject:" FOLD_SPACE "*(" FIELD_BODY "+)";
    /* a filename may be in double quotes (which supports \-quoting of a
     * character) or unquoted with a restricted character set */
    const char  smtpStringFilename[] =
        "(?im)^Content-Disposition:" FIELD_BODY "*;" FOLD_SPACE "*filename=("
        "\"(?:[\\t !#-\\[\\]-~]|\\\\.|\\r\\n[\\t ])*\"|"
        "[!#-'*+\\-./0-9=?A-Z^_`a-z{|}~]+"
        ")";

    const char  smtpStringURL[] =
        "https?://(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&/=]*)";

    const char  smtpStringEnhanced[] = "(ESMTP [_a-zA-Z0-9., @#]+)\\b";
#endif  /* YAF_ENABLE_HOOKS */

    const char  smtpStringApplabel[] =
        "(?i)^\\s*(?:(?:HE|EH)LO\\b|MAIL FROM:|RCPT TO:|(2[25]0[ -].*E?SMTP))";

    smtpRegexApplabel = ydPcreCompile(smtpStringApplabel, 0);
    if (NULL != smtpRegexApplabel) {
        pcreInitialized = 1;
    }
#if !YAF_ENABLE_HOOKS
    return pcreInitialized;
#else
    smtpRegexBdatLast = ydPcreCompile(smtpStringBdatLast, 0);
    smtpRegexBlankLine = ydPcreCompile(smtpStringBlankLine, 0);
    smtpRegexDataBdat = ydPcreCompile(smtpStringDataBdat, 0);
    smtpRegexEndData = ydPcreCompile(smtpStringEndData, 0);

    smtpRegexEnhanced = ydPcreCompile(smtpStringEnhanced, 0);
    smtpRegexFilename = ydPcreCompile(smtpStringFilename, 0);
    smtpRegexFrom = ydPcreCompile(smtpStringFrom, 0);
    smtpRegexHeader = ydPcreCompile(smtpStringHeader, 0);

    smtpRegexHello = ydPcreCompile(smtpStringHello, 0);
    smtpRegexResponse = ydPcreCompile(smtpStringResponse, 0);
    smtpRegexSize = ydPcreCompile(smtpStringSize, 0);
    smtpRegexStartTLS = ydPcreCompile(smtpStringStartTLS, 0);

    smtpRegexSubject = ydPcreCompile(smtpStringSubject, 0);
    smtpRegexTo = ydPcreCompile(smtpStringTo, 0);
    smtpRegexURL = ydPcreCompile(smtpStringURL, 0);

    return pcreInitialized;
#endif  /* #else of #if !YAF_ENABLE_HOOKS */
}
