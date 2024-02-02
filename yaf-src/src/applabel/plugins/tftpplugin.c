/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  tftpplugin.c
 *
 *  this is a protocol classifier for the Trivial File Transfer protocol
 *  (TFTP)
 *
 *  TFTP is a very simple protocol used to transfer files.
 *
 *  rfc 1350  href="http://www.ietf.org/rfc/rfc1350.txt"
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

#include <arpa/inet.h>
#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#include <pcre.h>

#define TFTP_PORT_NUMBER 69

YC_SCANNER_PROTOTYPE(tftpplugin_LTX_ycTFTPScanScan);


static pcre        *tftpRegex = NULL;
static unsigned int pcreInitialized = 0;

/**
 * static local functions
 *
 */
static uint16_t
ycTFTPScanInit(
    void);

/**
 * tftpplugin_LTX_ycTFTPScanScan
 *
 * returns TFTP_PORT_NUMBER if the passed in payload matches
 * a trivial file transfer protocol packet
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * return 0 if no match
 */
uint16_t
tftpplugin_LTX_ycTFTPScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#define NUM_CAPT_VECTS 60
    int      vects[NUM_CAPT_VECTS];
    uint32_t offset = 0;
    int      rc;
    uint16_t tempVar = 0;
    uint16_t opcode;

    if (payloadSize < 3) {
        return 0;
    }

    if (0 == pcreInitialized) {
        if (0 == ycTFTPScanInit()) {
            return 0;
        }
    }

    opcode = ntohs(*(uint16_t *)payload);
    offset += 2;

    if ((opcode > 5) || (opcode == 0)) {
        return 0;
    }

    if ((opcode == 1) || (opcode == 2)) {
        /* RRQ or WRQ */
        rc = pcre_exec(tftpRegex, NULL, (char *)payload, payloadSize,
                       0, 0, vects, NUM_CAPT_VECTS);
        if (rc <= 0) {
            return 0;
        }

#if YAF_ENABLE_HOOKS
        if (rc > 1) {
            uint8_t fileLength = 0;
            fileLength = vects[3] - vects[2];
            yfHookScanPayload(flow, payload, fileLength, NULL,
                              vects[2], 69, TFTP_PORT_NUMBER);
        }
        if (rc > 2) {
            tempVar = vects[5] - vects[4];  /*len of mode*/
            yfHookScanPayload(flow, payload, tempVar, NULL, vects[4], 70,
                              TFTP_PORT_NUMBER);
        }
#endif /* if YAF_ENABLE_HOOKS */
    } else if ((opcode == 3) || (opcode == 4)) {
        /* DATA or ACK packet */
        tempVar = ntohs(*(uint16_t *)(payload + offset));
        if (tempVar != 1) {
            return 0;
        }
    } else if (opcode == 5) {
        /* Error Packet */
        tempVar = ntohs(*(uint16_t *)(payload + offset));
        /* Error codes are 1-7 */
        if (tempVar > 8) {
            return 0;
        }
    }

    return TFTP_PORT_NUMBER;
}


/**
 * ycTFTScanInit
 *
 * this initializes the PCRE expressions needed to search the payload for
 * TFTP
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is complete correctly, 0 otherwise
 */
static
uint16_t
ycTFTPScanInit(
    void)
{
    const char *errorString;
    int         errorPos;

    const char  tftpRegexString[] = "\\x00[\\x01|\\x02]([-a-zA-Z1-9. ]+)"
        "\\x00(?i)(netascii|octet|mail)\\x00";

    tftpRegex = pcre_compile(tftpRegexString, PCRE_ANCHORED, &errorString,
                             &errorPos, NULL);

    if (NULL != tftpRegex) {
        pcreInitialized = 1;
    } else {
        g_debug("errpos is %d", errorPos);
    }

    return pcreInitialized;
}
