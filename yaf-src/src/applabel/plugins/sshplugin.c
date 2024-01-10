/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  sshplugin.c
 *
 *  This recognizes SSH packets
 *
 *  ------------------------------------------------------------------------
 *  Authors: Steven Ibarra
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

/*
 * the compiled regular expressions
 */
static pcre *sshVersionRegex = NULL;

/* 1 if initialized; -1 if initialization failed */
static int   pcreInitialized = 0;

YC_SCANNER_PROTOTYPE(sshplugin_LTX_ycSshScanScan);

/**
 * SSH Declarations are refreced from paylloadScanner.h
*/


/**
 * static local functions
 *
 */

static uint16_t
ycSshScanInit(
    void);

/**
 * sshplugin_LTX_ycSshScanScan
 *
 * scans a given payload to see if it conforms to our idea of what SSH traffic
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
 * @return 0 for no match SSH_PORT_NUMBER (22) for a match
 *
 */
uint16_t
sshplugin_LTX_ycSshScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#define NUM_CAPT_VECTS 60
    int vects[NUM_CAPT_VECTS];
    int rc;

    if (1 != pcreInitialized) {
        if (-1 == pcreInitialized || 0 == ycSshScanInit()) {
            return 0;
        }
    }

    rc = pcre_exec(sshVersionRegex, NULL, (char *)payload, payloadSize, 0,
                   0, vects, NUM_CAPT_VECTS);
    if (rc <= 0) {
        return 0;
    }

#if YAF_ENABLE_HOOKS
    uint32_t offset = 0;
    uint8_t  message_code = 0;
    uint32_t algo_length = 0;
    uint32_t packet_length = 0;
    uint32_t available_bytes = 0;
    uint32_t host_key_length = 0;
    uint32_t host_key_offset = 0;
    gboolean host_key_found = FALSE;

    if (rc == 2) {
        /* Server and Client*/
        yfHookScanPayload(flow, payload, payloadSize, sshVersionRegex, 0,
                          YF_SSH_VERSION, SSH_PORT_NUMBER);
    }

    /*
     * Use the offset of the end of the regex to determine the start of the
     * Binary Protocol (RFC4253 Section 6)
     */
    offset = vects[1];

    /* Look for KEXINIT message, ignoring transport messages (2-19) */
    for (;; ) {
        packet_length = ntohl(*(uint32_t *)(payload + offset));
        if ((packet_length + offset) >= payloadSize) {
            return SSH_PORT_NUMBER;
        }
        available_bytes = packet_length;

        /* Move the offset over Packet Length(4) and Padding Length(1);
         * subtract the Padding Length from available_bytes */
        offset += 5; available_bytes -= 1;

        /* We are expecting a Key Exchange Init Message (RFC 4253 Section 7) */
        message_code = *(payload + offset);
        if (message_code == SSH2_MSG_KEXINIT) {
            break;
        }
        if (message_code > SSH2_MSG_KEXINIT ||
            message_code == SSH_MSG_DISCONNECT ||
            message_code == 0)
        {
            return SSH_PORT_NUMBER;
        }
        /* Go to next packet for a message_code < 20 */
        offset += available_bytes;
    }

    /* Skip the KEXINIT mesage code(1) and the cookie (16 random bytes) */
    offset += 17; available_bytes -= 17;

    /* Note: We store the locations of algorithms' lengths in the
     * flowContext->dpi[] array since storing the entire text exceeds the
     * length that YAF permits DPI code to store. */

    /* Kex algorithms */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    yfHookScanPayload(flow, payload, 1, NULL, offset,
                      YF_SSH_KEX_ALGO, SSH_PORT_NUMBER);
    /* End of Algorith String */
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Server host key algorithms */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    yfHookScanPayload(flow, payload, 1, NULL, offset,
                      YF_SSH_SERVER_HOST_KEY_ALGO, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Encryption algorithms client to server */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    yfHookScanPayload(flow, payload, 1, NULL, offset,
                      YF_SSH_ENCRYPTION_ALGO_CLI_SRV, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Encryption algorithms for the server to client response */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    yfHookScanPayload(flow, payload, 1, NULL, offset,
                      YF_SSH_ENCRYPTION_ALGO_SRV_CLI, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* MAC algorithms client to server */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    yfHookScanPayload(flow, payload, 1, NULL, offset,
                      YF_SSH_MAC_ALGO_CLI_SRV, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* MAC algorithms server to client */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    yfHookScanPayload(flow, payload, 1, NULL, offset,
                      YF_SSH_MAC_ALGO_SRV_CLI, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Compression algorithms client to server */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    yfHookScanPayload(flow, payload, 1, NULL, offset,
                      YF_SSH_COMPRESS_ALGO_CLI_SRV, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Compression algorithms server to client */
    algo_length = ntohl(*(uint32_t *)(payload + offset));
    if (algo_length > available_bytes) {
        return SSH_PORT_NUMBER;
    }
    yfHookScanPayload(flow, payload, 1, NULL, offset,
                      YF_SSH_COMPRESS_ALGO_SRV_CLI, SSH_PORT_NUMBER);
    offset += 4 + algo_length; available_bytes -= 4 + algo_length;

    /* Finished with KEXINIT packet; move to next packet start */
    offset += available_bytes;

    /* Look for the key exchange messages, codes 30--34 */
    while (!host_key_found) {
        packet_length = ntohl(*(uint32_t *)(payload + offset));
        if ((packet_length + offset) >= payloadSize) {
            return SSH_PORT_NUMBER;
        }
        available_bytes = packet_length;
        offset += 5; available_bytes -= 1;

        /* Check for key exchange messages */
        message_code = *(payload + offset);
        switch (message_code) {
          case SSH_MSG_KEXDH_INIT:
          case SSH_MSG_KEX_DH_GEX_REQUEST:
            /* Client side messages; store the code in the offset location and
             * return */
            yfHookScanPayload(flow, payload, 1, NULL, message_code,
                              YF_SSH_CLIENT_KEX_REQUEST, SSH_PORT_NUMBER);
            return SSH_PORT_NUMBER;

          case SSH_MSG_KEX_DH_GEX_REPLY:
            /* Server side that definitely holds the host key */
            host_key_found = TRUE;
          /* FALLTHROUGH */
          case SSH_MSG_KEX_DH_GEX_GROUP:
            /* Server side that may hold the host key; cache the location.
             * Note that the offset is on the message_code so its value can be
             * checked by ydpProcessDPI(). */
            host_key_offset = offset;
            offset += 1; available_bytes -= 1;
            host_key_length = ntohl(*(uint32_t *)(payload + offset));
            if (host_key_length > available_bytes) {
                return SSH_PORT_NUMBER;
            }
            break;

          case 0:
          case SSH_MSG_DISCONNECT:
            /* give up */
            return SSH_PORT_NUMBER;

          case SSH2_MSG_NEWKEYS:
            /* stop looking */
            host_key_found = TRUE;
            break;

          default:
            if (message_code >= SSH2_MSG_KEXINIT) {
                /* stop looking */
                host_key_found = TRUE;
            }
            /* else ignore any message that uses codes 2-19 */
            break;
        }

        /* move to the next packet */
        offset += available_bytes;
    }

    if (host_key_offset) {
        yfHookScanPayload(flow, payload, 1, NULL, host_key_offset,
                          YF_SSH_HOST_KEY, SSH_PORT_NUMBER);
    }
#endif /* YAF_ENABLE_HOOKS */

    return SSH_PORT_NUMBER;
}

/**
 * ycSshScanInit
 *
 * this initializes the PCRE expressions needed to search the payload for
 * SSH
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is complete correctly, 0 otherwise
 */
static uint16_t
ycSshScanInit(
    void)
{
    const char  sshStringVersion[] =
        "(?m)^(SSH-\\d\\.\\d+-[ -~]{1,255})\\r?\\n";
    pcreInitialized = 1;
    const char *errorString;
    int         errorPos;

    sshVersionRegex = pcre_compile(
        sshStringVersion, 0, &errorString, &errorPos, NULL);
    if (!sshVersionRegex) {
        /* g_debug("Failed to compile '%s'; %s at position %d", */
        /*         sshStringVersion, errorString, errorPos); */
        pcreInitialized = -1;
    }

    return (1 == pcreInitialized);
}
