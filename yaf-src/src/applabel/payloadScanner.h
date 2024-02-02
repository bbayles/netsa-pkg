/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  playloadScanner.h
 *  This defines the interface to the payload scanner functions
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



#ifndef PAYLOAD_SCANNER_H_
#define PAYLOAD_SCANNER_H_

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>
/**
 * SSH Declarations
 * Refrence sshplugin.c and dpacketplugin.c to find
 * the implementation of the following definitions.
*/

/* IDs used by yfDPIData_t->dpacketID */
/* SSH List of Key Exchange Algorithms */
#define YF_SSH_KEX_ALGO                 20
/* SSH List of Host Key Algorithms */
#define YF_SSH_SERVER_HOST_KEY_ALGO     21
/* SSH List of Encryption Algorithms Client to Server */
#define YF_SSH_ENCRYPTION_ALGO_CLI_SRV  22
/* SSH List of MAC Algorithms Client to Server */
#define YF_SSH_MAC_ALGO_CLI_SRV         23
/* SSH List of Compression Algorithms Client to Server */
#define YF_SSH_COMPRESS_ALGO_CLI_SRV    24
/* SSH List of Encryption Algorithms Server to Client */
#define YF_SSH_ENCRYPTION_ALGO_SRV_CLI  25
/* SSH List of MAC Algorithms Server to Client */
#define YF_SSH_MAC_ALGO_SRV_CLI         26
/* SSH List of Compression Algorithms Server to Client */
#define YF_SSH_COMPRESS_ALGO_SRV_CLI    27
/* SSH Host Key */
#define YF_SSH_HOST_KEY                 28
/* SSH Version reported in initial packet */
#define YF_SSH_VERSION                  29
/* Client's KEX Request value */
#define YF_SSH_CLIENT_KEX_REQUEST       30

/* Values defined in the SSH RFCs. For a complete list:
 * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml */

/* Values between 1 and 19 are transport layer messages */
#define SSH_MSG_DISCONNECT              1

/* Key exchange initialization */
#define SSH2_MSG_KEXINIT                20
#define SSH2_MSG_NEWKEYS                21

/*
 * To find the message containing the host key, examine the message from the
 * client after the KEXINIT message.  Per RFC 4253 Section 8, if the client
 * sends KEXDH_INIT (or ECDH_INIT), the server sends the host key in the
 * KEXDH_REPLY (or ECDH_REPLY) message.  Per RFC 4419, if the client sends
 * group exchange init (KEX_DH_GEX_REQUEST), the server responds with
 * KEX_DH_GEX_GROUP, the client responds with MSG_KEX_DH_GEX_INIT (32), and
 * the server responds with KEX_DH_GEX_REPLY which contains the host key.
 */
#define SSH_MSG_KEXDH_INIT          30
#define SSH_MSG_KEXDH_REPLY         31
#define SSH2_MSG_KEX_ECDH_INIT      30
#define SSH2_MSG_KEX_ECDH_REPLY     31
#define SSH_MSG_KEX_DH_GEX_REQUEST  34
#define SSH_MSG_KEX_DH_GEX_GROUP    31
#define SSH_MSG_KEX_DH_GEX_REPLY    33

#define SSH_PORT_NUMBER 22

/**
 * End of the SSH declarations
*/

/**
 * SSL Declarations
 * Refrence tlsplugin.c and dpacketplugin.c to find
 * the implementation of the following definitions. 
 * 
*/

/* IDs used by yfDPIData_t->dpacketID */
/* sslClientVersion */
#define YF_SSL_CLIENT_VERSION   88
/* sslServerCipher */
#define YF_SSL_SERVER_CIPHER    89
/* sslCompressionMethod */
#define YF_SSL_COMPRESSION      90
/* sslCipherList */
#define YF_SSL_CIPHER_LIST      91
/* sslCipherList in SSL v2 */
#define YF_SSL_V2_CIPHER_LIST   92
/* offset of the start of a certificate */
#define YF_SSL_CERT_START       93
/* sslRecordVersion */
#define YF_SSL_RECORD_VERSION   94
/* sslServerName */
#define YF_SSL_SERVER_NAME      95
/* location of eliptic curve values */
#define YF_SSL_ELIPTIC_CURVE    96
/* location of eliptic curve point format list */
#define YF_SSL_ELIPTIC_FORMAT   97
/* ssl version? */
#define YF_SSL_VERSION          99
/* location of the client extension list */
#define YF_SSL_CLIENT_EXTENSION 100
/* location of the server extension list */
#define YF_SSL_SERVER_EXTENSION 101
/* the server version */
#define YF_SSL_SERVER_VERSION   102

/**
 * End of SSL Declarations
*/


/*
 *  Defines the prototype signature of the function that each appLabel plug-in
 *  function must define.  The function scans the payload and returns an
 *  appLabel or returns 0 if the payload does not match its rules.
 *
 *  The function's parameters are:
 *
 *  -- argc number of string arguments in argv
 *  -- argv string arguments for this plugin (first two are library
 *         name and function name)
 *  -- payload the packet payload
 *  -- payloadSize size of the packet payload
 *  -- flow a pointer to the flow state structure
 *  -- val a pointer to biflow state (used for forward vs reverse)
 *
 *  Adding the following to a plugin's C code ensures that the plugin's
 *  function, "file_LTX_functionScan", matches this signature:
 *
 *  @include "../payloadScanner.h"
 *  YC_SCANNER_PROTOTYPE(file_LTX_functionScan);
 *
 */
#define YC_SCANNER_PROTOTYPE(_func_name_) \
    uint16_t _func_name_(                 \
        int argc,                         \
        char *argv[],                     \
        const uint8_t * payload,          \
        unsigned int payloadSize,         \
        yfFlow_t * flow,                  \
        yfFlowVal_t * val)


/* if this is a power of 2, then the hash used for the sparse array is
 * (every so slightly) more efficient */
#define MAX_PAYLOAD_RULES 1024
#define LINE_BUF_SIZE 4096

typedef struct ycDnsScanMessageHeader_st {
    uint16_t   id;

    uint16_t   qr     : 1;
    uint16_t   opcode : 4;
    uint16_t   aa     : 1;
    uint16_t   tc     : 1;
    uint16_t   rd     : 1;
    uint16_t   ra     : 1;
    uint16_t   z      : 1;
    uint16_t   ad     : 1;
    uint16_t   cd     : 1;
    uint16_t   rcode  : 4;

    uint16_t   qdcount;
    uint16_t   ancount;
    uint16_t   nscount;
    uint16_t   arcount;
} ycDnsScanMessageHeader_t;

#define DNS_PORT_NUMBER 53
#define DNS_NAME_COMPRESSION 0xc0


/**
 * ycInitializeScanRules
 *
 * @param scriptFile
 * @param err
 *
 *
 * @return FALSE if an error occurs, TRUE if there were no errors
 *
 */
gboolean
ycInitializeScanRules(
    FILE    *scriptFile,
    GError **err);

/**
 * ycScanPayload
 *
 *
 * @param payloadData
 * @param payloadSize
 * @param flow
 * @param val
 *
 * @return the value of the label of the matching rule if there is a match,
 * otherwise 0
 *
 */
uint16_t
ycScanPayload(
    const uint8_t  *payloadData,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val);


/**
 * ycDnsScanRebuildHeader
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octect stream directly into the DNS structure
 *
 * @param payload a network stream capture
 * @param header a pointer to a client allocated dns message
 *        header structure
 *
 *
 */
void
ycDnsScanRebuildHeader(
    const uint8_t             *payload,
    ycDnsScanMessageHeader_t  *header);

/**
 * ycGetRuleType
 *
 * This function returns the type of rule that is used
 * for application labeling.  This will affect how DPI
 * is done for the DPI plugin.
 *
 * @param port port used to identify the application
 * @return ruleType
 *
 */
int
ycGetRuleType(
    uint16_t   port);

/**
 *
 * yfRemoveCRC
 *
 *
 * This function removes the Cyclic Redundancy Check codes
 * from a payload, in order to do DPI.
 *
 * @param start start of payload that contains CRCs
 * @param length length of payload that contains CRCs
 * @param dst destination buffer to copy payload without CRCs
 * @param dst_length length of destination buffer
 * @param block_size size of blocks of data
 * @param crc_length size of crc codes
 *
 *
 */
void
yfRemoveCRC(
    const uint8_t  *start,
    size_t          length,
    uint8_t        *dst,
    size_t         *dst_length,
    int             block_size,
    int             crc_length);

#endif /* ifndef PAYLOAD_SCANNER_H_ */
