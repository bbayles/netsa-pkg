/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  proxyplugin.c
 *
 *
 *  This plugin skips the HTTP CONNECT (which often happens when https
 *  traffic is proxied) to get to the TLS headers and certificates.
 *  Make sure to set the Proxy Port in yafApplabelRules.conf for this
 *  plugin to get called appropriately.  Otherwise https traffic will be
 *  labeled as http (80).
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

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <payloadScanner.h>

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#include <pcre.h>

YC_SCANNER_PROTOTYPE(proxyplugin_LTX_ycProxyScanScan);

static pcre        *httpConnectRegex = NULL;
static unsigned int pcreInitialized = 0;
static pcre        *httpConnectEstRegex = NULL;

/* this might be more - but I have to have a limit somewhere */
#define MAX_CERTS 10

/** defining the header structure for SSLv2 is pointless, because the
 *  first field of the record is variable length, either 2 or 3 bytes
 *  meaning that the first step has to be to figure out how far offset
 *  all of the other fields are.  Further, the client can send a v2
 *  client_hello stating that it is v3/TLS 1.0 capable, and the server
 *  can respond with v3/TLS 1.0 record formats
 */


/** this defines the record header for SSL V3 negotiations,
 *  it also works for TLS 1.0 */
typedef struct sslv3RecordHeader_st {
    uint8_t    contentType;
    uint8_t    protocolMajor;
    uint8_t    protocolMinor;
    uint16_t   length;
} sslv3RecordHeader_t;

/**
 * static local functions
 *
 */

static gboolean
decodeSSLv2(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    uint32_t        offset,
    uint32_t        firstpkt,
    uint8_t         datalength);

static gboolean
decodeTLSv1(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    uint32_t        offset,
    uint32_t        firstpkt,
    uint8_t         datalength,
    uint8_t         type);

static uint16_t
yfProxyScanInit(
    void);

#define TLS_PORT_NUMBER  443

#define TLS_VERSION_1 0x0301
#define SSL_VERSION_2 0x0002
#define SSL_VERSION_3 0x0003
#define TLS_VERSION_11 0x0302
#define TLS_VERSION_12 0x0303
#define SSL_VERSION 0x0200

/**
 * proxyplugin_LTX_ycProxyScanScan
 *
 * the scanner for recognizing SSL/TLS packets through a proxy.
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
 * @return TLS_PORT_NUMBER
 *         otherwise 0
 */
uint16_t
proxyplugin_LTX_ycProxyScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#define NUM_CAPT_VECTS 60
    int          vects[NUM_CAPT_VECTS];
    uint8_t      ssl_length;
    uint8_t      ssl_msgtype;
    uint16_t     tls_version;
    uint32_t     offset = 0;
    uint32_t     firstpkt = 0;
    unsigned int payloadLength = payloadSize;
    unsigned int loop = 0;
    int          rc;

    if (0 == pcreInitialized) {
        if (0 == yfProxyScanInit()) {
            return 0;
        }
    }

    /* if the applabel is 0, this is the fwd direction which should have
     * the HTTP CONNECT *
     * If not, we've probably already classified it as TLS and we're just
     * doing DPI */
    if (flow->appLabel == 0) {
        rc = pcre_exec(httpConnectRegex, NULL, (char *)payload, payloadSize,
                       0, 0, vects, NUM_CAPT_VECTS);
        if (rc <= 0) {
            rc = pcre_exec(httpConnectEstRegex, NULL, (char *)payload,
                           payloadSize, 0, 0, vects, NUM_CAPT_VECTS);
            if (rc <= 0) {
                return 0;
            }
        }
    } else if (flow->appLabel != TLS_PORT_NUMBER) {
        return 0;
    }

    /* every SSL/TLS header has to be at least 2 bytes long... */
    if (payloadSize < 45) {
        return 0;
    }

    while (loop < val->pkt && loop < YAF_MAX_PKT_BOUNDARY) {
        if (val->paybounds[loop] == 0) {
            loop++;
        } else {
            firstpkt = val->paybounds[loop];
            break;
        }
    }

    /* http/1.0 connection established messaged is 39 bytes! */

    payload += firstpkt;
    payloadLength -= firstpkt;

    /*understanding how to determine between SSLv2 and SSLv3/TLS is "borrowed"
     * from OpenSSL payload byte 0 for v2 is the start of the length field, but
     * its MSb is always reserved to tell us how long the length field is, and
     * in some cases, the second MSb is reserved as well */

    /* when length is 2 bytes in size (MSb == 1), and the message type code is
     * 0x01 (client_hello) we know we're doing SSL v2 */
    if ((payload[0] & 0x80) && (0x01 == payload[2])) {
        ssl_length = ((payload[0] & 0x7F) << 8) | payload[1];

        if (ssl_length < 2) {
            return 0;
        }

        ssl_msgtype = 1;
        offset += 3;

        /* this is the version from the handshake message */
        tls_version = ntohs(*(uint16_t *)(payload + offset));
        offset += 2;
        if (tls_version == TLS_VERSION_1 || tls_version == SSL_VERSION_2 ||
            tls_version == SSL_VERSION_3)
        {
            if (!decodeSSLv2(payload, payloadLength, flow, offset,
                             firstpkt, ssl_length))
            {
                return 0;
            }
        } else {
            return 0;
        }

        /* SSLv2 (client_hello) */
#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, 1, NULL, 41, 88, TLS_PORT_NUMBER);
        yfHookScanPayload(flow, payload, 2, NULL, tls_version, 94,
                          TLS_PORT_NUMBER);
#endif
        return TLS_PORT_NUMBER;
    } else {
        if ((0x00 == (payload[0] & 0x80)) && (0x00 == (payload[0] & 0x40))
            && (0x01 == payload[3]))
        {
            /* this is ssl v2 but with a 3-byte header */
            /* the second MSb means the record is a data record */
            /* the fourth byte should be 1 for client hello */
            if ((payload[0] == 0x16) && (payload[1] == 0x03)) {
                /* this is most likely tls, not sslv2 */
                goto tls;
            }

            ssl_length = ((payload[0] * 0x3F) << 8) | payload[1];

            if (ssl_length < 3) {
                return 0;
            }
            offset += 4;

            if ( ((size_t)offset + 2) < payloadLength) {
                tls_version = ntohs(*(uint16_t *)(payload + offset));
                offset += 2;

                if (tls_version == TLS_VERSION_1 ||
                    tls_version == SSL_VERSION_2 ||
                    tls_version == SSL_VERSION_3)
                {
                    if (!decodeSSLv2(payload, payloadLength, flow, offset,
                                     firstpkt, ssl_length))
                    {
                        return 0;
                    }
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
#if YAF_ENABLE_HOOKS
            yfHookScanPayload(flow, payload, 1, NULL, 41, 88, TLS_PORT_NUMBER);
            yfHookScanPayload(flow, payload, 2, NULL, tls_version, 94,
                              TLS_PORT_NUMBER);
#endif
            return TLS_PORT_NUMBER;
        }
      tls:
        if (payloadLength >= 10) {
            /* payload[0] is handshake request [0x16]
             * payload[1] is ssl major version, sslv3 & tls is 3
             * payload[5] is handshake command, 1=client_hello,2=server_hello
             * payload[3,4] is length
             * payload[9] is the version from the record */

            if ((payload[0] == 0x16) && (payload[1] == 0x03) &&
                ((payload[5] == 0x01) || (payload[5] == 0x02)) &&
                (((payload[3] == 0) && (payload[4] < 5)) ||
                 (payload[9] == payload[1])))
            {
                ssl_msgtype = payload[5];
                ssl_length = payload[4];
                tls_version = ntohs(*(uint16_t *)(payload + 1));
                /* 1 for content type, 2 for version, 2 for length,
                 * 1 for handshake type*/
                offset += 6;
                /* now we should be at record length */
                if (!decodeTLSv1(payload, payloadLength, flow, offset,
                                 firstpkt, ssl_length, ssl_msgtype))
                {
                    return 0;
                }

                /* SSLv3 / TLS */
#if YAF_ENABLE_HOOKS
                yfHookScanPayload(flow, payload, 1, NULL, 42, 88,
                                  TLS_PORT_NUMBER);
                yfHookScanPayload(flow, payload, 2, NULL, tls_version, 94,
                                  TLS_PORT_NUMBER);
#endif /* if YAF_ENABLE_HOOKS */
                return TLS_PORT_NUMBER;
            }
        }
    }

    return 0;
}


static gboolean
decodeTLSv1(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    uint32_t        offset,
    uint32_t        firstpkt,
    uint8_t         datalength,
    uint8_t         type)
{
    uint32_t record_len;
    uint32_t header_len = offset - 1;
    uint32_t cert_len, sub_cert_len;
    int      cert_count = 0;
    uint16_t cipher_suite_len;
    uint8_t  session_len;
    uint8_t  compression_len;
    uint8_t  next_msg;
    uint16_t ext_len = 0;
    uint32_t ext_ptr;
    uint16_t sub_ext_len;
    uint16_t sub_ext_type;

    /* Both Client and Server Hello's start off the same way */
    /* 3 for Length, 2 for Version, 32 for Random, 1 for session ID Len*/
    if ((size_t)offset + 39 > payloadSize) {
        return FALSE;
    }

    record_len = (ntohl(*(uint32_t *)(payload + offset)) & 0xFFFFFF00) >> 8;

    offset += 37; /* skip version  & random*/

    session_len = *(payload + offset);

    offset += session_len + 1;

    if ((size_t)offset + 2 > payloadSize) {
        return FALSE;
    }

    if (type == 1) {
        /* Client Hello */

        cipher_suite_len = ntohs(*(uint16_t *)(payload + offset));

        /* figure out number of ciphers by dividing by 2 */

        offset += 2;

        if (cipher_suite_len > payloadSize) {
            return FALSE;
        }

        if ((size_t)offset + cipher_suite_len > payloadSize) {
            return FALSE;
        }
        /* cipher length */
        /* ciphers are here */
        offset += cipher_suite_len;

        if ((size_t)offset + 1 > payloadSize) {
            return FALSE;
        }

        compression_len = *(payload + offset);

        offset += compression_len + 1;

#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, cipher_suite_len, NULL,
                          offset + firstpkt, 91, TLS_PORT_NUMBER);
#endif
    } else if (type == 2) {
        /* Server Hello */
        if ((size_t)offset + 3 > payloadSize) {
            return FALSE;
        }
        /* cipher is here */
#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, 2, NULL, offset + firstpkt, 89,
                          TLS_PORT_NUMBER);
#endif
        offset += 2;
        /* compression method */
#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, 1, NULL, offset + firstpkt, 90,
                          TLS_PORT_NUMBER);
#endif
        offset++;
    }

    if (((size_t)offset - header_len) < record_len) {
        int tot_ext = 0;
        /* extensions? */
        ext_len = ntohs(*(uint16_t *)(payload + offset));
        ext_ptr = offset + 2;
        offset += ext_len + 2;
#if YAF_ENABLE_HOOKS
        /* only want Client Hello's server name */
        if (type == 1 && (offset < payloadSize)) {
            while (ext_ptr < payloadSize && (tot_ext < ext_len)) {
                sub_ext_type = ntohs(*(uint16_t *)(payload + ext_ptr));
                ext_ptr += 2;
                sub_ext_len = ntohs(*(uint16_t *)(payload + ext_ptr));
                ext_ptr += 2;
                tot_ext += sizeof(uint16_t) + sizeof(uint16_t) + sub_ext_len;
                if (sub_ext_type != 0) {
                    ext_ptr += sub_ext_len;
                    continue;
                }
                if (sub_ext_len == 0) {
                    /* no server name listed */
                    break;
                }
                /* grab server name */
                /* jump past list length and type to get name length and name
                 * */
                ext_ptr += 3; /* 2 for length, 1 for type */
                sub_ext_len = ntohs(*(uint16_t *)(payload + ext_ptr));
                ext_ptr += 2;
                if ((ext_ptr + sub_ext_len) < payloadSize) {
                    yfHookScanPayload(flow, payload, sub_ext_len, NULL,
                                      ext_ptr + firstpkt, 95, TLS_PORT_NUMBER);
                }
                break;
            }
        }
#endif /* if YAF_ENABLE_HOOKS */
    }

    while (payloadSize > offset) {
        next_msg = *(payload + offset);
        if (next_msg == 11) {
            /* certificate */
            if ((size_t)offset + 7 > payloadSize) {
                return TRUE; /* prob should be false */
            }

            offset++;

            record_len = (ntohl(*(uint32_t *)(payload + offset)) &
                          0xFFFFFF00) >> 8;
            offset += 3;

            /* Total Cert Length */
            cert_len = (ntohl(*(uint32_t *)(payload + offset)) &
                        0xFFFFFF00) >> 8;
            offset += 3;

            while (payloadSize > ((size_t)offset + 4)) {
                sub_cert_len = (ntohl(*(uint32_t *)(payload + offset)) &
                                0xFFFFFF00) >> 8;
                if ((sub_cert_len > cert_len) || (sub_cert_len < 2)) {
                    /* it's at least got to have a version number */
                    return TRUE; /* prob should be false */
                } else if (sub_cert_len > payloadSize) {
                    /* just not enough room */
                    return TRUE;
                }

                /* offset of certificate */
                if (cert_count < MAX_CERTS) {
#if YAF_ENABLE_HOOKS
                    if (((size_t)offset + sub_cert_len + 3) < payloadSize) {
                        yfHookScanPayload(flow, payload, 1, NULL,
                                          offset + firstpkt, 93,
                                          TLS_PORT_NUMBER);
                    }
#endif /* if YAF_ENABLE_HOOKS */
                } else {
                    return TRUE;
                }

                cert_count++;
                offset += 3 + sub_cert_len;
            }
        } else if (next_msg == 22) {
            /* 1 for type, 2 for version, 2 for length - we know it's long */
            offset += 5;
        } else if (next_msg == 20 || next_msg == 21 || next_msg == 23) {
            offset += 3; /* 1 for type, 2 for version */

            if (((size_t)offset + 2) > payloadSize) {
                return TRUE; /* prob should be false */
            }

            record_len = ntohs(*(uint16_t *)(payload + offset));

            if (record_len > payloadSize) {
                return TRUE;
            }

            offset += record_len + 2;
        } else {
            return TRUE;
        }
    }

    return TRUE;
}


static gboolean
decodeSSLv2(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    uint32_t        offset,
    uint32_t        firstpkt,
    uint8_t         datalength)
{
    uint32_t record_len;
    uint16_t cipher_spec_length;
    uint16_t challenge_length;
    uint32_t cert_len, sub_cert_len;
    int      cert_count = 0;
    uint8_t  next_msg;

    if ((size_t)offset + 6 > payloadSize) {
        return FALSE;
    }

    cipher_spec_length = ntohs(*(uint16_t *)(payload + offset));

    /* cipher_spec_length */
    /* session length */

    offset += 4;

    /* challenge length */
    challenge_length = ntohs(*(uint16_t *)(payload + offset));

    offset += 2;

    if ((size_t)offset + cipher_spec_length > payloadSize) {
        return FALSE;
    }

    if (cipher_spec_length > payloadSize) {
        return FALSE;
    }

#if YAF_ENABLE_HOOKS
    yfHookScanPayload(flow, payload, cipher_spec_length, NULL,
                      offset + firstpkt, 92, TLS_PORT_NUMBER);
#endif
    offset += cipher_spec_length + challenge_length;

    while (payloadSize > offset) {
        next_msg = *(payload + offset);

        if (next_msg == 11) {
            /* certificate */
            if ((size_t)offset + 7 > payloadSize) {
                return TRUE; /* prob should be false */
            }

            offset++;

            record_len = (ntohl(*(uint32_t *)(payload + offset)) &
                          0xFFFFFF00) >> 8;
            offset += 3;

            /* Total Cert Length */
            cert_len = (ntohl(*(uint32_t *)(payload + offset)) &
                        0xFFFFFF00) >> 8;
            offset += 3;

            while (payloadSize > offset) {
                sub_cert_len = (ntohl(*(uint32_t *)(payload + offset)) &
                                0xFFFFFF00) >> 8;

                if ((sub_cert_len > cert_len) || (sub_cert_len < 2)) {
                    /* it's at least got to have a version number */
                    return TRUE; /* prob should be false */
                } else if (sub_cert_len > payloadSize) {
                    /* just not enough room */
                    return TRUE;
                }

                /* offset of certificate */
                if (cert_count < MAX_CERTS) {
#if YAF_ENABLE_HOOKS
                    if (((size_t)offset + sub_cert_len + 3) < payloadSize) {
                        yfHookScanPayload(flow, payload, 1, NULL,
                                          offset + firstpkt, 93,
                                          TLS_PORT_NUMBER);
                    }
#endif /* if YAF_ENABLE_HOOKS */
                } else {
                    return TRUE;
                }

                cert_count++;
                offset += 3 + sub_cert_len;
            }
        } else if (next_msg == 22) {
            /* 1 for type, 2 for version, 2 for length - we know it's long */
            offset += 5;
        } else if (next_msg == 20 || next_msg == 21 || next_msg == 23) {
            offset += 3; /* 1 for type, 2 for version */

            if (((size_t)offset + 2) > payloadSize) {
                return TRUE; /* prob should be false */
            }

            record_len = ntohs(*(uint16_t *)(payload + offset));

            if (record_len > payloadSize) {
                return TRUE;
            }

            offset += record_len + 2;
        } else {
            return TRUE;
        }
    }

    return TRUE;
}


static uint16_t
yfProxyScanInit(
    void)
{
    const char *errorString;
    int         errorPos;
    const char  httpRegexString[] =
        "^CONNECT [-a-zA-Z0-9.~;_]+:\\d+ HTTP/\\d\\.\\d\\b";
    const char  httpConnectString[] =
        "^HTTP/\\d\\.\\d 200 [Cc]onnection [Ee]stablished\\b";

    httpConnectRegex = pcre_compile(httpRegexString, PCRE_ANCHORED,
                                    &errorString, &errorPos, NULL);

    if (NULL != httpConnectRegex) {
        pcreInitialized = 1;
    }

    httpConnectEstRegex = pcre_compile(httpConnectString, PCRE_ANCHORED,
                                       &errorString, &errorPos, NULL);

    if (httpConnectEstRegex == NULL) {
        pcreInitialized = 0;
    }

    return pcreInitialized;
}
