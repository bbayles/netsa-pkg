/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */

/*
 *  tlsplugin.c
 *
 *
 *  This recognizes SSL & TLS packets
 *
 *  Remember to update proxyplugin.c with any changes.
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

#define CERT_CN     0x03 /* common name */
#define CERT_CNN    0x06 /* country name */
#define CERT_NULL   0x05
#define CERT_LN     0x07 /* locality name */
#define CERT_STATE  0x08 /* state or province name */
#define CERT_ADD    0x09 /* street address */
#define CERT_ORG    0x10 /* Organization Name */
#define CERT_ORGU   0x11 /* Organizational Unit Name */
#define CERT_TITLE  0x12 /* title */
#define CERT_ZIP    0x17 /* zip code */
#define CERT_PRINT  0x13 /* Printable String */
#define CERT_OID    0x06 /* Object Identifer */
#define CERT_SEQ    0x30 /* Start of Sequence */
#define CERT_SET    0x31 /* Start of Set */
#define CERT_TIME   0x17 /* UTC Time */

/* this might be more - but I have to have a limit somewhere */
#define MAX_CERTS 10

/** defining the header structure for SSLv2 is pointless, because the
 *  first field of the record is variable length, either 2 or 3 bytes
 *  meaning that the first step has to be to figure out how far offset
 *  all of the other fields are.  Further, the client can send a v2
 *  client_hello stating that it is v3/TLS 1.0 capable, and the server
 *  can respond with v3/TLS 1.0 record formats
 */

/**
 * SSL Declarations are refreced from paylloadScanner.h
 */


/** this defines the record header for SSL V3 negotiations,
 *  it also works for TLS 1.0 */
typedef struct sslv3RecordHeader_st {
    uint8_t    contentType;
    uint8_t    protocolMajor;
    uint8_t    protocolMinor;
    uint16_t   length;
} sslv3RecordHeader_t;

static gboolean
decodeSSLv2(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    uint32_t        offset,
    uint8_t         datalength);

static gboolean
decodeTLSv1(
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    uint32_t        offset,
    uint8_t         datalength,
    uint8_t         type);

YC_SCANNER_PROTOTYPE(tlsplugin_LTX_ycTlsScanScan);

#define TLS_PORT_NUMBER  443

#define TLS_VERSION_1 0x0301
#define SSL_VERSION_2 0x0002
#define SSL_VERSION_3 0x0003
#define TLS_VERSION_11 0x0302
#define TLS_VERSION_12 0x0303
#define SSL_VERSION 0x0200

/**
 * tlsplugin_LTX_ycTlsScanScan
 *
 * the scanner for recognizing SSL/TLS packets
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
tlsplugin_LTX_ycTlsScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
    uint8_t  ssl_length;
    uint8_t  ssl_msgtype;
    uint16_t tls_version;
    uint32_t offset = 0;

    /* every SSL/TLS header has to be at least 2 bytes long... */
    /* we need 5 to determine message type and version */
    if (payloadSize < 5) {
        return 0;
    }

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
            if (!decodeSSLv2(payload, payloadSize, flow, offset,
                             ssl_length))
            {
                return 0;
            }
        } else {
            return 0;
        }

        /* SSLv2 (client_hello) */
#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, 1, NULL, 2, YF_SSL_CLIENT_VERSION,
                          TLS_PORT_NUMBER);
        yfHookScanPayload(flow, payload, 2, NULL, tls_version,
                          YF_SSL_RECORD_VERSION,
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

            if ( ((size_t)offset + 2) < payloadSize) {
                tls_version = ntohs(*(uint16_t *)(payload + offset));
                offset += 2;

                if (tls_version == TLS_VERSION_1 ||
                    tls_version == SSL_VERSION_2 ||
                    tls_version == SSL_VERSION_3)
                {
                    if (!decodeSSLv2(payload, payloadSize, flow, offset,
                                     ssl_length))
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
            yfHookScanPayload(flow, payload, 1, NULL, 2, YF_SSL_CLIENT_VERSION,
                              TLS_PORT_NUMBER);
            yfHookScanPayload(flow, payload, 2, NULL, tls_version,
                              YF_SSL_RECORD_VERSION,
                              TLS_PORT_NUMBER);
#endif /* if YAF_ENABLE_HOOKS */
            return TLS_PORT_NUMBER;
        }
      tls:
        if (payloadSize >= 10) {
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
                if (!decodeTLSv1(payload, payloadSize, flow, offset,
                                 ssl_length, ssl_msgtype))
                {
                    return 0;
                }

                /* SSLv3 / TLS */
#if YAF_ENABLE_HOOKS
                yfHookScanPayload(flow, payload, 1, NULL, 3,
                                  YF_SSL_CLIENT_VERSION,
                                  TLS_PORT_NUMBER);
                yfHookScanPayload(flow, payload, 2, NULL, tls_version,
                                  YF_SSL_RECORD_VERSION,
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
    uint8_t         datalength,
    uint8_t         type)
{
    uint32_t record_len;
    uint32_t header_len = offset - 1;
    uint32_t cert_len, sub_cert_len;
    uint16_t cert_version;
    int      cert_count = 0;
    uint16_t ciphers = 0;
    uint16_t cipher_suite_len;
    uint8_t  session_len;
    uint8_t  compression_len;
    uint16_t version;

    /* Both Client and Server Hello's start off the same way */
    /* 3 for Length, 2 for Version, 32 for Random, 1 for session ID Len*/
    if ((size_t)offset + 39 > payloadSize) {
        return FALSE;
    }

    record_len = (ntohl(*(uint32_t *)(payload + offset)) & 0xFFFFFF00) >> 8;
    /* This might need to be 3 test and verify// */
    offset += 3;

    cert_version = ntohs(*(uint16_t *)(payload + offset));

    version = offset;
    offset += 34; /* skip version & random */

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

        ciphers = offset;

        /* cipher length */
        /* ciphers are here */
        offset += cipher_suite_len;

        if ((size_t)offset + 1 > payloadSize) {
            return FALSE;
        }

        compression_len = *(payload + offset);

        offset += compression_len + 1;

#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, 2, NULL, cert_version,
                          YF_SSL_RECORD_VERSION,
                          TLS_PORT_NUMBER);
        yfHookScanPayload(flow, payload, cipher_suite_len, NULL, ciphers,
                          YF_SSL_CIPHER_LIST, TLS_PORT_NUMBER);
        yfHookScanPayload(flow, payload, 2, NULL, version,
                          YF_SSL_VERSION, TLS_PORT_NUMBER);
#endif /* if YAF_ENABLE_HOOKS */
    } else if (type == 2) {
        /* Server Hello */
        if ((size_t)offset + 3 > payloadSize) {
            return FALSE;
        }
        /* cipher is here */
#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, 2, NULL, offset, YF_SSL_SERVER_CIPHER,
                          TLS_PORT_NUMBER);
#endif
        offset += 2;
        /* compression method */
#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, 2, NULL, cert_version,
                          YF_SSL_RECORD_VERSION,
                          TLS_PORT_NUMBER);
        yfHookScanPayload(flow, payload, 1, NULL, offset, YF_SSL_COMPRESSION,
                          TLS_PORT_NUMBER);
        yfHookScanPayload(flow, payload, 2, NULL, version,
                          YF_SSL_SERVER_VERSION, TLS_PORT_NUMBER);
#endif /* if YAF_ENABLE_HOOKS */
        offset++;
    }

    if (((size_t)offset - header_len) < record_len) {
        /* extensions? */

        const uint16_t ext_len = ntohs(*(uint16_t *)(payload + offset));
#if YAF_ENABLE_HOOKS
        uint32_t       ext_ptr = offset;
#endif

        offset += 2 + ext_len;
#if YAF_ENABLE_HOOKS
        /* only want Client Hello's server name */
        if (type == 1) {
            yfHookScanPayload(flow, payload, 2, NULL, ext_ptr,
                              YF_SSL_CLIENT_EXTENSION, TLS_PORT_NUMBER);
        } else if (type == 2) {
            yfHookScanPayload(flow, payload, 2, NULL, ext_ptr,
                              YF_SSL_SERVER_EXTENSION, TLS_PORT_NUMBER);
        }
        ext_ptr += 2;

        if (type == 1) {
            uint16_t sub_ext_len;
            uint16_t sub_ext_type;
            uint32_t tot_ext = 0;
            uint32_t ext_ptr2;
            uint16_t eli_curv_len;
            uint8_t  eli_form_len;

            while ((ext_ptr < payloadSize) && (tot_ext < ext_len)) {
                sub_ext_type = ntohs(*(uint16_t *)(payload + ext_ptr));
                ext_ptr += 2;
                sub_ext_len = ntohs(*(uint16_t *)(payload + ext_ptr));
                ext_ptr += 2;
                tot_ext += sizeof(uint16_t) + sizeof(uint16_t) + sub_ext_len;
                ext_ptr2 = ext_ptr;
                ext_ptr += sub_ext_len;

                switch (sub_ext_type) {
                  case 0:
                    /* server name */
                    /* jump past list length and type to get name length and
                     * name */
                    ext_ptr2 += 3; /* 2 for length, 1 for type */
                    sub_ext_len = ntohs(*(uint16_t *)(payload + ext_ptr2));
                    ext_ptr2 += 2;
                    if ((ext_ptr2 + sub_ext_len) < payloadSize) {
                        yfHookScanPayload(
                            flow, payload, sub_ext_len, NULL, ext_ptr2,
                            YF_SSL_SERVER_NAME, TLS_PORT_NUMBER);
                    }
                    break;

                  case 10:
                    /* elliptic curve list */
                    /* After grabing the length jump past it and grab the
                     * desired list */
                    eli_curv_len = ntohs(*(uint16_t *)(payload + ext_ptr2));
                    ext_ptr2 += 2;
                    if ((ext_ptr2 + eli_curv_len) < payloadSize) {
                        yfHookScanPayload(
                            flow, payload, eli_curv_len, NULL, ext_ptr2,
                            YF_SSL_ELIPTIC_CURVE, TLS_PORT_NUMBER);
                    }
                    break;

                  case 11:
                    /* elliptic curve point format list */
                    /* After grabing the length jump past it and grab the
                     * desired list */
                    eli_form_len = *(payload + ext_ptr2);
                    ext_ptr2 += 1;
                    if ((ext_ptr2 + eli_form_len) < payloadSize) {
                        yfHookScanPayload(
                            flow, payload, eli_form_len, NULL, ext_ptr2,
                            YF_SSL_ELIPTIC_FORMAT, TLS_PORT_NUMBER);
                    }
                    break;
                }
            }
        }
#endif /* if YAF_ENABLE_HOOKS */
    }

    while (payloadSize > offset) {
        switch (*(payload + offset)) {
          case 11:
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

            while (payloadSize > (offset + 4)) {
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
                if (cert_count >= MAX_CERTS) {
                    return TRUE;
                }
#if YAF_ENABLE_HOOKS
                if (((size_t)offset + sub_cert_len + 3) <= payloadSize) {
                    yfHookScanPayload(flow, payload, 1, NULL, offset,
                                      YF_SSL_CERT_START, TLS_PORT_NUMBER);
                }
#endif /* if YAF_ENABLE_HOOKS */
                cert_count++;
                offset += 3 + sub_cert_len;
            }
            break;

          case 22:
            /* 1 for type, 2 for version, 2 for length - we know it's long */
            offset += 5;
            break;
          case 20:
          case 21:
          case 23:
            offset += 3; /* 1 for type, 2 for version */
            if (((size_t)offset + 2) > payloadSize) {
                return TRUE; /* prob should be false */
            }
            record_len = ntohs(*(uint16_t *)(payload + offset));
            if (record_len > payloadSize) {
                return TRUE;
            }
            offset += record_len + 2;
            break;

          default:
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
    yfHookScanPayload(flow, payload, cipher_spec_length, NULL, offset,
                      YF_SSL_V2_CIPHER_LIST,
                      TLS_PORT_NUMBER);
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
                        yfHookScanPayload(flow, payload, 1, NULL, offset,
                                          YF_SSL_CERT_START, TLS_PORT_NUMBER);
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
