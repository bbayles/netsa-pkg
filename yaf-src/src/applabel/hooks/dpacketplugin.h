/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  dpacketplugin.h
 *  header file for dpacketplugin.c
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Sarneso
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

#include <yaf/autoinc.h>

#if YAF_ENABLE_HOOKS
#if YAF_ENABLE_APPLABEL

#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#else
#if   HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if   HAVE_MALLOC_H
#include <malloc.h>
#endif
#endif /* if STDC_HEADERS */

#include <ctype.h>

#if HAVE_OPENSSL
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif
#endif  /* HAVE_OPENSSL */

/**glib, we use the hash and the error string stuff */
#include <glib.h>
#include <glib/gstdio.h>


/** we obviously need some yaf details -- we're a plugin to it afterall! */
#include <yaf/yafhooks.h>
#include "payloadScanner.h"
#include <pcre.h>

/* fixbuf 2.x uses char* as the type of the name of info elements in
 * fbInfoElementSpec_t; wrap this around string literals to quiet compiler
 * warnings */
#define C(String) (char *)String


/*
 *  ASN.1 Tag Numbers (for SSL)
 *
 *  A Layman's Guide to a Subset of ASN.1, BER, and DER
 *  An RSA Laboratories Technical Note
 *  Burton S. Kaliski Jr.
 *  Revised November 1, 1993
 *
 *  https://luca.ntop.org/Teaching/Appunti/asn1.html
 *
 *  Not all these tags are used in the code but having them here is useful.
 */
#define CERT_BOOL               0x01
/* Integer */
#define CERT_INT                0x02
/* Bit String */
#define CERT_BITSTR             0x03
/* Octet String */
#define CERT_OCTSTR             0x04
#define CERT_NULL               0x05
/* Object Identifer */
#define CERT_OID                0x06
/* Start of Sequence */
#define CERT_SEQ                0x10
/* Start of Set */
#define CERT_SET                0x11
/* Printable String */
#define CERT_PRINT              0x13
/* 8-bit (T.61) Char String */
#define CERT_T61STR             0x14
/* ASCII String */
#define CERT_IA5STR             0x16
/* UTC Time */
#define CERT_TIME               0x17
#define CERT_EXPLICIT           0xa0
/* ASN.1 P/C Bit (primitive, constucted) */
#define CERT_PRIM               0x00
#define CERT_CONST              0x01
/* ASN.1 Length 0x81 is length follows in 1 byte */
#define CERT_1BYTE              0x81
/* ASN.1 Length 0x82 is length follows in 2 bytes */
#define CERT_2BYTE              0x82

/*
 *  BER encoding of object ids (OID): First byte is (40 * value1 + value2).
 *  Remaining bytes are in base-128 with the MSB high in all bytes except the
 *  last.  To compute the BER value in reverse order:
 *
 *  1. Mask value by 0x7f to get final byte
 *  2. Shift value right by 7.
 *  3. Stop if value is 0.
 *  4. Compute (0x80 | (0x7f & value)) to get the previous byte.
 *  5. Goto 2.
 *
 *  113549 ->
 *    final byte: (113549 & 0x7f) = 13 (0x0d)
 *    shift: 113549 >> 7 = 887, not zero
 *    next to last: (0x80 | (0x7f & 887)) = (0x80 | 119) = 0xf7
 *    shift: 887 >> 7 = 6, not zero
 *    second to last: (0x80 | (0x7f & 6)) = (0x80 | 6) = 0x86
 *    shift: 6 >> 7 = 0, end
 *    result: 0x86 0xf7 0x0d
 */

/*
 *  id-ce: {joint-iso-itu-t(2) ds(5) certificateExtension(29)}
 *
 *  http://oid-info.com/cgi-bin/display?tree=2.5.29
 *
 *  bytes: (40 * 2 + 5), base128(29) ==> (55, 1D)
 */
#define CERT_IDCE               0x551D

/*
 *  id-at: {joint-iso-itu-t(2) ds(5) attributeType(4)}
 *
 *  http://oid-info.com/cgi-bin/display?tree=2.5.4.45#focus
 *
 *  bytes: (40 * 2 + 5), base128(4) ==> (55, 04)
 */
#define CERT_IDAT               0x5504

/*
 *  pkcs-9: {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9}
 *
 *  http://oid-info.com/cgi-bin/display?tree=1.2.840.113549.1.9#focus
 *
 *  bytes: (40 * 1 + 2), base128(840), base128(113549), base128(1), base128(9)
 *  ==> (2A, 86 48, 86 f7 0d, 01, 09)
 */
static const uint8_t CERT_PKCS[] = {
    0x2A, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09
};

/*
 *  ldap-domainComponent: {itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100)
 *  pilotAttributeType(1) domainComponent(25)}
 *
 *  bytes (40 * 0 + 9), base128(2342), base128(19200300), base128(100),
 *  base128(1), base128(25) ==> (09, 92 26, 89, 93 f2 2c, 64, 01, 19)
 */
static const uint8_t CERT_DC[] = {
    0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19
};



#define DNS_LABEL_TYPE_MASK       0xC0
#define DNS_LABEL_TYPE_STANDARD   0x00
#define DNS_LABEL_TYPE_COMPRESSED 0xC0
#define DNS_LABEL_TYPE_EXTENDED   0x40
#define DNS_LABEL_OFFSET_MASK     0x3FFF

/*
 * Protocol Specific Template IDS - for quick lookup
 *
 */
#define YAF_IRC_FLOW_TID          0xC200
#define YAF_POP3_FLOW_TID         0xC300
#define YAF_TFTP_FLOW_TID         0xC400
#define YAF_SLP_FLOW_TID          0xC500
#define YAF_HTTP_FLOW_TID         0xC600
#define YAF_FTP_FLOW_TID          0xC700
#define YAF_IMAP_FLOW_TID         0xC800
#define YAF_RTSP_FLOW_TID         0xC900
#define YAF_SIP_FLOW_TID          0xCA00
#define YAF_SMTP_FLOW_TID         0xCB01
#define YAF_SMTP_MESSAGE_TID      0xCB02
#define YAF_SMTP_HEADER_TID       0xCB03
#define YAF_SSH_FLOW_TID          0xCC01
#define YAF_NNTP_FLOW_TID         0xCD00
#define YAF_DNS_FLOW_TID          0xCE00
#define YAF_DNSQR_FLOW_TID        0xCF00
#define YAF_DNSA_FLOW_TID         0xCE01
#define YAF_DNSAAAA_FLOW_TID      0xCE02
#define YAF_DNSCN_FLOW_TID        0xCE03
#define YAF_DNSMX_FLOW_TID        0xCE04
#define YAF_DNSNS_FLOW_TID        0xCE05
#define YAF_DNSPTR_FLOW_TID       0xCE06
#define YAF_DNSTXT_FLOW_TID       0xCE07
#define YAF_DNSSRV_FLOW_TID       0xCE08
#define YAF_DNSSOA_FLOW_TID       0xCE09
#define YAF_SSL_FLOW_TID          0xCA0A
#define YAF_SSL_CERT_FLOW_TID     0xCA0B
#define YAF_MYSQL_FLOW_TID        0xCE0C
#define YAF_MYSQLTXT_FLOW_TID     0xCE0D
#define YAF_DNSDS_FLOW_TID        0xCE0E
#define YAF_DNSRRSIG_FLOW_TID     0xCE0F
#define YAF_DNSNSEC_FLOW_TID      0xCE11
#define YAF_DNSKEY_FLOW_TID       0xCE12
#define YAF_DNSNSEC3_FLOW_TID     0xCE13
#define YAF_SSL_SUBCERT_FLOW_TID  0xCE14
#define YAF_DNP3_FLOW_TID         0xC202
#define YAF_DNP3_REC_FLOW_TID     0xC203
#define YAF_MODBUS_FLOW_TID       0xC204
#define YAF_ENIP_FLOW_TID         0xC205
#define YAF_RTP_FLOW_TID          0xC206
#define YAF_FULL_CERT_TID         0xC207

#define DPI_TOTAL_PROTOCOLS       22
#define MAX_PAYLOAD_RULES         1024

typedef struct ypBLValue_st ypBLValue_t;


typedef struct protocolRegexFields_st {
    pcre                   *rule;
    pcre_extra             *extra;
    const fbInfoElement_t  *elem;
    uint16_t                info_element_id;
} protocolRegexFields;

typedef struct protocolRegexRules_st {
    int                   numRules;
    enum { REGEX, PLUGIN, EMPTY, SIGNATURE } ruleType;
    uint16_t              applabel;
    protocolRegexFields   regexFields[MAX_PAYLOAD_RULES];
} protocolRegexRules_t;

typedef struct DPIActiveHash_st {
    uint16_t   portNumber;
    uint16_t   activated;
} DPIActiveHash_t;

typedef struct yfSSLFullCert_st yfSSLFullCert_t;

typedef struct yfDPIContext_st {
    char                  *dpiRulesFileName;
    DPIActiveHash_t        dpiActiveHash[MAX_PAYLOAD_RULES];
    ypBLValue_t           *appRuleArray[UINT16_MAX + 1];
    protocolRegexRules_t   ruleSet[DPI_TOTAL_PROTOCOLS + 1];
    unsigned int           dpiInitialized;
    uint16_t               dpi_user_limit;
    uint16_t               dpi_total_limit;
    /* count of protocols enabled */
    uint8_t                dpi_enabled;
    gboolean               dnssec;
    gboolean               cert_hash_export;
    gboolean               full_cert_export;
    gboolean               ssl_off;
} yfDPIContext_t;

/**
 * A YAF Deep Packet Inspection Structure.  Holds offsets in the payload as to
 * important stuff that we want to capture (see protocol PCRE rule files)
 *
 */

typedef struct yfDPIData_st {
    /* offset in the payload to the good stuff */
    unsigned int   dpacketCapt;
    /* id of the field we found */
    uint16_t       dpacketID;
    /* length of good stuff */
    uint16_t       dpacketCaptLen;
} yfDPIData_t;

typedef struct ypDPIFlowCtx_st {
    /* this plugin's yaf context */
    yfDPIContext_t   *yfctx;
    yfDPIData_t      *dpi;
    /* keep track of how much we're exporting per flow */
    size_t            dpi_len;
    /* For Bi-Directional - need to know how many in fwd payload */
    uint8_t           captureFwd;
    /* Total Captures Fwd & Rev */
    uint8_t           dpinum;
    /* Primarily for Uniflow - Since we don't know if it's a FWD or REV flow
     * this is set to know where to start in the dpi array */
    uint8_t           startOffset;
    /* full ssl cert ptr to clear basic lists */
    yfSSLFullCert_t  *full_ssl_cert;
    /* For Lists - we need to keep a ptr around so we can free it after
     * fBufAppend */
    void             *rec;
    /* extra buffer mainly for DNS stuff for now */
    uint8_t          *exbuf;
} ypDPIFlowCtx_t;

struct ypBLValue_st {
    size_t                  BLoffset;
    const fbInfoElement_t  *infoElement;
};

typedef struct ypBLKey_st {
    uint16_t   appLabel;
    uint16_t   id;
} ypBLKey_t;


/**
 * DPI Templates and related data structures.
 *
 */

static fbInfoElementSpec_t yaf_singleBL_spec[] = {
    {C("basicList"),    0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfIRCFlow_st {
    fbBasicList_t   ircMsg;
} yfIRCFlow_t;

typedef struct yfPOP3Flow_st {
    fbBasicList_t   pop3msg;
} yfPOP3Flow_t;


typedef struct yfModbusFlow_st {
    fbBasicList_t   mbmsg;
} yfModbusFlow_t;

typedef struct yfEnIPFlow_st {
    fbBasicList_t   enipmsg;
} yfEnIPFlow_t;

static fbInfoElementSpec_t yaf_tftp_spec[] = {
    {C("tftpFilename"),       FB_IE_VARLEN, 0 },
    {C("tftpMode"),           FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfTFTPFlow_st {
    fbVarfield_t   tftpFilename;
    fbVarfield_t   tftpMode;
} yfTFTPFlow_t;

static fbInfoElementSpec_t yaf_slp_spec[] = {
    {C("basicList"),          FB_IE_VARLEN, 0 },
    {C("slpVersion"),         1, 0 },
    {C("slpMessageType"),     1, 0 },
    {C("paddingOctets"),      6, 1 },
    FB_IESPEC_NULL
};

typedef struct yfSLPFlow_st {
    fbBasicList_t   slpString;
    uint8_t         slpVersion;
    uint8_t         slpMessageType;
    uint8_t         padding[6];
} yfSLPFlow_t;

static fbInfoElementSpec_t yaf_http_spec[] = {
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfHTTPFlow_st {
    fbBasicList_t   server;
    fbBasicList_t   userAgent;
    fbBasicList_t   get;
    fbBasicList_t   connection;
    fbBasicList_t   referer;
    fbBasicList_t   location;
    fbBasicList_t   host;
    fbBasicList_t   contentLength;
    fbBasicList_t   age;
    fbBasicList_t   response;
    fbBasicList_t   acceptLang;
    fbBasicList_t   accept;
    fbBasicList_t   contentType;
    fbBasicList_t   httpVersion;
    fbBasicList_t   httpCookie;
    fbBasicList_t   httpSetCookie;
    fbBasicList_t   httpAuthorization;
    fbBasicList_t   httpVia;
    fbBasicList_t   xforward;
    fbBasicList_t   httpRefresh;
    uint8_t         httpBasicListBuf[0];
} yfHTTPFlow_t;


static fbInfoElementSpec_t yaf_ftp_spec[] = {
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfFTPFlow_st {
    fbBasicList_t   ftpReturn;
    fbBasicList_t   ftpUser;
    fbBasicList_t   ftpPass;
    fbBasicList_t   ftpType;
    fbBasicList_t   ftpRespCode;
    uint8_t         ftpBasicListBuf[0];
} yfFTPFlow_t;

static fbInfoElementSpec_t yaf_imap_spec[] = {
    {C("basicList"),     FB_IE_VARLEN, 0 },
    {C("basicList"),     FB_IE_VARLEN, 0 },
    {C("basicList"),     FB_IE_VARLEN, 0 },
    {C("basicList"),     FB_IE_VARLEN, 0 },
    {C("basicList"),     FB_IE_VARLEN, 0 },
    {C("basicList"),     FB_IE_VARLEN, 0 },
    {C("basicList"),     FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfIMAPFlow_st {
    fbBasicList_t   imapCapability;
    fbBasicList_t   imapLogin;
    fbBasicList_t   imapStartTLS;
    fbBasicList_t   imapAuthenticate;
    fbBasicList_t   imapCommand;
    fbBasicList_t   imapExists;
    fbBasicList_t   imapRecent;
    uint8_t         imapBasicListBuf[0];
} yfIMAPFlow_t;


static fbInfoElementSpec_t yaf_rtsp_spec[] = {
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfRTSPFlow_st {
    fbBasicList_t   rtspURL;
    fbBasicList_t   rtspVersion;
    fbBasicList_t   rtspReturnCode;
    fbBasicList_t   rtspContentLength;
    fbBasicList_t   rtspCommand;
    fbBasicList_t   rtspContentType;
    fbBasicList_t   rtspTransport;
    fbBasicList_t   rtspCSeq;
    fbBasicList_t   rtspLocation;
    fbBasicList_t   rtspPacketsReceived;
    fbBasicList_t   rtspUserAgent;
    fbBasicList_t   rtspJitter;
    uint8_t         rtspBasicListBuf[0];
} yfRTSPFlow_t;


static fbInfoElementSpec_t yaf_sip_spec[] = {
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    {C("basicList"),      FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfSIPFlow_st {
    fbBasicList_t   sipInvite;
    fbBasicList_t   sipCommand;
    fbBasicList_t   sipVia;
    fbBasicList_t   sipMaxForwards;
    fbBasicList_t   sipAddress;
    fbBasicList_t   sipContentLength;
    fbBasicList_t   sipUserAgent;
    uint8_t         sipBasicListBuf[0];
} yfSIPFlow_t;


static fbInfoElementSpec_t yaf_nntp_spec[] = {
    {C("basicList"),    FB_IE_VARLEN, 0 },
    {C("basicList"),    FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfNNTPFlow_st {
    fbBasicList_t   nntpResponse;
    fbBasicList_t   nntpCommand;
} yfNNTPFlow_t;


/**
 * DNS!!!
 *
 */

static fbInfoElementSpec_t yaf_dns_spec[] = {
    {C("subTemplateList"), FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSFlow_st {
    fbSubTemplateList_t   dnsQRList;
} yfDNSFlow_t;


static fbInfoElementSpec_t yaf_dnsQR_spec[] = {
    {C("subTemplateList"),  FB_IE_VARLEN, 0 }, /*based on type of RR */
    {C("dnsQName"),         FB_IE_VARLEN, 0 },
    {C("dnsTTL"),           4, 0 },
    {C("dnsQRType"),        2, 0 },
    {C("dnsQueryResponse"), 1, 0 },  /*Q(0) or R(1) - uint8*/
    {C("dnsAuthoritative"), 1, 0 }, /* authoritative response (1)*/
    {C("dnsNXDomain"),      1, 0 }, /* nxdomain (1) */
    {C("dnsRRSection"),     1, 0 }, /*0, 1, 2, 3 (q, ans, auth, add'l) */
    {C("dnsID"),            2, 0 },
    {C("paddingOctets"),    4, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSQRFlow_st {
    fbSubTemplateList_t   dnsRRList;
    fbVarfield_t          dnsQName;
    uint32_t              dnsTTL;
    uint16_t              dnsQRType;
    uint8_t               dnsQueryResponse;
    uint8_t               dnsAuthoritative;
    uint8_t               dnsNXDomain;
    uint8_t               dnsRRSection;
    uint16_t              dnsID;
    uint8_t               padding[4];
} yfDNSQRFlow_t;


static fbInfoElementSpec_t yaf_dnsA_spec[] = {
    {C("sourceIPv4Address"),      4, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSAFlow_st {
    uint32_t   ip;
} yfDNSAFlow_t;

static fbInfoElementSpec_t yaf_dnsAAAA_spec[] = {
    {C("sourceIPv6Address"),      16, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSAAAAFlow_st {
    uint8_t   ip[16];
} yfDNSAAAAFlow_t;

static fbInfoElementSpec_t yaf_dnsCNAME_spec[] = {
    {C("dnsCName"),               FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSCNameFlow_st {
    fbVarfield_t   cname;
} yfDNSCNameFlow_t;

static fbInfoElementSpec_t yaf_dnsMX_spec[] = {
    {C("dnsMXExchange"),          FB_IE_VARLEN, 0 },
    {C("dnsMXPreference"),        2, 0 },
    {C("paddingOctets"),          6, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSMXFlow_st {
    fbVarfield_t   exchange;
    uint16_t       preference;
    uint8_t        padding[6];
} yfDNSMXFlow_t;

static fbInfoElementSpec_t yaf_dnsNS_spec[] = {
    {C("dnsNSDName"),             FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSNSFlow_st {
    fbVarfield_t   nsdname;
} yfDNSNSFlow_t;

static fbInfoElementSpec_t yaf_dnsPTR_spec[] = {
    {C("dnsPTRDName"),            FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSPTRFlow_st {
    fbVarfield_t   ptrdname;
} yfDNSPTRFlow_t;

static fbInfoElementSpec_t yaf_dnsTXT_spec[] = {
    {C("dnsTXTData"),             FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSTXTFlow_st {
    fbVarfield_t   txt_data;
} yfDNSTXTFlow_t;

static fbInfoElementSpec_t yaf_dnsSOA_spec[] = {
    {C("dnsSOAMName"),            FB_IE_VARLEN, 0 },
    {C("dnsSOARName"),            FB_IE_VARLEN, 0 },
    {C("dnsSOASerial"),           4, 0 },
    {C("dnsSOARefresh"),          4, 0 },
    {C("dnsSOARetry"),            4, 0 },
    {C("dnsSOAExpire"),           4, 0 },
    {C("dnsSOAMinimum"),          4, 0 },
    {C("paddingOctets"),          4, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSSOAFlow_st {
    fbVarfield_t   mname;
    fbVarfield_t   rname;
    uint32_t       serial;
    uint32_t       refresh;
    uint32_t       retry;
    uint32_t       expire;
    uint32_t       minimum;
    uint8_t        padding[4];
} yfDNSSOAFlow_t;

static fbInfoElementSpec_t yaf_dnsSRV_spec[] = {
    {C("dnsSRVTarget"),           FB_IE_VARLEN, 0 },
    {C("dnsSRVPriority"),         2, 0 },
    {C("dnsSRVWeight"),           2, 0 },
    {C("dnsSRVPort"),             2, 0 },
    {C("paddingOctets"),          2, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSSRVFlow_st {
    fbVarfield_t   dnsTarget;
    uint16_t       dnsPriority;
    uint16_t       dnsWeight;
    uint16_t       dnsPort;
    uint8_t        padding[2];
} yfDNSSRVFlow_t;


static fbInfoElementSpec_t yaf_dnsDS_spec[] = {
    {C("dnsDigest"),              FB_IE_VARLEN, 0 },
    {C("dnsKeyTag"),              2, 0 },
    {C("dnsAlgorithm"),           1, 0 },
    {C("dnsDigestType"),          1, 0 },
    {C("paddingOctets"),          4, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSDSFlow_st {
    fbVarfield_t   dnsDigest;
    uint16_t       dnsKeyTag;
    uint8_t        dnsAlgorithm;
    uint8_t        dnsDigestType;
    uint8_t        padding[4];
} yfDNSDSFlow_t;


static fbInfoElementSpec_t yaf_dnsSig_spec[] = {
    {C("dnsSigner"),              FB_IE_VARLEN, 0 },
    {C("dnsSignature"),           FB_IE_VARLEN, 0 },
    {C("dnsSignatureInception"),  4, 0 },
    {C("dnsSignatureExpiration"), 4, 0 },
    {C("dnsTTL"),                 4, 0 },
    {C("dnsKeyTag"),              2, 0 },
    {C("dnsTypeCovered"),         2, 0 },
    {C("dnsAlgorithm"),           1, 0 },
    {C("dnsLabels"),              1, 0 },
    {C("paddingOctets"),          6, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSRRSigFlow_st {
    fbVarfield_t   dnsSigner;
    fbVarfield_t   dnsSignature;
    uint32_t       dnsSigInception;
    uint32_t       dnsSigExp;
    uint32_t       dnsTTL;
    uint16_t       dnsTypeCovered;
    uint16_t       dnsKeyTag;
    uint8_t        dnsAlgorithm;
    uint8_t        dnsLabels;
    uint8_t        padding[6];
} yfDNSRRSigFlow_t;

static fbInfoElementSpec_t yaf_dnsNSEC_spec[] = {
    {C("dnsHashData"),            FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSNSECFlow_st {
    fbVarfield_t   dnsHashData;
} yfDNSNSECFlow_t;

static fbInfoElementSpec_t yaf_dnsKey_spec[] = {
    {C("dnsPublicKey"),           FB_IE_VARLEN, 0 },
    {C("dnsFlags"),               2, 0 },
    {C("protocolIdentifier"),     1, 0 },
    {C("dnsAlgorithm"),           1, 0 },
    {C("paddingOctets"),          4, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSKeyFlow_st {
    fbVarfield_t   dnsPublicKey;
    uint16_t       dnsFlags;
    uint8_t        protocol;
    uint8_t        dnsAlgorithm;
    uint8_t        padding[4];
} yfDNSKeyFlow_t;

static fbInfoElementSpec_t yaf_dnsNSEC3_spec[] = {
    {C("dnsSalt"),                FB_IE_VARLEN, 0 },
    {C("dnsHashData"),            FB_IE_VARLEN, 0 },
    {C("dnsIterations"),          2, 0 },
    {C("dnsAlgorithm"),           1, 0 },
    {C("paddingOctets"),          5, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSNSEC3Flow_st {
    fbVarfield_t   dnsSalt;
    fbVarfield_t   dnsNextDomainName;
    uint16_t       iterations;
    uint8_t        dnsAlgorithm;
    uint8_t        padding[5];
} yfDNSNSEC3Flow_t;

/**
 * SSL DPI
 *
 */

typedef struct yf_asn_tlv_st {
    uint8_t   class : 2;
    uint8_t   p_c   : 1;
    uint8_t   tag   : 5;
} yf_asn_tlv_t;

static fbInfoElementSpec_t yaf_ssl_spec[] = {
    {C("basicList"),            FB_IE_VARLEN, 0 }, /*list of ciphers 32bit */
    {C("sslServerCipher"),      4, 0 }, /*cipher suite in server hello */
    {C("sslClientVersion"),     1, 0 }, /* protocol version, 2 ssl, 3 tls */
    {C("sslCompressionMethod"), 1, 0 }, /*compression method in serv hello*/
    {C("sslRecordVersion"),     2, 0 }, /* message version */
    {C("subTemplateList"),      FB_IE_VARLEN, 0 }, /* list of certs */
    {C("sslServerName"),        FB_IE_VARLEN, 0 },
    {C("sslClientJA3"),        16, 0 },
    {C("sslServerJA3S"),        16, 0 },
    {C("sslClientJA3Fingerprint"), FB_IE_VARLEN, 0 },
    {C("sslServerJA3SFingerprint"), FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfSSLFlow_st {
    fbBasicList_t         sslCipherList;
    uint32_t              sslServerCipher;
    uint8_t               sslClientVersion;
    uint8_t               sslCompressionMethod;
    uint16_t              sslRecordVersion;
    fbSubTemplateList_t   sslCertList;
    fbVarfield_t          sslServerName;
    uint8_t               sslClientJA3[16];
    uint8_t               sslServerJA3S[16];
    fbVarfield_t          sslClientJA3Fingerprint;
    fbVarfield_t          sslServerJA3SFingerprint;
} yfSSLFlow_t;


static fbInfoElementSpec_t yaf_cert_spec[] = {
    {C("subTemplateList"),          FB_IE_VARLEN, 0 },
    {C("subTemplateList"),          FB_IE_VARLEN, 0 },
    {C("subTemplateList"),          FB_IE_VARLEN, 0 },
    {C("sslCertSignature"),         FB_IE_VARLEN, 0 },
    {C("sslCertSerialNumber"),      FB_IE_VARLEN, 0 },
    {C("sslCertValidityNotBefore"), FB_IE_VARLEN, 0 },
    {C("sslCertValidityNotAfter"),  FB_IE_VARLEN, 0 },
    {C("sslPublicKeyAlgorithm"),    FB_IE_VARLEN, 0 },
    {C("sslPublicKeyLength"),       2, 0 },
    {C("sslCertVersion"),           1, 0 },
    {C("paddingOctets"),            5, 1 },
    {C("sslCertificateHash"),       FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfSSLCertFlow_st {
    fbSubTemplateList_t   issuer;
    fbSubTemplateList_t   subject;
    fbSubTemplateList_t   extension;
    fbVarfield_t          sslCertSignature;
    fbVarfield_t          sslCertSerialNumber;
    fbVarfield_t          sslCertValidityNotBefore;
    fbVarfield_t          sslCertValidityNotAfter;
    fbVarfield_t          sslPublicKeyAlgorithm;
    uint16_t              sslPublicKeyLength;
    uint8_t               sslCertVersion;
    uint8_t               padding[5];
    fbVarfield_t          sslCertificateHash;
} yfSSLCertFlow_t;

static fbInfoElementSpec_t yaf_subssl_spec[] = {
    {C("sslObjectValue"),           FB_IE_VARLEN, 0 },
    {C("sslObjectType"),            1, 0 },
    {C("paddingOctets"),            7, 1 },
    FB_IESPEC_NULL
};

typedef struct yfSSLObjValue_st {
    fbVarfield_t   obj_value;
    uint8_t        obj_id;
    uint8_t        padding[7];
} yfSSLObjValue_t;

struct yfSSLFullCert_st {
    fbBasicList_t   cert;
};

/**
 * SSH DPI
 *
 *
*/
static fbInfoElementSpec_t yaf_ssh_spec[] = {
    {C("sshVersion"),                  FB_IE_VARLEN, 0 },
    {C("sshServerVersion"),            FB_IE_VARLEN, 0 },
    {C("sshKeyExchangeAlgorithm"),     FB_IE_VARLEN, 0 },
    {C("sshHostKeyAlgorithm"),         FB_IE_VARLEN, 0 },
    {C("sshServerHostKey"),            16, 0 },
    {C("sshCipher"),                   FB_IE_VARLEN, 0 },
    {C("sshMacAlgorithm"),             FB_IE_VARLEN, 0 },
    {C("sshCompressionMethod"),        FB_IE_VARLEN, 0 },
    {C("sshHassh"),                    16, 0 },
    {C("sshServerHassh"),              16, 0 },
    {C("sshHasshAlgorithms"),          FB_IE_VARLEN, 0 },
    {C("sshServerHasshAlgorithms"),    FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfSSHFlow_st {
    fbVarfield_t   sshVersion;
    fbVarfield_t   sshServerVersion;
    fbVarfield_t   sshKeyExchangeAlgorithm;
    fbVarfield_t   sshHostKeyAlgorithm;
    uint8_t        sshServerHostKey[16];
    fbVarfield_t   sshCipher;
    fbVarfield_t   sshMacAlgorithm;
    fbVarfield_t   sshCompressionMethod;
    uint8_t        sshHassh[16];
    uint8_t        sshServerHassh[16];
    fbVarfield_t   sshHasshAlgorithms;
    fbVarfield_t   sshServerHasshAlgorithms;
} yfSSHFlow_t;


/**
 * SMTP DPI
 *
 */

static fbInfoElementSpec_t yaf_smtp_spec[] = {
    {C("smtpHello"),        FB_IE_VARLEN, 0 },
    {C("smtpEnhanced"),     FB_IE_VARLEN, 0 },
    {C("smtpMessageSize"),  4, 0 },
    {C("smtpStartTLS"),     1, 0 },
    {C("paddingOctets"),    3, 1 },
    {C("smtpResponseList"), FB_IE_VARLEN, 0 },
    {C("smtpMessageList"),  FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfSMTPFlow_st {
    fbVarfield_t          smtpHello;
    fbVarfield_t          smtpEnhanced;
    uint32_t              smtpSize;
    uint8_t               smtpStartTLS;
    uint8_t               padding[3];
    fbBasicList_t         smtpResponseList;
    fbSubTemplateList_t   smtpMessageList;
} yfSMTPFlow_t;

static fbInfoElementSpec_t yaf_smtp_message_spec[] = {
    {C("smtpSubject"),      FB_IE_VARLEN, 0 },
    {C("smtpToList"),       FB_IE_VARLEN, 0 },
    {C("smtpFromList"),     FB_IE_VARLEN, 0 },
    {C("smtpFilenameList"), FB_IE_VARLEN, 0 },
    {C("smtpURLList"),      FB_IE_VARLEN, 0 },
    {C("smtpHeaderList"),   FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfSMTPMessage_st {
    fbVarfield_t          smtpSubject;
    fbBasicList_t         smtpToList;
    fbBasicList_t         smtpFromList;
    fbBasicList_t         smtpFilenameList;
    fbBasicList_t         smtpURLList;
    fbSubTemplateList_t   smtpHeaderList;
} yfSMTPMessage_t;

static fbInfoElementSpec_t yaf_smtp_header_spec[] = {
    {C("smtpKey"),        FB_IE_VARLEN, 0 },
    {C("smtpValue"),      FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfSMTPHeader_st {
    fbVarfield_t   smtpKey;
    fbVarfield_t   smtpValue;
} yfSMTPHeader_t;

/**
 * MySQL
 *
 */

static fbInfoElementSpec_t yaf_mysql_spec[] = {
    {C("subTemplateList"),         FB_IE_VARLEN, 0 },
    {C("mysqlUsername"),           FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfMySQLFlow_st {
    fbSubTemplateList_t   mysqlList;
    fbVarfield_t          mysqlUsername;
} yfMySQLFlow_t;

static fbInfoElementSpec_t yaf_mysql_txt_spec[] = {
    {C("mysqlCommandText"),        FB_IE_VARLEN, 0 },
    {C("mysqlCommandCode"),        1, 0 },
    {C("paddingOctets"),           7, 1 },
    FB_IESPEC_NULL
};

typedef struct yfMySQLTxtFlow_st {
    fbVarfield_t   mysqlCommandText;
    uint8_t        mysqlCommandCode;
    uint8_t        padding[7];
} yfMySQLTxtFlow_t;

/**
 * DNP
 *
 */
typedef struct yfDNP3Flow_st {
    fbSubTemplateList_t   dnp_list;
} yfDNP3Flow_t;

static fbInfoElementSpec_t yaf_dnp_spec[] = {
    {C("subTemplateList"),  FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNP3Rec_st {
    uint16_t       src_address;
    uint16_t       dst_address;
    uint8_t        function;
    uint8_t        padding[3];
    fbVarfield_t   object;
} yfDNP3Rec_t;

static fbInfoElementSpec_t yaf_dnp_rec_spec[] = {
    {C("dnp3SourceAddress"),      2, 0 },
    {C("dnp3DestinationAddress"), 2, 0 },
    {C("dnp3Function"),           1, 0 },
    {C("paddingOctets"),          3, 1 },
    {C("dnp3ObjectData"),         FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};

typedef struct yfRTPFlow_st {
    uint8_t   rtpPayloadType;
    uint8_t   reverseRtpPayloadType;
} yfRTPFlow_t;

static fbInfoElementSpec_t yaf_rtp_spec[] = {
    {C("rtpPayloadType"),        1, 0 },
    {C("reverseRtpPayloadType"), 1, 0 },
    FB_IESPEC_NULL
};

/**
 * Initialization functions
 *
 */

static void
ypParsePluginOpt(
    yfDPIContext_t  *ctx,
    const char      *option);

static gboolean
ypInitializeProtocolRules(
    yfDPIContext_t  *ctx,
    FILE            *dpiRuleFile,
    GError         **err);

static fbTemplate_t *
ypInitTemplate(
    fbSession_t          *session,
    fbInfoElementSpec_t  *spec,
    uint16_t              tid,
    const gchar          *name,
    const gchar          *description,
    uint32_t              flags,
    GError              **err);

static uint16_t
ypProtocolHashSearch(
    DPIActiveHash_t  *active,
    uint16_t          portNum,
    uint16_t          insert);

static gboolean
ypProtocolHashActivate(
    yfDPIContext_t  *ctx,
    uint16_t         portNum,
    uint16_t         index);

static void
ypProtocolHashDeactivate(
    yfDPIContext_t  *ctx,
    uint16_t         portNum);

static void
ypProtocolHashInitialize(
    yfDPIContext_t  *ctx);

static gboolean
ypPluginRegex(
    yfDPIContext_t  *ctx,
    uint16_t         elementID,
    int              index);


/**
 * DPI Essential FUNCTIONS
 *
 */

static void
ypFillBasicList(
    yfFlow_t      *flow,
    yfDPIData_t   *dpi,
    uint8_t        totalCaptures,
    uint8_t        forwardCaptures,
    fbVarfield_t **varField,
    uint8_t       *indexArray);

static uint8_t
ypDPIScanner(
    ypDPIFlowCtx_t  *flowContext,
    const uint8_t   *payloadData,
    unsigned int     payloadSize,
    uint32_t         offset,
    yfFlow_t        *flow,
    yfFlowVal_t     *val);


/**
 * DPI FREE FUNCTIONS
 *
 */

static void
ypFreeSLPRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeSSLRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeIRCRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreePOP3Rec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeTFTPRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeSMTPRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeNNTPRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeDNSRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeMySQLRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeDNPRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeModbusRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeEnIPRec(
    ypDPIFlowCtx_t  *flowContext);

static void
ypFreeSSHRec(
    ypDPIFlowCtx_t  *flowContext);

/**
 * DPI PROCESS FUNCTIONS
 *
 */

static void *
ypProcessGenericRegex(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos,
    uint16_t                        stmlTID,
    fbTemplate_t                   *stmlTemplate,
    uint8_t                         numBasicLists);

static void *
ypProcessGenericPlugin(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos,
    uint16_t                        stmlTID,
    fbTemplate_t                   *stmlTemplate,
    const char                     *blIEName);

static void *
ypProcessSLP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos);

static void *
ypProcessSSL(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiList_t       *mainRec,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos);


static void *
ypProcessTFTP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos);

static void *
ypProcessSMTP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos);

static void *
ypProcessNNTP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos);

static void *
ypProcessDNS(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos);

static void *
ypProcessMySQL(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos);

static void *
ypProcessDNP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos);

static void *
ypProcessRTP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos);


static void *
ypProcessSSH(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos);

/**
 * DNS PARSING
 *
 */

static void
ypDnsParser(
    yfDNSQRFlow_t **dnsQRecord,
    yfFlow_t       *flow,
    yfFlowVal_t    *val,
    uint8_t        *buf,
    unsigned int   *bufLen,
    uint8_t         recordCount,
    uint16_t        export_limit,
    gboolean        dnssec);

static uint16_t
ypDnsScanResourceRecord(
    yfDNSQRFlow_t **dnsQRecord,
    const uint8_t  *payload,
    unsigned int    payloadSize,
    uint16_t       *offset,
    uint8_t        *buf,
    unsigned int   *bufLen,
    uint16_t        export_limit,
    gboolean        dnssec);

static unsigned int
ypDnsEscapeValue(
    uint8_t        *dst,
    unsigned int    dst_size,
    const uint8_t  *src,
    unsigned int    src_size,
    gboolean        escape_dots);

static unsigned int
ypDnsGetName(
    uint8_t        *export_buffer,
    unsigned int    export_offset,
    const uint8_t  *payload,
    unsigned int    payload_size,
    uint16_t       *payload_offset,
    uint16_t        export_limit);


/**
 * SSL CERT Parsing
 *
 */

static gboolean
ypDecodeSSLCertificate(
    yfDPIContext_t   *ctx,
    yfSSLCertFlow_t **sslCert,
    const uint8_t    *payload,
    unsigned int      payloadSize,
    yfFlow_t         *flow,
    uint32_t          offsetptr);

static void
ypSslServerJA3S(
    uint16_t       scipher,
    uint16_t       sversion,
    char          *ser_extension,
    uint8_t       *smd5,
    fbVarfield_t  *string);

static void
ypSslClientJA3(
    fbBasicList_t  *ciphers,
    char           *ser_extension,
    uint16_t       *elliptic_curve,
    char           *elliptic_format,
    uint16_t        version,
    int             ellip_curve_len,
    uint8_t        *md5,
    fbVarfield_t   *string);

#if HAVE_OPENSSL
static void
ypComputeMD5(
    const char  *string,
    int          len,
    uint8_t     *mdbuff);
#else  /* HAVE_OPENSSL */
#define computeMD5(_s, _l, _buf)   memset(_buf, 0, 16)
#endif  /* HAVE_OPENSSL */

static gboolean
ypSslGreaseTableCheck(
    uint16_t   value);

static char *
ypSslStoreExtension(
    const uint8_t  *payload);

#endif /* #if YAF_ENABLE_APPLABEL */
#endif /* #if YAF_ENABLE_HOOKS */

/**
 * SSH Parsing
 *
 *
*/

#if YAF_ENABLE_HOOKS
static void
ypSshHASSH(
    GString       *kex,
    const gchar   *encryp,
    const gchar   *mac,
    const gchar   *compression,
    uint8_t       *md5,
    fbVarfield_t  *string);

static void
ypSshAlgoCompare(
    const GString *str,
    const GString *str2,
    fbVarfield_t  *str3);
#endif
