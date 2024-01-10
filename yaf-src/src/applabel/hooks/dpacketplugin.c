/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  dpacketplugin.c
 *
 *  Provides a plugin to inspect payloads and export the data
 *  in ipfix template format.  See yafdpi(1)
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

#define _YAF_SOURCE_

#include "dpacketplugin.h"

#if YAF_ENABLE_APPLABEL
#if YAF_ENABLE_HOOKS

#include "../../../infomodel/yaf_dpi.i"

/* for reading files */
/* #define MAX_PAYLOAD_RULES       1024 */
#define LINE_BUF_SIZE           4096
/* pcre rule limit */
#define NUM_SUBSTRING_VECTS     60
/* limit the length of strings */
#define MAX_CAPTURE_LENGTH      200
/* max num of DPI fields we'll export - total */
#define YAF_MAX_CAPTURE_FIELDS  50
/* per side */
#define YAF_MAX_CAPTURE_SIDE    25
/* DNS Max Name length */
#define DNS_MAX_NAME_LENGTH     255
/* SMTP Max Num Emails */
#define SMTP_MAX_EMAILS         10

/* User Limit on New Labels */
#define USER_LIMIT              30
/* Minimum Number of BasicLists sent for each protocol */
#define YAF_HTTP_STANDARD       20
#define YAF_FTP_STANDARD        5
#define YAF_IMAP_STANDARD       7
#define YAF_RTSP_STANDARD       12
#define YAF_SIP_STANDARD        7
//#define YAF_SSH_STANDARD        1
#define YAF_SMTP_STANDARD       11

/* incremement below to add a new protocol - 0 needs to be first */
/*#define DPI_TOTAL_PROTOCOLS 22*/

/**
 * SSL and SSH Declarations are refreced from paylloadScanner.h
*/

#define DPI_REGEX_PROTOCOLS 8

static const uint16_t   regexDPIProtos[] = {21, 80, 143, 554, 5060,
                                            20000, 502, 44818};
static const uint16_t   DPIProtocols[] = {0, 21, 22, 25, 53, 69, 80, 110, 119,
                                          143, 194, 427, 443, 554, 873,
                                          1723, 5060, 3306, 20000, 502, 44818,
                                          5004};

static DPIActiveHash_t *global_active_protos;
/* export DNSSEC info - NO by default */
static gboolean         dnssec_global = FALSE;
static gboolean         fullcert_global = FALSE;
static gboolean         certhash_global = FALSE;


/**
 *
 * file globals
 *
 */
/*static ypBLValue_t *appRuleArray[UINT16_MAX + 1];
 * static protocolRegexRules_t ruleSet[DPI_TOTAL_PROTOCOLS + 1];
 *
 * static char *dpiRulesFileName = NULL;
 * static unsigned int dpiInitialized = 0;
 *
 * static DPIActiveHash_t dpiActiveHash[MAX_PAYLOAD_RULES];
 *
 * static uint16_t dpi_user_limit = MAX_CAPTURE_LENGTH;
 * static uint16_t dpi_user_total_limit = 1000;
 */
/**
 * the first number is the meta data structure version
 * the second number is the _maximum_ number of bytes the plugin will export
 * the third number is if it requires application labeling (1 for yes)
 */
static struct yfHookMetaData metaData = {
    6,
    1000,
    1
};

/* For DNS binary octet escaping */
static const uint8_t hex_digits[] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

/* to support protocols that support expandable lists---lists with
 * user-defined elements */
typedef struct ypExtraElements_st {
    /* number of elements in the standard spec array */
    const unsigned int    standard;
    /* total number of elements in the spec array */
    unsigned int          count;
    /* used if addtional space is needed above the standard count */
    fbInfoElementSpec_t  *specs;
} ypExtraElements_t;

static ypExtraElements_t ftp_extra  = { YAF_FTP_STANDARD,  0, NULL };
static ypExtraElements_t http_extra = { YAF_HTTP_STANDARD, 0, NULL };
static ypExtraElements_t imap_extra = { YAF_IMAP_STANDARD, 0, NULL };
static ypExtraElements_t rtsp_extra = { YAF_RTSP_STANDARD, 0, NULL };
static ypExtraElements_t sip_extra  = { YAF_SIP_STANDARD,  0, NULL };


static fbTemplate_t     *ircTemplate;
static fbTemplate_t     *pop3Template;
static fbTemplate_t     *tftpTemplate;
static fbTemplate_t     *slpTemplate;
static fbTemplate_t     *httpTemplate;
static fbTemplate_t     *ftpTemplate;
static fbTemplate_t     *imapTemplate;
static fbTemplate_t     *rtspTemplate;
static fbTemplate_t     *sipTemplate;
static fbTemplate_t     *smtpTemplate;
static fbTemplate_t     *smtpMessageTemplate;
static fbTemplate_t     *smtpHeaderTemplate;
static fbTemplate_t     *sshTemplate;
static fbTemplate_t     *nntpTemplate;
static fbTemplate_t     *dnsTemplate;
static fbTemplate_t     *dnsQRTemplate;
static fbTemplate_t     *dnsATemplate;
static fbTemplate_t     *dnsAAAATemplate;
static fbTemplate_t     *dnsCNTemplate;
static fbTemplate_t     *dnsMXTemplate;
static fbTemplate_t     *dnsNSTemplate;
static fbTemplate_t     *dnsPTRTemplate;
static fbTemplate_t     *dnsTXTTemplate;
static fbTemplate_t     *dnsSRVTemplate;
static fbTemplate_t     *dnsSOATemplate;
static fbTemplate_t     *sslTemplate;
static fbTemplate_t     *sslCertTemplate;
static fbTemplate_t     *sslSubTemplate;
static fbTemplate_t     *sslFullCertTemplate;
static fbTemplate_t     *mysqlTemplate;
static fbTemplate_t     *mysqlTxtTemplate;
static fbTemplate_t     *dnsDSTemplate;
static fbTemplate_t     *dnsNSEC3Template;
static fbTemplate_t     *dnsNSECTemplate;
static fbTemplate_t     *dnsRRSigTemplate;
static fbTemplate_t     *dnsKeyTemplate;
static fbTemplate_t     *dnp3Template;
static fbTemplate_t     *dnp3RecTemplate;
static fbTemplate_t     *modbusTemplate;
static fbTemplate_t     *enipTemplate;
static fbTemplate_t     *rtpTemplate;


static void
yfAlignmentCheck1(
    void)
{
    size_t prevOffset = 0;
    size_t prevSize = 0;

#define DO_SIZE(S_, F_) (SIZE_T_CAST)sizeof(((S_ *)(0))->F_)
#define EA_STRING(S_, F_)                            \
    "alignment error in struct " #S_ " for element " \
    #F_ " offset %#"SIZE_T_FORMATX " size %"         \
    SIZE_T_FORMAT " (pad %"SIZE_T_FORMAT ")",        \
    (SIZE_T_CAST)offsetof(S_, F_), DO_SIZE(S_, F_),  \
    (SIZE_T_CAST)(offsetof(S_, F_) % DO_SIZE(S_, F_))
#define EG_STRING(S_, F_)                              \
    "gap error in struct " #S_ " for element " #F_     \
    " offset %#"SIZE_T_FORMATX " size %"SIZE_T_FORMAT, \
    (SIZE_T_CAST)offsetof(S_, F_),                     \
    DO_SIZE(S_, F_)
#define RUN_CHECKS(S_, F_, A_)                                   \
    {                                                            \
        if (((offsetof(S_, F_) % DO_SIZE(S_, F_)) != 0) && A_) { \
            g_error(EA_STRING(S_, F_));                          \
        }                                                        \
        if (offsetof(S_, F_) != (prevOffset + prevSize)) {       \
            g_error(EG_STRING(S_, F_));                          \
            return;                                              \
        }                                                        \
        prevOffset = offsetof(S_, F_);                           \
        prevSize = DO_SIZE(S_, F_);                              \
        /*fprintf(stderr, "%17s %40s %#5lx %3d %#5lx\n", #S_, #F_, \
         *      offsetof(S_,F_), DO_SIZE(S_,F_), \
         *      offsetof(S_,F_)+DO_SIZE(S_,F_));*/ \
    }

    RUN_CHECKS(yfSSLFlow_t, sslCipherList, 1);
    RUN_CHECKS(yfSSLFlow_t, sslServerCipher, 1);
    RUN_CHECKS(yfSSLFlow_t, sslClientVersion, 1);
    RUN_CHECKS(yfSSLFlow_t, sslCompressionMethod, 1);
    RUN_CHECKS(yfSSLFlow_t, sslRecordVersion, 1);
    RUN_CHECKS(yfSSLFlow_t, sslCertList, 0);
    RUN_CHECKS(yfSSLFlow_t, sslServerName, 1);
    RUN_CHECKS(yfSSLFlow_t, sslClientJA3, 1);
    RUN_CHECKS(yfSSLFlow_t, sslServerJA3S, 1);
    RUN_CHECKS(yfSSLFlow_t, sslClientJA3Fingerprint, 1);
    RUN_CHECKS(yfSSLFlow_t, sslServerJA3SFingerprint, 1);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfSSLObjValue_t, obj_value, 1);
    RUN_CHECKS(yfSSLObjValue_t, obj_id, 1);
    RUN_CHECKS(yfSSLObjValue_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSQRFlow_t, dnsRRList, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsQName, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsTTL, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsQRType, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsQueryResponse, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsAuthoritative, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsNXDomain, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsRRSection, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsID, 1);
    RUN_CHECKS(yfDNSQRFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfSSLCertFlow_t, issuer, 1);
    RUN_CHECKS(yfSSLCertFlow_t, subject, 1);
    RUN_CHECKS(yfSSLCertFlow_t, extension, 1);
    RUN_CHECKS(yfSSLCertFlow_t, sslCertSignature, 1);
    RUN_CHECKS(yfSSLCertFlow_t, sslCertSerialNumber, 1);
    RUN_CHECKS(yfSSLCertFlow_t, sslCertValidityNotBefore, 1);
    RUN_CHECKS(yfSSLCertFlow_t, sslCertValidityNotAfter, 1);
    RUN_CHECKS(yfSSLCertFlow_t, sslPublicKeyAlgorithm, 1);
    RUN_CHECKS(yfSSLCertFlow_t, sslPublicKeyLength, 1);
    RUN_CHECKS(yfSSLCertFlow_t, sslCertVersion, 1);
    RUN_CHECKS(yfSSLCertFlow_t, padding, 0);
    RUN_CHECKS(yfSSLCertFlow_t, sslCertificateHash, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSSOAFlow_t, mname, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, rname, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, serial, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, refresh, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, retry, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, expire, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, minimum, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSSRVFlow_t, dnsTarget, 1);
    RUN_CHECKS(yfDNSSRVFlow_t, dnsPriority, 1);
    RUN_CHECKS(yfDNSSRVFlow_t, dnsWeight, 1);
    RUN_CHECKS(yfDNSSRVFlow_t, dnsPort, 1);
    RUN_CHECKS(yfDNSSRVFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSMXFlow_t, exchange, 1);
    RUN_CHECKS(yfDNSMXFlow_t, preference, 1);
    RUN_CHECKS(yfDNSMXFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSDSFlow_t, dnsDigest, 1);
    RUN_CHECKS(yfDNSDSFlow_t, dnsKeyTag, 1);
    RUN_CHECKS(yfDNSDSFlow_t, dnsAlgorithm, 1);
    RUN_CHECKS(yfDNSDSFlow_t, dnsDigestType, 1);
    RUN_CHECKS(yfDNSDSFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSRRSigFlow_t, dnsSigner, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsSignature, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsSigInception, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsSigExp, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsTTL, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsTypeCovered, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsKeyTag, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsAlgorithm, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsLabels, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSNSECFlow_t, dnsHashData, 1);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSKeyFlow_t, dnsPublicKey, 1);
    RUN_CHECKS(yfDNSKeyFlow_t, dnsFlags, 1);
    RUN_CHECKS(yfDNSKeyFlow_t, protocol, 1);
    RUN_CHECKS(yfDNSKeyFlow_t, dnsAlgorithm, 1);
    RUN_CHECKS(yfDNSKeyFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSNSEC3Flow_t, dnsSalt, 1);
    RUN_CHECKS(yfDNSNSEC3Flow_t, dnsNextDomainName, 1);
    RUN_CHECKS(yfDNSNSEC3Flow_t, iterations, 1);
    RUN_CHECKS(yfDNSNSEC3Flow_t, dnsAlgorithm, 1);
    RUN_CHECKS(yfDNSNSEC3Flow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfMySQLFlow_t, mysqlList, 1);
    RUN_CHECKS(yfMySQLFlow_t, mysqlUsername, 1);

    prevOffset = 0;
    prevSize = 0;
    RUN_CHECKS(yfMySQLTxtFlow_t, mysqlCommandText, 1);
    RUN_CHECKS(yfMySQLTxtFlow_t, mysqlCommandCode, 1);
    RUN_CHECKS(yfMySQLTxtFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfSSHFlow_t, sshVersion, 1);
    RUN_CHECKS(yfSSHFlow_t, sshServerVersion, 1);
    RUN_CHECKS(yfSSHFlow_t, sshKeyExchangeAlgorithm, 1);
    RUN_CHECKS(yfSSHFlow_t, sshHostKeyAlgorithm, 1);
    RUN_CHECKS(yfSSHFlow_t, sshServerHostKey, 1);
    RUN_CHECKS(yfSSHFlow_t, sshCipher, 1);
    RUN_CHECKS(yfSSHFlow_t, sshMacAlgorithm, 1);
    RUN_CHECKS(yfSSHFlow_t, sshCompressionMethod, 1);
    RUN_CHECKS(yfSSHFlow_t, sshHassh, 1);
    RUN_CHECKS(yfSSHFlow_t, sshServerHassh, 1);
    RUN_CHECKS(yfSSHFlow_t, sshHasshAlgorithms, 1);
    RUN_CHECKS(yfSSHFlow_t, sshServerHasshAlgorithms, 1);



#undef DO_SIZE
#undef EA_STRING
#undef EG_STRING
#undef RUN_CHECKS
}


/**
 * hookInitialize
 *
 *
 * @param err
 *
 */
static gboolean
ypHookInitialize(
    yfDPIContext_t  *ctx,
    const char      *dpiFQFileName,
    GError         **err)
{
    FILE *dpiRuleFile = NULL;
    int   i;

    if (NULL == dpiFQFileName) {
        dpiFQFileName = YAF_CONF_DIR "/yafDPIRules.conf";
    }

    dpiRuleFile = fopen(dpiFQFileName, "r");
    if (NULL == dpiRuleFile) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "open Deep Packet Inspection Rule File \"%s\" for reading",
                           dpiFQFileName);
        return FALSE;
    }

    /* clear out rule array */
    for (i = 0; i < UINT16_MAX + 1; i++) {
        ctx->appRuleArray[i] = NULL;
    }

    g_debug("Initializing Rules from DPI File %s", dpiFQFileName);
    if (!ypInitializeProtocolRules(ctx, dpiRuleFile, err)) {
        return FALSE;
    }

    yfAlignmentCheck1();

    fclose(dpiRuleFile);

    ctx->dpiInitialized = 1;

    return TRUE;
}


/**
 * flowAlloc
 *
 * Callback invoked by yfHookFlowAlloc().  Function signature defined by
 * yfHookFlowAlloc_fn.  Referenced by yfHooksFuncs_t.flowAlloc.
 *
 * Allocate the hooks struct here, but don't allocate the DPI struct
 * until we want to fill it so we don't have to hold empty memory for long.
 *
 *
 */
void
ypFlowAlloc(
    void     **yfHookContext,
    yfFlow_t  *flow,
    void      *yfctx)
{
    ypDPIFlowCtx_t *newFlowContext = NULL;

    newFlowContext = (ypDPIFlowCtx_t *)g_slice_alloc0(sizeof(ypDPIFlowCtx_t));

    newFlowContext->dpinum = 0;
    newFlowContext->startOffset = 0;
    newFlowContext->exbuf = NULL;
    newFlowContext->dpi = NULL;
    newFlowContext->yfctx = yfctx;

    *yfHookContext = (void *)newFlowContext;
}


/**
 * getDPIInfoModel
 *
 *
 *
 * @return a pointer to a fixbuf info model
 *
 */
static fbInfoModel_t *
ypGetDPIInfoModel(
    void)
{
    static fbInfoModel_t *yaf_dpi_model = NULL;
    if (!yaf_dpi_model) {
        yaf_dpi_model = fbInfoModelAlloc();
        fbInfoModelAddElementArray(yaf_dpi_model,
                                   infomodel_array_static_yaf_dpi);
    }

    return yaf_dpi_model;
}


/**
 * flowClose
 *
 * Callback invoked by yfHookFlowClose().  Function signature defined by
 * yfHookFlowClose_fn.  Referenced by yfHooksFuncs_t.flowClose.
 *
 *
 * @param flow a pointer to the flow structure that maintains all the flow
 *             context
 *
 */
gboolean
ypFlowClose(
    void      *yfHookContext,
    yfFlow_t  *flow)
{
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t *ctx;
    uint8_t         newDPI;
    int             pos;

    if (NULL == flowContext) {
        /* log an error here, but how */
        return FALSE;
    }

    ctx = flowContext->yfctx;

    if (ctx->dpiInitialized == 0) {
        return TRUE;
    }

    if (flowContext->dpi == NULL) {
        flowContext->dpi = g_slice_alloc0(YAF_MAX_CAPTURE_FIELDS *
                                          sizeof(yfDPIData_t));
    }

    if (flow->appLabel) {
        pos = ypProtocolHashSearch(ctx->dpiActiveHash, flow->appLabel, 0);
        /* applabel isn't a dpi applabel or the rule type isn't REGEX */
        /* plugin decoders handle the DPI in the plugins */
        if (!pos || (ycGetRuleType(flow->appLabel) != REGEX)) {
            return TRUE;
        }
        /* Do DPI Processing from Rule Files */
        newDPI = ypDPIScanner(flowContext, flow->val.payload,
                              flow->val.paylen, 0, flow, &(flow->val));
        flowContext->captureFwd += newDPI;
        if (flow->rval.paylen) {
            newDPI = ypDPIScanner(flowContext, flow->rval.payload,
                                  flow->rval.paylen, 0, flow, &(flow->rval));
        }
    }

    /*fprintf(stderr, "closing flow %p with context %p\n", flow,flowContext);*/

    return TRUE;
}


/**
 * ypValidateFlowTab
 *
 * Callback invoked by yfHookValidateFlowTab().  Function signature defined by
 * yfHookValidateFlowTab_fn.  Referenced by yfHooksFuncs_t.validateFlowTab.
 *
 * returns FALSE if applabel mode is disabled, true otherwise
 *
 */
gboolean
ypValidateFlowTab(
    void      *yfctx,
    uint32_t   max_payload,
    gboolean   uniflow,
    gboolean   silkmode,
    gboolean   applabelmode,
    gboolean   entropymode,
    gboolean   fingerprintmode,
    gboolean   fpExportMode,
    gboolean   udp_max_payload,
    uint16_t   udp_uniflow_port,
    GError   **err)
{
    if (!applabelmode) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                    "ERROR: dpacketplugin.c will not operate without --applabel");
        return FALSE;
    }

    return TRUE;
}


/**
 * ypSearchPlugOpts
 *
 * check if DPI is turned on for this label
 *
 * @param appLabel
 * @return offset in Rule Array
 *
 */
static uint16_t
ypSearchPlugOpts(
    DPIActiveHash_t  *active,
    uint16_t          appLabel)
{
    uint16_t rc;

    rc = ypProtocolHashSearch(active, appLabel, 0);

    return rc;
}


/**
 * ypAddRuleKey
 *
 * @param appLabel
 * @param InfoElementId
 * @param fbBasicList_t*
 * @param fbInfoElement_t *
 */
static void
ypAddRuleKey(
    yfDPIContext_t         *ctx,
    uint16_t                applabel,
    uint16_t                id,
    const fbInfoElement_t  *ie,
    size_t                  bl)
{
    ypBLValue_t *val = NULL;

    val = g_slice_new0(ypBLValue_t);

    val->BLoffset = bl;
    val->infoElement = ie;

    if (ctx->appRuleArray[id] != NULL) {
        g_warning("Found multiple rules with the same ID: %d", id);
    }

    ctx->appRuleArray[id] = val;
}


/**
 * ypGetRule
 *
 * @param id ID of information element
 * @return ypBLValue_t
 *
 */
static ypBLValue_t *
ypGetRule(
    yfDPIContext_t  *ctx,
    uint16_t         id)
{
    return ctx->appRuleArray[id];
}


/**
 * ypAddSpec
 *
 * This creates a spec array for each protocol that allow users to add
 * their own basicList elements.  It then adds the given element to that
 * spec array and increments the counter for the amount of elements in the
 * array.  Returns -1 if applabel is not valid or max rule limit is exceeded.
 *
 * @param spec fbInfoElementSpec_t
 * @param applabel
 * @param offset
 *
 */
static int
ypAddSpec(
    fbInfoElementSpec_t  *spec,
    uint16_t              applabel,
    size_t               *offset)
{
    ypExtraElements_t *extra = NULL;

    g_assert(spec);

    switch (applabel) {
      case 80:
        extra = &http_extra;
        break;
      case 143:
        extra = &imap_extra;
        break;
      case 21:
        extra = &ftp_extra;
        break;
      case 554:
        extra = &rtsp_extra;
        break;
      case 5060:
        extra = &sip_extra;
        break;
      default:
        g_warning("May not add a DPI rule for applabel %u", applabel);
        return -1;
    }

    if (extra->count >= (extra->standard + USER_LIMIT)) {
        g_warning("User Limit Exceeded.  Max Rules permitted for proto "
                  "%d is: %d", applabel, extra->standard + USER_LIMIT);
        return -1;
    }

    if (extra->count >= extra->standard) {
        if (!extra->specs) {
            extra->specs = g_new0(fbInfoElementSpec_t, USER_LIMIT);
        }
        memcpy(extra->specs + (extra->count - extra->standard),
               spec, sizeof(fbInfoElementSpec_t));
    }
    *offset = (sizeof(fbBasicList_t) * extra->count);
    ++extra->count;
    return extra->count;
}


/**
 * ypInitializeProtocolRules
 *
 * @param dpiRuleFile
 * @param err
 *
 */
static gboolean
ypInitializeProtocolRules(
    yfDPIContext_t  *ctx,
    FILE            *dpiRuleFile,
    GError         **err)
{
    int         rulePos = 1;
    const char *errorString;
    int         errorPos, rc, readLength, BLoffset;
    int         tempNumRules = 0;
    int         tempNumProtos = 0;
    char        lineBuffer[LINE_BUF_SIZE];
    pcre       *ruleScanner;
    pcre       *commentScanner;
    pcre       *newRuleScanner;
    pcre       *fieldScanner;
    pcre       *totalScanner;
    pcre       *certExpScanner;
    pcre       *certHashScanner;
    pcre       *newRule;
    pcre_extra *newExtra;
    const char  commentScannerExp[] = "^\\s*#[^\\n]*\\n";
    const char  ruleScannerExp[] =
        "^[[:space:]]*label[[:space:]]+([[:digit:]]+)"
        "[[:space:]]+yaf[[:space:]]+([[:digit:]]+)[[:space:]]+"
        "((?:[^ \\n]| +[^ \\n])+)[ \\t]*\\n";
    const char newRuleScannerExp[] =
        "^[[:space:]]*label[[:space:]]+([[:digit:]]+)"
        "[[:space:]]+user[[:space:]]+([[:digit:]]+)[[:space:]]+"
        "name[[:space:]]+([a-zA-Z0-9_]+)[[:space:]]+"
        "((?:[^ \\n]| +[^ \\n])+)[ \\t]*\\n";
    const char   fieldLimitExp[] =
        "^[[:space:]]*limit[[:space:]]+field[[:space:]]+"
        "([[:digit:]]+)\\n";
    const char   totalLimitExp[] =
        "^[[:space:]]*limit[[:space:]]+total[[:space:]]+"
        "([[:digit:]]+)\\n";
    const char   certExportExp[] =
        "^[[:space:]]*cert_export_enabled[[:space:]]*="
        "[[:space:]]*+([[:digit:]])\\n";
    const char   certHashExp[] =
        "^[[:space:]]*cert_hash_enabled[[:space:]]*="
        "[[:space:]]*([[:digit:]])\\n";
    unsigned int bufferOffset = 0;
    int          currentStartPos = 0;
    int          substringVects[NUM_SUBSTRING_VECTS];
    char        *captString;
    uint16_t     applabel, elem_id;
    int          limit;
    const fbInfoElement_t *elem = NULL;
    fbInfoElementSpec_t    spec = {C("basicList"), 0, 0};
    fbInfoElement_t        add_element;
    size_t struct_offset;
    fbInfoModel_t         *model = ypGetDPIInfoModel();
    protocolRegexRules_t  *ruleSet;

    for (rc = 0; rc < DPI_TOTAL_PROTOCOLS + 1; rc++) {
        ctx->ruleSet[rc].numRules = 0;
    }

    ruleScanner = pcre_compile(ruleScannerExp, PCRE_MULTILINE, &errorString,
                               &errorPos, NULL);
    if (ruleScanner == NULL) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL,
                    "Couldn't build the DPI Rule Scanner: %s", errorString);
        return FALSE;
    }

    commentScanner = pcre_compile(commentScannerExp, PCRE_MULTILINE,
                                  &errorString, &errorPos, NULL);
    if (commentScanner == NULL) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL,
                    "Couldn't build the DPI Comment Scanner: %s", errorString);
        return FALSE;
    }

    newRuleScanner = pcre_compile(newRuleScannerExp, PCRE_MULTILINE,
                                  &errorString, &errorPos, NULL);
    if (newRuleScanner == NULL) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL,
                    "Couldn't build the DPI New Rule Scanner: %s", errorString);
        return FALSE;
    }

    fieldScanner = pcre_compile(fieldLimitExp, PCRE_MULTILINE,
                                &errorString, &errorPos, NULL);
    if (fieldScanner == NULL) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL,
                    "Couldn't build the DPI field Limit Scanner: %s",
                          errorString);
        return FALSE;
    }

    totalScanner = pcre_compile(totalLimitExp, PCRE_MULTILINE,
                                &errorString, &errorPos, NULL);
    if (totalScanner == NULL) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL,
                    "Couldn't build the DPI total Limit Scanner: %s",
                    errorString);
        return FALSE;
    }

    certExpScanner = pcre_compile(certExportExp, PCRE_MULTILINE,
                                  &errorString, &errorPos, NULL);
    if (certExpScanner == NULL) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL,
                    "Couldn't build the DPI Cert Exporter Scanner %s",
                    errorString);
        return FALSE;
    }

    certHashScanner = pcre_compile(certHashExp, PCRE_MULTILINE,
                                   &errorString, &errorPos, NULL);
    if (certHashScanner == NULL) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL,
                    "Couldn't build the DPI Cert Hash Scanner: %s",
                    errorString);
        return FALSE;
    }

    do {
        readLength = fread(lineBuffer + bufferOffset, 1, LINE_BUF_SIZE - 1 -
                           bufferOffset, dpiRuleFile);
        if (readLength == 0) {
            if (ferror(dpiRuleFile)) {
                g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                            "Couldn't read the DPI Rule File: %s",
                            strerror(errno));
                return FALSE;
            }
            break;
        }
        readLength += bufferOffset;
        substringVects[0] = 0;
        substringVects[1] = 0;

        while (substringVects[1] < readLength) {
            if ('\n' == *(lineBuffer + substringVects[1])
                || '\r' == *(lineBuffer + substringVects[1]))
            {
                substringVects[1]++;
                continue;
            }
            currentStartPos = substringVects[1];
            rc = pcre_exec(commentScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                continue;
            }

            substringVects[1] = currentStartPos;

            rc = pcre_exec(ruleScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                /* the applabel */
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                applabel = strtoul(captString, NULL, 10);
                rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, applabel, 0);
                if (!rulePos) {
                    /* protocol not turned on */
                    pcre_free(captString);
                    continue;
                }
                ruleSet = &ctx->ruleSet[rulePos];
                pcre_free(captString);

                /* the info element */
                pcre_get_substring(lineBuffer, substringVects, rc, 2,
                                   (const char **)&captString);
                elem_id = strtoul(captString, NULL, 10);
                elem = fbInfoModelGetElementByID(model, elem_id, CERT_PEN);
                if (!elem) {
                    g_warning("Element %d does not exist in Info Model.  "
                              "Please add Element to Model or use the "
                              "'new element' rule", elem_id);
                    pcre_free(captString);
                    continue;
                }
                ruleSet->applabel = applabel;
                ruleSet->regexFields[ruleSet->numRules].info_element_id =
                    elem_id;
                ruleSet->regexFields[ruleSet->numRules].elem =
                    elem;
                ruleSet->ruleType = ycGetRuleType(applabel);
                pcre_free(captString);

                /* the regex */
                pcre_get_substring(lineBuffer, substringVects, rc, 3,
                                   (const char **)&captString);
                newRule = pcre_compile(captString, PCRE_MULTILINE,
                                       &errorString, &errorPos, NULL);
                if (NULL == newRule) {
                    g_warning("Error Parsing DPI Rule for label %d yaf %d:"
                              " \"%s\": %s at position %d",
                              applabel, elem_id, captString,
                              errorString, errorPos);
                } else {
                    newExtra = pcre_study(newRule, 0, &errorString);
                    ruleSet->regexFields[ruleSet->numRules].rule = newRule;
                    ruleSet->regexFields[ruleSet->numRules].extra = newExtra;
                    ruleSet->numRules++;
                    tempNumRules++;
                }
                pcre_free(captString);
                /* add elem to rule array - if it doesn't exist already */
                if (!ctx->appRuleArray[elem_id]) {
                    /* get offset of element -
                     * basically which basicList in struct */
                    if (ypAddSpec(&spec, applabel, &struct_offset) == -1) {
                        exit(EXIT_FAILURE);
                    }
                    ypAddRuleKey(ctx, applabel, elem_id, elem, struct_offset);
                }

                if (MAX_PAYLOAD_RULES == ruleSet->numRules) {
                    g_warning("Maximum number of rules has been reached "
                              "within DPI Plugin");
                    break;
                }

                continue;
            }
            substringVects[1] = currentStartPos;

            rc = pcre_exec(newRuleScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                /* the applabel */
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                applabel = strtoul(captString, NULL, 10);
                rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, applabel, 0);
                if (!rulePos) {
                    /* protocol not turned on */
                    pcre_free(captString);
                    continue;
                }
                ruleSet = &ctx->ruleSet[rulePos];
                ruleSet->applabel = applabel;
                ruleSet->ruleType = ycGetRuleType(applabel);
                pcre_free(captString);

                /* the info element id */
                pcre_get_substring(lineBuffer, substringVects, rc, 2,
                                   (const char **)&captString);
                elem_id = strtoul(captString, NULL, 10);
                pcre_free(captString);

                /* the info element name */
                pcre_get_substring(lineBuffer, substringVects, rc, 3,
                                   (const char **)&captString);
                elem = fbInfoModelGetElementByID(model, elem_id, CERT_PEN);
                if (elem) {
                    g_warning("Info Element already exists with ID %d "
                              "in default Info Model. Ignoring rule.",
                              elem_id);
                    pcre_free(captString);
                    continue;
                }
                elem = fbInfoModelGetElementByName(model, captString);
                if (elem) {
                    g_warning("Info Element already exists with name %s "
                              "in default Info Model. Ignoring rule.",
                              captString);
                    pcre_free(captString);
                    continue;
                }
                memset(&add_element, 0, sizeof(add_element));
                add_element.num = elem_id;
                add_element.ent = CERT_PEN;
                add_element.len = FB_IE_VARLEN;
                add_element.ref.name = captString;
                add_element.midx = 0;
                add_element.flags = 0;
                fbInfoModelAddElement(model, &add_element);
                BLoffset = ypAddSpec(&spec, applabel, &struct_offset);
                if (BLoffset == -1) {
                    g_warning("NOT adding element for label %d.",
                              applabel);
                    pcre_free(captString);
                    continue;
                }
                ypAddRuleKey(ctx, applabel, elem_id,
                             fbInfoModelGetElementByName(model, captString),
                             struct_offset);
                ruleSet->regexFields[ruleSet->numRules].info_element_id =
                    elem_id;
                ruleSet->regexFields[ruleSet->numRules].elem =
                    fbInfoModelGetElementByName(model, captString);
                pcre_free(captString);

                /* the regex */
                pcre_get_substring(lineBuffer, substringVects, rc, 4,
                                   (const char **)&captString);
                newRule = pcre_compile(captString, PCRE_MULTILINE,
                                       &errorString, &errorPos, NULL);
                if (NULL == newRule) {
                    g_warning("Error Parsing DPI Rule for label %d user %d:"
                              " \"%s\": %s at position %d",
                              applabel, elem_id, captString,
                              errorString, errorPos);
                } else {
                    newExtra = pcre_study(newRule, 0, &errorString);
                    ruleSet->regexFields[ruleSet->numRules].rule = newRule;
                    ruleSet->regexFields[ruleSet->numRules].extra = newExtra;
                    ruleSet->numRules++;
                    tempNumRules++;
                }
                pcre_free(captString);

                if (MAX_PAYLOAD_RULES == ruleSet->numRules) {
                    g_warning("Maximum number of rules has been reached "
                              "within DPI Plugin");
                    break;
                }

                continue;
            }

            substringVects[1] = currentStartPos;
            rc = pcre_exec(fieldScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                limit = strtoul(captString, NULL, 10);
                if (limit > 65535) {
                    g_warning("Per Field Limit is Too Large (%d), "
                              "Setting to Default.", limit);
                    limit = MAX_CAPTURE_LENGTH;
                }
                ctx->dpi_user_limit = limit;
                pcre_free(captString);
                continue;
            }
            substringVects[1] = currentStartPos;

            rc = pcre_exec(totalScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                limit = strtoul(captString, NULL, 10);
                if (limit > 65535) {
                    g_warning("Total Limit is Too Large (%d), "
                              "Setting to Default.", limit);
                    limit = 1000;
                }
                ctx->dpi_total_limit = limit;
                pcre_free(captString);
                continue;
            }

            substringVects[1] = currentStartPos;

            rc = pcre_exec(certExpScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                limit = strtoul(captString, NULL, 10);
                if (limit) {
                    /* turn it on but turn standard ssl export off */
                    rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, 443, 0);
                    if (!rulePos) {
                        /* protocol not turned on - enable it now */
                        ypProtocolHashActivate(ctx, 443, ctx->dpi_enabled + 1);
                        ctx->dpi_enabled++;
                    }
                    /* if cert hash export is enabled - ssl_off must = FALSE */
                    if (!ctx->cert_hash_export) {
                        ctx->ssl_off = TRUE;
                    }
                    ctx->full_cert_export = TRUE;
                    fullcert_global = TRUE;
                    g_debug("SSL [Full] Certificate Export Enabled.");
                }
                pcre_free(captString);
                continue;
            }

            substringVects[1] = currentStartPos;
            rc = pcre_exec(certHashScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                limit = strtoul(captString, NULL, 10);
                if (limit) {
                    g_debug("SSL Certificate Hash Export Enabled.");
                    rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, 443, 0);
                    if (!rulePos) {
                        /* protocol not turned on */
                        /* turn it on but turn standard ssl export off */
                        ypProtocolHashActivate(ctx, 443, ctx->dpi_enabled + 1);
                        ctx->dpi_enabled++;
                    }
                    ctx->ssl_off = FALSE;
                    ctx->cert_hash_export = TRUE;
                    certhash_global = TRUE;
                }
                pcre_free(captString);
                continue;
            }

            substringVects[1] = currentStartPos;

            if ((PCRE_ERROR_NOMATCH == rc) && (substringVects[1] < readLength)
                && !feof(dpiRuleFile))
            {
                memmove(lineBuffer, lineBuffer + substringVects[1],
                        readLength - substringVects[1]);
                bufferOffset = readLength - substringVects[1];
                break;
            } else if (PCRE_ERROR_NOMATCH == rc && feof(dpiRuleFile)) {
                g_critical("Unparsed text at the end of the DPI Rule File!\n");
                break;
            }
        }
    } while (!ferror(dpiRuleFile) && !feof(dpiRuleFile));

    for (rc = 0; rc < DPI_REGEX_PROTOCOLS; rc++) {
        tempNumProtos++;
        rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, regexDPIProtos[rc],
                                       0);
        if (rulePos) {
            if (ctx->ruleSet[rulePos].numRules == 0) {
                tempNumProtos--;
                ypProtocolHashDeactivate(ctx, regexDPIProtos[rc]);
            }
        } else {
            tempNumProtos--;
        }
    }

    g_debug("DPI rule scanner accepted %d rules from the DPI Rule File",
            tempNumRules);
    if (tempNumProtos) {
        g_debug("DPI regular expressions cover %d protocols", tempNumProtos);
    }

    pcre_free(ruleScanner);
    pcre_free(commentScanner);
    pcre_free(newRuleScanner);
    pcre_free(totalScanner);
    pcre_free(fieldScanner);
    pcre_free(certExpScanner);
    pcre_free(certHashScanner);

    return TRUE;
}


/**
 * flowFree
 *
 * Callback invoked by yfHookFlowFree().  Function signature defined by
 * yfHookFlowFree_fn.  Referenced by yfHooksFuncs_t.flowFree.
 *
 *
 * @param flow pointer to the flow structure with the context information
 *
 *
 */
void
ypFlowFree(
    void      *yfHookContext,
    yfFlow_t  *flow)
{
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)yfHookContext;

    if (NULL == flowContext) {
        /* log an error here, but how */
        g_warning("couldn't free flow %p; not in hash table\n", flow);
        return;
    }

    if (flowContext->dpi) {
        g_slice_free1((sizeof(yfDPIData_t) * YAF_MAX_CAPTURE_FIELDS),
                      flowContext->dpi);
    }

    g_slice_free1(sizeof(ypDPIFlowCtx_t), flowContext);
}


/**
 * hookPacket
 *
 * Callback invoked by yfHookPacket().  Function signature defined by
 * yfHookPacket_fn.  Referenced by yfHooksFuncs_t.hookPacket.
 *
 * allows the plugin to examine the start of a flow capture and decide if a
 * flow capture should be dropped from processing
 *
 * @param key
 * @param pkt
 * @param caplen
 * @param iplen
 * @param tcpinfo
 * @param l2info
 *
 * @return TRUE to continue tracking this flow, false to drop tracking the flow
 *
 */
gboolean
ypHookPacket(
    yfFlowKey_t    *key,
    const uint8_t  *pkt,
    size_t          caplen,
    uint32_t        iplen,
    yfTCPInfo_t    *tcpinfo,
    yfL2Info_t     *l2info)
{
    /* this never decides to drop packet flow */

    return TRUE;
}


/**
 * flowPacket
 *
 * Callback invoked by yfHookFlowPacket().  Function signature defined by
 * yfHookFlowPacket_fn.  Referenced by yfHooksFuncs_t.flowPacket.
 *
 * gets called whenever a packet gets processed, relevant to the given flow
 *
 * DPI uses this in yafApplabel.c
 *
 * @param flow
 * @param val
 * @param pkt
 * @param caplen
 *
 *
 */
void
ypFlowPacket(
    void           *yfHookContext,
    yfFlow_t       *flow,
    yfFlowVal_t    *val,
    const uint8_t  *pkt,
    size_t          caplen,
    uint32_t        iplen,
    yfTCPInfo_t    *tcpinfo,
    yfL2Info_t     *l2info)
{
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t *ctx = NULL;
    uint16_t        tempAppLabel = 0;

    if (NULL == flowContext || iplen) {
        /* iplen should only be 0 if yafApplabel is calling this fn */
        return;
    }

    ctx = flowContext->yfctx;

    if (ctx->dpiInitialized == 0) {
        return;
    }

    flowContext->captureFwd = flowContext->dpinum;

    if (flowContext->captureFwd > YAF_MAX_CAPTURE_SIDE) {
        /* Max out at 25 per side  - usually won't happen in this case*/
        flowContext->dpinum = YAF_MAX_CAPTURE_SIDE;
        flowContext->captureFwd = YAF_MAX_CAPTURE_SIDE;
    }

    if (caplen && (flow->appLabel > 0)) {
        /* call to applabel's scan payload */
        tempAppLabel = ycScanPayload(pkt, caplen, flow, val);
    }

    /* If we pick up captures from another appLabel it messes with lists */
    if ((tempAppLabel != flow->appLabel)) {
        flowContext->dpinum = flowContext->captureFwd;
    }
}


/**
 * ypInitializeBL
 *
 * initialize basiclists for protocols that use them:
 * HTTP, FTP, IMAP, RTSP, SIP, SMTP, SSH
 *
 * @param ctx global yaf context for this process
 * @param first_basic_list first BL in list
 * @param proto_standard standard number of BL's yaf will send
 * @param app_pos the index into the ruleSet array for this protocol
 *
 */
static void
ypInitializeBLs(
    yfDPIContext_t  *ctx,
    fbBasicList_t   *first_basic_list,
    int              proto_standard,
    int              app_pos)
{
    protocolRegexRules_t *ruleSet = &ctx->ruleSet[app_pos];
    fbBasicList_t        *temp = first_basic_list;
    int rc, loop;

    for (loop = 0; loop < ruleSet->numRules; loop++) {
        fbBasicListInit(temp, 3, ruleSet->regexFields[loop].elem, 0);
        temp++;
    }

    rc = proto_standard - ruleSet->numRules;

    if (rc < 0) {
        return;
    }

    /* add some dummy elements to fill to proto_standard */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListInit(temp, 3, ruleSet->regexFields[0].elem, 0);
        temp++;
    }
}


/**
 * flowWrite
 *
 * Callback invoked by yfHookFlowWrite().  Function signature defined by
 * yfHookFlowWrite_fn.  Referenced by yfHooksFuncs_t.flowWrite.
 *
 *  this function gets called when the flow data is getting serialized to be
 *  written into ipfix format.  This function must put its data into the
 *  export stream (rec) in the order that it allocated the data according to
 *  its template model - For DPI it uses IPFIX lists to allocate new
 *  subTemplates in YAF's main subTemplateMultiList
 *
 * @param rec
 * @param rec_sz
 * @param flow
 * @param err
 *
 * @return FALSE if closing the flow should be delayed, TRUE if the data is
 *         available and the flow can be closed
 *
 */
gboolean
ypFlowWrite(
    void                           *yfHookContext,
    fbSubTemplateMultiList_t       *rec,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    GError                        **err)
{
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t *ctx;
    uint16_t        rc;

    if (NULL == flowContext) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                    "Unknown plugin flow %p", flow);
        return FALSE;
    }

    ctx = flowContext->yfctx;

    if (ctx->dpiInitialized == 0) {
        return TRUE;
    }

    if (flowContext->dpinum == 0) {
        /* Nothing to write! */
        return TRUE;
    }

    /*If there's no reverse payload & No Fwd captures this has to be uniflow*/
    if (!flow->rval.payload && !flowContext->captureFwd) {
        flowContext->startOffset = flowContext->captureFwd;
        flowContext->captureFwd = flowContext->dpinum;
        return TRUE;
    }

    /* make sure we have data to write */
    if ((flowContext->startOffset >= flowContext->dpinum)) {
        return TRUE;
    }

    /* make sure DPI is turned on for this protocol */
    rc = ypSearchPlugOpts(ctx->dpiActiveHash, flow->appLabel);
    if (!rc) {
        return TRUE;
    }
    switch (flow->appLabel) {
      case 21:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessGenericRegex(flowContext, stml, flow,
                                                 flowContext->captureFwd,
                                                 flowContext->dpinum, rc,
                                                 YAF_FTP_FLOW_TID, ftpTemplate,
                                                 YAF_FTP_STANDARD);
        break;
      case 22:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessSSH(flowContext, stml, flow,
                                                 flowContext->captureFwd,
                                                 flowContext->dpinum, rc);
        break;
      case 25:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessSMTP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
      case 53:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessDNS(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
      case 69:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessTFTP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
      case 80:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessGenericRegex(flowContext, stml, flow,
                                                 flowContext->captureFwd,
                                                 flowContext->dpinum, rc,
                                                 YAF_HTTP_FLOW_TID,
                                                 httpTemplate,
                                                 YAF_HTTP_STANDARD);
        break;
      case 110:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessGenericPlugin(flowContext, stml, flow,
                                                  flowContext->captureFwd,
                                                  flowContext->dpinum, rc,
                                                  YAF_POP3_FLOW_TID,
                                                  pop3Template,
                                                  "pop3TextMessage");
        break;
      case 119:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessNNTP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
      case 143:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessGenericRegex(flowContext, stml, flow,
                                                 flowContext->captureFwd,
                                                 flowContext->dpinum, rc,
                                                 YAF_IMAP_FLOW_TID,
                                                 imapTemplate,
                                                 YAF_IMAP_STANDARD);
        break;
      case 194:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessGenericPlugin(flowContext, stml, flow,
                                                  flowContext->captureFwd,
                                                  flowContext->dpinum, rc,
                                                  YAF_IRC_FLOW_TID,
                                                  ircTemplate,
                                                  "ircTextMessage");
        break;
      case 427:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessSLP(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
      case 443:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessSSL(flowContext, rec, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
      case 554:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessGenericRegex(flowContext, stml, flow,
                                                 flowContext->captureFwd,
                                                 flowContext->dpinum, rc,
                                                 YAF_RTSP_FLOW_TID,
                                                 rtspTemplate,
                                                 YAF_RTSP_STANDARD);
        break;
      case 5060:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessGenericRegex(flowContext, stml, flow,
                                                 flowContext->captureFwd,
                                                 flowContext->dpinum, rc,
                                                 YAF_SIP_FLOW_TID, sipTemplate,
                                                 YAF_SIP_STANDARD);
        break;
      case 3306:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessMySQL(flowContext, stml, flow,
                                          flowContext->captureFwd,
                                          flowContext->dpinum, rc);
        break;
      case 20000:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessDNP(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
      case 502:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessGenericPlugin(flowContext, stml, flow,
                                                  flowContext->captureFwd,
                                                  flowContext->dpinum, rc,
                                                  YAF_MODBUS_FLOW_TID,
                                                  modbusTemplate, "modbusData");
        break;
      case 44818:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessGenericPlugin(flowContext, stml, flow,
                                                  flowContext->captureFwd,
                                                  flowContext->dpinum, rc,
                                                  YAF_ENIP_FLOW_TID,
                                                  enipTemplate,
                                                  "ethernetIPData");
        break;
      case 5004:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessRTP(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
      default:
        break;
    }

    /* For UNIFLOW -> we'll only get back to hooks if uniflow is set */
    /* This way we'll use flow->val.payload & offsets will still be correct */
    flowContext->startOffset = flowContext->captureFwd;
    flowContext->captureFwd = flowContext->dpinum;
    return TRUE;
}


/**
 * getInfoModel
 *
 * Callback invoked by yfHookGetInfoModel().  Function signature defined by
 * yfHookGetInfoModel_fn.  Referenced by yfHooksFuncs_t.getInfoModel.
 *
 * gets the IPFIX information model elements
 *
 *
 * @return a pointer to a fixbuf information element model array
 *
 */
fbInfoElement_t *
ypGetInfoModel(
    void)
{
    return infomodel_array_static_yaf_dpi;
}


/**
 * getTemplate
 *
 * Callback invoked by yfHookGetTemplate().  Function signature defined by
 * yfHookGetTemplate_fn.  Referenced by yfHooksFuncs_t.getTemplate.
 *
 * gets the IPFIX data template for the information that will be returned
 *
 * @return a pointer to the fixbuf info element array for the templates
 *
 */
gboolean
ypGetTemplate(
    fbSession_t  *session)
{
    GError *err = NULL;

    if (ypSearchPlugOpts(global_active_protos, 194)) {
        if (!(ircTemplate = ypInitTemplate(
                  session, yaf_singleBL_spec,
                  YAF_IRC_FLOW_TID, "yaf_irc", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 110)) {
        if (!(pop3Template = ypInitTemplate(
                  session, yaf_singleBL_spec,
                  YAF_POP3_FLOW_TID, "yaf_pop3", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 69)) {
        if (!(tftpTemplate = ypInitTemplate(
                  session, yaf_tftp_spec,
                  YAF_TFTP_FLOW_TID, "yaf_tftp", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 427)) {
        if (!(slpTemplate = ypInitTemplate(
                  session, yaf_slp_spec,
                  YAF_SLP_FLOW_TID, "yaf_slp", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 80)) {
        if (!(httpTemplate = ypInitTemplate(
                  session, yaf_http_spec,
                  YAF_HTTP_FLOW_TID, "yaf_http", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 21)) {
        if (!(ftpTemplate = ypInitTemplate(
                  session, yaf_ftp_spec,
                  YAF_FTP_FLOW_TID, "yaf_ftp", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 143)) {
        if (!(imapTemplate = ypInitTemplate(
                  session, yaf_imap_spec,
                  YAF_IMAP_FLOW_TID, "yaf_imap", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 554)) {
        if (!(rtspTemplate = ypInitTemplate(
                  session, yaf_rtsp_spec,
                  YAF_RTSP_FLOW_TID, "yaf_rtsp", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 5060)) {
        if (!(sipTemplate = ypInitTemplate(
                  session, yaf_sip_spec,
                  YAF_SIP_FLOW_TID, "yaf_sip", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 25)) {
        if (!(smtpTemplate = ypInitTemplate(
                  session, yaf_smtp_spec,
                  YAF_SMTP_FLOW_TID, "yaf_smtp", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(smtpMessageTemplate = ypInitTemplate(
                  session, yaf_smtp_message_spec,
                  YAF_SMTP_MESSAGE_TID, "yaf_smtp_message", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(smtpHeaderTemplate = ypInitTemplate(
                  session, yaf_smtp_header_spec,
                  YAF_SMTP_HEADER_TID, "yaf_smtp_header", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 22)) {
        if (!(sshTemplate = ypInitTemplate(
                  session, yaf_ssh_spec,
                  YAF_SSH_FLOW_TID, "yaf_ssh", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 119)) {
        if (!(nntpTemplate = ypInitTemplate(
                  session, yaf_nntp_spec,
                  YAF_NNTP_FLOW_TID, "yaf_nntp", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 53)) {
        if (!(dnsTemplate = ypInitTemplate(
                  session, yaf_dns_spec,
                  YAF_DNS_FLOW_TID, "yaf_dns", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsQRTemplate = ypInitTemplate(
                  session, yaf_dnsQR_spec,
                  YAF_DNSQR_FLOW_TID, "yaf_dns_qr", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsATemplate = ypInitTemplate(
                  session, yaf_dnsA_spec,
                  YAF_DNSA_FLOW_TID, "yaf_dns_a", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsAAAATemplate = ypInitTemplate(
                  session, yaf_dnsAAAA_spec,
                  YAF_DNSAAAA_FLOW_TID, "yaf_dns_aaaa", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsCNTemplate = ypInitTemplate(
                  session, yaf_dnsCNAME_spec,
                  YAF_DNSCN_FLOW_TID, "yaf_dns_cname", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsMXTemplate = ypInitTemplate(
                  session, yaf_dnsMX_spec,
                  YAF_DNSMX_FLOW_TID, "yaf_dns_mx", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsNSTemplate = ypInitTemplate(
                  session, yaf_dnsNS_spec,
                  YAF_DNSNS_FLOW_TID, "yaf_dns_ns", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsPTRTemplate = ypInitTemplate(
                  session, yaf_dnsPTR_spec,
                  YAF_DNSPTR_FLOW_TID, "yaf_dns_ptr", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsTXTTemplate = ypInitTemplate(
                  session, yaf_dnsTXT_spec,
                  YAF_DNSTXT_FLOW_TID, "yaf_dns_txt", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsSOATemplate = ypInitTemplate(
                  session, yaf_dnsSOA_spec,
                  YAF_DNSSOA_FLOW_TID, "yaf_dns_soa", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsSRVTemplate = ypInitTemplate(
                  session, yaf_dnsSRV_spec,
                  YAF_DNSSRV_FLOW_TID, "yaf_dns_srv", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (dnssec_global) {
            if (!(dnsDSTemplate = ypInitTemplate(
                      session, yaf_dnsDS_spec,
                      YAF_DNSDS_FLOW_TID, "yaf_dns_ds", NULL,
                      0xffffffff, &err)))
            {
                return FALSE;
            }
            if (!(dnsRRSigTemplate = ypInitTemplate(
                      session, yaf_dnsSig_spec,
                      YAF_DNSRRSIG_FLOW_TID, "yaf_dns_sig", NULL,
                      0xffffffff, &err)))
            {
                return FALSE;
            }
            if (!(dnsNSECTemplate = ypInitTemplate(
                      session, yaf_dnsNSEC_spec,
                      YAF_DNSNSEC_FLOW_TID, "yaf_dns_nsec", NULL,
                      0xffffffff, &err)))
            {
                return FALSE;
            }
            if (!(dnsNSEC3Template = ypInitTemplate(
                      session, yaf_dnsNSEC3_spec,
                      YAF_DNSNSEC3_FLOW_TID, "yaf_dns_nsec3", NULL,
                      0xffffffff, &err)))
            {
                return FALSE;
            }
            if (!(dnsKeyTemplate = ypInitTemplate(
                      session, yaf_dnsKey_spec,
                      YAF_DNSKEY_FLOW_TID, "yaf_dns_key", NULL,
                      0xffffffff, &err)))
            {
                return FALSE;
            }
        }
    }
    if (ypSearchPlugOpts(global_active_protos, 443) || certhash_global) {
        if (!(sslTemplate = ypInitTemplate(
                  session, yaf_ssl_spec,
                  YAF_SSL_FLOW_TID, "yaf_ssl", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(sslCertTemplate = ypInitTemplate(
                  session, yaf_cert_spec,
                  YAF_SSL_CERT_FLOW_TID, "yaf_ssl_cert", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(sslSubTemplate = ypInitTemplate(
                  session, yaf_subssl_spec,
                  YAF_SSL_SUBCERT_FLOW_TID, "yaf_ssl_subcert", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }
    if (ypSearchPlugOpts(global_active_protos, 3306)) {
        if (!(mysqlTemplate = ypInitTemplate(
                  session, yaf_mysql_spec,
                  YAF_MYSQL_FLOW_TID, "yaf_mysql", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(mysqlTxtTemplate = ypInitTemplate(
                  session, yaf_mysql_txt_spec,
                  YAF_MYSQLTXT_FLOW_TID, "yaf_mysql_txt", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }
    /* DNP 3.0 */
    if (ypSearchPlugOpts(global_active_protos, 20000)) {
        if (!(dnp3Template = ypInitTemplate(
                  session, yaf_dnp_spec,
                  YAF_DNP3_FLOW_TID, "yaf_dnp", NULL,
                  0, &err)))
        {
            return FALSE;
        }
        if (!(dnp3RecTemplate = ypInitTemplate(
                  session, yaf_dnp_rec_spec,
                  YAF_DNP3_REC_FLOW_TID, "yaf_dnp_rec", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 502)) {
        if (!(modbusTemplate = ypInitTemplate(
                  session, yaf_singleBL_spec,
                  YAF_MODBUS_FLOW_TID, "yaf_modbus", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 44818)) {
        if (!(enipTemplate = ypInitTemplate(
                  session, yaf_singleBL_spec,
                  YAF_ENIP_FLOW_TID, "yaf_enip", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(global_active_protos, 5004)) {
        if (!(rtpTemplate = ypInitTemplate(
                  session, yaf_rtp_spec,
                  YAF_RTP_FLOW_TID, "yaf_rtp", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    if (fullcert_global) {
        if (!(sslFullCertTemplate = ypInitTemplate(
                  session, yaf_singleBL_spec,
                  YAF_FULL_CERT_TID, "yaf_ssl_cert_full", NULL,
                  0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    return TRUE;
}


/**
 * setPluginOpt
 *
 * Callback invoked by yfHookAddNewHook().  Function signature defined by
 * yfHookSetPluginOpt_fn.  Referenced by yfHooksFuncs_t.setPluginOpt.
 *
 * sets the pluginOpt variable passed from the command line
 *
 */
void
ypSetPluginOpt(
    const char  *option,
    void        *yfctx)
{
    yfDPIContext_t *ctx = (yfDPIContext_t *)yfctx;
    GError         *err = NULL;

    ypProtocolHashInitialize(ctx);
    ypParsePluginOpt(yfctx, option);

    if (!ypHookInitialize(ctx, ctx->dpiRulesFileName, &err)) {
        g_warning("Error setting up dpacketplugin: %s", err->message);
        g_clear_error(&err);
    }
}


/**
 * setPluginConf
 *
 * Callback invoked by yfHookAddNewHook().  Function signature defined by
 * yfHookSetPluginConf_fn.  Referenced by yfHooksFuncs_t.setPluginConf.
 *
 * sets the pluginConf variable passed from the command line
 *
 */
void
ypSetPluginConf(
    const char  *conf,
    void       **yfctx)
{
    yfDPIContext_t *newctx = NULL;

    newctx = (yfDPIContext_t *)g_slice_alloc0(sizeof(yfDPIContext_t));

    newctx->dpiInitialized = 0;
    newctx->dpi_user_limit = MAX_CAPTURE_LENGTH;
    newctx->dpi_total_limit = 1000;
    newctx->dnssec = FALSE;
    newctx->cert_hash_export = FALSE;
    newctx->full_cert_export = FALSE;
    newctx->ssl_off = FALSE;

    if (NULL != conf) {
        newctx->dpiRulesFileName = g_strdup(conf);
    } else {
        newctx->dpiRulesFileName = g_strdup(YAF_CONF_DIR "/yafDPIRules.conf");
    }

    *yfctx = (void *)newctx;
}


/**
 * ypProtocolHashInitialize
 *
 */
static void
ypProtocolHashInitialize(
    yfDPIContext_t  *ctx)
{
    int      loop;
    uint16_t insertLoc;

    for (loop = 0; loop < MAX_PAYLOAD_RULES; loop++) {
        ctx->dpiActiveHash[loop].activated = MAX_PAYLOAD_RULES + 1;
    }

    for (loop = 0; loop < DPI_TOTAL_PROTOCOLS; loop++) {
        insertLoc = DPIProtocols[loop] % MAX_PAYLOAD_RULES;
        if (ctx->dpiActiveHash[insertLoc].activated
            == (MAX_PAYLOAD_RULES + 1))
        {
            ctx->dpiActiveHash[insertLoc].portNumber = DPIProtocols[loop];
            ctx->dpiActiveHash[insertLoc].activated = 0;
        } else {
            insertLoc = ((MAX_PAYLOAD_RULES - DPIProtocols[loop]) ^
                         (DPIProtocols[loop] >> 8));
            insertLoc %= MAX_PAYLOAD_RULES;
            ctx->dpiActiveHash[insertLoc].portNumber = DPIProtocols[loop];
            ctx->dpiActiveHash[insertLoc].activated = 0;
        }
    }
}


/**
 * ypProtocolHashSearch
 *
 */
static uint16_t
ypProtocolHashSearch(
    DPIActiveHash_t  *active,
    uint16_t          portNum,
    uint16_t          insert)
{
    uint16_t searchLoc = portNum % MAX_PAYLOAD_RULES;

    if (active[searchLoc].portNumber == portNum) {
        if (insert) {
            active[searchLoc].activated = insert;
        }
        return active[searchLoc].activated;
    }

    searchLoc = ((MAX_PAYLOAD_RULES - portNum) ^ (portNum >> 8));
    searchLoc %= MAX_PAYLOAD_RULES;
    if (active[searchLoc].portNumber == portNum) {
        if (insert) {
            active[searchLoc].activated = insert;
        }
        return active[searchLoc].activated;
    }

    return 0;
}


/**
 * ypProtocolHashActivate
 *
 */
static gboolean
ypProtocolHashActivate(
    yfDPIContext_t  *ctx,
    uint16_t         portNum,
    uint16_t         index)
{
    if (!ypProtocolHashSearch(ctx->dpiActiveHash, portNum, index)) {
        return FALSE;
    }

    return TRUE;
}


static void
ypProtocolHashDeactivate(
    yfDPIContext_t  *ctx,
    uint16_t         portNum)
{
    uint16_t searchLoc = portNum % MAX_PAYLOAD_RULES;

    if (ctx->dpiActiveHash[searchLoc].portNumber == portNum) {
        ctx->dpiActiveHash[searchLoc].activated = 0;
        return;
    }

    searchLoc = ((MAX_PAYLOAD_RULES - portNum) ^ (portNum >> 8));
    searchLoc %= MAX_PAYLOAD_RULES;
    if (ctx->dpiActiveHash[searchLoc].portNumber == portNum) {
        ctx->dpiActiveHash[searchLoc].activated = 0;
    }
}


/**
 * ypParsePluginOpt
 *
 *  Parses pluginOpt string to find ports (applications) to execute
 *  Deep Packet Inspection
 *
 *  @param pluginOpt Variable
 *
 */
static void
ypParsePluginOpt(
    yfDPIContext_t  *ctx,
    const char      *option)
{
    char *plugOptIndex;
    char *plugOpt, *endPlugOpt;
    int   dpiNumOn = 1;
    int   loop;

    plugOptIndex = (char *)option;
    while (NULL != plugOptIndex && (dpiNumOn < YAF_MAX_CAPTURE_FIELDS)) {
        endPlugOpt = strchr(plugOptIndex, ' ');
        if (endPlugOpt == NULL) {
            if (!(strcasecmp(plugOptIndex, "dnssec"))) {
                ctx->dnssec = TRUE;
                dnssec_global = TRUE;
                break;
            }
            if (0 == atoi(plugOptIndex)) {
                break;
            }
            if (!ypProtocolHashActivate(ctx, (uint16_t)atoi(plugOptIndex),
                                        dpiNumOn))
            {
                g_debug("No Protocol %d for DPI", atoi(plugOptIndex));
                dpiNumOn--;
            }
            dpiNumOn++;
            break;
        } else if (plugOptIndex == endPlugOpt) {
            plugOpt = NULL;
            break;
        } else {
            plugOpt = g_new0(char, (endPlugOpt - plugOptIndex + 1));
            strncpy(plugOpt, plugOptIndex, (endPlugOpt - plugOptIndex));
            if (!(strcasecmp(plugOpt, "dnssec"))) {
                ctx->dnssec = TRUE;
                dnssec_global = TRUE;
                plugOptIndex = endPlugOpt + 1;
                continue;
            } else if (!ypProtocolHashActivate(ctx,
                                               (uint16_t)atoi(plugOptIndex),
                                               dpiNumOn))
            {
                g_debug("No Protocol %d for DPI", atoi(plugOptIndex));
                dpiNumOn--;
            }
            dpiNumOn++;
        }
        plugOptIndex = endPlugOpt + 1;
    }

    if ((dpiNumOn > 1) && ctx->dnssec) {
        if (!ypProtocolHashSearch(ctx->dpiActiveHash, 53, 0)) {
            g_warning("DNSSEC NOT AVAILABLE - DNS DPI MUST ALSO BE ON");
            ctx->dnssec = FALSE;
            dnssec_global = FALSE;
        } else {
            g_debug("DPI Running for %d Protocols", dpiNumOn - 1);
            g_debug("DNSSEC export enabled.");
        }
    } else if (ctx->dnssec && dpiNumOn < 2) {
        g_debug("DPI Running for ALL Protocols");
        for (loop = 0; loop < DPI_TOTAL_PROTOCOLS; loop++) {
            ypProtocolHashActivate(ctx, DPIProtocols[loop], loop);
        }
        g_debug("DNSSEC export enabled.");
    } else {
        if (!option) {
            g_debug("DPI Running for ALL Protocols");
            for (loop = 0; loop < DPI_TOTAL_PROTOCOLS; loop++) {
                ypProtocolHashActivate(ctx, DPIProtocols[loop], loop);
            }
            ctx->dpi_enabled = DPI_TOTAL_PROTOCOLS;
        } else {
            g_debug("DPI Running for %d Protocols", dpiNumOn - 1);
            ctx->dpi_enabled = dpiNumOn - 1;
        }
    }
    /* place holder for template export */
    global_active_protos = ctx->dpiActiveHash;
}


/**
 * ypPluginRegex
 *
 *
 */
static gboolean
ypPluginRegex(
    yfDPIContext_t  *ctx,
    uint16_t         elementID,
    int              index)
{
    protocolRegexRules_t *ruleSet = &ctx->ruleSet[index];
    int loop;

    for (loop = 0; loop < ruleSet->numRules; loop++) {
        if (elementID == ruleSet->regexFields[loop].info_element_id) {
            return TRUE;
        }
    }

    return FALSE;
}


/**
 * scanPayload
 *
 * Callback invoked by yfHookScanPayload().  Function signature defined by
 * yfHookScanPayload_fn.  Referenced by yfHooksFuncs_t.scanPayload.
 *
 * gets the important strings out of the payload by executing the passed pcre
 * or the offset/length to the bytes of interest.
 *
 * if expression is NULL, but a regular expression was given in the
 * yafDPIRules.conf with the elementID, use that regular expression against
 * the payload.
 *
 */
void
ypScanPayload(
    void           *yfHookContext,
    yfFlow_t       *flow,
    const uint8_t  *pkt,
    size_t          caplen,
    pcre           *expression,
    uint32_t        offset,
    uint16_t        elementID,
    uint16_t        applabel)
{
    int          rc;
    int          vects[NUM_SUBSTRING_VECTS];
    unsigned int captCount;
    unsigned int captCountCurrent = 0;
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t *ctx = NULL;
    int          rulePos = 0;
    protocolRegexRules_t *ruleSet;

    if (NULL == flowContext) {
        return;
    }

    ctx = flowContext->yfctx;

    if (ctx->dpiInitialized == 0) {
        return;
    }

    if (caplen == 0 && applabel != 53) {
        return;
    }

    /* determine if DPI is turned on for this appLabel */
    rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, applabel, 0);
    if (!rulePos) {
        return;
    }
    ruleSet = &ctx->ruleSet[rulePos];

    if (flowContext->dpi == NULL) {
        flowContext->dpi = g_slice_alloc0(YAF_MAX_CAPTURE_FIELDS *
                                          sizeof(yfDPIData_t));
    }

    captCount = flowContext->dpinum;

    if ((captCount >= YAF_MAX_CAPTURE_FIELDS) ||
        (flowContext->dpi_len >= ctx->dpi_total_limit))
    {
        return;
    }

    if (expression) {
        while (((rc = pcre_exec(expression, NULL, (const char *)pkt, caplen,
                                offset, 0, vects, NUM_SUBSTRING_VECTS)) > 0))
        {
            if (rc > 1) {
                flowContext->dpi[captCount].dpacketCaptLen =
                    vects[3] - vects[2];
                flowContext->dpi[captCount].dpacketCapt = vects[2];
            } else {
                flowContext->dpi[captCount].dpacketCaptLen =
                    vects[1] - vects[0];
                flowContext->dpi[captCount].dpacketCapt = vects[0];
            }
            offset = vects[0] + flowContext->dpi[captCount].dpacketCaptLen;
            if (flowContext->dpi[captCount].dpacketCaptLen >
                ctx->dpi_user_limit)
            {
                flowContext->dpi[captCount].dpacketCaptLen =
                    ctx->dpi_user_limit;
            }

            flowContext->dpi[captCount].dpacketID = elementID;
            flowContext->dpi_len += flowContext->dpi[captCount].dpacketCaptLen;
            if (flowContext->dpi_len > ctx->dpi_total_limit) {
                /* if we passed the limit - don't add this one */
                flowContext->dpinum = captCount;
                return;
            }
            captCount++;
            captCountCurrent++;
            if ((captCount >= YAF_MAX_CAPTURE_FIELDS) ||
                (captCountCurrent >= YAF_MAX_CAPTURE_SIDE))
            {
                flowContext->dpinum = captCount;
                return;
            }
        }
    } else if (ruleSet->numRules && ypPluginRegex(ctx, elementID, rulePos)) {
        /* the plugin has regexs in yafDPIRules.conf */
        flow->appLabel = applabel;
        captCount += ypDPIScanner(flowContext, pkt, caplen, offset, flow, NULL);
    } else {
        if (caplen > ctx->dpi_user_limit) {caplen = ctx->dpi_user_limit;}
        flowContext->dpi[captCount].dpacketCaptLen = caplen;
        flowContext->dpi[captCount].dpacketID = elementID;
        flowContext->dpi[captCount].dpacketCapt = offset;
        flowContext->dpi_len += caplen;
        if (flowContext->dpi_len > ctx->dpi_total_limit) {
            /* if we passed the limit - don't add this one */
            return;
        }
        captCount++;
    }

    flowContext->dpinum = captCount;
}


/**
 * ypGetMetaData
 *
 * Callback invoked by yfHookAddNewHook().  Function signature defined by
 * yfHookGetMetaData_fn.  Referenced by yfHooksFuncs_t.getMetaData.
 *
 * this returns the meta information about this plugin, the interface version
 * it was built with, and the amount of export data it will send
 *
 * @return a pointer to a meta data structure with the various fields
 * appropriately filled in, API version & export data size
 *
 */
const struct yfHookMetaData *
ypGetMetaData(
    void)
{
    return &metaData;
}


/**
 * ypGetTemplateCount
 *
 * Callback invoked by yfHookGetTemplateCount().  Function signature defined
 * by yfHookGetTemplateCount_fn.  Referenced by
 * yfHooksFuncs_t.getTemplateCount.
 *
 * this returns the number of templates we are adding to yaf's
 * main subtemplatemultilist, for DPI - this is usually just 1
 *
 */
uint8_t
ypGetTemplateCount(
    void      *yfHookContext,
    yfFlow_t  *flow)
{
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t *ctx = NULL;

    if (NULL == flowContext) {
        return 0;
    }

    if (!flowContext->dpinum) {
        /* Nothing captured */
        return 0;
    }

    ctx = flowContext->yfctx;

    if (!ypSearchPlugOpts(ctx->dpiActiveHash, flow->appLabel)) {
        return 0;
    }

    /* if this is uniflow & there's no rval DPI - then it will return 0 */
    if (!flow->rval.payload && !flowContext->captureFwd) {
        return 0;
    }

    /* if this is not uniflow startOffset should be 0 */
    if ((flowContext->startOffset < flowContext->dpinum)) {
        if ((flow->appLabel == 443) && (ctx->full_cert_export)) {
            /* regular ssl and full certs */
            return 2;
        }

        return 1;
    } else {
        /* won't pass condition to free */
        flowContext->startOffset = flowContext->dpinum + 1;
        return 0;
    }
}


/**
 * ypFreeBLRec
 *
 * Frees all of the basiclists in a struct
 *
 * @param first_basiclist first BL in the list
 * @param proto_standard standard number of elements for the protocol
 * @param app_pos index into ruleSet array for the protocol
 *
 */
static void
ypFreeBLRec(
    yfDPIContext_t  *ctx,
    fbBasicList_t   *first_basiclist,
    int              proto_standard,
    int              app_pos)
{
    protocolRegexRules_t *ruleSet = &ctx->ruleSet[app_pos];
    fbBasicList_t        *temp    = first_basiclist;
    int rc, loop;

    rc = proto_standard - ruleSet->numRules;

    for (loop = 0; loop < ruleSet->numRules; loop++) {
        fbBasicListClear(temp);
        temp++;
    }

    if (rc < 0) {
        return;
    }

    /* Free any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListClear(temp);
        temp++;
    }
}


/**
 * ypFreeLists
 *
 * Callback invoked by yfHookFreeLists().  Function signature defined by
 * yfHookFreeLists_fn.  Referenced by yfHooksFuncs_t.freeLists.
 *
 *
 *
 *
 */
void
ypFreeLists(
    void      *yfHookContext,
    yfFlow_t  *flow)
{
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t *ctx = NULL;
    int             rc;

    if (NULL == flowContext) {
        /* log an error here, but how */
        g_warning("couldn't free flow %p; not in hash table\n", flow);
        return;
    }

    ctx = flowContext->yfctx;

    if (!flowContext->dpinum) {
        return;
    }

    rc = ypSearchPlugOpts(ctx->dpiActiveHash, flow->appLabel);

    if (!rc) {
        return;
    }

    if (!flowContext->startOffset && !flow->rval.payload) {
        /* Uniflow case: captures must be in rev payload but
         * we don't have it now */
        /* Biflow case: startOffset is 0 and fwdcap is 0, we did get something
         * and its in the rev payload */
        return;
    }

    if (flowContext->startOffset <= flowContext->dpinum) {
        switch (flow->appLabel) {
          case 80:
            {
                yfHTTPFlow_t *rec = (yfHTTPFlow_t *)flowContext->rec;
                ypFreeBLRec(ctx, &(rec->server), YAF_HTTP_STANDARD, rc);
                break;
            }
          case 443:
            ypFreeSSLRec(flowContext);
            break;
          case 21:
            {
                yfFTPFlow_t *rec = (yfFTPFlow_t *)flowContext->rec;
                ypFreeBLRec(ctx, &(rec->ftpReturn), YAF_FTP_STANDARD, rc);
                break;
            }
          case 53:
            ypFreeDNSRec(flowContext);
            break;
          case 25:
            ypFreeSMTPRec(flowContext);
            break;
          case 22:
            {
                ypFreeSSHRec(flowContext);
                break;
            }
          case 143:
            {
                yfIMAPFlow_t *rec = (yfIMAPFlow_t *)flowContext->rec;
                ypFreeBLRec(ctx, &(rec->imapCapability), YAF_IMAP_STANDARD, rc);
                break;
            }
          case 69:
            ypFreeTFTPRec(flowContext);
            break;
          case 110:
            ypFreePOP3Rec(flowContext);
            break;
          case 119:
            ypFreeNNTPRec(flowContext);
            break;
          case 194:
            ypFreeIRCRec(flowContext);
            break;
          case 427:
            ypFreeSLPRec(flowContext);
            break;
          case 554:
            {
                yfRTSPFlow_t *rec = (yfRTSPFlow_t *)flowContext->rec;
                ypFreeBLRec(ctx, &(rec->rtspURL), YAF_RTSP_STANDARD, rc);
                break;
            }
          case 5060:
            {
                yfSIPFlow_t *rec = (yfSIPFlow_t *)flowContext->rec;
                ypFreeBLRec(ctx, &(rec->sipInvite), YAF_SIP_STANDARD, rc);
                break;
            }
          case 3306:
            ypFreeMySQLRec(flowContext);
            break;
          case 20000:
            ypFreeDNPRec(flowContext);
            break;
          case 502:
            ypFreeModbusRec(flowContext);
            break;
          case 44818:
            ypFreeEnIPRec(flowContext);
            break;
          default:
            break;
        }

        if (flowContext->exbuf) {
            g_slice_free1(ctx->dpi_total_limit, flowContext->exbuf);
        }
    }
}


static uint8_t
ypDPIScanner(
    ypDPIFlowCtx_t  *flowContext,
    const uint8_t   *payloadData,
    unsigned int     payloadSize,
    uint32_t         offset,
    yfFlow_t        *flow,
    yfFlowVal_t     *val)
{
    int         rc = 0;
    int         loop;
    int         subVects[NUM_SUBSTRING_VECTS];
    uint32_t    offsetptr;
    uint8_t     captCount = flowContext->dpinum;
    uint8_t     captDirection = 0;
    uint16_t    captLen = 0;
    pcre       *ruleHolder;
    pcre_extra *extraHolder;
    int         rulePos = 0;
    protocolRegexRules_t *ruleSet;
    yfDPIContext_t       *ctx = flowContext->yfctx;

    if ((captCount >= YAF_MAX_CAPTURE_FIELDS) ||
        (flowContext->dpi_len >= ctx->dpi_total_limit))
    {
        return 0;
    }

    rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, flow->appLabel, 0);
    ruleSet = &ctx->ruleSet[rulePos];

    for (loop = 0; loop < ruleSet->numRules; loop++) {
        ruleHolder = ruleSet->regexFields[loop].rule;
        extraHolder = ruleSet->regexFields[loop].extra;
        offsetptr = offset;
        while (((rc = pcre_exec(ruleHolder, extraHolder,
                                (char *)payloadData, payloadSize, offsetptr,
                                0, subVects, NUM_SUBSTRING_VECTS)) > 0))
        {
            if (rc > 1) {
                captLen = subVects[3] - subVects[2];
                flowContext->dpi[captCount].dpacketCapt = subVects[2];
            } else {
                captLen = subVects[1] - subVects[0];
                flowContext->dpi[captCount].dpacketCapt = subVects[0];
            }
            if (captLen == 0) {
                flowContext->dpinum = captCount;
                return captDirection;
            }

            /* truncate capture length to capture limit */
            flowContext->dpi[captCount].dpacketID =
                ruleSet->regexFields[loop].info_element_id;
            if (captLen > ctx->dpi_user_limit) {captLen = ctx->dpi_user_limit;}
            flowContext->dpi[captCount].dpacketCaptLen = captLen;

            flowContext->dpi_len += captLen;
            if (flowContext->dpi_len > ctx->dpi_total_limit) {
                /* buffer full */
                flowContext->dpinum = captCount;
                return captDirection;
            }
            offsetptr = subVects[0] + captLen;
            captCount++;
            captDirection++;
            if ((captCount >= YAF_MAX_CAPTURE_FIELDS) ||
                (captDirection >= YAF_MAX_CAPTURE_SIDE))
            {
                /* limits reached */
                flowContext->dpinum = captCount;
                return captDirection;
            }
        }
        if (rc < -5) {
            /* print regular expression error */
            g_debug(
                "Error: Regular Expression (App: %d Rule: %d) Error Code %d",
                flow->appLabel, loop + 1, rc);
        }
    }

    flowContext->dpinum = captCount;

    return captDirection;
}


/**
 * Protocol Specific Functions
 *
 */
static fbTemplate_t *
ypInitTemplate(
    fbSession_t          *session,
    fbInfoElementSpec_t  *spec,
    uint16_t              tid,
    const gchar          *name,
    const gchar          *description,
    uint32_t              flags,
    GError              **err)
{
    fbInfoModel_t *model = ypGetDPIInfoModel();
    fbTemplate_t  *tmpl  = NULL;
    GError        *error = NULL;
    const ypExtraElements_t *extra;

    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, spec, flags, &error)) {
        g_debug("Error adding spec array to template for tid %d %s", tid,
                error->message);
        return NULL;
    }

    switch (tid) {
      case YAF_HTTP_FLOW_TID:
        extra = &http_extra;
        break;
      case YAF_IMAP_FLOW_TID:
        extra = &imap_extra;
        break;
      case YAF_FTP_FLOW_TID:
        extra = &ftp_extra;
        break;
      case YAF_RTSP_FLOW_TID:
        extra = &rtsp_extra;
        break;
      case YAF_SIP_FLOW_TID:
        extra = &sip_extra;
        break;
      default:
        extra = NULL;
    }
    if (extra && extra->specs
        && !fbTemplateAppendSpecArray(tmpl, extra->specs, 0xffffffff, &error))
    {
        g_debug("Error adding extra spec array to template with tid %#06x: %s",
                tid, error->message);
        g_clear_error(&error);
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }

#if YAF_ENABLE_METADATA_EXPORT
    if (!fbSessionAddTemplateWithMetadata(session, FALSE, tid,
                                          tmpl, name, description, &error))
    {
        g_debug("Error adding template %#06x: %s", tid, error->message);
        g_clear_error(&error);
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
#else /* if YAF_ENABLE_METADATA_EXPORT */
    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, &error)) {
        g_debug("Error adding template %#06x: %s", tid, error->message);
        g_clear_error(&error);
        fbTemplateFreeUnused(tmpl);
        return NULL;
    }
#endif /* if YAF_ENABLE_METADATA_EXPORT */

    return tmpl;
}


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
    uint8_t                         numBasicLists)
{
    yfDPIData_t    *dpi = flowContext->dpi;
    yfDPIContext_t *ctx = flowContext->yfctx;
    void           *rec = NULL;
    uint8_t         start = flowContext->startOffset;
    int             total = 0;
    fbVarfield_t   *varField = NULL;
    uint16_t        temp_element;
    uint8_t         totalIndex[YAF_MAX_CAPTURE_FIELDS];
    int             loop, oloop;
    fbBasicList_t  *blist;
    ypBLValue_t    *val;
    protocolRegexRules_t *ruleSet;

    rec = fbSubTemplateMultiListEntryInit(stml, stmlTID, stmlTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    ypInitializeBLs(ctx, rec, numBasicLists, rulePos);
    ruleSet = &ctx->ruleSet[rulePos];

    for (oloop = 0; oloop < ruleSet->numRules; oloop++) {
        temp_element = ruleSet->regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(ctx, temp_element);
            if (val) {
                blist = (fbBasicList_t *)((uint8_t *)rec + val->BLoffset);
                varField = (fbVarfield_t *)fbBasicListInit(
                    blist, 3, val->infoElement, total);
                ypFillBasicList(flow, dpi, total, fwdcap, &varField,
                                totalIndex);
            }
            total = 0;
            varField = NULL;
        }
    }

    return (void *)rec;
}


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
    const char                     *blIEName)
{
    yfDPIData_t   *dpi   = flowContext->dpi;
    fbVarfield_t  *varField;
    void          *rec   = NULL;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    int            count = flowContext->startOffset;

    rec = fbSubTemplateMultiListEntryInit(stml, stmlTID, stmlTemplate, 1);

    varField = (fbVarfield_t *)fbBasicListInit(
        rec, 3, fbInfoModelGetElementByName(model, blIEName), totalcap);

    while (count < fwdcap && varField) {
        varField->buf = flow->val.payload + dpi[count].dpacketCapt;
        varField->len = dpi[count].dpacketCaptLen;
        varField = fbBasicListGetNextPtr(rec, varField);
        count++;
    }

    if (fwdcap < totalcap && flow->rval.payload) {
        while (count < totalcap && varField) {
            varField->buf = flow->rval.payload + dpi[count].dpacketCapt;
            varField->len = dpi[count].dpacketCaptLen;
            varField = fbBasicListGetNextPtr(rec, varField);
            count++;
        }
    }

    return (void *)rec;
}


static void *
ypProcessTFTP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos)
{
    yfDPIData_t  *dpi = flowContext->dpi;
    yfTFTPFlow_t *rec = NULL;
    int           count = flowContext->startOffset;

    rec = (yfTFTPFlow_t *)fbSubTemplateMultiListEntryInit(
        stml, YAF_TFTP_FLOW_TID, tftpTemplate, 1);

    if (fwdcap) {
        rec->tftpFilename.buf = flow->val.payload + dpi[count].dpacketCapt;
        rec->tftpFilename.len = dpi[count].dpacketCaptLen;
        if (fwdcap > 1) {
            count++;
            rec->tftpMode.buf = flow->val.payload + dpi[count].dpacketCapt;
            rec->tftpMode.len = dpi[count].dpacketCaptLen;
        }
    } else if (flow->rval.payload) {
        rec->tftpFilename.buf = flow->rval.payload + dpi[count].dpacketCapt;
        rec->tftpFilename.len = dpi[count].dpacketCaptLen;
        if (dpi[++count].dpacketCapt) {
            rec->tftpMode.buf = flow->rval.payload + dpi[count].dpacketCapt;
            rec->tftpMode.len = dpi[count].dpacketCaptLen;
        }
    }

    return (void *)rec;
}


static void *
ypProcessSMTP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos)
{
    yfDPIData_t   *dpi = flowContext->dpi;
    yfSMTPFlow_t  *rec = NULL;
    int            count;
    fbInfoModel_t *model = ypGetDPIInfoModel();

    const fbInfoElement_t *smtpElemTo;
    const fbInfoElement_t *smtpElemFrom;
    const fbInfoElement_t *smtpElemFile;
    const fbInfoElement_t *smtpElemURL;
    const fbInfoElement_t *smtpElemResponse;

    fbVarfield_t          *responseCode = NULL;
    fbVarfield_t          *smtpTo = NULL;
    fbVarfield_t          *smtpFrom = NULL;
    fbVarfield_t          *smtpFilename = NULL;
    fbVarfield_t          *smtpURL = NULL;
    yfSMTPMessage_t       *smtpEmail;
    yfSMTPHeader_t        *smtpHeader;

    /* DPI counts, one for each list */
    int      numMatchesTo;
    int      numMatchesFrom;
    int      numMatchesFile;
    int      numMatchesURL;
    int      numMatchesHeader;
    const uint8_t *msgBound[SMTP_MAX_EMAILS + 1];
    int      numMessages;
    int      msgIndex;

    unsigned int  maxMsgCapt = 0;
    const uint8_t *msgBegin;
    const uint8_t *msgEnd;
    const uint8_t *colon;

    const yfFlowVal_t *current;
    const yfFlowVal_t *msgData = NULL;

    rec = (yfSMTPFlow_t *)fbSubTemplateMultiListEntryInit(
        stml, YAF_SMTP_FLOW_TID, smtpTemplate, 1);
    rec->smtpHello.buf = NULL;
    rec->smtpEnhanced.buf = NULL;
    rec->smtpSize = 0;
    rec->smtpStartTLS = 0;

    /* Create an empty basicList of SMTP response codes; fill the list as we
     * scan the data. */
    smtpElemResponse = fbInfoModelGetElementByName(model, "smtpResponse");
    fbBasicListInit(&rec->smtpResponseList, 3, smtpElemResponse, 0);

    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    /* Assume one message */
    numMessages = 1;

    /* Capture top-level data; determine whether forward or reverse direction
     * captured the client; capture the response codes; note bounds between
     * messages when multiple in a single conversation */
    for (count = flowContext->startOffset; count < totalcap; ++count) {
        current = ((count < fwdcap) ? &flow->val : &flow->rval);
        switch (dpi[count].dpacketID) {
          case 26:   /* Hello */
            if (rec->smtpHello.buf == NULL) {
                rec->smtpHello.buf = current->payload + dpi[count].dpacketCapt;
                rec->smtpHello.len = dpi[count].dpacketCaptLen;
            }
            if (msgData != current) {
                if (NULL == msgData) {
                    msgData = current;
                } else {
                    break;
                }
            }
            if (dpi[count].dpacketCapt > maxMsgCapt) {
                maxMsgCapt = dpi[count].dpacketCapt;
            }
            break;
          case 27:   /* Enhanced */
            if (rec->smtpEnhanced.buf == NULL) {
                rec->smtpEnhanced.buf =
                    current->payload + dpi[count].dpacketCapt;
                rec->smtpEnhanced.len = dpi[count].dpacketCaptLen;
            }
            break;
          case 28:   /* Size */
            if (0 == rec->smtpSize) {
                rec->smtpSize = (uint32_t)strtoul(
                    (char *)(msgData->payload + dpi[count].dpacketCapt),
                    NULL, 10);
            }
            break;
          case 29:   /* StartTLS */
            rec->smtpStartTLS = 1;
            break;
          case 30:   /* Response codes */
            responseCode = (fbVarfield_t *)
                fbBasicListAddNewElements(&rec->smtpResponseList, 1);
            responseCode->buf = current->payload + dpi[count].dpacketCapt;
            responseCode->len = dpi[count].dpacketCaptLen;
            break;
          case 38:   /* End of one message / Start of another */
            if (msgData != current) {
                if (NULL == msgData) {
                    msgData = current;
                } else {
                    break;
                }
            }
            msgBound[numMessages] = current->payload + dpi[count].dpacketCapt;
            ++numMessages;
            if (dpi[count].dpacketCapt > maxMsgCapt) {
                maxMsgCapt = dpi[count].dpacketCapt;
            }
            break;
          case 31:   /* Subject */
          case 32:   /* To */
          case 33:   /* From */
          case 34:   /* File */
          case 35:   /* URL */
          case 36:   /* Header */
            if (msgData != current) {
                if (NULL == msgData) {
                    msgData = current;
                } else {
                    break;
                }
            }
            if (dpi[count].dpacketCapt > maxMsgCapt) {
                maxMsgCapt = dpi[count].dpacketCapt;
            }
            break;
        }
    }

    if (NULL == msgData) {
        fbSubTemplateListInit(&rec->smtpMessageList, 3,
                              YAF_SMTP_MESSAGE_TID, smtpMessageTemplate, 0);
        return rec;
    }

    /* the first message begins at the start of the payload */
    msgBound[0] = msgData->payload;

    /* if no data was captured within the last bounded message, decrement the
     * number of messages; otherwise, set the bound of the final message to
     * the end of the payload */
    if (msgData->payload + maxMsgCapt <= msgBound[numMessages - 1]) {
        --numMessages;
    } else {
        msgBound[numMessages] = msgData->payload + msgData->paylen;
    }

    /* Create the STL of messages */
    smtpEmail = ((yfSMTPMessage_t *)fbSubTemplateListInit(
                     &rec->smtpMessageList, 3,
                     YAF_SMTP_MESSAGE_TID, smtpMessageTemplate,
                     numMessages));

    smtpElemTo = fbInfoModelGetElementByName(model, "smtpTo");
    smtpElemFrom = fbInfoModelGetElementByName(model, "smtpFrom");
    smtpElemFile = fbInfoModelGetElementByName(model, "smtpFilename");
    smtpElemURL = fbInfoModelGetElementByName(model, "smtpURL");

    /* Process each message */
    for (msgIndex = 0; msgIndex < numMessages; ++msgIndex) {
        msgBegin = msgBound[msgIndex];
        msgEnd = msgBound[msgIndex + 1];

        /* for IEs stored in basicLists or STLs, count the number of items to
         * know how big to make the lists. */
        numMatchesTo = 0;
        numMatchesFrom = 0;
        numMatchesFile = 0;
        numMatchesURL = 0;
        numMatchesHeader = 0;

        for (count = flowContext->startOffset; count < totalcap; ++count) {
            if (msgData->payload + dpi[count].dpacketCapt >= msgBegin &&
                (msgData->payload + dpi[count].dpacketCapt <= msgEnd))
            {
                switch (dpi[count].dpacketID) {
                  case 32:   /* To */
                    numMatchesTo++;
                    break;
                  case 33:   /* From */
                    numMatchesFrom++;
                    break;
                  case 34:   /* File */
                    numMatchesFile++;
                    break;
                  case 35:   /* URL */
                    numMatchesURL++;
                    break;
                  case 36:   /* Header */
                    numMatchesHeader++;
                    break;
                }
            }
        }

        /* Create the basicLists and STLs */
        smtpTo = (fbVarfield_t *)fbBasicListInit(
            &smtpEmail->smtpToList, 3, smtpElemTo, numMatchesTo);

        smtpFrom = (fbVarfield_t *)fbBasicListInit(
            &smtpEmail->smtpFromList, 3, smtpElemFrom, numMatchesFrom);

        smtpFilename = (fbVarfield_t *)fbBasicListInit(
            &smtpEmail->smtpFilenameList, 3, smtpElemFile, numMatchesFile);

        smtpURL = (fbVarfield_t *)fbBasicListInit(
            &smtpEmail->smtpURLList, 3, smtpElemURL, numMatchesURL);

        smtpHeader = ((yfSMTPHeader_t *)fbSubTemplateListInit(
                          &smtpEmail->smtpHeaderList, 3,
                          YAF_SMTP_HEADER_TID, smtpHeaderTemplate,
                          numMatchesHeader));

        /* Fill the lists we just created */
        for (count = flowContext->startOffset; count < totalcap; ++count) {
            if (msgData->payload + dpi[count].dpacketCapt >= msgBegin &&
                msgData->payload + dpi[count].dpacketCapt <= msgEnd)
            {
                switch (dpi[count].dpacketID) {
                  case 31:   /* Subject */
                    if (NULL == smtpEmail->smtpSubject.buf) {
                        smtpEmail->smtpSubject.buf =
                            msgData->payload + dpi[count].dpacketCapt;
                        smtpEmail->smtpSubject.len = dpi[count].dpacketCaptLen;
                    }
                    break;
                  case 32:   /* To */
                    smtpTo->buf = msgData->payload + dpi[count].dpacketCapt;
                    smtpTo->len = dpi[count].dpacketCaptLen;
                    smtpTo = fbBasicListGetNextPtr(&smtpEmail->smtpToList,
                                                   smtpTo);
                    break;
                  case 33:   /* From */
                    smtpFrom->buf = msgData->payload + dpi[count].dpacketCapt;
                    smtpFrom->len = dpi[count].dpacketCaptLen;
                    smtpFrom = fbBasicListGetNextPtr(&smtpEmail->smtpFromList,
                                                     smtpFrom);
                    break;
                  case 34:   /* Filename */
                    smtpFilename->buf = msgData->payload +
                        dpi[count].dpacketCapt;
                    smtpFilename->len = dpi[count].dpacketCaptLen;
                    smtpFilename = fbBasicListGetNextPtr(
                        &smtpEmail->smtpFilenameList, smtpFilename);
                    break;
                  case 35:   /* URL */
                    smtpURL->buf = msgData->payload + dpi[count].dpacketCapt;
                    smtpURL->len = dpi[count].dpacketCaptLen;
                    smtpURL = fbBasicListGetNextPtr(&smtpEmail->smtpURLList,
                                                    smtpURL);
                    break;
                  case 36:   /* Header */
                    smtpHeader->smtpKey.buf =
                        msgData->payload + dpi[count].dpacketCapt;
                    colon = memchr(smtpHeader->smtpKey.buf, (int)(':'),
                                   dpi[count].dpacketCaptLen);
                    if (NULL == colon) {
                        smtpHeader->smtpKey.buf = NULL;
                        g_debug("Unable to find ':' in Email header");
                        break;
                    }
                    smtpHeader->smtpKey.len = colon - smtpHeader->smtpKey.buf;

                    /* initialze value length to remainder of capture len */
                    smtpHeader->smtpValue.len =
                        dpi[count].dpacketCaptLen - smtpHeader->smtpKey.len;

                    /* Move over the colon and any whitespace */
                    do {
                        ++colon;
                        --smtpHeader->smtpValue.len;
                    } while (isspace(*colon) && smtpHeader->smtpValue.len > 0);
                    smtpHeader->smtpValue.buf = (uint8_t *)colon;

                    smtpHeader = fbSubTemplateListGetNextPtr(
                        &smtpEmail->smtpHeaderList, smtpHeader);
                    break;
                }
            }
        }
        smtpEmail = fbSubTemplateListGetNextPtr(&rec->smtpMessageList,
                                                smtpEmail);
    }
    return (void *)rec;
}


static void *
ypProcessSLP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos)
{
    yfDPIData_t   *dpi = flowContext->dpi;
    yfSLPFlow_t   *rec = NULL;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    int            loop;
    int            total = 0;
    int            count = flowContext->startOffset;
    fbVarfield_t  *slpVar = NULL;
    const fbInfoElement_t *slpString;
    yfFlowVal_t   *val;

    g_assert(fwdcap <= totalcap);
    rec = (yfSLPFlow_t *)fbSubTemplateMultiListEntryInit(
        stml, YAF_SLP_FLOW_TID, slpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    for (loop = count; loop < totalcap; loop++) {
        if (dpi[loop].dpacketID > 91) {
            total++;
        }
    }
    slpString = fbInfoModelGetElementByName(model, "slpString");
    slpVar = (fbVarfield_t *)fbBasicListInit(
        &(rec->slpString), 3, slpString, total);

    val = &flow->val;
    for ( ; count < totalcap; ++count) {
        if (count == fwdcap) {
            val = &flow->rval;
        }
        if (dpi[count].dpacketID == 90) {
            rec->slpVersion = (uint8_t)*(val->payload +
                                         dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID == 91) {
            rec->slpMessageType = (uint8_t)*(val->payload +
                                             dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID > 91 && slpVar) {
            slpVar->buf = val->payload + dpi[count].dpacketCapt;
            slpVar->len = dpi[count].dpacketCaptLen;
            slpVar = fbBasicListGetNextPtr(&(rec->slpString), slpVar);
        }
    }

    return (void *)rec;
}


static void *
ypProcessNNTP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos)
{
    yfDPIData_t   *dpi = flowContext->dpi;
    yfNNTPFlow_t  *rec = NULL;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    uint8_t        count;
    uint8_t        start = flowContext->startOffset;
    int            total = 0;
    fbVarfield_t  *nntpVar = NULL;
    uint8_t        totalIndex[YAF_MAX_CAPTURE_FIELDS];
    const fbInfoElement_t *nntpResponse;
    const fbInfoElement_t *nntpCommand;

    rec = (yfNNTPFlow_t *)fbSubTemplateMultiListEntryInit(
        stml, YAF_NNTP_FLOW_TID, nntpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    /* nntp Response */
    for (count = start; count < totalcap; count++) {
        if (dpi[count].dpacketID == 172) {
            totalIndex[total] = count;
            total++;
        }
    }

    nntpResponse = fbInfoModelGetElementByName(model, "nntpResponse");
    nntpVar = (fbVarfield_t *)fbBasicListInit(
        &(rec->nntpResponse), 3, nntpResponse, total);

    ypFillBasicList(flow, dpi, total, fwdcap, &nntpVar, totalIndex);

    total = 0;
    nntpVar = NULL;
    /* nntp Command */
    for (count = start; count < totalcap; count++) {
        if (dpi[count].dpacketID == 173) {
            totalIndex[total] = count;
            total++;
        }
    }

    nntpCommand = fbInfoModelGetElementByName(model, "nntpCommand");
    nntpVar = (fbVarfield_t *)fbBasicListInit(
        &(rec->nntpCommand), 3, nntpCommand, total);

    ypFillBasicList(flow, dpi, total, fwdcap, &nntpVar, totalIndex);

    return (void *)rec;
}


static void *
ypProcessSSL(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiList_t       *mainRec,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos)
{
    yfDPIData_t     *dpi = flowContext->dpi;
    yfDPIContext_t  *ctx = flowContext->yfctx;
    yfSSLFlow_t     *rec = NULL;
    yfSSLFullCert_t *fullrec = NULL;
    yfSSLCertFlow_t *sslcert = NULL;
    fbInfoModel_t   *model = ypGetDPIInfoModel();
    int              count = flowContext->startOffset;
    int              total_certs = 0;
    uint32_t        *sslCiphers;
    const uint8_t   *payload = NULL;
    size_t           paySize = 0;
    uint8_t          totalIndex[YAF_MAX_CAPTURE_FIELDS];
    gboolean         ciphertrue = FALSE;
    int              i;
    fbVarfield_t    *sslfull = NULL;
    const fbInfoElement_t *sslCipherIE;
    const fbInfoElement_t *sslCertificateIE;
    uint16_t        version = 0;
    uint16_t        sversion = 0;
    uint16_t       *elliptic_curve = NULL;
    char           *elliptic_format = NULL;
    char           *extension = NULL;
    char           *ser_extension = NULL;
    int             ellip_curve_len = 0;

    rec = (yfSSLFlow_t *)fbSubTemplateMultiListEntryInit(
        stml, YAF_SSL_FLOW_TID, sslTemplate, 1);
    sslCipherIE = fbInfoModelGetElementByName(model, "sslCipher");
    sslCertificateIE = fbInfoModelGetElementByName(model, "sslCertificate");
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    for ( ; count < totalcap; ++count) {
        if (count < fwdcap) {
            payload = flow->val.payload;
            paySize = flow->val.paylen;
        } else if (flow->rval.payload) {
            payload = flow->rval.payload;
            paySize = flow->rval.paylen;
        } else {
            continue;
        }

         switch (dpi[count].dpacketID) {
          case YF_SSL_CIPHER_LIST:
            /* uses 2 bytes for each cipher */
            sslCiphers = (uint32_t *)fbBasicListInit(
                &rec->sslCipherList, 3, sslCipherIE,
                dpi[count].dpacketCaptLen / 2);
            for (i = 0; i < dpi[count].dpacketCaptLen && sslCiphers; i += 2) {
                *sslCiphers = (uint32_t)ntohs(
                    *(uint16_t *)(payload + dpi[count].dpacketCapt + i));
                sslCiphers = fbBasicListGetNextPtr(&rec->sslCipherList,
                                                   sslCiphers);
            }
            ciphertrue = TRUE;
            break;

          case YF_SSL_COMPRESSION:
            rec->sslCompressionMethod = *(payload + dpi[count].dpacketCapt);
            break;

          case YF_SSL_CLIENT_VERSION:
            /* major version */
            if (!rec->sslClientVersion) {
                rec->sslClientVersion = dpi[count].dpacketCapt;
            }
            break;

          case YF_SSL_RECORD_VERSION:
            /* record version */
            rec->sslRecordVersion = dpi[count].dpacketCapt;
            break;

          case YF_SSL_SERVER_CIPHER:
            rec->sslServerCipher =
                ntohs(*(uint16_t *)(payload + dpi[count].dpacketCapt));
            break;

          case YF_SSL_V2_CIPHER_LIST:
            /* uses 3 bytes for each cipher */
            sslCiphers = (uint32_t *)fbBasicListInit(
                &rec->sslCipherList, 3, sslCipherIE,
                dpi[count].dpacketCaptLen / 3);
            for (i = 0; i < dpi[count].dpacketCaptLen && sslCiphers; i += 3) {
                *sslCiphers =
                    (ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt + i))
                     & 0xFFFFFF00) >> 8;
                sslCiphers = fbBasicListGetNextPtr(&rec->sslCipherList,
                                                   sslCiphers);
            }
            ciphertrue = TRUE;
            break;

          case YF_SSL_CERT_START:
            /* cache location to examine the certificates below */
            totalIndex[total_certs] = count;
            total_certs++;
            break;

          case YF_SSL_SERVER_NAME:
            /* server Name */
            rec->sslServerName.buf =
                (uint8_t *)payload + dpi[count].dpacketCapt;
            rec->sslServerName.len = dpi[count].dpacketCaptLen;
            break;

          case YF_SSL_VERSION:
            version = ntohs(*(uint16_t *)(payload + dpi[count].dpacketCapt));
            break;

          case YF_SSL_ELIPTIC_CURVE:
            ellip_curve_len = dpi[count].dpacketCaptLen / 2;
            elliptic_curve = g_new0(uint16_t, ellip_curve_len);
            for (i = 0; i < ellip_curve_len; i++) {
                elliptic_curve[i] = ntohs(
                    *(uint16_t *)(payload + dpi[count].dpacketCapt + (i * 2)));
            }
            break;

          case YF_SSL_ELIPTIC_FORMAT:
            {
                /* join elliptic curve formats with hyphens */
                GString *str =
                    g_string_sized_new(1 + 4 * dpi[count].dpacketCaptLen);
                for (i = 0; i < dpi[count].dpacketCaptLen; i++) {
                    g_string_append_printf(
                        str, "%u-", *(payload + dpi[count].dpacketCapt + i));
                }
                if (str->len > 1 && '-' == str->str[str->len - 1]) {
                    g_string_truncate(str, str->len - 1);
                }
                elliptic_format = g_string_free(str, FALSE);
            }
            break;

          case YF_SSL_CLIENT_EXTENSION:
            extension = ypSslStoreExtension(payload + dpi[count].dpacketCapt);
            break;

          case YF_SSL_SERVER_EXTENSION:
            ser_extension = ypSslStoreExtension(payload + dpi[count].dpacketCapt);
            break;

          case YF_SSL_SERVER_VERSION:
            sversion = ntohs(*(uint16_t *)(payload + dpi[count].dpacketCapt));
            break;

          default:
            g_debug("TLS DPI capture position %u has unexpected value %u"
                    " (len = %u)",
                    count, dpi[count].dpacketID, dpi[count].dpacketCapt);
            break;
        }
    }
    ypSslClientJA3( &rec->sslCipherList, extension, elliptic_curve,
                  elliptic_format, version, ellip_curve_len, rec->sslClientJA3,
                  &rec->sslClientJA3Fingerprint);
    ypSslServerJA3S(rec->sslServerCipher, sversion, ser_extension,
                  rec->sslServerJA3S, &rec->sslServerJA3SFingerprint);

    if (!ciphertrue) {
        fbBasicListInit(&(rec->sslCipherList), 3, sslCipherIE, 0);
    }

    if (ctx->ssl_off) {
        /* NULL since we're doing full cert export */
        sslcert = (yfSSLCertFlow_t *)fbSubTemplateListInit(
            &(rec->sslCertList), 3, YAF_SSL_CERT_FLOW_TID, sslCertTemplate, 0);
   } else {
        /* use the cached locations of YF_SSL_CERT_START and parse the
         * certificates */
        sslcert = ((yfSSLCertFlow_t *)fbSubTemplateListInit(
                       &(rec->sslCertList), 3,
                       YAF_SSL_CERT_FLOW_TID, sslCertTemplate, total_certs));
        for (i = 0; i < total_certs; i++) {
            if (totalIndex[i] < fwdcap) {
                payload = flow->val.payload;
                paySize = flow->val.paylen;
            } else if (flow->rval.payload) {
                payload = flow->rval.payload;
                paySize = flow->rval.paylen;
            }
            if (!ypDecodeSSLCertificate(ctx, &sslcert, payload, paySize, flow,
                                        dpi[totalIndex[i]].dpacketCapt))
            {
                if (sslcert->issuer.tmpl == NULL) {
                    fbSubTemplateListInit(
                        &(sslcert->issuer), 3,
                        YAF_SSL_SUBCERT_FLOW_TID, sslSubTemplate, 0);
                }
                if (sslcert->subject.tmpl == NULL) {
                    fbSubTemplateListInit(
                        &(sslcert->subject), 3,
                        YAF_SSL_SUBCERT_FLOW_TID, sslSubTemplate, 0);
                }
                if (sslcert->extension.tmpl == NULL) {
                    fbSubTemplateListInit(
                        &(sslcert->extension), 3,
                        YAF_SSL_SUBCERT_FLOW_TID, sslSubTemplate, 0);
                }
            }

            if (!(sslcert =
                      fbSubTemplateListGetNextPtr(&(rec->sslCertList),
                                                  sslcert)))
            {
                break;
            }
        }
    }

    if (ctx->full_cert_export) {
        uint32_t sub_cert_len;
        uint32_t tot_bl_len = 0;
        stml = fbSubTemplateMultiListGetNextEntry(mainRec, stml);
        fullrec = (yfSSLFullCert_t *)fbSubTemplateMultiListEntryInit(
            stml, YAF_FULL_CERT_TID, sslFullCertTemplate, 1);
        sslfull = (fbVarfield_t *)fbBasicListInit(
            &(fullrec->cert), 3, sslCertificateIE, total_certs);
        for (i = 0; i < total_certs; i++) {
            if (totalIndex[i] < fwdcap) {
                payload = flow->val.payload;
                paySize = flow->val.paylen;
            } else if (flow->rval.payload) {
                payload = flow->rval.payload;
                paySize = flow->rval.paylen;
            }
            if (dpi[totalIndex[i]].dpacketCapt + 4 > paySize) {
                sslfull->len = 0;
                sslfull->buf = NULL;
                sslfull = (fbVarfield_t *)fbBasicListGetNextPtr(
                    &(fullrec->cert), sslfull);
                continue;
            }
            sub_cert_len = (
                ntohl(*(uint32_t *)(payload + dpi[totalIndex[i]].dpacketCapt))
                & 0xFFFFFF00) >> 8;

            /* only continue if we have enough payload for the whole cert */
            if (dpi[totalIndex[i]].dpacketCapt + sub_cert_len > paySize) {
                sslfull->len = 0;
                sslfull->buf = NULL;
                sslfull = (fbVarfield_t *)fbBasicListGetNextPtr(
                    &(fullrec->cert), sslfull);
                continue;
            }

            sslfull->buf =
                (uint8_t *)payload + dpi[totalIndex[i]].dpacketCapt + 3;
            sslfull->len = sub_cert_len;
            tot_bl_len += sub_cert_len;
            sslfull = (fbVarfield_t *)fbBasicListGetNextPtr(
                &(fullrec->cert), sslfull);
        }

        if (!tot_bl_len) {
            fbBasicListClear(&(fullrec->cert));
            sslfull = (fbVarfield_t *)fbBasicListInit(
                &(fullrec->cert), 3, sslCertificateIE, 0);
        }

        flowContext->full_ssl_cert = fullrec;
    }

    return (void *)rec;
}

static void *
ypProcessSSH(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos)
{
    yfDPIData_t    *dpi = flowContext->dpi;
    yfSSHFlow_t    *rec = NULL;
    int            count = flowContext->startOffset;
    uint8_t        client_kex_request = 0;
    uint8_t        server_kex_reply = 0;
    uint32_t       server_kex_offset = 0;
    const uint8_t *payload = NULL;

    /* True if it is a client response */
    gboolean       client;
    GString       *kex_algo =                g_string_sized_new(500);
    GString       *server_host =             g_string_sized_new(500);
    GString       *encryptio_algo =          g_string_sized_new(500);
    GString       *mac_algo =                g_string_sized_new(500);
    GString       *compression_algo =        g_string_sized_new(500);
    GString       *kex_algo_server =         g_string_sized_new(500);
    GString       *encryptio_algo_server =   g_string_sized_new(500);
    GString       *mac_algo_server =         g_string_sized_new(500);
    GString       *compression_algo_server = g_string_sized_new(500);
    GString       *server_host_server =      g_string_sized_new(500);
    GString       *server_host_key    =      g_string_sized_new(500);

    rec = (yfSSHFlow_t *)fbSubTemplateMultiListEntryInit(
        stml, YAF_SSH_FLOW_TID, sshTemplate, 1);

    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    payload = flow->val.payload;
    client = TRUE;

    for (count = flowContext->startOffset; count < totalcap; ++count) {
        if (count == fwdcap) {
            payload = flow->rval.payload;
            client = FALSE;
        }

        switch (dpi[count].dpacketID) {
          case YF_SSH_KEX_ALGO:
            if (client) {
                g_string_append_len(
                    kex_algo,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            } else {
                g_string_append_len(
                    kex_algo_server,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_SERVER_HOST_KEY_ALGO:
            if (client) {
                g_string_append_len(
                    server_host,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            } else {
                g_string_append_len(
                    server_host_server,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_ENCRYPTION_ALGO_CLI_SRV:
            if (client) {
                g_string_append_len(
                    encryptio_algo,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_MAC_ALGO_CLI_SRV:
            if (client) {
                g_string_append_len(
                    mac_algo,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_COMPRESS_ALGO_CLI_SRV:
            if (client) {
                g_string_append_len(
                    compression_algo,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_ENCRYPTION_ALGO_SRV_CLI:
            if (!client) {
                g_string_append_len(
                    encryptio_algo_server,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_MAC_ALGO_SRV_CLI:
            if (!client) {
                g_string_append_len(
                    mac_algo_server,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_COMPRESS_ALGO_SRV_CLI:
            if (!client) {
                g_string_append_len(
                    compression_algo_server,
                    (const char *)(payload + dpi[count].dpacketCapt + 4),
                    ntohl(*(uint32_t *)(payload + dpi[count].dpacketCapt)));
            }
            break;

          case YF_SSH_CLIENT_KEX_REQUEST:
            if (client) {
                client_kex_request = dpi[count].dpacketCapt;
            }
            break;

          case YF_SSH_HOST_KEY:
            if (server_host_server->len > 0) {
                server_kex_reply = *(payload + dpi[count].dpacketCapt);
                server_kex_offset = dpi[count].dpacketCapt + 1;
            }
            break;

          case YF_SSH_VERSION:
            if (client) {
                rec->sshVersion.buf =
                    (uint8_t *)payload + dpi[count].dpacketCapt;
                rec->sshVersion.len = dpi[count].dpacketCaptLen;
            } else {
                rec->sshServerVersion.buf =
                    (uint8_t *)payload + dpi[count].dpacketCapt;
                rec->sshServerVersion.len = dpi[count].dpacketCaptLen;
            }
            break;
        }
    }

    if ((client_kex_request == SSH_MSG_KEXDH_INIT &&
         server_kex_reply == SSH_MSG_KEXDH_REPLY) ||
        (client_kex_request == SSH_MSG_KEX_DH_GEX_REQUEST &&
         server_kex_reply == SSH_MSG_KEX_DH_GEX_REPLY))
    {
        g_string_append_len(
            server_host_key,
            (const char *)(payload + server_kex_offset + 4),
            ntohl(*(uint32_t *)(payload + server_kex_offset)));
        ypComputeMD5(server_host_key->str, server_host_key->len,
                    rec->sshServerHostKey);
    }

    ypSshAlgoCompare(kex_algo, kex_algo_server, &rec->sshKeyExchangeAlgorithm);
    ypSshAlgoCompare(server_host, server_host_server, &rec->sshHostKeyAlgorithm);
    ypSshAlgoCompare(encryptio_algo, encryptio_algo_server, &rec->sshCipher);
    /* Implicit is declared for the mac address when ever a cipher is used
     * that has a domain */
    if ((rec->sshCipher.buf != NULL) &&
        strchr((const char *)rec->sshCipher.buf, '@') != NULL)
    {
        rec->sshMacAlgorithm.len = strlen("implicit");
        rec->sshMacAlgorithm.buf = (uint8_t *)g_strdup("implicit");
    } else {
        ypSshAlgoCompare(mac_algo, mac_algo_server, &rec->sshMacAlgorithm);
    }
    ypSshAlgoCompare(compression_algo, compression_algo_server,
                 &rec->sshCompressionMethod);

    if (kex_algo->len > 0) {
        ypSshHASSH(kex_algo, encryptio_algo->str, mac_algo->str,
                  compression_algo->str, rec->sshHassh,
                  &rec->sshHasshAlgorithms);
    }
    if (kex_algo_server->len > 0) {
        ypSshHASSH(kex_algo_server, encryptio_algo_server->str,
                  mac_algo_server->str, compression_algo_server->str,
                  rec->sshServerHassh, &rec->sshServerHasshAlgorithms);
    }

    g_string_free(encryptio_algo, TRUE);
    g_string_free(server_host, TRUE);
    g_string_free(server_host_server, TRUE);
    g_string_free(encryptio_algo_server, TRUE);
    g_string_free(mac_algo, TRUE);
    g_string_free(mac_algo_server, TRUE);
    g_string_free(compression_algo, TRUE);
    g_string_free(compression_algo_server, TRUE);
    g_string_free(server_host_key, TRUE);

    return (void *)rec;
}

static void *
ypProcessDNS(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos)
{
    yfDPIData_t   *dpi = flowContext->dpi;
    yfDNSFlow_t   *rec = NULL;
    yfDNSQRFlow_t *dnsQRecord = NULL;
    uint8_t        recCountFwd = 0;
    uint8_t        recCountRev = 0;
    unsigned int   buflen = 0;
    int            count = flowContext->startOffset;

    flowContext->exbuf = g_slice_alloc0(flowContext->yfctx->dpi_total_limit);

    rec = (yfDNSFlow_t *)fbSubTemplateMultiListEntryInit(
        stml, YAF_DNS_FLOW_TID, dnsTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    while (count < totalcap) {
        if (dpi[count].dpacketID == 0) {
            recCountFwd += dpi[count].dpacketCapt;
        } else if (dpi[count].dpacketID == 1) {
            recCountRev += dpi[count].dpacketCapt;
        }
        count++;
    }

    dnsQRecord = (yfDNSQRFlow_t *)fbSubTemplateListInit(
        &(rec->dnsQRList), 3, YAF_DNSQR_FLOW_TID, dnsQRTemplate,
        recCountFwd + recCountRev);
    if (!dnsQRecord) {
        g_debug("Error initializing SubTemplateList for DNS Resource "
                "Record with %d Templates", recCountFwd + recCountRev);
        return NULL;
    }

    if (flow->val.payload && recCountFwd) {
        ypDnsParser(&dnsQRecord, flow, &(flow->val),
                    flowContext->exbuf, &buflen, recCountFwd,
                    flowContext->yfctx->dpi_total_limit,
                    flowContext->yfctx->dnssec);
    }

    if (recCountRev) {
        if (recCountFwd) {
            if (!(dnsQRecord = fbSubTemplateListGetNextPtr(&(rec->dnsQRList),
                                                           dnsQRecord)))
            {
                return (void *)rec;
            }
        }
        if (!flow->rval.payload) {
            /* Uniflow */
            ypDnsParser(&dnsQRecord, flow, &(flow->val),
                        flowContext->exbuf, &buflen, recCountRev,
                        flowContext->yfctx->dpi_total_limit,
                        flowContext->yfctx->dnssec);
        } else {
            ypDnsParser(&dnsQRecord, flow, &(flow->rval),
                        flowContext->exbuf, &buflen, recCountRev,
                        flowContext->yfctx->dpi_total_limit,
                        flowContext->yfctx->dnssec);
        }
    }

    return (void *)rec;
}


static void *
ypProcessMySQL(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos)
{
    yfDPIData_t      *dpi = flowContext->dpi;
    yfMySQLFlow_t    *rec = NULL;
    yfMySQLTxtFlow_t *mysql = NULL;
    yfFlowVal_t      *val;
    uint8_t           count;
    uint8_t           start = flowContext->startOffset;
    int total = 0;

    g_assert(fwdcap <= totalcap);
    rec = (yfMySQLFlow_t *)fbSubTemplateMultiListEntryInit(
        stml, YAF_MYSQL_FLOW_TID, mysqlTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    for (count = start; count < totalcap; ++count) {
        /* since we test dpacketID < 29(0x1d), the != 223 is redundant.  did
         * not want to remove before confirming the test is correct. */
        if ((dpi[count].dpacketID != 223) && (dpi[count].dpacketID < 0x1d)) {
            total++;
        }
    }

    mysql = (yfMySQLTxtFlow_t *)fbSubTemplateListInit(
        &(rec->mysqlList), 3, YAF_MYSQLTXT_FLOW_TID, mysqlTxtTemplate, total);
    val = &flow->val;
    for (count = start; count < totalcap && mysql != NULL; ++count) {
        if (count == fwdcap) {
            val = &flow->rval;
        }
        /* MySQL Username */
        if (dpi[count].dpacketID == 223) {
            rec->mysqlUsername.buf = val->payload + dpi[count].dpacketCapt;
            rec->mysqlUsername.len = dpi[count].dpacketCaptLen;
        } else {
            mysql->mysqlCommandCode = dpi[count].dpacketID;
            mysql->mysqlCommandText.buf = val->payload + dpi[count].dpacketCapt;
            mysql->mysqlCommandText.len = dpi[count].dpacketCaptLen;
            mysql = fbSubTemplateListGetNextPtr(&(rec->mysqlList), mysql);
        }
    }

    return (void *)rec;
}


static void *
ypProcessDNP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos)
{
    yfDPIData_t    *dpi = flowContext->dpi;
    yfDPIContext_t *ctx = flowContext->yfctx;
    yfDNP3Flow_t   *rec = (yfDNP3Flow_t *)flowContext->rec;
    yfDNP3Rec_t    *dnp = NULL;
    uint8_t         count;
    uint8_t         start = flowContext->startOffset;
    uint8_t        *crc_ptr;
    size_t          crc_len;
    int             total = 0;
    size_t          total_len = 0;

    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    count = start;
    while (count < totalcap) {
        if (dpi[count].dpacketID == 284) {
            total++;
        }
        count++;
    }

    if (total == 0) {
        rec = (yfDNP3Flow_t *)fbSubTemplateMultiListEntryInit(
            stml, YAF_DNP3_FLOW_TID, dnp3Template, 0);
        flowContext->dpinum = 0;
        return (void *)rec;
    }

    flowContext->exbuf = g_slice_alloc0(flowContext->yfctx->dpi_total_limit);
    crc_ptr = flowContext->exbuf;

    rec = (yfDNP3Flow_t *)fbSubTemplateMultiListEntryInit(
        stml, YAF_DNP3_FLOW_TID, dnp3Template, 1);

    dnp = (yfDNP3Rec_t *)fbSubTemplateListInit(
        &(rec->dnp_list), 3, YAF_DNP3_REC_FLOW_TID, dnp3RecTemplate, total);
    count = start;
    while (count < fwdcap && dnp) {
        if (dpi[count].dpacketID == 284) {
            if (dpi[count].dpacketCaptLen <= crc_len) {
                dnp->object.buf = crc_ptr + dpi[count].dpacketCapt;
                dnp->object.len = dpi[count].dpacketCaptLen;
                crc_ptr += crc_len;
                total_len += crc_len;
                /* FIXME: the reverse code is identical except it
                 * includes the following statement here.  why?
                 *
                 * crc_len = ctx->dpi_total_limit - total_len;
                 */
            }
            dnp = fbSubTemplateListGetNextPtr(&(rec->dnp_list), dnp);
        } else if (dpi[count].dpacketID == 281) {
            dnp->src_address = *((uint16_t *)(flow->val.payload +
                                              dpi[count].dpacketCapt));
        } else if (dpi[count].dpacketID == 282) {
            dnp->dst_address = *((uint16_t *)(flow->val.payload +
                                              dpi[count].dpacketCapt));
        } else if (dpi[count].dpacketID == 283) {
            dnp->function = *(flow->val.payload + dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID == 15) {
            crc_len = ctx->dpi_total_limit - total_len;
            yfRemoveCRC((flow->val.payload + dpi[count].dpacketCapt),
                        dpi[count].dpacketCaptLen,
                        crc_ptr, &crc_len, 16, 2);
        } else {
            continue;
        }
        count++;
    }

    while (count < totalcap && dnp && flow->rval.payload) {
        if (dpi[count].dpacketID == 284) {
            if (dpi[count].dpacketCaptLen <= crc_len) {
                dnp->object.buf = crc_ptr + dpi[count].dpacketCapt;
                dnp->object.len = dpi[count].dpacketCaptLen;
                crc_ptr += crc_len;
                total_len += crc_len;
                /* FIXME: why is this only in the reverse code? */
                crc_len = ctx->dpi_total_limit - total_len;
            }
            dnp = fbSubTemplateListGetNextPtr(&(rec->dnp_list), dnp);
        } else if (dpi[count].dpacketID == 281) {
            dnp->src_address = *((uint16_t *)(flow->rval.payload +
                                              dpi[count].dpacketCapt));
        } else if (dpi[count].dpacketID == 282) {
            dnp->dst_address = *((uint16_t *)(flow->rval.payload +
                                              dpi[count].dpacketCapt));
        } else if (dpi[count].dpacketID == 283) {
            dnp->function = *(flow->rval.payload + dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID == 15) {
            crc_len = ctx->dpi_total_limit - total_len;
            yfRemoveCRC((flow->rval.payload + dpi[count].dpacketCapt),
                        dpi[count].dpacketCaptLen, crc_ptr,
                        &crc_len, 16, 2);
        } else {
            continue;
        }
        count++;
    }

    return (void *)rec;
}


static void *
ypProcessRTP(
    ypDPIFlowCtx_t                 *flowContext,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    uint8_t                         fwdcap,
    uint8_t                         totalcap,
    uint16_t                        rulePos)
{
    yfDPIData_t *dpi = flowContext->dpi;
    yfRTPFlow_t *rec = NULL;
    int          count = flowContext->startOffset;

    rec = (yfRTPFlow_t *)fbSubTemplateMultiListEntryInit(
        stml, YAF_RTP_FLOW_TID, rtpTemplate, 1);
    rec->rtpPayloadType = dpi[0].dpacketCapt;
    if (count > 1) {
        rec->reverseRtpPayloadType = dpi[1].dpacketCapt;
    } else {
        rec->reverseRtpPayloadType = 0;
    }

    return (void *)rec;
}


/*
 *  totalCaptures is the length of the indexArray; it is not related
 *  to the totalcap value seen elsewhere in this file.
 */
static void
ypFillBasicList(
    yfFlow_t      *flow,
    yfDPIData_t   *dpi,
    uint8_t        totalCaptures,
    uint8_t        forwardCaptures,
    fbVarfield_t **varField,
    uint8_t       *indexArray)
{
    yfFlowVal_t *val;
    unsigned int i;

    if (!(*varField)) {
        return;
    }

    for (i = 0; i < totalCaptures; i++) {
        val = (indexArray[i] < forwardCaptures) ? &flow->val : &flow->rval;
        if (dpi[indexArray[i]].dpacketCapt + dpi[indexArray[i]].dpacketCaptLen
            > val->paylen)
        {
            continue;
        }
        if (val->payload) {
            (*varField)->buf = val->payload + dpi[indexArray[i]].dpacketCapt;
            (*varField)->len = dpi[indexArray[i]].dpacketCaptLen;
        }
        if (i + 1 < totalCaptures) {
            (*varField)++;
        }
    }
}


static void
ypFreeSLPRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfSLPFlow_t *rec = (yfSLPFlow_t *)flowContext->rec;

    fbBasicListClear(&(rec->slpString));
}


static void
ypFreeIRCRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfIRCFlow_t *rec = (yfIRCFlow_t *)flowContext->rec;
    fbBasicListClear(&(rec->ircMsg));
}


static void
ypFreePOP3Rec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfPOP3Flow_t *rec = (yfPOP3Flow_t *)flowContext->rec;

    fbBasicListClear(&(rec->pop3msg));
}


static void
ypFreeTFTPRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfTFTPFlow_t *rec = (yfTFTPFlow_t *)flowContext->rec;
    (void)rec;
}


static void
ypFreeSMTPRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfSMTPFlow_t    *rec = (yfSMTPFlow_t *)flowContext->rec;
    yfSMTPMessage_t *message = NULL;

    fbBasicListClear(&(rec->smtpResponseList));

    while ((message = fbSubTemplateListGetNextPtr(&(rec->smtpMessageList),
                                                  message)))
    {
        fbBasicListClear(&(message->smtpToList));
        fbBasicListClear(&(message->smtpFromList));
        fbBasicListClear(&(message->smtpFilenameList));
        fbBasicListClear(&(message->smtpURLList));
        fbSubTemplateListClear(&(message->smtpHeaderList));
    }

    fbSubTemplateListClear(&(rec->smtpMessageList));
}


static void
ypFreeDNSRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfDNSFlow_t   *rec = (yfDNSFlow_t *)flowContext->rec;
    yfDNSQRFlow_t *dns = NULL;

    if (rec == NULL) { /* Possibly a non-dns flow, or malformed dns that caused
                        * a failure during allocation of the QR stl. */
        return;
    }
    while ((dns = fbSubTemplateListGetNextPtr(&(rec->dnsQRList), dns))) {
        fbSubTemplateListClear(&(dns->dnsRRList));
    }

    fbSubTemplateListClear(&(rec->dnsQRList));
}


static void
ypFreeDNPRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfDNP3Flow_t *dnp = (yfDNP3Flow_t *)flowContext->rec;

    if (flowContext->dpinum) {
        fbSubTemplateListClear(&(dnp->dnp_list));
    }
}


static void
ypFreeMySQLRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfMySQLFlow_t *rec = (yfMySQLFlow_t *)flowContext->rec;

    fbSubTemplateListClear(&(rec->mysqlList));
}


static void
ypFreeSSLRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfSSLFlow_t     *rec = (yfSSLFlow_t *)flowContext->rec;
    yfSSLCertFlow_t *cert = NULL;
    yfSSLFullCert_t *fullrec = (yfSSLFullCert_t *)flowContext->full_ssl_cert;

    while ((cert = fbSubTemplateListGetNextPtr(&(rec->sslCertList), cert))) {
        fbSubTemplateListClear(&(cert->issuer));
        fbSubTemplateListClear(&(cert->subject));
        fbSubTemplateListClear(&(cert->extension));
    }

    fbSubTemplateListClear(&(rec->sslCertList));

    fbBasicListClear(&(rec->sslCipherList));

    g_free(rec->sslClientJA3Fingerprint.buf);
    g_free(rec->sslServerJA3SFingerprint.buf);

    if (fullrec) {
        fbBasicListClear(&(fullrec->cert));
    }
}

static void
ypFreeSSHRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfSSHFlow_t *rec = (yfSSHFlow_t *)flowContext->rec;

    g_free(rec->sshKeyExchangeAlgorithm.buf);
    g_free(rec->sshHasshAlgorithms.buf);
    g_free(rec->sshServerHasshAlgorithms.buf);
    g_free(rec->sshHostKeyAlgorithm.buf);
    g_free(rec->sshCipher.buf);
    g_free(rec->sshMacAlgorithm.buf);
    g_free(rec->sshCompressionMethod.buf);

    (void)rec;
}


static void
ypFreeNNTPRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfNNTPFlow_t *rec = (yfNNTPFlow_t *)flowContext->rec;

    fbBasicListClear(&(rec->nntpResponse));
    fbBasicListClear(&(rec->nntpCommand));
}


static void
ypFreeModbusRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfModbusFlow_t *rec = (yfModbusFlow_t *)flowContext->rec;

    fbBasicListClear(&(rec->mbmsg));
}


static void
ypFreeEnIPRec(
    ypDPIFlowCtx_t  *flowContext)
{
    yfEnIPFlow_t *rec = (yfEnIPFlow_t *)flowContext->rec;

    fbBasicListClear(&(rec->enipmsg));
}

/*
 * Decodes a DNS name, including uncompressing compressed names by
 * following pointers and escaping non-ASCII characters. Returns the
 * length of the escaped name added to the export buffer. Updates
 * payload_offset to increase it by the amount consumed (or to
 * payload_size in the case of an error.)
 */
static unsigned int
ypDnsGetName(
    uint8_t        *export_buffer,
    unsigned int    export_offset,
    const uint8_t  *payload,
    unsigned int    payload_size,
    uint16_t       *payload_offset,
    uint16_t        export_limit)
{
    /*
     * Pointer to the offset currently being updated. Starts as the
     * offset that was passed in, then switches to "nested_offset" when
     * name compression is encountered.
     */
    uint16_t    *working_offset = payload_offset;
    /*
     * The payload size limit currently in effect. Starts as the
     * passed-in payload size, then switches to just before the current
     * label when name compression is encountered. Prevents loops.
     */
    unsigned int working_size = payload_size;
    /* Local offset once we've followed a pointer to previous labels. */
    uint16_t     nested_offset = *payload_offset;

    /* How much written directly to the export_buffer. */
    unsigned int escaped_size = 0;
    /* And how much unescaped, to check DNS protocol limits. */
    unsigned int unescaped_size = 0;

    uint16_t     label_size;
    unsigned int escaped_copy_size;

    while (*working_offset < working_size) {
        label_size = payload[*working_offset];
        *working_offset += 1;
        switch (label_size & DNS_LABEL_TYPE_MASK) {

          case DNS_LABEL_TYPE_STANDARD:
            if (0 == label_size) {
                /* Empty label, end of name or root domain. */
                /*
                 * For compatibility, leave this blank for the root
                 * domain rather than using "." (for now).
                 */
                return escaped_size;
            } else {
                if (label_size + unescaped_size + 1 > DNS_MAX_NAME_LENGTH) {
                    /* Unescaped DNS name is longer than spec allows. */
                    goto err;
                }
                if (*working_offset + label_size >= working_size) {
                    /* Label text passes end of allowed payload */
                    goto err;
                }

                escaped_copy_size = ypDnsEscapeValue(
                    &export_buffer[export_offset + escaped_size],
                    export_limit - export_offset - escaped_size,
                    &payload[*working_offset], label_size,
                    TRUE);
                if ((export_offset + escaped_size + escaped_copy_size + 1)
                      > export_limit)
                {
                    goto err;
                }
                escaped_size += escaped_copy_size;
                export_buffer[export_offset + escaped_size] = '.';
                escaped_size += 1;

                *working_offset += label_size;
                unescaped_size += label_size + 1;
            }
            continue;

          case DNS_LABEL_TYPE_COMPRESSED:
            if (*working_offset >= working_size) {
                /* Encoded offset passes end of allowed payload */
                goto err;
            }
            /* Combine parts of compressed name offset and mask */
            label_size = (label_size << 8) | payload[*working_offset];
            label_size &= DNS_LABEL_OFFSET_MASK;
            *working_offset += 1;
            /*
             * Payload from the start of this compressed name offset is
             * no longer allowed, to prevent cycles or forward pointing
             * compressed names. Forward pointers will be caught by the
             * next loop iteration.
             */
            working_size = *working_offset - 2;
            nested_offset = label_size;
            working_offset = &nested_offset;
            continue;

          case DNS_LABEL_TYPE_EXTENDED:
            /*
             * See RFC6891, Extension Mechanisms for DNS (EDNS(0)),
             * which obsoletes RFC2671, RFC2673
             */
            /* YAF does not support this */
#if 0
            g_debug("Extended label types (%#04x) are not supported",
                    label_size);
#endif
            goto err;

          default:
            g_assert(0x80 == (label_size & DNS_LABEL_TYPE_MASK));
#if 0
            g_debug("Unknown DNS label type %#04x", label_size);
#endif
            goto err;

        }
    }

  err:
    /*
     * Set payload_offset to payload_size to "consume" everything and
     * prevent further processing.
     */
    *payload_offset = payload_size;
    return 0;
}

/*
 * Processes a DNS text value (either a name label or a TXT record
 * value) which may contain binary data and escapes the content.
 * Backslashes are escaped as "\\", newlines as "\n", and byte values
 * outside of 32-126 as "\xHH" where HH is a pair of hexadecimal digits.
 *
 * In addition, if escape_dots is true, then dots are encoded as "\.",
 * for internal dots in DNS name labels.
 *
 * Returns the length encoded into the destination buffer. Returns zero
 * and zeroes out the written the destination if the result did not
 * fit in the buffer.
 */
static unsigned int
ypDnsEscapeValue(
    uint8_t        *dst,
    unsigned int    dst_size,
    const uint8_t  *src,
    unsigned int    src_size,
    gboolean        escape_dots)
{
    unsigned int escaped_size = 0;
    unsigned int i;
    uint8_t b;

    for (i = 0; i < src_size; i++) {
        b = src[i];
        switch (b) {
          case '\\':
            if (escaped_size + 2 > dst_size) goto err;
            dst[escaped_size] = '\\';
            dst[escaped_size + 1] = '\\';
            escaped_size += 2;
            continue;
          case '\n':
            if (escaped_size + 2 > dst_size) goto err;
            dst[escaped_size] = '\\';
            dst[escaped_size + 1] = 'n';
            escaped_size += 2;
            continue;
          case '.':
            if (escape_dots) {
                if (escaped_size + 2 > dst_size) goto err;
                dst[escaped_size] = '\\';
                dst[escaped_size + 1] = '.';
                escaped_size += 2;
                continue;
            }
            /* fall through to default case if not escaping dots */
          default:
            if (b < 32 || b > 126) {
                /* control characters and special whitespace */
                if (escaped_size + 4 > dst_size) goto err;
                dst[escaped_size] = '\\';
                dst[escaped_size + 1] = 'x';
                dst[escaped_size + 2] = hex_digits[0x0f & (b >> 4)];
                dst[escaped_size + 3] = hex_digits[0x0f & b];
                escaped_size += 4;
                continue;
            } else {
                /* normal ASCII characters */
                if (escaped_size + 1 > dst_size) goto err;
                dst[escaped_size] = b;
                escaped_size += 1;
                continue;
            }
        }
    }

    /* success, return the escaped length of the value. */
    return escaped_size;

  err:
    /* clear out anything that was written before returning. */
    memset(dst, 0, escaped_size);
    return 0;
}

/*
 * Parses a DNS message from a flow's payload, encoding any
 * variable-length values into buf at position bufSize, avoiding writing
 * further than export_limit. Attempts to produce recordCount output
 * records, between various record types described in the DNS header.
 *
 * Ignores EDNS option pseudo-records (41).
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
    gboolean        dnssec)
{
    ycDnsScanMessageHeader_t header;
    uint16_t       offset = sizeof(ycDnsScanMessageHeader_t);
    uint16_t       firstpkt = val->paylen;
    uint16_t       msglen;
    size_t         nameLen;
    uint8_t        nxdomain = 0;
    unsigned int   bufSize = (*bufLen);
    uint16_t       rrType;
    unsigned int   loop = 0;
    const uint8_t *payload = val->payload;
    unsigned int   payloadSize = val->paylen;

    if (flow->key.proto == YF_PROTO_TCP) {
        while (loop < val->pkt && loop < YAF_MAX_PKT_BOUNDARY) {
            if (val->paybounds[loop] == 0) {
                loop++;
            } else {
                firstpkt = val->paybounds[loop];
                break;
            }
        }
        msglen = ntohs(*((uint16_t *)(payload)));
        if ((msglen + 2) == firstpkt) {
            /* this is the weird message length in TCP */
            payload += sizeof(uint16_t);
            payloadSize -= sizeof(uint16_t);
        }
    }

    ycDnsScanRebuildHeader(payload, &header);

    if (header.rcode != 0) {
        nxdomain = 1;
    }

#if defined(YAF_ENABLE_DNSAUTH)
    if (header.aa) {
        /* get the query part if authoritative */
        nxdomain = 1;
    }
#endif /* if defined(YAF_ENABLE_DNSAUTH) */

    for (loop = 0; loop < header.qdcount && offset < payloadSize; loop++) {
        nameLen = ypDnsGetName(buf, bufSize, payload, payloadSize,
                               &offset, export_limit);
        if ((!header.qr || nxdomain)) {
            fbSubTemplateListInit(
                &((*dnsQRecord)->dnsRRList), 3,
                YAF_DNSA_FLOW_TID, dnsATemplate, 0);
            (*dnsQRecord)->dnsQName.len = nameLen;
            (*dnsQRecord)->dnsQName.buf = buf + bufSize;
            bufSize += (*dnsQRecord)->dnsQName.len;
            (*dnsQRecord)->dnsAuthoritative = header.aa;
            (*dnsQRecord)->dnsNXDomain = header.rcode;
            (*dnsQRecord)->dnsRRSection = 0;
            (*dnsQRecord)->dnsQueryResponse = header.qr;
            (*dnsQRecord)->dnsID = header.id;
            if (((size_t)offset + 2) < payloadSize) {
                (*dnsQRecord)->dnsQRType =
                    ntohs(*((uint16_t *)(payload + offset)));
            }

            recordCount--;
            if (recordCount) {
                (*dnsQRecord)++;
            } else {
                goto cleanup;
            }
        }

        offset += (sizeof(uint16_t) * 2);
        /* skip over class */
        if (offset > payloadSize) {
            goto cleanup;
        }
    }
    if (loop < header.qdcount) {
        /* Not all questions processed. */
        goto cleanup;
    }

    for (loop = 0; loop < header.ancount && offset < payloadSize; loop++) {
        (*dnsQRecord)->dnsRRSection = 1;
        (*dnsQRecord)->dnsAuthoritative = header.aa;
        (*dnsQRecord)->dnsNXDomain = header.rcode;
        (*dnsQRecord)->dnsQueryResponse = 1;
        (*dnsQRecord)->dnsID = header.id;
        rrType = ypDnsScanResourceRecord(dnsQRecord, payload, payloadSize,
                                         &offset, buf, &bufSize,
                                         export_limit, dnssec);

        if (rrType != 41) { /* not EDNS option pseudo-record */
            recordCount--;
            if (recordCount) {
                (*dnsQRecord)++;
            } else {
                goto cleanup;
            }
        }

        if (offset > payloadSize) {
            goto cleanup;
        }

        if (bufSize > export_limit) {
            bufSize = export_limit;
            goto cleanup;
        }
    }
    if (loop < header.ancount) {
        /* Not all answer records processed. */
        goto cleanup;
    }

    for (loop = 0; loop < header.nscount && offset < payloadSize; loop++) {
        (*dnsQRecord)->dnsRRSection = 2;
        (*dnsQRecord)->dnsAuthoritative = header.aa;
        (*dnsQRecord)->dnsNXDomain = header.rcode;
        (*dnsQRecord)->dnsQueryResponse = 1;
        (*dnsQRecord)->dnsID = header.id;
        rrType = ypDnsScanResourceRecord(dnsQRecord, payload, payloadSize,
                                         &offset, buf, &bufSize,
                                         export_limit, dnssec);

        if (rrType != 41) { /* not EDNS option pseudo-record */
            recordCount--;
            if (recordCount) {
                (*dnsQRecord)++;
            } else {
                goto cleanup;
            }
        }

        if (offset > payloadSize) {
            goto cleanup;
        }

        if (bufSize > export_limit) {
            bufSize = export_limit;
            goto cleanup;
        }
    }
    if (loop < header.nscount) {
        /* Not all authority records processed. */
        goto cleanup;
    }

    for (loop = 0; loop < header.arcount && offset < payloadSize; loop++) {
        (*dnsQRecord)->dnsRRSection = 3;
        (*dnsQRecord)->dnsAuthoritative = header.aa;
        (*dnsQRecord)->dnsNXDomain = header.rcode;
        (*dnsQRecord)->dnsQueryResponse = 1;
        (*dnsQRecord)->dnsID = header.id;
        rrType = ypDnsScanResourceRecord(dnsQRecord, payload, payloadSize,
                                         &offset, buf, &bufSize,
                                         export_limit, dnssec);

        if (rrType != 41) { /* not EDNS option pseudo-record */
            recordCount--;
            if (recordCount) {
                (*dnsQRecord)++;
            } else {
                goto cleanup;
            }
        }

        if (offset > payloadSize) {
            goto cleanup;
        }

        if (bufSize > export_limit) {
            bufSize = export_limit;
            goto cleanup;
        }
    }
    if (loop < header.arcount) {
        /* Not all additional records processed. */
        goto cleanup;
    }

  cleanup:
    /* Make sure to pass export buffer usage back up to the caller */
    *bufLen = bufSize;

    /*
     * If something went wrong we need to pad the rest of the STL with
     * NULLs. This would most likely mean we ran out of space in the DNS
     * Export Buffer.
     */
    while (recordCount) {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                              YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        recordCount--;
        if (recordCount) {
            (*dnsQRecord)++;
        }
    }
}


static uint16_t
ypDnsScanResourceRecord(
    yfDNSQRFlow_t **dnsQRecord,
    const uint8_t  *payload,
    unsigned int    payloadSize,
    uint16_t       *offset,
    uint8_t        *buf,
    unsigned int   *bufLen,
    uint16_t        export_limit,
    gboolean        dnssec)
{
    uint16_t nameLen;
    uint16_t rrLen = 0;
    uint16_t rrType = 0;
    uint32_t temp_size;
    uint16_t temp_offset;
    uint16_t bufSize = (*bufLen);

    nameLen = ypDnsGetName(buf, bufSize, payload, payloadSize, offset,
                           export_limit);
    (*dnsQRecord)->dnsQName.len = nameLen;
    (*dnsQRecord)->dnsQName.buf = buf + bufSize;
    bufSize += (*dnsQRecord)->dnsQName.len;

    /*
     * Check early to make sure there's room for the rest of the RR
     * header items and abort, because we need to init this RR list item
     * on failure, and we don't want to check and do it every single
     * time.
     */
    if (*offset + sizeof(uint16_t) * 3 + sizeof(uint32_t) > payloadSize) {
        *offset = payloadSize;
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                              YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        goto cleanup;
    }

    /* RR type. Class is ignored. */
    rrType = ntohs(*((uint16_t *)(payload + (*offset))));
    (*dnsQRecord)->dnsQRType = rrType;
    *offset += sizeof(uint16_t) * 2;

    /* time to live */
    (*dnsQRecord)->dnsTTL = ntohl(*((uint32_t *)(payload + (*offset))));
    *offset += sizeof(uint32_t);

    rrLen = ntohs(*(uint16_t *)(payload + (*offset)));
    *offset += sizeof(uint16_t);

    /*
     * Another chance to abort, if the RR length extends past the end of
     * the captured payload.
     */
    if (*offset + rrLen > payloadSize) {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                              YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        goto cleanup;
    }

    temp_offset = (*offset);
    temp_size = temp_offset + rrLen;

    if (rrType == 1) { /* A */
        yfDNSAFlow_t *arecord = (yfDNSAFlow_t *)fbSubTemplateListInit(
            &((*dnsQRecord)->dnsRRList), 3,
            YAF_DNSA_FLOW_TID, dnsATemplate, 1);
        if (temp_offset + sizeof(uint32_t) > temp_size) {
            arecord->ip = 0;
        } else {
            arecord->ip = ntohl(*((uint32_t *)(payload + temp_offset)));
        }
    } else if (rrType == 2) { /* NS */
        yfDNSNSFlow_t *nsrecord = (yfDNSNSFlow_t *)fbSubTemplateListInit(
            &((*dnsQRecord)->dnsRRList), 3,
            YAF_DNSNS_FLOW_TID, dnsNSTemplate, 1);
        nsrecord->nsdname.len = ypDnsGetName(buf, bufSize, payload,
                                             temp_size, &temp_offset,
                                             export_limit);
        nsrecord->nsdname.buf = buf + bufSize;
        bufSize += nsrecord->nsdname.len;
    } else if (rrType == 5) { /* CNAME */
        yfDNSCNameFlow_t *cname = (yfDNSCNameFlow_t *)fbSubTemplateListInit(
            &((*dnsQRecord)->dnsRRList), 3,
            YAF_DNSCN_FLOW_TID, dnsCNTemplate, 1);
        cname->cname.len = ypDnsGetName(buf, bufSize, payload,
                                        temp_size, &temp_offset,
                                        export_limit);
        cname->cname.buf = buf + bufSize;
        bufSize += cname->cname.len;
    } else if (rrType == 12) { /* PTR */
        yfDNSPTRFlow_t *ptr = (yfDNSPTRFlow_t *)fbSubTemplateListInit(
            &((*dnsQRecord)->dnsRRList), 3,
            YAF_DNSPTR_FLOW_TID, dnsPTRTemplate, 1);
        ptr->ptrdname.len = ypDnsGetName(buf, bufSize, payload, temp_size,
                                         &temp_offset, export_limit);
        ptr->ptrdname.buf = buf + bufSize;
        bufSize += ptr->ptrdname.len;
    } else if (rrType == 15) { /* MX */
        yfDNSMXFlow_t *mx = (yfDNSMXFlow_t *)fbSubTemplateListInit(
            &((*dnsQRecord)->dnsRRList), 3,
            YAF_DNSMX_FLOW_TID, dnsMXTemplate, 1);
        if (temp_offset + sizeof(uint16_t) <= temp_size) {
            mx->preference = ntohs(*((uint16_t *)(payload + temp_offset)));
        }
        temp_offset += sizeof(uint16_t);
        mx->exchange.len = ypDnsGetName(buf, bufSize, payload, temp_size,
                                        &temp_offset, export_limit);
        mx->exchange.buf = buf + bufSize;
        bufSize += mx->exchange.len;
    } else if (rrType == 16) { /* TXT */
        yfDNSTXTFlow_t *txt = (yfDNSTXTFlow_t *)fbSubTemplateListInit(
            &((*dnsQRecord)->dnsRRList), 3,
            YAF_DNSTXT_FLOW_TID, dnsTXTTemplate, 1);
        if (temp_offset + 1 > temp_size ||
            temp_offset + 1 + payload[temp_offset] > temp_size)
        {
            txt->txt_data.len = 0;
        } else {
            txt->txt_data.len = ypDnsEscapeValue(
                &buf[bufSize], export_limit - bufSize,
                &payload[temp_offset + 1], payload[temp_offset],
                FALSE);
            if (txt->txt_data.len > 0) {
                txt->txt_data.buf = &buf[bufSize];
                bufSize += txt->txt_data.len;
            }
            temp_offset += payload[temp_offset] + 1;
        }
    } else if (rrType == 28) { /* AAAA */
        yfDNSAAAAFlow_t *aa = (yfDNSAAAAFlow_t *)fbSubTemplateListInit(
            &((*dnsQRecord)->dnsRRList), 3,
            YAF_DNSAAAA_FLOW_TID, dnsAAAATemplate, 1);
        if (temp_offset + sizeof(aa->ip) > temp_size) {
            memset(aa->ip, 0, sizeof(aa->ip));
        } else {
            memcpy(aa->ip, (payload + temp_offset), sizeof(aa->ip));
        }
    } else if (rrType == 6) { /* SOA */
        yfDNSSOAFlow_t *soa = (yfDNSSOAFlow_t *)fbSubTemplateListInit(
            &((*dnsQRecord)->dnsRRList), 3,
            YAF_DNSSOA_FLOW_TID, dnsSOATemplate, 1);
        soa->mname.len = ypDnsGetName(buf, bufSize, payload, temp_size,
                                      &temp_offset, export_limit);
        soa->mname.buf = buf + bufSize;
        bufSize += soa->mname.len;

        soa->rname.len = ypDnsGetName(buf, bufSize, payload, temp_size,
                                      &temp_offset, export_limit);
        soa->rname.buf = buf + bufSize;
        bufSize += soa->rname.len;

        if (temp_offset + sizeof(uint32_t) > temp_size) {
            goto cleanup;
        }
        soa->serial = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);

        if (temp_offset + sizeof(uint32_t) > temp_size) {
            goto cleanup;
        }
        soa->refresh = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);

        if (temp_offset + sizeof(uint32_t) > temp_size) {
            goto cleanup;
        }
        soa->retry = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);

        if (temp_offset + sizeof(uint32_t) > temp_size) {
            goto cleanup;
        }
        soa->expire = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);

        if (temp_offset + sizeof(uint32_t) > temp_size) {
            goto cleanup;
        }
        soa->minimum = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
    } else if (rrType == 33) { /* SRV */
        yfDNSSRVFlow_t *srv = (yfDNSSRVFlow_t *)fbSubTemplateListInit(
            &((*dnsQRecord)->dnsRRList), 3,
            YAF_DNSSRV_FLOW_TID, dnsSRVTemplate, 1);
        if (temp_offset + sizeof(uint16_t) > temp_size) {
            goto cleanup;
        }
        srv->dnsPriority = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);

        if (temp_offset + sizeof(uint16_t) > temp_size) {
            goto cleanup;
        }
        srv->dnsWeight = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);

        if (temp_offset + sizeof(uint16_t) > temp_size) {
            goto cleanup;
        }
        srv->dnsPort = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);

        srv->dnsTarget.len = ypDnsGetName(buf, bufSize, payload, temp_size,
                                          &temp_offset, export_limit);
        srv->dnsTarget.buf = buf + bufSize;
        bufSize += srv->dnsTarget.len;
    } else if (rrType == 43) { /* DS */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSDSFlow_t *ds = NULL;
            ds = (yfDNSDSFlow_t *)fbSubTemplateListInit(
                &((*dnsQRecord)->dnsRRList), 3,
                YAF_DNSDS_FLOW_TID, dnsDSTemplate, 1);

            if (temp_offset + sizeof(uint16_t) > temp_size) {
                goto cleanup;
            }
            ds->dnsKeyTag = ntohs(*((uint16_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint16_t);

            if (temp_offset + sizeof(uint8_t) > temp_size) {
                goto cleanup;
            }
            ds->dnsAlgorithm = *(payload + temp_offset);
            temp_offset += sizeof(uint8_t);

            if (temp_offset + sizeof(uint8_t) > temp_size) {
                goto cleanup;
            }
            ds->dnsDigestType = *(payload + temp_offset);
            temp_offset += sizeof(uint8_t);

            /* Digest is the remainder of the RR */
            if (temp_size > temp_offset) {
                goto cleanup;
            }
            ds->dnsDigest.buf = (uint8_t *)payload + temp_offset;
            ds->dnsDigest.len = temp_size - temp_offset;
        }
    } else if (rrType == 46) { /* RRSIG */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSRRSigFlow_t *rrsig = NULL;
            rrsig = (yfDNSRRSigFlow_t *)fbSubTemplateListInit(
                &((*dnsQRecord)->dnsRRList), 3,
                YAF_DNSRRSIG_FLOW_TID, dnsRRSigTemplate, 1);

            if (temp_offset + sizeof(uint16_t) > temp_size) {
                goto cleanup;
            }
            rrsig->dnsTypeCovered = ntohs(*((uint16_t *)(payload +
                                                         temp_offset)));
            temp_offset += sizeof(uint16_t);

            if (temp_offset + sizeof(uint8_t) > temp_size) {
                goto cleanup;
            }
            rrsig->dnsAlgorithm = *(payload + temp_offset);
            temp_offset += sizeof(uint8_t);

            if (temp_offset + sizeof(uint8_t) > temp_size) {
                goto cleanup;
            }
            rrsig->dnsLabels = *(payload + temp_offset);
            temp_offset += sizeof(uint8_t);

            if (temp_offset + sizeof(uint32_t) > temp_size) {
                goto cleanup;
            }
            rrsig->dnsTTL = ntohl(*((uint32_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint32_t);

            if (temp_offset + sizeof(uint32_t) > temp_size) {
                goto cleanup;
            }
            rrsig->dnsSigExp = ntohl(*((uint32_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint32_t);

            if (temp_offset + sizeof(uint32_t) > temp_size) {
                goto cleanup;
            }
            rrsig->dnsSigInception = ntohl(*((uint32_t *)(payload +
                                                          temp_offset)));
            temp_offset += sizeof(uint32_t);

            if (temp_offset + sizeof(uint16_t) > temp_size) {
                goto cleanup;
            }
            rrsig->dnsKeyTag = ntohs(*((uint16_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint16_t);

            rrsig->dnsSigner.len = ypDnsGetName(buf, bufSize, payload,
                                                temp_size, &temp_offset,
                                                export_limit);
            rrsig->dnsSigner.buf = buf + bufSize;
            bufSize += rrsig->dnsSigner.len;

            /* Signature is the remainder of the RR */
            if (temp_offset > temp_size) {
                goto cleanup;
            }
            rrsig->dnsSignature.buf = (uint8_t *)payload + temp_offset;
            rrsig->dnsSignature.len = temp_size - temp_offset;
        }
    } else if (rrType == 47) { /* NSEC */
        /* NSEC */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSNSECFlow_t *nsec = NULL;
            nsec = (yfDNSNSECFlow_t *)fbSubTemplateListInit(
                &((*dnsQRecord)->dnsRRList), 3,
                YAF_DNSNSEC_FLOW_TID, dnsNSECTemplate, 1);
            nsec->dnsHashData.len = ypDnsGetName(buf, bufSize, payload,
                                                 temp_size, &temp_offset,
                                                 export_limit);
            nsec->dnsHashData.buf = buf + bufSize;
            bufSize += nsec->dnsHashData.len;
            /* forget bitmaps. */
        }
    } else if (rrType == 48) {
        /* DNSKEY RR */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSKeyFlow_t *dnskey = NULL;
            dnskey = (yfDNSKeyFlow_t *)fbSubTemplateListInit(
                &((*dnsQRecord)->dnsRRList), 3,
                YAF_DNSKEY_FLOW_TID, dnsKeyTemplate, 1);
            if (temp_offset + sizeof(uint16_t) > temp_size) {
                goto cleanup;
            }
            dnskey->dnsFlags = ntohs(*((uint16_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint16_t);

            if (temp_offset + sizeof(uint8_t) >= temp_size) {
                goto cleanup;
            }
            dnskey->protocol = *(payload + temp_offset);
            temp_offset += sizeof(uint8_t);

            if (temp_offset + sizeof(uint8_t) > temp_size) {
                goto cleanup;
            }
            dnskey->dnsAlgorithm = *(payload + temp_offset);
            temp_offset += sizeof(uint8_t);

            /* Key is the remainder of the RR */
            if (temp_size > temp_offset) {
                goto cleanup;
            }
            dnskey->dnsPublicKey.buf = (uint8_t *)payload + temp_offset;
            dnskey->dnsPublicKey.len = temp_size - temp_offset;
        }
    } else if (rrType == 50 || rrType == 51) { /* NSEC3 + NSEC3PARAM */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSNSEC3Flow_t *nsec3 = NULL;
            nsec3 = (yfDNSNSEC3Flow_t *)fbSubTemplateListInit(
                &((*dnsQRecord)->dnsRRList), 3,
                YAF_DNSNSEC3_FLOW_TID, dnsNSEC3Template, 1);

            if (temp_offset + sizeof(uint8_t) > temp_size) {
                goto cleanup;
            }
            nsec3->dnsAlgorithm = *(payload + temp_offset);
            temp_offset += sizeof(uint8_t);

            /* skip over flags */
            if (temp_offset + sizeof(uint8_t) > temp_size) {
                goto cleanup;
            }
            temp_offset += sizeof(uint8_t);

            if (temp_offset + sizeof(uint16_t) > temp_size) {
                goto cleanup;
            }
            nsec3->iterations = ntohs(*((uint16_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint16_t);

            if (temp_offset + sizeof(uint8_t) > temp_size) {
                goto cleanup;
            }
            nsec3->dnsSalt.len = *(payload + temp_offset);
            temp_offset += sizeof(uint8_t);

            if (temp_offset + nsec3->dnsSalt.len > temp_size) {
                nsec3->dnsSalt.len = 0;
                goto cleanup;
            }
            nsec3->dnsSalt.buf = (uint8_t *)payload + temp_offset;
            temp_offset += nsec3->dnsSalt.len;

            if (rrType == 50) {
                if (temp_offset + sizeof(uint8_t) > temp_size) {
                    goto cleanup;
                }
                nsec3->dnsNextDomainName.len = *(payload + temp_offset);
                temp_offset += sizeof(uint8_t);
                if (temp_offset + nsec3->dnsNextDomainName.len > temp_size) {
                    nsec3->dnsNextDomainName.len = 0;
                    goto cleanup;
                }
                nsec3->dnsNextDomainName.buf =
                    (uint8_t *)payload + temp_offset;
            }
        }
    } else {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                              YAF_DNSA_FLOW_TID, dnsATemplate, 0);
    }

  cleanup:
    *offset += rrLen;
    if (*offset > payloadSize) {
        *offset = payloadSize;
    }
    *bufLen = bufSize;
    return rrType;
}


/*
 *  Decodes the length in `payload` at the current `offset`, sets the referent
 *  of `offset` to the octet AFTER the length, and returns the length.
 *  `payload_size` is the maximum number of octets to read.
 *
 *  If there are too few bytes to read the length, sets the referent of
 *  `offset` to one more than `payload_size` and returns UINT16_MAX.
 */
static uint16_t
ypDecodeLength(
    const uint8_t  *payload,
    uint32_t        payload_size,
    uint32_t       *offset)
{
    uint16_t obj_len;

    /*
     *  When the high bit of the byte at `offset` is not set, that single byte
     *  is the length (0--127).  When the high bit is set, the remaining bits
     *  are the length of length (either 1 byte (0x81) (128--255) or 2 bytes
     *  (0x82) (256--65535) in practice).
     */

    if (*offset + 4 <= payload_size) {
        /* there is enough payload */
        obj_len = *(payload + *offset);
        ++*offset;
        if (obj_len == CERT_1BYTE) {
            obj_len = *(payload + *offset);
            ++*offset;
        } else if (obj_len == CERT_2BYTE) {
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
            memcpy(&obj_len, (payload + offset), sizeof(uint16_t));
            obj_len = ntohs(obj_len);
#else
            obj_len = ntohs(*(uint16_t *)(payload + *offset));
#endif  /* HAVE_ALIGNED_ACCESS_REQUIRED */
            *offset += 2;
        }

        return obj_len;
    }

    /* Handle each step individually to avoid reading too much */
    if (*offset >= payload_size) {
        goto err;
    }
    obj_len = *(payload + *offset);
    ++*offset;
    if (obj_len == CERT_1BYTE) {
        if (*offset >= payload_size) {
            goto err;
        }
        obj_len = *(payload + *offset);
        ++*offset;
    } else if (obj_len == CERT_2BYTE) {
        if (*offset + 2 > payload_size) {
            goto err;
        }
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
        memcpy(&obj_len, (payload + offset), sizeof(uint16_t));
        obj_len = ntohs(obj_len);
#else
        obj_len = ntohs(*(uint16_t *)(payload + *offset));
#endif  /* HAVE_ALIGNED_ACCESS_REQUIRED */
        *offset += 2;
    }

    return obj_len;

  err:
    *offset = payload_size + 1;
    return UINT16_MAX;
}


/*
 *  Decodes the type of value in `payload` at `offset`, fills `tlv` with the
 *  type, moves `offset` to the first octet AFTER the length (that is, to the
 *  first octet of the item the tag describes), and returns the length.
 *  `payload_size` is the maximum number of octets to read.
 *
 *  If the tag is an ASN.1 NULL value (CERT_NULL), continues reading tags
 *  until a non-NULL tag is found or `payload_size` is reached.
 *
 *  If `payload_size` is reached, sets the referent of `offset` to
 *  `payload_size` and returns UINT16_MAX.
 */
static uint16_t
ypDecodeTLV(
    yf_asn_tlv_t   *tlv,
    const uint8_t  *payload,
    uint32_t        payload_size,
    uint32_t       *offset)
{
    uint8_t  val;
    uint16_t obj_len;

    while (*offset < payload_size) {
        val = *(payload + *offset);

        tlv->class = (val & 0xD0) >> 6;
        tlv->p_c = (val & 0x20) >> 5;
        tlv->tag = (val & 0x1F);
        ++*offset;

        obj_len = ypDecodeLength(payload, payload_size, offset);
        if (UINT16_MAX == obj_len || *offset > payload_size) {
            break;
        }
        if (tlv->tag != CERT_NULL) {
            return obj_len;
        }

        *offset += obj_len;
    }

    /* We have run out of bytes */
    *offset = payload_size;
    return UINT16_MAX;
}

/**
 *    Check whether the OID having length `obj_len` and starting at position
 *    *`offset` in `payload` is one that we want to capture.  If so, position
 *    `offset` on the final octet of the OID and return TRUE.  Otherwise leave
 *    `offset` unchanged and return FALSE.
 */
static gboolean
ypDecodeOID(
    const uint8_t  *payload,
    uint32_t       *offset,
    uint8_t         obj_len)
{
    uint16_t id_at;

    /*
     * To check for a child OID (having a value <= 127) one level below id-at
     * or pkcs-9, check that the obj_len is one more than the BER encoding of
     * the parent and move the offset to the child.
     *
     * To check exactly for ldap-domainComponent, check that the length
     * matches exactly, but return an offset one less for consistency with the
     * others.
     */
    switch (obj_len) {
      case 3:
        /* Check for OID under id-at */
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
        memcpy(&id_at, (payload + *offset), sizeof(uint16_t));
#else
        id_at = *(uint16_t *)(payload + *offset);
#endif
        if (CERT_IDAT == ntohs(id_at)) {
            *offset += 2;
            return TRUE;
        }
        break;
      case 9:
        /* Check for OID under pkcs-9 */
        if (0 == memcmp(payload + *offset, CERT_PKCS, sizeof(CERT_PKCS))) {
            *offset += sizeof(CERT_PKCS);
            return TRUE;
        }
        break;
      case 10:
        /* Check for exactly ldap-domainComponent */
        if (0 == memcmp(payload + *offset, CERT_DC, sizeof(CERT_DC))) {
            *offset += sizeof(CERT_DC) - 1;
            return TRUE;
        }
        break;
    }

    /* this is not the usual id-at, pkcs, or dc - so ignore it */
    return FALSE;
}


/**
 *    Returns the number of sequential CERT_SET objects found in the first
 *    `seq_len` octets of `payload`.  Includes only SETs that are entirely
 *    within `seq_len`.
 */
static uint8_t
ypGetSequenceCount(
    const uint8_t  *payload,
    uint16_t        seq_len)
{
    uint32_t     offset = 0;
    uint16_t     obj_len;
    uint8_t      count = 0;
    yf_asn_tlv_t tlv;

    for (;;) {
        obj_len = ypDecodeTLV(&tlv, payload, seq_len, &offset);
        if (UINT16_MAX == obj_len || offset >= seq_len) {
            return count;
        }
        offset += obj_len;
        if (tlv.tag != CERT_SET || offset > seq_len) {
            return count;
        }
        ++count;
    }
}


/**
 *    Loops over the first `ext_len` octets of `payload` which is expected to
 *    contain sequences (CERT_SEQ).  For each sequence, checks whether the
 *    first item is an OID where the OID is 3 octets long, its first two
 *    octets are certificateExtension (CERT_IDCE), and its final octet is a
 *    particular value of interest.
 *
 *    Returns the number of items found.  Includes only items that are
 *    entirely contained within ext_len.
 */
static uint8_t
ypGetExtensionCount(
    const uint8_t  *payload,
    uint16_t        ext_len)
{
    /* When checking whether the ObjectID is under certificateExtension, we
     * read 4 octets into a uint32_t.  The first should be CERT_OID, the
     * second (length) must be 3, and the lower two must those for a
     * certificate extension, CERT_IDCE. */
    const uint32_t  wanted = ((CERT_OID << 24) | 0x030000 | CERT_IDCE);
    uint32_t        oid_len_id_ce;
    uint32_t        offset = 0;
    uint32_t        next_item;
    yf_asn_tlv_t    tlv;
    uint16_t        obj_len = 0;
    uint8_t         count = 0;

    for (;;) {
        obj_len = ypDecodeTLV(&tlv, payload, ext_len, &offset);
        next_item = offset + obj_len;
        if (tlv.tag != CERT_SEQ || next_item > ext_len || obj_len < 5) {
            return count;
        }

#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
        memcpy(&oid_len_id_ce, payload + offset, sizeof(oid_len_id_ce));
#else
        oid_len_id_ce = *(uint32_t *)(payload + offset);
#endif
        if (ntohl(oid_len_id_ce) == wanted) {
            /* the +4 because `offset` is still at the CERT_OID */
            switch (*(payload + offset + 4)) {
              case 14:
                /* subject key identifier */
              case 15:
                /* key usage */
              case 16:
                /* private key usage period */
              case 17:
                /* alternative name */
              case 18:
                /* alternative name */
              case 29:
                /* authority key identifier */
              case 31:
                /* CRL dist points */
              case 32:
                /* Cert Policy ID */
              case 35:
                /* Authority Key ID */
              case 37:
                count++;
                break;
            }
        }

        offset = next_item;
    }
}


/**
 *    Processes the Issuer or Subject data at `seq_payload`, having length
 *    `seq_len`, initializes the subTemplateList `subCertSTL`, and adds
 *    `yaf_ssl_subcert_tmpl` records containing sslObjectType and
 *    sslObjectValue pairs to the `subCertSTL`.
 *
 *    Returns FALSE on error.
 */
static gboolean
ypDecodeIssuerSubject(
    fbSubTemplateList_t  *subCertSTL,
    const uint8_t        *seq_payload,
    unsigned int          seq_len)
{
    yfSSLObjValue_t   *sslObject = NULL;
    yf_asn_tlv_t       tlv = {0, 0, 0};
    uint32_t           offset = 0;
    uint8_t            seq_count;
    uint16_t           obj_len = 0;
    uint32_t           set_end;

    /* Each item is CERT_SET containing a CERT_SEQ which contains a CERT_OID
     * to label the data and the data itself (typically one of the string
     * types) */

    seq_count = ypGetSequenceCount(seq_payload, seq_len);
    sslObject = (yfSSLObjValue_t *)fbSubTemplateListInit(
        subCertSTL, 3, YAF_SSL_SUBCERT_FLOW_TID, sslSubTemplate, seq_count);

    for ( ; seq_count && sslObject; --seq_count, ++sslObject) {
        obj_len = ypDecodeTLV(&tlv, seq_payload, seq_len, &offset);
        /* note offset for the end of this set */
        set_end = offset + obj_len;
        if (set_end > seq_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SET) {
            break;
        }

        obj_len = ypDecodeTLV(&tlv, seq_payload, seq_len, &offset);
        if (offset + obj_len > seq_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SEQ) {
            break;
        }

        obj_len = ypDecodeTLV(&tlv, seq_payload, seq_len, &offset);
        if (offset + obj_len > seq_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_OID) {
            break;
        }

        if (!ypDecodeOID(seq_payload, &offset, obj_len)) {
            offset = set_end;
            continue;
        }

        /*
         *  ypDecodeOID() leaves `offset` on final octet of the OID which we
         *  use as the type.  The +2 moves us to the length of the data (we
         *  skip the ASN.1 type octet since we don't care about it).
         */

        sslObject->obj_id = *(seq_payload + offset);
        offset += 2;
        obj_len = ypDecodeLength(seq_payload, seq_len, &offset);
        if (offset + obj_len > seq_len) {
            sslObject->obj_id = 0;
            return FALSE;
        }

        /* OBJ VALUE */
        sslObject->obj_value.buf = (uint8_t *)seq_payload + offset;
        sslObject->obj_value.len = obj_len;
        offset += obj_len;
    }

#if 0
    /* The while() should take us the the end of the sequence, but we could
     * "break" out early for an unexpected case. */
    if (offset != seq_len) {
        g_debug("Issuer/Subject: offset is %u but expected to be at %u."
                "  Most recent tag was %#04x having length %u",
                offset, seq_len, tlv.tag, obj_len);
    }
#endif  /* 0 */

    return TRUE;
}


/**
 *  Called to parse one certificate whose starting-offset was captured while
 *  scanning the payload (YF_SSL_CERT_START).
 *
 *  @param ctx          DPI Context (unused)
 *  @param sslCert      the record within an STL to fill
 *  @param payload      all of the captured payload (either forward/reverse)
 *  @param payloadSize  the size of the payload
 *  @param flow         the current (top-level) flow record (unused)
 *  @param offset       the offset of the certificate's start within `paylaod`
 */
static gboolean
ypDecodeSSLCertificate(
    yfDPIContext_t   *ctx,
    yfSSLCertFlow_t **sslCert,
    const uint8_t    *payload,
    unsigned int      payloadSize,
    yfFlow_t         *flow,
    uint32_t          offset)
{
    yfSSLObjValue_t *sslObject = NULL;
    yf_asn_tlv_t     tlv;
    uint32_t         sub_cert_len;
    uint32_t         ext_end_offset;
    uint8_t          seq_count;
    uint16_t         obj_len;
    uint16_t         tmp16;

    (*sslCert)->sslCertificateHash.len = 0;

    /*
     *  Notes:
     *
     *  The certificate is represented as sequence containing two objects:
     *  Another sequence for the certificate's details and a sequence for the
     *  signature.
     *
     *  The ASN.1 sequences (0x10) in the certificate have the contructed bit
     *  set (bit-6, 0x20), resulting in 0x30 when examining the raw octets.
     *  Similarly, a raw octet for an ASN.1 set (0x11) appears as 0x31.
     *
     *  In much of the following, it would be more correct to use the length
     *  of the inner-most containing sequence as the upper limit instead of
     *  `sub_cert_len`.
     */

    /*
     * ensure there are 3 bytes for the length, 4 for outer CERT_SEQ ID and
     * the bytes holding its length, and 4 bytes for the inner CERT_SEQ and
     * its length
     */
    if ((size_t)offset + 3 + 4 + 4 > payloadSize) {
        return FALSE;
    }

    /* we read the length; `sub_cert_len` does not include the bytes that hold
     * the length */
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
    memcpy(&sub_cert_len, payload + offset, sizeof(sub_cert_len));
    sub_cert_len = (ntohl(sub_cert_len) & 0xFFFFFF00) >> 8;
#else
    sub_cert_len = (ntohl(*(uint32_t *)(payload + offset)) & 0xFFFFFF00) >> 8;
#endif
    offset += 3;

    /* only continue if we have enough payload for the whole cert and the
     * certificate's size is not ridiculously small */
    if (offset + sub_cert_len > payloadSize || sub_cert_len < 8) {
        return FALSE;
    }

    /* use local values for the payload and offset so we can ensure `cert_off`
     * never exceeds `sub_cert_len` */
    const uint8_t *cert_pay = payload + offset;
    uint32_t cert_off = 0;

    /* We expect a sequence (0x30) where the length is specified in two bytes
     * (CERT_2BYTE) [0x30 0x82] */
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
    memcpy(&tmp16, cert_pay + cert_off, &tmp16);
#else
    tmp16 = *(uint16_t *)(cert_pay + cert_off);
#endif
    if (ntohs(tmp16) != 0x3082) {
        return FALSE;
    }

    /* The following moves forward over the 2 bytes we just read, the 2
     * bytes holding the sequence's length, over the tag for the inner
     * sequence (0x3082 again (+2)), and over its length (+2). */
    cert_off += 8;
    if (cert_off >= sub_cert_len) {
        return FALSE;
    }

    /* the version is next unless this is version 1 certificate (1988).  The
     * version is denoted by CERT_EXPLICIT (0xA0), where the following octet
     * is its length (expected to be 0x03), followed by an object type
     * (CERT_INT == 0x02), the length of the integer (expected to be 0x01),
     * and finally the version number. */
    if (*(cert_pay + cert_off) == CERT_EXPLICIT) {
        cert_off += 4;
        if (cert_off >= sub_cert_len) {
            return FALSE;
        }
        (*sslCert)->sslCertVersion = *(cert_pay + cert_off);
        cert_off++;
    } else {
        /* default version is version 1 [0] */
        (*sslCert)->sslCertVersion = 0;
    }

    /* serial number */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len > sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag == CERT_INT) {
        (*sslCert)->sslCertSerialNumber.buf = (uint8_t *)cert_pay + cert_off;
        (*sslCert)->sslCertSerialNumber.len = obj_len;
    }
    cert_off += obj_len;

    /* signature algorithm */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len > sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        cert_off += obj_len;
    } else {
        obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
        if (cert_off + obj_len > sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag == CERT_OID) {
            (*sslCert)->sslCertSignature.buf = (uint8_t *)cert_pay + cert_off;
            (*sslCert)->sslCertSignature.len = obj_len;
        }
        cert_off += obj_len;
    }


    /* ISSUER - sequence */

    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len > sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        return FALSE;
    }
    if (!ypDecodeIssuerSubject(
            &(*sslCert)->issuer, cert_pay + cert_off, obj_len))
    {
        return FALSE;
    }
    cert_off += obj_len;

    /* VALIDITY is a sequence of times */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        return FALSE;
    }

    /* notBefore time */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_TIME) {
        return FALSE;
    }
    (*sslCert)->sslCertValidityNotBefore.buf = (uint8_t *)cert_pay + cert_off;
    (*sslCert)->sslCertValidityNotBefore.len = obj_len;

    cert_off += obj_len;

    /* not After time */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_TIME) {
        return FALSE;
    }
    (*sslCert)->sslCertValidityNotAfter.buf = (uint8_t *)cert_pay + cert_off;
    (*sslCert)->sslCertValidityNotAfter.len = obj_len;

    cert_off += obj_len;

    /* SUBJECT - sequence */

    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        return FALSE;
    }
    if (!ypDecodeIssuerSubject(
            &(*sslCert)->subject, cert_pay + cert_off, obj_len))
    {
        return FALSE;
    }
    cert_off += obj_len;

    /* subject public key info */
    /* this is a sequence of a sequence of algorithms and public key */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        cert_off += obj_len;
    } else {
        /* this is also a seq */
        obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
        if (cert_off + obj_len >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SEQ) {
            cert_off += obj_len;
        } else {
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (cert_off + obj_len >= sub_cert_len) {
                return FALSE;
            }
            /* this is the algorithm id */
            if (tlv.tag == CERT_OID) {
                (*sslCert)->sslPublicKeyAlgorithm.buf =
                    (uint8_t *)cert_pay + cert_off;
                (*sslCert)->sslPublicKeyAlgorithm.len = obj_len;
            }
            cert_off += obj_len;
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (cert_off + obj_len >= sub_cert_len) {
                return FALSE;
            }
            /* this is the actual public key */
            if (tlv.tag == CERT_BITSTR) {
                (*sslCert)->sslPublicKeyLength = obj_len;
            }
            cert_off += obj_len;
        }
    }

    /* EXTENSIONS! - ONLY AVAILABLE FOR VERSION 3 */
    /* since it's optional - it has a tag if it's here */
    obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
    if (cert_off + obj_len >= sub_cert_len) {
        return FALSE;
    }

    if ((tlv.class != 2) || ((*sslCert)->sslCertVersion != 2)) {
        /* no extensions */
        ext_end_offset = cert_off;
        fbSubTemplateListInit(&((*sslCert)->extension), 3,
                              YAF_SSL_SUBCERT_FLOW_TID, sslSubTemplate, 0);
    } else {
        obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
        /* note offset after all extensions */
        ext_end_offset = cert_off + obj_len;
        if (ext_end_offset >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SEQ) {
            return FALSE;
        }

        /* extensions */
        seq_count = ypGetExtensionCount((cert_pay + cert_off), obj_len);
        sslObject = (yfSSLObjValue_t *)fbSubTemplateListInit(
            &((*sslCert)->extension), 3,
            YAF_SSL_SUBCERT_FLOW_TID, sslSubTemplate, seq_count);

        /* exts is a sequence of a sequence of {id, critical flag, value} */
        while (seq_count && sslObject) {
            /* the offset at the end of the current extension */
            uint32_t cur_ext_end;
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            cur_ext_end = cert_off + obj_len;
            if (cur_ext_end >= sub_cert_len) {
                return FALSE;
            }
            if (tlv.tag != CERT_SEQ) {
                return FALSE;
            }

            /* get the object ID and see if it is one we want */
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (cert_off + obj_len >= cur_ext_end) {
                return FALSE;
            }
            if (tlv.tag != CERT_OID) {
                return FALSE;
            }
            if (obj_len != 3) {
                /* ignore this object */
                cert_off = cur_ext_end;
                continue;
            }
            if (cert_off + sizeof(tmp16) > sub_cert_len) {
                return FALSE;
            }
#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
            memcpy(&tmp16, cert_pay + cert_off, sizeof(tmp16));
#else
            tmp16 = *(uint16_t *)(cert_pay + cert_off);
#endif
            cert_off += 2;
            if (ntohs(tmp16) != CERT_IDCE) {
                /* ignore this object */
                cert_off = cur_ext_end;
                continue;
            }

            /* keep this switch() in sync with ypGetExtensionCount() */
            switch (*(cert_pay + cert_off)) {
              case 14:
                /* subject key identifier */
              case 15:
                /* key usage */
              case 16:
                /* private key usage period */
              case 17:
                /* alternative name */
              case 18:
                /* alternative name */
              case 29:
                /* authority key identifier */
              case 31:
                /* CRL dist points */
              case 32:
                /* Cert Policy ID */
              case 35:
                /* Authority Key ID */
              case 37:
                /* ext. key usage */
                break;
              default:
                /* ignore it; go to the next one */
                cert_off = cur_ext_end;
                continue;
            }

            /* wanted; decode the rest of this extension */
            sslObject->obj_id = *(cert_pay + cert_off);
            ++cert_off;

            /* read the next tag, which may give the type and length of the
             * data or indicate an optional CRITICAL flag if it is a
             * boolean */
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (cert_off + obj_len > cur_ext_end) {
                sslObject->obj_id = 0;
                return FALSE;
            }
            if (tlv.tag == CERT_BOOL) {
                cert_off += obj_len;
                /* this should be the object's data type and length */
                obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
                if (cert_off + obj_len > cur_ext_end) {
                    sslObject->obj_id = 0;
                    return FALSE;
                }
            }

            sslObject->obj_value.len = obj_len;
            sslObject->obj_value.buf = (uint8_t *)cert_pay + cert_off;
            cert_off += obj_len;
            seq_count--;
            sslObject++;
        }
    }

    if (ctx->cert_hash_export) {
        /* The signaure is represented by a sequence containing an OID which
         * is signing algorithm (a repeat of what we saw above) and the
         * signature bitstring */

        cert_off = ext_end_offset;
        if (cert_off >= sub_cert_len) {
            return TRUE;
        }

        obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
        if (cert_off + obj_len > sub_cert_len) {
            return TRUE;
        }

        if (tlv.tag == CERT_SEQ) {
            /* skip the OID */
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (tlv.tag != CERT_OID) {
                return TRUE;
            }
            cert_off += obj_len;
            if (cert_off >= sub_cert_len) {
                return TRUE;
            }

            /* read the bitstring */
            obj_len = ypDecodeTLV(&tlv, cert_pay, sub_cert_len, &cert_off);
            if (tlv.tag != CERT_BITSTR) {
                return TRUE;
            }
            if (cert_off + obj_len > sub_cert_len) {
                return TRUE;
            }

            /* there is one octet of padding; ignore it */
            cert_off++;
            obj_len -= 1;

            /* must be a multiple of 16 */
            if (obj_len & 0xF) {
                return TRUE;
            }
            (*sslCert)->sslCertificateHash.len = obj_len;
            (*sslCert)->sslCertificateHash.buf = (uint8_t *)cert_pay + cert_off;
        }
    }

    return TRUE;
}

/**
 * sslServerJA3
 *
 * Processes the plugin's arguments to create a string that will be used to
 * generate an MD5 Hash of a server response
 */
static void
ypSslServerJA3S(
    uint16_t       scipher,
    uint16_t       sversion,
    char          *ser_extension,
    uint8_t       *smd5,
    fbVarfield_t  *string)
{
    GString *str = g_string_sized_new(500);

    if (sversion != 0) {
        g_string_append_printf(str, "%hu,", sversion);
        g_string_append_printf(str, "%hu,", scipher);
    } else {
        g_string_append(str, ",,");
    }

    if (ser_extension != NULL) {
        g_string_append_printf(str, "%s", ser_extension);
    }

    g_free(ser_extension);
    ypComputeMD5(str->str, str->len, smd5);
    string->len = str->len;
    string->buf = (uint8_t *)g_string_free(str, FALSE);
}

/**
 * sslClientJA3
 *
 * Processes the plugin's arguments to create a string that will be used to
 * generate an MD5 Hash of a client response.
 */
static void
ypSslClientJA3(
    fbBasicList_t  *ciphers,
    char           *extension,
    uint16_t       *elliptic_curve,
    char           *elliptic_format,
    uint16_t        version,
    int             ellip_curve_len,
    uint8_t        *md5,
    fbVarfield_t   *string)
{
    GString  *str = g_string_sized_new(500);
    int       i;
    uint16_t *cipher;

    /*The version is added to the string*/
    if (version != 0) {
        g_string_append_printf(str, "%hu,", version);
    } else {
        g_string_append(str, ",,");
    }
    /*The ciphers are beinf added to the string*/
    for (i = 0; (cipher = (uint16_t *)fbBasicListGetIndexedDataPtr(ciphers, i));
         i++)
    {
        if (!ypSslGreaseTableCheck(*cipher)) {
            g_string_append_printf(str, "%hu-", *cipher);
        }
    }
    if (str->str[str->len - 1] == '-') {
        g_string_truncate(str, str->len - 1);
        g_string_append(str, ",");
    }

    /*Extensions are added at this point*/
    if (extension != NULL) {
        g_string_append_printf(str, "%s,", extension);
        /*The eliptical curve is added to string*/
        if (elliptic_curve != NULL) {
            for (i = 0; i < ellip_curve_len; i++) {
                if (!ypSslGreaseTableCheck(elliptic_curve[i])) {
                    g_string_append_printf(str, "%hu-", elliptic_curve[i]);
                }
            }
            if (str->str[str->len - 1] == '-') {
                g_string_truncate(str, str->len - 1);
                g_string_append(str, ",");
            }
        } else {
            g_string_append(str, ",");
        }
        /*The elliptical format is added to the string*/
        if (elliptic_format != NULL) {
            g_string_append_printf(str, "%s", elliptic_format);
        }
    } else {
        g_string_append(str, ",,");
    }

    g_free(elliptic_curve);
    g_free(elliptic_format);
    g_free(extension);
    ypComputeMD5(str->str, str->len, md5);
    string->len = str->len;
    string->buf = (uint8_t *)g_string_free(str, FALSE);
}

/**
 * computeMD5
 *
 * Processes the plugin's arguments to generate an MD5 Hash
 *
 */
#if HAVE_OPENSSL
static void
ypComputeMD5(
    const char  *string,
    int          len,
    uint8_t     *mdbuff)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000
    MD5((const unsigned char *)string, len, mdbuff);
#else
    EVP_MD_CTX   *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned char md_size[EVP_MAX_MD_SIZE];
    unsigned int  md_len;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, string, len);
    EVP_DigestFinal_ex(mdctx, md_size, &md_len);
    EVP_MD_CTX_free(mdctx);

    memcpy(mdbuff, md_size, 16);
#endif /* if OPENSSL_VERSION_NUMBER < 0x30000000 */
}
#endif /* ifdef HAVE_OPENSSL */

/**
 * sslClientJA3
 *
 * Processes the plugin's argument to verify if an extension is equal to a
 * grease table value
 */
static gboolean
ypSslGreaseTableCheck(
    uint16_t   value)
{
    uint16_t greaseTable[] = {
        2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
        35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250
    };

    for (size_t i = 0; i < sizeof(greaseTable) / sizeof(greaseTable[0]); i++) {
        if (greaseTable[i] == value) {
            return TRUE;
        }
    }
    return FALSE;
}

/**
 *  Takes the position in the payload where the extension list begins
 *  (specifically on the length of the extension list) and returns a newly
 *  allocated string containing the extension types joined by a hyphen.
 *
 *  The caller must g_free() the string when no longer required.
 */
static char *
ypSslStoreExtension(
    const uint8_t  *payload)
{
    uint16_t total_count = ntohs(*(uint16_t *)payload);
    uint16_t ext_type = 0;
    uint16_t ext_len = 0;
    uint32_t offset = 0;
    uint32_t total_ext = 0;

    GString *str = g_string_sized_new(500);

    offset += 2;

    while (total_ext + 4 < total_count) {
        ext_type = ntohs(*(uint16_t *)(payload + offset));
        offset += 2;
        ext_len = ntohs(*(uint16_t *)(payload + offset));
        offset += 2;
        total_ext += sizeof(uint16_t) + sizeof(uint16_t) + ext_len;
        if (!ypSslGreaseTableCheck(ext_type)) {
            g_string_append_printf(str, "%hu-", ext_type);
        }
        offset += ext_len;
    }
    if (str->len > 0 && str->str[str->len - 1] == '-') {
        g_string_truncate(str, str->len - 1);
    }
    return g_string_free(str, FALSE);
}

/**
 * Concatenate algorith strings to create HASSH string.
 * MD5 HASSH string to create HASSH hash.
 */
static void
ypSshHASSH(
    GString       *kex,
    const gchar   *encryp,
    const gchar   *mac,
    const gchar   *compression,
    uint8_t       *md5,
    fbVarfield_t  *string)
{
    g_string_append_printf(kex, ";%s;%s;%s", encryp, mac, compression);

    ypComputeMD5(kex->str, kex->len, md5);
    string->buf = (unsigned char *)kex->str;
    string->len =  kex->len;
    g_string_free(kex, FALSE);
}

/**
 * algo_Compare
 *
 * Compare the client `str1` and server `str2` algorithm strings
 * Split the given strings into tokens and compare first token
 * of the client & server string
 *
 */
static void
ypSshAlgoCompare(
    const GString *str1,
    const GString *str2,
    fbVarfield_t  *str3)
{
    if (strchr(str1->str, ',') != NULL) {
        gchar  **tokens1 = g_strsplit(str1->str, ",", -1);
        gchar  **tokens2 = g_strsplit(str2->str, ",", -1);
        gboolean algo_match = FALSE;
        for (unsigned int i = 0; i < g_strv_length(tokens1); i++) {
            for (unsigned int j = 0; j < g_strv_length(tokens2); j++) {
                if (strcmp(tokens2[j], tokens1[i]) == 0) {
                    str3->len = strlen(tokens1[i]);
                    str3->buf = (unsigned char *)g_strdup(tokens1[i]);
                    algo_match = TRUE;
                    break;
                }
            }
            if (algo_match == TRUE) {
                break;
            }
        }
        g_strfreev(tokens1);
        g_strfreev(tokens2);
    } else {
        str3->len = str1->len;
        str3->buf = (uint8_t *)g_strdup(str1->str);
    }
}
#endif /* #if YAF_ENABLE_HOOKS */
#endif /* #if YAF_ENABLE_APPLABEL */
