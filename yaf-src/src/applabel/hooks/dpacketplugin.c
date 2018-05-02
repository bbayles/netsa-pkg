/**
 * @internal
 *
 * @file dpacketplugin.c
 *
 * Provides a plugin to inspect payloads and export the data
 * in ipfix template format.  See yafdpi(1)
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2018 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso
 ** ------------------------------------------------------------------------
 *
 ** @OPENSOURCE_HEADER_START@
 ** Use of the YAF system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU Public License (GPL) Rights pursuant to Version 2, June 1991
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
 *
 *
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

/* User Limit on New Labels */
#define USER_LIMIT              30
/* Minimum Number of BasicLists sent for each protocol */
#define YAF_HTTP_STANDARD       20
#define YAF_FTP_STANDARD        5
#define YAF_IMAP_STANDARD       7
#define YAF_RTSP_STANDARD       12
#define YAF_SIP_STANDARD        7
#define YAF_SSH_STANDARD        1
#define YAF_SMTP_STANDARD       11

/* incremement below to add a new protocol - 0 needs to be first */
/*#define DPI_TOTAL_PROTOCOLS 22*/

#define DPI_REGEX_PROTOCOLS 10

static const uint16_t regexDPIProtos[] = {21, 80, 143, 554, 5060, 22,
                                          25, 20000, 502, 44818};
static const uint16_t DPIProtocols[] = {0, 21, 22, 25, 53, 69, 80, 110, 119,
                                        143, 194, 427, 443, 554, 873,
                                        1723, 5060, 3306, 20000, 502, 44818,
                                        5004};

static DPIActiveHash_t *global_active_protos;
/* export DNSSEC info - NO by default */
static gboolean dnssec_global = FALSE;
static gboolean fullcert_global = FALSE;
static gboolean certhash_global = FALSE;


/**
 *
 * file globals
 *
 */
/*static ypBLValue_t *appRuleArray[UINT16_MAX + 1];
static protocolRegexRules_t ruleSet[DPI_TOTAL_PROTOCOLS + 1];

static char *dpiRulesFileName = NULL;
static unsigned int dpiInitialized = 0;

static DPIActiveHash_t dpiActiveHash[MAX_PAYLOAD_RULES];

static uint16_t dpi_user_limit = MAX_CAPTURE_LENGTH;
static uint16_t dpi_user_total_limit = 1000;
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



/* only will be initialized if we have user-defined elements */
static fbInfoElementSpec_t *yaf_http_extra;
static fbInfoElementSpec_t *yaf_ftp_extra;
static fbInfoElementSpec_t *yaf_imap_extra;
static fbInfoElementSpec_t *yaf_rtsp_extra;
static fbInfoElementSpec_t *yaf_sip_extra;
static fbInfoElementSpec_t *yaf_ssh_extra;
static fbInfoElementSpec_t *yaf_smtp_extra;

static fbTemplate_t *ircTemplate;
static fbTemplate_t *pop3Template;
static fbTemplate_t *tftpTemplate;
static fbTemplate_t *slpTemplate;
static fbTemplate_t *httpTemplate;
static fbTemplate_t *ftpTemplate;
static fbTemplate_t *imapTemplate;
static fbTemplate_t *rtspTemplate;
static fbTemplate_t *sipTemplate;
static fbTemplate_t *smtpTemplate;
static fbTemplate_t *sshTemplate;
static fbTemplate_t *nntpTemplate;
static fbTemplate_t *dnsTemplate;
static fbTemplate_t *dnsQRTemplate;
static fbTemplate_t *dnsATemplate;
static fbTemplate_t *dnsAAAATemplate;
static fbTemplate_t *dnsCNTemplate;
static fbTemplate_t *dnsMXTemplate;
static fbTemplate_t *dnsNSTemplate;
static fbTemplate_t *dnsPTRTemplate;
static fbTemplate_t *dnsTXTTemplate;
static fbTemplate_t *dnsSRVTemplate;
static fbTemplate_t *dnsSOATemplate;
static fbTemplate_t *sslTemplate;
static fbTemplate_t *sslCertTemplate;
static fbTemplate_t *sslSubTemplate;
static fbTemplate_t *sslFullCertTemplate;
static fbTemplate_t *mysqlTemplate;
static fbTemplate_t *mysqlTxtTemplate;
static fbTemplate_t *dnsDSTemplate;
static fbTemplate_t *dnsNSEC3Template;
static fbTemplate_t *dnsNSECTemplate;
static fbTemplate_t *dnsRRSigTemplate;
static fbTemplate_t *dnsKeyTemplate;
static fbTemplate_t *dnp3Template;
static fbTemplate_t *dnp3RecTemplate;
static fbTemplate_t *modbusTemplate;
static fbTemplate_t *enipTemplate;
static fbTemplate_t *rtpTemplate;

/**
 *
 *
 */
#ifdef NDEBUG
#define assert(x)
#else
#define assert(x) if (!(x)) { fprintf(stderr,"assertion failed: \"%s\" at line %d of file %s\n",# x, __LINE__, __FILE__); abort(); }
#endif



void yfAlignmentCheck1()
{
    size_t prevOffset = 0;
    size_t prevSize = 0;

#define DO_SIZE(S_,F_) (SIZE_T_CAST)sizeof(((S_ *)(0))->F_)
#define EA_STRING(S_,F_) "alignment error in struct " #S_ " for element "   \
                         #F_ " offset %#"SIZE_T_FORMATX" size %"            \
        SIZE_T_FORMAT" (pad %"SIZE_T_FORMAT")",            \
        (SIZE_T_CAST)offsetof(S_,F_), DO_SIZE(S_,F_),      \
        (SIZE_T_CAST)(offsetof(S_,F_) % DO_SIZE(S_,F_))
#define EG_STRING(S_,F_) "gap error in struct " #S_ " for element " #F_     \
        " offset %#"SIZE_T_FORMATX" size %"SIZE_T_FORMAT,  \
        (SIZE_T_CAST)offsetof(S_,F_),                      \
        DO_SIZE(S_,F_)
#define RUN_CHECKS(S_,F_,A_) {                                  \
        if (((offsetof(S_,F_) % DO_SIZE(S_,F_)) != 0) && A_) {          \
            g_error(EA_STRING(S_,F_));                                  \
        }                                                               \
        if (offsetof(S_,F_) != (prevOffset+prevSize)) {                 \
            g_error(EG_STRING(S_,F_));                                  \
            return;                                                     \
        }                                                               \
        prevOffset = offsetof(S_,F_);                                   \
        prevSize = DO_SIZE(S_,F_);                                      \
        /*fprintf(stderr, "%17s %40s %#5lx %3d %#5lx\n", #S_, #F_,      \
                offsetof(S_,F_), DO_SIZE(S_,F_),                        \
                offsetof(S_,F_)+DO_SIZE(S_,F_));*/                      \
     }

    RUN_CHECKS(yfSSLFlow_t, sslCipherList, 1);
    RUN_CHECKS(yfSSLFlow_t, sslServerCipher, 1);
    RUN_CHECKS(yfSSLFlow_t, sslClientVersion, 1);
    RUN_CHECKS(yfSSLFlow_t, sslCompressionMethod, 1);
    RUN_CHECKS(yfSSLFlow_t, sslVersion, 1);
    RUN_CHECKS(yfSSLFlow_t, sslCertList, 0);
    RUN_CHECKS(yfSSLFlow_t, sslServerName, 1);

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
    RUN_CHECKS(yfSSLCertFlow_t, sig, 1);
    RUN_CHECKS(yfSSLCertFlow_t, serial, 1);
    RUN_CHECKS(yfSSLCertFlow_t, not_before, 1);
    RUN_CHECKS(yfSSLCertFlow_t, not_after, 1);
    RUN_CHECKS(yfSSLCertFlow_t, pkalg, 1);
    RUN_CHECKS(yfSSLCertFlow_t, pklen, 1);
    RUN_CHECKS(yfSSLCertFlow_t, version, 1);
    RUN_CHECKS(yfSSLCertFlow_t, padding, 0);
    RUN_CHECKS(yfSSLCertFlow_t, hash, 0);

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
gboolean ypHookInitialize (
    yfDPIContext_t   *ctx,
    char             *dpiFQFileName,
    GError           **err)
{
    FILE *dpiRuleFile = NULL;
    int i;

    if (NULL == dpiFQFileName) {
        dpiFQFileName = YAF_CONF_DIR"/yafDPIRules.conf";
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
 * Allocate the hooks struct here, but don't allocate the DPI struct
 * until we want to fill it so we don't have to hold empty memory for long.
 *
 *
 */
void ypFlowAlloc(
    void          **yfHookContext,
    yfFlow_t      *flow,
    void          *yfctx)
{

    ypDPIFlowCtx_t *newFlowContext = NULL;

    newFlowContext = (ypDPIFlowCtx_t *)yg_slice_alloc0(sizeof(ypDPIFlowCtx_t));

    newFlowContext->dpinum = 0;
    newFlowContext->startOffset = 0;
    newFlowContext->exbuf = NULL;
    newFlowContext->dpi = NULL;
    newFlowContext->yfctx = yfctx;

    *yfHookContext = (void *) newFlowContext;

    return;
}

/**
 * getDPIInfoModel
 *
 *
 *
 * @return a pointer to a fixbuf info model
 *
 */
fbInfoModel_t *ypGetDPIInfoModel()
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
 *
 * @param flow a pointer to the flow structure that maintains all the flow
 *             context
 *
 */

gboolean ypFlowClose(
    void              *yfHookContext,
    yfFlow_t          *flow)
{

    ypDPIFlowCtx_t      *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t      *ctx;
    uint8_t             newDPI;
    int                 pos;

    if (NULL == flowContext) {
        /* log an error here, but how */
        return FALSE;
    }

    ctx = flowContext->yfctx;

    if (ctx->dpiInitialized == 0) {
        return TRUE;
    }

    if (flowContext->dpi == NULL) {
        flowContext->dpi = yg_slice_alloc0(YAF_MAX_CAPTURE_FIELDS *
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
        newDPI = ypDPIScanner(flowContext, flow->val.payload,                              flow->val.paylen, 0, flow, &(flow->val));
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
 * returns FALSE if applabel mode is disabled, true otherwise
 *
 */
gboolean ypValidateFlowTab(
    void            *yfctx,
    uint32_t        max_payload,
    gboolean        uniflow,
    gboolean        silkmode,
    gboolean        applabelmode,
    gboolean        entropymode,
    gboolean        fingerprintmode,
    gboolean        fpExportMode,
    gboolean        udp_max_payload,
    gboolean        udp_uniflow_mode,
    GError          **err)
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

uint16_t ypSearchPlugOpts (
    DPIActiveHash_t   *active,
    uint16_t          appLabel)
{
    uint16_t          rc;

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
void ypAddRuleKey(
    yfDPIContext_t          *ctx,
    uint16_t                applabel,
    uint16_t                id,
    const fbInfoElement_t   *ie,
    size_t                  bl)
{

    ypBLValue_t             *val = NULL;

    val = yg_slice_new0(ypBLValue_t);

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
ypBLValue_t *ypGetRule(
    yfDPIContext_t         *ctx,
    uint16_t               id)
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
int ypAddSpec(
    fbInfoElementSpec_t      *spec,
    uint16_t                 applabel,
    size_t                   *offset)
{

    static int               http_extra = 0;
    static int               imap_extra = 0;
    static int               ftp_extra = 0;
    static int               rtsp_extra = 0;
    static int               sip_extra = 0;
    static int               ssh_extra = 0;
    static int               smtp_extra = 0;
    size_t                   new_spec = (sizeof(fbInfoElementSpec_t)
                                         * USER_LIMIT);

    if (applabel == 80) {
        if (spec) {
            if (http_extra < (YAF_HTTP_STANDARD + USER_LIMIT)) {
                if (http_extra >= YAF_HTTP_STANDARD) {
                    if (!yaf_http_extra) {
                        yaf_http_extra =
                            (fbInfoElementSpec_t *)g_malloc0(new_spec);
                    }
                    memcpy(yaf_http_extra + (http_extra - YAF_HTTP_STANDARD),
                           spec, sizeof(fbInfoElementSpec_t));
                }
            }
        }
        *offset = (sizeof(fbBasicList_t) * http_extra);
        if (http_extra < (YAF_HTTP_STANDARD + USER_LIMIT)) {
            http_extra++;
        } else {
            g_warning("User Limit Exceeded.  Max Rules permitted for proto "
                      "%d is: %d", applabel, YAF_HTTP_STANDARD + USER_LIMIT);
            return -1;
        }

        return http_extra;

    } else if (applabel == 143) {
        if (spec) {
            if (imap_extra < (YAF_IMAP_STANDARD + USER_LIMIT)) {
                if (imap_extra >= YAF_IMAP_STANDARD) {
                    if (!yaf_imap_extra) {
                        yaf_imap_extra =
                            (fbInfoElementSpec_t *)g_malloc0(new_spec);
                    }
                    memcpy(yaf_imap_extra + (imap_extra - YAF_IMAP_STANDARD),
                           spec, sizeof(fbInfoElementSpec_t));
                }
            }
        }

        *offset = (sizeof(fbBasicList_t) * imap_extra);

        if (imap_extra < (YAF_IMAP_STANDARD + USER_LIMIT)) {
            imap_extra++;
        } else {
            g_warning("User Limit Exceeded.  Max Rules permitted for proto "
                      "%d is: %d", applabel, YAF_IMAP_STANDARD + USER_LIMIT);
            return -1;
        }

        return imap_extra;

    } else if (applabel == 21) {
        if (spec) {
            if (ftp_extra < (YAF_FTP_STANDARD + USER_LIMIT)) {
                if (ftp_extra >= YAF_FTP_STANDARD) {
                    if (!yaf_ftp_extra) {
                        yaf_ftp_extra =
                            (fbInfoElementSpec_t *)g_malloc0(new_spec);
                    }
                    memcpy(yaf_ftp_extra + (ftp_extra - YAF_FTP_STANDARD),
                           spec, sizeof(fbInfoElementSpec_t));
                }
            }
        }
        *offset = (sizeof(fbBasicList_t) * ftp_extra);
        if (ftp_extra < (YAF_FTP_STANDARD + USER_LIMIT)) {
            ftp_extra++;
        } else {
            g_warning("User Limit Exceeded.  Max Rules permitted for proto "
                      "%d is: %d", applabel, YAF_FTP_STANDARD + USER_LIMIT);
            return -1;
        }

        return ftp_extra;

    } else if (applabel == 22) {

        if (spec) {
            if (ssh_extra < (YAF_SSH_STANDARD + USER_LIMIT)) {
                if (ssh_extra >= YAF_SSH_STANDARD) {
                    if (!yaf_ssh_extra) {
                        yaf_ssh_extra =
                            (fbInfoElementSpec_t *)g_malloc0(new_spec);
                    }
                    memcpy(yaf_ssh_extra + (ssh_extra - YAF_SSH_STANDARD),
                           spec, sizeof(fbInfoElementSpec_t));
                }
            }
        }

        *offset = (sizeof(fbBasicList_t) * ssh_extra);
        if (ssh_extra < (YAF_SSH_STANDARD + USER_LIMIT)) {
            ssh_extra++;
        } else {
            g_warning("User Limit Exceeded.  Max Rules permitted for proto "
                      "%d is: %d", applabel, YAF_SSH_STANDARD + USER_LIMIT);
            return -1;
        }

        return ssh_extra;

    } else if (applabel == 554) {

        if (spec) {
            if (rtsp_extra < (YAF_RTSP_STANDARD + USER_LIMIT)) {
                if (rtsp_extra >= YAF_RTSP_STANDARD) {
                    if (!yaf_rtsp_extra) {
                        yaf_rtsp_extra =
                            (fbInfoElementSpec_t *)g_malloc0(new_spec);
                    }
                    memcpy(yaf_rtsp_extra + (rtsp_extra - YAF_RTSP_STANDARD),
                           spec, sizeof(fbInfoElementSpec_t));
                }
            }
        }

        *offset = (sizeof(fbBasicList_t) * rtsp_extra);
        if (rtsp_extra < (YAF_RTSP_STANDARD + USER_LIMIT)) {
            rtsp_extra++;
        } else {
            g_warning("User Limit Exceeded.  Max Rules permitted for proto "
                      "%d is: %d", applabel, YAF_RTSP_STANDARD + USER_LIMIT);
            return -1;
        }

        return rtsp_extra;

    } else if (applabel == 5060) {

        if (spec) {
            if (sip_extra < (YAF_SIP_STANDARD + USER_LIMIT)) {
                if (sip_extra >= YAF_SIP_STANDARD) {
                    if (!yaf_sip_extra) {
                        yaf_sip_extra =
                            (fbInfoElementSpec_t *)g_malloc0(new_spec);
                    }
                    memcpy(yaf_sip_extra + (sip_extra - YAF_SIP_STANDARD),
                           spec, sizeof(fbInfoElementSpec_t));
                }
            }
        } else {
            g_warning("User Limit Exceeded.  Max Rules permitted for proto "
                      "%d is: %d", applabel, YAF_SIP_STANDARD + USER_LIMIT);
            return -1;
        }

        *offset = (sizeof(fbBasicList_t) * sip_extra);
        if (sip_extra < (YAF_SIP_STANDARD + USER_LIMIT)) {
            sip_extra++;
        }

        return sip_extra;

    } else if (applabel == 25) {

        if (spec) {
            if (smtp_extra < (YAF_SMTP_STANDARD + USER_LIMIT)) {
                if (smtp_extra >= YAF_SMTP_STANDARD) {
                    if (!yaf_smtp_extra) {
                        yaf_smtp_extra =
                            (fbInfoElementSpec_t *)g_malloc0(new_spec);
                    }
                    memcpy(yaf_smtp_extra + (smtp_extra - YAF_SMTP_STANDARD),
                           spec, sizeof(fbInfoElementSpec_t));
                }
            }
        }

        *offset = (sizeof(fbBasicList_t) * smtp_extra);

        if (smtp_extra < (YAF_SMTP_STANDARD + USER_LIMIT)) {
            smtp_extra++;
        } else {
            g_warning("User Limit Exceeded.  Max Rules permitted for proto "
                      "%d is: %d", applabel, YAF_SMTP_STANDARD + USER_LIMIT);
            return -1;
        }

        return smtp_extra;

    }

    return -1;
}


/**
 * ypInitializeProtocolRules
 *
 * @param dpiRuleFile
 * @param err
 *
 */
gboolean ypInitializeProtocolRules(
    yfDPIContext_t      *ctx,
    FILE                *dpiRuleFile,
    GError              **err)
{

    int        rulePos = 1;
    const char *errorString;
    int        errorPos, rc, readLength, BLoffset;
    int        tempNumRules = 0;
    int        tempNumProtos = 0;
    char       lineBuffer[LINE_BUF_SIZE];
    pcre       *ruleScanner;
    pcre       *commentScanner;
    pcre       *newRuleScanner;
    pcre       *fieldScanner;
    pcre       *totalScanner;
    pcre       *certExpScanner;
    pcre       *certHashScanner;
    pcre       *newRule;
    pcre_extra *newExtra;
    const char commentScannerExp[] = "^\\s*#[^\\n]*\\n";
    const char ruleScannerExp[]="^[[:space:]]*label[[:space:]]+([[:digit:]]+)"
        "[[:space:]]+yaf[[:space:]]+([[:digit:]]+)[[:space:]]+"
        "([^\\n].*)\\n";
    const char newRuleScannerExp[]="^[[:space:]]*label[[:space:]]+([[:digit:]]+)"
        "[[:space:]]+user[[:space:]]+([[:digit:]]+)[[:space:]]+"
        "name[[:space:]]+([a-zA-Z0-9_]+)[[:space:]]+([^\\n].*)\\n";
    const char fieldLimitExp[]="^[[:space:]]*limit[[:space:]]+field[[:space:]]+"
                               "([[:digit:]]+)\\n";
    const char totalLimitExp[]="^[[:space:]]*limit[[:space:]]+total[[:space:]]+"
                               "([[:digit:]]+)\\n";
    const char certExportExp[]="^[[:space:]]*cert_export_enabled[[:space:]]*="
                               "[[:space:]]*+([[:digit:]])\\n";
    const char certHashExp[]="^[[:space:]]*cert_hash_enabled[[:space:]]*="
                               "[[:space:]]*([[:digit:]])\\n";
    unsigned int bufferOffset = 0;
    int          currentStartPos = 0;
    int          substringVects[NUM_SUBSTRING_VECTS];
    char         *captString;
    uint16_t     applabel, elem_id;
    int          limit;
    const fbInfoElement_t *elem = NULL;
    fbInfoElementSpec_t spec;
    fbInfoElement_t add_element;
    size_t       struct_offset;
    fbInfoModel_t *model = ypGetDPIInfoModel();

    /* standard for any element we're adding */
    spec.len_override = 0;
    spec.name = "basicList";
    spec.flags = 0;

    for (rc = 0; rc < DPI_TOTAL_PROTOCOLS + 1; rc++) {
        ctx->ruleSet[rc].numRules = 0;
    }

    ruleScanner = pcre_compile(ruleScannerExp, PCRE_MULTILINE, &errorString,
                               &errorPos, NULL);
    if (ruleScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI Rule Scanner");
        return FALSE;
    }

    commentScanner = pcre_compile(commentScannerExp, PCRE_MULTILINE,
                                  &errorString, &errorPos, NULL);
    if (commentScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI Comment Scanner");
        return FALSE;
    }

    newRuleScanner = pcre_compile(newRuleScannerExp, PCRE_MULTILINE,
                                  &errorString,
                                  &errorPos, NULL);
    if (newRuleScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI New Rule Scanner");
        return FALSE;
    }

    fieldScanner = pcre_compile(fieldLimitExp, PCRE_MULTILINE,
                                &errorString,
                                &errorPos, NULL);
    if (fieldScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI field Limit Scanner");
        return FALSE;
    }

    totalScanner = pcre_compile(totalLimitExp, PCRE_MULTILINE,
                                &errorString,
                                &errorPos, NULL);
    if (totalScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI total Limit Scanner");
        return FALSE;
    }

    certExpScanner = pcre_compile(certExportExp, PCRE_MULTILINE,
                                  &errorString, &errorPos, NULL);
    if (certExpScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI Cert Exporter Scanner %s", errorString);
        return FALSE;
    }

    certHashScanner = pcre_compile(certHashExp, PCRE_MULTILINE,
                                   &errorString, &errorPos, NULL);
    if (certHashScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI Cert Hash Scanner");
        return FALSE;
    }

    do {
        readLength = fread(lineBuffer + bufferOffset, 1, LINE_BUF_SIZE - 1 -
                           bufferOffset, dpiRuleFile);
        if (readLength == 0) {
            if (ferror(dpiRuleFile)) {
                *err = g_error_new (YAF_ERROR_DOMAIN, YAF_ERROR_IO,
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
                || '\r' == *(lineBuffer + substringVects[1])) {
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
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                applabel = strtoul(captString, NULL, 10);
                rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, applabel, 0);
                if (!rulePos) {
                    /* protocol not turned on */
                    pcre_free(captString);
                    continue;
                }

                pcre_free(captString);
                pcre_get_substring(lineBuffer, substringVects, rc, 2,
                                   (const char **)&captString);
                elem_id = strtoul(captString, NULL, 10);

                if (!(elem = fbInfoModelGetElementByID(model, elem_id, 6871)))
                {
                    g_warning("Element %d does not exist in Info Model.  "
                              "Please add Element to Model or use the "
                              "'new element' rule", elem_id);
                    pcre_free(captString);
                    continue;
                }
                ctx->ruleSet[rulePos].applabel = applabel;
                ctx->ruleSet[rulePos].regexFields[ctx->ruleSet[rulePos].numRules].info_element_id =
                    elem_id;
                ctx->ruleSet[rulePos].regexFields[ctx->ruleSet[rulePos].numRules].elem =
                    elem;
                ctx->ruleSet[rulePos].ruleType = ycGetRuleType(applabel);
                pcre_free(captString);
                pcre_get_substring(lineBuffer, substringVects, rc, 3,
                                   (const char**)&captString);
                newRule = pcre_compile(captString, PCRE_MULTILINE,
                                       &errorString, &errorPos, NULL);
                if (NULL == newRule) {
                    g_warning("Error Parsing DPI Rule \"%s\"", captString);
                } else {
                    newExtra = pcre_study(newRule, 0, &errorString);
                    ctx->ruleSet[rulePos].regexFields[ctx->ruleSet[rulePos].numRules].rule = newRule;
                    ctx->ruleSet[rulePos].regexFields[ctx->ruleSet[rulePos].numRules].extra = newExtra;
                    ctx->ruleSet[rulePos].numRules++;
                    tempNumRules++;
                }
                pcre_free(captString);
                /* add elem to rule array - if it doesn't exist already */
                if (!ctx->appRuleArray[elem_id]) {
                    /* get offset of element -
                       basically which basicList in struct */
                    ypAddSpec(&spec, applabel, &struct_offset);
                    ypAddRuleKey(ctx, applabel, elem_id, elem, struct_offset);
                }

                if (MAX_PAYLOAD_RULES == ctx->ruleSet[rulePos].numRules) {
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
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                applabel = strtoul(captString, NULL, 10);
                rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, applabel, 0);
                if (!rulePos) {
                    /* protocol not turned on */
                    pcre_free(captString);
                    continue;
                }
                ctx->ruleSet[rulePos].applabel = applabel;
                ctx->ruleSet[rulePos].ruleType = ycGetRuleType(applabel);
                pcre_free(captString);
                pcre_get_substring(lineBuffer, substringVects, rc, 2,
                                   (const char **)&captString);
                elem_id = strtoul(captString, NULL, 10);
                pcre_free(captString);
                pcre_get_substring(lineBuffer, substringVects, rc, 3,
                                   (const char**)&captString);
                if (!(elem = fbInfoModelGetElementByID(model, elem_id, 6871)))
                {
                    memset(&add_element, 0, sizeof(add_element));
                    add_element.num = elem_id;
                    add_element.ent = 6871;
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
                                 fbInfoModelGetElementByName(model,captString),
                                 struct_offset);
                } else {
                    g_warning("Info Element already exists with ID %d "
                              "in default Info Model. Ignoring rule.",
                              elem_id);
                    pcre_free(captString);
                    continue;
                }
                ctx->ruleSet[rulePos].regexFields[ctx->ruleSet[rulePos].numRules].info_element_id =
                    elem_id;
                ctx->ruleSet[rulePos].regexFields[ctx->ruleSet[rulePos].numRules].elem =
                    fbInfoModelGetElementByName(model, captString);
                pcre_free(captString);
                pcre_get_substring(lineBuffer, substringVects, rc, 4,
                                       (const char**)&captString);
                newRule = pcre_compile(captString, PCRE_MULTILINE,
                                       &errorString, &errorPos, NULL);
                if (NULL == newRule) {
                    g_warning("Error Parsing DPI Rule \"%s\"", captString);
                } else {
                    newExtra = pcre_study(newRule, 0, &errorString);
                    ctx->ruleSet[rulePos].regexFields[ctx->ruleSet[rulePos].numRules].rule = newRule;
                    ctx->ruleSet[rulePos].regexFields[ctx->ruleSet[rulePos].numRules].extra = newExtra;
                    ctx->ruleSet[rulePos].numRules++;
                    tempNumRules++;
                }
                pcre_free(captString);

                if (MAX_PAYLOAD_RULES == ctx->ruleSet[rulePos].numRules) {
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
                        ypProtocolHashActivate(ctx, 443, ctx->dpi_enabled+1);
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
                        ypProtocolHashActivate(ctx, 443, ctx->dpi_enabled+1);
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
                && !feof (dpiRuleFile)) {
                memmove (lineBuffer, lineBuffer + substringVects[1],
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
        rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, regexDPIProtos[rc], 0);
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

    return TRUE;
}

/**
 * flowFree
 *
 *
 * @param flow pointer to the flow structure with the context information
 *
 *
 */
void ypFlowFree(
    void             *yfHookContext,
    yfFlow_t         *flow)
{

    ypDPIFlowCtx_t   *flowContext = (ypDPIFlowCtx_t *)yfHookContext;

    if (NULL == flowContext) {
        /* log an error here, but how */
        g_warning("couldn't free flow %p; not in hash table\n", flow);
        return;
    }

    if (flowContext->dpi) {
        yg_slice_free1((sizeof(yfDPIData_t) * YAF_MAX_CAPTURE_FIELDS),
                       flowContext->dpi);
    }

    yg_slice_free1(sizeof(ypDPIFlowCtx_t), flowContext);

    return;
}


/**
 * hookPacket
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
gboolean ypHookPacket(
    yfFlowKey_t          *key,
    const uint8_t        *pkt,
    size_t               caplen,
    uint16_t             iplen,
    yfTCPInfo_t          *tcpinfo,
    yfL2Info_t           *l2info)
{
    /* this never decides to drop packet flow */

    return TRUE;
}


/**
 * flowPacket
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

void ypFlowPacket(
    void                 *yfHookContext,
    yfFlow_t             *flow,
    yfFlowVal_t          *val,
    const uint8_t        *pkt,
    size_t               caplen,
    uint16_t             iplen,
    yfTCPInfo_t          *tcpinfo,
    yfL2Info_t           *l2info)
{

    ypDPIFlowCtx_t       *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t       *ctx = NULL;
    uint16_t             tempAppLabel = 0;


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

    return;
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
void ypInitializeBLs(
    yfDPIContext_t   *ctx,
    fbBasicList_t    *first_basic_list,
    int              proto_standard,
    int              app_pos)
{
    fbBasicList_t    *temp = first_basic_list;
    int              rc, loop;

    for (loop = 0; loop < ctx->ruleSet[app_pos].numRules; loop++) {
        fbBasicListInit(temp, 3, ctx->ruleSet[app_pos].regexFields[loop].elem, 0);
        temp++;
    }

    rc = proto_standard - ctx->ruleSet[app_pos].numRules;

    if (rc < 0) {
        return;
    }

    /* add some dummy elements to fill to proto_standard */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListInit(temp, 3, ctx->ruleSet[app_pos].regexFields[0].elem, 0);
        temp++;
    }
}

/**
 * flowWrite
 *
 *  this function gets called when the flow data is getting serialized to be
 *  written into ipfix format.  This function must put its data into the
 *  output stream (rec) in the order that it allocated the data according to
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
gboolean ypFlowWrite(
    void                           *yfHookContext,
    fbSubTemplateMultiList_t       *rec,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    GError                         **err)
{
    ypDPIFlowCtx_t            *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t            *ctx;
    uint16_t                   rc;

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
    if ((flowContext->startOffset >= flowContext->dpinum))
    {
        return TRUE;
    }

    /* make sure DPI is turned on for this protocol */
    rc = ypSearchPlugOpts(ctx->dpiActiveHash, flow->appLabel);
    if (!rc) {
        return TRUE;
    }

    switch(flow->appLabel) {
    case 21:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessFTP(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
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
        flowContext->rec = ypProcessHTTP(flowContext, stml, flow,
                                          flowContext->captureFwd,
                                          flowContext->dpinum, rc);
        break;
    case 110:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessPOP3(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
    case 119:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessNNTP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
    case 143:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessIMAP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
    case 194:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessIRC(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
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
        flowContext->rec = ypProcessRTSP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
    case 5060:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessSIP(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
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
        flowContext->rec = ypProcessModbus(flowContext, stml, flow,
                                           flowContext->captureFwd,
                                           flowContext->dpinum, rc);
        break;
      case 44818:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessEnIP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
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
 * gets the IPFIX information model elements
 *
 *
 * @return a pointer to a fixbuf information element model array
 *
 */
fbInfoElement_t *ypGetInfoModel()
{
    return infomodel_array_static_yaf_dpi;
}

/**
 * getTemplate
 *
 * gets the IPFIX data template for the information that will be returned
 *
 * @return a pointer to the fixbuf info element array for the templates
 *
 */
gboolean ypGetTemplate(
    fbSession_t     *session)
{
    GError               *err = NULL;

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
    }

    if (ypSearchPlugOpts(global_active_protos, 22)) {
        if (!(sshTemplate = ypInitTemplate(
                  session, yaf_singleBL_spec,
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
 * sets the pluginOpt variable passed from the command line
 *
 */
void ypSetPluginOpt(
    const char * option,
    void       * yfctx)
{
    yfDPIContext_t *ctx = (yfDPIContext_t *)yfctx;
    GError *err = NULL;

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
 * sets the pluginConf variable passed from the command line
 *
 */
void ypSetPluginConf(
    char             *conf,
    void             **yfctx)
{
    yfDPIContext_t   *newctx = NULL;

    newctx = (yfDPIContext_t *)yg_slice_alloc0(sizeof(yfDPIContext_t));

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
        newctx->dpiRulesFileName = g_strdup(YAF_CONF_DIR"/yafDPIRules.conf");
    }

    *yfctx = (void *)newctx;
}

/**
 * ypProtocolHashInitialize
 *
 */
void ypProtocolHashInitialize(
    yfDPIContext_t         *ctx)
{
    int               loop;
    uint16_t          insertLoc;

    for (loop = 0; loop < MAX_PAYLOAD_RULES; loop++) {
        ctx->dpiActiveHash[loop].activated = MAX_PAYLOAD_RULES + 1;
    }

    for (loop = 0; loop < DPI_TOTAL_PROTOCOLS; loop++) {
        insertLoc = DPIProtocols[loop] % MAX_PAYLOAD_RULES;
        if (ctx->dpiActiveHash[insertLoc].activated == (MAX_PAYLOAD_RULES + 1)) {
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
uint16_t ypProtocolHashSearch(
    DPIActiveHash_t           *active,
    uint16_t                  portNum,
    uint16_t                  insert)
{
    uint16_t                  searchLoc = portNum % MAX_PAYLOAD_RULES;

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
gboolean ypProtocolHashActivate(
    yfDPIContext_t          *ctx,
    uint16_t                portNum,
    uint16_t                index)
{
    if (!ypProtocolHashSearch(ctx->dpiActiveHash, portNum, index)) {
        return FALSE;
    }

    return TRUE;
}


void ypProtocolHashDeactivate(
    yfDPIContext_t            *ctx,
    uint16_t                  portNum)
{
    uint16_t                   searchLoc = portNum % MAX_PAYLOAD_RULES;

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
void ypParsePluginOpt(
    yfDPIContext_t     *ctx,
    const char         *option)
{
    char               *plugOptIndex;
    char               *plugOpt, *endPlugOpt;
    int                dpiNumOn = 1;
    int                loop;

    plugOptIndex = (char *)option;
    while (NULL != plugOptIndex && (dpiNumOn < YAF_MAX_CAPTURE_FIELDS)) {
        endPlugOpt = strchr(plugOptIndex, ' ');
        if (endPlugOpt == NULL) {
            if (!(strcasecmp(plugOptIndex, "dnssec"))) {
                ctx->dnssec = TRUE;
                dnssec_global = TRUE;
                break;
            }
            if ( 0 == atoi(plugOptIndex)) {
                break;
            }
            if (!ypProtocolHashActivate(ctx,(uint16_t)atoi(plugOptIndex),
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
            plugOpt = g_new0(char, (endPlugOpt-plugOptIndex + 1));
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
            ctx->dpi_enabled = dpiNumOn-1;
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
gboolean ypPluginRegex(
    yfDPIContext_t *ctx,
    uint16_t elementID,
    int      index)
{
    int loop;

    for ( loop = 0; loop < ctx->ruleSet[index].numRules; loop++) {
        if (elementID == ctx->ruleSet[index].regexFields[loop].info_element_id) {
            return TRUE;
        }
    }

    return FALSE;
}



/**
 * scanPayload
 *
 * gets the important strings out of the payload by executing the passed pcre
 * or the offset/length to the bytes of interest.
 *
 * if expression is NULL, but a regular expression was given in the
 * yafDPIRules.conf with the elementID, use that regular expression against
 * the payload.
 *
 */

void ypScanPayload(
    void           *yfHookContext,
    yfFlow_t       *flow,
    const uint8_t  *pkt,
    size_t         caplen,
    pcre           *expression,
    uint16_t       offset,
    uint16_t       elementID,
    uint16_t       applabel)
{

    int            rc;
    int            vects[NUM_SUBSTRING_VECTS];
    unsigned int   captCount;
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t *ctx = NULL;
    int            rulePos = 0;
    gboolean       scanner = FALSE;

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
    /*if (!ypSearchPlugOpts(applabel)) {
        return;
        }*/

    rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, applabel, 0);
    if (!rulePos) {
        return;
    }

    if (flowContext->dpi == NULL) {
        flowContext->dpi = yg_slice_alloc0(YAF_MAX_CAPTURE_FIELDS *
                                           sizeof(yfDPIData_t));
    }

    captCount = flowContext->dpinum;

    if ((captCount >= YAF_MAX_CAPTURE_FIELDS) &&
        (flowContext->dpi_len >= ctx->dpi_total_limit)) {
        return;
    }

    if ((expression == NULL) && ctx->ruleSet[rulePos].numRules) {
        /* determine if the plugin has regexs in yafDPIRules.conf */
        if (ypPluginRegex(ctx, elementID, rulePos)) {
            scanner = TRUE;
        } else {
            scanner = FALSE;
        }
    }

    if (expression) {
        rc = pcre_exec(expression, NULL, (char *)pkt, caplen, 0,
                       0, vects, NUM_SUBSTRING_VECTS);

        while ((rc > 0) && (captCount < YAF_MAX_CAPTURE_FIELDS) &&
               (flowContext->dpi_len < ctx->dpi_total_limit))
        {
            if (rc > 1) {
                flowContext->dpi[captCount].dpacketCaptLen = vects[3] - vects[2];
                flowContext->dpi[captCount].dpacketCapt = vects[2];
            } else {
                flowContext->dpi[captCount].dpacketCaptLen = vects[1] - vects[0];
                flowContext->dpi[captCount].dpacketCapt = vects[0];
            }
            offset = vects[0] + flowContext->dpi[captCount].dpacketCaptLen;
            if (flowContext->dpi[captCount].dpacketCaptLen > ctx->dpi_user_limit) {
                flowContext->dpi[captCount].dpacketCaptLen = ctx->dpi_user_limit;
            }

            flowContext->dpi[captCount].dpacketID = elementID;
            flowContext->dpi_len += flowContext->dpi[captCount].dpacketCaptLen;

            if (flowContext->dpi_len > ctx->dpi_total_limit) {
                /* if we passed the limit - don't add this one */
                flowContext->dpinum = captCount;
                return;
            }
            captCount++;

            rc = pcre_exec(expression, NULL, (char *)(pkt), caplen, offset,
                           0, vects, NUM_SUBSTRING_VECTS);

        }
    } else if (scanner) {
        flow->appLabel = applabel;
        captCount += ypDPIScanner(flowContext, pkt, caplen, offset, flow,NULL);

    } else {

        if (caplen > ctx->dpi_user_limit) caplen = ctx->dpi_user_limit;
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
 * this returns the meta information about this plugin, the interface version
 * it was built with, and the amount of export data it will send
 *
 * @return a pointer to a meta data structure with the various fields
 * appropriately filled in, API version & export data size
 *
 */
const struct yfHookMetaData* ypGetMetaData ()
{
    return &metaData;
}

/**
 * ypGetTemplateCount
 *
 * this returns the number of templates we are adding to yaf's
 * main subtemplatemultilist, for DPI - this is usually just 1
 *
 */
uint8_t ypGetTemplateCount(
    void                   *yfHookContext,
    yfFlow_t               *flow)
{

    ypDPIFlowCtx_t         *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t         *ctx = NULL;

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
    if ((flowContext->startOffset < flowContext->dpinum))
    {
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
void ypFreeBLRec(
    yfDPIContext_t  *ctx,
    fbBasicList_t   *first_basiclist,
    int             proto_standard,
    int             app_pos)
{

    fbBasicList_t   *temp = first_basiclist;
    int             rc, loop;

    rc = proto_standard - ctx->ruleSet[app_pos].numRules;

    for (loop = 0; loop < ctx->ruleSet[app_pos].numRules; loop++) {
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
 *
 *
 *
 */
void ypFreeLists(
    void             *yfHookContext,
    yfFlow_t         *flow)
{

    ypDPIFlowCtx_t   *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    yfDPIContext_t   *ctx = NULL;
    int              rc;

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
           we don't have it now */
        /* Biflow case: startOffset is 0 and fwdcap is 0, we did get something
           and its in the rev payload */
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
            {
                yfSMTPFlow_t *rec = (yfSMTPFlow_t *)flowContext->rec;
                ypFreeBLRec(ctx, &(rec->smtpHello), YAF_SMTP_STANDARD, rc);
                break;
            }
          case 22:
            {
                yfSSHFlow_t *rec = (yfSSHFlow_t *)flowContext->rec;
                ypFreeBLRec(ctx, &(rec->sshVersion), YAF_SSH_STANDARD, rc);
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
            yg_slice_free1(ctx->dpi_total_limit, flowContext->exbuf);
        }
    }

    return;
}

uint8_t
ypDPIScanner (
    ypDPIFlowCtx_t     *flowContext,
    const uint8_t      *payloadData,
    unsigned int       payloadSize,
    uint16_t           offset,
    yfFlow_t           *flow,
    yfFlowVal_t        *val)
{

    int                rc = 0;
    int                loop;
    int                subVects[NUM_SUBSTRING_VECTS];
    int                offsetptr;
    uint8_t            captCount = flowContext->dpinum;
    uint8_t            newCapture = flowContext->dpinum;
    uint8_t            captDirection = 0;
    uint16_t           captLen = 0;
    pcre               *ruleHolder;
    pcre_extra         *extraHolder;
    int                rulePos = 0;
    yfDPIContext_t     *ctx = flowContext->yfctx;

    rulePos = ypProtocolHashSearch(ctx->dpiActiveHash, flow->appLabel, 0);

    for ( loop = 0; loop < ctx->ruleSet[rulePos].numRules; loop++) {
        ruleHolder = ctx->ruleSet[rulePos].regexFields[loop].rule;
        extraHolder = ctx->ruleSet[rulePos].regexFields[loop].extra;
        offsetptr = offset;
        rc = pcre_exec(ruleHolder, extraHolder,
                       (char *)(payloadData), payloadSize, offsetptr,
                       0, subVects, NUM_SUBSTRING_VECTS) ;
        while ( (rc > 0) && (captDirection < YAF_MAX_CAPTURE_SIDE)) {
            /*Get only matched substring - don't need Labels*/
            if (rc > 1) {
                captLen = subVects[3] - subVects[2];
                flowContext->dpi[captCount].dpacketCapt = subVects[2];
            } else {
                captLen = subVects[1] - subVects[0];
                flowContext->dpi[captCount].dpacketCapt = subVects[0];
            }

            if (captLen <= 0) {
                flowContext->dpinum = captCount;
                return (flowContext->dpinum - newCapture);
            }

            /* truncate capture length to capture limit */
            flowContext->dpi[captCount].dpacketID =
                ctx->ruleSet[rulePos].regexFields[loop].info_element_id;
            if (captLen > ctx->dpi_user_limit) captLen = ctx->dpi_user_limit;
            flowContext->dpi[captCount].dpacketCaptLen =  captLen;
            flowContext->dpi_len += captLen;

            if (flowContext->dpi_len > ctx->dpi_total_limit) {
                /* buffer full */
                flowContext->dpinum = captCount;
                return captDirection;
            }
            offsetptr = subVects[0] + captLen;
            captCount++;
            captDirection++;
            rc = pcre_exec(ruleHolder, extraHolder, (char *)(payloadData),
                           payloadSize, offsetptr, 0, subVects,
                           NUM_SUBSTRING_VECTS);
        }
        if (rc < -5) {
            /* print regular expression error */
          g_debug("Error: Regular Expression (App: %d Rule: %d) Error Code %d",
                  flow->appLabel, loop+1, rc);
        }
    }

    flowContext->dpinum = captCount;

    return captDirection;
}


/**
 * Protocol Specific Functions
 *
 */

fbTemplate_t * ypInitTemplate(
    fbSession_t *session,
    fbInfoElementSpec_t *spec,
    uint16_t tid,
    const gchar *name,
    const gchar *description,
    uint32_t flags,
    GError **err)
{
    fbInfoModel_t *model = ypGetDPIInfoModel();
    fbTemplate_t *tmpl = NULL;
    gboolean rc = TRUE;
    GError *error = NULL;

    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, spec, flags, &error)) {
        g_debug("Error adding spec array to template for tid %d %s", tid,
                error->message);
        return NULL;
    }

    if (tid == YAF_HTTP_FLOW_TID) {
        if (yaf_http_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_http_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_IMAP_FLOW_TID) {
        if (yaf_imap_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_imap_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_FTP_FLOW_TID) {
        if (yaf_ftp_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_ftp_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_RTSP_FLOW_TID) {
        if (yaf_rtsp_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_rtsp_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_SSH_FLOW_TID) {
        if (yaf_ssh_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_ssh_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_SIP_FLOW_TID) {
        if (yaf_sip_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_sip_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_SMTP_FLOW_TID) {
        if (yaf_smtp_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_smtp_extra, 0xffffffff,
                                           &error);
        }
    }

    if (!rc) {
        g_debug("Error adding extra spec array to template with tid %02x: %s",
                tid, error->message);
        return NULL;
    }

#if YAF_ENABLE_METADATA_EXPORT
    if (!fbSessionAddTemplateWithMetadata(session, FALSE, tid,
                                          tmpl, name, description, &error))
    {
        return NULL;
    }
#else
    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, &error)) {
        g_debug("Error adding template %02x: %s", tid, error->message);
        return NULL;
    }
#endif

    return tmpl;
}

void *ypProcessIRC(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    fbVarfield_t *ircVarfield;
    yfIRCFlow_t  *rec = NULL;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    int count = flowContext->startOffset;

    rec =(yfIRCFlow_t *)fbSubTemplateMultiListEntryInit(stml, YAF_IRC_FLOW_TID,
                                                        ircTemplate, 1);

    ircVarfield = (fbVarfield_t *)fbBasicListInit(&(rec->ircMsg), 3,
                  fbInfoModelGetElementByName(model, "ircTextMessage"),
                                                  totalcap);

    while (count < fwdcap) {
        ircVarfield->buf = flow->val.payload + dpi[count].dpacketCapt;
        ircVarfield->len = dpi[count].dpacketCaptLen;
        ircVarfield = (fbVarfield_t*)fbBasicListGetNextPtr(&(rec->ircMsg), ircVarfield);
        count++;
    }

    if (fwdcap < totalcap && flow->rval.payload) {
        while (count < totalcap) {
            ircVarfield->buf = flow->rval.payload + dpi[count].dpacketCapt;
            ircVarfield->len = dpi[count].dpacketCaptLen;
            ircVarfield = (fbVarfield_t*)fbBasicListGetNextPtr(&(rec->ircMsg), ircVarfield);
            count++;
        }
    }

    return (void *)rec;
}

void *ypProcessPOP3(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t  *dpi = flowContext->dpi;
    fbVarfield_t *popvar;
    yfPOP3Flow_t *rec = NULL;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    int count = flowContext->startOffset;

    rec = (yfPOP3Flow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_POP3_FLOW_TID,
                                                          pop3Template, 1);
    popvar = (fbVarfield_t *)fbBasicListInit(&(rec->pop3msg), 3,
                     fbInfoModelGetElementByName(model, "pop3TextMessage"),
                                             totalcap);

    while (count < fwdcap && popvar) {
        popvar->buf = flow->val.payload + dpi[count].dpacketCapt;
        popvar->len = dpi[count].dpacketCaptLen;
        popvar = fbBasicListGetNextPtr(&(rec->pop3msg), popvar);
        count++;

    }

    if (fwdcap < totalcap && flow->rval.payload) {
        while (count < totalcap && popvar) {
            popvar->buf = flow->rval.payload + dpi[count].dpacketCapt;
            popvar->len = dpi[count].dpacketCaptLen;
            popvar = fbBasicListGetNextPtr(&(rec->pop3msg), popvar);
            count++;
        }
    }

    return (void *)rec;
}

void *ypProcessTFTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfTFTPFlow_t *rec = NULL;
    int count = flowContext->startOffset;

    rec = (yfTFTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_TFTP_FLOW_TID,
                                                          tftpTemplate, 1);

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

void *ypProcessSLP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfSLPFlow_t *rec = NULL;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    int loop;
    int total = 0;
    int count = flowContext->startOffset;
    fbVarfield_t *slpVar = NULL;

    rec = (yfSLPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                         YAF_SLP_FLOW_TID,
                                                         slpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    for (loop = count; loop < totalcap; loop++) {
        if (dpi[loop].dpacketID > 91) {
            total++;
        }
    }
    slpVar = (fbVarfield_t *)fbBasicListInit(&(rec->slpString), 3,
                       fbInfoModelGetElementByName(model, "slpString"), total);

    while (count < fwdcap) {
        if (dpi[count].dpacketID == 90) {
            rec->slpVersion = (uint8_t)*(flow->val.payload +
                                         dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID == 91) {
            rec->slpMessageType = (uint8_t)*(flow->val.payload +
                                             dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID > 91 && slpVar) {
            slpVar->buf = flow->val.payload + dpi[count].dpacketCapt;
            slpVar->len = dpi[count].dpacketCaptLen;
            slpVar = fbBasicListGetNextPtr(&(rec->slpString), slpVar);
        }
        count++;
    }

    /* should we collect reverse SLP version and message Type? */
    while (count < totalcap && flow->rval.payload) {
        if (dpi[count].dpacketID == 90) {
            rec->slpVersion = (uint8_t)*(flow->rval.payload +
                                         dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID == 91) {
          rec->slpMessageType = (uint8_t)*(flow->rval.payload +
                                           dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID > 91 && slpVar) {
            slpVar->buf= flow->rval.payload + dpi[count].dpacketCapt;
            slpVar->len= dpi[count].dpacketCaptLen;
            slpVar = fbBasicListGetNextPtr(&(rec->slpString), slpVar);
        }
        count++;
    }

    return (void *)rec;
}

void *ypProcessHTTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfDPIContext_t *ctx = flowContext->yfctx;
    yfHTTPFlow_t *rec = NULL;
    fbVarfield_t *httpVar = NULL;
    uint8_t start = flowContext->startOffset;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];
    uint16_t total = 0;
    uint16_t temp_element;
    int loop, oloop;
    ypBLValue_t *val;
    fbBasicList_t *blist = NULL;

    rec = (yfHTTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_HTTP_FLOW_TID,
                                                          httpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    ypInitializeBLs(ctx, &(rec->server), YAF_HTTP_STANDARD, rulePos);

    for (oloop = 0; oloop < ctx->ruleSet[rulePos].numRules; oloop++) {
        temp_element = ctx->ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(ctx,temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                httpVar = (fbVarfield_t *)fbBasicListInit(blist, 3,
                                                          val->infoElement,
                                                          total);
                ypFillBasicList(flow, dpi, total, fwdcap,&httpVar, totalIndex);
            }
            total = 0;
            httpVar = NULL;
        }
    }

    return (void *)rec;
}

void *ypProcessFTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t *dpi = flowContext->dpi;
    yfDPIContext_t *ctx = flowContext->yfctx;
    yfFTPFlow_t *rec = NULL;
    fbVarfield_t *ftpVar = NULL;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];
    uint8_t start = flowContext->startOffset;
    uint16_t temp_element;
    int loop, oloop;
    ypBLValue_t *val;
    int total = 0;
    fbBasicList_t *blist;


    rec = (yfFTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_FTP_FLOW_TID,
                                                          ftpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    ypInitializeBLs(ctx, &(rec->ftpReturn), YAF_FTP_STANDARD, rulePos);

    for (oloop = 0; oloop < ctx->ruleSet[rulePos].numRules; oloop++) {
        temp_element = ctx->ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(ctx, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                ftpVar = (fbVarfield_t *)fbBasicListInit(blist, 3,
                                                         val->infoElement,
                                                         total);
                ypFillBasicList(flow, dpi, total, fwdcap, &ftpVar, totalIndex);
            }
            total = 0;
            ftpVar = NULL;
        }
    }

    return (void *)rec;
}

void *ypProcessIMAP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfDPIContext_t *ctx = flowContext->yfctx;
    yfIMAPFlow_t *rec = NULL;
    uint8_t start = flowContext->startOffset;
    fbVarfield_t *imapVar = NULL;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];
    uint16_t temp_element;
    int loop, oloop;
    fbBasicList_t *blist;
    ypBLValue_t *val;
    int total = 0;

    rec = (yfIMAPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_IMAP_FLOW_TID,
                                                          imapTemplate, 1);

    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    ypInitializeBLs(ctx, &(rec->imapCapability), YAF_IMAP_STANDARD, rulePos);

    for (oloop = 0; oloop < ctx->ruleSet[rulePos].numRules; oloop++) {
        temp_element = ctx->ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(ctx, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                imapVar = (fbVarfield_t *)fbBasicListInit(blist, 3,
                                                         val->infoElement,
                                                         total);
                ypFillBasicList(flow, dpi, total, fwdcap,&imapVar, totalIndex);
            }
            total = 0;
            imapVar = NULL;
        }
    }

    return (void *)rec;
}

void *ypProcessSIP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t *dpi = flowContext->dpi;
    yfDPIContext_t *ctx = flowContext->yfctx;
    yfSIPFlow_t *rec = NULL;
    uint8_t start = flowContext->startOffset;
    int total = 0;
    fbVarfield_t *sipVar = NULL;
    uint16_t temp_element;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];
    int loop, oloop;
    fbBasicList_t *blist;
    ypBLValue_t *val;

    rec = (yfSIPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                         YAF_SIP_FLOW_TID,
                                                         sipTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    ypInitializeBLs(ctx, &(rec->sipInvite), YAF_SIP_STANDARD, rulePos);

    for (oloop = 0; oloop < ctx->ruleSet[rulePos].numRules; oloop++) {
        temp_element = ctx->ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(ctx, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                sipVar = (fbVarfield_t *)fbBasicListInit(blist, 3,
                                                         val->infoElement,
                                                         total);
                ypFillBasicList(flow, dpi, total, fwdcap, &sipVar, totalIndex);
            }
            total = 0;
            sipVar = NULL;
        }
    }

    return (void *)rec;
}

void *ypProcessSMTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfDPIContext_t *ctx = flowContext->yfctx;
    yfSMTPFlow_t *rec = NULL;
    uint8_t start = flowContext->startOffset;
    int total = 0;
    fbVarfield_t *smtpVar = NULL;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];
    uint16_t temp_element;
    int loop, oloop;
    fbBasicList_t *blist;
    ypBLValue_t *val;

    rec = (yfSMTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_SMTP_FLOW_TID,
                                                          smtpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    ypInitializeBLs(ctx, &(rec->smtpHello), YAF_SMTP_STANDARD, rulePos);

    for (oloop = 0; oloop < ctx->ruleSet[rulePos].numRules; oloop++) {
        temp_element = ctx->ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }

        if (total) {
            val = ypGetRule(ctx, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                smtpVar = (fbVarfield_t *)fbBasicListInit(blist, 3,
                                                         val->infoElement,
                                                         total);
                ypFillBasicList(flow, dpi, total,fwdcap, &smtpVar, totalIndex);
            }
            total = 0;
            smtpVar = NULL;
        }
    }

    return (void *)rec;
}

void *ypProcessNNTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfNNTPFlow_t *rec = NULL;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    uint8_t count;
    uint8_t start = flowContext->startOffset;
    int total = 0;
    fbVarfield_t *nntpVar = NULL;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];

    rec = (yfNNTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_NNTP_FLOW_TID,
                                                          nntpTemplate, 1);
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

    nntpVar = (fbVarfield_t *)fbBasicListInit(&(rec->nntpResponse), 3,
                           fbInfoModelGetElementByName(model, "nntpResponse"),
                                              total);

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

    nntpVar = (fbVarfield_t *)fbBasicListInit(&(rec->nntpCommand), 3,
                            fbInfoModelGetElementByName(model, "nntpCommand"),
                                              total);

    ypFillBasicList(flow, dpi, total, fwdcap, &nntpVar, totalIndex);

    return (void *)rec;
}

void *ypProcessSSL(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiList_t      *mainRec,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t         *dpi = flowContext->dpi;
    yfDPIContext_t      *ctx = flowContext->yfctx;
    yfSSLFlow_t         *rec = NULL;
    yfSSLFullCert_t     *fullrec = NULL;
    yfSSLCertFlow_t     *sslcert = NULL;
    fbInfoModel_t       *model = ypGetDPIInfoModel();
    int                 count = flowContext->startOffset;
    int                 total_certs = 0;
    uint32_t            *sslCiphers;
    uint8_t             *payload = NULL;
    size_t              paySize = 0;
    uint8_t             totalIndex[YAF_MAX_CAPTURE_FIELDS];
    gboolean            ciphertrue = FALSE;
    int                 i;
    fbVarfield_t        *sslfull = NULL;

    rec =(yfSSLFlow_t *)fbSubTemplateMultiListEntryInit(stml, YAF_SSL_FLOW_TID,
                                                        sslTemplate, 1);

    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    while (count < totalcap) {
        if (count < fwdcap) {
            payload = flow->val.payload;
            paySize = flow->val.paylen;
        } else if (flow->rval.payload) {
            payload = flow->rval.payload;
            paySize = flow->rval.paylen;
        } else {
            count++;
            continue;
        }

        if (dpi[count].dpacketID == 91) {
            sslCiphers = (uint32_t *)fbBasicListInit(&(rec->sslCipherList), 3,
                               fbInfoModelGetElementByName(model, "sslCipher"),
                                                 dpi[count].dpacketCaptLen/2);
            for (i=0; i < (dpi[count].dpacketCaptLen/2); i++) {
                *sslCiphers = (uint32_t)ntohs(*(uint16_t *)(payload +
                                                      dpi[count].dpacketCapt +
                                                            (i * 2)));
                if (!(sslCiphers = fbBasicListGetNextPtr(&(rec->sslCipherList),
                                                         sslCiphers)))
                {
                    break;
                }
            }
            ciphertrue = TRUE;
        } else if (dpi[count].dpacketID == 90) {
            rec->sslCompressionMethod = *(payload + dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID == 88) {
            /* major version */
            if (!rec->sslClientVersion) {
                rec->sslClientVersion = dpi[count].dpacketCapt;
            }
        } else if (dpi[count].dpacketID == 94) {
            /* record version */
            rec->sslVersion = dpi[count].dpacketCapt;
        } else if (dpi[count].dpacketID == 89) {
            rec->sslServerCipher = ntohs(*(uint16_t *)(payload +
                                                      dpi[count].dpacketCapt));
        } else if (dpi[count].dpacketID == 92) {
            sslCiphers = (uint32_t *)fbBasicListInit(&(rec->sslCipherList), 3,
                               fbInfoModelGetElementByName(model, "sslCipher"),
                                                  dpi[count].dpacketCaptLen/3);
            for (i=0; i < (dpi[count].dpacketCaptLen/3); i++) {
                *sslCiphers =(ntohl(*(uint32_t *)(payload +
                                                  dpi[count].dpacketCapt +
                                                  (i * 3))) & 0xFFFFFF00) >> 8;
                if (!(sslCiphers = fbBasicListGetNextPtr(&(rec->sslCipherList),
                                                         sslCiphers)))
                {
                    break;
                }
            }
            ciphertrue = TRUE;
        } else if (dpi[count].dpacketID == 93) {
            totalIndex[total_certs] = count;
            total_certs++;
        } else if (dpi[count].dpacketID == 95) {
            /* server Name */
            rec->sslServerName.buf = payload + dpi[count].dpacketCapt;
            rec->sslServerName.len = dpi[count].dpacketCaptLen;
        }

        count++;
    }

    if (!ciphertrue) {
        fbBasicListInit(&(rec->sslCipherList), 3,
                        fbInfoModelGetElementByName(model, "sslCipher"), 0);
    }

    if (!ctx->ssl_off) {
        sslcert = (yfSSLCertFlow_t *)fbSubTemplateListInit(&(rec->sslCertList), 3,
                                                           YAF_SSL_CERT_FLOW_TID,
                                                           sslCertTemplate,
                                                           total_certs);
    } else {
        /* NULL since we're doing full cert export */
        sslcert = (yfSSLCertFlow_t *)fbSubTemplateListInit(&(rec->sslCertList), 3,
                                                           YAF_SSL_CERT_FLOW_TID,
                                                           sslCertTemplate,
                                                           0);
    }

    if (!ctx->ssl_off) {
        for (i = 0; i < total_certs; i++) {
            if (totalIndex[i] < fwdcap) {
                payload = flow->val.payload;
                paySize = flow->val.paylen;
            } else if (flow->rval.payload) {
                payload = flow->rval.payload;
                paySize = flow->rval.paylen;
            }
            if (!ypDecodeSSLCertificate(ctx, &sslcert, payload, paySize, flow,
                                        dpi[totalIndex[i]].dpacketCapt)) {
                if (sslcert->issuer.tmpl == NULL) {
                    fbSubTemplateListInit(&(sslcert->issuer), 3,
                                          YAF_SSL_SUBCERT_FLOW_TID,
                                          sslSubTemplate, 0);
                }
                if (sslcert->subject.tmpl == NULL) {
                    fbSubTemplateListInit(&(sslcert->subject), 3,
                                          YAF_SSL_SUBCERT_FLOW_TID,
                                          sslSubTemplate, 0);
                }
                if (sslcert->extension.tmpl == NULL) {
                    fbSubTemplateListInit(&(sslcert->extension), 3,
                                          YAF_SSL_SUBCERT_FLOW_TID,
                                          sslSubTemplate, 0);
                }
            }

            if (!(sslcert =
                  fbSubTemplateListGetNextPtr(&(rec->sslCertList), sslcert)))
            {
                break;
            }
        }
    }

    if (ctx->full_cert_export) {
        uint32_t sub_cert_len;
        uint32_t tot_bl_len = 0;
        stml = fbSubTemplateMultiListGetNextEntry(mainRec, stml);
        fullrec =(yfSSLFullCert_t *)fbSubTemplateMultiListEntryInit(stml,
                                                                    YAF_FULL_CERT_TID,
                                                                    sslFullCertTemplate, 1);
        sslfull = (fbVarfield_t*)fbBasicListInit(&(fullrec->cert), 3,
                                                 fbInfoModelGetElementByName(model,
                                                 "sslCertificate"), total_certs);
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
                sslfull = (fbVarfield_t*)fbBasicListGetNextPtr(&(fullrec->cert),sslfull);
                continue;
            }
            sub_cert_len = (ntohl(*(uint32_t *)(payload + dpi[totalIndex[i]].dpacketCapt)) & 0xFFFFFF00)>>8;

            /* only continue if we have enough payload for the whole cert */
            if (dpi[totalIndex[i]].dpacketCapt + sub_cert_len > paySize) {
                sslfull->len = 0;
                sslfull->buf = NULL;
                sslfull = (fbVarfield_t*)fbBasicListGetNextPtr(&(fullrec->cert),sslfull);
                continue;
            }

            sslfull->buf = payload + dpi[totalIndex[i]].dpacketCapt + 3;
            sslfull->len = sub_cert_len;
            tot_bl_len += sub_cert_len;
            sslfull = (fbVarfield_t*)fbBasicListGetNextPtr(&(fullrec->cert),sslfull);
        }

        if (!tot_bl_len) {
            fbBasicListClear(&(fullrec->cert));
            sslfull = (fbVarfield_t*)fbBasicListInit(&(fullrec->cert), 3,
                                         fbInfoModelGetElementByName(model,
                                         "sslCertificate"), 0);
        }

        flowContext->full_ssl_cert = fullrec;

    }


    return (void *)rec;
}


void *ypProcessSSH(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfDPIContext_t *ctx = flowContext->yfctx;
    yfSSHFlow_t *rec = NULL;
    int start = flowContext->startOffset;
    fbVarfield_t *sshVar = NULL;
    fbBasicList_t *blist = NULL;
    ypBLValue_t *val;
    uint16_t temp_element;
    int loop, oloop;
    uint16_t total = 0;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];

    rec = (yfSSHFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                         YAF_SSH_FLOW_TID,
                                                         sshTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    ypInitializeBLs(ctx, &(rec->sshVersion), YAF_SSH_STANDARD, rulePos);

    for (oloop = 0; oloop < ctx->ruleSet[rulePos].numRules; oloop++) {
        temp_element = ctx->ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(ctx, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                sshVar = (fbVarfield_t *)fbBasicListInit(blist, 3,
                                                         val->infoElement,
                                                         total);
                ypFillBasicList(flow, dpi, total, fwdcap, &sshVar, totalIndex);
            }
            total = 0;
            sshVar = NULL;
        }
    }
    return (void *)rec;
}

void *ypProcessDNS(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t                   *dpi = flowContext->dpi;
    yfDNSFlow_t                   *rec = NULL;
    yfDNSQRFlow_t                 *dnsQRecord = NULL;
    uint8_t                       recCountFwd = 0;
    uint8_t                       recCountRev = 0;
    unsigned int                  buflen = 0;
    int                           count = flowContext->startOffset;

    flowContext->exbuf = yg_slice_alloc0(flowContext->yfctx->dpi_total_limit);

    rec = (yfDNSFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                         YAF_DNS_FLOW_TID,
                                                         dnsTemplate, 1);
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

    dnsQRecord = (yfDNSQRFlow_t *)fbSubTemplateListInit(&(rec->dnsQRList), 3,
                                                        YAF_DNSQR_FLOW_TID,
                                                        dnsQRTemplate,
                                                        recCountFwd +
                                                        recCountRev);
    if (!dnsQRecord) {
        g_debug("Error initializing SubTemplateList for DNS Resource "
                "Record with %d Templates", recCountFwd + recCountRev);
        return NULL;
    }

    if (flow->val.payload && recCountFwd) {
        ypDNSParser(&dnsQRecord, flow, &(flow->val),
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
            ypDNSParser(&dnsQRecord, flow, &(flow->val),
                        flowContext->exbuf, &buflen, recCountRev,
                        flowContext->yfctx->dpi_total_limit,
                        flowContext->yfctx->dnssec);
        } else {
            ypDNSParser(&dnsQRecord, flow, &(flow->rval),
                        flowContext->exbuf, &buflen, recCountRev,
                        flowContext->yfctx->dpi_total_limit,
                        flowContext->yfctx->dnssec);
        }
    }

    return (void *)rec;
}


void *ypProcessRTSP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t                  *dpi = flowContext->dpi;
    yfDPIContext_t               *ctx = flowContext->yfctx;
    yfRTSPFlow_t                 *rec = NULL;
    fbVarfield_t                 *rtspVar = NULL;
    fbBasicList_t                *blist;
    ypBLValue_t                  *val;
    uint8_t                      start = flowContext->startOffset;
    int                          total = 0;
    uint8_t                      totalIndex[YAF_MAX_CAPTURE_FIELDS];
    uint16_t                     temp_element;
    int                          loop, oloop;


    rec = (yfRTSPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_RTSP_FLOW_TID,
                                                          rtspTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    ypInitializeBLs(ctx, &(rec->rtspURL), YAF_RTSP_STANDARD, rulePos);

    for (oloop = 0; oloop < ctx->ruleSet[rulePos].numRules; oloop++) {
        temp_element = ctx->ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(ctx, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                rtspVar = (fbVarfield_t *)fbBasicListInit(blist, 3,
                                                          val->infoElement,
                                                          total);
                ypFillBasicList(flow, dpi, total, fwdcap,&rtspVar, totalIndex);
            }
            total = 0;
            rtspVar = NULL;
        }
    }
    return (void *)rec;
}

void *ypProcessMySQL(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{


    yfDPIData_t                  *dpi = flowContext->dpi;
    yfMySQLFlow_t                *rec = NULL;
    yfMySQLTxtFlow_t             *mysql = NULL;
    uint8_t                      count;
    uint8_t                      start = flowContext->startOffset;
    int                          total = 0;

    rec = (yfMySQLFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_MYSQL_FLOW_TID,
                                                          mysqlTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    count = start;
    while (count < totalcap) {
        if ((dpi[count].dpacketID != 223) && (dpi[count].dpacketID < 0x1d)) {
            total++;
        }
        count++;
    }

    mysql = (yfMySQLTxtFlow_t *)fbSubTemplateListInit(&(rec->mysqlList), 3,
                                                      YAF_MYSQLTXT_FLOW_TID,
                                                      mysqlTxtTemplate,
                                                      total);
    count = start;
    while (count < fwdcap && mysql) {
        /* MySQL Username */
        if (dpi[count].dpacketID == 223) {
            rec->mysqlUsername.buf = flow->val.payload +dpi[count].dpacketCapt;
            rec->mysqlUsername.len = dpi[count].dpacketCaptLen;
        } else {
            mysql->mysqlCommandCode = dpi[count].dpacketID;
            mysql->mysqlCommandText.buf = flow->val.payload +
                                          dpi[count].dpacketCapt;
            mysql->mysqlCommandText.len = dpi[count].dpacketCaptLen;
            mysql = fbSubTemplateListGetNextPtr(&(rec->mysqlList), mysql);
        }
        count++;
    }

    while (count < totalcap && mysql && flow->rval.payload) {
        /* MySQL Username */
        if (dpi[count].dpacketID == 223) {
            rec->mysqlUsername.buf =flow->rval.payload +dpi[count].dpacketCapt;
            rec->mysqlUsername.len = dpi[count].dpacketCaptLen;
        } else {
            mysql->mysqlCommandCode = dpi[count].dpacketID;
            mysql->mysqlCommandText.buf = flow->rval.payload +
                                          dpi[count].dpacketCapt;
            mysql->mysqlCommandText.len= dpi[count].dpacketCaptLen;
            mysql = fbSubTemplateListGetNextPtr(&(rec->mysqlList), mysql);
        }
        count++;
    }

    return (void *)rec;
}

void *ypProcessDNP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t                  *dpi = flowContext->dpi;
    yfDPIContext_t               *ctx = flowContext->yfctx;
    yfDNP3Flow_t                 *rec = (yfDNP3Flow_t *)flowContext->rec;
    yfDNP3Rec_t                  *dnp = NULL;
    uint8_t                      count;
    uint8_t                      start = flowContext->startOffset;
    uint8_t                      *crc_ptr;
    size_t                       crc_len;
    int                          total = 0;
    size_t                       total_len = 0;

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
        rec =(yfDNP3Flow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                             YAF_DNP3_FLOW_TID,
                                                             dnp3Template, 0);
        flowContext->dpinum = 0;
        return (void *)rec;
    }

    flowContext->exbuf = yg_slice_alloc0(flowContext->yfctx->dpi_total_limit);
    crc_ptr = flowContext->exbuf;

    rec = (yfDNP3Flow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_DNP3_FLOW_TID,
                                                          dnp3Template, 1);

    dnp = (yfDNP3Rec_t *)fbSubTemplateListInit(&(rec->dnp_list), 3,
                                              YAF_DNP3_REC_FLOW_TID,
                                              dnp3RecTemplate,
                                              total);
    count = start;
    while (count < fwdcap && dnp) {
        if (dpi[count].dpacketID == 284) {
            if (dpi[count].dpacketCaptLen <= crc_len) {
                dnp->object.buf = crc_ptr + dpi[count].dpacketCapt;
                dnp->object.len = dpi[count].dpacketCaptLen;
                crc_ptr += crc_len;
                total_len += crc_len;
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

void *ypProcessModbus(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t  *dpi = flowContext->dpi;
    fbVarfield_t *mbvar;
    yfModbusFlow_t *rec = NULL;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    int count = flowContext->startOffset;

    rec = (yfModbusFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_MODBUS_FLOW_TID,
                                                          modbusTemplate, 1);

    mbvar = (fbVarfield_t *)fbBasicListInit(&(rec->mbmsg), 3,
                             fbInfoModelGetElementByName(model, "modbusData"),
                                            totalcap);

    while (count < fwdcap && mbvar) {
        mbvar->buf = flow->val.payload + dpi[count].dpacketCapt;
        mbvar->len = dpi[count].dpacketCaptLen;
        mbvar = fbBasicListGetNextPtr(&(rec->mbmsg), mbvar);
        count++;

    }

    if (fwdcap < totalcap && flow->rval.payload) {
        while (count < totalcap && mbvar) {
            mbvar->buf = flow->rval.payload + dpi[count].dpacketCapt;
            mbvar->len = dpi[count].dpacketCaptLen;
            mbvar = fbBasicListGetNextPtr(&(rec->mbmsg), mbvar);
            count++;
        }
    }

    return (void *)rec;


}

void *ypProcessEnIP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t  *dpi = flowContext->dpi;
    fbVarfield_t *enipvar;
    yfEnIPFlow_t *rec = NULL;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    int count = flowContext->startOffset;

    rec = (yfEnIPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_ENIP_FLOW_TID,
                                                          enipTemplate, 1);

    enipvar = (fbVarfield_t *)fbBasicListInit(&(rec->enipmsg), 3,
                      fbInfoModelGetElementByName(model, "ethernetIPData"),
                                            totalcap);

    while (count < fwdcap && enipvar) {
        enipvar->buf = flow->val.payload + dpi[count].dpacketCapt;
        enipvar->len = dpi[count].dpacketCaptLen;
        enipvar = fbBasicListGetNextPtr(&(rec->enipmsg), enipvar);
        count++;

    }

    if (fwdcap < totalcap && flow->rval.payload) {
        while (count < totalcap && enipvar) {
            enipvar->buf = flow->rval.payload + dpi[count].dpacketCapt;
            enipvar->len = dpi[count].dpacketCaptLen;
            enipvar = fbBasicListGetNextPtr(&(rec->enipmsg), enipvar);
            count++;
        }
    }

    return (void *)rec;


}

void *ypProcessRTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t  *dpi = flowContext->dpi;
    yfRTPFlow_t *rec = NULL;
    int count = flowContext->startOffset;

    rec = (yfRTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                         YAF_RTP_FLOW_TID,
                                                         rtpTemplate, 1);
    rec->rtpPayloadType = dpi[0].dpacketCapt;
    if (count > 1) {
        rec->reverseRtpPayloadType = dpi[1].dpacketCapt;
    } else {
        rec->reverseRtpPayloadType = 0;
    }

    return (void *)rec;
}

void ypFillBasicList(
    yfFlow_t         *flow,
    yfDPIData_t      *dpi,
    uint8_t          totalCaptures,
    uint8_t          forwardCaptures,
    fbVarfield_t     **varField,
    uint8_t          *indexArray)
{
    int i;

    if (!(*varField)) {
        return;
    }

    for (i = 0; i < totalCaptures; i++) {
        if (indexArray[i] < forwardCaptures) {
            if ((dpi[indexArray[i]].dpacketCapt +
                 dpi[indexArray[i]].dpacketCaptLen) > flow->val.paylen) {
                continue;
            }
            if (flow->val.payload) {
                (*varField)->buf = flow->val.payload +
                    dpi[indexArray[i]].dpacketCapt;
                (*varField)->len = dpi[indexArray[i]].dpacketCaptLen;
            }
        } else {
            if ((dpi[indexArray[i]].dpacketCapt +
                 dpi[indexArray[i]].dpacketCaptLen) > flow->rval.paylen) {
                continue;
            }
            if (flow->rval.payload) {
                (*varField)->buf = flow->rval.payload +
                    dpi[indexArray[i]].dpacketCapt;
                (*varField)->len = dpi[indexArray[i]].dpacketCaptLen;
            }
        }

        if (i + 1 < totalCaptures) {
            (*varField)++;
        }
    }

}

void ypFreeSLPRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfSLPFlow_t *rec = (yfSLPFlow_t *)flowContext->rec;

    fbBasicListClear(&(rec->slpString));

}

void ypFreeIRCRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfIRCFlow_t *rec = (yfIRCFlow_t *)flowContext->rec;
    fbBasicListClear(&(rec->ircMsg));

}

void ypFreePOP3Rec(
    ypDPIFlowCtx_t *flowContext)
{

    yfPOP3Flow_t *rec = (yfPOP3Flow_t *)flowContext->rec;

    fbBasicListClear(&(rec->pop3msg));

}

void ypFreeTFTPRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfTFTPFlow_t *rec = (yfTFTPFlow_t *)flowContext->rec;
    (void) rec;
}

void ypFreeDNSRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfDNSFlow_t *rec = (yfDNSFlow_t *)flowContext->rec;
    yfDNSQRFlow_t *dns = NULL;

    while ((dns = fbSubTemplateListGetNextPtr(&(rec->dnsQRList), dns))) {
        fbSubTemplateListClear(&(dns->dnsRRList));
    }

    fbSubTemplateListClear(&(rec->dnsQRList));
}

void ypFreeDNPRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfDNP3Flow_t *dnp = (yfDNP3Flow_t *)flowContext->rec;

    if (flowContext->dpinum) {
        fbSubTemplateListClear(&(dnp->dnp_list));
    }

}

void ypFreeMySQLRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfMySQLFlow_t *rec = (yfMySQLFlow_t *)flowContext->rec;

    fbSubTemplateListClear(&(rec->mysqlList));
}

void ypFreeSSLRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfSSLFlow_t *rec = (yfSSLFlow_t *)flowContext->rec;
    yfSSLCertFlow_t *cert = NULL;
    yfSSLFullCert_t *fullrec = (yfSSLFullCert_t *)flowContext->full_ssl_cert;


    while ((cert = fbSubTemplateListGetNextPtr(&(rec->sslCertList), cert))) {
        fbSubTemplateListClear(&(cert->issuer));
        fbSubTemplateListClear(&(cert->subject));
        fbSubTemplateListClear(&(cert->extension));
    }

    fbSubTemplateListClear(&(rec->sslCertList));
    fbBasicListClear(&(rec->sslCipherList));

    if (fullrec) {
        fbBasicListClear(&(fullrec->cert));
    }

}

void ypFreeNNTPRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfNNTPFlow_t *rec = (yfNNTPFlow_t *)flowContext->rec;

    fbBasicListClear(&(rec->nntpResponse));
    fbBasicListClear(&(rec->nntpCommand));
}

void ypFreeModbusRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfModbusFlow_t *rec = (yfModbusFlow_t *)flowContext->rec;

    fbBasicListClear(&(rec->mbmsg));

}


void ypFreeEnIPRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfEnIPFlow_t *rec = (yfEnIPFlow_t *)flowContext->rec;

    fbBasicListClear(&(rec->enipmsg));

}

/**
 * ypGetDNSQName
 *
 * Does the DNS Name Compression Pointer Follow Game - returns the
 * length of the name
 *
 */
uint8_t ypGetDNSQName(
    uint8_t           *buf,
    uint16_t          bufoffset,
    uint8_t           *payload,
    unsigned int      payloadSize,
    uint16_t          *offset,
    uint16_t          export_limit)
{

    uint16_t          nameSize;
    uint16_t          toffset = *(offset);
    gboolean          pointer_flag = FALSE;
    int               pointer_depth = 0;
    uint8_t           temp_buf[DNS_MAX_NAME_LENGTH + 1];
    int               temp_buf_size = 0;

    while ( toffset < payloadSize ) {

        if ( 0 == *(payload + toffset) ) {
            if ( !pointer_flag ) {
                *offset += 1;
            }
            temp_buf[temp_buf_size] = '\0';
            toffset = 0;
            break;
        } else if (DNS_NAME_COMPRESSION ==
            (*(payload + toffset) & DNS_NAME_COMPRESSION))
        {
            if ( (toffset + 1) >= payloadSize ) {
                /*Incomplete Name Pointer */
                return 0;
            }
            toffset = ntohs(*((uint16_t *)(payload + toffset)));
            toffset = DNS_NAME_OFFSET & toffset;
            pointer_depth += 1;

            if ( pointer_depth > DNS_MAX_NAME_LENGTH ) {
                /* Too many pointers in DNS name */
                return 0;
            }

            if ( !pointer_flag ) {
                *offset += sizeof(uint16_t);
                pointer_flag = TRUE;
            }

            continue;

        } else {

            nameSize = *(payload + toffset);
            if ( (nameSize + temp_buf_size + 1) > DNS_MAX_NAME_LENGTH ) {
                /* DNS Name Too Long */
                return 0;
            }
            memcpy(temp_buf + temp_buf_size, (payload + toffset + 1),
                   nameSize);
            temp_buf[temp_buf_size + nameSize] = '.';
            temp_buf_size += nameSize + 1;
            if (!pointer_flag) {
                *offset += *(payload + toffset) + 1;
            }

            toffset += nameSize + 1;
        }
    }

    if (toffset >= payloadSize) {
        /*DNS Name outside payload */
        return 0;
    }

    if (bufoffset + temp_buf_size > export_limit) {
        /* Name too large to export in allowed buffer size*/
        return 0;
    }

    /* skip trailing '.' */
    memcpy(buf + bufoffset, temp_buf, temp_buf_size);
    bufoffset += temp_buf_size;

    return temp_buf_size;
}

void ypDNSParser(
    yfDNSQRFlow_t        **dnsQRecord,
    yfFlow_t             *flow,
    yfFlowVal_t          *val,
    uint8_t              *buf,
    unsigned int         *bufLen,
    uint8_t              recordCount,
    uint16_t             export_limit,
    gboolean             dnssec)
{

    ycDnsScanMessageHeader_t header;
    uint16_t                 payloadOffset = sizeof(ycDnsScanMessageHeader_t);
    uint16_t                 firstpkt = val->paylen;
    uint16_t                 msglen;
    size_t                   nameLen;
    uint8_t                  nxdomain = 0;
    unsigned int             bufSize = (*bufLen);
    uint16_t                 rrType;
    unsigned int             loop = 0;
    uint8_t                  *payload = val->payload;
    unsigned int             payloadSize = val->paylen;

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
#endif
    for (loop = 0; loop < header.qdcount; loop++) {
        nameLen = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                &payloadOffset, export_limit);
        if ((!header.qr || nxdomain)) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
            (*dnsQRecord)->dnsQName.len = nameLen;
            (*dnsQRecord)->dnsQName.buf = buf + bufSize;
            bufSize += (*dnsQRecord)->dnsQName.len;
            (*dnsQRecord)->dnsAuthoritative = header.aa;
            (*dnsQRecord)->dnsNXDomain = header.rcode;
            (*dnsQRecord)->dnsRRSection = 0;
            (*dnsQRecord)->dnsQueryResponse = header.qr;
            (*dnsQRecord)->dnsID = header.id;
            if ((payloadOffset + 2) < payloadSize) {
                (*dnsQRecord)->dnsQRType = ntohs(*((uint16_t *)(payload +
                                                        payloadOffset)));
            }

            recordCount--;
            if (recordCount) {
                (*dnsQRecord)++;
            } else {
                *bufLen = bufSize;
                return;
            }
        }

        payloadOffset += (sizeof(uint16_t) * 2);
        /* skip over class */
        if (payloadOffset > payloadSize) {
            goto err;
        }

    }

    for (loop = 0; loop < header.ancount; loop++) {
        (*dnsQRecord)->dnsRRSection = 1;
        (*dnsQRecord)->dnsAuthoritative = header.aa;
        (*dnsQRecord)->dnsNXDomain = header.rcode;
        (*dnsQRecord)->dnsQueryResponse = 1;
        (*dnsQRecord)->dnsID = header.id;
        rrType = ypDnsScanResourceRecord(dnsQRecord, payload, payloadSize,
                                         &payloadOffset, buf, &bufSize,
                                         export_limit, dnssec);

        if (rrType != 41) {
            recordCount--;
            if (recordCount) {
                (*dnsQRecord)++;
            } else {
                *bufLen = bufSize;
                return;
            }
        }

        if (payloadOffset > payloadSize) {
            goto err;
        }

        if (bufSize > export_limit) {
            bufSize = export_limit;
            goto err;
        }

    }

    for (loop = 0; loop < header.nscount; loop++) {
        (*dnsQRecord)->dnsRRSection = 2;
        (*dnsQRecord)->dnsAuthoritative = header.aa;
        (*dnsQRecord)->dnsNXDomain = header.rcode;
        (*dnsQRecord)->dnsQueryResponse = 1;
        (*dnsQRecord)->dnsID = header.id;
        rrType = ypDnsScanResourceRecord(dnsQRecord, payload, payloadSize,
                                         &payloadOffset, buf, &bufSize,
                                         export_limit, dnssec);

        if (rrType != 41) {
            recordCount--;
            if (recordCount) {
                (*dnsQRecord)++;
            } else {
                *bufLen = bufSize;
                return;
            }
        }

        if (payloadOffset > payloadSize) {
            goto err;
        }

        if (bufSize > export_limit) {
            bufSize = export_limit;
            goto err;
        }
    }

    for (loop = 0; loop < header.arcount; loop++) {
        (*dnsQRecord)->dnsRRSection = 3;
        (*dnsQRecord)->dnsAuthoritative = header.aa;
        (*dnsQRecord)->dnsNXDomain = header.rcode;
        (*dnsQRecord)->dnsQueryResponse = 1;
        (*dnsQRecord)->dnsID = header.id;
        rrType = ypDnsScanResourceRecord(dnsQRecord, payload, payloadSize,
                                         &payloadOffset, buf, &bufSize,
                                         export_limit, dnssec);

        if (rrType != 41) {
            recordCount--;
            if (recordCount) {
                (*dnsQRecord)++;
            } else {
                *bufLen = bufSize;
                return;
            }
        }

        if (payloadOffset > payloadSize) {
            goto err;
        }


        if (bufSize > export_limit) {
            bufSize = export_limit;
            goto err;
        }
    }

    *bufLen = bufSize;

    return;

err:
    *bufLen = bufSize;
    /* something went wrong so we need to pad the rest of the STL with NULLs */
    /* Most likely we ran out of space in the DNS Export Buffer */
    while (recordCount) {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,YAF_DNSA_FLOW_TID,
                              dnsATemplate, 0);
        recordCount--;
        if (recordCount) (*dnsQRecord)++;
    }

    return;
}

static
uint16_t ypDnsScanResourceRecord(
    yfDNSQRFlow_t                **dnsQRecord,
    uint8_t                      *payload,
    unsigned int                 payloadSize,
    uint16_t                     *offset,
    uint8_t                      *buf,
    unsigned int                 *bufLen,
    uint16_t                     export_limit,
    gboolean                     dnssec)
{

    uint16_t                    nameLen;
    uint16_t                    rrLen;
    uint16_t                    rrType;
    uint16_t                    temp_offset;
    uint16_t                    bufSize = (*bufLen);

    nameLen = ypGetDNSQName(buf, bufSize, payload, payloadSize, offset,
                            export_limit);
    (*dnsQRecord)->dnsQName.len = nameLen;
    (*dnsQRecord)->dnsQName.buf = buf + bufSize;
    bufSize += (*dnsQRecord)->dnsQName.len;

    rrType = ntohs(*((uint16_t *)(payload + (*offset))));
    (*dnsQRecord)->dnsQRType = rrType;

    /* skip class */
    *offset += (sizeof(uint16_t) * 2 );

    /* time to live */
    (*dnsQRecord)->dnsTTL = ntohl(*((uint32_t *)(payload + (*offset))));
    *offset += sizeof(uint32_t);

    if (*offset >= payloadSize) {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                              YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        return rrType;
    }

    rrLen = ntohs(*(uint16_t *)(payload + (*offset)));
    /* past length field */
    *offset += sizeof(uint16_t);

    if (*offset >= payloadSize) {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                              YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        return rrType;
    }

    temp_offset = (*offset);

    if (rrType == 1) {
        yfDNSAFlow_t *arecord = (yfDNSAFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSA_FLOW_TID, dnsATemplate, 1);
        arecord->ip = ntohl(*((uint32_t *)(payload + temp_offset)));

    } else if (rrType == 2) {
        yfDNSNSFlow_t *nsrecord = (yfDNSNSFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSNS_FLOW_TID, dnsNSTemplate, 1);
        nsrecord->nsdname.len = ypGetDNSQName(buf, bufSize, payload,
                                              payloadSize, &temp_offset,
                                              export_limit);
        nsrecord->nsdname.buf = buf + bufSize;
        bufSize += nsrecord->nsdname.len;

    } else if (rrType == 5) {
        yfDNSCNameFlow_t *cname = (yfDNSCNameFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSCN_FLOW_TID, dnsCNTemplate, 1);
        cname->cname.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                         &temp_offset,
                                         export_limit);
        cname->cname.buf = buf + bufSize;
        bufSize += cname->cname.len;

    } else if (rrType == 12) {
        yfDNSPTRFlow_t *ptr = (yfDNSPTRFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSPTR_FLOW_TID, dnsPTRTemplate, 1);
        ptr->ptrdname.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                          &temp_offset,
                                          export_limit);
        ptr->ptrdname.buf = buf + bufSize;
        bufSize += ptr->ptrdname.len;

    } else if (rrType == 15) {
        yfDNSMXFlow_t *mx = (yfDNSMXFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSMX_FLOW_TID, dnsMXTemplate, 1);
        mx->preference = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);
        if (temp_offset > payloadSize) {
            mx->exchange.len = 0;
            return rrType;
        }
        mx->exchange.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                         &temp_offset, export_limit);
        mx->exchange.buf = buf + bufSize;
        bufSize += mx->exchange.len;

    } else if (rrType == 16) {
        yfDNSTXTFlow_t *txt = (yfDNSTXTFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSTXT_FLOW_TID, dnsTXTTemplate, 1);
        txt->txt_data.len = *(payload + temp_offset);
        if (txt->txt_data.len + bufSize > export_limit) {
            temp_offset += txt->txt_data.len + 1;
            txt->txt_data.len = 0;
        } else {
            temp_offset++;
            txt->txt_data.buf = payload + temp_offset;
            bufSize += txt->txt_data.len;
            temp_offset += txt->txt_data.len;
        }

    } else if (rrType == 28) {
        yfDNSAAAAFlow_t *aa = (yfDNSAAAAFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSAAAA_FLOW_TID, dnsAAAATemplate, 1);
        memcpy(aa->ip, (payload + temp_offset), sizeof(aa->ip));

    } else if (rrType == 6) {
        yfDNSSOAFlow_t *soa = (yfDNSSOAFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSSOA_FLOW_TID, dnsSOATemplate, 1);
        soa->mname.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                       &temp_offset, export_limit);
        soa->mname.buf = buf + bufSize;
        bufSize += soa->mname.len;

        if (temp_offset > payloadSize) {
            soa->rname.len = 0;
            return rrType;
        }
        soa->rname.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                       &temp_offset, export_limit);
        soa->rname.buf = buf + bufSize;
        bufSize += soa->rname.len;
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        soa->serial = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        soa->refresh = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        soa->retry = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        soa->expire = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        soa->minimum = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }

    } else if (rrType == 33) {
        yfDNSSRVFlow_t *srv = (yfDNSSRVFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSSRV_FLOW_TID, dnsSRVTemplate, 1);
        srv->dnsPriority = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        srv->dnsWeight = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        srv->dnsPort = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        srv->dnsTarget.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                           &temp_offset, export_limit);
        srv->dnsTarget.buf = buf + bufSize;
        bufSize += srv->dnsTarget.len;
        if (temp_offset >= payloadSize) {
            return rrType;
        }

    } else if (rrType == 43) {
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSDSFlow_t *ds = NULL;
            ds =(yfDNSDSFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSDS_FLOW_TID, dnsDSTemplate, 1);
            ds->dnsKeyTag = ntohs(*((uint16_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint16_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            ds->dnsAlgorithm = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset >= payloadSize) {
                return rrType;
            }
            ds->dnsDigestType = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset >= payloadSize) {
                return rrType;
            }
            /* length of rrdata is rrLen - we know these 3 fields */
            /* should add up to 4 - so rest is digest */
            if ((temp_offset + (rrLen - 4)) >= payloadSize) {
                return rrType;
            }

            ds->dnsDigest.buf = payload + temp_offset;
            ds->dnsDigest.len = rrLen - 4;
        }
    } else if (rrType == 46) {
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSRRSigFlow_t *rrsig = NULL;
            rrsig = (yfDNSRRSigFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3, YAF_DNSRRSIG_FLOW_TID, dnsRRSigTemplate, 1);

            rrsig->dnsTypeCovered = ntohs(*((uint16_t *)(payload +
                                                         temp_offset)));
            temp_offset += sizeof(uint16_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsAlgorithm = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsLabels = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsTTL = ntohl(*((uint32_t *)(payload + temp_offset)));

            temp_offset += sizeof(uint32_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsSigExp = ntohl(*((uint32_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint32_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsSigInception = ntohl(*((uint32_t *)(payload +
                                                          temp_offset)));
            temp_offset += sizeof(uint32_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsKeyTag = ntohs(*((uint16_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint16_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsSigner.len = ypGetDNSQName(buf, bufSize, payload,
                                                 payloadSize, &temp_offset,
                                                 export_limit);
            rrsig->dnsSigner.buf = buf + bufSize;
            bufSize += rrsig->dnsSigner.len;

            /* signature is at offset 18 + signer's name len */
            if ((temp_offset + (rrLen - 18 + rrsig->dnsSigner.len)) >=
                payloadSize)
            {
                return rrType;
            }
            rrsig->dnsSignature.buf = payload + temp_offset;
            rrsig->dnsSignature.len = (rrLen - 18 - rrsig->dnsSigner.len);
        }
    } else if (rrType == 47) {
        /* NSEC */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSNSECFlow_t *nsec = NULL;
            nsec = (yfDNSNSECFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList),
                                                            3, YAF_DNSNSEC_FLOW_TID, dnsNSECTemplate, 1);
            nsec->dnsHashData.len = ypGetDNSQName(buf, bufSize, payload,
                                                  payloadSize, &temp_offset,
                                                  export_limit);
            nsec->dnsHashData.buf = buf + bufSize;
            bufSize += nsec->dnsHashData.len;
            /* subtract next domain name and add record len. forget bitmaps. */
            temp_offset = temp_offset - nsec->dnsHashData.len + rrLen;
        }
    } else if (rrType == 48) {
        /* DNSKEY RR */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSKeyFlow_t *dnskey = NULL;
            dnskey = (yfDNSKeyFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList),
                                                             3, YAF_DNSKEY_FLOW_TID, dnsKeyTemplate, 1);
            dnskey->dnsFlags = ntohs(*((uint16_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint16_t);

            if (temp_offset >= payloadSize) {
                return rrType;
            }
            dnskey->protocol = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset >= payloadSize) {
                return rrType;
            }
            dnskey->dnsAlgorithm = *(payload + temp_offset);
            temp_offset++;

            if ((temp_offset - 4 + rrLen) >= payloadSize) {
                return rrType;
            } else {
                dnskey->dnsPublicKey.buf = payload + temp_offset;
                dnskey->dnsPublicKey.len = rrLen - 4;
            }
        }
    } else if (rrType == 50 || rrType == 51) {
        /* NSEC3(PARAM)? */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            uint16_t off_hold = temp_offset;
            yfDNSNSEC3Flow_t *nsec3 = NULL;
            nsec3 = (yfDNSNSEC3Flow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList),
                                                              3, YAF_DNSNSEC3_FLOW_TID, dnsNSEC3Template, 1);
            nsec3->dnsAlgorithm = *(payload + temp_offset);

            /* skip over flags */
            temp_offset += sizeof(uint16_t);

            if (temp_offset >= payloadSize) {
                return rrType;
            }

            nsec3->iterations = ntohs(*((uint16_t *)(payload + temp_offset)));

            temp_offset += sizeof(uint16_t);

            if (temp_offset >= payloadSize) {
                return rrType;
            }

            nsec3->dnsSalt.len = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset + nsec3->dnsSalt.len >= payloadSize) {
                nsec3->dnsSalt.len = 0;
                return rrType;
            }
            nsec3->dnsSalt.buf = payload + temp_offset;
            temp_offset += nsec3->dnsSalt.len;

            if (rrType == 50) {
                nsec3->dnsNextDomainName.len = *(payload + temp_offset);
                temp_offset++;
                if (temp_offset + nsec3->dnsNextDomainName.len >= payloadSize)
                {
                    nsec3->dnsNextDomainName.len = 0;
                    return rrType;
                }
                nsec3->dnsNextDomainName.buf = payload + temp_offset;
                temp_offset = off_hold + rrLen;
            }
        }
    } else {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 3,
                              YAF_DNSA_FLOW_TID, dnsATemplate, 0);
    }

    *offset += rrLen;

    *bufLen = bufSize;
    return rrType;
}


uint16_t ypDecodeLength(
    uint8_t           *payload,
    uint16_t          *offset)
{
    uint16_t          obj_len;

    obj_len = *(payload + *offset);
    if (obj_len == CERT_1BYTE) {
        (*offset)++;
        obj_len = *(payload + *offset);
    } else if (obj_len == CERT_2BYTE) {
        (*offset)++;
        obj_len = ntohs(*(uint16_t *)(payload + *offset));
        (*offset)++;
    }

    return obj_len;
}

uint16_t ypDecodeTLV(
    yf_asn_tlv_t      *tlv,
    uint8_t           *payload,
    uint16_t          *offset)
{
    uint8_t            val = *(payload + *offset);
    uint16_t           len = 0;

    tlv->class = (val & 0xD0) >> 6;
    tlv->p_c = (val & 0x20) >> 5;
    tlv->tag = (val & 0x1F);

    (*offset)++;

    len = ypDecodeLength(payload, offset);
    (*offset)++;

    if (tlv->tag == CERT_NULL) {
        *offset += len;
        return ypDecodeTLV(tlv, payload, offset);
    }

    return len;

}

gboolean ypDecodeOID(
    uint8_t         *payload,
    uint16_t        *offset,
    uint8_t         obj_len)
{
    uint32_t tobjid;

    if (obj_len == 9) {
        /* pkcs-9 */
        tobjid = ntohl(*(uint32_t *)(payload + *offset));
        if (tobjid != CERT_PKCS) {
            return FALSE;
        }
        *offset += 8;
    } else if (obj_len == 10) {
        /* LDAP Domain Component */
        tobjid = ntohl(*(uint32_t *)(payload + *offset));
        if (tobjid != CERT_DC) {
            return FALSE;
        }
        *offset += 9;
    } else if (obj_len == 3) {
        *offset += 2;
    } else {
        /* this isn't the usual id-at, pkcs, or dc - so lets ignore it */
        return FALSE;
    }

    return TRUE;
}


uint8_t ypGetSequenceCount(
    uint8_t          *payload,
    uint16_t         seq_len)
{
    uint16_t         offsetptr = 0;
    uint16_t         len = 0;
    uint16_t         obj_len;
    uint8_t          count = 0;
    yf_asn_tlv_t     tlv;

    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    while (tlv.tag == CERT_SET && len < seq_len) {
        len += obj_len + 2;
        count++;
        offsetptr += obj_len;
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    }

    return count;
}

uint8_t ypGetExtensionCount(
    uint8_t                *payload,
    uint16_t                ext_len)
{

    uint16_t               offsetptr = 0;
    yf_asn_tlv_t           tlv;
    uint16_t               len = 2;
    uint16_t               obj_len = 0;
    uint16_t               id_ce;
    uint8_t                obj_type = 0;
    uint8_t                count = 0;

    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    while (tlv.tag == CERT_SEQ && len < ext_len) {
        len += obj_len + 2;
        if (*(payload + offsetptr) == CERT_OID) {
            id_ce = ntohs(*(uint16_t *)(payload + offsetptr + 2));
            if (id_ce == CERT_IDCE) {
                obj_type = *(payload + offsetptr + 4);
                switch (obj_type) {
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
                  default:
                    break;
                }
            }
        }
        offsetptr += obj_len;
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    }

    return count;
}




gboolean ypDecodeSSLCertificate(
    yfDPIContext_t          *ctx,
    yfSSLCertFlow_t         **sslCert,
    uint8_t                 *payload,
    unsigned int            payloadSize,
    yfFlow_t                *flow,
    uint16_t                offsetptr)
{
    uint32_t                sub_cert_len;
    uint16_t                tot_ext_len = 0;
    uint16_t                ext_hold = 0;
    uint8_t                 seq_count;
    uint8_t                 obj_type = 0;
    yf_asn_tlv_t            tlv;
    yfSSLObjValue_t         *sslObject = NULL;
    uint16_t                obj_len;
    uint16_t                set_len;
    uint16_t                off_hold;
    uint16_t                id_ce;

    /* we should start with the length of inner cert */
    if (offsetptr + 5 > payloadSize) {
        return FALSE;
    }

    sub_cert_len = (ntohl(*(uint32_t *)(payload + offsetptr)) & 0xFFFFFF00)>>8;

    /* only continue if we have enough payload for the whole cert */
    if (offsetptr + sub_cert_len > payloadSize) {
        return FALSE;
    }

    offsetptr += 3;
    /* this is a CERT which is a sequence with length > 0x7F [0x30 0x82]*/

    (*sslCert)->hash.len = 0;

    if (ntohs(*(uint16_t *)(payload + offsetptr)) != 0x3082) {
        return FALSE;
    }

    /* 2 bytes for above, 2 for length of CERT */
    /* Next we have a signed CERT so 0x3082 + length */

    offsetptr += 8;

    /* A0 is for explicit tagging of Version Number */
    /* 03 is an Integer - 02 is length, 01 is for tagging */
    if (*(payload + offsetptr) == CERT_EXPLICIT) {
        offsetptr += 4;
        (*sslCert)->version = *(payload + offsetptr);
        offsetptr++;
    } else {
        /* default version is version 1 [0] */
        (*sslCert)->version = 0;
    }

    /* serial number */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len > sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag == CERT_INT) {
        (*sslCert)->serial.buf = payload + offsetptr;
        (*sslCert)->serial.len = obj_len;
    }
    offsetptr += obj_len;

    /* signature */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len > sub_cert_len) {
        return FALSE;
    }

    if (tlv.tag != CERT_SEQ) {
        offsetptr += obj_len;
    } else {
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (tlv.tag == CERT_OID) {
            if (obj_len > sub_cert_len) {
                return FALSE;
            }
            (*sslCert)->sig.buf = payload + offsetptr;
            (*sslCert)->sig.len = obj_len;
        }
        offsetptr += obj_len;
    }

    /* issuer - sequence */

    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len > sub_cert_len) {
        return FALSE;
    }

    if (tlv.tag == CERT_SEQ) {
        seq_count = ypGetSequenceCount((payload + offsetptr), obj_len);
    } else {
        return FALSE;
    }

    sslObject = (yfSSLObjValue_t *)fbSubTemplateListInit(&((*sslCert)->issuer),
                                                         3,
                                                      YAF_SSL_SUBCERT_FLOW_TID,
                                                         sslSubTemplate,
                                                         seq_count);
    while (seq_count && sslObject) {
        set_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (set_len >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SET) {
            break;
        }
        off_hold = offsetptr;
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SEQ) {
            break;
        }
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }

        if (tlv.tag != CERT_OID) {
            break;
        }

        if (!ypDecodeOID(payload, &offsetptr, obj_len)) {
            sslObject++;
            seq_count--;
            offsetptr = off_hold + set_len;
            continue;
        }

        sslObject->obj_id = *(payload + offsetptr);
        offsetptr += 2;
        sslObject->obj_value.len = ypDecodeLength(payload, &offsetptr);
        if (sslObject->obj_value.len >= sub_cert_len) {
            sslObject->obj_value.len = 0;
            return FALSE;
        }
        offsetptr++;
        /* OBJ VALUE */
        sslObject->obj_value.buf = payload + offsetptr;
        offsetptr += sslObject->obj_value.len;
        seq_count--;
        sslObject++;
    }

    /* VALIDITY is a sequence of times */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        return FALSE;
    }

    /* notBefore time */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_TIME) {
        return FALSE;
    }
    (*sslCert)->not_before.buf = payload + offsetptr;
    (*sslCert)->not_before.len = obj_len;

    offsetptr += obj_len;

    /* not After time */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_TIME) {
        return FALSE;
    }
    (*sslCert)->not_after.buf = payload + offsetptr;
    (*sslCert)->not_after.len = obj_len;

    offsetptr += obj_len;

    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }

    /* subject - sequence */
    if (tlv.tag == CERT_SEQ) {
        seq_count = ypGetSequenceCount((payload + offsetptr), obj_len);
    } else {
        return FALSE;
    }

    sslObject = (yfSSLObjValue_t *)fbSubTemplateListInit(&((*sslCert)->subject), 3,
                                                         YAF_SSL_SUBCERT_FLOW_TID,
                                                         sslSubTemplate,
                                                         seq_count);

    while (seq_count && sslObject) {
        set_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (set_len >= sub_cert_len) {
            return FALSE;
        }
        off_hold = offsetptr;
        if (tlv.tag != CERT_SET) {
            break;
        }
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }

        if (tlv.tag != CERT_SEQ) {
            break;
        }
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_OID) {
            break;
        }

        if (!ypDecodeOID(payload, &offsetptr, obj_len)) {
            sslObject++;
            seq_count--;
            offsetptr = off_hold + set_len;
            continue;
        }

        sslObject->obj_id = *(payload + offsetptr);
        offsetptr += 2;
        sslObject->obj_value.len = ypDecodeLength(payload, &offsetptr);
        if (sslObject->obj_value.len >= sub_cert_len) {
            sslObject->obj_value.len = 0;
            return FALSE;
        }
        offsetptr++;
        /* OBJ VALUE */
        sslObject->obj_value.buf = payload + offsetptr;
        offsetptr += sslObject->obj_value.len;
        seq_count--;
        sslObject++;
    }

    /* subject public key info */
    /* this is a sequence of a sequence of algorithms and public key */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }
    /* this needs to be a sequence */
    if (tlv.tag != CERT_SEQ) {
        offsetptr += obj_len;
    } else {
        /* this is also a seq */
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SEQ) {
            offsetptr += obj_len;
        } else {
            obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (obj_len >= sub_cert_len) {
                return FALSE;
            }
            /* this is the algorithm id */
            if (tlv.tag == CERT_OID) {
                (*sslCert)->pkalg.buf = payload + offsetptr;
                (*sslCert)->pkalg.len = obj_len;
            }
            offsetptr += obj_len;
            obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (obj_len >= sub_cert_len) {
                return FALSE;
            }
            /* this is the actual public key */
            if (tlv.tag == CERT_BITSTR) {
                (*sslCert)->pklen = obj_len;
            }
            offsetptr += obj_len;
        }
    }

    /* EXTENSIONS! - ONLY AVAILABLE FOR VERSION 3 */
    /* since it's optional - it has a tag if it's here */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }

    if ((tlv.class != 2) || ((*sslCert)->version != 2)) {
        /* no extensions */
        ext_hold = offsetptr;
        fbSubTemplateListInit(&((*sslCert)->extension), 3,
                              YAF_SSL_SUBCERT_FLOW_TID, sslSubTemplate, 0);
    } else {
        uint16_t ext_len;
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        tot_ext_len = obj_len;
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }

        ext_hold = offsetptr;

        if (tlv.tag == CERT_SEQ) {
            seq_count = ypGetExtensionCount((payload + offsetptr), obj_len);
        } else {
            return FALSE;
        }
        /* extensions */
        sslObject =
            (yfSSLObjValue_t *)fbSubTemplateListInit(&((*sslCert)->extension),
                                                     3,
                                                     YAF_SSL_SUBCERT_FLOW_TID,
                                                     sslSubTemplate,
                                                     seq_count);
        /* exts is a sequence of a sequence of {id, critical flag, value} */
        while (seq_count && sslObject) {
            ext_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (ext_len >= sub_cert_len) {
                return FALSE;
            }

            if (tlv.tag != CERT_SEQ) {
                return FALSE;
            }

            off_hold = offsetptr;
            obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (obj_len >= ext_len) {
                return FALSE;
            }

            if (tlv.tag != CERT_OID) {
                return FALSE;
            }

            id_ce = ntohs(*(uint16_t *)(payload + offsetptr));
            if (id_ce != CERT_IDCE) {
                /* jump past this */
                offsetptr = off_hold + ext_len;
                continue;
            }
            offsetptr += 2;
            obj_type = *(payload + offsetptr);
            offsetptr++;
            obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (obj_len >= ext_len) {
                return FALSE;
            }
            if (tlv.tag == CERT_BOOL) {
                /* this is optional CRITICAL flag */
                offsetptr += obj_len;
                obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
                if (obj_len >= ext_len) {
                    return FALSE;
                }
            }
            switch (obj_type) {
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
                sslObject->obj_id = obj_type;
                sslObject->obj_value.len = obj_len;
                sslObject->obj_value.buf = payload + offsetptr;
                offsetptr += obj_len;
                seq_count--;
                sslObject++;
                break;
              default:
                offsetptr = off_hold + ext_len;
                continue;
            }
        }
    }

    if (ctx->cert_hash_export) {
        /* signature again */
        offsetptr = ext_hold + tot_ext_len;
        if (offsetptr > payloadSize) {
            return TRUE;
        }
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len > sub_cert_len) {
            return TRUE;
        }

        if (tlv.tag == CERT_SEQ) {
            obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (tlv.tag != CERT_OID) {
                return TRUE;
            }

            offsetptr += obj_len;
            if (offsetptr > payloadSize) {
                return TRUE;
            }
            obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            /*get past padding */
            offsetptr++;
            if ((offsetptr + obj_len) > payloadSize) {
                return TRUE;
            }
            if (tlv.tag != CERT_BITSTR) {
                return TRUE;
            }
            if ((obj_len-1) % 16) {
                return TRUE;
            }
            (*sslCert)->hash.len = obj_len - 1;
            (*sslCert)->hash.buf = payload + offsetptr;
        }
    }

    return TRUE;

}

#endif
#endif
