/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  dhcp_fp_plugin.c
 *
 *  Provides a plugin to inspect dhcp payloads and use the fingerbank.org
 *  DHCP fingerprints to identify what OS or device originated the flow.
 *  see www.fingerbank.org/signatures.html to download signature file:
 *  dhcp_fingerprints.conf
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
#include <yaf/autoinc.h>

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
#endif /* STDC_HEADERS */

#if YAF_ENABLE_HOOKS
#include <ctype.h>

/**glib, we use the hash and the error string stuff */
#include <glib.h>
#include <glib/gstdio.h>

#if YAF_ENABLE_APPLABEL

/** we obviously need some yaf details -- we're a plugin to it afterall! */
#include <yaf/yafhooks.h>

#include "../../../infomodel/yaf_dhcp.i"

/* fixbuf 2.x uses char* as the type of the name of info elements in
 * fbInfoElementSpec_t; wrap this around string literals to quiet compiler
 * warnings */
#define C(String) (char *)String


#define DHCP_APPLABEL           67
#define MAGICCOOKIE             0x63825363
#define YAF_DHCP_FLOW_TID       0xC201
#define YAF_DHCP_OP_TID         0xC208
#define MAX_LINE                1024
#define MAX_NAME                256
#define DHCP_REV                0x10
#define FINGERPRINT             "fingerprints"
#define VENDOR                  "vendor_id"
#define OS                      "description"


static struct yfHookMetaData metaData = {
    6,
    256,
    1
};

static fbInfoElementSpec_t   yaf_dhcp_fp_spec[] = {
    {C("dhcpFingerPrint"),           FB_IE_VARLEN, 0 },
    {C("dhcpVendorCode"),            FB_IE_VARLEN, 0 },
    {C("reverseDhcpFingerPrint"),    FB_IE_VARLEN, DHCP_REV },
    {C("reverseDhcpVendorCode"),     FB_IE_VARLEN, DHCP_REV },
    FB_IESPEC_NULL
};

static fbInfoElementSpec_t   yaf_dhcp_options_spec[] = {
    {C("basicList"),                 FB_IE_VARLEN, 0 },
    {C("dhcpVendorCode"),            FB_IE_VARLEN, 0 },
    {C("basicList"),                 FB_IE_VARLEN, DHCP_REV},
    {C("reverseDhcpVendorCode"),     FB_IE_VARLEN, DHCP_REV },
    FB_IESPEC_NULL
};

typedef struct yfDHCP_FP_Flow_st {
    fbVarfield_t   dhcpFP;
    fbVarfield_t   dhcpVC;
    fbVarfield_t   reverseDhcpFP;
    fbVarfield_t   reverseDhcpVC;
} yfDHCP_FP_Flow_t;

typedef struct yfDHCP_OP_Flow_st {
    fbBasicList_t   options;
    fbVarfield_t    dhcpVC;
    fbBasicList_t   revOptions;
    fbVarfield_t    reverseDhcpVC;
} yfDHCP_OP_Flow_t;

static fbTemplate_t *dhcpTemplate;
static fbTemplate_t *revDhcpTemplate;
static fbTemplate_t *dhcpOpTemplate;
static fbTemplate_t *revDhcpOpTemplate;

typedef struct ypDHCPFlowValCtx_st {
    char     *fp;
    size_t    fplen;
    uint8_t  *vc;
    size_t    vclen;
    uint8_t   options[256];
    uint8_t   count;
} ypDHCPFlowValCtx_t;


typedef struct dhcpFingerPrint_st {
    char     *desc;
    uint8_t   options[256];
} dhcpFingerPrint_t;

typedef struct dhcpOptions_st dhcpOptions_t;

struct dhcpOptions_st {
    dhcpOptions_t      *next;
    dhcpFingerPrint_t   fp;
};

typedef struct dhcpList_st {
    dhcpOptions_t  *head;
    int             count;
} dhcpList_t;

/*static dhcpList_t opList[256];
 * static int dhcpInitialized = 0;
 * static char *dhcp_fp_FileName = NULL;*/
static gboolean dhcp_uniflow_gl = FALSE;
static gboolean options_global = FALSE;

typedef struct yfDHCPContext_st {
    int          dhcpInitialized;
    gboolean     dhcp_uniflow;
    gboolean     export_options;
    char        *dhcp_fp_FileName;
    dhcpList_t   opList[256];
} yfDHCPContext_t;

typedef struct ypDHCPFlowCtx_st {
    ypDHCPFlowValCtx_t   val;
    ypDHCPFlowValCtx_t   rval;
    yfDHCP_OP_Flow_t    *rec;
    yfDHCPContext_t     *yfctx;
} ypDHCPFlowCtx_t;



/**
 *
 *
 */
#ifdef NDEBUG
#define assert(x)
#else
#define assert(x)                                                           \
    if (!(x)) {                                                             \
        fprintf(stderr, "assertion failed: \"%s\" at line %d of file %s\n", \
                # x, __LINE__, __FILE__); abort();                          \
    }
#endif /* ifdef NDEBUG */

#if YAF_ENABLE_METADATA_EXPORT
#define YF_fbSessionAddTemplate(_sess, _inex, _tid, _tmpl, _name, _desc, _err) \
    fbSessionAddTemplateWithMetadata(                                          \
        _sess, _inex, _tid, _tmpl, _name, _desc, _err)
#else
#define YF_fbSessionAddTemplate(_sess, _inex, _tid, _tmpl, _name, _desc, _err) \
    fbSessionAddTemplate(_sess, _inex, _tid, _tmpl, _err)
#endif /* if YAF_ENABLE_METADATA_EXPORT */


/**
 * flowAlloc
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
    ypDHCPFlowCtx_t *flowContext = NULL;

    flowContext = (ypDHCPFlowCtx_t *)g_slice_alloc0(sizeof(ypDHCPFlowCtx_t));

    flowContext->yfctx = yfctx;

    *yfHookContext = (void *)flowContext;
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
ypGetDHCPInfoModel(
    void)
{
    static fbInfoModel_t *yaf_dhcp_model = NULL;
    if (!yaf_dhcp_model) {
        yaf_dhcp_model = fbInfoModelAlloc();
        fbInfoModelAddElementArray(yaf_dhcp_model,
                                   infomodel_array_static_yaf_dhcp);
    }

    return yaf_dhcp_model;
}


/**
 * attachInOrderToSLL
 *
 * attaches the list of options to the single linked list.
 * in order by first options number
 *
 */
static void
attachInOrderToSLL(
    dhcpList_t     *list,
    dhcpOptions_t  *newEntry)
{
    dhcpOptions_t *next = list->head;
    dhcpOptions_t *prev = NULL;

    if (next == NULL) {
        list->head = newEntry;
    } else if (newEntry->fp.options[0] < next->fp.options[0]) {
        newEntry->next = next;
        list->head = newEntry;
    } else {
        while (next) {
            if (next->fp.options[0] > newEntry->fp.options[0]) {
                newEntry->next = next;
                prev->next = newEntry;
                break;
            } else if (next->next == NULL) {
                newEntry->next = NULL;
                next->next = newEntry;
                break;
            }
            prev = next;
            next = next->next;
        }
    }

    list->count += 1;
}


/**
 * parse_name_val
 *
 * parses an ini config file.
 *
 */
static void
parse_name_val(
    yfDHCPContext_t  *ctx,
    char             *name,
    char             *value)
{
    static char   *os_name = NULL;
    dhcpOptions_t *new_op = NULL;

    if (strcmp(name, VENDOR) == 0) {
        /* don't care at this point */
        return;
    } else if (strcmp(name, OS) == 0) {
        os_name = g_strdup(value);
        return;
    }

    if (strcmp(name, FINGERPRINT) == 0) {
        int     n = 0;
        gchar **f = g_strsplit(value, ",", -1);

        new_op = g_new0(dhcpOptions_t, 1);
        new_op->fp.desc = os_name;

        while (f[n] && *f[n]) {
            new_op->fp.options[n] = (uint8_t)atoi(f[n]);
            n++;
        }

        g_strfreev(f);
        attachInOrderToSLL(&(ctx->opList[n]), new_op);
    }
}


/**
 * ini_parse
 *
 * parse an ini-style config file
 *
 */
static int
ini_parse(
    yfDHCPContext_t  *ctx,
    FILE             *file)
{
    char     line[MAX_LINE];
    char     section[MAX_NAME] =  "";
    char     prev_name[MAX_NAME] = "";
    char    *start;
    char    *end;
    char    *name;
    char    *comment;
    char    *value;
    int      lineno = 0;
    int      error = 0;
    gboolean multiline = FALSE;

    while (fgets(line, sizeof(line), file) != NULL) {
        lineno++;
        start = g_strchomp(g_strchug(line));

        if (*start == ';' || *start == '#') {
            continue;
        } else if (*prev_name && *start && multiline) {
            if (strcmp(start, "EOT") == 0) {
                multiline = FALSE;
                continue;
            } else {
                parse_name_val(ctx, prev_name, start);
            }
            /* call something */
        } else if (*start == '[') {
            /* a new section */
            comment = strstr(start + 1, ";");
            end = strstr(start + 1, "]");
            if (comment) {
                if (comment > end) {
                    continue;
                }
            }
            if (end) {
                *end = '\0';
                strcpy(section, start + 1);
            }
        } else if (*start) {
            comment = strstr(start, ";");
            end = strstr(start, "=");
            if (!end) {
                end = strstr(start, ":");
            }
            if (!end) {
                continue;
            }
            if (comment) {
                if (comment > end) {
                    continue;
                }
            }
            *end = '\0';
            name = g_strchomp(start);
            value = g_strchug(end + 1);
            end = strstr(end, ";");
            if (end) {
                *end = '\0';
            }
            g_strchomp(value);
            strcpy(prev_name, name);
            if (strcmp(value, "<<EOT") == 0) {
                multiline = TRUE;
            } else {
                parse_name_val(ctx, name, value);
            }
        } else if (!error) {
            error = lineno;
        }
    }

    return error;
}


/**
 * hookInitialize
 *
 * @param filename
 * @param err
 *
 */
static gboolean
ypHookInitialize(
    yfDHCPContext_t  *ctx)
{
    FILE *dhcp_fp_File = NULL;

    dhcp_fp_File = fopen(ctx->dhcp_fp_FileName, "r");

    if (NULL == dhcp_fp_File) {
        fprintf(stderr, "Could not open "
                "DHCP Fingerprint File \"%s\" for reading\n",
                ctx->dhcp_fp_FileName);
        return FALSE;
    }

    g_debug("Initializing Fingerprints from DHCP File %s",
            ctx->dhcp_fp_FileName);

    ini_parse(ctx, dhcp_fp_File);

    fclose(dhcp_fp_File);

    return TRUE;
}


/**
 * ypDHCPScanner
 *
 * @param val ptr to fp struct
 * @param payload ptr to payload
 * @param paylen size of payload
 *
 */
static void
ypDHCPScanner(
    yfDHCPContext_t     *ctx,
    ypDHCPFlowValCtx_t  *val,
    uint8_t             *payload,
    size_t               paylen)
{
    dhcpOptions_t *cur;
    uint32_t       magic_cookie;
    uint16_t       offset = 0;
    /*uint16_t           op_offset;*/
    uint8_t        op, op_len = 0;
    uint8_t        op55len = 0;
    int            i;
    int            found = 0;

    if (paylen < 240) {
        return;
    }

    offset += 236;

    magic_cookie = ntohl(*(uint32_t *)(payload + offset));

    if (magic_cookie != MAGICCOOKIE) {
        return;
    }

    offset += 4;

    while ((size_t)offset + 2 < paylen) {
        op = *(payload + offset);
        offset++;
        op_len = *(payload + offset);
        offset++;
        if (op == 55) {
            if ((size_t)offset + op_len < paylen) {
                /*op_offset = offset;*/
                op55len = op_len;
                for (i = 0; i < op_len; i++) {
                    val->options[i] = *(payload + offset + i);
                }
            }
        } else if (op == 60) {
            /* Vendor Code */
            if ((size_t)offset + op_len < paylen) {
                val->vc = (payload + offset);
                val->vclen = op_len;
            }
        } else if (op_len == 0) {
            break;
        }
        offset += op_len;
    }

    if (op55len == 0) {
        return;
    }

    val->count = op55len;

    if (ctx->export_options) {
        return;
    }

    cur = ctx->opList[op55len].head;

    while (cur) {
        found = 1;
        if (cur->fp.options[0] > val->options[0]) {
            found = 0;
            break;
        } else {
            for (i = 0; i < op55len; i++) {
                if (val->options[i] != cur->fp.options[i]) {
                    found = 0;
                    break;
                }
            }
        }
        if (found == 1) {
            break;
        }
        cur = cur->next;
    }

    if ( (found == 1) && cur) {
        val->fp = cur->fp.desc;
        val->fplen = strlen(cur->fp.desc);
    }
    /* this would export options in dhcp pkt, but how will collector know? */
    /*else {
     *  if (op_offset) {
     *      val->fp = (char *)(payload + op_offset);
     *      val->fplen = op55len;
     *  }
     *  }*/
}


/**
 * flowClose
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
    ypDHCPFlowCtx_t *flowContext = (ypDHCPFlowCtx_t *)yfHookContext;

    if (flow->appLabel != DHCP_APPLABEL) {
        return TRUE;
    }
    if (flowContext == NULL) {
        return FALSE;
    }

    if (flowContext->yfctx->dhcpInitialized == 0) {
        return TRUE;
    }

    if (flow->val.paylen) {
        ypDHCPScanner(flowContext->yfctx, &(flowContext->val),
                      flow->val.payload, flow->val.paylen);
    }

    if (flow->rval.paylen) {
        ypDHCPScanner(flowContext->yfctx, &(flowContext->rval),
                      flow->rval.payload, flow->rval.paylen);
    }

    return TRUE;
}


/**
 * ypValidateFlowTab
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
    yfDHCPContext_t *ctx = (yfDHCPContext_t *)yfctx;

    if (!applabelmode) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                    "ERROR: dhcp_fp_plugin.c will not operate without --applabel");
        return FALSE;
    }

    if (uniflow) {
        ctx->dhcp_uniflow = TRUE;
        dhcp_uniflow_gl = TRUE;
    }

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
void
ypFlowFree(
    void      *yfHookContext,
    yfFlow_t  *flow)
{
    ypDHCPFlowCtx_t *flowContext = (ypDHCPFlowCtx_t *)yfHookContext;

    if (NULL == flowContext) {
        return;
    }

    g_slice_free1(sizeof(ypDHCPFlowCtx_t), flowContext);

    /* the other half of the slab allocator */
    /* free (flowContext); */
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
 * gets called whenever a packet gets processed, relevant to the given flow
 *
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
gboolean
ypFlowWrite(
    void                           *yfHookContext,
    fbSubTemplateMultiList_t       *rec,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    GError                        **err)
{
    ypDHCPFlowCtx_t  *flowContext = (ypDHCPFlowCtx_t *)yfHookContext;
    yfDHCP_FP_Flow_t *dhcp_rec = NULL;
    yfDHCP_OP_Flow_t *dhcp_op = NULL;
    uint8_t          *options = NULL;
    int loop;
    uint16_t          flags = DHCP_REV;
    fbInfoModel_t    *model = ypGetDHCPInfoModel();
    fbTemplate_t     *otmpl = revDhcpOpTemplate;
    fbTemplate_t     *tmpl = revDhcpTemplate;

    if (NULL == flowContext) {
        return TRUE;
    }

    if (flow->appLabel != DHCP_APPLABEL) {
        return TRUE;
    }

    if (flowContext->yfctx->dhcpInitialized == 0) {
        return TRUE;
    }

    if ((flowContext->yfctx->dhcp_uniflow) ||
        (!flowContext->rval.count && !flowContext->rval.vclen))
    {
        otmpl = dhcpOpTemplate;
        tmpl = dhcpTemplate;
        flags = 0;
    }

    stml = fbSubTemplateMultiListGetNextEntry(rec, stml);

    if (!stml) {
        return TRUE;
    }

    if (flowContext->yfctx->export_options) {
        dhcp_op = (yfDHCP_OP_Flow_t *)fbSubTemplateMultiListEntryInit(
            stml, (YAF_DHCP_OP_TID | flags), otmpl, 1);
        options = (uint8_t *)fbBasicListInit(
            &(dhcp_op->options), 3,
            fbInfoModelGetElementByName(model, "dhcpOption"),
            flowContext->val.count);
        for (loop = 0; loop < flowContext->val.count; loop++) {
            *options = flowContext->val.options[loop];
            options++;
        }

        if (flowContext->val.vc) {
            dhcp_op->dhcpVC.buf = flowContext->val.vc;
            dhcp_op->dhcpVC.len = flowContext->val.vclen;
        } else {
            dhcp_op->dhcpVC.len = 0;
        }

        if (flowContext->yfctx->dhcp_uniflow) {
            memcpy(&(flowContext->val), &(flowContext->rval),
                   sizeof(ypDHCPFlowValCtx_t));
            memset(&(flowContext->rval), 0, sizeof(ypDHCPFlowValCtx_t));
        } else if (flags) {
            options = (uint8_t *)fbBasicListInit(
                &(dhcp_op->revOptions), 3,
                fbInfoModelGetElementByName(model, "dhcpOption"),
                flowContext->rval.count);
            for (loop = 0; loop < flowContext->rval.count; loop++) {
                *options = flowContext->rval.options[loop];
                options++;
            }

            if (flowContext->rval.vc) {
                dhcp_op->reverseDhcpVC.buf = flowContext->rval.vc;
                dhcp_op->reverseDhcpVC.len = flowContext->rval.vclen;
            } else {
                dhcp_op->reverseDhcpVC.len = 0;
            }
        }

        flowContext->rec = (void *)dhcp_op;
    } else {
        dhcp_rec = (yfDHCP_FP_Flow_t *)fbSubTemplateMultiListEntryInit(
            stml, (YAF_DHCP_FLOW_TID | flags), tmpl, 1);

        if (flowContext->val.fp) {
            dhcp_rec->dhcpFP.buf = (uint8_t *)flowContext->val.fp;
            dhcp_rec->dhcpFP.len = flowContext->val.fplen;
        } else {
            dhcp_rec->dhcpFP.len = 0;
        }

        if (flowContext->val.vc) {
            dhcp_rec->dhcpVC.buf = flowContext->val.vc;
            dhcp_rec->dhcpVC.len = flowContext->val.vclen;
        } else {
            dhcp_rec->dhcpVC.len = 0;
        }

        /* if uniflow - copy reverse to fwd, when we return to this function
         * everything will be ready */
        if (flowContext->yfctx->dhcp_uniflow) {
            memcpy(&(flowContext->val), &(flowContext->rval),
                   sizeof(ypDHCPFlowValCtx_t));
            memset(&(flowContext->rval), 0, sizeof(ypDHCPFlowValCtx_t));
        } else if (flags) {
            if (flowContext->rval.fp) {
                dhcp_rec->reverseDhcpFP.buf = (uint8_t *)flowContext->rval.fp;
                dhcp_rec->reverseDhcpFP.len = flowContext->rval.fplen;
            } else {
                dhcp_rec->reverseDhcpFP.len = 0;
            }

            if (flowContext->rval.vc) {
                dhcp_rec->reverseDhcpVC.buf = flowContext->rval.vc;
                dhcp_rec->reverseDhcpVC.len = flowContext->rval.vclen;
            } else {
                dhcp_rec->reverseDhcpVC.len = 0;
            }
        }
    }

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
fbInfoElement_t *
ypGetInfoModel(
    void)
{
    return infomodel_array_static_yaf_dhcp;
}


/**
 * getTemplate
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
    GError        *err = NULL;
    fbInfoModel_t *model = ypGetDHCPInfoModel();
    uint16_t       flags = DHCP_REV;

    if (options_global) {
        if (!dhcp_uniflow_gl) {
            revDhcpOpTemplate = fbTemplateAlloc(model);

            if (!fbTemplateAppendSpecArray(
                    revDhcpOpTemplate, yaf_dhcp_options_spec, flags, &err))
            {
                g_warning(
                    "Error adding elements to DHCP Options Template:\n %s",
                    err->message);
                return FALSE;
            }

            if (!YF_fbSessionAddTemplate(
                    session, FALSE, YAF_DHCP_OP_TID | flags,
                    revDhcpOpTemplate, "yaf_dhcp_op_rev", NULL, &err))
            {
                g_warning("Error adding template %02x: %s",
                          YAF_DHCP_OP_TID | flags, err->message);
                return FALSE;
            }
        }

        dhcpOpTemplate = fbTemplateAlloc(model);
        if (!fbTemplateAppendSpecArray(dhcpOpTemplate, yaf_dhcp_options_spec,
                                       0, &err))
        {
            g_warning("Error adding elements to DHCP Options Template:\n %s",
                      err->message);
            return FALSE;
        }

        if (!YF_fbSessionAddTemplate(session, FALSE, YAF_DHCP_OP_TID,
                                     dhcpOpTemplate, "yaf_dhcp_op", NULL, &err))
        {
            g_warning("Error adding template %02x: %s", YAF_DHCP_OP_TID,
                      err->message);
            return FALSE;
        }
    } else {
        if (!dhcp_uniflow_gl) {
            revDhcpTemplate = fbTemplateAlloc(model);
            if (!fbTemplateAppendSpecArray(revDhcpTemplate, yaf_dhcp_fp_spec,
                                           flags, &err))
            {
                g_warning("Error adding elements to DHCP Template:\n %s",
                          err->message);
                return FALSE;
            }

            if (!YF_fbSessionAddTemplate(
                    session, FALSE, YAF_DHCP_FLOW_TID | flags,
                    revDhcpTemplate, "yaf_dhcp_rev", NULL, &err))
            {
                g_warning("Error adding template %02x: %s",
                          YAF_DHCP_FLOW_TID | flags, err->message);
                return FALSE;
            }
        }

        dhcpTemplate = fbTemplateAlloc(model);
        if (!fbTemplateAppendSpecArray(dhcpTemplate, yaf_dhcp_fp_spec, 0,
                                       &err))
        {
            g_warning("Error adding elements to DHCP Template:\n %s",
                      err->message);
            return FALSE;
        }

        if (!YF_fbSessionAddTemplate(session, FALSE, YAF_DHCP_FLOW_TID,
                                     dhcpTemplate, "yaf_dhcp", NULL, &err))
        {
            g_warning("Error adding template %02x: %s", YAF_DHCP_FLOW_TID,
                      err->message);
            return FALSE;
        }
    }

    return TRUE;
}


/**
 * setPluginConf
 *
 * sets the pluginConf variable passed from the command line
 *
 */
void
ypSetPluginConf(
    const char  *conf,
    void       **yfctx)
{
    yfDHCPContext_t *newctx = NULL;
    newctx = (yfDHCPContext_t *)g_slice_alloc0(sizeof(yfDHCPContext_t));

    newctx->dhcpInitialized = 1;

    if (NULL != conf) {
        newctx->dhcp_fp_FileName = g_strdup(conf);

        if (!ypHookInitialize(newctx)) {
            newctx->dhcpInitialized = 0;
        }
        newctx->export_options = FALSE;
        options_global = FALSE;
    } else {
        newctx->export_options = TRUE;
        options_global = TRUE;
        g_debug("Enabling DHCP Options Export.");
    }

    *yfctx = (void *)newctx;
}


#if 0
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
    const char  *option)
{
    /* No options available - ignore*/
}


#endif /* 0 */

/**
 * setPluginOpt
 *
 * sets the pluginOpt variable passed from the command line
 *
 */
void
ypSetPluginOpt(
    const char  *option,
    void        *yfctx)
{
    /*ypParsePluginOpt(option);*/
}


/**
 * scanPayload
 *
 *
 *
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
const struct yfHookMetaData *
ypGetMetaData(
    void)
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
uint8_t
ypGetTemplateCount(
    void      *yfHookContext,
    yfFlow_t  *flow)
{
    ypDHCPFlowCtx_t *flowContext = (ypDHCPFlowCtx_t *)yfHookContext;

    if (NULL == flowContext) {
        return 0;
    }

    if (flowContext->yfctx->dhcpInitialized == 0) {
        return 0;
    }

    if (flow->appLabel != DHCP_APPLABEL) {
        return 0;
    }

    if (flowContext->yfctx->dhcp_uniflow) {
        if (flowContext->val.fp || flowContext->val.vc) {
            return 1;
        } else if (flowContext->rval.fp || flowContext->rval.vc) {
            memcpy(&(flowContext->val), &(flowContext->rval),
                   sizeof(ypDHCPFlowValCtx_t));
            memset(&(flowContext->rval), 0, sizeof(ypDHCPFlowValCtx_t));
            return 0;
        }
    }

    if (flowContext->val.fp || flowContext->rval.fp || flowContext->val.vc ||
        flowContext->rval.vc || flowContext->val.count ||
        flowContext->rval.count)
    {
        return 1;
    }

    return 0;
}


/**
 * ypFreeLists
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
    ypDHCPFlowCtx_t *flowContext = (ypDHCPFlowCtx_t *)yfHookContext;

    if (NULL == flowContext) {
        return;
    }

    if (flowContext->yfctx->dhcpInitialized == 0) {
        return;
    }

    if (flowContext->rec) {
        if (flowContext->val.count) {
            fbBasicListClear(&(flowContext->rec->options));
        }
        if (flowContext->rval.count) {
            fbBasicListClear(&(flowContext->rec->revOptions));
        }
    }

    /* No LISTS */
}


#endif /* YAF_ENABLE_APPLABEL */
#endif /* YAF_ENABLE_HOOKS */
