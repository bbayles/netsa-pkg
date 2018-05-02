/**
 * \file ipfixDump.c
 *
 * \brief This dumps an ipfix file to outspec or stdout.
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2018 Carnegie Mellon University.
 ** All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Author: Emily Sarneso <ecoff@cert.org>
 ** ------------------------------------------------------------------------
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
 ** ------------------------------------------------------------------------
 */
#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <glib.h>
#include "ipfixDumpPrint.h"
#include <yaf/yafcore.h>

#if !YAF_ENABLE_HOOKS
#define INFOMODEL_EXCLUDE_yaf_dpi 1
#define INFOMODEL_EXCLUDE_yaf_dhcp 1
#endif

#include "infomodel.h"

static char                   *inspec = NULL;
static char                   *outspec = NULL;
static gboolean               id_version = FALSE;
static gboolean               yaf = FALSE;
static gboolean               dump_tmpl = FALSE;
static gboolean               dump_data = FALSE;
gboolean                      dump_stats = FALSE;
static FILE                   *outfile = NULL;
static FILE                   *infile = NULL;

static int                    msg_count = 0;
static int                    msg_rec_count = 0;
static int                    msg_rec_length = 0;
static int                    msg_tmpl_count = 0;
static int                    tmpl_count = 0;
static gboolean               eom = TRUE;

int                           id_tmpl_stats[65536];
static int                    max_tmpl_id = 0;
static int                    min_tmpl_id = 0;

static GOptionEntry id_core_option[] = {
    {"in", 'i', 0, G_OPTION_ARG_STRING, &inspec,
     "File to process [stdin]", "file name"},
    {"out", 'o', 0, G_OPTION_ARG_STRING, &outspec,
     "File to write to [stdout]", "file name"},
    {"yaf", 'y', 0, G_OPTION_ARG_NONE, &yaf,
     "Include YAF information elements", NULL},
    {"version", 'V', 0, G_OPTION_ARG_NONE, &id_version,
     "Print application version and exit", NULL},
    {"templates", 't', 0, G_OPTION_ARG_NONE, &dump_tmpl,
     "Print ONLY IPFIX templates that are present in the file.", NULL},
    {"data", 'd', 0, G_OPTION_ARG_NONE, &dump_data,
     "Print ONLY IPFIX data records that are present in the file.", NULL},
    { "stats", 's', 0, G_OPTION_ARG_NONE, &dump_stats,
      "Print ONLY File Statistics.", NULL},
    { NULL }
};


static fbInfoElementSpec_t simple_spec[] = {
    /* TCP-specific information */
    { "sourceIPv4Address",                  4, 0 },
    { "destinationIPv4Address",             4, 0 },
    FB_IESPEC_NULL
};


typedef struct simpleSpec_st {
    uint32_t           sip;
    uint32_t           dip;
} simpleSpec_t;


static void idPrintVersion() {
    fprintf(stderr,"ipfixDump version %s (c) 2018 Carnegie Mellon "
          "University.\n", VERSION);
    fprintf(stderr,"GNU General Public License (GPL) Rights "
            "pursuant to Version 2, June 1991\n");
    fprintf(stderr,"Some included library code covered by LGPL 2.1; "
            "see source for details.\n");
    fprintf(stderr,"Government Purpose License Rights (GPLR) "
            "pursuant to DFARS 252.227-7013\n");
    fprintf(stderr, "Send bug reports, feature requests, and comments to "
            "netsa-help@cert.org.\n");
}


static void idParseOptions (
    int *argc,
    char **argv[])
{

    GOptionContext     *ctx = NULL;
    GError             *err = NULL;

    ctx = g_option_context_new(" - ipfixDump Options");

    g_option_context_add_main_entries(ctx, id_core_option, NULL);

    g_option_context_set_help_enabled(ctx, TRUE);

    if (!g_option_context_parse(ctx, argc, argv, &err)) {
        fprintf(stderr, "option parsing failed: %s\n", err->message);
        exit(1);
    }

    if (id_version) {
        idPrintVersion();
        exit(-1);
    }

    if (inspec != NULL) {
        if ((strlen(inspec) == 1) && inspec[0] == '-') {
            infile = stdin;
        } else {
            infile = fopen(inspec, "r");
            if (infile == NULL) {
                fprintf(stderr, "Can not open input file %s for reading\n",
                        inspec);
                exit(1);
            }
        }
    } else {
        infile = stdin;
    }

    if (dump_stats) {
        memset(id_tmpl_stats, 0, sizeof(id_tmpl_stats));
        dump_data = TRUE;
    }

    if (outspec == NULL) {
        outfile = stdout;
    } else {
        /* file or a directory or stdout */
        if ((strlen(outspec) == 1) && outspec[0] == '-') {
            outfile = stdout;
        } else {
            outfile = fopen(outspec, "w");
            if (outfile == NULL) {
                fprintf(stderr, "Can not open output file %s for logging\n",
                        outspec);
                exit(-1);
            }
        }
    }

    g_option_context_free(ctx);

}

static void templateFree(
    void       *ctx,
    void       *app_ctx)
{
    (void)app_ctx;
    free(ctx);
}

/* print statistics for the current message if the msg_count is
 * non-zero */
static void idCloseMessage(
    void)
{
    if (msg_count) {
        if (!dump_stats) {
            if (msg_rec_count) {
                fprintf(outfile, "*** Msg Stats: %d Data Records "
                        "(length: %d) ***\n\n",
                        msg_rec_count, msg_rec_length);
            }
            if (msg_tmpl_count) {
                fprintf(outfile, "*** Msg Stats: %d Template Records *** "
                        "\n\n", msg_tmpl_count);
            }
        }
        tmpl_count += msg_tmpl_count;
    }
}


/* close the current message, print the header for the new message,
 * and reset the message counters */
static void idNewMessage(
    fBuf_t              *fbuf)
{
    idCloseMessage();

    if (!dump_stats) {
        idPrintHeader(outfile, fbuf);
    }

    eom = FALSE;
    /* reset msg counters */
    msg_rec_count = 0;
    msg_rec_length = 0;
    msg_tmpl_count = 0;
    ++msg_count;
}


static void idTemplateCallback(
    fbSession_t           *session,
    uint16_t              tid,
    fbTemplate_t          *tmpl,
    void                  *app_ctx,
    void                  **ctx,
    fbTemplateCtxFree_fn  *fn)
{
    GError *err = NULL;
    uint16_t len = 0;
    tmplContext_t *myctx = malloc(sizeof(tmplContext_t));
    uint16_t ntid = 0;
    /* get infomodel from session -
       give it to idPrintTmpl to add up length
       (should use type instead of length?) */

    if (eom) {
        idNewMessage((fBuf_t *)app_ctx);
    }

    len = idPrintTemplate(outfile, tmpl, ctx, tid, dump_data);

    ntid = fbSessionAddTemplate(session, TRUE, tid, tmpl, &err);

    if (ntid == 0) {
        fprintf(stderr, "Error adding template to session: %s\n",
                err->message);
    }

    /* mark every tmpl we have received */
    if (id_tmpl_stats[tid] == 0) {
        id_tmpl_stats[tid] = 1;
    }
    if (tid > max_tmpl_id) {
        max_tmpl_id = tid;
    }
    if (!min_tmpl_id || (min_tmpl_id > tid)) {
        min_tmpl_id = tid;
    }
    msg_tmpl_count++;
    myctx->len = len;
    myctx->count = fbTemplateCountElements(tmpl);
    myctx->tid = tid;
    *ctx = myctx;
    *fn = templateFree;

}



int
main (int argc, char *argv[])
{

    fbInfoModel_t *model = NULL;
    fbCollector_t *collector = NULL;
    fBuf_t        *fbuf = NULL;
    fbTemplate_t  *tmpl = NULL;
    GError        *err = NULL;
    gboolean      rc;
    fbSession_t  *session = NULL;
    tmplContext_t *tctx;
    uint16_t      tid, ntid;
    uint8_t       *buffer = NULL;
    size_t        buf_len;
    int           rec_count = 0;
    char          str_prefix[10];

    idParseOptions(&argc, &argv);

    model = fbInfoModelAlloc();

    if (yaf) {
        infomodelAddGlobalElements(model);
    }

    /* Create New Session */
    session = fbSessionAlloc(model);

    tmpl = fbTemplateAlloc(model);
    rc = fbTemplateAppendSpecArray(tmpl, simple_spec, 0, &err);
    if (FALSE == rc) {
        fprintf(stderr, "couldn't create template. %s\n", err->message);
        exit(-1);
    }

    tid = fbSessionAddTemplate(session, TRUE, FB_TID_AUTO, tmpl,
                               &err);
    if (tid == 0) {
        fprintf(stderr, "couldn't add template: %s\n.", err->message);
        exit(-1);
    }

    /* Allocate FP Collector */
    collector = fbCollectorAllocFP(NULL, infile);

    /* Allocate Buffer */
    fbuf = fBufAllocForCollection(session, collector);

    fBufSetAutomaticMode(fbuf, FALSE);

    fbSessionAddNewTemplateCallback(session, idTemplateCallback, fbuf);

    memset(str_prefix, 0, 10);

    for (;;) {
        tmpl = fBufNextCollectionTemplate(fbuf, &ntid, &err);
        if (!tmpl) {
            /* If no template - no message */
            if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOF)) {
                fBufFree(fbuf);
                g_clear_error(&err);
                eom = TRUE;
                break;
            }
            if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) {
                eom = TRUE;
            } else {
                fprintf(stderr, "Warning: %s\n", err->message);
            }
            g_clear_error(&err);
            continue;
        }

        if (eom) {
            idNewMessage(fbuf);
        }

        id_tmpl_stats[ntid] += 1;
        rc = fBufSetInternalTemplate(fbuf, ntid, &err);
        if (!rc) {
            fprintf(stderr, "Error setting internal template on collector\n");
            fprintf(stderr, "\t%s\n", err->message);
            exit(-41);
        }

        tctx = fbTemplateGetContext(tmpl);

        buffer = calloc(1, tctx->len);
        buf_len = tctx->len;

        rc = fBufNext(fbuf, buffer, &buf_len, &err);

        if (FALSE == rc) {
            if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOF)) {
                eom = TRUE;
                fprintf(stderr, "END OF FILE\n");
                fBufFree(fbuf);
                g_clear_error(&err);
                free(buffer);
                break;
            }
            if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) {
                eom = TRUE;
            } else {
                fprintf(stderr, "Warning: %s\n", err->message);
            }
            g_clear_error(&err);
            free(buffer);
            continue;
        }

        rec_count++;
        msg_rec_count++;

        /* FIXME: When record contains varlen or list elements,
         * 'buf_len' is the size of the fbVarfield_t or fb*List_t
         * structure and not the number of octets in that field. */
        msg_rec_length += buf_len;

        if (!dump_tmpl) {
            idPrintDataRecord(outfile, tmpl, buffer, buf_len, rec_count, "");
        }

        free(buffer);

    }

    if (eom) {
        idCloseMessage();
    }

    fbInfoModelFree(model);

    fprintf(outfile, "*** File Stats: %d Messages, %d Data Records, "
            "%d Template Records ***\n", msg_count, rec_count, tmpl_count);

    if (dump_stats) {
        int i;
        fprintf(outfile, "  Template ID | Records\n");
        for (i = min_tmpl_id; i <= max_tmpl_id; i++) {
            if (id_tmpl_stats[i] > 0) {
                fprintf(outfile, "%5d (0x%02x)| %d \n",
                        i, i, id_tmpl_stats[i] - 1);
            }
        }
    }


    return 0;
}
