/**
 * \file ipfixDump.c
 *
 * \brief This dumps an ipfix file to outspec or stdout.
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2023 Carnegie Mellon University.
 ** All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Author: Emily Sarneso
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_LICENSE_START@
 ** libfixbuf 2.0
 **
 ** Copyright 2018-2023 Carnegie Mellon University. All Rights Reserved.
 **
 ** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
 ** ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
 ** BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
 ** EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
 ** EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
 ** MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 ** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
 ** COPYRIGHT INFRINGEMENT.
 **
 ** Released under a GNU-Lesser GPL 3.0-style license, please see
 ** LICENSE.txt or contact permission@sei.cmu.edu for full terms.
 **
 ** [DISTRIBUTION STATEMENT A] This material has been approved for
 ** public release and unlimited distribution.  Please see Copyright
 ** notice for non-US Government use and distribution.
 **
 ** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent
 ** and Trademark Office by Carnegie Mellon University.
 **
 ** DM18-0325
 ** @OPENSOURCE_LICENSE_END@
 ** ------------------------------------------------------------------------
 */
#include "ipfixDump.h"

/* CERT IPFIX Private Enterprise Number */
#define CERT_PEN    6871

/* Initial size of the buffer for an in-memory record. */
#define RECBUF_CAPACITY_INITIAL 256

static char            *inspec = NULL;
static char            *outspec = NULL;
static gboolean         id_version = FALSE;
static gboolean         yaf = FALSE;
static gboolean         rfc5610 = FALSE;
static gboolean         only_tmpl = FALSE;
static gboolean         only_data = FALSE;
gboolean                only_stats = FALSE;
static FILE            *outfile = NULL;
static FILE            *infile = NULL;
static gchar           *cert_xml = NULL;
static gchar          **xml_files = NULL;

static int              msg_count = 0;
static int              msg_rec_count = 0;
static int              msg_rec_length = 0;
static int              msg_tmpl_count = 0;
static int              tmpl_count = 0;
static gboolean         eom = TRUE;

int                     id_tmpl_stats[1 + UINT16_MAX];
static int              max_tmpl_id = 0;
static int              min_tmpl_id = UINT16_MAX;
GHashTable             *template_names;

uint32_t                hexdump = 0;
uint32_t                sequence_number = 0;
size_t                  msglen;


static gboolean idParseHexdump(
    const gchar  *option_name,
    const gchar  *value,
    gpointer      data,
    GError      **error);

static GOptionEntry id_core_option[] = {
    {"in", 'i', 0, G_OPTION_ARG_STRING, &inspec,
     "Specify file to process [-]", "path"},
    {"out", 'o', 0, G_OPTION_ARG_STRING, &outspec,
     "Specify file to write to [-]", "path"},
    {"rfc5610", '\0', 0, G_OPTION_ARG_NONE, &rfc5610,
     "Add IEs that are read from element type records", NULL},
    {"element-file", 'e', 0, G_OPTION_ARG_FILENAME_ARRAY, &xml_files,
     "Load information elements from the given XML file", "path"},
    {"yaf", 'y', 0, G_OPTION_ARG_NONE, &yaf,
     "Load XML file of CERT information elements", NULL},
    {"templates", 't', 0, G_OPTION_ARG_NONE, &only_tmpl,
     "Print ONLY IPFIX templates that are present", NULL},
    {"data", 'd', 0, G_OPTION_ARG_NONE, &only_data,
     "Print ONLY IPFIX data records that are present", NULL},
    {"stats", 's', 0, G_OPTION_ARG_NONE, &only_stats,
     "Print ONLY File Statistics", NULL},
    {"hexdump", '\0', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
     &idParseHexdump,
     "Print first LEN octets of octetArrays as hex [0]", "len"},
    {"version", 'V', 0, G_OPTION_ARG_NONE, &id_version,
     "Print application version to stderr and exit", NULL},
    { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};


static void idPrintVersion(
    void)
{
    fprintf(stderr,"ipfixDump version %s (c) 2018-2023 Carnegie Mellon "
          "University.\n", FIXBUF_PACKAGE_VERISON);
    fprintf(stderr,"GNU Lesser General Public License (LGPL) Rights "
            "pursuant to Version 2, June 1991\n");
    fprintf(stderr,"Some included library code covered by LGPL 2.1; "
            "see source for details.\n");
    fprintf(stderr,"Government Purpose License Rights (GPLR) "
            "pursuant to DFARS 252.227-7013\n");
    fprintf(stderr, "Send bug reports, feature requests, and comments to "
            "netsa-help@cert.org.\n");
}


/**
 *    Attempts to find the cert_ipfix.xml file and returns its
 *    location.  Takes the program name as an argument.
 *
 *    This file is used by the --yaf switch.
 */
static gchar *idFindCertXml(
    const gchar   *argv0)
{
    GArray *locations;
    const gchar * const * sysdirs;
    gchar *path;
    gchar *dir;
    int i;

    /* directories that will be checked for the file */
    locations = g_array_sized_new(TRUE, TRUE, sizeof(gchar *), 8);

    /* the directory ../share/libfixbuf relative to the
     * application's location */
    path = g_path_get_dirname(argv0);
    dir = g_build_filename(path, "..", "share", FIXBUF_PACKAGE_NAME, NULL);
    g_array_append_val(locations, dir);
    g_free(path);

#if 0
    /* the user's data dir */
    dir = g_build_filename(g_get_user_data_dir(), FIXBUF_PACKAGE_NAME, NULL);
    g_array_append_val(locations, dir);
#endif  /* 0 */

    /* the compile-time location */
    dir = FIXBUF_PACKAGE_DATADIR;
    if (dir && *dir) {
        dir = g_build_filename(dir, NULL);
        g_array_append_val(locations, dir);
    }

    /* system locations */
    sysdirs = g_get_system_data_dirs();
    for (i = 0; (sysdirs[i]); ++i) {
        dir = g_build_filename(sysdirs[i], FIXBUF_PACKAGE_NAME, NULL);
        g_array_append_val(locations, dir);
    }

    /* search for the file */
    path = NULL;
    for (i = 0; !path && (dir = g_array_index(locations, gchar *, i)); ++i) {
        path = g_build_filename(dir, CERT_IPFIX_BASENAME, NULL);
        if (!g_file_test(path, G_FILE_TEST_IS_REGULAR)) {
            g_free(path);
            path = NULL;
        }
    }

    if (NULL == path) {
        fprintf(stderr, "%s: Failed to find '%s' in '%s'",
                g_get_prgname(), CERT_IPFIX_BASENAME,
                g_array_index(locations, gchar *, 0));
        for (i = 1; (dir = g_array_index(locations, gchar *, i)); ++i) {
            fprintf(stderr, ", '%s'", g_array_index(locations, gchar *, i));
        }
        fprintf(stderr, "\n");
        fprintf(stderr, ("%s: Replace --yaf with --element-file and"
                         " specify its location\n"), g_get_prgname());
    }

    for (i = 0; (dir = g_array_index(locations, gchar *, i)); ++i) {
        g_free(dir);
    }
    g_array_free(locations, TRUE);

    return path;
}


/**
 *    Callback function invoked by the GLib option parser to handle
 *    the argument to the --hexdump switch.
 *
 *    See the GLib documentation at
 *    <https://developer.gnome.org/glib/stable/glib-Commandline-option-parser.html#GOptionArgFunc>
 */
static gboolean idParseHexdump(
    const gchar  *option_name,
    const gchar  *value,
    gpointer      data,
    GError      **error)
{
    char *ep = NULL;
    long len;

    (void)option_name;
    (void)data;

    if (NULL == value) {
        hexdump = UINT16_MAX;
        return TRUE;
    }

    errno = 0;
    len = strtol(value, &ep, 10);
    if (len >= 0 && len <= UINT16_MAX && *ep == '\0' && ep != value) {
        hexdump = len;
        return TRUE;
    }
    if (errno != 0) {
        *error = g_error_new(G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
                             "Invalid %s '%s': %s\n",
                             option_name, value, strerror(errno));
        return FALSE;
    }
    if (*ep != '\0') {
        *error = g_error_new(G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
                             "Invalid %s '%s': Invalid argument\n",
                             option_name, value);
        return FALSE;
    }
    /* value out of range; treat as maximum */
    hexdump = UINT16_MAX;
    return TRUE;
}


/**
 *    Parse the command line options.
 */
static void idParseOptions(
    int *argc,
    char **argv[])
{
    GOptionContext     *ctx = NULL;
    GError             *err = NULL;
    gchar              *app;

    app = g_path_get_basename((*argv)[0]);
    g_set_prgname(app);
    g_free(app);

    ctx = g_option_context_new(" - ipfixDump Options");

    g_option_context_add_main_entries(ctx, id_core_option, NULL);

    g_option_context_set_help_enabled(ctx, TRUE);

    if (!g_option_context_parse(ctx, argc, argv, &err)) {
        fprintf(stderr, "%s: Option parsing failed: %s\n",
                g_get_prgname(), err->message);
        g_clear_error(&err);
        exit(1);
    }

    if (id_version) {
        idPrintVersion();
        exit(0);
    }

    if (yaf) {
        cert_xml = idFindCertXml((*argv)[0]);
        if (NULL == cert_xml) {
            exit(1);
        }
    }

    if (only_stats) {
        memset(id_tmpl_stats, 0, sizeof(id_tmpl_stats));
        only_data = TRUE;
    }

    /* check for non-arguments in argv */
    if (1 != *argc) {
        fprintf(stderr, "%s: Unrecognized argument %s\n",
                g_get_prgname(), (*argv)[1]);
        exit(1);
    }

    if (inspec != NULL) {
        if ((strlen(inspec) == 1) && inspec[0] == '-') {
            infile = stdin;
        } else {
            infile = fopen(inspec, "r");
            if (infile == NULL) {
                fprintf(stderr, "%s: Opening input file %s failed: %s\n",
                        g_get_prgname(), inspec, strerror(errno));
                exit(1);
            }
        }
    } else if (isatty(fileno(stdin))) {
        fprintf(stderr, "%s: No input argument and stdin is a terminal\n",
                g_get_prgname());
        exit(1);
    } else {
        infile = stdin;
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
                fprintf(stderr, "%s: Opening output file %s failed: %s\n",
                        g_get_prgname(), outspec, strerror(errno));
                exit(1);
            }
        }
    }

    g_option_context_free(ctx);
}


/**
 *    Free the template context object.  The signature of this
 *    function is given by fbTemplateCtxFree_fn.
 *    <https://tools.netsa.cert.org/fixbuf/libfixbuf/public_8h.html#a038c2bc9d92506c477979ea7dbdf3b46>
 */
static void templateFree(
    void       *ctx,
    void       *app_ctx)
{
    (void)app_ctx;
    g_free(ctx);
}

/**
 *    Print statistics for the current message if the msg_count is
 *    non-zero.
 */
static void idCloseMessage(
    void)
{
    if (msg_count) {
        if (!only_stats) {
            if (msg_rec_count) {
                fprintf(outfile, "*** Msg Stats: %d Data Records "
                        "(length: %d) ***\n\n",
                        msg_rec_count, msg_rec_length);
            }
            if (msg_tmpl_count) {
                fprintf(outfile, "*** Msg Stats: %d Template Records ***\n\n",
                        msg_tmpl_count);
            }
        }
        tmpl_count += msg_tmpl_count;
    }
}


/**
 *    Close the current message, print the header for the new message,
 *    and reset the message counters.
 */
static void idNewMessage(
    fBuf_t              *fbuf)
{
    idCloseMessage();

    if (!only_stats) {
        idPrintHeader(outfile, fbuf);
    }

    eom = FALSE;
    /* reset msg counters */
    msg_rec_count = 0;
    msg_rec_length = 0;
    msg_tmpl_count = 0;
    ++msg_count;
}


/**
 *    Callback invoked when a new template is seen.  The signature of
 *    this function is given by fbNewTemplateCallback_fn.
 *
 *    <https://tools.netsa.cert.org/fixbuf/libfixbuf/public_8h.html#a13b7083ca8ec73524e6c2b815a39d4d4>
 */
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
    tmplContext_t *myctx = g_new0(tmplContext_t, 1);
    uint16_t ntid = 0;
    static fbInfoElementSpec_t templateNameSpec[] = {
        {"templateId",   2,            0},
        {"templateName", FB_IE_VARLEN, 0},
        FB_IESPEC_NULL
    };
    /* get infomodel from session -
       give it to idPrintTmpl to add up length
       (should use type instead of length?) */

    if (eom) {
        idNewMessage((fBuf_t *)app_ctx);
    }

    myctx->count = fbTemplateCountElements(tmpl);
    myctx->scope = fbTemplateGetOptionsScope(tmpl);
    myctx->tid = tid;

    len = idPrintTemplate(outfile, tmpl, myctx, tid, only_data);

    ntid = fbSessionAddTemplate(session, TRUE, tid, tmpl, &err);

    if (ntid == 0) {
        fprintf(stderr, "%s: Error adding template to session: %s\n",
                g_get_prgname(), err->message);
        g_clear_error(&err);
    }

    /* mark every tmpl we have received */
    if (id_tmpl_stats[tid] == 0) {
        id_tmpl_stats[tid] = 1;
    }
    if (tid > max_tmpl_id) {
        max_tmpl_id = tid;
    }
    if (tid < min_tmpl_id) {
        min_tmpl_id = tid;
    }

    if (fbTemplateGetOptionsScope(tmpl)) {
        if (fbTemplateContainsAllElementsByName(tmpl, templateNameSpec)) {
            myctx->is_meta_template = TRUE;
        } else if (rfc5610 && fbInfoModelTypeInfoRecord(tmpl)) {
            myctx->is_meta_element = TRUE;
        }
    }

    ++msg_tmpl_count;
    myctx->len = len;
    *ctx = myctx;
    *fn = templateFree;
}


/**
 *    Parse a template name options record and insert the TID/name
 *    pair into the template_names hash table.
 */
static void idTemplateNameRecord(
    fbInfoModel_t      *model,
    fbTemplate_t       *tmpl,
    const uint8_t      *buffer)
{
    uint32_t count, i;
    const fbInfoElement_t *ie;
    const uint8_t *b;
    char name[UINT16_MAX];
    uint32_t len;
    uint16_t tid;

    (void)model;
    len = 0;
    tid = 0;

    b = buffer;
    count = fbTemplateCountElements(tmpl);

    for (i = 0; i < count; ++i) {
        ie = fbTemplateGetIndexedIE(tmpl, i);
        if (ie->ent == 0 && ie->num == 145) {
            /* templateId */
            if (ie->len == 2) {
                memcpy(&tid, b, sizeof(tid));
            } else if (ie->len == 1) {
                tid = *b;
            }
        } else if (ie->ent == CERT_PEN && ie->num == 1000) {
            /* templateName */
            if (ie->len == FB_IE_VARLEN) {
                fbVarfield_t var;
                memcpy(&var, b, sizeof(var));
                len = var.len;
                if (len) {
                    memcpy(name, (char *)var.buf, len);
                    name[len] = '\0';
                } else {
                    len = var.len;
                    memcpy(name, (char *)b, len);
                    name[len] = '\0';
                }
            }
        }

        if (ie->len != FB_IE_VARLEN) {
            b += ie->len;
        } else if (ie->type == FB_BASIC_LIST) {
            b += sizeof(fbBasicList_t);
        } else if (ie->type == FB_SUB_TMPL_LIST) {
            b += sizeof(fbSubTemplateList_t);
        } else if (ie->type == FB_SUB_TMPL_MULTI_LIST) {
            b += sizeof(fbSubTemplateMultiList_t);
        } else {
            b += sizeof(fbVarfield_t);
        }
    }

    if (tid >= 0x100 && len > 0) {
        g_hash_table_replace(template_names, GINT_TO_POINTER(tid),
                             g_strndup(name, len));
    }
}


/**
 *    Process an RFC5610 Record describing an InfoElement and add that
 *    element to the InfoModel.
 */
static gboolean idInfoElementRecord(
    fbInfoModel_t      *model,
    fbTemplate_t       *tmpl,
    const uint8_t      *buffer)
{
    uint32_t count, i;
    fbInfoElementOptRec_t rec;
    const fbInfoElement_t *ie;
    const uint8_t *b;

    memset(&rec, 0, sizeof(rec));

    b = buffer;
    count = fbTemplateCountElements(tmpl);

    for (i = 0; i < count; ++i) {
        ie = fbTemplateGetIndexedIE(tmpl, i);
        if (ie->ent == 0) {
            switch (ie->num) {
              case 346:
                /* privateEnterpriseNumber */
                if (ie->len == sizeof(rec.ie_pen)) {
                    memcpy(&rec.ie_pen, b, sizeof(rec.ie_pen));
                } else {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
                    memcpy(&rec.ie_pen, b, ie->len);
#else
                    memcpy((((uint8_t *)&rec.ie_pen)
                            + sizeof(rec.ie_pen) - ie->len), b, ie->len);
#endif
                }
                break;
              case 303:
                /* informationElementId */
                if (ie->len == sizeof(rec.ie_id)) {
                    memcpy(&rec.ie_id, b, sizeof(rec.ie_id));
                } else {
                    rec.ie_id = *b;
                }
                break;
              case 339:
                /* informationElementDataType */
                rec.ie_type = *b;
                break;
              case 344:
                /* informationElementSemantics */
                rec.ie_semantic = *b;
                break;
              case 345:
                /* informationElementUnits */
                if (ie->len == sizeof(rec.ie_units)) {
                    memcpy(&rec.ie_units, b, sizeof(rec.ie_units));
                } else {
                    rec.ie_units = *b;
                }
                break;
              case 342:
                /* informationElementRangeBegin */
                if (ie->len == sizeof(rec.ie_range_begin)) {
                    memcpy(&rec.ie_range_begin, b, sizeof(rec.ie_range_begin));
                } else {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
                    memcpy(&rec.ie_range_begin, b, ie->len);
#else
                    memcpy((((uint8_t *)&rec.ie_range_begin)
                            + sizeof(rec.ie_range_begin) - ie->len),
                           b, ie->len);
#endif
                }
                break;
              case 343:
                /* informationElementRangeEnd */
                if (ie->len == sizeof(rec.ie_range_end)) {
                    memcpy(&rec.ie_range_end, b, sizeof(rec.ie_range_end));
                } else {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
                    memcpy(&rec.ie_range_end, b, ie->len);
#else
                    memcpy((((uint8_t *)&rec.ie_range_end)
                            + sizeof(rec.ie_range_end) - ie->len), b, ie->len);
#endif
                }
                break;
              case 341:
                /* informationElementName */
                memcpy(&rec.ie_name, b, sizeof(rec.ie_name));
                break;
              case 340:
                /* informationElementDescription */
                memcpy(&rec.ie_desc, b, sizeof(rec.ie_desc));
                break;
            }
        }
        if (ie->len != FB_IE_VARLEN) {
            b += ie->len;
        } else if (ie->type == FB_BASIC_LIST) {
            b += sizeof(fbBasicList_t);
        } else if (ie->type == FB_SUB_TMPL_LIST) {
            b += sizeof(fbSubTemplateList_t);
        } else if (ie->type == FB_SUB_TMPL_MULTI_LIST) {
            b += sizeof(fbSubTemplateMultiList_t);
        } else {
            b += sizeof(fbVarfield_t);
        }
    }

    return fbInfoElementAddOptRecElement(model, &rec);
}


int
main(int argc, char *argv[])
{
    uint8_t             msgbuf[UINT16_MAX];
    fbInfoModel_t      *model = NULL;
    fBuf_t             *fbuf = NULL;
    fbTemplate_t       *tmpl = NULL;
    GError             *err = NULL;
    gboolean            rc;
    fbSession_t        *session = NULL;
    tmplContext_t      *tctx;
    uint16_t            ntid;
    uint8_t            *recbuf = NULL;
    size_t              recbuf_capacity;
    size_t              reclen;
    int                 rec_count = 0;
    gchar             **xml_file;
    int                 i;
    size_t              got;

    idParseOptions(&argc, &argv);

    model = fbInfoModelAlloc();

    if (cert_xml) {
        if (!fbInfoModelReadXMLFile(model, cert_xml, &err)) {
            fprintf(stderr, "%s: Failed to load elements from '%s': %s",
                    g_get_prgname(), cert_xml, err->message);
            g_clear_error(&err);
            exit(-1);
        }
        g_free(cert_xml);
    }
    if (xml_files) {
        for (xml_file = xml_files; *xml_file; ++xml_file) {
            if (!fbInfoModelReadXMLFile(model, *xml_file, &err)) {
                fprintf(stderr, "%s: Failed to load elements from '%s': %s",
                        g_get_prgname(), *xml_file, err->message);
                g_clear_error(&err);
                exit(-1);
            }
        }
        g_strfreev(xml_files);
    }

    /* Create New Session */
    session = fbSessionAlloc(model);

    template_names = g_hash_table_new_full(g_direct_hash, NULL, NULL, g_free);

    /* Allocate Collection Buffer */
    fbuf = fBufAllocForCollection(session, NULL);

    fBufSetAutomaticMode(fbuf, FALSE);

    fbSessionAddNewTemplateCallback(session, idTemplateCallback, fbuf);

    /* Allocate buffer for a single in-memory record */
    recbuf_capacity = RECBUF_CAPACITY_INITIAL;
    recbuf = g_new(uint8_t, recbuf_capacity);

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
            if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_BUFSZ)) {
                got = fread(msgbuf, 1, 4, infile);
                if (got != 4) {
                    if (0 != got) {
                        fprintf(stderr, "%s: Read %zu octets of 4 expected\n",
                                g_get_prgname(), got);
                    }
                    fBufFree(fbuf);
                    g_clear_error(&err);
                    eom = TRUE;
                    break;
                }
                if (ntohs(*((uint16_t *)(msgbuf))) != 10) {
                    fprintf(stderr,
                            "%s: Error: Illegal IPFIX Message version %#04x; "
                            "input is probably not an IPFIX Message stream.",
                            g_get_prgname(), ntohs(*((uint16_t *)(msgbuf))));
                    fBufFree(fbuf);
                    g_clear_error(&err);
                    eom = TRUE;
                    break;
                }
                msglen = ntohs(*((uint16_t *)(msgbuf + 2)));
                if (msglen < 16) {
                    fprintf(stderr,
                            "%s: Message length %zu too short to be IPFIX\n",
                            g_get_prgname(), msglen);
                    fBufFree(fbuf);
                    g_clear_error(&err);
                    eom = TRUE;
                    break;
                }
                got = fread(msgbuf + 4, 1, msglen - 4, infile);
                if (got < msglen - 4) {
                    fprintf(stderr, "%s: Read %zu octets of %zu expected\n",
                            g_get_prgname(), got, msglen - 4);
                    fBufFree(fbuf);
                    g_clear_error(&err);
                    eom = TRUE;
                    break;
                }
                sequence_number = ntohl(*((uint32_t *)(msgbuf + 8)));
                fBufSetBuffer(fbuf, msgbuf, msglen);
                eom = TRUE;
            } else if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) {
                eom = TRUE;
            } else {
                fprintf(stderr, "%s: Warning: %s\n",
                        g_get_prgname(), err->message);
            }
            g_clear_error(&err);
            continue;
        }

        if (eom) {
            idNewMessage(fbuf);
        }

        rc = fBufSetInternalTemplate(fbuf, ntid, &err);
        if (!rc) {
            fprintf(stderr,
                    "%s: Error setting internal template on collector: %s\n",
                    g_get_prgname(), err->message);
            g_clear_error(&err);
            exit(-41);
        }

        tctx = fbTemplateGetContext(tmpl);
        reclen = tctx->len;

        if (reclen > recbuf_capacity) {
            do {
                recbuf_capacity <<= 1;
            } while (reclen > recbuf_capacity);
            recbuf = g_renew(uint8_t, recbuf, recbuf_capacity);
        }
        memset(recbuf, 0, recbuf_capacity);

        rc = fBufNext(fbuf, recbuf, &reclen, &err);
        if (FALSE == rc) {
            if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOF)) {
                eom = TRUE;
                fprintf(stderr, "%s: END OF FILE\n", g_get_prgname());
                fBufFree(fbuf);
                g_clear_error(&err);
                break;
            }
            if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) {
                eom = TRUE;
            } else if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_BUFSZ)) {
                eom = TRUE;
            } else {
                fprintf(stderr, "%s: Warning: %s\n",
                        g_get_prgname(), err->message);
            }
            g_clear_error(&err);
            continue;
        }

        ++id_tmpl_stats[ntid];
        ++rec_count;
        ++msg_rec_count;

        /* NOTE: When record contains varlen or list elements,
         * 'reclen' is the size of the fbVarfield_t or fb*List_t
         * structure and not the number of octets in that field. */
        msg_rec_length += reclen;

        if (tctx->is_meta_template) {
            idTemplateNameRecord(model, tmpl, recbuf);
        } else if (tctx->is_meta_element) {
            idInfoElementRecord(model, tmpl, recbuf);
        }
        if (!only_tmpl) {
            idPrintDataRecord(outfile, tmpl, recbuf, reclen, rec_count, "");
        }
    }

    if (eom) {
        idCloseMessage();
    }

    fbInfoModelFree(model);
    g_free(recbuf);

    fprintf(outfile, "*** File Stats: %d Messages, %d Data Records, "
            "%d Template Records ***\n", msg_count, rec_count, tmpl_count);

    if (!only_stats) {
        /* do not print stats */
    } else if (g_hash_table_size(template_names) == 0) {
        /* print the template usage counts without the names */
        fprintf(outfile, "  Template ID | Records\n");
        for (i = min_tmpl_id; i <= max_tmpl_id; i++) {
            if (id_tmpl_stats[i] > 0) {
                fprintf(outfile, "%5d (%#06x)| %d \n",
                        i, i, id_tmpl_stats[i] - 1);
            }
        }
    } else {
        /* print the template usage counts with the names */
        const char *name;
        fprintf(outfile, "  Template ID |  Records  | Template Name\n");
        for (i = min_tmpl_id; i <= max_tmpl_id; i++) {
            if (id_tmpl_stats[i] > 0) {
                name = (char *)g_hash_table_lookup(template_names,
                                                   GINT_TO_POINTER(i));
                fprintf(outfile, "%5d (%#06x)|%11d| %s\n",
                        i, i, id_tmpl_stats[i] - 1, ((name) ? name : ""));
            }
        }
    }

    g_hash_table_destroy(template_names);

    return 0;
}
