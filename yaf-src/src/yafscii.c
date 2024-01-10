/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafscii.c
 *  YAF flow printer
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
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
#include <airframe/mio.h>
#include <airframe/mio_config.h>
#include <airframe/mio_source_file.h>
#include <airframe/mio_sink_file.h>
#include <airframe/logconfig.h>
#include <airframe/daeconfig.h>
#include <airframe/airutil.h>
#include <airframe/privconfig.h>
#include <yaf/yafcore.h>

/* wrap this around string literals that are assigned to variables of type
 * "char *" to quiet compiler warnings */
#define C(String) (char *)String


typedef struct ytContext_st {
    fBuf_t    *fbuf;
    yfFlow_t   flow;
} ytContext_t;

static uint32_t yaft_flows = 0;

static gboolean yaft_tabular = FALSE;
static gboolean yaft_mac = FALSE;
static gboolean yaft_first = TRUE;
static gboolean yaft_print_header = FALSE;

static uint32_t yaft_cliflags = MIO_F_CLI_FILE_IN |
    MIO_F_CLI_DIR_IN |
    MIO_F_CLI_DEF_STDIN |
    MIO_F_CLI_FILE_OUT |
    MIO_F_CLI_DIR_OUT |
    MIO_F_CLI_DEF_STDOUT;

static AirOptionEntry yaft_optentries[] = {
    AF_OPTION( "tabular", (char)0, 0, AF_OPT_TYPE_NONE, &yaft_tabular,
               "Print flows in tabular format", NULL ),
    AF_OPTION( "mac", (char)0, 0, AF_OPT_TYPE_NONE, &yaft_mac,
               "Print mac addresses (when used with --tabular)", NULL ),
    AF_OPTION( "print-header", (char)0, 0, AF_OPT_TYPE_NONE, &yaft_print_header,
               "Print column headers for tabular format", NULL),
    AF_OPTION_END
};

static void
ytParseOptions(
    int   *argc,
    char **argv[])
{
    AirOptionCtx *aoctx = NULL;

    aoctx = air_option_context_new("", argc, argv, yaft_optentries);

    mio_add_option_group(aoctx, yaft_cliflags);
    daec_add_option_group(aoctx);
    privc_add_option_group(aoctx);
    logc_add_option_group(aoctx, "yafscii", VERSION);

    air_option_context_set_help_enabled(aoctx);

    air_option_context_parse(aoctx);
    if (yaft_mac && !yaft_tabular) {
        g_warning("--mac requires --tabular");
    }
    if (yaft_print_header && !yaft_tabular) {
        g_warning("--print-header requires --tabular");
    }

    air_option_context_free(aoctx);
}


static gboolean
ytOpenSource(
    MIOSource  *source,
    void       *vctx,
    uint32_t   *flags,
    GError    **err)
{
    ytContext_t *yx = (ytContext_t *)vctx;

    /* start reading a YAF file */
    if (!(yx->fbuf = yfReaderForFP(yx->fbuf, mio_fp(source), err))) {
        *flags |= MIO_F_CTL_SOURCECLOSE;
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOF)) {
            g_clear_error(err);
        } else {
            *flags |= MIO_F_CTL_ERROR;
        }
        return FALSE;
    }

    return TRUE;
}


static gboolean
ytProcess(
    MIOSource  *source,
    MIOSink    *sink,
    void       *vctx,
    uint32_t   *flags,
    GError    **err)
{
    ytContext_t *yx = (ytContext_t *)vctx;
    gboolean     ok;

    /* Print first line column headers if tabular */
    if (yaft_tabular && yaft_first && yaft_print_header) {
        yfPrintColumnHeaders(mio_fp(sink), yaft_mac, err);
        yaft_first = FALSE;
    }

    /* read a flow */
    if ((ok = yfReadFlowExtended(yx->fbuf, &(yx->flow), err))) {
        ++yaft_flows;
        if (yaft_tabular) {
            ok = yfPrintDelimited(mio_fp(sink), &(yx->flow), yaft_mac, err);
        } else {
            ok = yfPrint(mio_fp(sink), &(yx->flow), err);
        }
    }

    /* handle error */
    if (!ok) {
        /* check for EOF */
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOF)) {
            g_clear_error(err);
            *flags |= MIO_F_CTL_SOURCECLOSE;
            ok = TRUE;
        } else {
            /* die on actual error */
            *flags |= MIO_F_CTL_ERROR;
        }
    }

    return ok;
}


int
main(
    int    argc,
    char  *argv[])
{
    GError      *err = NULL;
    ytContext_t  yx;
    MIOSource    source;
    MIOSink      sink;
    MIOAppDriver adrv;
    uint32_t     miodflags;
    int          rv = 0;

    /* parse options */
    ytParseOptions(&argc, &argv);

    /* check to make sure the data structures are sane */
    yfAlignmentCheck();

    /* set up logging */
    if (!logc_setup(&err)) {
        air_opterr("%s", err->message);
    }

    /* fork if necessary */
    if (!daec_setup(&err)) {
        air_opterr("%s", err->message);
    }

    /* initialize MIO option flags */
    miodflags = MIO_F_OPT_SINKLINK;

    if (!mio_config_source(&source, yaft_cliflags, &miodflags, &err)) {
        air_opterr("Cannot set up input: %s", err->message);
    }

    /* set up sink */
    if (!mio_config_sink(&source, &sink, C("%s.yaf.txt"), yaft_cliflags,
                         &miodflags, &err))
    {
        air_opterr("Cannot set up output: %s", err->message);
    }

    /* initialize yafscii context */
    yfFlowPrepare(&(yx.flow));
    yx.fbuf = NULL;

    /* set up an app driver */
    adrv.app_open_source = ytOpenSource;
    adrv.app_open_sink = NULL;
    adrv.app_close_source = NULL;
    adrv.app_close_sink = NULL;
    adrv.app_process = ytProcess;

    /* run dispatch loop */
    if (!mio_dispatch_loop(&source, &sink, &adrv, &yx, miodflags, mio_ov_poll,
                           1, mio_ov_poll))
    {
        rv = 1;
    }

    if (yx.fbuf) {
        fBufFree(yx.fbuf);
    }

    g_message("yafscii terminating with %d flows read", yaft_flows);

    return rv;
}
