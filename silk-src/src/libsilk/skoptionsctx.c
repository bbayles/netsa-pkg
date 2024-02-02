/*
** Copyright (C) 2011-2023 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
**
** SiLK 3.22.0
**
** Copyright 2023 Carnegie Mellon University.
**
** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
** INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
** UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
** AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
** PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
** THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
** INFRINGEMENT.
**
** Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
** contact permission@sei.cmu.edu for full terms.
**
** [DISTRIBUTION STATEMENT A] This material has been approved for public
** release and unlimited distribution.  Please see Copyright notice for
** non-US Government use and distribution.
**
** GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
**
** Contract No.: FA8702-15-D-0002
** Contractor Name: Carnegie Mellon University
** Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
**
** The Government's rights to use, modify, reproduce, release, perform,
** display, or disclose this software are restricted by paragraph (b)(2) of
** the Rights in Noncommercial Computer Software and Noncommercial Computer
** Software Documentation clause contained in the above identified
** contract. No restrictions apply after the expiration date shown
** above. Any reproduction of the software or portions thereof marked with
** this legend must also reproduce the markings.
**
** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
** Trademark Office by Carnegie Mellon University.
**
** This Software includes and/or makes use of Third-Party Software each
** subject to its own license.
**
** DM23-0973
**
** @OPENSOURCE_LICENSE_END@
*/

/*
**  skoptionsctx.c
**
**    Support for --xargs, reading from stdin, and looping over
**    filenames on the command line.
**
**    Mark Thomas
**    May 2011
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skoptionsctx.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/skstream.h>


/* LOCAL DEFINES AND TYPEDEFS */

#define PATH_IS_STDIN(path)                                     \
    (0 == strcmp((path), "-") || 0 == strcmp((path), "stdin"))
#define PATH_IS_STDOUT(path)                                    \
    (0 == strcmp((path), "-") || 0 == strcmp((path), "stdout"))

/* typedef struct sk_options_ctx_st sk_options_ctx_t; */
struct sk_options_ctx_st {
    sk_options_ctx_open_cb_t    open_cb_fn;
    FILE           *print_filenames;
    skstream_t     *xargs;
    skstream_t     *copy_input;
    const char     *input_pipe;
    char          **argv;
    int             argc;
    int             arg_index;
    unsigned int    flags;
    unsigned        stdin_used      :1;
    unsigned        stdout_used     :1;
    unsigned        parse_ok        :1;
    unsigned        init_ok         :1;
    unsigned        init_failed     :1;
    unsigned        read_stdin      :1;
    unsigned        no_more_inputs  :1;
};


/* LOCAL VARIABLE DEFINITIONS */

static const struct options_ctx_options_st {
    struct option   opt;
    const char     *help;
} options_ctx_options[] = {
    {{"print-filenames", NO_ARG,       0, SK_OPTIONS_CTX_PRINT_FILENAMES},
     ("Print input filenames while processing. Def. no")},
    {{"copy-input",      REQUIRED_ARG, 0, SK_OPTIONS_CTX_COPY_INPUT},
     ("Copy all input SiLK Flows to given pipe or file. Def. No")},
    {{"input-pipe",      REQUIRED_ARG, 0, SK_OPTIONS_CTX_INPUT_PIPE},
     ("Get input byte stream from pipe (stdin|pipe).\n"
      "\tThis switch is deprecated and will be removed in a future release.\n"
      "\tDefault is stdin if no filenames are given on the command line")},
    {{"xargs",           OPTIONAL_ARG, 0, SK_OPTIONS_CTX_XARGS},
     ("Read the names of the files to process from named text file,\n"
      "\tone name per line, or from the standard input if no parameter."
      " Def. no")},
    {{0, 0, 0, 0}, 0}    /* sentinel */
};



/* FUNCTION DEFINITIONS */

static const char *
optionsCtxSwitchName(
    int                 opt_index)
{
    size_t i;

    for (i = 0; options_ctx_options[i].help; ++i) {
        if (options_ctx_options[i].opt.val == opt_index) {
            return options_ctx_options[i].opt.name;
        }
    }
    skAbortBadCase(opt_index);
}

static int
optionsCtxHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    sk_options_ctx_t *arg_ctx = (sk_options_ctx_t*)cData;
    int rv;

    if (opt_arg && strlen(opt_arg) == strspn(opt_arg, "\t\n\v\f\r ")) {
        skAppPrintErr("Invalid %s: Argument contains only whitespace",
                      optionsCtxSwitchName(opt_index));
        return 1;
    }

    switch (opt_index) {
      case SK_OPTIONS_CTX_PRINT_FILENAMES:
        arg_ctx->print_filenames = stderr;
        break;

      case SK_OPTIONS_CTX_COPY_INPUT:
        if (arg_ctx->copy_input) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          optionsCtxSwitchName(opt_index));
            return 1;
        }
        if (NULL == opt_arg || PATH_IS_STDOUT(opt_arg)) {
            if (arg_ctx->stdout_used) {
                skAppPrintErr("Multiple outputs attempt"
                              " to use standard output");
                return 1;
            }
            arg_ctx->stdout_used = 1;
        }
        if ((rv = skStreamCreate(&arg_ctx->copy_input, SK_IO_WRITE,
                                 SK_CONTENT_SILK_FLOW))
            || (rv = skStreamBind(arg_ctx->copy_input, opt_arg)))
        {
            skStreamPrintLastErr(arg_ctx->copy_input, rv, skAppPrintErr);
            skStreamDestroy(&arg_ctx->copy_input);
            return 1;
        }
        break;

      case SK_OPTIONS_CTX_XARGS:
        if (arg_ctx->xargs) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          optionsCtxSwitchName(opt_index));
            return 1;
        }
        if (NULL == opt_arg || PATH_IS_STDIN(opt_arg)) {
            if (arg_ctx->stdin_used) {
                skAppPrintErr("Multiple inputs attempt to use standard input");
                return 1;
            }
            arg_ctx->stdin_used = 1;
        }
        if ((rv = skStreamCreate(&arg_ctx->xargs, SK_IO_READ, SK_CONTENT_TEXT))
            || (rv = skStreamBind(arg_ctx->xargs, (opt_arg ? opt_arg : "-"))))
        {
            skStreamPrintLastErr(arg_ctx->xargs, rv, &skAppPrintErr);
            skStreamDestroy(&arg_ctx->xargs);
            return 1;
        }
        break;

      case SK_OPTIONS_CTX_INPUT_PIPE:
        if (arg_ctx->input_pipe) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          optionsCtxSwitchName(opt_index));
            return 1;
        }
        if (NULL == opt_arg || PATH_IS_STDIN(opt_arg)) {
            if (FILEIsATty(stdin)
                && (arg_ctx->flags & (SK_OPTIONS_CTX_INPUT_BINARY
                                      | SK_OPTIONS_CTX_INPUT_SILK_FLOW)))
            {
                skAppPrintErr(("Invalid %s '%s': "
                               "Will not read binary data on a terminal"),
                              optionsCtxSwitchName(SK_OPTIONS_CTX_INPUT_PIPE),
                              opt_arg);
                return 1;
            }
            if (arg_ctx->stdin_used) {
                skAppPrintErr("Multiple inputs attempt to use standard input");
                return 1;
            }
            arg_ctx->stdin_used = 1;
        }
        arg_ctx->input_pipe = opt_arg;
        break;

      default:
        skAbortBadCase(opt_index);
    }

    return 0;
}


int
skOptionsCtxCopyStreamClose(
    sk_options_ctx_t   *arg_ctx,
    sk_msg_fn_t         err_fn)
{
    int rv;

    if (arg_ctx->copy_input && arg_ctx->init_ok) {
        rv = skStreamClose(arg_ctx->copy_input);
        if (rv && err_fn) {
            skStreamPrintLastErr(arg_ctx->copy_input, rv, err_fn);
        }
        return rv;
    }
    return 0;
}


int
skOptionsCtxCopyStreamIsActive(
    const sk_options_ctx_t *arg_ctx)
{
    return ((arg_ctx->copy_input) ? 1 : 0);
}


int
skOptionsCtxCopyStreamIsStdout(
    const sk_options_ctx_t *arg_ctx)
{
    if (arg_ctx->copy_input) {
        return PATH_IS_STDOUT(skStreamGetPathname(arg_ctx->copy_input));
    }
    return 0;
}


int
skOptionsCtxCountArgs(
    const sk_options_ctx_t *arg_ctx)
{
    if (!arg_ctx->parse_ok) {
        return -1;
    }
    return (arg_ctx->argc - arg_ctx->arg_index);
}


int
skOptionsCtxCreate(
    sk_options_ctx_t  **arg_ctx,
    unsigned int        flags)
{
    *arg_ctx = (sk_options_ctx_t*)calloc(1, sizeof(sk_options_ctx_t));
    if (NULL == *arg_ctx) {
        return -1;
    }
    (*arg_ctx)->flags = flags;
    return 0;
}


int
skOptionsCtxDestroy(
    sk_options_ctx_t  **arg_ctx)
{
    sk_options_ctx_t *ctx;
    int rv = 0;

    if (NULL == arg_ctx || NULL == *arg_ctx) {
        return 0;
    }
    ctx = *arg_ctx;
    *arg_ctx = NULL;

    skStreamDestroy(&ctx->xargs);
    if (ctx->copy_input) {
        if (ctx->init_ok) {
            rv = skStreamClose(ctx->copy_input);
        }
        skStreamDestroy(&ctx->copy_input);
    }
    free(ctx);
    return rv;
}


FILE *
skOptionsCtxGetPrintFilenames(
    const sk_options_ctx_t *arg_ctx)
{
    return arg_ctx->print_filenames;
}


int
skOptionsCtxNextArgument(
    sk_options_ctx_t   *arg_ctx,
    char              **arg)
{
    static char buf[PATH_MAX];
    int rv;

    assert(arg_ctx);
    assert(arg);

    if (arg_ctx->no_more_inputs) {
        return 1;
    }
    if (!arg_ctx->parse_ok || arg_ctx->init_failed) {
        return -1;
    }
    if (!arg_ctx->init_ok) {
        rv = skOptionsCtxOpenStreams(arg_ctx, NULL);
        if (rv) {
            return rv;
        }
    }

    if (arg_ctx->xargs) {
        for (;;) {
            rv = skStreamGetLine(arg_ctx->xargs, buf, sizeof(buf), NULL);
            if (SKSTREAM_OK == rv) {
                *arg = buf;
                return 0;
            }
            if (SKSTREAM_ERR_LONG_LINE == rv) {
                continue;
            }
            arg_ctx->no_more_inputs = 1;
            if (SKSTREAM_ERR_EOF == rv) {
                return 1;
            }
            skStreamPrintLastErr(arg_ctx->xargs, rv, skAppPrintErr);
            return -1;
        }
    }
    if (arg_ctx->input_pipe) {
        arg_ctx->no_more_inputs = 1;
        *arg = (char*)arg_ctx->input_pipe;
        return 0;
    }
    if (arg_ctx->read_stdin) {
        arg_ctx->no_more_inputs = 1;
        *arg = (char*)"-";
        return 0;
    }
    if (arg_ctx->arg_index < arg_ctx->argc) {
        *arg = arg_ctx->argv[arg_ctx->arg_index];
        ++arg_ctx->arg_index;
        return 0;
    }
    arg_ctx->no_more_inputs = 1;
    return 1;
}


int
skOptionsCtxNextSilkFile(
    sk_options_ctx_t   *arg_ctx,
    skstream_t        **stream,
    sk_msg_fn_t         err_fn)
{
    char *path;
    int rv;

    for (;;) {
        rv = skOptionsCtxNextArgument(arg_ctx, &path);
        if (rv != 0) {
            return rv;
        }
        rv = skStreamOpenSilkFlow(stream, path, SK_IO_READ);
        if (rv != SKSTREAM_OK) {
            if (err_fn) {
                skStreamPrintLastErr(*stream, rv, err_fn);
                skStreamDestroy(stream);
            }
            return -1;
        }
        if (arg_ctx->open_cb_fn) {
            rv = arg_ctx->open_cb_fn(*stream);
            if (rv) {
                if (rv > 0) {
                    skStreamDestroy(stream);
                    continue;
                }
                return rv;
            }
        }
        if (arg_ctx->copy_input) {
            skStreamSetCopyInput(*stream, arg_ctx->copy_input);
        }
        if (arg_ctx->print_filenames) {
            fprintf(arg_ctx->print_filenames, "%s\n", path);
        }
        return 0;
    }
}


int
skOptionsCtxOpenStreams(
    sk_options_ctx_t   *arg_ctx,
    sk_msg_fn_t         err_fn)
{
    int rv;

    if (!arg_ctx->parse_ok) {
        return -1;
    }
    if (arg_ctx->init_ok) {
        return 0;
    }
    if (arg_ctx->init_failed) {
        return -1;
    }

    if (arg_ctx->xargs) {
        rv = skStreamOpen(arg_ctx->xargs);
        if (rv) {
            if (err_fn) {
                skStreamPrintLastErr(arg_ctx->xargs, rv, err_fn);
            }
            arg_ctx->init_failed = 1;
            return -1;
        }
    }
    if (arg_ctx->copy_input) {
        rv = skStreamOpen(arg_ctx->copy_input);
        if (rv) {
            if (err_fn) {
                skStreamPrintLastErr(arg_ctx->copy_input, rv, err_fn);
            }
            arg_ctx->init_failed = 1;
            return -1;
        }
    }

    arg_ctx->init_ok = 1;
    return 0;
}


/* FIXME: consider adding a separate flags parameter here */
int
skOptionsCtxOptionsParse(
    sk_options_ctx_t   *arg_ctx,
    int                 argc,
    char              **argv)
{
    if (NULL == arg_ctx) {
        return skOptionsParse(argc, argv);
    }

    arg_ctx->argc = argc;
    arg_ctx->argv = argv;
    arg_ctx->arg_index = skOptionsParse(argc, argv);
    if (arg_ctx->arg_index < 0) {
        return arg_ctx->arg_index;
    }

    /*
     * if (ignore_non_switch_args) {
     *     return arg_index;
     * }
     */

    /* handle case where all args are specified with switches */
    if (arg_ctx->flags & SK_OPTIONS_CTX_SWITCHES_ONLY) {
        if (arg_ctx->arg_index != argc) {
            skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                          argv[arg_ctx->arg_index]);
            return -1;
        }
        return 0;
    }

    /* some sort of input is required */

    if (arg_ctx->xargs) {
        if (arg_ctx->input_pipe) {
            skAppPrintErr("May not use both --%s and --%s",
                          optionsCtxSwitchName(SK_OPTIONS_CTX_XARGS),
                          optionsCtxSwitchName(SK_OPTIONS_CTX_INPUT_PIPE));
            return 1;
        }
        if (arg_ctx->arg_index != argc) {
            skAppPrintErr("May not use --%s and give files on command line",
                          optionsCtxSwitchName(SK_OPTIONS_CTX_XARGS));
            return -1;
        }
        arg_ctx->parse_ok = 1;
        return 0;
    }

    if (arg_ctx->input_pipe) {
        if (arg_ctx->arg_index != argc) {
            skAppPrintErr("May not use --%s and give files on command line",
                          optionsCtxSwitchName(SK_OPTIONS_CTX_INPUT_PIPE));
            return -1;
        }
        arg_ctx->parse_ok = 1;
        return 0;
    }

    if (!(arg_ctx->flags & SK_OPTIONS_CTX_ALLOW_STDIN)) {
        if (arg_ctx->arg_index == argc) {
            skAppPrintErr("No input files specified on the command line");
            return -1;
        }
        arg_ctx->parse_ok = 1;
        return 0;
    }

    /* stdin or files listed on command line allowed */

    if (arg_ctx->arg_index < argc) {
        arg_ctx->parse_ok = 1;
        return 0;
    }

    if (FILEIsATty(stdin)
        && (arg_ctx->flags &
            (SK_OPTIONS_CTX_INPUT_BINARY | SK_OPTIONS_CTX_INPUT_SILK_FLOW)))
    {
        skAppPrintErr("No input files specified on the command line"
                      " and standard input is a terminal");
        return -1;
    }
    if (arg_ctx->stdin_used) {
        skAppPrintErr("Multiple inputs attempt to use standard input");
        return 1;
    }
    arg_ctx->stdin_used = 1;
    arg_ctx->read_stdin = 1;

    arg_ctx->parse_ok = 1;
    return 0;
}


int
skOptionsCtxOptionsRegister(
    const sk_options_ctx_t *arg_ctx)
{
    size_t i;
    int rv = 0;

    for (i = 0; options_ctx_options[i].help && 0 == rv; ++i) {
        if (arg_ctx->flags & options_ctx_options[i].opt.val) {
            rv = skOptionsRegisterCount(&options_ctx_options[i].opt, 1,
                                        optionsCtxHandler,(clientData)arg_ctx);
        }
    }
    return rv;
}

void
skOptionsCtxOptionsUsage(
    const sk_options_ctx_t *arg_ctx,
    FILE                   *fh)
{
    size_t i;

    for (i = 0; options_ctx_options[i].help; ++i) {
        if (arg_ctx->flags & options_ctx_options[i].opt.val) {
            fprintf(fh, "--%s %s. %s\n", options_ctx_options[i].opt.name,
                    SK_OPTION_HAS_ARG(options_ctx_options[i].opt),
                    options_ctx_options[i].help);
        }
    }
}


void
skOptionsCtxSetOpenCallback(
    sk_options_ctx_t           *arg_ctx,
    sk_options_ctx_open_cb_t    open_callback_fn)
{
    assert(arg_ctx);
    arg_ctx->open_cb_fn = open_callback_fn;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
