/*
** Copyright (C) 2001-2023 by Carnegie Mellon University.
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
 *  rwset.c
 *
 *    Michael Collins
 *    May 6th
 *
 *    rwset is an application which takes filter data and generates a
 *    tree (rwset) of ip addresses which come out of a filter file.
 *    This tree can then be used to generate aggregate properties;
 *    rwsets will be used for filtering large sets of ip addresses,
 *    aggregate properties per element can be counted, &c.
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwset.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write output from --help */
#define USAGE_FH stdout

/* What to do when malloc() fails */
#define EXIT_NO_MEMORY                                               \
    do {                                                             \
        skAppPrintOutOfMemory(NULL);                                 \
        exit(EXIT_FAILURE);                                          \
    } while(0)

/* maximum number of set files that can be created: sip, dip, nhip,
 * any(sip+dip) */
#define SET_FILE_TYPES 4


/* LOCAL VARIABLES */

/* the IPsets and the streams where they will be written */
static struct sets_st {
    skipset_t  *ipset;
    skstream_t *stream;
    int         set_type;
} sets[SET_FILE_TYPES];

/* number of sets to write */
static int num_sets = 0;

/* whether the stdout has been claimed as an output stream */
static int stdout_used = 0;

/* for input processing */
static sk_options_ctx_t *optctx = NULL;

/* how to handle IPv6 flows */
static sk_ipv6policy_t ipv6_policy = SK_IPV6POLICY_MIX;

/* options for write the IPsets */
static skipset_options_t set_options;


/* OPTIONS SETUP */

typedef enum {
    OPT_SIP_FILE,
    OPT_DIP_FILE,
    OPT_NHIP_FILE,
    OPT_ANY_FILE
} appOptionsEnum;

static struct option appOptions[] = {
    {"sip-file",            REQUIRED_ARG, 0, OPT_SIP_FILE},
    {"dip-file",            REQUIRED_ARG, 0, OPT_DIP_FILE},
    {"nhip-file",           REQUIRED_ARG, 0, OPT_NHIP_FILE},
    {"any-file",            REQUIRED_ARG, 0, OPT_ANY_FILE},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    ("Create an IPset containing the unique source addresses\n"
     "\tand write it to the named file. Def. No"),
    ("Create an IPset containing the unique destination addresses\n"
     "\tand write it to the named file. Def. No"),
    ("Create an IPset containing the unique next-hop addresses\n"
     "\tand write it to the named file. Def. No"),
    ("Create an IPset containing the unique source AND destination\n"
     "\taddresses and write it to the named file. Def. No"),
    (char *)NULL
};



/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);


/* FUNCTION DEFINITIONS */

/*
 *  appUsageLong();
 *
 *    Print complete usage information to USAGE_FH.  Pass this
 *    function to skOptionsSetUsageCallback(); skOptionsParse() will
 *    call this funciton and then exit the program when the --help
 *    option is given.
 */
static void
appUsageLong(
    void)
{
#define USAGE_MSG                                                            \
    ("<IPSET-CREATION-SWITCHES> [SWITCHES] [FILES]\n"                        \
     "\tRead SiLK Flow records and generate one or more binary IPset\n"      \
     "\tfile(s). At least one creation switch must be specified, and only\n" \
     "\tone IPset of each possible type may be created. To write an IPset\n" \
     "\tto the standard output, specify its name as '-' or 'stdout'. When\n" \
     "\tno file names are specified on command line, rwset attempts to\n"    \
     "\tread flows from the standard input.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
    skIPSetOptionsUsage(fh);
    skOptionsCtxOptionsUsage(optctx, fh);
    skIPv6PolicyUsage(fh);
    sksiteOptionsUsage(fh);
}


/*
 *  appTeardown()
 *
 *    Teardown all modules, close all files, and tidy up all
 *    application state.
 *
 *    This function is idempotent.
 */
static void
appTeardown(
    void)
{
    static int teardownFlag = 0;
    int i;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    for (i = 0; i < num_sets; ++i) {
        if (sets[i].ipset) {
            skIPSetDestroy(&sets[i].ipset);
            sets[i].ipset = NULL;
        }
        if (sets[i].stream) {
            skStreamDestroy(&sets[i].stream);
        }
    }

    /* close the copy stream */
    skOptionsCtxCopyStreamClose(optctx, &skAppPrintErr);

    skIPSetOptionsTeardown();
    skOptionsCtxDestroy(&optctx);
    skAppUnregister();
}


/*
 *  appSetup(argc, argv);
 *
 *    Perform all the setup for this application include setting up
 *    required modules, parsing options, etc.  This function should be
 *    passed the same arguments that were passed into main().
 *
 *    Returns to the caller if all setup succeeds.  If anything fails,
 *    this function will cause the application to exit with a FAILURE
 *    exit status.
 */
static void
appSetup(
    int                 argc,
    char              **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    unsigned int optctx_flags;
    int i;
    int j;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    memset(sets, 0, sizeof(sets));
    memset(&set_options, 0, sizeof(skipset_options_t));
    set_options.existing_silk_files = 1;
    set_options.argc = argc;
    set_options.argv = argv;

    optctx_flags = (SK_OPTIONS_CTX_INPUT_SILK_FLOW | SK_OPTIONS_CTX_ALLOW_STDIN
                    | SK_OPTIONS_CTX_XARGS | SK_OPTIONS_CTX_PRINT_FILENAMES
                    | SK_OPTIONS_CTX_COPY_INPUT);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skIPSetOptionsRegister(&set_options)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE)
        || skIPv6PolicyOptionsRegister(&ipv6_policy))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* Parse options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();           /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* Make certain the user has requested some output. */
    if (0 == num_sets) {
        skAppPrintErr("No output specified; must specify file(s) to create");
        skAppUsage();
    }
    assert(SET_FILE_TYPES > num_sets);

    /* make certain stdout is not being used for multiple outputs */
    if (stdout_used && skOptionsCtxCopyStreamIsStdout(optctx)) {
        skAppPrintErr("May not use stdout for multiple output streams");
        exit(EXIT_FAILURE);
    }

    /* Open each output file; if any open fails, remove any files we
     * have previously opened. */
    for (i = 0; i < num_sets; ++i) {
        rv = skStreamOpen(sets[i].stream);
        if (rv) {
            skStreamPrintLastErr(sets[i].stream, rv, &skAppPrintErr);
            for (j = 0; j < i; ++j) {
                if (skStreamIsSeekable(sets[j].stream)) {
                    unlink(skStreamGetPathname(sets[j].stream));
                }
            }
            exit(EXIT_FAILURE);
        }
    }

    /* open the --copy-input stream */
    if (skOptionsCtxOpenStreams(optctx, &skAppPrintErr)) {
        exit(EXIT_FAILURE);
    }

    return;                       /* OK */
}


/*
 *  status = appOptionsHandler(cData, opt_index, opt_arg);
 *
 *    This function is passed to skOptionsRegister(); it will be called
 *    by skOptionsParse() for each user-specified switch that the
 *    application has registered; it should handle the switch as
 *    required---typically by setting global variables---and return 1
 *    if the switch processing failed or 0 if it succeeded.  Returning
 *    a non-zero from from the handler causes skOptionsParse() to return
 *    a negative value.
 *
 *    The clientData in 'cData' is typically ignored; 'opt_index' is
 *    the index number that was specified as the last value for each
 *    struct option in appOptions[]; 'opt_arg' is the user's argument
 *    to the switch for options that have a REQUIRED_ARG or an
 *    OPTIONAL_ARG.
 */
static int
appOptionsHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    int rv;
    int i;

    switch ((appOptionsEnum)opt_index) {
      case OPT_SIP_FILE:
      case OPT_DIP_FILE:
      case OPT_NHIP_FILE:
      case OPT_ANY_FILE:
        /* check for duplicates */
        for (i = 0; i < num_sets; ++i) {
            if (sets[i].set_type == opt_index) {
                skAppPrintErr("Invalid %s: Switch used multiple times",
                              appOptions[opt_index].name);
                return 1;
            }
        }
        /* check for multiple streams using stdout */
        if (0 == strcmp(opt_arg, "stdout") || 0 == strcmp(opt_arg, "-")) {
            if (stdout_used) {
                skAppPrintErr("Multiple outputs are trying to use stdout");
                return 1;
            }
            stdout_used = 1;
        }
        /* create the output stream */
        assert(SET_FILE_TYPES > num_sets);
        sets[num_sets].set_type = opt_index;
        if ((rv = skStreamCreate(&(sets[num_sets].stream), SK_IO_WRITE,
                                 SK_CONTENT_SILK))
            || (rv = skStreamBind(sets[num_sets].stream, opt_arg)))
        {
            skStreamPrintLastErr(sets[num_sets].stream, rv, &skAppPrintErr);
            skStreamDestroy(&(sets[num_sets].stream));
            return 1;
        }
        /* create the IPset */
        if (skIPSetCreate(&(sets[num_sets].ipset), 0)) {
            EXIT_NO_MEMORY;
        }
        skIPSetOptionsBind(sets[num_sets].ipset, &set_options);
        ++num_sets;
        break;
    }

    return 0;                     /* OK */
}


/*
 *  status = rwsetProcessFile(stream);
 *
 *    Read the records from 'stream' and add them to the appropriate
 *    IPSet files.  Return 0 on success, or -1 on failure.
 */
static int
rwsetProcessFile(
    skstream_t         *stream)
{
    static rwRec rwrec;
    static skipaddr_t ip;
    int rv = SKIPSET_OK;
    int rv_in;
    int i = 0;

    /* copy invocation and notes (annotations) from SiLK Flow files to
     * output sets; these headers will not be written to the output if
     * --invocation-strip or --notes-strip was specified. */
    for (i = 0; i < num_sets; ++i) {
        rv = skHeaderCopyEntries(skStreamGetSilkHeader(sets[i].stream),
                                 skStreamGetSilkHeader(stream),
                                 SK_HENTRY_INVOCATION_ID);
        if (rv) {
            skStreamPrintLastErr(sets[i].stream, rv, &skAppPrintErr);
            return -1;
        }
        rv = skHeaderCopyEntries(skStreamGetSilkHeader(sets[i].stream),
                                 skStreamGetSilkHeader(stream),
                                 SK_HENTRY_ANNOTATION_ID);
        if (rv) {
            skStreamPrintLastErr(sets[i].stream, rv, &skAppPrintErr);
            return -1;
        }
    }

    /* Read in records */
    while ((rv_in = skStreamReadRecord(stream, &rwrec)) == SKSTREAM_OK) {
        for (i = 0; i < num_sets; ++i) {
            switch (sets[i].set_type) {
              case OPT_SIP_FILE:
                rwRecMemGetSIP(&rwrec, &ip);
                rv = skIPSetInsertAddress(sets[i].ipset, &ip, 0);
                if (rv) {
                    goto END;
                }
                break;
              case OPT_ANY_FILE:
                rwRecMemGetSIP(&rwrec, &ip);
                rv = skIPSetInsertAddress(sets[i].ipset, &ip, 0);
                if (rv) {
                    goto END;
                }
                /* FALLTHROUGH */
              case OPT_DIP_FILE:
                rwRecMemGetDIP(&rwrec, &ip);
                rv = skIPSetInsertAddress(sets[i].ipset, &ip, 0);
                if (rv) {
                    goto END;
                }
                break;
              case OPT_NHIP_FILE:
                rwRecMemGetNhIP(&rwrec, &ip);
                rv = skIPSetInsertAddress(sets[i].ipset, &ip, 0);
                if (rv) {
                    goto END;
                }
                break;
              default:
                skAbortBadCase(sets[i].set_type);
            }
        }
    }
    if (rv_in != SKSTREAM_ERR_EOF && rv_in != SKSTREAM_OK) {
        skStreamPrintLastErr(stream, rv_in, &skAppPrintErr);
    }

  END:
    if (rv) {
        skAppPrintErr("Error adding IP to %s: %s",
                      appOptions[i].name, skIPSetStrerror(rv));
        skStreamDestroy(&stream);
        return -1;
    }

    return 0;
}


int main(int argc, char **argv)
{
    skstream_t *stream;
    char errbuf[2 * PATH_MAX];
    ssize_t rv;
    int had_err = 0;
    int i;

    appSetup(argc, argv);                 /* never returns on error */

    /* process input files */
    while ((rv = skOptionsCtxNextSilkFile(optctx, &stream, &skAppPrintErr))
           == 0)
    {
        skStreamSetIPv6Policy(stream, ipv6_policy);
        if (rwsetProcessFile(stream)) {
            skStreamDestroy(&stream);
            exit(EXIT_FAILURE);
        }
        skStreamDestroy(&stream);
    }
    if (rv < 0) {
        exit(EXIT_FAILURE);
    }

    /* Write the output */
    for (i = 0; i < num_sets; ++i) {
        skIPSetClean(sets[i].ipset);
        rv = skIPSetWrite(sets[i].ipset, sets[i].stream);
        if (SKIPSET_OK == rv) {
            rv = skStreamClose(sets[i].stream);
            if (rv) {
                had_err = 1;
                skStreamLastErrMessage(sets[i].stream, rv,
                                       errbuf, sizeof(errbuf));
                skAppPrintErr("Error writing %s IPset: %s",
                              appOptions[sets[i].set_type].name, errbuf);
            }
        } else if (SKIPSET_ERR_FILEIO == rv) {
            had_err = 1;
            rv = skStreamGetLastReturnValue(sets[i].stream);
            skStreamLastErrMessage(sets[i].stream, rv, errbuf, sizeof(errbuf));
            skAppPrintErr("Error writing %s IPset: %s",
                          appOptions[sets[i].set_type].name, errbuf);
        } else {
            had_err = 1;
            skAppPrintErr("Error writing %s IPset to '%s': %s",
                          appOptions[sets[i].set_type].name,
                          skStreamGetPathname(sets[i].stream),
                          skIPSetStrerror(rv));
        }
        skStreamDestroy(&sets[i].stream);
        skIPSetDestroy(&sets[i].ipset);
        sets[i].ipset = NULL;
    }

    /* done */
    return ((had_err) ? EXIT_FAILURE : EXIT_SUCCESS);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
