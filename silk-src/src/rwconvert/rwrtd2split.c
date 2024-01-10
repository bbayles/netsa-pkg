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
 * rwrtd2split
 *
 *  Read an input file in RWROUTED format and write the records to a
 *  new file in RWSPLIT format.
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwrtd2split.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skstream.h>
#include <silk/rwrec.h>
#include <silk/utils.h>
#include <silk/sksite.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout


/* LOCAL VARIABLES */

static char *in_fpath;
static char *out_fpath;
static skstream_t *in_stream;
static skstream_t *out_stream;

static int64_t hdr_len = 0;
static int64_t rec_len;


/* OPTIONS SETUP */

/*
** typedef enum {
** } appOptionsEnum;
*/

static struct option appOptions[] = {
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
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
#define USAGE_MSG                                                         \
    ("<INPUT_FILE> <OUTPUT_FILE>\n"                                       \
     "\tConvert INPUT_FILE, which should be in the FT_RWROUTED format,\n" \
     "\tto an FT_RWSPLIT file and write the result to OUTPUT_FILE.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
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

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    if (in_stream) {
        skStreamDestroy(&in_stream);
    }
    if (out_stream) {
        skStreamDestroy(&out_stream);
    }

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
    sk_file_header_t *in_hdr;
    sk_file_header_t *out_hdr = NULL;
    int arg_index;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
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

    /* parse the options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage();           /* never returns */
    }

    /* Ensure the site config is available */
    if (sksiteConfigure(1)) {
        exit(EXIT_FAILURE);
    }

    /* Get the input file name */
    if (arg_index == argc) {
        skAppPrintErr("Missing input file name");
        skAppUsage();         /* never returns */
    }
    in_fpath = argv[arg_index];
    ++arg_index;

    /* Get the output file name */
    if (arg_index == argc) {
        skAppPrintErr("Missing output file name");
        skAppUsage();         /* never returns */
    }
    out_fpath = argv[arg_index];
    ++arg_index;

    /* We don't expect additional files */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        skAppUsage();
    }

    /* Open input file */
    rv = skStreamOpenSilkFlow(&in_stream, in_fpath, SK_IO_READ);
    if (rv) {
        skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
        skStreamDestroy(&in_stream);
        exit(EXIT_FAILURE);
    }

    /* Get input file's header */
    in_hdr = skStreamGetSilkHeader(in_stream);

    /* Check input version */
    if (skHeaderGetFileFormat(in_hdr) != FT_RWROUTED) {
        skAppPrintErr("Input file '%s' not in RWROUTED format",
                      in_fpath);
        skStreamDestroy(&in_stream);
        exit(EXIT_FAILURE);
    }

    /* Create and open output file */
    rv = skStreamCreate(&out_stream, SK_IO_WRITE, SK_CONTENT_SILK_FLOW);
    if (rv == SKSTREAM_OK) {
        rv = skStreamBind(out_stream, out_fpath);
    }
    if (rv == SKSTREAM_OK) {
        out_hdr = skStreamGetSilkHeader(out_stream);
        rv = skHeaderCopy(out_hdr, in_hdr,
                          (SKHDR_CP_ALL & ~SKHDR_CP_FORMAT));
    }
    if (rv == SKSTREAM_OK) {
        rv = skHeaderSetFileFormat(out_hdr, FT_RWSPLIT);
    }
    if (rv == SKSTREAM_OK) {
        rv = skStreamOpen(out_stream);
    }
    if (rv == SKSTREAM_OK) {
        rv = skStreamWriteSilkHeader(out_stream);
    }
    if (rv != SKSTREAM_OK) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skAppPrintErr("Unable to open output file '%s'.", out_fpath);
        skStreamDestroy(&out_stream);
        exit(EXIT_FAILURE);
    }

    hdr_len = skHeaderGetLength(out_hdr);
    rec_len = skHeaderGetRecordLength(out_hdr);
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
    int          UNUSED(opt_index),
    char        UNUSED(*opt_arg))
{
    return 0;
}


int main(int argc, char **argv)
{
    rwRec rwrec;
    int64_t rec_count = 0;
    int64_t file_size_real = 0;
    int64_t file_size_calc = 0;
    int in_rv;
    int rv;

    /* Setup app: open input and output files; will exit(1) on error */
    appSetup(argc, argv);

    /* Process body */
    while (SKSTREAM_OK == (in_rv = skStreamReadRecord(in_stream, &rwrec))) {
        rec_count++;
        rv = skStreamWriteRecord(out_stream, &rwrec);
        if (rv != SKSTREAM_OK) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
            if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                skAppPrintErr("Error writing to '%s'.  Stopping copy.",
                              out_fpath);
                break;
            }
        }
    }
    if ((SKSTREAM_OK != in_rv) && (SKSTREAM_ERR_EOF != in_rv)) {
        skStreamPrintLastErr(in_stream, in_rv, &skAppPrintErr);
    }

    skStreamDestroy(&in_stream);
    rv = skStreamClose(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
    }
    skStreamDestroy(&out_stream);

    file_size_real = skFileSize(out_fpath);
    file_size_calc = hdr_len + rec_len * rec_count;
    if (file_size_real != file_size_calc) {
        skAppPrintErr(("ERROR: output filesize mismatch."
                       " Calc. %" PRId64 " vs real %" PRId64),
                      file_size_calc, file_size_real);
        exit(EXIT_FAILURE);
    }

    /* done */
    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
