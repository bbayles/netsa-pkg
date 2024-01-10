/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
**  skheaders-test
**
**    Simple program to test the skheader.c code.
**
**    Mark Thomas
**    November 2006
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skheader-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>
#include "skheader_priv.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout


/* LOCAL VARIABLE DEFINITIONS */

/* name of file to read or write */
static const char *fname = NULL;

/* whether to read or write */
static int read_or_write = -1;


/* OPTIONS SETUP */

typedef enum {
    OPT_READ,
    OPT_WRITE
} appOptionsEnum;

static struct option appOptions[] = {
    {"read",            REQUIRED_ARG, 0, OPT_READ},
    {"write",           REQUIRED_ARG, 0, OPT_WRITE},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    "File to read.",
    "File to write",
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
#define USAGE_MSG                                                       \
    ("[SWITCHES] {--read=FILE | --write=FILE}\n"                        \
     "\tTest program for skheader.c.  With --write=FILE, writes a simple\n" \
     "\tfile to FILE.  With --read=FILE; reads that file.  Only use\n"  \
     "\t--read for files created with skheader-test --write=FILE\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
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
    int arg_index;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL))
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
        /* options parsing should print error */
        skAppUsage();           /* never returns */
    }

    /* Try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names. */
    sksiteConfigure(0);

    if (fname == NULL) {
        skAppPrintErr("Must specify --%s or --%s",
                      appOptions[OPT_READ].name, appOptions[OPT_WRITE].name);
        skAppUsage();
    }

    /* check for extraneous arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        skAppUsage();           /* never returns */
    }

    return;  /* OK */
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
    switch ((appOptionsEnum)opt_index) {
      case OPT_READ:
      case OPT_WRITE:
        if (fname) {
            skAppPrintErr("May only specify one of --%s or --%s and only once",
                          appOptions[OPT_READ].name,
                          appOptions[OPT_WRITE].name);
            return 1;
        }
        fname = opt_arg;
        read_or_write = opt_index;
        break;
    }

    return 0;  /* OK */
}




static int
doread(
    const char         *file)
{
    skstream_t *stream;
    sk_file_header_t *hdr;
    sk_header_entry_t *he;
    sk_hentry_iterator_t iter;
    int rv;

    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, file))
        || (rv = skStreamOpen(stream)))
    {
        skAppPrintErr("Unable to open %s", file);
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        skStreamDestroy(&stream);
        return -1;
    }

    if (skStreamReadSilkHeader(stream, &hdr)) {
        skAppPrintErr("Unable to read header start");
        return -1;
    }

    skHeaderIteratorBind(&iter, hdr);
    while ((he = skHeaderIteratorNext(&iter)) != NULL) {
        printf("HDR id = %" PRIu32 " / len = %" PRIu32 " / ",
                (uint32_t)skHeaderEntryGetTypeId(he),
                (uint32_t)he->he_spec.hes_len);
        skHeaderEntryPrint(he, stdout);
        printf("\n");
    }

    return 0;
}


static int
dowrite(
    const char         *file,
    int                 argc,
    char              **argv)
{
    skstream_t *stream;
    sk_file_header_t *hdr;
    int rv;

    if ((rv = skStreamCreate(&stream, SK_IO_WRITE, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, file)))
    {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        skStreamDestroy(&stream);
        return -1;
    }

    hdr = skStreamGetSilkHeader(stream);

    if (skHeaderAddPackedfile(hdr, 1164215667, 1, 5)) {
        skAppPrintErr("Unable to add packedfile hentry");
        return -1;
    }

    if (skHeaderAddInvocation(hdr, 1, argc, argv)) {
        skAppPrintErr("Unable to add invocation hentry");
        return -1;
    }

    if (skHeaderAddAnnotation(hdr, "blah blah blah")) {
        skAppPrintErr("Unable to add annotation hentry");
        return -1;
    }

    if (skHeaderAddProbename(hdr, "S1_yaf")) {
        skAppPrintErr("Unable to add probename hentry");
        return -1;
    }

    rv = skStreamOpen(stream);
    if (rv) {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        skStreamDestroy(&stream);
        return -1;
    }

    if (skStreamWriteSilkHeader(stream)) {
        skAppPrintErr("Unable to write header");
        return -1;
    }

    rv = skStreamClose(stream);
    if (rv) {
        skAppPrintErr("Error closing %s: %s", file, strerror(errno));
        return -1;
    }
    skStreamDestroy(&stream);

    return 0;
}


int main(int argc, char **argv)
{
    appSetup(argc, argv);                       /* never returns on error */

    skHeaderInitialize();

    switch ((appOptionsEnum)read_or_write) {
      case OPT_READ:
        doread(fname);
        break;
      case OPT_WRITE:
        dowrite(fname, argc, argv);
        break;
    }

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
