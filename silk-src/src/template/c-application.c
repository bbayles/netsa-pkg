/*
** Copyright (C) 2023 by Carnegie Mellon University.
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
**  Application commentary goes here.
**  Include the author's name and date (month and year is good enough).
**
*/


#include <silk/silk.h>

RCSIDENT("$Id$");

#include <silk/skstream.h>
#include <silk/sksite.h>
#include <silk/utils.h>
#error "If you need additional headers, add them here"


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout


/* EXPORTED VARIABLE DEFINITIONS */

#error "Any exported variables should also be declared in a header file."


/* LOCAL VARIABLE DEFINITIONS */

/* EXAMPLE: loop over files given on command line */
static int arg_index;


/* OPTIONS SETUP */

typedef enum {
#error "Give a enum value for each option, following these examples:"
    OPT_FIRST,                  /* remove when real options added */
    OPT_SECOND                  /* remove when real options added */
} appOptionsEnum;

static struct option appOptions[] = {

#error "add  the applications options here:"
#error "1: the option name"
#error "2: the argument type: REQUIRED_ARG, NO_ARG, OPTIONAL_ARG"
#error "3: always 0"
#error "4: the index number of the option starting at 0."
#error "NOTE: Keep each of appOptionsEeum, appOptions[], appHelp[], and"
#error "      the switch() cases in appOptionsHandler() in sync"

    {"first",           REQUIRED_ARG, 0, OPT_FIRST},  /* remove when real options added */
    {"second",          NO_ARG,       0, OPT_SECOND}, /* remove when real options added */
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
#error "add help strings here for the application's options"
    "My first option's help",   /* remove when real options added */
    "My second option's help",  /* remove when real options added */
    (char *)NULL
};



/* LOCAL FUNCTION PROTOTYPES */

static void appUsageLong(void);
static void appTeardown(void);
static void appSetup(int argc, char **argv);
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
#error "Give a brief description of your app"
#define USAGE_MSG                                                             \
    ("[SWITCHES] [FILES]\n"                                                   \
     "\tDoes nothing right now because no one has told this application\n"    \
     "\twhat it needs to do.\n")

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

#error "Anything you put in setup should now be torn down"
    /* for example, close sample output file */
    skStreamDestroy(&out_stream);

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
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
#error "Initialize any global variables here"
    /* for example: set global output to NULL */
    out_stream = NULL;

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

#error "Do any other module setup here"

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

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

#error "Do any options validation here"

#error "If you expect filenames on command line keep this:"
    /* arg_index is looking at first file name to process */
    if (arg_index == argc) {
        if (FILEIsATty(stdin)) {
            skAppPrintErr("No input files on command line and"
                          " stdin is connected to a terminal");
            skAppUsage();       /* never returns */
        }
    }

#error "If you do NOT expect filenames on command line, keep this:"
    /* check for extraneous arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        skAppUsage();           /* never returns */
    }

#error "Once all options are set, open input and output"
    /* for example, open a SiLK flow file as an output file */
    rv = skStreamOpenSilkFlow(&out_stream, output_path, SK_IO_WRITE);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skAppPrintErr("Unable to open output file. Exiting");
        skStreamDestroy(&out_stream);
        exit(EXIT_FAILURE);
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
    int rv;

    switch ((appOptionsEnum)opt_index) {
#error "Add options handling here.  Return 1 on failure."

      case OPT_FIRST:           /* remove when real options added */
        /* do something with the argument to the switch; for example,
         * parse as an integer */
        rv = skStringParseUint32(&value, opt_arg, 0, 0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;

      case OPT_SECOND:          /* remove when real options added */
        /* set a flag based on this option */
        flag = 1;
        break;
    }

    return 0;  /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


/*
 *  stream = appNextInput(argc, argv);
 *
 *    Open and return the next input file from the command line or the
 *    standard input if no files were given on the command line.
 */
static skstream_t *
appNextInput(
    int                 argc,
    char              **argv)
{
    static int initialized = 0;
    skstream_t *stream = NULL;
    const char *fname = NULL;
    int rv;

    if (arg_index < argc) {
        /* get current file and prepare to get next */
        fname = argv[arg_index];
        ++arg_index;
    } else {
        if (initialized) {
            /* no more input */
            return NULL;
        }
        /* input is from stdin */
        fname = "stdin";
    }

    initialized = 1;

    /* create stream and open file */
    rv = skStreamOpenSilkFlow(&stream, fname, SK_IO_READ);
    if (rv) {
        skStreamPrintLastErr(stream, rv, NULL);
        skStreamDestroy(&stream);
    }

    return stream;
}


int main(int argc, char **argv)
{
    skstream_t *in_stream;
    int in_rv = SKSTREAM_OK;
    int rv = SKSTREAM_OK;

    appSetup(argc, argv);                       /* never returns on error */

#error "Loop over files on command line or read from stdin."
#error "Process each file, preferably in a separate function."
    /* For each input, process each record */
    while (NULL != (in_stream = appNextInput(argc, argv))) {
        while ((in_rv = skStreamReadRecord(in_stream, &rwrec))==SKSTREAM_OK) {
            /* process record */
            rv = skStreamWriteRecord(out_stream, &rwrec);
            if (SKSTREAM_OK != rv) {
                skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
                skStreamDestroy(&in_stream);
                goto END;
            }
        }
        if (SKSTREAM_ERR_EOF != in_rv) {
            skStreamPrintLastErr(in_stream, in_rv, &skAppPrintErr);
        }
        skStreamDestroy(&in_stream);
    }

    rv = skStreamClose(out_stream);
    if (SKSTREAM_OK != rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
    }

  END:
    return ((SKSTREAM_OK == rv) ? EXIT_SUCCESS : EXIT_FAILURE);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
