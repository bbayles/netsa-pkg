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
**
**  rwappend.c
**
**  Suresh L Konda
**  8/10/2002
**      Append f2..fn to f1.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwappend.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write output from --help */
#define USAGE_FH stdout

/* where to write output from --print-stat */
#define STATISTICS_FH  stderr


/* LOCAL VARIABLES */

/* file to append to */
static skstream_t *out_stream = NULL;

/* whether to create the out_stream file if it does not exist */
static int allow_create = 0;

/* if creating the out_stream file, this is the name of the file to
 * use as the template for the new file. */
static const char *create_format = NULL;

/* whether to print the statistics */
static int print_statistics = 0;

/* index into argv[]; used to loop over filenames */
static int arg_index;


/* OPTIONS SETUP */

typedef enum {
    OPT_CREATE, OPT_PRINT_STATISTICS
} appOptionsEnum;

static struct option appOptions[] = {
    {"create",                  OPTIONAL_ARG, 0, OPT_CREATE},
    {"print-statistics",        NO_ARG,       0, OPT_PRINT_STATISTICS},
    {0,0,0,0}                   /* sentinel entry */
};

static const char *appHelp[] = {
    ("Create the TARGET-FILE if it does not exist.  Uses the\n"
     "\toptional SiLK file argument to determine the format of TARGET-FILE.\n"
     "\tDef. Exit when TARGET-FILE nonexistent; use default format"),
    ("Print to stderr the count of records read from each\n"
     "\tSOURCE-FILE and the total records added to the TARGET-FILE. Def. No"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  createFromTemplate(const char *new_path, const char *templ_file);


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
    ("[SWITCHES] TARGET-FILE SOURCE-FILE1 [SOURCE-FILE2...]\n"          \
     "\tAppend the SiLK Flow records contained in the second through\n" \
     "\tfinal filename arguments to the records contained in the\n"     \
     "\tfirst filename argument.  All files must be SiLK flow files;\n" \
     "\tthe TARGET-FILE must not be compressed.\n")

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
    int rv;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* close appended-to file */
    if (out_stream) {
        rv = skStreamDestroy(&out_stream);
        if (rv) {
            skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        }
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
    const char *output_path;
    int did_create = 0;
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

    /* parse options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage(); /* never returns */
    }

    /* try to load site config file; if it fails, we will not be able
     * to resolve flowtype and sensor from input file names */
    sksiteConfigure(0);

    /* get the output file */
    if (argc == arg_index) {
        skAppPrintErr("Missing name of TARGET-FILE");
        skAppUsage();           /* never returns */
    }

    /* get the target file */
    output_path = argv[arg_index];
    ++arg_index;

    /* If the target does not exist, complain or create it. */
    errno = 0;
    if (skFileExists(output_path)) {
        /* file exists and is a regular file */

    } else if (0 == errno) {
        /* file is not a regular file */
        skAppPrintErr("Target file '%s' is invalid: Not a regular file",
                      output_path);
        exit(EXIT_FAILURE);

    } else if (ENOENT != errno) {
        /* Some error other than "does not exist" */
        skAppPrintSyserror("Target file '%s' is invalid",
                           output_path);
        exit(EXIT_FAILURE);

    } else if (0 == allow_create) {
        /* file does not exist but --create not given */
        skAppPrintSyserror(
            "Target file '%s' is invalid and --%s not specified",
            output_path, appOptions[OPT_CREATE].name);
        exit(EXIT_FAILURE);

    } else {
        /* create the file */
        did_create = 1;
        if (createFromTemplate(output_path, create_format)) {
            exit(EXIT_FAILURE);
        }
    }

    /* open the target file for append */
    rv = skStreamOpenSilkFlow(&out_stream, output_path, SK_IO_APPEND);
    if (rv) {
        if (did_create) {
            skAppPrintErr("Unable to open newly created target file '%s'",
                          output_path);
        }
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        skStreamDestroy(&out_stream);
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
    switch ((appOptionsEnum)opt_index) {
      case OPT_CREATE:
        allow_create = 1;
        if (opt_arg) {
            errno = 0;
            if ( !skFileExists(opt_arg)) {
                skAppPrintSyserror("Invalid %s '%s'",
                                   appOptions[opt_index].name, opt_arg);
                return 1;
            }
            create_format = opt_arg;
        }
        break;

      case OPT_PRINT_STATISTICS:
        print_statistics = 1;
        break;
    }

    return 0;
}


/*
 *  status = createFromTemplate(new_path, templ_file);
 *
 *    Create a SiLK flow file at 'new_path'.  It should have the same
 *    format, version, and byte order as 'templ_file'.  If 'templ_file' is
 *    NULL, create 'new_file' in the default format.  Return 0 on
 *    success; non-zero otherwise.
 */
static int
createFromTemplate(
    const char         *new_path,
    const char         *templ_file)
{
    skstream_t *new_stream = NULL;
    skstream_t *stream = NULL;
    int rv, rv_temp;

    /* open the target file for write---this will create the file */
    if ((rv = skStreamCreate(&new_stream, SK_IO_WRITE, SK_CONTENT_SILK_FLOW))
        || (rv = skStreamBind(new_stream, new_path)))
    {
        goto END;
    }

    /* set file attributes based on the template if given */
    if (templ_file) {
        /* open the template file */
        rv_temp = skStreamOpenSilkFlow(&stream, templ_file, SK_IO_READ);
        if (rv_temp) {
            skStreamPrintLastErr(stream, rv_temp, &skAppPrintErr);
            skAppPrintErr("Cannot open template file '%s'",
                          templ_file);
            skStreamDestroy(&stream);
            skStreamDestroy(&new_stream);
            return 1;
        }

        rv = skHeaderCopy(skStreamGetSilkHeader(new_stream),
                          skStreamGetSilkHeader(stream),
                          SKHDR_CP_ALL);
    }

    /* open the target file, write the header, then close it */
    if (rv == SKSTREAM_OK) {
        rv = skStreamOpen(new_stream);
    }
    if (rv == SKSTREAM_OK) {
        rv = skStreamWriteSilkHeader(new_stream);
    }
    if (rv == SKSTREAM_OK) {
        rv = skStreamClose(new_stream);
    }

  END:
    if (rv != SKSTREAM_OK) {
        skStreamPrintLastErr(new_stream, rv, &skAppPrintErr);
        skAppPrintErr("Cannot create output file '%s'", new_path);
    }
    skStreamDestroy(&stream);
    skStreamDestroy(&new_stream);
    return rv;
}


int main(int argc, char **argv)
{
    const char *input_path;
    skstream_t *in_stream;
    rwRec rwrec;
    int file_count = 0;
    int rv;

    appSetup(argc, argv);                 /* never returns on error */

    /* loop over the source files */
    for ( ; arg_index < argc; ++arg_index) {
        input_path = argv[arg_index];

        /* skip files that are identical to the target or that we
         * cannot open */
        if (0 == strcmp(input_path, skStreamGetPathname(out_stream))) {
            skAppPrintErr(("Warning: skipping source-file%d:"
                           " identical to target file '%s'"),
                          file_count, input_path);
            continue;
        }
        rv = skStreamOpenSilkFlow(&in_stream, input_path, SK_IO_READ);
        if (rv) {
            skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
            skStreamDestroy(&in_stream);
            continue;
        }

        /* determine whether target file supports IPv6; if not, ignore
         * IPv6 flows */
        if (skStreamGetSupportsIPv6(out_stream) == 0) {
            skStreamSetIPv6Policy(in_stream, SK_IPV6POLICY_ASV4);
        }

        while ((rv = skStreamReadRecord(in_stream, &rwrec)) == SKSTREAM_OK) {
            rv = skStreamWriteRecord(out_stream, &rwrec);
            if (rv) {
                skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
                if (SKSTREAM_ERROR_IS_FATAL(rv)) {
                    skStreamDestroy(&in_stream);
                    goto END;
                }
            }
        }
        if (rv != SKSTREAM_ERR_EOF) {
            skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
        }

        if (print_statistics) {
            ++file_count;
            fprintf(STATISTICS_FH,
                    ("%s: appended %" PRIu64 " records from %s to %s\n"),
                    skAppName(), skStreamGetRecordCount(in_stream),
                    skStreamGetPathname(in_stream),
                    skStreamGetPathname(out_stream));
        }
        skStreamDestroy(&in_stream);
    }

    /* close target */
    rv = skStreamClose(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
    }

    if (print_statistics) {
        fprintf(STATISTICS_FH,
                ("%s: appended %" PRIu64 " records from %d file%s to %s\n"),
                skAppName(), skStreamGetRecordCount(out_stream),
                file_count, ((file_count == 1) ? "" : "s"),
                skStreamGetPathname(out_stream));
    }

  END:
    skStreamDestroy(&out_stream);
    appTeardown();

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
