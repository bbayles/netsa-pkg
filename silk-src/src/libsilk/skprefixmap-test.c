/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
** prefixmap_test.c
**
** Katherine Prevost
** December 3rd, 2004
**
** Small application to test the prefixmap library by taking a
** prefixmap file and an IP address and do a lookup on that file to
** print the result.
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skprefixmap-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skprefixmap.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* max expected length of a pmap dictionary entry */
#define DICTIONARY_ENTRY_BUFLEN 2048


/* EXPORTED FUNCTIONS */


/* LOCAL VARIABLES */



/* OPTIONS SETUP */

typedef enum {
    OPT_MAP_FILE, OPT_ADDRESS, OPT_STRING
} appOptionsEnum;

static struct option appOptions[] = {
    {"map-file", REQUIRED_ARG, 0, OPT_MAP_FILE},
    {"address",  REQUIRED_ARG, 0, OPT_ADDRESS},
    {"string",   NO_ARG,       0, OPT_STRING},
    {0,0,0,0}                   /* sentinel entry */
};

static const char *appHelp[] = {
    /* add help strings here for the applications options */
    "path name of the map file.",
    "IP address to look up",
    "output dictionary string instead of integer value",
    (char *)NULL
};

static struct {
    const char *map_file;       /* filename of map file */
    skipaddr_t  address;        /* IP address to look up */
    uint32_t    have_address;   /* whether an address was given */
    uint32_t    string;         /* look up string */
} prefixmap_test_opt;


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
    ("[SWITCHES]\n"                                                     \
     "\tSmall application to test the prefixmap library by taking a\n"  \
     "\tprefixmap file and an IP address and searching the file to\n"   \
     "\tprint the result.\n")

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

    memset(&prefixmap_test_opt, 0, sizeof(prefixmap_test_opt));

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* parse the options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        /* options parsing should print error */
        skAppUsage();           /* never returns */
    }

    if ( (NULL == prefixmap_test_opt.map_file) ||
         (0 == prefixmap_test_opt.have_address) ) {
        if ( NULL == prefixmap_test_opt.map_file ) {
            skAppPrintErr("Required argument map-file not provided.");
        }
        if ( 0 == prefixmap_test_opt.have_address ) {
            skAppPrintErr("Required argument address not provided.");
        }
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
      case OPT_MAP_FILE:
        prefixmap_test_opt.map_file = opt_arg;
        break;

      case OPT_ADDRESS:
        rv = skStringParseIP(&prefixmap_test_opt.address, opt_arg);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          appOptions[opt_index].name, opt_arg,
                          skStringParseStrerror(rv));
            exit(EXIT_FAILURE);
        }
        prefixmap_test_opt.have_address = 1;
        break;

    case OPT_STRING:
        prefixmap_test_opt.string = 1;
        break;
    }

    return 0;  /* OK */
}


int main(int argc, char **argv)
{
    skstream_t *inputFile;
    skPrefixMap_t *prefixMap;
    skPrefixMapErr_t map_error = SKPREFIXMAP_OK;
    char buf[DICTIONARY_ENTRY_BUFLEN];
    int rv;

    appSetup(argc, argv);                       /* never returns on error */

    /* Okay.  Now we should open the prefixmap file, read it in, and */
    /* then look up our address! */

    if ((rv = skStreamCreate(&inputFile, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(inputFile, prefixmap_test_opt.map_file))
        || (rv = skStreamOpen(inputFile)))
    {
        skStreamPrintLastErr(inputFile, rv, &skAppPrintErr);
        skStreamDestroy(&inputFile);
        exit(EXIT_FAILURE);
    }

    map_error = skPrefixMapRead(&prefixMap, inputFile);
    skStreamDestroy(&inputFile);

    if ( SKPREFIXMAP_OK != map_error ) {
        skAppPrintErr("Failed to read map file: %s",
                      skPrefixMapStrerror(map_error));
        exit(EXIT_FAILURE);
    }

    if ( prefixmap_test_opt.string ) {
        int v = skPrefixMapFindString(prefixMap, &prefixmap_test_opt.address,
                                      buf, sizeof(buf));
        if ( v < 0 ) {
            strncpy(buf, "(null)", sizeof(buf));
        }
        printf("%s\n", buf);
    } else {
        printf("%d\n",
               skPrefixMapFindValue(prefixMap, &prefixmap_test_opt.address));
    }

    skPrefixMapDelete(prefixMap);

    /* done */
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
