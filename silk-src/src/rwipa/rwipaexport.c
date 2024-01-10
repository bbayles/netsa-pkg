/*
** Copyright (C) 2007-2023 by Carnegie Mellon University.
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

#include <silk/silk.h>

RCSIDENT("$SiLK: rwipaexport.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skstringmap.h>
#include "rwipa.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write output from --help */
#define USAGE_FH stdout


/* LOCAL VARIABLES */

/* Name of the IPA catalog to export from */
static char *catalog_name = NULL;

/* Date/time string specifying the time to search for in the catalog */
static char *export_time_str = NULL;

/* index of first option that is not handled by the options handler. */
static int arg_index = 0;

/* the compression method to use when writing the file.
 * skCompMethodOptionsRegister() will set this to the default or
 * to the value the user specifies. */
static sk_compmethod_t comp_method;

/* map-name to write into prefix map */
static const char *prefix_map_name = NULL;


/* OPTIONS SETUP */

typedef enum {
    OPT_CATALOG_NAME,
    OPT_EXPORT_TIME,
    OPT_PREFIX_MAP_NAME
} appOptionsEnum;

static struct option appOptions[] = {
    {"catalog",         REQUIRED_ARG, 0, OPT_CATALOG_NAME},
    {"time",            REQUIRED_ARG, 0, OPT_EXPORT_TIME},
    {"prefix-map-name", REQUIRED_ARG, 0, OPT_PREFIX_MAP_NAME},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    "Export data from the named IPA catalog",
    ("Export data that was active at the specified time;\n"
     "\tspecify the time in YYYY/MM/DD[:HH[:MM[:SS]]] format. Def. None"),
    ("Write the specified name into the output prefix\n"
     "\tmap file. Switch ignored if output is not prefix map. Def. None"),
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static void
appUsageLong(
    void);
static void
appTeardown(
    void);
static void
appSetup(
    int                 argc,
    char              **argv);
static int
appOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg);


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
    ("--catalog=CATALOG [SWITCHES] OUTPUT_FILE\n"                         \
     "\tExport an existing IP Address Association (IPA) catalog to the\n" \
     "\tspecified OUTPUT_FILE.  The output will be in the same format\n"  \
     "\tthat was imported, that is, a SiLK IPSet, Bag, or Prefix Map.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
    skOptionsNotesUsage(fh);
    skCompMethodOptionsUsage(fh);
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

    skOptionsNotesTeardown();
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

    /* verify same number of options and help strings */
    assert((sizeof(appHelp) / sizeof(char *)) ==
           (sizeof(appOptions) / sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* register the options */
    if (skOptionsRegister(appOptions, & appOptionsHandler, NULL)
        || skOptionsNotesRegister(NULL)
        || skCompMethodOptionsRegister(&comp_method))
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
        skAppUsage();                            /* never returns */
    }

    /* need name of target file */
    if (arg_index == argc) {
        skAppPrintErr("No destination file name provided on command line.");
        skAppUsage();
    }

    /* A catalog name must be specified */
    if (catalog_name == NULL) {
        skAppPrintErr("You must specify a catalog name with the --%s option",
                      appOptions[OPT_CATALOG_NAME].name);
        skAppUsage();
    }

    return;                                      /* OK */
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
    switch ((appOptionsEnum) opt_index) {
      case OPT_CATALOG_NAME:
        if (catalog_name) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        catalog_name = opt_arg;
        break;
      case OPT_EXPORT_TIME:
        if (export_time_str) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        export_time_str = opt_arg;
        break;
      case OPT_PREFIX_MAP_NAME:
        if (prefix_map_name) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          appOptions[opt_index].name);
            return 1;
        }
        prefix_map_name = opt_arg;
        break;
    }

    return 0;                                    /* OK */
}


static int
export_set(
    IPAContext         *ipa,
    skstream_t         *stream)
{
    skIPTree_t            *set = NULL;
    skIPWildcard_t         ipwild;
    int                    rv;
    IPAAssoc               assoc;

    /* create IPset */
    if (skIPTreeCreate(&set)) {
        skAppPrintErr("Error allocating memory for IPset.");
        rv = -1;
        goto done;
    }

    /* Get IPs from IPA and add to the IPset */
    while (!ipa_get_assoc(ipa, &assoc)) {
        rv = skStringParseIPWildcard(&ipwild, assoc.range);
        if (rv) {
            /* error */
            skAppPrintErr("Invalid IP string %s: %s",
                          assoc.range, skStringParseStrerror(rv));
            rv = -1;
            goto done;
        }
        skIPTreeAddIPWildcard(set, &ipwild);
    }

    rv = skIPTreeWrite(set, stream);
    if (rv != SKIP_OK) {
        skAppPrintErr("Error writing IPset to file '%s': %s",
                      skStreamGetPathname(stream), skIPTreeStrError(rv));
        rv = -1;
        goto done;
    }

    /* Success */
    rv = 0;

  done:
    skIPTreeDelete(&set);
    return rv;
}


static int
export_bag(
    IPAContext         *ipa,
    skstream_t         *stream)
{
    int                    rv  = 0;
    skBag_t               *bag = NULL;
    skBagErr_t             bag_err;
    skIPWildcardIterator_t iter;
    skIPWildcard_t         ipwild;
    skBagTypedKey_t        bagkey;
    skBagTypedCounter_t    bagval;
    IPAAssoc               assoc;

    /* Create new bag */
    if (skBagCreate(&bag) != SKBAG_OK) {
        skAppPrintErr("Error allocating bag");
        rv = -1;
        goto done;
    }

    /* Set the type for the bag's key and counter */
    bagkey.type = SKBAG_KEY_IPADDR;
    bagval.type = SKBAG_COUNTER_U64;

    /* Get IP-value pairs from IPA and add to the Bag */

    while (!ipa_get_assoc(ipa, &assoc)) {
#if (SK_SIZEOF_LONG >= 8)
        bagval.val.u64 = strtoul(assoc.value, NULL, 10);
#else
        bagval.val.u64 = strtoull(assoc.value, NULL, 10);
#endif
        rv = skStringParseIPWildcard(&ipwild, assoc.range);
        if (rv) {
            /* error */
            skAppPrintErr("Invalid IP string '%s': %s",
                          assoc.range, skStringParseStrerror(rv));
            rv = -1;
            goto done;
        }

        skIPWildcardIteratorBind(&iter, &ipwild);
        while (skIPWildcardIteratorNext(&iter, &bagkey.val.addr)
               == SK_ITERATOR_OK)
        {
            if ((bag_err = skBagCounterAdd(bag, &bagkey, &bagval, NULL))
                != SKBAG_OK)
            {
                skAppPrintErr("Error setting value on bag: %s",
                              skBagStrerror(bag_err));
                rv = -1;
                goto done;
            }
        }
    }

    /* write output */
    bag_err = skBagWrite(bag, stream);
    if (bag_err != SKBAG_OK) {
        if (bag_err == SKBAG_ERR_OUTPUT) {
            skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Error writing Bag to '%s': %s",
                          skStreamGetPathname(stream), skBagStrerror(bag_err));
        }
        rv = -1;
        goto done;
    }

    /* Success */
    rv = 0;

  done:
    if (bag) {
        skBagDestroy(&bag);
    }

    return rv;
}


static int
export_pmap(
    IPAContext         *ipa,
    skstream_t         *stream)
{
    int               rv = 0;
    IPAAssoc          assoc;
    skPrefixMap_t    *map       = NULL;
    skPrefixMapErr_t  map_err;
    uint32_t          label_num = 0;
    uint32_t          new_label_num = 0;
    skipaddr_t        addr_begin;
    skipaddr_t        addr_end;

    /* Create the global prefix map */
    map_err = skPrefixMapCreate(&map);
    if (SKPREFIXMAP_OK != map_err) {
        skAppPrintErr("Error creating prefix map: %s",
                      skStringMapStrerror(map_err));
        rv = -1;
        goto done;
    }
    skPrefixMapSetContentType(map, SKPREFIXMAP_CONT_ADDR_V4);

    if (prefix_map_name) {
        map_err = skPrefixMapSetMapName(map, prefix_map_name);
        if (SKPREFIXMAP_OK != map_err) {
            skAppPrintErr("Error setting prefix map name: %s",
                          skStringMapStrerror(map_err));
            rv = -1;
            goto done;
        }
    }

    while (!ipa_get_assoc(ipa, &assoc)) {
        label_num = skPrefixMapDictionaryLookup(map, assoc.label);
        if (label_num == SKPREFIXMAP_NOT_FOUND) {
            label_num = new_label_num++;
            skPrefixMapDictionaryInsert(map, label_num, assoc.label);
        }
        skipaddrSetV4(&addr_begin, &assoc.begin);
        skipaddrSetV4(&addr_end, &assoc.end);
        skPrefixMapAddRange(map, &addr_begin, &addr_end, label_num);
    }

    map_err = skPrefixMapWrite(map, stream);
    if (map_err != SKPREFIXMAP_OK) {
        if (map_err == SKPREFIXMAP_ERR_IO) {
            skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Error writing prefix map to '%s': %s",
                          skStreamGetPathname(stream),
                          skPrefixMapStrerror(map_err));
        }
        rv = -1;
        goto done;
    }

  done:
    if (map) {
        skPrefixMapDelete(map);
    }

    return rv;
}



int main(int argc, char **argv)
{
    const char *filename   = NULL;
    int         rv         = 1;
    char       *ipa_db_url = NULL;
    IPAContext *ipa;
    skstream_t *stream = NULL;

    appSetup(argc, argv);       /* never returns on error */

    filename = argv[arg_index];

    ipa_db_url = get_ipa_config();
    if (ipa_db_url == NULL) {
        skAppPrintErr("Could not get IPA configuration");
        rv = EXIT_FAILURE;
        goto done;
    }

    ipa_create_context(&ipa, ipa_db_url, NULL);
    if (ipa == NULL) {
        skAppPrintErr("Could not create IPA context");
        rv = EXIT_FAILURE;
        goto done;
    }

    rv = ipa_get_dataset(ipa, catalog_name, export_time_str);
    switch (rv) {
      case IPA_OK:
        break;
      case IPA_ERR_NOTFOUND:
        skAppPrintErr("Dataset not found for given name and time");
        goto done;
      default:
        skAppPrintErr("IPA error retrieving dataset");
        goto done;
    }

    /* open output file and set headers */
    if ((rv = skStreamCreate(&stream, SK_IO_WRITE, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamSetCompressionMethod(stream, comp_method))
        || (rv = skOptionsNotesAddToStream(stream))
        || (rv = skHeaderAddInvocation(skStreamGetSilkHeader(stream),
                                       1, argc, argv))
        || (rv = skStreamOpen(stream)))
    {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        rv = EXIT_FAILURE;
        goto done;
    }

    switch (ipa->cat_type) {
      case IPA_CAT_SET:
        rv = export_set(ipa, stream);
        break;
      case IPA_CAT_BAG:
        rv = export_bag(ipa, stream);
        break;
      case IPA_CAT_PMAP:
        rv = export_pmap(ipa, stream);
        break;
      default:
        skAppPrintErr("Unsupported catalog type (%d)", ipa->cat_type);
        rv = -1;
        goto done;
    }

    if (rv == 0) {
        rv = skStreamClose(stream);
        if (rv) {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        }
    }

  done:
    skStreamDestroy(&stream);
    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
