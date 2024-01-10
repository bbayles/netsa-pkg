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

RCSIDENT("$SiLK: rwipaimport.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwipa.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write output from --help */
#define USAGE_FH stdout

/* max expected length of a pmap dictionary entry */
#define DICTIONARY_ENTRY_BUFLEN 2048


/* LOCAL VARIABLES */

/* Name of the IPA catalog to import to */
static char *catalog_name = NULL;

/* A short description of the catalog */
static char *catalog_desc = NULL;

/* Date/time string specifying beginning of validity interval */
static char *start_time_str = NULL;

/* Date/time string specifying end of validity interval */
static char *end_time_str = NULL;

/* index of first option that is not handled by the options handler. */
static int arg_index = 0;


/* OPTIONS SETUP */

typedef enum {
    OPT_CATALOG_NAME,
    OPT_CATALOG_DESC,
    OPT_START_TIME,
    OPT_END_TIME
} appOptionsEnum;

static struct option appOptions[] = {
    {"catalog",     REQUIRED_ARG, 0, OPT_CATALOG_NAME},
    {"description", REQUIRED_ARG, 0, OPT_CATALOG_DESC},
    {"start-time",  REQUIRED_ARG, 0, OPT_START_TIME  },
    {"end-time",    REQUIRED_ARG, 0, OPT_END_TIME    },
    {            0,            0, 0,                0} /* sentinel entry */
};

static const char *appHelp[] = {
    ("Import the data into the named IPA catalog; the catalog\n"
     "\twill be created if necessary"),
    ("Describe the catalog's contents (for new catalogs)"),
    ("Specify the time when the data is first valid, in\n"
     "\tYYYY/MM/DD[:HH[:MM[:SS]]] format. Def. None.  Requires --end-time"),
    ("Specify end of validity interval. Def. None"),
    (char *) NULL
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
#define USAGE_MSG                                                       \
    ("--catalog=CATALOG [SWITCHES] INPUT_FILE\n"                        \
     "\tImport a SiLK IPSet, Bag, or Prefix Map from the named\n"       \
     "\tINPUT_FILE to an IP Address Association (IPA) catalog.\n")

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

    /* verify same number of options and help strings */
    assert((sizeof(appHelp) / sizeof(char *)) ==
           (sizeof(appOptions) / sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)) {
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
        skAppUsage();           /* never returns */
    }

    /* Make sure there's a filename to process */
    if (arg_index == argc) {
        skAppPrintErr("No input file given on the command line");
        skAppUsage();
    }

    /* Make certain there is only one file name */
    if (arg_index + 1 < argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index+1]);
        skAppUsage();           /* never returns */
    }

    /* A catalog name must be specified */
    if (catalog_name == NULL) {
        skAppPrintErr("You must specify a catalog name with the --%s option",
                      appOptions[OPT_CATALOG_NAME].name);
        skAppUsage();
    }

    /* A time period (start time and end time) is optional, but if present,
     *  both must be specified */
    if ( (start_time_str == NULL) ^ (end_time_str == NULL)  ) {
        skAppPrintErr(("Incomplete time range specified."
                       "  If the imported data is\n"
                       "\tassociated with specific dates,"
                       " you must specify both the\n"
                       "\t--%s and --%s options"),
                      appOptions[OPT_START_TIME].name,
                      appOptions[OPT_END_TIME].name);
        skAppUsage();
    }

    return;                     /* OK */
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
    clientData UNUSED   (cData),
    int                 opt_index,
    char               *opt_arg)
{
    switch ((appOptionsEnum) opt_index) {
      case OPT_CATALOG_NAME:
        catalog_name = opt_arg;
        break;

      case OPT_CATALOG_DESC:
        catalog_desc = opt_arg;
        break;

      case OPT_START_TIME:
        start_time_str = opt_arg;
        break;

      case OPT_END_TIME:
        end_time_str = opt_arg;
        break;
    }

    return 0;                   /* OK */
}


static int
import_set(
    IPAContext         *ipa,
    skstream_t         *stream)
{
    skipset_t          *set    = NULL;
    skipset_iterator_t  iter;
    skipaddr_t          ipaddr;
    uint32_t            prefix;
    int                 rv = 0;

    /* Read ipTree from file */
    rv = skIPSetRead(&set, stream);
    if (SKIPSET_OK != rv) {
        if (SKIPSET_ERR_FILEIO == rv) {
            skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Error reading binary IPset from '%s': %s",
                          skStreamGetPathname(stream), skIPSetStrerror(rv));
        }
        rv = -1;
        goto done;
    }

    skIPSetIteratorBind(&iter, set, 1, SK_IPV6POLICY_IGNORE);
    while (skIPSetIteratorNext(&iter, &ipaddr, &prefix)
           == SK_ITERATOR_OK)
    {
        ipa_add_cidr(ipa, skipaddrGetV4(&ipaddr), prefix, (char*)"", 0);
    }

  done:
    skIPSetDestroy(&set);

    return rv;
}


static int
import_bag(
    IPAContext         *ipa,
    skstream_t         *stream)
{
    skBag_t            *bag      = NULL;
    skBagIterator_t    *bag_iter = NULL;
    skBagTypedKey_t     bagkey;
    skBagTypedCounter_t bagval;
    skBagErr_t          bagerr;

    int rv = 0;

    /* Read Bag from file */
    bagerr = skBagRead(&bag, stream);
    if (SKBAG_OK != bagerr) {
        if (SKBAG_ERR_READ == bagerr) {
            skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Error reading Bag from file '%s': %s",
                          skStreamGetPathname(stream), skBagStrerror(bagerr));
        }
        rv = -1;
        goto done;
    }

    bagerr = skBagIteratorCreate(bag, &bag_iter);
    if (SKBAG_OK != bagerr) {
        skAppPrintErr("Could not create Bag iterator: %s",
                      skBagStrerror(bagerr));
        rv = -1;
        goto done;
    }

    /* get key as a 32-bit number */
    bagkey.type = SKBAG_KEY_U32;
    bagval.type = SKBAG_COUNTER_U64;

    while (SKBAG_OK == skBagIteratorNextTyped(bag_iter, &bagkey, &bagval)) {
        /* FIXME: do we want to CIDRize if adjacent counts are the same? */
        ipa_add_assoc(ipa, bagkey.val.u32, bagkey.val.u32, (char*)"",
                      bagval.val.u64);
    }

  done:
    if (bag_iter) {
        skBagIteratorDestroy(bag_iter);
    }
    if (bag) {
        skBagDestroy(&bag);
    }
    return rv;
}


/*
 *  pmap = openMapFile(path);
 *
 *    Open the prefix map file at 'path' and verify that it can be
 *    processed by this program.
 */
static skPrefixMap_t *
openMapFile(
    skstream_t         *stream)
{
    skPrefixMap_t   *map    = NULL;
    skPrefixMapErr_t map_error;

    /* read in the prefixmap file */
    map_error = skPrefixMapRead(&map, stream);
    if (SKPREFIXMAP_OK != map_error) {
        if (SKPREFIXMAP_ERR_IO == map_error) {
            skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Failed to read prefix map file '%s': %s",
                          skStreamGetPathname(stream),
                          skPrefixMapStrerror(map_error));
        }
        map = NULL;
        goto ERROR;
    }

    /* verify that the prefix map is of the correct generation */
    if (skPrefixMapDictionaryGetWordCount(map) == 0) {
        skAppPrintErr("The pmap file'%s' cannot be processed by this program",
                      skStreamGetPathname(stream));
        goto ERROR;
    }

    /* complain if ranges were requested and the file does not contain
     * address data.  if only ranges were requested, destroy the map. */
    if (SKPREFIXMAP_CONT_ADDR_V4 != skPrefixMapGetContentType(map)) {
        skAppPrintErr(("The pmap file '%s'"
                       " does not contain an IPv4 address prefix map"),
                      skStreamGetPathname(stream));
    }

    /* Success */
    return map;

  ERROR:
    if (map) {
        skPrefixMapDelete(map);
    }
    return NULL;
}

static int
import_pmap(
    IPAContext         *ipa,
    skstream_t         *stream)
{
    skPrefixMap_t        *pmap = NULL;
    skPrefixMapIterator_t iter;
    char                  label[DICTIONARY_ENTRY_BUFLEN];
    skipaddr_t            start_addr;
    skipaddr_t            end_addr;
    uint32_t              val;

    /* open the prefix map file */
    pmap = openMapFile(stream);
    if (pmap == NULL) {
        return -1;
    }

    skPrefixMapIteratorBind(&iter, pmap);
    while (skPrefixMapIteratorNext(&iter, &start_addr, &end_addr, &val)
           != SK_ITERATOR_NO_MORE_ENTRIES)
    {
        skPrefixMapDictionaryGetEntry(pmap, val, label, sizeof(label));
        ipa_add_assoc(ipa, skipaddrGetV4(&start_addr),
                      skipaddrGetV4(&end_addr), label, val);
    }

    return 0;
}


int main(int argc, char **argv)
{
    char                format_name[128];
    const char         *filename     = NULL;
    skstream_t         *stream       = NULL;
    sk_file_header_t   *hdr          = NULL;
    IPACatalogType      catalog_type = IPA_CAT_NONE;
    int                 rv           = 1;
    char               *ipa_db_url   = NULL;
    IPAContext         *ipa;

    appSetup(argc, argv);       /* never returns on error */

    filename = argv[arg_index];

    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
        || (rv = skStreamBind(stream, filename))
        || (rv = skStreamOpen(stream))
        || (rv = skStreamReadSilkHeader(stream, &hdr)))
    {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        rv = -1;
        goto done;
    }

    switch (skHeaderGetFileFormat(hdr)) {
      case FT_IPSET:
        catalog_type = IPA_CAT_SET;
        break;

      case FT_RWBAG:
        catalog_type = IPA_CAT_BAG;
        break;

      case FT_PREFIXMAP:
        catalog_type = IPA_CAT_PMAP;
        break;

      default:
        skFileFormatGetName(format_name, sizeof(format_name),
                            skHeaderGetFileFormat(hdr));
        skAppPrintErr("Files in the %s format are not supported",
                      format_name);
        rv = -1;
        goto done;
    }

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

    ipa_begin(ipa);

    if (ipa_add_dataset(ipa, catalog_name, catalog_desc, catalog_type,
                        start_time_str, end_time_str) != IPA_OK)
    {
        rv = -1;
        goto done;
    }


    switch (catalog_type) {
      case IPA_CAT_SET:
        rv = import_set(ipa, stream);
        break;

      case IPA_CAT_BAG:
        rv = import_bag(ipa, stream);
        break;

      case IPA_CAT_PMAP:
        rv = import_pmap(ipa, stream);
        break;

      default:
        skAbortBadCase(catalog_type);
    }

    if (!rv) {
        ipa_commit(ipa);
    } else {
        skAppPrintErr("Warning: rolling back IPA transaction");
        ipa_rollback(ipa);
    }

  done:
    skStreamDestroy(&stream);
    if (ipa_db_url) {
        free(ipa_db_url);
    }
    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
