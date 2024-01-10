/*
** Copyright (C) 2003-2023 by Carnegie Mellon University.
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
 *  rwfileinfo
 *
 *    Prints information from the header of a SiLK file; also reports
 *    the file's size and the number of records in the file.
 *
 *  Mark Thomas
 *  November 2003
 */


#include <silk/silk.h>

RCSIDENT("$SiLK: rwfileinfo.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* when determining number of records in file, number of bytes to
 * request at one time */
#define RWINFO_BLOCK_SIZE 0x40000

/* format for a label */
#define LABEL_FMT "  %-20s"

/* format for a label that is a number, such as when printing command lines */
#define LABEL_NUM_FMT "%20d  "

/* A list of the fields that may be printed; keep in sync with the
 * rwinfo_entry[] array below */
enum rwinfo_id {
    RWINFO_FORMAT,
    RWINFO_VERSION,
    RWINFO_BYTE_ORDER,
    RWINFO_COMPRESSION,
    RWINFO_HEADER_LENGTH,
    RWINFO_RECORD_LENGTH,
    RWINFO_COUNT_RECORDS,
    RWINFO_FILE_SIZE,
    RWINFO_COMMAND_LINES,
    RWINFO_RECORD_VERSION,
    RWINFO_SILK_VERSION,
    RWINFO_PACKED_FILE_INFO,
    RWINFO_PROBE_NAME,
    RWINFO_ANNOTATIONS,
    RWINFO_PREFIX_MAP,
    RWINFO_IPSET,
    RWINFO_BAG,
    RWINFO_AGGBAG
};

/*
 *    Fields names, IDs, descriptions, and optional titles (name is
 *    used when title is NULL), followed by the numeric alias for the
 *    field.  We explicitly provide the alias so we can change the
 *    order of the fields in the future.
 */
static const sk_stringmap_entry_t rwinfo_entry[] = {
    {"format",
     RWINFO_FORMAT,
     ("The type of data the file contains,"
      " includes the name and its numeric ID (hexadecimal)"),
     "format(id)"},
    {"1",   RWINFO_FORMAT, NULL, NULL},

    {"version",
     RWINFO_VERSION,
     ("The general structure (or layout) of the file"),
     NULL},
    {"2",   RWINFO_VERSION, NULL, NULL},

    {"byte-order",
     RWINFO_BYTE_ORDER,
     ("The byte-order used to represent integers:"
      " BigEndian (network byte-order) or littleEndian)"),
     NULL},
    {"3",   RWINFO_BYTE_ORDER, NULL, NULL},

    {"compression",
     RWINFO_COMPRESSION,
     ("The compression library used to compress the data-section of"
      " the file; includes the name and its numeric ID (decimal)"),
     "compression(id)"},
    {"4",   RWINFO_COMPRESSION, NULL, NULL},

    {"header-length",
     RWINFO_HEADER_LENGTH,
     ("The length of the file's header (in octets)"),
     NULL},
    {"5",   RWINFO_HEADER_LENGTH, NULL, NULL},

    {"record-length",
     RWINFO_RECORD_LENGTH,
     ("The length of a single record (in octets), or 1 if the records"
      " do not have a fixed size"),
     NULL},
    {"6",   RWINFO_RECORD_LENGTH, NULL, NULL},

    {"count-records",
     RWINFO_COUNT_RECORDS,
     ("The number of records in the file, computed by dividing the length"
      " of the file's (uncompressed) data section by the record-length"),
     NULL},
    {"7",   RWINFO_COUNT_RECORDS, NULL, NULL},

    {"file-size",
     RWINFO_FILE_SIZE,
     ("The size of the file on disk as reported by the operating system"),
     NULL},
    {"8",   RWINFO_FILE_SIZE, NULL, NULL},

    {"command-lines",
     RWINFO_COMMAND_LINES,
     ("The command (or command history) used to generate this file."
      " Most recent command last"),
     NULL},
    {"9",   RWINFO_COMMAND_LINES, NULL, NULL},

    {"record-version",
     RWINFO_RECORD_VERSION,
     ("The version of the particular content type specified in format"),
     NULL},
    {"10",  RWINFO_RECORD_VERSION, NULL, NULL},

    {"silk-version",
     RWINFO_SILK_VERSION,
     ("The release of SiLK that wrote this file"),
     NULL},
    {"11",  RWINFO_SILK_VERSION, NULL, NULL},

    {"packed-file-info",
     RWINFO_PACKED_FILE_INFO,
     ("For a repository file created by rwflowpack, the starting hour,"
      " the flowtype, and the sensor for each record in the file"),
     NULL},
    {"12",  RWINFO_PACKED_FILE_INFO, NULL, NULL},

    {"probe-name",
     RWINFO_PROBE_NAME,
     ("For a file created by flowcap, the name of the probe"
      " from which the data was collected"),
     NULL},
    {"13",  RWINFO_PROBE_NAME, NULL, NULL},

    {"annotations",
     RWINFO_ANNOTATIONS,
     "The notes (annotations) that users have added to the file",
     NULL},
    {"14",  RWINFO_ANNOTATIONS, NULL, NULL},

    {"prefix-map",
     RWINFO_PREFIX_MAP,
     ("For a prefix map, the mapname stored in the header if one was set"
      " when the file was generated"),
     NULL},
    {"15",  RWINFO_PREFIX_MAP, NULL, NULL},

    {"ipset",
     RWINFO_IPSET,
     ("For an IPset file whose record-version is 3:"
      " a description of the tree data structure."
      " For an IPset file whose record-version is 4:"
      " whether the IPs are IPv4 or IPv6"),
     NULL},
    {"16",  RWINFO_IPSET, NULL, NULL},

    {"bag",
     RWINFO_BAG,
     ("For a bag file, the type and size of the key and of the counter"),
     NULL},
    {"17",  RWINFO_BAG, NULL, NULL},

    {"aggregate-bag",
     RWINFO_AGGBAG,
     ("For an aggregate bag file, the types of the key and the counter"),
     NULL},
    {"18",  RWINFO_AGGBAG, NULL, NULL},

    SK_STRINGMAP_SENTINEL
};



/* LOCAL VARIABLES */

/* string map used to parse the list of fields */
static sk_stringmap_t *avail_fields = NULL;

/* fields to print */
static sk_bitmap_t *print_fields = NULL;

/* whether to print the summary */
static int print_summary = 0;

/* whether to not print titles (0==print titles, 1==no titles) */
static int no_titles = 0;

/* for looping over files on the command line */
static sk_options_ctx_t *optctx = NULL;

/* FIXME: Consider adding --pager and --output-path support. */


/* OPTIONS SETUP */

/* Create constants for the option processor */
typedef enum rwinfoOptionIds {
    OPT_HELP_FIELDS,
    OPT_FIELDS,
    OPT_SUMMARY,
    OPT_NO_TITLES
} appOptionsEnum;

static struct option appOptions[] = {
    {"help-fields",     NO_ARG,       0, OPT_HELP_FIELDS},
    {"fields",          REQUIRED_ARG, 0, OPT_FIELDS},
    {"summary",         NO_ARG,       0, OPT_SUMMARY},
    {"no-titles",       NO_ARG,       0, OPT_NO_TITLES},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    "Describe each field and exit. Def. no",
    ("Print only these fields. Def. All fields. Available fields:"),
    "Print a summary of total files, file sizes, and records",
    ("Do not print file names or field names; only print the\n"
     "\tvalues, one per line"),
    (char *)NULL /* sentinel entry */
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void helpFields(FILE *fh);
static int  parseFields(const char *field_str);
static int
printFileInfo(
    const char         *path,
    int64_t            *recs,
    int64_t            *bytes);


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
    ("[SWITCHES] <FILES>\n"                                             \
     "\tPrint information (type, version, etc.) about a SiLK Flow,\n"   \
     "\tIPset, or Bag file.  Use the fields switch to control what\n"   \
     "\tinformation is printed.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
          case OPT_FIELDS:
            fprintf(fh, "%s\n", appHelp[i]);
            skStringMapPrintUsage(avail_fields, fh, 8);
            break;

          default:
            fprintf(fh, "%s\n", appHelp[i]);
            break;
        }
    }
    skOptionsCtxOptionsUsage(optctx, fh);
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

    skBitmapDestroy(&print_fields);
    skStringMapDestroy(avail_fields);
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
    sk_stringmap_status_t err;
    unsigned int optctx_flags;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    optctx_flags = (SK_OPTIONS_CTX_INPUT_BINARY | SK_OPTIONS_CTX_XARGS);

    /* register the options */
    if (skOptionsCtxCreate(&optctx, optctx_flags)
        || skOptionsCtxOptionsRegister(optctx)
        || skOptionsRegister(appOptions, &appOptionsHandler, NULL)
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

    /* create the stringmap of the available fields */
    if ((err = skStringMapCreate(&avail_fields))
        || (err = skStringMapAddEntries(avail_fields, -1, rwinfo_entry)))
    {
        skAppPrintErr("Unable to create stringmap: %s",
                      skStringMapStrerror(err));
        exit(EXIT_FAILURE);
    }

    /* create a bitmap of fields to print; this is double the size we
     * need, but the size is small so ignore it */
    skBitmapCreate(&print_fields, sizeof(rwinfo_entry)/sizeof(rwinfo_entry[0]));
    skBitmapSetAllBits(print_fields);

    /* parse options */
    rv = skOptionsCtxOptionsParse(optctx, argc, argv);
    if (rv < 0) {
        skAppUsage();  /* never returns */
    }

    /* try to load the site file to resolve sensor information */
    sksiteConfigure(0);

    return;  /* OK */
}


/*
 *  status = appOptionsHandler(cData, opt_index, opt_arg);
 *
 *    Called by skOptionsParse(), this handles a user-specified switch
 *    that the application has registered, typically by setting global
 *    variables.  Returns 1 if the switch processing failed or 0 if it
 *    succeeded.  Returning a non-zero from from the handler causes
 *    skOptionsParse() to return a negative value.
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
      case OPT_HELP_FIELDS:
        helpFields(USAGE_FH);
        exit(EXIT_SUCCESS);

      case OPT_FIELDS:
        if (parseFields(opt_arg)) {
            return 1;
        }
        break;

      case OPT_SUMMARY:
        print_summary = 1;
        break;

      case OPT_NO_TITLES:
        no_titles = 1;
        break;
    }

    return 0;
}


/*
 *  helpFields(fh);
 *
 *    Print a description of each field to the 'fh' file pointer
 */
static void
helpFields(
    FILE               *fh)
{
#define HELP_FIELDS                                                     \
    ("The following names may be used in the --%s switch. Names are\n"  \
     "case-insensitive and may be abbreviated"                          \
     " to the shortest unique prefix.\n"                                \
     "The output fields are always printed in the order they appear here.\n")

    fprintf(fh, HELP_FIELDS, appOptions[OPT_FIELDS].name);

    skStringMapPrintDetailedUsage(avail_fields, fh);
}


/*
 *  ok = parseFields(field_list);
 *
 *    Parse the user's field list, setting the appropriate bits in
 *    the print_fields bitmap.
 */
static int
parseFields(
    const char         *field_str)
{
    sk_stringmap_status_t err;
    sk_stringmap_entry_t *map_entry;
    sk_stringmap_iter_t *iter = NULL;
    char *err_msg;

    /* attempt to match */
    err = skStringMapParse(avail_fields, field_str, SKSTRINGMAP_DUPES_KEEP,
                           &iter, &err_msg);
    if (err) {
        skAppPrintErr("Invalid %s '%s': %s",
                      appOptions[OPT_FIELDS].name, field_str, err_msg);
        return -1;
    }

    /* turn off printing for all fields */
    skBitmapClearAllBits(print_fields);

    /* enable fields user listed */
    while (skStringMapIterNext(iter, &map_entry, NULL) == SK_ITERATOR_OK) {
        skBitmapSetBit(print_fields, map_entry->id);
    }

    skStringMapIterDestroy(iter);
    return 0;
}


/*
 *  status = getNumberRecs(stream, record_size, &count);
 *
 *    Given 'stream' to the opened file, read the file to determine
 *    the number of 'record_size' records in the file, and set 'count'
 *    to that value.  If the file was successfully read, return 0.  If
 *    an error occurs while reading the file, return -1.
 */
static int
getNumberRecs(
    skstream_t         *stream,
    size_t              rec_size,
    int64_t            *count)
{
    size_t block_size = RWINFO_BLOCK_SIZE;
    int64_t bytes = 0;
    ssize_t saw;
    imaxdiv_t rec;
    int rv = 0;

    if (0 == rec_size) {
        rec_size = 1;
    }

    /* modify block_size to read an integer number of records */
    if (rec_size > block_size) {
        block_size = rec_size;
    } else {
        block_size -= block_size % rec_size;
    }

    /* get number of bytes in file */
    while ((saw = skStreamRead(stream, NULL, block_size)) > 0) {
        bytes += saw;
    }
    if (saw != 0) {
        skStreamPrintLastErr(stream, saw, &skAppPrintErr);
        rv = -1;
    }

    /* compute number of records */
    rec = imaxdiv(bytes, rec_size);
    if (rec.rem != 0) {
        skAppPrintErr("Short read (%" PRIdMAX "/%lu)",
                      rec.rem, (unsigned long)rec_size);
        rv = -1;
    }
    *count = (int64_t)rec.quot;
    return rv;
}


/*
 *    If 'count' is 0, print the title for the 'id' entry unless
 *    no-titles was requested.
 *
 *    If 'count' is non-0 and no-titles was not requested, print
 *    spaces so multiple-header entries are aligned.
 */
static void
printLabel(
    sk_stringmap_id_t   id,
    int64_t             count)
{
    sk_stringmap_iter_t *iter;
    sk_stringmap_entry_t *entry;

    if (!no_titles) {
        if (0 != count) {
            printf(LABEL_FMT, "");
        } else {
            /* it seems like iterating over the rwinfo_entry[] array
             * to find the entry would be easier.... */
            skStringMapGetByID(avail_fields, id, &iter);
            assert(iter);
            skStringMapIterNext(iter, &entry, NULL);
            assert(entry);
            if (entry->userdata) {
                printf(LABEL_FMT, (const char *)entry->userdata);
            } else {
                printf(LABEL_FMT, entry->name);
            }
            skStringMapIterDestroy(iter);
        }
    }
}


/*
 *  status = printFileInfo(info, &total_recs, &total_bytes);
 *
 *    Given the file information in the 'info' structure, print the
 *    fields requested by the user---given in the 'print_fields'
 *    global---to the standard output.  Update the values pointed at
 *    by 'total_recs' and 'total_bytes' with the number of records and
 *    bytes in this file.  Return -1 if there is a problem opening or
 *    reading the file.  Return 0 otherwise.
 */
static int
printFileInfo(
    const char         *path,
    int64_t            *recs,
    int64_t            *bytes)
{
    char buf[1024];
    int count;
    int64_t rec_count;
    skstream_t *stream = NULL;
    sk_file_header_t *hdr;
    sk_header_entry_t *he;
    sk_hentry_iterator_t iter;
    int rv = SKSTREAM_OK;
    int retval = 0;

    if (SKSTREAM_OK == rv) {
        rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK);
    }
    if (SKSTREAM_OK == rv) {
        rv = skStreamBind(stream, path);
    }
    if (SKSTREAM_OK == rv) {
        rv = skStreamOpen(stream);
    }
    if (SKSTREAM_OK == rv) {
        rv = skStreamReadSilkHeaderStart(stream);
    }

    /* Give up if we can't read the beginning of the silk header */
    if (rv != SKSTREAM_OK) {
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        skStreamDestroy(&stream);
        return -1;
    }

    /* print file name */
    if (!no_titles) {
        printf("%s:\n", path);
    }

    /* read the header */
    rv = skStreamReadSilkHeader(stream, &hdr);
    switch (rv) {
      case SKSTREAM_OK:
        break;
      case SKHEADER_ERR_LEGACY:
        /* unrecognized file format.  disable printing of record
         * version and record size */
        skBitmapClearBit(print_fields, RWINFO_HEADER_LENGTH);
        skBitmapClearBit(print_fields, RWINFO_RECORD_LENGTH);
        skBitmapClearBit(print_fields, RWINFO_RECORD_VERSION);
        skBitmapClearBit(print_fields, RWINFO_SILK_VERSION);
        skBitmapClearBit(print_fields, RWINFO_COUNT_RECORDS);
        break;
      case SKSTREAM_ERR_COMPRESS_UNAVAILABLE:
      case SKSTREAM_ERR_COMPRESS_INVALID:
        /* unknown or unavailable compression-method.  disable
         * printing of record count */
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        retval = -1;
        skBitmapClearBit(print_fields, RWINFO_COUNT_RECORDS);
        break;
      default:
        /* print an error but continue */
        skStreamPrintLastErr(stream, rv, &skAppPrintErr);
        retval = -1;
        break;
    }

    if (skBitmapGetBit(print_fields, RWINFO_FORMAT)) {
        skFileFormatGetName(buf, sizeof(buf), skHeaderGetFileFormat(hdr));
        printLabel(RWINFO_FORMAT, 0);
        printf("%s(0x%02x)\n", buf, skHeaderGetFileFormat(hdr));
    }

    if (skBitmapGetBit(print_fields, RWINFO_VERSION)) {
        printLabel(RWINFO_VERSION, 0);
        printf("%u\n", skHeaderGetFileVersion(hdr));
    }

    if (skBitmapGetBit(print_fields, RWINFO_BYTE_ORDER)) {
        printLabel(RWINFO_BYTE_ORDER, 0);
        printf("%s\n", ((skHeaderGetByteOrder(hdr) == SILK_ENDIAN_BIG)
                        ? "BigEndian"
                        : "littleEndian"));
    }

    if (skBitmapGetBit(print_fields, RWINFO_COMPRESSION)) {
        skCompMethodGetName(buf, sizeof(buf),
                            skHeaderGetCompressionMethod(hdr));
        printLabel(RWINFO_COMPRESSION, 0);
        printf("%s(%u)\n", buf, skHeaderGetCompressionMethod(hdr));
    }

    if (skBitmapGetBit(print_fields, RWINFO_HEADER_LENGTH)) {
        printLabel(RWINFO_HEADER_LENGTH, 0);
        printf("%u\n", (unsigned int)skHeaderGetLength(hdr));
    }

    if (skBitmapGetBit(print_fields, RWINFO_RECORD_LENGTH)) {
        printLabel(RWINFO_RECORD_LENGTH, 0);
        printf("%u\n", (unsigned int)skHeaderGetRecordLength(hdr));
    }

    if (skBitmapGetBit(print_fields, RWINFO_RECORD_VERSION)) {
        printLabel(RWINFO_RECORD_VERSION, 0);
        printf("%d\n", skHeaderGetRecordVersion(hdr));
    }

    if (skBitmapGetBit(print_fields, RWINFO_SILK_VERSION)) {
        uint32_t vers = skHeaderGetSilkVersion(hdr);
        printLabel(RWINFO_SILK_VERSION, 0);
        if (vers == 0) {
            printf("0\n");
        } else {
            printf(("%" PRId32 ".%" PRId32 ".%" PRId32 "\n"),
                   (vers / 1000000), (vers / 1000 % 1000), (vers % 1000));
        }
    }

    if (skBitmapGetBit(print_fields, RWINFO_COUNT_RECORDS)) {
        rv = getNumberRecs(stream, skHeaderGetRecordLength(hdr), &rec_count);
        if (rv) {
            retval = -1;
        }
        printLabel(RWINFO_COUNT_RECORDS, 0);
        printf(("%" PRId64 "\n"), rec_count);
        *recs += rec_count;
    }

    if (skBitmapGetBit(print_fields, RWINFO_FILE_SIZE)) {
        int64_t sz = (int64_t)skFileSize(path);
        printLabel(RWINFO_FILE_SIZE, 0);
        printf(("%" PRId64 "\n"), sz);
        *bytes += sz;
    }

    if (skBitmapGetBit(print_fields, RWINFO_PACKED_FILE_INFO)) {
        count = 0;
        skHeaderIteratorBindType(&iter, hdr, SK_HENTRY_PACKEDFILE_ID);
        while ((he = skHeaderIteratorNext(&iter)) != NULL) {
            printLabel(RWINFO_PACKED_FILE_INFO, count);
            skHeaderEntryPrint(he, stdout);
            printf("\n");
            ++count;
        }
    }

    if (skBitmapGetBit(print_fields, RWINFO_PROBE_NAME)) {
        count = 0;
        skHeaderIteratorBindType(&iter, hdr, SK_HENTRY_PROBENAME_ID);
        while ((he = skHeaderIteratorNext(&iter)) != NULL) {
            printLabel(RWINFO_PROBE_NAME, count);
            skHeaderEntryPrint(he, stdout);
            printf("\n");
            ++count;
        }
    }

    if (skBitmapGetBit(print_fields, RWINFO_PREFIX_MAP)) {
        count = 0;
        skHeaderIteratorBindType(&iter, hdr, SK_HENTRY_PREFIXMAP_ID);
        while ((he = skHeaderIteratorNext(&iter)) != NULL) {
            printLabel(RWINFO_PREFIX_MAP, count);
            skHeaderEntryPrint(he, stdout);
            printf("\n");
            ++count;
        }
    }

    if (skBitmapGetBit(print_fields, RWINFO_IPSET)) {
        count = 0;
        skHeaderIteratorBindType(&iter, hdr, SK_HENTRY_IPSET_ID);
        while ((he = skHeaderIteratorNext(&iter)) != NULL) {
            printLabel(RWINFO_IPSET, count);
            skHeaderEntryPrint(he, stdout);
            printf("\n");
            ++count;
        }
    }

    if (skBitmapGetBit(print_fields, RWINFO_BAG)) {
        count = 0;
        skHeaderIteratorBindType(&iter, hdr, SK_HENTRY_BAG_ID);
        while ((he = skHeaderIteratorNext(&iter)) != NULL) {
            printLabel(RWINFO_BAG, 0);
            skHeaderEntryPrint(he, stdout);
            printf("\n");
            ++count;
        }
    }

    if (skBitmapGetBit(print_fields, RWINFO_AGGBAG)) {
        count = 0;
        skHeaderIteratorBindType(&iter, hdr, SK_HENTRY_AGGBAG_ID);
        while ((he = skHeaderIteratorNext(&iter)) != NULL) {
            printLabel(RWINFO_AGGBAG, 0);
            skHeaderEntryPrint(he, stdout);
            printf("\n");
            ++count;
        }
    }

    if (skBitmapGetBit(print_fields, RWINFO_COMMAND_LINES)) {
        count = 0;
        skHeaderIteratorBindType(&iter, hdr, SK_HENTRY_INVOCATION_ID);
        while ((he = skHeaderIteratorNext(&iter)) != NULL) {
            if (count == 0 && !no_titles) {
                printLabel(RWINFO_COMMAND_LINES, count);
                printf("\n");
            }
            ++count;
            if (!no_titles) {
                printf(LABEL_NUM_FMT, count);
            }
            skHeaderEntryPrint(he, stdout);
            printf("\n");
        }
    }

    if (skBitmapGetBit(print_fields, RWINFO_ANNOTATIONS)) {
        count = 0;
        skHeaderIteratorBindType(&iter, hdr, SK_HENTRY_ANNOTATION_ID);
        while ((he = skHeaderIteratorNext(&iter)) != NULL) {
            if (count == 0 && !no_titles) {
                printLabel(RWINFO_ANNOTATIONS, count);
                printf("\n");
            }
            ++count;
            if (!no_titles) {
                printf(LABEL_NUM_FMT, count);
            }
            skHeaderEntryPrint(he, stdout);
            printf("\n");
        }
    }

    skStreamDestroy(&stream);
    return retval;
}


/*
 *  For each file, get the file's info then print it
 */
int main(int argc, char **argv)
{
    int64_t total_files = 0;
    int64_t total_bytes = 0;
    int64_t total_recs = 0;
    int rv = EXIT_SUCCESS;
    char *path;

    appSetup(argc, argv);       /* never returns on error */

    while (skOptionsCtxNextArgument(optctx, &path) == 0) {
        if (printFileInfo(path, &total_recs, &total_bytes)) {
            rv = EXIT_FAILURE;
        }
        ++total_files;
    }

    if (print_summary) {
        if (!no_titles) {
            printf("**SUMMARY**:\n");
            printf(LABEL_FMT, "number-files");
        }
            printf(("%" PRId64 "\n"), total_files);
        if (skBitmapGetBit(print_fields, RWINFO_COUNT_RECORDS)) {
            if (!no_titles) {
                printf(LABEL_FMT, "total-records");
            }
            printf(("%" PRId64 "\n"), total_recs);
        }
        if (skBitmapGetBit(print_fields, RWINFO_FILE_SIZE)) {
            if (!no_titles) {
                printf(LABEL_FMT, "all-file-sizes");
            }
            printf(("%" PRId64 "\n"), total_bytes);
        }
    }

    /* done */
    return rv;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
