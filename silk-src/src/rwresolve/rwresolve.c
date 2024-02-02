/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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
**  rwresolve.c
**
**  Mark Thomas
**  December 2005
**
**      A pipe-line filter to read delimited textual input, convert
**      IP(s) to hostname(s), and print the results.  The default
**      field delimiter is '|' in deference to our default.  The
**      default fields are 1,2 (numbering starts at 1) as for rwcut.
**      Changes can be provided via options --ip-fields=<range> and
**      --delimiter=<char>.
**
**      The --ip-fields value is parsed to get a list of fields to
**      change.  The result is an array of "ip_field_type_t", where
**      each "line_part" is either an IP to lookup or a textual part
**      to be displayed as-is.
**
**      For the synchronous DNS resolution:
**
**      A line of text is read, and the ip_field_type_t of each field
**      is checked.  This creates an array of "line_part_t".
**      Contiguous textual fields are grouped into a single
**      "line_part" to speed output.  If the line_part contains an IP
**      address, it is converted to an integer (IPv6 addresses are not
**      supported).
**
**      Another function processes the array of "line_parts" to either
**      resolve the IP address or print the textual parts as-is.  The
**      function uses a hash table to avoid the DNS lookup for IPs it
**      has seen before.  If the hash table completely fills, it is
**      destroyed and re-created.
**
**      For the asynchronous DNS resolution:
**
**      The reading of a single line of input is similar to the above.
**
**      The array of line_part_t objects is stored in a "line_t", and
**      we create a linked-list of "line_t" objects.  For each IP to
**      be resolved in the array, an asynchronous DNS query object is
**      created.  The "line_t" contains an array of these outstanding
**      DNS queries.
**
**      At each iteration, the head item on the linked list of line_t
**      objects is checked to determine if the adns queries for that
**      line_t have resolved.  If so, the names are fetched and the
**      line is printed.  If not, the next line of input is read.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwresolve.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/hashlib.h>
#include <silk/skipaddr.h>
#include <silk/skstream.h>
#include <silk/skstringmap.h>
#include <silk/skvector.h>
#include <silk/utils.h>
#ifdef SK_HAVE_ADNS_H
#include <adns.h>
#endif
#ifdef SK_HAVE_CARES_H
#include <ares.h>
#endif


/* LOCAL DEFINES AND TYPEDEFS */

/* where to send usage output */
#define USAGE_FH stdout

/* max fields (columns) we support in each line of the output. */
#define MAX_FIELD_COUNT         1024

/* max length of input line---must be less than UINT16_MAX since we
 * use uint16_t to hold offsets into the line */
#define MAX_LINE_LENGTH         2048

/* the absolute max number of outstanding ADNS or C-ARES queries
 * permitted and the default maximum.  used to initialize and provide
 * range for max_requests which can be set with --max-requests */
#define RWRESOLVE_REQUESTS_ABS   1 << 15
#define RWRESOLVE_REQUESTS_DEF   128

/* initializer for hash table creation */
#define HASH_INITIAL_SIZE       500000

/* size of a hostname */
#ifdef NI_MAXHOST
#  define RWRESOLVE_MAXHOST     NI_MAXHOST
#else
#  define RWRESOLVE_MAXHOST     1025
#endif

/* DNS names are stored in large character buffers that have this
 * maximum size */
#define NAMEBUF_MAX_SIZE        (1 << 23)  /* 8 MB */

/* we use multiple allocations to get to the maximum buffer size.
 * each allocation has this size */
#define NAMEBUF_STEP_SIZE       (NAMEBUF_MAX_SIZE / 8)

/* the buffers are stored in an sk_vector. values in the vector of
 * buffers are indexed by a 32-bit integer, where part of the integer
 * is which vector entry, and part is an index into the character
 * buffer.  The following create the ID and get the values from the
 * ID */
#define NB_INDEX_CREATE(nbic_vector, nbic_offset)       \
    (((nbic_vector) << 23) | (nbic_offset))

#define NB_INDEX_GET_VECTOR(nbigv_index)        \
    ((nbigv_index) >> 23)

#define NB_INDEX_GET_OFFSET(nbigo_index)        \
    ((nbigo_index) & 0x007FFFFF)

/* since the ID has a max size of 32-bits, the maximum number of
 * buffers that the vector may hold is given here */
#define NAMEBUF_VECTOR_MAX      ((1 << 9) - 1)

/* value to signify that no columnar output should be attempted */
#define RWRESOLVE_NO_COLUMNS    INT32_MAX

/* message denoting an allocation failure */
#define PERROR_MEM_LINE(pml_line)                                       \
    skAppPrintErr("Out of memory at %s:%d", __FILE__, (pml_line))
#define PERROR_MEM  PERROR_MEM_LINE(__LINE__)


/* macros to print one line_part_t to the output */
#define PRINT_PART_TEXT(pp_line, pp_idx, pp_text)                       \
    if ((0 == (pp_line)->part[(pp_idx)].columnar)                       \
        || (RWRESOLVE_NO_COLUMNS == column_width))                      \
    {                                                                   \
        fprintf(outf, "%s%s", (pp_text),                                \
                ((pp_line)->part[(pp_idx)].delim ? delim_str : ""));    \
    } else {                                                            \
        char *cp = (pp_text);                                           \
        while (isspace((int)*cp)) {                                     \
            ++cp;                                                       \
        }                                                               \
        fprintf(outf, "%*s%s", column_width, cp,                        \
                ((pp_line)->part[(pp_idx)].delim ? delim_str : ""));    \
    }

#define PRINT_PART_DEFAULT(pp_line, pp_idx)                             \
    PRINT_PART_TEXT((pp_line), (pp_idx),                                \
                    &((pp_line)->buf[(pp_line)->part[(pp_idx)].offset]))



/* the type of each field on a line of input */
typedef enum ip_field_type_en {
    /* the final field to handle; nothing but text remains */
    RWRES_TEXT_FINAL,
    /* field is surrounded by lookup fields */
    RWRES_TEXT_SINGLE,
    /* field begins a contiguous text fields */
    RWRES_TEXT_OPEN,
    /* field is in middle of contiguous text fields */
    RWRES_TEXT_CONTINUE,
    /* field closes a list of contiguous text fields */
    RWRES_TEXT_CLOSE,
    /* field contains an IP to resolve */
    RWRES_LOOKUP
} ip_field_type_t;


/* for the synchronous case, there only needs to be one line_t object
 * to hold the current line.  for the asynchronous case, there is a
 * linked-list of them. */
typedef struct line_st line_t;

/* each line is split into "parts", where some parts are the IP fields
 * to be converted to names, and other parts are fields (or groups of
 * fields) to leave as-is */
typedef struct line_part_st {
#ifdef SK_HAVE_CARES_H
    /* pointer to the line containing this part */
    line_t         *line;
    uint32_t        cache_id;
#endif
    /* the IP address if this part contains an IP */
    skipaddr_t      ip;
    /* where in the line->buf does this part begin? */
    uint16_t        offset;
    /* whether there was a delimiter after the field */
    unsigned        delim :1;
    /* whether this part contains an address */
    unsigned        has_addr :1;
    /* whether this part should be printed in a fixed-width column */
    unsigned        columnar :1;
    /* whether the DNS lookup for this part is outstanding */
    unsigned        waiting :1;
} line_part_t;

struct line_st {
    /* the line of text from the input */
    char           *buf;
    /* information about each part of the input */
    line_part_t    *part;
    /* next line */
    line_t         *next;
#ifdef SK_HAVE_ADNS_H
    /* outstanding queries */
    adns_query     *adnsquery;
#endif
    /* number of queries that we made */
    uint16_t        query_count;
    /* the number of parts in the line */
    uint16_t        part_count;
    /* the available bytes in 'buf'. NOT the length of the current line */
    uint16_t        bufsiz;
};


/* possible resolve methods to use */
typedef enum resolver_type_en {
    RESOLVE_GETHOSTBYADDR,
    RESOLVE_GETNAMEINFO,
    RESOLVE_ADNS_SUBMIT,
    RESOLVE_CARES_SUBMIT
} resolver_type_t;

/* state used by getnameinfo() and/or gethostbyaddr() */
typedef struct resolve_state_st {
    char                hostname[RWRESOLVE_MAXHOST];
    struct sockaddr_in  sock;
} resolve_state_t;


/* LOCAL VARIABLES */

/* resolvers: the first of these will be the default */
static const sk_stringmap_entry_t resolver_name[] = {
#ifdef SK_HAVE_CARES_H
    {"c-ares",          RESOLVE_CARES_SUBMIT,   NULL, NULL},
#endif
#ifdef SK_HAVE_ADNS_H
    {"adns",            RESOLVE_ADNS_SUBMIT,    NULL, NULL},
#endif
#ifdef SK_HAVE_GETNAMEINFO
    {"getnameinfo",     RESOLVE_GETNAMEINFO,    NULL, NULL},
#endif
    {"gethostbyaddr",   RESOLVE_GETHOSTBYADDR,  NULL, NULL},
    SK_STRINGMAP_SENTINEL
};

/* which resolver function to use */
static resolver_type_t resolver;

/* what each field of the input contains */
static ip_field_type_t ip_fields[MAX_FIELD_COUNT];

/* number of IP fields to resolve */
static uint16_t ip_field_count = 0;

/* max number of line_part_t's we expect for each line */
static int line_part_count = 0;

/* input stream */
static skstream_t *in_stream = NULL;

/* where to send output */
static FILE *outf;

/* width of IP columns */
static int column_width = RWRESOLVE_NO_COLUMNS;

/* delimiter between the fields */
static char delimiter = '|';

/* a string containing the delimiter */
static char delim_str[2];

/* hash tables to cache DNS results for IPv4 and IPv6 lookups */
static HashTable *hash4 = NULL;
#if SK_ENABLE_IPV6
static HashTable *hash6 = NULL;
#endif

/* value that indicates the cache failed to allocate memory */
#define RWRES_CACHE_FAIL UINT32_MAX

/* value to store in hash to indicate that DNS lookup failed */
#define RWRES_NONAME     (UINT32_MAX - 1u)

#if defined(SK_HAVE_ADNS_H) || defined(SK_HAVE_CARES_H)
/* value to store in hash to indicate that DNS lookup is outstanding */
#define RWRES_WAITING    (UINT32_MAX - 2u)

/* maximum number of outstanding ADNS/C-ARES queries allowed */
static uint32_t max_requests = RWRESOLVE_REQUESTS_DEF;

/* when a memory error occurs, no_mem is set to the __LINE__ where it
 * occurred */
static int no_mem;

#endif  /* SK_HAVE_ADNS_H || SK_HAVE_CARES_H */


/* for efficiency of DNS name storage, a vector of character buffers
 * is maintained.  */
static sk_vector_t *namebuf_vec = NULL;

/* size of current buffer and number of bytes that are available */
static uint32_t namebuf_size = 0;
static size_t namebuf_avail = 0;

/* maintain list of line objects previous allocated */
static line_t *free_list = NULL;

/* FIXME: Consider adding --pager and --output-path support. */



/* OPTIONS SETUP */

typedef enum {
    OPT_IP_FIELDS, OPT_DELIMITER, OPT_COLUMN_WIDTH, OPT_RESOLVER
#if defined(SK_HAVE_ADNS_H) || defined(SK_HAVE_CARES_H)
    , OPT_MAX_REQUESTS
#endif
} appOptionsEnum;


static struct option appOptions[] = {
    {"ip-fields",       REQUIRED_ARG, 0, OPT_IP_FIELDS},
    {"delimiter",       REQUIRED_ARG, 0, OPT_DELIMITER},
    {"column-width",    REQUIRED_ARG, 0, OPT_COLUMN_WIDTH},
    {"resolver",        REQUIRED_ARG, 0, OPT_RESOLVER},
#if defined(SK_HAVE_ADNS_H) || defined(SK_HAVE_CARES_H)
    {"max-requests",    REQUIRED_ARG, 0, OPT_MAX_REQUESTS},
#endif
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    ("Convert IPs to host names in these input columns.  Column\n"
     "\tnumbers start with 1. Def. 1,2"),
    "Set delimiter between fields to this character. Def. '|'",
    ("Specify the output width of the column(s) specified\n"
     "\tin --fields.  Def. No justification for host names"),
    "Specify IP-to-host mapping function",
#if defined(SK_HAVE_ADNS_H) || defined(SK_HAVE_CARES_H)
    (char *)NULL,               /* handled below */
#endif
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  parseIPFields(const char *arg);
static int  parseResolverName(const char *res_name);
static void reallocCache(int recreate);
static void lineFreeListEmpty(void);


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
#define USAGE_MSG                                                             \
    ("[SWITCHES]\n"                                                           \
     "\tReads delimited text (such as from rwcut) from the standard input\n"  \
     "\tand resolves the IP addresses in the specified columns.  If the\n"    \
     "\t--ip-fields switch is not given, columns 1 and 2 are resolved.\n"     \
     "\tOutput is sent to the standard output.  Beware, this is going\n"      \
     "\tto be slow.\n")

    FILE *fh = USAGE_FH;
    int i;
    int j;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    skOptionsDefaultUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch (appOptions[i].val) {
          case OPT_RESOLVER:
            fprintf(fh, "%s. Def. %s\n",
                    appHelp[i], resolver_name[0].name);
            fprintf(fh, "\tChoices: %s", resolver_name[0].name);
            for (j = 1; resolver_name[j].name; ++j) {
                fprintf(fh, ", %s", resolver_name[j].name);
            }
            break;

#if defined(SK_HAVE_ADNS_H) || defined(SK_HAVE_CARES_H)
          case OPT_MAX_REQUESTS:
            {
                int comma = 0;
                fprintf(fh, "When an asynchronous resolver (");
                for (j = 0; resolver_name[j].name; ++j) {
                    switch (resolver_name[j].id) {
                      case RESOLVE_ADNS_SUBMIT:
                      case RESOLVE_CARES_SUBMIT:
                        fprintf(fh, "%s%s",
                                (comma ? ", " : ""), resolver_name[j].name);
                        comma = 1;
                        break;
                      default:
                        break;
                    }
                }
                fprintf(fh,
                        (") is used,\n\tallow no more than this many"
                         " pending DNS requests. 1-"
                         "%" PRIu32 ". Def. %" PRIu32),
                        RWRESOLVE_REQUESTS_ABS,RWRESOLVE_REQUESTS_DEF);
            }
            break;
#endif  /* SK_HAVE_ADNS_H || SK_HAVE_CARES_H */

          default:
            fprintf(fh, "%s", appHelp[i]);
            break;
        }
        fprintf(fh, "\n");
    }
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

    skStreamDestroy(&in_stream);

    reallocCache(0);
    lineFreeListEmpty();

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
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* initialize globals */
    resolver = (resolver_type_t)resolver_name[0].id;
    outf = stdout;

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

    /* parse options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage();             /* never returns */
    }

    /* check for extra arguments */
    if (arg_index != argc) {
        skAppPrintErr("Unexpected argument '%s'", argv[arg_index]);
        skAppUsage();             /* never returns */
    }

#if defined(SK_HAVE_ADNS_H) || defined(SK_HAVE_CARES_H)
    /* max number of outstanding requests must be at least as large as
     * the number of IP fields */
    if (max_requests < ip_field_count) {
        max_requests = ip_field_count;
    }
#endif  /* SK_HAVE_ADNS_H || SK_HAVE_CARES_H */

    /* set the delimiter string */
    snprintf(delim_str, sizeof(delim_str), "%c", delimiter);

    /* set the default fields if none specified */
    if (0 == line_part_count) {
        parseIPFields("1,2");
    }

    /* create hash table */
    reallocCache(1);

    /* open input */
    if ((rv = skStreamCreate(&in_stream, SK_IO_READ, SK_CONTENT_TEXT))
        || (rv = skStreamBind(in_stream, "stdin"))
        || (rv = skStreamOpen(in_stream)))
    {
        skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }

    return;                     /* OK */
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
    int rv;
    uint32_t tmp32;

    switch ((appOptionsEnum)opt_index) {
      case OPT_IP_FIELDS:
        if (parseIPFields(opt_arg)) {
            return 1;
        }
        break;

      case OPT_DELIMITER:
        delimiter = *opt_arg;
        if ('\0' == delimiter) {
            skAppPrintErr("Invalid %s: Empty string not valid argument",
                          appOptions[opt_index].name);
            return 1;
        }
        break;

      case OPT_COLUMN_WIDTH:
        rv = skStringParseUint32(&tmp32, opt_arg, 0, MAX_LINE_LENGTH);
        if (rv) {
            goto PARSE_ERROR;
        }
        column_width = (int)tmp32;
        break;

      case OPT_RESOLVER:
        if (parseResolverName(opt_arg)) {
            return 1;
        }
        break;

#if defined(SK_HAVE_ADNS_H) || defined(SK_HAVE_CARES_H)
      case OPT_MAX_REQUESTS:
        rv = skStringParseUint32(&max_requests, opt_arg,
                                 1, RWRESOLVE_REQUESTS_ABS);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;
#endif  /* SK_HAVE_ADNS_H || SK_HAVE_CARES_H */
    }

    return 0;                   /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


/* comparison function used to sort the user's field list */
static int
compr32(
    const void         *a,
    const void*         b)
{
    const uint32_t a32 = *((uint32_t*)a);
    const uint32_t b32 = *((uint32_t*)b);

    if (a32 < b32) {
        return -1;
    }
    if (a32 > b32) {
        return 1;
    }
    return 0;
}


/*
 *  is_ok = parseIPFields(arg);
 *
 *    Given a comma-separated list of numbers and/or ranges, set the
 *    appropriate flags in the 'ip_fields' array.
 */
static int
parseIPFields(
    const char         *arg)
{
    uint32_t *list;
    uint32_t count;
    uint32_t i;
    uint32_t j;
    int rv;

    /* have we been here before? */
    if (line_part_count) {
        skAppPrintErr("Invalid %s: Switch used multiple times",
                      appOptions[OPT_IP_FIELDS].name);
        return 1;
    }

    /* parse the values into an array */
    rv = skStringParseNumberList(&list, &count, arg, 1, MAX_FIELD_COUNT, 0);
    if (rv) {
        skAppPrintErr("Invalid %s '%s': %s",
                      appOptions[OPT_IP_FIELDS].name, arg,
                      skStringParseStrerror(rv));
        return 1;
    }

    /* the list of fields must be in ascending order and contain no
     * duplicates */
    qsort(list, count, sizeof(uint32_t), &compr32);
    for (i = 0, j = 1; j < count; ++j) {
        if (list[i] < list[j]) {
            ++i;
            if (i != j) {
                list[i] = list[j];
            }
        }
    }
    count = i + 1;

    /* initialize values */
    memset(ip_fields, 0, sizeof(ip_fields));
    i = 0;
    j = 0;

    /* handle the first field */
    if (i + 1 == list[j]) {
        /* this field is an IP to lookup */
        ip_fields[i] = RWRES_LOOKUP;
        ++ip_field_count;
        ++line_part_count;
        ++j;
        if (j == count) {
            ip_fields[i + 1] = RWRES_TEXT_FINAL;
            ++line_part_count;
            goto END;
        }
    } else {
        ip_fields[i] = RWRES_TEXT_OPEN;
        ++line_part_count;
    }
    ++i;

    /* handle all remaining fields */
    for ( ; i < MAX_FIELD_COUNT; ++i) {
        if (i + 1 == list[j]) {
            /* this field is an IP to lookup */

            /* properly close previous field */
            switch (ip_fields[i - 1]) {
              case RWRES_LOOKUP:
                break;

              case RWRES_TEXT_OPEN:
                ip_fields[i - 1] = RWRES_TEXT_SINGLE;
                break;

              case RWRES_TEXT_CONTINUE:
                ip_fields[i - 1] = RWRES_TEXT_CLOSE;
                break;

              default:
                skAbortBadCase(ip_fields[i-1]);
            }

            ip_fields[i] = RWRES_LOOKUP;
            ++ip_field_count;
            ++line_part_count;
            ++j;
            if (j == count) {
                ip_fields[i + 1] = RWRES_TEXT_FINAL;
                ++line_part_count;
                break;
            }
        } else {
            /* this is a text field. set its type based on the
             * previous field */
            switch (ip_fields[i - 1]) {
              case RWRES_LOOKUP:
                ip_fields[i] = RWRES_TEXT_OPEN;
                ++line_part_count;
                break;

              case RWRES_TEXT_OPEN:
              case RWRES_TEXT_CONTINUE:
                ip_fields[i] = RWRES_TEXT_CONTINUE;
                break;

              default:
                skAbortBadCase(ip_fields[i-1]);
            }
        }
    }

  END:
    free(list);
    return 0;                   /* OK */
}


/*
 *  ok = parseResolverName(res_name);
 *
 *    Set the global 'resolver' based on the resolver name specified
 *    in 'res_name'.  Return 0 on success, -1 on failure.
 */
static int
parseResolverName(
    const char         *res_name)
{
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_status_t rv_map;
    sk_stringmap_entry_t *found_entry;
    int rv = -1;

    /* create a stringmap of the available resolvers */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        PERROR_MEM;
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, resolver_name) != SKSTRINGMAP_OK) {
        goto END;
    }

    /* attempt to match */
    rv_map = skStringMapGetByName(str_map, res_name, &found_entry);
    switch (rv_map) {
      case SKSTRINGMAP_OK:
        resolver = (resolver_type_t)found_entry->id;
        rv = 0;
        break;

      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("%s value '%s' is ambiguous",
                      appOptions[OPT_RESOLVER].name, res_name);
        break;

      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr("%s value '%s' is not recognized",
                      appOptions[OPT_RESOLVER].name, res_name);
        break;

      default:
        skAppPrintErr("Unexpected return value from string-map parser (%d)",
                      rv_map);
        break;
    }

  END:
    if (str_map) {
        skStringMapDestroy(str_map);
    }
    return rv;
}


/*
 *  reallocCache(recreate);
 *
 *    Creates, clears, and/or destroys the hash table and vector used
 *    to cache the DNS names.
 *
 *    If the global hashtables 'hash4' and 'hash6' are non-NULL,
 *    calling this function destroys the hash tables and all of their
 *    contents.  (There is no way to clear the hash table.)
 *
 *    If 'recreate' is non-zero, calling this function creates new
 *    hashtables and stores them in the global 'hash4' and 'hash6'.
 *    The 'hash6' table is only created when using a resolver that
 *    supports IPv6 addresses.
 *
 *    This function also handles the namebuf vector.  When this
 *    function is called, the namebuf vector is emptied if it exists.
 *    If the namebuf vector does not exist and 'recreate' is 1, it is
 *    created.  If 'recreate' is 0 and the namebuf vector exists, it
 *    will be destroyed.
 *
 *    If an allocation fails, the problem terminates.
 */
static void
reallocCache(
    int                 recreate)
{
    uint32_t hash_no_value = UINT32_MAX;
    size_t i;
    void **p;

    if (namebuf_vec) {
        for (i = 0; i < skVectorGetCount(namebuf_vec); ++i) {
            p = (void**)skVectorGetValuePointer(namebuf_vec, i);
            if (p && *p) {
                free(*p);
            }
        }
        if (recreate) {
            /* empty the vector */
            skVectorClear(namebuf_vec);
        } else {
            /* destroy it */
            skVectorDestroy(namebuf_vec);
        }
    } else if (recreate) {
        namebuf_vec = skVectorNew(sizeof(char*));
        if (NULL == namebuf_vec) {
            PERROR_MEM;
            exit(EXIT_FAILURE);
        }
    }
    namebuf_avail = 0;
    namebuf_size = 0;

    if (hash4) {
        hashlib_free_table(hash4);
        hash4 = NULL;
    }
#if SK_ENABLE_IPV6
    if (hash6) {
        hashlib_free_table(hash6);
        hash6 = NULL;
    }
#endif

    if (recreate) {
        hash4 = hashlib_create_table(sizeof(uint32_t), sizeof(uint32_t),
                                     HTT_INPLACE, (uint8_t*)&hash_no_value,
                                     NULL, 0,
                                     HASH_INITIAL_SIZE, DEFAULT_LOAD_FACTOR);
        if (NULL == hash4) {
            PERROR_MEM;
            exit(EXIT_FAILURE);
        }
#if SK_ENABLE_IPV6
        if (resolver == RESOLVE_GETNAMEINFO
            || resolver == RESOLVE_CARES_SUBMIT)
        {
            hash6 = hashlib_create_table(16, sizeof(uint32_t),
                                         HTT_INPLACE, (uint8_t*)&hash_no_value,
                                         NULL, 0,
                                         HASH_INITIAL_SIZE,
                                         DEFAULT_LOAD_FACTOR);
            if (NULL == hash6) {
                PERROR_MEM;
                exit(EXIT_FAILURE);
            }
        }
#endif  /* SK_ENABLE_IPV6 */
    }
}


/*
 *  name = getCachedName(id);
 *
 *    Get the string in the cache that is indexed by 'id'.
 */
static char *
getCachedName(
    uint32_t            id)
{
    char **buf_ptr = (char**)skVectorGetValuePointer(namebuf_vec,
                                                     NB_INDEX_GET_VECTOR(id));
    return ((*buf_ptr) + NB_INDEX_GET_OFFSET(id));
}


/*
 *  id = cacheName(name);
 *
 *    Stores a copy of 'name' in a large character buffer.  Returns a
 *    32bit integer that can be used to get the name.  Returns
 *    UINT32_MAX if growing the buffer fails.
 */
static uint32_t
cacheName(
    const char         *name)
{
    static char *namebuf = NULL;
    static uint32_t namebuf_offset = 0;
    static uint32_t vector_idx = 0;
    size_t len = 1 + strlen(name);
    uint32_t rv;

    /* if namebuf is NULL, then namebuf_avail must be zero */
    assert(NULL != namebuf || 0 == namebuf_avail);

    if (len > namebuf_avail) {
        if ((0 == namebuf_size) || (NAMEBUF_MAX_SIZE == namebuf_size)) {
            /* must create new buffer */
            namebuf = (char*)malloc(NAMEBUF_STEP_SIZE);
            if (NULL == namebuf) {
                return RWRES_CACHE_FAIL;
            }

            if (skVectorAppendValue(namebuf_vec, &namebuf)) {
                free(namebuf);
                return RWRES_CACHE_FAIL;
            }
            vector_idx = skVectorGetCount(namebuf_vec) - 1;
            if (NAMEBUF_VECTOR_MAX == vector_idx) {
                /* ran out space in the 32bit ID */
                return RWRES_CACHE_FAIL;
            }
            namebuf_size = NAMEBUF_STEP_SIZE;
            namebuf_avail = namebuf_size;
            namebuf_offset = 0;

        } else {
            namebuf_size += NAMEBUF_STEP_SIZE;
            namebuf = (char*)realloc(namebuf, namebuf_size);
            if (NULL == namebuf) {
                /* failed.  restore old values */
                namebuf_size -= NAMEBUF_STEP_SIZE;
                skVectorGetValue(&namebuf, namebuf_vec, vector_idx);
                return RWRES_CACHE_FAIL;
            }
            /* buffer may have moved.  replace in vector */
            skVectorSetValue(namebuf_vec, vector_idx, &namebuf);
            namebuf_avail += NAMEBUF_STEP_SIZE;
        }
    }

    memcpy(namebuf + namebuf_offset, name, len);
    rv = NB_INDEX_CREATE(vector_idx, namebuf_offset);
    namebuf_avail -= len;
    namebuf_offset += len;
    return rv;
}


/*
 *  freeLine(line);
 *
 *    Frees all memory used by a line_t.  Does not cancel any
 *    outstanding DNS queries.
 */
static void
freeLine(
    line_t             *line)
{
    if (line) {
        if (line->buf) {
            free(line->buf);
        }
        if (line->part) {
            free(line->part);
        }
#ifdef SK_HAVE_ADNS_H
        if (line->adnsquery) {
            free(line->adnsquery);
        }
#endif
        free(line);
    }
}


/*
 *  line = allocLine();
 *
 *    Creates space for a new line_t object as well as space for the
 *    maximum number of line_part_t and adns queries.  Returns NULL if
 *    memory allocation failed.
 */
static line_t *
allocLine(
    void)
{
    line_t *line;

    line = (line_t*)calloc(1, sizeof(line_t));
    if (!line) {
        return NULL;
    }

    line->part = (line_part_t*)calloc(line_part_count, sizeof(line_part_t));
    if (!line->part) {
        freeLine(line);
        return NULL;
    }
#ifdef SK_HAVE_ADNS_H
    if (RESOLVE_ADNS_SUBMIT == resolver) {
        line->adnsquery = (adns_query*)calloc(ip_field_count,
                                              sizeof(adns_query));
        if (!line->adnsquery) {
            freeLine(line);
            return NULL;
        }
    }
#endif
    return line;
}


/*
 *  line = lineFreeListPop();
 *
 *    Return a line_t from the list of previously allocated line_t
 *    objects.  Return NULL if the free list is empty.
 *
 *    The line's fields will be set it 0 or NULL, with the exception
 *    of the 'buf' and 'bufsiz' fields.
 */
static line_t *
lineFreeListPop(
    void)
{
    line_t *line = NULL;

    if (free_list) {
        line = free_list;
        free_list = free_list->next;
        line->next = NULL;
        line->part_count = 0;
        line->query_count = 0;
#ifdef SK_HAVE_ADNS_H
        if (line->adnsquery) {
            memset(line->adnsquery, 0, ip_field_count * sizeof(adns_query));
        }
#endif
    }
    return line;
}


/*
 *  lineFreeListPush(line);
 *
 *    Put 'line' onto the list of previously allocated line_t objects
 *    so it can be re-used.
 */
static void
lineFreeListPush(
    line_t             *line)
{
    line->next = free_list;
    free_list = line;
}


/*
 *  lineFreeListEmpty();
 *
 *    Deallocate all line_t objects that exist on the free list.
 */
static void
lineFreeListEmpty(
    void)
{
    line_t *line;

    while (free_list) {
        line = free_list;
        free_list = free_list->next;
        freeLine(line);
    }
}


/*
 *  ok = getLine(&line);
 *
 *    Gets the next line of input.  This function will use previously
 *    allocated line_t objects if any exist; otherwise it will
 *    allocate a new line_t object.  The text of the line will be
 *    stored in memory local to the 'line' structure---either re-using
 *    the existing buffer or growing it if it too small.
 *
 *    In addition, the line will be parsed in accordance with the
 *    global 'ip_fields' array, and the line_part_t's of the 'part[]'
 *    array on 'line' will be filled in with the offets into
 *    line->buf.  The number of part[] elements found is stored in
 *    line->part_count.
 *
 *    The function will attempt to parse the IP fields.  If parsing
 *    succeeds, the 'ip' and 'has_addr' members of the appropriate
 *    'line_part_t' are set; otherwise, the 'has_addr' element is set
 *    to 0.
 *
 *    Returns 0 if there was input and all allocations succeeded.
 *    Returns 1 if there is no more input.  Returns -2 if memory
 *    allocatation failed.  Returns -1 if there was an error reading
 *    the input.
 */
static int
getLine(
    line_t            **new_line)
{
    static int pending_line = 0;
    static char line_buffer[MAX_LINE_LENGTH];
    size_t line_len;
    line_t *line = NULL;
    int rv;
    char *cp;
    char *ep;
    int field;
    int i;

    assert(new_line);

    *new_line = NULL;

    if (!pending_line) {
        /* get next valid line of input */
        while (SKSTREAM_OK != (rv = skStreamGetLine(in_stream, line_buffer,
                                                    sizeof(line_buffer), NULL)))
        {
            switch (rv) {
              case SKSTREAM_ERR_EOF:
                /* no more input */
                return 1;

              case SKSTREAM_ERR_LONG_LINE:
                /* bad: line was longer than sizeof(line) */
                continue;

              default:
                /* unexpected error */
                skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
                return -1;
            }
        }
    }

    line_len = strlen(line_buffer);

    /* get a line object */
    line = lineFreeListPop();
    if (!line) {
        line = allocLine();
        if (!line) {
            pending_line = 1;
            return -2;
        }
    }

    /* check size of line's buffer against length this line */
    if (line->bufsiz > line_len) {
        strncpy(line->buf, line_buffer, line->bufsiz);
    } else {
        /* too small */
        if (line->buf) {
            free(line->buf);
        }
        line->buf = strdup(line_buffer);
        if (line->buf) {
            line->bufsiz = 1 + line_len;
        } else {
            line->bufsiz = 0;
            lineFreeListPush(line);
            pending_line = 1;
            return -2;
        }
    }

    *new_line = line;

    /* process each field */
    for (cp = line->buf, field = 0, i = 0; *cp; ++field) {

        switch (ip_fields[field]) {
          case RWRES_LOOKUP:
            line->part[i].offset = cp - line->buf;
            line->part[i].columnar = 1;
            ep = strchr(cp, delimiter);
            if (ep) {
                *ep = '\0';
            }
            if (skStringParseIP(&line->part[i].ip, cp)) {
                /* parsing failed, print as any other text */
                line->part[i].has_addr = 0;
#if SK_ENABLE_IPV6
            } else if (skipaddrIsV6(&line->part[i].ip)) {
                if ((resolver == RESOLVE_GETNAMEINFO)
                    || (resolver == RESOLVE_CARES_SUBMIT))
                {
                    /* address is v6 and resolver supports it */
                    line->part[i].has_addr = 1;
                } else {
                    /* address is v6, but the resolver doesn't handle
                     * v6 addresses.  Print as text */
                    line->part[i].has_addr = 0;
                }
#endif  /* SK_ENABLE_IPV6 */
            } else {
                /* IP is v4 */
                line->part[i].has_addr = 1;
            }



            if (ep) {
                line->part[i].delim = 1;
                cp = ep + 1;
            } else {
                line->part[i].delim = 0;
                cp = &line->buf[line_len];
            }
            ++i;
            break;

          case RWRES_TEXT_FINAL:
            line->part[i].offset = cp - line->buf;
            cp = &line->buf[line_len];
            ++i;
            break;

          case RWRES_TEXT_OPEN:
            line->part[i].offset = cp - line->buf;
            line->part[i].columnar = 0;
            line->part[i].has_addr = 0;
            /* FALLTHROUGH */

          case RWRES_TEXT_CONTINUE:
            ep = strchr(cp, delimiter);
            if (ep) {
                cp = ep + 1;
                if (!*cp) {
                    line->part[i].delim = 0;
                    ++i;
                }
            } else {
                /* unexpected end of input */
                line->part[i].delim = 0;
                cp = &line->buf[line_len];
                ++i;
            }
            break;

          case RWRES_TEXT_SINGLE:
            line->part[i].offset = cp - line->buf;
            line->part[i].columnar = 0;
            line->part[i].has_addr = 0;
            /* FALLTHROUGH */

          case RWRES_TEXT_CLOSE:
            ep = strchr(cp, delimiter);
            if (ep) {
                *ep = '\0';
                line->part[i].delim = 1;
                cp = ep + 1;
            } else {
                line->part[i].delim = 0;
                cp = &line->buf[line_len];
            }
            ++i;
            break;
        }
    }

    line->part_count = i;

    return 0;
}


/*
 *  ok = resolve_gethostbyaddr();
 *
 *    Process the input using the synchronous DNS resolver
 *    gethostbyaddr().
 *
 *    A line of input is read, the IPs on the line are
 *    processed---either fetched from the cache or resolved and then
 *    inserted into the cache---and the line is printed.
 */
static int
resolve_gethostbyaddr(
    void)
{
    line_t *line = NULL;
    uint16_t i;
    uint32_t *cache_id;
    struct hostent *he;
    in_addr_t addr;
    int rv;

    /* process the input */
    while ((rv = getLine(&line)) == 0) {
        for (i = 0; i < line->part_count; ++i) {
            if (!line->part[i].has_addr) {
                /* no lookup necessary for this part */
                PRINT_PART_DEFAULT(line, i);
                continue;
            }

            /* check the hash for the IP */
            addr = htonl(skipaddrGetV4(&line->part[i].ip));
            rv = hashlib_insert(hash4, (uint8_t*)&addr, (uint8_t**)&cache_id);
            switch (rv) {
              case OK_DUPLICATE:
                /* found in cache */
                if (*cache_id == RWRES_NONAME) {
                    /* previous lookup failed */
                    PRINT_PART_DEFAULT(line, i);
                } else {
                    PRINT_PART_TEXT(line, i, getCachedName(*cache_id));
                }
                break;

              case ERR_OUTOFMEMORY:
              case ERR_NOMOREBLOCKS:
                reallocCache(1);
                rv = hashlib_insert(hash4, (uint8_t*)&addr,
                                    (uint8_t**)&cache_id);
                if (rv != OK) {
                    PERROR_MEM;
                    rv = -1;
                    goto END;
                }
                /* FALLTHROUGH */

              case OK:
                /* new entry; must do the DNS lookup */
                he = gethostbyaddr((char*)&addr, sizeof(in_addr_t), AF_INET);
                if (!he) {
                    /* lookup failed */
                    *cache_id = RWRES_NONAME;
                    PRINT_PART_DEFAULT(line, i);
                } else {
                    /* lookup succeeded; print result */
                    PRINT_PART_TEXT(line, i, he->h_name);
                    /* cache result */
                    *cache_id = cacheName(he->h_name);
                    if (RWRES_CACHE_FAIL == *cache_id) {
                        /* allocatation failed. reallocate everything */
                        reallocCache(1);
                    }
                }
                break;
            }
        }

        fprintf(outf, "\n");
        lineFreeListPush(line);
        line = NULL;
    }

  END:
    if (line) {
        lineFreeListPush(line);
    }
    return (rv >= 0 ? 0 : 1);
}


#ifdef SK_HAVE_GETNAMEINFO
/*
 *  ok = resolve_getnameinfo();
 *
 *    Process the input using the synchronous DNS resolver
 *    getnameinfo().
 *
 *    A line of input is read, the IPs on the line are
 *    processed---either fetched from the cache or resolved and then
 *    inserted into the cache---and the line is printed.
 */
static int
resolve_getnameinfo(
    void)
{
    char hostname[RWRESOLVE_MAXHOST];
    line_t *line = NULL;
    uint16_t i;
    uint32_t *cache_id;
    struct sockaddr_in sa4;
    int rv;

#if SK_ENABLE_IPV6
    struct sockaddr_in6 sa6;

    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
    sa6.sin6_len = sizeof(struct sockaddr_in6);
#endif
#endif  /* SK_ENABLE_IPV6 */

    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
#ifdef SK_HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sa4.sin_len = sizeof(struct sockaddr_in);
#endif

    /* process the input */
    while ((rv = getLine(&line)) == 0) {
        for (i = 0; i < line->part_count; ++i) {
            if (!line->part[i].has_addr) {
                /* no lookup necessary for this part */
                PRINT_PART_DEFAULT(line, i);
                continue;
            }

#if SK_ENABLE_IPV6
            if (skipaddrIsV6(&line->part[i].ip)) {
                skipaddrGetV6(&line->part[i].ip, sa6.sin6_addr.s6_addr);
                rv = hashlib_insert(hash6, (uint8_t*)sa6.sin6_addr.s6_addr,
                                    (uint8_t**)&cache_id);
                switch (rv) {
                  case OK_DUPLICATE:
                    /* found in cache */
                    if (*cache_id == RWRES_NONAME) {
                        /* previous lookup failed */
                        PRINT_PART_DEFAULT(line, i);
                    } else {
                        PRINT_PART_TEXT(line, i, getCachedName(*cache_id));
                    }
                    break;

                  case ERR_OUTOFMEMORY:
                  case ERR_NOMOREBLOCKS:
                    reallocCache(1);
                    rv = hashlib_insert(hash6, (uint8_t*)sa6.sin6_addr.s6_addr,
                                        (uint8_t**)&cache_id);
                    if (rv != OK) {
                        PERROR_MEM;
                        rv = -1;
                        goto END;
                    }
                    /* FALLTHROUGH */

                  case OK:
                    /* new entry; must do the DNS lookup */
                    rv = getnameinfo((struct sockaddr *)&sa6, sizeof(sa6),
                                     hostname, sizeof(hostname),
                                     NULL, 0, NI_NAMEREQD);
                    if (0 != rv) {
                        /* lookup failed */
                        assert(-1 == rv);
                        *cache_id = RWRES_NONAME;
                        PRINT_PART_DEFAULT(line, i);
                    } else {
                        /* lookup succeeded. print result */
                        PRINT_PART_TEXT(line, i, hostname);
                        /* cache result */
                        *cache_id = cacheName(hostname);
                        if (RWRES_CACHE_FAIL == *cache_id) {
                            /* allocatation failed. reallocate everything */
                            reallocCache(1);
                        }
                    }
                    break;
                }

                /* get the next part */
                continue;
            }
#endif  /* SK_ENABLE_IPV6 */

            /* address is IPv4 */
            sa4.sin_addr.s_addr = htonl(skipaddrGetV4(&line->part[i].ip));
            rv = hashlib_insert(hash4, (uint8_t*)&sa4.sin_addr.s_addr,
                                (uint8_t**)&cache_id);
            switch (rv) {
              case OK_DUPLICATE:
                /* found in cache */
                if (*cache_id == RWRES_NONAME) {
                    /* previous lookup failed */
                    PRINT_PART_DEFAULT(line, i);
                } else {
                    PRINT_PART_TEXT(line, i, getCachedName(*cache_id));
                }
                break;

              case ERR_OUTOFMEMORY:
              case ERR_NOMOREBLOCKS:
                reallocCache(1);
                rv = hashlib_insert(hash4, (uint8_t*)&sa4.sin_addr.s_addr,
                                    (uint8_t**)&cache_id);
                if (rv != OK) {
                    PERROR_MEM;
                    rv = -1;
                    goto END;
                }
                /* FALLTHROUGH */

              case OK:
                /* new entry; must do the DNS lookup */
                rv = getnameinfo((struct sockaddr *)&sa4, sizeof(sa4),
                                 hostname, sizeof(hostname),
                                 NULL, 0, NI_NAMEREQD);
                if (0 != rv) {
                    /* lookup failed */
                    *cache_id = RWRES_NONAME;
                    PRINT_PART_DEFAULT(line, i);
                } else {
                    /* lookup succeeded. print result */
                    PRINT_PART_TEXT(line, i, hostname);
                    /* cache result */
                    *cache_id = cacheName(hostname);
                    if (RWRES_CACHE_FAIL == *cache_id) {
                        /* allocatation failed. reallocate everything */
                        reallocCache(1);
                    }
                }
                break;
            }
        }

        fprintf(outf, "\n");
        lineFreeListPush(line);
        line = NULL;
    }

  END:
    if (line) {
        lineFreeListPush(line);
    }
    return (rv >= 0 ? 0 : 1);
}
#endif  /* SK_HAVE_GETNAMEINFO */


#ifdef SK_HAVE_ADNS_H
/*
 *  ok = resolve_adns_submit();
 *
 *    Process the input using the asynchronous DNS resolver library
 *    ADNS.
 *
 *    A line of input is read, and adns_submit() is called on each IP
 *    address to be looked up.  To allow input processing to continue
 *    while waiting for the DNS lookup to complete, a linked-list of
 *    input lines is maintained.  The input line contains an array of
 *    outstanding DNS queries.
 *
 *    At each iteration, the head item on the linked list of line_t
 *    objects is checked to determine if the adns queries for that
 *    line_t have resolved.  If so, the names are fetched and the
 *    line is printed.  If not, the next line of input is read.
 *
 *    If the maximum number of ADNS requets is reached, processing of
 *    input stops until some of the outstanding requests are handled.
 *
 *    If an out of memory condition is detected, all lines in the
 *    linked list are printed, and then the cache of DNS names is
 *    destroyed.  An LRU cache would be better, but the brute force
 *    method is simple and it works.
 */
static int
resolve_adns_submit(
    void)
{
    const adns_queryflags qflags
        = (adns_queryflags)(adns_qf_quoteok_cname|adns_qf_cname_loose);
    adns_state adns;
    adns_answer **answers;
    uint16_t answer_count;
    uint32_t num_requests;
    line_t *line;
    line_t *head;
    line_t *tail;
    line_t *line_no_mem;
    uint32_t *cache_id;
    uint32_t ipv4;
    char arpa_addr[64];        /* "255.255.255.255.in-addr.arpa", */
    uint16_t i, j;
    int eof;
    int rv;

    /* The pointers for maintaining the linked list of lines */
    head = tail = NULL;

    /* If a memory error occurs when building a line, we keep a
     * pointer to that line and process outstanding requests.  This is
     * a pointer to the postponed line. */
    line_no_mem = NULL;

    /* set to non-zero when all input has been processed */
    eof = 0;

    /* non-zero for a memory error; value will be __LINE__ where error
     * occurred. */
    no_mem = 0;

    /* initialize the ADNS library */
    rv = adns_init(&adns, (adns_initflags)0, 0);
    if (rv) {
        PERROR_MEM;
        return 1;
    }

    /* all DSN queries for a line must be answered before we move to
     * the next line, so there are at most 'ip_field_count' answers
     * outstanding. */
    answers = (adns_answer**)calloc(ip_field_count, sizeof(adns_answer*));
    if (NULL == answers) {
        PERROR_MEM;
        adns_finish(adns);
        return 1;
    }
    answer_count = 0;

    /* number of outstanding requests.  used to ensure no more that
     * max_requests are ever made */
    num_requests = 0;

    /* continue processing as long as there is input or outstanding
     * queries to process */
    while (head || !eof) {

        /* remove as many lines from the linked list as possible */
        while (head) {
            line = head;

            /* check whether all the results for this line are ready */
            while (answer_count < line->query_count) {
                /* if adding another line's worth of DNS requests will
                 * put us over max_requests, we need to wait for the
                 * queries to complete */
                if (no_mem || num_requests + ip_field_count > max_requests) {
                    rv = adns_wait(adns, &line->adnsquery[answer_count],
                                   &answers[answer_count], NULL);
                } else {
                    rv = adns_check(adns, &line->adnsquery[answer_count],
                                    &answers[answer_count], NULL);
                }
                if (EAGAIN == rv) {
                    /* not ready */
                    break;
                }
                if (0 != rv) {
                    if (no_mem || num_requests + ip_field_count > max_requests){
                        skAppPrintSyserror("Error in adns_wait()");
                    } else {
                        skAppPrintSyserror("Error in adns_check()");
                    }
                    exit(EXIT_FAILURE);
                }
                --num_requests;
                ++answer_count;
            }

            if (answer_count != line->query_count) {
                /* queries are still outstanding for this line, so
                 * there is nothing to print */
                break;
            }

            /* print the line */
            for (i = 0, j = 0; i < line->part_count; ++i) {
                if (!line->part[i].has_addr) {
                    /* no lookup necessary for this part */
                    PRINT_PART_DEFAULT(line, i);
                    continue;
                }

                ipv4 = skipaddrGetV4(&line->part[i].ip);
                rv = hashlib_lookup(hash4, (uint8_t*)&ipv4,
                                    (uint8_t**)&cache_id);
                if (rv != OK) {
                    /* we are looking up something we know should be
                     * there; something must be wrong */
                    skAbort();
                }
                if (!line->part[i].waiting) {
                    if (*cache_id == RWRES_NONAME) {
                        /* previous lookup failed */
                        PRINT_PART_DEFAULT(line, i);
                    } else {
                        PRINT_PART_TEXT(line, i, getCachedName(*cache_id));
                    }
                } else {
                    if (answers[j]->status == adns_s_ok) {
                        PRINT_PART_TEXT(line, i, *answers[j]->rrs.str);
                        *cache_id = cacheName(*answers[j]->rrs.str);
                        if (RWRES_CACHE_FAIL == *cache_id) {
                            /* have pending lines that use the address.
                             * just print the IP, and set no_mem so
                             * all pending lines will be processed. */
                            *cache_id = RWRES_NONAME;
                            no_mem = __LINE__;
                        }
                    } else {
                        *cache_id = RWRES_NONAME;
                        PRINT_PART_DEFAULT(line, i);
                    }
                    free(answers[j]);
                    ++j;
                }
            }

            fprintf(outf, "\n");

            answer_count = 0;

            /* go to next line */
            head = line->next;

            /* add the line to the free list */
            lineFreeListPush(line);
        }

        /* no line to read if we're at end of input */
        if (eof) {
            continue;
        }

        /* handle no memory condition from elsewhere */
        if (no_mem) {
            if (head) {
                /* we should have called 'adns_wait()' to completely
                 * process all entries in the while() loop.  something
                 * is unhappy. */
                PERROR_MEM_LINE(no_mem);
                skAppPrintErr("Memory condition not handled");
                exit(EXIT_FAILURE);
            }
            /* all lines have been printed, we can safely rebuild the
             * cache */
            reallocCache(1);
            no_mem = 0;
        }

        /* if there is a line that got postponed due to memory issues,
         * handle it now */
        if (line_no_mem) {
            line = line_no_mem;
            line_no_mem = NULL;
        } else {
            rv = getLine(&line);
            if (0 != rv) {
                if (-2 == rv) {
                    /* not enough memory to get line */
                    if (head) {
                        no_mem = __LINE__;
                        continue;
                    }
                    /* no lines are in waiting but we cannot create a new
                     * line.  not much we can do */
                    PERROR_MEM;
                    exit(EXIT_FAILURE);
                }
                /* no more data. */
                eof = 1;
                continue;
            }
        }

        for (i = 0; !no_mem && i < line->part_count; ++i) {
            if (!line->part[i].has_addr) {
                /* no lookup necessary for this part */
                continue;
            }

            /* check for the IP or get space to store it */
            ipv4 = skipaddrGetV4(&line->part[i].ip);
            rv = hashlib_insert(hash4, (uint8_t*)&ipv4,
                                (uint8_t**)&cache_id);
            switch (rv) {
              case OK_DUPLICATE:
                line->part[i].waiting = 0;
                /* found in cache. nothing to do with it yet */
                break;

              case ERR_OUTOFMEMORY:
              case ERR_NOMOREBLOCKS:
                /* memory error processing code is at bottom of
                 * outermost while()  */
                no_mem = __LINE__;
                goto LINE_NO_MEM;

              case OK:
                /* new entry; must do the DNS lookup */
                snprintf(arpa_addr, sizeof(arpa_addr),
                         "%d.%d.%d.%d.in-addr.arpa",
                         (ipv4 & 0xFF),
                         ((ipv4 >> 8) & 0xFF),
                         ((ipv4 >> 16) & 0xFF),
                         ((ipv4 >> 24) & 0xFF));
                rv = adns_submit(adns, arpa_addr, adns_r_ptr, qflags,
                                 NULL, &line->adnsquery[line->query_count]);
                if (0 == rv) {
                    *cache_id = RWRES_WAITING;
                    line->part[i].waiting = 1;
                    ++line->query_count;
                    ++num_requests;
                } else if (ENOMEM == rv) {
                    /* memory error processing code is at bottom of
                     * outermost while()  */
                    no_mem = __LINE__;
                    goto LINE_NO_MEM;
                } else {
                    /* treat as if lookup failed */
                   *cache_id = RWRES_NONAME;
                    line->part[i].waiting = 0;
                }
                break;
            }
        }

        /* add the line to the linked list */
        if (NULL == head) {
            head = line;
        } else {
            tail->next = line;
        }
        tail = line;

        /* we're good */
        continue;

        /* error processing code for failure to create a line */
      LINE_NO_MEM:
        /* postpone processing of this line.  free all resources it is
         * using.  loop around so we can print all outstanding lines,
         * rebuild the cache, then try again. */
        for (j = 0; j < line->query_count; ++j) {
            adns_cancel(line->adnsquery[j]);
        }
        line_no_mem = line;

        if (!head) {
            /* there are no outstanding lines. try to empty the cache */
            if (0 == hashlib_count_entries(hash4)) {
                /* name cache is empty but still could not allocate
                 * memory.  there is not much way to save ourselves */
                PERROR_MEM_LINE(no_mem);
                exit(EXIT_FAILURE);
            }
            reallocCache(1);
        }
    }

    if (answers) {
        free(answers);
    }
    adns_finish(adns);

    return 0;
}
#endif  /* SK_HAVE_ADNS_H */


#ifdef SK_HAVE_CARES_H

static void
rwres_callback(
    void               *v_line_part,
    int                 status,
    int          UNUSED(timeouts),
    char               *node,
    char        UNUSED(*service))
{
    line_part_t *line_part = (line_part_t*)v_line_part;
    uint32_t *cache_id;
    int rv;

    --line_part->line->query_count;

    switch (status) {
      case ARES_ENOMEM:
        line_part->cache_id = RWRES_NONAME;
        no_mem = __LINE__;
        break;

      case ARES_SUCCESS:
        line_part->cache_id = cacheName(node);
        if (RWRES_CACHE_FAIL == line_part->cache_id) {
            line_part->cache_id = RWRES_NONAME;
            no_mem = __LINE__;
        }
        break;

      default:
        line_part->cache_id = RWRES_NONAME;
        break;
    }

    /* update value in the hash */
#if SK_ENABLE_IPV6
    if (skipaddrIsV6(&line_part->ip)) {
        char ipv6[16];
        skipaddrGetV6(&line_part->ip, ipv6);
        rv = hashlib_insert(hash6, (uint8_t*)ipv6, (uint8_t**)&cache_id);
    } else
#endif  /* SK_ENABLE_IPV6 */
    {
        uint32_t ipv4;
        ipv4 = htonl(skipaddrGetV4(&line_part->ip));
        rv = hashlib_insert(hash4, (uint8_t*)&ipv4, (uint8_t**)&cache_id);
    }
    if (rv != OK_DUPLICATE) {
        skAbort();
    }
    *cache_id = line_part->cache_id;
}


/*
 *  ok = resolve_cares_submit();
 *
 *    Process the input using the asynchronous DNS resolver library
 *    ARES.
 *
 *    A line of input is read, and ares_submit() is called on each IP
 *    address to be looked up.  To allow input processing to continue
 *    while waiting for the DNS lookup to complete, a linked-list of
 *    input lines is maintained.  The input line contains an array of
 *    outstanding DNS queries.
 *
 *    At each iteration, the head item on the linked list of line_t
 *    objects is checked to determine if the ares queries for that
 *    line_t have resolved.  If so, the names are fetched and the
 *    line is printed.  If not, the next line of input is read.
 *
 *    If the maximum number of ARES requets is reached, processing of
 *    input stops until some of the outstanding requests are handled.
 *
 *    If an out of memory condition is detected, all lines in the
 *    linked list are printed, and then the cache of DNS names is
 *    destroyed.  An LRU cache would be better, but the brute force
 *    method is simple and it works.
 */
static int
resolve_cares_submit(
    void)
{
    ares_channel ares = NULL;
    uint32_t num_requests;
    line_t *line;
    line_t *head;
    line_t *tail;
    line_t *line_no_mem;
    uint32_t *cache_id;
    uint16_t i;
    int eof;
    int retval = 1;
    struct sockaddr_in sa4;
    int rv;
    struct ares_options ares_opts;
    int ares_optmask = 0;

#if SK_ENABLE_IPV6
    struct sockaddr_in6 sa6;

    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
    sa6.sin6_len = sizeof(struct sockaddr_in6);
#endif
#endif  /* SK_ENABLE_IPV6 */

    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
#ifdef SK_HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sa4.sin_len = sizeof(struct sockaddr_in);
#endif

    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
#ifdef SK_HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sa4.sin_len = sizeof(struct sockaddr_in);
#endif

    /* The pointers for maintaining the linked list of lines */
    head = tail = NULL;

    /* If a memory error occurs when building a line, we keep a
     * pointer to that line and process outstanding requests.  This is
     * a pointer to the postponed line. */
    line_no_mem = NULL;

    /* set to non-zero when all input has been processed */
    eof = 0;

    /* non-zero for a memory error; value will be __LINE__ where error
     * occurred. */
    no_mem = 0;

    /* do lookups in the host file ("f") and DNS ("b") */
    memset(&ares_opts, 0, sizeof(ares_opts));
    ares_opts.lookups = (char*)"fb";
    ares_optmask |= ARES_OPT_LOOKUPS;

#if defined(CARES_HAVE_ARES_LIBRARY_INIT) && CARES_HAVE_ARES_LIBRARY_INIT
    rv = ares_library_init(ARES_LIB_INIT_ALL);
    if (0 != rv) {
        skAppPrintErr("Unable to initialize c-ares: %s",
                      ares_strerror(rv));
        return retval;
    }
#endif
    /* initialize the ARES library */
    rv = ares_init_options(&ares, &ares_opts, ares_optmask);
    if (0 != rv) {
        skAppPrintErr("Unable to initialize c-ares: %s",
                      ares_strerror(rv));
        goto END;
    }

    /* continue processing as long as there is input or outstanding
     * queries to process */
    while (head || !eof) {

        /* print as many lines as we can by processing all lines at
         * front of list that have zero outstanding requests */
        while (head && 0 == head->query_count) {
            /* line is ready to be printed */
            line = head;
            head = line->next;

            for (i = 0; i < line->part_count; ++i) {
                if (!line->part[i].has_addr) {
                    /* no lookup necessary for this part */
                    PRINT_PART_DEFAULT(line, i);
                    continue;
                }

                if (line->part[i].cache_id != RWRES_WAITING) {
                    cache_id = &line->part[i].cache_id;

#if SK_ENABLE_IPV6
                } else if (skipaddrIsV6(&line->part[i].ip)) {
                    skipaddrGetV6(&line->part[i].ip, sa6.sin6_addr.s6_addr);
                    if (hashlib_lookup(hash6, (uint8_t*)sa6.sin6_addr.s6_addr,
                                       (uint8_t**)&cache_id) != OK)
                    {
                        skAbort();
                    }
#endif  /* SK_ENABLE_IPV6 */

                } else {
                    sa4.sin_addr.s_addr
                        = htonl(skipaddrGetV4(&line->part[i].ip));
                    if (hashlib_lookup(hash4, (uint8_t*)&sa4.sin_addr.s_addr,
                                       (uint8_t**)&cache_id) != OK)
                    {
                        skAbort();
                    }
                }
                if (*cache_id == RWRES_NONAME) {
                    /* previous lookup failed */
                    PRINT_PART_DEFAULT(line, i);
                } else {
                    PRINT_PART_TEXT(line, i, getCachedName(*cache_id));
                }
            }
            fprintf(outf, "\n");

            /* add the line to the free list */
            lineFreeListPush(line);
        }

        /* count number of outstanding requests to ensure no more
         * than max_requests are ever made */
        num_requests = 0;
        for (line = head; line != NULL; line = line->next) {
            num_requests += line->query_count;
        }

        /* wait for the outstanding queries to complete when
         * -- we're at the end of the input, or
         * -- we're out of memory, or
         * -- adding another line's worth of DNS requests will put
         *    us over max_requests
         */
        if (num_requests
            && (eof || no_mem
                || num_requests + ip_field_count > max_requests))
        {
            int nfds;
            fd_set readers, writers;
            struct timeval tv, *tvp;

            FD_ZERO(&readers);
            FD_ZERO(&writers);
            nfds = ares_fds(ares, &readers, &writers);
            if (0 == nfds) {
                break;
            }
            tvp = ares_timeout(ares, NULL, &tv);
            select(nfds, &readers, &writers, NULL, tvp);
            ares_process(ares, &readers, &writers);

            /* try to print lines */
            continue;
        }

        /* handle no memory condition from elsewhere */
        if (no_mem) {
            if (head) {
                /* we should have called 'ares_process()' to
                 * completely process all entries in the linked list.
                 * something is unhappy. */
                PERROR_MEM_LINE(no_mem);
                skAppPrintErr("Memory condition not handled");
                exit(EXIT_FAILURE);
            }
            /* all lines have been printed, we can safely rebuild the
             * cache */
            reallocCache(1);
            no_mem = 0;
        }

        /* if there is a line that got postponed due to memory issues,
         * handle it now */
        if (line_no_mem) {
            line = line_no_mem;
            line_no_mem = NULL;
        } else {
            /* get the next line of input */
            rv = getLine(&line);
            if (0 != rv) {
                if (-2 == rv) {
                    /* no memory to get line */
                    if (head) {
                        /* print all entries and then rebuild the cache */
                        no_mem = __LINE__;
                        continue;
                    }
                    /* no lines are in waiting but we cannot create a new
                     * line.  not much we can do */
                    PERROR_MEM;
                    exit(EXIT_FAILURE);
                }
                /* no more data (or error reading input) */
                eof = 1;
                continue;
            }
        }

        for (i = 0; !no_mem && i < line->part_count; ++i) {
            if (!line->part[i].has_addr) {
                /* no lookup necessary for this part */
                continue;
            }

#if SK_ENABLE_IPV6
            if (skipaddrIsV6(&line->part[i].ip)) {
                skipaddrGetV6(&line->part[i].ip, sa6.sin6_addr.s6_addr);
                rv = hashlib_insert(hash6, (uint8_t*)sa6.sin6_addr.s6_addr,
                                    (uint8_t**)&cache_id);
                switch (rv) {
                  case OK_DUPLICATE:
                    /* found in cache */
                    line->part[i].waiting = 0;
                    line->part[i].cache_id = *cache_id;
                    break;

                  case ERR_OUTOFMEMORY:
                  case ERR_NOMOREBLOCKS:
                    /* memory error processing code is at bottom of
                     * outermost while()  */
                    no_mem = __LINE__;
                    goto LINE_NO_MEM;

                  case OK:
                    /* new entry; must do the DNS lookup */
                    *cache_id = RWRES_WAITING;
                    line->part[i].waiting = 1;
                    line->part[i].line = line;
                    ++line->query_count;
                    ++num_requests;
                    ares_getnameinfo(ares, (struct sockaddr *)&sa6,sizeof(sa6),
                                     ARES_NI_LOOKUPHOST|ARES_NI_NAMEREQD,
                                     rwres_callback, &line->part[i]);
                    break;
                }
            } else
#endif  /* SK_ENABLE_IPV6 */
            {
                /* address is IPv4 */
                sa4.sin_addr.s_addr = htonl(skipaddrGetV4(&line->part[i].ip));
                rv = hashlib_insert(hash4, (uint8_t*)&sa4.sin_addr.s_addr,
                                    (uint8_t**)&cache_id);
                switch (rv) {
                  case OK_DUPLICATE:
                    /* found in cache. */
                    line->part[i].waiting = 0;
                    line->part[i].cache_id = *cache_id;
                    break;

                  case ERR_OUTOFMEMORY:
                  case ERR_NOMOREBLOCKS:
                    /* memory error processing code is at bottom of
                     * outermost while()  */
                    no_mem = __LINE__;
                    goto LINE_NO_MEM;

                  case OK:
                    /* new entry; must do the DNS lookup */
                    *cache_id = RWRES_WAITING;
                    line->part[i].waiting = 1;
                    line->part[i].line = line;
                    ++line->query_count;
                    ++num_requests;
                    ares_getnameinfo(ares, (struct sockaddr *)&sa4,sizeof(sa4),
                                     ARES_NI_LOOKUPHOST|ARES_NI_NAMEREQD,
                                     rwres_callback, &line->part[i]);
                    break;
                }
            }
        }

        /* add the line to the linked list */
        if (NULL == head) {
            head = line;
        } else {
            tail->next = line;
        }
        tail = line;

        /* we're good */
        continue;

        /* error processing code for failure to create a line */
      LINE_NO_MEM:
        /* postpone processing of this line.  free all resources it is
         * using.  loop around so we can print all outstanding lines,
         * rebuild the cache, then try again. */
        ares_cancel(ares);
        if (line->buf) {
            free(line->buf);
            line->buf = NULL;
        }
        line_no_mem = line;

        if (!head) {
            /* there are no outstanding lines. try to empty the cache */
            if (0 == hashlib_count_entries(hash4)) {
                /* name cache is empty but still could not allocate
                 * memory.  there is not much way to save ourselves */
                PERROR_MEM_LINE(no_mem);
                exit(EXIT_FAILURE);
            }
            reallocCache(1);
        }
    }

  END:
    if (ares) {
        ares_destroy(ares);
    }
#if defined(CARES_HAVE_ARES_LIBRARY_CLEANUP) && CARES_HAVE_ARES_LIBRARY_CLEANUP
    ares_library_cleanup();
#endif

    return 0;
}
#endif  /* SK_HAVE_CARES_H */


int main(int argc, char **argv)
{
    int rv = 0;

    appSetup(argc, argv);                       /* never returns on error */

    switch (resolver) {
      case RESOLVE_GETHOSTBYADDR:
        rv = resolve_gethostbyaddr();
        break;

      case RESOLVE_GETNAMEINFO:
#ifdef SK_HAVE_GETNAMEINFO
        rv = resolve_getnameinfo();
#else
        skAbort();
#endif
        break;

      case RESOLVE_ADNS_SUBMIT:
#ifdef SK_HAVE_ADNS_H
        rv = resolve_adns_submit();
#else
        skAbort();
#endif
        break;

      case RESOLVE_CARES_SUBMIT:
#ifdef SK_HAVE_CARES_H
        rv = resolve_cares_submit();
#else
        skAbort();
#endif
        break;
    }

    return (rv ? EXIT_FAILURE : EXIT_SUCCESS);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
