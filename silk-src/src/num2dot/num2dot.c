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
**  num2doc.c
**
**  Suresh L Konda
**  7/31/2002
**      "filter" to convert numeric ip to dotted ip. The default field
**      delimiter is '|' in deference to our internal default.  The
**      default field is 1 (numbering starts at 1).  Changes can be
**      provided via options --ip-fields=<range> and
**      --delimiter=<char>.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: num2dot.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skipaddr.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to send usage output */
#define USAGE_FH stdout

/* max fields (columns) we support in each line of the output. */
#define MAX_FIELD_COUNT         1024

/* max length of input line */
#define MAX_LINE_LENGTH         2048

/* default field(s) to convert. this gets passed to parseIPFields() if
 * the user does not provide an --ip-fields value */
#define N2D_DEFAULT_FIELDS      "1"

/* the type of each field on a line of input (from rwresolve.c) */
typedef enum ip_field_type_en {
    /* the final field to handle; nothing but text remains */
    N2D_TEXT_FINAL,
    /* field is surrounded by IP fields */
    N2D_TEXT_SINGLE,
    /* field begins a list of contiguous text fields */
    N2D_TEXT_OPEN,
    /* field is in middle of contiguous text fields */
    N2D_TEXT_CONTINUE,
    /* field closes a list of contiguous text fields */
    N2D_TEXT_CLOSE,
    /* field contains an IP to convert */
    N2D_CONVERT
} ip_field_type_t;



/* LOCAL VARIABLES */

/* what each field of the input contains */
static ip_field_type_t ip_fields[MAX_FIELD_COUNT];

/* number of expected "parts" on a line when all contiguous non-IP
 * fields become a single "part" */
static int line_part_count = 0;

/* input stream (stdin) */
static skstream_t *in_stream = NULL;

/* where to send output (stdout) */
static FILE *outf;

/* width of IP columns */
static const int column_width = 15;

/* delimiter between the fields */
static char delimiter = '|';



/* OPTIONS SETUP */

typedef enum {
    OPT_IP_FIELDS, OPT_DELIMITER
} appOptionsEnum;

static struct option appOptions[] = {
    {"ip-fields", REQUIRED_ARG, 0, OPT_IP_FIELDS},
    {"delimiter", REQUIRED_ARG, 0, OPT_DELIMITER},
    {0,0,0,0}     /* sentinel entry */
};

static const char *appHelp[] = {
    ("Convert numbers to dotted-decimal IP addresses in these\n"
     "\tinput columns.  Column numbers begin with 1."
     " Def. " N2D_DEFAULT_FIELDS),
    "Specify the delimiter to expect between fields. Def. '|'",
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int  parseIPFields(const char *b);


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
    ("[SWITCHES]\n"                                                          \
     "\tRead pipe (|) delimited text from the standard input, convert\n"     \
     "\tinteger values in the specified column(s) (default first column)\n"  \
     "\tto dotted-decimal IP addresses, and print result to standard output.\n")

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

    skStreamDestroy(&in_stream);

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
        skAppUsage();           /* never returns */
    }

    /* check for extra arguments */
    if (arg_index != argc) {
        skAppPrintErr("Unexpected argument '%s'", argv[arg_index]);
        skAppUsage();             /* never returns */
    }

    /* set the default fields if none specified */
    if (0 == line_part_count) {
        parseIPFields(N2D_DEFAULT_FIELDS);
    }

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
    switch (opt_index) {
      case OPT_IP_FIELDS:
        /* ip fields */
        parseIPFields(opt_arg);          /* never returns on error */
        break;

      case OPT_DELIMITER:
        /* delimiter */
        delimiter = *opt_arg;
        if ('\0' == delimiter) {
            skAppPrintErr("Empty string not valid argument for --delimiter");
            return 1;
        }
        break;

      default:
        skAbortBadCase(opt_index);
    }
    return 0;                   /* OK */
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
    skQSort(list, count, sizeof(uint32_t), &compr32);
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
        /* this field is a number to convert to an IP */
        ip_fields[i] = N2D_CONVERT;
        ++line_part_count;
        ++j;
        if (j == count) {
            ip_fields[i + 1] = N2D_TEXT_FINAL;
            ++line_part_count;
            goto END;
        }
    } else {
        ip_fields[i] = N2D_TEXT_OPEN;
        ++line_part_count;
    }
    ++i;

    /* handle all remaining fields */
    for ( ; i < MAX_FIELD_COUNT; ++i) {
        if (i + 1 == list[j]) {
            /* this field is an IP to lookup */

            /* properly close previous field */
            switch (ip_fields[i - 1]) {
              case N2D_CONVERT:
                break;

              case N2D_TEXT_OPEN:
                ip_fields[i - 1] = N2D_TEXT_SINGLE;
                break;

              case N2D_TEXT_CONTINUE:
                ip_fields[i - 1] = N2D_TEXT_CLOSE;
                break;

              default:
                skAbortBadCase(ip_fields[i-1]);
            }

            ip_fields[i] = N2D_CONVERT;
            ++line_part_count;
            ++j;
            if (j == count) {
                ip_fields[i + 1] = N2D_TEXT_FINAL;
                ++line_part_count;
                break;
            }
        } else {
            /* this is a text field. set its type based on the
             * previous field */
            switch (ip_fields[i - 1]) {
              case N2D_CONVERT:
                ip_fields[i] = N2D_TEXT_OPEN;
                ++line_part_count;
                break;

              case N2D_TEXT_OPEN:
              case N2D_TEXT_CONTINUE:
                ip_fields[i] = N2D_TEXT_CONTINUE;
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


int main(int argc, char **argv)
{
    char line_buf[MAX_LINE_LENGTH];
    char *cp, *sp, *ep;
    int lc = 0;
    uint32_t num;
    uint32_t field;
    int rv;

    appSetup(argc, argv);                       /* never returns */

    /* read until end of file */
    while ((rv = skStreamGetLine(in_stream, line_buf, sizeof(line_buf), &lc))
           != SKSTREAM_ERR_EOF)
    {
        switch (rv) {
          case SKSTREAM_OK:
            /* good, we got our line */
            break;
          case SKSTREAM_ERR_LONG_LINE:
            /* bad: line was longer than sizeof(line_buf) */
            skAppPrintErr("Input line %d too long. ignored",
                          lc);
            continue;
          default:
            /* unexpected error */
            skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
            goto END;
        }

        /* process each field in the line */
        for (cp = line_buf, sp = cp, field = 0; *cp != '\0'; ++field) {
            switch (ip_fields[field]) {
              case N2D_CONVERT:
                /* field contains a number to convert to IP */
                ep = strchr(cp, delimiter);
                if (ep) {
                    *ep = '\0';
                }
                if (0 == skStringParseUint32(&num, cp, 0, 0)) {
                    char ipstr[SKIPADDR_STRLEN];
                    skipaddr_t ipaddr;

                    skipaddrSetV4(&ipaddr, &num);
                    fprintf(outf, "%*s", column_width,
                            skipaddrString(ipstr, &ipaddr, 0));
                } else {
                    while (isspace((int)*cp)) {
                        ++cp;
                    }
                    fprintf(outf, "%*s", column_width, cp);
                }
                if (ep) {
                    fprintf(outf, "%c", delimiter);
                    cp = ep + 1;
                } else {
                    cp += strlen(cp);
                }
                break;

              case N2D_TEXT_FINAL:
                /* the final field to handle; nothing but text remains */
                fprintf(outf, "%s", cp);
                cp += strlen(cp);
                break;

              case N2D_TEXT_OPEN:
                /* field begins contiguous text fields */
                sp = cp;
                /* FALLTHROUGH */

              case N2D_TEXT_CONTINUE:
                /* field is in middle of contiguous text fields */
                ep = strchr(cp, delimiter);
                if (ep) {
                    cp = ep + 1;
                    if (!*cp) {
                        /* unexpected end of input */
                        fprintf(outf, "%s", sp);
                    }
                } else {
                    /* unexpected end of input */
                    fprintf(outf, "%s", sp);
                    cp += strlen(cp);
                }
                break;

              case N2D_TEXT_SINGLE:
                /* field is surrounded by IP fields */
                sp = cp;
                /* FALLTHROUGH */

              case N2D_TEXT_CLOSE:
                /* field closes a list of contiguous text fields */
                ep = strchr(cp, delimiter);
                if (ep) {
                    *ep = '\0';
                    fprintf(outf, "%s%c", sp, delimiter);
                    cp = ep + 1;
                } else {
                    fprintf(outf, "%s", sp);
                    cp += strlen(cp);
                }
                break;
            }
        }
        fprintf(outf, "\n");
    }

  END:
    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
