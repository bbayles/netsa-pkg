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
 *  rwsetbuild.c
 *
 *    Build an IPset from textual data.
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: rwsetbuild.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write output from --help */
#define USAGE_FH stdout

#define EXIT_NO_MEMORY                                               \
    do {                                                             \
        skAppPrintOutOfMemory(NULL);                                 \
        exit(EXIT_FAILURE);                                          \
    } while(0)

#define SUGGEST_IP_RANGES                                               \
    "Multiple IPs on single line; did you intend to use --ip-ranges?"

/*
 *  is_int = SETBUILD_BUF_IS_INT(sbii_buf)
 *
 *    Return a true value if 'sbii_buf' contains a single
 *    integer; that is, it only contains digits and whitespace.
 */
#define SETBUILD_BUF_IS_INT(sbii_buf)                                   \
    ('\0' == (sbii_buf)[strspn(sbii_buf, "0123456789 \t\n\v\f\r")])

/* error message for mixed IPv6 and integer input */
#define SETBUILD_ERR_MIX_INT_V6  "May not mix IPv6 addresses and integer IPs"


/* LOCAL VARIABLES */

/* the IPset the application creates. */
static skipset_t *ipset = NULL;

/* input and output streams */
static skstream_t *in_stream = NULL;
static skstream_t *out_stream = NULL;

/* whether the input contains IP ranges; default 0 == no */
static int ip_ranges = 0;

/* the separator to use between the two IPs */
static char delimiter = '-';

/* parameters to use when writing the IPset */
static skipset_options_t set_options;


/* OPTIONS SETUP */

typedef enum {
    OPT_IP_RANGES
} appOptionsEnum;

static struct option appOptions[] = {
    {"ip-ranges",       OPTIONAL_ARG, 0, OPT_IP_RANGES},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    ("Allow input to contain IP-IP or NUM-NUM. Optional\n"
     "\targument is the delimiter to use between the values. Def. No, '-'.\n"
     "\tUse of this switch disables support for SiLK Wildcard IPs"),
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
#define USAGE_MSG                                                             \
    ("[SWITCHES] [<INPUT_FILE> [<OUTPUT_FILE>]]\n"                            \
     "\tRead IP addresses from the text file INPUT_FILE and write a binary\n" \
     "\tIPset file to OUTPUT_FILE.  Supported IP formats are canonical\n"     \
     "\t(e.g, dotted quad for IPv4), SiLK Wildcard, and integer for IPv4.\n"  \
     "\tUse 'stdin' or '-' as INPUT_FILE to read the IPs from the standard\n" \
     "\tinput; use 'stdout' or '-' as OUTPUT_FILE to write the IPset to\n"    \
     "\tthe standard output when the standard output is not a terminal.\n"    \
     "\tINPUT_FILE and OUTPUT_FILE default to 'stdin' and 'stdout'.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
    skIPSetOptionsUsage(fh);
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

    if (ipset) {
        skIPSetDestroy(&ipset);
    }
    skStreamDestroy(&in_stream);
    skStreamDestroy(&out_stream);

    skIPSetOptionsTeardown();
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
    const char *in_fname;
    const char *out_fname;
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
    memset(&set_options, 0, sizeof(skipset_options_t));
    set_options.argc = argc;
    set_options.argv = argv;

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skIPSetOptionsRegister(&set_options))
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
        skAppUsage(); /* never returns */
    }

    /* default is to read from stdin and write to stdout */
    in_fname = "-";
    out_fname = "-";

    /* process files named on the command line */
    switch (argc - arg_index) {
      case 2:
        in_fname = argv[arg_index++];
        out_fname = argv[arg_index++];
        break;

      case 1:
        in_fname = argv[arg_index++];
        break;

      case 0:
        /* Do not allow reading from a tty when no input */
        if (FILEIsATty(stdin)) {
            skAppPrintErr("Must specify '-' as the input to read"
                          " from a terminal");
            exit(EXIT_FAILURE);
        }
        break;

      default:
        skAppPrintErr("Too many arguments;"
                      " a maximum of two files may be specified");
        skAppUsage();
    }

    /* we should have processed all arguments */
    assert(arg_index == argc);

    /* create the IPset */
    if (skIPSetCreate(&ipset, 0)) {
        EXIT_NO_MEMORY;
    }
    skIPSetOptionsBind(ipset, &set_options);

    /* create input */
    if ((rv = skStreamCreate(&in_stream, SK_IO_READ, SK_CONTENT_TEXT))
        || (rv = skStreamBind(in_stream, in_fname))
        || (rv = skStreamSetCommentStart(in_stream, "#")))
    {
        skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }

    /* create output */
    if ((rv = skStreamCreate(&out_stream, SK_IO_WRITE, SK_CONTENT_SILK))
        || (rv = skStreamBind(out_stream, out_fname)))
    {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }

    /* open the streams */
    rv = skStreamOpen(in_stream);
    if (rv) {
        skStreamPrintLastErr(in_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
    rv = skStreamOpen(out_stream);
    if (rv) {
        skStreamPrintLastErr(out_stream, rv, &skAppPrintErr);
        exit(EXIT_FAILURE);
    }
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
      case OPT_IP_RANGES:
        ip_ranges = 1;
        if (opt_arg) {
            const char *char_name;
            switch (opt_arg[0]) {
              case '#':
                char_name = "comment start('#')";
                break;
              case '\n':
                char_name = "newline";
                break;
              case '\r':
                char_name = "carriage return";
                break;
              case '\0':
                char_name = "end-of-string";
                break;
              default:
                char_name = NULL;
                break;
            }
            if (char_name) {
                skAppPrintErr(
                    "Invalid %s: Separator may not be the %s character",
                    appOptions[opt_index].name, char_name);
                return 1;
            }
            delimiter = opt_arg[0];
        }
        break;
    }

    return 0;
}


/*
 *  buildIPSetRanges(stream);
 *
 *    Read IP addresses from the stream named by 'stream' and use them
 *    to build the global ipset.  Allow the input to support ranges of
 *    IPs.  Return 0 on success or -1 on failure.
 */
static int
buildIPSetRanges(
    skstream_t         *stream)
{
#if SK_ENABLE_IPV6
    int saw_integer = 0;
#endif
    int lc = 0;
    char line_buf[512];
    char *sep;
    skipaddr_t ip;
    skipaddr_t ip_min;
    skipaddr_t ip_max;
    uint32_t prefix;
    const int delim_is_space = isspace((int)delimiter);
    int rv;

    /* read until end of file */
    while ((rv = skStreamGetLine(stream, line_buf, sizeof(line_buf), &lc))
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
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            goto END;
        }

        /* support whitespace separators */
        if (!delim_is_space) {
            sep = strchr(line_buf, delimiter);
        } else {
            /* ignore leading whitespace */
            sep = line_buf;
            while (isspace((int)*sep)) {
                ++sep;
            }
            sep = strchr(sep, delimiter);
            if (sep) {
                /* allow a lone IP to have trailing whitespace */
                char *cp = sep;
                while (isspace((int)*cp)) {
                    ++cp;
                }
                if (*cp == '\0') {
                    sep = NULL;
                }
            }
        }
        if (sep == NULL) {
            /* parse as IP with possible CIDR designation */
            rv = skStringParseCIDR(&ip, &prefix, line_buf);
            if (rv != 0) {
                skAppPrintErr("Invalid IP on line %d: %s",
                              lc, skStringParseStrerror(rv));
                goto END;
            }

#if SK_ENABLE_IPV6
            /* do not allow integers mixed with IPv6 addresses */
            if (saw_integer) {
                if (skipaddrIsV6(&ip)) {
                    skAppPrintErr("Error on line %d: %s",
                                  lc, SETBUILD_ERR_MIX_INT_V6);
                    rv = -1;
                    goto END;
                }
            } else if (SETBUILD_BUF_IS_INT(line_buf)) {
                saw_integer = 1;
                if (skIPSetIsV6(ipset)) {
                    skAppPrintErr("Error on line %d: %s",
                                  lc, SETBUILD_ERR_MIX_INT_V6);
                    rv = -1;
                    goto END;
                }
            }
#endif  /* SK_ENABLE_IPV6 */

            rv = skIPSetInsertAddress(ipset, &ip, prefix);
            if (rv) {
                skAppPrintErr("Error adding IP on line %d to IPset: %s",
                              lc, skIPSetStrerror(rv));
                goto END;
            }
            continue;
        }

        /* parse two IP addresses */
        *sep = '\0';
        ++sep;
        rv = skStringParseIP(&ip_min, line_buf);
        if (rv != 0) {
            skAppPrintErr("Invalid minimum IP on line %d: %s",
                          lc, skStringParseStrerror(rv));
            goto END;
        }
        rv = skStringParseIP(&ip_max, sep);
        if (rv != 0) {
            skAppPrintErr("Invalid maximum IP on line %d: %s",
                          lc, skStringParseStrerror(rv));
            goto END;
        }

        if (skipaddrCompare(&ip_min, &ip_max) > 0) {
            skAppPrintErr("Invalid IP range on line %d: min > max",
                          lc);
            rv = -1;
            goto END;
        }

#if SK_ENABLE_IPV6
        /* do not allow integers mixed with IPv6 addresses */
        if (saw_integer) {
            if (skipaddrIsV6(&ip_min) || skipaddrIsV6(&ip_max)) {
                skAppPrintErr("Error on line %d: %s",
                              lc, SETBUILD_ERR_MIX_INT_V6);
                rv = -1;
                goto END;
            }
        } else if (SETBUILD_BUF_IS_INT(line_buf) || SETBUILD_BUF_IS_INT(sep)) {
            saw_integer = 1;
            if (skIPSetIsV6(ipset)) {
                skAppPrintErr("Error on line %d: %s",
                              lc, SETBUILD_ERR_MIX_INT_V6);
                rv = -1;
                goto END;
            }
        }
#endif  /* SK_ENABLE_IPV6 */

        rv = skIPSetInsertRange(ipset, &ip_min, &ip_max);
        if (rv) {
            skAppPrintErr("Error adding IP range on line %d to IPset: %s",
                          lc, skIPSetStrerror(rv));
            goto END;
        }
    }

    /* success */
    rv = 0;

  END:
    if (rv != 0) {
        return -1;
    }
    return 0;
}


/*
 *  buildIPSetWildcards(stream);
 *
 *    Read IP addresses from the stream named by 'stream' and use them
 *    to build the global ipset.  Allow the input to contain
 *    IPWildcards.  Return 0 on success or -1 on failure.
 */
static int
buildIPSetWildcards(
    skstream_t         *stream)
{
#if SK_ENABLE_IPV6
    int saw_integer = 0;
#endif
    int lc = 0;
    char line_buf[512];
    skIPWildcard_t ipwild;
    skipaddr_t ip;
    uint32_t prefix;
    char *cp;
    int rv;

    /* read until end of file */
    while ((rv = skStreamGetLine(stream, line_buf, sizeof(line_buf), &lc))
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
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            goto END;
        }

        /* first, attempt to parse as a CIDR block */
        rv = skStringParseCIDR(&ip, &prefix, line_buf);
        if (rv == 0) {
#if SK_ENABLE_IPV6
            /* do not allow integers mixed with IPv6 addresses */
            if (saw_integer) {
                if (skipaddrIsV6(&ip)) {
                    skAppPrintErr("Error on line %d: %s",
                                  lc, SETBUILD_ERR_MIX_INT_V6);
                    rv = -1;
                    goto END;
                }
            } else if (SETBUILD_BUF_IS_INT(line_buf)) {
                saw_integer = 1;
                if (skIPSetIsV6(ipset)) {
                    skAppPrintErr("Error on line %d: %s",
                                  lc, SETBUILD_ERR_MIX_INT_V6);
                    rv = -1;
                    goto END;
                }
            }
#endif  /* SK_ENABLE_IPV6 */

            rv = skIPSetInsertAddress(ipset, &ip, prefix);
            if (rv) {
                skAppPrintErr("Error adding IP on line %d to IPset: %s",
                              lc, skIPSetStrerror(rv));
                goto END;
            }
            continue;
        }

        /* else parse the line as an IPWildcard */
        rv = skStringParseIPWildcard(&ipwild, line_buf);
        if (rv != 0) {
            /* failed to parse an IPWildcard.  See if the user has
             * entered two IP addresses, and if so, suggest they use
             * the --ip-ranges switch. */
            int rv2;
            rv2 = skStringParseIP(&ip, line_buf);
            if (rv2 > 0) {
                /* parsed an IP and there is extra text after the IP
                 * address; check to see if it is another IP addr */
#if SK_ENABLE_IPV6
                if (skipaddrIsV6(&ip)
                    && ((cp = strchr(line_buf + rv2, ':')) != NULL))
                {
                    while (isxdigit((int) *(cp - 1))) {
                        --cp;
                    }
                    if (skStringParseIP(&ip, cp) == 0) {
                        skAppPrintErr(("Invalid IP on line %d: "
                                       SUGGEST_IP_RANGES),
                                      lc);
                        goto END;
                    }
                }
#endif
                if (!skipaddrIsV6(&ip)
                    && ((cp = strchr(line_buf + rv2, '.')) != NULL))
                {
                    while (isxdigit((int) *(cp - 1))) {
                        --cp;
                    }
                    if (skStringParseIP(&ip, cp) == 0) {
                        skAppPrintErr(("Invalid IP on line %d: "
                                       SUGGEST_IP_RANGES),
                                      lc);
                        goto END;
                    }
                }
            }
            /* report initial error */
            skAppPrintErr("Invalid IP Wildcard on line %d: %s",
                          lc, skStringParseStrerror(rv));
            goto END;
        }

#if SK_ENABLE_IPV6
        /* do not allow integers mixed with IPv6 addresses */
        if (saw_integer && skIPWildcardIsV6(&ipwild)) {
            skAppPrintErr("Error on line %d: %s",
                          lc, SETBUILD_ERR_MIX_INT_V6);
            rv = -1;
            goto END;
        }
#endif  /* SK_ENABLE_IPV6 */

        rv = skIPSetInsertIPWildcard(ipset, &ipwild);
        if (rv) {
            skAppPrintErr("Error adding IP Wildcard on line %d to IPset: %s",
                          lc, skIPSetStrerror(rv));
            goto END;
        }
    }

    /* success */
    rv = 0;

  END:
    if (rv != 0) {
        return -1;
    }
    return 0;
}


int main(int argc, char **argv)
{
    int rv;

    appSetup(argc, argv);

    /* read input file */
    if (ip_ranges) {
        if (buildIPSetRanges(in_stream)) {
            return 1;
        }
    } else {
        if (buildIPSetWildcards(in_stream)) {
            return 1;
        }
    }

    skIPSetClean(ipset);

    /* write output to stream */
    rv = skIPSetWrite(ipset, out_stream);
    if (rv) {
        if (SKIPSET_ERR_FILEIO == rv) {
            skStreamPrintLastErr(out_stream,
                                 skStreamGetLastReturnValue(out_stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Unable to write IPset to '%s': %s",
                          skStreamGetPathname(out_stream),skIPSetStrerror(rv));
        }
        return 1;
    }

    skStreamDestroy(&in_stream);
    skStreamDestroy(&out_stream);

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
