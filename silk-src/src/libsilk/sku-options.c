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
**  sku-options.c
**
**  Suresh L Konda
**
**  12/4/2001
**
**  Routines to support long option parsing with multiple sets of options.
**
**  Four functions are exported:
**  skOptionsSetup();
**  skOptionsTeardown();
**  skOptionsRegister();
**  skOptionsParse();
**
**  Each client calls skOptionsRegister with:
**      1. a pointer to struct option []
**      2. a handler to process the option. The handler will be called with two
**         arguments:
**              1. the clientData
**              2. the original val value passed to the registry via
**                 options associated with this option
**              3. the optarg returned by getopt();
**      3. an opaque pointer to arbitrary data called clientData which
**      Error Return : 1
**
**  Once all clients have registered, then call skOptionsParse with argc, argv
**  which parses the options and calls the handler as required.
**
**  It returns -1 on error or optind if OK.  Thus, argv[optind] is the first
**  non-option argument given to the application.
**
**  Currently, we do NOT do flag versus val handling: flag is always
**  assumed to be NULL and val is the appropriate unique entity that
**  allows the handler to deal with the option to be parsed.  It is
**  suggested that the caller use a distinct index value in the val part.
**
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: sku-options.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/sksite.h>
#include <silk/silk_files.h>
#include <silk/skstringmap.h>


/* TYPEDEFS AND DEFINES */

/* Where to write --version information */
#define VERS_FH stdout

/* Start options at this offset to avoid having an option with index
 * of '?' (63) which is the value used to indicate an error. */
#define OPTION_OFFSET 64

/* Initial size of options arrays, and number of options to add to the
 * arrays */
#define OPTION_ARRAY_NUM_ENTRIES  16

/* Message to print when out of memory */
#define SK_OPTION_NO_MEMORY(nomem_obj)                          \
    skAppPrintOutOfMemory(#nomem_obj)

/* Name of environment variable containing the default value for the
 * --ip-format switch */
#define SK_IP_FORMAT_ENVAR              "SILK_IP_FORMAT"

/* Name of environment variable containing the default value for the
 * --timestamp-format switch */
#define SK_TIMESTAMP_FORMAT_ENVAR       "SILK_TIMESTAMP_FORMAT"


/*
 *  struct option has the following definition:
 *
 *  struct option {
 *      char *name;
 *      int has_arg;
 *      int *flag;
 *      int val;
 *  };
 *
 */

typedef struct sk_options_map_st {
    /* the callback function provided by the caller */
    optHandler    om_handler;
    /* the callback data provided by the caller */
    clientData    om_data;
    /* the index provided by the caller*/
    int           om_index;
} sk_options_map_t;

typedef struct sk_options_st {
    /* function to use to print usage */
    usage_fn_t          o_usage_fn;
    /* for printing version info */
    usage_fn_t          o_version_fn;
    /* array of all options for this app */
    struct option      *o_options;
    /* array mapping options to a particular options handler */
    sk_options_map_t   *o_map;
    /* global option count */
    size_t              o_count;
    /* size of the arrays */
    size_t              o_capacity;
} sk_options_t;



/* LOCAL VARIABLES */

static sk_options_t app_options_static;

static sk_options_t *app_options = &app_options_static;

typedef enum {
    OPT_VAL_HELP, OPT_VAL_VERSION
} defaultOptionsEnum;

/* options that everyone gets */
static struct option defaultOptions[] = {
    {"help",        NO_ARG,       0, OPT_VAL_HELP},
    {"version",     NO_ARG,       0, OPT_VAL_VERSION},
    {0,0,0,0}       /* sentinel */
};

static const char *defaultHelp[] = {
    "Print this usage output and exit. Def. No",
    "Print this program's version and exit. Def. No",
    (char*)NULL /* sentinel */
};

/* All shortened forms of help should invoke help.  This lets us
 * define options like --help-foo and --help-bar. */
static const struct option optionAliases[] = {
    {"hel" ,        NO_ARG,       0, OPT_VAL_HELP},
    {"he",          NO_ARG,       0, OPT_VAL_HELP},
    {"h",           NO_ARG,       0, OPT_VAL_HELP},
    {0,0,0,0}       /* sentinel */
};


/* FUNCTION DEFINITONS */

void
skOptionsDefaultUsage(
    FILE               *fh)
{
    int i;
    for (i = 0; defaultOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", defaultOptions[i].name,
                SK_OPTION_HAS_ARG(defaultOptions[i]), defaultHelp[i]);
    }
}


/*
 *  printVersion();
 *
 *    Print version information and information about how SiLK was
 *    configured.
 */
static void
printVersion(
    void)
{
#define COPYRIGHT_LICENSE                                       \
    ("Copyright (C) 2001-2023 by Carnegie Mellon University\n"  \
     "GNU General Public License (GPL) Rights"                  \
     " pursuant to Version 2, June 1991.\n"                     \
     "Some included library code covered by LGPL 2.1;"          \
     " see source for details.\n"                               \
     "Government Purpose License Rights (GPLR)"                 \
     " pursuant to DFARS 252.227-7013.")

    uint8_t default_compmethod;
    uint8_t i;
    char comp_name[SK_MAX_STRLEN_FILE_FORMAT+1];
    const char *packing_logic;
    const char *python_dir = SILK_PYTHON_SITE_PKG;

    fprintf(VERS_FH, "%s: part of %s %s; configuration settings:\n",
            skAppName(), SK_PACKAGE_NAME, SK_PACKAGE_VERSION);

    fprintf(VERS_FH, "    * %-32s  %s\n",
            "Root of packed data tree:", sksiteGetDefaultRootDir());

#ifndef SK_PACKING_LOGIC_PATH
    packing_logic = "Run-time plug-in";
#else
    packing_logic = SK_PACKING_LOGIC_PATH;
    if (strrchr(packing_logic, '/')) {
        packing_logic = 1 + strrchr(packing_logic, '/');
    }
#endif
    fprintf(VERS_FH, "    * %-32s  %s\n",
            "Packing logic:", packing_logic);

    fprintf(VERS_FH, "    * %-32s  %s\n",
            "Timezone support:",
#if  SK_ENABLE_LOCALTIME
            "local"
#else
            "UTC"
#endif
            );

    default_compmethod = skCompMethodGetDefault();
    skCompMethodGetName(comp_name, sizeof(comp_name), default_compmethod);
    fprintf(VERS_FH, "    * %-32s  %s [default]",
            "Available compression methods:", comp_name);

    for (i = 0; skCompMethodCheck(i); ++i) {
        if (i == default_compmethod) {
            continue;
        }
        if (SK_COMPMETHOD_IS_AVAIL != skCompMethodCheck(i)) {
            /* not available */
            continue;
        }
        skCompMethodGetName(comp_name, sizeof(comp_name), i);
        fprintf(VERS_FH, ", %s", comp_name);
    }
    fprintf(VERS_FH, "\n");

    fprintf(VERS_FH, "    * %-32s  %s\n",
            "IPv6 network connections:",
#if SK_ENABLE_INET6_NETWORKING
            "yes"
#else
            "no"
#endif
            );

    fprintf(VERS_FH, "    * %-32s  %s\n",
            "IPv6 flow record support:",
#if SK_ENABLE_IPV6
            "yes"
#else
            "no"
#endif
            );

    fprintf(VERS_FH, "    * %-32s  %s\n",
            "IPset record compatibility:",
#if !defined(SK_IPSET_DEFAULT_VERSION)
            "1.0.0"
#elif SK_IPSET_DEFAULT_VERSION == 5
            "3.14.0"
#elif SK_IPSET_DEFAULT_VERSION == 4
            "3.7.0"
#else
            "1.0.0"
#endif
            );

    fprintf(VERS_FH, "    * %-32s  %s\n",
            "IPFIX/NetFlow9/sFlow collection:",
#if   SK_ENABLE_IPFIX
            "ipfix,netflow9,sflow"
#else
            "no"
#endif
            );


    fprintf(VERS_FH, "    * %-32s  %s\n",
            "Transport encryption:",
#if SK_ENABLE_GNUTLS
            "GnuTLS"
#else
            "no"
#endif
            );

    fprintf(VERS_FH, "    * %-32s  %s\n",
            "PySiLK support:", ((python_dir[0]) ? python_dir : "no"));

    fprintf(VERS_FH, "    * %-32s  %s\n",
            "Enable assert():",
#ifndef NDEBUG
            "yes"
#else
            "no"
#endif
            );

    fprintf(VERS_FH,
            ("%s\n"
             "Send bug reports, feature requests, and comments to %s.\n"),
            COPYRIGHT_LICENSE, SK_PACKAGE_BUGREPORT);
}


/*
 *  status = defaultOptionsHandler(cData, opt_index, opt_arg);
 *
 *    Called by skOptionsParse() to handle the default/global options
 *    defined in the defaultOptions[] array.  This handler will exit
 *    the application.
 */
static int
defaultOptionsHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char        UNUSED(*opt_arg))
{
    switch ((defaultOptionsEnum)opt_index) {
      case OPT_VAL_HELP:
        app_options->o_usage_fn();
        break;

      case OPT_VAL_VERSION:
        app_options->o_version_fn();
        break;
    }

    skAppUnregister();
    exit(EXIT_SUCCESS);
    return 0; /* NOTREACHED */
}


static void
defaultHelpOutput(
    void)
{
    skAppStandardUsage(stdout, "", NULL, NULL);
}


void
skOptionsSetup(
    void)
{
    /* check whether already called */
    if (app_options->o_usage_fn) {
        return;
    }

    /* tell getopt_long() that it should print errors */
    opterr = 1;

    /* set a default usage function */
    skOptionsSetUsageCallback(&defaultHelpOutput);

    /* set the version function */
    skOptionsSetVersionCallback(&printVersion);

    /* allocate initial space */
    app_options->o_options = (struct option*)calloc(OPTION_ARRAY_NUM_ENTRIES,
                                                    sizeof(struct option));
    app_options->o_map = (sk_options_map_t*)calloc(OPTION_ARRAY_NUM_ENTRIES,
                                                   sizeof(sk_options_map_t));
    if (!app_options->o_options || !app_options->o_map) {
        SK_OPTION_NO_MEMORY(app_options->o_options);
        exit(EXIT_FAILURE);
    }

    app_options->o_count = 0;
    app_options->o_capacity = OPTION_ARRAY_NUM_ENTRIES;

    /* add default switches */
    if (skOptionsRegister(defaultOptions, defaultOptionsHandler, NULL)) {
        skAppPrintErr("Unable to set default options");
        exit(EXIT_FAILURE);
    }
    if (skOptionsRegister(optionAliases, defaultOptionsHandler, NULL)) {
        skAppPrintErr("Unable to set default options");
        exit(EXIT_FAILURE);
    }
}


void
skOptionsSetUsageCallback(
    usage_fn_t          help_fn)
{
    app_options->o_usage_fn = help_fn;
}


void
skOptionsSetVersionCallback(
    usage_fn_t          version_fn)
{
    app_options->o_version_fn = version_fn;
}


void
skOptionsTeardown(
    void)
{
    if ( app_options->o_options == 0) {
        return;
    }
    free(app_options->o_options);
    free(app_options->o_map);
    app_options->o_options = /* (struct option (*)[1]) */ NULL;
    app_options->o_map = /* (sk_options_map (*)[1]) */ NULL;
    return;
}


int
skOptionsRegister(
    const struct option    *options,
    optHandler              handler,
    clientData              cData)
{
    return skOptionsRegisterCount(options, 0, handler, cData);
}


int
skOptionsRegisterCount(
    const struct option    *new_options,
    size_t                  num_options,
    optHandler              handler,
    clientData              cData)
{
    struct option *cur_options;
    size_t i;
    size_t j;
    size_t new_capacity;
    void *old_mem;

    if (app_options->o_usage_fn == NULL) {
        skAppPrintErr("Must call skOptionsSetup() before registering options");
        return -1;
    }

    /* count the options that were passed in */
    if (num_options == 0) {
        for (j = 0; new_options[j].name; ++j)
            ;
        num_options = j;
    } else {
        for (j = 0; j < num_options && new_options[j].name; ++j)
            ;
        num_options = j;
    }

    if (0 == num_options) {
        /* empty options list */
        return 0;
    }

    /*  New total number of options will be the current value plus the
     *  number of options passed in.  */
    new_capacity = app_options->o_count + num_options;

    /* Determine whether we need to grow the arrays.  The capacity
     * must remain greater than the count, because we need to have one
     * blank space for the sentinel. */
    if (new_capacity >= app_options->o_capacity) {

        /* allow space for several additional entries */
        new_capacity += OPTION_ARRAY_NUM_ENTRIES;

        /*
         *  Get or grow the space for the arrays.
         */
        old_mem = app_options->o_options;
        app_options->o_options
            = (struct option*)realloc(app_options->o_options,
                                      (new_capacity * sizeof(struct option)));
        if (app_options->o_options == NULL) {
            app_options->o_options = (struct option*)old_mem;
            SK_OPTION_NO_MEMORY(app_options->o_options);
            return -1;
        }

        old_mem = app_options->o_map;
        app_options->o_map
            = (sk_options_map_t*)realloc(app_options->o_map,
                                         (new_capacity
                                          * sizeof(sk_options_map_t)));
        if (app_options->o_map == NULL) {
            app_options->o_map = (sk_options_map_t*)old_mem;
            SK_OPTION_NO_MEMORY(app_options->o_map);
            return -1;
        }

        app_options->o_capacity = new_capacity;
    }

    for (j = 0; j < num_options; ++j, ++new_options) {
        /* check for name clashes */
        for (i = 0, cur_options = app_options->o_options;
             i < app_options->o_count;
             ++i, ++cur_options)
        {
            if (strcmp(cur_options->name, new_options->name)==0) {
                skAppPrintErr("Cannot register option '%s': name already used",
                              new_options->name);
                return -1;
            }
        }

        assert(cur_options == &app_options->o_options[app_options->o_count]);

        /* a clean new entry. record it. */
        cur_options->name    = new_options->name;
        cur_options->has_arg = new_options->has_arg;
        cur_options->flag    = new_options->flag;

        /* the 'val' used internally is the OPTION_OFFSET plus the
         * index into the 'o_map' array; the o_map array will be used to
         * get the 'val' the called handed us. */
        cur_options->val     = OPTION_OFFSET + app_options->o_count;

        /* original val to be returned with handler */
        app_options->o_map[app_options->o_count].om_index   = new_options->val;
        app_options->o_map[app_options->o_count].om_handler = handler;
        app_options->o_map[app_options->o_count].om_data    = cData;

        ++app_options->o_count;
    }

    /* set the sentinel for o_options */
    memset(&app_options->o_options[app_options->o_count], 0,
           sizeof(struct option));

    return 0;
}


/*
 *  skOptionsParse:
 *      Adjust the global options array to allow for the help
 *      option. If help is selected by the user, call the stashed
 *      usageFunction.  Parse input options given a set of
 *      pre-registered options and their handlers.  For each
 *      legitimate option, call the handler.
 *  SideEffects:
 *      The individual handlers update whatever datastruture they wish
 *      to via the clientData argument to the handler.
 *  Return:
 *      optind which points at the first non-option argument passed if
 *      all is OK.  If not OK, the return -1 for error.
 */
int
skOptionsParse(
    int                 argc,
    char              **argv)
{
    int done = 0;
    int c;
    int idx;

    while (! done) {
        int option_index;
#ifdef SK_HAVE_GETOPT_LONG_ONLY
        c = getopt_long_only(argc, argv, "",
                             (const struct option *)app_options->o_options,
                             &option_index);
#else
        c = _getopt_internal(argc, argv, "",
                             (const struct option *)app_options->o_options,
                             &option_index, 1);
#endif
        switch (c) {

          case '?':
            /*skAppPrintErr("Invalid or ambiguous option"); */
            return -1;

          case -1:
            done = 1;
            break;

          default:
            /* a legit value: call the handler */
            idx = c - OPTION_OFFSET;
            if (app_options->o_map[idx].om_handler(
                    app_options->o_map[idx].om_data,
                    app_options->o_map[idx].om_index,
                    optarg))
            {
                /* handler indicated an error */
                return -1;
            }
            break;
        }
    }

    return optind;
}


/* find shortest unique prefix for the option 'option_name' */
int
skOptionsGetShortestPrefix(
    const char         *option_name)
{
    struct option *opt = NULL;
    const char *cp;
    const char *sp;
    int longest = 0;
    size_t i;
    int j;

    /* check that the input inupt */
    if (option_name == NULL || option_name[0] == '\0') {
        return -1;
    }

    /* find 'option_name' in the list of all options */
    for (i = 0, opt = app_options->o_options;
         i < app_options->o_count;
         ++i, ++opt)
    {
        if (0 == strcmp(option_name, opt->name)) {
            break;
        }
    }

    if (i == app_options->o_count) {
        /* did not find 'option_name' in the list of options, or no
         * options have been registered. */
        return -1;
    }

    for (i = 0; i < app_options->o_count; ++i) {
        if (opt->val == app_options->o_options[i].val) {
            /* skip options that map to same value as 'option_name' */
            continue;
        }

        /* find the character where the strings differ */
        for (j = 1, cp = option_name, sp = app_options->o_options[i].name;
             *cp && *sp && *cp == *sp;
             ++j, ++cp, ++sp)
            ;  /* empty */

        if (*cp == '\0') {
            /* reached end of option_name.  if *sp is NUL, we have
             * matched ourself, which we should have avoided
             * above. */
            assert(*sp != '\0');

            /* since option_name is a substring of
             * o_options[].name, the full option name is always
             * required. */
            return j;
        }

        if (j > longest) {
            longest = j;
        }
    }

    return longest;
}


/* check whether dirname exists */
int
skOptionsCheckDirectory(
    const char         *dirname,
    const char         *option_name)
{
    if (!dirname || !dirname[0]) {
        skAppPrintErr("Invalid %s: The directory name is empty",
                      option_name);
        return -1;
    }
    if (strlen(dirname)+1 >= PATH_MAX) {
        skAppPrintErr("Invalid %s: The directory name is too long",
                      option_name);
        return -1;
    }
    if (!skDirExists(dirname)) {
        skAppPrintErr("Invalid %s: Nonexistent path '%s'",
                      option_name, dirname);
        return -1;
    }
    if (dirname[0] != '/') {
        skAppPrintErr(("Invalid %s: Must use complete path"
                       " ('%s' does not begin with slash)"),
                      option_name, dirname);
        return -1;
    }
    return 0;
}


#if 0
/* verify argument contains printable characters other than space */
int
skOptionsCheckContainsPrintable(
    const char         *opt_argument,
    const char         *option_name)
{
    const char *cp;

    if (opt_argument) {
        cp = opt_argument;
        while (*cp && (!isprint((int)*cp) || *cp == ' ')) {
            ++cp;
        }
        if (*cp == '\0') {
            skAppPrintErr(("Invalid %s: Argument does not contain printable"
                           " characters"),
                          option_name);
            return -1;
        }
    }
    return 0;
}
#endif  /* 0 */


/* *******************************************************************
 *    Support for setting the temporary directory
 */

static struct option tempdir_option[] = {
    {"temp-directory",      REQUIRED_ARG, 0, 0},
    {0,0,0,0}               /* sentinel */
};

static int
tempdir_option_handler(
    clientData          cData,
    int          UNUSED(opt_index),
    char               *opt_arg)
{
    const char **var_location = (const char**)cData;

    assert(opt_index == 0);
    assert(opt_arg);
    *var_location = opt_arg;
    return 0;
}

int
skOptionsTempDirRegister(
    const char        **var_location)
{
    if (var_location == NULL) {
        return -1;
    }
    return skOptionsRegister(tempdir_option, tempdir_option_handler,
                             (clientData)var_location);
}

void
skOptionsTempDirUsage(
    FILE               *fh)
{
    fprintf(fh,
            ("--%s %s. Store temporary files in this directory.\n"
             "\tDef. $" SK_TEMPDIR_ENVAR1 " or $" SK_TEMPDIR_ENVAR2
#ifdef SK_TEMPDIR_DEFAULT
             " or " SK_TEMPDIR_DEFAULT
#endif
             "\n"),
            tempdir_option[0].name, SK_OPTION_HAS_ARG(tempdir_option[0]));
}



/* *******************************************************************
 *    Support for formatting IP addresses
 */

/* flags passed to skOptionsIPFormatRegister() that determines what
 * switches to enable */
static uint32_t ip_format_flags = 0;

/* some values in ipformat_names[] may not be combined. this array
 * holds values used to check for invalid combinations.  Each entry is
 * two 16 bit values where the lower bits indicate the parameter and
 * the upper 16 bits are the mask of values it conflicts with.  */
static const uint32_t ip_format_param_group[] = {
    /* bits | mask */
    0x0001 | (0x000F << 16),  /* canonical   */
    0x0002 | (0x000F << 16),  /* decimal     */
    0x0004 | (0x000F << 16),  /* hexadecimal */
    0x0008 | (0x000F << 16),  /* no-mixed    */
    0x0000 | (0x0000 << 16),  /* zero-padded */
    0x0010 | (0x0030 << 16),  /* map-v4      */
    0x0020 | (0x0030 << 16),  /* unmap-v6    */
    0x0018 | (0x003F << 16)   /* force-ipv6  */
};


enum ipformat_option_en {
    OPT_VAL_IP_FORMAT, OPT_VAL_INTEGER_IPS, OPT_VAL_ZERO_PAD_IPS
};

static const struct option ipformat_option[] = {
    {"ip-format",           REQUIRED_ARG, 0, OPT_VAL_IP_FORMAT},
    {"integer-ips",         NO_ARG,       0, OPT_VAL_INTEGER_IPS},
    {"zero-pad-ips",        NO_ARG,       0, OPT_VAL_ZERO_PAD_IPS},
    {0,0,0,0}               /* sentinel */
};

/* printed IP address formats: the first of these will be the default */
static const sk_stringmap_entry_t ipformat_names[] = {
    {"canonical",       SKIPADDR_CANONICAL,
     "in canonical format (192.0.2.1, 2001:db8::1)",
     &ip_format_param_group[0]},
    {"decimal",         SKIPADDR_DECIMAL,
     "as integer number in decimal format",
     &ip_format_param_group[1]},
    {"hexadecimal",     SKIPADDR_HEXADECIMAL,
     "as integer number in hexadecimal format",
     &ip_format_param_group[2]},
    {"no-mixed",        SKIPADDR_NO_MIXED,
     "in canonical format but no mixed IPv4/IPv6 for IPv6 IPs",
     &ip_format_param_group[3]},
    {"zero-padded",     SKIPADDR_ZEROPAD,
     "pad result to its maximum width with zeros",
     &ip_format_param_group[4]},
    {"map-v4",          SKIPADDR_MAP_V4,
     "map IPv4 into ::ffff:0:0/96 netblock prior to formatting",
     &ip_format_param_group[5]},
    {"unmap-v6",        SKIPADDR_UNMAP_V6,
     "convert IPv6 in ::ffff:0:0/96 to IPv4 prior to formatting",
     &ip_format_param_group[6]},
    {"force-ipv6",      SKIPADDR_FORCE_IPV6,
     "alias equivalent to \"map-v4,no-mixed\"",
     &ip_format_param_group[7]},
    SK_STRINGMAP_SENTINEL
};


/*
 *    If the SK_OPTION_IP_FORMAT_UNMAP_V6 flag was passed to
 *    skOptionsIPFormatRegister(), enable unmap-v6 (SKIPADDR_UNMAP_V6)
 *    in the in the ip formatting flags unless the user selected
 *    decimal or hexadecimal as the format, or the user specified
 *    map-v4 (SKIPADDR_MAP_V4).
 */
static void
ipformat_check_unmapv6(
    uint32_t           *out_flags)
{
    if (ip_format_flags & SK_OPTION_IP_FORMAT_UNMAP_V6) {
        switch (*out_flags & 0x7f) {
          case SKIPADDR_DECIMAL:
          case SKIPADDR_HEXADECIMAL:
            break;
          default:
            if (0 == (SKIPADDR_MAP_V4 & *out_flags)) {
                *out_flags |= SKIPADDR_UNMAP_V6;
            }
            break;
        }
    }
}


/*
 *  status = ipformat_option_parse(format_string, out_flags);
 *
 *    Parse the ip-format value contained in 'format_string' and set
 *    'out_flags' to the result of parsing the string.  Return 0 on
 *    success, or -1 if parsing of the value fails.
 */
static int
ipformat_option_parse(
    const char         *format,
    uint32_t           *out_flags,
    const char         *option_name)
{
    char *errmsg;
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *found_entry;
    const sk_stringmap_entry_t *entry;
    uint32_t groups_seen = 0;
    uint32_t bits;
    uint32_t mask;
    int rv = -1;

    assert(sizeof(ip_format_param_group)/sizeof(ip_format_param_group[0])
           == (sizeof(ipformat_names)/sizeof(ipformat_names[0]) - 1));

    /* create a stringmap of the available ip formats */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, ipformat_names) != SKSTRINGMAP_OK){
        skAppPrintOutOfMemory(NULL);
        goto END;
    }

    /* attempt to match */
    if (skStringMapParse(str_map, format, SKSTRINGMAP_DUPES_ERROR,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s", option_name, errmsg);
        goto END;
    }

    *out_flags = 0;

    while (skStringMapIterNext(iter, &found_entry, NULL) == SK_ITERATOR_OK) {
        bits = 0xFFFF & *(uint32_t *)found_entry->userdata;
        mask = (*(uint32_t *)found_entry->userdata) >> 16;
        /* check whether have seen another argument in this group */
        if (groups_seen & (mask & ~bits)) {
            /* yes, we have; generate error msg and return */
            char buf[256] = "";
            int first = 1;
            for (entry = ipformat_names; entry->name; ++entry) {
                uint32_t b = 0xFFFF & *(uint32_t *)entry->userdata;
                if (b & (groups_seen & mask)) {
                    if (first) {
                        first = 0;
                    } else {
                        strncat(buf, ",", sizeof(buf)-strlen(buf)-1);
                    }
                    strncat(buf, entry->name, sizeof(buf)-strlen(buf)-1);
                }
            }
            skAppPrintErr("Invalid %s: May not combine %s with %s",
                          option_name, found_entry->name, buf);
            goto END;
        }
        groups_seen |= bits;
        *out_flags |= found_entry->id;
    }

    ipformat_check_unmapv6(out_flags);

    rv = 0;

  END:
    skStringMapDestroy(str_map);
    skStringMapIterDestroy(iter);
    return rv;
}

static int
ipformat_option_handler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    uint32_t *var_location = (uint32_t*)cData;

    switch ((enum ipformat_option_en)opt_index) {
      case OPT_VAL_IP_FORMAT:
        if (ipformat_option_parse(
                opt_arg, var_location, ipformat_option[opt_index].name))
        {
            return 1;
        }
        break;
      case OPT_VAL_INTEGER_IPS:
        assert(ip_format_flags & SK_OPTION_IP_FORMAT_INTEGER_IPS);
        if (ipformat_option_parse(
                "decimal", var_location, ipformat_option[opt_index].name))
        {
            skAbort();
        }
        break;
      case OPT_VAL_ZERO_PAD_IPS:
        assert(ip_format_flags & SK_OPTION_IP_FORMAT_ZERO_PAD_IPS);
        if (ipformat_option_parse(
                "zero-padded", var_location, ipformat_option[opt_index].name))
        {
            skAbort();
        }
        break;
    }

    return 0;
}

int
skOptionsIPFormatRegister(
    uint32_t           *var_location,
    uint32_t            flags)
{
    struct option opts[2];
    const char *env;
    uint32_t tmp_val = 0;
    unsigned int i;
    int rv = 0;

    if (var_location == NULL) {
        return -1;
    }

    ip_format_flags = flags;
    ipformat_check_unmapv6(var_location);

    env = getenv(SK_IP_FORMAT_ENVAR);
    if (env && env[0]) {
        if (0 == ipformat_option_parse(env, &tmp_val, SK_IP_FORMAT_ENVAR)) {
            *var_location = tmp_val;
        }
    }

    memset(opts, 0, sizeof(opts));

    for (i = 0; ipformat_option[i].name; ++i) {
        if ((0 == i) || (ip_format_flags & (1 << (i - 1)))) {
            memcpy(opts, &ipformat_option[i], sizeof(struct option));
            rv = skOptionsRegister(opts, ipformat_option_handler,
                                   (clientData)var_location);
            if (rv) {
                return rv;
            }
        }
    }
    return rv;
}


/*
 *  skOptionsIPFormatUsage(fh);
 *
 *    Print the description of the argument to the --ip-format
 *    switch to the 'fh' file handle.
 */
void
skOptionsIPFormatUsage(
    FILE               *fh)
{
    const sk_stringmap_entry_t *e;
    char defaults[256] = "";

    if (0 == (ip_format_flags & SK_OPTION_IP_FORMAT_UNMAP_V6)) {
        strncpy(defaults, ipformat_names[0].name, sizeof(defaults));
    } else {
        for (e = ipformat_names; e->name; ++e) {
            if (e->id == SKIPADDR_UNMAP_V6) {
                snprintf(defaults, sizeof(defaults), "%s,%s",
                         ipformat_names[0].name, e->name);
                break;
            }
        }
    }
    assert(defaults[0]);

    fprintf(fh, ("--%s %s. Print each IP address in the specified format.\n"
                 "\tDef. $" SK_IP_FORMAT_ENVAR " or %s.  Choices:\n"),
            ipformat_option[OPT_VAL_IP_FORMAT].name,
            SK_OPTION_HAS_ARG(ipformat_option[OPT_VAL_IP_FORMAT]), defaults);
    for (e = ipformat_names; e->name; ++e) {
        if (e->id == SKIPADDR_ZEROPAD) {
            fprintf(fh, "\tThe following may be combined with the above:\n");
        }
        fprintf(fh, "\t%-11s - %s\n", e->name, e->description);
    }

    if (ip_format_flags & SK_OPTION_IP_FORMAT_INTEGER_IPS) {
        fprintf(fh, "--%s %s. DEPRECATED. Equivalent to --ip-format=decimal\n",
                ipformat_option[OPT_VAL_INTEGER_IPS].name,
                SK_OPTION_HAS_ARG(ipformat_option[OPT_VAL_INTEGER_IPS]));
    }
    if (ip_format_flags & SK_OPTION_IP_FORMAT_ZERO_PAD_IPS) {
        fprintf(fh,
                "--%s %s. DEPRECATED. Equivalent to --ip-format=zero-padded\n",
                ipformat_option[OPT_VAL_ZERO_PAD_IPS].name,
                SK_OPTION_HAS_ARG(ipformat_option[OPT_VAL_ZERO_PAD_IPS]));
    }
}


/* *******************************************************************
 *    Support for formatting Timestamps
 */

static uint32_t time_format_flags = 0;

static char time_format_epoch_name[256];

enum time_format_option_en {
    OPT_VAL_TIMESTAMP_FORMAT, OPT_VAL_EPOCH_TIME, OPT_VAL_LEGACY_TIMESTAMPS
};

static const struct option time_format_option[] = {
    {"timestamp-format",    REQUIRED_ARG, 0, OPT_VAL_TIMESTAMP_FORMAT},
    {"epoch-time",          NO_ARG,       0, OPT_VAL_EPOCH_TIME},
    {"legacy-timestamps",   OPTIONAL_ARG, 0, OPT_VAL_LEGACY_TIMESTAMPS},
    {0,0,0,0}               /* sentinel */
};

/* timestamp formats: the first of these will be the default */
static const sk_stringmap_entry_t time_format_names[] = {
    {"default", 0,                      "yyyy/mm/ddThh:mm:ss", NULL},
    {"iso",     SKTIMESTAMP_ISO,        "yyyy-mm-dd hh:mm:ss", NULL},
    {"m/d/y",   SKTIMESTAMP_MMDDYYYY,   "mm/dd/yyyy hh:mm:ss", NULL},
    {"epoch",   SKTIMESTAMP_EPOCH,
     "seconds since UNIX epoch; ignores timezone", NULL},
    SK_STRINGMAP_SENTINEL
};
static const sk_stringmap_entry_t time_format_zones[] = {
    {"utc",     SKTIMESTAMP_UTC,        "use UTC", NULL},
    {"local",   SKTIMESTAMP_LOCAL,
     "use TZ environment variable or local timezone", NULL},
    SK_STRINGMAP_SENTINEL
};
static const sk_stringmap_entry_t time_format_misc[] = {
    {"no-msec", SKTIMESTAMP_NOMSEC,     "truncate milliseconds", NULL},
    SK_STRINGMAP_SENTINEL
};

/*
 *  status = time_format_option_parse(format_string, out_flags, from_environ);
 *
 *    Parse the timestamp-format value contained in 'format_string'
 *    and set 'out_flags' to the result of parsing the string.  Return
 *    0 on success, or -1 if parsing of the value fails.
 *
 *    If 'from_environ' is true, assume 'format' was set from an
 *    environment variable.
 */
static int
time_format_option_parse(
    const char         *format,
    uint32_t           *out_flags,
    const char         *option_name)
{
    char buf[256];
    char *errmsg;
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *found_entry;
    const sk_stringmap_entry_t *entry;
    int name_seen = 0;
    int zone_seen = 0;
    int from_environ = 0;
    int rv = -1;

    if (option_name && 0 == strcmp(option_name, SK_TIMESTAMP_FORMAT_ENVAR)) {
        from_environ = 1;
    }

    /* create a stringmap of the available timestamp formats */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, time_format_names)
        != SKSTRINGMAP_OK)
    {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, time_format_zones)
        != SKSTRINGMAP_OK)
    {
        skAppPrintOutOfMemory(NULL);
        goto END;
    }
    if (from_environ
        || 0 == (time_format_flags & (SK_OPTION_TIMESTAMP_NEVER_MSEC
                                      | SK_OPTION_TIMESTAMP_ALWAYS_MSEC)))
    {
        if (skStringMapAddEntries(str_map, -1, time_format_misc)
            != SKSTRINGMAP_OK)
        {
            skAppPrintOutOfMemory(NULL);
            goto END;
        }
    }

    /* attempt to match */
    if (skStringMapParse(str_map, format, SKSTRINGMAP_DUPES_ERROR,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s", option_name, errmsg);
        goto END;
    }

    *out_flags = 0;
    if (time_format_flags & SK_OPTION_TIMESTAMP_NEVER_MSEC) {
        *out_flags |= SKTIMESTAMP_NOMSEC;
    }

    while (skStringMapIterNext(iter, &found_entry, NULL) == SK_ITERATOR_OK) {
        *out_flags |= found_entry->id;
        switch (found_entry->id) {
          case SKTIMESTAMP_NOMSEC:
            if (time_format_flags & SK_OPTION_TIMESTAMP_ALWAYS_MSEC) {
                /* this should only occur when 'from_environ' is true;
                 * disable the no-msec setting. */
                assert(from_environ);
                *out_flags = *out_flags & ~SKTIMESTAMP_NOMSEC;
            }
            break;

          case 0:
          case SKTIMESTAMP_EPOCH:
          case SKTIMESTAMP_ISO:
          case SKTIMESTAMP_MMDDYYYY:
            if (name_seen) {
                entry = time_format_names;
                strncpy(buf, entry->name, sizeof(buf));
                for (++entry; entry->name; ++entry) {
                    strncat(buf, ",", sizeof(buf)-strlen(buf)-1);
                    strncat(buf, entry->name, sizeof(buf)-strlen(buf)-1);
                }
                skAppPrintErr("Invalid %s: May only specify one of %s",
                              option_name, buf);
                goto END;
            }
            name_seen = 1;
            break;

          case SKTIMESTAMP_UTC:
          case SKTIMESTAMP_LOCAL:
            if (zone_seen) {
                entry = time_format_zones;
                strncpy(buf, entry->name, sizeof(buf));
                for (++entry; entry->name; ++entry) {
                    strncat(buf, ",", sizeof(buf)-strlen(buf)-1);
                    strncat(buf, entry->name, sizeof(buf)-strlen(buf)-1);
                }
                skAppPrintErr("Invalid %s: May only specify one of %s",
                              option_name, buf);
                goto END;
            }
            zone_seen = 1;
            break;

          default:
            skAbortBadCase(found_entry->id);
        }
    }

    rv = 0;

  END:
    if (str_map) {
        skStringMapDestroy(str_map);
    }
    if (iter) {
        skStringMapIterDestroy(iter);
    }
    return rv;
}

static int
time_format_option_handler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    uint32_t *var_location = (uint32_t*)cData;

    switch ((enum time_format_option_en)opt_index) {
      case OPT_VAL_TIMESTAMP_FORMAT:
        if (time_format_option_parse(
                opt_arg, var_location, time_format_option[opt_index].name))
        {
            return 1;
        }
        break;

      case OPT_VAL_EPOCH_TIME:
        if (time_format_option_parse(
                "epoch", var_location, time_format_option[opt_index].name))
        {
            skAbort();
        }
        break;

      case OPT_VAL_LEGACY_TIMESTAMPS:
        if ((opt_arg == NULL) || (opt_arg[0] == '\0') || (opt_arg[0] == '1')) {
            if (time_format_flags & (SK_OPTION_TIMESTAMP_NEVER_MSEC
                                     | SK_OPTION_TIMESTAMP_ALWAYS_MSEC))
            {
                if (time_format_option_parse(
                        "m/d/y", var_location,
                        time_format_option[opt_index].name))
                {
                    skAbort();
                }
            } else {
                if (time_format_option_parse(
                        "m/d/y,no-msec", var_location,
                        time_format_option[opt_index].name))
                {
                    skAbort();
                }
            }
        } else if (time_format_option_parse(
                       time_format_names[0].name, var_location,
                       time_format_option[opt_index].name))
        {
            skAbort();
        }
        break;
    }
    return 0;
}

int
skOptionsTimestampFormatRegister(
    uint32_t           *var_location,
    uint32_t            flags,
    ...)
{
    struct option opts[4];
    const struct option *tfo;
    const char *env;
    uint32_t tmp_val = 0;
    unsigned int num_opts;
    va_list arg;

    assert(sizeof(opts) >= sizeof(time_format_option));

    va_start(arg, flags);
    if (var_location == NULL) {
        va_end(arg);
        return -1;
    }

    time_format_flags = flags;
    if (time_format_flags & SK_OPTION_TIMESTAMP_NEVER_MSEC) {
        *var_location |= SKTIMESTAMP_NOMSEC;
    }

    env = getenv(SK_TIMESTAMP_FORMAT_ENVAR);
    if (env && env[0]) {
        if (time_format_option_parse(env, &tmp_val, SK_TIMESTAMP_FORMAT_ENVAR)
            == 0)
        {
            *var_location = tmp_val;
        }
    }

    /* copy --timestamp-format */
    memset(opts, 0, sizeof(opts));
    num_opts = 0;

    for (tfo = time_format_option; tfo->name; ++tfo) {
        assert(num_opts < sizeof(opts)/sizeof(opts[0]));
        switch ((enum time_format_option_en)tfo->val) {
          case OPT_VAL_TIMESTAMP_FORMAT:
            memcpy(&opts[num_opts], tfo, sizeof(opts[0]));
            ++num_opts;
            break;

          case OPT_VAL_LEGACY_TIMESTAMPS:
            if (time_format_flags & SK_OPTION_TIMESTAMP_OPTION_LEGACY){
                memcpy(&opts[num_opts], tfo, sizeof(opts[0]));
                ++num_opts;
            }
            break;

          case OPT_VAL_EPOCH_TIME:
            if (time_format_flags & SK_OPTION_TIMESTAMP_OPTION_EPOCH_NAME) {
                snprintf(time_format_epoch_name,sizeof(time_format_epoch_name),
                         "%s", va_arg(arg, char *));
                memcpy(&opts[num_opts], tfo, sizeof(opts[0]));
                opts[num_opts].name = time_format_epoch_name;
                ++num_opts;
            } else if (time_format_flags & SK_OPTION_TIMESTAMP_OPTION_EPOCH) {
                memcpy(&opts[num_opts], tfo, sizeof(opts[0]));
                ++num_opts;
            }
            break;
        }
    }

    va_end(arg);

    return skOptionsRegister(opts, time_format_option_handler,
                             (clientData)var_location);
}


void
skOptionsTimestampFormatUsage(
    FILE               *fh)
{
    const sk_stringmap_entry_t *e;
    const char *label;
    const char *sss;
    const struct option *tfo;

    /* whether to include milliseconds in timestamp help */
    if (time_format_flags & SK_OPTION_TIMESTAMP_NEVER_MSEC) {
        sss = "";
    } else {
        sss = ".sss";
    }

    for (tfo = time_format_option; tfo->name; ++tfo) {
        switch ((enum time_format_option_en)tfo->val) {
          case OPT_VAL_TIMESTAMP_FORMAT:
            fprintf(
                fh,
                ("--%s %s. Print each timestamp in this format and timezone.\n"
                 "\tDef. $" SK_TIMESTAMP_FORMAT_ENVAR " or %s,%s.  Choices:\n"),
                tfo->name, SK_OPTION_HAS_ARG(*tfo),
                time_format_names[0].name,
                time_format_zones[(SK_ENABLE_LOCALTIME != 0)].name);
            label = "Format:";
            for (e = time_format_names; e->name; ++e) {
                if (SKTIMESTAMP_EPOCH == e->id) {
                    sss = "";
                }
                fprintf(fh, "\t%-10s%-8s - %s%s\n",
                        label, e->name, e->description, sss);
                label = "";
            }
            label = "Timezone:";
            for (e = time_format_zones; e->name; ++e) {
                fprintf(fh, "\t%-10s%-8s - %s\n",
                        label, e->name, e->description);
                label = "";
            }
            if (0 == (time_format_flags & (SK_OPTION_TIMESTAMP_NEVER_MSEC
                                           | SK_OPTION_TIMESTAMP_ALWAYS_MSEC)))
            {
                label = "Misc:";
                for (e = time_format_misc; e->name; ++e) {
                    fprintf(fh, "\t%-10s%-8s - %s\n",
                            label, e->name, e->description);
                    label = "";
                }
            }
            break;

          case OPT_VAL_EPOCH_TIME:
            if (time_format_flags & SK_OPTION_TIMESTAMP_OPTION_EPOCH_NAME) {
                fprintf(fh, ("--%s %s. DEPRECATED."
                             " Equivalent to --%s=epoch\n"),
                        time_format_epoch_name, SK_OPTION_HAS_ARG(*tfo),
                        time_format_option[OPT_VAL_TIMESTAMP_FORMAT].name);
            } else if (time_format_flags & SK_OPTION_TIMESTAMP_OPTION_EPOCH) {
                fprintf(fh, ("--%s %s. DEPRECATED."
                             " Equivalent to --%s=epoch\n"),
                        tfo->name, SK_OPTION_HAS_ARG(*tfo),
                        time_format_option[OPT_VAL_TIMESTAMP_FORMAT].name);
            }
            break;

          case OPT_VAL_LEGACY_TIMESTAMPS:
            if (time_format_flags & SK_OPTION_TIMESTAMP_OPTION_LEGACY) {
                fprintf(
                    fh, "--%s %s. DEPRECATED. Equivalent to --%s=m/d/y%s\n",
                    tfo->name, SK_OPTION_HAS_ARG(*tfo),
                    time_format_option[OPT_VAL_TIMESTAMP_FORMAT].name,
                    ((time_format_flags & (SK_OPTION_TIMESTAMP_NEVER_MSEC
                                           | SK_OPTION_TIMESTAMP_ALWAYS_MSEC))
                     ? ""
                     : ",no-msec"));
            }
            break;
        }
    }
}


#if  SK_SUPPORT_CONF_FILE
/*
 *  readline:
 *      Read a line (including newline) from a file.  Will also read a
 *      last line (terminated by EOF) properly.
 *  SideEffects:
 *      Moves the read position of file to the next line.
 *  Return:
 *      A newly allocated string containing the next line.  NULL at
 *      EOF, or if there is a problem.
 */
static char *
readline(
    FILE               *file)
{
    static int gapsize = 64;
    char *line;
    int blocksize = 1;
    int writepoint = 0;
    char *retval = NULL;

    if (file == NULL) {
        return NULL;
    }

    /* Initial allocation for line */
    line = (char *)malloc(sizeof(char) * gapsize);
    if (line == NULL) {
        return NULL;
    }

    for (;;) {
        /* How many chars are left? */
        size_t empty = gapsize * blocksize - writepoint;
        char *wp = &line[writepoint];

        /* Get chars */
        if (fgets(wp, empty, file) == NULL) {
            if (writepoint != 0) {
                /* End of file */
                retval = strdup(line);
            }
            goto end;
        }

        /* If we haven't reached the end of the line, realloc. */
        if ((strlen(wp) == empty - 1) &&
            (wp[empty - 2] != '\n'))
        {
            char *tmpline;
            writepoint = gapsize * blocksize - 1;
            tmpline = realloc(line, sizeof(char) * (gapsize * (++blocksize)));
            if (tmpline) {
                line = tmpline;
            } else {
                goto end;
            }
        } else {
            /* We've reached the end of the line. */
            break;
        }
    }

    /* Allocate only enough space for the line. */
    retval = strdup(line);

  end:
    /* Cleanup */
    free(line);

    return retval;
}


/*
 * optionsHandleConfFile:
 *
 *     Loads a configuration file.  The configuration file consists of
 *     a series of newline-terminated lines.  A line consisting of
 *     only whitespace, or whose first non-whitespace character is a
 *     `#' character is ignored.  All other lines should consist of a
 *     single option name followed by the option's value (if any),
 *     separated by whitespace.  Whitespace at the beginning and end
 *     of the line is ignored.
 *
 * BUGS:
 *     If you intersperse switches (options) and arguments, arguments
 *     before the configuration file is parsed will not be seen.
 *
 *  Return:
 *      0 if ok. -1 else
 */
int
optionsHandleConfFile(
    char               *filename)
{
    static int gapsize = 10;
    int num_lines = 0;
    int num_alloc = 0;
    char **lines = NULL;
    char *line = NULL;
    FILE *file;
    int retval = -1;
    int i;
    char **argv = NULL;
    int argc = 0;
    int saved_optind;

    if (filename == NULL) {
        skAppPrintErr("NULL configuration filename");
        return -1;
    }

    /* Open the file */
    file = fopen(filename, "r");
    if (file == NULL) {
        skAppPrintErr("Could not open \"%s\" for reading.", filename);
        return -1;
    }

    /* Alloc the line buffer */
    num_alloc = gapsize;
    lines = (char **)malloc(sizeof(char *) * num_alloc);
    if (lines == NULL) {
        skAppPrintErr("Memory allocation error.");
        goto end;
    }

    /* Read in the lines */
    while ((line = readline(file))) {
        char *newline;
        size_t len;
        char *c;

        /* Strip it */
        len = skStrip(line);

        /* Elide commented or empty lines. */
        if (line[0] == '\0' || line[0] == '#') {
            free(line);
            continue;
        }

        /* Allocate space for the line, plus two characters. */
        c = newline = (char *)malloc(sizeof(char) * (len + 3));

        /* Copy the line, prepending hyphens  */
        *c++ = '-';
        *c++ = '-';
        strncpy(c, line, (len+1));
        free(line);
        lines[num_lines++] = newline;

        /* Allocate more space, if necessary */
        if (num_lines > num_alloc) {
            char **tmp;

            num_alloc += gapsize;
            tmp = realloc(lines, sizeof(char *) * num_alloc);
            if (tmp == NULL) {
                goto end;
            }
            lines = tmp;
        }
    }

    /* Allocate space for argv-style pointer */
    argv = (char **)malloc(sizeof(char *) * num_lines * 2 + 1);
    if (argv == NULL) {
        goto end;
    }
    /* First operand is program name, ignored */
    argv[argc++] = "";

    /* Parse the lines. */
    for (i = 0; i < num_lines; i++) {
        /* Set the next argument to the beginning of the line */
        char *c = argv[argc++] = lines[i];

        /* Find a space */
        while (*c && !isspace((int)*c)) {
            c++;
        }
        if (*c) {
            /* If we found a space, end the first arg, and find the
               option value. */
            *c++ = '\0';
            while (isspace((int)*c)) { /* Don't need to check for 0
                                          due to strip */
                c++;
            }
            /* Set the next argument to the option value. */
            argv[argc++] = c;
        }
    }

    saved_optind = optind;
#ifdef SK_USE_OPTRESET
    optreset = 1;
#endif
#ifdef SK_HAVE_GETOPT_LONG_ONLY
    optind = 1;
#else
    optind = 0;
#endif
    /* Parse the options */
    if (skOptionsParse(argc, argv) != -1) {
        retval = 0;
    }
    optind = saved_optind;
#ifdef SK_USE_OPTRESET
    optreset = 1;
#endif

  end:
    /* Cleanup */
    if (file) {
        fclose(file);
    }
    if (argv) {
        free(argv);
    }
    if (lines) {
        for (i = 0; i < num_lines; i++) {
            free(lines[i]);
        }
        free(lines);
    }
    return retval;
}
#endif /* SK_SUPPORT_CONF_FILE */


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
