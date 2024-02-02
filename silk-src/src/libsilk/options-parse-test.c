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
**  Test the options parsing code.  Moved from options.c to this
**  external file.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: options-parse-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>


static char *pName;


static struct  option filter_options[] = {
    {"stime",             REQUIRED_ARG,   0, 0},
    {"etime",             REQUIRED_ARG,   0, 1},
    {"duration",          REQUIRED_ARG,   0, 2},
    {"sport",             REQUIRED_ARG,   0, 3},
    {"dport",             REQUIRED_ARG,   0, 4},
    {"protocol",          REQUIRED_ARG,   0, 5},
    {"bytes",             REQUIRED_ARG,   0, 6},
    {"pkts",              REQUIRED_ARG,   0, 7},
    {"flows",             REQUIRED_ARG,   0, 8},
    {"saddress",          REQUIRED_ARG,   0, 9},
    {"daddress",          REQUIRED_ARG,   0, 10},
    {"bytes_per_packet",  REQUIRED_ARG,   0, 13},
    {"pkts_per_flow",     REQUIRED_ARG,   0, 14},
    {"bytes_per_flow",    REQUIRED_ARG,   0, 15},
    {"not-saddress",      REQUIRED_ARG,   0, 16},
    {"not-daddress",      REQUIRED_ARG,   0, 17},
    {0, 0, 0, 0}
};

static struct option fglob_options[] = {
    {"start-date", REQUIRED_ARG, 0, 1},
    {"end-date", REQUIRED_ARG, 0, 2},
    {"tcpdump", NO_ARG, 0, 3},
    {"glob", REQUIRED_ARG, 0, 4},
    {0, 0, 0, 0}
};

#if SK_SUPPORT_CONF_FILE
static struct option conffile_option[] = {
    {"conffile", REQUIRED_ARG, 0, 1},
    {0, 0, 0, 0}
};
#endif  /* SK_SUPPORT_CONF_FILE */


static void
filterUsage(
    char        UNUSED(*p_name))
{
    unsigned int i;

    fprintf(stdout, "Filter Options:\n");
    for (i = 0; i < (sizeof(filter_options)/sizeof(struct option)) - 1; i++ ) {
        fprintf(stdout, "--%s %s\n", filter_options[i].name,
                filter_options[i].has_arg ? filter_options[i].has_arg == 1
                ? "Required Arg" : "Optional Arg" : "No Arg");
    }
    return;
}

static void
fglobUsage(
    char        UNUSED(*p_name))
{
    unsigned int i;

    fprintf(stdout, "Fglob Options:\n");
    for (i = 0; i < (sizeof(fglob_options)/sizeof(struct option)) - 1; i++ ) {
        fprintf(stdout, "--%s %s\n", fglob_options[i].name,
                fglob_options[i].has_arg ? fglob_options[i].has_arg == 1
                ? "Required Arg" : "Optional Arg" : "No Arg");
    }
    return;
}

#if  SK_SUPPORT_CONF_FILE
static void
conffileUsage(
    char        UNUSED(*p_name))
{
    unsigned int i;

    fprintf(stdout, "ConfFile Options:\n");
    for (i = 0; i < (sizeof(conffile_option)/sizeof(struct option)) - 1; i++ )
    {
        fprintf(stdout, "--%s %s\n", conffile_option[i].name,
                conffile_option[i].has_arg ? conffile_option[i].has_arg == 1
                ? "Required Arg" : "Optional Arg" : "No Arg");
    }
    return;
}
#endif  /* SK_SUPPORT_CONF_FILE */


/* optHandlers */
static int
filterHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    static int optionCount = (sizeof(filter_options)/sizeof(struct option))-1;

    if (opt_index < 0 || opt_index > optionCount) {
        fprintf(stderr, "filterHandler: invalid index %d\n", opt_index);
        return 1;                   /* error */
    }

    if (opt_index == 18) {
        filterUsage(pName);
        return 0;
    }
    fprintf(stderr, "filterHandler: %s %s %s\n",
            filter_options[opt_index].name,
            (filter_options[opt_index].has_arg == 0
             ? "No Arg"
             : (filter_options[opt_index].has_arg == 1
                ? "Required Arg"
                : "Optional Arg")),
            opt_arg ? opt_arg : "NULL");
    return 0;                     /* OK */
}

static int
fglobHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{

    static int optionCount = (sizeof(fglob_options)/sizeof(struct option)) - 1;

    if (opt_index < 0 || opt_index > optionCount) {
        fprintf(stderr, "fglobHandler: invalid index %d\n", opt_index);
        return 1;                   /* error */
    }

    if (opt_index == 5) {
        fglobUsage(pName);
        return 0;
    }

    fprintf(stderr, "fglobHandler: %s %s %s\n",
            fglob_options[opt_index-1].name,
            (fglob_options[opt_index-1].has_arg == 0
             ? "No Arg"
             : (fglob_options[opt_index-1].has_arg == 1
                ? "Required Arg"
                : "Optional Arg")),
            opt_arg ? opt_arg : "NULL");
    return 0;                     /* OK */
}


#if  SK_SUPPORT_CONF_FILE
static int
conffileHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    static int optionCount = (sizeof(conffile_option)/
                              sizeof(struct option)) - 1;

    if (opt_index < 0 || opt_index > optionCount) {
        fprintf(stderr, "fglobHandler: invalid index %d\n", opt_index);
        return 1;                       /* error */
    }

    if (opt_index == 1) {
        int retval;
        fprintf(stderr, "conffileHandler: %s %s %s\n",
                conffile_option[opt_index-1].name,
                conffile_option[opt_index-1].has_arg == 0 ? "No Arg" :
                (conffile_option[opt_index-1].has_arg == 1 ?
                 "Required Arg" : "Optional Arg"),
                opt_arg ? opt_arg : "NULL");
        fprintf(stderr, "Parsing conffile %s\n", opt_arg);
        retval = optionsHandleConfFile(opt_arg);
        fprintf(stderr, "Finished parsing conffile %s\n", opt_arg);
        return retval;
    }
    else {
        fprintf(stderr, "Unhandled conffile option index %d\n", opt_index);
    }
    return 0;
}
#endif  /* SK_SUPPORT_CONF_FILE */


static void
shortest_prefix(
    void)
{
    const char *names[] = {
        "stime",
        "end-date",
        "glob",
        "bytes",
        "bytes_per_packet",
        NULL
    };
    int i;
    int len;

    for (i = 0; names[i] != NULL; ++i) {
        len = skOptionsGetShortestPrefix(names[i]);
        fprintf(stderr, "Prefix for '%s' is %d\n",
                names[i], len);
    }
}


int main(int argc, char **argv)
{
    int nextArgIndex;

    pName = argv[0];

    skAppRegister(pName);

    if (argc < 2) {
        filterUsage(pName);
        fglobUsage(pName);
#if  SK_SUPPORT_CONF_FILE
        conffileUsage(pName);
#endif
        skAppUnregister();
        exit(EXIT_FAILURE);
    }

    if (skOptionsRegister(&filter_options[0], filterHandler, NULL)) {
        fprintf(stderr, "Unable to register filter options\n");
        filterUsage(pName);
        skAppUnregister();
        exit(EXIT_FAILURE);
    }
    if (skOptionsRegister(fglob_options, fglobHandler, NULL)) {
        fprintf(stderr, "Unable to register fglob options\n");
        fglobUsage(pName);
        skAppUnregister();
        exit(EXIT_FAILURE);
    }
#if SK_SUPPORT_CONF_FILE
    if (skOptionsRegister(conffile_option, conffileHandler, NULL)) {
        fprintf(stderr, "Unable to register conffile options\n");
        conffileUsage(pName);
        skAppUnregister();
        exit(EXIT_FAILURE);
    }
#endif  /* SK_SUPPORT_CONF_FILE */

    shortest_prefix();

    nextArgIndex = skOptionsParse(argc, argv);
    if (nextArgIndex == -1) {
        fprintf(stderr, "Parse error");
        skAppUnregister();
        exit(EXIT_FAILURE);
    }

    if (nextArgIndex < argc) {
        fprintf(stdout, "Remaining command line arguments: ");
        while (nextArgIndex < argc) {
            fprintf(stdout, "[%s] ", argv[nextArgIndex]);
            nextArgIndex++;
        }
        fprintf(stdout, "\n");
    }

    skAppUnregister();
    exit(EXIT_SUCCESS);
}



/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
