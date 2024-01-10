/*
 *  Copyright 2005-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  airopt.c
 *  Airframe options interface
 *
 *  ------------------------------------------------------------------------
 *  Authors: Tony Cebzanov
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 2.15.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2313
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */

#define _AIRFRAME_SOURCE_
#include <airframe/airopt.h>

struct _AirOptionCtx {
#if USE_GOPTION
    GOptionContext  *octx;
#elif USE_POPT
    poptContext      octx;
    GArray          *options;
#endif /* if USE_GOPTION */
    int             *argc;
    char          ***argv;
};

void
air_opterr(
    const char  *fmt,
    ...)
{
    va_list ap;

    fprintf(stderr, "Command-line argument error: \n");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\nUse --help for usage.\n");

    exit(1);
}


AirOptionCtx *
air_option_context_new(
    const char      *helpstr,
    int             *argc,
    char          ***argv,
    AirOptionEntry  *entries)
{
    AirOptionCtx   *aoctx;
#if USE_GOPTION
    GOptionContext *octx = NULL;
#elif USE_POPT
    poptContext     octx = NULL;
    int             i    = 0;
#endif /* if USE_GOPTION */

    aoctx = g_new0(AirOptionCtx, 1);
#if USE_GOPTION
    octx = g_option_context_new(helpstr);
    if (entries) {
        g_option_context_add_main_entries(octx, entries, NULL);
    }
#elif USE_POPT

    aoctx->options = g_array_sized_new(TRUE, TRUE, sizeof(AirOptionEntry), 64);
    if (entries) {
        for (i = 0; !AF_OPTION_EMPTY(entries[i]); i++) {
            g_array_append_val(aoctx->options, entries[i]);
        }
    }
    octx = poptGetContext(NULL, *argc,  (const char **)*argv,
                          (AirOptionEntry *)aoctx->options->data, 0);

    poptSetOtherOptionHelp(octx, helpstr);
#endif /* if USE_GOPTION */

    aoctx->argc = argc;
    aoctx->argv = argv;
    aoctx->octx = octx;

    return aoctx;
}


gboolean
air_option_context_add_group(
    AirOptionCtx    *aoctx,
    const char      *shortname,
    const char      *longname,
    const char      *description,
    AirOptionEntry  *entries)
{
    g_assert(aoctx != NULL);
    g_assert(aoctx->octx != NULL);

#if USE_GOPTION
    {
        GOptionGroup *ogroup;

        /* create an option group */
        ogroup = g_option_group_new(shortname, longname,
                                    description, NULL, NULL);
        g_option_group_add_entries(ogroup, entries);
        g_option_context_add_group(aoctx->octx, ogroup);

        return TRUE;
    }
#elif USE_POPT
    {
        struct poptOption poption;

        poption.longName   = NULL;
        poption.shortName  = '\0';
        poption.argInfo    = POPT_ARG_INCLUDE_TABLE;
        poption.arg        = entries;
        poption.val        = 0;
        poption.descrip    = longname;
        poption.argDescrip = NULL;
        g_array_append_val(aoctx->options, poption);

        return TRUE;
    }
#endif /* if USE_GOPTION */

    return FALSE;
}


void
air_option_context_parse(
    AirOptionCtx  *aoctx)
{
#if USE_GOPTION
    GError *oerr = NULL;

    g_option_context_parse(aoctx->octx, aoctx->argc, aoctx->argv, &oerr);
    if (oerr) {
        air_opterr("%s", oerr->message);
    }
#elif USE_POPT
    {
        int        argcount = 0;
        char     **rest     = 0;
        int        rc;

        GPtrArray *new_argv = NULL;

        rc = poptGetNextOpt(aoctx->octx);
        if (rc != -1) {
            air_opterr("%s", poptStrerror(rc));
        }

        /* We have to manually construct the argv here because GLib keeps the
         * program name in argv[0] and popt doesn't. */
        new_argv = g_ptr_array_sized_new(64);
        g_ptr_array_add(new_argv, g_strdup(*(aoctx->argv)[0]));

        /* Do the actual parsing, returning non-switch args */
        rest = (char **)poptGetArgs(aoctx->octx);

        /* Walk through the remaining args, adding them to the new argv and
         * counting them for argc */
        while ( (rest != NULL) && rest[argcount] != NULL) {
            g_ptr_array_add(new_argv, g_strdup(rest[argcount]));
            argcount++;
        }
        g_ptr_array_add(new_argv, NULL);
        /* Now replace the original argc and argv with post-parse values */
        *(aoctx->argc) = argcount;
        *(aoctx->argv) = (char **)g_ptr_array_free(new_argv, FALSE);
    }
#endif /* if USE_GOPTION */
}


void
air_option_context_set_help_enabled(
    AirOptionCtx  *aoctx)
{
    g_assert(aoctx != NULL);
    g_assert(aoctx->octx != NULL);
#if USE_GOPTION
    g_option_context_set_help_enabled(aoctx->octx, TRUE);
#elif USE_POPT
    {
        struct poptOption poption;

        poption.longName   = NULL;
        poption.shortName  = '\0';
        poption.argInfo    = POPT_ARG_INCLUDE_TABLE;
        poption.arg        = poptHelpOptions;
        poption.val        = 0;
        poption.descrip    =  "Help options:";
        poption.argDescrip = NULL;
        g_array_append_val(aoctx->options,  poption);
    }
#endif /* if USE_GOPTION */
}


void
air_option_context_usage(
    AirOptionCtx  *aoctx)
{
    g_assert(aoctx != NULL);
    g_assert(aoctx->octx != NULL);

#if USE_GOPTION
    g_fprintf(stderr, "%s",
              g_option_context_get_help(aoctx->octx, FALSE, NULL));
#elif USE_POPT
    poptPrintHelp(aoctx->octx, stderr, 0);
#endif /* if USE_GOPTION */
}


void
air_option_context_free(
    AirOptionCtx  *aoctx)
{
#if USE_GOPTION
    g_option_context_free(aoctx->octx);
    g_free(aoctx);
#elif USE_POPT
    g_array_free(aoctx->options, TRUE);
    poptFreeContext(aoctx->octx);
#endif /* if USE_GOPTION */
}
