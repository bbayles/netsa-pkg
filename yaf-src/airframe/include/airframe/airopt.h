/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  airopt.h
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

/**
 * @file
 *
 * Airframe options interface.
 */

/* idem hack */
#ifndef _AIR_AIROPT_H_
#define _AIR_AIROPT_H_

#include <airframe/autoinc.h>

#if USE_GOPTION
#include <glib/gprintf.h>

typedef GOptionEntry AirOptionEntry;

/** Macro used to define command-line options
 *
 * @param longname The full name of the option
 * @param shortname A single character identifier for the option
 * @param flag Special option flags.  Currently unused.
 * @param type The data type (one of AF_OPT_TYPE_*) for the option's value.
 * @param var Pointer to the location where the option value will be stored.
 * @param desc Description of the option in help output.
 * @param vardesc Description of the option's value in help output.
 */
#define AF_OPTION(longname, shortname, flag, type, var, desc, vardesc) \
    { longname, shortname, flag, type, var, desc, vardesc }

/**
 * Macro used to terminate an AF_OPTION list
 */
#define AF_OPTION_END { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }

/**
 * Macro to test if an AF_OPTION structure is empty
 */
#define AF_OPTION_EMPTY(option) (option.long_name == NULL)

/** No option argument */
#define AF_OPT_TYPE_NONE          G_OPTION_ARG_NONE

/** Integer option argument */
#define AF_OPT_TYPE_INT           G_OPTION_ARG_INT
#define AF_OPT_TYPE_INT64         G_OPTION_ARG_INT64

/** String option argument */
#define AF_OPT_TYPE_STRING        G_OPTION_ARG_STRING
/** Array of strings */
#define AF_OPT_TYPE_STRING_ARRAY  G_OPTION_ARG_STRING_ARRAY

/** Double-precision argument */
#define AF_OPT_TYPE_DOUBLE        G_OPTION_ARG_DOUBLE

/** Callback argument */
#define AF_OPT_TYPE_CALLBACK      G_OPTION_ARG_CALLBACK

#elif USE_POPT

#include <popt.h>

typedef struct poptOption AirOptionEntry;

/** Macro used to define command-line options
 *
 * @param longname The full name of the option
 * @param shortname A single character identifier for the option
 * @param flag Special option flags.  Currently unused.
 * @param type The data type (one of AF_OPT_TYPE_*) for the option's value.
 * @param var Pointer to the location where the option value will be stored.
 * @param desc Description of the option in help output.
 * @param vardesc Description of the option's value in help output.
 */
#define AF_OPTION(longname, shortname, flag, type, var, desc, vardesc) \
    { longname, shortname, type, var, flag, desc, vardesc }

/**
 * Macro used to terminate an AF_OPTION list
 */
#define AF_OPTION_END POPT_TABLEEND

/**
 * Macro to test if an AF_OPTION structure is empty
 */
#define AF_OPTION_EMPTY(option)  \
    (option.longName == NULL     \
     && option.shortName == '\0' \
     && option.argInfo == 0)

/** No option argument */
#define AF_OPT_TYPE_NONE          POPT_ARG_NONE

/** Integer option argument */
#define AF_OPT_TYPE_INT           POPT_ARG_INT
#define AF_OPT_TYPE_INT64         POPT_ARG_LONGLONG

/** String option argument */
#define AF_OPT_TYPE_STRING        POPT_ARG_STRING
/** Array of strings */
#define AF_OPT_TYPE_STRING_ARRAY  POPT_ARG_ARGV

/** Double-precision option argument */
#define AF_OPT_TYPE_DOUBLE        POPT_ARG_DOUBLE

#else /* if USE_GOPTION */

#error A suitable GLib or popt library was not found for options processing.

#endif /* if USE_GOPTION */

/**
 * Opaque options context structure.
 */
typedef struct _AirOptionCtx AirOptionCtx;

/**
 * Print a formatted option error message on standard error and exit the
 * process. Use this only during command-line option processing. This call
 * will not return.
 *
 * @param fmt format string of error message
 */
void
air_opterr(
    const char  *fmt,
    ...);

/**
 * Create a new option context.
 *
 * @param helpstr Text to be displayed after the name of the command in help
 * @param argc The address of the program's argc count
 * @param argv The address of the program's argv array
 * @param entries An array of AF_OPTION structures terminated by AF_OPTION_END
 * @return An initialized AirOptionCtx, or NULL if an error occurred.
 */
AirOptionCtx *
air_option_context_new(
    const char      *helpstr,
    int             *argc,
    char          ***argv,
    AirOptionEntry  *entries);

/**
 * Add a group of options to an option context.
 *
 * @param aoctx AirOptionCtx to be modified
 * @param shortname A short name for the group, which should not contains
 * spaces
 * @param longname The full name of the option group, shown in help
 * @param description A brief description of the option group shown in help
 * @param entries An array of AF_OPTION structures terminated by AF_OPTION_END
 * @return TRUE if group add was successful, FALSE otherwise
 */
gboolean
air_option_context_add_group(
    AirOptionCtx    *aoctx,
    const char      *shortname,
    const char      *longname,
    const char      *description,
    AirOptionEntry  *entries);

/**
 * Parse command line arguments based on option entries that have been added
 * to the option context.  The argc and argv associated with the context will
 * be updated by this function, with recognized options removed. Prints
 * an error to standard error and terminates the process if the command-line
 * cannot be parsed.
 *
 * @param aoctx AirOptionCtx to be parsed
 */
void
air_option_context_parse(
    AirOptionCtx  *aoctx);

/**
 * Enable the display of option help by invoking your program with the --help
 * or --usage parameters.
 *
 * @param aoctx AirOptionCtx to be modified.
 */
void
air_option_context_set_help_enabled(
    AirOptionCtx  *aoctx);

/**
 * Print a command line option usage message for your program, if supported by
 * the underlying options library.
 *
 * @param aoctx AirOptionCtx to be displayed.
 */
void
air_option_context_usage(
    AirOptionCtx  *aoctx);

/**
 * Destroy an options context.
 *
 * @param aoctx AirOptionCtx to be freed.
 */
void
air_option_context_free(
    AirOptionCtx  *aoctx);

#endif /* ifndef _AIR_AIROPT_H_ */
