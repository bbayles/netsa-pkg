/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
 *  skcompmethod.c
 *
 *    Convert between the names and the integer identifiers of the
 *    compression methods known to SiLK, and allow setting of the
 *    compression method via a command line switch.
 */

/* define sk_compmethod_names[] in silk_files.h */
#define SKCOMPMETHOD_SOURCE 1
#include <silk/silk.h>

RCSIDENT("$SiLK: skcompmethod.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_files.h>
#include <silk/skstringmap.h>
#include <silk/utils.h>


/* TYPEDEFS AND DEFINES */

/*
 *    Name of environment variable containing the default value for
 *    the --compression-method switch.
 *
 *    One potential drawback to using this variable is that it may
 *    force output to stdout to be compressed when normally that data
 *    is not compressed (the idea being no point to compress the data
 *    if it is going to another application that will need to
 *    uncompress it).
 */
#define SK_COMP_METHOD_ENVAR    "SILK_COMPRESSION_METHOD"

/*
 *    Name used by --compression-method switch to indicate the best
 *    compression method available.
 */
#define COMPMETHOD_STRING_BEST  "best"


/* LOCAL VARIABLES */

/*
 *    Default compression method.  Initialized based on variable set
 *    by the configure script.  It may be modified for an application
 *    by calling skCompMethodSetDefault().
 */
static sk_compmethod_t compmethod_default = SK_ENABLE_OUTPUT_COMPRESSION;


/* FUNCTION DEFINITIONS */

/*
 *    Return the number of valid entries in the sk_compmethod_names[]
 *    array defined in silk_files.h.
 */
static size_t
compMethodGetCount(
    void)
{
    static size_t compmethod_count = 0;
    size_t count;
    size_t len;
    size_t i;

    if (compmethod_count) {
        /* already initialized */
        return compmethod_count;
    }

    /* get the length of the sk_compmethod_names[] array */
    count = sizeof(sk_compmethod_names)/sizeof(sk_compmethod_names[0]);

    /* loop over sk_compmethod_names[] until we find a NULL name or a
     * name that is an empty string */
    for (i = 0; i < count; ++i) {
        if (NULL == sk_compmethod_names[i]) {
            break;
        }

        len = strlen(sk_compmethod_names[i]);
        if (0 == len) {
            break;
        }

#if 0
        /* check the length of the file format name */
        if (len > SK_MAX_STRLEN_COMPMETHOD) {
            skAppPrintErr(("FATAL! sk_compmethod_names[] in silk_files.h"
                           " contains a name '%s' whose length (%" SK_PRIuZ
                           ") is longer than the maximum allowed (%u)"),
                          sk_compmethod_names[i], len,
                          SK_MAX_STRLEN_COMPMETHOD);
            skAbort();
        }
#endif  /* 0 */
    }

    if (i >= UINT8_MAX) {
        skAppPrintErr("FATAL! sk_compmethod_names[] in silk_files.h"
                      " contains more than %u entries",
                      UINT8_MAX - 1u);
        skAbort();
    }
    if (0 == i) {
        skAppPrintErr("FATAL! sk_compmethod_names[] in silk_files.h"
                      " does not contain any names");
        skAbort();
    }

    /* only the final entry in array should be NULL or the empty
     * string */
    if (count - i > 1) {
        skAppPrintErr(("FATAL! sk_compmethod_names[] in silk_files.h"
                       " contains a NULL or empty-string entry at"
                       " position %" SK_PRIuZ),
                      i);
        skAbort();
    }

    compmethod_count = i;
    return compmethod_count;
}


/* Fill 'buffer' (of size 'buffer_size') with name of compression
 * method in 'cm'. */
int
skCompMethodGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_compmethod_t     cm)
{
    if (cm < compMethodGetCount()) {
        /* Known compmethod, give name */
        assert(cm < sizeof(sk_compmethod_names)/sizeof(sk_compmethod_names[0]));
        assert(sk_compmethod_names[cm] && sk_compmethod_names[cm][0]);
        return snprintf(buffer, buffer_size, "%s", sk_compmethod_names[cm]);
    }

    /* Unknown compression method, give integer */
    return snprintf(buffer, buffer_size, "%u", cm);
}


/* Check whether the value in 'comp_method' is AVAILABLE (an explicit
 * comp-method that is compiled into SiLK), VALID (an explicit
 * comp-method that is not available), or KNOWN (the "best" or
 * "default" pseudo-values). */
int
skCompMethodCheck(
    sk_compmethod_t     comp_method)
{
    switch (comp_method) {
      case SK_COMPMETHOD_DEFAULT:
      case SK_COMPMETHOD_BEST:
        return SK_COMPMETHOD_IS_KNOWN;

      case SK_COMPMETHOD_NONE:
#if SK_ENABLE_ZLIB
      case SK_COMPMETHOD_ZLIB:
#endif
#if SK_ENABLE_LZO
      case SK_COMPMETHOD_LZO1X:
#endif
#if SK_ENABLE_SNAPPY
      case SK_COMPMETHOD_SNAPPY:
#endif
        return SK_COMPMETHOD_IS_AVAIL;
    }

    if (((uint8_t)comp_method) < compMethodGetCount()) {
        return SK_COMPMETHOD_IS_VALID;
    }
    return 0;
}


/* Return the "best" compression method. */
sk_compmethod_t
skCompMethodGetBest(
    void)
{
#if   SK_ENABLE_LZO
    return SK_COMPMETHOD_LZO1X;
#elif SK_ENABLE_SNAPPY
    return SK_COMPMETHOD_SNAPPY;
#elif SK_ENABLE_ZLIB
    return SK_COMPMETHOD_ZLIB;
#else
    return SK_COMPMETHOD_NONE;
#endif
}


/* Return the default compression method. */
sk_compmethod_t
skCompMethodGetDefault(
    void)
{
    /* return the value from configure */
    return compmethod_default;
}


/* Set the default compression method to 'comp_method.' */
int
skCompMethodSetDefault(
    sk_compmethod_t     comp_method)
{
    if (SK_COMPMETHOD_IS_AVAIL != skCompMethodCheck(comp_method)) {
        return -1;
    }
    compmethod_default = comp_method;
    return 0;
}


/* ========================================================================
 * Support for the --compression-method switch and environment variable
 */

/*
 *    If set, ignore the environment variable.  Caller may set it by
 *    calling skCompMethodOptionsNoEnviron().  Used by daemons.
 */
static int compmethod_opts_ignore_envar = 0;

typedef enum {
    OPT_COMPRESSION_METHOD
} compmethod_opts_enum_t;

static struct option compmethod_opts[] = {
    {"compression-method",  REQUIRED_ARG, 0, OPT_COMPRESSION_METHOD},
    {0,0,0,0}               /* sentinel entry */
};


static int
compMethodParse(
    const char         *user_string,
    sk_compmethod_t    *out_comp_method,
    const char         *option_name)
{
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_status_t rv_map;
    sk_stringmap_entry_t *map_entry;
    sk_stringmap_entry_t insert_entry;
    size_t count;
    sk_compmethod_t cm;
    int rv = -1;

    count = compMethodGetCount();

    /* create a stringmap of all compression methods and "best" */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintErr("Unable to create stringmap");
        goto END;
    }
    memset(&insert_entry, 0, sizeof(insert_entry));
    insert_entry.name = COMPMETHOD_STRING_BEST;
    insert_entry.id = (sk_stringmap_id_t)SK_COMPMETHOD_BEST;
    if (skStringMapAddEntries(str_map, 1, &insert_entry) != SKSTRINGMAP_OK) {
        goto END;
    }
    for (cm = 0; cm < count; ++cm) {
        memset(&insert_entry, 0, sizeof(insert_entry));
        insert_entry.name = sk_compmethod_names[cm];
        insert_entry.id = (sk_stringmap_id_t)cm;
        if (skStringMapAddEntries(str_map, 1, &insert_entry)
            != SKSTRINGMAP_OK)
        {
            skAppPrintErr("Unable to add stringmap entry for %s",
                          insert_entry.name);
            goto END;
        }
    }

    /* attempt to match */
    rv_map = skStringMapGetByName(str_map, user_string, &map_entry);
    switch (rv_map) {
      case SKSTRINGMAP_OK:
        assert(map_entry->id <= UINT8_MAX);
        cm = map_entry->id;
        /* mask of 5 verifies value is available or "best" */
        if (skCompMethodCheck(cm) & 5) {
            *out_comp_method = cm;
            rv = 0;
            break;
        }
        skAppPrintErr("Invalid %s: Compression method %s is not available",
                      option_name, map_entry->name);
        break;

      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("Invalid %s '%s': Value is ambiguous",
                      option_name, user_string);
        break;

      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr("Invalid %s '%s': Value does not match any known method",
                      option_name, user_string);
        break;

      default:
        skAppPrintErr("Invalid %s '%s':"
                      " Unexpected return value from string-map parser (%d)",
                      option_name, user_string, rv_map);
        break;
    }

  END:
    if (str_map) {
        skStringMapDestroy(str_map);
    }
    return rv;
}


static int
compMethodOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    if (opt_index != OPT_COMPRESSION_METHOD) {
        skAbort();
    }
    return compMethodParse(opt_arg, (sk_compmethod_t *)cData,
                           compmethod_opts[OPT_COMPRESSION_METHOD].name);
}


void
skCompMethodOptionsNoEnviron(
    void)
{
    compmethod_opts_ignore_envar = 1;
}


int
skCompMethodOptionsRegister(
    sk_compmethod_t    *compression_method)
{
    sk_compmethod_t cm = SK_COMPMETHOD_DEFAULT;
    const char *env;

    if (compression_method == NULL) {
        return -1;
    }
    if (0 == compmethod_opts_ignore_envar) {
        env = getenv(SK_COMP_METHOD_ENVAR);
        if (env && env[0]) {
            compMethodParse(env, &cm, SK_COMP_METHOD_ENVAR);
        }
    }
    *compression_method = cm;

    return skOptionsRegister(compmethod_opts, &compMethodOptionsHandler,
                             compression_method);
}


void
skCompMethodOptionsUsage(
    FILE               *fh)
{
    const struct option *opt = compmethod_opts;
    size_t count;
    sk_compmethod_t cm;

    count = compMethodGetCount();

    fprintf(fh, "--%s %s. ", opt->name, SK_OPTION_HAS_ARG(*opt));
    fprintf(fh, ("Set compression library to use for binary output\n"
                 "\tfiles. Def. "));
    if (compmethod_opts_ignore_envar) {
        fprintf(fh, "%s. ", sk_compmethod_names[skCompMethodGetDefault()]);
    } else {
        fprintf(fh, "$" SK_COMP_METHOD_ENVAR " or %s.\n\t",
                sk_compmethod_names[skCompMethodGetDefault()]);
    }

    fprintf(fh, "Choices: " COMPMETHOD_STRING_BEST " [=%s]",
            sk_compmethod_names[skCompMethodGetBest()]);
    for (cm = 0; cm < count; ++cm) {
        if (SK_COMPMETHOD_IS_AVAIL != skCompMethodCheck(cm)) {
            continue;
        }
        fprintf(fh, ", %s", sk_compmethod_names[cm]);
    }
    fprintf(fh, "\n");
}



/** DEPRECATED FUNCTIONS **********************************************/

#include <silk/sksite.h>

int
sksiteCompmethodCheck(
    sk_compmethod_t     comp_method)
{
    return skCompMethodCheck(comp_method);
}

sk_compmethod_t
sksiteCompmethodGetBest(
    void)
{
    return skCompMethodGetBest();
}

sk_compmethod_t
sksiteCompmethodGetDefault(
    void)
{
    return skCompMethodGetDefault();
}

int
sksiteCompmethodGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_compmethod_t     comp_method)
{
    return skCompMethodGetName(buffer, buffer_size, comp_method);
}

int
sksiteCompmethodSetDefault(
    sk_compmethod_t     compression_method)
{
    return skCompMethodSetDefault(compression_method);
}

int
sksiteCompmethodOptionsRegister(
    sk_compmethod_t    *compression_method)
{
    return skCompMethodOptionsRegister(compression_method);
}

void
sksiteCompmethodOptionsUsage(
    FILE               *fh)
{
    skCompMethodOptionsUsage(fh);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
