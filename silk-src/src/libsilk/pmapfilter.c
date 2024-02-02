/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
**  pmapfilter.c
**
**    Katherine Prevost
**    April 20th, 2004
**
**    Support for using prefix maps from within SiLK applications.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: pmapfilter.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/skplugin.h>
#include <silk/skstream.h>
#include <silk/rwrec.h>
#include <silk/skvector.h>
#include <silk/skstringmap.h>
#include <silk/skprefixmap.h>


/* TYPEDEFS AND DEFINES */

/* Plugin protocol version */
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0

/* given a bitmap 'b' of size 's', return true if bit 'i' is ON */
#define PMAP_BMAP_CHECK(b,s,i)                                          \
    (((i) >= (s)) ? 0 : (((b)[(i)>>5] & (1<<((i) & 0x1F))) != 0))

/* turn ON the 'i'th bit in bitmap 'b' */
#define PMAP_BMAP_SET(b,i)                      \
    ((b)[(i)>>5] |= (1 << ((i) & 0x1F)))

/* compute number of uint32_t's required for a bitmap of 's' bits */
#define PMAP_BMAP_SIZE(s)                       \
    (((s) <= 0) ? 1u : (1 + ((s) - 1)/32))

/* call function the free function 'f' on 'x' if x is not NULL */
#define FREE_NONNULL(f, x) do { if (x) { f(x); x = NULL; } } while (0)

/* print out of memory message */
#define ERR_NO_MEM(nomem_obj)                                  \
    skAppPrintOutOfMemory(#nomem_obj)

/*
 *  ASSERT_RESULT(ar_func_args, ar_type, ar_expected);
 *
 *    ar_func_args  -- is a function and any arugments it requires
 *    ar_type       -- is the type that ar_func_args returns
 *    ar_expected   -- is the expected return value from ar_func_args
 *
 *    If assert() is disabled, simply call 'ar_func_args'.
 *
 *    If assert() is enabled, call 'ar_func_args', capture its result,
 *    and assert() that its result is 'ar_expected'.
 */
#ifdef  NDEBUG
/* asserts are disabled; just call the function */
#define ASSERT_RESULT(ar_func_args, ar_type, ar_expected)  ar_func_args
#else
#define ASSERT_RESULT(ar_func_args, ar_type, ar_expected)       \
    do {                                                        \
        ar_type ar_rv = (ar_func_args);                         \
        assert(ar_rv == (ar_expected));                         \
    } while(0)
#endif


typedef enum direction_e {
    DIR_SOURCE,
    DIR_DEST,
    DIR_ANY
} direction_t;

/* Forward-declare the pmap_data_t type, a wrapper around the pmap */
struct pmap_data_st;
typedef struct pmap_data_st pmap_data_t;


/* The per-direction portion of pmap_data */
typedef struct directed_pmap_data_st {
    /* Pointer to containing pmap_data object */
    pmap_data_t      *data;
    /* rwfilter command line option for this direction */
    char             *filter_option;
    /* Direction-based field name */
    char             *field_name;
    /* Value bitfield for filtering on a map */
    uint32_t         *val_bitmap;
    /* Number of bits in the 'val_bitmap' */
    uint32_t          size_bitmap;
    /* The field for this direction */
    skplugin_field_t *field;
    /* The direction */
    direction_t       dir;
} directed_pmap_data_t;

struct pmap_data_st {
    /* The prefix map */
    skPrefixMap_t        *pmap;
    /* Name of the pmap */
    char                 *mapname;
    /* The path to the pmap file */
    char                 *filepath;
    /* source direction data */
    directed_pmap_data_t  sdir;
    /* destination direction data */
    directed_pmap_data_t  ddir;
    /* any direction data */
    directed_pmap_data_t  adir;
    /* Cached for convenience */
    skPrefixMapContent_t  type;
};


/* LOCAL VARIABLES */

/* Vector of prefix map information */
static sk_vector_t *pmap_vector;

/* whether the prefixmap is being ignored.  if so, all functions
 * that use the prefixmap during setup should return success. */
static int ignore_prefix_map = 0;

/* maximum column width */
static uint32_t max_column_width = 0;

/* Option names */
static const char *pmap_file_option = "pmap-file";
static const char *pmap_saddress_option = "pmap-saddress";
static const char *pmap_daddress_option = "pmap-daddress";
static const char *pmap_aaddress_option = "pmap-any-address";
static const char *pmap_sport_proto_option = "pmap-sport-proto";
static const char *pmap_dport_proto_option = "pmap-dport-proto";
static const char *pmap_aport_proto_option = "pmap-any-port-proto";
static const char *pmap_column_width_option = "pmap-column-width";

/* Deprecated field titles */
static const char *pmap_title_val  = "val";
static const char *pmap_title_sval = "sval";
static const char *pmap_title_dval = "dval";

/* Direction indicators (must currently be the same length) */
static const char    src_dir_name[] = "src-";
static const char    dst_dir_name[] = "dst-";
static const char    any_dir_name[] = "any-";

/* Option naming prefix */
static const char   pmap_prefix[]   = "pmap-";
static const size_t pmap_prefix_len = sizeof(pmap_prefix) - 1;


/* PRIVATE FUNCTION PROTOTYPES */

static int
pmapFilterSetupBitmap(
    uint32_t              **bitmap,
    uint32_t               *bitmap_size,
    const skPrefixMap_t    *prefix_map,
    const char             *opt_arg,
    const char             *mapname);
static skplugin_err_t
pmap_filter_fn(
    const rwRec        *rwrec,
    void               *data,
    void              **extra);
static skplugin_err_t
pmap_text_fn(
    const rwRec        *rec,
    char               *dest,
    size_t              width,
    void               *data,
    void              **extra);
static skplugin_err_t
pmap_bin_fn(
    const rwRec        *rec,
    uint8_t            *dest,
    void               *data,
    void              **extra);
static skplugin_err_t
pmap_bin_to_text_fn(
    const uint8_t      *bin,
    char               *dest,
    size_t              width,
    void               *data);
static skplugin_err_t
pmap_column_width_handler(
    const char         *opt_arg,
    void               *cbdata);
static skplugin_err_t
pmapfile_handler(
    const char         *opt_arg,
    void               *cbdata);
static skplugin_err_t
pmap_handle_filter_option(
    const char         *opt_arg,
    void               *cbdata);
static skplugin_err_t pmap_field_init(void *cbdata);
static void pmap_data_destroy(pmap_data_t *data);
static void pmap_teardown(void);


/* FUNCTION DEFINITIONS */

/* Public entry point */
skplugin_err_t
skPrefixMapAddFields(
    uint16_t            major_version,
    uint16_t            minor_version,
    void        UNUSED(*data))
{
    skplugin_err_t err;

#define PMAP_FILE_HELP(str_arg)                                         \
    ("Prefix map file to read.  Def. None.  When the argument has\n"    \
     "\tthe form \"<mapfile>:<filename>\","                             \
     " the \"mapname\" is used to generate\n"                           \
     str_arg)

    assert(strlen(src_dir_name) == strlen(dst_dir_name));

    /* Check API version */
    err = skpinSimpleCheckVersion(major_version, minor_version,
                                  PLUGIN_API_VERSION_MAJOR,
                                  PLUGIN_API_VERSION_MINOR,
                                  skAppPrintErr);
    if (err != SKPLUGIN_OK) {
        return err;
    }

    /* Initialize global variables */
    pmap_vector = skVectorNew(sizeof(pmap_data_t *));
    if (pmap_vector == NULL) {
        ERR_NO_MEM(pmap_vector);
        return SKPLUGIN_ERR;
    }

    /* Add --pmap-file to apps that accept RWREC: rwcut, rwsort, etc */
    err = skpinRegOption2(pmap_file_option,
                          REQUIRED_ARG,
                          PMAP_FILE_HELP(
                              "\tfield names.  As such, this switch must"
                              " precede the --fields switch."), NULL,
                          pmapfile_handler, NULL,
                          2,
                          SKPLUGIN_FN_REC_TO_TEXT,
                          SKPLUGIN_FN_REC_TO_BIN);
    if (err == SKPLUGIN_ERR_FATAL) {
        return err;
    }

    /* Add --pmap-column-width to apps that produce TEXT: rwcut, rwuniq  */
    err = skpinRegOption2(pmap_column_width_option,
                          REQUIRED_ARG,
                          "Maximum column width to use for output.", NULL,
                          pmap_column_width_handler, NULL,
                          2,
                          SKPLUGIN_FN_REC_TO_TEXT,
                          SKPLUGIN_FN_BIN_TO_TEXT);
    if (err == SKPLUGIN_ERR_FATAL) {
        return err;
    }

    /* Add --pmap-file to rwfilter */
    err = skpinRegOption2(pmap_file_option,
                          REQUIRED_ARG,
                          PMAP_FILE_HELP(
                              "\tfiltering switches.  This switch must"
                              " precede other --pmap-* switches."), NULL,
                          pmapfile_handler, NULL,
                          1, SKPLUGIN_FN_FILTER);
    if (err == SKPLUGIN_ERR_FATAL) {
        return err;
    }

    /* Register cleanup function */
    skpinRegCleanup(pmap_teardown);

    return SKPLUGIN_OK;
}


/*
 *  skplugin_err_t pmap_column_width_handler(const char *opt_arg,
 *      void *cbdata);
 *
 *    Handles the pmap column width command line option.
 */
static skplugin_err_t
pmap_column_width_handler(
    const char         *opt_arg,
    void        UNUSED(*cbdata))
{
    uint32_t tmp32;
    int rv;

    if (max_column_width > 0) {
        skAppPrintErr("Invalid %s: Switch used multiple times",
                      pmap_column_width_option);
        return SKPLUGIN_ERR;
    }
    rv = skStringParseUint32(&tmp32, opt_arg, 1, INT32_MAX);
    if (rv) {
        skAppPrintErr("Invalid %s '%s': %s",
                      pmap_column_width_option, opt_arg,
                      skStringParseStrerror(rv));
        return SKPLUGIN_ERR;
    }
    max_column_width = tmp32;

    return SKPLUGIN_OK;
}


/*
 *  skplugin_err_t pmap_field_init(void *cbdata)
 *
 *    Initialization callback for pmap-based fields.  Sets the proper
 *    column width for the field in question.
 */
static skplugin_err_t
pmap_field_init(
    void               *cbdata)
{
    directed_pmap_data_t *dir_data  = (directed_pmap_data_t *)cbdata;
    const pmap_data_t    *pmap_data = dir_data->data;
    uint32_t              title_len;
    uint32_t              len;

    len = skPrefixMapDictionaryGetMaxWordSize(pmap_data->pmap);
    title_len = (uint32_t)strlen(dir_data->field_name);
    if (title_len > len) {
        len = title_len;
    }
    if (max_column_width > 0 && max_column_width < len) {
        len = max_column_width;
    }

    skpinSetFieldWidths(dir_data->field, len, 4);

    return SKPLUGIN_OK;
}


/*
 *  void pmap_data_destroy(pmap_data_t *data)
 *
 *      Destroys and frees a pmap_data_t object.
 */
static void
pmap_data_destroy(
    pmap_data_t        *data)
{
    if (data) {
        FREE_NONNULL(free, data->mapname);
        FREE_NONNULL(free, data->filepath);
        FREE_NONNULL(skPrefixMapDelete, data->pmap);
        FREE_NONNULL(free, data->sdir.val_bitmap);
        FREE_NONNULL(free, data->ddir.val_bitmap);
        FREE_NONNULL(free, data->adir.val_bitmap);
        FREE_NONNULL(free, data->sdir.filter_option);
        FREE_NONNULL(free, data->ddir.filter_option);
        FREE_NONNULL(free, data->adir.filter_option);
        FREE_NONNULL(free, data->sdir.field_name);
        FREE_NONNULL(free, data->ddir.field_name);
        assert(data->adir.field_name == NULL);
        free(data);
    }
}

/*
 *  void pmap_filter_help(FILE *fh, const struct option *option, void *cbdata)
 *
 *    Writes dynamically created option help for filter options to fh.
 */
static void
pmap_filter_help(
    FILE                   *fh,
    const struct option    *option,
    void                   *cbdata)
{
    directed_pmap_data_t *dir_data  = (directed_pmap_data_t *)cbdata;
    pmap_data_t          *pmap_data = dir_data->data;

    fprintf(fh, "--%s %s. ", option->name, SK_OPTION_HAS_ARG(*option));
    switch (dir_data->dir) {
      case DIR_SOURCE:
        switch (skPrefixMapGetContentType(pmap_data->pmap)) {
          case SKPREFIXMAP_CONT_ADDR_V4:
          case SKPREFIXMAP_CONT_ADDR_V6:
            fprintf(fh, "Source address");
            break;
          case SKPREFIXMAP_CONT_PROTO_PORT:
            fprintf(fh, "Protocol/Source-port pair");
            break;
        }

        fprintf(fh, (" map to a label specified\n"
                     "\tin this comma separated list of labels."
                     "  The mapping is defined by the\n"
                     "\tprefix map file '%s'"),
                pmap_data->filepath);
        break;
      case DIR_DEST:
        fprintf(fh, "As previous switch for the ");
        switch (skPrefixMapGetContentType(pmap_data->pmap)) {
          case SKPREFIXMAP_CONT_ADDR_V4:
          case SKPREFIXMAP_CONT_ADDR_V6:
            fprintf(fh, "destination address");
            break;
          case SKPREFIXMAP_CONT_PROTO_PORT:
            fprintf(fh, "protocol/dest-port pair");
            break;
        }
        break;
      case DIR_ANY:
        fprintf(fh, "As previous switch for either ");
        switch (skPrefixMapGetContentType(pmap_data->pmap)) {
          case SKPREFIXMAP_CONT_ADDR_V4:
          case SKPREFIXMAP_CONT_ADDR_V6:
            fprintf(fh, "source or destination address");
            break;
          case SKPREFIXMAP_CONT_PROTO_PORT:
            fprintf(fh, "protocol/source or destination port pair");
            break;
        }
        break;
    }
    fprintf(fh, "\n");
}


/*
 *  skplugin_err_t pmap_handle_filter_option(const char *opt_arg, void *cbdata)
 *
 *    Option handler for dynamically generated rwfilter options.
 */
static skplugin_err_t
pmap_handle_filter_option(
    const char         *opt_arg,
    void               *cbdata)
{
    directed_pmap_data_t *dir_data  = (directed_pmap_data_t *)cbdata;
    pmap_data_t          *pmap_data = dir_data->data;
    int                   new_filter;
    skplugin_callbacks_t  regdata;

    memset(&regdata, 0, sizeof(regdata));
    regdata.filter = pmap_filter_fn;

    if (ignore_prefix_map) {
        static int filter_registered = 0;

        /* register the filter but don't create the bitmap. we have to
         * register the filter in case this is the only filtering
         * option the user provided. */
        if (filter_registered) {
            return SKPLUGIN_OK;
        }

        return skpinRegFilter(NULL, &regdata, pmap_data);
    }

    /* If the source, dest, and any val_bitmaps are all null, this is
     * a new filter */
    new_filter = ((pmap_data->sdir.val_bitmap == NULL)
                  && (pmap_data->ddir.val_bitmap == NULL)
                  && (pmap_data->adir.val_bitmap == NULL));

    /* Add the arguments to the appropriate bitmap */
    if (pmapFilterSetupBitmap(&dir_data->val_bitmap, &dir_data->size_bitmap,
                              pmap_data->pmap, opt_arg, pmap_data->filepath))
    {
        return SKPLUGIN_ERR;
    }

    /* If this filter hasn't already been added, add it. */
    if (new_filter) {
        return skpinRegFilter(NULL, &regdata, pmap_data);
    }

    return SKPLUGIN_OK;
}


/*
 *  skplugin_err_t pmapfile_handler(const char *opt_arg, void *cbdata)
 *
 *    Handler for --pmap-file option.  Actually registers the filter and
 *    fields.
 */
static skplugin_err_t
pmapfile_handler(
    const char         *opt_arg,
    void        UNUSED(*cbdata))
{
    /* Whether we have seen any unnamed pmaps */
    static int           have_unnamed_pmap = 0;
    skPrefixMapErr_t     map_error         = SKPREFIXMAP_OK;
    skstream_t          *stream            = NULL;
    skPrefixMap_t       *prefix_map        = NULL;
    pmap_data_t         *pmap_data         = NULL;
    int                  ok;
    const char          *filename;
    const char          *sep;
    const char          *mapname           = NULL;
    size_t               namelen           = 0;
    char                 prefixed_name[PATH_MAX];
    size_t               i;
    ssize_t              sz;
    int                  rv                = SKPLUGIN_ERR;
    skplugin_callbacks_t regdata;

    /* We can only have one pmap whenever we have any pmap without a
     * mapname.  If we've seen one and enter this function a second
     * time, it is an error */
    if (have_unnamed_pmap) {
        skAppPrintErr(("Invalid %s: You may use only one prefix map"
                       " when you are\n"
                       "\tusing a prefix map without specifying a mapname"),
                      pmap_file_option);
        return SKPLUGIN_ERR;
    }

    /* Parse the argument into a field name and file name */
    sep = strchr(opt_arg, ':');
    if (NULL == sep) {
        /* We do not have a mapname.  We'll check for one in the pmap
         * once we read it. */
        filename = opt_arg;
    } else if (sep == opt_arg) {
        /* Treat a 0-length mapname on the command as having none.
         * Allows use of default mapname for files that contain the
         * separator. */
        filename = sep + 1;
    } else {
        /* A mapname was supplied on the command line */
        if (sep == opt_arg) {
            skAppPrintErr("Invalid %s: Zero length mapnames are not allowed",
                          pmap_file_option);
            return SKPLUGIN_ERR;
        }
        if (memchr(opt_arg, ',', sep - opt_arg) != NULL) {
            skAppPrintErr("Invalid %s: The mapname may not include a comma",
                          pmap_file_option);
            return SKPLUGIN_ERR;
        }
        mapname = opt_arg;
        filename = sep + 1;
        namelen = sep - opt_arg;
    }

    ok = skpinOpenDataInputStream(&stream, SK_CONTENT_SILK, filename);
    if (ok == -1) {
        /* problem opening file */
        skAppPrintErr("Failed to open the prefix map file '%s'",
                      filename);
        return SKPLUGIN_ERR;
    }
    if (ok == 1) {
        /* master needs to process the file, since it may contain the
         * map name we use for creating switches */
        if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))
            || (rv = skStreamBind(stream, filename))
            || (rv = skStreamOpen(stream)))
        {
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            skStreamDestroy(&stream);
            return SKPLUGIN_ERR;
        }

        /* the master can ignore the file for filtering */
        ignore_prefix_map = 1;
    }

    map_error = skPrefixMapRead(&prefix_map, stream);
    if (SKPREFIXMAP_OK != map_error) {
        if (SKPREFIXMAP_ERR_IO == map_error) {
            skStreamPrintLastErr(stream, skStreamGetLastReturnValue(stream),
                                 &skAppPrintErr);
        } else {
            skAppPrintErr("Failed to read the prefix map file '%s': %s",
                          opt_arg, skPrefixMapStrerror(map_error));
        }
        skStreamDestroy(&stream);
        return SKPLUGIN_ERR;
    }
    skStreamDestroy(&stream);

    if (NULL == mapname) {
        /* No mapname was supplied on the command line.  Check for a
         * mapname insided the pmap. */
        mapname = skPrefixMapGetMapName(prefix_map);
        if (mapname) {
            /* The pmap supplied a mapname */
            namelen = strlen(mapname);
        } else {
            /* No mapname.  Accept for legacy purposes, unless we have
             * read any other pmaps */
            have_unnamed_pmap = 1;
            if (skVectorGetCount(pmap_vector) != 0) {
                skAppPrintErr(("Invalid %s: You may use only one prefix map"
                               " when you are\n"
                               "\t using a prefix map without"
                               " specifying a mapname"),
                              pmap_file_option);
                goto END;
            }
        }
    }

    /* Allocate the pmap_data structure */
    pmap_data = (pmap_data_t *)calloc(1, sizeof(*pmap_data));
    if (pmap_data == NULL) {
        ERR_NO_MEM(pmap_data);
        rv = SKPLUGIN_ERR_FATAL;
        goto END;
    }

    /* pmap_data now "owns" prefix_map */
    pmap_data->pmap = prefix_map;
    prefix_map = NULL;

    /* Cache the content type */
    pmap_data->type = skPrefixMapGetContentType(pmap_data->pmap);

    /* Fill the direction structure for each direction */
    pmap_data->sdir.dir = DIR_SOURCE;
    pmap_data->ddir.dir = DIR_DEST;
    pmap_data->adir.dir = DIR_ANY;
    pmap_data->sdir.data = pmap_data;
    pmap_data->ddir.data = pmap_data;
    pmap_data->adir.data = pmap_data;

    /* Record the path to the pmap file */
    pmap_data->filepath = strdup(filename);
    if (NULL == pmap_data->filepath) {
        ERR_NO_MEM(pmap_data->filepath);
        rv = SKPLUGIN_ERR_FATAL;
        goto END;
    }

    if (mapname == NULL)  {
        /* Pmap without a mapname. */

        /* Add the proper legacy option names to the pmap_data structure */
        switch (pmap_data->type) {
          case SKPREFIXMAP_CONT_ADDR_V4:
          case SKPREFIXMAP_CONT_ADDR_V6:
            pmap_data->sdir.filter_option = strdup(pmap_saddress_option);
            pmap_data->ddir.filter_option = strdup(pmap_daddress_option);
            pmap_data->adir.filter_option = strdup(pmap_aaddress_option);
            break;
          case SKPREFIXMAP_CONT_PROTO_PORT:
            pmap_data->sdir.filter_option = strdup(pmap_sport_proto_option);
            pmap_data->ddir.filter_option = strdup(pmap_dport_proto_option);
            pmap_data->adir.filter_option = strdup(pmap_aport_proto_option);
            break;
        }
        if ((pmap_data->sdir.filter_option == NULL)
            || (pmap_data->ddir.filter_option == NULL)
            || (pmap_data->adir.filter_option == NULL))
        {
            ERR_NO_MEM(filter_option);
            rv = SKPLUGIN_ERR_FATAL;
            goto END;
        }
        pmap_data->mapname = strdup(pmap_title_val);
        pmap_data->sdir.field_name = strdup(pmap_title_sval);
        pmap_data->ddir.field_name = strdup(pmap_title_dval);
        if ((pmap_data->mapname == NULL)
            || (pmap_data->sdir.field_name == NULL)
            || (pmap_data->ddir.field_name == NULL))
        {
            ERR_NO_MEM(field_name);
            rv = SKPLUGIN_ERR_FATAL;
            goto END;
        }

    } else { /* if (mapname == NULL) */

        /* Create the field names */
        pmap_data->mapname = (char *)malloc(namelen + 1);
        if (NULL == pmap_data->mapname) {
            ERR_NO_MEM(pmap_data->mapname);
            rv = SKPLUGIN_ERR_FATAL;
            goto END;
        }
        strncpy(pmap_data->mapname, mapname, namelen + 1);
        pmap_data->mapname[namelen] = '\0';

        /* Create the destination-themed names */
        sz = snprintf(prefixed_name, sizeof(prefixed_name), "%s%s%s",
                      pmap_prefix, src_dir_name, pmap_data->mapname);
        if ((size_t)sz >= sizeof(prefixed_name)) {
            skAppPrintErr("mapname is too long\n");
            rv = SKPLUGIN_ERR_FATAL;
            goto END;
        }
        pmap_data->sdir.filter_option = strdup(prefixed_name);
        pmap_data->sdir.field_name = strdup(prefixed_name + pmap_prefix_len);
        if ((pmap_data->sdir.filter_option == NULL)
            || (pmap_data->sdir.field_name == NULL))
        {
            ERR_NO_MEM(pmap_data->sdir);
            rv = SKPLUGIN_ERR_FATAL;
            goto END;
        }

        sz = snprintf(prefixed_name, sizeof(prefixed_name), "%s%s%s",
                      pmap_prefix, dst_dir_name, pmap_data->mapname);
        if ((size_t)sz >= sizeof(prefixed_name)) {
            skAppPrintErr("mapname is too long\n");
            rv = SKPLUGIN_ERR_FATAL;
            goto END;
        }
        pmap_data->ddir.filter_option = strdup(prefixed_name);
        pmap_data->ddir.field_name = strdup(prefixed_name + pmap_prefix_len);
        if ((pmap_data->ddir.filter_option == NULL)
            || (pmap_data->ddir.field_name == NULL))
        {
            ERR_NO_MEM(pmap_data->ddir);
            rv = SKPLUGIN_ERR_FATAL;
            goto END;
        }

        sz = snprintf(prefixed_name, sizeof(prefixed_name), "%s%s%s",
                      pmap_prefix, any_dir_name, pmap_data->mapname);
        if ((size_t)sz >= sizeof(prefixed_name)) {
            skAppPrintErr("mapname is too long\n");
            rv = SKPLUGIN_ERR_FATAL;
            goto END;
        }
        pmap_data->adir.filter_option = strdup(prefixed_name);
        if (pmap_data->adir.filter_option == NULL) {
            ERR_NO_MEM(pmap_data->ddir);
            rv = SKPLUGIN_ERR_FATAL;
            goto END;
        }

    } /* if (mapname == NULL) */


    /* Verify unique field names */
    for (i = 0; i < skVectorGetCount(pmap_vector); ++i) {
        pmap_data_t *p;

        skVectorGetValue(&p, pmap_vector, i);
        if ((strcmp(pmap_data->mapname, p->mapname) == 0) ||
            (strcmp(pmap_data->sdir.field_name, p->sdir.field_name) == 0) ||
            (strcmp(pmap_data->ddir.field_name, p->ddir.field_name) == 0))
        {
            skAppPrintErr(("Invalid %s: Multiple pmaps use the mapname '%s':\n"
                           "\t%s\n\t%s"),
                          pmap_file_option, pmap_data->mapname,
                          p->filepath, pmap_data->filepath);
            rv = SKPLUGIN_ERR;
            goto END;
        }
    }

    /* Register fields and filter options */
    memset(&regdata, 0, sizeof(regdata));
    regdata.init = pmap_field_init;
    regdata.column_width = 0;
    regdata.bin_bytes = 4;
    regdata.rec_to_text = pmap_text_fn;
    regdata.rec_to_bin = pmap_bin_fn;
    regdata.bin_to_text = pmap_bin_to_text_fn;

    for (i = 0; i < 2; ++i) {
        directed_pmap_data_t *dir = ((0 == i)
                                     ? &pmap_data->sdir
                                     : &pmap_data->ddir);

        skpinRegField(&dir->field, dir->field_name, NULL, &regdata, dir);
        skpinRegOption2(dir->filter_option,
                        REQUIRED_ARG,
                        NULL, &pmap_filter_help,
                        &pmap_handle_filter_option, dir,
                        1, SKPLUGIN_FN_FILTER);
    }

    /* Register the "any" filter separately */
    skpinRegOption2(pmap_data->adir.filter_option,
                    REQUIRED_ARG,
                    NULL, &pmap_filter_help,
                    &pmap_handle_filter_option, &pmap_data->adir,
                    1, SKPLUGIN_FN_FILTER);


    if (skVectorAppendValue(pmap_vector, &pmap_data)) {
        rv = SKPLUGIN_ERR_FATAL;
        goto END;
    }

    rv = SKPLUGIN_OK;

  END:
    if (rv != SKPLUGIN_OK) {
        if (prefix_map) {
            skPrefixMapDelete(prefix_map);
        }
        if (pmap_data) {
            pmap_data_destroy(pmap_data);
        }
    }
    return (skplugin_err_t)rv;
}


/*
 *  is_valid = pmapCheckValueIsValid(pmap, target);
 *
 *    Return 1 if any keys in the prefix map 'pmap' have a value of
 *    'target'.  Return 0 otherwise.
 */
static int
pmapCheckValueIsValid(
    const skPrefixMap_t    *prefix_map,
    uint32_t                target)
{
    skPrefixMapIterator_t iter;
    union key_un {
        skPrefixMapProtoPort_t  pp;
        skipaddr_t              addr;
    } key_beg, key_end;
    uint32_t val;

    skPrefixMapIteratorBind(&iter, prefix_map);
    while (skPrefixMapIteratorNext(&iter, &key_beg, &key_end, &val)
           != SK_ITERATOR_NO_MORE_ENTRIES)
    {
        if (val == target) {
            return 1;
        }
    }
    return 0;
}


/*
 *  int pmapFilterSetupBitmap(uint32_t **bitmap, uint32_t **bitmap_size,
 *                            skPrefixMap_t *prefix_map,
 *                            char *opt_arg, char *pmap_path);
 *
 *    Parses 'opt_arg', a string representation of comma-separated
 *    pmap values to filter on with respect to the given 'prefix_map',
 *    and sets the relevant bits in the bit-vector 'bitmap', whose
 *    current size is 'bitmap_size'.  Creates the bitmap if necessary
 *    and may adjust the bitmap's size.  Returns -1 if the argument
 *    was not parsable or if there is a memory allocation error.
 */
static int
pmapFilterSetupBitmap(
    uint32_t              **bitmap_arg,
    uint32_t               *bitmap_size,
    const skPrefixMap_t    *prefix_map,
    const char             *opt_arg,
    const char             *pmap_path)
{
    uint32_t bmap_len;
    char *arg_copy = NULL;
    char *label;
    char *next_token;
    uint32_t code;
    uint32_t *bitmap = NULL;
    int rv = -1;

    if (ignore_prefix_map) {
        return 0;
    }

    assert(bitmap_arg);
    assert(prefix_map);
    assert(opt_arg);

    /* Get a pointer to the bitmap---creating it if required */
    if (*bitmap_arg) {
        bitmap = *bitmap_arg;
    } else {
        /* Allocate the bitmap. */
        bmap_len = skPrefixMapDictionaryGetWordCount(prefix_map);

        bitmap = (uint32_t*)calloc(PMAP_BMAP_SIZE(bmap_len), sizeof(uint32_t));
        if (NULL == bitmap) {
            ERR_NO_MEM(bitmap);
            goto END;
        }
        *bitmap_size = bmap_len;
    }

    /* Make a modifiable copy of the user's argument */
    arg_copy = strdup(opt_arg);
    if (arg_copy == NULL) {
        ERR_NO_MEM(arg_copy);
        goto END;
    }

    /* Find each token which should be a label in the pmap */
    next_token = arg_copy;
    while ((label = strsep(&next_token, ",")) != NULL) {
        code = skPrefixMapDictionaryLookup(prefix_map, label);
        if (SKPREFIXMAP_NOT_FOUND == code) {
            /* label was not found in dictionary.  if label is a
             * number and if any key in the prefix map has that number
             * as its value, set that position in the bitmap,
             * reallocating the bitmap if necessary */
            if (skStringParseUint32(&code, label, 0, SKPREFIXMAP_MAX_VALUE)) {
                skAppPrintErr(("The label '%s' was not found in prefix map\n"
                               "\tdictionary loaded from '%s'"),
                              label, pmap_path);
                goto END;
            }

            if (0 == pmapCheckValueIsValid(prefix_map, code)) {
                skAppPrintErr(("The value '%s' was not found in prefix map\n"
                               "\tdictionary loaded from '%s'"),
                              label, pmap_path);
                goto END;
            }

            /* ensure bitmap can set the bit 'code' */
            bmap_len = code + 1;

            /* see if we need to grow the bitmap */
            if (PMAP_BMAP_SIZE(bmap_len) > PMAP_BMAP_SIZE(*bitmap_size)) {
                uint32_t *old = bitmap;
                bitmap = (uint32_t*)realloc(bitmap, (PMAP_BMAP_SIZE(bmap_len)
                                                     * sizeof(uint32_t)));
                if (NULL == bitmap) {
                    bitmap = old;
                    ERR_NO_MEM(bitmap);
                    goto END;
                }
                memset(&bitmap[PMAP_BMAP_SIZE(*bitmap_size)], 0,
                       ((PMAP_BMAP_SIZE(bmap_len)-PMAP_BMAP_SIZE(*bitmap_size))
                        * sizeof(uint32_t)));
            }
            /* alway set bitmap size to maximum number */
            if (bmap_len > *bitmap_size) {
                *bitmap_size = bmap_len;
            }
        }
        PMAP_BMAP_SET(bitmap, code);
    }

    /* Success */
    rv = 0;
    *bitmap_arg = bitmap;

  END:
    if (*bitmap_arg == NULL && bitmap != NULL) {
        free(bitmap);
    }
    if (arg_copy) {
        free(arg_copy);
    }
    return rv;
}


/*
 *  skplugin_err_t pmap_filter(rwRec *rwrec, void *data, void **extra);
 *
 *    The function actually used to implement filtering for the filter
 *    plugin.  Returns SKPLUGIN_FILTER_PASS if the record passes the
 *    filter, SKPLUGIN_FILTER_FAIL if it fails the filter.
 */
static skplugin_err_t
pmap_filter_fn(
    const rwRec            *rwrec,
    void                   *data,
    void           UNUSED(**extra))
{
    pmap_data_t            *pmap_data = (pmap_data_t *)data;
    skipaddr_t              addr;
    skPrefixMapProtoPort_t  pp;
    uint32_t                code;

    assert(ignore_prefix_map == 0);

    switch (pmap_data->type) {
      case SKPREFIXMAP_CONT_ADDR_V4:
      case SKPREFIXMAP_CONT_ADDR_V6:
        if (pmap_data->sdir.val_bitmap) {
            rwRecMemGetSIP(rwrec, &addr);
            code = skPrefixMapFindValue(pmap_data->pmap, &addr);
            if (!PMAP_BMAP_CHECK(pmap_data->sdir.val_bitmap,
                                 pmap_data->sdir.size_bitmap, code))
            {
                return SKPLUGIN_FILTER_FAIL; /* Reject */
            }
        }
        if (pmap_data->ddir.val_bitmap) {
            rwRecMemGetDIP(rwrec, &addr);
            code = skPrefixMapFindValue(pmap_data->pmap, &addr);
            if (!PMAP_BMAP_CHECK(pmap_data->ddir.val_bitmap,
                                 pmap_data->ddir.size_bitmap, code))
            {
                return SKPLUGIN_FILTER_FAIL; /* Reject */
            }
        }
        if (pmap_data->adir.val_bitmap) {
            rwRecMemGetSIP(rwrec, &addr);
            code = skPrefixMapFindValue(pmap_data->pmap, &addr);
            if (!PMAP_BMAP_CHECK(pmap_data->adir.val_bitmap,
                                 pmap_data->adir.size_bitmap, code))
            {
                rwRecMemGetDIP(rwrec, &addr);
                code = skPrefixMapFindValue(pmap_data->pmap, &addr);
                if (!PMAP_BMAP_CHECK(pmap_data->adir.val_bitmap,
                                     pmap_data->adir.size_bitmap, code))
                {
                    return SKPLUGIN_FILTER_FAIL; /* Reject */
                }
            }
        }
        return SKPLUGIN_FILTER_PASS; /* Accept */

      case SKPREFIXMAP_CONT_PROTO_PORT:
        pp.proto = rwRecGetProto(rwrec);
        if (pmap_data->sdir.val_bitmap) {
            pp.port = rwRecGetSPort(rwrec);
            code = skPrefixMapFindValue(pmap_data->pmap, &pp);
            if (!PMAP_BMAP_CHECK(pmap_data->sdir.val_bitmap,
                                 pmap_data->sdir.size_bitmap, code))
            {
                return SKPLUGIN_FILTER_FAIL; /* Reject */
            }
        }
        if (pmap_data->ddir.val_bitmap) {
            pp.port = rwRecGetDPort(rwrec);
            code = skPrefixMapFindValue(pmap_data->pmap, &pp);
            if (!PMAP_BMAP_CHECK(pmap_data->ddir.val_bitmap,
                                 pmap_data->ddir.size_bitmap, code))
            {
                return SKPLUGIN_FILTER_FAIL; /* Reject */
            }
        }
        if (pmap_data->adir.val_bitmap) {
            pp.port = rwRecGetSPort(rwrec);
            code = skPrefixMapFindValue(pmap_data->pmap, &pp);
            if (!PMAP_BMAP_CHECK(pmap_data->adir.val_bitmap,
                                 pmap_data->adir.size_bitmap, code))
            {
                pp.port = rwRecGetDPort(rwrec);
                code = skPrefixMapFindValue(pmap_data->pmap, &pp);
                if (!PMAP_BMAP_CHECK(pmap_data->adir.val_bitmap,
                                     pmap_data->adir.size_bitmap, code))
                {
                    return SKPLUGIN_FILTER_FAIL; /* Reject */
                }
            }
        }
        return SKPLUGIN_FILTER_PASS; /* Accept */
    }

    /* Unknown type: Accept all */
    return SKPLUGIN_FILTER_PASS; /* NOTREACHED */
}


/*
 * This function is used to convert from an rwrec to a text value for
 * a field.
 */
static skplugin_err_t
pmap_text_fn(
    const rwRec            *rec,
    char                   *dest,
    size_t                  width,
    void                   *data,
    void           UNUSED(**extra))
{
    directed_pmap_data_t   *dir_data  = (directed_pmap_data_t *)data;
    pmap_data_t            *pmap_data = dir_data->data;
    skipaddr_t              addr;
    skPrefixMapProtoPort_t  pp;
    int                     rv;

    if (SKPREFIXMAP_CONT_PROTO_PORT == pmap_data->type) {
        pp.proto = rwRecGetProto(rec);
        switch (dir_data->dir) {
          case DIR_SOURCE:
            pp.port = rwRecGetSPort(rec);
            break;
          case DIR_DEST:
            pp.port = rwRecGetDPort(rec);
            break;
          case DIR_ANY:
            skAbortBadCase(dir_data->dir);
        }
        rv = skPrefixMapFindString(pmap_data->pmap, &pp, dest, width);
    } else {
        switch (dir_data->dir) {
          case DIR_SOURCE:
            rwRecMemGetSIP(rec, &addr);
            break;
          case DIR_DEST:
            rwRecMemGetDIP(rec, &addr);
            break;
          case DIR_ANY:
            skAbortBadCase(dir_data->dir);
        }
        rv = skPrefixMapFindString(pmap_data->pmap, &addr, dest, width);
    }

    return (rv >= 0) ? SKPLUGIN_OK : SKPLUGIN_ERR;
}



/*
 * This function is used to convert from an rwrec to a binary value
 * for sorting or determining unique values.
 */
static skplugin_err_t
pmap_bin_fn(
    const rwRec            *rec,
    uint8_t                *dest,
    void                   *data,
    void           UNUSED(**extra))
{
    directed_pmap_data_t   *dir_data  = (directed_pmap_data_t *)data;
    pmap_data_t            *pmap_data = dir_data->data;
    skipaddr_t              addr;
    skPrefixMapProtoPort_t  pp;
    uint32_t                code;

    if (SKPREFIXMAP_CONT_PROTO_PORT == pmap_data->type) {
        pp.proto = rwRecGetProto(rec);
        switch (dir_data->dir) {
          case DIR_SOURCE:
            pp.port = rwRecGetSPort(rec);
            break;
          case DIR_DEST:
            pp.port = rwRecGetDPort(rec);
            break;
          case DIR_ANY:
            skAbortBadCase(dir_data->dir);
        }
        code = htonl(skPrefixMapFindValue(pmap_data->pmap, &pp));
    } else {
        switch (dir_data->dir) {
          case DIR_SOURCE:
            rwRecMemGetSIP(rec, &addr);
            break;
          case DIR_DEST:
            rwRecMemGetDIP(rec, &addr);
            break;
          case DIR_ANY:
            skAbortBadCase(dir_data->dir);
        }
        code = htonl(skPrefixMapFindValue(pmap_data->pmap, &addr));
    }

    memcpy(dest, &code, sizeof(code));

    return SKPLUGIN_OK;
}


/*
 * This function is for mapping from binary values produced by
 * pmap_bin_fn to text.
 */
static skplugin_err_t
pmap_bin_to_text_fn(
    const uint8_t      *bin,
    char               *dest,
    size_t              width,
    void               *data)
{
    skPrefixMap_t *pmap = ((directed_pmap_data_t *)data)->data->pmap;
    uint32_t       key;
    int            rv;

    key = ((bin[0] << 24) | (bin[1] << 16) | (bin[2] << 8) | (bin[3]));
    rv = skPrefixMapDictionaryGetEntry(pmap, key, dest, width);
    return (rv >= 0) ? SKPLUGIN_OK : SKPLUGIN_ERR;
}


/*
 *  void pmap_teardown(void);
 *
 *     Called by skplugin to tear down this plugin.
 */
static void
pmap_teardown(
    void)
{
    size_t       i;
    pmap_data_t *pmap_data;

    if (pmap_vector) {
        for (i = 0; i < skVectorGetCount(pmap_vector); ++i) {
            ASSERT_RESULT(skVectorGetValue(&pmap_data, pmap_vector, i),
                          int, 0);
            pmap_data_destroy(pmap_data);
        }

        skVectorDestroy(pmap_vector);
        pmap_vector = NULL;
    }
}

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
