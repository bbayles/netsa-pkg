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
 *  skite.c
 *
 *    Manages access to the classes, types, and sensors that are read
 *    from the silk.conf file.
 *
 *    Maps class,type,sensor,time tuples to file names in the data
 *    repository.
 *
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: sksite.c 05d39531ae59 2023-05-17 15:23:40Z mthomas $");

#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>
#include <silk/skstringmap.h>
#include <silk/redblack.h>
#include "sksiteconfig.h"
#ifdef __CYGWIN__
#include "skcygwin.h"
#endif

#ifdef  SKSITE_TRACE_LEVEL
#define TRACEMSG_LEVEL 1
#endif
/* use TRACEMSG_LEVEL as our tracing variable */
#define TRACEMSG(msg) TRACEMSG_TO_TRACEMSGLVL(1, msg)
#include <silk/sktracemsg.h>


/* TYPEDEFS AND DEFINES */

#define SILK_CONFIG_FILE_NAME "silk.conf"
#define SILK_DEFAULT_PATH_FORMAT "%T/%Y/%m/%d/%x"

/* if all other attempts to get a data root directory fail, use this */
#define FALLBACK_DATA_ROOTDIR "/data"

/* characters that may not appear in a flowtype (including a class name and a
 * type name): whitespace, double-quote('"'), single-quote('\''),
 * backslash('\\'), forward-slash('/'), comma (',') */
#define SITE_BAD_CHARS_FLOWTYPE  "\t\n\v\f\r \b\a\"'\\/,"

/* characters that may not appear in a sensor name: all characters that may
 * not appear in a flowtype plus underscore ('_') */
#define SITE_BAD_CHARS_SENSOR    "_" SITE_BAD_CHARS_FLOWTYPE


/*
 *  For each SKSITE_ERR_ code, define the default format to use
 */

#define SKSITE_ERR_CLASS_NO_DEFAULT_MSG                         \
    "The configuration file does not specify a default class"

#define SKSITE_ERR_CLASS_UNKNOWN_MSG            \
    "The class name '%s' is not recognized"

#define SKSITE_ERR_FLOWTYPE_NO_DELIM_MSG                                \
    "The flowtype '%s' does not include the class-type separator '%c'"

#define SKSITE_ERR_FLOWTYPE_TYPE_NOT_IN_CLASS_MSG               \
    "The flowtype '%s' uses a type that is not in the class"

#define SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS_MSG           \
    "The flowtype '%s' uses an unrecognized class name"

#define SKSITE_ERR_FLOWTYPE_UNKNOWN_TYPE_MSG            \
    "The flowtype '%s' uses an unrecognized type name"

#define SKSITE_ERR_SENSOR_NOT_IN_CLASSES_MSG                    \
    "Sensor '%s' is not a member of the specified class(es)"

#define SKSITE_ERR_TYPE_NOT_IN_CLASSES_MSG \
    "The type name '%s' is not recognized in the specified class(es)"

#define SKSITE_ERR_TYPE_UNKNOWN_MSG             \
    "The type name '%s' is not recognized"

#define SKSITE_ERR_UNKNOWN_SENSOR_MSG           \
    "The sensor name '%s' is not recognized"

#define SKSITE_ERR_UNKNOWN_SENSOR_ID_MSG                \
    "The sensor ID %s is not recognized"

#define SKSITE_ERR_SENSORGROUP_UNKNOWN_MSG              \
    "The sensor-group name '%s' is not recognized"

#define SKSITE_ERR_UTILS_OFFSET_MSG                     \
    "Sensor range/ID '%s' is invalid: %s"


/** Local Datatypes ***************************************************/

/* internal type for string lengths */
typedef unsigned int    site_strlen_t;

typedef struct sensor_struct_st {
    /* unique name for this sensor */
    const char         *sn_name;
    /* description of this sensor (for end-user use) */
    const char         *sn_description;
    /* vector of classes it belongs to */
    sk_vector_t        *sn_class_list;
    /* vector of groups it belongs to (for grouping in rwuniq,etc) */
    sk_vector_t        *sn_sensorgroup_list;
    /* length of the name */
    site_strlen_t       sn_name_strlen;
    /* the sensor's id--must be its position in the array */
    sk_sensor_id_t      sn_id;
} sensor_struct_t;

typedef struct sensorgroup_struct_st {
    /* unique name for this group */
    const char         *sg_name;
    /* vector of sensors (by sk_sensor_id_t) in this group */
    sk_vector_t        *sg_sensor_list;
    /* length of the name */
    site_strlen_t       sg_name_strlen;
    /* the group's id--must be its position in the array */
    sk_sensorgroup_id_t sg_id;
} sensorgroup_struct_t;

typedef struct class_struct_st {
    /* unique name for this class */
    const char         *cl_name;
    /* vector of sensors (by sk_sensor_id_t) in class */
    sk_vector_t        *cl_sensor_list;
    /* vector of flowtypes (by sk_flowtype_id_t) in class */
    sk_vector_t        *cl_flowtype_list;
    /* vector of class's default flowtypes (by sk_flowtype_id_t) */
    sk_vector_t        *cl_default_flowtype_list;
    /* length of the name */
    site_strlen_t       cl_name_strlen;
    /* the class's id--must be its position in the array */
    sk_class_id_t       cl_id;
} class_struct_t;

typedef struct flowtype_struct_st {
    /* unique name for this flowtype */
    const char         *ft_name;
    /* unique name for this flowtype within its class */
    const char         *ft_type;
    /* length of name */
    site_strlen_t       ft_name_strlen;
    /* length of type */
    site_strlen_t       ft_type_strlen;
    /* the class ID */
    sk_class_id_t       ft_class;
    /* the flowtype's id--must be its position in the array */
    sk_flowtype_id_t    ft_id;
} flowtype_struct_t;

/* The %-conversion characters supported by the path-format; exported
 * so it can be checked during silk.conf parsing */
const char path_format_conversions[] = "%CFHNTYdfmnx";


typedef enum site_token_status_en {
    /* Parsed a token */
    SITE_TOKEN_OK = 0,
    /* No more data */
    SITE_TOKEN_END_OF_DATA = 1,
    /* Encountered an error; added error to iterator */
    SITE_TOKEN_ERR = -1,
    /* Encountered an error; unable to push error onto error iter */
    SITE_TOKEN_ERR_FATAL = -2
} site_token_status_t;


/** Options ***********************************************************/

typedef enum {
    OPT_SITE_CONFIG_FILE
} siteOptionsEnum;

/* switch */
static struct option siteOptions[] = {
    {"site-config-file",        REQUIRED_ARG, 0, OPT_SITE_CONFIG_FILE},
    {0,0,0,0}                   /* sentinel */
};


/** Config Storage ****************************************************/

#define MIN_FIELD_SIZE 3
#define INVALID_LABEL "?"


static char data_rootdir[PATH_MAX];
static char silk_config_file[PATH_MAX];
static char path_format[PATH_MAX];
static char packing_logic_path[PATH_MAX];


/* flags the caller passed to sksiteOptionsRegister() */
static uint32_t     site_opt_flags = 0;

/* 0 if not yet configured, 1 if configuration succeeded, -1 if it
 * failed due to parse errors.  Calling sksiteConfigure() with a
 * non-existent file does not change its value */
static int          configured = 0;

/* The list of sensors (vector of pointers to sensor_struct_t), the
 * max field width, and the min and max known IDs. */
static sk_vector_t     *sensor_list;
static site_strlen_t    sensor_max_name_strlen = MIN_FIELD_SIZE;
static int              sensor_min_id = -1;
static int              sensor_max_id = -1;

/* Data structure to find sensors by name */
static struct rbtree   *sensor_map;

/* Default class for fglob. */
static sk_class_id_t    default_class = SK_INVALID_CLASS;

/* The list of classes (vector of pointers to class_struct_t), the max
 * field width, and the max known ID. */
static sk_vector_t     *class_list;
static site_strlen_t    class_max_name_strlen = MIN_FIELD_SIZE;
static int              class_max_id = -1;

/* The list of sensorgroups (vector of pointers to
 * sensorgroup_struct_t), the max field width, and the max known
 * ID. */
static sk_vector_t     *sensorgroup_list;
static site_strlen_t    sensorgroup_max_name_strlen = MIN_FIELD_SIZE;
static int              sensorgroup_max_id = -1;

/* Data structure to find sensorgroups by name */
static struct rbtree   *sensorgroup_map;

/* The list of flowtypes (vector of pointers to flowtype_struct_t),
 * the max field width of the flowtype, the max field width of the
 * type, and the max known ID. */
static sk_vector_t     *flowtype_list;
static site_strlen_t    flowtype_max_name_strlen = MIN_FIELD_SIZE;
static site_strlen_t    flowtype_max_type_strlen = MIN_FIELD_SIZE;
static int              flowtype_max_id = -1;

/** Local Function Prototypes *****************************************/

static int siteOptionsHandler(clientData cData, int opt_index, char *opt_arg);

static void
siteSensorFree(
    sensor_struct_t    *sn);
static void
siteClassFree(
    class_struct_t     *cl);
static void
siteSensorgroupFree(
    sensorgroup_struct_t   *sg);
static void
siteFlowtypeFree(
    flowtype_struct_t  *ft);
static int
siteSensorCompare(
    const void         *obj1,
    const void         *obj2,
    const void         *ctx);
static sk_sensor_id_t
siteSensorLookup2(
    const char         *sensor_name,
    site_strlen_t       sensor_name_len);
static int
siteSensorgroupCompare(
    const void         *obj1,
    const void         *obj2,
    const void         *ctx);
static sk_sensorgroup_id_t
siteSensorgroupLookup2(
    const char         *sensorgroup_name,
    site_strlen_t       sensorgroup_name_len);
static int
siteErrorIterPush(
    sksite_error_iterator_t    *iter,
    int                         error_code,
    const char                 *format,
    ...)
    SK_CHECK_PRINTF(3, 4);


/**********************************************************************/

int
sksiteInitialize(
    int          UNUSED(levels))
{
    static int initialized = 0;
    const char *silk_data_rootdir_env;
    int silk_data_rootdir_set = 0;

    if (initialized) {
        return 0;
    }
    initialized = 1;

    /* store the root_directory from configure, or the env var if given */
    silk_data_rootdir_env = getenv(SILK_DATA_ROOTDIR_ENVAR);
    if (silk_data_rootdir_env) {
        /* env var is defined, use it instead */
        while (isspace((int)*silk_data_rootdir_env)) {
            ++silk_data_rootdir_env;
        }
        if (*silk_data_rootdir_env) {
            if (sksiteSetRootDir(silk_data_rootdir_env)) {
                skAppPrintErr("Problem setting data root directory "
                              "from environment");
                skAbort();
            }
            silk_data_rootdir_set = 1;
        }
    }
    if (!silk_data_rootdir_set) {
        if (sksiteSetRootDir(sksiteGetDefaultRootDir())) {
            skAppPrintErr("Data root directory is too long");
            skAbort();
        }
    }

    /* Basic initialization of site config data structures */
    strncpy(path_format, SILK_DEFAULT_PATH_FORMAT, sizeof(path_format));
    sensor_list = skVectorNew(sizeof(sensor_struct_t *));
    class_list = skVectorNew(sizeof(class_struct_t *));
    sensorgroup_list = skVectorNew(sizeof(sensorgroup_struct_t *));
    flowtype_list = skVectorNew(sizeof(flowtype_struct_t *));

    sensor_map = rbinit(siteSensorCompare, NULL);
    sensorgroup_map = rbinit(siteSensorgroupCompare, NULL);

    return 0;
}


int
sksiteOptionsRegister(
    uint32_t            flags)
{
    site_opt_flags = flags;

    /* Add a --site-config-file option if requested */
    if (site_opt_flags & SK_SITE_FLAG_CONFIG_FILE) {
        if (skOptionsRegister(siteOptions, &siteOptionsHandler, NULL))
        {
            return -1;
        }
    }
    return 0;
}


void
sksiteOptionsUsage(
    FILE               *fh)
{
#define MIN_TEXT_ON_LINE  15
#define MAX_TEXT_ON_LINE  72

    char *cp, *ep, *sp;
    char path[PATH_MAX];
    char buf[3 * PATH_MAX];

    /* print where we would get the silk.conf file, as well as the
     * other places we might look. */
    if (site_opt_flags & SK_SITE_FLAG_CONFIG_FILE) {
        fprintf(fh, "--%s %s. Location of the site configuration file.\n",
                siteOptions[OPT_SITE_CONFIG_FILE].name,
                SK_OPTION_HAS_ARG(siteOptions[OPT_SITE_CONFIG_FILE]));

        /* put the text into a buffer, and then wrap the text in the
         * buffer at space characters. */
        snprintf(buf, sizeof(buf),
                 ("Currently '%s'. Def. $" SILK_CONFIG_FILE_ENVAR ","
                  " $" SILK_DATA_ROOTDIR_ENVAR "/" SILK_CONFIG_FILE_NAME ","
                  " or '%s/" SILK_CONFIG_FILE_NAME "'"),
                 sksiteGetConfigPath(path, sizeof(path)),
                 sksiteGetDefaultRootDir());
        sp = buf;
        while (strlen(sp) > MAX_TEXT_ON_LINE) {
            cp = &sp[MIN_TEXT_ON_LINE];
            while ((ep = strchr(cp+1, ' ')) != NULL) {
                if (ep - sp > MAX_TEXT_ON_LINE) {
                    /* text is now too long */
                    if (cp == &sp[MIN_TEXT_ON_LINE]) {
                        /* this is the first space character we have
                         * on this line; so use it */
                        cp = ep;
                    }
                    break;
                }
                cp = ep;
            }
            if (cp == &sp[MIN_TEXT_ON_LINE]) {
                /* no space characters anywhere on the line */
                break;
            }
            assert(' ' == *cp);
            *cp = '\0';
            fprintf(fh, "\t%s\n", sp);
            sp = cp + 1;
        }
        if (*sp) {
            fprintf(fh, "\t%s\n", sp);
        }
    }
}


static int
siteOptionsHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    switch ((siteOptionsEnum)opt_index) {
      case OPT_SITE_CONFIG_FILE:
        assert(site_opt_flags & SK_SITE_FLAG_CONFIG_FILE);
        if (configured) {
            skAppPrintErr("Ignoring --%s: site already configured",
                          siteOptions[opt_index].name);
        } else if (!skFileExists(opt_arg)) {
            skAppPrintErr("Invalid --%s: file '%s' does not exist",
                          siteOptions[opt_index].name, opt_arg);
            return 1;
        } else if (sksiteSetConfigPath(opt_arg)) {
            skAppPrintErr("Invalid --%s: path name '%s' is too long",
                          siteOptions[opt_index].name, opt_arg);
            return 1;
        }
        sksiteConfigure(1);
        break;
    }
    return 0;
}


static char *
siteFindConfigPath(
    char               *buffer,
    size_t              bufsize)
{
    const char *silk_config_file_env;
    ssize_t len;

    /* use environment variable if set; do not check for existence */
    silk_config_file_env = getenv(SILK_CONFIG_FILE_ENVAR);
    if (silk_config_file_env) {
        while (isspace((int)*silk_config_file_env)) {
            ++silk_config_file_env;
        }
        if (*silk_config_file_env) {
            if (bufsize <= strlen(silk_config_file_env)) {
                return NULL;
            }
            strncpy(buffer, silk_config_file_env, bufsize);
            return buffer;
        }
    }

    /* does it exist in SILK_DATA_ROOTDIR/silk.conf ? */
    len = snprintf(buffer, bufsize, "%s/%s",
                   data_rootdir, SILK_CONFIG_FILE_NAME);
    if ((size_t)len > bufsize) {
        return NULL;
    }
    if (skFileExists(buffer)) {
        return buffer;
    }

    /* not under SILK_DATA_ROOTDIR, try SILK_PATH/share/silk and
     * ../share/silk/silk.conf */
    if (skFindFile(SILK_CONFIG_FILE_NAME, buffer, bufsize, 0)) {
        return buffer;
    }

    /* it is not anywhere; return SILK_DATA_ROOTDIR/silk.conf */
    len = snprintf(buffer, bufsize, "%s/%s",
                   data_rootdir, SILK_CONFIG_FILE_NAME);
    if ((size_t)len > bufsize) {
        return NULL;
    }
    return buffer;
}

/*
 *    Used by rbtree to compare two sensor_struct_t.
 */
static int
siteSensorCompare(
    const void *v_a,
    const void *v_b,
    const void  UNUSED(*ctx))
{
    const sensor_struct_t *a = (const sensor_struct_t *)v_a;
    const sensor_struct_t *b = (const sensor_struct_t *)v_b;

    int rv = (int)a->sn_name_strlen - (int)b->sn_name_strlen;
    if (0 != rv) {
        return rv;
    }
    return strcmp(a->sn_name, b->sn_name);
}

/*
 *    Used by rbtree to compare two sensorgroup_struct_t.
 */
static int
siteSensorgroupCompare(
    const void *v_a,
    const void *v_b,
    const void  UNUSED(*ctx))
{
    const sensorgroup_struct_t *a = (const sensorgroup_struct_t *)v_a;
    const sensorgroup_struct_t *b = (const sensorgroup_struct_t *)v_b;

    int rv = (int)a->sg_name_strlen - (int)b->sg_name_strlen;
    if (0 != rv) {
        return rv;
    }
    return strcmp(a->sg_name, b->sg_name);
}

int
sksiteConfigure(
    int                 verbose)
{
    char cl_name[SK_MAX_STRLEN_FLOWTYPE+1];
    sk_class_iter_t cl_iter;
    sk_class_id_t cl_id;
    sk_flowtype_iter_t ft_iter;
    sk_flowtype_id_t ft_id;

    /* once we've attempted to parse a file, this function no longer
     * attempts configuration */
    if (configured != 0) {
        return ((configured == -1) ? -1 : 0);
    }

    /* configuration hasn't happened yet.  attempt it. */
    if (silk_config_file[0]) {
        /* sksiteSetConfigPath() was called. does the file exist? */
        if (!skFileExists(silk_config_file)) {
            /* Missing file---do not modify 'configured' */
            if (verbose) {
                skAppPrintErr("Site configuration file not found");
            }
            return -2;
        }
    } else {
        /* no config file set yet.  try to find it.  only set
         * silk_config_file if we find an existing file */
        if (!siteFindConfigPath(silk_config_file, sizeof(silk_config_file))) {
            /* we only get NULL if 'silk_config_file' is too small */
            if (verbose) {
                skAppPrintErr("Error getting site configuration file");
            }
            silk_config_file[0] = '\0';
            return -2;
        }
        if (!(silk_config_file[0] && skFileExists(silk_config_file))) {
            /* Missing file---do not modify 'configured' */
            if (verbose) {
                skAppPrintErr("Site configuration file not found");
            }
            silk_config_file[0] = '\0';
            return -2;
        }
    }

    /* we have a file; attempt to parse it */
    if (sksiteconfigParse(silk_config_file, verbose)) {
        /* Failed */
        configured = -1;
    } else {
        /* Success (so far) */
        configured = 1;

        sksiteClassIterator(&cl_iter);
        while (sksiteClassIteratorNext(&cl_iter, &cl_id)) {
            sksiteClassFlowtypeIterator(cl_id, &ft_iter);
            if (!sksiteFlowtypeIteratorNext(&ft_iter, &ft_id)) {
                sksiteClassGetName(cl_name, sizeof(cl_name), cl_id);
                sksiteconfigErr(
                    "Site configuration error: class '%s' contains no types",
                    cl_name);
                configured = -1;
            }
        }
        /* a total absence of classes is not an error */
    }
    return ((configured == -1) ? -1 : 0);
}


int
sksiteSetConfigPath(
    const char         *filename)
{
    if (configured) {
        return -1;
    }
    if (NULL == filename || '\0' == *filename
        || strlen(filename) >= sizeof(silk_config_file))
    {
        return -1;
    }
    strncpy(silk_config_file, filename, sizeof(silk_config_file));
    return 0;
}


char *
sksiteGetConfigPath(
    char               *buffer,
    size_t              bufsize)
{
    /* if the site-config file is set, return it. */
    if (silk_config_file[0] != '\0') {
        if (bufsize <= strlen(silk_config_file)) {
            return NULL;
        }
        strncpy(buffer, silk_config_file, bufsize);
        return buffer;
    }

    /* else, return result of attempting to find it */
    return siteFindConfigPath(buffer, bufsize);
}


void
sksiteTeardown(
    void)
{
    static int teardown = 0;
    size_t count;
    size_t i;

    if (teardown) {
        return;
    }
    teardown = 1;

    /* destroy the maps first to avoid having to remove individual items from
     * them */
    if (sensor_map) {
        rbdestroy(sensor_map);
        sensor_map = NULL;
    }
    if (sensorgroup_map) {
        rbdestroy(sensorgroup_map);
        sensorgroup_map = NULL;
    }
    if (class_list) {
        class_struct_t *cl;
        count = skVectorGetCount(class_list);
        for (i = 0; i < count; ++i) {
            skVectorGetValue(&cl, class_list, i);
            siteClassFree(cl);
        }
        skVectorDestroy(class_list);
    }
    if (flowtype_list) {
        flowtype_struct_t *ft;
        count = skVectorGetCount(flowtype_list);
        for (i = 0; i < count; ++i) {
            skVectorGetValue(&ft, flowtype_list, i);
            siteFlowtypeFree(ft);
        }
        skVectorDestroy(flowtype_list);
    }
    if (sensorgroup_list) {
        sensorgroup_struct_t *sg;
        count = skVectorGetCount(sensorgroup_list);
        for (i = 0; i < count; ++i) {
            skVectorGetValue(&sg, sensorgroup_list, i);
            siteSensorgroupFree(sg);
        }
        skVectorDestroy(sensorgroup_list);
    }
    if (sensor_list) {
        sensor_struct_t *sn;
        count = skVectorGetCount(sensor_list);
        for (i = 0; i < count; ++i) {
            skVectorGetValue(&sn, sensor_list, i);
            siteSensorFree(sn);
        }
        skVectorDestroy(sensor_list);
    }
}


/** Iterators *********************************************************/

int
sksiteSensorIteratorNext(
    sk_sensor_iter_t   *iter,
    sk_sensor_id_t     *out_sensor_id)
{
    sensor_struct_t *sn = NULL;

    if (iter->si_vector == NULL) {
        return 0;
    }
    if (iter->si_contains_pointers) {
        while (sn == NULL) {
            if (skVectorGetValue(&sn, iter->si_vector, iter->si_index)) {
                return 0;
            }
            if (sn == NULL) {
                ++iter->si_index;
            }
        }
        *out_sensor_id = sn->sn_id;
        ++iter->si_index;
        return 1;
    } else {
        if (skVectorGetValue(out_sensor_id, iter->si_vector, iter->si_index)) {
            return 0;
        }
        ++iter->si_index;
        return 1;
    }
}


int
sksiteClassIteratorNext(
    sk_class_iter_t    *iter,
    sk_class_id_t      *out_class_id)
{
    class_struct_t *cl = NULL;

    if (iter->ci_vector == NULL) {
        return 0;
    }
    if (iter->ci_contains_pointers) {
        while (cl == NULL) {
            if (skVectorGetValue(&cl, iter->ci_vector, iter->ci_index)) {
                return 0;
            }
            if (cl == NULL) {
                ++iter->ci_index;
            }
        }
        *out_class_id = cl->cl_id;
        ++iter->ci_index;
        return 1;
    } else {
        if (skVectorGetValue(out_class_id, iter->ci_vector, iter->ci_index)) {
            return 0;
        }
        ++iter->ci_index;
        return 1;
    }
}


int
sksiteSensorgroupIteratorNext(
    sk_sensorgroup_iter_t  *iter,
    sk_sensorgroup_id_t    *out_group_id)
{
    sensorgroup_struct_t *sg = NULL;

    if (iter->gi_vector == NULL) {
        return 0;
    }
    if (iter->gi_contains_pointers) {
        while (sg == NULL) {
            if (skVectorGetValue(&sg, iter->gi_vector, iter->gi_index)) {
                return 0;
            }
            if (sg == NULL) {
                ++iter->gi_index;
            }
        }
        *out_group_id = sg->sg_id;
        ++iter->gi_index;
        return 1;
    } else {
        if (skVectorGetValue(out_group_id, iter->gi_vector, iter->gi_index)) {
            return 0;
        }
        ++iter->gi_index;
        return 1;
    }
}


int
sksiteFlowtypeIteratorNext(
    sk_flowtype_iter_t *iter,
    sk_flowtype_id_t   *out_flowtype_id)
{
    flowtype_struct_t *ft = NULL;

    if (iter->fi_vector == NULL) {
        return 0;
    }
    if (iter->fi_contains_pointers) {
        while (NULL == ft) {
            if (skVectorGetValue(&ft, iter->fi_vector, iter->fi_index)) {
                return 0;
            }
            if (NULL == ft) {
                ++iter->fi_index;
            }
        }
        *out_flowtype_id = ft->ft_id;
        ++iter->fi_index;
        return 1;
    } else {
        if (skVectorGetValue(out_flowtype_id, iter->fi_vector, iter->fi_index))
        {
            return 0;
        }
        ++iter->fi_index;
        return 1;
    }
}

/** Sensors ***********************************************************/

int
sksiteSensorCreate(
    sk_sensor_id_t      sensor_id,
    const char         *sensor_name)
{
    sensor_struct_t *sn = NULL;
    const sensor_struct_t *added;
    const size_t vcap = skVectorGetCapacity(sensor_list);
    site_strlen_t sensor_name_len;

    /* check bounds and length/legality of name */
    if (sensor_id >= SK_MAX_NUM_SENSORS) {
        return -1;
    }
    if (sksiteSensorNameIsLegal(sensor_name) != 0) {
        return -1;
    }

    sensor_name_len = strlen(sensor_name);

    /* verify sensor does not exist */
    if (sksiteSensorExists(sensor_id)) {
        return -1;
    }
    if (siteSensorLookup2(sensor_name, sensor_name_len) != SK_INVALID_SENSOR) {
        return -1;
    }
#if 0
    /* Since there is no distinction between sensors and sensorgroups when
     * parsing the --sensors switch, them sharing a name causes the sensor to
     * hide the sensorgroup. */
    if (siteSensorgroupLookup2(sensor_name, sensor_name_len)
        != SK_INVALID_SENSORGROUP)
    {
        skAppPrintErr(
            "Warning: A sensorgroup already exists with the name '%s'",
            sensor_name);
    }
#endif  /* 0 */

    if (sensor_id >= vcap) {
        if (skVectorSetCapacity(sensor_list, sensor_id + 1)) {
            goto alloc_error;
        }
    }

    sn = (sensor_struct_t *) calloc(1, sizeof(sensor_struct_t));
    if (sn == NULL) {
        goto alloc_error;
    }
    sn->sn_name_strlen = sensor_name_len;
    sn->sn_name = strdup(sensor_name);
    sn->sn_class_list = skVectorNew(sizeof(sk_class_id_t));
    sn->sn_sensorgroup_list = skVectorNew(sizeof(sk_sensorgroup_id_t));
    if ((sn->sn_name == NULL) ||
        (sn->sn_class_list == NULL) ||
        (sn->sn_sensorgroup_list == NULL))
    {
        goto alloc_error;
    }

    sn->sn_id = sensor_id;
    if (sn->sn_name_strlen > sensor_max_name_strlen) {
        sensor_max_name_strlen = sn->sn_name_strlen;
    }

    if (sensor_id > sensor_max_id) {
        sensor_max_id = sensor_id;
    }
    if ((sensor_min_id == -1) || (sensor_id < sensor_min_id)) {
        sensor_min_id = sensor_id;
    }
    if (skVectorSetValue(sensor_list, sensor_id, &sn)) {
        goto alloc_error;
    }

    added = (sensor_struct_t *)rbsearch(sn, sensor_map);
    if (NULL == added) {
        goto alloc_error;
    }
    assert(added == sn);
    /* assert(siteSensorLookup2(sn->sn_name, sn->sn_name_strlen) */
    /*        == sensor_id); */

    return 0;

  alloc_error:
    siteSensorFree(sn);
    return -1;
}


/*
 *  siteSensorFree(sn);
 *
 *    Free all memory associated with the Sensor 'sn'; 'sn' may be
 *    NULL.
 */
static void
siteSensorFree(
    sensor_struct_t    *sn)
{
    if (sn != NULL) {
        if (sensor_map) {
            rbdelete(sn, sensor_map);
        }
        if (sn->sn_class_list != NULL) {
            skVectorDestroy(sn->sn_class_list);
        }
        if (sn->sn_sensorgroup_list != NULL) {
            skVectorDestroy(sn->sn_sensorgroup_list);
        }
        if (sn->sn_name != NULL) {
            free((char*)sn->sn_name);
        }
        if (sn->sn_description != NULL) {
            free((char*)sn->sn_description);
        }
        free(sn);
    }
}


/**
 *    Implements sksiteSensorLookup() and requires the name's length as the
 *    second argument.
 */
static sk_sensor_id_t
siteSensorLookup2(
    const char         *sensor_name,
    site_strlen_t       sensor_name_len)
{
    const sensor_struct_t *sn;
    sensor_struct_t target;

    target.sn_name = sensor_name;
    target.sn_name_strlen = sensor_name_len;
    sn = (const sensor_struct_t *)rbfind(&target, sensor_map);
    if (sn) {
        return sn->sn_id;
    }
    return SK_INVALID_SENSOR;
}


sk_sensor_id_t
sksiteSensorLookup(
    const char         *sensor_name)
{
    return siteSensorLookup2(sensor_name, strlen(sensor_name));
}


int
sksiteSensorExists(
    sk_sensor_id_t      sensor_id)
{
    sensor_struct_t *sn;

    if (skVectorGetValue(&sn, sensor_list, sensor_id) || (NULL == sn)) {
        return 0;
    }
    return 1;
}


sk_sensor_id_t
sksiteSensorGetMinID(
    void)
{
    return sensor_min_id;
}


sk_sensor_id_t
sksiteSensorGetMaxID(
    void)
{
    return sensor_max_id;
}


size_t
sksiteSensorGetMaxNameStrLen(
    void)
{
    return sensor_max_name_strlen;
}


int
sksiteSensorGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_sensor_id_t      sensor_id)
{
    sensor_struct_t *sn;

    if (sensor_id == SK_INVALID_SENSOR) {
        /* Invalid sensor, give message */
        return snprintf(buffer, buffer_size, "%s", INVALID_LABEL);
    } else if (skVectorGetValue(&sn, sensor_list, sensor_id) || (NULL == sn)) {
        /* Unknown sensor, give numeric value */
        return snprintf(buffer, buffer_size, "%u", (unsigned int)sensor_id);
    } else {
        /* Known sensor, give name */
        return snprintf(buffer, buffer_size, "%s", sn->sn_name);
    }
}


int
sksiteIsSensorInClass(
    sk_sensor_id_t      sensor_id,
    sk_class_id_t       class_id)
{
    sk_class_iter_t ci;
    sk_class_id_t check_id;

    sksiteSensorClassIterator(sensor_id, &ci);
    while (sksiteClassIteratorNext(&ci, &check_id)) {
        if (check_id == class_id) {
            return 1;
        }
    }
    return 0;
}


int
sksiteIsSensorInSensorgroup(
    sk_sensor_id_t      sensor_id,
    sk_sensorgroup_id_t group_id)
{
    sk_sensorgroup_iter_t gi;
    sk_sensorgroup_id_t check_id;

    sksiteSensorSensorgroupIterator(sensor_id, &gi);
    while (sksiteSensorgroupIteratorNext(&gi, &check_id)) {
        if (check_id == group_id) {
            return 1;
        }
    }
    return 0;
}


void
sksiteSensorIterator(
    sk_sensor_iter_t   *iter)
{
    iter->si_index = 0;
    iter->si_vector = sensor_list;
    iter->si_contains_pointers = 1;
}


void
sksiteSensorClassIterator(
    sk_sensor_id_t      sensor_id,
    sk_class_iter_t    *iter)
{
    sensor_struct_t *sn = NULL;

    iter->ci_index = 0;
    iter->ci_contains_pointers = 0;
    if (skVectorGetValue(&sn, sensor_list, sensor_id) || (NULL == sn)) {
        iter->ci_vector = NULL;
    } else {
        iter->ci_vector = sn->sn_class_list;
    }
}


void
sksiteSensorSensorgroupIterator(
    sk_sensor_id_t          sensor_id,
    sk_sensorgroup_iter_t  *iter)
{
    sensor_struct_t *sn = NULL;

    iter->gi_index = 0;
    iter->gi_contains_pointers = 0;
    if (skVectorGetValue(&sn, sensor_list, sensor_id) || (NULL == sn)) {
        iter->gi_vector = NULL;
    } else {
        iter->gi_vector = sn->sn_sensorgroup_list;
    }
}


int
sksiteSensorNameIsLegal(
    const char         *name)
{
    size_t len;

    if (NULL == name) {
        return -1;
    }
    len = strcspn(name, SITE_BAD_CHARS_SENSOR);
    /* check that length is between 1 and SK_MAX_STRLEN_FLOWTYPE */
    if (len < 1) {
        return -2;
    }
    if (len > SK_MAX_STRLEN_SENSOR) {
        return -3;
    }
    /* check that name begins with a letter */
    if (!isalpha((int)*name)) {
        return -1;
    }
    /* check whether we matched an invalid character */
    if (name[len] != '\0') {
        return len;
    }

    return 0;
}


int
sksiteSensorGetClassCount(
    sk_sensor_id_t      sensor_id)
{
    sensor_struct_t *sn = NULL;

    if (skVectorGetValue(&sn, sensor_list, sensor_id) || (NULL == sn)) {
        return 0;
    }
    return skVectorGetCount(sn->sn_class_list);
}


const char *
sksiteSensorGetDescription(
    sk_sensor_id_t      sensor_id)
{
    sensor_struct_t *sn = NULL;

    if (skVectorGetValue(&sn, sensor_list, sensor_id) || (NULL == sn)) {
        return NULL;
    }
    return sn->sn_description;
}


int
sksiteSensorSetDescription(
    sk_sensor_id_t      sensor_id,
    const char         *sensor_description)
{
    sensor_struct_t *sn = NULL;

    if (skVectorGetValue(&sn, sensor_list, sensor_id) || (NULL == sn)) {
        return -1;
    }

    if (sn->sn_description) {
        free((char*)sn->sn_description);
    }
    if (NULL == sensor_description) {
        sn->sn_description = NULL;
    } else {
        sn->sn_description = strdup(sensor_description);
        if (NULL == sn->sn_description) {
            return -1;
        }
    }
    return 0;
}


/** Classes ***********************************************************/

static int
sksiteFlowtypeNameIsLegal(
    const char         *name)
{
    size_t len;

    if (NULL == name) {
        return -1;
    }
    len = strcspn(name, SITE_BAD_CHARS_FLOWTYPE);
    /* check that length is between 1 and SK_MAX_STRLEN_FLOWTYPE */
    if (len < 1) {
        return -2;
    }
    if (len > SK_MAX_STRLEN_FLOWTYPE) {
        return -3;
    }
    /* check that name begins with a letter */
    if (!isalpha((int)*name)) {
        return -1;
    }
    /* check whether we matched an invalid character */
    if (name[len] != '\0') {
        return len;
    }

    return 0;
}


int
sksiteClassCreate(
    sk_class_id_t       class_id,
    const char         *class_name)
{
    class_struct_t *cl = NULL;
    const size_t vcap = skVectorGetCapacity(class_list);

    /* check bounds and length/legality of name */
    if (class_id >= SK_MAX_NUM_CLASSES) {
        return -1;
    }
    if (sksiteFlowtypeNameIsLegal(class_name) != 0) {
        return -1;
    }

    /* verify class does not exist */
    if (sksiteClassExists(class_id)) {
        return -1;
    }
    if (sksiteClassLookup(class_name) != SK_INVALID_CLASS) {
        return -1;
    }

    if (class_id >= vcap) {
        if (skVectorSetCapacity(class_list, class_id + 1)) {
            goto alloc_error;
        }
    }

    cl = (class_struct_t *) calloc(1, sizeof(class_struct_t));
    if (cl == NULL) {
        goto alloc_error;
    }
    cl->cl_name = strdup(class_name);
    cl->cl_sensor_list = skVectorNew(sizeof(sk_sensor_id_t));
    cl->cl_flowtype_list = skVectorNew(sizeof(sk_flowtype_id_t));
    cl->cl_default_flowtype_list = skVectorNew(sizeof(sk_flowtype_id_t));
    if ((cl->cl_name == NULL) ||
        (cl->cl_sensor_list == NULL) ||
        (cl->cl_flowtype_list == NULL) ||
        (cl->cl_default_flowtype_list == NULL))
    {
        goto alloc_error;
    }

    cl->cl_id = class_id;
    cl->cl_name_strlen = strlen(class_name);
    if (cl->cl_name_strlen > class_max_name_strlen) {
        class_max_name_strlen = cl->cl_name_strlen;
    }

    if (class_id > class_max_id) {
        class_max_id = class_id;
    }

    if (skVectorSetValue(class_list, class_id, &cl)) {
        goto alloc_error;
    }

    return 0;

  alloc_error:
    siteClassFree(cl);
    return -1;
}


/*
 *  siteClassFree(sg);
 *
 *    Free all memory associated with the Class 'cl'; 'cl' may
 *    be NULL.  Does not free any sensors or flowtypes.
 */
static void
siteClassFree(
    class_struct_t     *cl)
{
    if (cl != NULL) {
        if (cl->cl_default_flowtype_list != NULL) {
            skVectorDestroy(cl->cl_default_flowtype_list);
        }

        if (cl->cl_flowtype_list != NULL) {
            skVectorDestroy(cl->cl_flowtype_list);
        }

        if (cl->cl_sensor_list != NULL) {
            skVectorDestroy(cl->cl_sensor_list);
        }

        if (cl->cl_name != NULL) {
            free((char*)cl->cl_name);
        }
        free(cl);
    }
}

int
sksiteClassSetDefault(
    sk_class_id_t       class_id)
{
    sk_flowtype_iter_t ft_iter;
    sk_flowtype_id_t ft_id;
    sk_sensor_iter_t sn_iter;
    sk_sensor_id_t sn_id;

    if (0 == sksiteClassExists(class_id)) {
        return -1;
    }
    sksiteClassFlowtypeIterator(class_id, &ft_iter);
    if (!sksiteFlowtypeIteratorNext(&ft_iter, &ft_id)) {
        /* no flowtypes exist for this class */
        return -1;
    }
    sksiteClassSensorIterator(class_id, &sn_iter);
    if (!sksiteSensorIteratorNext(&sn_iter, &sn_id)) {
        /* no sensors exist for this class */
        return -1;
    }
    default_class = class_id;
    return 0;
}


sk_class_id_t
sksiteClassGetDefault(
    void)
{
    return default_class;
}


sk_class_id_t
sksiteClassLookup(
    const char         *class_name)
{
    sk_class_id_t id;
    class_struct_t *cl;

    for (id = 0; 0 == skVectorGetValue(&cl, class_list, id); ++id) {
        if ((cl != NULL) && (strcmp(cl->cl_name, class_name) == 0)) {
            return id;
        }
    }
    return SK_INVALID_CLASS;
}


int
sksiteClassExists(
    sk_class_id_t       class_id)
{
    class_struct_t *cl;

    if (skVectorGetValue(&cl, class_list, class_id) || (NULL == cl)) {
        return 0;
    }
    return 1;
}


sk_class_id_t
sksiteClassGetMaxID(
    void)
{
    return class_max_id;
}


size_t
sksiteClassGetMaxNameStrLen(
    void)
{
    return class_max_name_strlen;
}


int
sksiteClassGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_class_id_t       class_id)
{
    class_struct_t *cl;

    if (class_id == SK_INVALID_CLASS) {
        /* Invalid class, give message */
        return snprintf(buffer, buffer_size, "%s", INVALID_LABEL);
    } else if (skVectorGetValue(&cl, class_list, class_id) || (NULL == cl)) {
        /* Unknown class, give numeric value */
        return snprintf(buffer, buffer_size, "%u", (unsigned int)class_id);
    } else {
        /* Known value, print name */
        return snprintf(buffer, buffer_size, "%s", cl->cl_name);
    }
}


int
sksiteClassAddSensor(
    sk_class_id_t       class_id,
    sk_sensor_id_t      sensor_id)
{
    int i;
    class_struct_t *cl;
    sensor_struct_t *sn;
    sk_sensor_id_t id;

    if (skVectorGetValue(&cl, class_list, class_id) || (NULL == cl)) {
        return -1;              /* Invalid class_id */
    }
    if (skVectorGetValue(&sn, sensor_list, sensor_id) || (NULL == sn)) {
        return -1;              /* Invalid sensor_id */
    }
    for (i = 0; 0 == skVectorGetValue(&id, cl->cl_sensor_list, i); ++i) {
        if (id == sensor_id) {
            return 0;
        }
    }
    /* XXX Recover and not add to class list either? */
    if (skVectorAppendValue(sn->sn_class_list, &class_id)) {
        return -1;
    }
    if (skVectorAppendValue(cl->cl_sensor_list, &sensor_id)) {
        return -1;
    }
    return 0;
}


int
sksiteClassAddSensorgroup(
    sk_class_id_t       class_id,
    sk_sensorgroup_id_t group_id)
{
    int i;
    class_struct_t *cl;
    sensorgroup_struct_t *sg;
    sk_sensor_id_t id;

    if (skVectorGetValue(&cl, class_list, class_id) || (NULL == cl)) {
        return -1;              /* Invalid class_id */
    }
    if (skVectorGetValue(&sg, sensorgroup_list, group_id) || (NULL == sg)) {
        return -1;              /* Invalid group_id */
    }
    for (i = 0; 0 == skVectorGetValue(&id, sg->sg_sensor_list, i); ++i) {
        if (sksiteClassAddSensor(class_id, id)) {
            return -1;
        }
    }
    return 0;
}


void
sksiteClassIterator(
    sk_class_iter_t    *iter)
{
    iter->ci_index = 0;
    iter->ci_vector = class_list;
    iter->ci_contains_pointers = 1;
}


void
sksiteClassSensorIterator(
    sk_class_id_t       class_id,
    sk_sensor_iter_t   *iter)
{
    class_struct_t *cl;

    iter->si_index = 0;
    iter->si_contains_pointers = 0;
    if (skVectorGetValue(&cl, class_list, class_id) || (NULL == cl)) {
        iter->si_vector = NULL;
    } else {
        iter->si_vector = cl->cl_sensor_list;
    }
}


void
sksiteClassFlowtypeIterator(
    sk_class_id_t       class_id,
    sk_flowtype_iter_t *iter)
{
    class_struct_t *cl;

    memset(iter, 0, sizeof(sk_flowtype_iter_t));
    if ((0 == skVectorGetValue(&cl, class_list, class_id)) && (NULL != cl)) {
        iter->fi_vector = cl->cl_flowtype_list;
    }
}


void
sksiteClassDefaultFlowtypeIterator(
    sk_flowtype_id_t    class_id,
    sk_flowtype_iter_t *iter)
{
    class_struct_t *cl;

    if (skVectorGetValue(&cl, class_list, class_id) || (NULL == cl)) {
        iter->fi_vector = NULL;
        return;
    }
    iter->fi_index = 0;
    iter->fi_vector = cl->cl_default_flowtype_list;
    iter->fi_contains_pointers = 0;
}


int
sksiteClassGetSensorCount(
    sk_class_id_t       class_id)
{
    class_struct_t *cl;

    if (skVectorGetValue(&cl, class_list, class_id) || (NULL == cl)) {
        return 0;
    }
    return skVectorGetCount(cl->cl_sensor_list);
}


int
sksiteClassAddDefaultFlowtype(
    sk_class_id_t       class_id,
    sk_flowtype_id_t    flowtype_id)
{
    int i;
    class_struct_t *cl;
    flowtype_struct_t *ft;
    sk_flowtype_id_t id;

    if (skVectorGetValue(&ft, flowtype_list, flowtype_id) || (NULL == ft)) {
        return -1;
    }
    if (skVectorGetValue(&cl, class_list, class_id) || (NULL == cl)) {
        return -1;
    }
    if (ft->ft_class != class_id) {
        return -1;
    }
    for (i=0; 0 == skVectorGetValue(&id, cl->cl_default_flowtype_list, i); ++i)
    {
        if (id == flowtype_id) {
            return 0;
        }
    }
    if (skVectorAppendValue(cl->cl_default_flowtype_list, &flowtype_id)) {
        return -1;
    }
    return 0;
}

/** Sensorgroups ******************************************************/

int
sksiteSensorgroupCreate(
    sk_sensorgroup_id_t sensorgroup_id,
    const char         *sensorgroup_name)
{
    sensorgroup_struct_t *sg = NULL;
    const sensorgroup_struct_t *added;
    const size_t vcap = skVectorGetCapacity(sensorgroup_list);
    site_strlen_t sensorgroup_name_len;

    if (sensorgroup_id >= SK_MAX_NUM_SENSORGROUPS) {
        return -1;
    }

    sensorgroup_name_len = strlen(sensorgroup_name);

    /* verify sensorgroup does not exist */
    if (sksiteSensorgroupExists(sensorgroup_id)) {
        return -1;
    }
    if (siteSensorgroupLookup2(sensorgroup_name, sensorgroup_name_len)
        != SK_INVALID_SENSORGROUP)
    {
        return -1;
    }
#if 0
    /* Since there is no distinction between sensors and sensorgroups when
     * parsing the --sensors switch, them sharing a name causes the sensor to
     * hide the sensorgroup. */
    if (siteSensorLookup2(sensorgroup_name, sensorgroup_name_len)
        != SK_INVALID_SENSOR)
    {
        skAppPrintErr(
            "Warning: A sensor already exists with the name '%s'",
            sensor_name);
    }
#endif  /* 0 */

    if (sensorgroup_id >= vcap) {
        if (skVectorSetCapacity(sensorgroup_list, sensorgroup_id + 1)) {
            goto alloc_error;
        }
    }

    sg = (sensorgroup_struct_t *) calloc(1, sizeof(sensorgroup_struct_t));
    if (sg == NULL) {
        goto alloc_error;
    }
    sg->sg_name = strdup(sensorgroup_name);
    sg->sg_sensor_list = skVectorNew(sizeof(sk_sensor_id_t));
    if ((sg->sg_name == NULL) ||
        (sg->sg_sensor_list == NULL))
    {
        goto alloc_error;
    }

    sg->sg_id = sensorgroup_id;
    sg->sg_name_strlen = strlen(sensorgroup_name);

    if (sg->sg_name_strlen > sensorgroup_max_name_strlen) {
        sensorgroup_max_name_strlen = sg->sg_name_strlen;
    }
    if (sensorgroup_id > sensorgroup_max_id) {
        sensorgroup_max_id = sensorgroup_id;
    }

    if (skVectorSetValue(sensorgroup_list, sensorgroup_id, &sg)) {
        goto alloc_error;
    }

    added = (sensorgroup_struct_t *)rbsearch(sg, sensorgroup_map);
    if (NULL == added) {
        goto alloc_error;
    }
    assert(added == sg);

    return 0;

  alloc_error:
    siteSensorgroupFree(sg);
    return -1;
}


/*
 *  siteSensorgroupFree(sg);
 *
 *    Free all memory associated with the Sensorgroup 'sg'; 'sg' may
 *    be NULL.
 */
static void
siteSensorgroupFree(
    sensorgroup_struct_t   *sg)
{
    if (sg != NULL) {
        if (sensorgroup_map) {
            rbdelete(sg, sensorgroup_map);
        }
        if (sg->sg_sensor_list != NULL) {
            skVectorDestroy(sg->sg_sensor_list);
        }
        if (sg->sg_name != NULL) {
            free((char *)sg->sg_name);
        }
        free(sg);
    }
}


/**
 *    Implements sksiteSensorgroupLookup() and requires the group name's
 *    length as the second argument.
 */
static sk_sensorgroup_id_t
siteSensorgroupLookup2(
    const char         *sensorgroup_name,
    site_strlen_t       sensorgroup_name_len)
{
    const sensorgroup_struct_t *sg;
    sensorgroup_struct_t target;

    target.sg_name = sensorgroup_name;
    target.sg_name_strlen = sensorgroup_name_len;
    sg = (const sensorgroup_struct_t *)rbfind(&target, sensorgroup_map);
    if (sg) {
        return sg->sg_id;
    }
    return SK_INVALID_SENSORGROUP;
}

sk_sensorgroup_id_t
sksiteSensorgroupLookup(
    const char         *sensorgroup_name)
{
    return siteSensorgroupLookup2(sensorgroup_name, strlen(sensorgroup_name));
}


int
sksiteSensorgroupExists(
    sk_sensorgroup_id_t sensorgroup_id)
{
    sensorgroup_struct_t *sg;

    if (skVectorGetValue(&sg, sensorgroup_list, sensorgroup_id)|| (NULL == sg))
    {
        return 0;
    }
    return 1;
}


sk_sensorgroup_id_t
sksiteSensorgroupGetMaxID(
    void)
{
    return sensorgroup_max_id;
}


size_t
sksiteSensorgroupGetMaxNameStrLen(
    void)
{
    return sensorgroup_max_name_strlen;
}


int
sksiteSensorgroupGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_sensorgroup_id_t group_id)
{
    sensorgroup_struct_t *sg;

    if (group_id == SK_INVALID_SENSORGROUP) {
        /* Invalid group, give message */
        return snprintf(buffer, buffer_size, "%s", INVALID_LABEL);
    } else if (skVectorGetValue(&sg, sensorgroup_list, group_id)
               || (NULL == sg))
    {
        /* Unknown sensorgroup, give numeric value */
        return snprintf(buffer, buffer_size, "%u", (unsigned int)group_id);
    } else {
        /* Known sensorgroup, give name */
        return snprintf(buffer, buffer_size, "%s", sg->sg_name);
    }
}


int
sksiteSensorgroupAddSensor(
    sk_sensorgroup_id_t group_id,
    sk_sensor_id_t      sensor_id)
{
    int i;
    sensorgroup_struct_t *sg;
    sensor_struct_t *sn;
    sk_sensor_id_t id;

    if (skVectorGetValue(&sg, sensorgroup_list, group_id) || (NULL == sg)) {
        return -1;              /* Invalid group_id */
    }
    if (skVectorGetValue(&sn, sensor_list, sensor_id) || (NULL == sn)) {
        return -1;              /* Invalid sensor_id */
    }
    for (i = 0; 0 == skVectorGetValue(&id, sg->sg_sensor_list, i); ++i) {
        if (id == sensor_id) {
            return 0;           /* Already there */
        }
    }
    /* add sensor to the group */
    if (skVectorAppendValue(sg->sg_sensor_list, &sensor_id)) {
        return -1;              /* Memory failure */
    }
    /* add group to the sensor */
    if (skVectorAppendValue(sn->sn_sensorgroup_list, &group_id)) {
        /* should undo the previous append */
        return -1;              /* Memory failure */
    }

    return 0;
}


int
sksiteSensorgroupAddSensorgroup(
    sk_sensorgroup_id_t dest,
    sk_sensorgroup_id_t src)
{
    int i;
    sensorgroup_struct_t *sg_src;
    sensorgroup_struct_t *sg_dest;
    sk_sensor_id_t id;

    if (skVectorGetValue(&sg_src, sensorgroup_list, src) || (NULL == sg_src)) {
        return -1;              /* Invalid source group_id */
    }
    if (skVectorGetValue(&sg_dest, sensorgroup_list, dest)||(NULL == sg_dest)){
        return -1;              /* Invalid dest group_id */
    }
    for (i = 0; 0 == skVectorGetValue(&id, sg_src->sg_sensor_list, i); ++i) {
        if (sksiteSensorgroupAddSensor(dest, id)) {
            return -1;
        }
    }
    return 0;
}


void
sksiteSensorgroupIterator(
    sk_sensorgroup_iter_t  *iter)
{
    iter->gi_index = 0;
    iter->gi_vector = sensorgroup_list;
    iter->gi_contains_pointers = 1;
}


void
sksiteSensorgroupSensorIterator(
    sk_sensorgroup_id_t     group_id,
    sk_sensor_iter_t       *iter)
{
    sensorgroup_struct_t *sg;

    iter->si_index = 0;
    iter->si_contains_pointers = 0;
    if (skVectorGetValue(&sg, sensorgroup_list, group_id) || (NULL == sg)) {
        iter->si_vector = NULL;
    } else {
        iter->si_vector = sg->sg_sensor_list;
    }
}

/** Flowtypes *********************************************************/

int
sksiteFlowtypeCreate(
    sk_flowtype_id_t    flowtype_id,
    const char         *flowtype_name,
    sk_class_id_t       class_id,
    const char         *type_name)
/*  const char         *prefix,
    sk_file_format_t    file_format,
    sk_file_version_t   file_version, */
{
    flowtype_struct_t *ft = NULL;
    class_struct_t *cl = NULL;
    const size_t vcap = skVectorGetCapacity(flowtype_list);

    assert(flowtype_name);
    assert(type_name);

    /* check bounds and length/legality of name */
    if (flowtype_id >= SK_MAX_NUM_FLOWTYPES) {
        return -1;
    }
    if (sksiteFlowtypeNameIsLegal(flowtype_name) != 0) {
        return -1;
    }
    if (sksiteFlowtypeNameIsLegal(type_name) != 0) {
        return -1;
    }
#if 0
    /* treat "all" as a reserved type name */
    if (strcmp("all", type_name)) {
        return -1;
    }
#endif

    /* verify class exists */
    if (skVectorGetValue(&cl, class_list, class_id) || (NULL == cl)) {
        return -1;
    }

    /* verify flowtype does not exist, and verify type is unique on
     * this class */
    if (sksiteFlowtypeExists(flowtype_id)) {
        return -1;
    }
    if (sksiteFlowtypeLookup(flowtype_name) != SK_INVALID_FLOWTYPE) {
        return -1;
    }
    if (sksiteFlowtypeLookupByClassIDType(class_id, type_name)
        != SK_INVALID_FLOWTYPE)
    {
        return -1;
    }

    if (flowtype_id >= vcap) {
        if (skVectorSetCapacity(flowtype_list, flowtype_id + 1)) {
            goto alloc_error;
        }
    }
    ft = (flowtype_struct_t *) calloc(1, sizeof(flowtype_struct_t));
    if (ft == NULL) {
        goto alloc_error;
    }

    ft->ft_id = flowtype_id;
    ft->ft_name = strdup(flowtype_name);
    ft->ft_type = strdup(type_name);
    if (ft->ft_name == NULL) {
        goto alloc_error;
    }

    ft->ft_class = class_id;

    ft->ft_name_strlen = strlen(flowtype_name);
    if (ft->ft_name_strlen > flowtype_max_name_strlen) {
        flowtype_max_name_strlen = ft->ft_name_strlen;
    }
    ft->ft_type_strlen = strlen(type_name);
    if (ft->ft_type_strlen > flowtype_max_type_strlen) {
        flowtype_max_type_strlen = ft->ft_type_strlen;
    }

    /* Now register it on the list */

    if (skVectorAppendValue(cl->cl_flowtype_list, &flowtype_id)) {
        goto alloc_error;
    }

    if (flowtype_id > flowtype_max_id) {
        flowtype_max_id = flowtype_id;
    }

    if (skVectorSetValue(flowtype_list, flowtype_id, &ft)) {
        goto alloc_error;
    }

    return 0;

  alloc_error:
    siteFlowtypeFree(ft);
    return -1;
}


/*
 *  siteFlowtypeFree(sg);
 *
 *    Free all memory associated with the Flowtype 'ft'; 'ft' may
 *    be NULL.
 */
static void
siteFlowtypeFree(
    flowtype_struct_t  *ft)
{
    if (ft != NULL) {
        if (ft->ft_name != NULL) {
            free((char*)ft->ft_name);
        }
        if (ft->ft_type != NULL) {
            free((char*)ft->ft_type);
        }
        free(ft);
    }
}


sk_flowtype_id_t
sksiteFlowtypeLookup(
    const char         *flowtype_name)
{
    sk_flowtype_id_t id;
    flowtype_struct_t *ft;

    for (id = 0; 0 == skVectorGetValue(&ft, flowtype_list, id); ++id) {
        if ((ft != NULL) && (strcmp(ft->ft_name, flowtype_name) == 0)) {
            return id;
        }
    }
    return SK_INVALID_FLOWTYPE;
}


sk_flowtype_id_t
sksiteFlowtypeLookupByClassType(
    const char         *class_name,
    const char         *type_name)
{
    flowtype_struct_t *ft;
    sk_flowtype_iter_t iter;
    sk_flowtype_id_t id;
    sk_class_id_t class_id;

    if (class_name == NULL || type_name == NULL) {
        return SK_INVALID_FLOWTYPE;
    }

    class_id = sksiteClassLookup(class_name);
    sksiteClassFlowtypeIterator(class_id, &iter);
    while (sksiteFlowtypeIteratorNext(&iter, &id)) {
        if (0 == skVectorGetValue(&ft, flowtype_list, id)) {
            if ((ft != NULL) && (strcmp(ft->ft_type, type_name) == 0)) {
                return id;
            }
        }
    }

    /* not found */
    return SK_INVALID_FLOWTYPE;
}


sk_flowtype_id_t
sksiteFlowtypeLookupByClassIDType(
    sk_class_id_t       class_id,
    const char         *type_name)
{
    flowtype_struct_t *ft;
    sk_flowtype_iter_t iter;
    sk_flowtype_id_t id;

    if (type_name == NULL) {
        return SK_INVALID_FLOWTYPE;
    }

    sksiteClassFlowtypeIterator(class_id, &iter);
    while (sksiteFlowtypeIteratorNext(&iter, &id)) {
        if (0 == skVectorGetValue(&ft, flowtype_list, id)) {
            if ((ft != NULL) && (strcmp(ft->ft_type, type_name) == 0)) {
                return id;
            }
        }
    }

    /* not found */
    return SK_INVALID_FLOWTYPE;
}


int
sksiteFlowtypeExists(
    sk_flowtype_id_t    flowtype_id)
{
    flowtype_struct_t *ft;

    if (skVectorGetValue(&ft, flowtype_list, flowtype_id) || (NULL == ft)) {
        return 0;
    }
    return 1;
}


sk_flowtype_id_t
sksiteFlowtypeGetMaxID(
    void)
{
    return flowtype_max_id;
}


int
sksiteFlowtypeGetClass(
    char               *buffer,
    size_t              buffer_size,
    sk_flowtype_id_t    flowtype_id)
{
    flowtype_struct_t *ft;

    if (skVectorGetValue(&ft, flowtype_list, flowtype_id) || (NULL == ft)) {
        /* Unknown flowtype */
        return snprintf(buffer, buffer_size, "%s", INVALID_LABEL);
    } else {
        /* Known flowtype; lookup the class */
        return sksiteClassGetName(buffer, buffer_size, ft->ft_class);
    }
}


sk_class_id_t
sksiteFlowtypeGetClassID(
    sk_flowtype_id_t    flowtype_id)
{
    flowtype_struct_t *ft;

    if (skVectorGetValue(&ft, flowtype_list, flowtype_id) || (NULL == ft)) {
        return SK_INVALID_CLASS;
    }
    return ft->ft_class;
}


size_t
sksiteFlowtypeGetMaxNameStrLen(
    void)
{
    return flowtype_max_name_strlen;
}


int
sksiteFlowtypeGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_flowtype_id_t    flowtype_id)
{
    flowtype_struct_t *ft;

    if (flowtype_id == SK_INVALID_FLOWTYPE) {
        /* Invalid flowtype, give message */
        return snprintf(buffer, buffer_size, "%s", INVALID_LABEL);
    } else if (skVectorGetValue(&ft, flowtype_list, flowtype_id)
               || (NULL == ft))
    {
        /* Unknown flowtype, give numeric value */
        return snprintf(buffer, buffer_size, "%u", (unsigned int)flowtype_id);
    } else {
        /* Known filetype, give name */
        return snprintf(buffer, buffer_size, "%s", ft->ft_name);
    }
}


size_t
sksiteFlowtypeGetMaxTypeStrLen(
    void)
{
    return flowtype_max_type_strlen;
}


int
sksiteFlowtypeGetType(
    char               *buffer,
    size_t              buffer_size,
    sk_flowtype_id_t    flowtype_id)
{
    flowtype_struct_t *ft;

    if (skVectorGetValue(&ft, flowtype_list, flowtype_id) || (NULL == ft)) {
        /* Unknown flowtype, give numeric flowtype value */
        return snprintf(buffer, buffer_size, "%u", (unsigned int)flowtype_id);
    } else {
        /* Known flowtype, give string flowtype value */
        return snprintf(buffer, buffer_size, "%s", ft->ft_type);
    }
}


void
sksiteFlowtypeIterator(
    sk_flowtype_iter_t *iter)
{
    iter->fi_index = 0;
    iter->fi_vector = flowtype_list;
    iter->fi_contains_pointers = 1;
}


void
sksiteFlowtypeAssert(
    const char         *pack_logic_file,
    sk_flowtype_id_t    flowtype_id,
    const char         *class_name,
    const char         *type_name)
{
    sk_class_id_t class_id;
    sk_flowtype_id_t check_id = SK_INVALID_FLOWTYPE;

    class_id = sksiteClassLookup(class_name);
    if (class_id == SK_INVALID_CLASS) {
        goto FAIL_ASSERT;
    }
    check_id = sksiteFlowtypeLookupByClassIDType(class_id, type_name);
    if (check_id == SK_INVALID_FLOWTYPE) {
        goto FAIL_ASSERT;
    }
    if (check_id != flowtype_id) {
        goto FAIL_ASSERT;
    }

    /* all is well */
    return;

  FAIL_ASSERT:
#define ERROR_MSG                                                       \
    "Mismatch in packing-logic [%s] versus site-config-file [%s]: "

    if (class_id == SK_INVALID_CLASS) {
        skAppPrintErr((ERROR_MSG
                       "Class '%s' does not exist in site-config-file"),
                      pack_logic_file, silk_config_file,
                      class_name);
    } else if (check_id == SK_INVALID_FLOWTYPE) {
        skAppPrintErr((ERROR_MSG
                       "No flowtype for class/type '%s/%s' exists in"
                       " site-config-file"),
                      pack_logic_file, silk_config_file,
                      class_name, type_name);
    } else if (check_id != flowtype_id) {
        skAppPrintErr((ERROR_MSG
                       "Flowtype ID for class/type '%s/%s' (%d) in"
                       " site-config-file does not match ID in"
                       " packing-logic (%d)"),
                      pack_logic_file, silk_config_file,
                      class_name, type_name, check_id, flowtype_id);
    }
    abort();
#undef ERROR_MSG
}

/** Error Supports Types/Functions*************************************/

/* typedef struct sksite_error_iterator_st sksite_error_iterator_t; */
struct sksite_error_iterator_st {
    sk_vector_t  *error_vector;
    site_strlen_t pos;
};

typedef struct sksite_validation_error_st {
    int           error_code;
    char         *error_string;
} sksite_validation_error_t;


void
sksiteErrorIteratorReset(
    sksite_error_iterator_t    *iter)
{
    iter->pos = UINT32_MAX;
}

int
sksiteErrorIteratorNext(
    sksite_error_iterator_t    *iter)
{
    if (NULL == iter) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    if (iter->pos == UINT32_MAX) {
        if (0 == skVectorGetCount(iter->error_vector)) {
            return SK_ITERATOR_NO_MORE_ENTRIES;
        }
        iter->pos = 0;
        return SK_ITERATOR_OK;
    }
    if (iter->pos + 1 >= skVectorGetCount(iter->error_vector)) {
        return SK_ITERATOR_NO_MORE_ENTRIES;
    }
    ++iter->pos;
    return SK_ITERATOR_OK;
}

static void
siteErrorIterFreeVector(
    sksite_error_iterator_t    *iter)
{
    sksite_validation_error_t err;
    size_t i;

    if (iter->error_vector) {
        i = skVectorGetCount(iter->error_vector);
        while (i > 0) {
            --i;
            skVectorGetValue(&err, iter->error_vector, i);
            free(err.error_string);
        }
        skVectorDestroy(iter->error_vector);
    }
}


void
sksiteErrorIteratorFree(
    sksite_error_iterator_t    *iter)
{
    if (iter) {
        siteErrorIterFreeVector(iter);
        free(iter);
    }
}

SK_DIAGNOSTIC_FORMAT_NONLITERAL_PUSH
static int
siteErrorIterPush(
    sksite_error_iterator_t    *iter,
    int                         error_code,
    const char                 *format,
    ...)
{
    sksite_validation_error_t err;
    char buf[1024];
    va_list args;
    ssize_t sz;
    int rv = -1;

    assert(iter);
    va_start(args, format);
    if (iter->error_vector) {
        memset(&err, 0, sizeof(err));
        err.error_code = error_code;

        sz = vsnprintf(buf, sizeof(buf), format, args);
        if ((size_t)sz < sizeof(buf)) {
            err.error_string = strdup(buf);
        } else if (sz < 0) {
            skAppPrintErr("vsnprintf() returned negative value");
            skAbort();
        } else {
            size_t len = sz + 1;;
            err.error_string = (char *)calloc(len, sizeof(char));
            if (err.error_string) {
                va_end(args);
                va_start(args, format);
                sz = vsnprintf(err.error_string, len, format, args);
            }
        }

        if (NULL == err.error_string) {
            skAppPrintOutOfMemory("copy string");
            goto END;
        }
        if (skVectorAppendValue(iter->error_vector, &err)) {
            skAppPrintOutOfMemory("vector entry");
            free(err.error_string);
            goto END;
        }
    }

    rv = 0;
  END:
    va_end(args);
    return rv;
}
SK_DIAGNOSTIC_FORMAT_NONLITERAL_POP


static int
siteErrorIterCreateVector(
    sksite_error_iterator_t    *iter)
{
    assert(iter);
    iter->error_vector = skVectorNew(sizeof(sksite_validation_error_t));
    if (NULL == iter->error_vector) {
        skAppPrintOutOfMemory("vector");
        return -1;
    }
    return 0;
}


/*
 *  ok = siteErrorIterCreate(&iter);
 *
 *    Create a new error iterator at the location specified by 'iter'.
 *
 *    Return 0 on success, or -1 on allocation error.
 */
static int
siteErrorIterCreate(
    sksite_error_iterator_t   **iter)
{
    assert(iter);
    *iter = (sksite_error_iterator_t*)malloc(sizeof(sksite_error_iterator_t));
    if (*iter == NULL) {
        skAppPrintOutOfMemory("error iterator");
        return -1;
    }
    if (siteErrorIterCreateVector(*iter)) {
        free(*iter);
        *iter = NULL;
        return -1;
    }
    sksiteErrorIteratorReset(*iter);
    return 0;
}


/*
 *  name = siteErrorIterGetter(iter, action, &error_code);
 *
 *    Gets the current value for the error iterator, where the type of
 *    returned value depends on the 'action', as specified here:
 *
 *    1. Set 'error_code' to the numeric error code, a value defined
 *    in the sksite_validate_enum_t enumeration, and return the token
 *    that caused the error to be set.  When 'action' is 1,
 *    'error_code' must not be NULL.
 *
 *    2. Return the token that caused the error to be set.  Ignores
 *    paramter 'error_cde'
 *
 *    3. Return a pointer to a static buffer, where the buffer
 *    contains an appropriate error message given the code.  Ignores
 *    paramter 'error_code'.
 */
static const char *
siteErrorIterGetter(
    const sksite_error_iterator_t  *iter,
    int                             action,
    int                            *error_code)
{
    sksite_validation_error_t err;

    /* if action is 1, error_code not be NULL */
    assert(1 != action || NULL != error_code);

    if (NULL == iter) {
        return NULL;
    }
    if (skVectorGetValue(&err, iter->error_vector, iter->pos)) {
        return NULL;
    }

    if (1 == action) {
        *error_code = err.error_code;
        return err.error_string;
    }
    if (2 == action) {
        return err.error_string;
    }
    return err.error_string;
}


int
sksiteErrorIteratorGetCode(
    const sksite_error_iterator_t  *iter)
{
    int error_code = -1;

    if (NULL == siteErrorIterGetter(iter, 1, &error_code)) {
        return -1;
    }
    switch (error_code) {
      case SKSITE_ERR_FLOWTYPE_NO_DELIM:
      case SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS:
      case SKSITE_ERR_FLOWTYPE_UNKNOWN_TYPE:
      case SKSITE_ERR_FLOWTYPE_TYPE_NOT_IN_CLASS:
      case SKSITE_ERR_UNKNOWN_SENSOR:
      case SKSITE_ERR_UNKNOWN_SENSOR_ID:
      case SKSITE_ERR_TYPE_NOT_IN_CLASSES:
      case SKSITE_ERR_SENSOR_NOT_IN_CLASSES:
      case SKSITE_ERR_CLASS_UNKNOWN:
      case SKSITE_ERR_TYPE_UNKNOWN:
      case SKSITE_ERR_CLASS_NO_DEFAULT:
      case SKSITE_ERR_SENSORGROUP_UNKNOWN:
      case SKSITE_ERR_LONG_TOKEN:
      case SKSITE_ERR_LONG_FILE:
      case SKSITE_ERR_BAD_FILE_BEGIN:
      case SKSITE_ERR_BAD_ESCAPE:
      case SKSITE_ERR_FILE_IO:
      case SKSITE_ERR_FILE_RECURSE:
        return error_code;
      default:
        return SKSITE_ERR_UTILS_OFFSET;
    }
    /* return -1; */
}


const char *
sksiteErrorIteratorGetToken(
    const sksite_error_iterator_t  *iter)
{
    return siteErrorIterGetter(iter, 2, NULL);
}


const char *
sksiteErrorIteratorGetMessage(
    const sksite_error_iterator_t  *iter)
{
    return siteErrorIterGetter(iter, 3, NULL);
}


/** Compatibility Functions *******************************************/

#define SITE_TOKENIZER_MAX_LEN  4000

#define SITE_TOKEN_MAX_DEPTH  2

struct site_tokenizer_st {
    /* buffer to hold the current token */
    char                buf[SITE_TOKENIZER_MAX_LEN];
    /* maximum length of name allowed in `buf` */
    site_strlen_t       len;
    /* position(s) within the argument(s) being parsed */
    const char         *pos[SITE_TOKEN_MAX_DEPTH];
    /* current depth within the 'pos' array */
    unsigned int        depth;
    /* To support a file name ("@foo" so struct is named `at`) */
    struct at_st {
        /* current length of name in `file` */
        site_strlen_t len;
        /* available space remaining in `file` */
        site_strlen_t rem;
        /* the open stream */
        skstream_t   *stream;
        /* file name */
        char          file[PATH_MAX + 1];
        /* buffer holding the current line read from the file */
        char          line_buf[1024];
    }                   at;
};
typedef struct site_tokenizer_st site_tokenizer_t;


static void
siteTokenizerInit(
    site_tokenizer_t   *state,
    const char         *list,
    site_strlen_t       max_length)
{
    assert(max_length < sizeof(state->buf));
    memset(state, 0, sizeof(*state));
    state->depth = 0;
    state->pos[state->depth] = list;
    state->len = max_length;
    state->at.rem = sizeof(state->at.file) - 1;
}

/*
 *  Cleans a buffer in place to remove leading commas and whitespace before
 *  the first token, trailing commas and whitespace after the final token, any
 *  whitespace that surrounds the comma delimter, and repeated commas.
 *  Returns the length of the resulting string.
 */
static int
siteTokenizerCleanFileInputLine(
    char   *buffer)
{
    char *cp;    /* search for comma */
    char *ep;    /* end of next token position */
    char *dp;    /* destination position */
    char *sp;    /* source/start of token position */

    dp = sp = buffer;

    for (;;) {
        /* `sp` is either at the start of the buffer or just after a comma;
         * move over any leading whitespace or commas */
        while (isspace(*sp) || ',' == *sp) {
            ++sp;
        }
        /* `sp` is at start of token or at end of the string. Search forward
         * for a comma.  If found, set `ep` to char just before the comma. If
         * not found, either `sp` is at the end of the buffer or there is a
         * final token to process in which case `ep` is set to the end of the
         * buffer. */
        cp = strchr(sp, ',');
        if (cp) {
            ep = cp - 1;
        } else if (*sp) {
            /* no comma but still have data; this is the final token */
            ep = sp + strlen(sp) - 1;
        } else {
            /* `sp` is at the end of the string, remove trailing comma added
             * after the most recent token (if any) end exit loop */
            if (dp > buffer) {
                assert(',' == *(dp - 1));
                --dp;
            }
            break;
        }
        /* move backward from `ep` over any trailing whitespace */
        while (ep > sp && isspace(*ep)) {
            --ep;
        }
        /* `sp` at start of token and `ep` at the end. Copy it. After this,
         * `dp` is on char just after the copied token. */
        if (sp == dp) {
            /* no need to copy, just move */
            dp = ep + 1;
        } else {
            while (sp <= ep) {
                *dp = *sp;
                ++dp;
                ++sp;
            }
        }
        if (NULL == cp) {
            /* if no comma was found; exit loop */
            break;
        }
        /* include a comma in the destination, though we may remove it if
         * there are no more tokens. We do this so `sp` and `dp` stay in sync
         * for case where the incoming buffer is fine as-is. */
        *dp = ',';
        ++dp;
        /* move `sp` to just after the comma */
        sp = cp + 1;
    }

    /* close string and return the length */
    *dp = '\0';
    return dp - buffer;
}


/*
 *    Return SITE_TOKEN_OK if the function parses a token.  Return
 *    SITE_TOKEN_END_OF_DATA if the function has reached the end of the input.
 *    Return SITE_TOKEN_ERR if an error was added to the error_iter or
 *    SITE_TOKEN_ERR_FATAL if an attempt to push an error onto error_iter
 *    fails.
 */
static site_token_status_t
siteTokenizerNext(
    site_tokenizer_t         *state,
    char                    **name,
    sksite_error_iterator_t  *error_iter)
{
    const char *ep;
    const char *sp;
    size_t len;
    site_token_status_t rv = SITE_TOKEN_OK;
    /* used to remember location of a bad @x escape */
    const char *bad = NULL;
    /* skStream return code */
    ssize_t strrv;

    assert(state);
    assert(name);
    assert(state->pos[state->depth]);

    /* set output name */
    *name = state->buf;

    /* loop until find token, reach end of data, or error */
    for (;;) {

        memset(state->buf, 0, sizeof(state->buf));
        memset(state->at.file, 0, sizeof(state->at.file));
        state->at.len = 0;
        state->at.rem = sizeof(state->at.file) - 1;

        /* if there is an open stream, try to read a line from it */
        while (state->at.stream) {
            /* if state->depth is set, we already have a partial line (though
             * we may be at the end of that line) */
            if (state->depth) {
                if (*state->pos[state->depth]) {
                    /* more entries on this line */
                    break;
                }
                /* finished with this line */
                --state->depth;
            }

            /* read next line from file */
            strrv = skStreamGetLine(state->at.stream, state->at.line_buf,
                                    sizeof(state->at.line_buf), NULL);
            if (SKSTREAM_OK == strrv) {
                TRACEMSG(("L%d, read line \"%s\"",
                          __LINE__, state->at.line_buf));
                /* we have a line; trim leading and trailing whitespace and
                 * whitespace around commas */
                len = siteTokenizerCleanFileInputLine(state->at.line_buf);
                if (0 == len) {
                    continue;
                }
                ++state->depth;
                state->pos[state->depth] = state->at.line_buf;
                TRACEMSG(("L%d, trimmed line \"%s\"",
                          __LINE__, state->pos[state->depth]));
                break;
            }

            /* either end of file or error reading */
            if (SKSTREAM_ERR_EOF != strrv) {
                char msgbuf[PATH_MAX * 2];
                skStreamLastErrMessage(state->at.stream, strrv,
                                       msgbuf, sizeof(msgbuf) - 1);
                rv = SITE_TOKEN_ERR;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_FILE_IO,
                        "Error reading file: %s", msgbuf))
                {
                    rv = SITE_TOKEN_ERR_FATAL;
                }
            }
            skStreamDestroy(&state->at.stream);
            memset(state->at.file, 0, sizeof(state->at.file));
            state->at.len = 0;
            state->at.rem = sizeof(state->at.file) - 1;
            if (SKSTREAM_ERR_EOF != strrv) {
                return rv;
            }
            /* finished with the file; continue reading the option's
             * arguments */
        }

        /* ignore leading comma or multiple commas */
        while (',' == *state->pos[state->depth]) {
            ++state->pos[state->depth];
        }

        if (!*state->pos[state->depth]) {
            /* no more data on this line or in this argument */
            if (0 == state->depth) {
                /* no more data */
                return SITE_TOKEN_END_OF_DATA;
            }
            /* pop back to the option's argument */
            --state->depth;
            continue;
        }

        TRACEMSG(("L%d, state->depth = %u, state->pos[] = '%s'\n"
                  "state->buf = '%s'\n" "state->file = '%s'",
                  __LINE__, state->depth, state->pos[state->depth],
                  state->buf, state->at.file));

        /* record the starting position */
        sp = state->pos[state->depth];

        /* if first char is not '@', then treat as an ordinary token. */
        if ('@' != *state->pos[state->depth]) {
            ep = strchr(state->pos[state->depth], ',');
            if (ep) {
                /* record length, move 'ep' to start of next token */
                len = ep - state->pos[state->depth];
                ++ep;
            } else {
                /* get length; move 'ep' to the NUL */
                len = strlen(state->pos[state->depth]);
                ep = state->pos[state->depth] + len;
            }
            if (len >= state->len) {
                /* token too long */
                rv = SITE_TOKEN_ERR;
                len = state->len;
            }
            strncpy(state->buf, state->pos[state->depth], len);
            state->buf[len] = '\0';
            state->pos[state->depth] = ep;
            if (SITE_TOKEN_ERR == rv) {
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_LONG_TOKEN,
                        ("Token's length (%ld) is longer than maximum"
                         " allowed (%u); token begins with \"%s\""),
                        ep - sp, state->len, state->buf))
                {
                    return SITE_TOKEN_ERR_FATAL;
                }
            }
            return rv;
        }

        TRACEMSG(("L%d, state->depth = %u, state->pos[] = '%s',"
                  " state->buf = '%s'",
                  __LINE__, state->depth, state->pos[state->depth],
                  state->buf));

        /* we are at the start of a file name; find its end */
        ++state->pos[state->depth];
        while (*state->pos[state->depth]) {
            len = strcspn(state->pos[state->depth], ",@");
            ep = state->pos[state->depth] + len;
            TRACEMSG(("L%d, state->pos[state->depth] = '%s', len = %zu",
                      __LINE__, state->pos[state->depth], len));
            if (len >= state->at.rem) {
                /* file name too long */
                len = state->at.rem;
                rv = SITE_TOKEN_ERR;
            }
            /* copy the text we just spanned */
            strncpy(state->at.file + state->at.len,
                    state->pos[state->depth], len);
            state->at.len += len;
            state->at.rem -= len;
            state->at.file[state->at.len] = '\0';
            state->pos[state->depth] = ep + (',' == *ep);
            TRACEMSG(("L%d, ep = '%s'", __LINE__, ep));
            if ('@' != *ep) {
                /* end of filename */
                break;
            }
            /* next character must be a ',' or '@' */
            ++ep;
            TRACEMSG(("L%d, ep = '%s'", __LINE__, ep));
            if ('@' == *ep || ',' == *ep) {
                /* got what we expected; ignore the first '@' by moving
                 * state->pos[] forward; move 'ep' to next char */
                len = 1;
                ++state->pos[state->depth];
                ++ep;
            } else {
                /* illegal character; record the character if this is the
                 * first bad one */
                if (!bad) {
                    bad = ep;
                }
                if ('\0' == *ep) {
                    len = 1;
                } else {
                    len = 2;
                    ++ep;
                }
            }
            /* add the text to the file name */
            if (len >= state->at.rem) {
                len = state->at.rem;
                rv = SITE_TOKEN_ERR;
            }
            strncpy(state->at.file + state->at.len,
                    state->pos[state->depth], len);
            state->at.len += len;
            state->at.rem -= len;
            state->at.file[state->at.len] = '\0';
            state->pos[state->depth] = ep;
        }

        /* error about a long token */
        if (rv) {
            /* shorten amount of filename displayed */
            state->at.file[((state->at.len < 80) ? state->at.len : 80)] = '\0';
            if (siteErrorIterPush(
                    error_iter, SKSITE_ERR_LONG_FILE,
                    ("Filename's length (%ld) is longer than maximum"
                     " allowed (%u); filename begins \"%s\""),
                    state->pos[state->depth] - sp - 1, state->at.len,
                    state->at.file))
            {
                return SITE_TOKEN_ERR_FATAL;
            }
            return SITE_TOKEN_ERR;
        }

        /* If we found bad escape, return that error now */
        if (bad) {
            if ('\0' == *bad) {
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_BAD_ESCAPE,
                        ("Token '@%s' contains a single @ at end of token:"
                         " After the initial '@', only the '@@' and '@,'"
                         " sequences are allowed"),
                        state->at.file))
                {
                    return SITE_TOKEN_ERR_FATAL;
                }
            } else if (siteErrorIterPush(
                           error_iter, SKSITE_ERR_BAD_ESCAPE,
                           ("Token '@%s' contains illegal sequence '@%c':"
                            " After the initial '@', only the '@@' and '@,'"
                            " sequences are allowed"),
                           state->at.file, *bad))
            {
                return SITE_TOKEN_ERR_FATAL;
            }
            return SITE_TOKEN_ERR;
        }

        /* If the token was a single "@" (which means at.file is empty),
         * return that token since sometime that is used to mean "default" */
        if ('\0' == state->at.file[0]) {
            state->buf[0] = *sp;
            state->buf[1] = '\0';
            TRACEMSG(("L%d, Found file name '%s'; returning token '%s'",
                      __LINE__, state->at.file, state->buf));
            return SITE_TOKEN_OK;
        }

        /* Will not accept @FILE inside a file */
        if (state->depth > 0) {
            if (siteErrorIterPush(
                    error_iter, SKSITE_ERR_FILE_RECURSE,
                    ("Bad token '@%s' found in file '%s': "
                     "May not recursively use @FILE construct within a file"),
                    state->at.file, skStreamGetPathname(state->at.stream)))
            {
                return SITE_TOKEN_ERR_FATAL;
            }
            return SITE_TOKEN_ERR;
        }

        /* Attempt to open the file */
        TRACEMSG(("L%d, Found file name '%s'", __LINE__, state->at.file));
        if ((strrv = skStreamCreate(&state->at.stream, SK_IO_READ,
                                    SK_CONTENT_TEXT))
            || (strrv = skStreamBind(state->at.stream, state->at.file))
            || (strrv = skStreamSetCommentStart(state->at.stream, "#"))
            || (strrv = skStreamOpen(state->at.stream)))
        {
            char msgbuf[PATH_MAX * 2];
            skStreamLastErrMessage(state->at.stream, strrv,
                                   msgbuf, sizeof(msgbuf)-1);
            skStreamDestroy(&state->at.stream);
            if (siteErrorIterPush(error_iter, SKSITE_ERR_FILE_IO,
                                  "%s", msgbuf))
            {
                return SITE_TOKEN_ERR_FATAL;
            }
            return SITE_TOKEN_ERR;
        }
    }
}


#if 0
static const char *
siteTokenizerGetPosition(
    site_tokenizer_t   *state)
{
    assert(state);
    return state->pos;
}
#endif  /* 0 */

int
sksiteParseFlowtypeList(
    sk_vector_t                *ft_vector,
    const char                 *ft_name_list,
    const char                 *all_classes_token,
    const char                 *all_types_token,
    const char                 *default_class_token,
    const char                 *default_types_token,
    sksite_error_iterator_t   **out_error_iter)
{
    const char separator = '/';
    sksite_error_iterator_t *error_iter = NULL;
    sk_bitmap_t *bitmap;
    site_tokenizer_t tokens;
    site_token_status_t sts;
    size_t vector_count;
    int invalid_count = 0;
    char *type_name;
    char *name;
    sk_flowtype_iter_t ft_iter;
    sk_flowtype_id_t id;
    sk_class_iter_t class_iter;
    sk_class_id_t class_id;
    int rv = -1;

    sksiteConfigure(0);

    if (NULL == ft_vector || NULL == ft_name_list) {
        goto END;
    }
    if (skVectorGetElementSize(ft_vector) != sizeof(sk_flowtype_id_t)) {
        goto END;
    }
    if ('\0' == *ft_name_list) {
        rv = 0;
        goto END;
    }
    vector_count = skVectorGetCount(ft_vector);

    /* create the object that holds invalid tokens */
    if (out_error_iter) {
        if (siteErrorIterCreate(&error_iter)) {
            goto END;
        }
    }

    /* parse the name_list as a comma separated list of tokens */
    siteTokenizerInit(&tokens, ft_name_list, (2 + 2*SK_MAX_STRLEN_FLOWTYPE));
    while ((sts = siteTokenizerNext(&tokens, &name, error_iter))
           != SITE_TOKEN_END_OF_DATA)
    {
        if (SITE_TOKEN_OK != sts) {
            if (SITE_TOKEN_ERR_FATAL == sts) {
                goto END;
            }
            ++invalid_count;
            continue;
        }

        /* convert the separator between class and type to '\0' */
        type_name = strchr(name, separator);
        if (NULL == type_name) {
            ++invalid_count;
            if (siteErrorIterPush(
                    error_iter, SKSITE_ERR_FLOWTYPE_NO_DELIM,
                    SKSITE_ERR_FLOWTYPE_NO_DELIM_MSG, name, separator))
            {
                goto END;
            }
            continue;
        }
        *type_name = '\0';
        ++type_name;

        /* attempt to find the class/type pair.  if the lookup fails,
         * test for special tokens */
        id = sksiteFlowtypeLookupByClassType(name, type_name);
        if (SK_INVALID_FLOWTYPE != id) {
            /* Found the class and type */
            if (skVectorAppendValue(ft_vector, &id)) { goto END; }
        } else if (all_classes_token
                   && 0 == strcmp(name, all_classes_token))
        {
            /* Using all classes */
            if (all_types_token
                && 0 == strcmp(type_name, all_types_token))
            {
                /* Using all classes and all types. */
                sksiteFlowtypeIterator(&ft_iter);
                while (sksiteFlowtypeIteratorNext(&ft_iter, &id)) {
                    if (skVectorAppendValue(ft_vector, &id)) { goto END; }
                }
            } else if (default_types_token
                       && 0 == strcmp(name, default_types_token))
            {
                /* Loop over all classes and add each class's default
                 * flowtypes. */
                sksiteClassIterator(&class_iter);
                while (sksiteClassIteratorNext(&class_iter, &class_id)) {
                    sksiteClassDefaultFlowtypeIterator(class_id, &ft_iter);
                    while (sksiteFlowtypeIteratorNext(&ft_iter, &id)) {
                        if (skVectorAppendValue(ft_vector, &id)) { goto END; }
                    }
                }
                /* FIXME: What if no default types are defined? */
            } else {
                /* Loop over all classes and add flowtype if type_name
                 * is valid for that class.  Do not complain unless
                 * the type in not valid for any class. */
                size_t found_type = skVectorGetCount(ft_vector);

                sksiteClassIterator(&class_iter);
                while (sksiteClassIteratorNext(&class_iter, &class_id)) {
                    id = sksiteFlowtypeLookupByClassIDType(class_id,type_name);
                    if (SK_INVALID_FLOWTYPE != id) {
                        if (skVectorAppendValue(ft_vector, &id)) { goto END; }
                    }
                }
                if (found_type == skVectorGetCount(ft_vector)) {
                    ++invalid_count;
                    *(type_name-1) = separator;
                    if (siteErrorIterPush(
                            error_iter, SKSITE_ERR_FLOWTYPE_UNKNOWN_TYPE,
                            SKSITE_ERR_FLOWTYPE_UNKNOWN_TYPE_MSG, name))
                    {
                        goto END;
                    }
                }
            }
        } else {
            /* Check for name as a class name or the default token */
            class_id = sksiteClassLookup(name);
            if (SK_INVALID_CLASS != class_id) {
                /* class name is known */
            } else if (default_class_token
                       && 0 == strcmp(name, default_class_token))
            {
                class_id = sksiteClassGetDefault();
                if (SK_INVALID_CLASS == class_id) {
                    ++invalid_count;
                    if (siteErrorIterPush(
                            error_iter, SKSITE_ERR_CLASS_NO_DEFAULT,
                            SKSITE_ERR_CLASS_NO_DEFAULT_MSG))
                    {
                        goto END;
                    }
                }
            } else {
                ++invalid_count;
                *(type_name-1) = separator;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS,
                        SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS_MSG, name))
                {
                    goto END;
                }
            }

            /* Handle the type if the class is valid */
            if (SK_INVALID_CLASS == class_id) {
                /* class is invalid; do nothing */
            } else if (all_types_token
                       && 0 == strcmp(type_name, all_types_token))
            {
                /* Use all types in the specified class */
                sksiteClassFlowtypeIterator(class_id, &ft_iter);
                while (sksiteFlowtypeIteratorNext(&ft_iter, &id)) {
                    if (skVectorAppendValue(ft_vector, &id)) { goto END; }
                }
            } else if (default_types_token
                       && 0 == strcmp(type_name, default_types_token))
            {
                /* Use the default types in the specified class */
                sksiteClassDefaultFlowtypeIterator(class_id, &ft_iter);
                while (sksiteFlowtypeIteratorNext(&ft_iter, &id)) {
                    if (skVectorAppendValue(ft_vector, &id)) { goto END; }
                }
                /* FIXME: What if no default types are defined? */
            } else {
                /* the type cannot be valid since the first thing we
                 * checked was for valid class/type pair */
                ++invalid_count;
                *(type_name-1) = separator;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_FLOWTYPE_TYPE_NOT_IN_CLASS,
                        SKSITE_ERR_FLOWTYPE_TYPE_NOT_IN_CLASS_MSG, name))
                {
                    goto END;
                }
            }
        }
    }

    /* remove duplicates */
    if (skBitmapCreate(&bitmap, 1+sksiteFlowtypeGetMaxID())) {
        goto END;
    }
    while (0 == skVectorGetValue(&id, ft_vector, vector_count)) {
        if (skBitmapGetBit(bitmap, id)) {
            skVectorRemoveValue(ft_vector, vector_count, NULL);
        } else {
            skBitmapSetBit(bitmap, id);
            ++vector_count;
        }
    }
    skBitmapDestroy(&bitmap);

    /* set out_error_iter if we encountered invalid tokens */
    if (NULL != out_error_iter && invalid_count > 0) {
        *out_error_iter = error_iter;
        error_iter = NULL;
    }
    rv = 0;

  END:
    sksiteErrorIteratorFree(error_iter);
    if (0 == rv) {
        return invalid_count;
    }
    return rv;
}


int
sksiteParseClassList(
    sk_vector_t                *class_vector,
    const char                 *class_name_list,
    const char                 *all_classes_token,
    const char                 *default_class_token,
    sksite_error_iterator_t   **out_error_iter)
{
    sksite_error_iterator_t *error_iter = NULL;
    sk_bitmap_t *bitmap;
    site_tokenizer_t tokens;
    site_token_status_t sts;
    sk_class_iter_t ci;
    size_t vector_count;
    int invalid_count = 0;
    char *name;
    sk_class_id_t id;
    int rv = -1;

    sksiteConfigure(0);

    if (NULL == class_vector || NULL == class_name_list) {
        goto END;
    }
    if (skVectorGetElementSize(class_vector) != sizeof(sk_class_id_t)) {
        goto END;
    }
    if ('\0' == *class_name_list) {
        rv = 0;
        goto END;
    }
    vector_count = skVectorGetCount(class_vector);

    /* create the object that holds invalid tokens */
    if (out_error_iter) {
        if (siteErrorIterCreate(&error_iter)) {
            goto END;
        }
    }

    /* parse the name_list as a comma separated list of tokens */
    siteTokenizerInit(&tokens, class_name_list, SK_MAX_STRLEN_FLOWTYPE + 1);
    while ((sts = siteTokenizerNext(&tokens, &name, error_iter))
           != SITE_TOKEN_END_OF_DATA)
    {
        if (SITE_TOKEN_OK != sts) {
            if (SITE_TOKEN_ERR_FATAL == sts) {
                goto END;
            }
            ++invalid_count;
            continue;
        }

        /* look up token as a class name */
        id = sksiteClassLookup(name);
        if (SK_INVALID_CLASS != id) {
            /* found it */
            if (skVectorAppendValue(class_vector, &id)) { goto END; }
        } else if (default_class_token
                   && strcmp(name, default_class_token) == 0)
        {
            /* matches default class */
            id = sksiteClassGetDefault();
            if (SK_INVALID_CLASS != id) {
                if (skVectorAppendValue(class_vector, &id)) { goto END; }
            } else {
                ++invalid_count;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_CLASS_NO_DEFAULT,
                        SKSITE_ERR_CLASS_NO_DEFAULT_MSG))
                {
                    goto END;
                }
            }
        } else if (all_classes_token
                   && strcmp(name, all_classes_token) == 0)
        {
            /* matches all classes string */
            sksiteClassIterator(&ci);
            while (sksiteClassIteratorNext(&ci, &id)) {
                if (skVectorAppendValue(class_vector, &id)) { goto END; }
            }
        } else {
            ++invalid_count;
            if (siteErrorIterPush(
                    error_iter, SKSITE_ERR_CLASS_UNKNOWN,
                    SKSITE_ERR_CLASS_UNKNOWN_MSG, name))
            {
                goto END;
            }
        }
    }

    /* remove duplicates */
    if (skBitmapCreate(&bitmap, 1+sksiteClassGetMaxID())) {
        goto END;
    }
    while (0 == skVectorGetValue(&id, class_vector, vector_count)) {
        if (skBitmapGetBit(bitmap, id)) {
            skVectorRemoveValue(class_vector, vector_count, NULL);
        } else {
            skBitmapSetBit(bitmap, id);
            ++vector_count;
        }
    }
    skBitmapDestroy(&bitmap);

    /* set out_error_iter if we encountered invalid tokens */
    if (NULL != out_error_iter && invalid_count > 0) {
        *out_error_iter = error_iter;
        error_iter = NULL;
    }
    rv = 0;

  END:
    sksiteErrorIteratorFree(error_iter);
    if (0 == rv) {
        return invalid_count;
    }
    return rv;
}


int
sksiteParseTypeList(
    sk_vector_t                *ft_vector,
    const char                 *type_name_list,
    const sk_vector_t          *class_vector,
    const char                 *all_types_token,
    const char                 *default_type_token,
    sksite_error_iterator_t   **out_error_iter)
{
    sksite_error_iterator_t *error_iter = NULL;
    sk_bitmap_t *bitmap;
    site_tokenizer_t tokens;
    site_token_status_t sts;
    sk_flowtype_iter_t ft_iter;
    unsigned int found_type;
    size_t vector_count;
    int invalid_count = 0;
    char *name;
    sk_class_id_t class_id;
    sk_flowtype_id_t id;
    size_t i;
    int rv = -1;

    sksiteConfigure(0);

    if (NULL == ft_vector || NULL == type_name_list || NULL == class_vector) {
        goto END;
    }
    if (skVectorGetElementSize(ft_vector) != sizeof(sk_flowtype_id_t)) {
        goto END;
    }
    if (skVectorGetElementSize(class_vector) != sizeof(sk_class_id_t)) {
        goto END;
    }
    if ('\0' == *type_name_list) {
        rv = 0;
        goto END;
    }
    vector_count = skVectorGetCount(ft_vector);

    /* create the object that holds invalid tokens */
    if (out_error_iter) {
        if (siteErrorIterCreate(&error_iter)) {
            goto END;
        }
    }

    /* parse the name_list as a comma separated list of tokens */
    siteTokenizerInit(&tokens, type_name_list, SK_MAX_STRLEN_FLOWTYPE + 1);
    while ((sts = siteTokenizerNext(&tokens, &name, error_iter))
           != SITE_TOKEN_END_OF_DATA)
    {
        if (SITE_TOKEN_OK != sts) {
            if (SITE_TOKEN_ERR_FATAL == sts) {
                goto END;
            }
            ++invalid_count;
            continue;
        }

        found_type = 0;

        if (all_types_token
            && strcmp(name, all_types_token) == 0)
        {
            /* for each class given in the class_vector, add all types
             * for that class to the vector */
            for (i=0; 0 == skVectorGetValue(&class_id, class_vector, i); ++i){
                sksiteClassFlowtypeIterator(class_id, &ft_iter);
                while (sksiteFlowtypeIteratorNext(&ft_iter, &id)) {
                    if (skVectorAppendValue(ft_vector, &id)) { goto END; }
                    ++found_type;
                }
            }
        } else if (default_type_token
                   && strcmp(name, default_type_token) == 0)
        {
            /* for each class given in the class_vector, add the
             * default types for that class to the vector */
            for (i=0; 0 == skVectorGetValue(&class_id, class_vector, i); ++i){
                sksiteClassDefaultFlowtypeIterator(class_id, &ft_iter);
                while (sksiteFlowtypeIteratorNext(&ft_iter, &id)) {
                    if (skVectorAppendValue(ft_vector, &id)) { goto END; }
                    ++found_type;
                }
            }
        } else {
            /* for each class given in the class_vector, check whether
             * 'name' is a valid type in that class */
            for (i=0; 0 == skVectorGetValue(&class_id, class_vector, i); ++i){
                id = sksiteFlowtypeLookupByClassIDType(class_id, name);
                if (SK_INVALID_FLOWTYPE != id) {
                    if (skVectorAppendValue(ft_vector, &id)) { goto END; }
                    ++found_type;
                }
            }
        }
        if (!found_type) {
            ++invalid_count;
            if (siteErrorIterPush(
                    error_iter, SKSITE_ERR_TYPE_NOT_IN_CLASSES,
                    SKSITE_ERR_TYPE_NOT_IN_CLASSES_MSG, name))
            {
                goto END;
            }
        }
    }

    /* remove duplicates */
    if (skBitmapCreate(&bitmap, 1+sksiteFlowtypeGetMaxID())) {
        goto END;
    }
    while (0 == skVectorGetValue(&id, ft_vector, vector_count)) {
        if (skBitmapGetBit(bitmap, id)) {
            skVectorRemoveValue(ft_vector, vector_count, NULL);
        } else {
            skBitmapSetBit(bitmap, id);
            ++vector_count;
        }
    }
    skBitmapDestroy(&bitmap);

    /* set out_error_iter if we encountered invalid tokens */
    if (NULL != out_error_iter && invalid_count > 0) {
        *out_error_iter = error_iter;
        error_iter = NULL;
    }

    rv = 0;

  END:
    sksiteErrorIteratorFree(error_iter);
    if (0 == rv) {
        return invalid_count;
    }
    return rv;
}


int
sksiteParseSensorList(
    sk_vector_t                *sensor_vector,
    const char                 *sensor_name_list,
    const sk_vector_t          *classes_vector,
    const char                 *all_sensors_token,
    unsigned int                flags,
    sksite_error_iterator_t   **out_error_iter)
{
    sksite_error_iterator_t *error_iter = NULL;
    sk_bitmap_t *sensor_mask = NULL;
    char numbuf[64];
    site_tokenizer_t tokens;
    site_token_status_t sts;
    size_t vector_count;
    int invalid_count = 0;
    char *name;
    sk_sensorgroup_id_t group_id;
    sk_sensor_iter_t sensor_iter;
    sk_sensor_id_t min_sensor_id;
    sk_sensor_id_t max_sensor_id;
    sk_class_id_t class_id;
    sk_sensor_id_t id;
    uint32_t val_min;
    uint32_t val_max;
    size_t i;
    int p_err;
    int rv = -1;

    sksiteConfigure(0);

    min_sensor_id = sksiteSensorGetMinID();
    max_sensor_id = sksiteSensorGetMaxID();

    if (NULL == sensor_vector || NULL == sensor_name_list) {
        goto END;
    }
    if (skVectorGetElementSize(sensor_vector) != sizeof(sk_sensor_id_t)) {
        goto END;
    }
    if (SK_INVALID_SENSOR == min_sensor_id) {
        rv = 0;
        goto END;
    }
    if ('\0' == *sensor_name_list) {
        rv = 0;
        goto END;
    }
    vector_count = skVectorGetCount(sensor_vector);

    /* create the object that holds invalid tokens */
    if (out_error_iter) {
        if (siteErrorIterCreate(&error_iter)) {
            goto END;
        }
    }

    /* when classes_vector is provided, create a bitmap that holds all
     * sensor_ids that exist on the specified classes */
    if (classes_vector) {
        if (skBitmapCreate(&sensor_mask, 1 + max_sensor_id)) {
            goto END;
        }
        for (i = 0; 0 == skVectorGetValue(&class_id, classes_vector, i); ++i) {
            sksiteClassSensorIterator(class_id, &sensor_iter);
            while (sksiteSensorIteratorNext(&sensor_iter, &id)) {
                skBitmapSetBit(sensor_mask, id);
            }
        }
    }

    /* parse the name_list as a comma separated list of tokens */
    siteTokenizerInit(&tokens, sensor_name_list, SK_MAX_STRLEN_SENSOR + 1);
    while ((sts = siteTokenizerNext(&tokens, &name, error_iter))
           != SITE_TOKEN_END_OF_DATA)
    {
        if (SITE_TOKEN_OK != sts) {
            if (SITE_TOKEN_ERR_FATAL == sts) {
                goto END;
            }
            ++invalid_count;
            continue;
        }

        /* look up token as a sensor name */
        id = sksiteSensorLookup(name);
        if (SK_INVALID_SENSOR != id) {
            if (NULL == sensor_mask || skBitmapGetBit(sensor_mask, id)) {
                if (skVectorAppendValue(sensor_vector, &id)) { goto END; }
            } else {
                ++invalid_count;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_SENSOR_NOT_IN_CLASSES,
                        SKSITE_ERR_SENSOR_NOT_IN_CLASSES_MSG, name))
                {
                    goto END;
                }
            }

        } else if (all_sensors_token
                   && strcmp(name, all_sensors_token) == 0)
        {
            sksiteSensorIterator(&sensor_iter);
            while (sksiteSensorIteratorNext(&sensor_iter, &id)) {
                if (NULL == sensor_mask || skBitmapGetBit(sensor_mask, id)) {
                    if (skVectorAppendValue(sensor_vector, &id)) { goto END; }
                }
            }

        } else if ((flags & SKSITE_SENSORS_ALLOW_GROUP)
                   && ((group_id = sksiteSensorgroupLookup(name))
                       != SK_INVALID_SENSORGROUP))
        {
            sksiteSensorgroupSensorIterator(group_id, &sensor_iter);
            while (sksiteSensorIteratorNext(&sensor_iter, &id)) {
                if (NULL == sensor_mask || skBitmapGetBit(sensor_mask, id)) {
                    if (skVectorAppendValue(sensor_vector, &id)) { goto END; }
                }
            }

        } else if ((0 == (flags & (SKSITE_SENSORS_ALLOW_ID
                                   | SKSITE_SENSORS_ALLOW_RANGE)))
                   || !isdigit((int)(*name)))
        {
            /* either not a number or numbers not supported */
            ++invalid_count;
            if (siteErrorIterPush(error_iter, SKSITE_ERR_UNKNOWN_SENSOR,
                                  SKSITE_ERR_UNKNOWN_SENSOR_MSG, name))
            {
                goto END;
            }

        } else {
            if (0 == (flags & SKSITE_SENSORS_ALLOW_RANGE)) {
                /* parse as a single number */
                val_min = 0;
                p_err = skStringParseUint32(&val_min, name, min_sensor_id,
                                            max_sensor_id);
                val_max = val_min;
            } else {
                /* parse the token as a single number or a range */
                p_err = skStringParseRange32(&val_min, &val_max, name,
                                             min_sensor_id, max_sensor_id,
                                             SKUTILS_RANGE_NO_OPEN);
            }
            if (p_err < 0) {
                /* error parsing a number or range */
                ++invalid_count;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_UTILS_OFFSET + p_err,
                        SKSITE_ERR_UTILS_OFFSET_MSG, name,
                        skStringParseStrerror(p_err)))
                {
                    goto END;
                }
            } else if (p_err > 0) {
                /* text after a number */
                ++invalid_count;
                if (siteErrorIterPush(error_iter, SKSITE_ERR_UNKNOWN_SENSOR,
                                      SKSITE_ERR_UNKNOWN_SENSOR_MSG, name))
                {
                    goto END;
                }
            } else if (!sksiteSensorExists((sk_sensor_id_t)val_min)) {
                /* start of range is not valid */
                snprintf(numbuf, sizeof(numbuf), "%" PRIu32, val_min);
                ++invalid_count;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_UNKNOWN_SENSOR_ID,
                        SKSITE_ERR_UNKNOWN_SENSOR_ID_MSG, numbuf))
                {
                    goto END;
                }
            } else if (!sksiteSensorExists((sk_sensor_id_t)val_max)) {
                /* end of range is not valid */
                snprintf(numbuf, sizeof(numbuf), "%" PRIu32, val_max);
                ++invalid_count;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_UNKNOWN_SENSOR_ID,
                        SKSITE_ERR_UNKNOWN_SENSOR_ID_MSG, numbuf))
                {
                    goto END;
                }
            } else if (NULL == sensor_mask) {
                /* add all sensor IDs in range that are valid */
                for (id = (sk_sensor_id_t)val_min;
                     id <= (sk_sensor_id_t)val_max;
                     ++id)
                {
                    if (sksiteSensorExists(id)) {
                        if (skVectorAppendValue(sensor_vector, &id)) {
                            goto END;
                        }
                    }
                }
            } else {
                /* add all sensor IDs in range that are in sensor_mask */
                for (id = (sk_sensor_id_t)val_min;
                     id <= (sk_sensor_id_t)val_max;
                     ++id)
                {
                    if (skBitmapGetBit(sensor_mask, id)) {
                        if (skVectorAppendValue(sensor_vector, &id)) {
                            goto END;
                        }
                    } else {
                        snprintf(numbuf, sizeof(numbuf), "%" PRIu32, val_min);
                        ++invalid_count;
                        if (siteErrorIterPush(
                                error_iter, SKSITE_ERR_SENSOR_NOT_IN_CLASSES,
                                SKSITE_ERR_SENSOR_NOT_IN_CLASSES_MSG, numbuf))
                        {
                            goto END;
                        }
                    }
                }
            }
        }
    }

    /* remove duplicates */
    if (sensor_mask) {
        skBitmapClearAllBits(sensor_mask);
    } else {
        if (skBitmapCreate(&sensor_mask, 1 + max_sensor_id)) {
            goto END;
        }
    }
    while (0 == skVectorGetValue(&id, sensor_vector, vector_count)) {
        if (skBitmapGetBit(sensor_mask, id)) {
            skVectorRemoveValue(sensor_vector, vector_count, NULL);
        } else {
            skBitmapSetBit(sensor_mask, id);
            ++vector_count;
        }
    }

    /* set out_error_iter if we encountered invalid tokens */
    if (NULL != out_error_iter && invalid_count > 0) {
        *out_error_iter = error_iter;
        error_iter = NULL;
    }

    rv = 0;

  END:
    sksiteErrorIteratorFree(error_iter);
    skBitmapDestroy(&sensor_mask);
    if (0 == rv) {
        return invalid_count;
    }
    return rv;
}


int
sksiteParseSensorgroupList(
    sk_vector_t                *group_vector,
    const char                 *group_name_list,
    sksite_error_iterator_t   **out_error_iter)
{
    sksite_error_iterator_t *error_iter = NULL;
    sk_bitmap_t *bitmap = NULL;
    site_tokenizer_t tokens;
    site_token_status_t sts;
    size_t vector_count;
    int invalid_count = 0;
    char *name;
    sk_sensorgroup_id_t id;
    int rv = -1;

    sksiteConfigure(0);

    if (NULL == group_vector || NULL == group_name_list) {
        goto END;
    }
    if (skVectorGetElementSize(group_vector) != sizeof(sk_sensorgroup_id_t)) {
        goto END;
    }
    if ('\0' == *group_name_list) {
        rv = 0;
        goto END;
    }
    vector_count = skVectorGetCount(group_vector);

    /* create the object that holds invalid tokens */
    if (out_error_iter) {
        if (siteErrorIterCreate(&error_iter)) {
            goto END;
        }
    }

    /* parse the name_list as a comma separated list of tokens */
    siteTokenizerInit(&tokens, group_name_list, SITE_TOKENIZER_MAX_LEN - 1);
    while ((sts = siteTokenizerNext(&tokens, &name, error_iter))
           != SITE_TOKEN_END_OF_DATA)
    {
        if (SITE_TOKEN_OK != sts) {
            if (SITE_TOKEN_ERR_FATAL == sts) {
                goto END;
            }
            ++invalid_count;
            continue;
        }

        /* look up token as a group name */
        id = sksiteSensorgroupLookup(name);
        if (SK_INVALID_SENSORGROUP != id) {
            /* found it */
            if (skVectorAppendValue(group_vector, &id)) { goto END; }
        } else {
            ++invalid_count;
            if (siteErrorIterPush(error_iter, SKSITE_ERR_SENSORGROUP_UNKNOWN,
                                  SKSITE_ERR_SENSORGROUP_UNKNOWN_MSG, name))
            {
                goto END;
            }
        }
    }

    /* remove duplicates */
    if (skBitmapCreate(&bitmap, 1 + sksiteSensorgroupGetMaxID())) {
        goto END;
    }
    while (0 == skVectorGetValue(&id, group_vector, vector_count)) {
        if (skBitmapGetBit(bitmap, id)) {
            skVectorRemoveValue(group_vector, vector_count, NULL);
        } else {
            skBitmapSetBit(bitmap, id);
            ++vector_count;
        }
    }
    skBitmapDestroy(&bitmap);

    /* set out_error_iter if we encountered invalid tokens */
    if (NULL != out_error_iter && invalid_count > 0) {
        *out_error_iter = error_iter;
        error_iter = NULL;
    }

    rv = 0;

  END:
    sksiteErrorIteratorFree(error_iter);
    skBitmapDestroy(&bitmap);
    if (0 == rv) {
        return invalid_count;
    }
    return rv;
}


int
sksiteRepoIteratorParseTimes(
    sktime_t           *start_time,
    sktime_t           *end_time,
    const char         *start_time_str,
    const char         *end_time_str,
    int                *error_code)
{
#ifndef NDEBUG
    int time_rv;
#endif
    unsigned int start_precision = 0;
    unsigned int end_precision = 0;
    time_t t;
    int rv;

    assert(start_time);
    assert(end_time);

    if (!start_time_str) {
        /* When there is no start time, make certain there is no end
         * time, then look at everything from the start of today
         * through the current hour. */
        if (end_time_str) {
            if (error_code) {
                *error_code = -1;
            }
            return -1;
        }

        *start_time = sktimeNow();
#ifndef NDEBUG
        time_rv =
#endif
            skDatetimeCeiling(end_time, start_time, SK_PARSED_DATETIME_HOUR);
        assert(0 == time_rv);
#ifndef NDEBUG
        time_rv =
#endif
            skDatetimeFloor(start_time, start_time, SK_PARSED_DATETIME_DAY);
        assert(0 == time_rv);
        return 0;
    }

    /* Parse the starting time */
    rv = skStringParseDatetime(start_time, start_time_str, &start_precision);
    if (rv) {
        if (error_code) {
            *error_code = rv;
        }
        return 1;
    }
#if 0
    if ((0 == (start_precision & SK_PARSED_DATETIME_EPOCH))
        && (SK_PARSED_DATETIME_GET_PRECISION(start_precision)
            > SK_PARSED_DATETIME_HOUR))
    {
        skAppPrintErr(
            "Warning: Starting precision greater than hours ignored");
    }
#endif  /* 0 */

    /* Force start_time to start of hour */
#ifndef NDEBUG
    time_rv =
#endif
        skDatetimeFloor(start_time, start_time, SK_PARSED_DATETIME_HOUR);
    assert(0 == time_rv);

    if (end_time_str) {
        /* Parse the end time */
        rv = skStringParseDatetime(end_time, end_time_str, &end_precision);
        if (rv) {
            if (error_code) {
                *error_code = rv;
            }
            return 2;
        }

        /* Force end time to start of hour */
#ifndef NDEBUG
        time_rv =
#endif
            skDatetimeFloor(end_time, end_time, SK_PARSED_DATETIME_HOUR);
        assert(0 == time_rv);

        /* Make any required adjustements to end-time */
        if (end_precision & SK_PARSED_DATETIME_EPOCH) {
            /* take the end-time as-is when it is an epoch time */

        } else if (SK_PARSED_DATETIME_GET_PRECISION(start_precision)
                   == SK_PARSED_DATETIME_DAY)
        {
            /* when no starting hour given, we look at the full days,
             * regardless of the precision of the ending time; go to
             * the last hour of the ending day. */
#if 0
            if (SK_PARSED_DATETIME_GET_PRECISION(end_precision)
                >= SK_PARSED_DATETIME_HOUR)
            {
                skAppPrintErr("Warning: Strarting precision greater than days"
                              " ignored when ending has no hour");
            }
#endif  /* 0 */
#ifndef NDEBUG
            time_rv =
#endif
                skDatetimeCeiling(end_time, end_time, start_precision);
            assert(0 == time_rv);
#ifndef NDEBUG
            time_rv =
#endif
                skDatetimeFloor(end_time, end_time, SK_PARSED_DATETIME_HOUR);
            assert(0 == time_rv);

        } else if (SK_PARSED_DATETIME_GET_PRECISION(end_precision)
                   < SK_PARSED_DATETIME_HOUR)
        {
            /* starting time has an hour but ending time does not; use
             * same hour for ending time */
            struct tm work_tm;
            int work_hour;

            /* get starting hour */
            t = *start_time / 1000;
#if  SK_ENABLE_LOCALTIME
            localtime_r(&t, &work_tm);
#else
            gmtime_r(&t, &work_tm);
#endif
            work_hour = work_tm.tm_hour;

            /* break apart end time */
            t = *end_time / 1000;
#if  SK_ENABLE_LOCALTIME
            localtime_r(&t, &work_tm);
#else
            gmtime_r(&t, &work_tm);
#endif
            /* set end hour to start hour and re-combine */
            work_tm.tm_hour = work_hour;
            work_tm.tm_isdst = -1;
#if  SK_ENABLE_LOCALTIME
            t = mktime(&work_tm);
#else
            t = timegm(&work_tm);
#endif
            assert(-1 != t);
            *end_time = sktimeCreate((t - (t % 3600)), 0);

#if 0
        } else if (SK_PARSED_DATETIME_GET_PRECISION(end_precision)
                   > SK_PARSED_DATETIME_HOUR)
        {
            skAppPrintErr(
                "Warning: Ending precision greater than hours ignored");
#endif  /* 0 */
        }

    } else if ((SK_PARSED_DATETIME_GET_PRECISION(start_precision)
                >= SK_PARSED_DATETIME_HOUR)
               || (start_precision & SK_PARSED_DATETIME_EPOCH))
    {
        /* no ending time was given and the starting time contains an
         * hour or the starting time was expressed as epoch seconds;
         * we only look at that single hour */
        *end_time = *start_time;

    } else {
        /* no ending time was given and the starting time was to the
         * day; look at that entire day */
#ifndef NDEBUG
        time_rv =
#endif
            skDatetimeCeiling(end_time, start_time, start_precision);
        assert(0 == time_rv);
        /* Force end time to start of hour */
#ifndef NDEBUG
        time_rv =
#endif
            skDatetimeFloor(end_time, end_time, SK_PARSED_DATETIME_HOUR);
        assert(0 == time_rv);
    }

    if (*end_time < *start_time) {
        return -2;
    }

    return 0;
}


/** Paths *************************************************************/

const char *
sksiteGetDefaultRootDir(
    void)
{
    static char default_rootdir[PATH_MAX];
#ifdef SILK_DATA_ROOTDIR
    const char *root = "" SILK_DATA_ROOTDIR "";
#else
    const char *root = NULL;
#endif

#ifdef __CYGWIN__
    if (skCygwinGetDataRootDir(default_rootdir, sizeof(default_rootdir))
        != NULL)
    {
        return default_rootdir;
    }
#endif
    if (default_rootdir[0]) {
        return default_rootdir;
    }
    if (root && root[0] == '/') {
        strncpy(default_rootdir, root, sizeof(default_rootdir));
    } else {
        strncpy(default_rootdir, FALLBACK_DATA_ROOTDIR,
                sizeof(default_rootdir));
    }
    default_rootdir[sizeof(default_rootdir)-1] = '\0';
    return default_rootdir;
}


char *
sksiteGetRootDir(
    char               *buffer,
    size_t              bufsize)
{
    if (bufsize < 1+strlen(data_rootdir)) {
        return NULL;
    }
    strncpy(buffer, data_rootdir, bufsize);
    return buffer;
}


int
sksiteSetRootDir(
    const char         *rootdir)
{
    if (rootdir == NULL || rootdir[0] == '\0')  {
        return -1;
    }
    if (strlen(rootdir) >= sizeof(data_rootdir)) {
        return -1;
    }
    strncpy(data_rootdir, rootdir, sizeof(data_rootdir));
    return 0;
}


int
sksiteSetPathFormat(
    const char         *format)
{
    if ((format == NULL) || (format[0] == '\0')) {
        return -1;
    }
    if (strlen(format) + 1 > sizeof(path_format)) {
        return -1;
    }
    strncpy(path_format, format, sizeof(path_format));
    path_format[sizeof(path_format)-1] = '\0';
    return 0;
}


char *
sksiteGetPackingLogicPath(
    char               *buffer,
    size_t              bufsize)
{
    if (packing_logic_path[0] == '\0') {
        return NULL;
    }
    if (bufsize < 1+strlen(packing_logic_path)) {
        return NULL;
    }
    strncpy(buffer, packing_logic_path, bufsize);
    return buffer;
}


int
sksiteSetPackingLogicPath(
    const char         *pathname)
{
    if ((pathname == NULL) || (pathname[0] == '\0')) {
        return -1;
    }
    if (strlen(pathname) + 1 > sizeof(packing_logic_path)) {
        return -1;
    }
    strncpy(packing_logic_path, pathname, sizeof(packing_logic_path));
    packing_logic_path[sizeof(packing_logic_path)-1] = '\0';
    return 0;
}


char *
sksiteGeneratePathname(
    char               *buffer,
    size_t              bufsize,
    sk_flowtype_id_t    flowtype_id,
    sk_sensor_id_t      sensor_id,
    sktime_t            timestamp,
    const char         *suffix,
    char              **reldir_begin,
    char              **filename_begin)
{
    /* convert sktime_t to time_t platforms */
    const time_t tt = (time_t)(timestamp / 1000);
    struct tm trec;
    char ftype_name_buffer[SK_MAX_STRLEN_FLOWTYPE+1];
    char sensor_name_buffer[SK_MAX_STRLEN_SENSOR+1];
    const char *suf = NULL;
    const char *pos;
    const char *next_pos;
    char *buf;
    size_t len;

    if (buffer == NULL || bufsize == 0) {
        return NULL;
    }

    if (!sksiteFlowtypeExists(flowtype_id)) {
        return NULL;
    }

    if (!sksiteSensorExists(sensor_id)) {
        return NULL;
    }

    /* set 'suf' to the suffix if it was provided and not the empty
     * string; ignore the leading '.' if suffix, it is added later. */
    if (suffix && *suffix) {
        suf = suffix;
        if (*suf == '.') {
            ++suf;
        }
    }

    gmtime_r(&tt, &trec);

    buf = buffer;

    /* First, add the data_rootdir */
    len = snprintf(buf, bufsize, "%s/", data_rootdir);
    if (len >= bufsize) {
        return NULL;
    }
    buf += len;
    bufsize -= len;

    /* Apply the format */
    pos = path_format;
    while (NULL != (next_pos = strchr(pos, '%'))) {
        assert(strchr(path_format_conversions, next_pos[1]));
        /* copy text we just jumped over */
        len = next_pos - pos;
        if (len >= bufsize) {
            return NULL;
        }
        strncpy(buf, pos, len);
        buf += len;
        bufsize -= len;
        /* handle conversion */
        pos = next_pos + 1;
        switch (*pos) {
          case '%':
            if (bufsize >= 1) {
                buf[0] = '%';
            }
            len = 1;
            break;
          case 'C':
            len = sksiteFlowtypeGetClass(buf, bufsize, flowtype_id);
            break;
          case 'F':
            len = sksiteFlowtypeGetName(buf, bufsize, flowtype_id);
            break;
          case 'H':
            len = snprintf(buf, bufsize, "%02d", trec.tm_hour);
            break;
          case 'N':
            len = sksiteSensorGetName(buf, bufsize, sensor_id);
            break;
          case 'T':
            len = sksiteFlowtypeGetType(buf, bufsize, flowtype_id);
            break;
          case 'Y':
            len = snprintf(buf, bufsize, "%04d", trec.tm_year + 1900);
            break;
          case 'd':
            len = snprintf(buf, bufsize, "%02d", trec.tm_mday);
            break;
          case 'f':
            len = snprintf(buf, bufsize, "%u", flowtype_id);
            break;
          case 'm':
            len = snprintf(buf, bufsize, "%02d", trec.tm_mon + 1);
            break;
          case 'n':
            len = snprintf(buf, bufsize, "%u", sensor_id);
            break;
          case 'x':
            sksiteFlowtypeGetName(ftype_name_buffer, sizeof(ftype_name_buffer),
                                  flowtype_id);
            sksiteSensorGetName(sensor_name_buffer,
                                sizeof(sensor_name_buffer), sensor_id);
            len = snprintf(buf, bufsize, "%s-%s_%04d%02d%02d.%02d",
                           ftype_name_buffer, sensor_name_buffer,
                           trec.tm_year + 1900,
                           trec.tm_mon + 1, trec.tm_mday, trec.tm_hour);
            break;
          default:
            skAbortBadCase((int)*pos);
        }
        if (len >= bufsize) {
            return NULL;
        }
        ++pos;
        buf += len;
        bufsize -= len;
    }
    /* handle remaining text (since %x is always last, this should
     * never be needed) */
    len = snprintf(buf, bufsize, "%s", pos);
    if (len >= bufsize) {
        return NULL;
    }
    buf += len;
    bufsize -= len;

    /* Optionally add suffix */
    if (suf) {
        len = snprintf(buf, bufsize, ".%s", suf);
        if (len >= bufsize) {
            return NULL;
        }
        buf += len;
        bufsize -= len;
    }

    /* And finally, add NUL (probably not necessary since NUL should
     * have been added at each step above) */
    if (bufsize == 0) {
        return NULL;
    }
    *buf = '\0';

    if (reldir_begin) {
        *reldir_begin = &buffer[1+strlen(data_rootdir)];
    }
    if (filename_begin) {
        *filename_begin = strrchr(buffer, '/') + 1;
    }

    return buffer;
}


sk_flowtype_id_t
sksiteParseFilename(
    sk_flowtype_id_t   *out_flowtype,
    sk_sensor_id_t     *out_sensor,
    sktime_t           *out_timestamp,
    const char        **out_suffix,
    const char         *filename)
{
    char buf[PATH_MAX];
    char *cp;
    char *sp;
    char *ep;
    sk_flowtype_id_t ft;
    unsigned long temp1, temp2;

    /* check input */
    if (!filename) {
        return SK_INVALID_FLOWTYPE;
    }

    /* copy file portion of filename into buf */
    sp = skBasename_r(buf, filename, sizeof(buf));
    if (sp == NULL) {
        /* input name too long */
        return SK_INVALID_FLOWTYPE;
    }

    /* find the flowtype/sensor separator, which is a hyphen, e.g.,
     * "in-S2".  The while() loop is here to support flowtypes that
     * contain hyphens.  (For this to work correctly, we really should
     * make certain we do not allow one flowtype that is a substring of
     * another at the '-', e.g., "in" and "in-web"). */
    cp = sp;
    while ((ep = strchr(cp, '-')) != NULL) {
        *ep = '\0';

        /* see if file type exists */
        ft = sksiteFlowtypeLookup(sp);
        if (ft != SK_INVALID_FLOWTYPE) {
            /* it does */
            ++ep;
            break;
        }
        /* else we failed; restore 'ep' and move 'cp' to the character
         * after 'ep' and try again. */
        *ep = '-';
        cp = ep + 1;
    }
    if (NULL == ep) {
        return SK_INVALID_FLOWTYPE;
    }
    if (out_flowtype) {
        *out_flowtype = ft;
    }

    /* find the sensor/timestamp separator, which is an underscore,
     * e.g., "S2_20120926".  Sensors may not contain an underscore. */
    sp = ep;
    ep = strchr(sp, '_');
    if (NULL == ep) {
        return SK_INVALID_FLOWTYPE;
    }
    *ep = '\0';
    ++ep;

    if (out_sensor) {
        *out_sensor = siteSensorLookup2(sp, ep - sp - 1);
    }

    /* move to start of time; convert "YYYYMMDD." into a single
     * integer, then pull out each part */
    sp = ep;
    errno = 0;
    temp1 = strtoul(sp, &ep, 10);
    if (sp == ep || *ep != '.' || (temp1 == ULONG_MAX && errno == ERANGE)
        || (temp1 < 19700101 || temp1 >= 20380119))
    {
        return SK_INVALID_FLOWTYPE;
    }

    /* now handle the hour "HH." or "HH\0" */
    sp = ep + 1;
    errno = 0;
    temp2 = strtoul(sp, &ep, 10);
    if (sp == ep || (*ep != '.' && *ep != '\0')
        || (temp2 == ULONG_MAX && errno == ERANGE) || (temp2 > 23))
    {
        return SK_INVALID_FLOWTYPE;
    }

    if (out_timestamp) {
        struct tm trec;
        time_t t;

        memset(&trec, 0, sizeof(struct tm));
        trec.tm_mday = temp1 % 100;
        temp1 /= 100;
        trec.tm_mon  = temp1 % 100 - 1;
        trec.tm_year = (temp1 / 100) - 1900;
        trec.tm_hour = temp2;
        t = timegm(&trec);
        if (t == (time_t)(-1)) {
            return SK_INVALID_FLOWTYPE;
        }
        *out_timestamp = sktimeCreate(t, 0);
    }

    if (out_suffix) {
        *out_suffix = &filename[ep-buf];
    }

    return ft;
}


char *
sksiteParseGeneratePath(
    char               *buffer,
    size_t              bufsize,
    const char         *filename,
    const char         *suffix,
    char              **reldir_begin,
    char              **filename_begin)
{
    sk_flowtype_id_t flowtype;
    sk_sensor_id_t sensor;
    sktime_t timestamp;
    const char *old_suffix;
    char new_suffix[PATH_MAX];

    if (sksiteParseFilename(&flowtype, &sensor, &timestamp, &old_suffix,
                            filename)
        == SK_INVALID_FLOWTYPE)
    {
        return NULL;
    }

    if (*old_suffix != '\0' && suffix == NULL) {
        /* there was a suffix on 'filename' and the caller didn't
         * provide a new suffix; append old suffix to new name */
        if (strlen(old_suffix) >= sizeof(new_suffix)) {
            /* suffix too long */
            return NULL;
        }
        strncpy(new_suffix, old_suffix, sizeof(new_suffix));
        suffix = new_suffix;
    }

    return sksiteGeneratePathname(buffer, bufsize, flowtype, sensor, timestamp,
                                  suffix, reldir_begin, filename_begin);
}


/** Special Support Functions *****************************************/

/*
 *  ok = sksiteValidateFlowtypes(ft_vec,ft_count,ft_strings,delim,error_iter);
 *
 *    Validate the class/type pairs specified in the character pointer
 *    array 'ft_strings'.  Each value in the array should contain a
 *    valid class name and type name, with the names separated by the
 *    character 'delim'.  The class name and/or the type name may be
 *    "all".
 *
 *    If 'ft_count' is non-negative, it is used as the number of
 *    entries in 'ft_strings'.  If 'ft_count' is negative,
 *    'ft_strings' is treated a NULL-terminated array.
 *
 *    The valid flowtype IDs are appended to the 'ft_vec' vector,
 *    unless the flowtype ID is already present in 'ft_vec'.
 *
 *    If 'error_iter' is non-NULL and an invalid class/type pair is
 *    encountered, a new sksite_error_iterator_t is allocated at the
 *    specified location, and an appropriate error code is added to
 *    the iterator, along with a pointer into the 'ft_strings' array.
 *    The caller must ensure that entries in the 'ft_strings' array
 *    remain valid while iterating over the errors.
 *
 *    The function returns 0 if all flowtypes were valid.  A return
 *    value of -1 indicates invalid input---for example, 'ft_vec'
 *    elements are not the correct size. A positive return value
 *    indicates the number of invalid class/type pairs.
 */
int
sksiteValidateFlowtypes(
    sk_vector_t                *flowtypes_vec,
    int                         flowtype_count,
    const char                **flowtype_strings,
    char                        separator,
    sksite_error_iterator_t   **out_error_iter)
{
    BITMAP_DECLARE(flowtype_seen, SK_MAX_NUM_FLOWTYPES);
    char class_name[2 + SK_MAX_STRLEN_FLOWTYPE];
    sksite_error_iterator_t *error_iter = NULL;
    const char *type_name;
    const char *ft_string;
    sk_flowtype_iter_t fi;
    sk_flowtype_id_t ft;
    sk_class_id_t class_id;
    int invalid_count = 0;
    size_t num_flowtypes;
    size_t i;
    int rv = -1;

    sksiteConfigure(0);

    /* get number of flowtypes */
    if (flowtype_count >= 0) {
        num_flowtypes = flowtype_count;
    } else {
        /* null terminated array; count entries */
        num_flowtypes = 0;
        while (flowtype_strings[num_flowtypes]) {
            ++num_flowtypes;
        }
    }
    if (0 == num_flowtypes) {
        return 0;
    }

    /* check the incoming vector */
    if (NULL == flowtypes_vec
        || skVectorGetElementSize(flowtypes_vec) != sizeof(sk_flowtype_id_t))
    {
        goto END;
    }

    /* 'flowtype_seen' keeps track of which flowtypes we have seen;
     * initialize it with values from the incoming vector */
    BITMAP_INIT(flowtype_seen);
    for (i = 0; 0 == skVectorGetValue(&ft, flowtypes_vec, i); ++i) {
        BITMAP_SETBIT(flowtype_seen, ft);
    }

    /* create the object that holds invalid tokens */
    if (out_error_iter) {
        if (siteErrorIterCreate(&error_iter)) {
            goto END;
        }
    }

    /* process each string in 'flowtype_strings' */
    for (i = 0; i < num_flowtypes; ++i) {
        ft_string = flowtype_strings[i];

        /* copy class part of the string into a separate buffer */
        if ('\0' == separator) {
            type_name = ft_string + strlen(ft_string);
        } else {
            type_name = strchr(ft_string, separator);
            if (NULL == type_name) {
                ++invalid_count;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_FLOWTYPE_NO_DELIM,
                        SKSITE_ERR_FLOWTYPE_NO_DELIM_MSG, ft_string, separator))
                {
                    goto END;
                }
                continue;
            }
        }
        if ((type_name - ft_string) > ((int)sizeof(class_name) - 1)) {
            ++invalid_count;
            if (siteErrorIterPush(
                    error_iter, SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS,
                    SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS_MSG, ft_string))
            {
                goto END;
            }
            continue;
        }
        strncpy(class_name, ft_string, sizeof(class_name));
        class_name[type_name - ft_string] = '\0';
        ++type_name;

        /* find class and type.  if lookup fails, test for special
         * "all" keyword */
        ft = sksiteFlowtypeLookupByClassType(class_name, type_name);
        if (SK_INVALID_FLOWTYPE != ft) {
            /* The class and type pair is valid */
            if (!BITMAP_GETBIT(flowtype_seen, ft)) {
                BITMAP_SETBIT(flowtype_seen, ft);
                if (skVectorAppendValue(flowtypes_vec, &ft)) {
                    goto END;
                }
            }

        } else if (0 == strcmp(class_name, "all")) {
            if (0 == strcmp(type_name, "all")) {
                /* Use all classes and all types. */
                sksiteFlowtypeIterator(&fi);
                while (sksiteFlowtypeIteratorNext(&fi, &ft)) {
                    if (!BITMAP_GETBIT(flowtype_seen, ft)) {
                        BITMAP_SETBIT(flowtype_seen, ft);
                        if (skVectorAppendValue(flowtypes_vec, &ft)) {
                            goto END;
                        }
                    }
                }
            } else {
                /* Loop over all classes and add flowtype if type_name
                 * is valid for that class.  Don't complain unless the
                 * type in not valid for any class. */
                sk_class_iter_t ci;
                int found_type = 0;

                sksiteClassIterator(&ci);
                while (sksiteClassIteratorNext(&ci, &class_id)) {
                    ft = sksiteFlowtypeLookupByClassIDType(class_id,type_name);
                    if (SK_INVALID_FLOWTYPE != ft) {
                        ++found_type;
                        if (!BITMAP_GETBIT(flowtype_seen, ft)) {
                            BITMAP_SETBIT(flowtype_seen, ft);
                            if (skVectorAppendValue(flowtypes_vec, &ft)) {
                                goto END;
                            }
                        }
                    }
                }
                if (!found_type) {
                    ++invalid_count;
                    if (siteErrorIterPush(
                            error_iter, SKSITE_ERR_FLOWTYPE_UNKNOWN_TYPE,
                            SKSITE_ERR_FLOWTYPE_UNKNOWN_TYPE_MSG, ft_string))
                    {
                        goto END;
                    }
                }
            }

        } else if (0 == strcmp(type_name, "all")) {
            /* Use all types in the specified class */
            class_id = sksiteClassLookup(class_name);
            if (SK_INVALID_CLASS == class_id) {
                ++invalid_count;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS,
                        SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS_MSG, ft_string))
                {
                    goto END;
                }
            } else {
                sksiteClassFlowtypeIterator(class_id, &fi);
                while (sksiteFlowtypeIteratorNext(&fi, &ft)) {
                    if (!BITMAP_GETBIT(flowtype_seen, ft)) {
                        BITMAP_SETBIT(flowtype_seen, ft);
                        if (skVectorAppendValue(flowtypes_vec, &ft)) {
                            goto END;
                        }
                    }
                }
            }

        } else {
            /* Invalid class/type */
            ++invalid_count;
            if (SK_INVALID_CLASS == sksiteClassLookup(class_name)) {
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS,
                        SKSITE_ERR_FLOWTYPE_UNKNOWN_CLASS_MSG, ft_string))
                {
                    goto END;
                }
            } else {
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_FLOWTYPE_TYPE_NOT_IN_CLASS,
                        SKSITE_ERR_FLOWTYPE_TYPE_NOT_IN_CLASS_MSG, ft_string))
                {
                    goto END;
                }
            }
        }
    }

    /* set out_error_iter if we encountered invalid tokens */
    if (NULL != out_error_iter && invalid_count > 0) {
        *out_error_iter = error_iter;
        error_iter = NULL;
    }

    rv = 0;

  END:
    sksiteErrorIteratorFree(error_iter);
    if (0 == rv) {
        return invalid_count;
    }
    return rv;
}


/*
 *  ok = sksiteValidateSensors(s_vec, ft_vec, s_count, s_strings, error_iter);
 *
 *    Validate the sensor names and/or sensor IDs listed in the
 *    character pointer array 's_strings'.  Each value in the array
 *    should contain a valid sensor name or a valid sensor numeric ID.
 *
 *    If 's_count' is non-negative, it is used as the number of
 *    entries in 's_strings'.  If 's_count' is negative, 's_strings'
 *    is treated a NULL-terminated array.
 *
 *    The valid sensor IDs are appended to the 's_vec' vector,
 *    unless the sensor ID is already present in 's_vec'.
 *
 *    If 'ft_vec' is non-NULL, it should point to a vector containing
 *    flowtype IDs, and only sensors that exist in the specified
 *    flowtypes will be added to 's_vec'.  Other sensors are treated
 *    as invalid.
 *
 *    If 'error_iter' is non-NULL and an invalid sensor is
 *    encountered, a new sksite_error_iterator_t is allocated at the
 *    specified location, and an appropriate error code is added to
 *    the iterator, along with a pointer into the 's_strings' array.
 *    The caller must ensure that entries in the 's_strings' array
 *    remain valid while iterating over the errors.
 *
 *    The function returns 0 if all sensors were valid.  A return
 *    value of -1 indicates invalid input---for example, 's_vec'
 *    elements are not the correct size. A positive return value
 *    indicates the number of invalid sensors.
 */
int
sksiteValidateSensors(
    sk_vector_t                *sensors_vec,
    const sk_vector_t          *flowtypes_vec,
    int                         sensor_count,
    const char                **sensor_strings,
    sksite_error_iterator_t   **out_error_iter)
{
    BITMAP_DECLARE(classes, SK_MAX_NUM_FLOWTYPES);
    sksite_error_iterator_t *error_iter = NULL;
    const char *sen_string = NULL;
    sk_bitmap_t *sensor_bits = NULL;
    uint32_t min_sensor_id;
    uint32_t max_sensor_id;
    uint32_t tmp32;
    sk_sensor_id_t sid = SK_INVALID_SENSOR;
    sk_flowtype_id_t ft;
    int found_sensor;
    sk_class_iter_t ci;
    sk_class_id_t class_of_sensor;
    int invalid_count = 0;
    size_t num_sensors;
    size_t i;
    int rv = -1;

    sksiteConfigure(0);

    min_sensor_id = sksiteSensorGetMinID();
    max_sensor_id = sksiteSensorGetMaxID();
    BITMAP_INIT(classes);

    /* get number of sensors */
    if (sensor_count >= 0) {
        num_sensors = sensor_count;
    } else {
        /* null terminated array; count entries */
        num_sensors = 0;
        while (sensor_strings[num_sensors]) {
            ++num_sensors;
        }
    }
    if (0 == num_sensors) {
        return 0;
    }

    /* check the incoming vector */
    if (NULL == sensors_vec
        || skVectorGetElementSize(sensors_vec) != sizeof(sk_sensor_id_t))
    {
        goto END;
    }

    /* if flowtypes_vec was given, we limit the sensors to the sensors
     * that appear in those classes */
    if (NULL == flowtypes_vec) {
        /* accept all sensors */
        memset(classes, 0xFF, sizeof(classes));
    } else {
        if (skVectorGetElementSize(flowtypes_vec) != sizeof(sk_flowtype_id_t)){
            goto END;
        }
        for (i = 0; 0 == skVectorGetValue(&ft, flowtypes_vec, i); ++i) {
            BITMAP_SETBIT(classes, sksiteFlowtypeGetClassID(ft));
        }
    }

    /* create a bitmap for all the sensors */
    if (skBitmapCreate(&sensor_bits, 1 + max_sensor_id)) {
        goto END;
    }

    /* Sets bits in 'sensor_bits' for IDs already present in the vector */
    for (i = 0; 0 == skVectorGetValue(&sid, sensors_vec, i); ++i) {
        skBitmapSetBit(sensor_bits, sid);
    }

    /* create the object that holds invalid tokens */
    if (out_error_iter) {
        if (siteErrorIterCreate(&error_iter)) {
            goto END;
        }
    }

    /* process at each string in 'sensor_strings' */
    for (i = 0; i < num_sensors; ++i) {
        sen_string = sensor_strings[i];

        /* lookup sen_string as a sensor name; if that fails, try it
         * as a sensor id */
        sid = sksiteSensorLookup(sen_string);
        if (SK_INVALID_SENSOR == sid) {
            if (0 != skStringParseUint32(&tmp32, sen_string,
                                         min_sensor_id, max_sensor_id))
            {
                ++invalid_count;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_UNKNOWN_SENSOR,
                        SKSITE_ERR_UNKNOWN_SENSOR_MSG, sen_string))
                {
                    goto END;
                }
                continue;
            }
            sid = (sk_sensor_id_t)tmp32;
            if (!sksiteSensorExists(sid)) {
                ++invalid_count;
                if (siteErrorIterPush(
                        error_iter, SKSITE_ERR_UNKNOWN_SENSOR_ID,
                        SKSITE_ERR_UNKNOWN_SENSOR_ID_MSG, sen_string))
                {
                    goto END;
                }
                continue;
            }
        }

        if (!skBitmapGetBit(sensor_bits, sid)) {
            if (NULL == flowtypes_vec) {
                if (skVectorAppendValue(sensors_vec, &sid)) {
                    goto END;
                }
            } else {
                /* loop 'class_of_sensor' over all classes that 'sid'
                 * is a member of */
                found_sensor = 0;
                sksiteSensorClassIterator(sid, &ci);
                while (sksiteClassIteratorNext(&ci, &class_of_sensor)) {
                    if (BITMAP_GETBIT(classes, class_of_sensor)) {
                        found_sensor = 1;
                        skBitmapSetBit(sensor_bits, sid);
                        if (skVectorAppendValue(sensors_vec, &sid)) {
                            goto END;
                        }
                        break;
                    }
                }

                /* warn about unused sensor */
                if (0 == found_sensor) {
                    ++invalid_count;
                    if (siteErrorIterPush(
                            error_iter, SKSITE_ERR_SENSOR_NOT_IN_CLASSES,
                            SKSITE_ERR_SENSOR_NOT_IN_CLASSES_MSG, sen_string))
                    {
                        goto END;
                    }
                }
            }
        }
    }

    /* set out_error_iter if we encountered invalid tokens */
    if (NULL != out_error_iter && invalid_count > 0) {
        *out_error_iter = error_iter;
        error_iter = NULL;
    }

    rv = 0;

  END:
    sksiteErrorIteratorFree(error_iter);
    if (sensor_bits) {
        skBitmapDestroy(&sensor_bits);
    }
    if (0 == rv) {
        return invalid_count;
    }
    return rv;
}


/** DATA_ROOTDIR File Iteration (fglob) *******************************/

/* typedef struct sksite_repo_iter_st sksite_repo_iter_t; */
struct sksite_repo_iter_st {
    sk_vector_t    *sen_ft_vec;
    size_t          sensor_idx;
    sktime_t        time_start;
    sktime_t        time_end;
    sktime_t        time_idx;
    uint32_t        flags;
    uint8_t         first_call;
};

typedef struct sensor_flowtype_st {
    sk_sensor_id_t      sensor;
    sk_flowtype_id_t    flowtype;
} sensor_flowtype_t;


/*
 *  more_files = siteRepoIterIncrement(iter, &attr);
 *
 *    Increment the file iterator so that it points to the next file,
 *    and set the values in 'attr' to the tuple for that file.
 *
 *    Return 1 if the iterator moved to the next file, or 0 if there
 *    are no more files.
 */
static int
siteRepoIterIncrement(
    sksite_repo_iter_t *iter,
    sksite_fileattr_t  *attr)
{
    sensor_flowtype_t sen_ft;

    /* Make certain we haven't reached the end of the data. */
    if (iter->time_idx > iter->time_end) {
        return 0;
    }

    if (iter->first_call) {
        iter->first_call = 0;
        assert(iter->sensor_idx == 0);
        if (skVectorGetValue(&sen_ft, iter->sen_ft_vec, iter->sensor_idx) == 0)
        {
            attr->sensor = sen_ft.sensor;
            attr->flowtype = sen_ft.flowtype;
            attr->timestamp = iter->time_idx;
            return 1;
        }
        /* Empty iterator */
        return 0;
    }

    /* First, see if we can increment the sensor/flowtype pair */
    ++iter->sensor_idx;
    if (skVectorGetValue(&sen_ft, iter->sen_ft_vec, iter->sensor_idx) == 0) {
        attr->sensor = sen_ft.sensor;
        attr->flowtype = sen_ft.flowtype;
        attr->timestamp = iter->time_idx;
        return 1;
    }
    /* On last sensor/flowtype; reset and try time */
    iter->sensor_idx = 0;

    /* Finally, increment the time: go to next hour */
    iter->time_idx += 3600000;
    if (iter->time_idx > iter->time_end) {
        /* We're done. */
        return 0;
    }

    if (skVectorGetValue(&sen_ft, iter->sen_ft_vec, iter->sensor_idx) != 0) {
        return 0;
    }
    attr->sensor = sen_ft.sensor;
    attr->flowtype = sen_ft.flowtype;
    attr->timestamp = iter->time_idx;
    return 1;
}


/*
 *  more_files = siteRepoIterNext(iter, &attr, name, name_len, &is_missing);
 *
 *    Increment the file iterator so that it points to the next file,
 *    set the values in 'attr' to the tuple for that file, set 'name'
 *    to the pathname to that file, and, if 'is_missing' is not NULL,
 *    set 'is_missing' to 0 if the file exists, or 1 if it does not.
 *
 *    Return SK_ITERATOR_OK if the iterator moved to the next file, or
 *    SK_ITERATOR_NO_MORE_ENTRIES if there are no more files.
 */
static int
siteRepoIterNext(
    sksite_repo_iter_t *iter,
    sksite_fileattr_t  *attr,
    char               *name,
    size_t              name_len,
    int                *is_missing)
{
    const char suffix[] = ".gz";
    char *cp;

    assert(iter);
    assert(attr);
    assert(name);

    while (siteRepoIterIncrement(iter, attr)) {

        /* check whether file exists */
        if (NULL == sksiteGeneratePathname(name, name_len, attr->flowtype,
                                           attr->sensor, attr->timestamp,
                                           suffix, NULL, NULL))
        {
            /* error */
            continue;
        }

        cp = &name[strlen(name) + 1 - sizeof(suffix)];
        *cp = '\0';
        if (skFileExists(name)) {
            if (is_missing) {
                *is_missing = 0;
            }
            return SK_ITERATOR_OK;
        }
        *cp = '.';
        if (skFileExists(name)) {
            if (is_missing) {
                *is_missing = 0;
            }
            return SK_ITERATOR_OK;
        }
        *cp = '\0';
        if (iter->flags & RETURN_MISSING) {
            if (is_missing) {
                *is_missing = 1;
            }
            return SK_ITERATOR_OK;
        }
    }

    return SK_ITERATOR_NO_MORE_ENTRIES;
}


int
sksiteRepoIteratorCreate(
    sksite_repo_iter_t    **iter,
    const sk_vector_t      *flowtypes_vec,
    const sk_vector_t      *sensor_vec,
    sktime_t                start_time,
    sktime_t                end_time,
    uint32_t                flags)
{
    sensor_flowtype_t sen_ft;
    sk_sensor_iter_t sen_iter;
    sk_flowtype_id_t ft;
    sk_class_id_t class_id;
    sk_sensor_id_t sid;
    size_t i, j;

    if (NULL == iter
        || NULL == flowtypes_vec
        || sizeof(sk_flowtype_id_t) != skVectorGetElementSize(flowtypes_vec)
        || end_time < start_time)
    {
        return -1;
    }
    if (sensor_vec
        && sizeof(sk_sensor_id_t) != skVectorGetElementSize(sensor_vec))
    {
        return -1;
    }

    memset(&sen_ft, 0, sizeof(sensor_flowtype_t));

    *iter = (sksite_repo_iter_t*)calloc(1, sizeof(sksite_repo_iter_t));
    if (NULL == *iter) {
        return -1;
    }

    (*iter)->sen_ft_vec = skVectorNew(sizeof(sensor_flowtype_t));
    if (NULL == (*iter)->sen_ft_vec) {
        sksiteRepoIteratorDestroy(iter);
        return -1;
    }

    (*iter)->time_start = start_time;
    (*iter)->time_end = end_time;
    (*iter)->flags = flags;

    for (i = 0; 0 == skVectorGetValue(&ft, flowtypes_vec, i); ++i) {
        class_id = sksiteFlowtypeGetClassID(ft);
        if (NULL == sensor_vec) {
            sksiteClassSensorIterator(class_id, &sen_iter);
            while (sksiteSensorIteratorNext(&sen_iter, &sid)) {
                sen_ft.sensor = sid;
                sen_ft.flowtype = ft;
                if (skVectorAppendValue((*iter)->sen_ft_vec, &sen_ft)) {
                    sksiteRepoIteratorDestroy(iter);
                    return -1;
                }
            }
        } else {
            for (j = 0; 0 == skVectorGetValue(&sid, sensor_vec, j); ++j) {
                if (sksiteIsSensorInClass(sid, class_id)) {
                    sen_ft.sensor = sid;
                    sen_ft.flowtype = ft;
                    if (skVectorAppendValue((*iter)->sen_ft_vec, &sen_ft)) {
                        sksiteRepoIteratorDestroy(iter);
                        return -1;
                    }
                }
            }
        }
    }

    sksiteRepoIteratorReset(*iter);

    return 0;
}


void
sksiteRepoIteratorDestroy(
    sksite_repo_iter_t    **iter)
{
    if (iter && *iter) {
        if ((*iter)->sen_ft_vec) {
            skVectorDestroy((*iter)->sen_ft_vec);
        }
        memset(*iter, 0, sizeof(sksite_repo_iter_t));
        free(*iter);
    }
}


int
sksiteRepoIteratorNextFileattr(
    sksite_repo_iter_t *iter,
    sksite_fileattr_t  *fileattr,
    int                *is_missing)
{
    char path[PATH_MAX];

    return siteRepoIterNext(iter, fileattr, path, sizeof(path), is_missing);
}

int
sksiteRepoIteratorNextPath(
    sksite_repo_iter_t *iter,
    char               *path,
    size_t              path_len,
    int                *is_missing)
{
    sksite_fileattr_t attr;

    return siteRepoIterNext(iter, &attr, path, path_len, is_missing);
}


int
sksiteRepoIteratorNextStream(
    sksite_repo_iter_t     *iter,
    skstream_t            **stream,
    int                    *is_missing,
    sk_msg_fn_t             err_fn)
{
    char path[PATH_MAX];
    sksite_fileattr_t attr;
    int file_missing;
    int rv;

    if (NULL == is_missing) {
        is_missing = &file_missing;
    }

    do {
        rv = siteRepoIterNext(iter, &attr, path, sizeof(path), is_missing);
        if (0 != rv) {
            return rv;
        }

        if (*is_missing) {
            if ((rv = skStreamCreate(stream, SK_IO_READ, SK_CONTENT_SILK_FLOW))
                || (rv = skStreamBind(*stream, path)))
            {
                if (err_fn) {
                    skStreamPrintLastErr(*stream, rv, err_fn);
                }
                skStreamDestroy(stream);
            }
        } else {
            rv = skStreamOpenSilkFlow(stream, path, SK_IO_READ);
            if (0 != rv) {
                if (err_fn) {
                    skStreamPrintLastErr(*stream, rv, err_fn);
                }
                skStreamDestroy(stream);
            }
        }
    } while (0 != rv);

    return rv;
}


size_t
sksiteRepoIteratorGetFileattrs(
    sksite_repo_iter_t *iter,
    sksite_fileattr_t  *attr_array,
    size_t              attr_max_count)
{
    char path[PATH_MAX];
    int is_missing;
    size_t count = 0;
    sksite_fileattr_t *attr = attr_array;
    int rv;

    while (attr_max_count > 0) {
        --attr_max_count;
        rv = siteRepoIterNext(iter, attr, path, sizeof(path), &is_missing);
        if (rv) {
            return count;
        }
        ++count;
        ++attr;
    }
    return count;
}

int
sksiteRepoIteratorRemainingFileattrs(
    sksite_repo_iter_t *iter,
    sk_vector_t        *fileattr_vec)
{
    char path[PATH_MAX];
    int is_missing;
    sksite_fileattr_t attr;

    if (NULL == fileattr_vec
        || sizeof(sksite_fileattr_t) != skVectorGetElementSize(fileattr_vec))
    {
        return -1;
    }

    while (siteRepoIterNext(iter, &attr, path, sizeof(path), &is_missing)
           == SK_ITERATOR_OK)
    {
        if (skVectorAppendValue(fileattr_vec, &attr)) {
            return -1;
        }
    }
    return 0;
}


void
sksiteRepoIteratorReset(
    sksite_repo_iter_t *iter)
{
    assert(iter);

    iter->time_idx = iter->time_start;
    iter->sensor_idx = 0;
    iter->first_call = 1;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
