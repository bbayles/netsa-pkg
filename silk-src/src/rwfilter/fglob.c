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
**  10/14/2002
** Suresh L. Konda
**
** fglob.c
**
** routines for globbing files in the special dir hierarchy we have for
** packed files.
**
** There are three externally visible routines:
**  fglobSetup(): setup stuff
**  fglobNext():  call repeatedly till no more files
**  fglobTeardown(): clean up
**  fglobValid(): 1 if user specified any params; 0 else.
**
**  There is also a set of GetXX routines to gain access to the internals
**  of the fglob data structure.
**
** Details are given as block comments before these routines.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: fglob.c d5c2aee1abcc 2023-05-01 21:10:21Z mthomas $");

#include <silk/skvector.h>
#include "rwfilter.h"


/* LOCAL TYPEDEFS AND DEFINES */

/* Output handle for --print-missing-files output */
#define MISSING_FH stderr

/*
 *  Structure for all pertinent information for a given find request.
 */
typedef struct fglobListStruct_st {
    /* flag: number of globbing options specified */
    int8_t              fg_user_option_count;
    /* flag: 1 if the globber was partly initialized; 2 if completely init'd */
    int8_t              fg_initialized;
    /* flag: 1 to print msg about existence of each file */
    int8_t              fg_missing;

    /* specified class/types */
    sk_flowtype_id_t   *fg_flowtype_list;
    /* number of class/type pairs designated: length of fg_flowtype_list */
    int                 fg_flowtype_count;
    /* current class/type when globbing; index into fg_flowtype_list */
    int                 fg_flowtype_idx;

    /* list of sensor IDs wanted for each class/type */
    int               **fg_sensor_list;
    /* for each class/type, number of sensors: length of fg_sensor_list[i] */
    int                *fg_sensor_count;
    /* current sensor when globbing; index into
     * fg_sensor_list[fg_flowtype_idx] */
    int                 fg_sensor_idx;

    /* start, end, current time---as milliseconds since the UNIX epoch
     * in UTC */
    sktime_t            fg_time_start;
    sktime_t            fg_time_end;
    sktime_t            fg_time_idx;

    /* user's input to various options.  This will be an array of
     * char*, index by the FGLOB_OPT_* enum.  The array will be
     * created once we know the number of options.*/
    char              **fg_option;

} fglobListStruct_t;



/* INTERNAL FUNCTIONS */

static int fglobAdjustCountersFlowtype(void);
static int fglobParseClassAndType(void);

static int fglobInit(void);
static int fglobLoadSiteConfig(void);
static int fglobInitTimes(void);
static int fglobHandler(clientData cData, int opt_index, char *opt_arg);
static void fglobEnableAllSensors(void);
static int fglobParseSensors(sk_bitmap_t **sensor_bits_ptr);


/* INTERNAL VARIABLES */

static fglobListStruct_t fglob_list;
static fglobListStruct_t * const fList = &fglob_list;




/* OPTIONS SETUP */

enum fglobOptionEnum {
    FGLOB_OPT_CLASS, FGLOB_OPT_TYPES, FGLOB_OPT_FLOWTYPES, FGLOB_OPT_SENSORS,
    FGLOB_OPT_START_DATE, FGLOB_OPT_END_DATE,
    FGLOB_OPT_PRINT_MISSING_FILES,
    FGLOB_OPT_DATA_ROOTDIR
};

static struct option fglobOptions[] = {
    {"class",                REQUIRED_ARG, 0, FGLOB_OPT_CLASS},
    {"types",                REQUIRED_ARG, 0, FGLOB_OPT_TYPES},
    {"flowtypes",            REQUIRED_ARG, 0, FGLOB_OPT_FLOWTYPES},
    {"sensors",              REQUIRED_ARG, 0, FGLOB_OPT_SENSORS},
    {"start-date",           REQUIRED_ARG, 0, FGLOB_OPT_START_DATE},
    {"end-date",             REQUIRED_ARG, 0, FGLOB_OPT_END_DATE},
    {"print-missing-files",  NO_ARG,       0, FGLOB_OPT_PRINT_MISSING_FILES},
    {"data-rootdir",         REQUIRED_ARG, 0, FGLOB_OPT_DATA_ROOTDIR},
    {0, 0, 0, 0}
};


static const char *fglobHelp[] = {
    ("Class of data to process. May also be @FILE to read the class\n"
     "\tname from the file or file path named FILE."),
    ("Comma separated list of type(s) of data to process within\n"
     "\tthe specified class. Use @FILE within the list to read the types\n"
     "\tfrom the file or file path named FILE. Use 'all' to process\n"
     "\tevery type for the specified class. The type names and default\n"
     "\ttype(s) vary by class as shown in the table, which\n"
     "\tlists \"* class (available types) Def. default types\":"),
    ("Comma separated list of class/type pairs to process or\n"
     "\t@FILE to read class/type pairs from the file or file path named FILE.\n"
     "\tMay use 'all' for class and/or type.  This is an alternate way to\n"
     "\tspecify class/type; switch cannot be used with --class and --type"),
    ("Comma separated list of sensor names, sensor IDs, ranges\n"
     "\tof sensor IDs, and @FILE to read sensor names and IDs from the\n"
     "\tfile or file path named FILE.  Valid sensors vary by class.\n"
     "\tUse 'rwsiteinfo --fields=sensor,id-sensor,class:list' to see a\n"
     "\tmapping of sensor names to IDs and classes."),
    ("First hour of data to process.  Specify date in\n"
     "\tYYYY/MM/DD[:HH] format; time is in "
#if  SK_ENABLE_LOCALTIME
     "localtime"
#else
     "UTC"
#endif
     ".  When no hour is\n"
     "\tspecified, the entire date is processed.  Def. Start of today"),
    ("Final hour of data to process specified as YYYY/MM/DD[:HH].\n"
     "\tWhen no hour specified, end of day is used unless start-date includes\n"
     "\tan hour.  When switch not specified, defaults to value in start-date"),
    ("Print the names of missing files to STDERR.\n"
     "\tDef. No"),
    ("Root of directory tree containing packed data"),
    (char*)NULL
};

/*
 *  is_ok = fglobSetup();
 *
 *    Initialize the values in the global fList structure: set
 *    everything to zero; set times to -1.  Register fglob options and
 *    handler.  Check the environment for variable giving the location
 *    of the data.
 *
 *    Return 0 if OK. 1 else.
 */
int
fglobSetup(
    void)
{
    size_t num_opts = sizeof(fglobOptions) / sizeof(struct option);

    /* verify same number of options and help strings */
    assert((sizeof(fglobHelp)/sizeof(char *)) ==
           (sizeof(fglobOptions)/sizeof(struct option)));

    /* zero out everything */
    memset(fList, 0, sizeof(fglobListStruct_t));

    /* Create an array to hold the option strings */
    fList->fg_option = (char**)calloc(num_opts, sizeof(char*));
    if (NULL == fList->fg_option) {
        skAppPrintOutOfMemory(NULL);
        return 1;
    }

    /* set start/end days/hours to be able to trap whether user gave
     * it explicitly
     */
    fList->fg_time_start = 0;
    fList->fg_time_end = 0;

    /* register the options */
    if (skOptionsRegister(fglobOptions, &fglobHandler, (clientData)fList)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        return 1;
    }

    return 0;                     /* OK */
}


/*
 *  fglobUsageClass(fh)
 *
 *    Print the usage for the --class switch to the specified file
 *    handle.
 */
static void
fglobUsageClass(
    FILE               *fh)
{
    sk_class_id_t class_id;
    sk_class_iter_t ci;
    char class_name[SK_MAX_STRLEN_FLOWTYPE+1];
    int class_count = 0;

    /* CLASS: Use sksite to get list of classes */

    fprintf(fh, "%s", fglobHelp[FGLOB_OPT_CLASS]);

    class_id = sksiteClassGetDefault();
    if (class_id != SK_INVALID_CLASS) {
        sksiteClassGetName(class_name, sizeof(class_name), class_id);
        fprintf(fh, "  Def. %s", class_name);
    }

    sksiteClassIterator(&ci);
    while (sksiteClassIteratorNext(&ci, &class_id)) {
        sksiteClassGetName(class_name, sizeof(class_name), class_id);
        ++class_count;
        if (class_count == 1) {
            /* print first class */
            fprintf(fh, "\n\tAvailable classes: %s", class_name);
        } else {
            fprintf(fh, ",%s", class_name);
        }
    }
    fprintf(fh, "\n");
}


/*
 *  fglobUsageType(fh)
 *
 *    Print the usage for the --type switch to the specified file
 *    handle.
 */
static void
fglobUsageType(
    FILE               *fh)
{
    sk_class_id_t class_id;
    sk_class_iter_t ci;
    sk_flowtype_id_t flowtype_id;
    sk_flowtype_iter_t fi;
    char name[SK_MAX_STRLEN_FLOWTYPE+1];
    char buf[128 + SK_MAX_STRLEN_FLOWTYPE];
    char *pos;
    int len;
    int flowtype_count;
    char *maybe_wrap;
    char old_char;
    const char *line_leader = "\t  * ";
    const char *cont_line_leader = "\t    ";
    const int wrap_col = 79 - 7;

    /* TYPE: For each class, read the list of types and
     * default list of types from sksite. */

    fprintf(fh, "%s\n", fglobHelp[FGLOB_OPT_TYPES]);

    /* loop over all the classes */
    sksiteClassIterator(&ci);
    while (sksiteClassIteratorNext(&ci, &class_id)) {
        pos = buf;

        /* print class name */
        sksiteClassGetName(name, sizeof(name), class_id);
        len = snprintf(pos, sizeof(buf)-(pos-buf), "%s%s", line_leader, name);
        pos += len;

        /* loop over the flowtypes in the class */
        flowtype_count = 0;
        sksiteClassFlowtypeIterator(class_id, &fi);
        while (sksiteFlowtypeIteratorNext(&fi, &flowtype_id)) {
            sksiteFlowtypeGetType(name, sizeof(name), flowtype_id);
            ++flowtype_count;
            maybe_wrap = pos;
            if (flowtype_count == 1) {
                /* print first type for this class */
                len = snprintf(pos, sizeof(buf)-(pos-buf), " (%s", name);
                pos += len;
            } else {
                /* print remaining types for the class */
                len = snprintf(pos, sizeof(buf)-(pos-buf), ",%s", name);
                pos += len;
            }
            /* check if we need to wrap the line */
            if ((pos - buf) > wrap_col) {
                if (flowtype_count > 1) {
                    ++maybe_wrap;
                }
                old_char = *maybe_wrap;
                *maybe_wrap = '\0';
                fprintf(fh, "%s\n", buf);
                *maybe_wrap = old_char;
                pos = buf;
                len = snprintf(pos, sizeof(buf)-(pos-buf), "%s%s",
                               cont_line_leader, maybe_wrap);
                pos += len;
            }
        }
        if (flowtype_count > 0) {
            len = snprintf(pos, sizeof(buf)-(pos-buf), ").");
            pos += len;
        }
        /* loop over the default flowtypes in the class */
        flowtype_count = 0;
        sksiteClassDefaultFlowtypeIterator(class_id, &fi);
        while (sksiteFlowtypeIteratorNext(&fi, &flowtype_id)) {
            sksiteFlowtypeGetType(name, sizeof(name), flowtype_id);
            ++flowtype_count;
            maybe_wrap = pos;
            if (flowtype_count == 1) {
                /* print first default type for this class */
                len = snprintf(pos, sizeof(buf)-(pos-buf), " Def. %s", name);
                pos += len;
            } else {
                len = snprintf(pos, sizeof(buf)-(pos-buf), ",%s", name);
                pos += len;
            }
            /* check if we need to wrap the line */
            if ((pos - buf) > wrap_col) {
                if (flowtype_count > 1) {
                    ++maybe_wrap;
                }
                old_char = *maybe_wrap;
                *maybe_wrap = '\0';
                fprintf(fh, "%s\n", buf);
                if (old_char == ' ') {
                    ++maybe_wrap;
                } else {
                    *maybe_wrap = old_char;
                }
                pos = buf;
                len = snprintf(pos, sizeof(buf)-(pos-buf), "%s%s",
                               cont_line_leader, maybe_wrap);
                pos += len;
            }
        }
        fprintf(fh, "%s\n", buf);
    }
}


/*
 *  fglobUsage(fh);
 *
 *    Print, to the given file handle, the usage for the command-line
 *    switches provided by the fglob library.
 */
void
fglobUsage(
    FILE               *fh)
{
#define MIN_TEXT_ON_LINE  15
#define MAX_TEXT_ON_LINE  72

    char *cp, *ep, *sp;
    char buf[2 * PATH_MAX];
    char path[PATH_MAX];
    int have_config = 0;
    int opt;

    fprintf(fh, ("\nFILE SELECTION SWITCHES choose which files to read"
                 " from the data store:\n\n"));

    switch (sksiteConfigure(0)) {
      case 0:
        have_config = 1;
        break;
      case -1:
        fprintf(fh, "WARNING: site configuration file contains errors\n");
        break;
      case -2:
        fprintf(fh, "WARNING: site configuration file was not found\n");
        break;
      default:
        fprintf(fh, ("WARNING: site configuration file"
                     "was not found or contains errors\n"));
        break;
    }

    for (opt = 0; fglobOptions[opt].name; ++opt) {
        fprintf(fh, "--%s %s. ", fglobOptions[opt].name,
                SK_OPTION_HAS_ARG(fglobOptions[opt]));
        switch (fglobOptions[opt].val) {

          case FGLOB_OPT_CLASS:
            fglobUsageClass(fh);
            break;

          case FGLOB_OPT_TYPES:
            fglobUsageType(fh);
            break;

          case FGLOB_OPT_SENSORS:
            fprintf(fh, "%s", fglobHelp[opt]);
            if (have_config) {
                fprintf(fh, "  Valid IDs are %u--%u",
                        sksiteSensorGetMinID(), sksiteSensorGetMaxID());
            }
            fprintf(fh, "\n");
            break;

          case FGLOB_OPT_DATA_ROOTDIR:
            fprintf(fh, "%s.\n", fglobHelp[opt]);

            /* put the text into a buffer, and then wrap the text in
             * the buffer at space characters. */
            snprintf(buf, sizeof(buf),
                     ("Currently '%s'. Def. $" SILK_DATA_ROOTDIR_ENVAR
                      " or '%s'"),
                     sksiteGetRootDir(path, sizeof(path)),
                     sksiteGetDefaultRootDir());
            sp = buf;
            while (strlen(sp) > MAX_TEXT_ON_LINE) {
                cp = &sp[MIN_TEXT_ON_LINE];
                while ((ep = strchr(cp+1, ' ')) != NULL) {
                    /* text is now too long */
                    if (ep - sp > MAX_TEXT_ON_LINE) {
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
            break;

          default:
            fprintf(fh, "%s\n", fglobHelp[opt]);
            break;
        }
    }

    sksiteOptionsUsage(fh);
}


/*
 *  fglobTeardown()
 *
 *    Free the elements in fList which were malloc'ed.  Do not free
 *    the fList struct itself---it is a global static.  Multiple calls
 *    to this function are handled gracefully.
 */
void
fglobTeardown(
    void)
{
    static int teardownFlag = 0;
    int i;

    /* Idempotency check. */
    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* free our data structures */
    if (fList->fg_flowtype_list) {
        free(fList->fg_flowtype_list);
        fList->fg_flowtype_list = NULL;
    }
    if (fList->fg_sensor_list) {
        for (i = sksiteFlowtypeGetMaxID(); i >= 0; --i) {
            if (fList->fg_sensor_list[i]) {
                free(fList->fg_sensor_list[i]);
            }
        }
        free(fList->fg_sensor_list);
        fList->fg_sensor_list = NULL;
    }
    if (fList->fg_sensor_count) {
        free(fList->fg_sensor_count);
        fList->fg_sensor_count = NULL;
    }

    /* free the options */
    if (fList->fg_option) {
        free(fList->fg_option);
        fList->fg_option = NULL;
    }

    return;
}


/*
 *  filename = fglobNext();
 *
 *    Return the name of next available file.  Returns NULL if all
 *    files have been processed.
 *
 *    Will complete the initialization of the library if required.
 */
char *
fglobNext(
    char               *buf,
    size_t              bufsize)
{
    int (*file_exists_fn)(const char *path);
    char *ext;

    {
        file_exists_fn = &skFileExists;
    }

    if (!fList->fg_initialized) {
        if (fglobInit()) {
            /* error */
            return NULL;
        }
    }

    /* keep adjusting the counters until we find a file that exists */
    while (fglobAdjustCountersFlowtype()) {
        /* Create the full path to the data file from the root dir,
         * pathPrefix, year, month, day, hour, flow-type dependent
         * file prefix, and sensor name.  Create the name with a '.gz'
         * extention, but hide the extension the first time we look
         * for the file. */
        if (!sksiteGeneratePathname(
                buf, bufsize, fList->fg_flowtype_list[fList->fg_flowtype_idx],
                fList->fg_sensor_list[fList->fg_flowtype_idx]
                [fList->fg_sensor_idx], fList->fg_time_idx, ".gz", NULL, NULL))
        {
            continue;
        }

        /* hide the compression extension */
        ext = &buf[strlen(buf) - 3];
        assert(*ext == '.');
        *ext = '\0';

        if (!file_exists_fn(buf)) {
            /* check for compressed version of file */
            *ext = '.';

            if (!file_exists_fn(buf)) {
                if (fList->fg_missing) {
                    *ext = '\0';
                    fprintf(MISSING_FH, "Missing %s\n", buf);
                }
                continue;
            }
        }

        return buf;
    }

    return NULL;
}


/*
 *  count = fglobFileCount();
 *
 *    Return an estimate (upper bound) of the number of files
 *    remaining to process.  The returned value assumes that a file
 *    exists for every valid hour-flowtype-sensor tuple which is left
 *    to process.
 */
int
fglobFileCount(
    void)
{
    int count = 0;
    sktime_t hours;
    int i;

    if (!fList->fg_initialized) {
        if (fglobInit()) {
            /* error */
            return -1;
        }
    }

    /* compute number of files we visit every hour, which is the
     * number of sensors that exist for every flowtype */
    for (i = 0; i < fList->fg_flowtype_count; ++i) {
        count += fList->fg_sensor_count[i];
    }

    /* compute number of hours we have left to process */
    hours = 1 + ((fList->fg_time_end - fList->fg_time_idx) / 3600000);

    /* files to visit is the product of those two values */
    count *= hours;

    /* if no files have been processed yet, just return */
    if (fList->fg_initialized < 2) {
        return count;
    }

    /* remove the files for the flowtypes we have already processed
     * in this hour */
    for (i = 0; i < fList->fg_flowtype_idx; ++i) {
        count -= fList->fg_sensor_count[i];
    }

    /* remove the files for the sensors associated with the current
     * flowtype which we have already processed  */
    count -= fList->fg_sensor_idx;

    return count;
}


/*
 *  is_ok = fglobInit();
 *
 *    This is an internal function and should be called to initialize
 *    things based on the options given by the user.  Hence this must
 *    be called after the options are parsed.  To make life easier for
 *    the application programmer, this routine is called by the first
 *    call to fglobNext().
 *
 *    Return 0 for OK. 1 else;
 */
static int
fglobInit(
    void)
{
    fList->fg_initialized = 1;

    /* load the site config */
    if (fglobLoadSiteConfig()) {
        /* error */
        return 1;
    }

    /* set up the times */
    if (fglobInitTimes()) {
        /* error */
        return 1;
    }

    /* parse the classes and types */
    if (fglobParseClassAndType()) {
        /* error */
        return 1;
    }

    /* now parse the sensor list and check w.r.t. the class/type. */
    if (fglobParseSensors(NULL)) {
        /* error */
        return 1;
    }

    return 0;
}


/*
 *  is_ok = fglobHandler(cData, opt_index, opt_arg);
 *
 *    Called by options processor.  Return 1 on error, 0 on success.
 */
static int
fglobHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    fList->fg_user_option_count++;

    switch (opt_index) {
      case FGLOB_OPT_CLASS:
      case FGLOB_OPT_TYPES:
      case FGLOB_OPT_FLOWTYPES:
      case FGLOB_OPT_SENSORS:
      case FGLOB_OPT_START_DATE:
      case FGLOB_OPT_END_DATE:
        if (fList->fg_option[opt_index] != NULL) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          fglobOptions[opt_index].name);
            return 1;
        }
        fList->fg_option[opt_index] = opt_arg;
        break;

      case FGLOB_OPT_PRINT_MISSING_FILES:
        fList->fg_missing = 1;
        break;

      case FGLOB_OPT_DATA_ROOTDIR:
        if (!skDirExists(opt_arg)) {
            skAppPrintErr("Root data directory '%s' does not exist", opt_arg);
            return 1;
        }
        if (sksiteSetRootDir(opt_arg)) {
            skAppPrintErr("Unable to set root data directory to %s", opt_arg);
            return 1;
        }
        break;

      default:
        /* programmer error */
        skAbortBadCase(opt_index);
    }

    return 0;                     /* OK */
}


/*
 *  have_more_data = fglobAdjustCountersFlowtype();
 *
 *    Go to the next (or first if fg_initialized is < 2) sensor, or
 *    type, or class, or hour, or day.  Return 0 if there is nothing
 *    else to iterate over, or 1 otherwise.
 *
 *    fglobInit() must be called before calling this function.
 *
 *    When fg_initialized < 2, the function assumes this is the first
 *    time it has been called and it will complete the initialization
 *    of the counters that was started by fglobInit(); otherwise it
 *    will increment the counters.
 */
static int
fglobAdjustCountersFlowtype(
    void)
{
    if (fList->fg_initialized < 2) {
        /* was init called? */
        assert(fList->fg_initialized);

        /* This is the first call into this function.  All of the
         * indexes are at zero; there is nothing we need to lookup, so
         * simply set the "we've been here" flag and return. */
        fList->fg_initialized = 2;

        return 1;
    }

    /* This is not the first call into this function; need to
     * increment or reset the appropriate counters. */

    /* Make certain we haven't reached the end of the data. */
    if (fList->fg_time_idx > fList->fg_time_end) {
        return 0;
    }

    /* First, see if we can increment the sensor */
    fList->fg_sensor_idx++;
    if (fList->fg_sensor_idx < fList->fg_sensor_count[fList->fg_flowtype_idx])
    {
        /* we're good: looking at next sensor--same class, type & time */
        return 1;
    }
    /* On last sensor; reset and try class/type */
    fList->fg_sensor_idx = 0;

    /* Try to increment the class/type */
    if (fList->fg_flowtype_count > 1) {
        fList->fg_flowtype_idx++;
        if (fList->fg_flowtype_idx < fList->fg_flowtype_count) {
            /* we're good: looking at next class/type -- same time */
            return 1;
        }
        /* On last class/type; reset and try time */
        fList->fg_flowtype_idx = 0;
    }

    /* Finally, increment the time: go to next hour */
    fList->fg_time_idx += 3600000;
    if (fList->fg_time_idx > fList->fg_time_end) {
        /* We're done. */
        return 0;
    }

    return 1;
}


/*
 *  status = fglobLoadSiteConfig();
 *
 *    Load the site configuration file and allocate the arrays of
 *    flowtypes and sensors that depend on the number of items
 *    defined.  Return 0 for success, non-zero on error.
 */
static int
fglobLoadSiteConfig(
    void)
{
    int flowtype_count;
    int sensor_count;
    int i;

    /* load the site config */
    if (sksiteConfigure(1)) {
        /* error */
        return 1;
    }

    /* return if we have already allocated everything */
    if (fList->fg_sensor_count != NULL) {
        return 0;
    }

    /* Allocate memory for lists, based on sizes from sksite */
    flowtype_count = sksiteFlowtypeGetMaxID() + 1;
    sensor_count = sksiteSensorGetMaxID() + 1;

    fList->fg_flowtype_list
        = (sk_flowtype_id_t*)calloc(flowtype_count, sizeof(sk_flowtype_id_t));
    if (fList->fg_flowtype_list == NULL) {
        skAppPrintOutOfMemory(NULL);
        return 1;
    }
    fList->fg_sensor_list = (int**)calloc(flowtype_count, sizeof(int*));
    if (fList->fg_sensor_list == NULL) {
        skAppPrintOutOfMemory(NULL);
        return 1;
    }
    for (i = 0; i < flowtype_count; ++i) {
        fList->fg_sensor_list[i] = (int*)calloc(sensor_count + 1, sizeof(int));
        if (fList->fg_sensor_list[i] == NULL) {
            skAppPrintOutOfMemory(NULL);
            return 1;
        }
    }

    fList->fg_sensor_count = (int*)calloc(flowtype_count, sizeof(int));
    if (fList->fg_sensor_count == NULL) {
        skAppPrintOutOfMemory(NULL);
        return 1;
    }

    return 0;
}


/*
 *  is_ok = fglobInitTimes();
 *
 *    Verify the user's time inputs and initialize the start and end
 *    times based on the input.  Return 0 if all is well; otherwise
 *    print an error and return 1.
 */
static int
fglobInitTimes(
    void)
{
    sktime_t start_val = 0;
    sktime_t end_val = 0;
    int error_code = 0;
    int rv;

    rv = sksiteRepoIteratorParseTimes(&start_val, &end_val,
                                      fList->fg_option[FGLOB_OPT_START_DATE],
                                      fList->fg_option[FGLOB_OPT_END_DATE],
                                      &error_code);
    switch (rv) {
      case 0:
        /* parse was successful */
        fList->fg_time_start = start_val;
        fList->fg_time_end = end_val;
        /* Set the current time to the starting value. */
        fList->fg_time_idx = fList->fg_time_start;
        break;
      case 1:
        /* failed to parse start date */
        skAppPrintErr("Invalid %s '%s': %s",
                      fglobOptions[FGLOB_OPT_START_DATE].name,
                      fList->fg_option[FGLOB_OPT_START_DATE],
                      skStringParseStrerror(error_code));
        break;
      case 2:
        /* failed to parse end date */
        skAppPrintErr("Invalid %s '%s': %s",
                      fglobOptions[FGLOB_OPT_END_DATE].name,
                      fList->fg_option[FGLOB_OPT_END_DATE],
                      skStringParseStrerror(error_code));
        break;
      case -1:
        /* --end-date provided without --start-date */
        skAppPrintErr("Cannot use --%s without --%s",
                      fglobOptions[FGLOB_OPT_END_DATE].name,
                      fglobOptions[FGLOB_OPT_START_DATE].name);
        break;
      case -2:
        /* bad range */
        skAppPrintErr("%s of %s is earlier than %s of %s",
                      fglobOptions[FGLOB_OPT_END_DATE].name,
                      fList->fg_option[FGLOB_OPT_END_DATE],
                      fglobOptions[FGLOB_OPT_START_DATE].name,
                      fList->fg_option[FGLOB_OPT_START_DATE]);
        break;
      default:
        /* unexpected error */
        skAppPrintErr("Error parsing %s '%s' and/or %s '%s'",
                      fglobOptions[FGLOB_OPT_START_DATE].name,
                      fList->fg_option[FGLOB_OPT_START_DATE],
                      fglobOptions[FGLOB_OPT_END_DATE].name,
                      fList->fg_option[FGLOB_OPT_END_DATE]);
        break;
    }

    return ((rv) ? 1 : 0);
}


/*
 *  fglobEnableAllSensors();
 *
 *    For each of the configured flowtypes, add every sensor that is
 *    valid for that flowtype.
 */
static void
fglobEnableAllSensors(
    void)
{
    sk_sensor_iter_t si;
    sk_sensor_id_t sensor_id;
    sk_class_iter_t ci;
    sk_class_id_t class_of_sensor;
    int k;

    /* loop 'sensor_id' over all the sensors in silk.conf */
    sksiteSensorIterator(&si);
    while (sksiteSensorIteratorNext(&si, &sensor_id)) {

        /* loop 'class_of_sensor' over all classes 'sensor_id' is a
         * member of */
        sksiteSensorClassIterator(sensor_id, &ci);
        while (sksiteClassIteratorNext(&ci, &class_of_sensor)) {

            /* loop 'k' over all the flowtypes we are using */
            for (k = 0; k < fList->fg_flowtype_count; ++k) {

                /* if the class of the flowtype equals
                 * 'class_of_sensor', we will search over that
                 * sensor */
                if (sksiteFlowtypeGetClassID(fList->fg_flowtype_list[k])
                    == class_of_sensor)
                {
                    /* add this sensor to this flowtype */
                    fList->fg_sensor_list[k][fList->fg_sensor_count[k]++] =
                        sensor_id;
                }
            }
        }
    }
}


/*
 *  fglobAddSensor(sensor_bits, sensor_id, warn_unused);
 *
 *    Check whether 'sensor_id' has been set in the 'sensor_bits'
 *    bitmap.  If so, return immediately.
 *
 *    Otherwise, add it to the bitmap.  In addition, for the classes
 *    that have been specified that 'sensor_id' is a member of, add
 *    sensor_id to the list of sensors to process for that flowtype.
 *    If 'sensor_id' does not belong to any specified flowtypes, print
 *    a warning if 'warn_unused' is non-zero.
 */
static void
fglobAddSensor(
    sk_bitmap_t        *sensor_bits,
    sk_sensor_id_t      sensor_id,
    int                 warn_unused)
{
    int found_sensor = 0;
    sk_class_iter_t ci;
    sk_class_id_t class_of_sensor;
    int k;

    /* return if we have already processed this sensor */
    if (skBitmapGetBit(sensor_bits, sensor_id)) {
        return;
    }

    skBitmapSetBit(sensor_bits, sensor_id);

    /* loop 'class_of_sensor' over all classes that 'sensor_id' is a
     * member of */
    sksiteSensorClassIterator(sensor_id, &ci);
    while (sksiteClassIteratorNext(&ci, &class_of_sensor)) {
        /* loop 'k' over all the flowtypes we are using */
        for (k = 0; k < fList->fg_flowtype_count; ++k) {

            /* if the class of the flowtype equals 'class_of_sensor',
             * we will search over that sensor */
            if (sksiteFlowtypeGetClassID(fList->fg_flowtype_list[k])
                == class_of_sensor)
            {
                /* add this sensor to this flowtype */
                fList->fg_sensor_list[k][fList->fg_sensor_count[k]++] =
                    sensor_id;
                ++found_sensor;
            }
        }
    }

    /* warn about unused sensor */
    if ((0 == found_sensor) && warn_unused) {
        char sensor_name[SK_MAX_STRLEN_SENSOR+1];

        if (sksiteSensorExists(sensor_id)) {
            sksiteSensorGetName(sensor_name, sizeof(sensor_name), sensor_id);
            skAppPrintErr(("Ignoring sensor %s (ID=%u) that is"
                           " not used by specified flowtype%s"),
                          sensor_name, sensor_id,
                          ((fList->fg_flowtype_count > 1) ? "s" : ""));
        }
    }
}


/*
 *  is_ok = fglobParseSensors(sensor_bitmap_ptr);
 *
 *    Set the list of sensors to process based on the user's --sensor
 *    input that is specified in the fList global variable.  If the
 *    user did not specify --sensors, use all sensors for the
 *    specified flowtypes.
 *
 *    The sensor list can be a combination of named sensors and lone
 *    integers or integer ranges, separated by commas:
 *    "S01,8,3-6,S02".
 *
 *    For each sensor parsed, the fglobAddSensor() function will be
 *    called with that sensor's ID.
 *
 *    If parsing is successful and if 'sensor_bitmap_ptr' is non-NULL,
 *    an sk_bitmap_t will be created in the location it specifies.  It
 *    is the caller's responsibility to destroy the bitmap.  The
 *    'sensor_bitmap_ptr' should only be non-NULL when a --sensors
 *    value has been specified.
 *
 *    Function returns 0 on success or 1 on error: malloc error, bad
 *    sensor name, number out of range.
 */
static int
fglobParseSensors(
    sk_bitmap_t       **sensor_bits_ptr)
{
    const unsigned int flags = (SKSITE_SENSORS_ALLOW_RANGE
                                | SKSITE_SENSORS_ALLOW_GROUP);
    sk_vector_t *sensors_vec = NULL;
    sk_bitmap_t *sensor_bits = NULL;
    sksite_error_iterator_t *error_iter = NULL;
    sk_sensor_id_t id;
    size_t i;
    int rv = 0;

    /* enable all sensors if no --sensors line was given */
    if (NULL == fList->fg_option[FGLOB_OPT_SENSORS]) {
        assert(NULL == sensor_bits_ptr);
        fglobEnableAllSensors();
        return 0;
    }

    /* create a bitmap for all the sensors */
    if (skBitmapCreate(&sensor_bits, 1 + sksiteSensorGetMaxID())) {
        skAppPrintOutOfMemory(NULL);
        rv = 1;
        goto END;
    }

    /* create a vector to hold the parsed sensors */
    sensors_vec = skVectorNew(sizeof(sk_sensor_id_t));
    if (NULL == sensors_vec) {
        skAppPrintOutOfMemory(NULL);
        rv = 1;
        goto END;
    }

    rv = sksiteParseSensorList(sensors_vec,fList->fg_option[FGLOB_OPT_SENSORS],
                               NULL, NULL, flags, &error_iter);
    if (rv) {
        if (rv < 0) {
            skAppPrintErr("Invalid %s: Internal error parsing argument",
                          fglobOptions[FGLOB_OPT_SENSORS].name);
        } else if (1 == rv) {
            sksiteErrorIteratorNext(error_iter);
            skAppPrintErr("Invalid %s '%s': %s",
                          fglobOptions[FGLOB_OPT_SENSORS].name,
                          fList->fg_option[FGLOB_OPT_SENSORS],
                          sksiteErrorIteratorGetMessage(error_iter));
            assert(sksiteErrorIteratorNext(error_iter)
                   == SK_ITERATOR_NO_MORE_ENTRIES);
        } else {
            skAppPrintErr("Invalid %s '%s': Found multiple errors:",
                          fglobOptions[FGLOB_OPT_SENSORS].name,
                          fList->fg_option[FGLOB_OPT_SENSORS]);
            while (sksiteErrorIteratorNext(error_iter) == SK_ITERATOR_OK) {
                skAppPrintErr("%s", sksiteErrorIteratorGetMessage(error_iter));
            }
        }
        sksiteErrorIteratorFree(error_iter);
        error_iter = NULL;
        rv = 1;
        goto END;
    }
    if (0 == skVectorGetCount(sensors_vec)) {
        skAppPrintErr("Invalid %s '%s': No valid sensors found",
                      fglobOptions[FGLOB_OPT_SENSORS].name,
                      fList->fg_option[FGLOB_OPT_SENSORS]);
        rv = 1;
        goto END;
    }

    /* add each sensor */
    for (i = 0; 0 == skVectorGetValue(&id, sensors_vec, i); ++i) {
        fglobAddSensor(sensor_bits, id, (sensor_bits_ptr == NULL));
    }

    /* does each class/type have sensors? */
    if ((0 == rv) && skBitmapGetHighCount(sensor_bits)
        && (sensor_bits_ptr == NULL))
    {
        /* For any class/type combinations for which we didn't find a
         * sensor, print an error. */
        char class_name[SK_MAX_STRLEN_FLOWTYPE+1];
        char type_name[SK_MAX_STRLEN_FLOWTYPE+1];

        for (i = 0; i < (size_t)fList->fg_flowtype_count; ++i) {
            if (0 == fList->fg_sensor_count[i]) {
                sksiteFlowtypeGetClass(class_name, sizeof(class_name),
                                       fList->fg_flowtype_list[i]);
                sksiteFlowtypeGetType(type_name, sizeof(type_name),
                                      fList->fg_flowtype_list[i]);
                skAppPrintErr(("No corresponding sensors given for"
                               " class/type pair '%s/%s'"),
                              class_name, type_name);
                rv = 1;
                break;
            }
        }
    }

  END:
    skVectorDestroy(sensors_vec);
    if (sensor_bits_ptr && (0 == rv)) {
        *sensor_bits_ptr = sensor_bits;
    } else if (sensor_bits) {
        skBitmapDestroy(&sensor_bits);
    }

    return rv;
}


/*
 *  fglobAddFlowtype(flowtype_id);
 *
 *    Append 'flowtype_id' to the list of flowtypes to use.  However,
 *    if 'flowtype_id' has been previously added to the list of
 *    flowtypes, ignore it.
 */
static void
fglobAddFlowtype(
    sk_flowtype_id_t    flowtype_id)
{
    int j;

    assert(flowtype_id != SK_INVALID_FLOWTYPE);

    for (j = 0; j < fList->fg_flowtype_count; ++j) {
        if (flowtype_id == fList->fg_flowtype_list[j]) {
            return;
        }
    }

    fList->fg_flowtype_list[fList->fg_flowtype_count] = flowtype_id;
    ++fList->fg_flowtype_count;
}


/*
 *  ok = fglobParseFlowtypes();
 *
 *    Parse the list of comma-separated class/type pairs listed in the
 *    --flowtypes switch.  Return 0 on success, or 1 on failure.
 */
static int
fglobParseFlowtypes(
    void)
{
    sk_vector_t *flowtypes_vec = NULL;
    sksite_error_iterator_t *error_iter = NULL;
    sk_flowtype_id_t id;
    size_t i;
    int rv = 0;

    /* create a vector to hold the parsed flowtypes */
    flowtypes_vec = skVectorNew(sizeof(sk_flowtype_id_t));
    if (NULL == flowtypes_vec) {
        skAppPrintOutOfMemory(NULL);
        rv = 1;
        goto END;
    }

    rv = sksiteParseFlowtypeList(flowtypes_vec,
                                 fList->fg_option[FGLOB_OPT_FLOWTYPES],
                                 "all", "all", NULL, NULL, &error_iter);
    if (rv) {
        if (rv < 0) {
            skAppPrintErr("Invalid %s: Internal error parsing argument",
                          fglobOptions[FGLOB_OPT_FLOWTYPES].name);
        } else if (1 == rv) {
            sksiteErrorIteratorNext(error_iter);
            skAppPrintErr("Invalid %s '%s': %s",
                          fglobOptions[FGLOB_OPT_FLOWTYPES].name,
                          fList->fg_option[FGLOB_OPT_FLOWTYPES],
                          sksiteErrorIteratorGetMessage(error_iter));
            assert(sksiteErrorIteratorNext(error_iter)
                   == SK_ITERATOR_NO_MORE_ENTRIES);
        } else {
            skAppPrintErr("Invalid %s '%s': Found multiple errors:",
                          fglobOptions[FGLOB_OPT_FLOWTYPES].name,
                          fList->fg_option[FGLOB_OPT_FLOWTYPES]);
            while (sksiteErrorIteratorNext(error_iter) == SK_ITERATOR_OK) {
                skAppPrintErr("%s", sksiteErrorIteratorGetMessage(error_iter));
            }
        }
        sksiteErrorIteratorFree(error_iter);
        error_iter = NULL;
        rv = 1;
        goto END;
    }
    if (0 == skVectorGetCount(flowtypes_vec)) {
        skAppPrintErr("Invalid %s '%s': No valid flowtypes found",
                      fglobOptions[FGLOB_OPT_FLOWTYPES].name,
                      fList->fg_option[FGLOB_OPT_FLOWTYPES]);
        rv = 1;
        goto END;
    }

    /* add each flowtype */
    for (i = 0; 0 == skVectorGetValue(&id, flowtypes_vec, i); ++i) {
        fglobAddFlowtype(id);
    }

  END:
    skVectorDestroy(flowtypes_vec);
    return rv;
}


/*
 *  is_ok = fglobParseClassAndType();
 *
 *    Will parse the user's --class and --type input, or use the
 *    defaults if no class and/or type was given.  Return 0 on
 *    success, 1 on failure.
 *
 *    Will also verify that each listed type belongs to a class, and
 *    each class has at least one type.
 */
static int
fglobParseClassAndType(
    void)
{
    sk_class_id_t class_id;
    char path[PATH_MAX];
    char class_name_buf[SK_MAX_STRLEN_FLOWTYPE+1];
    char *class_name;
    sk_vector_t *class_vec = NULL;
    sk_vector_t *flowtypes_vec = NULL;
    sksite_error_iterator_t *error_iter = NULL;
    sk_flowtype_id_t id;
    size_t i;
    int rv = 0;

    /* have we been here before? */
    if (fList->fg_flowtype_count > 0) {
        return 0;
    }

    /* handle case when --flowtypes is given */
    if (fList->fg_option[FGLOB_OPT_FLOWTYPES]) {
        if (fList->fg_option[FGLOB_OPT_CLASS]
            || fList->fg_option[FGLOB_OPT_TYPES])
        {
            skAppPrintErr(("Cannot use --%s when either --%s or --%s are"
                           " specified"),
                          fglobOptions[FGLOB_OPT_FLOWTYPES].name,
                          fglobOptions[FGLOB_OPT_CLASS].name,
                          fglobOptions[FGLOB_OPT_TYPES].name);
            return 1;
        }
        return fglobParseFlowtypes();
    }

    /* parse --class or use default */
    class_name = fList->fg_option[FGLOB_OPT_CLASS];
    if (NULL == class_name) {
        /* no class given, use default class and get its name */
        class_id = sksiteClassGetDefault();
        if (SK_INVALID_CLASS == class_id) {
            skAppPrintErr(("No --class given and no default class"
                           " specified in %s"),
                          sksiteGetConfigPath(path, sizeof(path)));
            return 1;
        }
        sksiteClassGetName(class_name_buf, sizeof(class_name_buf), class_id);
        class_name = class_name_buf;
    } else {
        class_id = sksiteClassLookup(class_name);
        if (SK_INVALID_CLASS == class_id) {
            if (strchr(class_name, ',')) {
                skAppPrintErr(("Invalid --%s: Use --%s to"
                               " process multiple classes"),
                              fglobOptions[FGLOB_OPT_CLASS].name,
                              fglobOptions[FGLOB_OPT_FLOWTYPES].name);
            } else if (0 == strcmp(class_name, "all")) {
                skAppPrintErr(("Invalid --%s: Use --%s to"
                               " process all classes"),
                              fglobOptions[FGLOB_OPT_CLASS].name,
                              fglobOptions[FGLOB_OPT_FLOWTYPES].name);
            } else {
                skAppPrintErr(("Invalid --%s: Cannot find class '%s'\n"
                               "\tUse the --help option to see valid classes"),
                              fglobOptions[FGLOB_OPT_CLASS].name,
                              class_name);
            }
            return 1;
        }
    }

    /* create vectors for the class and for the flowtypes */
    class_vec = skVectorNew(sizeof(sk_class_id_t));
    flowtypes_vec = skVectorNew(sizeof(sk_flowtype_id_t));
    if (NULL == class_vec || NULL == flowtypes_vec) {
        skAppPrintOutOfMemory(NULL);
        rv = 1;
        goto END;
    }

    skVectorAppendValue(class_vec, &class_id);

    /* if user didn't give --type, use default types for the class */
    if (NULL == fList->fg_option[FGLOB_OPT_TYPES]) {
        if (sksiteParseTypeList(flowtypes_vec, "@", class_vec, "all", "@",
                                &error_iter))
        {
            skAbort();
        }
        if (skVectorGetCount(flowtypes_vec) == 0) {
            skAppPrintErr(("No --type given and no default types"
                           " specified for class %s in %s"),
                          class_name, sksiteGetConfigPath(path, sizeof(path)));
            rv = 1;
            goto END;
        }
    } else {
        rv = sksiteParseTypeList(flowtypes_vec,
                                 fList->fg_option[FGLOB_OPT_TYPES],
                                 class_vec, "all", NULL, &error_iter);
        if (rv) {
            if (rv < 0) {
                skAppPrintErr("Invalid %s: Internal error parsing argument",
                              fglobOptions[FGLOB_OPT_TYPES].name);
            } else if (1 == rv) {
                sksiteErrorIteratorNext(error_iter);
                skAppPrintErr("Invalid %s '%s': %s",
                              fglobOptions[FGLOB_OPT_TYPES].name,
                              fList->fg_option[FGLOB_OPT_TYPES],
                              sksiteErrorIteratorGetMessage(error_iter));
                assert(sksiteErrorIteratorNext(error_iter)
                       == SK_ITERATOR_NO_MORE_ENTRIES);
            } else {
                skAppPrintErr("Invalid %s '%s': Found multiple errors:",
                              fglobOptions[FGLOB_OPT_TYPES].name,
                              fList->fg_option[FGLOB_OPT_TYPES]);
                while (sksiteErrorIteratorNext(error_iter) == SK_ITERATOR_OK) {
                    skAppPrintErr("%s",
                                  sksiteErrorIteratorGetMessage(error_iter));
                }
            }
            sksiteErrorIteratorFree(error_iter);
            error_iter = NULL;
            rv = 1;
            goto END;
        }
        if (0 == skVectorGetCount(flowtypes_vec)) {
            skAppPrintErr("Invalid %s '%s': No valid types found",
                          fglobOptions[FGLOB_OPT_TYPES].name,
                          fList->fg_option[FGLOB_OPT_TYPES]);
            rv = 1;
            goto END;
        }
    }

    /* add each flowtype */
    for (i = 0; 0 == skVectorGetValue(&id, flowtypes_vec, i); ++i) {
        fglobAddFlowtype(id);
    }

  END:
    skVectorDestroy(class_vec);
    skVectorDestroy(flowtypes_vec);
    return rv;
}


/*
 *  is_used = fglobValid();
 *
 *    Return 1 if fglob is to be used; 0 if it is not to be used, or
 *    -1 if there were errors with classes, types, sensors, or
 *    times.
 */
int
fglobValid(
    void)
{
    if (fList->fg_user_option_count == 0) {
        /* no fglob options given */
        return 0;
    }

    if (!fList->fg_initialized) {
        if (fglobInit()) {
            return -1;
        }
    }
    return 1;
}


/*
 *  option_count = fglobSetFilters(sensor_bitmap, file_info_bitmap);
 *
 *    This function is used when filtering a previous data pull.  It
 *    allows the --class, --type, and --sensor switches to work over
 *    this data.
 *
 *    Fill in the 'sensor_bitmap' with the values the user provided to
 *    fglob's --sensor switch as defined in the silk.conf file.
 *
 *    Fill in the 'file_info_bitmap' with the values the user provided
 *    to fglob's --class and --type switches as defined in the
 *    silk.conf file.
 */
int
fglobSetFilters(
    sk_bitmap_t       **sensor_bitmap,
    sk_bitmap_t       **flowtype_bitmap)
{
    int i;
    int rv = 0; /* no filters, no errors */

    assert(sensor_bitmap);
    assert(flowtype_bitmap);

    /* Do we have sensor info? */
    if (fList->fg_option[FGLOB_OPT_SENSORS]) {
        /* ensure site configuration file */
        if (fglobLoadSiteConfig()) {
            return -1;
        }

        if (fglobParseSensors(sensor_bitmap)) {
            return -1;
        }

        rv += 1;
    }

    if (fList->fg_option[FGLOB_OPT_CLASS]
        || fList->fg_option[FGLOB_OPT_TYPES]
        || fList->fg_option[FGLOB_OPT_FLOWTYPES])
    {
        /* ensure site configuration file */
        if (fglobLoadSiteConfig()) {
            return -1;
        }

        /* User gave us at least class/type information */
        if (fglobParseClassAndType()) {
            /* error */
            return -2;
        }

        if (skBitmapCreate(flowtype_bitmap, sksiteFlowtypeGetMaxID()+1)) {
            return -1;
        }

        for (i = 0; i < fList->fg_flowtype_count; ++i) {
            skBitmapSetBit(*flowtype_bitmap, fList->fg_flowtype_list[i]);
        }

        rv += 2;
    }

    /* Adjust the value of the 'fg_user_option_count' member */
    if (fList->fg_option[FGLOB_OPT_CLASS]) {
        --fList->fg_user_option_count;
    }
    if (fList->fg_option[FGLOB_OPT_TYPES]) {
        --fList->fg_user_option_count;
    }
    if (fList->fg_option[FGLOB_OPT_FLOWTYPES]) {
        --fList->fg_user_option_count;
    }
    if (fList->fg_option[FGLOB_OPT_SENSORS]) {
        --fList->fg_user_option_count;
    }

    return rv;
}




/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
