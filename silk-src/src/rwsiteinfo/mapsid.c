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
**  mapsid.c
**    Print a map of sensorID integers to names from silk.conf.
**
**
**    mapsid is deprecated as of SiLK 3.0.  Use rwsiteinfo instead.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: mapsid.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/sksite.h>


/* LOCAL DEFINES AND TYPEDEFS */

/* where to write --help output */
#define USAGE_FH stdout

/* where to send output */
#define OUT_FH stdout

/* how to print each line */
typedef enum mapping_dir_en {
    /* print name first:  S1 -> 1 */
    MAP_NAME_TO_NUM,
    /* print number first:  1 -> S1 */
    MAP_NUM_TO_NAME
} mapping_dir_t;


/* LOCAL VARIABLES */

/* whether to print the classes for each sensor */
static int print_classes = 0;

/* whether to print the description for each sensor */
static int print_descriptions = 0;

/* width to use for the sensor name.  This will be set when one of the
 * --print-* switches is specified and mapsid is printing more than
 * one sensor. */
static int sensor_name_width = -1;

/* OPTIONS SETUP */


typedef enum {
    OPT_PRINT_CLASSES, OPT_PRINT_DESCRIPTIONS
} appOptionsEnum;


static struct option appOptions[] = {
    {"print-classes",       NO_ARG, 0, OPT_PRINT_CLASSES},
    {"print-descriptions",  NO_ARG, 0, OPT_PRINT_DESCRIPTIONS},
    {0,0,0,0}               /* sentinel entry */
};

static const char *appHelp[] = {
    ("Print the name of the class(es) that each sensor\n"
     "\tcollects data for. Def. No"),
    ("Print the description for each sensor. Def. No"),
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
#define USAGE_MSG                                                       \
    ("[SWITCHES] [SENSORS]\n"                                           \
     "\tMaps between sensor names and sensor IDs.  Prints a list of\n"  \
     "\tall sensors when no command line arguments are given.\n"        \
     "\tAs of SiLK 3.0, mapsid is deprecated; use rwsiteinfo instead.\n")

    FILE *fh = USAGE_FH;

    skAppStandardUsage(fh, USAGE_MSG, appOptions, appHelp);
    sksiteOptionsUsage(fh);
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
    char        UNUSED(*opt_arg))
{
    switch ((appOptionsEnum)opt_index) {
      case OPT_PRINT_CLASSES:
        print_classes = 1;
        break;
      case OPT_PRINT_DESCRIPTIONS:
        print_descriptions = 1;
        break;
    }

    return 0;  /* OK */
}


/*
 *  printSensor(sid, mapping_dir);
 *
 *    Print information about the sensor 'sid'.  The value
 *    'mapping_dir' determines whether the sensor name or sensor ID is
 *    printed first on the line.
 */
static void
printSensor(
    sk_sensor_id_t      sid,
    mapping_dir_t       dir)
{
    char sensor_name[SK_MAX_STRLEN_SENSOR+1];
    char class_name[SK_MAX_STRLEN_FLOWTYPE+1];
    int class_count = 0;
    const char *desc;
    sk_class_iter_t ci;
    sk_class_id_t clid;

    sksiteSensorGetName(sensor_name, sizeof(sensor_name), sid);

    if (MAP_NUM_TO_NAME == dir) {
        fprintf(OUT_FH, "%5u -> %*s", sid, sensor_name_width, sensor_name);
    } else {
        assert(MAP_NAME_TO_NUM == dir);
        fprintf(OUT_FH, "%s -> %5u", sensor_name, sid);
    }

    if (print_classes) {
        sksiteSensorClassIterator(sid, &ci);
        fprintf(OUT_FH, "  [");
        while (sksiteClassIteratorNext(&ci, &clid)) {
            sksiteClassGetName(class_name, sizeof(class_name), clid);
            if (class_count == 0) {
                fprintf(OUT_FH, "%s", class_name);
            } else {
                fprintf(OUT_FH, ",%s", class_name);
            }
            ++class_count;
        }
        fprintf(OUT_FH, "]");
    }
    if (print_descriptions) {
        desc = sksiteSensorGetDescription(sid);
        if (desc) {
            fprintf(OUT_FH, "  \"%s\"", desc);
        }
    }
    fprintf(OUT_FH, "\n");
}


/*
 *  printByNameOrNumber(sensor);
 *
 *    Look up the sensor that has the name or the ID specified in the
 *    string 'sensor' and print it to OUT_FH.  Also print its
 *    class(es) if requested.
 */
static void
printByNameOrNumber(
    const char         *sensor)
{
    char sensor_name[SK_MAX_STRLEN_SENSOR+1];
    int rv;
    uint32_t temp;
    sk_sensor_id_t sid;
    int count;
    sk_sensor_iter_t si;

    /* try to parse as a number */
    rv = skStringParseUint32(&temp, sensor, 0, SK_INVALID_SENSOR-1);
    if (rv < 0 && rv != SKUTILS_ERR_BAD_CHAR) {
        skAppPrintErr("Invalid Sensor Number '%s': %s",
                      sensor, skStringParseStrerror(rv));
        return;
    }
    if (rv == 0) {
        /* got a clean parse */
        sid = (sk_sensor_id_t)temp;
        if ( !sksiteSensorExists(sid) ) {
            skAppPrintErr("Number '%s' is not a valid sensor number",
                          sensor);
            return;
        }

        printSensor(sid, MAP_NUM_TO_NAME);
        return;
    }

    /* didn't get a clean parse. try to treat as a name */
    sid = sksiteSensorLookup(sensor);
    if (sid != SK_INVALID_SENSOR) {
        printSensor(sid, MAP_NAME_TO_NUM);
        return;
    }

    /* try a case-insensitive search, manually iterating over all
     * the sensors */
    count = 0;
    sksiteSensorIterator(&si);
    while (sksiteSensorIteratorNext(&si, &sid)) {
        sksiteSensorGetName(sensor_name, sizeof(sensor_name), sid);
        if (0 == strcasecmp(sensor_name, sensor)) {
            printSensor(sid, MAP_NAME_TO_NUM);
            ++count;
        }
    }
    if (count == 0) {
        skAppPrintErr("Name '%s' is not a valid sensor name", sensor);
    }
}


/*
 *  printAllSensors();
 *
 *    Print all sensor IDs and Names to the OUT_FH.  Also, print class
 *    list if requested.
 */
static void
printAllSensors(
    void)
{
    sk_sensor_iter_t si;
    sk_sensor_id_t sid;
    int sensor_count = 0;

    sksiteSensorIterator(&si);
    while ( sksiteSensorIteratorNext(&si, &sid) ) {
        printSensor(sid, MAP_NUM_TO_NAME);
        sensor_count++;
    }

    fprintf(OUT_FH, "Total sensors %d\n", sensor_count);
}


int main(int argc, char **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    int arg_index;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || sksiteOptionsRegister(SK_SITE_FLAG_CONFIG_FILE))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* parse the options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        /* options parsing should print error */
        skAppUsage();           /* never returns */
    }

    /* ensure the site config is available */
    if (sksiteConfigure(1)) {
        exit(EXIT_FAILURE);
    }

    /* if we are printing more than one sensor and a --print-* switch
     * was given, set the width of the sensor name fields so the
     * values align */
    if ((argc != arg_index + 1) && (print_descriptions || print_classes)) {
        sensor_name_width = -1 * (int)sksiteSensorGetMaxNameStrLen();
    }

    if (argc > arg_index) {
        for ( ; arg_index < argc; ++arg_index) {
            printByNameOrNumber(argv[arg_index]);
        }
    } else {
        /* no args. print all */
        printAllSensors();
    }

    skAppUnregister();

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
