/*
** Copyright (C) 2003-2023 by Carnegie Mellon University.
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

#include <silk/silk.h>

RCSIDENT("$SiLK: flowcapsetup.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/sksite.h>
#include "flowcap.h"


/* TYPEDEFS AND DEFINES */

/* Where to print --help output */
#define USAGE_FH stdout


/* LOCAL VARIABLES */

/* Name of sensor configuration file */
static const char *sensor_configuration = NULL;

/* Stashed probe list */
static char *probe_list = NULL;

/* Whether to exit after checking syntax of sensor.conf.  If value>1,
 * print names of probes that were parsed.  */
static int verify_sensor_config = 0;


/* OPTIONS SETUP */

typedef enum {
    OPT_SENSOR_CONFIG, OPT_VERIFY_SENSOR_CONFIG,
    OPT_DESTINATION_DIR,
    OPT_MAX_FILE_SIZE, OPT_TIMEOUT, OPT_CLOCK_TIME,
#ifdef SK_HAVE_STATVFS
    OPT_FREESPACE_MINIMUM, OPT_SPACE_MAXIMUM_PERCENT,
#endif
    OPT_PROBES, OPT_FC_VERSION
} appOptionsEnum;

static struct option appOptions[] = {
    {"sensor-configuration",  REQUIRED_ARG, 0, OPT_SENSOR_CONFIG},
    {"verify-sensor-config",  OPTIONAL_ARG, 0, OPT_VERIFY_SENSOR_CONFIG},
    {"destination-directory", REQUIRED_ARG, 0, OPT_DESTINATION_DIR},
    {"max-file-size",         REQUIRED_ARG, 0, OPT_MAX_FILE_SIZE},
    {"timeout",               REQUIRED_ARG, 0, OPT_TIMEOUT},
    {"clock-time",            OPTIONAL_ARG, 0, OPT_CLOCK_TIME},
#ifdef SK_HAVE_STATVFS
    {"freespace-minimum",     REQUIRED_ARG, 0, OPT_FREESPACE_MINIMUM},
    {"space-maximum-percent", REQUIRED_ARG, 0, OPT_SPACE_MAXIMUM_PERCENT},
#endif
    {"probes",                REQUIRED_ARG, 0, OPT_PROBES},
    {"fc-version",            REQUIRED_ARG, 0, OPT_FC_VERSION},
    {0,0,0,0}                 /* sentinel entry */
};

static const char *appHelp[] = {
    ("Read sensor configuration from named file."),
    ("Verify that the sensor configuration file is\n"
     "\tcorrect and immediately exit.  If argument provided, print the names\n"
     "\tof the probes defined in the file. Def. no"),
    ("Store aggregated packed flow files in this\n"
     "\tdirectory for processing by rwsender."),
    ("Close the aggregated flow file when it reaches this\n"
     "\tsize (in bytes) so it can be sent to the packer.  Append k, m, g, t\n"
     "\tfor kilo-, mega-, giga-, tera-bytes, respectively."),
    ("Close the aggregated flow file when it reaches this\n"
     "\tage (in seconds) so it can be sent to the packer. Def. 60"),
    ("Base the file closing times around midnight plus this\n"
     "\toptional number of seconds as an offset. Def. no, 0"),
#ifdef SK_HAVE_STATVFS
    ("Set the minimum free space (in bytes) to maintain\n"
     "\ton the filesystem. Accepts k,m,g,t suffix. Def. "
     DEFAULT_FREESPACE_MINIMUM),
    ("Set the maximum percentage of the disk to\n"
     "\tuse. Def." /* valued added in usage */),
#endif /* SK_HAVE_STATVFS */
    ("Ignore all probes in the sensor-configuration file except\n"
     "\tfor these, a comma separated list of probe names. Def. Use all probes"),
    NULL, /* generate dynamically */
    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int  appOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static void validateOptions(void);
static int  verifySensorConfig(const char *sensor_conf, int verbose);
static int  parseProbeList(void);


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
#define USAGE_MSG                                                           \
    ("<SWITCHES>\n"                                                         \
     "\tflowcap is a daemon which listens to devices which produce flow\n"  \
     "\tdata (flow sources), homogenizes the data, stores it, and\n"        \
     "\tforwards as a compressed stream to a flowcap client program.\n")

    FILE *fh = USAGE_FH;
    unsigned int i;

    fprintf(fh, "%s %s", skAppName(), USAGE_MSG);
    fprintf(fh, "\nSWITCHES:\n");
    skOptionsDefaultUsage(fh);
    sksiteOptionsUsage(fh);

    for (i = 0; appOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. ", appOptions[i].name,
                SK_OPTION_HAS_ARG(appOptions[i]));
        switch ((appOptionsEnum)appOptions[i].val) {
          case OPT_FC_VERSION:
            fprintf(fh, ("Write IPv4 records in this flowcap record format."
                         " Def. %d.\n\tChoices: %d-%d."
                         " This switch is ignored for IPv6 records."),
                    FC_VERSION_DEFAULT, FC_VERSION_MIN, FC_VERSION_MAX);
            break;
#ifdef SK_HAVE_STATVFS
          case OPT_SPACE_MAXIMUM_PERCENT:
            fprintf(fh, "%s %.2f%%", appHelp[i],
                    DEFAULT_SPACE_MAXIMUM_PERCENT);
            break;
#endif
          default:
            fprintf(fh, "%s", appHelp[i]);
            break;
        }
        fprintf(fh, "\n");
    }
    skCompMethodOptionsUsage(fh);

    fprintf(fh, "\nLogging and daemonization switches:\n");
    skdaemonOptionsUsage(fh);
}


/*
 *  status = appOptionsHandler(cData, opt_index, opt_arg);
 *
 *    Called by skOptionsParse(), this handles a user-specified switch
 *    that the application has registered, typically by setting global
 *    variables.  Returns 1 if the switch processing failed or 0 if it
 *    succeeded.  Returning a non-zero from from the handler causes
 *    skOptionsParse() to return a negative value.
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
    struct tm tm;
    time_t t;
    uint32_t tmp_32;
    uint64_t tmp_64;
    int rv;

    switch ((appOptionsEnum)opt_index) {
      case OPT_SENSOR_CONFIG:
        sensor_configuration = opt_arg;
        break;

      case OPT_VERIFY_SENSOR_CONFIG:
        verify_sensor_config = 1;
        if (opt_arg && (opt_arg[0] != '\0') && (0 != strcmp(opt_arg, "0"))) {
            /* be verbose */
            verify_sensor_config = 2;
        }
        break;

      case OPT_MAX_FILE_SIZE:
        rv = skStringParseHumanUint64(&tmp_64, opt_arg, SK_HUMAN_NORMAL);
        if (rv) {
            goto PARSE_ERROR;
        }
        if (tmp_64 > UINT32_MAX) {
            skAppPrintErr("Invalid %s '%s': Value is above the maximum %lu",
                          appOptions[opt_index].name, opt_arg,
                          (unsigned long)UINT32_MAX);
        }
        max_file_size = tmp_64;
        break;

      case OPT_TIMEOUT:
        rv = skStringParseUint32(&tmp_32, opt_arg, 1, 0xFFFFFFFE);
        if (rv) {
            goto PARSE_ERROR;
        }
        write_timeout = tmp_32;
        break;

      case OPT_CLOCK_TIME:
        if (opt_arg) {
            rv = skStringParseUint32(&tmp_32, opt_arg, 0, 0xFFFFFFFE);
            if (rv) {
                goto PARSE_ERROR;
            }
        }
        /* Find midnight */
        t = time(NULL);
        if (gmtime_r(&t, &tm) == NULL) {
            skAppPrintErr("Could not determine current time");
            return 1;
        }
        tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
        t = timegm(&tm);
        /* Add in offset */
        if (opt_arg) {
            t += tmp_32;
        }
        clock_time = sktimeCreate(t, 0);
        break;

      case OPT_PROBES:
        probe_list = opt_arg;
        break;

      case OPT_FC_VERSION:
        rv = skStringParseUint32(&tmp_32, opt_arg,
                                 FC_VERSION_MIN, FC_VERSION_MAX);
        if (rv) {
            goto PARSE_ERROR;
        }
        flowcap_version = tmp_32;
        break;

      case OPT_DESTINATION_DIR:
        if (skOptionsCheckDirectory(opt_arg, appOptions[opt_index].name)) {
            return 1;
        }
        if (strlen(opt_arg) > PATH_MAX - FC_NAME_MAX) {
            skAppPrintErr("The --%s name is too long '%s'",
                          appOptions[opt_index].name, opt_arg);
            return 1;
        }
        destination_dir = opt_arg;
        break;

#ifdef SK_HAVE_STATVFS
      case OPT_FREESPACE_MINIMUM:
        rv = skStringParseHumanUint64(&tmp_64, opt_arg, SK_HUMAN_NORMAL);
        if (rv) {
            goto PARSE_ERROR;
        }
        freespace_minimum = (int64_t)tmp_64;
        break;

      case OPT_SPACE_MAXIMUM_PERCENT:
        rv = skStringParseDouble(&space_maximum_percent, opt_arg, 0.0, 100.0);
        if (rv) {
            goto PARSE_ERROR;
        }
        break;
#endif /* SK_HAVE_STATVFS */

    } /* switch */

    return 0;

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  appOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
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
void
appSetup(
    int                 argc,
    char              **argv)
{
    SILK_FEATURES_DEFINE_STRUCT(features);
    int arg_index;
    int rv;

    /* verify same number of options and help strings */
    assert((sizeof(appHelp)/sizeof(char *)) ==
           (sizeof(appOptions)/sizeof(struct option)));

    /* register the application */
    skAppRegister(argv[0]);
    skAppVerifyFeatures(&features, NULL);
    skOptionsSetUsageCallback(&appUsageLong);

    /* Set the default compression level to "best", and do not get the
     * comp_method from the environment. */
    skCompMethodSetDefault(skCompMethodGetBest());
    skCompMethodOptionsNoEnviron();

    /* register the options */
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)
        || skCompMethodOptionsRegister(&comp_method)
        || sksiteOptionsRegister(0))
    {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* flowcap runs as a daemon */
    if (skdaemonSetup((SKLOG_FEATURE_LEGACY | SKLOG_FEATURE_SYSLOG),
                      argc, argv))
    {
        exit(EXIT_FAILURE);
    }

    /* initialize globals */
#ifdef SK_HAVE_STATVFS
    {
        uint64_t tmp_64;
        rv = skStringParseHumanUint64(&tmp_64, DEFAULT_FREESPACE_MINIMUM,
                                     SK_HUMAN_NORMAL);
        if (rv) {
            skAppPrintErr("Bad default value for freespace_minimum: '%s': %s",
                          DEFAULT_FREESPACE_MINIMUM,skStringParseStrerror(rv));
            exit(EXIT_FAILURE);
        }
        freespace_minimum = (int64_t)tmp_64;
    }
#endif /* SK_HAVE_STATVFS */

    /* register the teardown handler */
    if (atexit(appTeardown) < 0) {
        skAppPrintErr("Unable to register appTeardown() with atexit()");
        appTeardown();
        exit(EXIT_FAILURE);
    }

    /* parse options. If OK, arg_index is the first arg not used up */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage();/* never returns */
    }

    probe_vec = skVectorNew(sizeof(skpc_probe_t *));
    if (probe_vec == NULL) {
        skAppPrintErr("Vector create failed");
        exit(EXIT_FAILURE);
    }

    validateOptions();

    /* Check that there aren't any extraneous arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many or unrecognized argument specified '%s'",
                      argv[arg_index]);
        skAppUsage();             /* never returns */
    }

    /* if no probes were specified on the command line, use all probes
     * from the sensor.conf file */
    if (skVectorGetCount(probe_vec) == 0) {
        skpc_probe_iter_t iter;
        const skpc_probe_t *probe;

        skpcProbeIteratorBind(&iter);
        while (skpcProbeIteratorNext(&iter, &probe)) {
            if (skVectorAppendValue(probe_vec, &probe) == -1) {
                skAppPrintErr("Vector append failed");
                exit(EXIT_FAILURE);
            }
        }
    }

    /* this should never happen */
    if (skVectorGetCount(probe_vec) < 1) {
        skAbort();
    }

    /* create the flowcap readers */
    if (createReaders()) {
        exit(EXIT_FAILURE);
    }

    /* finished with the vector */
    if (probe_vec) {
        skVectorDestroy(probe_vec);
        probe_vec = NULL;
    }
}


/*
 *  validateOptions();
 *
 *    Called after all options have been seen to verify that a valid
 *    set of options have been provided.  Returns if all options are
 *    valid.  Exits the program if options are invalid.
 */
static void
validateOptions(
    void)
{
    int error = 0;
    int rv;

    if (skpcSetup() != 0) {
        skAppPrintErr("Unable to setup probe configuration handler");
        exit(EXIT_FAILURE);
    }

    /* parse the sensor-config file and the list of probes */
    rv = verifySensorConfig(sensor_configuration, (verify_sensor_config > 1));
    if (verify_sensor_config) {
        skpcTeardown();
        skAppUnregister();
        exit((0 == rv) ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    if (rv) {
        ++error;
    } else if (probe_list) {
        /* parse the list of probes */
        if (parseProbeList()) {
            ++error;
        }
    }

    /* must have a destination_dir */
    if (NULL == destination_dir) {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_DESTINATION_DIR].name);
        ++error;
    }

    /* check for max-file-size */
    if (0 == max_file_size) {
        skAppPrintErr("The --%s switch is required",
                      appOptions[OPT_MAX_FILE_SIZE].name);
        ++error;
    }

    /* verify the required options for logging */
    if (skdaemonOptionsVerify()) {
        ++error;
    }

    if (error) {
        exit(EXIT_FAILURE);
    }

    /*
     * When calculating disk space, allow for compression to produce a
     * file that is actually larger than the maximum file size.
     *
     * Assume a compressed block could be 15% larger than the standard
     * block size---libz is 10%, lzo1x is 6%.
     *
     * We're using the default block size from skiobuf.h, so we assume
     * that skstream doesn't use a different block size.
     */
    alloc_file_size = (uint64_t)(max_file_size
                                 + (double)SKSTREAM_DEFAULT_BLOCKSIZE * 0.15);
}


/*
 *  status = verifySensorConfig(sensor_conf, verbose);
 *
 *    Verify that the 'sensor_conf' file is valid.  If verbose is
 *    non-zero, print the probes and sensors that were found in the
 *    file.
 *
 *    Return 0 if the file is valid, -1 otherwise.
 */
static int
verifySensorConfig(
    const char         *sensor_conf,
    int                 verbose)
{
    skpc_probe_iter_t probe_iter;
    const skpc_probe_t *probe;
    uint32_t count;
    int first;

    if (NULL == sensor_conf) {
        skAppPrintErr("The --%s option is required",
                      appOptions[OPT_SENSOR_CONFIG].name);
        return -1;
    }

    /* parse the sensor configuration file */
    if (skpcParse(sensor_conf, NULL) != 0) {
        skAppPrintErr("Errors while parsing %s file '%s'",
                      appOptions[OPT_SENSOR_CONFIG].name, sensor_conf);
        return -1;
    }

    /* verify probe is not reading data from files, since flowcap does
     * not support that. */
    count = 0;
    skpcProbeIteratorBind(&probe_iter);
    while (skpcProbeIteratorNext(&probe_iter, &probe)) {
        if (skpcProbeGetPollDirectory(probe) || skpcProbeGetFileSource(probe)) {
            skAppPrintErr(("Error verifying probe '%s':\n"
                           "\tReading flow data from files is not supported"
                           " in %s"),
                          skpcProbeGetName(probe), skAppName());
            ++count;
        }
    }
    if (count) {
        return -1;
    }

    /* verify the sensor-conf has probes */
    count = skpcCountProbes();
    if (0 == count) {
        skAppPrintErr("No probe definitions exist in '%s'",
                      sensor_conf);
        return -1;
    }

    /* if a value was provided to the --verify-sensor switch, be verbose */
    if (verbose) {
        /* print the probes */
        printf("%s: Successfully parsed %" PRIu32 " probe%s:\n",
               skAppName(), count, ((count == 1) ? "" : "s"));
        skpcProbeIteratorBind(&probe_iter);
        first = 1;
        while (skpcProbeIteratorNext(&probe_iter, &probe)) {
            if (first) {
                first = 0;
                printf("\t%s", skpcProbeGetName(probe));
            } else {
                printf(", %s", skpcProbeGetName(probe));
            }
        }
        printf("\n");
    }

    return 0;
}


/*
 *  status = parseProbeList();
 *
 *    Parse the global 'probe_list' string and add named probes to the
 *    global 'probe_vec'.  Return 0 on success, or -1 if we do not
 *    find a probe with the specified name.
 */
static int
parseProbeList(
    void)
{
    const skpc_probe_t *probe;
    int error_count = 0;
    char *cp;
    char *ep;

    cp = probe_list;
    while (*cp) {
        /* 'cp' at start of token, find where it ends */
        ep = strchr(cp, ',');
        if (ep == cp) {
            /* double comma, ignore */
            ++cp;
            continue;
        }
        if (ep == NULL) {
            /* no more commas, set 'ep' to end of string */
            ep = cp + strlen(cp);
        } else {
            /* end this token, move 'ep' to start of next token */
            *ep = '\0';
            ep++;
        }

        /* search for the probe */
        probe = skpcProbeLookupByName(cp);
        if (NULL == probe) {
            /* error */
            skAppPrintErr("No probes have the name '%s'", cp);
            ++error_count;
        } else if (skVectorAppendValue(probe_vec, &probe) == -1) {
            skAppPrintErr("Vector append failed");
            exit(EXIT_FAILURE);
        }

        /* move to next token */
        cp = ep;
    }

    return ((error_count == 0) ? 0 : -1);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
