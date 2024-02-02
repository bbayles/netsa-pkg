/*
 *  Copyright 2005-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  logconfig.c
 *  Generic glib-based logging configuration support
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
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
#include <airframe/logconfig.h>
#include <airframe/daeconfig.h>
#include <airframe/airutil.h>

/* wrap this around string literals that are assigned to variables of type
 * "char *" to quiet compiler warnings */
#define C(String) (char *)String


#ifdef  USE_GOPTION
#define AF_OPTION_WRAP "\n\t\t\t\t"
#else
#define AF_OPTION_WRAP " "
#endif


typedef struct logc_st {
    /* Options */
    const char  *appname;
    const char  *version;
    char        *logspec;
    char        *loglevel;
    gboolean     opt_version;
    gboolean     opt_verbose;
    /* Logging sockets */
    GIOChannel  *logfile;
} logc_t;

static logc_t  logc = { "", "", NULL, NULL, FALSE, FALSE, NULL };

static AirOptionEntry logc_optentries[] = {
    AF_OPTION("log", 'l', 0, AF_OPT_TYPE_STRING, &(logc.logspec),
              AF_OPTION_WRAP "Log facility, log file path, or stderr [stderr]",
              "logspec"),
    AF_OPTION("loglevel", 'L', 0, AF_OPT_TYPE_STRING, &(logc.loglevel),
              AF_OPTION_WRAP "Log level (debug, message, warning, critical,"
              AF_OPTION_WRAP "error, quiet)", "level"),
    AF_OPTION("verbose", 'v', 0, AF_OPT_TYPE_NONE, &(logc.opt_verbose),
              AF_OPTION_WRAP "Verbose logging, equivalent to -L debug", NULL),
    AF_OPTION("version", 'V', 0, AF_OPT_TYPE_NONE, &(logc.opt_version),
              AF_OPTION_WRAP "Print application version and exit", NULL),
    AF_OPTION_END
};


gboolean
logc_add_option_group(
    AirOptionCtx  *aoctx,
    const char    *appname,
    const char    *version)
{
    g_assert(aoctx != NULL);

    /* store application name and version */
    logc.appname = appname;
    logc.version = version;

    air_option_context_add_group(
        aoctx, "log", "Logging Options:",
        AF_OPTION_WRAP "Show help for logging options", logc_optentries);

    return TRUE;
}


static void
logc_print_version(
    void)
{
    fprintf(stdout, "%s version %s (c) 2006-2023 Carnegie Mellon University.\n",
            logc.appname, logc.version);
    fprintf(stdout, "GNU General Public License (GPL) Rights "
            "pursuant to Version 2, June 1991\n");
    fprintf(stdout, "Some included library code covered by LGPL 2.1; "
            "see source for details.\n");
    fprintf(stdout, "Send bug reports, feature requests, and comments to "
            "netsa-help@cert.org.\n");
}


static gint
logc_syslog_level(
    GLogLevelFlags   level)
{
    if (level & G_LOG_LEVEL_DEBUG) {return LOG_DEBUG;}
    if (level & G_LOG_LEVEL_INFO) {return LOG_INFO;}
    if (level & G_LOG_LEVEL_MESSAGE) {return LOG_NOTICE;}
    if (level & G_LOG_LEVEL_WARNING) {return LOG_WARNING;}
    if (level & G_LOG_LEVEL_CRITICAL) {return LOG_ERR;}
    if (level & G_LOG_LEVEL_ERROR) {return LOG_ERR;}

    return LOG_DEBUG;
}


static gboolean
logc_parse_log_level(
    const char      *levstr,
    GLogLevelFlags  *levflag)
{
    if (strcmp("debug", levstr) == 0) {
        *levflag = G_LOG_FLAG_RECURSION |
            G_LOG_FLAG_FATAL |
            G_LOG_LEVEL_ERROR |
            G_LOG_LEVEL_CRITICAL |
            G_LOG_LEVEL_WARNING |
            G_LOG_LEVEL_MESSAGE |
            G_LOG_LEVEL_INFO |
            G_LOG_LEVEL_DEBUG;
        return TRUE;
    }

    if (strcmp("info", levstr) == 0) {
        *levflag = G_LOG_FLAG_RECURSION |
            G_LOG_FLAG_FATAL |
            G_LOG_LEVEL_ERROR |
            G_LOG_LEVEL_CRITICAL |
            G_LOG_LEVEL_WARNING |
            G_LOG_LEVEL_MESSAGE |
            G_LOG_LEVEL_INFO;
        return TRUE;
    }

    if (strcmp("message", levstr) == 0) {
        *levflag = G_LOG_FLAG_RECURSION |
            G_LOG_FLAG_FATAL |
            G_LOG_LEVEL_ERROR |
            G_LOG_LEVEL_CRITICAL |
            G_LOG_LEVEL_WARNING |
            G_LOG_LEVEL_MESSAGE;
        return TRUE;
    }

    if (strcmp("warning", levstr) == 0) {
        *levflag = G_LOG_FLAG_RECURSION |
            G_LOG_FLAG_FATAL |
            G_LOG_LEVEL_ERROR |
            G_LOG_LEVEL_CRITICAL |
            G_LOG_LEVEL_WARNING;
        return TRUE;
    }

    if (strcmp("critical", levstr) == 0) {
        *levflag = G_LOG_FLAG_RECURSION |
            G_LOG_FLAG_FATAL |
            G_LOG_LEVEL_ERROR |
            G_LOG_LEVEL_CRITICAL;
        return TRUE;
    }

    if (strcmp("error", levstr) == 0) {
        *levflag = G_LOG_FLAG_RECURSION |
            G_LOG_FLAG_FATAL |
            G_LOG_LEVEL_ERROR;
        return TRUE;
    }

    if (strcmp("quiet", levstr) == 0) {
        *levflag = 0;
        return TRUE;
    }

    return FALSE;
}


static gboolean
logc_parse_syslog_facility(
    const char  *facstr,
    gint        *facility)
{
#ifdef LOG_AUTH
    if (strcmp("auth", facstr) == 0) {
        *facility = LOG_AUTH;
        return TRUE;
    }
#endif /* ifdef LOG_AUTH */

#ifdef LOG_AUTHPRIV
    if (strcmp("authpriv", facstr) == 0) {
        *facility = LOG_AUTHPRIV;
        return TRUE;
    }
#endif /* ifdef LOG_AUTHPRIV */

#ifdef LOG_CONSOLE
    if (strcmp("console", facstr) == 0) {
        *facility = LOG_CONSOLE;
        return TRUE;
    }
#endif /* ifdef LOG_CONSOLE */

#ifdef LOG_CRON
    if (strcmp("cron", facstr) == 0) {
        *facility = LOG_CRON;
        return TRUE;
    }
#endif /* ifdef LOG_CRON */

#ifdef LOG_DAEMON
    if (strcmp("daemon", facstr) == 0) {
        *facility = LOG_DAEMON;
        return TRUE;
    }
#endif /* ifdef LOG_DAEMON */

#ifdef LOG_FTP
    if (strcmp("ftp", facstr) == 0) {
        *facility = LOG_FTP;
        return TRUE;
    }
#endif /* ifdef LOG_FTP */

#ifdef LOG_LPR
    if (strcmp("lpr", facstr) == 0) {
        *facility = LOG_LPR;
        return TRUE;
    }
#endif /* ifdef LOG_LPR */

#ifdef LOG_MAIL
    if (strcmp("mail", facstr) == 0) {
        *facility = LOG_MAIL;
        return TRUE;
    }
#endif /* ifdef LOG_MAIL */

#ifdef LOG_NEWS
    if (strcmp("news", facstr) == 0) {
        *facility = LOG_NEWS;
        return TRUE;
    }
#endif /* ifdef LOG_NEWS */

#ifdef LOG_SECURITY
    if (strcmp("security", facstr) == 0) {
        *facility = LOG_SECURITY;
        return TRUE;
    }
#endif /* ifdef LOG_SECURITY */

#ifdef LOG_USER
    if (strcmp("user", facstr) == 0) {
        *facility = LOG_USER;
        return TRUE;
    }
#endif /* ifdef LOG_USER */

#ifdef LOG_UUCP
    if (strcmp("uucp", facstr) == 0) {
        *facility = LOG_UUCP;
        return TRUE;
    }
#endif /* ifdef LOG_UUCP */

#ifdef LOG_LOCAL0
    if (strcmp("local0", facstr) == 0) {
        *facility = LOG_LOCAL0;
        return TRUE;
    }
#endif /* ifdef LOG_LOCAL0 */

#ifdef LOG_LOCAL1
    if (strcmp("local1", facstr) == 0) {
        *facility = LOG_LOCAL1;
        return TRUE;
    }
#endif /* ifdef LOG_LOCAL1 */

#ifdef LOG_LOCAL2
    if (strcmp("local2", facstr) == 0) {
        *facility = LOG_LOCAL2;
        return TRUE;
    }
#endif /* ifdef LOG_LOCAL2 */

#ifdef LOG_LOCAL3
    if (strcmp("local3", facstr) == 0) {
        *facility = LOG_LOCAL3;
        return TRUE;
    }
#endif /* ifdef LOG_LOCAL3 */

#ifdef LOG_LOCAL4
    if (strcmp("local4", facstr) == 0) {
        *facility = LOG_LOCAL4;
        return TRUE;
    }
#endif /* ifdef LOG_LOCAL4 */

#ifdef LOG_LOCAL5
    if (strcmp("local5", facstr) == 0) {
        *facility = LOG_LOCAL5;
        return TRUE;
    }
#endif /* ifdef LOG_LOCAL5 */

#ifdef LOG_LOCAL6
    if (strcmp("local6", facstr) == 0) {
        *facility = LOG_LOCAL6;
        return TRUE;
    }
#endif /* ifdef LOG_LOCAL6 */

#ifdef LOG_LOCAL7
    if (strcmp("local7", facstr) == 0) {
        *facility = LOG_LOCAL7;
        return TRUE;
    }
#endif /* ifdef LOG_LOCAL7 */

    return FALSE;
}


static void
logc_logger_file(
    const char      *domain,
    GLogLevelFlags   log_level,
    const char      *message,
    gpointer         user_data)
{
    gsize bw;
    char  timebuf[80];

    air_time_buf_print(timebuf, time(NULL), AIR_TIME_ISO8601);

    g_io_channel_write_chars(logc.logfile, "[", 1, &bw, NULL);
    g_io_channel_write_chars(logc.logfile, timebuf, -1, &bw, NULL);
    g_io_channel_write_chars(logc.logfile, "] ", 2, &bw, NULL);
    g_io_channel_write_chars(logc.logfile, message, -1, &bw, NULL);
    g_io_channel_write_chars(logc.logfile, "\n", 1, &bw, NULL);
    g_io_channel_flush(logc.logfile, NULL);
}


static void
logc_logger_syslog(
    const char      *domain,
    GLogLevelFlags   log_level,
    const char      *message,
    gpointer         user_data)
{
    syslog(logc_syslog_level(log_level), "%s", message);
}


static void
logc_logger_null(
    const char      *domain,
    GLogLevelFlags   log_level,
    const char      *message,
    gpointer         user_data)
{
}


void
logc_set(
    char  *spec,
    char  *level)
{
    if (spec) {
        logc.logspec = strdup(spec);
    }
    if (level) {
        logc.loglevel = strdup(level);
    }
}


gboolean
logc_setup(
    GError **err)
{
    GLogLevelFlags levels;
    int            facility;

    /* check for version flag */
    if (logc.opt_version) {
        logc_print_version();
        exit(0);
    }

    /* default to stderr, or user for forking daemon */
    if (logc.logspec == NULL) {
        if (daec_will_fork()) {
            logc.logspec = C("user");
        } else {
            logc.logspec = C("stderr");
        }
    }

    /* default to warning logging; handle verbose flag */
    if (logc.loglevel == NULL) {
        if (logc.opt_verbose) {
            logc.loglevel = C("debug");
        } else {
            logc.loglevel = C("warning");
        }
    }

    /* parse log level */
    if (!logc_parse_log_level(logc.loglevel, &levels)) {
        g_set_error(err, LOGC_ERROR_DOMAIN,
                    LOGC_ERROR_ARGUMENT,
                    "log level %s not recognized.",
                    logc.loglevel);
        return FALSE;
    }

    if (strcmp(logc.logspec, "stderr") == 0) {
        if (daec_will_fork()) {
            g_set_error(err, LOGC_ERROR_DOMAIN,
                        LOGC_ERROR_ARGUMENT,
                        "Can't log to stderr as daemon.");
            return FALSE;
        }

        /* set log file to stderr */
        logc.logfile = g_io_channel_unix_new(fileno(stderr));

        /* use file logger */
        g_log_set_handler(G_LOG_DOMAIN, levels, logc_logger_file, NULL);
    } else if (strchr(logc.logspec, '/')) {
        /* open log file */
        logc.logfile = g_io_channel_new_file(logc.logspec, "a", err);
        if (logc.logfile == NULL) {return FALSE;}

        /* use file logger */
        g_log_set_handler(G_LOG_DOMAIN, levels, logc_logger_file, NULL);
    } else {
        /* try to parse facility name */
        if (!logc_parse_syslog_facility(logc.logspec, &facility)) {
            g_set_error(err, LOGC_ERROR_DOMAIN,
                        LOGC_ERROR_ARGUMENT,
                        "syslog(3) facility %s not recognized.",
                        logc.logspec);
            return FALSE;
        }

        /* open log socket */
        openlog(logc.appname, LOG_CONS | LOG_PID, facility);

        /* use syslog logger */
        g_log_set_handler(G_LOG_DOMAIN, levels, logc_logger_syslog, NULL);
    }

    /* set default log handler to eat messages */
    g_log_set_default_handler(logc_logger_null, NULL);
    g_message("%s starting", logc.appname);

    return TRUE;
}
