/*
 *  Copyright 2005-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  airutil.c
 *  General utility functions
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

/* Yeah, this is a dumb place for mainpage */

/**
 * @mainpage Airframe Application Utility Library
 *
 * @section Introduction
 *
 * Airframe is an application utility library designed to ease the creation of
 * command-line applications written in C that process data from a variety of
 * input sources to a variety of output sources. It builds atop the fundamental
 * data structures and utilities in glib (http://www.gtk.org) 2.0, adding
 * additional higher-level functionality.
 *
 * All of the Airframe modules provide their own command-line processing atop
 * the GOption facility; in this way, all Airframe applications have similar
 * command-line user interfaces.
 *
 * Airframe was originally developed for NAF
 * (http://tools.netsa.cert.org/naf), and is the mechanism by which the NAF
 * tools have a common interface. It evolved from the libair common library
 * used by the AirCERT project (http://aircert.sourceforge.net). It is released
 * as a separate library in the hopes that other applications developers may
 * find it useful.
 *
 * @section Modules
 *
 * Airframe provides four modules which may be used to ease application
 * creation. The daeconfig module (defined in daeconfig.h) handles
 * user-controlled daemonization, compatible with the filedaemon pattern.
 * The privconfig module (defined in privconfig.h) handles
 * user-controlled privilege management. The logconfig module (defined in
 * logconfig.h) handles user-controlled log message routing. The mio module
 * (defined in mio.h and mio_config.h) handles user-controlled file, network,
 * and packet capture I/O and record-oriented dispatch.
 *
 * @section Utilities
 *
 * Additional utility functions we've found useful in building applications
 * for handling network event data are defined in airutil.h. airopt.h defines
 * a command-line options processing layer atop glib-2 or popt, and is used
 * by Airframe's modules and client applications. Also, airlock.h allows
 * applications not using MIO for I/O and dispatch to interoperate with
 * filedaemon-style locking.
 *
 * The filedaemon pattern implemented by MIO may be wrapped around any
 * stdin-to-stdout filter application using the
 * <a href="../filedaemon.1.pdf">filedaemon</a> application built and installed
 * with Airframe.
 *
 * Airframe also includes an application called
 * <a href="../airdaemon.1.pdf">airdaemon</a> which simply invokes
 * a child process and restarts it after a configurable delay if it exits
 * abnormally.  airdaemon can retry after a fixed delay, or use a binary
 * exponential backoff strategy to increase the retry delay.
 *
 * @section Copyright
 *
 * Airframe is copyright 2006-2023 Carnegie Mellon University, and is released
 * under the GNU Lesser General Public License. See the COPYING file in the
 * distribution for details.
 *
 * Airframe was developed at the CERT Network Situational Awareness Group
 * by Brian Trammell for use in the NAF tools; certain modules
 * were written by Tony Cebzanov
 */

/**
 * @file
 *
 * Airframe utility functions. A home for utility functions that have no other.
 */

/* idem hack */
#ifndef _AIR_AIRUTIL_H_
#define _AIR_AIRUTIL_H_

#include <airframe/autoinc.h>

/** Minimum buffer size for air_time_buf_print() */
#define AIR_TIME_BUF_MINSZ       20
/** Minimum buffer size for air_ipaddr_buf_print() */
#define AIR_IPADDR_BUF_MINSZ     16
/** Minimum buffer size for air_ip6addr_buf_print() */
#define AIR_IP6ADDR_BUF_MINSZ    40

/** Time format description for air_time_* functions */
typedef enum air_timefmt_en {
    /** ISO8601 format with space between date and time */
    AIR_TIME_ISO8601,
    /** ISO8601 format with T between date and time */
    AIR_TIME_ISO8601_NS,
    /** Time format squished into single string for ASCII sort by time. */
    AIR_TIME_SQUISHED,
    /** ISO8601 format with time only */
    AIR_TIME_ISO8601_HMS
} AirTimeFormat;

/**
 * Append a string format of a time to a given GString in a given format.
 *
 * @param str string to append to
 * @param time time to append in epoch seconds
 * @param fmtid time format description
 */
void
air_time_g_string_append(
    GString        *str,
    time_t          time,
    AirTimeFormat   fmtid);

/**
 * Append a string format of a time in epoch milliseconds to a given GString
 * in a given format.
 *
 * @param str string to append to
 * @param mstime time to append in epoch milliseconds
 * @param fmtid time format description
 */
void
air_mstime_g_string_append(
    GString        *str,
    uint64_t        mstime,
    AirTimeFormat   fmtid);

/**
 * Write a string format of a time to a given buffer in a given format.
 *
 * @param buf buffer to write to
 * @param time time to print in epoch seconds
 * @param fmtid time format description
 */
void
air_time_buf_print(
    char           *buf,
    time_t          time,
    AirTimeFormat   fmtid);

/**
 * Portable, less unix-ish timegm() implementation. Converts a UTC year,
 * month, day, hour, minute, and second into a time in
 * epoch seconds. Handles leap years but not leap seconds. mon is 1-based
 * (as in English representations), and year is CE, not 1900-based.
 *
 * @param year year of date to convert (year CE)
 * @param mon month of date to convert (1-12)
 * @param day day of date to convert (1-31)
 * @param hour hour of date to convert (0-23)
 * @param min minute of date to convert (0-59)
 * @param sec second of date to convert (0-59)
 * @return epoch seconds
 */
time_t
air_time_gm(
    uint32_t   year,
    uint32_t   mon,
    uint32_t   day,
    uint32_t   hour,
    uint32_t   min,
    uint32_t   sec);

/**
 * Write the dotted quad format of an IPv4 address to a given buffer.
 * The buffer must be at least AIR_IPADDR_BUF_MINSZ (16) bytes long.
 *
 * @param buf buffer to write to
 * @param ipaddr address to print
 */
void
air_ipaddr_buf_print(
    char      *buf,
    uint32_t   ipaddr);

/**
 * Write the presentation format of an IPv6 address to a given buffer.
 * The buffer must be at least AIR_IP6ADDR_BUF_MINSZ (40) bytes long.
 *
 * @param buf buffer to write to
 * @param ipaddr address to print
 */
void
air_ip6addr_buf_print(
    char           *buf,
    const uint8_t  *ipaddr);

/**
 * Given a CIDR prefix length, return a mask for extracting the network part
 * of the address.
 *
 * @param pfx prefix length (0-32)
 * @return network-part mask bits
 */
uint32_t
air_mask_from_prefix(
    uint32_t   pfx);

/**
 * Append a given binary buffer as a hex + ASCII dump with 16 bytes per line
 * to the given GString.
 *
 * @param str       string to append to
 * @param lpfx      string to prefix each line of output with.
 *                  Use for indentation and labeling.
 * @param buf       Buffer to dump to GString
 * @param len       Length of buf
 */
void
air_hexdump_g_string_append(
    GString        *str,
    const char     *lpfx,
    const uint8_t  *buf,
    uint32_t        len);

/**
 * Maximize socket receive buffer size. Sets the socket's receive buffer to
 * the highest available size less than or equal to the given size.
 *
 * @param sock socket to increase buffer size of
 * @param size pointer to maximum size to set. Returns actually set size.
 * @return TRUE on success, FALSE otherwise.
 */
gboolean
air_sock_maxrcvbuf(
    int   sock,
    int  *size);

/**
 * Maximize socket send buffer size. Sets the socket's receive buffer to
 * the highest available size less than or equal to the given size.
 *
 * @param sock socket to increase buffer size of
 * @param size pointer to maximum size to set. Returns actually set size.
 * @return TRUE on success, FALSE otherwise.
 */
gboolean
air_sock_maxsndbuf(
    int   sock,
    int  *size);

/**
 * Ignore SIGPIPE, so that failed pipe writes or TCP writes on reset sockets
 * will return EPIPE instead of terminating the application.
 */
void
air_ignore_sigpipe(
    void);

#endif /* ifndef _AIR_AIRUTIL_H_ */
