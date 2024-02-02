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

#define _AIRFRAME_SOURCE_
#include <airframe/airutil.h>

#define AIR_TIME_ISO8601_FMT     "%04u-%02u-%02u %02u:%02u:%02u"
#define AIR_TIME_ISO8601_NS_FMT  "%04u-%02u-%02uT%02u:%02u:%02u"
#define AIR_TIME_ISO8601_HMS_FMT "%02u:%02u:%02u"
#define AIR_TIME_SQUISHED_FMT    "%04u%02u%02u%02u%02u%02u"


static const char *
air_time_select_format(
    AirTimeFormat   fmtid)
{
    switch (fmtid) {
      case AIR_TIME_ISO8601:
        return AIR_TIME_ISO8601_FMT;
      case AIR_TIME_ISO8601_NS:
        return AIR_TIME_ISO8601_NS_FMT;
      case AIR_TIME_SQUISHED:
        return AIR_TIME_SQUISHED_FMT;
      case AIR_TIME_ISO8601_HMS:
        return AIR_TIME_ISO8601_HMS_FMT;
    }
    return AIR_TIME_ISO8601_FMT;
}


void
air_time_g_string_append(
    GString        *str,
    time_t          time,
    AirTimeFormat   fmtid)
{
    struct tm   time_tm;
    const char *fmt;

    fmt = air_time_select_format(fmtid);

#if ENABLE_LOCALTIME
    localtime_r(&time, &time_tm);
#else
    gmtime_r(&time, &time_tm);
#endif

    if (AIR_TIME_ISO8601_HMS == fmtid) {
        g_string_append_printf(str, fmt,
                               time_tm.tm_hour,
                               time_tm.tm_min,
                               time_tm.tm_sec);
    } else {
        g_string_append_printf(str, fmt,
                               time_tm.tm_year + 1900,
                               time_tm.tm_mon + 1,
                               time_tm.tm_mday,
                               time_tm.tm_hour,
                               time_tm.tm_min,
                               time_tm.tm_sec);
    }
}


void
air_time_buf_print(
    char           *buf,
    time_t          time,
    AirTimeFormat   fmtid)
{
    struct tm   time_tm;
    const char *fmt;

    fmt = air_time_select_format(fmtid);
#if ENABLE_LOCALTIME
    localtime_r(&time, &time_tm);
#else
    gmtime_r(&time, &time_tm);
#endif
    snprintf(buf, AIR_TIME_BUF_MINSZ, fmt,
             time_tm.tm_year + 1900,
             time_tm.tm_mon + 1,
             time_tm.tm_mday,
             time_tm.tm_hour,
             time_tm.tm_min,
             time_tm.tm_sec);
}


void
air_mstime_g_string_append(
    GString        *str,
    uint64_t        mstime,
    AirTimeFormat   fmtid)
{
    uint32_t msrem;

    msrem = mstime % 1000;
    mstime = mstime / 1000;

    air_time_g_string_append(str, mstime, fmtid);
    g_string_append_printf(str, ".%03u", msrem);
}


/* Note: heavily inspired by Python 2.2 timegm() implementation. */

time_t
air_time_gm(
    uint32_t   year,
    uint32_t   mon,
    uint32_t   day,
    uint32_t   hour,
    uint32_t   min,
    uint32_t   sec)
{
    static uint32_t dpm[] = { 31, 28, 31, 30,
                              31, 30, 31, 31,
                              30, 31, 30, 31 };
    time_t          epoday = 0, eposec = 0;
    uint32_t        i;

    /* assert input validity */
    g_assert(year >= 1970);
    g_assert((mon >= 1) && (mon <= 12));

    /* calculate day offset to beginning of year */
    epoday = (365 * (year - 1970)) +
        (((year - 1) / 4 - 1969 / 4) -
         ((year - 1) / 100 - 1969 / 100) +
         ((year - 1) / 400 - 1969 / 400));

    /* add day offset to beginning of month */
    for (i = 1; i < mon; i++) {
        epoday += dpm[i - 1];
    }

    /* add day offset for leap year */
    if (mon > 2 &&
        ((!(year % 4) && (year % 100)) || !(year % 400)))
    {
        epoday += 1;
    }

    /* add day offset for beginning of day */
    epoday += (day - 1);

    /* convert day offset to epoch */
    eposec = epoday * 86400;

    /* add hour, minute, second offset */
    eposec += hour * 3600;
    eposec += min * 60;
    eposec += sec;

    /* All done. */
    return eposec;
}


void
air_ipaddr_buf_print(
    char      *buf,
    uint32_t   ipaddr)
{
    uint8_t  dqp[4];
    uint32_t mask = 0xff000000U;

    /* split the address */
    dqp[0] = (ipaddr & mask) >> 24;
    mask >>= 8;
    dqp[1] = (ipaddr & mask) >> 16;
    mask >>= 8;
    dqp[2] = (ipaddr & mask) >> 8;
    mask >>= 8;
    dqp[3] = (ipaddr & mask);

    /* print to it */
    snprintf(buf, AIR_IPADDR_BUF_MINSZ,
             "%hhu.%hhu.%hhu.%hhu", dqp[0], dqp[1], dqp[2], dqp[3]);
}


void
air_ip6addr_buf_print(
    char           *buf,
    const uint8_t  *ipaddr)
{
    char     *cp = buf;
    const uint16_t *aqp = (uint16_t *)ipaddr;
    uint16_t  aq;
    gboolean  colon_start = FALSE;
    gboolean  colon_end = FALSE;

    for (; (const uint8_t *)aqp < ipaddr + 16; aqp++) {
        aq = g_ntohs(*aqp);
        if (aq || colon_end) {
            if ((uint8_t *)aqp < ipaddr + 14) {
                snprintf(cp, 6, "%04hx:", aq);
                cp += 5;
            } else {
                snprintf(cp, 5, "%04hx", aq);
                cp += 4;
            }
            if (colon_start) {
                colon_end = TRUE;
            }
        } else if (!colon_start) {
            if ((uint8_t *)aqp == ipaddr) {
                snprintf(cp, 3, "::");
                cp += 2;
            } else {
                snprintf(cp, 2, ":");
                cp += 1;
            }
            colon_start = TRUE;
        }
    }
}


uint32_t
air_mask_from_prefix(
    uint32_t   pfx)
{
    uint32_t mask = 0;
    uint32_t i = 0;

    for (i = 0; i < pfx; i++) {
        mask >>= 1;
        mask |= 0x80000000U;
    }

    return mask;
}


static uint32_t
air_hexdump_g_string_append_line(
    GString        *str,
    const char     *lpfx,
    const uint8_t  *cp,
    uint32_t        lineoff,
    uint32_t        buflen)
{
    uint32_t cwr = 0, twr = 0;

    /* stubbornly refuse to print nothing */
    if (!buflen) {return 0;}

    /* print line header */
    g_string_append_printf(str, "%s %04x:", lpfx, lineoff);

    /* print hex characters */
    for (twr = 0; twr < 16; twr++) {
        if (buflen) {
            g_string_append_printf(str, " %02hhx", cp[twr]);
            cwr++; buflen--;
        } else {
            g_string_append(str, "   ");
        }
    }

    /* print characters */
    g_string_append_c(str, ' ');
    for (twr = 0; twr < cwr; twr++) {
        if ((cp[twr] > 32 && cp[twr] < 128) || cp[twr] == 32) {
            g_string_append_c(str, cp[twr]);
        } else {
            g_string_append_c(str, '.');
        }
    }
    g_string_append_c(str, '\n');

    return cwr;
}


void
air_hexdump_g_string_append(
    GString        *str,
    const char     *lpfx,
    const uint8_t  *buf,
    uint32_t        len)
{
    uint32_t cwr = 0, lineoff = 0;

    do {
        cwr = air_hexdump_g_string_append_line(str, lpfx, buf, lineoff, len);
        buf += cwr; len -= cwr; lineoff += cwr;
    } while (cwr == 16);
}


gboolean
air_sock_maxrcvbuf(
    int   sock,
    int  *size)
{
    while (*size > 4096) {
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, size, sizeof(*size)) == 0) {
            return TRUE;
        }
        if (errno != ENOBUFS) {return FALSE;}
        *size -= (*size > 1024 * 1024)
            ? 1024 * 1024
            : 2048;
    }
    return FALSE;
}


gboolean
air_sock_maxsndbuf(
    int   sock,
    int  *size)
{
    while (*size > 4096) {
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, size, sizeof(*size)) == 0) {
            return TRUE;
        }
        if (errno != ENOBUFS) {return FALSE;}
        *size -= (*size > 1024 * 1024)
            ? 1024 * 1024
            : 2048;
    }
    return FALSE;
}


void
air_ignore_sigpipe(
    void)
{
    struct sigaction sa, osa;

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGPIPE, &sa, &osa)) {
        g_error("sigaction(SIGPIPE) failed: %s", strerror(errno));
    }
}
