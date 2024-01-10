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
**  sku-times.c
**
**  various utility functions for dealing with time
**
**  Suresh L Konda
**  1/24/2002
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: sku-times.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>


/* Time to ASCII */
char *
sktimestamp_r(
    char               *outbuf,
    sktime_t            t,
    unsigned int        timestamp_flags)
{
    struct tm ts;
    struct tm *rv;
    imaxdiv_t t_div;
    time_t t_sec;
    const int form_mask = (SKTIMESTAMP_NOMSEC | SKTIMESTAMP_EPOCH
                           | SKTIMESTAMP_MMDDYYYY | SKTIMESTAMP_ISO);

    t_div = imaxdiv(t, 1000);
    t_sec = (time_t)(t_div.quot);

    if (timestamp_flags & SKTIMESTAMP_EPOCH) {
        if (timestamp_flags & SKTIMESTAMP_NOMSEC) {
            snprintf(outbuf, SKTIMESTAMP_STRLEN-1, ("%" PRIdMAX), t_div.quot);
        } else {
            snprintf(outbuf, SKTIMESTAMP_STRLEN-1, ("%" PRIdMAX ".%03" PRIdMAX),
                     t_div.quot, t_div.rem);
        }
        return outbuf;
    }

    switch (timestamp_flags & (SKTIMESTAMP_UTC | SKTIMESTAMP_LOCAL)) {
      case SKTIMESTAMP_UTC:
        /* force UTC */
        rv = gmtime_r(&t_sec, &ts);
        break;
      case SKTIMESTAMP_LOCAL:
        /* force localtime */
        rv = localtime_r(&t_sec, &ts);
        break;
      default:
        /* use default timezone */
#if  SK_ENABLE_LOCALTIME
        rv = localtime_r(&t_sec, &ts);
#else
        rv = gmtime_r(&t_sec, &ts);
#endif
        break;
    }
    if (NULL == rv) {
        memset(&ts, 0, sizeof(struct tm));
    }

    switch (timestamp_flags & form_mask) {
      case SKTIMESTAMP_EPOCH:
      case (SKTIMESTAMP_EPOCH | SKTIMESTAMP_NOMSEC):
        /* these should have been handled above */
        skAbortBadCase(timestamp_flags & form_mask);
        break;

      case SKTIMESTAMP_MMDDYYYY:
        /* "MM/DD/YYYY HH:MM:SS.sss" */
        snprintf(outbuf, SKTIMESTAMP_STRLEN-1,
                 ("%02d/%02d/%04d %02d:%02d:%02d.%03" PRIdMAX),
                 ts.tm_mon + 1, ts.tm_mday, ts.tm_year + 1900,
                 ts.tm_hour, ts.tm_min, ts.tm_sec, t_div.rem);
        break;

      case (SKTIMESTAMP_MMDDYYYY | SKTIMESTAMP_NOMSEC):
        /* "MM/DD/YYYY HH:MM:SS" */
        snprintf(outbuf, SKTIMESTAMP_STRLEN-1, "%02d/%02d/%04d %02d:%02d:%02d",
                 ts.tm_mon + 1, ts.tm_mday, ts.tm_year + 1900,
                 ts.tm_hour, ts.tm_min, ts.tm_sec);
        break;

      case SKTIMESTAMP_ISO:
        /* "YYYY-MM-DD HH:MM:SS.sss" */
        snprintf(outbuf, SKTIMESTAMP_STRLEN-1,
                 ("%04d-%02d-%02d %02d:%02d:%02d.%03" PRIdMAX),
                 ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday,
                 ts.tm_hour, ts.tm_min, ts.tm_sec, t_div.rem);
        break;

      case (SKTIMESTAMP_ISO | SKTIMESTAMP_NOMSEC):
        /* "YYYY-MM-DD HH:MM:SS" */
        snprintf(outbuf, SKTIMESTAMP_STRLEN-1, "%04d-%02d-%02d %02d:%02d:%02d",
                 ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday,
                 ts.tm_hour, ts.tm_min, ts.tm_sec);
        break;

      case SKTIMESTAMP_NOMSEC:
        /* "YYYY/MM/DDTHH:MM:SS" */
        snprintf(outbuf, SKTIMESTAMP_STRLEN-1, "%04d/%02d/%02dT%02d:%02d:%02d",
                 ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday,
                 ts.tm_hour, ts.tm_min, ts.tm_sec);
        break;

      default:
        /* "YYYY/MM/DDTHH:MM:SS.sss" */
        snprintf(outbuf, SKTIMESTAMP_STRLEN-1,
                 ("%04d/%02d/%02dT%02d:%02d:%02d.%03" PRIdMAX),
                 ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday,
                 ts.tm_hour, ts.tm_min, ts.tm_sec, t_div.rem);
        break;
    }

    return outbuf;
}


char *
sktimestamp(
    sktime_t            t,
    unsigned int        timestamp_flags)
{
    static char t_buf[SKTIMESTAMP_STRLEN];
    return sktimestamp_r(t_buf, t, timestamp_flags);
}



/*
 *  max_day = skGetMaxDayInMonth(year, month);
 *
 *    Return the maximum number of days in 'month' in the specified
 *    'year'.
 *
 *    NOTE:  Months are in the 1..12 range and NOT 0..11
 *
 */
int
skGetMaxDayInMonth(
    int                 yr,
    int                 mo)
{
    static int month_days[12] = {31,28,31,30,31,30,31,31,30,31,30,31};

    /* use a 0-based array */
    assert(1 <= mo && mo <= 12);

    /* if not February or not a potential leap year, return fixed
     * value from array */
    if ((mo != 2) || ((yr % 4) != 0)) {
        return month_days[mo-1];
    }
    /* else year is divisible by 4, need more tests */

    /* year not divisible by 100 is a leap year, and year divisible by
     * 400 is a leap year */
    if (((yr % 100) != 0) || ((yr % 400) == 0)) {
        return 1 + month_days[mo-1];
    }
    /* else year is divisible by 100 but not by 400; not a leap year */

    return month_days[mo-1];
}


/* like gettimeofday returning an sktime_t */
sktime_t
sktimeNow(
    void)
{
    struct timeval tv;

    (void)gettimeofday(&tv, NULL);
    return sktimeCreateFromTimeval(&tv);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
