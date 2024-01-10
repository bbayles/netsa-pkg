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
**  sku-compat.c
**
**    Function
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: sku-compat.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>


/* Compute quotient and remainder in one structure like div(), but
 * with intmax_t's instead of int's. */
sk_imaxdiv_t
sk_imaxdiv(
    sk_intmax_t         numer,
    sk_intmax_t         denom)
{
    sk_imaxdiv_t res;
    res.quot = numer / denom;
    res.rem = numer % denom;
    return res;
}


/* Copy data from 'src' to 'dst' stopping at value 'c' or when 'len'
 * octets have been copied.  If 'c' was not found, NULL is returned;
 * else return value points to character after 'c' in 'dst'. */
void *
sk_memccpy(
    void               *dst,
    const void         *src,
    int                 c,
    size_t              len)
{
    uint8_t *c_dst = (uint8_t*)dst;
    const uint8_t *c_src = (const uint8_t*)src;

    for ( ; len > 0; --len) {
        *c_dst = *c_src;
        ++c_dst;
        if (*c_src == c) {
            return c_dst;
        }
        ++c_src;
    }
    return NULL;
}


/* Set environment variable 'name' to 'value', unless 'name' already
 * exists in the environment and 'overwrite' is 0. */
int
sk_setenv(
    const char         *name,
    const char         *value,
    int                 overwrite)
{
    /* This function allocates new memory on every call.  This will be
     * reported as a memory leak in valgrind, but that is hard to
     * avoid.  We could reduce memory usage by overwriting the current
     * value for 'name' when 'name' exists in the environment and
     * strlen(value) is not greater than strlen(getenv(name)). */

    char *buf;

    if (strchr(name, '=')) {
        errno = EINVAL;
        return -1;
    }

    if (overwrite || !getenv(name)) {
        buf = (char*)malloc(2 + strlen(name) + strlen(value));
        if (NULL == buf) {
            return -1;
        }
        strcpy(buf, name);
        strcat(buf, "=");
        strcat(buf, value);
        return putenv(buf);
    }

    return 0;
}


/* Return next 'delim'-delimited token from *stringp; move *stringp to
 * start of next token. */
char *
sk_strsep(
    char              **stringp,
    const char         *delim)
{
    char *cp = *stringp;
    size_t sz;

    if (NULL == cp) {
        return NULL;
    }

    sz = strcspn(cp, delim);
    if (cp[sz] == '\0') {
        /* reached end of string */
        *stringp = NULL;
    } else {
        cp[sz] = '\0';
        *stringp += (sz + 1);
    }

    return cp;
}


/* Inverse of gmtime(); convert a struct tm to time_t. */
time_t
sk_timegm(
    struct tm          *tm)
{
    time_t t_offset, t_2offset;
    struct tm tm_offset;

    /* compute time_t with the timezone offset */
    t_offset = mktime(tm);
    if (t_offset == -1) {
        /* see if adjusting the hour allows mktime() to work */
        tm->tm_hour--;
        t_offset = mktime(tm);
        if (t_offset == -1) {
            return -1;
        }
        /* adjusting hour worked; add back that time */
        t_offset += 3600;
    }

    /* compute a second value with another timezone offset */
    gmtime_r(&t_offset, &tm_offset);
    tm_offset.tm_isdst = 0;
    t_2offset = mktime(&tm_offset);
    if (t_2offset == -1) {
        tm_offset.tm_hour--;
        t_2offset = mktime(&tm_offset);
        if (t_2offset == -1) {
            return -1;
        }
        t_2offset += 3600;
    }

    /* difference in the two time_t's is one TZ offset */
    return (t_offset - (t_2offset - t_offset));
}


#if 0
/* just like snprintf(), but always NUL terminates */
int
sk_snprintf(
    char               *str,
    size_t              size,
    const char         *format,
    ...)
{
    va_list args;
    int rv;

    va_start(args, format);
    rv = sk_vsnprintf(str, size, format, args);
    va_end(args);
    return rv;
}


/* just like vsnprintf(), but always NUL terminates */
int
sk_vsnprintf(
    char               *str,
    size_t              size,
    const char         *format,
    va_list             args)
{
#undef vsnprintf
    int rv = vsnprintf(str, size, format, args);
    str[size-1] = '\0';
    return rv;
}
#endif


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
