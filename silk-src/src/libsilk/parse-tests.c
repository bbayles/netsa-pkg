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
**  Tests for the parsing routines in silkstring.c
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: parse-tests.c 35b901fd2f56 2023-03-10 19:46:07Z mthomas $");

#include <silk/skipaddr.h>
#include <silk/utils.h>

#ifndef USE_GETADDRINFO
#  ifdef SK_HAVE_GETADDRINFO
#    define USE_GETADDRINFO 1
#  else
#    define USE_GETADDRINFO 0
#  endif
#endif
#if !USE_GETADDRINFO && SK_ENABLE_INET6_NETWORKING
#  undef SK_ENABLE_INET6_NETWORKING
#  define SK_ENABLE_INET6_NETWORKING 0
#endif


int c;

#define P_HEADER(str)                                           \
    c = 0, printf("\n>>>>> RUNNING TESTS ON " str "\n\n")
#define P_WARNS(val)                                            \
    if ((val) == 0) {} else printf("\t EXPECT WARNINGS")
#define P_NULL(str)                                             \
    (((str) == NULL) ? printf("NULL") : printf("'%s'", str))
#define P_STATUS(failed)                                                \
    printf("  TEST %s", (((failed) == 0) ? "PASSED" : "FAILED"))
#define P_BEGIN                                 \
    printf("TEST_BEGIN[%3d]: ", ++c)
#define P_END                                   \
    printf("TEST_END\n\n")
#define P_NL                                    \
    printf("\n")
#define P_ERR(val)                                                      \
    if (val >= 0) {}                                                    \
    else printf(ERR_STR "%s\n", skStringParseStrerror(val))

#define GOT_STR " got: "
#define EXP_STR "         expected: "
#define ERR_STR "         strerror: "

#define SENTINEL "END_OF_INPUT"

#define IS_SENTINEL(str) \
    (((str) != NULL) && (0 == strcmp((str), SENTINEL)))


/* OPTIONS SETUP */

enum {
    OPT_NUMBERS,
    OPT_LISTS,
    OPT_DATES,
    OPT_TCP_FLAGS,
    OPT_SIGNALS,
    OPT_IP_ADDRESSES,
    OPT_HOST_PORT_PAIRS,
    OPT_ALL_TESTS               /* Must be last!! */
};

static struct option appOptions[] = {
    {"numbers",         NO_ARG, 0, OPT_NUMBERS},
    {"lists",           NO_ARG, 0, OPT_LISTS},
    {"dates",           NO_ARG, 0, OPT_DATES},
    {"tcp-flags",       NO_ARG, 0, OPT_TCP_FLAGS},
    {"signals",         NO_ARG, 0, OPT_SIGNALS},
    {"ip-addresses",    NO_ARG, 0, OPT_IP_ADDRESSES},
    {"host-port-pairs", NO_ARG, 0, OPT_HOST_PORT_PAIRS},
    {"all-tests",       NO_ARG, 0, OPT_ALL_TESTS},
    {0,0,0,0}           /* sentinel entry */
};

static const char *appHelp[] = {
    "Run tests to parse numbers. Def. No",
    "Run tests to parse list of numbers. Def. No",
    "Run tests to parse dates and date-ranges. Def. No",
    "Run tests to parse TCP flags and high/mask pairs. Def. No",
    "Run tests to parse signal names. Def. No",
    "Run tests to parse IP addresses. Def. No",
    "Run tests to parse hosts and host:port pairs. Def. No",
    "Run all of the above tests. Def. No",
    NULL
};


/* FUNCTION DEFINITIONS */


/* Tests for skStringParseNumberList() */

static int
number_list_parser(
    void)
{
    int rv;
    uint32_t *result_val;
    uint32_t result_count;
    uint32_t i, j;
    int failed, print_results;

    static struct {
        int         exp_retval;
        uint32_t    exp_count;
        uint32_t    exp_array[16];
        uint32_t    min;
        uint32_t    max;
        uint32_t    count;
        const char *str;
    } input[] = {
        { 0,  6, {0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "0,1,2,3,4,5" },
        { 0,  6, {5,4,3,2,1,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "5,4,3,2,1,0" },
        { 0,  6, {5,4,3,2,1,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "5,4,3,2,1,0 " },
        { 0,  6, {0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "0-5" },
        { 0,  6, {0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, " 0-5" },
        { 0,  6, {0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "0-5 " },
        { 0,  6, {0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, " 0-5 " },
        { 0,  1, {2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "2" },
        { 0,  1, {2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "2-2" },
        { 0,  2, {2,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "2,2" },
        { 0,  2, {2,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, " 2,2" },
        { 0,  2, {2,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "2,2 " },
        { 0, 10, {0,1,2,3,4,5,0,1,2,3,0,0,0,0,0,0}, 0, 5, 10, "0-5,0-3" },
        {SKUTILS_ERR_TOO_MANY_FIELDS,
              0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "0-5,0-4" },
        {SKUTILS_ERR_MAXIMUM,
              0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "1-6" },
        {SKUTILS_ERR_BAD_CHAR,
              0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "2-3-" },
        {SKUTILS_ERR_BAD_CHAR,
              0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "2 3" },
        {SKUTILS_ERR_BAD_CHAR,
              0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "2-" },
        {SKUTILS_ERR_BAD_RANGE,
              0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "3-2" },
        {SKUTILS_ERR_MINIMUM,
              0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 1, 5, 10, "0-5" },
        {SKUTILS_ERR_EMPTY,
              0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "" },
        {SKUTILS_ERR_EMPTY,
              0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, "   " },
        {SKUTILS_ERR_INVALID,
              0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 5, 10, NULL },
        { 0,  0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0, 0,  0, SENTINEL }
    };


    P_HEADER("skStringParseNumberList()");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("min=%3u, max=%3u, count=%3u,  str=",
               input[i].min, input[i].max, input[i].count);
        P_NULL(input[i].str);
        P_WARNS(input[i].exp_retval);
        P_NL;

        result_val = NULL;
        result_count = 0;
        failed = 0;
        print_results = 0;

        rv = skStringParseNumberList(&result_val, &result_count,
                                     input[i].str,
                                     input[i].min,
                                     input[i].max,
                                     input[i].count);
        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv != 0) {
            print_results = 1;
        } else if (result_count != input[i].exp_count) {
            failed = 1;
        } else if (result_count != 0 && result_val == NULL) {
            failed = 1;
        } else {
            for (j = 0; j < result_count; ++j) {
                if (result_val[j] != input[i].exp_array[j]) {
                    failed = 1;
                    break;
                }
            }
        }

        P_STATUS(failed);

        if ( failed || print_results) {
            printf(GOT_STR "ret=%3d, count=%3" PRIu32 ", res=",
                   rv, result_count);
            if (result_val == NULL) {
                printf("NULL");
            } else if (result_count == 0) {
                printf("[]");
            } else {
                printf(("[%" PRIu32), result_val[0]);
                for (j = 1; j < result_count; ++j) {
                    printf((",%" PRIu32), result_val[j]);
                }
                printf("]");
            }
        }
        P_NL;

        if (failed) {
            printf(EXP_STR "ret=%3d, count=%3lu, res=",
                   input[i].exp_retval, (unsigned long)input[i].exp_count);
            if (input[i].exp_count == 0) {
                printf("[]");
            } else {
                printf("[%lu", (unsigned long)input[i].exp_array[0]);
                for (j = 1; j < input[i].exp_count; ++j) {
                    printf(",%lu", (unsigned long)input[i].exp_array[j]);
                }
                printf("]");
            }
            P_NL;
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        if (result_val != NULL) {
            free(result_val);
        }

        P_END;
    }

    return 0;
}



/* Tests for skStringParseNumberListToBitmap() */

static int
number_list_to_bitmap_parser(
    void)
{
#define BMAP_SIZE  95
    int rv;
    sk_bitmap_t bmap;
    uint32_t result_val[(((BMAP_SIZE) >> 5)
                         + ((((BMAP_SIZE) & 0x1F) == 0) ? 0 : 1))];
    uint32_t i, j;
    int failed, print_results;

    static struct {
        int         exp_retval;
        uint32_t    exp_array[3];
        uint32_t    max;
        const char *str;
    } input[] = {
        { 0, {          63,           0, 0}, 63, "0,1,2,3,4,5" },
        { 0, {          63,           0, 0}, 64, "5,4,3,2,1,0" },
        { 0, {          63,           0, 0}, 65, "0-5" },
        { 0, {          63,           0, 0}, 96, "0-5,0-3" },
        { 0, {           0,           1, 0}, 64, "32" },
        { 0, {           0,           1, 0}, 64, "32-32" },
        { 0, {           0,           1, 0}, 64, "32,32" },
        { 0, { 4294967295u,           0, 0}, 64, "0-31" },
        { 0, { 4294967295u,           0, 0}, 64, " 0-31" },
        { 0, { 4294967295u,           0, 0}, 64, "0-31 " },
        { 0, { 4294967295u,           0, 0}, 64, " 0-31 " },
        { 0, {           0, 1073741824u, 0}, 63, "62" },
        { 0, {           0, 2147483648u, 0}, 64, "63" },
        { 0, {           0, 3221225472u, 0}, 64, "62-" },
        { 0, {           0,           0, 1}, 65, "64" },
        { 0, {           0,           0, 2}, 66, "65" },

        {SKUTILS_ERR_MAXIMUM,   {0,0,0}, 64, "1-65" },
        {SKUTILS_ERR_BAD_CHAR,  {0,0,0}, 64, "2-3-" },
        {SKUTILS_ERR_BAD_CHAR,  {0,0,0}, 64, "2 3" },
        {SKUTILS_ERR_BAD_RANGE, {0,0,0}, 64, "3-2" },
        {SKUTILS_ERR_MAXIMUM,   {0,0,0}, 64, "64" },
        {SKUTILS_ERR_EMPTY,     {0,0,0}, 64, "" },
        {SKUTILS_ERR_EMPTY,     {0,0,0}, 64, "   " },
        {SKUTILS_ERR_INVALID,   {0,0,0}, 64, NULL },

        { 0, {0,0,0},  0, SENTINEL }
    };


    P_HEADER("skStringParseNumberListToBitmap()");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("max=%3u,  str=",
               input[i].max);
        P_NULL(input[i].str);
        P_NL;

        skBitmapBind(&bmap, input[i].max, result_val, sizeof(result_val));
        failed = 0;
        print_results = 0;

        rv = skStringParseNumberListToBitmap(&bmap, input[i].str);
        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv != 0) {
            print_results = 1;
        } else {
            for (j = 0; j < 3; ++j) {
                if (result_val[j] != input[i].exp_array[j]) {
                    failed = 1;
                    break;
                }
            }
        }

        P_STATUS(failed);

        if ( failed || print_results) {
            printf(GOT_STR "ret=%3d, res=",
                   rv);
            printf("[%lu", (unsigned long)result_val[0]);
            for (j = 1; j < 3; ++j) {
                printf(",%lu", (unsigned long)result_val[j]);
            }
            printf("]");
        }
        P_NL;

        if (failed) {
            printf(EXP_STR "ret=%3d, res=",
                   input[i].exp_retval);
            printf("[%lu", (unsigned long)input[i].exp_array[0]);
            for (j = 1; j < 3; ++j) {
                printf(",%lu", (unsigned long)input[i].exp_array[j]);
            }
            printf("]");
            P_NL;
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        P_END;
    }

    return 0;
}



/* Tests for skStringParseDatetime() */

static int
datetime_parser(
    void)
{
    uint32_t i;
    int rv;
    sktime_t result_val;
    unsigned int precision;
    int failed, print_results;

    static struct {
        int             exp_retval;
        sktime_t        exp_result;
        unsigned int    exp_prec;
        const char     *str;
    } input[] = {
        {0,       1099526400000LL,  3, "2004/11/04"},
        {0,       1099526400000LL,  3, "2004/11/04   "},
        {0,       1099526400000LL,  3, "   2004/11/04"},
        {0,       1099526400000LL,  3, " 2004/11/04  "},
        {0,       1099566000000LL,  4, "2004/11/04:11"},
        {0,       1099566720000LL,  5, "2004/11/4:11:12"},
        {0,       1099566733000LL,  6, "2004/11/4:11:12:13"},
        {0,       1099566733456LL,  7, "2004/11/4:11:12:13.456"},
        {0,       1099566733000LL, 14, "1099566733"},
        {0,       1099566733456LL, 15, "1099566733.456"},
        {0,       1099566733400LL,  7, "2004/11/4:11:12:13.4"},
        {0,       1099566733450LL,  7, "2004/11/4:11:12:13.45"},
        {0,       1099566733456LL,  7, "2004/11/4:11:12:13.456111111"},
        {0,       1099566733456LL,  7, "2004/11/4:11:12:13.456999999"},
        {SKUTILS_ERR_BAD_CHAR,  0,  6, "2004/11/4:11:12:13:14"},
        {SKUTILS_ERR_BAD_CHAR,  0,  6, "2004/11/4:11:12:13-2004/11/4:11:12:14"},
        {SKUTILS_ERR_BAD_CHAR,  0,  0, "2004-11-4"},
        {SKUTILS_ERR_BAD_CHAR,  0,  0, "2004/11/4:11:12:13  x"},
        {SKUTILS_ERR_MINIMUM,   0,  0, "200411.04"},
        {SKUTILS_ERR_OVERFLOW,  0,  0, "109956673345629384756"},
        {SKUTILS_ERR_SHORT,     0,  1, "2004"},
        {SKUTILS_ERR_SHORT,     0,  1, "2004/"},
        {SKUTILS_ERR_BAD_CHAR,  0,  3, "  2004/11/4 11:12:13  "},
        {SKUTILS_ERR_SHORT,     0,  2, "2004/11"},
        {SKUTILS_ERR_SHORT,     0,  2, "2004/11/"},
        {SKUTILS_ERR_MINIMUM,   0,  0, "2004/0/4"},
        {SKUTILS_ERR_MAXIMUM,   0,  0, "2004/13/4"},
        {SKUTILS_ERR_MINIMUM,   0,  0, "1959/01/01"},
        {SKUTILS_ERR_BAD_CHAR,  0,  0, "2004/11/4:-3:-3:-3"},
        {SKUTILS_ERR_BAD_CHAR,  0,  0, "2004/11/4::11:12"},
        {SKUTILS_ERR_MAXIMUM,   0,  0, "2004/11/31"},
        {SKUTILS_ERR_MAXIMUM,   0,  0, "2004/11/4:24"},
        {SKUTILS_ERR_MAXIMUM,   0,  0, "2004/11/4:23:60:59"},
        {SKUTILS_ERR_MAXIMUM,   0,  0, "2004/11/4:23:59:60"},
        {SKUTILS_ERR_MAXIMUM,   0,  2, "2004/11/40"},
        {SKUTILS_ERR_MAXIMUM,   0,  3, "2004/11/4:110"},
        {SKUTILS_ERR_MAXIMUM,   0,  4, "2004/11/4:11:120"},
        {SKUTILS_ERR_MAXIMUM,   0,  5, "2004/11/4:11:12:130"},
        {SKUTILS_ERR_EMPTY,     0,  0, "   "},
        {SKUTILS_ERR_EMPTY,     0,  0, ""},
        {SKUTILS_ERR_INVALID,   0,  0, NULL},
        {0,                     0,  0, SENTINEL}
    };

    P_HEADER("skStringParseDatetime()");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("str=");
        P_NULL(input[i].str);
        P_WARNS(input[i].exp_retval);
        P_NL;

        result_val = 0;
        precision = 0;
        failed = 0;
        print_results = 0;

        rv = skStringParseDatetime(&result_val, input[i].str, &precision);

        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv != 0) {
            print_results = 1;
        } else if (result_val != input[i].exp_result) {
            failed = 1;
        } else if (precision != input[i].exp_prec) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf((GOT_STR "ret=%3d, precision=%3u, result=%15" PRId64),
                   rv, precision, (int64_t)result_val);
        }
        P_NL;

        if (failed) {
            printf((EXP_STR "ret=%3d, precision=%3u, result=%15" PRId64 "\n"),
                   input[i].exp_retval, input[i].exp_prec,
                   (int64_t)input[i].exp_result);
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        P_END;
    }

    return 0;
}



/* Tests for skStringParseDatetimeRange() */

static int
datetime_range_parser(
    void)
{
    uint32_t i;
    int rv;
    sktime_t s_time, e_time;
    unsigned int s_precision, e_precision;
    int failed, print_results;

    static struct {
        int             exp_retval;
        sktime_t        exp_start_time;
        sktime_t        exp_end_time;
        unsigned int    exp_start_prec;
        unsigned int    exp_end_prec;
        const char     *str;
    } input[] = {
        {SKUTILS_OK,            1099526400000LL,       INT64_MAX, 3, 0,
         "2004/11/04"},
        {SKUTILS_OK,            1099526400000LL,       INT64_MAX, 3, 0,
         "2004/11/04   "},
        {SKUTILS_OK,            1099526400000LL,       INT64_MAX, 3, 0,
         "   2004/11/04"},
        {SKUTILS_OK,            1099526400000LL,       INT64_MAX, 3, 0,
         " 2004/11/04  "},
        {SKUTILS_OK,            1099566000000LL,       INT64_MAX, 4, 0,
         "2004/11/04:11"},
        {SKUTILS_OK,            1099566720000LL,       INT64_MAX, 5, 0,
         "2004/11/4:11:12"},
        {SKUTILS_OK,            1099566733000LL,       INT64_MAX, 6, 0,
         "2004/11/4:11:12:13"},
        {SKUTILS_ERR_BAD_CHAR,                0,               0, 6, 0,
         "2004/11/4:11:12:13:14"},
        {SKUTILS_OK,            1099526400000LL, 1099612800000LL, 3, 3,
         "2004/11/04-2004/11/05"},
        {SKUTILS_OK,            1099566733000LL, 1099566733000LL, 6, 6,
         "2004/11/4:11:12:13-2004/11/4:11:12:13"},
        {SKUTILS_OK,            1099566733000LL, 1099566734000LL, 6, 6,
         "2004/11/4:11:12:13-   2004/11/4:11:12:14"},
        {SKUTILS_OK,            1099566733000LL, 1099566734000LL, 7, 7,
         "2004/11/4:11:12:13.000-2004/11/4:11:12:14.000"},
        {SKUTILS_OK,            1099566733000LL, 1099566734000LL, 6, 6,
         "2004/11/4:11:12:13-2004/11/4:11:12:14"},
        {SKUTILS_OK,            1099566733000LL, 1099566733000LL, 6, 6,
         "2004/11/4:11:12:13-2004/11/4:11:12:13"},
        {SKUTILS_ERR_BAD_RANGE,  1099566733000LL, 1099566732000LL, 6, 6,
         "2004/11/4:11:12:13-2004/11/4:11:12:12"},
        {SKUTILS_OK,            1099566733000LL, 1099566780000LL, 6, 5,
         "2004/11/4:11:12:13-2004/11/4:11:13"},
        {SKUTILS_OK,            1099566733000LL, 1099569600000LL, 6, 4,
         "2004/11/4:11:12:13-2004/11/4:12"},
        {SKUTILS_OK,            1099566733000LL, 1099612800000LL, 6, 3,
         "2004/11/4:11:12:13-2004/11/5"},
        {SKUTILS_ERR_SHORT,     1099566733000LL,               0, 6, 1,
         "2004/11/4:11:12:13-2004"},
        {SKUTILS_ERR_SHORT,     1099566733000LL,               0, 6, 1,
         "2004/11/4:11:12:13-2004/"},
        {SKUTILS_ERR_BAD_CHAR,  1099566733000LL,               0, 6, 3,
         "2004/11/4:11:12:13-  2004/11/4 11:12:13  "},
        {SKUTILS_ERR_SHORT,     1099566733000LL,               0, 6, 2,
         "2004/11/4:11:12:13-2004/11/"},
        {SKUTILS_ERR_MINIMUM,   1099566733000LL,               0, 6, 0,
         "2004/11/4:11:12:13-2004/0/4"},
        {SKUTILS_ERR_MAXIMUM,   1099566733000LL,               0, 6, 0,
         "2004/11/4:11:12:13-2004/13/4"},
        {SKUTILS_ERR_MINIMUM,   1099566733000LL,               0, 6, 0,
         "2004/11/4:11:12:13-1959/01/01"},
        {SKUTILS_ERR_BAD_CHAR,  1099566733000LL,               0, 6, 0,
         "2004/11/4:11:12:13-2004/11/4:-3:-3:-3"},
        {SKUTILS_ERR_BAD_CHAR,  1099566733000LL,               0, 6, 0,
         "2004/11/4:11:12:13-2004/11/4::11:12"},
        {SKUTILS_ERR_MAXIMUM,   1099566733000LL,               0, 6, 0,
         "2004/11/4:11:12:13-2004/11/31"},
        {SKUTILS_ERR_MAXIMUM,   1099566733000LL,               0, 6, 0,
         "2004/11/4:11:12:13-2004/11/4:24"},
        {SKUTILS_ERR_MAXIMUM,   1099566733000LL,               0, 6, 0,
         "2004/11/4:11:12:13-2004/11/4:23:60:59"},
        {SKUTILS_ERR_MAXIMUM,   1099566733000LL,               0, 6, 0,
         "2004/11/4:11:12:13-2004/11/4:23:59:60"},
        {SKUTILS_ERR_EMPTY,                   0,               0, 0, 0,
         "   "},
        {SKUTILS_ERR_EMPTY,                   0,               0, 0, 0,
         ""},
        {SKUTILS_ERR_INVALID,                 0,               0, 0, 0,
         NULL},
        {0,                                   0,               0, 0, 0,
          SENTINEL}
    };

    P_HEADER("skStringParseDatetimeRange()");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("str=");
        P_NULL(input[i].str);
        P_WARNS(input[i].exp_retval);
        P_NL;

        s_precision = 0;
        e_precision = 0;
        failed = 0;
        print_results = 0;

        rv = skStringParseDatetimeRange(&s_time, &e_time, input[i].str,
                                        &s_precision, &e_precision);

        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (s_time != input[i].exp_start_time) {
            failed = 1;
        } else if (e_time != input[i].exp_end_time) {
            failed = 1;
        } else if (s_precision != input[i].exp_start_prec) {
            failed = 1;
        } else if (e_precision != input[i].exp_end_prec) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf((GOT_STR "ret=%3d, s_prec=%3u, e_prec=%3u, "
                    "s_time=%15" PRId64 ", e_time=%15" PRId64),
                   rv, s_precision, e_precision,
                   (int64_t)s_time, (int64_t)e_time);
        }
        P_NL;

        if (failed) {
            printf((EXP_STR "ret=%3d, s_prec=%3u, e_prec=%3u, "
                    "s_time=%15" PRId64 ", e_time=%15" PRId64 "\n"),
                   input[i].exp_retval,
                   input[i].exp_start_prec, input[i].exp_end_prec,
                   (int64_t)input[i].exp_start_time,
                   (int64_t)input[i].exp_end_time);
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        P_END;
    }

    return 0;
}



/* Tests for skDatetimeCeiling() */

static int
datetime_ceiling_parser(
    void)
{
    uint32_t i;
    int rv;
    sktime_t ceiling_time;
    int failed, print_results;
    static struct {
        int             exp_retval;
        sktime_t        exp_ceiling_time;
        unsigned int    prec;
        sktime_t        in_time;
    } input[] = {
        /* 2004-Nov-04 11:12:13.000 */
        {0,  INT64_C(1099566733000), 15, INT64_C(1099566733000)},
        /* 2004-Nov-04 11:12:13.456 */
        {0,  INT64_C(1099566733456),  7, INT64_C(1099566733456)},
        /* 2004-Nov-04 11:12:13.999 */
        {0,  INT64_C(1099566733999),  6, INT64_C(1099566733456)},
        /* 2004-Nov-04 11:12:59.999 */
        {0,  INT64_C(1099566779999),  5, INT64_C(1099566733456)},
        /* 2004-Nov-04 11:59:59.999 */
        {0,  INT64_C(1099569599999),  4, INT64_C(1099566733456)},
        /* 2004-Nov-04 23:59:59.999 */
        {0,  INT64_C(1099612799999),  3, INT64_C(1099566733456)},
        /* 2004-Nov-30 23:59:59.999 */
        {0,  INT64_C(1101859199999),  2, INT64_C(1099566733456)},
        /* 2004-Dec-31 23:59:59.999 */
        {0,  INT64_C(1104537599999),  1, INT64_C(1099566733456)},
        /* invalid precision */
        {-1,             INT64_C(0),  0, INT64_C(1099566733456)},
        /* invalid precision */
        {-1,             INT64_C(0), 99, INT64_C(1099566733456)},
        /* sentinel */
        {0,              INT64_C(0),  0, INT64_C(0)}
    };


    P_HEADER("skDatetimeCeiling()");

    for (i = 0; input[i].in_time; ++i) {

        P_BEGIN;
        printf(("input=%" PRId64), input[i].in_time);
        P_WARNS(input[i].exp_retval);
        P_NL;

        failed = 0;
        print_results = 0;
        ceiling_time = 0;

        rv = (skDatetimeCeiling(
                  &ceiling_time, &input[i].in_time, input[i].prec));

        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (ceiling_time != input[i].exp_ceiling_time) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf((GOT_STR "ret=%3d, ceiling_time=%15" PRId64),
                   rv, ceiling_time);
        }
        P_NL;

        if (failed) {
            printf((EXP_STR "ret=%3d, ceiling_time=%15" PRId64 "\n"),
                   input[i].exp_retval, input[i].exp_ceiling_time);
        }

        P_END;
    }

    return 0;
}



/* Tests for skDatetimeFloor() */

static int
datetime_floor_parser(
    void)
{
    uint32_t i;
    int rv;
    sktime_t floor_time;
    int failed, print_results;
    static struct {
        int             exp_retval;
        sktime_t        exp_floor_time;
        unsigned int    prec;
        sktime_t        in_time;
    } input[] = {
        /* 2004-Nov-04 11:12:13.000 */
        {0,  INT64_C(1099566733000), 15, INT64_C(1099566733000)},
        /* 2004-Nov-04 11:12:13.456 */
        {0,  INT64_C(1099566733456),  7, INT64_C(1099566733456)},
        /* 2004-Nov-04 11:12:13.000 */
        {0,  INT64_C(1099566733000),  6, INT64_C(1099566733456)},
        /* 2004-Nov-04 11:12:00.000 */
        {0,  INT64_C(1099566720000),  5, INT64_C(1099566733456)},
        /* 2004-Nov-04 11:00:00.000 */
        {0,  INT64_C(1099566000000),  4, INT64_C(1099566733456)},
        /* 2004-Nov-04 00:00:00.000 */
        {0,  INT64_C(1099526400000),  3, INT64_C(1099566733456)},
        /* 2004-Nov-01 00:00:00.000 */
        {0,  INT64_C(1099267200000),  2, INT64_C(1099566733456)},
        /* 2004-Jan-01 00:00:00.000 */
        {0,  INT64_C(1072915200000),  1, INT64_C(1099566733456)},
        /* invalid precision */
        {-1,             INT64_C(0),  0, INT64_C(1099566733456)},
        /* invalid precision */
        {-1,             INT64_C(0), 99, INT64_C(1099566733456)},
        /* sentinel */
        {0,              INT64_C(0),  0, INT64_C(0)}
    };


    P_HEADER("skDatetimeFloor()");

    for (i = 0; input[i].in_time; ++i) {

        P_BEGIN;
        printf(("input=%" PRId64), input[i].in_time);
        P_WARNS(input[i].exp_retval);
        P_NL;

        failed = 0;
        print_results = 0;
        floor_time = 0;

        rv = (skDatetimeFloor(
                  &floor_time, &input[i].in_time, input[i].prec));

        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (floor_time != input[i].exp_floor_time) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf((GOT_STR "ret=%3d, floor_time=%15" PRId64),
                   rv, floor_time);
        }
        P_NL;

        if (failed) {
            printf((EXP_STR "ret=%3d, floor_time=%15" PRId64 "\n"),
                   input[i].exp_retval, input[i].exp_floor_time);
        }

        P_END;
    }

    return 0;
}



/* Tests for skStringParseUint32() */

static int
uint32_parser(
    void)
{
    uint32_t i;
    int rv;
    uint32_t result_val;
    int failed, print_results;

    static struct {
        uint32_t    min;
        uint32_t    max;
        int         exp_retval;
        uint32_t    exp_result;
        const char *str;
    } input[] = {
        { 0,          20, SKUTILS_OK,                     10, "  10  "},
        { 0,          20, SKUTILS_ERR_MAXIMUM,           100, "  100 "},
        { 0,          20, SKUTILS_ERR_BAD_CHAR,            0, "  -10 "},
        {30,          50, SKUTILS_OK,                     40, "   40 "},
        {30,          50, SKUTILS_ERR_MINIMUM,            10, "   10 "},
        { 0,          20, SKUTILS_OK,                      0, "   0  "},
        { 0,          20, SKUTILS_OK,                     20, "  20  "},
        { 0,          20, SKUTILS_ERR_BAD_CHAR,            0, "  x1  "},
        { 0,          20, SKUTILS_OK,                     11, " 011 "},
        { 0,          20, 2,                               2, " 2x"},
        { 0,          20, 2,                               2, " 2 x"},
        { 0,          20, 2,                               2, " 2 3"},
        { 0,          20, SKUTILS_ERR_BAD_CHAR,            0, ":2x"},
        { 0,          20, SKUTILS_ERR_EMPTY,               0, ""},
        { 0,          20, SKUTILS_ERR_EMPTY,               0, "   "},
        { 0,           0, SKUTILS_OK,                     10, "10"},
        { 0,          20, SKUTILS_ERR_MAXIMUM,   4294967295u, "4294967295"},
        { 0,          20, SKUTILS_ERR_OVERFLOW,            0, "4294967295429888"},
        { 0, 4294967295u, SKUTILS_OK,            4294967295u, "4294967295"},
        { 0,           0, SKUTILS_OK,            4294967295u, "4294967295"},
        { 0,           0, SKUTILS_ERR_INVALID,             0, NULL},
        { 0,           0, 0,                               0, SENTINEL}
    };

    P_HEADER("skStringParseUint32()");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("min=%3u, max=%10u,  str=",
               input[i].min, input[i].max);
        P_NULL(input[i].str);
        P_NL;

        result_val = 0;
        failed = 0;
        print_results = 0;

        rv = skStringParseUint32(&result_val, input[i].str,
                                 input[i].min, input[i].max);

        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (result_val != input[i].exp_result) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf(GOT_STR "ret=%3d; result=%10lu",
                   rv, (unsigned long)result_val);
        }
        P_NL;

        if (failed) {
            printf(EXP_STR "ret=%3d, result=%10lu\n",
                   input[i].exp_retval,
                   (unsigned long)input[i].exp_result);
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        P_END;
    }

    return 0;
}



/* Tests for skStringParseRange64() */

static int
range_uint64_parser(
    void)
{
    uint32_t i;
    int rv;
    uint64_t result_lo;
    uint64_t result_hi;
    int failed, print_results;

    static struct {
        int             exp_retval;
        uint64_t        min;
        uint64_t        max;
        unsigned int    flags;
        uint64_t        exp_result_lo;
        uint64_t        exp_result_hi;
        const char     *str;
    } input[] = {
        {SKUTILS_OK,            0, 0,
         SKUTILS_RANGE_ONLY_RANGE,      4,          14,
         "4-14"},
        {SKUTILS_OK,            0, UINT32_MAX,
         SKUTILS_RANGE_ONLY_RANGE,      4,          14,
         "    4-14"},
        {SKUTILS_OK,            0, 0,
         SKUTILS_RANGE_ONLY_RANGE,      4,          14,
         "4-14    "},
        {SKUTILS_OK,            4, 14,
         SKUTILS_RANGE_ONLY_RANGE,      4,          14,
         "    4-14    "},

        {SKUTILS_ERR_MINIMUM,   5, 14,
         SKUTILS_RANGE_ONLY_RANGE,      4,           0,
         "    4-14    "},
        {SKUTILS_ERR_MINIMUM,  15, 20,
         SKUTILS_RANGE_ONLY_RANGE,      4,           0,
         "    4-14    "},
        {SKUTILS_ERR_MAXIMUM,   0,  3,
         SKUTILS_RANGE_ONLY_RANGE,      4,           0,
         "    4-14    "},
        {SKUTILS_ERR_MAXIMUM,   0, 12,
         SKUTILS_RANGE_ONLY_RANGE,      4,          14,
         "    4-14    "},
        {SKUTILS_ERR_BAD_RANGE, 0,  0,
         SKUTILS_RANGE_ONLY_RANGE,     14,           4,
         "    14-4    "},
        {SKUTILS_ERR_OVERFLOW,  0,  0,
         SKUTILS_RANGE_ONLY_RANGE,      4,           0,
         "4-18446744073709551622"},

        {SKUTILS_ERR_BAD_CHAR,  0, 0,
         SKUTILS_RANGE_ONLY_RANGE,      4,           0,
         "4- 14"},
        {SKUTILS_ERR_BAD_CHAR,  0, 0,
         SKUTILS_RANGE_ONLY_RANGE,      4,          14,
         "4-14x"},
        {SKUTILS_ERR_BAD_CHAR,  0, 0,
         SKUTILS_RANGE_ONLY_RANGE,      4,           0,
         "4=14"},
        {SKUTILS_ERR_BAD_CHAR,  0, 0,
         SKUTILS_RANGE_ONLY_RANGE,      4,           0,
         "4 14"},
        {SKUTILS_ERR_BAD_CHAR,  0, 0,
         SKUTILS_RANGE_ONLY_RANGE,      4,           0,
         "4--14"},
        {SKUTILS_ERR_BAD_CHAR,  0, 0,
         SKUTILS_RANGE_ONLY_RANGE,      0,           0,
         "-4-14"},

        {SKUTILS_ERR_SHORT,     0, 0,
         SKUTILS_RANGE_ONLY_RANGE,      4,           0,
         " 4"},
        {SKUTILS_ERR_SHORT,     0, 0,
         SKUTILS_RANGE_ONLY_RANGE,      4,           0,
         " 4-"},

        {SKUTILS_OK,            2, 22,
         SKUTILS_RANGE_SINGLE_OPEN,     4,          14,
         " 4-14 "},
        {SKUTILS_OK,            2, 22,
         SKUTILS_RANGE_SINGLE_OPEN,     4,          22,
         "4-"},
        {SKUTILS_OK,            2, 22,
         SKUTILS_RANGE_SINGLE_OPEN,     4,           4,
         "4"},
        {SKUTILS_OK,            2, 22,
         SKUTILS_RANGE_SINGLE_OPEN,     4,           4,
         "4-4"},
        {SKUTILS_OK,            2, 22,
         SKUTILS_RANGE_SINGLE_OPEN | SKUTILS_RANGE_MAX_SINGLE,  4, 22,
         "4"},
        {SKUTILS_OK,            2, 22,
         SKUTILS_RANGE_SINGLE_OPEN | SKUTILS_RANGE_MAX_SINGLE,  4,  4,
         "4-4"},

        {SKUTILS_ERR_BAD_CHAR,  2, 22,
         SKUTILS_RANGE_SINGLE_OPEN,     4,           0,
         "4- 14"},

        {SKUTILS_OK,            2, 22,
         SKUTILS_RANGE_NO_SINGLE,     4,          14,
         " 4-14 "},
        {SKUTILS_OK,            0,  0,
         SKUTILS_RANGE_NO_SINGLE,     4,   UINT64_MAX,
         "4-"},
        {SKUTILS_ERR_SHORT,     2, 22,
         SKUTILS_RANGE_NO_SINGLE,     4,           0,
         "4"},
        {SKUTILS_ERR_SHORT,            2, 22,
         SKUTILS_RANGE_NO_SINGLE | SKUTILS_RANGE_MAX_SINGLE,  4, 0,
         "4"},

        {SKUTILS_OK,            2, 22,
         SKUTILS_RANGE_NO_OPEN,       4,          14,
         " 4-14 "},
        {SKUTILS_ERR_SHORT,     0,  0,
         SKUTILS_RANGE_NO_OPEN,       4,           0,
         "4-"},
        {SKUTILS_OK,            2, 22,
         SKUTILS_RANGE_NO_OPEN,       4,           4,
         "4"},
        {SKUTILS_OK,            2, 22,
         SKUTILS_RANGE_NO_OPEN | SKUTILS_RANGE_MAX_SINGLE,  4, 22,
         "4"},

        {0, 0, 0, 0, 0, 0, SENTINEL}
    };


    P_HEADER("skStringParseRange64()");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("flags=%3u,  str=",
               input[i].flags);
        P_NULL(input[i].str);
        P_NL;

        result_lo = 0;
        result_hi = 0;
        failed = 0;
        print_results = 1;

        rv = skStringParseRange64(&result_lo, &result_hi, input[i].str,
                                  input[i].min, input[i].max, input[i].flags);

        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (result_lo != input[i].exp_result_lo
                   || result_hi != input[i].exp_result_hi)
        {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf((GOT_STR "ret=%3d;"
                    " result_lo=%" PRIu64 "; result_hi=%" PRIu64),
                   rv, result_lo, result_hi);
        }
        P_NL;

        if (failed) {
            printf((EXP_STR "ret=%3d,"
                    " result_lo=%" PRIu64 "; result_hi=%" PRIu64 "\n"),
                   input[i].exp_retval,
                   input[i].exp_result_lo, input[i].exp_result_hi);
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        if (result_lo != input[i].exp_result_lo
            || result_hi != input[i].exp_result_hi)
        {
            printf("**");
        }
        P_END;
    }

    return 0;
}



/* Tests for skStringParseHumanUint64() */

static int
human_uint64_parser(
    void)
{
    uint32_t i;
    int rv;
    uint64_t result_val;
    int failed, print_results;

    static struct {
        int             exp_retval;
        uint64_t        exp_result;
        unsigned int    flags;
        const char     *str;
    } input[] = {
        {SKUTILS_OK,           256, SK_HUMAN_NORMAL,    "256" },
        {SKUTILS_OK,           256, SK_HUMAN_NORMAL,    " 256" },
        {SKUTILS_OK,           256, SK_HUMAN_NORMAL,    " 256 " },
        {SKUTILS_ERR_BAD_CHAR,   0, SK_HUMAN_NORMAL,    ":256" },
        {SKUTILS_OK,          1024, SK_HUMAN_NORMAL,    "1k " },
        {SKUTILS_OK,          1024, SK_HUMAN_NORMAL,    " 1k " },
        {3,                      1, SK_HUMAN_END_NO_WS, " 1 k " },
        {4,                      1, SK_HUMAN_NORMAL,    " 1 k " },
        {SKUTILS_OK,          1024, SK_HUMAN_MID_WS,    " 1 k "},
        {SKUTILS_OK,          1024, SK_HUMAN_MID_WS,    " 1 k "},
        {5,                   1024, (SK_HUMAN_MID_WS |SK_HUMAN_END_NO_WS),
         " 1 k "},
        {SKUTILS_OK,       1048576, SK_HUMAN_NORMAL,    "1m" },
        {SKUTILS_OK,       1048576, SK_HUMAN_NORMAL,    "1M" },
        {SKUTILS_OK,       1572864, SK_HUMAN_NORMAL,    "1.5m" },
        {SKUTILS_OK,       1000000, SK_HUMAN_LOWER_SI,  "1m" },
        {SKUTILS_OK,       1048576, SK_HUMAN_LOWER_SI,  "1M" },
        {SKUTILS_OK,       1048576, SK_HUMAN_UPPER_SI,  "1m" },
        {SKUTILS_OK,       1000000, SK_HUMAN_UPPER_SI,  "1M" },
        {3,             1073741824, SK_HUMAN_NORMAL,    "1gbit" },
        {SKUTILS_OK,     536870912, SK_HUMAN_NORMAL,    "0.5g " },
        {5,              536870912, SK_HUMAN_END_NO_WS, "0.5g " },
        {SKUTILS_ERR_OVERFLOW,   0, SK_HUMAN_NORMAL,
         "28446744073709551616"},
        {0,       4398046511104ULL, SK_HUMAN_NORMAL,    "4096g" },
        {SKUTILS_ERR_UNDERFLOW,  0, SK_HUMAN_NORMAL,    "-50k" },
        {SKUTILS_ERR_BAD_CHAR,   0, SK_HUMAN_NORMAL,    " NaN(Not a number) "},
        {SKUTILS_ERR_INVALID,    0, SK_HUMAN_NORMAL,    NULL },
        {SKUTILS_ERR_EMPTY,      0, SK_HUMAN_NORMAL,    "" },
        {SKUTILS_ERR_EMPTY,      0, SK_HUMAN_NORMAL,    "   " },
        {0,                      0, SK_HUMAN_NORMAL,    SENTINEL }
    };


    P_HEADER("skStringParseHumanUint64()");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("flags=%3u,  str=",
               input[i].flags);
        P_NULL(input[i].str);
        P_NL;

        result_val = 0;
        failed = 0;
        print_results = 0;

        rv = skStringParseHumanUint64(&result_val, input[i].str,
                                      input[i].flags);

        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (result_val != input[i].exp_result) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf(GOT_STR "ret=%3d; result=%20llu",
                   rv, (unsigned long long)result_val);
        }
        P_NL;

        if (failed) {
            printf(EXP_STR "ret=%3d, result=%20llu\n",
                   input[i].exp_retval,
                   (unsigned long long)input[i].exp_result);
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        P_END;
    }

    return 0;
}



/* Tests for skStringParseTCPFlags() */

static int
tcp_flag_parser(
    void)
{
    uint32_t i;
    int rv;
    uint8_t result_val;
    int failed, print_results;

    static struct {
        int         exp_retval;
        uint8_t     exp_result;
        const char *str;
    } input[] = {
        {0,                     1, "F"},
        {0,                     2, "S"},
        {0,                     4, "R"},
        {0,                     8, "P"},
        {0,                    16, "A"},
        {0,                    32, "U"},
        {0,                    64, "E"},
        {0,                   128, "C"},
        {0,                   128, " C"},
        {0,                   128, " C "},
        {0,                   128, "C "},
        {0,                    17, "  F  a  "},
        {0,                    17, "  a  f  "},
        {0,                    17, "  f  A  "},
        {SKUTILS_ERR_BAD_CHAR, 17, "FA/FAS"},
        {SKUTILS_ERR_BAD_CHAR,  0, "  /FAS"},
        {0,                    19, "FAFAS"},
        {0,                   251, "FSPUAEC"},
        {0,                   255, "FSrpauEC"},
        {0,                   255, "-"},
        {SKUTILS_ERR_BAD_CHAR,  0, "T"},
        {SKUTILS_ERR_BAD_CHAR,  0, ".A"},
        {SKUTILS_ERR_BAD_CHAR, 16, "A."},
        {0,                    17, "  FA  "},
        {SKUTILS_ERR_BAD_CHAR, 17, "  FAT  "},
        {0,                     0, " "},
        {0,                     0, ""},
        {SKUTILS_ERR_INVALID,   0, NULL},
        {0,                     0, SENTINEL}
    };

    P_HEADER("skStringParseTCPFlags()");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("str=");
        P_NULL(input[i].str);
        P_NL;

        result_val = 0;
        failed = 0;
        print_results = 0;

        rv = skStringParseTCPFlags(&result_val, input[i].str);
        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (result_val != input[i].exp_result) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf(GOT_STR "ret=%3d; result=%3u",
                   rv, result_val);
        }
        P_NL;

        if (failed) {
            printf(EXP_STR "ret=%3d, result=%3u\n",
                   input[i].exp_retval, input[i].exp_result);
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        P_END;
    }

    return 0;
}



/* Tests for skStringParseTCPFlagsHighMask() */

static int
flag_high_mask_parser(
    void)
{
    uint32_t i;
    int rv;
    uint8_t high, mask;
    int failed, print_results;

    static struct {
        int         exp_retval;
        uint8_t     exp_high;
        uint8_t     exp_mask;
        const char *str;
    } input[] = {
        {0,                      18,  23, "AS/ASRF" },
        {0,                      32,  32, "U   / U" },
        {SKUTILS_ERR_BAD_CHAR,    0,   0, "G   / U" },
        {SKUTILS_ERR_BAD_CHAR,   17,   0, "AFTSR" },
        {SKUTILS_ERR_BAD_CHAR,   17,  17, "AF/AFTSR" },
        {0,                      17,  17, "AF/af" },
        {0,                      17,  19, "af/ASF" },
        {SKUTILS_ERR_BAD_CHAR,   17,  19, "af/ASF/" },
        {0,                      17,  19, "  A F  / A S F  " },
        {0,                      17,  19, " AF/ASF" },
        {0,                      17,  19, " AF/ASF " },
        {0,                      17,  19, "AF/ASF " },
        {0,                       0,  17, "/AF"},
        {0,                      17, 255, " AF/- " },
        {0,                     255, 255, "A-F/-" },
        {SKUTILS_ERR_BAD_RANGE,  18, 176, "  AS / AUC" },
        {SKUTILS_ERR_BAD_RANGE, 255, 176, "-/ AUC" },
        {SKUTILS_ERR_SHORT,      18,   0, "AS" },
        {SKUTILS_ERR_SHORT,      18,   0, "AS/" },
        {SKUTILS_ERR_EMPTY,       0,   0, " " },
        {SKUTILS_ERR_EMPTY,       0,   0, "" },
        {SKUTILS_ERR_INVALID,     0,   0, NULL },
        {0,                       0,   0, SENTINEL }
    };

    P_HEADER("skStringParseTCPFlagsHighMask()");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("str=");
        P_NULL(input[i].str);
        P_NL;

        high = 0;
        mask = 0;
        failed = 0;
        print_results = 0;

        rv = skStringParseTCPFlagsHighMask(&high, &mask,
                                           input[i].str);
        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (high != input[i].exp_high) {
            failed = 1;
        } else if (mask != input[i].exp_mask) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf(GOT_STR "ret=%3d; high=%3u, mask=%3u",
                   rv, high, mask);
        }
        P_NL;

        if (failed) {
            printf(EXP_STR "ret=%3d, high=%3u, mask=%3u\n",
                   input[i].exp_retval,
                   input[i].exp_high, input[i].exp_mask);
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        P_END;
    }

    return 0;
}



/* Tests for skStringParseSignal() */

static int
signal_parser(
    void)
{
    uint32_t i;
    int rv;
    int sig_num;
    int failed, print_results;

    static struct {
        int         exp_retval;
        int         exp_signal;
        const char *str;
    } input[] = {
        {0,                       9, "KILL" },
        {0,                       9, "kill" },
        {0,                       9, "  SIGKILL  " },
        {0,                       9, "  9  " },
        {SKUTILS_ERR_BAD_CHAR,    0, "-KILL" },
        {SKUTILS_ERR_BAD_CHAR,    0, "  -KILL  " },
        {SKUTILS_ERR_BAD_CHAR,    0, "KIL" },
        {SKUTILS_ERR_BAD_CHAR,    0, "KILLKILL" },
        {SKUTILS_ERR_BAD_CHAR,    0, "KILLKILLKILLKILLKILLKILLKILLKILL," },
        {4,                       9, "KILL,25" },
        {6,                       9, "  KILL,25 " },
        {SKUTILS_ERR_EMPTY,       0, " " },
        {SKUTILS_ERR_EMPTY,       0, "" },
        {SKUTILS_ERR_INVALID,     0, NULL },
        {0,                       0, SENTINEL }
    };

    P_HEADER("skStringParseSignal()");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("str=");
        P_NULL(input[i].str);
        P_NL;

        sig_num = 0;
        failed = 0;
        print_results = 0;

        rv = skStringParseSignal(&sig_num, input[i].str);
        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (sig_num != input[i].exp_signal) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf(GOT_STR "ret=%3d; signal=%3u",
                   rv, sig_num);
        }
        P_NL;

        if (failed) {
            printf(EXP_STR "ret=%3d, signal=%3u\n",
                   input[i].exp_retval,
                   input[i].exp_signal);
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        P_END;
    }

    return 0;
}



/* Tests for skStringParseIP() */

static int
ip_parser(
    void)
{
    skipaddr_t ipaddr;
    uint32_t i;
    int rv;
    uint32_t ip;
    int failed, print_results;

    static struct {
        int         exp_retval;
        uint32_t    exp_ip;
        const char *str;
    } input[] = {
        {0,                      0, "0.0.0.0"},
        {0,            4294967295u, "255.255.255.255"},
        {0,              167772160, "10.0.0.0"},
        {0,              168430090, "10.10.10.10"},
        {0,              168496141, "10.11.12.13"},
        {0,              167772160, " 10.0.0.0"},
        {0,              167772160, "10.0.0.0 "},
        {0,              167772160, "  10.0.0.0  "},
        {0,              167772160, "010.000.000.000"},
        {15,             167772160, "010.000.000.000x"},
        {15,             167772160, "010.000.000.000a"},
        {15,             167772160, "010.000.000.000|"},
        {15,             167772160, "       10.0.0.0:80"},
        {8,              167772160, "10.0.0.0       ."},
        {0,              167772160, "167772160"},
        {0,              167772160, " 167772160"},
        {0,              167772160, "167772160 "},
        {0,              167772160, "  167772160  "},
        {9,              167772160, "167772160      ."},
        {15,             167772160, "      167772160|"},
        {SKUTILS_ERR_BAD_CHAR,   0, "    10.10.10.10.10  "},
        {SKUTILS_ERR_INVALID,    0, NULL},
        {SKUTILS_ERR_EMPTY,      0, ""},
        {SKUTILS_ERR_EMPTY,      0, "  "},
        {SKUTILS_ERR_BAD_CHAR,   0, "     -167772160"},
        {SKUTILS_ERR_BAD_CHAR,   0, "     -167772160|"},
        {SKUTILS_ERR_MAXIMUM,    0, "      167772160."},
        {SKUTILS_ERR_MAXIMUM,    0, " 256.256.256.256"},
        {SKUTILS_ERR_SHORT,      0, "  10.10."},
        {SKUTILS_ERR_SHORT,      0, "  10.10.10"},
        {SKUTILS_ERR_BAD_CHAR,   0, "  10.x.x.x  "},
        {SKUTILS_ERR_BAD_CHAR,   0, "  .10.10.10.10  "},
        {SKUTILS_ERR_BAD_CHAR,   0, "  10..10.10.10  "},
        {SKUTILS_ERR_BAD_CHAR,   0, "  10.10..10.10  "},
        {SKUTILS_ERR_BAD_CHAR,   0, "  10.10.10..10  "},
        {SKUTILS_ERR_BAD_CHAR,   0, "  10.10.10.10.  "},
        {SKUTILS_ERR_BAD_CHAR,   0, "  10.10:10.10   "},
        {SKUTILS_ERR_OVERFLOW,   0, "10.0.0.98752938745983475983475039248759"},
        {SKUTILS_ERR_BAD_CHAR,   0, "10.0|0.0"},
        {SKUTILS_ERR_BAD_CHAR,   0, " 10.  0.  0.  0"},
        {2,                     10, "10 .   0.  0.  0"},
        {0,                      0, SENTINEL}
    };

    P_HEADER("skStringParseIP() [IPv4]");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("str=");
        P_NULL(input[i].str);
        P_NL;

        skipaddrClear(&ipaddr);
        print_results = 0;
        failed = 0;

        rv = skStringParseIP(&ipaddr, input[i].str);
        ip = skipaddrGetV4(&ipaddr);
        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (ip != input[i].exp_ip) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf(GOT_STR "ret=%3d; ip=%10lu",
                   rv, (unsigned long)ip);
        }
        P_NL;

        if (failed) {
            printf(EXP_STR "ret=%3d, ip=%10lu\n",
                   input[i].exp_retval,
                   (unsigned long)input[i].exp_ip);
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        P_END;
    }

    return 0;
}


#if SK_ENABLE_IPV6

/* Tests for skStringParseIP() */

#define ZERO_IPV6 {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

static const char *
v6tostring(
    uint8_t            *ip)
{
    static char buf[50];
    char *cp;
    int i;

    cp = buf;
    for (i = 0; i < 16; ++i) {
        if (!(i & 0x01) && i > 0) { *cp = ':'; ++cp; }
        cp += snprintf(cp, (sizeof(buf) - (cp - buf)), "%02x", ip[i]);
        if ((size_t)(cp - buf) > sizeof(buf)) {
            skAbort();
        }
    }

    return buf;
}


static int
ipv6_parser(
    void)
{
    skipaddr_t ipaddr;
    uint32_t i;
    int rv;
    uint8_t ipv6[16];
    int failed, print_results;

    static struct {
        int         exp_retval;
        uint8_t     exp_ip[16];
        const char *str;
    } input[] = {
        {0, ZERO_IPV6, "0:0:0:0:0:0:0:0"},
        {0, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
         "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
        {0, {0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
         "10:0:0:0:0:0:0:0"},
        {0, {0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10,
             0x00, 0x10, 0x00, 0x10, 0x00, 0x10, 0x00, 0x10},
         "10:10:10:10:10:10:10:10"},
        {0, {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
             0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10},
         "1010:1010:1010:1010:1010:1010:1010:1010"},
        {0, {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
             0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27},
         "1011:1213:1415:1617:2021:2223:2425:2627"},
        {0, {0xf0, 0xff, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
             0x20, 0x2f, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27},
         "f0ff:f2f3:f4f5:f6f7:202f:2223:2425:2627"},
        {0, {0xf0, 0xff, 0xfa, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
             0xa0, 0xaf, 0xaa, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
         "f0ff:faf3:f4f5:f6f7:a0af:aaa3:a4a5:a6a7"},
        {0, {0xf0, 0xff, 0xfa, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
             0xa0, 0xaf, 0xaa, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
         "     f0ff:faf3:f4f5:f6f7:a0af:aaa3:a4a5:a6a7"},
        {0, {0xf0, 0xff, 0xfa, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
             0xa0, 0xaf, 0xaa, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
         "f0ff:faf3:f4f5:f6f7:a0af:aaa3:a4a5:a6a7    "},
        {0, {0xf0, 0xff, 0xfa, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
             0xa0, 0xaf, 0xaa, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
         "   f0ff:faf3:f4f5:f6f7:a0af:aaa3:a4a5:a6a7  "},
        {39, {0xf0, 0xff, 0xfa, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
              0xa0, 0xaf, 0xaa, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
         "f0ff:faf3:f4f5:f6f7:a0af:aaa3:a4a5:a6a7x  "},
        {39, {0xf0, 0xff, 0xfa, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
              0xa0, 0xaf, 0xaa, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
         "f0ff:faf3:f4f5:f6f7:a0af:aaa3:a4a5:a6a7  x"},
        {39, {0xf0, 0xff, 0xfa, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
              0xa0, 0xaf, 0xaa, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
         "f0ff:faf3:f4f5:f6f7:a0af:aaa3:a4a5:a6a7|  "},
        {39, {0xf0, 0xff, 0xfa, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
              0xa0, 0xaf, 0xaa, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
         "f0ff:faf3:f4f5:f6f7:a0af:aaa3:a4a5:a6a7JUNK"},
        {39, {0xf0, 0xff, 0xfa, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
              0xa0, 0xaf, 0xaa, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
         "f0ff:faf3:f4f5:f6f7:a0af:aaa3:a4a5:a6a7 stuff"},

#if 0
        {0,              167772160, " 10:0:0:0"},
        {0,              167772160, "10:0:0:0 "},
        {0,              167772160, "  10:0:0:0  "},
        {0,              167772160, "010:000:000:000"},
        {15,             167772160, "010:000:000:000:"},
        {8,              167772160, "10:0:0:0       :"},
        {0,              167772160, "167772160"},
        {0,              167772160, " 167772160"},
        {0,              167772160, "167772160 "},
        {0,              167772160, "  167772160  "},
        {9,             167772160, "167772160      :"},
        {15,             167772160, "      167772160|"},
#endif

        {0, ZERO_IPV6, "::"},
        {0, ZERO_IPV6, "0::0"},
        {0, ZERO_IPV6, "0:0::0"},
        {0, ZERO_IPV6, "0:0:0::0"},
        {0, ZERO_IPV6, "0:0:0:0::0"},
        {0, ZERO_IPV6, "0:0:0:0:0::0"},
        {0, ZERO_IPV6, "0:0:0:0:0:0::0"},
        {0, ZERO_IPV6, "0:0:0:0:0::0:0"},
        {0, ZERO_IPV6, "0:0:0:0::0:0:0"},
        {0, ZERO_IPV6, "0:0:0::0:0:0:0"},
        {0, ZERO_IPV6, "0:0::0:0:0:0:0"},
        {0, ZERO_IPV6, "0::0:0:0:0:0:0"},
        {0, ZERO_IPV6, "0::0:0:0:0:0"},
        {0, ZERO_IPV6, "0::0:0:0:0"},
        {0, ZERO_IPV6, "0::0:0:0"},
        {0, ZERO_IPV6, "0::0:0"},
        {0, ZERO_IPV6, "::0"},
        {0, ZERO_IPV6, "::0:0"},
        {0, ZERO_IPV6, "::0:0:0"},
        {0, ZERO_IPV6, "::0:0:0:0"},
        {0, ZERO_IPV6, "::0:0:0:0:0"},
        {0, ZERO_IPV6, "::0:0:0:0:0:0"},
        {0, ZERO_IPV6, "0:0:0:0:0:0:0::"},
        {0, ZERO_IPV6, "0:0:0:0:0:0::0"},
        {0, ZERO_IPV6, "0:0:0:0:0::"},
        {0, ZERO_IPV6, "0:0:0:0::"},
        {0, ZERO_IPV6, "0:0:0::"},
        {0, ZERO_IPV6, "0:0::"},
        {0, ZERO_IPV6, "0::"},

        {0, ZERO_IPV6, "0:0:0:0:0:0:0.0.0.0"},
        {0, ZERO_IPV6, "0:0:0:0:0::0.0.0.0"},
        {0, ZERO_IPV6, "0:0:0:0::0.0.0.0"},
        {0, ZERO_IPV6, "0:0:0::0.0.0.0"},
        {0, ZERO_IPV6, "0:0::0.0.0.0"},
        {0, ZERO_IPV6, "0::0.0.0.0"},
        {0, ZERO_IPV6, "::0.0.0.0"},
        {0, ZERO_IPV6, "::0:0.0.0.0"},
        {0, ZERO_IPV6, "::0:0:0.0.0.0"},
        {0, ZERO_IPV6, "::0:0:0:0.0.0.0"},
        {0, ZERO_IPV6, "::0:0:0:0:0.0.0.0"},
        {0, ZERO_IPV6, "::0:0:0:0:0:0.0.0.0"},
        {0, ZERO_IPV6, "0::0:0:0:0:0.0.0.0"},
        {0, ZERO_IPV6, "0:0::0:0:0:0.0.0.0"},
        {0, ZERO_IPV6, "0:0:0::0:0:0.0.0.0"},
        {0, ZERO_IPV6, "0:0:0:0::0:0.0.0.0"},
        {0, ZERO_IPV6, "0:0:0:0:0::0.0.0.0"},
        {0, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
         "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"},
        {0, {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
             0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10},
         "1010:1010:1010:1010:1010:1010:16.16.16.16"},
        {0, {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
             0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27},
         "1011:1213:1415:1617:2021:2223:36.37.38.39"},

        {SKUTILS_ERR_INVALID,    ZERO_IPV6, NULL},
        {SKUTILS_ERR_EMPTY,      ZERO_IPV6, ""},
        {SKUTILS_ERR_EMPTY,      ZERO_IPV6, "  "},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, " -10:0:0:0:0:0:0:0"},
        {SKUTILS_ERR_MAXIMUM,    ZERO_IPV6, " 10000:0:0:0:0:0:0:0"},
        {SKUTILS_ERR_MAXIMUM,    ZERO_IPV6, " 0:0:0:0:0:0:0:10000"},
        {SKUTILS_ERR_SHORT,      ZERO_IPV6, "  10:10:"},
        {SKUTILS_ERR_SHORT,      ZERO_IPV6, "  10:10:10"},
        {SKUTILS_ERR_SHORT,      ZERO_IPV6, "0:0:0:0:0:0:0"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "  10:10.10:10::"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "  :10:10:10:10::"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "  ::10:10:10:10:STUFF"},
        {SKUTILS_ERR_SHORT,      ZERO_IPV6, "  ::10:10:10:10:"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "  10:10:10:::10"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "  10::10:10::10"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "  10:10::10::10"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "  10::10::10:10"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "  10:x:x:x:x:x:x:x  "},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6,
         "f0ff:faf3:f4f5:f6f7:a0af:aaa3:a4a5:a6a7:ffff"},
        {SKUTILS_ERR_OVERFLOW,   ZERO_IPV6,
         "11:12:13:14:15:16:17:98752938745983475983475039248759"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "10:0|0:0:0:0:0:0"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, " 10:  0:  0:  0: 10: 10: 10: 10"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "10 :10:10:10:10:10:10:10"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, ":10:10:10:10:10:10:10:10"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "0:0:0:0:0:0:0:0:0.0.0.0"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "0:0:0:0:0:0:0:0.0.0.0"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "::0.0.0.0:0"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "0::0.0.0.0:0"},
        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "0::0.0.0.0.0"},

        {SKUTILS_ERR_BAD_CHAR,   ZERO_IPV6, "2001:db8 10 10 10 10 10 10"},
        {12, {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
         "2001:db8::10 10"},

        {0, ZERO_IPV6, SENTINEL}
    };

    P_HEADER("skStringParseIP() [IPv6]");

    for (i = 0; !IS_SENTINEL(input[i].str); ++i) {

        P_BEGIN;
        printf("str=");
        P_NULL(input[i].str);
        P_NL;

        skipaddrClear(&ipaddr);
        memset(ipv6, 0, sizeof(ipv6));
        print_results = 0;
        failed = 0;

        rv = skStringParseIP(&ipaddr, input[i].str);
        skipaddrGetV6(&ipaddr, ipv6);
        if (rv != input[i].exp_retval) {
            failed = 1;
        } else if (rv < 0) {
            print_results = 1;
        } else if (memcmp(ipv6, input[i].exp_ip, sizeof(ipv6))) {
            failed = 1;
        }

        P_STATUS(failed);

        if (failed || print_results) {
            printf(GOT_STR "ret=%3d; ip=%s",
                   rv, v6tostring(ipv6));
        }
        P_NL;

        if (failed) {
            printf(EXP_STR "ret=%3d, ip=%s\n",
                   input[i].exp_retval,
                   v6tostring(input[i].exp_ip));
        }

        if ( failed || print_results) {
            P_ERR(rv);
        }

        P_END;
    }

    return 0;
}

#endif /* SK_ENABLE_IPV6 */


/* helper for host_port_parser() */
static void
host_port_print_flags(
    uint8_t             flags)
{
    int count = 0;

    printf(" flags=(");
    if (flags & PORT_REQUIRED) {
        printf("%sPORT_REQUIRED", ((count > 0) ? "|" : ""));
        ++count;
    }
    if (flags & PORT_PROHIBITED) {
        printf("%sPORT_PROHIBITED", ((count > 0) ? "|" : ""));
        ++count;
    }
    if (flags & HOST_REQUIRED) {
        printf("%sHOST_REQUIRED", ((count > 0) ? "|" : ""));
        ++count;
    }
    if (flags & HOST_PROHIBITED) {
        printf("%sHOST_PROHIBITED", ((count > 0) ? "|" : ""));
        ++count;
    }
    if (flags & IPV6_REQUIRED) {
        printf("%sIPV6_REQUIRED", ((count > 0) ? "|" : ""));
        ++count;
    }
    if (flags & IPV6_PROHIBITED) {
        printf("%sIPV6_PROHIBITED", ((count > 0) ? "|" : ""));
        ++count;
    }
    printf(")");
}



/* Tests for skStringParseHostPortPair() */

static int
host_port_parser(
    void)
{
    uint32_t i;
    int rv;
    int always_print_strerror = 0;
    char *parse_tests_strerror_env = NULL;

    static struct {
        const char *str;
        const char *addr;
        uint16_t port;
    } good_inputs[] = {
        {"12345",           NULL,        12345},
        {"localhost",       "localhost", 0},
        {"127.0.0.1",       "127.0.0.1", 0},
        {"localhost:12345", "localhost", 12345},
        {"127.0.0.1:12345", "127.0.0.1", 12345},
        {"[::1]",           "::1",       0},
        {"[::1]:12345",     "::1",       12345},
        {SENTINEL, NULL, 0}
    };

    static struct {
        const char *str;
        uint8_t flags;
        int err;
    } bad_inputs[] = {
        {"1923.12.35.4",     0, SKUTILS_ERR_RESOLVE},
        {"localhost:a",      0, SKUTILS_ERR_BAD_CHAR},
        {"localhost: 12345", 0, SKUTILS_ERR_BAD_CHAR},
        {"localhost:123456", 0, SKUTILS_ERR_MAXIMUM},
        {"localhost::",      0, SKUTILS_ERR_RESOLVE},
        {"[::1]:",           0, SKUTILS_ERR_SHORT},
        {"aa[::1]",          0, SKUTILS_ERR_RESOLVE},
        {"[::1",             0, SKUTILS_ERR_BAD_CHAR},
        {SENTINEL, 0, 0}
    };

    /* if "PARSE_TESTS_STRERROR" is set in the environment, always
     * print errors messages.  Normally, error messages are not
     * printed in this test since the message may contain text
     * generaed by gai_strerror(), which may differ between
     * platforms. */
    parse_tests_strerror_env = getenv("PARSE_TESTS_STRERROR");
    if (parse_tests_strerror_env) {
        switch (parse_tests_strerror_env[0]) {
          case '\0':
          case '0':
          case 'F':
          case 'f':
            break;
          default:
            always_print_strerror = 1;
            break;
        }
    }

    P_HEADER("skStringParseHostPortPair()");

    for (i = 0; !IS_SENTINEL(good_inputs[i].str); i++) {
        uint8_t flags;

        for (flags = 0; flags < (1 << 6); flags++) {
            sk_sockaddr_array_t *addrs;
            int failed = 0;
            uint32_t j;
            int rv_exp = 0;

            P_BEGIN;

            printf("str=");
            P_NULL(good_inputs[i].str);
            host_port_print_flags(flags);
            P_NL;

            rv = skStringParseHostPortPair(&addrs, good_inputs[i].str, flags);

            /* Check prohibited flag combinations */
            if (((flags & (PORT_REQUIRED | PORT_PROHIBITED)) ==
                 (PORT_REQUIRED | PORT_PROHIBITED))
                || ((flags & (HOST_REQUIRED | HOST_PROHIBITED)) ==
                    (HOST_REQUIRED | HOST_PROHIBITED))
                || ((flags & (IPV6_REQUIRED | IPV6_PROHIBITED)) ==
                    (IPV6_REQUIRED | IPV6_PROHIBITED))
                || (!SK_ENABLE_INET6_NETWORKING && (flags & IPV6_REQUIRED))
                || ((flags & (HOST_PROHIBITED | PORT_PROHIBITED)) ==
                    (HOST_PROHIBITED | PORT_PROHIBITED)))
            {
                rv_exp = SKUTILS_ERR_INVALID;
                if (rv != rv_exp) {
                    failed = 1;
                }
                goto next;
            }

            if (((flags & PORT_REQUIRED) && !good_inputs[i].port)
                || ((flags & PORT_PROHIBITED) && good_inputs[i].port)
                || ((flags & HOST_REQUIRED) && !good_inputs[i].addr)
                || ((flags & HOST_PROHIBITED) && good_inputs[i].addr))
            {
                rv_exp = SKUTILS_ERR_OTHER;
                if (rv != rv_exp) {
                    failed = 1;
                }
                goto next;
            }

            /* to check the result of skStringParseHostPortPair(), we
             * must see what results we get for the hostname or
             * address, since not all hosts support IPv6, and not all
             * hosts return an IPv6 address for "localhost". */
            {
                uint32_t num_addrs = 0;
#if USE_GETADDRINFO
                struct addrinfo *addrinfo;
                struct addrinfo hints;
                struct addrinfo *current;
                char port_buf[7];
                char *port_str;
                int err;

                memset(&hints, 0, sizeof(hints));
                if (!SK_ENABLE_INET6_NETWORKING || (flags & IPV6_PROHIBITED)) {
                    hints.ai_family = AF_INET;
                } else if (flags & IPV6_REQUIRED) {
                    hints.ai_family = AF_INET6;
                } else {
                    hints.ai_family = AF_UNSPEC;
                }
                if (good_inputs[i].addr == NULL) {
                    hints.ai_flags = AI_PASSIVE;
                }
                if (good_inputs[i].port == 0) {
                    port_str = NULL;
                } else {
                    snprintf(port_buf, sizeof(port_buf), "%" PRIu32,
                             good_inputs[i].port);
                    port_str = port_buf;
                }
                hints.ai_socktype = SOCK_STREAM;
                err = getaddrinfo(good_inputs[i].addr, port_str,
                                  &hints, &addrinfo);
                if (err != 0) {
                    rv_exp = SKUTILS_ERR_RESOLVE;
                    if (rv != rv_exp) {
                        failed = 1;
                    }
                    goto next;
                }

                current = addrinfo;
                while (current) {
                    switch (current->ai_addr->sa_family) {
#if SK_ENABLE_INET6_NETWORKING
                      case AF_INET6:
                        if (!(flags & IPV6_PROHIBITED)) {
                            num_addrs++;
                        }
                        break;
#endif  /* SK_ENABLE_INET6_NETWORKING */
                      case AF_INET:
                        if (!(flags & IPV6_REQUIRED)) {
                            num_addrs++;
                        }
                        break;
                      default:
                        current = current->ai_next;
                        continue;
                    }
                    current = current->ai_next;
                }
                freeaddrinfo(addrinfo);

#else /* #if !USE_GETADDRINFO */
                struct hostent *he;
                char **current;

                if (NULL == good_inputs[i].addr) {
                    /* there should only be a port */
                    num_addrs = 1;
                } else {
                    he = gethostbyname(good_inputs[i].addr);
                    if (he == NULL || (he->h_addrtype != AF_INET)) {
                        rv_exp = SKUTILS_ERR_RESOLVE;
                        if (rv != rv_exp) {
                            failed = 1;
                            goto next;
                        }
                    }
                    if (he) {
                        current = he->h_addr_list;
                        while (*current) {
                            if (!(flags & IPV6_REQUIRED)) {
                                num_addrs++;
                            }
                            current++;
                        }
                    }
                }
#endif  /* USE_GETADDRINFO */

                if (rv == SKUTILS_OK
                    && (num_addrs == 0
                        || num_addrs != skSockaddrArrayGetSize(addrs)))
                {
                    failed = 1;
                } else if (rv < 0 && num_addrs > 0) {
                    failed = 1;
                }
                if (failed) {
                    goto next;
                }
            }

            if (rv < 0) {
#if !SK_ENABLE_INET6_NETWORKING
                if (0 == rv_exp && 0 == strcmp("::1", good_inputs[i].addr)) {
                    rv_exp = SKUTILS_ERR_RESOLVE;
                }
#endif  /* SK_ENABLE_INET6_NETWORKING */
                if (!failed && rv != rv_exp) {
                    failed = 1;
                }
                goto next;
            }

            for (j = 0; j < skSockaddrArrayGetSize(addrs); j++) {
                uint16_t port;
                sk_sockaddr_t *addr = skSockaddrArrayGet(addrs, j);
                switch (addr->sa.sa_family) {
                  case AF_INET:
                    port = addr->v4.sin_port;
                    if (flags & IPV6_REQUIRED) {
                        failed = 1;
                        goto next;
                    }
                    break;
                  case AF_INET6:
#if !SK_ENABLE_INET6_NETWORKING
                    failed = 1;
                    rv_exp = SKUTILS_ERR_OTHER;
                    goto next;
#else  /* SK_ENABLE_INET6_NETWORKING */
                    port = addr->v6.sin6_port;
                    if (flags & IPV6_PROHIBITED) {
                        failed = 1;
                    }
#endif  /* SK_ENABLE_INET6_NETWORKING */
                    break;
                  default:
                    failed = 1;
                    goto next;
                }

                port = ntohs(port);
                if (port && (flags & PORT_PROHIBITED)) {
                    failed = 1;
                }
                if (!port && (flags & PORT_REQUIRED)) {
                    failed = 1;
                }
                if (port != good_inputs[i].port) {
                    failed = 1;
                }
            }

          next:
            if (rv == SKUTILS_OK) {
                skSockaddrArrayDestroy(addrs);
            }
            P_STATUS(failed);
            /* normally, when the result of parsing returns the expected
             * error code, we want to print the error code and message.
             * However, do not do that when the message contains text from
             * gai_strerror() unless always_print_strerror is true. */
            if (!failed
                && ((rv == SKUTILS_OK)
                    || (rv == SKUTILS_ERR_RESOLVE && !always_print_strerror)))
            {
                P_NL;
            } else {
                printf(EXP_STR "%3d;" GOT_STR "%3d", rv_exp, rv);
                P_NL;
                P_ERR(rv);
            }
            P_END;
        }
    }

    for (i = 0; !IS_SENTINEL(bad_inputs[i].str); i++) {
        sk_sockaddr_array_t *addrs;
        uint8_t flags = bad_inputs[i].flags;
        int failed = 0;

        P_BEGIN;

        printf("str=");
        P_NULL(bad_inputs[i].str);
        host_port_print_flags(flags);
        P_NL;

        rv = skStringParseHostPortPair(&addrs, bad_inputs[i].str, flags);
        if (rv != bad_inputs[i].err) {
            failed = 1;
        }
        if (rv > 0) {
            skSockaddrArrayDestroy(addrs);
        }
        P_STATUS(failed);

        /* normally, when the result of parsing returns the expected
         * error code, we want to print the error code and message.
         * However, do not do that when the message contains text from
         * gai_strerror() unless always_print_strerror is true. */
        if (!failed
            && ((rv == SKUTILS_OK)
                || (rv == SKUTILS_ERR_RESOLVE && !always_print_strerror)))
        {
            P_NL;
        } else {
            printf(EXP_STR "%3d;" GOT_STR "%3d", bad_inputs[i].err, rv);
            P_NL;
            P_ERR(rv);
        }
        P_END;
    }

    return 0;
}



/* **********  END OF TESTS  ********** */

/*
 *  appUsageLong();
 *
 *    Print complete usage information to USAGE_FH.
 */
static void
appUsageLong(
    void)
{
#define USAGE_MSG                                                       \
    ("[SWITCHES]\n"                                                     \
     "\tRun tests to check string parsing\n")

    skAppStandardUsage(stdout, USAGE_MSG, appOptions, appHelp);
}


/*
 *  status = appOptionsHandler(cData, opt_index, opt_arg);
 *
 *    Run tests for value of switch specified.
 */
static int
appOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
    int i;

    switch (opt_index) {
      case OPT_NUMBERS:
        uint32_parser();
        range_uint64_parser();
        human_uint64_parser();
        break;

      case OPT_LISTS:
        number_list_parser();
        number_list_to_bitmap_parser();
        break;

      case OPT_DATES:
        datetime_parser();
        datetime_ceiling_parser();
        datetime_floor_parser();
        datetime_range_parser();
        break;

      case OPT_TCP_FLAGS:
        tcp_flag_parser();
        flag_high_mask_parser();
        break;

      case OPT_SIGNALS:
        signal_parser();
        break;

      case OPT_IP_ADDRESSES:
        ip_parser();
#if SK_ENABLE_IPV6
        ipv6_parser();
#endif
        break;

      case OPT_HOST_PORT_PAIRS:
        host_port_parser();
        break;

      case OPT_ALL_TESTS:
        for (i = 0; i < opt_index; ++i) {
            appOptionsHandler(cData, i, opt_arg);
        }
        break;
    }

    return 0;                     /* OK */
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
    if (skOptionsRegister(appOptions, &appOptionsHandler, NULL)) {
        skAppPrintErr("Unable to register options");
        exit(EXIT_FAILURE);
    }

    /* parse options */
    arg_index = skOptionsParse(argc, argv);
    if (arg_index < 0) {
        skAppUsage();           /* never returns */
    }

    /* check for extraneous arguments */
    if (arg_index != argc) {
        skAppPrintErr("Too many arguments or unrecognized switch '%s'",
                      argv[arg_index]);
        skAppUsage();           /* never returns */
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
