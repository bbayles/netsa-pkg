/*
** Copyright (C) 2010-2023 by Carnegie Mellon University.
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
**  Extra simplified registration functions for skplugin
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skplugin-simple.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skdllist.h>
#include <silk/skipaddr.h>
#include <silk/skplugin.h>
#include <silk/utils.h>


/* LOCAL DEFINES AND TYPEDEFS */

typedef struct int_field_info_st {
    skplugin_int_field_fn_t fn;
    uint64_t                min;
    uint8_t                 bytes;
} int_field_info_t;

typedef struct ipv4_field_info_st {
    skplugin_ipv4_field_fn_t fn;
} ipv4_field_info_t;

typedef struct ip_field_info_st {
    skplugin_ip_field_fn_t fn;
} ip_field_info_t;

typedef struct text_field_info_st {
    /* 'int_info' must be first, since this struct may be cast as an
     * int_field_info_t */
    int_field_info_t            int_info;
    skplugin_text_field_fn_t    text_fn;
} text_field_info_t;

typedef struct list_field_info_st {
    /* 'int_info' must be first, since this struct may be cast as an
     * int_field_info_t */
    int_field_info_t            int_info;
    size_t                      entries;
    const char                **list;
    const char                 *default_value;
} list_field_info_t;

typedef struct int_field_aggregator_st {
    /* 'int_info' must be first, since this struct may be cast as an
     * int_field_info_t */
    int_field_info_t            int_info;
    skplugin_int_agg_fn_t       agg;
} int_field_aggregator_t;


/* LOCAL VARIABLES */

static const char *no_description = "No help for this switch";

/* A place to store dynamic allocations that should be freed during
 * plugin cleanup */
static sk_dllist_t *free_list = NULL;


/* FUNCTION DEFINITIONS */

/* Plugin cleanup function */
static void
cleanup_free_list(
    void)
{
    if (free_list) {
        skDLListDestroy(free_list);
        free_list = NULL;
    }
}

/* Adds a pointer to be freed during cleanup to the free list. */
static void
add_to_free_list(
    void               *data)
{
    if (free_list == NULL) {
        free_list = skDLListCreate(free);
        if (free_list == NULL) {
            return;
        }
        skpinRegCleanup(cleanup_free_list);
    }
    skDLListPushTail(free_list, data);
}

/* Does the conversion of uint64_t to binary value */
static void
bin_from_int(
    int_field_info_t   *info,
    uint8_t            *dest,
    uint64_t            val)
{
    uint8_t *vp = (uint8_t *)&val;

    assert(info != NULL);
    val = hton64(val - info->min);
    memcpy(dest, vp + (sizeof(val) - info->bytes), info->bytes);
}


/* Does the conversion of binary to uint64_t */
static uint64_t
int_from_bin(
    const uint8_t      *bin,
    int_field_info_t   *info)
{
    uint64_t val = 0;
    uint8_t *vp = (uint8_t *)&val;
    assert(info != NULL);
    memcpy(vp + (sizeof(val) - info->bytes), bin, info->bytes);
    val = ntoh64(val) + info->min;
    return val;
}


/* rec_to_text for integers */
static skplugin_err_t
int_to_text(
    const rwRec            *rec,
    char                   *dest,
    size_t                  width,
    void                   *cbdata,
    void           UNUSED(**extra))
{
    int_field_info_t *info = (int_field_info_t *)cbdata;

    assert(info != NULL);
    assert(extra == NULL);

    snprintf(dest, width, "%" PRIu64, info->fn(rec));

    return SKPLUGIN_OK;
}


/* rec_to_bin for integers */
static skplugin_err_t
int_to_bin(
    const rwRec            *rec,
    uint8_t                *dest,
    void                   *cbdata,
    void           UNUSED(**extra))
{
    int_field_info_t *info = (int_field_info_t *)cbdata;

    assert(info != NULL);
    assert(extra == NULL);

    bin_from_int(info, dest, info->fn(rec));

    return SKPLUGIN_OK;
}


/* bin_to_text for integers */
static skplugin_err_t
int_bin_to_text(
    const uint8_t      *bin,
    char               *dest,
    size_t              width,
    void               *cbdata)
{

    int_field_info_t *info = (int_field_info_t *)cbdata;

    assert(info != NULL);
    snprintf(dest, width, "%" PRIu64, int_from_bin(bin, info));

    return SKPLUGIN_OK;
}


/* Initialize an int_field_info_t structure */
static size_t
setup_int_info(
    int_field_info_t           *info,
    uint64_t                    min,
    uint64_t                    max,
    skplugin_int_field_fn_t     fn)
{
    uint64_t size;
    uint64_t size_max;
    size_t   width;

    assert(min < max);

    info->min = min;
    size = max - min;

    /* Determine number of bytes required to hold integer */
    info->bytes = 1;
    size_max = 0xff;
    while (size > size_max) {
        info->bytes++;
        size_max = (size_max << 8) | 0xff;
    }

    /* Determine number of bytes needed to display 'max' in decimal form */
    width = 1;
    while ((max /= 10)) {
        width++;
    }

    info->fn = fn;

    return width;
}


/* Register an integer field */
skplugin_err_t
skpinRegIntField(
    const char                 *name,
    uint64_t                    min,
    uint64_t                    max,
    skplugin_int_field_fn_t     fn,
    size_t                      width)
{
    int_field_info_t *info;
    skplugin_callbacks_t callbacks;
    size_t w;

    if (max == 0) {
        max = UINT64_MAX;
    }

    if (min > max) {
        return SKPLUGIN_ERR;
    }

    info = (int_field_info_t*)malloc(sizeof(*info));
    if (info == NULL) {
        return SKPLUGIN_ERR;
    }
    add_to_free_list(info);

    memset(&callbacks, 0, sizeof(callbacks));

    w = setup_int_info(info, min, max, fn);

    callbacks.column_width = width ? width : w;
    callbacks.bin_bytes    = info->bytes;
    callbacks.rec_to_text  = int_to_text;
    callbacks.rec_to_bin   = int_to_bin;
    callbacks.bin_to_text  = int_bin_to_text;

    return skpinRegField(NULL, name, no_description, &callbacks, info);
}


/* rec_to_text for ipv4 */
static skplugin_err_t
ipv4_to_text(
    const rwRec            *rec,
    char                   *dest,
    size_t                  width,
    void                   *cbdata,
    void           UNUSED(**extra))
{
    char addr[SKIPADDR_STRLEN];
    ipv4_field_info_t *info = (ipv4_field_info_t *)cbdata;
    skipaddr_t ipaddr;
    uint32_t ipv4;

    assert(info != NULL);
    assert(extra == NULL);

    ipv4 = info->fn(rec);
    skipaddrSetV4(&ipaddr, &ipv4);
    if (width >= sizeof(addr)) {
        skipaddrString(dest, &ipaddr, SKIPADDR_CANONICAL);
    } else {
        skipaddrString(addr, &ipaddr, SKIPADDR_CANONICAL);
        strncpy(dest, addr, width);
        dest[width - 1] = '\0';
    }

    return SKPLUGIN_OK;
}


/* rec_to_bin for ipv4 */
static skplugin_err_t
ipv4_to_bin(
    const rwRec            *rec,
    uint8_t                *dest,
    void                   *cbdata,
    void           UNUSED(**extra))
{
    uint32_t val;
    ipv4_field_info_t *info = (ipv4_field_info_t *)cbdata;

    assert(info != NULL);
    assert(extra == NULL);

    val = htonl(info->fn(rec));
    memcpy(dest, &val, sizeof(val));

    return SKPLUGIN_OK;
}


/* bin_to_text for ipv4 */
static skplugin_err_t
ipv4_bin_to_text(
    const uint8_t          *bin,
    char                   *dest,
    size_t                  width,
    void            UNUSED(*cbdata))
{
    char addr[SKIPADDR_STRLEN];
    skipaddr_t ipaddr;
    uint32_t val;

    assert(cbdata != NULL);
    memcpy(&val, bin, sizeof(val));
    val = ntohl(val);
    skipaddrSetV4(&ipaddr, &val);
    if (width >= sizeof(addr)) {
        skipaddrString(dest, &ipaddr, SKIPADDR_CANONICAL);
    } else {
        skipaddrString(addr, &ipaddr, SKIPADDR_CANONICAL);
        strncpy(dest, addr, width);
        dest[width - 1] = '\0';
    }

    return SKPLUGIN_OK;
}


/* Register an IPv4 field */
skplugin_err_t
skpinRegIPv4Field(
    const char                 *name,
    skplugin_ipv4_field_fn_t    fn,
    size_t                      width)
{
    skplugin_callbacks_t callbacks;
    ipv4_field_info_t *info;

    info = (ipv4_field_info_t*)malloc(sizeof(*info));
    if (info == NULL) {
        return SKPLUGIN_ERR;
    }
    add_to_free_list(info);

    info->fn = fn;

    memset(&callbacks, 0, sizeof(callbacks));

    callbacks.column_width = width ? width : 15;
    callbacks.bin_bytes    = 4;
    callbacks.rec_to_text  = ipv4_to_text;
    callbacks.rec_to_bin   = ipv4_to_bin;
    callbacks.bin_to_text  = ipv4_bin_to_text;

    return skpinRegField(NULL, name, no_description, &callbacks, info);
}


/* rec_to_text for skipaddr_t */
static skplugin_err_t
ip_to_text(
    const rwRec            *rec,
    char                   *dest,
    size_t                  width,
    void                   *cbdata,
    void           UNUSED(**extra))
{
    skipaddr_t val;
    char addr[SKIPADDR_STRLEN];
    ip_field_info_t *info = (ip_field_info_t *)cbdata;

    assert(info != NULL);
    assert(extra == NULL);

    info->fn(&val, rec);
    if (width >= sizeof(addr)) {
        skipaddrString(dest, &val, SKIPADDR_CANONICAL);
    } else {
        skipaddrString(addr, &val, SKIPADDR_CANONICAL);
        strncpy(dest, addr, width);
        dest[width - 1] = '\0';
    }

    return SKPLUGIN_OK;
}


/* rec_to_bin for skipaddr_t */
static skplugin_err_t
ip_to_bin(
    const rwRec            *rec,
    uint8_t                *dest,
    void                   *cbdata,
    void           UNUSED(**extra))
{
    skipaddr_t val;
    ip_field_info_t *info = (ip_field_info_t *)cbdata;

    assert(info != NULL);
    assert(extra == NULL);

    info->fn(&val, rec);
#if SK_ENABLE_IPV6
    skipaddrGetAsV6(&val, dest);
#else
    {
        uint32_t val32 = htonl(skipaddrGetV4(&val));
        memcpy(dest, &val32, sizeof(val32));
    }
#endif

    return SKPLUGIN_OK;
}


/* bin_to_text for skipaddr_t */
static skplugin_err_t
ip_bin_to_text(
    const uint8_t          *bin,
    char                   *dest,
    size_t                  width,
    void            UNUSED(*cbdata))
{
    skipaddr_t val;
    char addr[SKIPADDR_STRLEN];

    assert(cbdata != NULL);
#if SK_ENABLE_IPV6
    skipaddrSetV6(&val, bin);
    skipaddrV6toV4(&val, &val);
#else
    {
        uint32_t val32;
        memcpy(&val32, bin, sizeof(val32));
        val32 = ntohl(val32);
        skipaddrSetV4(&val, &val32);
    }
#endif
    if (width >= sizeof(addr)) {
        skipaddrString(dest, &val, SKIPADDR_CANONICAL);
    } else {
        skipaddrString(addr, &val, SKIPADDR_CANONICAL);
        strncpy(dest, addr, width);
        dest[width - 1] = '\0';
    }

    return SKPLUGIN_OK;
}


/* Register an IP address field */
skplugin_err_t
skpinRegIPAddressField(
    const char             *name,
    skplugin_ip_field_fn_t  fn,
    size_t                  width)
{
    skplugin_callbacks_t callbacks;
    ip_field_info_t *info;

    info = (ip_field_info_t*)malloc(sizeof(*info));
    if (info == NULL) {
        return SKPLUGIN_ERR;
    }
    add_to_free_list(info);

    info->fn = fn;

    memset(&callbacks, 0, sizeof(callbacks));

#if SK_ENABLE_IPV6
    callbacks.column_width = width ? width : 39;
    callbacks.bin_bytes    = 16;
#else
    callbacks.column_width = width ? width : 15;
    callbacks.bin_bytes    = 4;
#endif
    callbacks.rec_to_text  = ip_to_text;
    callbacks.rec_to_bin   = ip_to_bin;
    callbacks.bin_to_text  = ip_bin_to_text;

    return skpinRegField(NULL, name, no_description, &callbacks, info);
}


/* rec_to_text for a "text" field */
static skplugin_err_t
text_to_text(
    const rwRec            *rec,
    char                   *dest,
    size_t                  width,
    void                   *cbdata,
    void           UNUSED(**extra))
{
    text_field_info_t *info = (text_field_info_t *)cbdata;

    assert(info != NULL);
    assert(extra == NULL);

    info->text_fn(dest, width, info->int_info.fn(rec));

    return SKPLUGIN_OK;
}


/* bin_to_text for a "text" field */
static skplugin_err_t
text_bin_to_text(
    const uint8_t      *bin,
    char               *dest,
    size_t              width,
    void               *cbdata)
{
    text_field_info_t *info = (text_field_info_t *)cbdata;

    assert(info != NULL);

    info->text_fn(dest, width, int_from_bin(bin, &info->int_info));

    return SKPLUGIN_OK;
}


/* Registers a text field */
skplugin_err_t
skpinRegTextField(
    const char                 *name,
    uint64_t                    min,
    uint64_t                    max,
    skplugin_int_field_fn_t     value_fn,
    skplugin_text_field_fn_t    text_fn,
    size_t                      width)
{
    skplugin_callbacks_t callbacks;
    text_field_info_t *text_info;

    if (max == 0) {
        max = UINT64_MAX;
    }

    if (min > max) {
        return SKPLUGIN_ERR;
    }

    text_info = (text_field_info_t*)malloc(sizeof(*text_info));
    if (text_info == NULL) {
        return SKPLUGIN_ERR;
    }
    add_to_free_list(text_info);

    /* Verify that text_info can be cast as an int_field_info_t. */
    assert((void *)text_info == (void *)&text_info->int_info);

    setup_int_info(&text_info->int_info, min, max, value_fn);
    text_info->text_fn = text_fn;

    memset(&callbacks, 0, sizeof(callbacks));

    callbacks.column_width = width;
    callbacks.bin_bytes    = text_info->int_info.bytes;
    callbacks.rec_to_text  = text_to_text;
    callbacks.rec_to_bin   = int_to_bin;
    callbacks.bin_to_text  = text_bin_to_text;

    return skpinRegField(NULL, name, no_description, &callbacks, text_info);
}


/* rec_to_text for a string list field */
static skplugin_err_t
list_to_text(
    const rwRec            *rec,
    char                   *dest,
    size_t                  width,
    void                   *cbdata,
    void           UNUSED(**extra))
{
    list_field_info_t *info = (list_field_info_t *)cbdata;
    const char *text_val;
    uint64_t val;

    assert(info != NULL);
    assert(extra == NULL);

    val = info->int_info.fn(rec);
    if (val >= info->entries) {
        text_val = info->default_value;
    } else {
        text_val = info->list[val];
    }
    strncpy(dest, text_val, width);
    dest[width - 1] = '\0';

    return SKPLUGIN_OK;
}


/* bin_to_text for a string list field */
static skplugin_err_t
list_bin_to_text(
    const uint8_t      *bin,
    char               *dest,
    size_t              width,
    void               *cbdata)
{
    list_field_info_t *info = (list_field_info_t *)cbdata;
    const char *text_val;
    uint64_t val;

    assert(info != NULL);

    val = int_from_bin(bin, &info->int_info);
    if (val >= info->entries) {
        text_val = info->default_value;
    } else {
        text_val = info->list[val];
    }
    strncpy(dest, text_val, width);
    dest[width - 1] = '\0';

    return SKPLUGIN_OK;
}


/* Registers a string list field */
skplugin_err_t
skpinRegStringListField(
    const char                 *name,
    const char                **list,
    size_t                      entries,
    const char                 *default_value,
    skplugin_int_field_fn_t     fn,
    size_t                      width)
{
    skplugin_callbacks_t callbacks;
    list_field_info_t *info;
    const char **entry;
    size_t count;

    assert(list);
    assert(list[0] != NULL);

    info = (list_field_info_t*)malloc(sizeof(*info));
    if (info == NULL) {
        return SKPLUGIN_ERR;
    }
    add_to_free_list(info);

    info->list = list;
    info->default_value = default_value ? default_value : "";

    if (entries == 0) {
        for (entry = list; *entry; entry++) {
            entries++;
        }
    }
    info->entries = entries;
    if (width == 0) {
        if (default_value) {
            width = strlen(default_value);
        }
        for (count = 0, entry = list;
             count < entries;
             count++, entry++)
        {
            size_t len = strlen(*entry);
            if (len > width) {
                width = len;
            }
        }
    }

    /* Verify that list_info can be cast as an int_field_info_t. */
    assert((void *)info == (void *)&info->int_info);

    setup_int_info(&info->int_info, 0, entries, fn);

    memset(&callbacks, 0, sizeof(callbacks));

    callbacks.column_width = width;
    callbacks.bin_bytes    = info->int_info.bytes;
    callbacks.rec_to_text  = list_to_text;
    callbacks.rec_to_bin   = int_to_bin;
    callbacks.bin_to_text  = list_bin_to_text;

    return skpinRegField(NULL, name, no_description, &callbacks, info);
}


/*    INTEGER AGGREGATE VALUE FIELD    */

/* add_rec_to_bin for an integer aggregate */
static skplugin_err_t
int_add_rec_to_bin(
    const rwRec            *rec,
    uint8_t                *dest,
    void                   *cbdata,
    void           UNUSED(**extra))
{
    int_field_aggregator_t *info = (int_field_aggregator_t *)cbdata;
    uint64_t val;

    assert(info != NULL);
    assert(extra == NULL);

    val = info->agg(int_from_bin(dest, &info->int_info),
                    info->int_info.fn(rec));
    bin_from_int(&info->int_info, dest, val);

    return SKPLUGIN_OK;
}


/* bin_compare for an integer aggregate */
static skplugin_err_t
int_bin_compare(
    int                *cmp,
    const uint8_t      *value_a,
    const uint8_t      *value_b,
    void               *cbdata)
{
    int_field_info_t *info = (int_field_info_t *)cbdata;

    assert(info != NULL);

    *cmp = memcmp(value_a, value_b, info->bytes);
    return SKPLUGIN_OK;
}


/* bin_merge for an integer aggregate*/
static skplugin_err_t
int_bin_merge(
    uint8_t            *dest,
    const uint8_t      *src,
    void               *cbdata)
{
    int_field_aggregator_t *info = (int_field_aggregator_t *)cbdata;
    uint64_t val;

    val = info->agg(int_from_bin(dest, &info->int_info),
                    int_from_bin(src, &info->int_info));
    bin_from_int(&info->int_info, dest, val);

    return SKPLUGIN_OK;
}


/* Registers an integer aggregate field */
skplugin_err_t
skpinRegIntAggregator(
    const char                 *name,
    uint64_t                    max,
    skplugin_int_field_fn_t     fn,
    skplugin_int_agg_fn_t       agg,
    uint64_t                    initial,
    size_t                      width)
{
    skplugin_callbacks_t callbacks;
    int_field_aggregator_t *info;
    size_t w;

    if (max == 0) {
        max = UINT64_MAX;
    }

    if (initial > max) {
        return SKPLUGIN_ERR;
    }

    info = (int_field_aggregator_t*)malloc(sizeof(*info));
    if (info == NULL) {
        return SKPLUGIN_ERR;
    }
    add_to_free_list(info);

    /* Verify that info can be cast as an int_field_info_t. */
    assert((void *)info == (void *)&info->int_info);

    w = setup_int_info(&info->int_info, 0, max, fn);
    info->agg = agg;

    memset(&callbacks, 0, sizeof(callbacks));

    initial = hton64(initial);

    callbacks.column_width   = width ? width : w;
    callbacks.bin_bytes      = info->int_info.bytes;
    callbacks.add_rec_to_bin = int_add_rec_to_bin;
    callbacks.bin_to_text    = int_bin_to_text;
    callbacks.bin_merge      = int_bin_merge;
    callbacks.bin_compare    = int_bin_compare;
    callbacks.initial        = (const uint8_t *)&initial;

    return skpinRegField(NULL, name, no_description, &callbacks, info);
}


static uint64_t
int_sum_fn(
    uint64_t            a,
    uint64_t            b)
{
    return a + b;
}


static uint64_t
int_max_fn(
    uint64_t            a,
    uint64_t            b)
{
    return (a > b) ? a : b;
}


static uint64_t
int_min_fn(
    uint64_t            a,
    uint64_t            b)
{
    return (a > b) ? b : a;
}


/* Registers an integer sum aggregate field */
skplugin_err_t
skpinRegIntSumAggregator(
    const char                 *name,
    uint64_t                    max,
    skplugin_int_field_fn_t     fn,
    size_t                      width)
{
    return skpinRegIntAggregator(name, max, fn, int_sum_fn, 0, width);
}


/* Registers an integer minimum aggregate field */
skplugin_err_t
skpinRegIntMinAggregator(
    const char                 *name,
    uint64_t                    max,
    skplugin_int_field_fn_t     fn,
    size_t                      width)
{
    return skpinRegIntAggregator(name, max, fn, int_min_fn,
                                 ((0 == max) ? UINT64_MAX : max), width);
}


/* Registers an integer maximum aggregate field */
skplugin_err_t
skpinRegIntMaxAggregator(
    const char                 *name,
    uint64_t                    max,
    skplugin_int_field_fn_t     fn,
    size_t                      width)
{
    return skpinRegIntAggregator(name, max, fn, int_max_fn, 0, width);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
