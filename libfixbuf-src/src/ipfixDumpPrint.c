/*
 *
 ** @file ipfixDumpPrint.c
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2023 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso <netsa-help@cert.org>
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_LICENSE_START@
 ** libfixbuf 2.0
 **
 ** Copyright 2018-2023 Carnegie Mellon University. All Rights Reserved.
 **
 ** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
 ** ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
 ** BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
 ** EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
 ** EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
 ** MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 ** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
 ** COPYRIGHT INFRINGEMENT.
 **
 ** Released under a GNU-Lesser GPL 3.0-style license, please see
 ** LICENSE.txt or contact permission@sei.cmu.edu for full terms.
 **
 ** [DISTRIBUTION STATEMENT A] This material has been approved for
 ** public release and unlimited distribution.  Please see Copyright
 ** notice for non-US Government use and distribution.
 **
 ** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent
 ** and Trademark Office by Carnegie Mellon University.
 **
 ** DM18-0325
 ** @OPENSOURCE_LICENSE_END@
 ** ------------------------------------------------------------------------
 */

#include "ipfixDump.h"
#include <stdarg.h>

/* size of buffer to hold indentation prefix */
#define PREFIX_BUFSIZ       256

/* size of buffer to hold element name and (ent/id) */
#define ELEMENT_BUFSIZ      128

/* size of buffer to hold template ID and name */
#define TMPL_NAME_BUFSIZ    128

/* size of buffer to hold list semantic */
#define SEMANTIC_BUFSIZ      32

#ifdef __GNUC__
static void idPrint(
    FILE *fp,
    const char *format,
    ...)
    __attribute__((format (printf, 2, 3)));
#endif

static void idPrintValue(
    FILE                          *fp,
    const fbInfoElement_t         *ie,
    uint8_t                       *val,
    size_t                         buf_len,
    char                          *str_prefix);


/**
 * mdPrintIP6Address
 *
 *
 */
static void mdPrintIP6Address(
    char        *ipaddr_buf,
    uint8_t     *ipaddr)
{
    char            *cp = ipaddr_buf;
    uint16_t        *aqp = (uint16_t *)ipaddr;
    uint16_t        aq;
    gboolean        colon_start = FALSE;
    gboolean        colon_end = FALSE;

    for (; (uint8_t *)aqp < ipaddr + 16; aqp++) {
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


/**
 *    Does nothing if 'only_stats' is set; otherwise acts like fprintf.
 *
 */
static void idPrint(
    FILE       *fp,
    const char *format,
    ...)
{
    va_list args;
    if (!only_stats) {
        va_start(args, format);
        vfprintf(fp, format, args);
        va_end(args);
    }
}


/**
 *    Sets 'dest' to the contents of 'current' plus one indentation layer.
 *
 *    Using this function makes it easy to change the indentation.
 *
 */
static void idAddIndentLevel(
    char        *dest,
    const char  *current,
    size_t       dest_bufsiz)
{
    /* pointless if() quiets truncation warning in gcc-7.1 */
    if ((size_t)snprintf(dest, dest_bufsiz, "%s\t", current) >= dest_bufsiz) {}
}


/**
 *    Puts textual information about the template whose ID is 'tid'
 *    into 'tmpl_str'.  The information is the template ID (both
 *    decimal and hex) and the template name if available.
 *
 *    @param tmpl_str        The buffer to write to
 *    @param tid             The ID of the template to get info of
 *    @param tmpl_str_bufsiz The sizeof the tmpl_str buffer
 *
 */
static void idFormatTemplateId(
    char       *tmpl_str,
    int         tid,
    size_t      tmpl_str_bufsiz)
{
    const char *name;

    name = (char *)g_hash_table_lookup(template_names, GINT_TO_POINTER(tid));
    snprintf(tmpl_str, tmpl_str_bufsiz, "tid: %5u (%#06x) %s",
             tid, tid, ((name) ? name : ""));
}


static void idFormatListSemantic(
    char       *sem_str,
    int         semantic,
    size_t      sem_str_bufsiz)
{
    switch (semantic) {
      case 0:
        snprintf(sem_str, sem_str_bufsiz, "0-noneOf");
        break;
      case 1:
        snprintf(sem_str, sem_str_bufsiz, "1-exactlyOneOf");
        break;
      case 2:
        snprintf(sem_str, sem_str_bufsiz, "2-oneOrMoreOf");
        break;
      case 3:
        snprintf(sem_str, sem_str_bufsiz, "3-allOf");
        break;
      case 4:
        snprintf(sem_str, sem_str_bufsiz, "4-ordered");
        break;
      case 0xFF:
        snprintf(sem_str, sem_str_bufsiz, "255-undefined");
        break;
      default:
        snprintf(sem_str, sem_str_bufsiz, "%u-unassigned", semantic);
        break;
    }
}


/**
 *    Puts textual information about the InfoElement 'ie' into into
 *    'elem_str'.  The information is the ID (and enterprise ID when
 *    non-standard) and the element's name.  The 'in_basicList' flag
 *    changes how the element's name is accessed and changes the
 *    formatting by removing whitespace between the ID and name.
 */
static void idFormatElement(
    char                   *elem_str,
    const fbInfoElement_t  *ie,
    size_t                  elem_str_bufsiz,
    int                     in_basicList,
    int                     is_scope)
{
    const int element_width = 40;
    char buf[32];
    int len;

    if (0 == ie->ent) {
        len = snprintf(buf, sizeof(buf), "(%d)%s",
                       ie->num, (is_scope ? " (S)" : ""));
    } else {
        len = snprintf(buf, sizeof(buf), "(%d/%d)%s",
                       ie->ent, ie->num, (is_scope ? " (S)" : ""));
    }
    if (in_basicList) {
        snprintf(elem_str, elem_str_bufsiz, "%s %s", buf, ie->ref.name);
    } else {
        snprintf(elem_str, elem_str_bufsiz, "%s%*s",
                 buf, element_width - len, ie->ref.canon->ref.name);
    }
}


/**
 *    Formats a timestamp and prints it to the handle 'fp'.  The
 *    timestamp is given as an UNIX epoch offset, with seconds in
 *    'sec' and fractional seconds in 'frac'.  The value 'frac_places'
 *    is the number of fractional digits (0 for seconds, 3 for milli,
 *    6 for micro, 9 for nano).
 */
static void idPrintTimestamp(
    FILE     *fp,
    time_t    sec,
    uint64_t  frac,
    int       frac_places)
{
    struct tm time_tm;
    char frac_str[32] = "";

    gmtime_r(&sec, &time_tm);

    if (frac_places) {
        snprintf(frac_str, sizeof(frac_str), ".%0*" PRIu64, frac_places, frac);
    }

    idPrint(fp, "%04u-%02u-%02u %02u:%02u:%02u%s\n",
            time_tm.tm_year+1900, time_tm.tm_mon+1, time_tm.tm_mday,
            time_tm.tm_hour, time_tm.tm_min, time_tm.tm_sec, frac_str);
}


/**
 *    Puts the name of the datatype given by 'dt' into 'dt_str'.
 */
static void idFormatDataType(
    char          *dt_str,
    uint8_t        dt,
    size_t         dt_str_bufsiz)
{
    switch (dt) {
      case FB_OCTET_ARRAY:
        strncpy(dt_str, "octet", dt_str_bufsiz);
        break;
      case FB_UINT_8:
        strncpy(dt_str, "uint8", dt_str_bufsiz);
        break;
      case FB_UINT_16:
        strncpy(dt_str, "uint16", dt_str_bufsiz);
        break;
      case FB_UINT_32:
        strncpy(dt_str, "uint32", dt_str_bufsiz);
        break;
      case FB_UINT_64:
        strncpy(dt_str, "uint64", dt_str_bufsiz);
        break;
      case FB_INT_8:
        strncpy(dt_str, "int8", dt_str_bufsiz);
        break;
      case FB_INT_16:
        strncpy(dt_str, "int16", dt_str_bufsiz);
        break;
      case FB_INT_32:
        strncpy(dt_str, "int32", dt_str_bufsiz);
        break;
      case FB_INT_64:
        strncpy(dt_str, "int64", dt_str_bufsiz);
        break;
      case FB_FLOAT_32:
        strncpy(dt_str, "float32", dt_str_bufsiz);
        break;
      case FB_FLOAT_64:
        strncpy(dt_str, "float64", dt_str_bufsiz);
        break;
      case FB_BOOL:
        strncpy(dt_str, "bool", dt_str_bufsiz);
        break;
      case FB_MAC_ADDR:
        strncpy(dt_str, "mac", dt_str_bufsiz);
        break;
      case FB_STRING:
        strncpy(dt_str, "string", dt_str_bufsiz);
        break;
      case FB_DT_SEC:
        strncpy(dt_str, "sec", dt_str_bufsiz);
        break;
      case FB_DT_MILSEC:
        strncpy(dt_str, "millisec", dt_str_bufsiz);
        break;
      case FB_DT_MICROSEC:
        strncpy(dt_str, "microsec", dt_str_bufsiz);
        break;
      case FB_DT_NANOSEC:
        strncpy(dt_str, "nanosec", dt_str_bufsiz);
        break;
      case FB_IP4_ADDR:
        strncpy(dt_str, "ipv4", dt_str_bufsiz);
        break;
      case FB_IP6_ADDR:
        strncpy(dt_str, "ipv6", dt_str_bufsiz);
        break;
      case FB_BASIC_LIST:
        strncpy(dt_str, "bl", dt_str_bufsiz);
        break;
      case FB_SUB_TMPL_LIST:
        strncpy(dt_str, "stl", dt_str_bufsiz);
        break;
      case FB_SUB_TMPL_MULTI_LIST:
        strncpy(dt_str, "stml", dt_str_bufsiz);
        break;
      default:
        snprintf(dt_str, dt_str_bufsiz, "%d", dt);
    }
}


/**
 *    Print a textual representation of an IPFIX message header to
 *    'outfile'.  Uses the global values 'sequence_number' and
 *    'msglen'.
 */
void idPrintHeader(
    FILE              *outfile,
    fBuf_t            *fbuf)
{
    fbSession_t *session = fBufGetSession(fbuf);
    uint32_t secs = fBufGetExportTime(fbuf);
    long epochtime = secs;
    struct tm time_tm;

    gmtime_r(&epochtime, &time_tm);

    fprintf(outfile, "--- Message Header ---\n");
    fprintf(outfile, "export time: %04u-%02u-%02u %02u:%02u:%02u\t",
            time_tm.tm_year + 1900,
            time_tm.tm_mon + 1,
            time_tm.tm_mday,
            time_tm.tm_hour,
            time_tm.tm_min,
            time_tm.tm_sec);
    fprintf(outfile, "observation domain id: %u\n",
            fbSessionGetDomain(session));
    fprintf(outfile, "message length: %-16zu\t", msglen);
    fprintf(outfile, "sequence number: %u (%#x)\n\n",
            sequence_number, sequence_number);
}


/**
 *    Print a textual representation of 'tmpl' to 'fp'.  'ctx' is the
 *    template context created when the template was first read.
 */
uint16_t idPrintTemplate(
    FILE              *fp,
    fbTemplate_t      *tmpl,
    tmplContext_t     *ctx,
    uint16_t          tid,
    gboolean          noprint)
{
    uint32_t count = ctx->count;
    uint16_t scope = ctx->scope;
    uint16_t length = 0;
    char dt_str[25];
    char prefix[PREFIX_BUFSIZ];
    fbInfoElement_t *ie = NULL;
    const char *name;
    unsigned int i;

    idAddIndentLevel(prefix, "", sizeof(prefix));

    if (!noprint) {
        if (fbTemplateGetOptionsScope(tmpl)) {
            fprintf(fp, "--- options template record ---\n");
        } else {
            fprintf(fp, "--- template record ---\n");
        }
        fprintf(fp, "header:\n");
        fprintf(fp, "%stid: %5u (%#06x)", prefix, tid, tid);
        fprintf(fp, "    field count: %5u", count);
        fprintf(fp, "    scope: %5u", scope);
        name = (char *)g_hash_table_lookup(template_names,GINT_TO_POINTER(tid));
        if (name) {
            fprintf(fp, "    name: %s", name);
        }
        fprintf(fp, "\nfields:\n");
    }

    for (i = 0; i < count; i++) {
        ie = fbTemplateGetIndexedIE(tmpl, i);

        if (!noprint) {
            idFormatDataType(dt_str, ie->type, sizeof(dt_str));
            fprintf(fp, "%sent: %5u", prefix, ie->ent);
            fprintf(fp, "  id: %5u", ie->num);
            fprintf(fp, "  type: %-8s", dt_str);
            fprintf(fp, "  len: %5u", ie->len);
            fprintf(fp, " %s", (i < scope) ? "(S)" : "   ");
            fprintf(fp, " %s\n", ie->ref.canon->ref.name);
        }

        if (ie->len != FB_IE_VARLEN) {
            length += ie->len;
        } else if (ie->type == FB_BASIC_LIST) {
            length += sizeof(fbBasicList_t);
        } else if (ie->type == FB_SUB_TMPL_LIST) {
            length += sizeof(fbSubTemplateList_t);
        } else if (ie->type == FB_SUB_TMPL_MULTI_LIST) {
            length += sizeof(fbSubTemplateMultiList_t);
        } else {
            length += sizeof(fbVarfield_t);
        }
    }

    return length;
}


/**
 *    Print a textual representation of 'entry' to 'fp'.  'index' is
 *    the location of the entry in the STML.
 */
static void idPrintSTMLEntry(
    FILE                          *fp,
    fbSubTemplateMultiListEntry_t *entry,
    uint8_t                        index,
    char                          *prefix)
{
    uint8_t *data = NULL;
    int i = 0;
    char str_prefix[PREFIX_BUFSIZ];
    char str_template[TMPL_NAME_BUFSIZ];

    idAddIndentLevel(str_prefix, prefix, sizeof(str_prefix));

    idPrint(fp, "%s+++ subTemplateMultiListEntry %d +++\n", prefix, index);

    idFormatTemplateId(str_template, entry->tmplID, sizeof(str_template));
    ++id_tmpl_stats[entry->tmplID];

    /* idPrint(fp, "%sheader:\n", prefix); */
    idPrint(fp, "%scount: %-4d", str_prefix, entry->numElements);
    idPrint(fp, "    %s\n", str_template);

    while ((data = fbSubTemplateMultiListEntryNextDataPtr(entry, data))) {
        ++i;
        idPrintDataRecord(fp, entry->tmpl, data, 0, i, prefix);
    }
}


/**
 *    Print a textual representation of 'stl' to 'fp'.
 */
static void idPrintSTL(
    FILE                *fp,
    fbSubTemplateList_t *stl,
    size_t               buf_len,
    char                *parent_prefix)
{
    int i = 0;
    uint8_t *data = NULL;
    char prefix[PREFIX_BUFSIZ];
    char str_prefix[PREFIX_BUFSIZ];
    char str_template[TMPL_NAME_BUFSIZ];
    char str_semantic[SEMANTIC_BUFSIZ];

    (void)buf_len;

    idAddIndentLevel(prefix, parent_prefix, sizeof(prefix));
    idAddIndentLevel(str_prefix, prefix, sizeof(str_prefix));

    idPrint(fp, "\n%s+++ subTemplateList +++\n", prefix);

    idFormatTemplateId(str_template, stl->tmplID, sizeof(str_template));
    ++id_tmpl_stats[stl->tmplID];

    idFormatListSemantic(str_semantic, stl->semantic, sizeof(str_semantic));

    /* idPrint(fp, "%sheader:\n", prefix); */
    idPrint(fp, "%scount: %-4d", str_prefix, stl->numElements);
    idPrint(fp, "    semantic: %-14s", str_semantic);
    idPrint(fp, "    %s\n", str_template);

    while ((data = fbSubTemplateListGetNextPtr(stl, data))) {
        ++i;
        idPrintDataRecord(fp, (fbTemplate_t*)(stl->tmpl), data, 0, i,
                          prefix);
    }
}


/**
 *    Print a textual representation of 'stml' to 'fp'.
 */
static void idPrintSTML(
    FILE                     *fp,
    fbSubTemplateMultiList_t *stml,
    size_t                    buf_len,
    char                     *parent_prefix)
{
    fbSubTemplateMultiListEntry_t *entry = NULL;
    char prefix[PREFIX_BUFSIZ];
    char str_prefix[PREFIX_BUFSIZ];
    char str_semantic[SEMANTIC_BUFSIZ];
    int i = 0;

    (void)buf_len;

    idAddIndentLevel(prefix, parent_prefix, sizeof(prefix));
    idAddIndentLevel(str_prefix, prefix, sizeof(str_prefix));

    idPrint(fp, "\n%s+++ subTemplateMultiList +++\n", prefix);

    idFormatListSemantic(str_semantic, stml->semantic, sizeof(str_semantic));

    /* idPrint(fp, "%sheader:\n", prefix); */
    idPrint(fp, "%scount: %-4d", str_prefix, stml->numElements);
    idPrint(fp, "    semantic: %s\n", str_semantic);

    while ((entry = fbSubTemplateMultiListGetNextEntry(stml, entry))) {
        ++i;
        idPrintSTMLEntry(fp, entry, i, prefix);
    }
}


/**
 *    Print a textual representation of 'bl' to 'fp'.
 */
static void idPrintBL(
    FILE          *fp,
    fbBasicList_t *bl,
    size_t         buf_len,
    const char    *parent_prefix)
{
    const fbInfoElement_t    *ie = bl->infoElement;
    uint8_t                  *data = NULL;
    int                      i = 0;
    char                     prefix[PREFIX_BUFSIZ];
    char                     str_prefix[PREFIX_BUFSIZ];
    char                     str_elem[ELEMENT_BUFSIZ];
    char                     str_semantic[SEMANTIC_BUFSIZ];

    idAddIndentLevel(prefix, parent_prefix, sizeof(prefix));
    idAddIndentLevel(str_prefix, prefix, sizeof(str_prefix));

    idPrint(fp, "\n%s+++ basicList +++\n", prefix);

    idFormatListSemantic(str_semantic, bl->semantic, sizeof(str_semantic));

    /* idPrint(fp, "%sheader:\n", prefix); */
    idPrint(fp, "%scount: %-4d", str_prefix, bl->numElements);
    idPrint(fp, "    semantic: %-14s", str_semantic);
    idPrint(fp, "    ie: ");
    if (!ie) {
        idPrint(fp, "[Unknown]\n");
        return;
    }
    idFormatElement(str_elem, ie, sizeof(str_elem), 1, 0);
    idPrint(fp, "%s\n", str_elem);

    while ((data = fbBasicListGetNextPtr(bl, data))) {
        ++i;
        idPrint(fp, "%s%-2d : ", str_prefix, i);
        idPrintValue(fp, ie, data, buf_len, str_prefix);
    }
}


/**
 *    Print the value of element 'ie' to 'fp'.  The value is given in
 *    'val', and its octet length is in 'buf_len'.
 */
static void idPrintValue(
    FILE                          *fp,
    const fbInfoElement_t         *ie,
    uint8_t                       *val,
    size_t                         buf_len,
    char                          *str_prefix)
{
    switch (ie->type) {
      case FB_BOOL:
      case FB_UINT_8:
      case FB_UINT_16:
      case FB_UINT_32:
      case FB_UINT_64:
        {
            uint64_t u64 = 0;
            g_assert(ie->len <= 8);
#if G_BYTE_ORDER == G_BIG_ENDIAN
            memcpy(((uint8_t *)(&u64)) + (8 - ie->len), val, ie->len);
#else
            memcpy(&u64, val, ie->len);
#endif
            idPrint(fp, "%" PRIu64 "\n", u64);
            break;
        }

      case FB_INT_8:
      case FB_INT_16:
      case FB_INT_32:
      case FB_INT_64:
        {
            int64_t i64;
            uint8_t *sign_byte = val;
            g_assert(ie->len <= 8);
#if G_BYTE_ORDER != G_BIG_ENDIAN
            sign_byte = val + ie->len - 1;
#endif
            memset(&i64, ((0x80 & *sign_byte) ? 0xff : 0), sizeof(i64));
#if G_BYTE_ORDER == G_BIG_ENDIAN
            memcpy(((uint8_t *)(&i64)) + (8 - ie->len), val, ie->len);
#else
            memcpy(&i64, val, ie->len);
#endif
            idPrint(fp, "%" PRIi64 "\n", i64);
            break;
        }

      case FB_IP4_ADDR:
#if G_BYTE_ORDER == G_BIG_ENDIAN
        idPrint(fp, "%u.%u.%u.%u\n", val[0], val[1], val[2], val[3]);
#elif G_BYTE_ORDER == G_LITTLE_ENDIAN
        idPrint(fp, "%u.%u.%u.%u\n", val[3], val[2], val[1], val[0]);
#else
        {
            uint32_t ip;
            memcpy(&ip, val, sizeof(ip));
            idPrint(fp, "%u.%u.%u.%u\n",
                    (ip >> 24), (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
        }
#endif
        break;

      case FB_IP6_ADDR:
        {
            char ip_buf[40];
            mdPrintIP6Address(ip_buf, val);
            idPrint(fp, "%s\n", ip_buf);
            break;
        }

      case FB_FLOAT_64:
        if (ie->len == 8) {
            double d;
            memcpy(&d, val, sizeof(d));
            idPrint(fp, "%.8g\n", d);
            break;
        }
        /* FALLTHROUGH */
      case FB_FLOAT_32:
        {
            float f;
            g_assert(ie->len == 4);
            memcpy(&f, val, sizeof(f));
            idPrint(fp, "%.8g\n", f);
            break;
        }

      case FB_DT_SEC:
        {
            time_t secs = *(uint32_t *)val;
            idPrintTimestamp(fp, secs, 0, 0);
            break;
        }
      case FB_DT_MILSEC:
        {
            uint64_t milli;
            memcpy(&milli, val, sizeof(milli));
            idPrintTimestamp(fp, (time_t)(milli / 1000), milli % 1000, 3);
            break;
        }
        break;
      case FB_DT_MICROSEC:
      case FB_DT_NANOSEC:
        {
            /* FIXME: Handle NTP wraparaound for Feb 8 2036 */
            /*
             *    The number of seconds between Jan 1, 1900 (the NTP
             *    epoch) and Jan 1, 1970 (the UNIX epoch)
             */
            const uint64_t NTP_EPOCH_TO_UNIX_EPOCH = UINT64_C(0x83AA7E80);
            const uint64_t NTPFRAC = UINT64_C(0x100000000);
            uint64_t u64;
            time_t sec;

            memcpy(&u64, val, sizeof(u64));
            sec = (int64_t)(u64 >> 32) - NTP_EPOCH_TO_UNIX_EPOCH;
            if (ie->type == FB_DT_MICROSEC) {
                uint64_t frac = (u64 & UINT64_C(0xfffff800)) / NTPFRAC;
                idPrintTimestamp(fp, sec, frac, 6);
            } else {
                uint64_t frac = (u64 & UINT32_MAX) / NTPFRAC;
                idPrintTimestamp(fp, sec, frac, 9);
            }
        }
        break;

      case FB_BASIC_LIST:
        idPrintBL(fp, (fbBasicList_t *)val, buf_len, str_prefix);
        fbBasicListClear((fbBasicList_t *)val);
        break;
      case FB_SUB_TMPL_LIST:
        idPrintSTL(fp, (fbSubTemplateList_t *)val, buf_len, str_prefix);
        fbSubTemplateListClear((fbSubTemplateList_t *)val);
        break;
      case FB_SUB_TMPL_MULTI_LIST:
        idPrintSTML(fp, (fbSubTemplateMultiList_t *)val, buf_len, str_prefix);
        fbSubTemplateMultiListClear((fbSubTemplateMultiList_t *)val);
        break;

      case FB_MAC_ADDR:
        idPrint(fp, "%02x:%02x:%02x:%02x:%02x:%02x\n",
                val[0], val[1], val[2], val[3], val[4], val[5]);
        break;
      case FB_STRING:
        if (ie->len == FB_IE_VARLEN) {
            fbVarfield_t var;
            memcpy(&var, val, sizeof(var));
            idPrint(fp, "(len: %" PRIu64 ") %.*s\n",
                    (uint64_t)var.len, (int)var.len, var.buf);
        } else {
            char buf[UINT16_MAX + 1];
            uint32_t len = ie->len;
            if (len > UINT16_MAX) {
                len = UINT16_MAX;
            }
            memcpy(buf, val, len);
            buf[len] = '\0';
            idPrint(fp, "(len: %u) %.*s\n", len, len, buf);
        }
        break;

      case FB_OCTET_ARRAY:
        if (ie->len <= 8) {
            uint64_t u64 = 0;
#if G_BYTE_ORDER == G_BIG_ENDIAN
            memcpy(((uint8_t *)(&u64)) + (8 - ie->len), val, ie->len);
#else
            memcpy(&u64, val, ie->len);
#endif
            idPrint(fp, "%" PRIu64 "\n", u64);
        } else {
            fbVarfield_t var;
            uint32_t len;
            const uint8_t *buf;

            if (ie->len == FB_IE_VARLEN) {
                memcpy(&var, val, sizeof(var));
                len = var.len;
                buf = var.buf;
            } else {
                len = ie->len;
                buf = val;
            }
            if (0 == hexdump) {
                idPrint(fp, "len: %u\n", len);
            } else if (0 == len) {
                idPrint(fp, "(len: 0)\n");
            } else {
                char charbuf[2 * UINT16_MAX + 1];
                char *c;
                uint32_t printlen;
                uint32_t i;

                charbuf[0] = '\0';
                printlen = ((len < hexdump) ? len : hexdump);
                for (i = 0, c = charbuf; i < printlen; ++i, c += 2) {
                    snprintf(c, 3, "%02x", buf[i]);
                }
                idPrint(fp, "(len: %u) 0x%s\n", len, charbuf);
            }
        }
        break;
    }
}


/**
 *    Print a textual representation of a record to 'fp'.  The
 *    record's template is 'tmpl', its data is given by 'buffer'
 *    having length 'buf_len'.
 */
void idPrintDataRecord(
    FILE         *fp,
    fbTemplate_t *tmpl,
    uint8_t      *buffer,
    size_t       buf_len,
    int          rec_count,
    char         *prefix)
{
    tmplContext_t *tc = (tmplContext_t *)fbTemplateGetContext(tmpl);
    fbInfoElement_t *ie = NULL;
    uint16_t buf_walk = 0;
    unsigned int i;
    char str_prefix[PREFIX_BUFSIZ];
    char str_elem[ELEMENT_BUFSIZ];
    char str_tmpl[TMPL_NAME_BUFSIZ];
    int top_level;

    top_level = ('\0' == prefix[0]);

    idAddIndentLevel(str_prefix, prefix, sizeof(str_prefix));

    idPrint(fp, "%s--- data record %d ---\n", prefix, rec_count);

    idFormatTemplateId(str_tmpl, tc->tid, sizeof(str_tmpl));

    idPrint(fp, "%sheader:\n", prefix);
    idPrint(fp, "%scount: %-4u", str_prefix, tc->count);
    idPrint(fp, "    %s\n", str_tmpl);

    idPrint(fp, "%sfields:\n", prefix);

    for (i = 0; i < tc->count; i++) {
        ie = fbTemplateGetIndexedIE(tmpl, i);
        idFormatElement(str_elem, ie, sizeof(str_elem), 0,
                        (top_level && (i < tc->scope)));
        idPrint(fp, "%s%s : ", str_prefix, str_elem);

        /* if a padding element, print its length and continue */
        if (ie->num == 210 && ie->ent == 0) {
            idPrint(fp, "len: %d\n", ie->len);
            buf_walk += ie->len;
            continue;
        }

        idPrintValue(fp, ie, buffer + buf_walk, buf_len, str_prefix);
        /* fflush(fp); */
        if (ie->len != FB_IE_VARLEN) {
            buf_walk += ie->len;
        } else if (ie->type == FB_BASIC_LIST) {
            buf_walk += sizeof(fbBasicList_t);
        } else if (ie->type == FB_SUB_TMPL_LIST) {
            buf_walk += sizeof(fbSubTemplateList_t);
        } else if (ie->type == FB_SUB_TMPL_MULTI_LIST) {
            buf_walk += sizeof(fbSubTemplateMultiList_t);
        } else {
            buf_walk += sizeof(fbVarfield_t);
        }
    }
}
