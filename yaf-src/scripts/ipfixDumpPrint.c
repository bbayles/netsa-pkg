#include "ipfixDumpPrint.h"
#include <stdarg.h>

#define FBSTLNEXT(a, b) fbSubTemplateListGetNextPtr(a, b)
#define FBSTMLNEXT(a, b) fbSubTemplateMultiListEntryNextDataPtr(a, b)
#define FBBLNEXT(a, b) fbBasicListGetNextPtr(a, b)
#define FBSTMLNEXTENTRY(a, b) fbSubTemplateMultiListGetNextEntry(a, b)
#define DT_MAX 25

extern int id_tmpl_stats[65536];
extern gboolean dump_stats;

/**
 * mdPrintIP4Address
 *
 *
 */
void mdPrintIP4Address(
    char           *ipaddr_buf,
    uint32_t       ip)
{
    uint32_t mask = 0xff000000U;
    uint8_t dqp[4];

    /* split the address */
    dqp[0] = (ip & mask) >> 24;
    mask >>= 8;
    dqp[1] = (ip & mask) >> 16;
    mask >>= 8;
    dqp[2] = (ip & mask) >> 8;
    mask >>= 8;
    dqp[3] = (ip & mask);

    /* print to it */
    snprintf(ipaddr_buf, 16,
             "%hhu.%hhu.%hhu.%hhu",dqp[0],dqp[1],dqp[2],dqp[3]);

}

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

static void idPrint(
    FILE *fp,
    const char *format,
    ...)
{
    va_list args;
    if (!dump_stats) {
        va_start(args, format);
        vfprintf(fp, format, args);
        va_end(args);
    }
}


void idPrintDataType(
    char          *fb_dt,
    uint8_t        dt)
{

    switch (dt) {
      case FB_OCTET_ARRAY:
        strncpy(fb_dt, "octet", DT_MAX);
        break;
      case FB_UINT_8:
        strncpy(fb_dt, "uint8", DT_MAX);
        break;
      case FB_UINT_16:
        strncpy(fb_dt, "uint16", DT_MAX);
        break;
      case FB_UINT_32:
        strncpy(fb_dt, "uint32", DT_MAX);
        break;
      case FB_UINT_64:
        strncpy(fb_dt, "uint64", DT_MAX);
        break;
      case FB_INT_8:
        strncpy(fb_dt, "int8", DT_MAX);
        break;
      case FB_INT_16:
        strncpy(fb_dt, "int16", DT_MAX);
        break;
      case FB_INT_32:
        strncpy(fb_dt, "int32", DT_MAX);
        break;
      case FB_INT_64:
        strncpy(fb_dt, "int64", DT_MAX);
        break;
      case FB_FLOAT_32:
        strncpy(fb_dt, "float32", DT_MAX);
        break;
      case FB_FLOAT_64:
        strncpy(fb_dt, "float64", DT_MAX);
        break;
      case FB_BOOL:
        strncpy(fb_dt, "bool", DT_MAX);
        break;
      case FB_MAC_ADDR:
        strncpy(fb_dt, "mac", DT_MAX);
        break;
      case FB_STRING:
        strncpy(fb_dt, "string", DT_MAX);
        break;
      case FB_DT_SEC:
        strncpy(fb_dt, "sec", DT_MAX);
        break;
      case FB_DT_MILSEC:
        strncpy(fb_dt, "milsec", DT_MAX);
        break;
      case FB_DT_MICROSEC:
        strncpy(fb_dt, "micsec", DT_MAX);
        break;
      case FB_DT_NANOSEC:
        strncpy(fb_dt, "nanosec", DT_MAX);
        break;
      case FB_IP4_ADDR:
        strncpy(fb_dt, "ipv4", DT_MAX);
        break;
      case FB_IP6_ADDR:
        strncpy(fb_dt, "ipv6", DT_MAX);
        break;
      case FB_BASIC_LIST:
        strncpy(fb_dt, "bl", DT_MAX);
        break;
      case FB_SUB_TMPL_LIST:
        strncpy(fb_dt, "stl", DT_MAX);
        break;
      case FB_SUB_TMPL_MULTI_LIST:
        strncpy(fb_dt, "stml", DT_MAX);
        break;
      default:
        sprintf(fb_dt, "%d", dt);
    }
}


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
    /*    fprintf(outfile, "observation domain id: %u\n\n",
          fbCollectorGetObservationDomain(collector));*/
    fprintf(outfile, "observation domain id: %u\n\n",
            fbSessionGetDomain(session));

}

uint16_t idPrintTemplate(
    FILE              *fp,
    fbTemplate_t      *tmpl,
    void              **ctx,
    uint16_t          tid,
    gboolean          noprint)
{

    uint32_t count = fbTemplateCountElements(tmpl);
    uint16_t length = 0;
    char dt_str[DT_MAX];
    fbInfoElement_t *ie = NULL;
    int i = 0;

    if (!noprint) {
        if (fbTemplateGetOptionsScope(tmpl)) {
            fprintf(fp, "--- options template record ---\n");
        } else {
            fprintf(fp, "--- template record ---\n");
        }
        fprintf(fp, "header:\n");
        fprintf(fp, "\ttid: %5u (0x%x)", tid, tid);
        fprintf(fp, "\tfield count: %5u", count);
        fprintf(fp, "\tscope: %5u\n", fbTemplateGetOptionsScope(tmpl));
        fprintf(fp, "fields:\n");
    }

    for (i = 0; i < count; i++) {
        ie = fbTemplateGetIndexedIE(tmpl, i);
        idPrintDataType(dt_str, ie->type);
        if (!noprint) {
            fprintf(fp, "\t ent: %5u", ie->ent);
            fprintf(fp, "  id: %5u", ie->num);
            fprintf(fp, "  type: %s", dt_str);
            fprintf(fp, "\tlength: %5u", ie->len);
            fprintf(fp, "  %s\n", ie->ref.canon->ref.name);
        }

        if (ie->len != 65535) {
            length += ie->len;
        } else if (ie->num == 293) {
            length += sizeof(fbSubTemplateMultiList_t);
        } else if (ie->num == 292) {
            length += sizeof(fbSubTemplateList_t);
        } else if (ie->num == 291) {
            length += sizeof(fbBasicList_t);
        } else {
            length += sizeof(fbVarfield_t);
        }
    }

    /* if (!noprint) { */
    /*     fprintf(fp, "\n"); */
    /* } */

    return length;
}

void idPrintSTMLEntry(
    FILE                          *fp,
    fbSubTemplateMultiListEntry_t *entry,
    uint8_t                       index,
    char                          *str_prefix)
{
    uint8_t *data = NULL;
    int i = 0;
    char str_prefix2[DT_MAX];

    strcpy(str_prefix2, str_prefix);
    strcat(str_prefix2, "\t");

    idPrint(fp, "\t+++ subTemplateMultiListEntry %d +++\n", index);

    idPrint(fp, "\theader:");
    idPrint(fp, "\tcount: %3d", entry->numElements);
    idPrint(fp, "\t\ttid: %5d (0x%02x)\n", entry->tmplID, entry->tmplID);

    id_tmpl_stats[entry->tmplID] += 1;

    while ((data = FBSTMLNEXT(entry, data))) {
        idPrintDataRecord(fp, entry->tmpl, data, 0, i, str_prefix2);
        i++;
    }
}



void idPrintSTL(
    FILE                     *fp,
    uint8_t                  *buffer,
    size_t                   buf_len,
    char                     *str_prefix)
{
    int i = 0;
    fbSubTemplateList_t *stl = (fbSubTemplateList_t*)buffer;
    uint8_t *data = NULL;
    char str_prefix2[DT_MAX];

    strcpy(str_prefix2,str_prefix);
    strcat(str_prefix2,"\t");

    idPrint(fp, "\n%s+++ subTemplateList +++\n", str_prefix);

    idPrint(fp, "%s\theader:", str_prefix);
    idPrint(fp, "\tcount: %3d", stl->numElements);
    idPrint(fp, "\ttid: %5d (0x%02x)", stl->tmplID, stl->tmplID);
    idPrint(fp, "\tsemantic: %3d\n", stl->semantic);

    id_tmpl_stats[stl->tmplID] += 1;

    while ((data = FBSTLNEXT(stl, data))) {
        idPrintDataRecord(fp, (fbTemplate_t*)(stl->tmpl), data, 0, i,
                          str_prefix2);
        i++;
    }

}



void idPrintSTML(
    FILE           *fp,
    uint8_t        *buffer,
    size_t          buf_len,
    char            *str_prefix)
{
    fbSubTemplateMultiList_t *stml = (fbSubTemplateMultiList_t*)buffer;
    fbSubTemplateMultiListEntry_t *entry = NULL;
    int i = 0;

    idPrint(fp, "elements: %3d", stml->numElements);
    idPrint(fp, "\tsemantic: %3d\n", stml->semantic);

    while ((entry = FBSTMLNEXTENTRY(stml, entry))) {
        idPrintSTMLEntry(fp, entry, i, str_prefix);
        i++;
    }

}


void idPrintBL(
    FILE             *fp,
    uint8_t          *buffer,
    size_t            buf_len,
    char              *str_prefix)
{

    fbBasicList_t            *bl = (fbBasicList_t*)buffer;
    const fbInfoElement_t    *ie = bl->infoElement;
    uint8_t                  *data = NULL;
    uint8_t                  thing48[6];
    uint64_t                 thing = 0;
    uint32_t                 mpls = 0;
    int                      loop, i;
    char                     ip_buf[40];
    char                     str_prefix2[DT_MAX];

    strcpy(str_prefix2,str_prefix);
    strcat(str_prefix2,"\t");

    if (!ie) {
        idPrint(fp, "count: %3d", bl->numElements);
        if (bl->semantic) {
            idPrint(fp, "\tsemantic: %5d\n", bl->semantic);
        } else {
            idPrint(fp, "\n");
        }
        return;
    }

    i = 0;
    if (bl->semantic) {
        idPrint(fp, "(%d) %s [%d]\n", ie->num, ie->ref.name, bl->semantic);
    } else {
        idPrint(fp, "(%d) %s\n", ie->num, ie->ref.name);
    }

    if (bl->numElements == 0) {
        idPrint(fp, "%s empty list\n", str_prefix2);
    }

    while ((data = FBBLNEXT(bl, data))) {
        idPrint(fp, "%s %d : ", str_prefix2, i);
        i++;

        switch (ie->len) {
          case 1:
            idPrint(fp, "%d\n", *(data));
            break;
          case 2:
            idPrint(fp, "%d\n", *((uint16_t *)(data)));
            break;
          case 3:
            memcpy(&mpls, data, 3);
            idPrint(fp, "%u\n", mpls);
            break;
          case 4:
            if (ie->type == FB_IP4_ADDR) {
                mdPrintIP4Address(ip_buf, *((uint32_t *)(data)));
                idPrint(fp, "%s\n", ip_buf);
            } else {
                idPrint(fp, "%u\n", *((uint32_t *)data));
            }
            break;
          case 6:
            memcpy(thing48, data, 6);
            if (ie->type == FB_MAC_ADDR) {
                for (loop = 0; loop < 5; loop++) {
                    idPrint(fp, "%02x:", thing48[loop]);
                }
                idPrint(fp, "%02x\n", thing48[loop]);
            }
            else {
                /* probably padding */
                idPrint(fp, "length: %d\n", ie->len);
            }
            break;
          case 8:
            {
                memcpy(&thing, data, sizeof(uint64_t));
                if (ie->type == FB_DT_MILSEC) {
                    uint64_t secs = thing/1000;
                    struct tm time_tm;
                    gmtime_r((time_t *)(&secs), &time_tm);
                    idPrint(fp, "%04u-%02u-%02u %02u:%02u:%02u\n",
                            time_tm.tm_year+1900, time_tm.tm_mon+1,
                            time_tm.tm_mday, time_tm.tm_hour, time_tm.tm_min,
                            time_tm.tm_sec);
                } else {
                    idPrint(fp, "%"PRIu64"\n", thing);
                }
                break;
            }
          case 16:
            if (ie->type == FB_IP6_ADDR) {
                mdPrintIP6Address(ip_buf, data);
                idPrint(fp, "%s|\n", ip_buf);
                break;
            } /* else - continue through and print length */
          default:
            if (ie->num == FB_IE_SUBTEMPLATE_MULTILIST) {
                idPrintSTML(fp, data, buf_len, str_prefix2);
            } else if (ie->num == FB_IE_SUBTEMPLATE_LIST) {
                idPrintSTL(fp, data, buf_len, str_prefix2);
            } else if (ie->num == FB_IE_BASIC_LIST) {
                idPrintBL(fp, data, buf_len, str_prefix2);
            } else {
                fbVarfield_t *var = (fbVarfield_t *)(data);
                if (ie->type == FB_STRING) {
                    idPrint(fp, "(length: %zu) %.*s\n", var->len,
                            (int)var->len, var->buf);
                } else {
                    idPrint(fp, "length: %zu \n",  var->len);
                }
            }

        }
    }
}




void idPrintDataRecord(
    FILE         *fp,
    fbTemplate_t *tmpl,
    uint8_t      *buffer,
    size_t       buf_len,
    int          rec_count,
    char         *prefix)
{

    tmplContext_t *tc = (void *)fbTemplateGetContext(tmpl);
    fbInfoElement_t *ie = NULL;
    uint16_t buf_walk = 0;
    char ip_buf[40];
    uint8_t thing48[6];
    uint32_t mpls = 0;
    uint64_t thing = 0;
    int i, loop;
    char str_prefix2[DT_MAX];

    strcpy(str_prefix2, prefix);
    strcat(str_prefix2, "\t");

    idPrint(fp, "%s--- data record %d ---\n", prefix, rec_count);
    idPrint(fp, "%sheader:\n", prefix);
    idPrint(fp, "%s\ttid: %5u (0x%02x)", prefix, tc->tid, tc->tid);
    idPrint(fp, "\tfield count: %5u\n", tc->count);
    idPrint(fp, "%sfields:\n", prefix);

    for (i = 0; i < tc->count; i++) {
        ie = fbTemplateGetIndexedIE(tmpl, i);
        idPrint(fp, "%s\t(%d)%*s %30s \t : \t", prefix, ie->num,
                ((ie->num < 100)
                 ? ((ie->num < 10) ? 4 : 3)
                 : ((ie->num < 1000) ? 2 : (ie->num < 10000))), "",
                ie->ref.canon->ref.name);

        /* if padding, print length and continue */
        if (ie->num == 210) {
            idPrint(fp, "length: %d\n", ie->len);
            buf_walk += ie->len;
            continue;
        }

        switch (ie->len) {
          case 1:
            idPrint(fp, "%d\n", *(buffer + buf_walk));
            buf_walk++;
            break;
          case 2:
            idPrint(fp, "%d\n", *((uint16_t *)(buffer + buf_walk)));
            buf_walk += 2;
            break;
          case 4:
            if (ie->type == FB_IP4_ADDR) {
                mdPrintIP4Address(ip_buf, *((uint32_t *)(buffer+buf_walk)));
                idPrint(fp, "%s\n", ip_buf);
            } else {
                idPrint(fp, "%u\n", *((uint32_t *)(buffer + buf_walk)));
            }
            buf_walk += 4;
            break;
          case 3:
            memcpy(&mpls, buffer+buf_walk, 3);
            idPrint(fp, "%u\n", mpls);
            buf_walk += 3;
            break;
          case 6:
            memcpy(thing48, buffer+buf_walk, 6);
            if (ie->type == FB_MAC_ADDR) {
                for (loop = 0; loop < 5; loop++) {
                    idPrint(fp, "%02x:", thing48[loop]);
                }
                idPrint(fp, "%02x\n", thing48[loop]);
            }
            else {
                /* probably padding */
                idPrint(fp, "length: %d\n", ie->len);
            }
            buf_walk += 6;
            break;
          case 8:
            {
                memcpy(&thing, buffer+buf_walk, sizeof(uint64_t));
                if (ie->type == FB_DT_MILSEC) {
                    uint64_t secs = thing/1000;
                    struct tm time_tm;
                    gmtime_r((time_t *)(&secs), &time_tm);
                    idPrint(fp, "%04u-%02u-%02u %02u:%02u:%02u\n",
                            time_tm.tm_year+1900, time_tm.tm_mon+1, time_tm.tm_mday,
                            time_tm.tm_hour, time_tm.tm_min, time_tm.tm_sec);
                } else {
                    idPrint(fp, "%"PRIu64"\n", thing);
                }
                buf_walk += 8;
                break;
            }
          case 16:
            if (ie->type == FB_IP6_ADDR) {
                mdPrintIP6Address(ip_buf, buffer+buf_walk);
                idPrint(fp, "%s\n", ip_buf);
            } else {
                idPrint(fp, "length: %d\n", ie->len);
            }
            buf_walk += 16;
            break;
            /* padding situations */
          case 65535:
            if (ie->num == FB_IE_SUBTEMPLATE_MULTILIST) {
                idPrintSTML(fp, buffer + buf_walk, buf_len, str_prefix2);
                fbSubTemplateMultiListClear((fbSubTemplateMultiList_t *)(buffer+buf_walk));
                buf_walk += sizeof(fbSubTemplateMultiList_t);
            } else if (ie->num == FB_IE_SUBTEMPLATE_LIST) {
                idPrintSTL(fp, buffer+buf_walk, buf_len, str_prefix2);
                fbSubTemplateListClear((fbSubTemplateList_t *)(buffer+buf_walk));
                buf_walk += sizeof(fbSubTemplateList_t);
            } else if (ie->num == FB_IE_BASIC_LIST) {
                idPrintBL(fp, buffer+buf_walk, buf_len, str_prefix2);
                fbBasicListClear((fbBasicList_t *)(buffer+buf_walk));
                buf_walk += sizeof(fbBasicList_t);
            } else {
                fbVarfield_t *var = (fbVarfield_t *)(buffer+buf_walk);
                if (ie->type == FB_STRING) {
                    idPrint(fp, "(length: %zu) %.*s\n", var->len,
                            (int)var->len, var->buf);
                } else {
                    idPrint(fp, "length: %zu\n",  var->len);
                }
                buf_walk += sizeof(fbVarfield_t);
            }
            break;
          default:
            idPrint(fp, "length: %d\n", ie->len);
            buf_walk += ie->len;
        }
    }
}
