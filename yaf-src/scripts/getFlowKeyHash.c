/**
 ** @file getFlowKeyHash.c
 *
 * This program determines the filename for a given flow
 * when using the --pcap-per-flow option with YAF.
 * Given IPs, ports, protocol, vlan, and start time -
 * this program will give the filename of the pcap
 * for the particular flow.  This uses YAF's flow key hash
 * function to calculate the hash, and given the time
 * date can calculate which directory the file resides in.
 *
 * the pcap-per-flow option writes a pcap file for each
 * flow it processes, in the file directory given to --pcap.
 * Based on the last 3 digits of the flow's start time
 * milliseconds, the flow key hash, and the flow's start
 * time, you can find the pcap file which contains the entire
 * flow.
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2018 Carnegie Mellon University.
 ** All Rights Reserved.
 **
 ** ------------------------------------------------------------------------
 ** Author: Emily Sarneso <ecoff@cert.org>
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the YAF system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU Public License (GPL) Rights pursuant to Version 2, June 1991
 ** Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
 **
 ** NO WARRANTY
 **
 ** ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
 ** PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
 ** PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
 ** "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
 ** KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
 ** MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
 ** OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
 ** SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
 ** TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
 ** WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
 ** LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
 ** CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
 ** CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
 ** DELIVERABLES UNDER THIS LICENSE.
 **
 ** Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
 ** Mellon University, its trustees, officers, employees, and agents from
 ** all claims or demands made against them (and any related losses,
 ** expenses, or attorney's fees) arising out of, or relating to Licensee's
 ** and/or its sub licensees' negligent use or willful misuse of or
 ** negligent conduct or willful misconduct regarding the Software,
 ** facilities, or other rights or assistance granted by Carnegie Mellon
 ** University under this License, including, but not limited to, any
 ** claims of product liability, personal injury, death, damage to
 ** property, or violation of any laws or regulations.
 **
 ** Carnegie Mellon University Software Engineering Institute authored
 ** documents are sponsored by the U.S. Department of Defense under
 ** Contract FA8721-05-C-0003. Carnegie Mellon University retains
 ** copyrights in all material produced under this contract. The U.S.
 ** Government retains a non-exclusive, royalty-free license to publish or
 ** reproduce these documents, or allow others to do so, for U.S.
 ** Government purposes only pursuant to the copyright license under the
 ** contract clause at 252.227.7013.
 **
 ** @OPENSOURCE_HEADER_END@
 ** ------------------------------------------------------------------------
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <libgen.h>
#include <glib.h>
#include <string.h>
#include <airframe/airutil.h>
#include <fixbuf/public.h>

/* environment variable */
#define YAF_IGNORE_SNMP "YAF_IGNORE_SNMP"

static char * sip = NULL;
static char * dip = NULL;
static char * sip6 = NULL;
static char * dip6 = NULL;
static char * dport = NULL;
static char * sport = NULL;
static char * protocol = NULL;
static char * vlan = NULL;
static char * date = NULL;
static char * user_time = NULL;
static char * input = NULL;
static char * output = "-";
static gboolean ipfix = FALSE;
static gboolean reverse = FALSE;
static gboolean snmp = FALSE;

static GOptionEntry md_core_option[] = {
    {"in", 'i', 0, G_OPTION_ARG_STRING, &input,
     "IPFIX Input Specifier [stdin]", NULL },
    {"out", 'o', 0, G_OPTION_ARG_STRING, &output,
     "Output Specifier [stdout]", NULL },
    {"sip4", 's', 0, G_OPTION_ARG_STRING, &sip,
     "Source IPv4 in form 127.0.0.1. Req.", NULL},
    {"dip4", 'd', 0, G_OPTION_ARG_STRING, &dip,
     "Destination IPv4 in form 127.0.0.1 Req.", NULL},
    {"sip6", 0, 0, G_OPTION_ARG_STRING, &sip6,
     "Source IPv6 in form 2001:48af::1:1", NULL},
    {"dip6", 0, 0, G_OPTION_ARG_STRING, &dip6,
     "Destination IPv6 Address", NULL},
    {"sport", 'S', 0, G_OPTION_ARG_STRING, &sport,
     "Source Port Req.", NULL},
    {"dport", 'D', 0, G_OPTION_ARG_STRING, &dport,
     "Destination Port Req.", NULL},
    {"protocol", 'p', 0, G_OPTION_ARG_STRING, &protocol,
     "Protocol Req.", NULL},
    {"vlan", 'v', 0, G_OPTION_ARG_STRING, &vlan, "vlan [0]", NULL},
    {"date", 'y', 0, G_OPTION_ARG_STRING, &date,
     "DATE form: 2009-01-23 [0]", NULL},
    {"time", 't', 0, G_OPTION_ARG_STRING, &user_time,
     "TIME form: 22:54:23.343 [0]", NULL},
    {"ipfix", 'I', 0, G_OPTION_ARG_NONE, &ipfix,
     "Export IPFIX to stdout [no]", NULL},
    {"reverse", 'R', 0, G_OPTION_ARG_NONE, &reverse,
      "Flip source and destination values to calculate "
     "\n\t\t\treverse flow key hash", NULL},
    {"snmp", 0, 0, G_OPTION_ARG_NONE, &snmp,
     "Ignore the ingressInterface value.", NULL},
    { NULL }
};

static fbInfoElement_t new_info_elements[] = {
    FB_IE_INIT("yafFlowKeyHash", 6841, 106, 4, FB_IE_F_ENDIAN|FB_IE_F_REVERSIBLE),
    FB_IE_NULL
};

static fbInfoElementSpec_t simple_flow[] = {
    { "flowStartMilliseconds",              8, 0 },
    { "flowEndMilliseconds",                8, 0 },
    { "sourceIPv6Address",                  16, 0 },
    { "destinationIPv6Address",             16, 0 },
    { "packetTotalCount",                   8, 0 },
    { "packetDeltaCount",                   8, 0 },
    { "sourceIPv4Address",                  4, 0 },
    { "destinationIPv4Address",             4, 0 },
    { "sourceTransportPort",                2, 0 },
    { "destinationTransportPort",           2, 0 },
    { "ingressInterface",                   4, 0 },
    { "vlanId",                             2, 0 },
    { "protocolIdentifier",                 1, 0 },
    FB_IESPEC_NULL
};


static fbInfoElementSpec_t simple_out_flow[] = {
    { "flowStartMilliseconds",              8, 0 },
    { "flowEndMilliseconds",                8, 0 },
    { "packetTotalCount",                   8, 0 },
    { "yafFlowKeyHash",                     4, 0 },
    { "reverseYafFlowKeyHash",              4, 0 },
    FB_IESPEC_NULL
};

typedef struct simpleFlow_st {
    uint64_t    sms;
    uint64_t    ems;
    uint8_t     sip6[16];
    uint8_t     dip6[16];
    uint64_t    pkt;
    uint64_t    dpkt;
    uint32_t    sip;
    uint32_t    dip;
    uint16_t    sport;
    uint16_t    dport;
    uint32_t    ingress;
    uint16_t    vlan;
    uint8_t     proto;
} simpleFlow_t;

typedef struct simpleOutFlow_st {
    uint64_t    sms;
    uint64_t    ems;
    uint64_t    pkt;
    uint32_t    hash;
    uint32_t    rhash;
} simpleOutFlow_t;


static uint32_t flowKeyHash(
    simpleFlow_t *flow,
    gboolean      rev)
{
    uint32_t key_hash = 0;
    uint32_t *v6p;

    if (rev) {
        if (flow->sip || flow->dip) {
            key_hash = (flow->dport << 16) ^ flow->sport ^
                       (flow->proto << 12) ^ (4 << 4) ^
                       (flow->vlan << 20) ^ flow->dip ^ flow->sip;
        } else {
            v6p = (uint32_t *)flow->dip6;
            key_hash = (flow->dport << 16) ^ flow->sport ^
                       (flow->proto << 12) ^ (6 << 4) ^
                       (flow->vlan << 20) ^ *v6p;
            v6p++;
            key_hash ^= *v6p;
            v6p++;
            key_hash ^= *v6p;
            v6p++;
            key_hash ^= *v6p;
            v6p = (uint32_t *)flow->sip6;
            key_hash ^= *v6p;
            v6p++;
            key_hash ^= *v6p;
            v6p++;
            key_hash ^= *v6p;
            v6p++;
            key_hash ^= *v6p;
        }
    } else {
        if (flow->sip || flow->dip) {
            key_hash = (flow->sport << 16) ^ flow->dport ^
                       (flow->proto << 12) ^ (4 << 4) ^
                       (flow->vlan << 20) ^ flow->sip ^ flow->dip;
        } else {
            v6p = (uint32_t *)flow->sip6;
            key_hash = (flow->sport << 16) ^ flow->dport ^
                       (flow->proto << 12) ^ (6 << 4) ^
                       (flow->vlan << 20) ^ *v6p;
            v6p++;
            key_hash ^= *v6p;
            v6p++;
            key_hash ^= *v6p;
            v6p++;
            key_hash ^= *v6p;
            v6p = (uint32_t *)flow->dip6;
            key_hash ^= *v6p;
            v6p++;
            key_hash ^= *v6p;
            v6p++;
            key_hash ^= *v6p;
            v6p++;
            key_hash ^= *v6p;
        }
    }

    return key_hash;
}


static void printIPAddress(char *ipaddr_buf,
                           uint32_t ip)
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

static void printIP6Address(
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

static uint32_t convertIP4Address(
    char *ipaddr_buf)
{

    uint32_t ip;

    if (inet_aton(ipaddr_buf, (struct in_addr *)&ip) == 0) {
        fprintf(stderr, "Invalid IP Address\n");
        exit(-1);
    }

    return g_ntohl(ip);
}

static void convertIP6Address(
    char      *ipaddr_buf,
    uint8_t   *ip6)
{
    if (inet_pton(AF_INET6, ipaddr_buf, ip6) <= 0) {
        fprintf(stderr, "Invalid IPv6 Address\n");
        exit(-1);
    }
}


static fBuf_t *exportIPFIX(
    char *output,
    GError **err)
{
    fbInfoModel_t *infoModel = NULL;
    fbExporter_t  *exp = NULL;
    fbTemplate_t  *template = NULL;
    fbSession_t   *esession = NULL;
    fBuf_t        *exbuf = NULL;
    int           rc;

    infoModel = fbInfoModelAlloc();

    fbInfoModelAddElementArray(infoModel, new_info_elements);

    esession = fbSessionAlloc(infoModel);

    template = fbTemplateAlloc(infoModel);

    rc = fbTemplateAppendSpecArray(template, simple_out_flow, 0, err);

    if (!rc) {
        return NULL;
    }

    rc = fbSessionAddTemplate(esession, TRUE, 999, template, err);

    if (!rc) {
        return NULL;
    }

    rc = fbSessionAddTemplate(esession, FALSE, 999, template, err);

    if (!rc) {
        return NULL;
    }

    exp = fbExporterAllocFile(output);

    if (!exp) {
        return NULL;
    }

    exbuf = fBufAllocForExport(esession, exp);

    if (!exbuf) {
        return NULL;
    }

    if (!fBufSetInternalTemplate(exbuf, 999, err)) {
        return NULL;
    }

    if (!fBufSetExportTemplate(exbuf, 999, err)) {
        return NULL;
    }

    if (!fbSessionExportTemplates(esession, err)) {
        return NULL;
    }

    return exbuf;

}


static gboolean collectIPFIX(
    char      *input,
    FILE      *fp,
    GError    **err)
{
    fbSession_t *session = NULL;
    fbTemplate_t *template = NULL;
    fbTemplate_t *nt = NULL;
    fBuf_t      *buf = NULL;
    fBuf_t      *exbuf = NULL;
    fbCollector_t *coll = NULL;
    fbInfoModel_t *infoModel = NULL;
    char         ip_buf[40];
    simpleFlow_t    flow;
    simpleOutFlow_t oflow;
    size_t       len;
    int          rc;
    int          ecount = 0;
    gboolean     hdr = TRUE;
    uint16_t     tid;
    char         c = ' ';

    infoModel = fbInfoModelAlloc();

    template = fbTemplateAlloc(infoModel);

    rc = fbTemplateAppendSpecArray(template, simple_flow, 0, err);
    if (!rc) {
        return FALSE;
    }

    session = fbSessionAlloc(infoModel);
    rc = fbSessionAddTemplate(session, TRUE, 999, template, err);
    if (!rc) {
        return FALSE;
    }

    coll = fbCollectorAllocFile(NULL, input, err);
    if (!coll) {
        return FALSE;
    }

    buf = fBufAllocForCollection(session, coll);

    rc = fBufSetInternalTemplate(buf, 999, err);
    if (!rc) {
        return FALSE;
    }

    if (ipfix) {
        exbuf = exportIPFIX(output, err);
        if (!exbuf) {
            return FALSE;
        }
    }

    len = sizeof(flow);

    while (1) {
        nt = fBufNextCollectionTemplate(buf, &tid, err);
        if (nt) {
            if (fbTemplateGetOptionsScope(nt)) {
                rc = fBufNext(buf, (uint8_t *)&flow, &len, err);
                if (!rc) goto err;
                continue;
            }
        } else goto err;

        rc = fBufNext(buf, (uint8_t *)&flow, &len, err);
        if (!rc) goto err;

        if (hdr && !ipfix) {
            /* if the first record is v6, print the v6 header */
            if (flow.sip) {
                fprintf(fp, "%12csIP|%12cdIP|sPort|dPort|pro|%cvlan|"
                        "%6chash|%18cms\n", c, c, c, c, c);
            } else {
                fprintf(fp, "%37csIP|%37cdIP|sPort|dPort|pro|%cvlan|"
                            "%6chash|%18cms\n", c, c, c, c, c);
            }
            hdr = FALSE;
        }

        if (flow.ingress && !flow.vlan) {
            flow.vlan = flow.ingress;
        }

        if (snmp) {
            flow.vlan = 0;
        }

        if (ipfix) {
            if (ecount >= 2) {
                /* only export first 2 */
                continue;
            }

            oflow.sms = flow.sms;
            oflow.ems = flow.ems;
            oflow.hash = flowKeyHash(&flow, FALSE);
            if (reverse) {
                oflow.rhash = flowKeyHash(&flow, TRUE);
            } else { oflow.rhash = 0; }

            if (flow.pkt) oflow.pkt = flow.pkt;
            else oflow.pkt = flow.dpkt;

            rc = fBufAppend(exbuf, (uint8_t *)&oflow, sizeof(oflow), err);
            if (!rc) goto err;

            ecount++;

            continue;
        }

        if (flow.sip || flow.dip) {
            printIPAddress(ip_buf, flow.sip);
            fprintf(fp, "%15s|", ip_buf);
            printIPAddress(ip_buf, flow.dip);
            fprintf(fp, "%15s|", ip_buf);
        } else {
            printIP6Address(ip_buf, flow.sip6);
            fprintf(fp, "%40s|", ip_buf);
            printIP6Address(ip_buf, flow.dip6);
            fprintf(fp, "%40s|", ip_buf);
        }

        fprintf(fp, "%5d|%5d|%3d|%5d|%10u|%20"PRIu64"\n",
                flow.sport, flow.dport, flow.proto, flow.vlan,
                flowKeyHash(&flow, reverse), flow.sms);
        continue;

      err:
        if (ipfix) {
            fBufEmit(exbuf, err);
            fBufFree(exbuf);
            fbInfoModelFree(infoModel);
        }
        if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) {
            g_clear_error(err);
            continue;
        } else {
            fBufFree(buf);
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOF)) {
                g_clear_error(err);
                return TRUE;
            }
            return FALSE;
        }
    }

    return TRUE;
}





/**
 * main
 *
 */
int
main (int argc, char *argv[]) {

    GOptionContext *ctx = NULL;
    GError *err = NULL;
    simpleFlow_t flow;
    simpleOutFlow_t oflow;
    uint32_t year, month, day, hour, sec, min, ms;
    time_t epoch_ms;
    gchar **split;
    uint32_t key_hash = 0;
    char c = ' ';
    FILE *fp = NULL;
    fBuf_t *buf = NULL;

    ctx = g_option_context_new(" - getFlowKeyHash Options");

    g_option_context_add_main_entries(ctx, md_core_option, NULL);

    g_option_context_set_help_enabled(ctx, TRUE);

    if (!g_option_context_parse(ctx, &argc, &argv, &err)) {
        fprintf(stderr, "option parsing failed: %s\n", err->message);
        exit(-1);
    }

    memset(&flow, 0, sizeof(simpleFlow_t));

    if (((!sip && !sip6) || (!dip && !dip6)) && !input) {
        /* assume stdin */
        input = g_strdup("-");
    }

    /* only open output file if writing text */
    if (output && !ipfix) {
        if (strlen(output) == 1 && output[0] == '-') {
            fp = stdout;
        } else {
            fp = fopen(output, "w");
            if (fp == NULL) {
                fprintf(stderr, "Can not open output file %s\n", output);
                exit(-1);
            }
        }
    } else {
        if (!ipfix) {
            fp = stdout;
        }
    }

    if (!vlan && !snmp) {
        const char *env2 = getenv(YAF_IGNORE_SNMP);
        if (env2) {
            if (env2[0] == '1') {
                snmp = TRUE;
            }
        }
    }

    if (input) {
        if (strlen(input) == 1 && input[0] == '-') {
            if (isatty(fileno(stdin))) {
                fprintf(stderr, "Refusing to read from terminal on stdin\n");
                exit(1);
            }

        }
        if (!collectIPFIX(input, fp, &err)) {
            fprintf(stderr, "Error Processing IPFIX %s\n", err->message);
            exit(-1);
        }
        goto end;
    }


    if (sip) {
        flow.sip = convertIP4Address(sip);
    }
    if (dip) {
        flow.dip = convertIP4Address(dip);
    }
    if (sip6) {
        convertIP6Address(sip6, flow.sip6);
    }
    if (dip6) {
        convertIP6Address(dip6, flow.dip6);
    }
    if (sport) {
        flow.sport = atoi(sport);
    }
    if (dport) {
        flow.dport = atoi(dport);
    }
    if (protocol) {
        flow.proto = atoi(protocol);
    }
    if (vlan) {
        flow.vlan = atoi(vlan);
    }

    if (ipfix) {
        key_hash = flowKeyHash(&flow, FALSE);
    } else {
        key_hash = flowKeyHash(&flow, reverse);
    }

    if (date && user_time) {
        split = g_strsplit(date, "-", -1);
        if (split[0]) {
            year = atoi(split[0]);
        } else {
            fprintf(stderr, "Invalid Date. Correct Format 2012-03-07\n");
            exit(-1);
        }
        if (split[1]) {
            month = atoi(split[1]);
        } else {
            fprintf(stderr, "Invalid Date. Correct Format 2012-03-07\n");
            exit(-1);
        }
        if (split[2]) {
            day = atoi(split[2]);
        } else {
            fprintf(stderr, "Invalid Date. Correct Format 2012-03-07\n");
            exit(-1);
        }

        g_strfreev(split);

        split = g_strsplit(user_time, ":", -1);
        if (split[0]) {
            hour = atoi(split[0]);
        } else {
            fprintf(stderr, "Invalid Time. Correct Format 07:21:33.345\n");
            exit(-1);
        }

        if (split[1]) {
            min = atoi(split[1]);
        } else {
            fprintf(stderr, "Invalid Time. Correct Format 07:21:33.345\n");
            exit(-1);
        }

        if (split[2]) {
            sec = atoi(split[2]);
        } else {
            fprintf(stderr, "Invalid Time. Correct Format 07:21:33.345\n");
            exit(-1);
        }

        g_strfreev(split);

        split = g_strsplit(user_time, ".", -1);
        if (split[1]) {
            ms = atoi(split[1]);
        } else {
            ms = 0;
            fprintf(stderr, "Missing milliseconds.  "
                    "Milliseconds determines file directory.\n");
        }

        epoch_ms = air_time_gm(year, month, day, hour, min, sec);

        if (ipfix) {
            buf = exportIPFIX(output, &err);
            if (!buf) {
                fprintf(stderr, "Error exporting IPFIX: %s\n", err->message);
                g_clear_error(&err);
                exit(-1);
            }
            oflow.sms = (epoch_ms * 1000) + ms;
            oflow.hash = key_hash;
            oflow.pkt = 0;
            if (reverse) {
                oflow.rhash = flowKeyHash(&flow, TRUE);
            }

            if (!fBufAppend(buf, (uint8_t *)&oflow, sizeof(oflow), &err)) {
                fprintf(stderr, "Error appending buffer: %s\n", err->message);
                g_clear_error(&err);
                fBufFree(buf);
                exit(-1);
            }

            fBufEmit(buf, &err);
            fBufFree(buf);
            goto end;
        }

        if (sip || dip) {
            fprintf(fp, "%12csIP|%12cdIP|sPort|dPort|pro|%cvlan|"
                    "%6chash|%18cms\n", c, c, c, c, c);
            fprintf(fp, "%15s|", sip);
            fprintf(fp, "%15s|", dip);
        } else {
            fprintf(fp, "%37csIP|%37cdIP|sPort|dPort|pro|%cvlan|"
                    "%6chash|%18cms\n", c, c, c, c, c);

            fprintf(fp, "%40s|", sip6);
            fprintf(fp, "%40s|", dip6);
        }

        fprintf(fp, "%5d|%5d|%3d|%5d|%10u|%17llu%03d\n",
                flow.sport, flow.dport, flow.proto, flow.vlan,
                key_hash, (long long unsigned int)epoch_ms, ms);
        fprintf(fp, "\nFILE PATH: %03d/%u-%d%d%d%d%d%d_0.pcap\n",
                ms, key_hash, year, month, day, hour, min, sec);

        g_strfreev(split);

    } else {

        if (ipfix) {
            buf = exportIPFIX(output, &err);
            if (!buf) {
                fprintf(stderr, "Error exporting IPFIX: %s\n", err->message);
                g_clear_error(&err);
                exit(-1);
            }
            oflow.sms = 0;
            oflow.hash = key_hash;
            oflow.pkt = 0;
            if (reverse) {
                oflow.rhash = flowKeyHash(&flow, TRUE);
            }

            if (!fBufAppend(buf, (uint8_t *)&oflow, sizeof(oflow), &err)) {
                fprintf(stderr, "Error appending buffer: %s\n", err->message);
                g_clear_error(&err);
                fBufFree(buf);
                exit(-1);
            }

            fBufEmit(buf, &err);
            fBufFree(buf);
            goto end;
        }

        if (sip || dip) {
            fprintf(fp, "%12csIP|%12cdIP|sPort|dPort|pro|%cvlan|"
                    "%6chash\n", c, c, c, c);
            fprintf(fp, "%15s|", sip);
            fprintf(fp, "%15s|", dip);
        } else {
            fprintf(fp, "%37csIP|%37cdIP|sPort|dPort|pro|%cvlan|"
                    "%6chash\n", c, c, c, c);
            fprintf(fp, "%40s|", sip6);
            fprintf(fp, "%40s|", dip6);
        }
        fprintf(fp, "%5d|%5d|%3d|%5d|%10u\n",
                flow.sport, flow.dport, flow.proto, flow.vlan,
                key_hash);
    }

  end:

    g_option_context_free(ctx);

    return 0;
}
