/**
 ** yaf.c
 ** Yet Another Flow generator
 * **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2016 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell
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
 */

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <airframe/logconfig.h>
#include <airframe/privconfig.h>
#include <airframe/airutil.h>
#include <airframe/airopt.h>
#include <yaf/yafcore.h>
#include <yaf/yaftab.h>
#include <yaf/yafrag.h>

#include "yafcap.h"
#include "yafstat.h"
#include "yafctx.h"
#if YAF_ENABLE_DAG
#include "yafdag.h"
#endif
#if YAF_ENABLE_NAPATECH
#include "yafpcapx.h"
#endif
#if YAF_ENABLE_NETRONOME
#include "yafnfe.h"
#endif
#if YAF_ENABLE_PFRING
#include "yafpfring.h"
#endif
#if YAF_ENABLE_APPLABEL
#include "yafapplabel.h"
#endif
#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif
#if YAF_ENABLE_P0F
#include "applabel/p0f/yfp0f.h"
#endif
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* I/O configuration */
static yfConfig_t    yaf_config = YF_CONFIG_INIT;
static char          *yaf_config_file = NULL;
static int           yaf_opt_rotate = 0;
static int           yaf_opt_stats = 300;
static gboolean      yaf_opt_no_tombstone = FALSE;
static uint16_t      yaf_opt_configured_id = 0;
static uint64_t      yaf_rotate_ms = 0;
static gboolean      yaf_opt_caplist_mode = FALSE;
static char          *yaf_opt_ipfix_transport = NULL;
static gboolean      yaf_opt_ipfix_tls = FALSE;
static char          *yaf_pcap_meta_file = NULL;
static gboolean      yaf_index_pcap = FALSE;
static gboolean      yaf_daemon = FALSE;
static char          *yaf_pidfile = NULL;
static char          *yaf_tmp_file = NULL;
static int           yaf_opt_udp_temp_timeout = 600;
static int           yaf_live_type = 0;
static gboolean      yaf_opt_promisc = FALSE;
#ifdef HAVE_SPREAD
/* spread config options */
static char         *yaf_opt_spread_group = 0;
static char         *yaf_opt_spread_groupby = 0;
#endif

/* GOption managed flow table options */
static int          yaf_opt_idle = 300;
static int          yaf_opt_active = 1800;
static int          yaf_opt_max_flows = 0;
static int          yaf_opt_max_payload = 0;
static int          yaf_opt_payload_export = 0;
static gboolean     yaf_opt_payload_export_on = FALSE;
static gboolean     yaf_opt_applabel_mode = FALSE;
static gboolean     yaf_opt_force_read_all = FALSE;

#if YAF_ENABLE_APPLABEL
static char       *yaf_opt_applabel_rules = NULL;
#endif
static gboolean     yaf_opt_ndpi = FALSE;
static char         *yaf_ndpi_proto_file = NULL;
static gboolean     yaf_opt_entropy_mode = FALSE;
static gboolean     yaf_opt_uniflow_mode = FALSE;
static uint16_t     yaf_opt_udp_uniflow_port = 0;
static gboolean     yaf_opt_silk_mode = FALSE;
static gboolean     yaf_opt_p0fprint_mode = FALSE;
#if YAF_ENABLE_P0F
static char       *yaf_opt_p0f_fingerprints = NULL;
#endif
static gboolean     yaf_opt_fpExport_mode = FALSE;
static gboolean     yaf_opt_udp_max_payload = FALSE;
static gboolean     yaf_opt_extra_stats_mode = FALSE;
static int          yaf_opt_max_pcap = 25;
static int          yaf_opt_pcap_timer = 0;
static char         *yaf_hash_search = NULL;
static char         *yaf_stime_search = NULL;
static int          yaf_opt_ingress_int = 0;
static int          yaf_opt_egress_int = 0;
static gboolean     yaf_novlan_in_key;
/* GOption managed fragment table options */
static int          yaf_opt_max_frags = 0;
static gboolean     yaf_opt_nofrag = FALSE;

/* GOption managed decoder options and derived decoder config */
static gboolean     yaf_opt_ip4_mode = FALSE;
static gboolean     yaf_opt_ip6_mode = FALSE;
static uint16_t     yaf_reqtype;
static gboolean     yaf_opt_gre_mode = FALSE;
static gboolean     yaf_opt_mac_mode = FALSE;

/* GOption managed core export options */
static gboolean        yaf_opt_ip6map_mode = FALSE;

#ifdef YAF_ENABLE_HOOKS
static char          *pluginName = NULL;
static char          *pluginOpts = NULL;
static char          *pluginConf = NULL;
static gboolean      hooks_initialized = FALSE;
#endif
/* array of configuration information that is passed to flow table */
static void          *yfctx[YAF_MAX_HOOKS];

/* global quit flag */
int    yaf_quit = 0;

/* Runtime functions */

typedef void *(*yfLiveOpen_fn)(const char *, int, int *, GError **);
static yfLiveOpen_fn yaf_liveopen_fn = NULL;

typedef gboolean (*yfLoop_fn)(yfContext_t *);
static yfLoop_fn yaf_loop_fn = NULL;

typedef void (*yfClose_fn)(void *);
static yfClose_fn yaf_close_fn = NULL;

#define THE_LAME_80COL_FORMATTER_STRING "\n\t\t\t\t"

/*local functions */
#if YAF_ENABLE_HOOKS
static void pluginOptParse(GError **err);
#endif
/* Local derived configutation */

AirOptionEntry yaf_optent_core[] = {
    AF_OPTION( "in", 'i', 0, AF_OPT_TYPE_STRING, &yaf_config.inspec,
               THE_LAME_80COL_FORMATTER_STRING"Input (file, - for stdin; "
               "interface)", "inspec"),
    AF_OPTION( "out", 'o', 0, AF_OPT_TYPE_STRING, &yaf_config.outspec,
               THE_LAME_80COL_FORMATTER_STRING"Output (file, - for stdout; "
               "file prefix,"THE_LAME_80COL_FORMATTER_STRING"address)",
               "outspec"),
    AF_OPTION( "config", 'c', 0, AF_OPT_TYPE_STRING, &yaf_config_file,
               THE_LAME_80COL_FORMATTER_STRING"YAF configuration filename",
               "file"),
#ifdef HAVE_SPREAD
    AF_OPTION( "group", 'g', 0, AF_OPT_TYPE_STRING, &yaf_opt_spread_group,
               THE_LAME_80COL_FORMATTER_STRING"Spread group name (comma "
               "seperated list). "THE_LAME_80COL_FORMATTER_STRING
               "For groupby: comma separated "
               THE_LAME_80COL_FORMATTER_STRING"group_name:value,[group_name:"
               "value,...]", "group-name"),
    AF_OPTION( "groupby", (char)0, 0, AF_OPT_TYPE_STRING,
               &yaf_opt_spread_groupby, THE_LAME_80COL_FORMATTER_STRING
               "<port, vlan, applabel, protocol, version>"
               THE_LAME_80COL_FORMATTER_STRING"(Must be used "
               "with group and group must have"THE_LAME_80COL_FORMATTER_STRING
               "values to groupby", "type"),
#endif
    AF_OPTION( "live", 'P', 0, AF_OPT_TYPE_STRING, &yaf_config.livetype,
               THE_LAME_80COL_FORMATTER_STRING"Capture from interface in -i; "
               "type is "THE_LAME_80COL_FORMATTER_STRING"[pcap], dag, "
               "napatech, netronome, pfring, zc", "type"),
    AF_OPTION( "filter", 'F', 0, AF_OPT_TYPE_STRING, &yaf_config.bpf_expr,
               THE_LAME_80COL_FORMATTER_STRING"BPF filtering expression",
               "expression"),
    AF_OPTION( "caplist", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_caplist_mode,
               THE_LAME_80COL_FORMATTER_STRING"Read ordered list of input "
               "files from "THE_LAME_80COL_FORMATTER_STRING"file in -i", NULL),
#if YAF_ENABLE_ZLIB
    AF_OPTION( "decompress", (char)0, 0, AF_OPT_TYPE_STRING, &yaf_tmp_file,
               THE_LAME_80COL_FORMATTER_STRING"Decompression file directory",
                "dir"),
#endif
    AF_OPTION( "rotate", 'R', 0, AF_OPT_TYPE_INT, &yaf_opt_rotate,
               THE_LAME_80COL_FORMATTER_STRING"Rotate output files every n "
               "seconds ", "sec" ),
    AF_OPTION( "lock", 'k', 0, AF_OPT_TYPE_NONE, &yaf_config.lockmode,
               THE_LAME_80COL_FORMATTER_STRING"Use exclusive .lock files on "
               "output for"THE_LAME_80COL_FORMATTER_STRING"concurrency", NULL),
    AF_OPTION( "daemonize", 'd', 0, AF_OPT_TYPE_NONE, &yaf_daemon,
               THE_LAME_80COL_FORMATTER_STRING"Daemonize yaf.", NULL),
    AF_OPTION( "pidfile", (char)0, 0, AF_OPT_TYPE_STRING, &yaf_pidfile,
               THE_LAME_80COL_FORMATTER_STRING"Complete path to the process ID "
               "file.", NULL),
    AF_OPTION( "promisc-off", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_promisc,
               THE_LAME_80COL_FORMATTER_STRING"Do not put the interface in "
               "promiscuous mode.", NULL),
    AF_OPTION( "noerror", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_config.noerror,
               THE_LAME_80COL_FORMATTER_STRING"Do not error out on single "
               "PCAP file issue"THE_LAME_80COL_FORMATTER_STRING" with "
               "multiple inputs", NULL ),
#ifdef HAVE_SPREAD
    AF_OPTION("ipfix", (char)0, 0,AF_OPT_TYPE_STRING, &yaf_opt_ipfix_transport,
              THE_LAME_80COL_FORMATTER_STRING"Export via IPFIX (tcp, udp, "
              "sctp, spread) to CP "THE_LAME_80COL_FORMATTER_STRING"at -o",
              "protocol" ),
#else
    AF_OPTION("ipfix",(char)0, 0, AF_OPT_TYPE_STRING, &yaf_opt_ipfix_transport,
              THE_LAME_80COL_FORMATTER_STRING"Export via IPFIX (tcp, udp, "
              "sctp) to CP at -o","protocol"),
#endif
    AF_OPTION_END
};

AirOptionEntry yaf_optent_dec[] = {
    AF_OPTION( "no-frag", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_nofrag,
               THE_LAME_80COL_FORMATTER_STRING"Disable IP fragment reassembly",
               NULL ),
    AF_OPTION( "max-frags", (char)0, 0, AF_OPT_TYPE_INT, &yaf_opt_max_frags,
               THE_LAME_80COL_FORMATTER_STRING"Maximum size of fragment table "
               "[0]", "fragments" ),
    AF_OPTION( "ip4-only", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_ip4_mode,
               THE_LAME_80COL_FORMATTER_STRING"Only process IPv4 packets",
               NULL ),
    AF_OPTION( "ip6-only", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_ip6_mode,
               THE_LAME_80COL_FORMATTER_STRING"Only process IPv6 packets",
               NULL ),
    AF_OPTION( "gre-decode", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_gre_mode,
               THE_LAME_80COL_FORMATTER_STRING"Decode GRE encapsulated "
               "packets", NULL ),
    AF_OPTION_END
};

AirOptionEntry yaf_optent_flow[] = {
    AF_OPTION( "idle-timeout", 'I', 0, AF_OPT_TYPE_INT, &yaf_opt_idle,
               THE_LAME_80COL_FORMATTER_STRING"Idle flow timeout [300, 5m]",
               "sec" ),
    AF_OPTION( "active-timeout", 'A', 0, AF_OPT_TYPE_INT, &yaf_opt_active,
               THE_LAME_80COL_FORMATTER_STRING"Active flow timeout [1800, "
               "30m]", "sec" ),
    AF_OPTION( "max-flows", (char)0, 0, AF_OPT_TYPE_INT, &yaf_opt_max_flows,
               THE_LAME_80COL_FORMATTER_STRING"Maximum size of flow table [0]",
               "flows" ),
    AF_OPTION( "udp-temp-timeout", (char)0, 0, AF_OPT_TYPE_INT,
               &yaf_opt_udp_temp_timeout,
               THE_LAME_80COL_FORMATTER_STRING"UDP template timeout period "
               "[600 sec, 10 m]", "sec"),
    AF_OPTION( "force-read-all", (char)0, 0, AF_OPT_TYPE_NONE,
               &yaf_opt_force_read_all, THE_LAME_80COL_FORMATTER_STRING"Force "
               "read of any out of sequence packets", NULL),
    AF_OPTION( "no-vlan-in-key", (char)0, 0, AF_OPT_TYPE_NONE,
               &yaf_novlan_in_key, THE_LAME_80COL_FORMATTER_STRING"Do not use "
               "the VLAN in the flow key hash calculation", NULL),
    AF_OPTION_END
};

AirOptionEntry yaf_optent_exp[] = {
    AF_OPTION( "no-output", (char)0, 0, AF_OPT_TYPE_NONE,&yaf_config.no_output,
               THE_LAME_80COL_FORMATTER_STRING"Turn off IPFIX export", NULL),
    AF_OPTION( "no-stats", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_config.nostats,
               THE_LAME_80COL_FORMATTER_STRING"Turn off stats option records "
               "IPFIX export", NULL),
    AF_OPTION( "stats", (char)0, 0, AF_OPT_TYPE_INT, &yaf_opt_stats,
               THE_LAME_80COL_FORMATTER_STRING"Export yaf process stats "
               "every n seconds "THE_LAME_80COL_FORMATTER_STRING
               "[300 (5 min)]", NULL),
    AF_OPTION( "no-tombstone", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_no_tombstone,
               THE_LAME_80COL_FORMATTER_STRING"Turn off tombstone records "
               "IPFIX export", NULL),
    AF_OPTION( "tombstone-configured-id", (char)0, 0, AF_OPT_TYPE_INT, &yaf_opt_configured_id,
               THE_LAME_80COL_FORMATTER_STRING"Set tombstone record's 16 bit "
               "configured identifier.", NULL),
    AF_OPTION( "silk", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_silk_mode,
               THE_LAME_80COL_FORMATTER_STRING"Clamp octets to 32 bits, "
               "note continued in"THE_LAME_80COL_FORMATTER_STRING
               "flowEndReason.  Now Exports TCP Fields within "
               THE_LAME_80COL_FORMATTER_STRING"flow record instead of "
               "subTemplateMultiList.", NULL ),
    AF_OPTION( "mac", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_mac_mode,
               THE_LAME_80COL_FORMATTER_STRING"Export MAC-layer information",
               NULL ),
    AF_OPTION( "uniflow", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_uniflow_mode,
               THE_LAME_80COL_FORMATTER_STRING"Write uniflows for "
               "compatibility", NULL ),
    AF_OPTION( "udp-uniflow", 0, 0, AF_OPT_TYPE_INT, &yaf_opt_udp_uniflow_port,
               THE_LAME_80COL_FORMATTER_STRING"Exports a single UDP packet "
               "as a flow on the"THE_LAME_80COL_FORMATTER_STRING"given port. "
               "Use 1 for all ports [0]", "port" ),
    AF_OPTION( "force-ip6-export", (char)0, 0, AF_OPT_TYPE_NONE,
               &yaf_opt_ip6map_mode, THE_LAME_80COL_FORMATTER_STRING"Export "
               "all IPv4 addresses as IPv6 in "THE_LAME_80COL_FORMATTER_STRING
               "::FFFF/96 [N/A]", NULL ),
    AF_OPTION( "observation-domain", (char)0, 0, AF_OPT_TYPE_INT,
               &yaf_config.odid, THE_LAME_80COL_FORMATTER_STRING
               "Set observationDomainID on exported"
               THE_LAME_80COL_FORMATTER_STRING"messages [0]", "odId" ),
    AF_OPTION( "flow-stats", (char)0, 0, AF_OPT_TYPE_NONE,
               &yaf_opt_extra_stats_mode, THE_LAME_80COL_FORMATTER_STRING
               "Export extra flow attributes and statistics ", NULL),
    AF_OPTION( "delta", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_config.deltaMode,
               THE_LAME_80COL_FORMATTER_STRING"Export packet and octet counts "
               "using delta "THE_LAME_80COL_FORMATTER_STRING
               "information elements", NULL),
    AF_OPTION ("ingress", (char)0, 0, AF_OPT_TYPE_INT, &yaf_opt_ingress_int,
               THE_LAME_80COL_FORMATTER_STRING"Set ingressInterface field in "
               "flow template", NULL),
    AF_OPTION( "egress", (char)0, 0, AF_OPT_TYPE_INT, &yaf_opt_egress_int,
               THE_LAME_80COL_FORMATTER_STRING"Set egressInterface field in "
               "flow template", NULL),
#if YAF_ENABLE_METADATA_EXPORT
    AF_OPTION( "template-info", (char)0, 0, AF_OPT_TYPE_NONE,
               &yaf_config.tmpl_metadata,
               THE_LAME_80COL_FORMATTER_STRING"Export template and information"
               " element metadata before data", NULL),
#endif
#if YAF_ENABLE_DAG_SEPARATE_INTERFACES || YAF_ENABLE_SEPARATE_INTERFACES
    AF_OPTION( "export-interface", (char)0, 0, AF_OPT_TYPE_NONE,
               &yaf_config.exportInterface, THE_LAME_80COL_FORMATTER_STRING
               "Export DAG, Napatech, or Netronome interface numbers in "
               "export records", NULL ),
#endif
    AF_OPTION_END
};

AirOptionEntry yaf_optent_ipfix[] = {
    AF_OPTION( "ipfix-port", (char)0, 0, AF_OPT_TYPE_STRING,
               &(yaf_config.connspec.svc), THE_LAME_80COL_FORMATTER_STRING
               "Select IPFIX export port [4739, 4740]", "port" ),
    AF_OPTION( "tls", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_ipfix_tls,
               THE_LAME_80COL_FORMATTER_STRING"Use TLS/DTLS to secure IPFIX "
               "export", NULL ),
    AF_OPTION( "tls-ca", (char)0, 0, AF_OPT_TYPE_STRING,
               &(yaf_config.connspec.ssl_ca_file),
               THE_LAME_80COL_FORMATTER_STRING"Specify TLS Certificate "
               "Authority file", "cafile" ),
    AF_OPTION( "tls-cert", (char)0, 0, AF_OPT_TYPE_STRING,
               &(yaf_config.connspec.ssl_cert_file),
               THE_LAME_80COL_FORMATTER_STRING"Specify TLS Certificate file",
               "certfile" ),
    AF_OPTION( "tls-key", (char)0, 0, AF_OPT_TYPE_STRING,
               &(yaf_config.connspec.ssl_key_file),
               THE_LAME_80COL_FORMATTER_STRING"Specify TLS Private Key file",
               "keyfile" ),
    AF_OPTION_END
};

AirOptionEntry yaf_optent_pcap[] = {
    AF_OPTION( "pcap", 'p', 0, AF_OPT_TYPE_STRING, &yaf_config.pcapdir,
               THE_LAME_80COL_FORMATTER_STRING"Directory/File prefix to store "
               THE_LAME_80COL_FORMATTER_STRING"rolling pcap files", "dir"),
    AF_OPTION( "pcap-per-flow", (char)0, 0, AF_OPT_TYPE_NONE,
               &yaf_config.pcap_per_flow,
               THE_LAME_80COL_FORMATTER_STRING"Create a separate pcap file for"
               " each flow"THE_LAME_80COL_FORMATTER_STRING
               "in the --pcap directory", NULL),
    AF_OPTION( "max-pcap", (char)0, 0, AF_OPT_TYPE_INT, &yaf_opt_max_pcap,
               THE_LAME_80COL_FORMATTER_STRING"Max File Size of Pcap File "
               "[25 MB]", "MB"),
    AF_OPTION( "pcap-timer", (char)0, 0, AF_OPT_TYPE_INT,
               &yaf_opt_pcap_timer,
               THE_LAME_80COL_FORMATTER_STRING"Number of seconds for rolling"
               THE_LAME_80COL_FORMATTER_STRING" pcap file [300]", "sec"),
    AF_OPTION( "pcap-meta-file", (char)0, 0, AF_OPT_TYPE_STRING,
               &yaf_pcap_meta_file,
               THE_LAME_80COL_FORMATTER_STRING"Metadata file for rolling pcap "
               THE_LAME_80COL_FORMATTER_STRING"output or indexing input pcap",
               "path"),
    AF_OPTION( "index-pcap", (char)0, 0, AF_OPT_TYPE_NONE,
               &yaf_index_pcap,
               THE_LAME_80COL_FORMATTER_STRING"Index the pcap with offset and "
               THE_LAME_80COL_FORMATTER_STRING"lengths per packet", NULL),
    AF_OPTION( "hash", (char)0, 0, AF_OPT_TYPE_STRING,
               &yaf_hash_search,
               THE_LAME_80COL_FORMATTER_STRING"Create only a PCAP for the "
               THE_LAME_80COL_FORMATTER_STRING"given hash", "hash"),
    AF_OPTION( "stime", (char)0, 0, AF_OPT_TYPE_STRING,
               &yaf_stime_search,
               THE_LAME_80COL_FORMATTER_STRING"Create only a PCAP for the given stime"
               THE_LAME_80COL_FORMATTER_STRING"(--hash must also be present)", "ms"),
    AF_OPTION_END
};


#if YAF_ENABLE_PAYLOAD
AirOptionEntry yaf_optent_payload[] = {
    AF_OPTION( "max-payload", 's', 0, AF_OPT_TYPE_INT, &yaf_opt_max_payload,
               THE_LAME_80COL_FORMATTER_STRING"Maximum payload to capture per "
               "flow [0]", "octets" ),
    AF_OPTION( "export-payload", (char)0, 0, AF_OPT_TYPE_NONE,
               &yaf_opt_payload_export_on, THE_LAME_80COL_FORMATTER_STRING
               "Maximum payload to export per flow direction [0]", NULL),
    AF_OPTION( "udp-payload", (char)0, 0, AF_OPT_TYPE_NONE,
               &yaf_opt_udp_max_payload, THE_LAME_80COL_FORMATTER_STRING
               "Capture maximum payload for udp flow", NULL),
    AF_OPTION ( "max-export", (char)0, 0, AF_OPT_TYPE_INT,
                &yaf_opt_payload_export, THE_LAME_80COL_FORMATTER_STRING
                "Maximum payload to export per flow direction[0]", NULL),
#if YAF_ENABLE_ENTROPY
    AF_OPTION( "entropy", (char)0, 0, AF_OPT_TYPE_NONE, &yaf_opt_entropy_mode,
               THE_LAME_80COL_FORMATTER_STRING"Export Shannon entropy of "
               "captured payload", NULL),
#endif
#if YAF_ENABLE_APPLABEL
    AF_OPTION( "applabel-rules", 0, 0, AF_OPT_TYPE_STRING,
               &yaf_opt_applabel_rules,
               THE_LAME_80COL_FORMATTER_STRING"specify the name of the "
               "application labeler"THE_LAME_80COL_FORMATTER_STRING"rules "
               "file", "file"),
    AF_OPTION("applabel", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_applabel_mode,
              THE_LAME_80COL_FORMATTER_STRING"enable the packet inspection "
              "protocol"THE_LAME_80COL_FORMATTER_STRING"application labeler "
              "engine", NULL ),
#endif
#if YAF_ENABLE_NDPI
    AF_OPTION( "ndpi", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_ndpi,
               THE_LAME_80COL_FORMATTER_STRING"enable nDPI application "
               "labeling.", NULL),
    AF_OPTION( "ndpi-protocol-file", 0, 0, AF_OPT_TYPE_STRING,
               &yaf_ndpi_proto_file, THE_LAME_80COL_FORMATTER_STRING"Specify"
               " protocol file for sub-protocol"THE_LAME_80COL_FORMATTER_STRING
               "and port-based protocol detection", "file"),
#endif
#if YAF_ENABLE_P0F
    AF_OPTION( "p0f-fingerprints", 0, 0, AF_OPT_TYPE_STRING,
               &yaf_opt_p0f_fingerprints,
               THE_LAME_80COL_FORMATTER_STRING"specify the location of the "
               "p0f fingerprint "THE_LAME_80COL_FORMATTER_STRING
               "files", "file"),
    AF_OPTION("p0fprint", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_p0fprint_mode,
              THE_LAME_80COL_FORMATTER_STRING"enable the p0f OS "
              "fingerprinter", NULL ),
#endif
#if YAF_ENABLE_FPEXPORT
    AF_OPTION("fpexport", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_fpExport_mode,
              THE_LAME_80COL_FORMATTER_STRING"enable export of handshake "
              "headers for"THE_LAME_80COL_FORMATTER_STRING"external OS "
              "fingerprinters", NULL ),
#endif
    AF_OPTION_END
};
#endif

#ifdef YAF_ENABLE_HOOKS
AirOptionEntry yaf_optent_plugin[] = {
    AF_OPTION( "plugin-name", '\0', 0, AF_OPT_TYPE_STRING, &pluginName,
               THE_LAME_80COL_FORMATTER_STRING"load a yaf plugin(s)",
               "libplugin_name[,libplugin_name...]"),
    AF_OPTION( "plugin-opts", '\0', 0, AF_OPT_TYPE_STRING, &pluginOpts,
               THE_LAME_80COL_FORMATTER_STRING"parse options to the "
               "plugin(s)","\"plugin_opts[,plugin_opts...]\""),
    AF_OPTION( "plugin-conf", '\0', 0, AF_OPT_TYPE_STRING, &pluginConf,
               THE_LAME_80COL_FORMATTER_STRING"configuration file for the "
               "plugin(s)", "\"plugin_conf[,plugin_conf...]\""),
    AF_OPTION_END
};
#endif

/**
 * yfVersionString
 *
 * Print version info and info about how YAF was configured
 *
 */
static GString *yfVersionString(
    const char *verNumStr)
{

    GString *resultString;

    resultString = g_string_new("");

    g_string_append_printf(resultString, "%s  Build Configuration:\n",
                           verNumStr);

    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Timezone support:",
#if ENABLE_LOCALTIME
                           "local"
#else
                           "UTC"
#endif
                           );

    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Fixbuf version:",
                           FIXBUF_VERSION);

    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "DAG support:",
#if YAF_ENABLE_DAG
                           "YES"
#else
                           "NO"
#endif
                           );

    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Napatech support:",
#if YAF_ENABLE_NAPATECH
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Netronome support:",
#if YAF_ENABLE_NETRONOME
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "Bivio support:",
#if YAF_ENABLE_BIVIO
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "PFRING support:",
#if YAF_ENABLE_PFRING
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "Compact IPv4 support:",
#if YAF_COMPACT_V4
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Plugin support: ",
#if YAF_ENABLE_HOOKS
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Application Labeling:",
#if YAF_ENABLE_APPLABEL
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Payload Processing Support:",
#if YAF_ENABLE_PAYLOAD
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "Entropy support:",
#if YAF_ENABLE_ENTROPY
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "Fingerprint Export Support:",
#if YAF_ENABLE_FPEXPORT
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "P0F Support:",
#if YAF_ENABLE_P0F
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "Spread Support:",
#if HAVE_SPREAD
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "MPLS Support:",
#if YAF_MPLS
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "Non-IP Support:",
#if YAF_NONIP
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "Separate Interface Support:",
#if YAF_ENABLE_SEPARATE_INTERFACES
                           "YES"
#elif YAF_ENABLE_DAG_SEPARATE_INTERFACES
                           "YES (Dag)"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "nDPI Support:",
#if YAF_ENABLE_NDPI
                           "YES"
#else
                           "NO"
#endif
                           );

    g_string_append_printf(resultString,"    * %-32s  %s\n",
                           "IE Metadata Export:",
#if YAF_ENABLE_METADATA_EXPORT
                           "YES"
#else
                           "NO"
#endif
                           );

    return resultString;
};

#ifdef HAVE_SPREAD
static void groups_from_list( char *list, char ***groups,
                              uint16_t **spreadIndex,
                              uint8_t  *numSpreadGroups)
{
    gchar **sa = g_strsplit( list, ",", -1 );
    int n = 0, x = 0, g = 0, spaces = 0;
    gchar **spread_split = NULL;
    gboolean catch_all_group = FALSE;

    while (sa[n] && *sa[n]) {
        ++n;
    }
    g_debug("Adding Spread Groups: %s", list);

    *groups = g_new0( char *, n+1 );

    *spreadIndex = g_new0(uint16_t, n);

    if (n > 255) {
        g_debug("Spread Max Groups is 255: "
                "List will be contained to 255 Groups");
        n = 255;
    }
    *numSpreadGroups = n;

    n = 0;
    while (sa[n] && *sa[n]) {
        spread_split = g_strsplit(sa[n], ":", -1);
        if (spread_split[x] && *spread_split[x]) {
            while (isspace(*(spread_split[x] + spaces))) {
                /* Remove leading white space */
                spaces++;
            }
            (*groups)[g] = g_strdup(spread_split[x] + spaces);
            x++;
            if (spread_split[x] && *(spread_split[x])) {
                (*spreadIndex)[g] = atoi(spread_split[x]);
            } else {
                (*spreadIndex)[g] = 0;
                catch_all_group = TRUE;
            }
            g++;
        }
        x = 0;
        ++n;
        spaces = 0;
    }

    if (!catch_all_group) {
        g_warning("NO CATCHALL SPREAD GROUP GIVEN - FLOWS WILL BE LOST");
    }

    g_strfreev(spread_split);
    g_strfreev( sa );
}
#endif /* HAVE_SPREAD */


/**
 * yfExit
 *
 * exit handler for YAF
 *
 */

void yfExit() {

    if (yaf_pidfile) {
        unlink(yaf_pidfile);
    }
}

/**
 * yfDaemonize
 *
 * daemonize yaf.  An alternative to using airdaemon which has
 * it's issues.
 *
 */
static void yfDaemonize()
{
    pid_t pid;
    int rv = -1;
    char str[256];
    int fp;

    if (chdir("/") == -1) {
        rv = errno;
        g_warning("Cannot change directory: %s", strerror(rv));
        exit(-1);
    }

    if ((pid = fork()) == -1) {
        rv = errno;
        g_warning("Cannot fork for daemon: %s", strerror(rv));
        exit(-1);
    } else if (pid != 0) {
        g_debug("Forked child %ld.  Parent exiting", (long)pid);
        _exit(EXIT_SUCCESS);
    }

    setsid();

    umask(0022);

    rv = atexit(yfExit);
    if (rv == -1) {
        g_warning("Unable to register function with atexit(): %s",
                  strerror(rv));
        exit(-1);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);

    if (yaf_pidfile) {
        fp = open(yaf_pidfile, O_RDWR|O_CREAT, 0640);
        if (fp < 0) {
            g_warning("Unable to open pid file %s", yaf_pidfile);
            exit(1);
        }
        sprintf(str, "%d\n", getpid());
        if (!write(fp, str, strlen(str))) {
            g_warning("Unable to write pid to file");
        }
    } else {
        g_debug("pid: %d", getpid());
    }

}

/**
 * Lua helper functions
 *
 */
#define yf_lua_getnum(_key_, _ret_)                     \
    lua_getglobal(L, _key_);                            \
    if (!lua_isnil(L, -1)) {                            \
        _ret_= (int)lua_tonumber(L, -1);                \
    }                                                   \
    lua_pop(L, 1);

#define yf_lua_getstr(_key_, _ret_)                     \
    lua_getglobal(L, _key_);                            \
    if (!lua_isnil(L, -1)) {                            \
        _ret_= strdup(lua_tostring(L, -1));             \
    }                                                   \
    lua_pop(L, 1);

#define yf_lua_getbool(_key_, _ret_)                    \
    lua_getglobal(L, _key_);                            \
    if (!lua_isnil(L, -1)) {                            \
        _ret_ = (int)lua_toboolean(L, -1);              \
    }                                                   \
    lua_pop(L, 1);

#define yf_lua_checktablebool(_key_, _val_)             \
    lua_pushstring(L, _key_);                           \
    lua_gettable(L, -2);                                \
    if (!lua_isnil(L, -1)) {                            \
        _val_ = (int)lua_toboolean(L, -1);              \
    }                                                   \
    lua_pop(L, 1);

#define yf_lua_gettableint(_key_, _val_)                \
    lua_pushstring(L, _key_);                           \
    lua_gettable(L, -2);                                \
    if (!lua_isnil(L, -1)) {                            \
        if (!lua_isnumber(L, -1)) {                     \
            g_error("%s must be a number", _key_);      \
        }                                               \
        _val_ = (int)lua_tonumber(L, -1);               \
    }                                                   \
    lua_pop(L, 1);

int yfLuaGetLen(
    lua_State *L,
    int index)
{
    int len = 0;

    lua_len(L, index);
    len = lua_tointeger(L, -1);
    lua_pop(L, 1);

    return len;
}

char * yfLuaGetStrField(
    lua_State  *L,
    const char *key)
{
    const char *result;

    lua_pushstring(L, key);
    lua_gettable(L, -2);

    result = lua_tostring(L, -1);
    lua_pop(L, 1);

    return (char *)g_strdup(result);
}

/**
 * yfLuaLoadConfig
 *
 *
 */
static void yfLuaLoadConfig(
                            void)
{
    lua_State *L = luaL_newstate();
    int i, len;
    char *str = NULL;
    GError *err = NULL;

    luaopen_base(L);
    luaopen_io(L);
    luaopen_string(L);
    luaopen_math(L);

    if (luaL_loadfile(L, yaf_config_file)) {
        air_opterr("Error loading config file: %s", lua_tostring(L, -1));
    }

    if (lua_pcall(L, 0, 0, 0)) {
        air_opterr("can't run the config file: %s", lua_tostring(L, -1));
    }

    /*logging options*/
    lua_getglobal(L, "log");
    if (!lua_isnil(L, -1)) {
        if (!lua_istable(L, -1)) {
            air_opterr("log is not a valid table. Should be in the form: "
                       "log = {spec=\"filename\", level=\"debug\"}");
        }
        str = yfLuaGetStrField(L, "spec");
        logc_set(str, NULL);
        free(str);
        str = yfLuaGetStrField(L, "level");
        logc_set(NULL, str);
        free(str);
    }

    if (!logc_setup(&err)) {
        air_opterr("%s", err->message);
    }

    lua_getglobal(L, "input");
    if (!lua_istable(L, -1)) {
        air_opterr("input is not a valid table. "
                   "Should be in the form {inf=, type=}");
    }

    yaf_config.livetype = yfLuaGetStrField(L, "type");
    yf_lua_checktablebool("force_read_all", yaf_opt_force_read_all);
#if YAF_ENABLE_DAG_SEPARATE_INTERFACES || YAF_ENABLE_SEPARATE_INTERFACES
    yf_lua_checktablebool("export_interface", yaf_config.exportInterface);
#endif

    if (yaf_config.livetype == NULL) {
        yaf_config.inspec = yfLuaGetStrField(L, "file");
    } else if (strncmp(yaf_config.livetype, "file", 4) == 0) {
        yaf_config.inspec = yfLuaGetStrField(L, "file");
        g_free(yaf_config.livetype);
        yaf_config.livetype = 0;
    } else if (strncmp(yaf_config.livetype, "caplist", 7) == 0) {
        yaf_config.inspec = yfLuaGetStrField(L, "file");
        yf_lua_checktablebool("noerror", yaf_config.noerror);
        yaf_opt_caplist_mode = TRUE;
        g_free(yaf_config.livetype);
        yaf_config.livetype = 0;
    } else {
        yaf_config.inspec = yfLuaGetStrField(L, "inf");
    }

    lua_getglobal(L, "output");
    if (!lua_istable(L, -1)) {
        air_opterr("output is not a valid table. Should be in the form "
                   "{host=, port=, protocol=}");
    }

    str = yfLuaGetStrField(L, "file");
    if (str) {
        yaf_config.outspec = str;
        yf_lua_gettableint("rotate", yaf_opt_rotate);
        yf_lua_checktablebool("lock", yaf_config.lockmode);
    } else {
        yaf_opt_ipfix_transport = yfLuaGetStrField(L, "protocol");
        if (strcmp(yaf_opt_ipfix_transport, "spread") == 0) {
#ifdef HAVE_SPREAD
            yaf_config.outspec = yfLuaGetStrField(L, "daemon");
            yaf_config.ipfixSpreadTrans = TRUE;
            yaf_opt_spread_groupby = yfLuaGetStrField(L, "groupby");
            lua_pushstring(L, "groups");
            lua_gettable(L, -2);
            if (!lua_isnil(L, -1)) {
                if (!lua_istable(L, -1)) {
                    air_opterr("groups is not a valid table. Should be in "
                               "the form: groups={{name=\"NAME\"}}");
                }
                len = yfLuaGetLen(L, -1);
                yaf_config.numSpreadGroups = len;
                if (len) {
                    yaf_config.spreadparams.groups = g_new0( char *, len+1);
                    yaf_config.spreadGroupIndex = g_new0(uint16_t, len);
                }
                for (i = 1; i <= len; i++) {
                    lua_rawgeti(L, -1, i);
                    if (!lua_istable(L, -1)) {
                        air_opterr("group must be a valid table. Should be "
                                   "in the form: {name=\"NAME\", [value=]}");
                    }
                    yaf_config.spreadparams.groups[i-1] = yfLuaGetStrField(L,
                                                                       "name");
                    yf_lua_gettableint("value",
                                       yaf_config.spreadGroupIndex[i-1]);
                    lua_pop(L, 1);
                }

            }
#else
            air_opterr("Spread is not enabled. Configure --with-spread");
#endif
        } else {
            yaf_config.outspec = yfLuaGetStrField(L, "host");
            yaf_config.connspec.svc = yfLuaGetStrField(L, "port");
            yf_lua_gettableint("udp_temp_timeout", yaf_opt_udp_temp_timeout);
        }
    }

    yf_lua_getnum("stats", yaf_opt_stats);
    yf_lua_getbool("no_tombstone", yaf_opt_no_tombstone);
    yf_lua_getnum("tombstone_configured_id", yaf_opt_configured_id);
    yf_lua_getnum("ingress", yaf_opt_ingress_int);
    yf_lua_getnum("egress", yaf_opt_egress_int);
    yf_lua_getnum("obdomain", yaf_config.odid);
    yf_lua_getnum("maxflows", yaf_opt_max_flows);
    yf_lua_getnum("maxfrags", yaf_opt_max_frags);
    yf_lua_getnum("idle_timeout", yaf_opt_idle);
    yf_lua_getnum("active_timeout", yaf_opt_active);
    yf_lua_getnum("maxpayload", yaf_opt_max_payload);
    yf_lua_getnum("maxexport", yaf_opt_payload_export);
    yf_lua_getbool("export_payload", yaf_opt_payload_export_on);
    yf_lua_getnum("udp_uniflow", yaf_opt_udp_uniflow_port);
    yf_lua_getbool("udp_payload", yaf_opt_udp_max_payload);

    /* decode options */
    lua_getglobal(L, "decode");
    if (!lua_isnil(L, -1)) {
        if (!lua_istable(L, -1)) {
            air_opterr("decode is not a valid table. Should be in the "
                       "form: decode = {gre=true, ip4_only=true}");
        }
        yf_lua_checktablebool("gre", yaf_opt_gre_mode);
        yf_lua_checktablebool("ip4_only", yaf_opt_ip4_mode);
        yf_lua_checktablebool("ip6_only", yaf_opt_ip6_mode);
        yf_lua_checktablebool("nofrag", yaf_opt_nofrag);
    }

    /* export options */
    lua_getglobal(L, "export");
    if (!lua_isnil(L, -1)) {
        if (!lua_istable(L, -1)) {
            air_opterr("export is not a valid table. Should be in the "
                       "form: export = {silk=true, uniflow=true, mac=true}");
        }
        yf_lua_checktablebool("silk", yaf_opt_silk_mode);
        yf_lua_checktablebool("uniflow", yaf_opt_uniflow_mode);
        yf_lua_checktablebool("force_ip6", yaf_opt_ip6map_mode);
        yf_lua_checktablebool("flow_stats", yaf_opt_extra_stats_mode);
        yf_lua_checktablebool("delta", yaf_config.deltaMode);
        yf_lua_checktablebool("mac", yaf_opt_mac_mode);
    }

    /* tls options */
    lua_getglobal(L, "tls");
    if (!lua_isnil(L, -1)) {
        if (!lua_istable(L, -1)) {
            air_opterr("tls is not a valid table. Should be in the form: "
                       "tls = {ca=\"\", cert=\"\", key=\"\"}");
        }
        yaf_opt_ipfix_tls = TRUE;
        yaf_config.connspec.ssl_ca_file = yfLuaGetStrField(L, "ca");
        yaf_config.connspec.ssl_cert_file = yfLuaGetStrField(L, "cert");
        yaf_config.connspec.ssl_key_file = yfLuaGetStrField(L, "key");
        lua_pop(L, 1);
    }

    /*entropy options */
#if YAF_ENABLE_ENTROPY
    yf_lua_getbool("entropy", yaf_opt_entropy_mode);
#endif

    /* applabel options */
#if YAF_ENABLE_APPLABEL
    yf_lua_getbool("applabel", yaf_opt_applabel_mode);
    yf_lua_getstr("applabel_rules", yaf_opt_applabel_rules);
#endif

#if YAF_ENABLE_NDPI
    yf_lua_getbool("ndpi", yaf_opt_ndpi);
    yf_lua_getstr("ndpi_proto_file", yaf_ndpi_proto_file);
#endif

    /* p0f options */
#if YAF_ENABLE_P0F
    yf_lua_getbool("p0fprint", yaf_opt_p0fprint_mode);
    yf_lua_getstr("p0f_fingerprints", yaf_opt_p0f_fingerprints);
#endif

    /* fpexport option */
#if YAF_ENABLE_FPEXPORT
    yf_lua_getbool("fpexport",  yaf_opt_fpExport_mode);
#endif

#if YAF_ENABLE_ZLIB
    yf_lua_getstr("decompress", yaf_tmp_file);
#endif

    /* plugin options */
#if YAF_ENABLE_HOOKS
    lua_getglobal(L, "plugin");
    if (!lua_isnil(L, -1)) {
        if (!lua_istable(L, -1)) {
            air_opterr("plugin is not a valid table. Should be in the form: "
                       "plugin = {{name=\"dpacketplugin.la\", options=\"\"}}");
        }
        len = yfLuaGetLen(L, -1);
        for (i = 1; i <= len; i++) {
            lua_rawgeti(L, -1, i);
            if (lua_istable(L, -1)) {
                pluginName = yfLuaGetStrField(L, "name");
                pluginConf = yfLuaGetStrField(L, "conf");
                pluginOpts = yfLuaGetStrField(L, "options");
                if(!yfHookAddNewHook(pluginName, pluginOpts, pluginConf, yfctx, &err))
                {
                    g_warning("Couldn't load requested plugin: %s",
                              err->message);
                }
                hooks_initialized = TRUE;
            }
            lua_pop(L, 1);
        }
    }
#endif


    /* pcap options */
    lua_getglobal(L, "pcap");
    if (!lua_isnil(L, -1)) {
        if (!lua_istable(L, -1)) {
            air_opterr("pcap is not a valid table. Should be in the form: "
                       "pcap = {path=\"\", meta=\"\", maxpcap=25}");
        }

        yf_lua_gettableint("maxpcap", yaf_opt_max_pcap);
        yf_lua_gettableint("pcap_timer", yaf_opt_pcap_timer);
        yaf_pcap_meta_file = yfLuaGetStrField(L, "meta");
        yaf_config.pcapdir = yfLuaGetStrField(L, "path");
        /* pcap per flow and index pcap */
    }


    /* pidfile */
    yf_lua_getstr("pidfile", yaf_pidfile);

    /* BPF filter */
    yf_lua_getstr("filter", yaf_config.bpf_expr);

    lua_close(L);
}


/**
 * yfParseOptions
 *
 * parses the command line options via calls to the Airframe
 * library functions
 *
 *
 *
 */
static void yfParseOptions(
    int             *argc,
    char            **argv[]) {

    AirOptionCtx    *aoctx = NULL;
    GError          *err = NULL;
    GString         *versionString;

    aoctx = air_option_context_new("", argc, argv, yaf_optent_core);

    air_option_context_add_group(aoctx, "decode", "Decoder Options:",
                                 THE_LAME_80COL_FORMATTER_STRING"Show help "
                                 "for packet decoder options", yaf_optent_dec);
    air_option_context_add_group(aoctx, "flow", "Flow table Options:",
                                 THE_LAME_80COL_FORMATTER_STRING"Show help "
                                 "for flow table options", yaf_optent_flow);
    air_option_context_add_group(aoctx, "export", "Export Options:",
                                 THE_LAME_80COL_FORMATTER_STRING"Show help "
                                 "for export format options", yaf_optent_exp);
    air_option_context_add_group(aoctx, "ipfix", "IPFIX Options:",
                                 THE_LAME_80COL_FORMATTER_STRING"Show help "
                                 "for IPFIX export options", yaf_optent_ipfix);
    air_option_context_add_group(aoctx, "pcap", "PCAP Options:",
                                 THE_LAME_80COL_FORMATTER_STRING"Show help "
                                 "for PCAP Export Options", yaf_optent_pcap);
#if YAF_ENABLE_PAYLOAD
    air_option_context_add_group(aoctx, "payload", "Payload Options:",
                                 THE_LAME_80COL_FORMATTER_STRING"Show the "
                                 "help for payload options",
                                 yaf_optent_payload);
#endif
#ifdef YAF_ENABLE_HOOKS
    air_option_context_add_group(aoctx, "plugin", "Plugin Options:",
                                 THE_LAME_80COL_FORMATTER_STRING"Show help "
                                 "for plugin interface options",
                                 yaf_optent_plugin);
#endif
    privc_add_option_group(aoctx);

    versionString = yfVersionString(VERSION);

    logc_add_option_group(aoctx, "yaf", versionString->str);

    air_option_context_set_help_enabled(aoctx);

    air_option_context_parse(aoctx);

    if (yaf_config_file) {
        yfLuaLoadConfig();
    } else {
        /* set up logging and privilege drop */
        if (!logc_setup(&err)) {
            air_opterr("%s", err->message);
        }
    }

    if (!privc_setup(&err)) {
        air_opterr("%s", err->message);
    }

#if YAF_ENABLE_APPLABEL
    if (yaf_opt_applabel_rules && (FALSE == yaf_opt_applabel_mode)) {
        g_warning("--applabel-rules requires --applabel.");
        g_warning("application labeling engine will not operate");
        yaf_opt_applabel_mode = FALSE;
    }
    if (TRUE == yaf_opt_applabel_mode) {
        if (yaf_opt_max_payload == 0) {
            g_warning("--applabel requires --max-payload.");
            g_warning("application labeling engine will not operate");
            yaf_opt_applabel_mode = FALSE;
        } else {
            if (!yfAppLabelInit(yaf_opt_applabel_rules, &err)) {
                if (NULL != err) {
                    g_warning("application labeler config error: %s",
                              err->message);
                    g_warning("application labeling engine will not operate");
                    g_clear_error(&err);
                    yaf_opt_applabel_mode = FALSE;
                }
            }
        }
    }
#endif
#if YAF_ENABLE_NDPI
    if (yaf_ndpi_proto_file && (FALSE == yaf_opt_ndpi)) {
        g_warning("--ndpi-proto-file requires --ndpi.");
        g_warning("NDPI labeling will not operate");
    }
    if (TRUE == yaf_opt_ndpi) {
        if (yaf_opt_max_payload == 0) {
            g_warning("--ndpi requires --max-payload.");
            g_warning("NDPI labeling will not operate");
            yaf_opt_ndpi = FALSE;
        }
    }
#endif

#if YAF_ENABLE_P0F
    if (yaf_opt_p0f_fingerprints && (FALSE == yaf_opt_p0fprint_mode)) {
        g_warning("--p0f-fingerprints requires --p0fprint.");
        g_warning("p0f fingerprinting engine will not operate");
        yaf_opt_p0fprint_mode = FALSE;
    }
    if (TRUE == yaf_opt_p0fprint_mode) {
        if (yaf_opt_max_payload == 0){
            g_warning("--p0fprint requires --max-payload");
            yaf_opt_p0fprint_mode = FALSE;
        } else if (!yfpLoadConfig(yaf_opt_p0f_fingerprints, &err)) {
            g_warning("Error loading config files: %s", err->message);
            yaf_opt_p0fprint_mode = FALSE;
            g_clear_error(&err);
        }
    }
#endif
#if YAF_ENABLE_FPEXPORT
    if (TRUE == yaf_opt_fpExport_mode) {
        if (yaf_opt_max_payload == 0) {
            g_warning("--fpexport requires --max-payload.");
            yaf_opt_fpExport_mode = FALSE;
        }
    }
#endif
    if (TRUE == yaf_opt_udp_max_payload) {
        if (yaf_opt_max_payload == 0) {
            g_warning("--udp-payload requires --max-payload > 0.");
            yaf_opt_udp_max_payload = FALSE;
        }
    }

#ifdef YAF_ENABLE_HOOKS
    if (NULL != pluginName && !hooks_initialized) {
        pluginOptParse(&err);
    }
#endif

#if YAF_ENABLE_BIVIO
    /* export Interface numbers if BIVIO is enabled */
    yaf_config.exportInterface = TRUE;
#endif

#if YAF_ENABLE_ENTROPY
    if (TRUE == yaf_opt_entropy_mode) {
        if (yaf_opt_max_payload == 0) {
            g_warning("--entropy requires --max-payload.");
            yaf_opt_entropy_mode = FALSE;
        }
    }
#endif

    /* process ip4mode and ip6mode */
    if (yaf_opt_ip4_mode && yaf_opt_ip6_mode) {
        g_warning("cannot run in both ip4-only and ip6-only modes; "
                  "ignoring these flags");
        yaf_opt_ip4_mode = FALSE;
        yaf_opt_ip6_mode = FALSE;
    }

    if (yaf_opt_ip4_mode) {
        yaf_reqtype = YF_TYPE_IPv4;
    } else if (yaf_opt_ip6_mode) {
        yaf_reqtype = YF_TYPE_IPv6;
    } else {
        yaf_reqtype = YF_TYPE_IPANY;
    }

    /* process core library options */
    if (yaf_opt_payload_export_on && !yaf_opt_payload_export) {
        yaf_opt_payload_export = yaf_opt_max_payload;
    }

    if (yaf_opt_payload_export > yaf_opt_max_payload) {
        g_warning("--max-export can not be larger than max-payload.  Setting to %d",
                  yaf_opt_max_payload);
        yaf_opt_payload_export = yaf_opt_max_payload;
    }

    if (yaf_opt_payload_export) {
        yfWriterExportPayload(yaf_opt_payload_export);
    }

    if (yaf_opt_ip6map_mode) {
        yfWriterExportMappedV6(TRUE);
    }


    /* Pre-process input options */
    if (yaf_config.livetype) {
        /* can't use caplist with live */
        if (yaf_opt_caplist_mode) {
            air_opterr("Please choose only one of --live or --caplist");
        }

        /* select live capture type */
        if ((*yaf_config.livetype == (char)0) ||
            (strncmp(yaf_config.livetype, "pcap", 4) == 0))
        {
            /* live capture via pcap (--live=pcap or --live) */
            yaf_liveopen_fn = (yfLiveOpen_fn)yfCapOpenLive;
            yaf_loop_fn = (yfLoop_fn)yfCapMain;
            yaf_close_fn = (yfClose_fn)yfCapClose;
            yaf_live_type = 0;

#if YAF_ENABLE_DAG
        } else if (strncmp(yaf_config.livetype, "dag", 3) == 0) {
            /* live capture via dag (--live=dag) */
            yaf_liveopen_fn = (yfLiveOpen_fn)yfDagOpenLive;
            yaf_loop_fn = (yfLoop_fn)yfDagMain;
            yaf_close_fn = (yfClose_fn)yfDagClose;
            if (yaf_config.pcapdir) {
                g_warning("--pcap not valid for --live dag");
                yaf_config.pcapdir = NULL;
            }
            yaf_live_type = 1;
#endif
#if YAF_ENABLE_NAPATECH
        } else if (strncmp(yaf_config.livetype, "napatech", 8) == 0) {
            /* live capture via napatech adapter (--live=napatech) */
            yaf_liveopen_fn = (yfLiveOpen_fn)yfPcapxOpenLive;
            yaf_loop_fn = (yfLoop_fn)yfPcapxMain;
            yaf_close_fn = (yfClose_fn)yfPcapxClose;
            if (yaf_config.pcapdir) {
                g_warning("--pcap not valid for --live napatech");
                yaf_config.pcapdir = NULL;
            }
            yaf_live_type = 2;
#endif
#if YAF_ENABLE_NETRONOME
        } else if (strncmp(yaf_config.livetype, "netronome", 9) == 0) {
            yaf_liveopen_fn = (yfLiveOpen_fn)yfNFEOpenLive;
            yaf_loop_fn = (yfLoop_fn)yfNFEMain;
            yaf_close_fn = (yfClose_fn)yfNFEClose;
            if (yaf_config.pcapdir) {
                g_warning("--pcap not valid for --live netronome");
                yaf_config.pcapdir = NULL;
            }
#endif
#if YAF_ENABLE_PFRING
        } else if (strncmp(yaf_config.livetype, "pfring", 6) == 0) {
            yaf_liveopen_fn = (yfLiveOpen_fn)yfPfRingOpenLive;
            yaf_loop_fn = (yfLoop_fn)yfPfRingMain;
            yaf_close_fn = (yfClose_fn)yfPfRingClose;
            if (yaf_config.pcapdir) {
                g_warning("--pcap not valid for --live pfring");
                yaf_config.pcapdir = NULL;
            }
#if YAF_ENABLE_PFRINGZC
        } else if (strncmp(yaf_config.livetype, "zc", 2) == 0) {
          yaf_liveopen_fn = (yfLiveOpen_fn)yfPfRingZCOpenLive;
          yaf_loop_fn = (yfLoop_fn)yfPfRingZCMain;
          yaf_close_fn = (yfClose_fn)yfPfRingZCClose;
          if (yaf_config.pcapdir) {
            g_warning("--pcap not valid for --live zc");
            yaf_config.pcapdir = NULL;
          }
#endif
#endif
        } else {
            /* unsupported live capture type */
            air_opterr("Unsupported live capture type %s", yaf_config.livetype);
        }

        /* Require an interface name for live input */
        if (!yaf_config.inspec) {
            air_opterr("--live requires interface name in --in");
        }

    } else {
        /* Use pcap loop and close functions */
        yaf_loop_fn = (yfLoop_fn)yfCapMain;
        yaf_close_fn =(yfClose_fn)yfCapClose;

        /* Default to stdin for no input */
        if (!yaf_config.inspec || !strlen(yaf_config.inspec)) {
            yaf_config.inspec = "-";
        }
    }

    /* calculate live rotation delay in milliseconds */
    yaf_rotate_ms = yaf_opt_rotate * 1000;
    yaf_config.rotate_ms = yaf_rotate_ms;

    if (yaf_opt_stats == 0) {
        yaf_config.nostats = TRUE;
    } else {
        yaf_config.stats = yaf_opt_stats;
    }

    yaf_config.tombstone_configured_id = yaf_opt_configured_id;
    yaf_config.no_tombstone = yaf_opt_no_tombstone;
    yaf_config.ingressInt = yaf_opt_ingress_int;
    yaf_config.egressInt = yaf_opt_egress_int;

    /* Pre-process output options */
    if (yaf_opt_ipfix_transport) {
        /* set default port */
        if (!yaf_config.connspec.svc) {
            yaf_config.connspec.svc = yaf_opt_ipfix_tls ? "4740" : "4739";
        }

        /* Require a hostname for IPFIX output */
        if (!yaf_config.outspec) {
            air_opterr("--ipfix requires hostname in --out");
        }

        /* set hostname */
        yaf_config.connspec.host = yaf_config.outspec;

        if ((*yaf_opt_ipfix_transport == (char)0) ||
            (strcmp(yaf_opt_ipfix_transport, "sctp") == 0))
        {
            if (yaf_opt_ipfix_tls) {
                yaf_config.connspec.transport = FB_DTLS_SCTP;
            } else {
                yaf_config.connspec.transport = FB_SCTP;
            }
        } else if (strcmp(yaf_opt_ipfix_transport, "tcp") == 0) {
            if (yaf_opt_ipfix_tls) {
                yaf_config.connspec.transport = FB_TLS_TCP;
            } else {
                yaf_config.connspec.transport = FB_TCP;
            }
        } else if (strcmp(yaf_opt_ipfix_transport, "udp") == 0) {
            if (yaf_opt_ipfix_tls) {
                yaf_config.connspec.transport = FB_DTLS_UDP;
            } else {
                yaf_config.connspec.transport = FB_UDP;
            }
            if (yaf_opt_udp_temp_timeout == 0) {
                yaf_config.yaf_udp_template_timeout = 600000;
            } else {
                /* convert to milliseconds */
                yaf_config.yaf_udp_template_timeout =
                    yaf_opt_udp_temp_timeout * 1000;
            }
#ifdef HAVE_SPREAD
        } else if (strcmp(yaf_opt_ipfix_transport, "spread") == 0) {
            yaf_config.spreadparams.daemon = yaf_config.outspec;
            if (!yaf_config.numSpreadGroups) {
                if (!yaf_opt_spread_group) {
                    air_opterr( "'--ipfix spread' requires at least one Spread "
                                "group in '--group'" );
                }
                groups_from_list( yaf_opt_spread_group,
                                  &yaf_config.spreadparams.groups,
                                  &yaf_config.spreadGroupIndex,
                                  &yaf_config.numSpreadGroups);
            }
            yaf_config.ipfixSpreadTrans = TRUE;
            yaf_config.spreadGroupby = 0;
            if (yaf_opt_spread_groupby != 0) {
                /*if (!yaf_config.spreadGroupIndex[0]) {
                    air_opterr("Invalid groupby: Must have values to group by"
                               " in --group");
                               }*/
                if (!(strcmp(yaf_opt_spread_groupby, "port")) ||
                    !(strcmp(yaf_opt_spread_groupby, "Port")))
                {
                    yaf_config.spreadGroupby = 1;
                } else if (!(strcmp(yaf_opt_spread_groupby, "vlan")) ||
                           !(strcmp(yaf_opt_spread_groupby, "Vlan")))
                {
                    yaf_config.spreadGroupby = 2;
                } else if (!(strcmp(yaf_opt_spread_groupby, "applabel")) ||
                           (!strcmp(yaf_opt_spread_groupby, "Applabel")))
                {
                    if (!yaf_opt_applabel_mode) {
                        air_opterr("Spread can't groupby applabel without "
                                   "--applabel");
                    }
                    yaf_config.spreadGroupby = 3;
                } else if (!(strcmp(yaf_opt_spread_groupby, "protocol")) ||
                           !(strcmp(yaf_opt_spread_groupby, "Protocol")))
                {
                    yaf_config.spreadGroupby = 4;
                } else if (!(strcmp(yaf_opt_spread_groupby, "version")) ||
                           !(strcmp(yaf_opt_spread_groupby, "Version")))
                {
                    yaf_config.spreadGroupby = 5;
                } else {
                    air_opterr("Unsupported groupby type %s",
                               yaf_opt_spread_groupby);
                }
            } else {
                if (yaf_config.spreadGroupIndex[0]) {
                    air_opterr("--groupby <value> not given - "
                               "No value to groupby");
                }
            }

#endif /* HAVE_SPREAD */
        } else {
            air_opterr("Unsupported IPFIX transport protocol %s",
                       yaf_opt_ipfix_transport);
        }

        /* grab TLS password from environment */
        if (yaf_opt_ipfix_tls) {
            yaf_config.connspec.ssl_key_pass = getenv("YAF_TLS_PASS");
        }

        /* mark that a network connection is requested for this spec */
        yaf_config.ipfixNetTrans = TRUE;

    } else {
        if (!yaf_config.outspec || !strlen(yaf_config.outspec)) {
            if (yaf_rotate_ms) {
                /* Require a path prefix for IPFIX output */
                air_opterr("--rotate requires prefix in --out");
            } else {
                /* Default to stdout for no output without rotation */
                if (!yaf_config.no_output) {
                    yaf_config.outspec = "-";
                }
            }
        }
    }

    /* Check for stdin/stdout is terminal */
    if ((strlen(yaf_config.inspec) == 1) && yaf_config.inspec[0] == '-') {
        /* Don't open stdin if it's a terminal */
        if (isatty(fileno(stdin))) {
            air_opterr("Refusing to read from terminal on stdin");
        }
    }

    if (!yaf_config.no_output) {
        if ((strlen(yaf_config.outspec) == 1) && yaf_config.outspec[0] == '-')
        {
            /* Don't open stdout if it's a terminal */
            if (isatty(fileno(stdout))) {
                air_opterr("Refusing to write to terminal on stdout");
            }
        }
    } else {
        yaf_config.rotate_ms = 0;
        if (yaf_config.outspec) {
            g_warning("Ignoring --out %s due to presence of --no-output.",
                      yaf_config.outspec);
        }
    }

    if (yaf_config.pcapdir) {
        if (yaf_config.pcap_per_flow && yaf_opt_max_payload == 0) {
            air_opterr("--pcap-per-flow requires --max-payload");
        }
        if (yaf_config.pcap_per_flow) {
            if (!(g_file_test(yaf_config.pcapdir, G_FILE_TEST_IS_DIR))) {
                air_opterr("--pcap requires a valid directory when "
                           "using --pcap-per-flow");
            }
            if (yaf_index_pcap) {
               g_warning("Ignoring --index-pcap option with --pcap-per-flow.");
               yaf_index_pcap = FALSE;
            }
            if (yaf_pcap_meta_file) {
                g_warning("Ignoring --pcap-meta-file option with "
                          "--pcap-per-flow.");
                yaf_pcap_meta_file = NULL;
            }
        }
    } else if (yaf_config.pcap_per_flow) {
        air_opterr("--pcap-per-flow requires --pcap");
    }

    yaf_config.pcap_timer = yaf_opt_pcap_timer;
    if (yaf_opt_max_pcap) {
        yaf_config.max_pcap = yaf_opt_max_pcap * 1024 * 1024;
    } else {
        yaf_config.max_pcap = yaf_config.max_pcap * 1024 * 1024;
    }

    if (yaf_hash_search) {
        if (!yaf_config.pcapdir) {
            air_opterr("--hash requires --pcap");
        }
        if (yaf_pcap_meta_file) {
            g_warning("Ignoring --pcap-meta-file option.");
            yaf_pcap_meta_file = NULL;
        }
        yaf_config.pcap_per_flow = TRUE;
    }

    if (yaf_stime_search) {
        if (!yaf_hash_search) {
            air_opterr("--stime requires --hash");
        }
    }

    if (yaf_opt_promisc) {
        yfSetPromiscMode(0);
    }

    if (yaf_daemon) {
        yfDaemonize();
    }

    g_string_free(versionString, TRUE);

    air_option_context_free(aoctx);
}

#ifdef YAF_ENABLE_HOOKS
/*
 *yfPluginLoad
 *
 * parses parameters for plugin loading and calls the hook add function to
 * load the plugins
 *
 */
static void pluginOptParse(GError **err) {

    char *plugName, *endPlugName = NULL;
    char *plugOpt, *endPlugOpt = NULL;
    char *plugConf, *endPlugConf = NULL;
    char *plugNameIndex, *plugOptIndex, *plugConfIndex;
    unsigned char plugNameAlloc = 0;
    unsigned char plugOptAlloc = 0;
    unsigned char plugConfAlloc = 0;

    plugNameIndex = pluginName;
    plugOptIndex = pluginOpts;
    plugConfIndex = pluginConf;

    while (NULL != plugNameIndex) {
        /* Plugin file */
        endPlugName = strchr(plugNameIndex, ',');
        if (NULL == endPlugName) {
            plugName = plugNameIndex;
        } else {
            plugName = g_new0(char, (endPlugName - plugNameIndex + 1));
            strncpy(plugName, plugNameIndex, (endPlugName - plugNameIndex));
            plugNameAlloc = 1;
        }

        /* Plugin options */
        if (NULL == plugOptIndex) {
            plugOpt = NULL;
        } else {
            endPlugOpt = strchr(plugOptIndex, ',');
            if (NULL == endPlugOpt) {
                plugOpt = plugOptIndex;
            } else if ( plugOptIndex == endPlugOpt) {
                plugOpt = NULL;
            } else {
                plugOpt = g_new0(char, (endPlugOpt - plugOptIndex + 1));
                strncpy(plugOpt, plugOptIndex, (endPlugOpt - plugOptIndex));
                plugOptAlloc = 1;
            }

        }

        /* Plugin config */
        if (NULL == plugConfIndex) {
            plugConf = NULL;
        } else {
            endPlugConf = strchr(plugConfIndex, ',');
            if (NULL == endPlugConf) {
                plugConf = plugConfIndex;
            } else if ( plugConfIndex == endPlugConf) {
                plugConf = NULL;
            } else {
                plugConf = g_new0(char, (endPlugConf - plugConfIndex + 1));
                strncpy(plugConf, plugConfIndex,(endPlugConf - plugConfIndex));
                plugConfAlloc = 1;
            }

        }

        /* Attempt to load/initialize the plugin */
        if (!yfHookAddNewHook(plugName, plugOpt, plugConf, yfctx, err)) {
            g_warning("couldn't load requested plugin: %s",
                  (*err)->message);
        }

        if (NULL != plugNameIndex) {
            if (NULL != endPlugName) {
                plugNameIndex = endPlugName + 1;
            } else {
                /* we're done anyway */
                break;
            }
        }
        if (NULL != plugOptIndex) {
            if (NULL != endPlugOpt) {
                plugOptIndex = endPlugOpt + 1;
            } else {
                plugOptIndex = NULL;
            }
        }

        if (NULL != plugConfIndex) {
            if (NULL != endPlugConf) {
                plugConfIndex = endPlugConf + 1;
            } else {
                plugConfIndex = NULL;
            }
        }

        if (0 != plugNameAlloc) {
            g_free(plugName);
            plugNameAlloc = 0;
        }
        if (0 != plugOptAlloc) {
            g_free(plugOpt);
            plugOptAlloc = 0;
        }
        if (0 != plugConfAlloc) {
            g_free(plugConf);
            plugConfAlloc = 0;
        }
    }
}
#endif

/**
 *
 *
 *
 *
 *
 */
void yfQuit() {
    yaf_quit++;

#if YAF_ENABLE_PFRING
    yfPfRingBreakLoop(NULL);
#endif

}

/**
 *
 *
 *
 *
 *
 */
static void yfQuitInit()
{
    struct sigaction sa, osa;

    /* install quit flag handlers */
    sa.sa_handler = yfQuit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT,&sa,&osa)) {
        g_error("sigaction(SIGINT) failed: %s", strerror(errno));
    }

    sa.sa_handler = yfQuit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM,&sa,&osa)) {
        g_error("sigaction(SIGTERM) failed: %s", strerror(errno));
    }
}

/**
 *
 *
 *
 *
 *
 */
int main (
    int             argc,
    char            *argv[])
{
    GError          *err = NULL;
    yfContext_t     ctx = YF_CTX_INIT;
    int             datalink;
    gboolean        loop_ok = TRUE;

    /* check structure alignment */
    yfAlignmentCheck();

    /* parse options */
    yfParseOptions(&argc, &argv);
    ctx.cfg = &yaf_config;

    /* record yaf start time */
    ctx.yaf_start_time = time(NULL) * 1000;

    /* Set up quit handler */
    yfQuitInit();

    /* Initialize random number generator using the system time */
    srand((unsigned) time(NULL));
    ctx.cfg->tombstone_unique_id = rand(); 

    /* open interface if we're doing live capture */
    if (yaf_liveopen_fn) {
        /* open interface */
        if (!(ctx.pktsrc = yaf_liveopen_fn(yaf_config.inspec,
                                           yaf_opt_max_payload + 96,
                                           &datalink, &err)))
        {
            g_warning("Cannot open interface %s: %s", yaf_config.inspec,
                      err->message);
            exit(1);
        }

        /* drop privilege */
        if (!privc_become(&err)) {
            if (g_error_matches(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_NODROP)) {
                g_warning("running as root in --live mode, "
                          "but not dropping privilege");
                g_clear_error(&err);
            } else {
                yaf_close_fn(ctx.pktsrc);
                g_warning("Cannot drop privilege: %s", err->message);
                exit(1);
            }
        }
    } else {
        if (yaf_opt_caplist_mode) {
            /* open input file list */
            if (!(ctx.pktsrc = yfCapOpenFileList(yaf_config.inspec, &datalink,
                                                 yaf_tmp_file, &err)))
            {
                g_warning("Cannot open packet file list file %s: %s",
                         yaf_config.inspec, err->message);
                exit(1);
            }
            /* drop privilege */
            if (!privc_become(&err)) {
                if (g_error_matches(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_NODROP)) {
                    g_warning("running as root in --caplist mode, "
                              "but not dropping privilege");
                    g_clear_error(&err);
                } else {
                    yaf_close_fn(ctx.pktsrc);
                    g_warning("Cannot drop privilege: %s", err->message);
                    exit(1);
                }
            }
        } else {
            /* open input file */
            if (!(ctx.pktsrc = yfCapOpenFile(yaf_config.inspec, &datalink,
                                             yaf_tmp_file, &err)))
            {
                g_warning("Cannot open packet file %s: %s",
                          yaf_config.inspec, err->message);
                exit(1);
            }
        }
    }

    if (yaf_opt_mac_mode) {
        yaf_config.macmode = TRUE;
    }

    if (yaf_opt_extra_stats_mode) {
        yaf_config.statsmode = TRUE;
    }

    if (yaf_opt_silk_mode) {
        yaf_config.silkmode = TRUE;
    }

    /* Calculate packet buffer size */
    if (yaf_opt_max_payload) {
        /* 54 for Headers (14 for L2, 20 for IP, 20 for L4) */
        /* This was added bc we now capture starting at L2 up to max-payload
           for possible PCAP capture */
        ctx.pbuflen = YF_PBUFLEN_BASE + yaf_opt_max_payload + 54;
    } else {
        ctx.pbuflen = YF_PBUFLEN_NOPAYLOAD;
    }

    /* Allocate a packet ring. */
    ctx.pbufring = rgaAlloc(ctx.pbuflen, 128);

    /* Set up decode context */
    ctx.dectx = yfDecodeCtxAlloc(datalink, yaf_reqtype, yaf_opt_gre_mode);

    /* Set up flow table */
    ctx.flowtab = yfFlowTabAlloc(yaf_opt_idle * 1000,
                                 yaf_opt_active * 1000,
                                 yaf_opt_max_flows,
                                 yaf_opt_max_payload,
                                 yaf_opt_uniflow_mode,
                                 yaf_opt_silk_mode,
                                 yaf_opt_mac_mode,
                                 yaf_opt_applabel_mode,
                                 yaf_opt_entropy_mode,
                                 yaf_opt_p0fprint_mode,
                                 yaf_opt_fpExport_mode,
                                 yaf_opt_udp_max_payload,
                                 yaf_opt_udp_uniflow_port,
                                 yaf_config.pcapdir,
                                 yaf_pcap_meta_file,
                                 yaf_config.max_pcap,
                                 yaf_config.pcap_per_flow,
                                 yaf_opt_force_read_all,
                                 yaf_opt_extra_stats_mode,
                                 yaf_index_pcap,
                                 yaf_novlan_in_key,
                                 yaf_opt_ndpi,
                                 yaf_ndpi_proto_file,
                                 yaf_hash_search,
                                 yaf_stime_search,
                                 yfctx);

    /* Set up fragment table - ONLY IF USER SAYS */
    if (!yaf_opt_nofrag) {
        ctx.fragtab = yfFragTabAlloc(30000,
                                     yaf_opt_max_frags,
                                     yaf_opt_max_payload);
    }

    /* We have a packet source, an output stream,
       and all the tables we need. Run with it. */

    yfStatInit(&ctx);

    loop_ok = yaf_loop_fn(&ctx);

    yfStatComplete();

    /* Close packet source */
    yaf_close_fn(ctx.pktsrc);

    /* Clean up! */
    if (ctx.flowtab) {
        yfFlowTabFree(ctx.flowtab);
    }
    if (ctx.fragtab) {
        yfFragTabFree(ctx.fragtab);
    }
    if (ctx.dectx) {
        yfDecodeCtxFree(ctx.dectx);
    }
    if (ctx.pbufring) {
        rgaFree(ctx.pbufring);
    }

    /* Print exit message */
    if (loop_ok) {
        g_debug("yaf terminating");
    } else {
        g_warning("yaf terminating on error: %s", ctx.err->message);
    }

    return loop_ok ? 0 : 1;
}
