/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yaf.c
 *  Yet Another Flow generator
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

/* wrap this around string literals that are assigned to variables of type
 * "char *" to quiet compiler warnings */
#define C(String) (char *)String

#define DEFAULT_VXLAN_PORT 4789
#define DEFAULT_GENEVE_PORT 6081

/* I/O configuration */
static yfConfig_t yaf_config = YF_CONFIG_INIT;
static char      *yaf_config_file = NULL;
static int        yaf_opt_rotate = 0;
static int        yaf_opt_stats = 300;
static gboolean   yaf_opt_no_tombstone = FALSE;
static uint16_t   yaf_opt_configured_id = 0;
static uint64_t   yaf_rotate_ms = 0;
static gboolean   yaf_opt_caplist_mode = FALSE;
static char      *yaf_opt_ipfix_transport = NULL;
static gboolean   yaf_opt_ipfix_tls = FALSE;
static char      *yaf_pcap_meta_file = NULL;
static gboolean   yaf_index_pcap = FALSE;
static gboolean   yaf_daemon = FALSE;
static char      *yaf_pidfile = NULL;
static char      *yaf_tmp_file = NULL;
static int        yaf_opt_udp_temp_timeout = 600;
static int        yaf_live_type = 0;
static gboolean   yaf_opt_promisc = FALSE;
#ifdef HAVE_SPREAD
/* spread config options */
static char      *yaf_opt_spread_group = 0;
static char      *yaf_opt_spread_groupby = 0;
#endif

/* GOption managed flow table options */
static int      yaf_opt_idle = 300;
static int      yaf_opt_active = 1800;
static int      yaf_opt_max_flows = 0;
static int      yaf_opt_max_payload = 0;
static int      yaf_opt_payload_export = 0;
#if YAF_ENABLE_APPLABEL
static char    *yaf_opt_payload_applabels = NULL;
#endif
static gboolean yaf_opt_payload_export_on = FALSE;
static gboolean yaf_opt_applabel_mode = FALSE;
static gboolean yaf_opt_force_read_all = FALSE;

#if YAF_ENABLE_APPLABEL
static char    *yaf_opt_applabel_rules = NULL;
#endif
static gboolean yaf_opt_ndpi = FALSE;
static char    *yaf_ndpi_proto_file = NULL;
static gboolean yaf_opt_entropy_mode = FALSE;
static gboolean yaf_opt_uniflow_mode = FALSE;
static uint16_t yaf_opt_udp_uniflow_port = 0;
static gboolean yaf_opt_silk_mode = FALSE;
static gboolean yaf_opt_p0fprint_mode = FALSE;
#if YAF_ENABLE_P0F
static char    *yaf_opt_p0f_fingerprints = NULL;
#endif
static gboolean yaf_opt_fpExport_mode = FALSE;
static gboolean yaf_opt_udp_max_payload = FALSE;
static gboolean yaf_opt_extra_stats_mode = FALSE;
static int      yaf_opt_max_pcap = 25;
static int      yaf_opt_pcap_timer = 0;
static char    *yaf_hash_search = NULL;
static char    *yaf_stime_search = NULL;
static int      yaf_opt_ingress_int = 0;
static int      yaf_opt_egress_int = 0;
static gboolean yaf_novlan_in_key;
/* GOption managed fragment table options */
static int      yaf_opt_max_frags = 0;
static gboolean yaf_opt_nofrag = FALSE;

/* GOption managed decoder options and derived decoder config */
static gboolean yaf_opt_ip4_mode = FALSE;
static gboolean yaf_opt_ip6_mode = FALSE;
static uint16_t yaf_reqtype;
static gboolean yaf_opt_gre_mode = FALSE;
static gboolean yaf_opt_vxlan_mode = FALSE;
static gboolean yaf_opt_geneve_mode = FALSE;
static GArray  *yaf_opt_vxlan_ports = NULL;
static GArray  *yaf_opt_geneve_ports = NULL;
static gboolean yaf_opt_mac_mode = FALSE;

/* GOption managed core export options */
static gboolean yaf_opt_ip6map_mode = FALSE;

#ifdef YAF_ENABLE_HOOKS
static char    *pluginName = NULL;
static char    *pluginOpts = NULL;
static char    *pluginConf = NULL;
static gboolean hooks_initialized = FALSE;
#endif /* ifdef YAF_ENABLE_HOOKS */
/* array of configuration information that is passed to flow table */
static void    *yfctx[YAF_MAX_HOOKS];

/* global quit flag */
int             yaf_quit = 0;

/* Runtime functions */

typedef void *(*yfLiveOpen_fn)(
    const char *,
    int,
    int *,
    GError **);
static yfLiveOpen_fn yaf_liveopen_fn = NULL;

typedef gboolean (*yfLoop_fn)(
    yfContext_t *);
static yfLoop_fn yaf_loop_fn = NULL;

typedef void (*yfClose_fn)(
    void *);
static yfClose_fn yaf_close_fn = NULL;

#ifdef USE_GOPTION
#define AF_OPTION_WRAP "\n\t\t\t\t"
#else
#define AF_OPTION_WRAP " "
#endif

/* Local functions prototypes */

static void
yaf_opt_save_vxlan_ports(
    const gchar  *option_name,
    const gchar  *yaf_opt_vxlan_ports_str,
    gpointer      data,
    GError      **error);

static void
yaf_opt_save_geneve_ports(
    const gchar  *option_name,
    const gchar  *yaf_opt_geneve_ports_str,
    gpointer      data,
    GError      **error);

static void
yaf_opt_finalize_decode_ports(
    void);

static void
yaf_opt_ports_str_2_array(
    const gchar  *option_name,
    const gchar  *ports_str,
    GArray       *ports_array,
    GError      **error);

static void
yaf_opt_remove_array_dups(
    GArray *g);

#if YAF_ENABLE_HOOKS
static void
pluginOptParse(
    GError **err);
#endif /* if YAF_ENABLE_HOOKS */


/* Local derived configuration */

static AirOptionEntry yaf_optent_core[] = {
    AF_OPTION("in", 'i', 0, AF_OPT_TYPE_STRING, &yaf_config.inspec,
              AF_OPTION_WRAP "Input (file, - for stdin; interface) [-]",
              "inspec"),
    AF_OPTION("out", 'o', 0, AF_OPT_TYPE_STRING, &yaf_config.outspec,
              AF_OPTION_WRAP "Output (file, - for stdout; file prefix;"
              AF_OPTION_WRAP "address) [-]",
              "outspec"),
    AF_OPTION("config", 'c', 0, AF_OPT_TYPE_STRING, &yaf_config_file,
              AF_OPTION_WRAP "YAF configuration filename",
              "file"),
#ifdef HAVE_SPREAD
    AF_OPTION("group", 'g', 0, AF_OPT_TYPE_STRING, &yaf_opt_spread_group,
              AF_OPTION_WRAP "Spread group name (comma seperated list)."
              AF_OPTION_WRAP "For groupby: comma separated"
              AF_OPTION_WRAP "group_name:value,[group_name:value,...]",
              "group-name"),
    AF_OPTION("groupby", 0, 0, AF_OPT_TYPE_STRING, &yaf_opt_spread_groupby,
              AF_OPTION_WRAP "<port, vlan, applabel, protocol, version>"
              AF_OPTION_WRAP "(Must be used with group and group must have"
              AF_OPTION_WRAP "values to groupby", "type"),
#endif /* ifdef HAVE_SPREAD */
    AF_OPTION("live", 'P', 0, AF_OPT_TYPE_STRING, &yaf_config.livetype,
              AF_OPTION_WRAP "Capture from interface in -i; type is"
              AF_OPTION_WRAP "[pcap], dag, napatech, netronome, pfring, zc",
              "type"),
    AF_OPTION("filter", 'F', 0, AF_OPT_TYPE_STRING, &yaf_config.bpf_expr,
              AF_OPTION_WRAP "BPF filtering expression",
              "expression"),
    AF_OPTION("caplist", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_caplist_mode,
              AF_OPTION_WRAP "Read ordered list of input files from"
              AF_OPTION_WRAP "file in -i", NULL),
#if YAF_ENABLE_ZLIB
    AF_OPTION("decompress", 0, 0, AF_OPT_TYPE_STRING, &yaf_tmp_file,
              AF_OPTION_WRAP "Decompression file directory [$TMPDIR]", "dir"),
#endif
    AF_OPTION("rotate", 'R', 0, AF_OPT_TYPE_INT, &yaf_opt_rotate,
              AF_OPTION_WRAP "Rotate output files every n seconds", "sec"),
    AF_OPTION("lock", 'k', 0, AF_OPT_TYPE_NONE, &yaf_config.lockmode,
              AF_OPTION_WRAP "Use exclusive .lock files on output for"
              AF_OPTION_WRAP "concurrency", NULL),
    AF_OPTION("daemonize", 'd', 0, AF_OPT_TYPE_NONE, &yaf_daemon,
              AF_OPTION_WRAP "Daemonize yaf", NULL),
    AF_OPTION("pidfile", 0, 0, AF_OPT_TYPE_STRING, &yaf_pidfile,
              AF_OPTION_WRAP "Complete path to the process ID file", "path"),
    AF_OPTION("promisc-off", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_promisc,
              AF_OPTION_WRAP "Do not put the interface in promiscuous mode",
              NULL),
    AF_OPTION("noerror", 0, 0, AF_OPT_TYPE_NONE, &yaf_config.noerror,
              AF_OPTION_WRAP "Do not error out on single PCAP file issue"
              AF_OPTION_WRAP "with multiple inputs", NULL),
#ifdef HAVE_SPREAD
    AF_OPTION("ipfix", 0, 0, AF_OPT_TYPE_STRING, &yaf_opt_ipfix_transport,
              AF_OPTION_WRAP "Export via IPFIX (tcp, udp, sctp, spread) to CP"
              AF_OPTION_WRAP "at -o",
              "protocol"),
#else /* ifdef HAVE_SPREAD */
    AF_OPTION("ipfix", 0, 0, AF_OPT_TYPE_STRING, &yaf_opt_ipfix_transport,
              AF_OPTION_WRAP "Export via IPFIX (tcp, udp, sctp) to CP at -o",
              "protocol"),
#endif /* ifdef HAVE_SPREAD */
    AF_OPTION_END
};

static AirOptionEntry yaf_optent_dec[] = {
    AF_OPTION("no-frag", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_nofrag,
              AF_OPTION_WRAP "Disable IP fragment reassembly",
              NULL),
    AF_OPTION("max-frags", 0, 0, AF_OPT_TYPE_INT, &yaf_opt_max_frags,
              AF_OPTION_WRAP "Maximum size of fragment table [0]", "fragments"),
    AF_OPTION("ip4-only", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_ip4_mode,
              AF_OPTION_WRAP "Only process IPv4 packets",
              NULL),
    AF_OPTION("ip6-only", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_ip6_mode,
              AF_OPTION_WRAP "Only process IPv6 packets",
              NULL),
    AF_OPTION("gre-decode", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_gre_mode,
              AF_OPTION_WRAP "Decode GRE encapsulated packets", NULL),
    AF_OPTION("vxlan-decode", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_vxlan_mode,
              AF_OPTION_WRAP "Decode VxLAN encapsulated packets", NULL),
    AF_OPTION("vxlan-decode-ports", 0, 0, AF_OPT_TYPE_CALLBACK,
              yaf_opt_save_vxlan_ports,
              AF_OPTION_WRAP "Decode VxLAN packets only over these ports",
              "port[,port...]"),
    AF_OPTION("geneve-decode", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_geneve_mode,
              AF_OPTION_WRAP "Decode Geneve encapsulated packets", NULL),
    AF_OPTION("geneve-decode-ports", 0, 0, AF_OPT_TYPE_CALLBACK,
              yaf_opt_save_geneve_ports,
              AF_OPTION_WRAP "Decode Geneve packets only over these ports",
              "port[,port...]"),
    AF_OPTION_END
};

static AirOptionEntry yaf_optent_flow[] = {
    AF_OPTION("idle-timeout", 'I', 0, AF_OPT_TYPE_INT, &yaf_opt_idle,
              AF_OPTION_WRAP "Idle flow timeout [300, 5m]",
              "sec"),
    AF_OPTION("active-timeout", 'A', 0, AF_OPT_TYPE_INT, &yaf_opt_active,
              AF_OPTION_WRAP "Active flow timeout [1800, 30m]", "sec"),
    AF_OPTION("max-flows", 0, 0, AF_OPT_TYPE_INT, &yaf_opt_max_flows,
              AF_OPTION_WRAP "Maximum size of flow table [0]",
              "flows"),
    AF_OPTION("udp-temp-timeout", 0, 0, AF_OPT_TYPE_INT,
              &yaf_opt_udp_temp_timeout,
              AF_OPTION_WRAP "UDP template timeout period [600, 10m]", "sec"),
    AF_OPTION("force-read-all", 0, 0, AF_OPT_TYPE_NONE,
              &yaf_opt_force_read_all,
              AF_OPTION_WRAP "Force read of any out of sequence packets", NULL),
    AF_OPTION("no-vlan-in-key", 0, 0, AF_OPT_TYPE_NONE, &yaf_novlan_in_key,
              AF_OPTION_WRAP "Do not use the VLAN in the flow key hash"
              AF_OPTION_WRAP "calculation", NULL),
    AF_OPTION_END
};

static AirOptionEntry yaf_optent_exp[] = {
    AF_OPTION("no-output", 0, 0, AF_OPT_TYPE_NONE, &yaf_config.no_output,
              AF_OPTION_WRAP "Turn off IPFIX export", NULL),
    AF_OPTION("no-stats", 0, 0, AF_OPT_TYPE_NONE, &yaf_config.nostats,
              AF_OPTION_WRAP "Turn off stats option records IPFIX export",
              NULL),
    AF_OPTION("stats", 0, 0, AF_OPT_TYPE_INT, &yaf_opt_stats,
              AF_OPTION_WRAP "Export yaf process statistics every n seconds"
              AF_OPTION_WRAP "[300, 5m]", "n"),
    AF_OPTION("no-tombstone", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_no_tombstone,
              AF_OPTION_WRAP "Turn off export of tombstone records", NULL),
    AF_OPTION("tombstone-configured-id", 0, 0, AF_OPT_TYPE_INT,
              &yaf_opt_configured_id,
              AF_OPTION_WRAP "Set tombstone record's 16 bit configured"
              AF_OPTION_WRAP "identifier [0]",
              "ident"),
    AF_OPTION("silk", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_silk_mode,
              AF_OPTION_WRAP "Clamp octets to 32 bits, note continued in"
              AF_OPTION_WRAP "flowEndReason, export TCP Fields within"
              AF_OPTION_WRAP "flow record instead of subTemplateMultiList",
              NULL),
    AF_OPTION("mac", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_mac_mode,
              AF_OPTION_WRAP "Export MAC-layer information",
              NULL),
    AF_OPTION("uniflow", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_uniflow_mode,
              AF_OPTION_WRAP "Write uniflows for compatibility", NULL),
    AF_OPTION("udp-uniflow", 0, 0, AF_OPT_TYPE_INT, &yaf_opt_udp_uniflow_port,
              AF_OPTION_WRAP "Exports a single UDP packet as a flow on the"
              AF_OPTION_WRAP "given port. Use 1 for all ports [0]", "port"),
    AF_OPTION("force-ip6-export", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_ip6map_mode,
              AF_OPTION_WRAP "Export all IPv4 addresses as IPv6 in ::ffff/96",
              NULL),
    AF_OPTION("observation-domain", 0, 0, AF_OPT_TYPE_INT, &yaf_config.odid,
              AF_OPTION_WRAP "Set observationDomainID on exported"
              AF_OPTION_WRAP "messages [0]", "odId"),
    AF_OPTION("flow-stats", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_extra_stats_mode,
              AF_OPTION_WRAP "Export extra flow attributes and statistics",
              NULL),
    AF_OPTION("delta", 0, 0, AF_OPT_TYPE_NONE, &yaf_config.deltaMode,
              AF_OPTION_WRAP "Export packet and octet counts using delta"
              AF_OPTION_WRAP "information elements", NULL),
    AF_OPTION("ingress", 0, 0, AF_OPT_TYPE_INT, &yaf_opt_ingress_int,
              AF_OPTION_WRAP "Set ingressInterface field in flow template [0]",
              "ingressId"),
    AF_OPTION("egress", 0, 0, AF_OPT_TYPE_INT, &yaf_opt_egress_int,
              AF_OPTION_WRAP "Set egressInterface field in flow template [0]",
              "egressId"),
#if YAF_ENABLE_METADATA_EXPORT
    AF_OPTION("metadata-export", 0, 0, AF_OPT_TYPE_NONE,
              &yaf_config.tmpl_metadata,
              AF_OPTION_WRAP "Export template and information element"
              AF_OPTION_WRAP "metadata before data", NULL),
#endif /* if YAF_ENABLE_METADATA_EXPORT */
#if YAF_ENABLE_DAG_SEPARATE_INTERFACES || YAF_ENABLE_SEPARATE_INTERFACES
    AF_OPTION("export-interface", 0, 0, AF_OPT_TYPE_NONE,
              &yaf_config.exportInterface,
              AF_OPTION_WRAP "Export DAG, Napatech, or Netronome interface"
              AF_OPTION_WRAP "numbers in export records", NULL),
#endif /* if YAF_ENABLE_DAG_SEPARATE_INTERFACES ||
        * YAF_ENABLE_SEPARATE_INTERFACES */
    AF_OPTION_END
};

static AirOptionEntry yaf_optent_ipfix[] = {
    AF_OPTION("ipfix-port", 0, 0, AF_OPT_TYPE_STRING,
              &(yaf_config.connspec.svc),
              AF_OPTION_WRAP "Select IPFIX export port [4739, 4740]", "port"),
    AF_OPTION("tls", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_ipfix_tls,
              AF_OPTION_WRAP "Use TLS/DTLS to secure IPFIX export", NULL),
    AF_OPTION("tls-ca", 0, 0, AF_OPT_TYPE_STRING,
              &(yaf_config.connspec.ssl_ca_file),
              AF_OPTION_WRAP "Specify TLS Certificate Authority file",
              "cafile"),
    AF_OPTION("tls-cert", 0, 0, AF_OPT_TYPE_STRING,
              &(yaf_config.connspec.ssl_cert_file),
              AF_OPTION_WRAP "Specify TLS Certificate file",
              "certfile"),
    AF_OPTION("tls-key", 0, 0, AF_OPT_TYPE_STRING,
              &(yaf_config.connspec.ssl_key_file),
              AF_OPTION_WRAP "Specify TLS Private Key file",
              "keyfile"),
    AF_OPTION_END
};

static AirOptionEntry yaf_optent_pcap[] = {
    AF_OPTION("pcap", 'p', 0, AF_OPT_TYPE_STRING, &yaf_config.pcapdir,
              AF_OPTION_WRAP "Directory/File prefix to store rolling"
              AF_OPTION_WRAP "pcap files", "dir"),
    AF_OPTION("pcap-per-flow", 0, 0, AF_OPT_TYPE_NONE,
              &yaf_config.pcap_per_flow,
              AF_OPTION_WRAP "Create a separate pcap file for each flow"
              AF_OPTION_WRAP "in the --pcap directory", NULL),
    AF_OPTION("max-pcap", 0, 0, AF_OPT_TYPE_INT, &yaf_opt_max_pcap,
              AF_OPTION_WRAP "Max File Size of Pcap File [25 MB]", "MB"),
    AF_OPTION("pcap-timer", 0, 0, AF_OPT_TYPE_INT, &yaf_opt_pcap_timer,
              AF_OPTION_WRAP "Number of seconds for rolling pcap file [300]",
              "sec"),
    AF_OPTION("pcap-meta-file", 0, 0, AF_OPT_TYPE_STRING, &yaf_pcap_meta_file,
              AF_OPTION_WRAP "Metadata file for rolling pcap output or"
              AF_OPTION_WRAP "indexing input pcap",
              "path"),
    AF_OPTION("index-pcap", 0, 0, AF_OPT_TYPE_NONE, &yaf_index_pcap,
              AF_OPTION_WRAP "Index the pcap with offset and lengths"
              AF_OPTION_WRAP "per packet", NULL),
    AF_OPTION("hash", 0, 0, AF_OPT_TYPE_STRING, &yaf_hash_search,
              AF_OPTION_WRAP "Create only a PCAP for the given hash", "hash"),
    AF_OPTION("stime", 0, 0, AF_OPT_TYPE_STRING, &yaf_stime_search,
              AF_OPTION_WRAP "Create only a PCAP for the given stime"
              AF_OPTION_WRAP "(--hash must also be present)",
              "ms"),
    AF_OPTION_END
};


#if YAF_ENABLE_PAYLOAD
static AirOptionEntry yaf_optent_payload[] = {
    AF_OPTION("max-payload", 's', 0, AF_OPT_TYPE_INT, &yaf_opt_max_payload,
              AF_OPTION_WRAP "Maximum payload to capture per flow [0]",
              "octets"),
    AF_OPTION("export-payload", 0, 0, AF_OPT_TYPE_NONE,
              &yaf_opt_payload_export_on,
              AF_OPTION_WRAP "Enable payload export", NULL),
#if YAF_ENABLE_APPLABEL
    AF_OPTION("payload-applabel-select", 0, 0, AF_OPT_TYPE_STRING,
              &yaf_opt_payload_applabels,
              AF_OPTION_WRAP "Export payload for only these silkApplabels",
              "appLabel[,appLabel...]"),
#endif  /* YAF_ENABLE_APPLABEL */
    AF_OPTION("udp-payload", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_udp_max_payload,
              AF_OPTION_WRAP "Capture maximum payload for udp flow", NULL),
    AF_OPTION("max-export", 0, 0, AF_OPT_TYPE_INT, &yaf_opt_payload_export,
              AF_OPTION_WRAP "Maximum payload to export per flow direction"
              AF_OPTION_WRAP "when export-payload is active [max-payload]",
              "octets"),
#if YAF_ENABLE_ENTROPY
    AF_OPTION("entropy", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_entropy_mode,
              AF_OPTION_WRAP "Export Shannon entropy of captured payload",
              NULL),
#endif
#if YAF_ENABLE_APPLABEL
    AF_OPTION("applabel-rules", 0, 0, AF_OPT_TYPE_STRING,
              &yaf_opt_applabel_rules,
              AF_OPTION_WRAP "Specify the name of the application labeler"
              AF_OPTION_WRAP "rules file", "file"),
    AF_OPTION("applabel", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_applabel_mode,
              AF_OPTION_WRAP "Enable the packet inspection protocol"
              AF_OPTION_WRAP "application labeler engine", NULL),
#endif /* if YAF_ENABLE_APPLABEL */
#if YAF_ENABLE_NDPI
    AF_OPTION("ndpi", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_ndpi,
              AF_OPTION_WRAP "Enable nDPI application labeling", NULL),
    AF_OPTION("ndpi-protocol-file", 0, 0, AF_OPT_TYPE_STRING,
              &yaf_ndpi_proto_file,
              AF_OPTION_WRAP "Specify protocol file for sub-protocol"
              AF_OPTION_WRAP "and port-based protocol detection", "file"),
#endif /* if YAF_ENABLE_NDPI */
#if YAF_ENABLE_P0F
    AF_OPTION("p0f-fingerprints", 0, 0, AF_OPT_TYPE_STRING,
              &yaf_opt_p0f_fingerprints,
              AF_OPTION_WRAP "Specify the location of the p0f fingerprint"
              AF_OPTION_WRAP "files", "file"),
    AF_OPTION("p0fprint", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_p0fprint_mode,
              AF_OPTION_WRAP "Enable the p0f OS fingerprinter", NULL),
#endif /* if YAF_ENABLE_P0F */
#if YAF_ENABLE_FPEXPORT
    AF_OPTION("fpexport", 0, 0, AF_OPT_TYPE_NONE, &yaf_opt_fpExport_mode,
              AF_OPTION_WRAP "Enable export of handshake headers for"
              AF_OPTION_WRAP "external OS fingerprinters", NULL),
#endif /* if YAF_ENABLE_FPEXPORT */
    AF_OPTION_END
};
#endif /* if YAF_ENABLE_PAYLOAD */

#ifdef YAF_ENABLE_HOOKS
static AirOptionEntry yaf_optent_plugin[] = {
    AF_OPTION("plugin-name", 0, 0, AF_OPT_TYPE_STRING, &pluginName,
              AF_OPTION_WRAP "Load a yaf plugin(s)",
              "libplugin_name[,libplugin_name...]"),
    AF_OPTION("plugin-opts", 0, 0, AF_OPT_TYPE_STRING, &pluginOpts,
              AF_OPTION_WRAP "Parse options to the plugin(s)",
              "\"plugin_opts[,plugin_opts...]\""),
    AF_OPTION("plugin-conf", 0, 0, AF_OPT_TYPE_STRING, &pluginConf,
              AF_OPTION_WRAP "Configuration file for the plugin(s)",
              "\"plugin_conf[,plugin_conf...]\""),
    AF_OPTION_END
};
#endif /* ifdef YAF_ENABLE_HOOKS */

/**
 * yfVersionString
 *
 * Print version info and info about how YAF was configured
 *
 */
static GString *
yfVersionString(
    const char  *verNumStr)
{
    GString *resultString;

    resultString = g_string_new(NULL);

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
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Bivio support:",
#if YAF_ENABLE_BIVIO
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "PFRING support:",
#if YAF_ENABLE_PFRING
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Compact IPv4 support:",
#if YAF_ENABLE_COMPACT_IP4
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
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Entropy support:",
#if YAF_ENABLE_ENTROPY
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Fingerprint Export Support:",
#if YAF_ENABLE_FPEXPORT
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "P0F Support:",
#if YAF_ENABLE_P0F
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Spread Support:",
#if HAVE_SPREAD
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "MPLS Support:",
#if YAF_MPLS
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Non-IP Support:",
#if YAF_NONIP
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Separate Interface Support:",
#if YAF_ENABLE_SEPARATE_INTERFACES
                           "YES"
#elif YAF_ENABLE_DAG_SEPARATE_INTERFACES
                           "YES (Dag)"
#else
                           "NO"
#endif /* if YAF_ENABLE_SEPARATE_INTERFACES */
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "nDPI Support:",
#if YAF_ENABLE_NDPI
                           "YES"
#else
                           "NO"
#endif
                           );

    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "IE Metadata Export:",
#if YAF_ENABLE_METADATA_EXPORT
                           "YES"
#else
                           "NO"
#endif
                           );

    return resultString;
}


#ifdef HAVE_SPREAD
static void
groups_from_list(
    char      *list,
    char    ***groups,
    uint16_t **spreadIndex,
    uint8_t   *numSpreadGroups)
{
    gchar  **sa = g_strsplit( list, ",", -1 );
    int      n = 0, x = 0, g = 0, spaces = 0;
    gchar  **spread_split = NULL;
    gboolean catch_all_group = FALSE;

    while (sa[n] && *sa[n]) {
        ++n;
    }
    g_debug("Adding Spread Groups: %s", list);

    *groups = g_new0( char *, n + 1 );

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
static void
yfExit(
    void)
{
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
static void
yfDaemonize(
    void)
{
    pid_t pid;
    int   rv = -1;
    char  str[256];
    int   fp;

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
        fp = open(yaf_pidfile, O_RDWR | O_CREAT, 0640);
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
#define yf_lua_getnum(_key_, _ret_)       \
    lua_getglobal(L, _key_);              \
    if (!lua_isnil(L, -1)) {              \
        _ret_ = (int)lua_tonumber(L, -1); \
    }                                     \
    lua_pop(L, 1);

#define yf_lua_getstr(_key_, _ret_)          \
    lua_getglobal(L, _key_);                 \
    if (!lua_isnil(L, -1)) {                 \
        _ret_ = strdup(lua_tostring(L, -1)); \
    }                                        \
    lua_pop(L, 1);

#define yf_lua_getbool(_key_, _ret_)       \
    lua_getglobal(L, _key_);               \
    if (!lua_isnil(L, -1)) {               \
        _ret_ = (int)lua_toboolean(L, -1); \
    }                                      \
    lua_pop(L, 1);

#define yf_lua_checktablebool(_key_, _val_) \
    lua_pushstring(L, _key_);               \
    lua_gettable(L, -2);                    \
    if (!lua_isnil(L, -1)) {                \
        _val_ = (int)lua_toboolean(L, -1);  \
    }                                       \
    lua_pop(L, 1);

#define yf_lua_gettableint(_key_, _val_)           \
    lua_pushstring(L, _key_);                      \
    lua_gettable(L, -2);                           \
    if (!lua_isnil(L, -1)) {                       \
        if (!lua_isnumber(L, -1)) {                \
            g_error("%s must be a number", _key_); \
        }                                          \
        _val_ = (int)lua_tonumber(L, -1);          \
    }                                              \
    lua_pop(L, 1);

static int
yfLuaGetLen(
    lua_State  *L,
    int         index)
{
    int len = 0;

    lua_len(L, index);
    len = lua_tointeger(L, -1);
    lua_pop(L, 1);

    return len;
}


static char *
yfLuaGetStrField(
    lua_State   *L,
    const char  *key)
{
    const char *result;

    lua_pushstring(L, key);
    lua_gettable(L, -2);

    result = lua_tostring(L, -1);
    lua_pop(L, 1);

    return (char *)g_strdup(result);
}

static void
yfLuaGetSaveTablePort(
    lua_State   *L,
    const char  *table,
    GArray      *ports_array)
{
    lua_getglobal(L, table);
    if (!lua_isnil(L, -1)) {
        if (lua_istable(L, -1)) {
            gboolean warned = FALSE;
            long     i, port;
            int      len = yfLuaGetLen(L, -1);

            /* Add the ports to the array */
            for (i = 1; i <= len; ++i) {
                lua_rawgeti(L, -1, i);
                if (lua_isnumber(L, -1)) {
                    port = (long)lua_tonumber(L, -1);
                    if (port < 0 || port > UINT16_MAX) {
                        g_warning("Ignoring out-of-range port entry %ld in %s",
                                  port, table);
                    }
                    g_array_append_val(ports_array, port);
                } else if (!warned) {
                    warned = TRUE;
                    g_warning("Ignoring non-number entry in %s", table);
                }
                lua_pop(L, 1);
            }

            /* Finished with the table */
            lua_pop(L, 1);
        } else {
            air_opterr("%s is not a valid table. Should be in the form:"
                       " %s = { 4789, 6081, ...}", table, table);
        }
    }
}

/**
 * yfLuaLoadConfig
 *
 *
 */
static void
yfLuaLoadConfig(
    void)
{
    lua_State *L = luaL_newstate();
    int        i, len;
    char      *str = NULL;
    GError    *err = NULL;

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
                    yaf_config.spreadparams.groups = g_new0( char *, len + 1);
                    yaf_config.spreadGroupIndex = g_new0(uint16_t, len);
                }
                for (i = 1; i <= len; i++) {
                    lua_rawgeti(L, -1, i);
                    if (!lua_istable(L, -1)) {
                        air_opterr("group must be a valid table. Should be "
                                   "in the form: {name=\"NAME\", [value=]}");
                    }
                    yaf_config.spreadparams.groups[i - 1] =
                        yfLuaGetStrField(L, "name");
                    yf_lua_gettableint("value",
                                       yaf_config.spreadGroupIndex[i - 1]);
                    lua_pop(L, 1);
                }
            }
#else /* ifdef HAVE_SPREAD */
            air_opterr("Spread is not enabled. Configure --with-spread");
#endif /* ifdef HAVE_SPREAD */
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

#if YAF_ENABLE_APPLABEL
    /* enable payload export but only for these applabels */
    lua_getglobal(L, "export_payload_applabels");
    if (!lua_isnil(L, -1)) {
        GArray   *applabels;
        gboolean  warned = FALSE;
        long      applabel;

        if (!lua_istable(L, -1)) {
            air_opterr("export_payload_applabels is not a valid table."
                       " Should be in the form:"
                       " export_payload_applabels = { 80, 25, ...}");
        }
        len = yfLuaGetLen(L, -1);
        applabels = g_array_sized_new(FALSE, FALSE, sizeof(applabel), len);
        for (i = 1; i <= len; ++i) {
            lua_rawgeti(L, -1, i);
            if (lua_isnumber(L, -1)) {
                applabel = (long)lua_tonumber(L, -1);
                if (applabel >= 0 && applabel <= UINT16_MAX) {
                    g_array_append_val(applabels, applabel);
                }
            } else if (!warned) {
                warned = TRUE;
                g_warning("Ignoring non-number entry in"
                          " export_payload_applabels");
            }
            lua_pop(L, 1);
        }
        /* Finished with the table */
        lua_pop(L, 1);
        if (0 == applabels->len) {
            air_opterr("Found no valid applabels in export_payload_applabels");
        }
        yaf_opt_payload_export_on = TRUE;
        yfWriterExportPayloadApplabels(applabels);
        g_array_free(applabels, TRUE);
    }
#endif  /* YAF_ENABLE_APPLABEL */

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
        yf_lua_checktablebool("vxlan", yaf_opt_vxlan_mode);
        yf_lua_checktablebool("geneve", yaf_opt_geneve_mode);
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
#if YAF_ENABLE_METADATA_EXPORT
        yf_lua_checktablebool("metadata", yaf_config.tmpl_metadata);
#endif
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
                if (!yfHookAddNewHook(
                        pluginName, pluginOpts, pluginConf, yfctx, &err))
                {
                    g_warning("Couldn't load requested plugin: %s",
                              err->message);
                }
                hooks_initialized = TRUE;
            }
            lua_pop(L, 1);
        }
    }
#endif /* if YAF_ENABLE_HOOKS */

    /* Use these ports to trigger VxLAN or Geneve decoding */
    yfLuaGetSaveTablePort(L, "vxlan_ports", yaf_opt_vxlan_ports);
    yfLuaGetSaveTablePort(L, "geneve_ports", yaf_opt_geneve_ports);


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
static void
yfParseOptions(
    int   *argc,
    char **argv[])
{
    AirOptionCtx *aoctx = NULL;
    GError       *err = NULL;
    GString      *versionString;

    aoctx = air_option_context_new("", argc, argv, yaf_optent_core);

    /* Initialize opt variables */
    yaf_opt_vxlan_ports = g_array_new(FALSE, TRUE, sizeof(uint16_t));
    yaf_opt_geneve_ports = g_array_new(FALSE, TRUE, sizeof(uint16_t));

    air_option_context_add_group(
        aoctx, "decode", "Decoder Options:",
        AF_OPTION_WRAP "Show help for packet decoder options", yaf_optent_dec);
    air_option_context_add_group(
        aoctx, "flow", "Flow table Options:",
        AF_OPTION_WRAP "Show help for flow table options", yaf_optent_flow);
    air_option_context_add_group(
        aoctx, "export", "Export Options:",
        AF_OPTION_WRAP "Show help for export format options", yaf_optent_exp);
    air_option_context_add_group(
        aoctx, "ipfix", "IPFIX Options:",
        AF_OPTION_WRAP "Show help for IPFIX export options", yaf_optent_ipfix);
    air_option_context_add_group(
        aoctx, "pcap", "PCAP Options:",
        AF_OPTION_WRAP "Show help for PCAP Export Options", yaf_optent_pcap);
#if YAF_ENABLE_PAYLOAD
    air_option_context_add_group(
        aoctx, "payload", "Payload Options:",
        AF_OPTION_WRAP "Show help for payload options", yaf_optent_payload);
#endif /* if YAF_ENABLE_PAYLOAD */
#ifdef YAF_ENABLE_HOOKS
    air_option_context_add_group(
        aoctx, "plugin", "Plugin Options:",
        AF_OPTION_WRAP "Show help for plugin interface options",
        yaf_optent_plugin);
#endif /* ifdef YAF_ENABLE_HOOKS */
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
    yaf_opt_finalize_decode_ports();

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
#endif /* if YAF_ENABLE_APPLABEL */
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
#endif /* if YAF_ENABLE_NDPI */

#if YAF_ENABLE_P0F
    if (yaf_opt_p0f_fingerprints && (FALSE == yaf_opt_p0fprint_mode)) {
        g_warning("--p0f-fingerprints requires --p0fprint.");
        g_warning("p0f fingerprinting engine will not operate");
        yaf_opt_p0fprint_mode = FALSE;
    }
    if (TRUE == yaf_opt_p0fprint_mode) {
        if (yaf_opt_max_payload == 0) {
            g_warning("--p0fprint requires --max-payload");
            yaf_opt_p0fprint_mode = FALSE;
        } else if (!yfpLoadConfig(yaf_opt_p0f_fingerprints, &err)) {
            g_warning("Error loading config files: %s", err->message);
            yaf_opt_p0fprint_mode = FALSE;
            g_clear_error(&err);
        }
    }
#endif /* if YAF_ENABLE_P0F */
#if YAF_ENABLE_FPEXPORT
    if (TRUE == yaf_opt_fpExport_mode) {
        if (yaf_opt_max_payload == 0) {
            g_warning("--fpexport requires --max-payload.");
            yaf_opt_fpExport_mode = FALSE;
        }
    }
#endif /* if YAF_ENABLE_FPEXPORT */
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
#endif /* if YAF_ENABLE_ENTROPY */

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

#if YAF_ENABLE_APPLABEL
    if (yaf_opt_payload_applabels) {
        gchar      **labels = g_strsplit(yaf_opt_payload_applabels, ",", -1);
        GArray      *applabels = NULL;
        char        *ep;
        unsigned int i;
        long         applabel;

        /* count entries in the list to size the GArray */
        for (i = 0; labels[i] != NULL; ++i)
            ;                   /* empty */

        applabels = g_array_sized_new(FALSE, FALSE, sizeof(applabel), i);
        for (i = 0; labels[i] != NULL; ++i) {
            ep = labels[i];
            errno = 0;
            applabel = strtol(labels[i], &ep, 0);
            if (applabel >= 0 && applabel <= UINT16_MAX &&
                ep != labels[i] && 0 == errno)
            {
                g_array_append_val(applabels, applabel);
            }
        }

        if (applabels->len > 0) {
            yaf_opt_payload_export_on = TRUE;
            yfWriterExportPayloadApplabels(applabels);
        }
        g_strfreev(labels);
        g_array_free(applabels, TRUE);
        g_free(yaf_opt_payload_applabels);
    }
#endif  /* YAF_ENABLE_APPLABEL */

    /* process core library options */
    if (yaf_opt_payload_export_on && !yaf_opt_payload_export) {
        yaf_opt_payload_export = yaf_opt_max_payload;
    }

    if (yaf_opt_payload_export > yaf_opt_max_payload) {
        g_warning(
            "--max-export can not be larger than max-payload.  Setting to %d",
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
#endif /* if YAF_ENABLE_DAG */
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
#endif /* if YAF_ENABLE_NAPATECH */
#if YAF_ENABLE_NETRONOME
        } else if (strncmp(yaf_config.livetype, "netronome", 9) == 0) {
            yaf_liveopen_fn = (yfLiveOpen_fn)yfNFEOpenLive;
            yaf_loop_fn = (yfLoop_fn)yfNFEMain;
            yaf_close_fn = (yfClose_fn)yfNFEClose;
            if (yaf_config.pcapdir) {
                g_warning("--pcap not valid for --live netronome");
                yaf_config.pcapdir = NULL;
            }
#endif /* if YAF_ENABLE_NETRONOME */
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
#endif /* if YAF_ENABLE_PFRINGZC */
#endif /* if YAF_ENABLE_PFRING */
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
        yaf_close_fn = (yfClose_fn)yfCapClose;

        /* Default to stdin for no input */
        if (!yaf_config.inspec || !strlen(yaf_config.inspec)) {
            yaf_config.inspec = C("-");
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
    yaf_config.layer2IdExportMode = yaf_opt_vxlan_mode || yaf_opt_geneve_mode;
    yaf_config.ingressInt = (uint32_t)yaf_opt_ingress_int;
    yaf_config.egressInt = (uint32_t)yaf_opt_egress_int;

    /* Pre-process output options */
    if (yaf_opt_ipfix_transport) {
        /* set default port */
        if (!yaf_config.connspec.svc) {
            yaf_config.connspec.svc = yaf_opt_ipfix_tls ? C("4740") : C("4739");
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
                 *  air_opterr("Invalid groupby: Must have values to group by"
                 *             " in --group");
                 *             }*/
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
                    yaf_config.outspec = C("-");
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
        if ((strlen(yaf_config.outspec) == 1) && yaf_config.outspec[0] == '-') {
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


/**
 * @brief Parse the comma separated ports string and append the values into
 * the GArray
 *
 * @param option_name The option that called this function
 * @param ports_str A comma separated string of ports between 0 and 65535
 *        inclusive
 * @param ports_array The GArray to append the ports to
 * @param error The return location for a recoverable error
 */
static void
yaf_opt_ports_str_2_array(
    const gchar  *option_name,
    const gchar  *ports_str,
    GArray       *ports_array,
    GError      **error)
{
    gchar **ports = g_strsplit(ports_str, ",", -1);
    char   *ep;
    long    port;

    /* Append the ports into the array */
    for (uint16_t i = 0; ports[i] != NULL; ++i) {
        ep = ports[i];
        errno = 0;
        port = strtol(ports[i], &ep, 0);
        if (port >= 0 && port <= UINT16_MAX && ep != ports[i] && 0 == errno) {
            g_array_append_val(ports_array, port);
        } else {
            g_warning("Ignoring out-of-range port entry %ld in %s",
                      port, option_name);
        }
    }
    g_strfreev(ports);
}

/**
 * @brief OptionArgFunc to read vxlan-decode-ports from command line options
 *
 * @param option_name The name of the option being parsed
 * @param yaf_opt_vxlan_ports_str The value to be parsed
 * @param data User data added to the GOptionGroup ogroup
 * @param error The return location for a recoverable error
 */
static void
yaf_opt_save_vxlan_ports(
    const gchar  *option_name,
    const gchar  *yaf_opt_vxlan_ports_str,
    gpointer      data,
    GError      **error)
{
    yaf_opt_ports_str_2_array(option_name, yaf_opt_vxlan_ports_str,
                              yaf_opt_vxlan_ports, error);
}

/**
 * @brief OptionArgFunc to read geneve-decode-ports from command line options
 *
 * @param option_name The name of the option being parsed
 * @param yaf_opt_geneve_ports_str The value to be parsed
 * @param data User data added to the GOptionGroup ogroup
 * @param error The return location for a recoverable error
 */
static void
yaf_opt_save_geneve_ports(
    const gchar  *option_name,
    const gchar  *yaf_opt_geneve_ports_str,
    gpointer      data,
    GError      **error)
{
    yaf_opt_ports_str_2_array(option_name, yaf_opt_geneve_ports_str,
                              yaf_opt_geneve_ports, error);
}

/**
 * @brief Remove duplicate uint16's from GArray in-place.
 *
 * @param g The GArray to edit
 */
static void
yaf_opt_remove_array_dups(
    GArray  *g)
{
    if (g->len <= 1) {
        return;
    }
    guint i = 0, j = 0;
    while (i < (g->len - 1)) {
        j = i + 1;
        uint16_t a = g_array_index(g, uint16_t, i);
        while (j < g->len) {
            uint16_t b = g_array_index(g, uint16_t, j);
            if (a == b) {
                g_array_remove_index(g, j);
            } else {
                j++;
            }
        }
        i++;
    }
}

/**
 * @brief Finalize the GArrays used in yaf options.
 *
 */
static void
yaf_opt_finalize_decode_ports(
    void)
{
    /* Make sure the ports array is NULL if the decoding mode is not enabled */
    if (!yaf_opt_vxlan_mode && yaf_opt_vxlan_ports) {
        g_array_free(yaf_opt_vxlan_ports, TRUE);
        yaf_opt_vxlan_ports = NULL;
    }
    if (!yaf_opt_geneve_mode && yaf_opt_geneve_ports) {
        g_array_free(yaf_opt_geneve_ports, TRUE);
        yaf_opt_geneve_ports = NULL;
    }

    /* Finalize the ports arrays by setting defaults and removing duplicates */
    if (yaf_opt_vxlan_mode) {
        if (yaf_opt_vxlan_ports->len > 0) {
            yaf_opt_remove_array_dups(yaf_opt_vxlan_ports);
        } else {
            uint16_t default_port = DEFAULT_VXLAN_PORT;
            g_array_append_val(yaf_opt_vxlan_ports, default_port);
        }
    }
    if (yaf_opt_geneve_mode) {
        if (yaf_opt_geneve_ports->len > 0) {
            yaf_opt_remove_array_dups(yaf_opt_geneve_ports);
        } else {
            uint16_t default_port = DEFAULT_GENEVE_PORT;
            g_array_append_val(yaf_opt_geneve_ports, default_port);
        }
    }
}

#ifdef YAF_ENABLE_HOOKS
/*
 * yfPluginLoad
 *
 * parses parameters for plugin loading and calls the hook add function to
 * load the plugins
 *
 */
static void
pluginOptParse(
    GError **err)
{
    char         *plugName, *endPlugName = NULL;
    char         *plugOpt, *endPlugOpt = NULL;
    char         *plugConf, *endPlugConf = NULL;
    char         *plugNameIndex, *plugOptIndex, *plugConfIndex;
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
            } else if (plugOptIndex == endPlugOpt) {
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
            } else if (plugConfIndex == endPlugConf) {
                plugConf = NULL;
            } else {
                plugConf = g_new0(char, (endPlugConf - plugConfIndex + 1));
                strncpy(plugConf, plugConfIndex, (endPlugConf - plugConfIndex));
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


#endif /* ifdef YAF_ENABLE_HOOKS */

/**
 *
 *
 *
 *
 *
 */
static void
yfQuit(
    int   s)
{
    (void)s;
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
static void
yfQuitInit(
    void)
{
    struct sigaction sa, osa;

    /* install quit flag handlers */
    sa.sa_handler = yfQuit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &sa, &osa)) {
        g_error("sigaction(SIGINT) failed: %s", strerror(errno));
    }

    sa.sa_handler = yfQuit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, &osa)) {
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
int
main(
    int    argc,
    char  *argv[])
{
    GError     *err = NULL;
    yfContext_t ctx = YF_CTX_INIT;
    int         datalink;
    gboolean    loop_ok = TRUE;

    /* check structure alignment */
    yfAlignmentCheck();

    /* parse options */
    yfParseOptions(&argc, &argv);
    ctx.cfg = &yaf_config;

    /* record yaf start time */
    ctx.yaf_start_time = time(NULL) * 1000;

    /* Set up quit handler */
    yfQuitInit();

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
                if (g_error_matches(err, PRIVC_ERROR_DOMAIN,
                                    PRIVC_ERROR_NODROP))
                {
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
         * for possible PCAP capture */
        ctx.pbuflen = YF_PBUFLEN_BASE + yaf_opt_max_payload + 54;
    } else {
        ctx.pbuflen = YF_PBUFLEN_NOPAYLOAD;
    }

    /* Allocate a packet ring. */
    ctx.pbufring = rgaAlloc(ctx.pbuflen, 128);

    /* Set up decode context */
    ctx.dectx = yfDecodeCtxAlloc(datalink,
                                 yaf_reqtype,
                                 yaf_opt_gre_mode,
                                 yaf_opt_vxlan_ports,
                                 yaf_opt_geneve_ports);

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
    * and all the tables we need. Run with it. */

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
