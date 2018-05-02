/*
 ** public.h
 ** fixbuf IPFIX Implementation Public Interface
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2018 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell, Dan Ruef
 ** ------------------------------------------------------------------------
 ** Use of the libfixbuf system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** Copyright 2018 Carnegie Mellon University. All Rights Reserved.
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
 ** License.txt or contact permission@sei.cmu.edu for full terms.
 **
 ** [DISTRIBUTION STATEMENT A] This material has been approved for
 ** public release and unlimited distribution.  Please see Copyright
 ** notice for non-US Government use and distribution.
 **
 ** Carnegie Mellon® and CERT® are registered in the U.S. Patent and
 ** Trademark Office by Carnegie Mellon University.
 **
 ** ------------------------------------------------------------------------
 */

/**
 * @mainpage libfixbuf - IPFIX Protocol Library
 *
 * \subpage How-To
 *
 * @section Introduction
 *
 * libfixbuf is a compliant implementation of the IPFIX Protocol,
 * as defined in the "Specification of the IPFIX Protocol for the Export of IP
 * Flow Information" (RFC 5101). It supports the information model
 * defined in "Information Model for IP Flow Information Export"
 * (RFC 5102), extended as proposed by "Bidirectional Flow Export using
 * IPFIX" (RFC 5103) to support information elements for representing biflows.
 *
 * libfixbuf supports UDP, TCP, SCTP, TLS over TCP, and Spread as transport
 * protocols. Support for DTLS over UDP and DTLS over SCTP is forthcoming.
 * It also supports operation as an IPFIX File Writer or IPFIX File Reader as
 * defined in "An IPFIX-Based File Format" (draft-trammell-ipfix-file, current
 * revision -05).
 *
 * As of version 1.0, libfixbuf supports structured data elements as described
 * in "Export of Structured Data in IPFIX" (RFC 6313).  This adds the ability
 * to export basicLists, subTemplateLists, and subTemplateMultiLists.

 * libfixbuf's public API is defined in public.h; see the \ref How-To section
 * or public.h for general documentation on getting started with libfixbuf, as
 * well as detailed documentation on the public API calls and data types.
 *
 * @section Downloading
 *
 * libfixbuf is distributed from http://tools.netsa.cert.org/fixbuf
 *
 * @section Building
 *
 * libfixbuf uses a reasonably standard autotools-based build system.
 * The customary build procedure (<tt>./configure && make
 * && make install</tt>) should work in most environments.
 *
 * libfixbuf requires glib-2.0 version 2.6.4 or later. If built against
 * version 2.10 or later, it will automatically use the glib slab allocator
 * for increased memory allocation performance. glib is available on most
 * modern Linux distributions and BSD ports collections, or in source form from
 * <a href="http://www.gtk.org">http://www.gtk.org</a>.
 *
 * libfixbuf automatically uses the getaddrinfo(3) facility and the
 * accompanying dual IPv4/IPv6 stack support if present. getaddrinfo(3)
 * must be present to export or collect flows over IPv6.
 *
 * libfixbuf does not build with SCTP support by default. The --with-sctp
 * option must be given to the libfixbuf ./configure script to include SCTP
 * support. Also note that SCTP requires kernel support, and applications
 * built against libfixbuf with libsctp may fail at runtime if that kernel
 * support is not present.
 *
 * libfixbuf does not build with TLS support by default. The --with-openssl
 * option must be given to the libfixbuf ./configure script to include TLS
 * support.
 *
 * Spread support requires <a href="http://www.spread.org">Spread</a> 4.1 or
 * later. libfixbuf does not build with Spread support by default.
 * The --with-spread option must be given to libfixbuf ./configure script to
 * include Spread support.
 *
 * @section Known Issues
 *
 * The following are known issues with libfixbuf as of version 1.0.0:
 *
 * <ul>
 * <li>There is no support for DTLS over UDP or DTLS over SCTP transport.</li>
 * <li>There is no support for application-selectable SCTP stream assignment
 *     or SCTP partial reliability. Templates are sent reliably on stream 0,
 *     and data sets are sent reliably on stream 1.
 * </li>
 * <li>There is no automatic support for periodic template retransmission
 *     or periodic template expiration as required when transporting IPFIX
 *     over UDP. Applications using libfixbuf to transport IPFIX messages
 *     over UDP must maintain these timeouts and manually manage the session.
 *     However, inactive UDP collector sessions are timed out after 30 minutes,
 *     at which time the session is freed and all templates associated with the
 *     session are removed.
 * </li>
 * </ul>
 *
 * @section Copyright
 *
 * libfixbuf is copyright 2005-2017 Carnegie Mellon University, and is released
 * under the GNU Lesser General Public License (LGPL). See the COPYING file in
 * the distribution for details.
 *
 * libfixbuf was developed at Carnegie Mellon University
 * by Brian Trammell and the CERT Network Situational Awareness Group
 * Engineering Team for use in the YAF and SiLK tools.
 *
 */

/**
 *
 * @page How-To Getting started with libfixbuf
 *
 * Include fixbuf/public.h
 * in order to use the public fixbuf API.
 *
 * This documentation uses IPFIX terminology as defined in RFC 5101,
 * "Specification of the IPFIX Protocol for the Exchange of IP Traffic Flow
 * Information"
 *
 * The following sections provide information on specific libfixbuf usage:
 *
 * - \ref export Exporters
 * - \ref read  IPFIX File Collectors
 * - \ref collect Network Collectors
 * - \ref udp UDP Collectors
 * - \ref v9 NetFlow v9 Collectors
 * - \ref sflow sFlow Collectors
 * - \ref spread Spread Collectors
 * - \ref noconnect Connection-less collector
 * - \ref lists BasicLists, SubTemplateLists, SubTemplateMultiLists
 * - \ref rfc_5610 RFC 5610
 *
 * @section types Data Types
 *
 * public.h defines the data types and routines required to support IPFIX
 * Exporting Process and IPFIX Collecting Process creation. Each data type is
 * manipulated primarily by routines named "fb" followed by the type name
 * (e.g., "Session", "Collector") followed by a description of the routine's
 * action. The routines operating on the fBuf_t IPFIX Mesaage buffer type are
 * named beginning with "fBuf".
 *
 * The fBuf_t opaque type implements a transcoding IPFIX Message buffer for
 * both export and collection, and is the "core" interface to the fixbuf
 * library.
 *
 * The fbInfoModel_t opaque type implements an IPFIX Information Model,
 * including both IANA managed Information Elements and vendor-specific
 * Information Elements. The fbTemplate_t opaque type implements an IPFIX
 * Template or an IPFIX Options Template. Both are defined in terms of
 * Information Elements, represented by the fbInfoElement_t public type.
 * An fBuf_t message buffer maintains internal Templates, which represent
 * records within the fixbuf application client, and external Templates,
 * which represent records as they appear on the wire, for use during
 * transcoding. For a Spread Exporter, Templates are managed per group.  For
 * a Spread Collector, Templates are managed per Session.
 *
 * The state of an IPFIX Transport Session, including IPFIX Message Sequence
 * Number tracking and the internal and external Templates in use within the
 * Session, are maintained by the fbSession_t opaque type.
 *
 * An Exporting Process' connection to its corresponding Collecting Process
 * is encapsulated by the fbExporter_t opaque type. Exporters may be created
 * to connect via the network using one of the supported IPFIX transport
 * protocols, or to write to IPFIX Files specified by name or by open ANSI C
 * file pointer.
 *
 * A Collecting Process' connection to a corresponding Exporting Process is
 * encapsulated by the fbCollector_t opaque type. The passive connection used
 * to listen for connections from Exporting Processes is managed by the
 * fbListener_t opaque type; Collectors can be made to read from IPFIX Files
 * specified directly by name or by open ANSI C file pointer, as well.
 *
 * Network addresses are specified for Exporters, Collectors, and Listeners
 * using the fbConnSpec_t and fbTransport_t public types.
 *
 * This file also defines the GError error codes used by all the fixbuf types
 * and routines within the FB_ERROR_DOMAIN domain.
 *
 * @page export Exporter Usage
 *
 * How-To Export IPFIX:
 * Each fixbuf application must have a single fbInfoModel_t instance that
 * represents the Information Elements that the application understands.
 * The fbInfoModelAlloc() call allocates a new Information Model with the
 * IANA-managed information elements (current as of the fixbuf release date)
 * preloaded. Additional vendor-specific information elements may be added
 * with fbInfoModelAddElement() and fbInfoModelAddElementArray().
 *
 * To create an Exporter, first create an fbSession_t attached to the
 * application's fbInfoModel_t to hold the Exporter's Transport Session
 * state using fbSessionAlloc(). If exporting via the Spread protocol, create
 * an fbSpreadParams_t and set its session to your newly defined session,
 * group names (a null terminated array), and Spread daemon name.
 *
 * Then create an fbExporter_t to encapsulate the connection to the
 * Collecting Process or the file on disk, using the fbExporterAllocFP(),
 * fbExporterAllocFile(), fbExporterAllocNet(), fbExporterAllocBuffer(),
 * or fbExporterAllocSpread() calls.
 *
 * With an fbSession_t and an fbExporter_t available, create a buffer for
 * writing via fBufAllocForExport().
 *
 * Create and populate templates for addition to this session using the
 * fbTemplate calls, then add them to the session via fbSessionAddTemplate().
 *
 * If exporting via Spread, before calling fbSessionAddTemplate(), set the
 * group that should receive this template with the fBufSetSpreadExportGroup()
 * call.  If more than 1 group should receive the template, use the
 * fbSessionAddTemplatesMulticast() which will call fBufSetSpreadExportGroup()
 * on the given group(s) multicast the template to the given group(s).
 * For Spread, do not use fbSessionAddTemplate() to send to multiple groups.
 *
 * Once the templates have been added to the session, use
 * fbSessionExportTemplates() to add the templates to the buffer and then
 * set the internal and external template IDs with fBufSetInternalTemplate()
 * and fBufSetExportTemplate().  You can then use fBufAppend() to write
 * records into IPFIX Messages and Messages to the output stream.
 *
 * Note that Templates use internal reference counting, so they may be added
 * to multiple sessions, or to the same session using multiple template IDs or
 * multiple domains, or as both an internal and an external template on the
 * same session.
 *
 * By default, fBufAppend() will emit an IPFIX Message to the output stream
 * when the end of the message buffer is reached on write. The
 * fBufSetAutomaticMode() call can be used to modify this behavior,
 * causing fBufAppend() to return FB_ERROR_EOM when at end of message. Use
 * this if your application requires manual control of message export. In this
 * case, fBufEmit() will emit a Message to the output stream.  If using Spread,
 * call fBufSetSpreadExportGroup() to set the groups to export to on the
 * buffer before calling fBufAppend().
 *
 * @page read IPFIX File Collectors
 *
 * How-To Read IPFIX Files:
 *
 * Using fixbuf to read from IPFIX Files as a Collecting Process is very
 * much like the Export case. Create an fbInfoModel_t using fbInfoModelAlloc()
 * and any additional, vendor-specific information elements using
 * fbInfoModelAddElement() or fbInfoModelAddElementArray().  Next create
 * an fbSession_t using fbSessionAlloc() and add internal templates via
 * fbSessionAddTemplate(). External templates do not need to be added
 * for collection, as they will be loaded from templates in the file.
 *
 * Then create an fbCollector_t to encapsulate the file, using the
 * fbCollectorAllocFP() or fbCollectorAllocFile() calls.
 *
 * With an fbSession_t and an fbCollector_t available, create a buffer for
 * writing via fBufAllocForCollection(). Set the internal template
 * ID with fBufSetInternalTemplate(), and use
 * fBufNext() to read records from IPFIX Messages and Messages from the
 * input stream.
 *
 * By default, fBufNext() will consume an IPFIX Message from the input stream
 * when the end of the message buffer is reached on read. The
 * fBufSetAutomaticMode() call can be used to modify this behavior,
 * causing fBufNext() to return FB_ERROR_EOM when at end of message. Use
 * this if your application requires manual control of message collection.
 * In this case, fBufNextMessage() will consume a Message from the input
 * stream.
 *
 * @page collect Network Collectors
 *
 * Listening over the Network - TCP Recommended:
 *
 * An additional type, fbListener_t, is used to build Collecting Processes
 * to listen for connections from IPFIX Exporting Processes via the network.
 * To use a listener, first create an fbInfoModel_t using fbInfoModelAlloc()
 * and any additional, vendor-specific information elements using
 * fbInfoModelAddElement() or fbInfoModelAddElementArray().  Next create
 * an fbSession_t using fbSessionAlloc() and add internal templates via
 * fbSessionAddTemplate(). Instead of
 * maintaining state for a particular Transport Session, this fbSession_t
 * instance will be used as a template for each Transport Session created
 * by the listener.
 *
 * Then create an fbListener_t to encapsulate a passive socket on the network
 * to wait for connections from Exporting Processes using the
 * fbListenerAlloc() call.
 *
 * To wait for a connection from an Exporting Process, call fbListenerWait(),
 * which handles the cloning of the fbSession_t, the creation of the
 * fbCollector_t, and the creation of the buffer for reading from that
 * collector, and returns the newly created fBuf_t instance.
 *
 * A listener binds to each address returned by getaddrinfo().  Once a
 * packet has been received, the collector will only read packets on the
 * address it received the first packet UNLESS fbListenerWait() is called
 * again.  If the application is expecting multiple connections or IPFIX
 * records from multiple IPFIX (UDP) exporters, then the application should
 * put the fBuf_t returned from fbListenerWait() into to manual mode by
 * calling fBufSetAutomaticMode(fbuf, FALSE) and handle FB_ERROR_EOM errors
 * returned from fBufNext() by calling fbListenerWait() again.
 *
 * Each listener tracks every active collector/buffer (i.e., each active
 * Session) it created; the fbListenerWait() call will return an fBuf_t from
 * which another IPFIX Message may be read if no new connections are available.
 * The preferred parameter may be used to request an fBuf_t to try first, to
 * minimize switching among available Sessions. See the documentation for
 * fbListenerWait() for more details.
 *
 * If an application wants to wait for connections on multiple ports or
 * multiple transport protocols, the application can use fbListenerGroupWait()
 * to accept multiple connections.  The application should create separate
 * sessions and fbConnSpec_ts for each fbListener and call fbListenerAlloc()
 * to allocate each listener.  Create an fbListenerGroup_t by calling
 * fbListenerGroupAlloc() and add each listener to the group using
 * fbListenerGroupAddListener().  Instead of calling fbListenerWait(), use
 * the function fbListenerGroupWait() to listen on all addresses in the group.
 * fbListenerGroupWait() returns an fbListenerGroupResult_t which is a linked
 * list of results.  The fbListenerGroupResult_t contains a pointer to an
 * fBuf_t and the fbListener_t that created the fBuf_t as well as a pointer
 * to the next result, if available.  Use fbListenerFreeGroupResult() to free
 * the result when fBufNext() has been called on each fBuf_t.
 *
 * The application could also use fbListenerWaitNoCollectors() to handle only
 * the initial accepting of a connection (for TCP).  Once the application
 * returns to fbListenerWaitNoCollectors(), fixbuf will ignore that socket
 * descriptor for the length of the connection.
 *
 * Additionally, the application can use fbListenerOwnSocketCollectorTCP()
 * to provide its own socket for listening instead of libfixbuf creating
 * one for it.
 *
 * To reject incoming connections, the application should use the
 * fbListenerAppInit function callback.  This will be called right after
 * accept() is called (in the TCP case).  The application can veto the
 * connection by returning FALSE.  Once the connection is vetoed, fixbuf
 * will not listen on that socket descriptor.
 * If the appinit() function should reject a connection the application
 * should set the error code to FB_ERROR_NLREAD and the application should
 * ignore FB_ERROR_NLREAD error codes.  The appinit() function works slightly
 * different for UDP.  See the udp instructions for how to use appinit() for
 * collecting IPFIX over UDP.
 *
 * @page udp UDP Collectors
 *
 * How-To Collect IPFIX over UDP:
 *
 * It is not recommended to use UDP for IPFIX transport, since
 * UDP is not a reliable transport protocol, and therefore cannot guarantee
 * the delivery of messages.  libfixbuf stores sequence numbers and reports
 * protential loss of messages.  Templates over UDP must be re-sent at regular
 * intervals.  Fixbuf does not automatically retransmit messages at regular
 * intervals, it is left to the application author to call
 * fbSessionExportTemplates().  In accordance with RFC 5101, the templates
 * should be resent at least three times in the Template refresh timeout
 * period.  Make sure the record size does not exceed the path MTU.
 * libfixbuf will return an error if the message exceeds the path MTU.
 *
 * A UDP collector session is associated with a unique IP, observation domain
 * pair.  UDP sessions timeout after 30 minutes of inactivity.  When a session
 * times out, all templates and state are discarded, this includes any related
 * NetFlow v9 templates and/or state.  libfixbuf will discard
 * any data records for which it does not contain a template for. Template IDs
 * are unique per UDP session (IP and Observation Domain.) Once
 * templates are refreshed, old templates may not be used or referenced by
 * the collecting session.  A UDP collector manages multiple sessions on
 * one collector and fbuf.  If the application is using the fbListenerAppInit
 * and fbListenerAppFree functions to maintain context per session, it is
 * necessary to call fbCollectorGetContext() after each call to fBufNext() to
 * receive the correct ctx pointer (as opposed to calling it after
 * fbListenerWait() returns in the TCP case).  If the application needs to
 * manage context PER SESSION, the application must turn on multi-session mode
 * w/ fbCollectorSetUDPMultiSession() (this allows for backwards compatibility
 * with old applications.)  Previously, the appinit() function was called
 * only from fbListenerAlloc() for UDP connections, which did not allow the
 * application the peer information.  The appinit() function is now called
 * during fbListenerAlloc() (with a NULL peer address) and also when
 * a new UDP connection is made to the collector, giving the application
 * veto power over session creation.  If the application does not call
 * fbCollectorSetUDPMultiSession(), the application will not receive the
 * callback to it's appinit() function, which only allows the application
 * to set one ctx pointer on all sessions.  Likewise, appfree() is only
 * called once, when the collector is freed, if not in multi-session mode.
 * If the application is in multi-session mode, appfree() will be called
 * once for each session when the collector is freed AND anytime a session
 * is timed out.

 * Note: If the appinit() function returns FALSE, libfixbuf will
 * reject any subsequent messages from the
 * peer address, observation domain until the timeout period has expired.
 * If the appinit() function should reject a "connection" the application
 * should set the error code to FB_ERROR_NLREAD and return FALSE.
 *      Example usage:
 *     \code{.c}
 *         g_set_error(error, FB_ERROR_DOMAIN, FB_ERROR_NLREAD, "some msg");
 *      \endcode
 *
 *
 * To only accept IPFIX from one host without using the appinit() and
 * appfree() functions, it is encouraged to
 * use fbCollectorSetAcceptOnly().  UDP messages received from other hosts
 * will return FB_ERROR_NLREAD.  The application should ignore errors with
 * this error code by clearing the error and calling fBufNext().
 *
 * @page v9  NetFlow v9 Collectors
 *
 * How-To use libfixbuf as a NetFlow v9 Collector:
 *
 * libfixbuf can be used as a NetFlow v9 collector and convert NetFlow to
 * IPFIX.  Follow the steps above to create an fbListener.  After creating
 * the listener, retrieve the collector by calling fbListenerGetCollector()
 * before calling fbCollectorSetNetflowV9Translator().  Fixbuf can decode all
 * NetFlow v9 information elements up to 346.  Since fixbuf removes the
 * SysUpTime from the NetFlow v9 Header, when fixbuf encounters elements 21
 * and 22 (which rely on the SysUpTime to determine flow start and end times)
 * it will add IPFIX Element 160 (systemInitTimeMilliseconds) to the template
 * and corresponding flow record. systemInitTimeMilliseconds is the Packet
 * Export Time (found in the NetFlow v9 Header) converted to milliseconds
 * minus the SysUpTime. Also, for arbitrary Cisco Elements (ID > 346), fixbuf
 * will convert the element ID to 9999 in order to decode the element properly.
 * The exceptions are elements 33002 (NF_F_FW_EXT_EVENT) and 40005
 * (NF_F_FW_EVENT) which are often exported from Cisco's ASA device. These
 * elements will be converted to their corresponding element id's in
 * libfixbuf's default Information Model, 9997 and 9998 respectively.
 * Similarly, the Cisco ASA will also export elements 40001, 40002, 40003,
 * and 40004.  These elements are substituted with the IPFIX elements 225, 226,
 * 227, and 228 respectively.
 *
 * libfixbuf will also convert NetFlow v9 Options Templates and Options Records
 * to IPFIX.  Due to the differences between IPFIX and NetFlow v9 Options
 * Templates the NetFlow v9 Scope Field Type is dropped and replaced with the
 * Information Element ID 263, messageScope.  The Scope Field Length will
 * be carried over to the IPFIX Options Template, and the messageScope will
 * have the length specified by Scope Field Length.  This holds true for all
 * Scope Elements defined in the NetFlow v9 Options Template.  In order to
 * retrieve the value for the Scope Field Type, the IPFIX internal template
 * should use the messageScope Information Element and use the length
 * override (the default length for messageScope is 1).
 *
 * libfixbuf differentiates Netflow v9 streams by IP and observation domain.
 * If no activity is seen from a NetFlow v9 exporter within 30 minutes, the
 * session and all the templates associated with it will be freed. It is best
 * to set the template timeout period on the device to under 30 minutes.
 *
 * fbCollectorGetNetflowMissed() can be used to retrieve the number of
 * potential missed export packets.  This is not the number of FLOW records
 * that the collector has missed.  NetFlow v9 increases sequence numbers
 * by the number of export packets it has sent, NOT the number of flow
 * records.  An export packet may not contain any flow records.  Fixbuf
 * tries to account for any reboot of the device and not count large
 * sequence number discrepancies in it's missed count.
 *
 * To disable NetFlow v9 log messages such as sequence number mismatch
 * messages, option template removal messages, and record count discrepancy
 * messages, run `make clean`, `CFLAGS="-DFB_SUPPRESS_LOGS=1" make -e`,
 * `make install` when installing libfixbuf.
 *
 * @page sflow sFlow Collectors
 *
 * How to use libfixbuf to collect sFlow v5
 *
 * libfixbuf can be used to collect sFlow and convert sFlow to
 * IPFIX.  Follow the steps above to create an fbListener.  After creating
 * the listener, retrieve the collector by calling fbListenerGetCollector()
 * before calling fbCollectorSetSFlowTranslator().  Essentially, the libfixbuf
 * translator is an IPFIX mediator which converts sFlow to IPFIX.  sFlow v5 is
 * a fixed format protocol.  The same steps are used to retrieve flow records
 * from the buffer, call fBufNext().  The internal template should contain
 * some subset of the fields listed below.  sFlow Data Records will have a
 * template ID of 0xEEEE and the Options Records will have a template ID of
 * 0xEEEF.
 *
 * Fixbuf first reads the sFlow header to ensure the buffer contains
 * sFlow v5.  Fixbuf currently only has support for sFlow v5.  The
 * sFlow header only contains the time since the device last rebooted
 * (but not the time of reboot) and this time will be reported in the
 * systemInitTimeMilliseconds field. Fixbuf records the time that the
 * sFlow message was received in the collectionTimeMilliseconds field.
 * Once the first message has been received, the translator will
 * create an external buffer and export the fixed templates to the
 * fixbuf session.  Note: the first sFlow message that fixbuf receives
 * will not be processed - this is used to setup the translation
 * process.  The translator will keep track of sequence numbers per
 * peer (IP)/observation domain (agent ID) by default.  There are
 * multiple sequence numbers in sFlow.  Each sFlow message has a
 * sequence number and each sample has a sequence number.  The sFlow
 * message sequence number is used to determine if sFlow messages have
 * been dropped.  Fixbuf will report if either sequence number is out
 * of sequence and emit a warning. The warning is just for
 * notification, libfixbuf will process all well-formed samples that
 * it receives.
 *
 * libfixbuf will process Flow Samples (1), Extended Flow Samples (3), Counter
 * Samples (2), and Extended Counter Samples (4).  Any other format will
 * return an FB_ERROR_SFLOW.  Applications should ignore (and potentially log)
 * FB_ERROR_SFLOW errors.  FB_ERROR_SFLOW errors are not fatal.
 * With an sFlow sample, fixbuf can handle the following formats:
 *
 * - Raw Packet Data, enterprise = 0, format = 1
 * - Ethernet Frame Data, enterprise = 0, format = 2
 * - IPv4 Data, enterprise = 0, format = 3
 * - IPv6 Data, enterprise = 0, format = 4
 * - Extended Switch data, enterprise = 0, format = 1001
 * - Extended Router data, enterprise = 0, format = 1002
 * - Extended Gatway Data, enterprise = 0, format = 1003
 *
 * Any other flow sample format will be silently ignored.
 * Each sFlow flow record can contain the following fields, formats are listed
 * in the parenthesis:
 *
 *  IPFIX FIELDS | sFlow FIELDS | Reduced Length
 * ------------- | ------------- | -------------
 * sourceIPv6Address | Ipv6 Address in IPv6 (4) or Raw Packet (1) Data | N
 * destinationIPv6Address | Ipv6 Address in IPv6 (4) or Raw Packet (1) Data| N
 * ipNextHopIPv6Address | Extended Router Data (1002) | N
 * bgpNextHopIPv6Address | Extended Gateway Data (1003) | N
 * collectorIPv6Address | Message Header Data | N
 * collectionTimeMilliseconds | Message Header Data | N
 * systemInitTimeMilliseconds | Message Header Data | N
 * collectorIPv4Address | Message Header Data | N
 * protocolIdentifier | IPv4 (3) or IPv6 (4) or Raw Packet (1) Data | N
 * ipClassOfService | IPv4 (3) or IPv6 (4) or Raw Packet (1) Data | N
 * sourceIPv4PrefixLength  |Extended Router Data (1002) | N
 * destinationIPv4PrefixLength | Extended Router Data (1002) | N
 * sourceIPv4Address | IPv4 (3) or Raw Packet (1) Data | N
 * destinationIPv4Address | IPv4 (3) or Raw Packet (1) Data| N
 * octetTotalCount | Flow Sample Header Data | 4
 * packetTotalCount | Flow Sample Header Data | 4
 * ingressInterface | Flow Sample Header Data | N
 * egressInterface | Flow Sample Header Data | N
 * sourceMacAddress | Ethernet (2), IPv4 (3), IPv6 (4) or Raw Packet (1) Data | N
 * destinationMacAddress | Ethernet (2), IPv4 (3), IPv6 (4) or Raw Packet (1) Data | N
 * ipNextHopIPv4Address | Extended Router Data (1002) | N
 * bgpSourceAsNumber | Extended Gateway Data (1003)| N
 * bgpDestinationAsNumber| Extended Gateway Data (1003) | N
 * bgpNextHopIPv4Address| Extended Gateway Data (1003) | N
 * samplingPacketInterval | Message Header Data | N
 * samplingPopulation| Message Header Data | N
 * droppedPacketTotalCount| Message Header Data | 4
 * selectorId| Message Header Data | 4
 * vlanId | IPv4 (3) or IPv6 (4) or Raw Packet (1) Data | N
 * sourceTransportPort | IPv4 (3) or IPv6 (4) or Raw Packet (1) Data | N
 * destinationTransportPort | IPv4 (3) or IPv6 (4) or Raw Packet (1) Data | N
 * tcpControlBits | IPv4 (3) or IPv6 (4) or Raw Packet (1) Data | 2
 * dot1qVlanId | Extended Switch Data (1001) | N
 * postDot1qVlanId | Extended Switch Data (1001) | N
 * dot1qPriority  | Extended Switch Data (1001) | N
 *
 * libfixbuf will also convert sFlow Counter Records to Options Records
 * in IPFIX. libfixbuf will only process the Generic Interface Counters
 * (format = 1).  Other formats will be silently ignored.
 * The following fields are present in the Counter (Options) Template/Record:
 *
 *  IPFIX FIELDS | sFlow FIELDS | Reduced Length
 * ------------- | ------------- | --------------
 * collectorIPv6Address | Message Header Data | N
 * collectionTimeMilliseconds | Message Header Data | N
 * systemInitTimeMilliseconds | Message Header Data | N
 * collectorIPv4Address  | Message Header Data | N
 * ingressInterface | Counter Sample Header Data | N
 * octetTotalCount | ifINOctets (1) | N
 * ingressInterfaceType | ifType (1) | N
 * packetTotalCount | ifInUcastPkts (1) | 4
 * ingressMulticastPacketTotalCount | ifInMulticastPkts (1) | 4
 * ingressBroadcastPacketTotalCount | ifInBroadcastPkts (1) | 4
 * notSentPacketTotalCount | ifInDiscards (1) | 4
 * droppedPacketTotalCount | ifInErrors (1) | 4
 * postOctetTotalCount | ifOutOctets (1) | N
 * ignoredPacketTotalCount | ifInUnknownProtos (1) | 4
 * postPacketTotalCount | ifOutUcastPkts (1) | 4
 * egressBroadcastPacketTotalCount |  ifOutBroadcastPkts (1) | 4
 * selectorId | Message Header Data | 4
 *
 *
 * fbCollectorSFlowMissed() can be used to retrieve the number of
 * potential missed export packets.  This is not the number of FLOW samples
 * that the collector has missed.  Fixbuf
 * tries to account for any reboot of the device and not count large
 * sequence number discrepancies in it's missed count.
 *
 * Fixbuf will return FB_ERROR_SFLOW if it tries to process any
 *  malformed samples.
 *
 * @page spread Spread Collectors
 *
 * How-To use the Spread Protocol:
 *
 * The instructions for using Spread in libfixbuf are similar to the
 * setup for reading from IPFIX files.  As described above in the Exporters
 * section, the first step is to create an fbInfoModel_t and fbSession_t.
 * Next, create the internal template(s) and add it to the fbSession_t.
 * Define an fbSpreadParams_t and set the session, groups to subscribe to,
 * and Spread Daemon name.
 *     Example usage:
 *     \code{.c}
 *       fbSpreadParams_t spread;
 *       char *groups[25];
 *       groups[0] = strdup("group1");
 *       groups[1] = '\0';
 *       spread.daemon = "daemon1"
 *       spread.groups = groups;
 *       spread.session = session;
 *       collector = fbCollectorAllocSpread(0, &spread, &err);
 *      \endcode
 *
 * Then create an fbCollector_t to connect and listen to the Spread Daemon
 * using fbCollectorAllocSpread().
 *
 * With an fbSession_t and fbcollector_t available, create a buffer for
 * writing via fBufAllocForCollection().  Set the internal template ID with
 * fBufSetInternalTemplate(), and use fBufNext() to read records from IPFIX
 * Messages published to the group your collector is subscribing to.
 *
 * To view all the Spread Groups that were sent the incoming record, call
 * fbCollectorGetSpreadReturnGroups() on the collector.
 *
 * @page noconnect Connection-less Collector
 *
 * How-To use libfixbuf with just a data buffer:
 *
 * To use fixbuf independent of the transport mode, the application must
 * create an fbInfoModel_t using fbInfoModelAlloc()
 * and any additional, vendor-specific information elements using
 * fbInfoModelAddElement() or fbInfoModelAddElementArray().  Next create
 * an fbSession_t using fbSessionAlloc() and add internal templates via
 * fbSessionAddTemplate().
 * The application will handle all connections and reading and simply pass fixbuf
 * the buffer to be decoded.  The buffer must contain valid IPFIX and should
 * begin with the standard IPFIX header.  Ideally, the application should
 * provide the necessary templates before any data records to ensure that
 * the application can decode all of the data records.
 *
 * The application should NOT create an fbCollector.  To create the fBuf,
 * use fBufAllocForCollection() and set the second parameter to NULL.
 * The application then has everything needed to start reading from the IPFIX
 * source.  Ideally, the application will read the first 4 bytes of the message
 * first to determine the length of the next IPFIX message.  The first 2 bytes
 * are the IPFIX version (0x000A) and the third and fourth bytes are the length
 * of the following IPFIX message (including the IPFIX message header). The
 * application should then continue reading the length of the IPFIX message
 * into an allocated buffer.  The buffer should then be set on the fBuf by
 * calling fBufSetBuffer(). The application will continue to call fBufNext()
 * to receive the data records until fBufNext() returns FALSE with error
 * code FB_ERROR_BUFSZ.  However, if the fBuf is in manual mode
 * fbufSetAutomaticMode(buf, FALSE) AND the application was reading the
 * message length, fixbuf will first return an FB_ERROR_EOM which will
 * signal to the application to perform another read (if the application
 * ignores FB_ERROR_EOM errors and calls fBufNext(), fBufNext() will then
 * return FB_ERROR_BUFSZ). This error notifies the application that there is
 * not enough data in the buffer to read a full IPFIX message.  If the
 * application only read the size of the IPFIX message, the entire buffer
 * should have been read.  However, if the application was reading more than
 * the IPFIX message length, additional data may remain in the buffer that
 * belongs to the next IPFIX message.  To determine how much data was left
 * in the buffer unread, fBufRemaining() will return the length
 * of the buffer that was not processed.  That remaining data should be copied
 * to the beginning of the buffer and the remaining IPFIX message data should
 * be read.  After each read, the application needs to call fBufSetBuffer().
 * Note that fBufSetBuffer() sets the collector and exporter on the fBuf to
 * NULL.  The application should clear the FB_ERROR_BUFSZ and/or FB_ERROR_EOM
 * error when they occur using g_clear_error().
 *
 * fixbuf may return the following error codes if it encounters one
 * of the below issues.  The application should determine the error and
 * respond appropriately.
 *
 *  - FB_ERROR_IPFIX
 *     - If the first 2 bytes != 0x000A
 *     - If the length in the header < 16
 *  - FB_ERROR_EOM
 *     - If the application read only the message length and the application
 *       called fBufSetAutomatic(fbuf, FALSE) (the fBuf is in manual mode).
 *       This means the remaining buffer length == 0 and the application
 *       should clear the error and perform another read
 *  - FB_ERROR_BUFSZ
 *     - If the header message length > the given buffer length
 *     - if the given buffer == NULL
 *     - If the given buffer length < 16
 *     - If buffer length == 0
 *
 *
 *     Example usage:
 *     \code{.c}
 *        FILE *fp;
 *        uint8_t buf[65535];
 *        ...
 *        rc = fread(buf, 1, 4, fp);
 *        if (rc > 0) {
 *           len = ntohs(*((uint16_t *)(buf+2)));
 *           rc = fread(buf+4, 1, len-4, fp);
 *           if (rc > 0) {
 *               fBufSetBuffer(fbuf, buf, rc+4);
 *           } else if (feof(fp))
 *           ....
 *           while (1) {
 *               ret = fBufNext(fbuf, (uint8_t *)rec, &len, &err);
 *               if (FALSE == ret) {
 *                  if (g_error_matches(err, FB_ERROR_DOMAIN, FB_ERROR_BUFSZ)){
 *                     rem = fBufRemaining(fbuf);
 *                     g_clear_error(&err);
 *                     break;
 *                  }
 *               }
 *            }
 *      \endcode
 *
 * @page lists Lists in IPFIX
 *
 * How-To deal with BasicLists, SubTemplateLists, & SubTemplateMultiLists:
 *
 * @section general General Information
 * Each of the list structures uses a nested list of data.
 * The basic list nests a single information element, while the others use a
 * nested template.  The template used for nesting is part of the listed
 * templates sent to the collector when the connection is made, or when the
 * data transfer begins.  There is no way to mark a template from this list as
 * one that will be nested, or one that will be used as the highest level
 * template.  Each of the templates in the list are treated as equals.
 *
 * The collector does not learn which template or information element is nested
 * until the data arrives.  This requires flexbility in the collectors to
 * handle each of the possible results.
 *
 * @subsection internalTemplates Internal Templates for Sub Templates
 * The setting of the internal template has not changed with the addition of
 * the list structures.  The internal template is still used to perform the
 * initial decoding of the data that arrives at the collector.
 *
 * Basic lists are not transcoded in the same way as templates because they
 * contain just one information element, thus having no order, so the data can
 * just be parsed and copied to a buffer.
 *
 * The question with decoding sub templates becomes, what do we use as an
 * internal template for any sub templates that arrive?  The answer is a new
 * structure in fixbuf that pairs external and internal template IDs for use
 * in decoding sub templates.  The pairs are added to the session that is used
 * for the connection, using fbSessionAddTemplatePair().
 *
 * Because the external template IDs are only unique for that session, the
 * collector must know the IDs of the templates that are collected in order to
 * pair an internal template with the external template.  As a result, callback
 * functionality has been added to fixbuf to alert the user when a new external
 * template has arrived.  The callback functions are stored in the session
 * structure, which manages the templates.  fbNewTemplateCallback_fn gives the
 * application the session pointer, the template, the template ID, as well as a
 * context variable that is stored for the application in the template.  The
 * callback also gives the user another callback that can be used to free the
 * context variable upon template deletion.  This information is sufficient for
 * the application to successfully add template pairs to the session for sub
 * template decoding.
 *
 * If the application does not use the callback or does not add any template
 * pairs to the session, then fixbuf will transcode each of the sub templates
 * as if the external and internal template were same.  This causes all of the
 * fields sent over the wire to be transcoded into the data buffer on the
 * collecting side.  The details of that template are passed up to the
 * collector upon receipt of data so it knows how the data is structured in
 * the buffer.
 *
 * If the application adds any template pair to the list, then the list will be
 * referenced for each transcode.  Any external template the application
 * wishes to process MUST have an entry in the list.
 * There are 3 cases for entries in the list:
 *   -# There is no entry for the given external template ID, so the entire
 *      sub template is ignored by the transcoder.
 *      The collector will be given a sub template list (or multi list entry)
 *      struct with the number of elements in the list set to 0, and the data
 *      pointer set to NULL.
 *   -# The listing exists, and the external and internal template IDs are set
 *      to the same value.  When decoding, the list of internal templates is
 *      queried to see if a template exists with the same ID as the external
 *      template. If not, the transcoder decodes each of the
 *      information elements, in the same order, into the buffer. This is a
 *      change as setting them equal to each other used to force a full decode.
 *      This change highlights the need for careful template ID management.
 *   -# The listing exists, and the external and internal template IDs are
 *      different.  This will transcode in the standard way external templates
 *      have been transcoded into internal templates, selecting the desired
 *      elements (listed in the internal template) from the data that arrived
 *      in the external template.
 *
 *
 *
 * @subsection iterating Iterating Over the Lists
 * There are four scenerios in which the user needs to iterate through the
 * elements in a list, whether to fill in, or process the data:
 *  -#  Iterating over the repeated information element data in a basic list
 *  -#  Iterating over the decoded data elements in a sub template list
 *  -#  Iterating over the entries that make up a sub template multi list
 *  -#  Iterating over the docoded data elements in an entry of a sub template
 *      multi list
 * The two iterating mechanisms are the same in each case:
 * Each of the function names start with the structure being iterated over,
 * e.g., fbBasicList, or fbSubTemplateMultiListEntry
 *  -#  Indexing
 *      The function used here is (structName)GetIndexed(dataPtr or entry)()
 *      It takes a pointer to the struct, and the index to be retrieved.
 *      Example usage:
 *          for(i = 0; myStructPtr = ...GetIndexedDataPtr(listPtr, i); i++) {
 *              process the data that myStructPtr points to.
 *          }
 *          The loop will end because when i is passed the bounds of the list
 *          the GetIndexedDataPtr() returns NULL.
 *
 *  -# Incrementing
 *     The function used here is (structName)GetNext(dataPtr or entry)()
 *     It takes a pointer to the struct, and a pointer to an element in the
 *     list.  Pass in NULL at the beginning to get the first element back.
 *     Example usage:
 *     \code{.c}
 *       myStructPtr = NULL;
 *          while(myStructPtr = ...GetNextPtr(listPtr, myStructPtr)) {
 *              process the data that myStructPtr points to.
 *          }
 *      \endcode
 *     The loop will end because the function will return NULL when
 *     it gets passed the end of the list.  A key part here is
 *     initializing myStructPtr to NULL at the beginning!
 *
 * @page rfc_5610 RFC 5610
 *
 * What is RFC 5610?
 *
 * RFC 5610 provides a mechanism to export full type information for
 * Information Elements from the IPFIX Information Model.  Libfixbuf
 * version 1.4 and later provides API functions to create IPFIX
 * Option Template/Records that can encode the full set of properties
 * for the definition of an Information Element in order for a
 * Collecting Process to be able to know how to decode data that
 * contains enterprise-specific Information Elements.
 *
 * @section exp RFC 5610 Exporters
 *
 * To create a new enterprise-specific Information Element, the
 * Exporting Process should define a new information element using
 * the FB_IE_INIT_FULL() macro to provide the name, private enterprise
 * number, id, length, description, data type, and units of the
 * information element.  The Information Elements should then be
 * added to the Information Model using fbInfoModelAddElement() or
 * fbInfoModelAddElementArray().
 *
 * Once an enterprise-specific information element exists, there are
 * two ways to export that information.  The simplest way is to
 * configure automated enterprise-specific information element
 * information export.  This is done by calling
 * fbSessionEnableTypeMetadata() with the `enabled` parameter set to
 * `TRUE`.  Once this has been set, the full set of information
 * elements in the information model that have a non-zero Private
 * Enterprise Number will be exported every time template records are
 * exported.
 *
 * The other option is to export the information element options
 * records manually. An information element options template can then
 * be created using fbInfoElementAllocTypeTemplate().  This creates an
 * option template that contains all of the necessary properties to
 * define an Information Element:
 *
 * - informationElementRangeBegin
 * - informationElementRangeEnd
 * - privateEnterpriseNumber
 * - informationElementUnits
 * - informationElementId
 * - informationElementDataType
 * - informationElementSemantics
 * - paddingOctets
 * - informationElementName
 * - informationElementDescription
 *
 * Then the template can be added to the session using
 * fbSessionAddTemplate().  You will need to add it twice, once as an
 * internal template, and once as an external template.  Create the
 * exporter and fbuf as described above for the necessary mode of
 * transport.  Then, to write out an information element options
 * record, use fbInfoElementWriteOptionsRecord(), using the template
 * IDs returned by the fbSessionAddTemplate() calls as the internal
 * and export template IDs, passing it a pointer to the information
 * element you want to export.  For example:
 *
 *  \code{.c} fbInfoElementWriteOptionsRecord(fbuf, fbInfoModelGetElementByName(infoModel, "myNewElement"), itid, etid, *err); \endcode
 *
 * The Options Record will automatically be appended to the fbuf
 * and will be sent upon calling fBufEmit().
 *
 * @section col RFC 5610 - Collector Usage
 *
 * In order to collect the above Options records, the collecting
 * process can manually define the above Options Template and
 * provide a template callback function to collect and add
 * each element to the Information Model using
 * fbInfoElementAddOptRecElement() and fbInfoModelTypeInfoRecord().
 *
 * OR - the collector can simply use fBufSetAutomaticInsert()
 * after creating an fBuf to automatically insert any information
 * elements into the Information Model.
 *
 */

/**
 * @file
 *
 *  Fixbuf IPFIX protocol library public interface
 *
 */

#ifndef _FB_PUBLIC_H_
#define _FB_PUBLIC_H_
#include <fixbuf/autoinc.h>
#include "version.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Version check macro
 */
#define FIXBUF_CHECK_VERSION(major, minor, release)    \
    (FIXBUF_VERSION_MAJOR > (major) || \
     (FIXBUF_VERSION_MAJOR == (major) && FIXBUF_VERSION_MINOR > (minor)) || \
     (FIXBUF_VERSION_MAJOR == (major) && FIXBUF_VERSION_MINOR == (minor) && \
      FIXBUF_VERSION_RELEASE >= (release)))

/*
 * Error Handling Definitions
 */

/** All fixbuf errors are returned within the FB_ERROR_DOMAIN domain. */
#define FB_ERROR_DOMAIN             g_quark_from_string("fixbufError")
/** No template was available for the given template ID. */
#define FB_ERROR_TMPL               1
/**
 * End of IPFIX message. Either there are no more records present in the
 * message on read, or the message MTU has been reached on write.
 */
#define FB_ERROR_EOM                2
/**
 * End of IPFIX Message stream. No more messages are available from the
 * transport layer on read, either because the session has closed, or the
 * file has been processed.
 */
#define FB_ERROR_EOF                3
/**
 * Illegal IPFIX mesaage content on read. The input stream is malformed, or
 * is not an IPFIX Message after all.
 */
#define FB_ERROR_IPFIX              4
/**
 * A message was received larger than the collector buffer size.
 * Should never occur. This condition is checked at the transport layer
 * in case future versions of fixbuf support dynamic buffer sizing.
 */
#define FB_ERROR_BUFSZ              5
/** The requested feature is not yet implemented. */
#define FB_ERROR_IMPL               6
/** An unspecified I/O error occured. */
#define FB_ERROR_IO                 7
/**
 * No data is available for reading from the transport layer.
 * Either a transport layer read was interrupted, or timed out.
 */
#define FB_ERROR_NLREAD             8
/**
 * An attempt to write data to the transport layer failed due to
 * closure of the remote end of the connection. Currently only occurs with
 * the TCP transport layer.
 */
#define FB_ERROR_NLWRITE            9
/**
 * The specified Information Element does not exist in the Information Model.
 */
#define FB_ERROR_NOELEMENT          10
/**
 * A connection or association could not be established or maintained.
 */
#define FB_ERROR_CONN               11
/**
 * Illegal NetflowV9 content on a read.  Can't parse the Netflow header or
 * the stream is not a NetflowV9 stream
 */
#define FB_ERROR_NETFLOWV9          12
/**
 * Miscellaneous error occured during translator operation
 */
#define FB_ERROR_TRANSMISC          13
/**
 * Illegal sFlow content on a read.
 */
#define FB_ERROR_SFLOW              14
/**
 * Setup error
 */
#define FB_ERROR_SETUP              15
/**
 * Internal template with defaulted element sizes
 */
#define FB_ERROR_LAXSIZE            16

/*
 * Public Datatypes and Constants
 */

struct fBuf_st;
/**
 * An IPFIX message buffer. Used to encode and decode records from
 * IPFIX Messages. The internals of this structure are private to
 * libfixbuf.
 */
typedef struct fBuf_st fBuf_t;

/**
 * A variable-length field value. Variable-length information element
 * content is represented by an fbVarfield_t on the internal side of the
 * transcoder; that is, variable length fields in an IPFIX Message must be
 * represented by this structure within the application record.
 */
typedef struct fbVarfield_st {
    /** Length of content in buffer. */
    size_t      len;
    /**
     * Content buffer. In network byte order as appropriate. On write, this
     * buffer will be copied into the message buffer. On read, this buffer
     * points into the message buffer and must be copied by the caller before
     * any call to fBufNext().
     */
    uint8_t     *buf;
} fbVarfield_t;


struct fbInfoModel_st;
/**
 * An IPFIX information model. Contains information element definitions.
 * The internals of this structure are private to libfixbuf.
 */
typedef struct fbInfoModel_st fbInfoModel_t;

/**
 * An iterator over the information elements in an information model.
 */
typedef struct fbInfoModelIter_st {
    /**
     * information Model
     */
    const fbInfoModel_t *model;
    /**
     * iterator index
     */
    guint                index;
} fbInfoModelIter_t;

/**
 * Convenience macro for creating full fbInfoElement_t static initializers.
 * Used for creating information element arrays suitable for passing to
 * fbInfoModelAddElementArray().
 */
#define FB_IE_INIT_FULL(_name_, _ent_, _num_, _len_, _flags_, _min_, _max_, _type_, _desc_)\
    { {(const struct fbInfoElement_st*)_name_}, 0, _ent_, _num_, _len_, _flags_, _min_, _max_, _type_, _desc_ }

/**
 * @deprecated Convenience macro for creating default fbInfoElement_t
 * static initializers.  Used for creating information element arrays
 * suitable for passing to fbInfoModelAddElementArray().
 */
#define FB_IE_INIT(_name_, _ent_, _num_, _len_, _flags_) \
    FB_IE_INIT_FULL(_name_, _ent_, _num_, _len_, _flags_, 0, 0, 0, (char*)NULL)


/**
 * Convenience macro defining a null information element initializer to
 * terminate a constant information element array for passing to
 * fbInfoModelAddElementArray().
 */
#define FB_IE_NULL FB_IE_INIT(NULL, 0, 0, 0, 0)

/**
 * Convenience macro for extracting the information element
 * semantic value from the flags variable in the fbInfoElement_t struct
 *
 */
#define FB_IE_SEMANTIC(flags) ((flags & 0x0000ff00) >> 8)

/**
 * Convenience macro for extracting the information element
 * units value from the flags variable in the fbInfoElement_t struct
 *
 */
#define FB_IE_UNITS(flags) ((flags & 0xFFFF0000) >> 16)

/**
 * Default treatment flags value. Provided for initializer convenience.
 * Corresponds to octet-array semantics for a non-reversible, non-alien IE.
 */
#define FB_IE_F_NONE                            0x00000000

/**
 * Information element endian conversion flag. If set, IE is an integer and
 * will be endian-converted on transcode.
 */
#define FB_IE_F_ENDIAN                          0x00000001

/**
 * Information element reversible flag. If set for an information element
 * with an enterprise number of 0 (an IETF/IANA IE), adding the information
 * element via fbInfoModelAddElement() or fbInfoModelAddElementArray() will
 * cause a second, reverse information element to be added to the model
 * following the conventions in IETF Internet-Draft draft-ietf-ipfix-biflow-03.
 * Note that the reverse PEN has not yet been assigned, so this implementation
 * uses a provisional reverse IE as defined by the macro FB_IE_PEN_REVERSE.
 */
#define FB_IE_F_REVERSIBLE                      0x00000040

/**
 * Information element alien flag. If set, IE is enterprise-specific and was
 * recieved via an external template at a Collecting Process. It is therefore
 * subject to semantic typing via options (not yet implemented). Do not set this
 * flag on information elements added programmatically to an information model
 * via fbInfoModelAddElement() or fbInfoModelAddElementArray().
 */
#define FB_IE_F_ALIEN                           0x00000080

/**
 * An Information Element Semantics Flags used to describe an information
 * element as a quantity.
 */
#define FB_IE_QUANTITY                          0x00000100

/**
 * An Information Element Semantics Flags used to describe an information
 * element as a totalCounter.
 *
 */
#define FB_IE_TOTALCOUNTER                      0x00000200

/**
 * An Information Element Semantics Flag used to describe an information
 * element as a deltaCounter.
 */
#define FB_IE_DELTACOUNTER                      0x00000300

/**
 * An Information Element Semantics Flag used to describe an information
 * element as an identifier.
 */
#define FB_IE_IDENTIFIER                        0x00000400

/**
 * An Information Element Semantics Flag used to describe an information
 * element as a flags element.
 */
#define FB_IE_FLAGS                             0x00000500

/**
 * An Information Element Semantics Flag used to describe an information
 * element as a List Element.
 *
 */
#define FB_IE_LIST                              0x00000600

/**
 * An Information Element Semantics Flag used to describe an information
 * element as an SNMP counter.
 *
 */
#define FB_IE_SNMPCOUNTER                       0x00000700

/**
 * An Information Element Semantics Flag used to describe an information
 * element as a SNMP gauge.
 *
 */
#define FB_IE_SNMPGAUGE                         0x00000800

/**
 * An Information Element Semantics Flag used to describe an information
 * element as a Default element.
 *
 */
#define FB_IE_DEFAULT                           0x00000000

/**
 * Information Element Units - See RFC 5610
 *
 */

/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_BITS                           0x00010000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_OCTETS                         0x00020000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_PACKETS                        0x00030000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_FLOWS                          0x00040000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_SECONDS                        0x00050000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_MILLISECONDS                   0x00060000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_MICROSECONDS                   0x00070000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_NANOSECONDS                    0x00080000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_WORDS                          0x00090000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_MESSAGES                       0x000A0000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_HOPS                           0x000B0000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element. See RFC 5610
 *
 */
#define FB_UNITS_ENTRIES                        0x000C0000
/**
 * An Information Element Units Flag used to describe the units
 * of an information element.  Recently added for layer 2 frames
 *
 */
#define FB_UNITS_FRAMES                         0x000D0000

/**
 * Information element length constant for variable-length IE.
 */
#define FB_IE_VARLEN                            65535

/**
 * Information element number constant for basic lists
 * This will change upon updates to the specification.
 */
#define FB_IE_BASIC_LIST                        291
/**
 * Information element number constant for sub template lists
 * This will change upon updates to the IPFIX lists specification
 */
#define FB_IE_SUBTEMPLATE_LIST                  292
/**
 * Information element number constant for sub template multi lists
 * This will change upon updates to the IPFIX lists specification
*/
#define FB_IE_SUBTEMPLATE_MULTILIST             293

/**
 * Private enterprise number for reverse information elements
 * (see draft-ietf-ipfix-biflow-03 section 6.1).  If an information element with
 * FB_IE_F_REVERSIBLE and a zero enterprise number (i.e., an IANA-assigned
 * information element) is added to a model, the reverse IE will be generated
 * by setting the enterprise number to this constant.
 */
#define FB_IE_PEN_REVERSE                       29305

/**
 * Reverse information element bit for vendor-specific information elements
 * (see draft-ietf-ipfix-biflow-03 section 6.2). If an information element with
 * FB_IE_F_REVERSIBLE and a non-zero enterprise number (i.e., a vendor-specific
 * information element) is added to a model, the reverse IE number will be
 * generated by ORing this bit with the given forward information element
 * number.
 */
#define FB_IE_VENDOR_BIT_REVERSE                0x4000

/**
 * Generic Information Element ID for undefined Cisco NetFlow v9 Elements.
 *
 *
 */
#define FB_CISCO_GENERIC                       9999
/**
 * Information Element ID for Cisco NSEL Element NF_F_FW_EVENT often
 * exported by Cisco's ASA Device.  This must be converted to a different
 * Information Element ID due to the reverse IE bit in IPFIX.
 * Cisco uses IE ID 40005.
 * http://www.cisco.com/en/US/docs/security/asa/asa82/netflow/netflow.html
 */
#define FB_CISCO_ASA_EVENT_ID                  9998
/**
 * Information Element ID for Cisco NSEL Element NF_F_FW_EXT_EVENT often
 * exported by Cisco's ASA Device.  This must be converted to a different
 * Information Element ID due to the reverse IE bit in IPFIX.
 * Cisco uses IE ID 33002
 * http://www.cisco.com/en/US/docs/security/asa/asa82/netflow/netflow.html
 * More Information about event codes can be found here:
 * http://www.cisco.com/en/US/docs/security/asa/asa84/system/netflow/netflow.pdf
 */
#define FB_CISCO_ASA_EVENT_XTRA                9997
/**
 * Reverse information element name prefix. This string is prepended to an
 * information element name, and the first character after this string
 * is capitalized, when generating a reverse information element.
 */
#define FB_IE_REVERSE_STR                       "reverse"

/** Length of reverse information element name prefix. */
#define FB_IE_REVERSE_STRLEN                    7

/**
 * From RFC 5610: A description of the abstract data type of an IPFIX
 * information element as registered in the IANA IPFIX IE Data Type
 * subregistry.
 */
typedef enum fbInfoElementDataType_en {
    FB_OCTET_ARRAY,
    FB_UINT_8,
    FB_UINT_16,
    FB_UINT_32,
    FB_UINT_64,
    FB_INT_8,
    FB_INT_16,
    FB_INT_32,
    FB_INT_64,
    FB_FLOAT_32,
    FB_FLOAT_64,
    FB_BOOL,
    FB_MAC_ADDR,
    FB_STRING,
    FB_DT_SEC,
    FB_DT_MILSEC,
    FB_DT_MICROSEC,
    FB_DT_NANOSEC,
    FB_IP4_ADDR,
    FB_IP6_ADDR,
    FB_BASIC_LIST,
    FB_SUB_TMPL_LIST,
    FB_SUB_TMPL_MULTI_LIST
} fbInfoElementDataType_t;

/**
 * A single IPFIX Information Element definition.
 * An Information Element defines the type of data in each field of
 * a record. This structure may be contained in an fbInfoModel_t,
 * in which case the name field contians the information element name,
 * or an an fbTemplate_t, in which case the canon field references the
 * fbInfoElement_t contained within the Information Model.
 */
typedef struct fbInfoElement_st {
    /** Information element name. */
    union {
        /**
         * Pointer to canonical copy of IE.
         * Set by fbInfoElementCopyToTemplate(),
         * and valid only for template IEs.
         */
        const struct fbInfoElement_st *canon;
        /**
         * Information element name. Storage for this is managed
         * by fbInfoModel. Valid only for model IEs.
         */
        const char                    *name;
    }  ref;

    /**
     * Multiple IE index. Must be 0 for model IEs.
     * Defines the ordering of identical IEs in templates.
     * Set and managed automatically by the fbTemplate_t routines.
     */
    uint32_t            midx;
    /** Private Enterprise Number. Set to 0 for IETF-defined IEs. */
    uint32_t            ent;
    /**
     * Information Element number. Does not include the on-wire
     * enterprise bit; i.e. num & 0x8000 == 0 even if ent > 0.
     */
    uint16_t            num;
    /** Information element length in octets. */
    uint16_t            len;
    /** Flags. Bitwise OR of FB_IE_F_* constants. */
    /** Use Macros to get units and semantic */
    uint32_t            flags;
    /** range min */
    uint64_t            min;
    /** range max */
    uint64_t            max;
    /** Data Type */
    uint8_t             type;
    /** description */
    const char          *description;
} fbInfoElement_t;

/**
 * The corresponding struct to the Information Element Type Options Template.
 * If collecting this element, use the function fbInfoElementAddOptRecElem()
 * to add this element to the info model.
 *
 */
typedef struct fbInfoElementOptRec_st {
    /** private enterprise number */
    uint32_t       ie_pen;
    /** information element id */
    uint16_t       ie_id;
    /** ie data type */
    uint8_t        ie_type;
    /** ie semantic */
    uint8_t        ie_semantic;
    /** ie units */
    uint16_t       ie_units;
    /** padding to align with template */
    uint8_t        padding[6];
    /** ie range min */
    uint64_t       ie_range_begin;
    /** ie range max */
    uint64_t       ie_range_end;
    /** information element name */
    fbVarfield_t   ie_name;
    /** information element description */
    fbVarfield_t   ie_desc;
} fbInfoElementOptRec_t;


/**
 * Template ID argument to pass to fbSessionAddTemplate to automatically
 * assign a template ID.
 */
#define FB_TID_AUTO         0

/**
 * Reserved set ID for template sets.
 */
#define FB_TID_TS           2

/**
 * Reserved set ID for options template sets.
 */
#define FB_TID_OTS          3

/**
 * Minimum non-reserved template ID available for data sets.
 */
#define FB_TID_MIN_DATA     256

struct fbTemplate_st;
/**
 * An IPFIX Template or Options Template. Templates define the structure of
 * data records and options records within an IPFIX Message.
 * The internals of this structure are private to libfixbuf.
 */
typedef struct fbTemplate_st fbTemplate_t;

/**
 * Convenience macro defining a null information element specification
 * initializer to terminate a constant information element specifier array
 * for passing to fbTemplateAppendSpecArray().
 */
#define FB_IESPEC_NULL { NULL, 0, 0 }

/**
 * A single IPFIX Information Element specification.
 * Used to name an information element for inclusion in a template by
 * fbTemplateAppendSpecArray().
 */
typedef struct fbInfoElementSpec_st {
    /** Information element name */
    char                *name;
    /**
     * The size of the information element in bytes.  For internal
     * templates, this is the size of the memory location that will be
     * filled by the transcoder (i.e., the size of a field in a
     * struct). Zero cannot be used to default the size of elements
     * used in internal templates. This is so changes in the "default"
     * length will not silently be different then the sizes of fields
     * in an internal struct definition. Zero can be used as the size
     * of #FB_IE_VARLEN elements.  This field can also be used to
     * specify reduced-length encoding.
     */
    uint16_t            len_override;
    /**
     * Application flags word. If nonzero, then the flags argument to
     * fbTemplateAppendSpec() or fbTemplateAppendSpecArray() MUST match at
     * least one bit of this flags word in order for the information element
     * to be appended.
     */
    uint32_t            flags;
} fbInfoElementSpec_t;

struct fbSession_st;
/**
 * An IPFIX Transport Session state container. Though Session creation and
 * lifetime are managed by the fbCollector_t and fbExporter_t types, each
 * fBuf_t buffer uses this type to store session state, including internal
 * and external Templates and Message Sequence Number information.
 */
typedef struct fbSession_st fbSession_t;

/** Transport protocol for connection specifier. */
typedef enum fbTransport_en {
    /**
     * Partially reliable datagram transport via SCTP.
     * Only available if fixbuf was built with SCTP support.
     */
    FB_SCTP,
    /** Reliable stream transport via TCP. */
    FB_TCP,
    /** Unreliable datagram transport via UDP. */
    FB_UDP,
    /**
     * Secure, partially reliable datagram transport via DTLS over SCTP.
     * Only available if fixbuf was built with OpenSSL support.
     * Requires an OpenSSL implementation of DLTS over SCTP, not yet available.
     */
    FB_DTLS_SCTP,
    /**
     * Secure, reliable stream transport via TLS over TCP.
     * Only available if fixbuf was built with OpenSSL support.
     */
    FB_TLS_TCP,
    /**
     * Secure, unreliable datagram transport via DTLS over UDP.
     * Only available if fixbuf was built with OpenSSL support.
     * Requires OpenSSL 0.9.8 or later with DTLS support.
     */
    FB_DTLS_UDP,
} fbTransport_t;

/**
 * Connection specifier. Used to define a peer address for fbExporter_t, or a
 * passive address for fbListener_t.
 */
typedef struct fbConnSpec_st {
    /** Transport protocol to use */
    fbTransport_t       transport;
    /** Hostname to connect/listen to. NULL to listen on all interfaces. */
    char                *host;
    /** Service name or port number to connect/listen to. */
    char                *svc;
    /** Path to certificate authority file. Only used for OpenSSL transport. */
    char                *ssl_ca_file;
    /** Path to certificate file. Only used for OpenSSL transport. */
    char                *ssl_cert_file;
    /** Path to private key file. Only used for OpenSSL transport. */
    char                *ssl_key_file;
    /** Private key decryption password. Only used for OpenSSL transport. */
    char                *ssl_key_pass;
    /**
     * Pointer to address info cache. Initialize to NULL.
     * For fixbuf internal use only.
     */
    void                *vai;
    /**
     * Pointer to SSL context cache. Initialize to NULL.
     * For fixbuf internal use only.
     */
    void                *vssl_ctx;
} fbConnSpec_t;

/**
 * Convenience macro defining a null static fbConnSpec_t.
 */
#define FB_CONNSPEC_INIT { FB_SCTP, NULL, NULL,         \
                           NULL, NULL, NULL, NULL,      \
                           NULL, NULL }

#if HAVE_SPREAD
/**
 * Spread connection parameters. Used to define a spread daemon and group
 * or list of groups for spread.
 */

#define FB_SPREADPARAMS_INIT { 0, 0, 0 }

typedef struct fbSpreadParams_st {
    /** pointer to the session, this MUST be set to a valid session before
    *   the spec is passed to fbExporterAllocSpread. */
    fbSession_t * session;
    /** pointer to the daemon host address, in Spread format.  Must be set
    *   before the spec is passed to fbExporterAllocSpread */
    char *          daemon;
    /** pointer to array of group names, must have at least one, and must
    *   be null term array */
    char **         groups;
} fbSpreadParams_t;

#endif /* HAVE_SPREAD */

struct fbExporter_st;
/**
 * IPFIX Exporting Process endpoint. Used to export messages from an associated
 * IPFIX Message Buffer to a remote Collecting Process, or to an IPFIX File.
 * The internals of this structure are private to libfixbuf.
 */
typedef struct fbExporter_st fbExporter_t;

struct fbCollector_st;
/**
 * IPFIX Collecting Process endpoint. Used to collect messages into an
 * associated IPFIX Message Buffer from a remote Exporting Process, or from
 * an IPFIX File. Use this with the fbListener_t structure to implement a full
 * Collecting Process, including Transport Session setup. The internals of
 * this structure are private to libfixbuf.
 */
typedef struct fbCollector_st fbCollector_t;

struct fbListener_st;
/**
 * IPFIX Collecting Process session listener. Used to wait for connections
 * from IPFIX Exporting Processes, and to manage open connections via a
 * select(2)-based mechanism. The internals of this structure are private
 * to libfixbuf.
 */
typedef struct fbListener_st fbListener_t;

/**
 *  ListenerGroup and associated data type definitions
 */
typedef struct fbListenerEntry_st fbListenerEntry_t;

/**
 *  ListenerEntry's make up a listener group as a linked list
 */
struct fbListenerEntry_st
{
    /** pointer to the next listener entry in the linked list */
    fbListenerEntry_t  *next;
    /** pointer to the previous listener entry in the linked list */
    fbListenerEntry_t  *prev;
    /** pointer to the listener to add to the list */
    fbListener_t       *listener;
};

/**
 * typedef for listener group result
 */
typedef struct fbListenerGroupResult_st fbListenerGroupResult_t;

/**
 * ListenerGroupResult's contain the listener who's listening socket got a new
 * connection.  It is tied to the fBuf_t that is produced for the connection
 * These make up a linked list as well
 */
struct fbListenerGroupResult_st
{
    /** Pointer to the next listener group result */
    fbListenerGroupResult_t *next;
    /** pointer to the listener that received a new connection */
    fbListener_t    *listener;
    /** pointer to the fbuf created for that new connection */
    fBuf_t          *fbuf;
};

struct fbListenerGroup_st;
/**
 * Structure that holds the listeners that are added to the group.
 */
typedef struct fbListenerGroup_st fbListenerGroup_t;

/**
 * A callback function that is called when a template is freed.  The free
 * function should be set during the fbNewTemplateCtxCallback.
 *
 * @param tmpl_ctx a pointer to the ctx that is stored within the fbTemplate.
 * @param app_ctx the app_ctx pointer that was passed to the
 *                fbSessionAddNewTemplateCallback() call
 * @return NO return value
 */
typedef void (*fbTemplateCtxFree_fn)(
    void           *tmpl_ctx,
    void           *app_ctx);

/**
 * A callback function that will be called when the session receives
 * a new external template.  This callback can be used to assign an
 * internal template to an incoming external template for nested template
 * records using fbSessionAddTemplatePair() or to apply some context variable
 * to a template.
 *
 * The callback should be set using fbSessionAddNewTemplateCallback(), and
 * that function should be called after fbSessionAlloc().  Libfixbuf often
 * clones session upon receiving a connection (particularly in the UDP case
 * since a collector and fbuf can have multiple sessions), and this callback
 * is carried over to cloned sessions.
 *
 * @param session a pointer to the session that received the template
 * @param tid the template ID for the template that was received
 * @param tmpl pointer to the template information of the received template
 * @param app_ctx the app_ctx pointer that was passed to the
 *                fbSessionAddNewTemplateCallback() call
 * @param tmpl_ctx pointer that is stored in the fbTemplate structure.
 * @param fn a callback function that should be called to free the ctx
 *                when the template is freed/replaced.
 * @return NO return value
 **/
typedef void (*fbNewTemplateCallback_fn) (
    fbSession_t           *session,
    uint16_t              tid,
    fbTemplate_t          *tmpl,
    void                  *app_ctx,
    void                  **tmpl_ctx,
    fbTemplateCtxFree_fn  *fn);


/**
 * The following Semantic values are for use in the structured Data Types:
 *  basicLists, subTemplateLists, and subTemplateMultiLists.
 */
/**
 * Semantic field for indicating the value has not been set
 */
#define FB_LIST_SEM_UNDEFINED       0xFF
/**
 * Semantic field for none-of value defined in RFC 6313
 */
#define FB_LIST_SEM_NONE_OF         0x00
/**
 * Semantic field for exactly-one-of value defined in RFC 6313
 */
#define FB_LIST_SEM_EXACTLY_ONE_OF  0x01
/**
 * Semantic field for the one-or-more-of value defined in RFC 6313
 */
#define FB_LIST_SEM_ONE_OR_MORE_OF  0x02
/**
 * Semantic field for the all-of value defined in RFC 6313
 */
#define FB_LIST_SEM_ALL_OF          0x03
/**
 * Semantic field for the ordered value defined in RFC 6313
 */
#define FB_LIST_SEM_ORDERED         0x04

/**
 *   validates the value of the semantic field,
 *
 * @param semantic The value of the semantic field to be validated  *
 * @return TRUE is valid {0xFF, 0x00-0x04}, FALSE if not
 */
gboolean fbListValidSemantic(
    uint8_t semantic);

/****** BASICLIST FUNCTIONS AND STRUCTS *******/
/**
 * A basic list element in a template which structure represents a
 * basic list on the internal side, basic lists in an IPFIX Message must
 * be represented by this structure within the application record.
 */
typedef struct fbBasicList_st {
    /** pointer to the information element that is repeated in the list */
    const fbInfoElement_t   *infoElement;
    /** pointer to the memory that stores the elements in the list */
    uint8_t                 *dataPtr;
    /** number of elements in the list */
    uint16_t                numElements;
    /** length of the buffer used to store the elements in the list */
    uint16_t                dataLength;
    /** semantic field to describe the list */
    uint8_t                 semantic;
} fbBasicList_t;


/**
 *  allocates a Basic List Structure
 *
 * @return a pointer a to the allocated basic list in memory
 */
fbBasicList_t*  fbBasicListAlloc(
    void);

/**
 * Initializes the basic list structure based on the parameters.
 * This function allocates a buffer large enough to hold
 * num elements amount of the infoElements.
 *
 * @param basicListPtr a pointer to the basic list structure to fill
 * @param semantic the semantic value to be used in the basic list
 * @param infoElement a pointer to the info element to be used in the list
 * @param numElements number of elements in the list
 * @return a pointer to the memory where the list data is to be written
 */

void* fbBasicListInit(
    fbBasicList_t          *basicListPtr,
    uint8_t                 semantic,
    const fbInfoElement_t  *infoElement,
    uint16_t                numElements);

/**
 *  use this function to initialize the basic list, but it gets the pointer
 *  to a buffer and its length allocated independently from these functions
 *  This will generally be used by a collector that does not want to
 *  free and allocate new buffers for each incoming message
 *
 * @param basicListPtr a pointer to the basic list structure to fill
 * @param semantic the semantic value to be used in the basic list
 * @param infoElement a pointer to the info element to be used in the list
 * @param numElements number of elements in the list
 * @param dataLength length of the buffer passed to the function
 * @param dataPtr pointer to the buffer previously allocated for the list
 * @return a pointer to the beginning of the buffer on success, NULL on failure
 */
void* fbBasicListInitWithOwnBuffer(
    fbBasicList_t          *basicListPtr,
    uint8_t                 semantic,
    const fbInfoElement_t  *infoElement,
    uint16_t                numElements,
    uint16_t                dataLength,
    uint8_t                *dataPtr);

/**
 *   This initializes a basic list structure for collection.  The key
 *   part of this function is it sets the dataPtr to NULL.
 *   If your basic list is declared as a pointer, then allocated using
 *   something like g_slice_alloc0 which sets it all to zero, you do not
 *   need to call this function.  But if your basic list struct isn't
 *   a pointer, there dataPtr parameter will be set to garbage, which will
 *   break other fixbuf calls, so this function is required
 *
 * @param basicListPtr pointer to the basic list to be initialized
 * @return NONE
 */
void fbBasicListCollectorInit(
    fbBasicList_t  *basicListPtr);


/**
 *  Get Semantic field for Basic List
 *  presumably used in collectors after decoding
 *
 *  @param basicListPtr pointer to the basic list to retrieve the semantic from
 *  @return the 8-bit semantic value describing the basic list
 */
uint8_t fbBasicListGetSemantic(
    fbBasicList_t  *basicListPtr);

/**
 *  Sets the semantic for describing a basic list
 *  generally used in exporters before decoding
 *
 *  @param basicListPtr pointer to the basic list to set the semantic
 *  @param semantic value to set the semantic field to
 *  @return NONE
 */
void fbBasicListSetSemantic(
    fbBasicList_t  *basicListPtr,
    uint8_t         semantic);


/**
 * This function returns a pointer to the information element used in the list
 * it is mainly used in collectors to retrieve information
 *
 * @param basicListPtr pointer to the basic list to get the infoElement from
 * @return pointer to the information element from the list
 */
const fbInfoElement_t*  fbBasicListGetInfoElement(
     fbBasicList_t  *basicListPtr);

/**
 *
 * @param basicListPtr pointer to the basic list to get the data pointer from
 * @return the pointer to the data held by the basic list
 */
void* fbBasicListGetDataPtr(
    fbBasicList_t   *basicListPtr);

/**
 * Function retrieves the index'th element in the list
 * index is 0-based.  Goes from 0 - (numElements-1)
 * @param basicListPtr pointer to the basic list to retrieve the dataPtr
 * @param bl_index the index of the element to retrieve
 * @return a pointer to the data in the index'th slot in the list, NULL
 * if the index is past the bounds of the list
 */
void* fbBasicListGetIndexedDataPtr(
    fbBasicList_t   *basicListPtr,
    uint16_t         bl_index);

/**
 * Function returns the next element in the list based on the currentPtr
 * @param basicListPtr pointer to the basic list
 * @param currentPtr pointer to the current element being used.  Set to NULL
 * to retrieve the first element.
 * @return a pointer to the next data slot, based on the current pointer.
 * NULL if the new pointer is passed the end of the buffer
 */
void* fbBasicListGetNextPtr(
    fbBasicList_t   *basicListPtr,
    void            *currentPtr);

/**
 * Free the current data pointer, allocating a new buffer to accomodate
 * the new number of elements.  The remaining parameters are unchanged.
 * If the number of elements hasn't changed
 * the original buffer is used and its pointer is returned
 * @param basicList pointer to the basic list to realloc
 * @param newNumElements new number of elements to allocate for the list
 * @return pointer to the data pointer for the list after realloc
 */
void* fbBasicListRealloc(
    fbBasicList_t  *basicList,
    uint16_t        newNumElements);

/**
 *  Allocates an additional elememnt into the basic list
 *  must be called after calling BasicListInit
 * @param basicList pointer to the basic list to add elements to
 * @param numNewElements number of elements to add to the list
 * @return a pointer to the newly allocated element(s)
*/
void* fbBasicListAddNewElements(
    fbBasicList_t  *basicList,
    uint16_t        numNewElements);

/**
 * Clear the parameters of the basic list and free the data buffer
 * @param basicListPtr pointer to the basic list to clear
 * @return NONE
 */
void fbBasicListClear(
    fbBasicList_t  *basicListPtr);

/**
 * Clear the parameters of the basic list, but do not free the buffer.
 * This should get used when the user provides their own buffer
 * @param basicList pointer to the basic list to clear without freeing
 * @return NONE
 */
void fbBasicListClearWithoutFree(
    fbBasicList_t  *basicList);

/**
 * Clear the basic list, then free the basic list pointer
 * @param basicListPtr pointer to the basic list to free
 * @return NONE
 */
void fbBasicListFree(
    fbBasicList_t  *basicListPtr);


/******* END OF BASICLIST ********/



/******* SUBTEMPLATELIST FUNCTIONS ****/

/**
 * Structure used to hold information of a sub template list.
 * This structure is filled in by the user in an exporter to tell
 * fixbuf how to encode the data.
 * This structure is filled in by the transcoder in a collector,
 * feeding the useful information up to the user
 */
typedef struct fbSubTemplateList_st {
    /** length of the allocated buffer used to hold the data */
    /** I made this a union to allow this to work on 64-bit archs */
    union {
        size_t          length;
        uint64_t        extra;
    } dataLength;
    /** pointer to the template used to structure the data */
    const fbTemplate_t  *tmpl;
    /** pointer to the buffer used to hold the data */
    uint8_t             *dataPtr;
    /** ID of the template used to structure the data */
    uint16_t            tmplID;
    /** number of elements in the list */
    uint16_t            numElements;
    /** value used to describe the contents of the list, all-of, one-of, etc*/
    uint8_t             semantic;
} fbSubTemplateList_t;

/**
 *  Allocates a subTemplateList_t
 *  Based on how subTemplateLists will be used and set up amidst data
 *  structures, this function may never be used
 * @return pointer to the new sub template list
 */
fbSubTemplateList_t* fbSubTemplateListAlloc(
    void);

/**
 *  Initializes a subTemplateList structure and alloc's the dataPtr
 *  to get a buffer able to hold numElements in the template
 *  This will mainly be used in exporters preparing to encode
 *
 * @param sTL pointer to the sub template list to initialize
 * @param semantic the semantic value used to describe the list contents
 * @param tmplID id of the template used for encoding the list data
 * @param tmpl pointer to the template struct used for encoding the list data
 * @param numElements number of elements in the list
 * @return a pointer to the allocated buffer (location of first element)
 */
void*  fbSubTemplateListInit(
    fbSubTemplateList_t    *sTL,
    uint8_t                 semantic,
    uint16_t                tmplID,
    const fbTemplate_t     *tmpl,
    uint16_t                numElements);

/**
 *  Initializes the subTemplateList but does not allocate a buffer.  It
 *  accepts a previously allocated buffer and data length and uses it.
 *  This will generally be used in collectors providing their own buffer
 *
 * @param subTemplateList pointer to the sub template list to initialize
 * @param semantic the semantic value used to describe the list contents
 * @param tmplID id of the template used for encoding the list data
 * @param tmpl pointer to the template struct used for encoding the list data
 * @param numElements number of elements in the list
 * @param dataLength length of the data buffer
 * @param dataPtr pointer to the previously allocated data buffer
 * @returns a pointer to that buffer
*/
void* fbSubTemplateListInitWithOwnBuffer(
    fbSubTemplateList_t    *subTemplateList,
    uint8_t                 semantic,
    uint16_t                tmplID,
    const fbTemplate_t     *tmpl,
    uint16_t                numElements,
    uint16_t                dataLength,
    uint8_t                *dataPtr);

/**
 * Initializes a sub template list variable on a collector.  If the
 * fbSubTemplateList variable is in a struct, it will likely not be set to 0's
 * If not, the dataPtr will not be NULL, so the transcoder will not allocate
 * the right memory for it, as it will assuming it's set up.  This will break.
 * Call this function right after declaring the struct variable that contains
 * the fbSubTemplateList.  It only needs to be called once for each STL
 * @param STL pointer to the sub template list to initialize for collection
 * @return NONE
 */
void fbSubTemplateListCollectorInit(
    fbSubTemplateList_t    *STL);

/**
 * Returns a pointer to the buffer that contains the data for the list
 * @param subTemplateListPtr pointer to the STL to get the pointer from
 * @return a pointer to the data buffer used by the sub template list
 */
void* fbSubTemplateListGetDataPtr(
    const fbSubTemplateList_t  *subTemplateListPtr);

/**
 * This function is used to iterate over the elements in the list by
 * passing in a counter to indicate which element is to be returned
 * @param subTemplateListPtr pointer to the STL
 * @param index The index of the element to be retrieved (0-based)
 * @return a pointer to the desired element.  NULL if index >= numElements
 */
void* fbSubTemplateListGetIndexedDataPtr(
    const fbSubTemplateList_t  *subTemplateListPtr,
    uint16_t                    index);

/**
 * This function also traverses the elements in the list by accepting
 * a pointer to the last element the user accessed, moves it to the next
 * element and returns a pointer to the next element.  A current element of
 * NULL tells the function to return the first element in the list.
 * @param subTemplateListPtr pointer to the STL to get data from
 * @param currentPtr pointer to the last element accessed.  NULL causes the
 *                   pointer to the first element to be returned
 * @return the pointer to the next element in the list.  Returns NULL if
 *         currentPtr points to the last element in the list.
 */
void* fbSubTemplateListGetNextPtr(
    const fbSubTemplateList_t  *subTemplateListPtr,
    void                       *currentPtr);

/**
 * Sets the semantic parameter of a subTemplateList
 * @param subTemplateListPtr pointer to the sub template list
 * @param semantic Semantic value for the list
 * @return NONE
 */
void fbSubTemplateListSetSemantic(
    fbSubTemplateList_t    *subTemplateListPtr,
    uint8_t                 semantic);

/**
 * Gets the semantic value from a sub template list
 * @param subTemplateListPtr pointer to the sub template list
 * @return the semantic field from the list
 */
uint8_t fbSubTemplateListGetSemantic(
    fbSubTemplateList_t    *subTemplateListPtr);

/**
 * Gets the template pointer from the list structure
 * @param subTemplateListPtr pointer to the sub template list
 * @return a pointer to the template used by the sub template list
 */
const fbTemplate_t* fbSubTemplateListGetTemplate(
    fbSubTemplateList_t    *subTemplateListPtr);

/**
 * Gets the template ID for the template used by the list
 * @param subTemplateListPtr pointer to the sub template list
 * @return the template ID used by the sub template list
 */
uint16_t fbSubTemplateListGetTemplateID(
    fbSubTemplateList_t    *subTemplateListPtr);

/**
 *  Free the current data pointer, allocating a new buffer to accomodate
 *  the new number of elements.  The remaining parameters are unchanged.
 *  If the number of elements hasn't changed
 *  the original buffer is used and its pointer is returned
 *
 * @param subTemplateList pointer to the sub template list to realloc
 * @param newNumElements value for the new number of elements for the list
 * @return pointer to the data buffer after realloc
 */
void* fbSubTemplateListRealloc(
    fbSubTemplateList_t    *subTemplateList,
    uint16_t                newNumElements);

/**
 *  Allocates space for a number of additional element in the sub template list
 *  must be called after the list has been fbSubTemplateListInit()'d
 *
 * @param subTemplateList pointer to the sub template list
 * @param numNewElements number of new elements to add to the list
 * @return a pointer to the first newly allocated element
 */
void* fbSubTemplateListAddNewElements(
    fbSubTemplateList_t    *subTemplateList,
    uint16_t                numNewElements);

/**
 *  Clears a subtemplate list struct, notably freeing the dataPtr and setting
 *  it to NULL.
 *  This should be used after each call to fBufNext:
 *  If the dataPtr is not NULL in DecodeSubTemplateList, it will not allocate
 *  new memory for the new record, which could cause a buffer overflow if the
 *  new record has a longer list than the current one.
 *  An alternative is to allocate a large buffer and assign it to dataPtr
 *  on your own, then never clear it with this.  Be certain this buffer is
 *  longer than needed for all possible lists
 * @param subTemplateListPtr pointer to the sub template list to clear
 * @return NONE
 */
void fbSubTemplateListClear(
    fbSubTemplateList_t    *subTemplateListPtr);

/**
 *  Clears the sub template list parameters but does not free the data ptr.
 *  This is used in conjuction with STLInitOwnBuffer because that buffer
 *  is allocated at the beginning by the user and will be freed at the end
 *  by the user, outside of fixbuf api calls
 * @param subTemplateListPtr pointer to the sub template list to clear
 * @return NONE
*/
void fbSubTemplateListClearWithoutFree(
    fbSubTemplateList_t    *subTemplateListPtr);

/**
 *  Frees and clears a subTemplateList struct.  This frees the dataPtr AND
 *  frees the memory pointed to by the subTemplateListPtr
 * Used in conjunction with subTemplateListAlloc(), unlikely to be used
 * @param subTemplateListPtr pointer to the sub template list to free
 * @return NONE
 */
void fbSubTemplateListFree(
    fbSubTemplateList_t    *subTemplateListPtr);

/********* END OF SUBTEMPLATELIST **********/
/**
 *  Entries contain the same type of information at SubTemplateLists:
 *  template ID and template pointers to describe the data
 *  the number of data elements and the data pointer and data length
 *
 * Sub template multi lists are inherently nested constructions.
 * At a high level, they are a list of sub template lists.
 * The first level is a list of fbSubTemplateMultiListEntry_t's, which each
 * contain the information that describes the data contained in them.
 * Initializing a fbSubTemplateMultiList_t with a semantic and number of
 * elements returns memory that contains numElements blocks of memory
 * containing fbSubTemplateMultiListEntry_t's.  It is not ready to accept
 * data.  Each of the fbSubTemplateMultiListEntry_t's needed to be set up
 * then data is copied into the entries.
 */


typedef struct fbSubTemplateMultiListEntry_st {
    /** pointer to the template used to structure the data in this entry */
    fbTemplate_t   *tmpl;
    /** pointer to the buffer used to hold the data in this entry */
    uint8_t        *dataPtr;
    /** length of the buffer used to hold the data in this entry */
    size_t          dataLength;
    /** ID of the template used to structure the data in this entry */
    uint16_t        tmplID;
    /** number of elements in this entry */
    uint16_t        numElements;
} fbSubTemplateMultiListEntry_t;

/**
 * Multilists just contain the semantic to describe the sub lists,
 * the number of sub lists, and a pointer to the first entry
*/
typedef struct fbSubTemplateMultiList_st {
    /** pointer to the first entry in the multi list */
    fbSubTemplateMultiListEntry_t  *firstEntry;
    /** number of sub template lists in the multi list */
    uint16_t                        numElements;
    /** value used to describe the list of sub templates */
    uint8_t                         semantic;
} fbSubTemplateMultiList_t;


/**
 *  Allocates a subTemplateMultiList_t
 *  Based on how subTemplateMultiLists will be used and
 *  set up amidst data structures, this function may never be used
 *
 *  @return pointer to the new sub template multi list
 */
fbSubTemplateMultiList_t* fbSubTemplateMultiListAlloc(
    void);


/**
 *  Initializes the multi list with semantic, numbers of elements,
 *  and allocates memory to store numElements worth of entries
 *
 * @param STML pointer to the sub template multi list to initialize
 * @param semantic value used to describe the entries in the multi list
 * @param numElements number of entries in the multi list
 * @return pointer to the first uninitialized entry
 */
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListInit(
    fbSubTemplateMultiList_t   *STML,
    uint8_t                     semantic,
    uint16_t                    numElements);

/**
 * Sets the semantic field for the multi list
 * @param STML pointer to the sub template multi list
 * @param semantic Value for the semantic field of the sub template multi list
 * @return NONE
*/
void fbSubTemplateMultiListSetSemantic(
    fbSubTemplateMultiList_t   *STML,
    uint8_t                     semantic);

/**
 * Get the semantic paramter from the multi list
 * @param STML pointer to the sub template multi list
 * @return semantic parameter describing the contents of the multi list
 */
uint8_t fbSubTemplateMultiListGetSemantic(
    fbSubTemplateMultiList_t   *STML);

/**
 *  Clears all of the entries (frees their data pointers), then frees the
 *  memory containing the entries
 * @param STML pointer to the sub template mutli list to clear
 * @return NONE
 */
void fbSubTemplateMultiListClear(
    fbSubTemplateMultiList_t   *STML);

/**
 * Clears the memory used by the entries of a sub template multi list
 * NOTE: if any of those entries contain another layer of structures, that
 * second layer must be freed by the user, this function cannot do that.
 * example: an entry's template contains an element of type basicList.  The
 * memory used by that basicList isn't freed by this function
 * @param STML pointer to the sub template multi list
 * @return NONE
 */
void fbSubTemplateMultiListClearEntries(
    fbSubTemplateMultiList_t   *STML);

/**
 * Clears the multi list, then frees the memory pointed to by STML
 * @param STML pointer to the sub template multi list
 * @return NONE
 */
void fbSubTemplateMultiListFree(
    fbSubTemplateMultiList_t   *STML);

/**
 *  Clears the entries used by the multi list, then if newNumElements
 *  is different than numElements, frees the entries buffer and allocates
 *  a new one.
 *
 * @param STML pointer to the sub template mutli list
 * @param newNumEntries the new number of entries for the STML
 * @return pointer to the first entry
*/
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListRealloc(
    fbSubTemplateMultiList_t   *STML,
    uint16_t                    newNumEntries);

/**
 *  Adds entries to the multi list of entries
 *  can only be run after the list has been initialized
 *
 * @param STML pointer to the sub template multi list
 * @param numNewEntries number of entries to add to the list
 * @return a pointer to the new entry
 */
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListAddNewEntries(
    fbSubTemplateMultiList_t   *STML,
    uint16_t                    numNewEntries);

/**
 * Retrieve the first entry in the multi list
 * @param STML pointer to the sub template multi list
 * @return pointer to the first entry used by the list
 */
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListGetFirstEntry(
    fbSubTemplateMultiList_t   *STML);

/**
 * Retrieve a pointer to the entry of a specific index.  The entry indexes
 * are zero based.  NULL is returned if the index requested is too high
 * @param STML pointer to the sub template mutli list
 * @param index index of the entry to be returned
 * @return the index'th entry used by the list.  NULL If index >= numElements
 */
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListGetIndexedEntry(
    fbSubTemplateMultiList_t   *STML,
    uint16_t                    index);

/**
 * This function also traverses the elements in the list by accepting
 * a pointer to the last element the user accessed, moves it to the next
 * element and returns a pointer to the next element.  A current element of
 * NULL tells the function to return the first element in the list.
 * @param STML pointer to the sub template multi list to get data from
 * @param currentEntry pointer to the last element accessed.
 *                     NULL means none have been accessed yet
 * @return the pointer to the next element in the list.  Returns the NULL
 *         if currentEntry points to the last entry.
 */
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListGetNextEntry(
    fbSubTemplateMultiList_t       *STML,
    fbSubTemplateMultiListEntry_t  *currentEntry);

/**
 *  Initializes the multi list entry with the template values,
 *  and allocates the memory used by the entry to hold the data.
 *
 *  @param entry pointer to the entry to initialize
 *  @param tmplID ID of the template used to structure the data elements
 *  @param tmpl pointer to the template used to structure the data elements
 *  @param numElements number of data elements in the entry
 *
 *  @return pointer to the data buffer to be filled in
*/
void* fbSubTemplateMultiListEntryInit(
    fbSubTemplateMultiListEntry_t  *entry,
    uint16_t                        tmplID,
    fbTemplate_t                   *tmpl,
    uint16_t                        numElements);

/**
 *  Frees the memory for the data used by the entry, then allocates
 *  a new buffer based on the size of the template and newNumElements.
 *  (if numElements doesn't change, the pointer is returned without freeing
 *  and allocating)
 *
 *  @param entry pointer to the entry to realloc
 *  @param newNumElements the new number of elements for the entry
 *  @return pointer to buffer to write data to
 */
void *fbSubTemplateMultiListEntryRealloc(
    fbSubTemplateMultiListEntry_t  *entry,
    uint16_t                        newNumElements);

/**
 *  Allocates space for a number of additional elements in the sub
 *  template multi list entry.  May only be called after the STML entry
 *  has been initialized with fbSubTemplateMultiListEntryInit().
 *
 *  @param entry pointer to the STML entry to add additional elements to
 *  @param numNewElements number of new elements to add to the STML entry
 *  @return a pointer to the first newly allocated element
 */
void* fbSubTemplateMultiListEntryAddNewElements(
    fbSubTemplateMultiListEntry_t   *entry,
    uint16_t                         numNewElements);

/**
 *  Frees the memory pointed to by the data buffer holding the data elements
 *
 *  @param entry pointer to the entry to clear the contents of.
 *  @return NONE
 */
void fbSubTemplateMultiListEntryClear(
    fbSubTemplateMultiListEntry_t   *entry);

/**
 * Retrieves the data pointer for this entry
 *
 * @param entry pointer to the entry to get the data pointer from
 * @return pointer to the buffer used to store data for this entry
 */
void* fbSubTemplateMultiListEntryGetDataPtr(
    fbSubTemplateMultiListEntry_t   *entry);

/**
 * This function traverses the elements in the entry by accepting
 * a pointer to the last element the user accessed, moves it to the next
 * element and returns a pointer to the next element.  A current element of
 * NULL tells the function to return the first element in the list.
 * @param entry pointer to the entry to get the next element from
 * @param currentPtr pointer to the last element accessed.  NULL means return
                     a pointer to the first element.
 * @return the pointer to the next element in the list.  Returns NULL if
 *         currentPtr points to the last element in the list
 */
void* fbSubTemplateMultiListEntryNextDataPtr(
    fbSubTemplateMultiListEntry_t   *entry,
    void                            *currentPtr);

/**
 * Returns a pointer to a data element in the entry based on the index.
 * If the index is >= to the number of elements in the list, NULL is returned.
 * The elements are 0-based, so index = 0 is returns the first elements.
 *
 * @param entry pointer to the entry to get a data pointer from.
 * @param index the number of the element in the list to return
 * @return the pointer to the index'th element used by the entry
 *         NULL if the index is >= numElements
 */
void* fbSubTemplateMultiListEntryGetIndexedPtr(
    fbSubTemplateMultiListEntry_t   *entry,
    uint16_t                         index);

/**
 * Retrieve the template pointer used to structure the data elements
 *
 * @param entry pointer to the entry to get the template from
 * @return the template pointer used to describe the contents of the entry
 */
const fbTemplate_t* fbSubTemplateMultiListEntryGetTemplate(
    fbSubTemplateMultiListEntry_t   *entry);

/**
 * Retrieve the template ID for the template used to structure the data
 *
 * @param entry pointer to the entry to get the template ID from
 * @returns the template ID for template that describes the data
 */
uint16_t fbSubTemplateMultiListEntryGetTemplateID(
    fbSubTemplateMultiListEntry_t   *entry);

/************** END OF STML FUNCTIONS *********** */

/**
 * Clear all of the memory that fixbuf allocated during
 * transcode of this record.  This will free all of the memory
 * allocated for list structures when fixbuf was encoding or
 * decoding the record.  The template provided is the internal
 * template that was set on the fBuf before fBufNext() or
 * fBufAppend() was called with the data.  The template MUST
 * match the record or bad things WILL happen without indication.
 * This does not free the record itself.  It will only free any
 * list information elements and nested list information elements.
 *
 * @param tmpl pointer to the internal template that MUST match the record
 * @param record pointer to the data
 * @return NONE
 */
void fBufListFree(
    fbTemplate_t     *tmpl,
    uint8_t          *record);


/**
 * Allocates and returns a fbListenerGroup with no entries
 *
 * @return a pointer to the created fbListenerGroup_t, or NULL on error
 */
fbListenerGroup_t* fbListenerGroupAlloc(
    void);

/**
 * frees a listener group
 *
 * @param group fbListenerGroup
 * @return nothing
 */
void fbListenerGroupFree(
    fbListenerGroup_t *group);

/**
 * Adds a previously allocated listener to the previously allocated group.
 * The listener is placed at the head of the list
 *
 * @param group pointer to the allocated group to add the listener to
 * @param listener pointer to the listener structure to add to the group
 * @return 0 upon success. "1" if entry couldn't be allocated
 *         "2" if either of the incoming pointers are NULL
 */
int fbListenerGroupAddListener(
    fbListenerGroup_t          *group,
    const fbListener_t         *listener);

/**
 * Removes the listener from the group.
 * IT DOES NOT FREE THE LISTENER OR THE GROUP
 *
 * @param group pointer to the group to remove from the listener from
 * @param listener pointer to the listener to remove from the group
 * @return 0 on success, and "1" if the listener is not found
 *         "2" if either of the pointers are NULL
 */
int fbListenerGroupDeleteListener(
    fbListenerGroup_t          *group,
    const fbListener_t         *listener);

/**
 *  Similar to fbListenerWait, except that is looks for connections for
 *  multiple listeners.  It takes a previously allocated and filled
 *  listener group.  It returns a pointer to the head of a list of
 *  listenerGroupResults.
 *  @param group pointer to the group of listeners to wait on
 *  @param err error string structure seen throughout fixbuf
 *  @return pointer to the head of the listener group result list
 *          NULL on error, and sets the error string
 */
fbListenerGroupResult_t* fbListenerGroupWait(
    fbListenerGroup_t          *group,
    GError                     **err);


/**
 * Free the fbListenerGroupResult_t returned from fbListenerGroupWait
 *
 * @param result fbListenerGroupResult_t
 * @return nothing
 */
void fbListenerFreeGroupResult(
    fbListenerGroupResult_t *result);

/**
 *  Returns an fBuf wrapped around an independently managed socket and a
 *  properly created listener for TCP connections.
 *  The caller is only responsible for creating the socket.
 *  The existing collector code will close the socket and cleanup everything.
 *
 *  @param listener pointer to the listener to wrap around the socket
 *  @param sock the socket descriptor of the independently managed socket
 *  @param err standard fixbuf err structure pointer
 *  @return pointer to the fbuf for the collector.
 *          NULL if sock is 0, 1, or 2 (stdin, stdout, or stderr)
 */
fBuf_t  *fbListenerOwnSocketCollectorTCP(
    fbListener_t   *listener,
    int             sock,
    GError        **err);

/**
 *  Same as fbListenerOwnSocketCollectorTCP but for TLS (not tested)
 *
 *  @param listener pointer to the listener to wait on
 *  @param sock independently managed socket descriptor
 *  @param err standard fixbuf err structure pointer
 *  @return pointer to the fbuf for the collector
 *          NULL if sock is 0, 1, or 2 (stdin, stdout, or stderr)
 */
fBuf_t  *fbListenerOwnSocketCollectorTLS(
    fbListener_t   *listener,
    int             sock,
    GError        **err);

/**
 *  Interrupts the select call of a specific collector by way of its fBuf.
 *  This is mainly used by fbListenerInterrupt to interrupt all of the
 *  collector sockets well.
 */
void    fBufInterruptSocket(
    fBuf_t         *fbuf);


/**
 * Application context initialization function type for fbListener_t.
 * This function is called after accept(2) for TCP or SCTP with the peer
 * address in the peer argument. For UDP, it is called during fbListener_t
 * initialization and the peer address will be NULL.  If the Collector is in
 * multi-session mode, the appinit function will be called when a new UDP
 * connection occurs with the peer address, similiar to the TCP case.  Use
 * fbCollectorSetUDPMultiSession() to turn on multi-session mode
 * (off by default).  The application may veto fbCollector_t creation by
 * returning FALSE. In multi-session mode, if the connection is to be ignored,
 * the application should set error code FB_ERROR_NLREAD on the err and return
 * FALSE.  If the application returns FALSE, fixbuf will maintain information
 * about that peer, and will reject connections from that peer until shutdown
 * or until that session times out.  Fixbuf will return FB_ERROR_NLREAD for
 * previously rejected sessions.
 * The context (returned via out-parameter ctx) will be
 * stored in the fbCollector_t, and is retrievable via a call to
 * fbCollectorGetContext().  If not in multi-session mode and using the appinit
 * fn, the ctx will be associated with all UDP sessions.
 */
typedef gboolean        (*fbListenerAppInit_fn) (
    fbListener_t                *listener,
    void                        **ctx,
    int                         fd,
    struct sockaddr             *peer,
    size_t                      peerlen,
    GError                      **err);

/**
 * Application context free function type for fbListener_t.
 * If the Collector is in multi-session mode (see appinit fn), then the
 * appfree function will be called if a session is timed out (does not receive
 * a UDP message for more than 30 minutes.)
 * Called during fbCollector_t cleanup.
 */
typedef void            (*fbListenerAppFree_fn) (
    void                        *ctx);

/*
 * Public Function Calls. These calls will remain available and retain
 * their functionality in all subsequent versions of libfixbuf.
 */


/**
 * Set the internal template on a buffer to the given template ID. The internal
 * template describes the format of the record pointed to by the recbase
 * parameter to fBufAppend() (for export) and fBufNext() (for collection). The
 * given template ID must identify a current internal template in the buffer's
 * associated session.
 *
 * An internal template must be set on a buffer before calling fBufAppend() or
 * fBufNext().
 *
 * @param fbuf      an IPFIX message buffer
 * @param int_tid   template ID of the new internal template
 * @param err       An error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fBufSetInternalTemplate(
    fBuf_t              *fbuf,
    uint16_t            int_tid,
    GError              **err);

/**
 * Set the external template for export on a buffer to the given template ID.
 * The external template describes the record that will be written to the
 * IPFIX message. The buffer must be initialized for export. The given ID is
 * scoped to the observation domain of the associated session
 * (see fbSessionSetDomain()), and must identify a current external template
 * for the current domain in the buffer's associated session.
 *
 * An export template must be set on a buffer before calling fBufAppend().
 *
 * @param fbuf      an IPFIX message buffer
 * @param ext_tid   template ID of the new external template within the
 *                  current domain.
 * @param err       An error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fBufSetExportTemplate(
    fBuf_t              *fbuf,
    uint16_t            ext_tid,
    GError              **err);

#if HAVE_SPREAD
/**
 * fBufSetSpreadExportGroup
 *
 * This function checks to see if the groups you are setting on the buffer
 * are different than the groups previously set.  If so, it will emit the
 * buffer, set the first group on the session (to get templates & sequence
 * numbers) and THEN set the desired group(s) for export on a buffer.  This
 * should be called before setting external templates with
 * fbSessionAddTemplate() and before calling fBufAppend().  If using
 * fbSessionAddTemplatesMulticast(), it is not necessary to call this before
 * because it is called within this function.
 *
 * @param fbuf       an IPFIX message buffer
 * @param groups     an array of Spread Export Groups
 * @param num_groups number of groups from groups to be added
 * @param err        an error description, set on failure.
 */
void                 fBufSetSpreadExportGroup(
    fBuf_t             *fbuf,
    char               **groups,
    int                num_groups,
    GError             **err);
#endif

/**
 * Set the automatic mode flag on a buffer. In automatic mode, a call to
 * fBufAppend() or fbSessionExportTemplates() that overruns the available space
 * in the buffer will cause a call to fBufEmit() to emit the message in the
 * buffer to the exporter before starting a new message; and a call to
 * fBufNext() that overruns the buffer will cause a call to fBufNextMessage()
 * to read another message from the collector before attempting to read a
 * record. In manual mode, end of message on any buffer read/write call
 * results in FB_ERROR_EOM. Buffers are created in automatic mode by default.
 *
 * @param fbuf      an IPFIX message buffer
 * @param automatic TRUE for this buffer to be automatic, FALSE for manual.
 */

void                fBufSetAutomaticMode(
    fBuf_t              *fbuf,
    gboolean            automatic);

/**
 * Set the automatic insert flag on a buffer.  In automatic insert mode,
 * any information element type records that are collected, will automatically
 * be inserted into the information model that is set on the fbuf's session.
 * This allows an application to retrieve information about a non-standard
 * information.  This should be called after the fbuf is created.  This
 * function creates the internal template for the Info Element Type Record
 * and adds it to the session.
 *
 * @param fbuf        an IPFIX message buffer
 * @param err         Gerror pointer
 * @return            TRUE or FALSE if the internal template could not be
 *                    created
 */
gboolean         fBufSetAutomaticInsert(
    fBuf_t             *fbuf,
    GError             **err);


/**
 * Retrieve the session associated with a buffer.
 *
 * @param fbuf      an IPFIX message buffer
 * @return the associated session
 */

fbSession_t         *fBufGetSession(
    fBuf_t              *fbuf);

/**
 * Free a buffer. Also frees any associated session, exporter, or collector,
 * closing exporting process or collecting process endpoint connections
 * and removing collecting process endpoints from any listeners, as necessary.
 *
 * @param fbuf      an IPFIX message buffer
 */

void                fBufFree(
    fBuf_t              *fbuf);

/**
 * Allocate a new buffer for export. Associates the buffer with a given
 * session and exporting process endpoint; these become owned by the buffer.
 * Session and exporter are freed by fBufFree.  Must never be freed by user
 *
 * @param session   a session initialized with appropriate
 *                  internal and external templates
 * @param exporter  an exporting process endpoint
 * @return a new IPFIX message buffer, owning the session and exporter,
 *         for export use via fBufAppend() and fBufEmit().
 */

fBuf_t              *fBufAllocForExport(
    fbSession_t         *session,
    fbExporter_t        *exporter);

/**
 * Retrieve the exporting process endpoint associated with a buffer.
 * The buffer must have been allocated with fBufAllocForExport();
 * otherwise, returns NULL.
 *
 * @param fbuf      an IPFIX message buffer
 * @return the associated exporting process endpoint
 */

fbExporter_t        *fBufGetExporter(
    fBuf_t              *fbuf);

/**
 * Associate an exporting process endpoint with a buffer.
 * The exporter will be used to write IPFIX messgaes to a transport.
 * The exporter becomes owned by the buffer; any previous exporter
 * associated with the buffer is closed if necessary and freed.
 *
 * @param fbuf      an IPFIX message buffer
 * @param exporter  an exporting process endpoint
 */

void                fBufSetExporter(
    fBuf_t              *fbuf,
    fbExporter_t        *exporter);


/**
 * Retrieve the length of the buffer that is remaining after
 * processing.  An IPFIX collector that is not using fixbuf to
 * handle connections would use this function upon receiving an
 * FB_ERROR_BUFSZ error to determine how many bytes are left in the
 * buffer (set by fBufSetBuffer) that are not processed.
 *
 * @param fbuf an IPFIX message buffer
 * @return length of buffer not read
 *
 */
size_t fBufRemaining(
    fBuf_t      *fbuf);


/**
 * Set a buffer on an fBuf for collection.  This can be used
 * by applications that want to handle their own connections, file reading,
 * etc.  This call should be made after the call to read and before
 * calling fBufNext.  fBufNext will return FB_ERROR_BUFSZ when there is not
 * enough buffer space to read a full IPFIX message.
 *
 * @param fbuf an IPFIX message buffer
 * @param buf the data buffer to use for processing IPFIX
 * @param buflen the length of IPFIX data in buf
 *
 */
void fBufSetBuffer(
    fBuf_t         *fbuf,
    uint8_t        *buf,
    size_t          buflen);


/**
 * Append a record to a buffer. Uses the present internal template set via
 * fBufSetInternalTemplate() to describe the record of size recsize located
 * in memory at recbase.  Uses the present export template set via
 * fBufSetExportTemplate() to describe the record structure to be written to
 * the buffer. Information Elements present in the external template that are
 * not present in the internal template are transcoded into the message as
 * zeroes. If the buffer is in automatic mode, may cause a message to be
 * emitted via fBufEmit() if there is insufficient space in the buffer for
 * the record.
 *
 * If the internal template contains any variable length Information Elements,
 * those must be represented in the record by fbVarfield_t structures.
 *
 * @param fbuf      an IPFIX message buffer
 * @param recbase   pointer to internal record
 * @param recsize   size of internal record in bytes
 * @param err       an error description, set on failure.
 *                  Must not be NULL, as it is used internally in
 *                  automatic mode to detect message restart.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fBufAppend(
    fBuf_t              *fbuf,
    uint8_t             *recbase,
    size_t              recsize,
    GError              **err);

/**
 * Emit the message currently in a buffer using the associated exporting
 * process endpoint.
 *
 * @param fbuf      an IPFIX message buffer
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fBufEmit(
    fBuf_t              *fbuf,
    GError              **err);

/**
 * Set the export time on the message currently in a buffer. This will be used
 * as the export time of the message created by the first call to fBufAppend()
 * after the current message, if any, is emitted. Use 0 for the export time
 * to cause the export time to be taken from the system clock at message
 * creation time.
 *
 * @param fbuf      an IPFIX message buffer
 * @param extime    the export time in epoch seconds.
 */

void                fBufSetExportTime(
    fBuf_t              *fbuf,
    uint32_t            extime);

/**
 * Allocate a new buffer for collection. Associates the buffer with a given
 * session and collecting process endpoint; these become owned by the buffer.
 * Session and collector are freed by fBufFree.  Must not be freed by user
 *
 * @param session   a session initialized with appropriate
 *                  internal templates
 * @param collector  an collecting process endpoint
 * @return a new IPFIX message buffer, owning the session and collector,
 *         for collection use via fBufNext() and fBufNextMessage().
 */

fBuf_t              *fBufAllocForCollection(
    fbSession_t         *session,
    fbCollector_t       *collector);

/**
 * Retrieve the collecting process endpoint associated with a buffer.
 * The buffer must have been allocated with fBufAllocForCollection();
 * otherwise, returns NULL.
 *
 * @param fbuf      an IPFIX message buffer
 * @return the associated collecting process endpoint
 */

fbCollector_t       *fBufGetCollector(
    fBuf_t              *fbuf);

/**
 * Associate an collecting process endpoint with a buffer.
 * The collector will be used to read IPFIX messgaes from a transport.
 * The collector becomes owned by the buffer; any previous collector
 * associated with the buffer is closed if necessary and freed.
 *
 * @param fbuf      an IPFIX message buffer
 * @param collector  an collecting process endpoint
 */

void                fBufSetCollector(
    fBuf_t              *fbuf,
    fbCollector_t       *collector);

/**
 * Retrieve a record from a buffer. Uses the external template taken from
 * the message to read the next record available from a data set in the message.
 * Copies the record to a buffer at recbase, with a maximum record size
 * pointed to by recsize, described by the present internal template set via
 * fBufSetInternalTemplate(). Reads and processes any templates and options
 * templates between the last record read (or beginning of message) and the
 * next data record. Information Elements present in the internal template
 * that are not present in the external template are transcoded into the
 * record at recbase as zeroes. If the buffer is in automatic mode, may cause
 * a message to be read via fBufNextMessage() if there are no more records
 * available in the message buffer.
 *
 * If the internal template contains any variable length Information Elements,
 * those must be represented in the record at recbase by fbVarfield_t
 * structures.
 *
 * @param fbuf      an IPFIX message buffer
 * @param recbase   pointer to internal record buffer; will contain
 *                  record data after call.
 * @param recsize   On call, pointer to size of internal record buffer
 *                  in bytes. Contains number of bytes actually transcoded
 *                  at end of call.
 * @param err       an error description, set on failure.
 *                  Must not be NULL, as it is used internally in
 *                  automatic mode to detect message restart.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fBufNext(
    fBuf_t              *fbuf,
    uint8_t             *recbase,
    size_t              *recsize,
    GError              **err);

/**
 * Read a new message into a buffer using the associated collecting
 * process endpoint. Called by fBufNext() on end of message in automatic
 * mode; should be called after an FB_ERROR_EOM return from fBufNext in
 * manual mode, or to skip the current message and go on to the next
 * in the stream.
 *
 * @param fbuf      an IPFIX message buffer
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */


gboolean            fBufNextMessage(
    fBuf_t              *fbuf,
    GError              **err);

/**
 * Retrieve the export time on the message currently in a buffer.
 *
 * @param fbuf      an IPFIX message buffer
 * @return the export time in epoch seconds.
 */

uint32_t            fBufGetExportTime(
    fBuf_t              *fbuf);

/**
 * Retrieve the external template used to read the last record from the buffer.
 * If no record has been read, returns NULL. Stores the external template ID
 * within the current domain in ext_tid, if not NULL.
 *
 * This routine is not particularly useful to applications, as it would be
 * called after the record described by the external template had been
 * transcoded, and as such could not be used to select an
 * appropriate internal template for a given external template. However,
 * it is used by fBufNextCollectionTemplate(), and may be useful in certain
 * contexts, so is made public.
 *
 * Usually, you'll want to use fBufNextCollectionTemplate() instead.
 *
 * @param fbuf      an IPFIX message buffer
 * @param ext_tid   pointer to external template ID storage, or NULL.
 * @return the external template describing the last record read.
 */

fbTemplate_t    *fBufGetCollectionTemplate(
    fBuf_t          *fbuf,
    uint16_t        *ext_tid);

/**
 * Retrieve the external template that will be used to read the next record
 * from the buffer. If no next record is available, returns NULL. Stores the
 * external template ID within the current domain in ext_tid, if not NULL.
 * Reads and processes any templates and options
 * templates between the last record read (or beginning of message) and the
 * next data record. If the buffer is in automatic mode, may cause
 * a message to be read via fBufNextMessage() if there are no more records
 * available in the message buffer.
 *
 * @param fbuf      an IPFIX message buffer
 * @param ext_tid   pointer to external template ID storage, or NULL.
 * @param err       an error description, set on failure.
 *                  Must not be NULL, as it is used internally in
 *                  automatic mode to detect message restart.
 * @return the external template describing the last record read.
 */

fbTemplate_t    *fBufNextCollectionTemplate(
    fBuf_t          *fbuf,
    uint16_t        *ext_tid,
    GError          **err);

/**
 * Allocate a new information model. The information model will contain all
 * the default information elements in the IANA-managed number space, and may
 * be extended via fbInfoModelAddElement() and fbInfoModelAddElementArray().
 *
 * An Information Model is required to create Templates and Sessions. Each
 * application should have only one Information Model.
 *
 * @return a new Information Model
 */

fbInfoModel_t       *fbInfoModelAlloc(void);

/**
 * Free an information model. Must not be called until all sessions and
 * templates depending on the information model have also been freed; i.e.,
 * at application cleanup time.
 *
 * @param model     An information model
 */

void                fbInfoModelFree(
    fbInfoModel_t       *model);

/**
 * Add a single information element to an information
 * model. The information element is assumed to be in "canonical" form; that
 * is, its ref.name field should contain the information element name. The
 * information element and its name are copied into the model; the caller may
 * free or reuse its storage after this call.
 *
 * See fbInfoModelAddElementArray() for a more convenient method of statically
 * adding information elements to information models.
 *
 * @param model     An information model
 * @param ie        Pointer to an information element to copy into the model
 */

void                fbInfoModelAddElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ie);

/**
 * Add multiple information elements in an array to an information
 * model. The information elements are assumed to be in "canonical" form; that
 * is, their ref.name fields should contain the information element name. Each
 * information element and its name are copied into the model; the caller may
 * free or reuse its storage after this call.
 *
 * The ie parameter points to the first information element in an array,
 * usually statically initialized with an array of FB_IE_INIT macros followed
 * by an FB_IE_NULL macro.
 * @param model     An information model
 * @param ie        Pointer to an IE array to copy into the model
 */

void                fbInfoModelAddElementArray(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ie);

/**
 * Return a pointer to the canonical information element within an information
 * model given the information element name. The returned information element
 * is owned by the information model and must not be modified.
 *
 * @param model     An information model
 * @param name      The name of the information element to look up
 * @return          The named information element within the model,
 *                  or NULL if no such element exists.
 */

const fbInfoElement_t     *fbInfoModelGetElementByName(
    fbInfoModel_t       *model,
    const char          *name);

/**
 * Return a pointer to the canonical information element within an information
 * model given the information element ID and enterprise ID.  The returned
 * information element is owned by the information model and must not be
 * modified.
 *
 * @param model     An information model
 * @param id        An information element id
 * @param ent       An enterprise id
 * @return          The named information element within the model, or NULL
 *                  if no such element exists.
 */

const fbInfoElement_t    *fbInfoModelGetElementByID(
    fbInfoModel_t       *model,
    uint16_t            id,
    uint32_t            ent);

/**
 * Return the number of information elements in the information model.
 *
 * @param model     An information model
 * @return          The number of information elements in the
 *                  information model
 */
guint fbInfoModelCountElements(
    const fbInfoModel_t *model);

/**
 * Initialize an information model iterator for iteration.
 *
 * @param iter      A pointer to the iterator to initialize
 * @param model     An information model
 */

void fbInfoModelIterInit(
    fbInfoModelIter_t   *iter,
    const fbInfoModel_t *model);

/**
 * Return a pointer to the next information element in the information
 * model.  Returns NULL once all information elements have been
 * returned.
 *
 * @param iter      An information model iterator
 * @return          The next information element within the model, or NULL
 *                  if there are no more elements.
 */

const fbInfoElement_t *fbInfoModelIterNext(
    fbInfoModelIter_t *iter);

/**
 * Allocate the Options Template that will be used to define Information
 * Element Type Records.  This function does not add the template to the
 * session or fbuf.  This function allocates the template, appends the
 * appropriate elements to the template, and sets the scope on the template.
 * See RFC 5610 for more info.
 *
 * @param model       A pointer to an existing info model
 * @param err         GError
 * @return            The pointer to the newly allocated template.
 *
 */

fbTemplate_t *fbInfoElementAllocTypeTemplate(
    fbInfoModel_t          *model,
    GError                 **err);

/**
 * Export an options record to the given fbuf with information element type
 * information about the given information element.  See RFC 5610 for details.
 * Use fbInfoElementAllocTypeTemplate() and add the returned template
 * to the session,  before calling this function.
 *
 * @param fbuf       An existing fbuf
 * @param model_ie   A pointer to the information element to export type info.
 * @param itid       The internal template id of the Options Template.
 * @param etid       The external template id of the Options Template.
 * @param err        GError
 * @return           TRUE if successful, FALSE if an error occurred.
 */

gboolean fbInfoElementWriteOptionsRecord(
    fBuf_t                  *fbuf,
    const fbInfoElement_t   *model_ie,
    uint16_t                itid,
    uint16_t                etid,
    GError                  **err);

/**
 * Add an element that we received via an Options Record to the given info
 * model.  Returns True if the element was successfully added.  False, if
 * it couldn't be added.  This function will not add elements that have a
 * private enterprise number of 0, for security reasons.
 *
 * @param model        An information model
 * @param rec          A pointer to the received fbInfoElementOptRec.
 * @return             TRUE if item was successfully added to info model.
 *
 */
gboolean fbInfoElementAddOptRecElement(
    fbInfoModel_t           *model,
    fbInfoElementOptRec_t   *rec);

/**
 * Checks to see if the template contains all of the elements the RFC 5610
 * info element type record should contain.  If so, and the fbuf is in
 * "automatic insert" mode, we'll insert the elements in our own info model.
 *
 * @param tmpl         A pointer to the template
 * @return             TRUE if template contains all the info elements
 *
 */
gboolean fbInfoModelTypeInfoRecord(
    fbTemplate_t            *tmpl);

/**
 * Allocate a new empty template. The template will be associated with the
 * given Information Model, and only able to use Information Elements defined
 * within that Information Model. Templates may be associated with multiple
 * sessions, with different template IDs each time, and as such are
 * reference counted and owned by sessions. A template must be associated
 * with at least one session or it will be leaked; each template is freed
 * after its last associated session is freed.
 *
 * Use fbTemplateAppend(), fbTemplateAppendSpec(), and
 * fbTemplateAppendSpecArray() to "fill in" a template after creating it,
 * and before associating it with any session.
 *
 * @param model     An information model
 * @return a new, empty Template.
 */

fbTemplate_t        *fbTemplateAlloc(
    fbInfoModel_t       *model);

/**
 * Append an information element to a template. The information element is taken
 * to be an example; the canonical element from the template's associated model
 * is looked up by enterprise and element number and copied. If no information
 * element exists in the model with the given enterprise and element number,
 * it is copied to the model with the name "_alienInformationElement".
 *
 * This call is intended primarily for use by fBuf_t's template reader, but can
 * also be useful to simulate receipt of templates over the wire.
 *
 * @param tmpl      Template to append information element to
 * @param ex_ie     Example IE to add to the template
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbTemplateAppend(
    fbTemplate_t        *tmpl,
    fbInfoElement_t     *ex_ie,
    GError              **err);

/**
 * Append an information element described by specifier to a template.
 * The information element named by the specifier is copied from the template's
 * associated model, and the length and flags are overriden from the specifier.
 *
 * @param tmpl      Template to append information element to.
 * @param spec      Specifier describing information element to append.
 * @param flags     Application flags. Must match one bit of spec flags word
 *                  or the append will be silently skipped. Used for
 *                  building multiple templates with different information
 *                  element features from a single specifier.
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbTemplateAppendSpec(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec,
    uint32_t            flags,
    GError              **err);

/**
 * Append information elements described by a specifier array to a template.
 * The information elements named by the specifiers are copied from the
 * template's associated model, and the length and flags are overriden from
 * each specifier. The array is read until the FB_IESPEC_NULL convenience macro
 * is encountered.
 *
 * @param tmpl      Template to append information element to.
 * @param spec      Pointer to first specifier in specifier array to append.
 * @param flags     Application flags. Must contain all bits of spec flags word
 *                  or the append will be silently skipped. Used for
 *                  building multiple templates with different information
 *                  element features from a single specifier.
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbTemplateAppendSpecArray(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec,
    uint32_t            flags,
    GError              **err);

/**
 * Determine number of information elements in a template.
 *
 * @param tmpl      A template
 * @return information element count
 */

uint32_t            fbTemplateCountElements(
    fbTemplate_t        *tmpl);

/**
 * Set the number of information elements in a template that are scope. This
 * causes the template to become an options template, and must be called after
 * all the scope information elements have been appended to the template.
 *
 * @param tmpl          Template to set scope on
 * @param scope_count   Number of scope information elements
 */

void                fbTemplateSetOptionsScope(
    fbTemplate_t        *tmpl,
    uint16_t            scope_count);

/**
 * Determine number of scope information elements in a template. The template
 * is an options template if nonzero.
 *
 * @param tmpl      A template
 * @return scope information element count
 */
uint32_t            fbTemplateGetOptionsScope(
    fbTemplate_t        *tmpl);

/**
 * Determine if a template contains a given information element. Matches against
 * information element private enterprise number, number, and multiple-IE index
 * (i.e., to determine if a given template contains six instances of a given
 * information element, set ex_ie->midx = 5 before this call).
 *
 * @param tmpl      Template to search
 * @param ex_ie     Pointer to an information element to search for
 * @return          TRUE if the template contains the given IE
 */

gboolean           fbTemplateContainsElement(
    fbTemplate_t            *tmpl,
    const fbInfoElement_t   *ex_ie);

/**
 * Determine if a template contains at least one instance of a given
 * information element, specified by name in the template's information model.
 *
 * @param tmpl      Template to search
 * @param spec      Specifier of information element to search for
 * @return          TRUE if the template contains the given IE
 */

gboolean           fbTemplateContainsElementByName(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec);

/**
 * Determine if a template contains at least one instance of each
 * information element in a given information element specifier array.
 *
 * @param tmpl      Template to search
 * @param spec      Pointer to specifier array to search for
 * @return          TRUE if the template contains all the given IEs
 */

gboolean           fbTemplateContainsAllElementsByName(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec);

/**
 * Determine if a template contains at least one instance of each
 * information element in a given information element specifier array that
 * match the given flags argument.
 *
 * @param tmpl      Template to search
 * @param spec      Pointer to specifier array to search for
 * @param flags     Flags to match info elements
 * @return          TRUE if the template contains all the given IEs
 */
gboolean            fbTemplateContainsAllFlaggedElementsByName(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec,
    uint32_t             flags);

/**
 * Return the information element in the template referenced by the index
 *
 * @param tmpl      Pointer to the template
 * @param IEindex   index of the information element to return
 * @return          A pointer to the information element at index IEindex,
 *                  NULL if IEindex is greater than number of elements
 */
fbInfoElement_t*    fbTemplateGetIndexedIE(
    fbTemplate_t       *tmpl,
    uint32_t            IEindex);

/**
 * Free a template if it is not currently in use by any Session. Use this
 * to clean up while creating templates in case of error.
 *
 * @param tmpl template to free
 */

void                fbTemplateFreeUnused(
    fbTemplate_t        *tmpl);

/**
 * Get the ctx pointer associated with a Template.  The ctx pointer
 * is typically set during the template callback when the new template
 * is received.
 * @param tmpl Template Pointer
 * @return ctx The application Context Pointer
 */
void               *fbTemplateGetContext(
    fbTemplate_t         *tmpl);

/**
 * Allocate a transport session state container. The new session is associated
 * with the given information model, contains no templates, and is usable
 * either for collection or export.
 *
 * Each fbExporter_t, fbListener_t, and fbCollector_t must have its own
 * session; session state cannot be shared.
 *
 * The fbSession_t returned by this function is not freed by calling
 * fBufFree() or fbListenerFree().  It should be freed by the application
 * by calling fbSessionFree().
 *
 * @param model     An information model.  Not freed by sessionFree.  Must
                    be freed by user after calling SessionFree
 * @return a new, empty session state container.
 */

fbSession_t         *fbSessionAlloc(
    fbInfoModel_t       *model);

/**
 * Configure a session to export type information for enterprise-specific
 * information elements as options records according to RFC 5610
 *
 * @param session pointer
 * @param enabled TRUE to enable type metadata export, FALSE to disable
 * @param err error mesasge
 * @return NONE
 */
gboolean fbSessionEnableTypeMetadata(
    fbSession_t                *session,
    gboolean                    enabled,
    GError                    **err);

/**
 * Configure a session to export template metadata as options records
 *
 * @param session pointer
 * @param enabled TRUE to enable template metadata export, FALSE to disable
 * @param err error mesasge
 * @return NONE
 */
gboolean fbSessionEnableTemplateMetadata(
    fbSession_t                *session,
    gboolean                    enabled,
    GError                    **err);

/**
 * Add a template to the session with the provided metadata.
 * This function appends the metadata to the buffer as well
 * as the template.
 *
 * @param session   A session state container
 * @param internal  TRUE if the template is internal, FALSE if external.
 * @param tid       Template ID to assign, replacing any current template
 *                  in case of collision; or FB_TID_AUTO to assign a new tId.
 * @param tmpl      Template to add
 * @param name      Template name
 * @param description Template description
 * @param err       error message
 * @return template id of newly added template
 */
uint16_t fbSessionAddTemplateWithMetadata(
    fbSession_t         *session,
    gboolean             internal,
    uint16_t             tid,
    fbTemplate_t        *tmpl,
    const char          *name,
    const char          *description,
    GError              **err);

/**
 * Add template metadata for a given template
 *
 * @param session pointer
 * @param tid template id
 * @param name template name
 * @param description template description
 * @param err error mesasge
 * @return NONE
 */
gboolean fbSessionSetTemplateMetadata(
    fbSession_t         *session,
    uint16_t             tid,
    const char          *name,
    const char          *description,
    GError             **err);

/**
 * fbSessionGetInfoModel
 *
 * @param session
 * @return a pointer to the info model for the session
 *
 *
 */
fbInfoModel_t       *fbSessionGetInfoModel(
    fbSession_t         *session);

/**
 * This function sets the callback that allows the application to set its
 * own context variable with a new incoming template.  Assigning a callback
 * is not required and is only useful if the application either needs to
 * store some information about the template or to prevent certain nested
 * templates from being transcoded.  If the application's template contains
 * a subTemplateMultiList or subTemplateList and the callback is not used,
 * all incoming templates contained in these lists will be fully transcoded
 * and the application is responsible for freeing any nested lists contained
 * within those objects.
 *
 * This function should be called after fbSessionAlloc().  Fixbuf often
 * clones sessions upon receiving a connection.  In the TCP case, the
 * application has access to the session right after fbListenerWait() returns
 * by calling fBufGetSession().  In the UDP case, the application does
 * not have access to the fbSession until after a call to fBufNext() for
 * fBufNextCollectionTemplate() and by this time the application may have
 * already received some templates.  Therefore, it is important to call this
 * function before fBufNext().  Any callbacks added to the session will be
 * carried over to cloned sessions.
 *
 * @param session pointer session to assign the callback to
 * @param callback the function that should be called when a new template
 *                 is received
 * @param app_ctx parameter that gets passed onto the callback function
 * @return NONE
 */
void fbSessionAddNewTemplateCallback(
    fbSession_t               *session,
    fbNewTemplateCallback_fn   callback,
    void                      *app_ctx);

/**
 * Adds an external-internal template pair to the session.  This tells the
 * transcoder which internal template to use for a given external template
 * used in a sub template list, or a sub template multi list.
 *
 * If the value of int_tid is 0, it tells fixbuf NOT to decode any list where
 * the external template is ent_tid. This allows a collector to specify which
 * templates that are included in lists it can handle.
 *
 * If ent_tid and int_tid are set equal to each other, it tells the transcoder
 * to decode all of the fields from the external template, by using the
 * external template also as the internal template (lining up all the fields)
 * The exception to this is if there is an existing internal template with
 * the same template ID as the external template. In this case, the internal
 * template with the appropriate ID will be used. To avoid this potentially
 * unintended consequence, be careful and deliberate with template IDs.
 *
 * @param session pointer to the session to add the pair to
 * @param ent_tid the external template ID
 * @param int_tid the internal template ID used to decode the data when the
                  associated external template is used
 * @return NONE
 */
void fbSessionAddTemplatePair(
    fbSession_t    *session,
    uint16_t        ent_tid,
    uint16_t        int_tid);

/**
 * remove a template pair from the list
 * this is called by fixbuf when a template is revoked from the session by
 * the node on the other end of the connection
 *
 * @param session pointer to the session to remove the pair from
 * @param ext_tid the external template ID for the pair
 * @return NONE
 */
void fbSessionRemoveTemplatePair(
    fbSession_t    *session,
    uint16_t        ext_tid);

/**
 * Function to find a pair, uniquely identified by the external ID, and return
 * the associated internal template ID
 *
 * @param session pointer to the session used to find the pair
 * @param ext_tid external template ID used to find a pair
 * @return the internal template ID from the pair.  0 if the pair isn't found
 */
uint16_t    fbSessionLookupTemplatePair(
    fbSession_t    *session,
    uint16_t        ext_tid);

/**
 * Free a transport session state container. This is done automatically when
 * freeing the listener or buffer with which the session is
 * associated. Use this call if a session needs to be destroyed before it
 * is associated.
 *
 * @param session   session state container to free.
 */

void                fbSessionFree(
    fbSession_t         *session);

/**
 * Reset the external state (sequence numbers and templates) in a session
 * state container.
 *
 * FIXME: Verify that this call actually makes sense; either that a session
 * is reassociatable with a new collector, or that you need to do this when
 * reassociating a collector with a connection. Once this is done, rewrite
 * this documentation
 *
 * @param session   session state container to reset
 */

void                fbSessionResetExternal(
    fbSession_t         *session);

/**
 * Set the current observation domain on a session. The domain
 * is used to scope sequence numbers and external templates. This is called
 * automatically during collection, but must be called to set the domain
 * for export before adding external templates or writing records.
 *
 * Notice that a domain change does not automatically cause any associated
 * export buffers to emit messages; a domain change takes effect with the
 * next message started. Therefore, call fBufEmit() before setting the domain
 * on the buffer's associated session.
 *
 * @param session   a session state container
 * @param domain    ID of the observation domain to set
 */

void                fbSessionSetDomain(
    fbSession_t         *session,
    uint32_t            domain);

/**
 * Retrieve the current domain on a session.
 *
 * @param session a session state container
 * @return the ID of the session's current observation domain
 */

uint32_t            fbSessionGetDomain(
    fbSession_t         *session);

/**
 * Retrieve collector that was created with the session
 *
 * @param session a session state container
 * @return fbCollector_t the collector that was created with the session
 *
 */
fbCollector_t *fbSessionGetCollector(
    fbSession_t        *session);

#if HAVE_SPREAD
/**
 * fbSessionAddTemplatesMulticast
 *
 * Set and send templates for 1 or more groups.
 * This loops through the groups and adds the template to each
 * group's session and adds the template to the buffer.
 * This function is really meant for external templates, since
 * they are exported, although can be used for internal templates.
 * Since internal templates are not managed per group, they can simply
 * be added with fbSessionAddTemplate().
 * It is necessary to use this function if you plan on managing
 * templates per group.  Using fbSessionAddTemplate() will not allow
 * you to send a tmpl(s) to more than 1 group.
 *
 * @param session    a session state container
 * @param group      group names
 * @param internal   TRUE for internal tmpl, FALSE for external
 * @param tid        template id
 * @param tmpl       pointer to template with template id tid
 * @param err        error mesasge
 * @return           template ID
 */
uint16_t        fbSessionAddTemplatesMulticast(
    fbSession_t      *session,
    char             **groups,
    gboolean         internal,
    uint16_t         tid,
    fbTemplate_t     *tmpl,
    GError           **err);

/**
 * fbSessionAddTemplatesMulticastWithMetadata
 *
 * Set and send templates for 1 or more groups.
 * This loops through the groups and adds the template to each
 * group's session and adds the template to the buffer.
 * This function is really meant for external templates, since
 * they are exported, although can be used for internal templates.
 * Since internal templates are not managed per group, they can simply
 * be added with fbSessionAddTemplate().
 * It is necessary to use this function if you plan on managing
 * templates per group.  Using fbSessionAddTemplate() will not allow
 * you to send a tmpl(s) to more than 1 group.
 *
 * @param session    a session state container
 * @param group      group names
 * @param internal   TRUE for internal tmpl, FALSE for external
 * @param tid        template id
 * @param tmpl       pointer to template with template id tid
 * @param name       name of template (required)
 * @param description description of template (optional)
 * @param err        error mesasge
 * @return           template ID
 */
uint16_t        fbSessionAddTemplatesMulticastWithMetadata(
    fbSession_t      *session,
    char             **groups,
    gboolean         internal,
    uint16_t         tid,
    fbTemplate_t     *tmpl,
    char             *name,
    char             *description,
    GError           **err);

/**
 * fbSessionSpreadEnableTemplateMetadata
 *
 * Enable template metadata export for Spread Sessions.
 * This will configure a session to send option records
 * that describe templates.
 *
 * @param session pointer
 * @param groups spread groups to enable
 * @param enabled TRUE to enable template metadata export, FALSE to disable
 * @param err error message
 * @return TRUE/FALSE (False only if templates could not be added to the session).
 *
 */

gboolean fbSessionSpreadEnableTemplateMetadata(
    fbSession_t                *session,
    char                       **groups,
    gboolean                   enabled,
    GError                     **err);

/**
 * fbSessionSpreadEnableTypeMetadata
 *
 * Enable information element metadata export for Spread Sessions.
 * This will configure a session to send option records for
 * each private enterprise element added to the information model.
 *
 * @param session pointer
 * @param groups spread groups to enable
 * @param enable TRUE to eanble metadata export, FALSE to disable
 * @param err error message
 * @return TRUE/FALSE (False only if IE type template could not be added to the session).
 *
 */
gboolean fbSessionSpreadEnableTypeMetadata(
    fbSession_t                *session,
    char                       **groups,
    gboolean                   enabled,
    GError                     **err);

#endif

/**
 * Export a single external template in the current domain of a given session.
 * Writes the template to the associated export buffer. May cause a message to
 * be emitted if the associated export buffer is in automatic mode, or return
 * with FB_ERROR_EOM if the associated export buffer is not in automatic mode.
 *
 * @param session   a session state container associated with an export buffer
 * @param tid       template ID within current domain to export
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbSessionExportTemplate(
    fbSession_t         *session,
    uint16_t            tid,
    GError              **err);

/**
 * Export all external templates in the current domain of a given session.
 * Writes templates to the associated export buffer. May cause a message to
 * be emitted if the associated export buffer is in automatic mode, or return
 * with FB_ERROR_EOM if the associated export buffer is not in automatic mode.
 *
 * @param session   a session state container associated with an export buffer
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbSessionExportTemplates(
    fbSession_t         *session,
    GError              **err);

/**
 * Add a template to a session. If external, adds the template to the current
 * domain, and exports the template if the session is associated with an export
 * buffer. Assigns the template ID given in tid, or assigns a template ID if
 * tid is FB_TID_AUTO.
 * If using FB_TID_AUTO, external templates start at 256 and count up, internal
 * templates start at 65535 and count down. This is to avoid inadvertant
 * unrelated external and internal templates having the same ID
 *
 * @param session   A session state container
 * @param internal  TRUE if the template is internal, FALSE if external.
 * @param tid       Template ID to assign, replacing any current template
 *                  in case of collision; or FB_TID_AUTO to assign a new tId.
 * @param tmpl      Template to add
 * @param err       An error description, set on failure
 * @return the template ID of the added template, or 0 on failure.
 */

uint16_t            fbSessionAddTemplate(
    fbSession_t         *session,
    gboolean            internal,
    uint16_t            tid,
    fbTemplate_t        *tmpl,
    GError              **err);

/**
 * Remove a template from a session.  If external, removes the template from
 * the current domain, and exports a template revocation set if the session is
 * associated with an export buffer.
 *
 * @param session   A session state container
 * @param internal  TRUE if the template is internal, FALSE if external.
 * @param tid       Template ID to remove.
 * @param err       An error description, set on failure
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbSessionRemoveTemplate(
    fbSession_t         *session,
    gboolean            internal,
    uint16_t            tid,
    GError              **err);

/**
 * Retrieve a template from a session by ID. If external, retrieves the
 * template within the current domain.
 *
 * @param session   A session state container
 * @param internal  TRUE if the template is internal, FALSE if external.
 * @param tid       ID of the template to retrieve.
 * @param err       An error description, set on failure.
 * @return The template with the given ID, or NULL on failure.
 */

fbTemplate_t        *fbSessionGetTemplate(
    fbSession_t         *session,
    gboolean            internal,
    uint16_t            tid,
    GError              **err);

/**
 * Allocate an exporting process endpoint for a network connection.
 * The remote collecting process is specified by the given connection specifier.
 * The underlying socket connection will not be opened until the first message
 * is emitted from the buffer associated with the exporter.
 *
 * @param spec      remote endpoint connection specifier.  A copy is made
                    for the exporter, it is freed later.  User is responsible
                    for original spec pointer
 * @return a new exporting process endpoint
 */

fbExporter_t        *fbExporterAllocNet(
    fbConnSpec_t        *spec);

#if HAVE_SPREAD
/**
 * fbCollectorGetSpreadReturnGroups
 *
 * This function is useful if need to know what groups were set on the message.
 * Also useful if you are subscribed to more than 1 group, or want to know
 * what other groups the message published to.
 *
 * @param collector
 * @param array of groups
 * @return number in the array of groups
 */
int fbCollectorGetSpreadReturnGroups(
    fbCollector_t *collector,
    char *groups[]);

/**
 *  Allocate an exporting process endpoint for a Spread connection.
 *  This connection will use the Spread toolkit for exporting and collecting
 *  IPFIX records.  Note that the connection to the Spread daemon will not
 *  take place until the first message is emitted from the buffer.
 *  This is not synonymous with appending the first record to the buffer.
 *  NOTE: unlike the other connection specifiers, the session MUST be set
 *  in the fbSpreadSpec_t structure BEFORE it is passed to this method.
 *
 * @param params      Spread connection specifier
 * @return a new exporting process endpoint
 */

fbExporter_t        *fbExporterAllocSpread(
    fbSpreadParams_t      *params );

#endif /* HAVE_SPREAD */

/**
 * Allocate an exporting process endpoint for a named file. The underlying
 * file will not be opened until the first message is emitted from the
 * buffer associated with the exporter.
 *
 * @param path      pathname of the IPFIX File to write, or "-" to
 *                  open standard output.  Path is duplicated and handled.
 *                  Original pointer is up to the user.
 * @return a new exporting process endpoint
 */

fbExporter_t        *fbExporterAllocFile(
    const char          *path);

/**
 * Allocate an exporting process for a buffer. The underlying
 * buffer will be allocated to the given size.
 *
 * @param buf       buffer that will be allocated and used to copy IPFIX to.
 * @param bufsize   size of buffer that will be allocated.
 *
 * @return a new exporting process endpoint
 */
fbExporter_t        *fbExporterAllocBuffer(
    uint8_t                  *buf,
    uint16_t                  bufsize);


/**
 * Allocate an exporting process endpoint for an opened ANSI C file pointer.
 *
 * @param fp        open file pointer to write to.  File pointer is created
                    and freed outside of the Exporter functions.
 * @return a new exporting process endpoint
 */

fbExporter_t        *fbExporterAllocFP(
    FILE                *fp);

/**
 * Set the SCTP stream for the next message exported. To change the SCTP
 * stream used for export, first emit any message in the exporter's associated
 * buffer with fbufEmit(), then use this call to set the stream for the next
 * message. This call cancels automatic stream selection, use
 * fbExporterAutoStream() to re-enable it. This call is a no-op for non-SCTP
 * exporters.
 *
 * @param exporter      an exporting process endpoint.
 * @param sctp_stream   SCTP stream to use for next message.
 */

void                fbExporterSetStream(
    fbExporter_t        *exporter,
    int                 sctp_stream);

/**
 * Enable automatic SCTP stream selection for the next message exported.
 * Automatic stream selection is the default; use this call to re-enable it
 * on a given exporter after using fbExporterSetStream(). With automatic
 * stream selection, the minimal behavior specified in the original IPFIX
 * protocol (RFC xxxx) is used: all templates and options templates are
 * exported on stream 0, and all data is exported on stream 1. This call is a
 * no-op for non-SCTP exporters.
 *
 * @param exporter      an exporting process endpoint.
 */

void                fbExporterAutoStream(
    fbExporter_t        *exporter);

/**
 * Force the file or socket underlying an exporting process endpoint to close.
 * No effect on open file endpoints. The file or socket may be reopened on a
 * subsequent message emission from the associated buffer.
 *
 * @param exporter  an exporting process endpoint.
 */
void                fbExporterClose(
    fbExporter_t       *exporter);

/**
 * Get the (transcoded) message length that was copied to the
 * exporting buffer upon fBufEmit().
 *
 * @param exporter an exporting process endpoint.
 */
size_t fbExporterGetMsgLen(
    fbExporter_t   *exporter);

/**
 * Allocate a collecting process endpoint for a named file. The underlying
 * file will be opened immediately.
 *
 * @param ctx       application context; for application use, retrievable
 *                  by fbCollectorGetContext
 * @param path      path of file to read, or "-" to read standard input.
                    Used to get fp, user creates and frees.
 * @param err       An error description, set on failure.
 * @return a collecting process endpoint, or NULL on failure.
 */

fbCollector_t       *fbCollectorAllocFile(
    void                *ctx,
    const char          *path,
    GError              **err);

/**
 * Allocate a collecting process endpoint for an open file.
 *
 * @param ctx       application context; for application use, retrievable
 *                  by fbCollectorGetContext
 * @param fp      file pointer to file to read.  Created and freed by user.
                    Must be kept around for the life of the collector.
 * @return a collecting process endpoint.
 */

fbCollector_t       *fbCollectorAllocFP(
    void                *ctx,
    FILE                *fp);


#if HAVE_SPREAD
/**
*   Allocate a collecting process endpoint for the Spread transport.
*
*   @param ctx      application context
*   @param params   point to fbSpreadSpec_t containing Spread params
*   @param err      error description, set on failure
*
*   @return         a collecting endpoint, or null on failure
*/

fbCollector_t       *fbCollectorAllocSpread(
    void                *ctx,
    fbSpreadParams_t    *params,
    GError              **err );

#endif /* HAVE_SPREAD */

/**
 * Retrieve the application context associated with a collector. This context
 * is taken from the ctx argument of fbCollectorAllocFile() or
 * fbCollectorAllocFP(), or passed out via the ctx argument to the
 * appinit function argument to fbListenerAlloc().
 *
 * @param collector a collecting process endpoint.
 * @return the application context
 */

void                *fbCollectorGetContext(
    fbCollector_t       *collector);

/**
 * Close the file or socket underlying a collecting process endpoint.
 * No effect on open file endpoints. If the collector is attached to a
 * buffer managed by a listener, the buffer will be removed from the
 * listener (that is, it will not be returned by subsequent fbListenerWait()
 * calls).
 *
 * @param collector  a collecting process endpoint.
 */

void                fbCollectorClose(
    fbCollector_t       *collector);


/**
 * Set the collector to only receive from the given IP address over UDP.
 * The port will be ignored.  Use fbListenerGetCollector() to get the pointer
 * to the collector after calling fbListenerAlloc(). ONLY valid for UDP.
 * Set the address family in address.
 *
 * @param collector pointer to collector
 * @param address pointer to sockaddr struct with IP address and family.
 * @param address_length address length
 *
 */
void                fbCollectorSetAcceptOnly(
    fbCollector_t       *collector,
    struct sockaddr     *address,
    size_t              address_length);

/**
 * Allocate a listener. The listener will listen on a specified local endpoint,
 * and create a new collecting process endpoint and collection buffer for each
 * incoming connection. Each new buffer will be associated with a clone of
 * a given session state container.
 *
 * The application may associate context with each created collecting process
 * endpoint, or veto a connection attempt, via a function colled on each
 * connection attempt passed in via the appinit parameter. If this function
 * will create application context, provide a function via the
 * appfree parameter which will free it.
 *
 * The fbListener_t returned should be freed by the application by calling
 * fbListenerFree().
 *
 * @param spec      local endpoint connection specifier.
                    A copy is made of this, which is freed by listener.
                    Original pointer freeing is up to the user.
 * @param session   session state container to clone for each collection buffer
 *                  created by the listener.  Not freed by listener.  Must
 *                  be kept alive while listener exists.
 * @param appinit   application connection initiation function. Called on each
 *                  collection attempt; vetoes connection attempts and creates
 *                  application context.
 * @param appfree   application context free function.
 * @param err       An error description, set on failure.
 * @return a new listener, or NULL on failure.
 */
fbListener_t        *fbListenerAlloc(
    fbConnSpec_t            *spec,
    fbSession_t             *session,
    fbListenerAppInit_fn    appinit,
    fbListenerAppFree_fn    appfree,
    GError                  **err);

/**
 * Free a listener. Stops listening on the local endpoint, and frees any
 * open buffers still managed by the listener.
 *
 * @param listener a listener
 */

void                fbListenerFree(
    fbListener_t            *listener);

/**
 * Wait on a listener. Accepts pending connections from exporting processes.
 * Returns the next collection buffer with available data to read; if the
 * collection buffer returned by the last call to fbListenerWait() is available,
 * it is preferred. Blocks forever (or until fbListenerInterrupt() is called)
 * if no messages or connections are available.
 *
 * To effectively use fbListenerWait(), the application should set up an
 * session state container with internal templates, call fbListenerWait()
 * to accept a first connection, then read records from the collector buffer
 * to end of message (FB_ERROR_EOM). At end of message, the application should
 * then call fbListenerWait() to accept pending connections or switch to
 * another collector buffer with available data. Note that each collector
 * buffer returned created by fbListenerWait() is set to automatic mode using
 * fBufSetAutomaticMode().  To modify this behavior, call
 * fBufSetAutomaticMode(fbuf, TRUE) on the fbuf returned from this function.
 *
 * @param listener  a listener
 * @param err       An error description, set on failure.
 * @return a collection buffer with available data, or NULL on failure.
 */

fBuf_t              *fbListenerWait(
    fbListener_t            *listener,
    GError                  **err);

/**
 * Waits for an incoming connection, just like fbListenerWait, except that
 * this function doesn't monitor active collectors.  This allows for a
 * multi threaded application to have one thread monitoring the listeners,
 * and one keeping track of collectors
 * @param listener  The listener to wait for connections on
 * @param err       An error description, set on failure.
 * @return a collection buffer for the new connection, NULL on failure.
 */

fBuf_t              *fbListenerWaitNoCollectors(
    fbListener_t            *listener,
    GError                  **err);

/**
 * Cause the current or next call to fbListenerWait to unblock and return.
 * Use this from a thread or a signal handler to interrupt a blocked listener.
 *
 * @param listener listener to interrupt.
 */

void                fbListenerInterrupt(
    fbListener_t            *listener);


/**
 *fbListenerGetCollector
 *
 * If a collector is associated with the listener class, this will return a
 * handle to the collector state structure.
 *
 * @param listener handle to the listener state
 * @param collector pointer to a collector state pointer, set on return
 *        if there is no error
 *
 * @param err a GError structure holding an error message on error
 *
 * @return FALSE on error, check err, TRUE on success
 *
 */
gboolean            fbListenerGetCollector(
    fbListener_t        *listener,
    fbCollector_t       **collector,
    GError              **err);




/**
 * fbCollectorClearTranslator
 *
 * this removes an input translator from a given
 * collector such that it will operate on IPFIX
 * protocol again
 *
 * @param collector the collector on which to remove
 *        the translator
 *
 * @param err when an error occurs, a Glib GError
 *        structure is set with an error description
 *
 * @return TRUE on success, FALSE on failure
 */
gboolean    fbCollectorClearTranslator(
    fbCollector_t   *collector,
    GError          **err);


/**
 *fbCollectorSetNetflowV9Translator
 *
 * this sets the collector input translator
 * to convert NetFlowV9 into IPFIX for the
 * given collector
 *
 * @param collector pointer to the collector state
 *        to perform Netflow V9 conversion on
 * @param err GError structure that holds the error
 *        message if an error occurs
 *
 *
 * @return TRUE on success, FALSE on error
 */
gboolean    fbCollectorSetNetflowV9Translator(
    fbCollector_t               *collector,
    GError                      **err);


/**
 *fbCollectorSetSFlowTranslator
 *
 * this sets the collector input translator
 * to convert SFlow into IPFIX for the
 * given collector
 *
 * @param collector pointer to the collector state
 *        to perform SFlow conversion on
 * @param err GError structure that holds the error
 *        message if an error occurs
 *
 *
 * @return TRUE on success, FALSE on error
 */
gboolean    fbCollectorSetSFlowTranslator(
    fbCollector_t               *collector,
    GError                      **err);

/**
 * fbCollectorGetNetflowMissed
 *
 * Returns the number of potential missed export packets of the Netflow
 * v9 session that is currently set on the collector (the session is set on
 * the collector when an export packet is received) if peer is NULL.  If peer
 * is set, this will look up the session for that peer/obdomain pair and return
 * the missed export packets associated with that peer and obdomain.  If
 * peer/obdomain pair doesn't exist, this function returns 0.
 * This can't return the number of missed flow records since Netflow v9
 * increases sequence numbers by the number of export packets it has sent,
 * NOT the number of flow records (like IPFIX and netflow v5 does).
 *
 * @param collector
 * @param peer [OPTIONAL] peer address of NetFlow v9 exporter
 * @param peerlen size of peer object
 * @param obdomain observation domain of NetFlow v9 exporter
 * @return number of missed packets since beginning of session
 *
 */
uint32_t fbCollectorGetNetflowMissed(
    fbCollector_t         *collector,
    struct sockaddr       *peer,
    size_t                 peerlen,
    uint32_t               obdomain);

/**
 * fbCollectorGetSFlowMissed
 *
 * Returns the number of potential missed export packets of the
 * SFlow session that is identified with the given ip/agentID. The agent
 * ID is a field that is in the sFlow header and is sent with every
 * packet.  Fixbuf keeps track of sequence numbers for sFlow sessions
 * per agent ID.
 *
 * @param collector
 * @param peer address of exporter to lookup
 * @param peerlen sizeof(peer)
 * @param obdomain observation domain of peer exporter
 * @return number of missed packets since beginning of session
 *
 */

uint32_t fbCollectorGetSFlowMissed(
    fbCollector_t         *collector,
    struct sockaddr       *peer,
    size_t                 peerlen,
    uint32_t               obdomain);

/**
 * Retrieves information about the node connected to this collector
 *
 * @param collector pointer to the collector to get peer information from
 * @return pointer to sockaddr structure containing IP information of peer
 */
struct sockaddr* fbCollectorGetPeer(
    fbCollector_t   *collector);

/**
 * Retrieves the observation domain of the node connected to the UDP collector.
 * The observation domain only gets set on the collector when collecting
 * via UDP.  If the collector is using another mode of transport, use
 * fbSessionGetDomain().
 *
 * @param collector
 *
 */
uint32_t fbCollectorGetObservationDomain(
    fbCollector_t  *collector);

/**
 * Attempt to maintain backwards compatibility with UDP.  As of version 1.2,
 * fixbuf calls the appinit functions when a new UDP connection occurs, as
 * opposed to calling it during fbListenerAlloc.  To maintain compatibility,
 * with old applications, fixbuf will still call appinit in fbListenerAlloc
 * with a null peer address.  If UDP multi session is turned on, it will ALSO
 * call appinit() when a new UDP connection occurs.  Likewise with appfree().
 * Call fbListenerGetCollector() to obtain collector.
 *
 * @param collector     pointer to collector associated with listener.
 * @param multi_session TRUE if multi-session enabled, FALSE by default.
 */
void fbCollectorSetUDPMultiSession(
    fbCollector_t *collector,
    gboolean       multi_session);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
