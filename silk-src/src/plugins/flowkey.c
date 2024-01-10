/*
** Copyright (C) 2016-2023 by Carnegie Mellon University.
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
 *  flowkey.c
 *
 *    A plug-in to define key fields for rwcut, rwsort, rwuniq, etc,
 *    to print, sort, and group by the flow-key hash that is computed
 *    by YAF.  The plug-in also adds a --flowkey partitioning switch
 *    to rwfilter.
 *
 *    Note that the flow key hash computed by this plug-in is probably
 *    not going to match the value computed by YAF:
 *
 *      When SiLK processes an IPFIX bi-flow, it splits the record
 *      into two uni-flow and reverses the source and destination
 *      fields in the reverse record.  The flow key hash for this
 *      reverse record is different than that of the forward record.
 *      (The getFlowKeyHash tool has a --reverse switch to duplicate
 *      this behavior.)
 *
 *      YAF computes the flow key hash using the vlan ID.  SiLK
 *      ignores the VLAN id unless the probe where the flow record was
 *      collected included "interface-values vlan" in the probe block
 *      of the sensor.conf file or the rwipfix2silk tool is run with
 *      the switch --interface-values=vlan.
 *
 *      For a uni-flow record or the forward half of a bi-flow record,
 *      SiLK stores the vlan ID in the SNMP input field, but that
 *      field is normally not stored in the files in the SiLK
 *      repository; when reading these files, the input field is set
 *      to 0.  For that field to be stored, rwflowpack must be run
 *      with the command line switch --pack-interfaces.  (The --snmp
 *      switch on the getFlowKeyHash tool may duplicate this
 *      behavior.)
 *
 *
 *    Suggestions:
 *
 *      Add a "reverseFlowkey" field that computes what the reverse
 *      flow key would be.
 *
 *      Add a --biflowkey switch for rwfilter that passes the flow
 *      record if either the forward or reverse flow key matches.
 *
 *      Add some way to suppress having the SNMP value as part of the
 *      flow key hash.  Ideally it would be called something like
 *      --flowkey-without-snmp, but that is (1)a bit unwieldy and (2)a
 *      conflict for the --flowkey field on rwfilter.
 *
 *
 *  Mark Thomas
 *  December 2016
 *
 */

#include <silk/silk.h>

RCSIDENT("$SiLK: flowkey.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/rwrec.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/skplugin.h>
#include <silk/utils.h>


/* DEFINES AND TYPEDEFS */

/*
 *    These variables specify the version of the SiLK plug-in API.
 *    They are used in the call to skpinSimpleCheckVersion() below.
 *    See the description of that function for their meaning.
 */
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0

/*
 *    Switch for rwfilter
 */
#define FLOWKEY_SWTICH  "flowkey"


/* LOCAL VARIABLES */

/* the list of flowkeys used by rwfilter are maintained in an IPset */
skipset_t *flowkeys = NULL;


/* LOCAL FUNCTION PROTOTYPES */

static skplugin_err_t parseFlowkeys(const char *, void *);
static skplugin_err_t filterByFlowkey(const rwRec *, void *, void **);
static uint64_t recToFlowkey(const rwRec *);
static skplugin_err_t freeSet(void *);



/* FUNCTION DEFINITIONS */

/*
 *    This is the registration function.
 *
 *    When you provide "--plugin=my-plugin.so" on the command line to
 *    an application, the application calls this function to determine
 *    the new switches and/or fields that "my-plugin" provides.
 *
 *    This function is called with three arguments: the first two
 *    describe the version of the plug-in API, and the third is a
 *    pointer that is currently unused.
 */
skplugin_err_t
SKPLUGIN_SETUP_FN(
    uint16_t            major_version,
    uint16_t            minor_version,
    void        UNUSED(*plug_in_data))
{
    skplugin_err_t err;

    /* Check the plug-in API version */
    err = skpinSimpleCheckVersion(major_version, minor_version,
                                  PLUGIN_API_VERSION_MAJOR,
                                  PLUGIN_API_VERSION_MINOR,
                                  skAppPrintErr);
    if (err != SKPLUGIN_OK) {
        return err;
    }

    /* register the --flowkey switch for rwfilter.  when the switch is
     * given, call skpinRegFilter() to register the filter
     * function. */
    err = (skpinRegOption2(
              FLOWKEY_SWTICH, REQUIRED_ARG,
              ("Flow-key matches one of these values, a comma-separated"
               " list of decimal or hexadecimal numbers"
               " (hexadecimal numbers must be preceded by '0x'"),
              NULL, &parseFlowkeys, NULL, 1, SKPLUGIN_FN_FILTER));
    if (SKPLUGIN_OK != err && SKPLUGIN_ERR_DID_NOT_REGISTER != err) {
        return err;
    }

    /* register the field for rwcut, rwsort, rwuniq */
    err = skpinRegIntField("flowkey", 0, UINT32_MAX, recToFlowkey, 0);
    if (SKPLUGIN_OK != err) {
        return err;
    }

    return SKPLUGIN_OK;
}


/*
 *  status = parseFlowkeys(opt_arg, cddata);
 *
 *    Parse the list of flowkeys passed to the --flowkey switch.
 *    'opt_arg' is the argument the user passed to the switch.
 *
 *    Returns SKPLUGIN_OK on success, or SKPLUGIN_ERR if there was a
 *    problem.
 */
static skplugin_err_t
parseFlowkeys(
    const char         *opt_arg,
    void               *cbdata)
{
    skplugin_err_t err = SKPLUGIN_ERR;
    skplugin_callbacks_t regdata;
    const char *sp;
    char *ep;
    unsigned long val;
    uint32_t u32;
    skipaddr_t ipaddr;
    ssize_t rv;

    (void)cbdata;               /* UNUSED */

    if (flowkeys) {
        skAppPrintErr("Invalid %s: Switch used multiple times",
                      FLOWKEY_SWTICH);
        goto END;
    }

    if (skIPSetCreate(&flowkeys, 0)) {
        skAppPrintOutOfMemory("IPset create");
        goto END;
    }

    sp = opt_arg;

    /* ignore leading whitespace */
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }

    for (;;) {
        while (',' == *sp) {
            ++sp;
        }
        if ('\0' == *sp) {
            break;
        }
        if (isspace((int)*sp)) {
            ++sp;
            while (*sp && isspace((int)*sp)) {
                ++sp;
            }
            if ('\0' != *sp) {
                skAppPrintErr("Invalid %s: List contains embedded whitespace",
                              FLOWKEY_SWTICH);
                goto END;
            }
            break;
        }

        /* number that begins with '-' is not unsigned */
        if ('-' == *sp) {
            skAppPrintErr("Invalid %s: Unexpected character '-'",
                          FLOWKEY_SWTICH);
            goto END;
        }

        /* parse the string */
        errno = 0;
        val = strtoul(sp, &ep, 0);
        if (sp == ep) {
            /* parse error */
            skAppPrintErr("Invalid %s: Unexpected character '%c'",
                          FLOWKEY_SWTICH, *sp);
            goto END;
        }

        if (val == ULONG_MAX && errno == ERANGE) {
            /* overflow */
            skAppPrintErr("Invalid %s: Value overflows the parser",
                          FLOWKEY_SWTICH);
            goto END;
        }
#if ULONG_MAX > UINT32_MAX
        if (val > UINT32_MAX) {
            skAppPrintErr("Invalid %s: Value is larger than %" PRIu32,
                          FLOWKEY_SWTICH, UINT32_MAX);
            goto END;
        }
#endif

        if ((',' != *ep) && ('\0' != *ep) && !isspace(*ep)) {
            skAppPrintErr("Invalid %s: Unexpected character '%c'",
                          FLOWKEY_SWTICH, *ep);
            goto END;
        }

        u32 = val;
        skipaddrSetV4(&ipaddr, &u32);
        rv = skIPSetInsertAddress(flowkeys, &ipaddr, 32);
        if (rv) {
            skAppPrintErr("Unable to add key %" PRIu32 ": %s",
                          u32, skIPSetStrerror(rv));
            goto END;
        }

        sp = ep;
    }

    memset(&regdata, 0, sizeof(regdata));
    regdata.filter = filterByFlowkey;
    regdata.cleanup = freeSet;
    err = skpinRegFilter(NULL, &regdata, NULL);

  END:
    if (SKPLUGIN_ERR == err) {
        skIPSetDestroy(&flowkeys);
    }
    return err;
}


uint64_t
recToFlowkey(
    const rwRec            *rwrec)
{
#if SK_ENABLE_IPV6
    if (rwRecIsIPv6(rwrec)) {
        union fk_ip_un {
            uint8_t     u8[16];
            uint32_t    u32[4];
        } sip, dip;

        rwRecMemGetSIPv6(rwrec, sip.u8);
        rwRecMemGetDIPv6(rwrec, dip.u8);

        return ((rwRecGetSPort(rwrec) << 16)
                ^ (rwRecGetDPort(rwrec))
                ^ (rwRecGetProto(rwrec) << 12)
                ^ (4 << 4)
                ^ ((rwRecGetInput(rwrec) & 0x0FFF) << 20)
                ^ (sip.u32[0])
                ^ (sip.u32[1])
                ^ (sip.u32[2])
                ^ (sip.u32[3])
                ^ (dip.u32[0])
                ^ (dip.u32[1])
                ^ (dip.u32[2])
                ^ (dip.u32[3]));
    }
#endif  /* SK_ENABLE_IPV6 */

    return ((rwRecGetSPort(rwrec) << 16)
            ^ (rwRecGetDPort(rwrec))
            ^ (rwRecGetProto(rwrec) << 12)
            ^ (4 << 4)
            ^ ((rwRecGetInput(rwrec) & 0x0FFF) << 20)
            ^ (rwRecGetSIPv4(rwrec))
            ^ (rwRecGetDIPv4(rwrec)));
}


/*
 *  status = filter(rwrec, cbdata, extra);
 *
 *    The function actually used to implement filtering for the
 *    plugin.  Returns SKPLUGIN_FILTER_PASS if the record passes the
 *    filter, SKPLUGIN_FILTER_FAIL if it fails the filter.
 */
static skplugin_err_t
filterByFlowkey(
    const rwRec        *rwrec,
    void               *cbdata,
    void              **extra)
{
    skipaddr_t ipaddr;
    uint32_t key;

    (void)cbdata;
    (void)extra;

    key = recToFlowkey(rwrec);
    skipaddrSetV4(&ipaddr, &key);

    return (skIPSetCheckAddress(flowkeys, &ipaddr)
            ? SKPLUGIN_FILTER_PASS
            : SKPLUGIN_FILTER_FAIL);
}


static skplugin_err_t
freeSet(
    void               *cbdata)
{
    (void)cbdata;

    skIPSetDestroy(&flowkeys);
    return SKPLUGIN_OK;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
