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
**  rwp2f_minbytes.c
**
**    An example of a simple plug-in that can be used with rwptoflow.
**
**  Mark Thomas
**  September 2006
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwp2f_minbytes.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/skplugin.h>
#include <silk/skstream.h>
#include "rwppacketheaders.h"

/* Plugin protocol version */
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0


/* LOCAL VARIABLE DEFINITIONS */

/*
 * rwptoflow hands the packet to the plugin as an "extra argument".
 * rwptoflow and its plugins must agree on the name of this argument.
 * The extra argument is specified in a NULL-terminated array of
 * argument names defined in rwppacketheaders.h.
 */
static const char *plugin_extra_args[] = RWP2F_EXTRA_ARGUMENTS;

/* the minimum number of bytes a packet must have to pass, as entered
 * by the user */
static uint32_t byte_limit = 0;


/* OPTIONS SETUP */

typedef enum {
    OPT_BYTE_LIMIT
} plugin_options_enum;

static struct option plugin_options[] = {
    {"byte-limit",      REQUIRED_ARG, 0, OPT_BYTE_LIMIT},
    {0,0,0,0}           /* sentinel */
};

static const char *plugin_help[] = {
    ("Reject the packet if its length (hdr+payload) is less\n"
     "\tthan this value"),
    (char*)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static skplugin_err_t optionsHandler(const char *opt_arg, void *cbdata);
static skplugin_err_t
p2f_minbytes(
    rwRec              *rwrec,
    void               *cbdata,
    void              **extra_args);


/* FUNCTION DEFINITIONS */

/* the registration function called by skplugin.c */
skplugin_err_t
SKPLUGIN_SETUP_FN(
    uint16_t            major_version,
    uint16_t            minor_version,
    void        UNUSED(*pi_data))
{
    int i;
    skplugin_err_t rv;

    /* Check API version */
    rv = skpinSimpleCheckVersion(major_version, minor_version,
                                 PLUGIN_API_VERSION_MAJOR,
                                 PLUGIN_API_VERSION_MINOR,
                                 skAppPrintErr);
    if (rv != SKPLUGIN_OK) {
        return rv;
    }

    assert((sizeof(plugin_options)/sizeof(struct option))
           == (sizeof(plugin_help)/sizeof(char*)));

    /* register the options to use for rwptoflow.  when the option is
     * given, we will call skpinRegTransform() to register the
     * transformation function. */
    for (i = 0; plugin_options[i].name; ++i) {
        rv = skpinRegOption2(plugin_options[i].name, plugin_options[i].has_arg,
                             plugin_help[i], NULL, &optionsHandler,
                             (void*)&plugin_options[i].val,
                             1, SKPLUGIN_APP_TRANSFORM);
        if (SKPLUGIN_OK != rv && SKPLUGIN_ERR_DID_NOT_REGISTER != rv) {
            return rv;
        }
    }

    return SKPLUGIN_OK;
}


/*
 *  status = optionsHandler(opt_arg, &index);
 *
 *    Handles options for the plugin.  'opt_arg' is the argument, or
 *    NULL if no argument was given.  'index' is the enum passed in
 *    when the option was registered.
 *
 *    Returns SKPLUGIN_OK on success, or SKPLUGIN_ERR if there was a
 *    problem.
 */
static skplugin_err_t
optionsHandler(
    const char         *opt_arg,
    void               *cbdata)
{
    plugin_options_enum opt_index = *((plugin_options_enum*)cbdata);
    skplugin_callbacks_t regdata;
    int rv;

    switch (opt_index) {
      case OPT_BYTE_LIMIT:
        rv = skStringParseUint32(&byte_limit, opt_arg, 0, 0);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          plugin_options[opt_index].name, opt_arg,
                          skStringParseStrerror(rv));
            return SKPLUGIN_ERR;
        }
        break;
    }

    /* register the transform function */
    memset(&regdata, 0, sizeof(regdata));
    regdata.transform = p2f_minbytes;
    regdata.extra = plugin_extra_args;
    return skpinRegTransformer(NULL, &regdata, NULL);
}


skplugin_err_t
p2f_minbytes(
    rwRec       UNUSED(*rwrec),
    void        UNUSED(*cbdata),
    void              **extra_args)
{
    sk_pktsrc_t *pktsrc = (sk_pktsrc_t*)extra_args[0];
    ip_header_t *iph;

    iph = (ip_header_t*)(pktsrc->pcap_data + sizeof(eth_header_t));
    if (ntohs(iph->tlen) < byte_limit) {
        return SKPLUGIN_FILTER_FAIL;
    }

    return SKPLUGIN_FILTER_PASS;
}




/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
