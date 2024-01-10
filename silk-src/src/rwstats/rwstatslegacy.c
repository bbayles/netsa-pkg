/*
** Copyright (C) 2001-2023 by Carnegie Mellon University.
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
**  rwstatslegacy.c
**
**  Functions to support deprecated features of rwstats.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: rwstatslegacy.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwstats.h"


/* OPTIONS SETUP */

typedef enum legacyOptions_en {
    LEGOPT_SIP, LEGOPT_DIP, LEGOPT_SPORT, LEGOPT_DPORT, LEGOPT_PROTOCOL,
    LEGOPT_ICMP,

    LEGOPT_FLOWS, LEGOPT_PACKETS, LEGOPT_BYTES
} legacyOptionsEnum;

static struct option legacyOptions[] = {
    {"sip",                    OPTIONAL_ARG, 0, LEGOPT_SIP},
    {"dip",                    OPTIONAL_ARG, 0, LEGOPT_DIP},
    {"sport",                  NO_ARG,       0, LEGOPT_SPORT},
    {"dport",                  NO_ARG,       0, LEGOPT_DPORT},
    {"protocol",               NO_ARG,       0, LEGOPT_PROTOCOL},
    {"icmp",                   NO_ARG,       0, LEGOPT_ICMP},

    {"flows",                  NO_ARG,       0, LEGOPT_FLOWS},
    {"packets",                NO_ARG,       0, LEGOPT_PACKETS},
    {"bytes",                  NO_ARG,       0, LEGOPT_BYTES},

    {0,0,0,0}                  /* sentinel entry */
};

static const char *legacyHelp[] = {
    ("Use: --fields=sip\n"
     "\tUse the source address as (part of) the key"),
    ("Use: --fields=dip\n"
     "\tUse the destination address as (part of) the key"),
    ("Use: --fields=sport\n"
     "\tUse the source port as (part of) the key"),
    ("Use: --fields=dport\n"
     "\tUse the destination port as (part of) the key"),
    ("Use: --fields=proto\n"
     "\tUse the protocol as the key"),
    ("Use: --fields=icmp\n"
     "\tUse the ICMP type and code as the key"),

    ("Use: --values=flows\n"
     "\tUse the flow count as the value"),
    ("Use: --values=packets\n"
     "\tUse the packet count as the value"),
    ("Use: --values=bytes\n"
     "\tUse the byte count as the value"),

    (char *)NULL
};


/* LOCAL FUNCTION PROTOTYPES */

static int
legacyOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg);


/* FUNCTION DEFINITIONS */

/*
 *  legacyOptionsSetup(void);
 *
 *    Register the legacy options.
 */
int
legacyOptionsSetup(
    clientData          cData)
{
    assert((sizeof(legacyHelp)/sizeof(char *)) ==
           (sizeof(legacyOptions)/sizeof(struct option)));

    /* register the options */
    if (skOptionsRegister(legacyOptions, &legacyOptionsHandler, cData))
    {
        skAppPrintErr("Unable to register legacy options");
        return 1;
    }

    return 0;
}


/*
 *  legacyOptionsUsage(fh);
 *
 *    Print the usage information for the legacy options to the named
 *    file handle.
 */
void
legacyOptionsUsage(
    FILE               *fh)
{
    unsigned int i;

    fprintf(fh, "\nLEGACY SWITCHES:\n");
    for (i = 0; legacyOptions[i].name; ++i) {
        fprintf(fh, "--%s %s. %s\n", legacyOptions[i].name,
                SK_OPTION_HAS_ARG(legacyOptions[i]), legacyHelp[i]);
    }
}


/*
 *  status = legacyOptionsHandler(cData, opt_index, opt_arg);
 *
 *    Process the legacy versions of the switches.
 */
static int
legacyOptionsHandler(
    clientData          cData,
    int                 opt_index,
    char               *opt_arg)
{
#define KEY_COMBO_ERR(a, b)                                             \

    static int old_id = -1;
    rwstats_legacy_t *leg = (rwstats_legacy_t*)cData;
    const char *val_type = NULL;
    uint32_t val;
    int rv;

    switch ((legacyOptionsEnum)opt_index) {
      case LEGOPT_SIP:
        if (opt_arg) {
            rv = skStringParseUint32(&val, opt_arg, 1, 31);
            if (rv) {
                goto PARSE_ERROR;
            }
            cidr_sip = UINT32_MAX << (32 - val);
        }
        break;

      case LEGOPT_DIP:
        if (opt_arg) {
            rv = skStringParseUint32(&val, opt_arg, 1, 31);
            if (rv) {
                goto PARSE_ERROR;
            }
            cidr_dip = UINT32_MAX << (32 - val);
        }
        break;

      case LEGOPT_SPORT:
      case LEGOPT_DPORT:
      case LEGOPT_PROTOCOL:
      case LEGOPT_ICMP:
        break;

      case LEGOPT_FLOWS:
        val_type = "Records";
        break;

      case LEGOPT_PACKETS:
      case LEGOPT_BYTES:
        val_type = legacyOptions[opt_index].name;
        break;
    }

    if (opt_index <= LEGOPT_ICMP) {
        /* if old_id is -1, then leg->fields must be NULL */
        assert(old_id >= 0 || NULL == leg->fields);
        if (NULL == leg->fields) {
            old_id = opt_index;
            leg->fields = legacyOptions[opt_index].name;
        } else if (((1 << LEGOPT_SIP) | (1 << LEGOPT_DIP))
                   == ((1 << old_id) | (1 << opt_index)))
        {
            leg->fields = "sip,dip";
        } else if (((1 << LEGOPT_SPORT) | (1 << LEGOPT_DPORT))
                   == ((1 << old_id) | (1 << opt_index)))
        {
            leg->fields = "sport,dport";
        } else {
            skAppPrintErr(("Key combination --%s and --%s is not supported.\n"
                           "\tUse the --fields switch for this combination"),
                          legacyOptions[opt_index].name,
                          legacyOptions[old_id].name);
            return 1;
        }
    } else {
        assert(val_type != NULL);
        if (leg->values) {
            skAppPrintErr(("May only specify one of --%s, --%s or --%s.\n"
                           "Use the --values switch for multiple values"),
                          legacyOptions[LEGOPT_FLOWS].name,
                          legacyOptions[LEGOPT_PACKETS].name,
                          legacyOptions[LEGOPT_BYTES].name);
            return 1;
        }
        leg->values = val_type;
    }

    return 0;                   /* OK */

  PARSE_ERROR:
    skAppPrintErr("Invalid %s '%s': %s",
                  legacyOptions[opt_index].name, opt_arg,
                  skStringParseStrerror(rv));
    return 1;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
