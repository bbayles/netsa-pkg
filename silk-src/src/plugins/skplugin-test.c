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
**  Tests for the simplified skplugin registration functions.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skplugin-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skplugin.h>
#include <silk/utils.h>
#include <silk/rwrec.h>


/* DEFINES AND TYPEDEFS */

/*
 *    These variables specify the version of the SiLK plug-in API.
 *    They are used in the call to skpinSimpleCheckVersion() below.
 *    See the description of that function for their meaning.
 */
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0

/* LOCAL VARIABLES */

static const char *test_labels[] =
    {
        "Low",
        "Medium",
        "High",
        NULL
    };

/* LOCAL FUNCTION PROTOTYPES */

static uint64_t
test_bytes(
    const rwRec        *rec);
static uint32_t
test_sipv4(
    const rwRec        *rec);
static void
test_sip(
    skipaddr_t         *dest,
    const rwRec        *rec);
static void
test_text(
    char               *dest,
    size_t              width,
    uint64_t            val);
static uint64_t
test_list(
    const rwRec        *rec);
static uint64_t
test_weird(
    uint64_t            current,
    uint64_t            operand);

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
    skplugin_err_t rv;

    /* Check the plug-in API version */
    rv = skpinSimpleCheckVersion(major_version, minor_version,
                                 PLUGIN_API_VERSION_MAJOR,
                                 PLUGIN_API_VERSION_MINOR,
                                 skAppPrintErr);
    if (rv != SKPLUGIN_OK) {
        return rv;
    }

    rv = skpinRegIntField("copy-bytes", 0, UINT32_MAX, test_bytes, 0);
    if (SKPLUGIN_OK != rv) {
        return rv;
    }
    rv = skpinRegIPv4Field("copy-sipv4", test_sipv4, 0);
    if (SKPLUGIN_OK != rv) {
        return rv;
    }
    rv = skpinRegIPAddressField("copy-sip", test_sip, 0);
    if (SKPLUGIN_OK != rv) {
        return rv;
    }
    rv = skpinRegTextField("text-bytes", 0, UINT32_MAX, test_bytes,
                           test_text, 20);
    if (SKPLUGIN_OK != rv) {
        return rv;
    }
    rv = skpinRegStringListField("quant-bytes", test_labels, 0,
                                 "Too many", test_list, 0);
    if (SKPLUGIN_OK != rv) {
        return rv;
    }
    rv = skpinRegIntSumAggregator("sum-bytes", 0, test_bytes, 0);
    if (SKPLUGIN_OK != rv) {
        return rv;
    }
    rv = skpinRegIntMinAggregator("min-bytes", 0, test_bytes, 0);
    if (SKPLUGIN_OK != rv) {
        return rv;
    }
    rv = skpinRegIntMaxAggregator("max-bytes", 0, test_bytes, 0);
    if (SKPLUGIN_OK != rv) {
        return rv;
    }
    rv = skpinRegIntAggregator("weird-bytes", UINT32_MAX, test_bytes,
                               test_weird, 0, 0);
    if (SKPLUGIN_OK != rv) {
        return rv;
    }

    return SKPLUGIN_OK;
}

static uint64_t
test_bytes(
    const rwRec        *rec)
{
    return rwRecGetBytes(rec);
}

static uint32_t
test_sipv4(
    const rwRec        *rec)
{
    return rwRecGetSIPv4(rec);
}

static void
test_sip(
    skipaddr_t         *dest,
    const rwRec        *rec)
{
    rwRecMemGetSIP(rec, dest);
}

static void
test_text(
    char               *dest,
    size_t              width,
    uint64_t            val)
{
    snprintf(dest, width, "Byte count %" PRIu64, val);
    dest[width - 1] = '\0';
}

static uint64_t
test_list(
    const rwRec        *rec)
{
    uint32_t bytes = rwRecGetBytes(rec);

    if (bytes < 100) {
        return 0;
    } else if (bytes < 150) {
        return 1;
    } else if (bytes < 200) {
        return 2;
    }
    return 3;
}

static uint64_t
test_weird(
    uint64_t            current,
    uint64_t            operand)
{
    if (current > operand) {
        return (current - operand) / 2;
    }
    return (operand - current) / 2;
}

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
