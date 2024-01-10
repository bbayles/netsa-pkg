/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafapplabel.c
 *
 *  This file implements the application labeler interface for YAF.  It
 *  allows a limited set of information about a _flow_ to captured.  It
 *  processes very packet that comes through the pipe in order to pull
 *  out its information and record flow type and details.
 *
 *  It must be enabled with a configure option to be included in YAF.
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio
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

#if YAF_ENABLE_APPLABEL

#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include "applabel/payloadScanner.h"
#include "yafapplabel.h"

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

gboolean
yfAppLabelInit(
    const char  *ruleFileName,
    GError     **err)
{
    FILE *ruleFile = NULL;

    if (NULL == ruleFileName) {
        ruleFileName = YAF_CONF_DIR "/yafApplabelRules.conf";
    }

    ruleFile = fopen(ruleFileName, "r");
    if (NULL == ruleFile) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_IO, "could not open "
                           "application labeler rule file \"%s\" for reading",
                           ruleFileName);
        return FALSE;
    }

    g_debug("Initializing Rules From File: %s", ruleFileName);
    if (!ycInitializeScanRules(ruleFile, err)) {
        return FALSE;
    }

    return TRUE;
}


void
yfAppLabelFlow(
    yfFlow_t  *flow)
{
    if (!flow->appLabel && flow->val.paylen) {
        flow->appLabel =
            ycScanPayload(flow->val.payload, flow->val.paylen, flow,
                          &(flow->val));
    }

#if YAF_ENABLE_HOOKS
    yfHookFlowPacket(flow, &(flow->rval), flow->rval.payload,
                     flow->rval.paylen, 0, NULL, NULL);
#endif

    if (!flow->appLabel && flow->rval.paylen) {
        flow->appLabel =
            ycScanPayload(flow->rval.payload, flow->rval.paylen, flow,
                          &(flow->rval));
    }
}


#endif /*YAF_ENABLE_APPLABEL*/
