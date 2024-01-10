/*
** Copyright (C) 2007-2023 by Carnegie Mellon University.
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

#include <silk/silk.h>

RCSIDENT("$SiLK: rwipautils.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "rwipa.h"


#define IPA_CONFIG_FILE "silk-ipa.conf"
#define IPA_CONFIG_LINE_LENGTH 1024


char *
get_ipa_config(
    void)
{
    skstream_t *conf_stream = NULL;
    char filename[PATH_MAX];
    char line[IPA_CONFIG_LINE_LENGTH];
    char *ipa_url = NULL;
    int rv;

    /* Read in the data file */
    if (NULL == skFindFile(IPA_CONFIG_FILE, filename, sizeof(filename), 1)) {
        skAppPrintErr("Could not locate config file '%s'.",
                      IPA_CONFIG_FILE);
        return NULL;
    }

    /* open input */
    if ((rv = skStreamCreate(&conf_stream, SK_IO_READ, SK_CONTENT_TEXT))
        || (rv = skStreamBind(conf_stream, filename))
        || (rv = skStreamSetCommentStart(conf_stream, "#"))
        || (rv = skStreamOpen(conf_stream)))
    {
        skStreamPrintLastErr(conf_stream, rv, &skAppPrintErr);
        skStreamDestroy(&conf_stream);
        exit(EXIT_FAILURE);
    }
    while (skStreamGetLine(conf_stream, line, sizeof(line), NULL)
           == SKSTREAM_OK)
    {
        /* FIXME: smarter config file reading, please */
        if (strlen(line) > 0) {
            ipa_url = strdup(line);
            break;
        }
    }

    skStreamDestroy(&conf_stream);
    /* Should be free()d by the caller */
    return ipa_url;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
