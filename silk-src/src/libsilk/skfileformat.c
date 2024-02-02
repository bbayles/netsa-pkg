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
 *  skfileformat.c
 *
 *    Convert between the names and the integer identifiers of the
 *    file formats known to SiLK.
 */

/* define sk_file_format_names[] in silk_files.h */
#define SKFILEFORMAT_SOURCE 1
#include <silk/silk.h>

RCSIDENT("$SiLK: skfileformat.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_files.h>
#include <silk/utils.h>



/* TYPEDEFS AND DEFINES */

#define INVALID_LABEL  "?"


/* FUNCTION DEFINITIONS */

/*
 *    Return the number of valid entries in the sk_file_format_names[]
 *    array defined in silk_files.h.
 */
static size_t
fileFormatGetCount(
    void)
{
    static size_t file_format_count = 0;
    size_t count;
    size_t len;
    size_t i;

    if (file_format_count) {
        /* already initialized */
        return file_format_count;
    }

    /* get the length of the sk_file_format_names[] array */
    count = sizeof(sk_file_format_names)/sizeof(sk_file_format_names[0]);

    /* loop over sk_file_format_names[] until we find a NULL name or a
     * name that is an empty string */
    for (i = 0; i < count; ++i) {
        if (NULL == sk_file_format_names[i]) {
            break;
        }

        len = strlen(sk_file_format_names[i]);
        if (0 == len) {
            break;
        }

        /* check the length of the file format name */
        if (len > SK_MAX_STRLEN_FILE_FORMAT) {
            skAppPrintErr(("FATAL! sk_file_format_names[] in silk_files.h"
                           " contains a name '%s' whose length (%" SK_PRIuZ
                           ") is longer than the maximum allowed (%u)"),
                          sk_file_format_names[i], len,
                          SK_MAX_STRLEN_FILE_FORMAT);
            skAbort();
        }
    }

    if (i >= UINT8_MAX) {
        skAppPrintErr("FATAL! sk_file_format_names[] in silk_files.h"
                      " contains more than %u entries",
                      UINT8_MAX - 1u);
        skAbort();
    }
    if (0 == i) {
        skAppPrintErr("FATAL! sk_file_format_names[] in silk_files.h"
                      " does not contain any names");
        skAbort();
    }

    /* only the final entry in array should be NULL or the empty
     * string */
    if (count - i > 1) {
        skAppPrintErr(("FATAL! sk_file_format_names[] in silk_files.h"
                       " contains a NULL or empty-string entry at"
                       " position %" SK_PRIuZ),
                      i);
        skAbort();
    }

    file_format_count = i;
    return file_format_count;
}


int
skFileFormatGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_file_format_t    id)
{
    if (id < fileFormatGetCount()) {
        /* Known file format, give name */
        assert(id < (sizeof(sk_file_format_names)
                     / sizeof(sk_file_format_names[0])));
        assert(sk_file_format_names[id] && sk_file_format_names[id][0]);
        return snprintf(buffer, buffer_size, "%s", sk_file_format_names[id]);
    }

    /* Unknown file format, give integer */
    return snprintf(buffer, buffer_size, "%s[%u]", INVALID_LABEL, id);
}


sk_file_format_t
skFileFormatFromName(
    const char         *name)
{
    size_t count;
    size_t i;

    count = fileFormatGetCount();

    for (i = 0; i < count; ++i) {
        if (strcmp(name, sk_file_format_names[i]) == 0) {
            return (sk_file_format_t)i;
        }
    }
    return SK_INVALID_FILE_FORMAT;
}


int
skFileFormatIsValid(
    sk_file_format_t    id)
{
    return (id < fileFormatGetCount());
}


/** DEPRECATED FUNCTIONS **********************************************/

#include <silk/sksite.h>

int
sksiteFileformatGetName(
    char               *buffer,
    size_t              buffer_size,
    sk_file_format_t    format_id)
{
    return skFileFormatGetName(buffer, buffer_size, format_id);
}

int
sksiteFileformatIsValid(
    sk_file_format_t    format_id)
{
    return skFileFormatIsValid(format_id);
}

sk_file_format_t
sksiteFileformatFromName(
    const char         *name)
{
    return skFileFormatFromName(name);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
