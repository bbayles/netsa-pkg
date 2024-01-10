/*
** Copyright (C) 2009-2023 by Carnegie Mellon University.
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
**  uniq-distproto.c
**
**    A plug-in to be loaded by rwuniq to count the number of distinct
**    protocols per key.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: uniq-distproto.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skplugin.h>
#include <silk/rwrec.h>


/* DEFINES AND TYPEDEFS */

/* Plugin protocol version */
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0

/* Width of text field */
#define FIELD_WIDTH 3

/* Number of uint8_t's for a bitmaps of protocols */
#define BITMAP_SIZE  32         /* 256/8 */


/* LOCAL VARIABLES */

static const uint8_t BitsSetTable256[] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};


/* FUNCTION DECLARATIONS */

static skplugin_err_t
recAddToMap(
    const rwRec        *rwrec,
    uint8_t            *bin_value,
    void               *idx,
    void              **extra);
static skplugin_err_t
mapToText(
    const uint8_t      *bin_value,
    char               *text_value,
    size_t              text_size,
    void               *idx);
static skplugin_err_t
mergeMaps(
    uint8_t            *dst_bin,
    const uint8_t      *src_bin,
    void               *idx);
static skplugin_err_t
compareMaps(
    int                *cmp,
    const uint8_t      *bin_a,
    const uint8_t      *bin_b,
    void               *idx);


/* FUNCTION DEFINITIONS */

/* the registration function called by skplugin.c */
skplugin_err_t
SKPLUGIN_SETUP_FN(
    uint16_t            major_version,
    uint16_t            minor_version,
    void        UNUSED(*pi_data))
{
    uint8_t init_value[BITMAP_SIZE];
    skplugin_field_t *field;
    skplugin_err_t rv;
    skplugin_callbacks_t regdata;

    /* Check API version */
    rv = skpinSimpleCheckVersion(major_version, minor_version,
                                 PLUGIN_API_VERSION_MAJOR,
                                 PLUGIN_API_VERSION_MINOR,
                                 skAppPrintErr);
    if (rv != SKPLUGIN_OK) {
        return rv;
    }

    memset(&init_value, 0, sizeof(init_value));

    /* register the new aggregate to use with rwuniq */
    memset(&regdata, 0, sizeof(regdata));
    regdata.column_width = FIELD_WIDTH;
    regdata.bin_bytes = sizeof(init_value);
    regdata.add_rec_to_bin = recAddToMap;
    regdata.bin_to_text = mapToText;
    regdata.bin_merge = mergeMaps;
    regdata.bin_compare = compareMaps;
    regdata.initial = init_value;
    return skpinRegField(&field, "proto-distinct", NULL, &regdata, NULL);
}


/*
 *  status = recAddToMap(rwrec, bin_val, &v_unused, NULL);
 *
 *    Given the SiLK Flow record 'rwrec' and an existing binary value
 *    'bin_val', add the protocol from 'rwrec' to 'bin_val'.
 */
static skplugin_err_t
recAddToMap(
    const rwRec            *rwrec,
    uint8_t                *map_value,
    void            UNUSED(*v_unused),
    void           UNUSED(**extra))
{
    uint8_t proto = rwRecGetProto(rwrec);

    map_value[proto >> 3] |= 1 << (proto & 0x7);
    return SKPLUGIN_OK;
}


/*
 *  status = mapToText(bin_value, text_val, text_len, &v_unused);
 *
 *    Given the binary value 'bin_value' created by calls to
 *    'recAddToMap()', fill 'text_val', a buffer of 'text_len'
 *    characters, with a textual representation of the binary
 *    value---in this case, the number of bits that are set in
 *    'bin_value'.
 */
static skplugin_err_t
mapToText(
    const uint8_t          *bin_value,
    char                   *text_value,
    size_t                  text_size,
    void            UNUSED(*v_unused))
{
    int i;
    int c = 0;

    for (i = 0; i < BITMAP_SIZE; ++i) {
        c += BitsSetTable256[bin_value[i]];
    }

    snprintf(text_value, text_size, "%3d", c);
    return SKPLUGIN_OK;
}


/*
 *  status = mergeMaps(dst_bin, src_bin, &v_unused);
 *
 *    Given two binary values 'dst_bin' and 'src_bin' created by calls
 *    to 'recAddToMap()', fill 'dst_bin', with the result of adding
 *    the two binary values---in this case, the result of performing a
 *    bitwise-OR on the values.
 */
static skplugin_err_t
mergeMaps(
    uint8_t                *dst_bin,
    const uint8_t          *src_bin,
    void            UNUSED(*v_unused))
{
    int i;

    for (i = 0; i < BITMAP_SIZE; ++i) {
        dst_bin[i] |= src_bin[i];
    }
    return SKPLUGIN_OK;
}


/*
 *  status = compareMaps(cmp, bin_a, bin_b, &v_unused);
 *
 *    Given two binary values 'bin_a' and 'bin_a' created by calls to
 *    'recAddToMap()', fill 'cmp', with the result of comparing the
 *    two binary values---in this case, the result of counting the
 *    number of bits set in each bitmap.
 */
static skplugin_err_t
compareMaps(
    int                    *cmp,
    const uint8_t          *bin_a,
    const uint8_t          *bin_b,
    void            UNUSED(*v_unused))
{
    int i;

    /* compute A-B to get correct comparison value. */
    *cmp = 0;
    for (i = 0; i < BITMAP_SIZE; ++i) {
        *cmp += ((int)(BitsSetTable256[bin_a[i]])
                 - (int)(BitsSetTable256[bin_b[i]]));
    }
    return SKPLUGIN_OK;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
