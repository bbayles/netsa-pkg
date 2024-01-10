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
**  skheader-legacy.c
**
**    Routines to read, write, and manipulate the header of a SiLK file
**
**    Mark Thomas
**    November 2006
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skheader-legacy.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "skheader_priv.h"
#include "skstream_priv.h"


#define INVOCATION_BUFSIZE  512


/* Every header-entry has a hentry-type associated with it */
typedef struct sk_headlegacy_type_st {
    /* function to call to read the header */
    sk_headlegacy_read_fn_t     hleg_read;
    /* function to call to set the record length */
    sk_headlegacy_recsize_fn_t  hleg_reclen;
    /* version at which header padding was added, or 0 for no padding */
    uint8_t                     hleg_vers_padding;
    /* version at which compression-on-read was added, or 0 for none */
    uint8_t                     hleg_vers_compress;
} sk_headlegacy_type_t;



/* LOCAL VARIABLES */

/* A linked list of all registered header types */
static sk_headlegacy_type_t *headlegacy_type_list[UINT8_MAX];



/* LOCAL FUNCTION PROTOTYPES */

static sk_headlegacy_type_t *
skHeaderLegacyLookup(
    sk_file_format_t    file_format);

static uint16_t
legacyHeaderReclenRwbag(
    sk_file_version_t   vers);

static int
legacyHeaderInvocation(
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    size_t             *bytes_read);

static int
legacyHeaderPackedfile(
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    size_t             *bytes_read);

static int
legacyHeaderProbename(
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    size_t             *bytes_read);


/* FUNCTION DEFINITIONS */


/*  ****  LEGACY SUPPORT  ************************************************  */


int
skHeaderLegacyInitialize(
    void)
{
    int rv = 0;

    memset(headlegacy_type_list, 0, sizeof(headlegacy_type_list));

    rv |= skHeaderLegacyRegister(FT_RWAUGMENTED,
                                 &legacyHeaderPackedfile,
                                 &augmentedioGetRecLen,
                                 2, 2);
    rv |= skHeaderLegacyRegister(FT_RWAUGROUTING,
                                 &legacyHeaderPackedfile,
                                 &augroutingioGetRecLen,
                                 2, 2);
    rv |= skHeaderLegacyRegister(FT_RWAUGSNMPOUT,
                                 &legacyHeaderPackedfile,
                                 &augsnmpoutioGetRecLen,
                                 2, 2);
    rv |= skHeaderLegacyRegister(FT_RWAUGWEB,
                                 &legacyHeaderPackedfile,
                                 &augwebioGetRecLen,
                                 2, 2);

    rv |= skHeaderLegacyRegister(FT_RWNOTROUTED,
                                 &legacyHeaderPackedfile,
                                 &notroutedioGetRecLen,
                                 2, 3);
    rv |= skHeaderLegacyRegister(FT_RWROUTED,
                                 &legacyHeaderPackedfile,
                                 &routedioGetRecLen,
                                 2, 3);
    rv |= skHeaderLegacyRegister(FT_RWSPLIT,
                                 &legacyHeaderPackedfile,
                                 &splitioGetRecLen,
                                 2, 3);
    rv |= skHeaderLegacyRegister(FT_RWWWW,
                                 &legacyHeaderPackedfile,
                                 &wwwioGetRecLen,
                                 2, 3);

    rv |= skHeaderLegacyRegister(FT_RWFILTER,
                                 &legacyHeaderInvocation,
                                 &filterioGetRecLen,
                                 2, 4);
    rv |= skHeaderLegacyRegister(FT_RWGENERIC,
                                 NULL,
                                 &genericioGetRecLen,
                                 2, 3);

    rv |= skHeaderLegacyRegister(FT_FLOWCAP,
                                 &legacyHeaderProbename,
                                 &flowcapioGetRecLen,
                                 0, 1);

    rv |= skHeaderLegacyRegister(FT_IPSET,
                                 NULL,
                                 NULL,
                                 0, 1);
    rv |= skHeaderLegacyRegister(FT_RWBAG,
                                 NULL,
                                 &legacyHeaderReclenRwbag,
                                 0, 2);
    rv |= skHeaderLegacyRegister(FT_PREFIXMAP,
                                 NULL,
                                 NULL,
                                 0, 0);
    rv |= skHeaderLegacyRegister(FT_SHUFFLE,
                                 NULL,
                                 NULL,
                                 0, 0);

    return rv;
}


/* Register a legacy header type */
int
skHeaderLegacyRegister(
    sk_file_format_t            file_format,
    sk_headlegacy_read_fn_t     read_fn,
    sk_headlegacy_recsize_fn_t  reclen_fn,
    uint8_t                     vers_padding,
    uint8_t                     vers_compress)
{
    sk_headlegacy_type_t *new_reg;

    if (file_format >= UINT8_MAX) {
        return -1;
    }

    if (headlegacy_type_list[file_format]) {
        return -1;
    }

    new_reg = (sk_headlegacy_type_t*)calloc(1, sizeof(sk_headlegacy_type_t));
    if (NULL == new_reg) {
        return SKHEADER_ERR_ALLOC;
    }
    new_reg->hleg_read = read_fn;
    new_reg->hleg_reclen = reclen_fn;
    new_reg->hleg_vers_padding = vers_padding;
    new_reg->hleg_vers_compress = vers_compress;

    headlegacy_type_list[file_format] = new_reg;
    return SKHEADER_OK;
}


int
skHeaderLegacyDispatch(
    skstream_t         *stream,
    sk_file_header_t   *hdr)
{
    sk_headlegacy_type_t *leghead;
    size_t bytes_read = 0;
    int rv;

    /* get a handle to the structure describing this header */
    leghead = skHeaderLegacyLookup(hdr->fh_start.file_format);
    if (leghead == NULL) {
        return SKHEADER_ERR_LEGACY;
    }

    /* Set record version to the file version */
    hdr->fh_start.rec_version = hdr->fh_start.file_version;

    /* Set silk version to 0 */
    hdr->fh_start.silk_version = 0;

    /* Verify that compression value makes sense given the legacy
     * file's version */
    if ((hdr->fh_start.rec_version < leghead->hleg_vers_compress)
        && (hdr->fh_start.comp_method != SK_COMPMETHOD_NONE))
    {
        return SKHEADER_ERR_BAD_COMPRESSION;
    }

    /* call function to set record length, or set to 1 */
    if (leghead->hleg_reclen) {
        hdr->fh_start.rec_size
            = leghead->hleg_reclen(hdr->fh_start.rec_version);
    } else {
        hdr->fh_start.rec_size = 1;
    }

    /* call function to read remainder of header, except padding */
    if (leghead->hleg_read) {
        rv = leghead->hleg_read(stream, hdr, &bytes_read);
        hdr->header_length += bytes_read;
        if (rv) {
            return rv;
        }
    }
    /* else assume header is just a genericHeader */

    /* read the header padding */
    if ((leghead->hleg_vers_padding > 0)
        && (hdr->fh_start.rec_version >= leghead->hleg_vers_padding))
    {
        static uint8_t padding[SK_MAX_RECORD_SIZE];
        uint32_t pad_len;
        ssize_t saw;

        assert(hdr->fh_start.rec_size > 0);
        assert(hdr->fh_start.rec_size < SK_MAX_RECORD_SIZE);

        pad_len = (hdr->fh_start.rec_size
                   - (hdr->header_length % hdr->fh_start.rec_size));
        /* if pad_len == rec_size, the header is already an even
         * multiple of the record size, and there is no padding. */
        if (pad_len < hdr->fh_start.rec_size) {
            saw = skStreamRead(stream, padding, pad_len);
            if (saw == -1) {
                return -1;
            }
            hdr->header_length += saw;
            if ((size_t)saw != pad_len) {
                return SKHEADER_ERR_SHORTREAD;
            }
        }
    }

    return SKHEADER_OK;
}


void
skHeaderLegacyTeardown(
    void)
{
    unsigned int i;

    for (i = 0; i < UINT8_MAX; ++i) {
        if (headlegacy_type_list[i]) {
            free(headlegacy_type_list[i]);
            headlegacy_type_list[i] = NULL;
        }
    }
}


static sk_headlegacy_type_t *
skHeaderLegacyLookup(
    sk_file_format_t    file_format)
{
    if (file_format < UINT8_MAX) {
        return headlegacy_type_list[file_format];
    }
    return NULL;
}


static uint16_t
legacyHeaderReclenRwbag(
    sk_file_version_t   vers)
{
    if (vers == 1) {
        return sizeof(uint32_t) + sizeof(uint32_t);
    }
    return sizeof(uint32_t) + sizeof(uint64_t);
}



/*
 *  status = legacyHeaderInvocation(stream, hdr, &bytes_read);
 *
 *    Read the command line history from a legacy file that 'stream'
 *    opened to read, and add Invocation Header Entries to the 'hdr'.
 *
 *    The function adds to 'bytes_read' the number of bytes it reads.
 */
static int
legacyHeaderInvocation(
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    size_t             *bytes_read)
{
    uint32_t cmd_count;
    uint16_t cmd_line_len;
    uint16_t buf_len = INVOCATION_BUFSIZE;
    char *buf;
    char *c;
    uint32_t i;
    ssize_t saw;
    int rv = -1;
    int save_errno = 0;
    int swap_flag;

    assert(stream);
    assert(hdr);
    assert(bytes_read);

    swap_flag = !skHeaderIsNativeByteOrder(hdr);

    /* read the number of command lines; the hdrLen already accounts
     * for this */
    saw = skStreamRead(stream, &cmd_count, sizeof(cmd_count));
    if (saw == -1) {
        return -1;
    }
    *bytes_read += saw;
    if ((size_t)saw != sizeof(cmd_count)) {
        return SKHEADER_ERR_SHORTREAD;
    }
    if (swap_flag) {
        cmd_count = BSWAP32(cmd_count);
    }

    /* create a tempory buffer to hold the command line */
    buf = (char*)malloc(buf_len * sizeof(char));
    if (!buf) {
        return SKHEADER_ERR_ALLOC;
    }

    /* load each command line into the temporary buffer */
    for (i = 0; i < cmd_count; i++) {
        /* read the command line length */
        saw = skStreamRead(stream, &cmd_line_len, sizeof(cmd_line_len));
        if (saw == -1) {
            save_errno = errno;
            rv = -1;
            goto END;
        }
        *bytes_read += saw;
        if ((size_t)saw != sizeof(cmd_line_len)) {
            rv = SKHEADER_ERR_SHORTREAD;
            goto END;
        }
        if (swap_flag) {
            cmd_line_len = BSWAP16(cmd_line_len);
        }

        if (cmd_line_len == 0) {
            continue;
        }

        if (cmd_line_len > buf_len) {
            /* grow the buffer if it is too small */
            char *old_buf = buf;
            buf_len = cmd_line_len + INVOCATION_BUFSIZE;
            buf = (char*)realloc(buf, buf_len);
            if (buf == NULL) {
                save_errno = errno;
                buf = old_buf;
                rv = SKHEADER_ERR_ALLOC;
                goto END;
            }
        }

        /* read the command line into buf */
        saw = skStreamRead(stream, buf, cmd_line_len);
        if (saw == -1) {
            save_errno = errno;
            rv = -1;
            goto END;
        }
        *bytes_read += saw;
        if (saw != cmd_line_len) {
            rv = SKHEADER_ERR_SHORTREAD;
            goto END;
        }

        /* convert each '\0' to ' ' except final */
        for (c = buf; cmd_line_len > 0; ++c, --cmd_line_len) {
            if (*c == '\0') {
                *c = ' ';
            }
        }
        /* this should already be \0, but just make certain */
        *c = '\0';

        /* create a header entry for the command line */
        rv = skHeaderAddInvocation(hdr, 0, 1, &buf);
        if (rv) {
            save_errno = errno;
            goto END;
        }
    }

    rv = SKHEADER_OK;

  END:
    if (buf) {
        free(buf);
    }
    errno = save_errno;

    return rv;
}


/*
 *  status = legacyHeaderPackedfile(stream, hdr, &bytes_read);
 *
 *    Read the start-time from a legacy file that 'fd' opened to read,
 *    and use it and the file's 'pathname' to add a Packedfile Header
 *    Entry to the 'hdr'.
 *
 *    The function adds to 'bytes_read' the number of bytes it reads.
 *    The 'swap_file' says whether the time value must be byte-swapped
 *    when reading.
 */
static int
legacyHeaderPackedfile(
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    size_t             *bytes_read)
{
    uint32_t start_time;
    sk_flowtype_id_t flow_type;
    sk_sensor_id_t sensor_id;
    ssize_t saw;

    assert(stream);
    assert(hdr);
    assert(bytes_read);

    /* read the start time */
    saw = skStreamRead(stream, &start_time, sizeof(start_time));
    if (saw == -1) {
        return -1;
    }
    *bytes_read += saw;
    if (saw != sizeof(start_time)) {
        return SKHEADER_ERR_SHORTREAD;
    }
    if ( !skHeaderIsNativeByteOrder(hdr)) {
        start_time = BSWAP32(start_time);
    }

    /* set the flow_type and sensor_id from the file name */
    if (sksiteParseFilename(&flow_type, &sensor_id, NULL, NULL,
                            skStreamGetPathname(stream))
        == SK_INVALID_FLOWTYPE)
    {
        flow_type = SK_INVALID_FLOWTYPE;
        sensor_id = SK_INVALID_SENSOR;
    }

    /* create the header entry */
    return skHeaderAddPackedfile(hdr, sktimeCreate(start_time, 0),
                                 flow_type, sensor_id);
}


/*
 *  status = legacyHeaderProbename(fd, hdr, &bytes_read);
 *
 *    Read the sensor and probe names from a legacy flowcap file and
 *    use them to add a Probename header to 'hdr'.
 *
 *    The function adds to 'bytes_read' the number of bytes it reads.
 *    The 'swap_file' says whether the time value must be byte-swapped
 *    when reading.
 */
static int
legacyHeaderProbename(
    skstream_t         *stream,
    sk_file_header_t   *hdr,
    size_t             *bytes_read)
{
    /* Old flowcap files have a sensor name and probe name field, each
     * of 25 bytes (SK_MAX_STRLEN_SENSOR+1) */
#define SK_HENTRY_SP_LEGACY_ENTRYSIZE  25
    char sensor_probe[2 * SK_HENTRY_SP_LEGACY_ENTRYSIZE];
    char *probe_name;
    char *cp;
    ssize_t saw;

    /* if compression-level is 6, set to LZO */
    if (6 == (int)hdr->fh_start.comp_method) {
        hdr->fh_start.comp_method = SK_COMPMETHOD_LZO1X;
    }

    /* read the sensor and probe names as a single string */
    saw = skStreamRead(stream, sensor_probe, sizeof(sensor_probe));
    if (saw == -1) {
        return -1;
    }
    *bytes_read += saw;
    if (saw != sizeof(sensor_probe)) {
        return SKHEADER_ERR_SHORTREAD;
    }

    /* find end of sensor name */
    cp = (char*)memchr(sensor_probe, '\0', SK_HENTRY_SP_LEGACY_ENTRYSIZE);

    /* find start of probe name */
    probe_name = &(sensor_probe[SK_HENTRY_SP_LEGACY_ENTRYSIZE]);

    /* if sensor name and probe name are identical, use that value
     * when creating the Probename header.  Otherwise, merge the
     * legacy sensor and probe names to a single value with an
     * underscore ("_") between them */
    if (0 != strcmp(sensor_probe, probe_name)) {
        if (cp) {
            *cp = '_';
            ++cp;
            if (cp != probe_name) {
                memmove(cp, probe_name, SK_HENTRY_SP_LEGACY_ENTRYSIZE);
            }
        }
    }
    sensor_probe[sizeof(sensor_probe)-1] = '\0';

    /* create the header entry */
    return skHeaderAddProbename(hdr, sensor_probe);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
