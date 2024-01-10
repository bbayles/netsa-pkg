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
**  sktempfile.c
**
**    Functions to handle temp file creation and access.
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: sktempfile.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skstream.h>
#include <silk/sktempfile.h>
#include <silk/skvector.h>
#include <silk/utils.h>


/* TYPDEFS AND DEFINES */

/* Print debugging messages when this environment variable is set to a
 * positive integer. */
#define SKTEMPFILE_DEBUG_ENVAR "SILK_TEMPFILE_DEBUG"


/* typedef struct sk_tempfilectx_st sk_tempfilectx_t; */
struct sk_tempfilectx_st {
    /* template used to make temporary files. */
    char tf_template[PATH_MAX];

    /* names of temporary files */
    sk_vector_t *tf_names;

    /* whether to enable debugging */
    unsigned     print_debug :1;

    /* true when in teardown; avoids some print_debug messages */
    unsigned     in_teardown :1;
};


/*
 *  TEMPFILE_DEBUGn(td_ctx, td_fmt, ...);
 *
 *    Print a message when the print_debug member is active.  Use a
 *    value of n that matches the number of arguments to the format.
 *
 *    TEMPFILE_DEBUG1(tmpctx, "one is %d", 1);
 */
#define TEMPFILE_DEBUG0(td_ctx, td_fmt)                         \
    if (!(td_ctx)->print_debug) { /* no-op */ } else {          \
        skAppPrintErr(SKTEMPFILE_DEBUG_ENVAR ": " td_fmt);      \
    }
#define TEMPFILE_DEBUG1(td_ctx, td_fmt, td_arg1)                \
    if (!(td_ctx)->print_debug) { /* no-op */ } else {          \
        skAppPrintErr((SKTEMPFILE_DEBUG_ENVAR ": " td_fmt),     \
                      (td_arg1));                               \
    }
#define TEMPFILE_DEBUG2(td_ctx, td_fmt, td_arg1, td_arg2)       \
    if (!(td_ctx)->print_debug) { /* no-op */ } else {          \
        skAppPrintErr((SKTEMPFILE_DEBUG_ENVAR ": " td_fmt),     \
                      (td_arg1), (td_arg2));                    \
    }
#define TEMPFILE_DEBUG3(td_ctx, td_fmt, td_arg1, td_arg2, td_arg3)      \
    if (!(td_ctx)->print_debug) { /* no-op */ } else {                  \
        skAppPrintErr((SKTEMPFILE_DEBUG_ENVAR ": " td_fmt),             \
                      (td_arg1), (td_arg2), (td_arg3));                 \
    }
#define TEMPFILE_DEBUG4(td_ctx, td_fmt, td_arg1, td_arg2, td_arg3, td_arg4) \
    if (!(td_ctx)->print_debug) { /* no-op */ } else {                  \
        skAppPrintErr((SKTEMPFILE_DEBUG_ENVAR ": " td_fmt),             \
                      (td_arg1), (td_arg2), (td_arg3), (td_arg4));      \
    }


/* EXPORTED VARIABLES */

/* placeholder for files that have been removed from the vector */
const char * const sktempfile_null = "NULL";


/* LOCAL VARIABLES */



/* FUNCTION DEFINITIONS */


/* find the tmpdir to use, initialize template, create vector */
int
skTempFileInitialize(
    sk_tempfilectx_t  **tmpctx,
    const char         *user_temp_dir,
    const char         *prefix_name,
    sk_msg_fn_t         err_fn)
{
    sk_tempfilectx_t *t;
    const char *tmp_dir = NULL;
    const char *env_value;
    uint32_t debug_lvl;
    int rv;

    if (NULL == prefix_name) {
        prefix_name = skAppName();
    }

    tmp_dir = skTempDir(user_temp_dir, err_fn);
    if (NULL == tmp_dir) {
        return -1;
    }

    t = (sk_tempfilectx_t*)calloc(1, sizeof(sk_tempfilectx_t));
    if (NULL == t) {
        return -1;
    }

    rv = snprintf(t->tf_template, sizeof(t->tf_template),
                  "%s/%s.%d.XXXXXXXX", tmp_dir, prefix_name, (int)getpid());
    if ((size_t)rv >= sizeof(t->tf_template) || rv < 0) {
        if (err_fn) {
            err_fn("Error initializing template for temporary file names");
        }
        free(t);
        return -1;
    }

    /* initialize tmp_names */
    t->tf_names = skVectorNew(sizeof(char*));
    if (NULL == t->tf_names) {
        if (err_fn) {
            err_fn("Unable to allocate vector for temporary file names");
        }
        free(t);
        return -1;
    }

    /* Check for debugging */
    env_value = getenv(SKTEMPFILE_DEBUG_ENVAR);
    if ((env_value != NULL)
        && (0 == skStringParseUint32(&debug_lvl, env_value, 1, 0)))
    {
        t->print_debug = 1;
    }

    TEMPFILE_DEBUG1(t, "Initialization complete for '%s'", t->tf_template);

    *tmpctx = t;
    return 0;
}


/* remove all temp files and destroy vector */
void
skTempFileTeardown(
    sk_tempfilectx_t  **tmpctx)
{
    sk_tempfilectx_t *t;
    int i;

    if (tmpctx && *tmpctx) {
        t = *tmpctx;
        *tmpctx = NULL;

        t->in_teardown = 1;

        TEMPFILE_DEBUG1(t, "Tearing down '%s'...", t->tf_template);

        if (t->tf_names) {
            for (i = skVectorGetCount(t->tf_names)-1; i >= 0; --i) {
                skTempFileRemove(t, i);
            }
            skVectorDestroy(t->tf_names);
        }

        TEMPFILE_DEBUG1(t, "Teardown complete for '%s'", t->tf_template);

        free(t);
    }
}


/* create new file */
FILE *
skTempFileCreate(
    sk_tempfilectx_t   *tmpctx,
    int                *tmp_idx,
    char              **out_name)
{
    int saved_errno;
    FILE *fp = NULL;
    char *name;
    int fd;

    if (NULL == tmpctx || NULL == tmp_idx) {
        errno = 0;
        return NULL;
    }

    /* copy template name */
    name = strdup(tmpctx->tf_template);
    if (NULL == name) {
        saved_errno = errno;
        TEMPFILE_DEBUG1(tmpctx, "Failed to strdup(): %s",
                        strerror(errno));
        errno = saved_errno;
        return NULL;
    }

    /* open file */
    fd = mkstemp(name);
    if (fd == -1) {
        saved_errno = errno;
        TEMPFILE_DEBUG2(tmpctx, "Failed to mkstemp('%s'): %s",
                        name, strerror(errno));
        free(name);
        errno = saved_errno;
        return NULL;
    }

    /* convert descriptor to FILE pointer */
    fp = fdopen(fd, "w+");
    if (fp == NULL) {
        saved_errno = errno;
        TEMPFILE_DEBUG3(tmpctx, "Failed to fdopen(%d ['%s']): %s",
                        fd, name, strerror(errno));
        close(fd);
        unlink(name);
        free(name);
        errno = saved_errno;
        return NULL;
    }

    /* append to vector */
    if (skVectorAppendValue(tmpctx->tf_names, &name)) {
        saved_errno = errno;
        TEMPFILE_DEBUG1(tmpctx, "Failed to skVectorAppendValue(): %s",
                        strerror(errno));
        fclose(fp);
        unlink(name);
        free(name);
        errno = saved_errno;
        return NULL;
    }

    *tmp_idx = skVectorGetCount(tmpctx->tf_names) - 1;

    TEMPFILE_DEBUG2(tmpctx, "Created new temp %d => '%s'", *tmp_idx, name);

    if (out_name) {
        *out_name = name;
    }

    return fp;
}


/* create new file as an skstream */
skstream_t *
skTempFileCreateStream(
    sk_tempfilectx_t   *tmpctx,
    int                *tmp_idx)
{
    char errbuf[2 * PATH_MAX];
    skstream_t *stream = NULL;
    sk_file_header_t *hdr;
    sk_compmethod_t compmethod;
    const char *name;
    ssize_t rv;
    int saved_errno;

    compmethod = SK_COMPMETHOD_BEST;

    if (NULL == tmpctx || NULL == tmp_idx) {
        errno = 0;
        return NULL;
    }

    /* should only fail due to an allocation error */
    if (skStreamCreate(&stream, SK_IO_WRITE, SK_CONTENT_SILK)) {
        saved_errno = errno;
        TEMPFILE_DEBUG1(tmpctx, "Cannot create stream object: %s",
                        strerror(errno));
        goto ERROR;
    }

    /* could fail due to an allocation error */
    if ((rv = skStreamBind(stream, tmpctx->tf_template))) {
        saved_errno = skStreamGetLastErrno(stream);
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        TEMPFILE_DEBUG1(tmpctx, "Cannot bind name to stream: %s", errbuf);
        goto ERROR;
    }

    /* setting the header normally should not fail */
    hdr = skStreamGetSilkHeader(stream);
    if ((rv = skHeaderSetFileFormat(hdr, FT_TEMPFILE))
        || (rv = skHeaderSetRecordVersion(hdr, 1))
        || (rv = skHeaderSetRecordLength(hdr, 1))
        || (rv = skHeaderSetCompressionMethod(hdr, compmethod)))
    {
        saved_errno = skStreamGetLastErrno(stream);
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        TEMPFILE_DEBUG1(tmpctx, "Cannot set file header: %s", errbuf);
        goto ERROR;
    }

    /* open the file */
    if ((rv = skStreamMakeTemp(stream))) {
        saved_errno = skStreamGetLastErrno(stream);
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        TEMPFILE_DEBUG1(tmpctx, "Cannot create temporary file: %s", errbuf);
        goto ERROR;
    }

    /* write the header */
    if ((rv = skStreamWriteSilkHeader(stream))) {
        saved_errno = skStreamGetLastErrno(stream);
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        TEMPFILE_DEBUG1(tmpctx, "Cannot write the file's header: %s", errbuf);
        unlink(skStreamGetPathname(stream));
        goto ERROR;
    }

    /* copy the file's name and append it to the vector */
    name = strdup(skStreamGetPathname(stream));
    if (NULL == name) {
        saved_errno = errno;
        TEMPFILE_DEBUG1(tmpctx, "Cannot copy string: %s", strerror(errno));
        unlink(skStreamGetPathname(stream));
        goto ERROR;
    }
    if (skVectorAppendValue(tmpctx->tf_names, &name)) {
        saved_errno = errno;
        TEMPFILE_DEBUG1(tmpctx, "Cannot append to vector: %s",
                        strerror(errno));
        unlink(name);
        goto ERROR;
    }

    *tmp_idx = skVectorGetCount(tmpctx->tf_names) - 1;

    TEMPFILE_DEBUG2(tmpctx, "Created new temp %d => '%s'", *tmp_idx, name);

    return stream;

  ERROR:
    skStreamDestroy(&stream);
    errno = saved_errno;
    return NULL;
}


/* get name of file */
const char *
skTempFileGetName(
    const sk_tempfilectx_t *tmpctx,
    int                     tmp_idx)
{
    char **name;

    assert(tmpctx);

    name = (char**)skVectorGetValuePointer(tmpctx->tf_names, tmp_idx);
    if (name && *name) {
        return *name;
    }
    return sktempfile_null;
}


/* open existing file */
FILE *
skTempFileOpen(
    const sk_tempfilectx_t *tmpctx,
    int                     tmp_idx)
{
    const char *name;

    name = skTempFileGetName(tmpctx, tmp_idx);
    TEMPFILE_DEBUG2(tmpctx, "Opening existing temp %d => '%s'", tmp_idx, name);

    if (name == sktempfile_null) {
        errno = 0;
        return NULL;
    }
    return fopen(name, "r+");
}


skstream_t *
skTempFileOpenStream(
    const sk_tempfilectx_t *tmpctx,
    int                     tmp_idx)
{
    char errbuf[2 * PATH_MAX];
    skstream_t *stream = NULL;
    sk_file_header_t *hdr;
    const char *name;
    ssize_t rv;
    int saved_errno;

    name = skTempFileGetName(tmpctx, tmp_idx);
    TEMPFILE_DEBUG2(tmpctx, "Opening existing temp %d => '%s'", tmp_idx, name);

    if (name == sktempfile_null) {
        errno = 0;
        return NULL;
    }

    if ((rv = skStreamCreate(&stream, SK_IO_READ, SK_CONTENT_SILK))) {
        saved_errno = errno;
        TEMPFILE_DEBUG1(tmpctx, "Cannot create stream object: %s",
                        strerror(errno));
        goto ERROR;
    }

    if ((rv = skStreamBind(stream, name))) {
        saved_errno = skStreamGetLastErrno(stream);
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        TEMPFILE_DEBUG1(tmpctx, "Cannot bind name to stream: %s", errbuf);
        goto ERROR;
    }

    if ((rv = skStreamOpen(stream))) {
        saved_errno = skStreamGetLastErrno(stream);
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        TEMPFILE_DEBUG1(tmpctx, "Cannot open existing file: %s", errbuf);
        goto ERROR;
    }

    if ((rv = skStreamReadSilkHeader(stream, &hdr))) {
        saved_errno = skStreamGetLastErrno(stream);
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        TEMPFILE_DEBUG1(tmpctx, "Cannot read the file's header: %s", errbuf);
        goto ERROR;
    }

    if ((rv = skStreamCheckSilkHeader(stream, FT_TEMPFILE, 1, 1, NULL))) {
        saved_errno = 0;
        TEMPFILE_DEBUG1(tmpctx, "Unexpected header on file: %s", errbuf);
        goto ERROR;
    }

    return stream;

  ERROR:
    skStreamDestroy(&stream);
    errno = saved_errno;
    return NULL;
}


/* remove file */
void
skTempFileRemove(
    sk_tempfilectx_t   *tmpctx,
    int                 tmp_idx)
{
    const char *name;

    name = skTempFileGetName(tmpctx, tmp_idx);
    if (name == sktempfile_null) {
        if (!tmpctx->in_teardown) {
            TEMPFILE_DEBUG2(tmpctx, "Removing temp %d => '%s'", tmp_idx, name);
        }
        return;
    }

    TEMPFILE_DEBUG3(tmpctx, "Removing temp %d => '%s' of size %" PRId64,
                    tmp_idx, name, (int64_t)skFileSize(name));
    if (-1 == unlink(name)) {
        if (skFileExists(name)) {
            TEMPFILE_DEBUG2(tmpctx, "Failed to unlink('%s'): %s",
                            name, strerror(errno));
        }
    }

    free((char*)name);
    skVectorSetValue(tmpctx->tf_names, tmp_idx, &sktempfile_null);
}


/*
 *  ok = skTempFileWriteBuffer(&tmp_idx, buffer, size, count);
 *
 *    Print 'count' records having size 'size' bytes from 'buffer'
 *    into a newly created temporary file.  Index the temp file by
 *    'tmp_idx'.  Returns 0 on success, or -1 if a temp file cannot be
 *    created, or the write or close calls fail.
 */
int
skTempFileWriteBuffer(
    sk_tempfilectx_t   *tmpctx,
    int                *tmp_idx,
    const void         *rec_buffer,
    uint32_t            rec_size,
    uint32_t            rec_count)
{
    int saved_errno = 0;
    FILE* temp_filep = NULL;
    char *name;
    ssize_t rv = -1; /* return value */

    temp_filep = skTempFileCreate(tmpctx, tmp_idx, &name);
    if (temp_filep == NULL) {
        saved_errno = errno;
        goto END;
    }

    TEMPFILE_DEBUG4(
        tmpctx,
        "Writing %" PRIu32 " %" PRIu32 "-byte records to temp %d => '%s'",
        rec_count, rec_size, *tmp_idx, name);

    if (rec_count != fwrite(rec_buffer, rec_size, rec_count, temp_filep)) {
        /* error writing */
        saved_errno = errno;
        TEMPFILE_DEBUG2(tmpctx, "Failed to fwrite('%s'): %s",
                        name, strerror(errno));
        goto END;
    }

    /* Success so far */
    rv = 0;

  END:
    /* close the file if open */
    if (temp_filep) {
        if (rv != 0) {
            /* already an error, so just close the file */
            fclose(temp_filep);
        } else if (fclose(temp_filep) == EOF) {
            saved_errno = errno;
            TEMPFILE_DEBUG2(tmpctx, "Failed to fclose('%s'): %s",
                            name, strerror(errno));
            rv = -1;
        }
    }
    errno = saved_errno;
    return rv;
}


int
skTempFileWriteBufferStream(
    sk_tempfilectx_t   *tmpctx,
    int                *tmp_idx,
    const void         *rec_buffer,
    uint32_t            rec_size,
    uint32_t            rec_count)
{
    char errbuf[2 * PATH_MAX];
    int saved_errno = 0;
    skstream_t *stream = NULL;
    uint64_t bytes;
    size_t part;
    const uint8_t *b;
    ssize_t rv;

    stream = skTempFileCreateStream(tmpctx, tmp_idx);
    if (NULL == stream) {
        return -1;
    }

    TEMPFILE_DEBUG4(
        tmpctx,
        "Writing %" PRIu32 " %" PRIu32 "-byte records to temp %d => '%s'",
        rec_count, rec_size, *tmp_idx, skStreamGetPathname(stream));

    bytes = rec_size * rec_count;
    b = (const uint8_t*)rec_buffer;
    do {
        part = (bytes > SSIZE_MAX) ? SSIZE_MAX : bytes;
        rv = skStreamWrite(stream, b, part);
        if (rv != (ssize_t)part) {
            /* error writing */
            saved_errno = skStreamGetLastErrno(stream);
            skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
            TEMPFILE_DEBUG2(
                tmpctx, "Cannot write %" SK_PRIdZ " bytes to stream: %s",
                part, errbuf);
            goto ERROR;
        }
        bytes -= part;
        b += part;
    } while (bytes > 0);

    rv = skStreamClose(stream);
    if (rv) {
        saved_errno = skStreamGetLastErrno(stream);
        skStreamLastErrMessage(stream, rv, errbuf, sizeof(errbuf));
        TEMPFILE_DEBUG1(tmpctx, "Cannot write close stream: %s", errbuf);
        goto ERROR;
    }

    TEMPFILE_DEBUG4(
        tmpctx,
        "Stored %" PRIu64 " bytes as %" PRId64 " bytes (%.3f%%) in '%s'",
        (uint64_t)rec_size * (uint64_t)rec_count,
        skFileSize(skStreamGetPathname(stream)),
        ((double)skFileSize(skStreamGetPathname(stream))
         / (double)rec_size * 100.0 / (uint64_t)rec_count),
        skStreamGetPathname(stream));

    skStreamDestroy(&stream);
    return 0;

  ERROR:
    skStreamDestroy(&stream);
    errno = saved_errno;
    return -1;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
