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
**  sktempfile.h
**
**    The functions in this file are used to create temporary files.
**    The caller can reference the files by an integer identifier.
**
*/
#ifndef _SKSKTEMPFILE_H
#define _SKSKTEMPFILE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKTEMPFILE_H, "$SiLK: sktempfile.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>


/**
 *  @file
 *
 *    Functions to ease the creation and access of temporary files.
 *
 *    This file is part of libsilk.
 *
 *
 *    skTempFile makes creating and accessing temporary files easier
 *    by allowing the calling application to reference the temporary
 *    files by numeric indexes, where the first temporary file has an
 *    index of 0, the second has an index of 1, and the N'th has an
 *    index of N-1.
 *
 *    The caller uses skTempFileInitialize() to create a new context
 *    object.  This context object must be passed to all other
 *    skTempFile*() functions.
 *
 *    The caller uses skTempFileCreate() to create a new temporary
 *    file and fclose() to close the file.  Alternatively, the caller
 *    can use skTempFileWriteBuffer() to write a buffer into a new
 *    temporary file.  In either case, the file can be re-opened via
 *    skTempFileOpen().
 *
 *    For compressed temporary files, the caller should use
 *    skTempFileCreateStream() to create the stream, skStreamDestroy()
 *    to close and destroy the stream, and skTempFileOpenStream() to
 *    re-open the existing stream.  The helper function
 *    skTempFileWriteBufferStream() writes a buffer of data in a
 *    format readable by skTempFileOpenStream().
 *
 *    The temporary files are not removed until either the
 *    skTempFileRemove() or skTempFileTeardown() functions are
 *    explicitly called.  The user of skTempFiles should add an
 *    atexit() handler and a signal handler that each call
 *    skTempFileTeardown().
 *
 *    Set the SILK_TEMPFILE_DEBUG environment variable to a positive
 *    integer to print debug messages as temp files are created and
 *    removed.
 *
 *
 */


/**
 *    skTempFile context
 */
typedef struct sk_tempfilectx_st sk_tempfilectx_t;


/**
 *    Constant returned by skTempFileGetName() to indicate no file
 *    exists for the given index.
 */
extern const char * const sktempfile_null;


/**
 *    Creates a new skTempFile context object, tmpctx.  The parameters
 *    to this function are passed to skTempDir() which will use
 *    'user_temp_dir' as the temporary directory if that value is
 *    not-NULL, or skTempDir() consults environment variables to find
 *    a suitable temporary directory.
 *
 *    'prefix_name' is used as the file name prefix for files created
 *    in the temporary directory.  If it is NULL, the application name
 *    and process ID are used.
 *
 *    Returns -1 if a temporary directory cannot be found, if the
 *    user's temporary directory does not exist, or on memory
 *    allocation error.
 */
int
skTempFileInitialize(
    sk_tempfilectx_t  **tmpctx,
    const char         *user_temp_dir,
    const char         *prefix_name,
    sk_msg_fn_t         err_fn);

/**
 *    Removes all temporary files, destroys the skTempFile context
 *    object, and sets the 'tmpctx' pointer to NULL.  When 'tmpctx' or
 *    '*tmpctx' is NULL, this function is a no-op.
 */
void
skTempFileTeardown(
    sk_tempfilectx_t  **tmpctx);

/**
 *    Creates and opens a new temporary file.  Returns an open FILE
 *    pointer.  'tmp_idx', which must not be NULL, is set to the index
 *    of the file, which can be used to access the file.  If 'name' is
 *    non-NULL, it is set to point to the name of the file.
 *
 *    Returns NULL if a temporary file cannot be created.  The value
 *    of 'errno' should contain the error that prevented the file from
 *    being created.  A return value of NULL and errno of 0 indicates
 *    either 'tmpctx' or 'tmp_idx' was NULL.
 *
 *    Files created with this function must be opened by calling
 *    skTempFileOpen().
 *
 *    See also skTempFileCreateStream(), skTempFileWriteBuffer().
 */
FILE *
skTempFileCreate(
    sk_tempfilectx_t   *tmpctx,
    int                *tmp_idx,
    char              **name);

/**
 *    Creates and opens a new temporary file.  Returns an skstream
 *    whose record format is FT_TEMPFILE, whose record length is 1,
 *    and that uses compression.  'tmp_idx', which must not be NULL,
 *    is set to the index of the file, which can be used to access the
 *    file.
 *
 *    Returns NULL if a temporary file cannot be created.  The value of
 *    'errno' should contain the error that prevented the file from
 *    being created.  A return value of -1 and errno of 0 indicates
 *    either 'tmpctx' or 'tmp_idx' was NULL.
 *
 *    Files created with this function must be opened by calling
 *    skTempFileOpenStream().
 *
 *    See also skTempFileCreate(), skTempFileWriteBufferStream().
 */
skstream_t *
skTempFileCreateStream(
    sk_tempfilectx_t   *tmpctx,
    int                *tmp_idx);

/**
 *    Returns the name of the file index by 'tmp_idx'.  Returns the
 *    value 'sktempfile_null' if no file is index by 'tmp_idx'.
 */
const char *
skTempFileGetName(
    const sk_tempfilectx_t *tmpctx,
    int                     tmp_idx);

/**
 *    Re-opens the existing temporary file indexed by 'tmp_idx' and
 *    returns a FILE pointer to that file.
 *
 *    This function should only be used to create temporary files
 *    created using skTempFileCreate() or skTempFileWriteBuffer().
 *
 *    Returns NULL if no file is index by 'tmp_idx' or if there is an
 *    error opening the file.  The value of 'errno' should contain the
 *    error that prevented the function from succeeding.  A return
 *    value of NULL and errno of 0 indicates 'tmp_idx' is not known
 *    index.
 *
 *    See also skTempFileOpenStream().
 */
FILE *
skTempFileOpen(
    const sk_tempfilectx_t *tmpctx,
    int                     tmp_idx);

/**
 *    Re-opens the existing temporary file indexed by 'tmp_idx' and
 *    returns an skstream whose record format is FT_TEMPFILE and whose
 *    record length is 1.
 *
 *    This function should only be used to create temporary files
 *    created using skTempFileCreateStream() or
 *    skTempFileWriteBufferStream().
 *
 *    Returns NULL if no file is index by 'tmp_idx' or if there is an
 *    error opening the file.  The value of 'errno' should contain the
 *    error that prevented the function from succeeding.  A return
 *    value of -1 and errno of 0 indicates 'tmp_idx' is not known
 *    index.
 *
 *    See also skTempFileOpen().
 */
skstream_t *
skTempFileOpenStream(
    const sk_tempfilectx_t *tmpctx,
    int                     tmp_idx);

/**
 *    Removes the temporary file indexed by 'tmp_idx'.  Does nothing
 *    if 'tmp_idx' does not exist.
 */
void
skTempFileRemove(
    sk_tempfilectx_t   *tmpctx,
    int                 tmp_idx);

/**
 *    Creates a new temporary file, writes the data from 'buffer' to
 *    the file, and closes the file.  The 'buffer' contains 'count'
 *    elements each 'size' bytes in length.  'tmp_idx', which must not
 *    be NULL, is set to the index of the file.  This index can be
 *    used to access the file.
 *
 *    Returns 0 on success.
 *
 *    Returns -1 if a file could not be created or if there is an
 *    error writing the buffer to the file.  The value of 'errno'
 *    should contain the error that prevented the function from
 *    succeeding.
 *
 *    Files created with this function must be opened by calling
 *    skTempFileOpen().
 */
int
skTempFileWriteBuffer(
    sk_tempfilectx_t   *tmpctx,
    int                *tmp_idx,
    const void         *elem_buffer,
    uint32_t            elem_size,
    uint32_t            elem_count);

/**
 *    Creates a new temporary file for storing a data buffer just as
 *    skTempFileWriteBuffer() does, except the file is written with a
 *    SiLK file header and must be opened with skTempFileOpenStream().
 */
int
skTempFileWriteBufferStream(
    sk_tempfilectx_t   *tmpctx,
    int                *tmp_idx,
    const void         *elem_buffer,
    uint32_t            elem_size,
    uint32_t            elem_count);

#ifdef __cplusplus
}
#endif
#endif  /* _SKSKTEMPFILE_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
