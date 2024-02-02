/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
#ifndef _RWFLOW_UTILS_H
#define _RWFLOW_UTILS_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWFLOW_UTILS_H, "$SiLK: rwflow_utils.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  rwflow_utils.h
**
**    Definitions and prototypes for functions shared between
**    rwflowpack and rwflowappend.
*/

#include <silk/skstream.h>


/*
 *  stream = openRepoStream(repo_file, &out_mode, no_lock, &shut_down_flag);
 *
 *    Either open an existing repository (hourly) data file or create
 *    a new repository file at the location specified by 'repo_file'.
 *    Return the opened stream on success; return NULL on failure.
 *
 *    The location pointed to be 'out_mode' will be set to
 *    SK_IO_APPEND if an existing file was opened, or SK_IO_WRITE if a
 *    new file was opened.
 *
 *    When a file is successfully opened, the function will obtain a
 *    write lock on the file unless the 'no_lock' argument is
 *    non-zero.
 *
 *    The caller must provide the location of the variable that
 *    denotes when the daemon is shutting down in the 'shut_down_flag'
 *    argument.  The function will check this variable while obtaining
 *    the write lock.
 *
 *    For existing files opened for append, the file descriptor is
 *    positioned at the end of the file.  For new files, the file
 *    descriptor is at position 0 and the file is empty.
 */
skstream_t *
openRepoStream(
    const char         *repo_file,
    skstream_mode_t    *out_mode,
    int                 no_lock,
    volatile int       *shut_down_flag);


/*
 *  status = verifyCommandString(command, switch_name);
 *
 *    Verify that the command string specified in 'command' does not
 *    contain unknown conversions.  If 'command' is valid, return 0.
 *
 *    If 'command' is not valid, print an error that 'switch_name' is
 *    invalid and return -1.  If 'switch_name' is NULL, no error is
 *    printed.
 */
int
verifyCommandString(
    const char         *command,
    const char         *switch_name);


/*
 *  runCommand(switch_name, command, file);
 *
 *    Run the command specified in 'command' in a subprocess.  The
 *    string "%s" in 'command' will be replaced by 'filename'.  The
 *    switch_name is used in a debugging log message to report the
 *    command being run.
 */
void
runCommand(
    const char         *switch_name,
    const char         *command,
    const char         *file);


/*
 *  errorDirectorySetPath(directory);
 *
 *    Set 'directory' as the name of the error directory.  Overrides
 *    any previous value.  If 'directory' is NULL, unsets the
 *    error-directory.
 *
 *    The caller should ensure 'directory' is an existing directory
 *    prior to calling this function.
 *
 *    This function simply maintains a pointer to the specified value
 *    'directory'.  The caller should ensure 'directory' is valid
 *    throughout the life of the application.
 */
void
errorDirectorySetPath(
    const char         *directory);


/*
 *  is_set = errorDirectoryIsSet();
 *
 *    Return 1 if an error directory has been specified.  Return 0
 *    otherwise.
 */
int
errorDirectoryIsSet(
    void);


/*
 *  status = errorDirectoryInsertFile(filename);
 *
 *    Move 'filename' to the error-directory.  Return 0 on success.
 *    Return 1 if the error-directory is not set.  Return -1 on error.
 */
int
errorDirectoryInsertFile(
    const char         *filename);


/*
 *  archiveDirectorySetFlat();
 *
 *    On a call to archiveDirectoryInsertOrRemove(), do not create
 *    subdirectories under the archive-directory.
 */
void
archiveDirectorySetFlat(
    void);


/*
 *  archiveDirectorySetPath(directory);
 *
 *    Set 'directory' as the name of the archive directory.  Overrides
 *    any previous value.  If 'directory' is NULL, unsets the
 *    archive-directory.
 *
 *    The caller should ensure 'directory' is an existing directory
 *    prior to calling this function.
 *
 *    This function simply maintains a pointer to the specified value
 *    'directory'.  The caller should ensure 'directory' is valid
 *    throughout the life of the application.
 */
void
archiveDirectorySetPath(
    const char         *directory);


/*
 *  archiveDirectorySetPostCommand(command, switch_name);
 *
 *    Specify 'command' as a command to run on files that get copied
 *    into the archive-directory.  The string "%s" in command will be
 *    replaced with the path to the archived file.  'switch_name' is
 *    used in a debug log message to report that 'command' is being
 *    run.
 */
void
archiveDirectorySetPostCommand(
    const char         *command,
    const char         *switch_name);


/*
 *  archiveDirectorySetNoRemove();
 *
 *    Normally, calling archiveDirectoryInsertOrRemove(f) always
 *    effects the file 'f'.  The file 'f' is either moved into the
 *    archive-directory or 'f' is completely removed if the
 *    archive-directory is not set.  However, if this function has
 *    been called and if archive-directory is not set, the file 'f'
 *    will not be removed.
 */
void
archiveDirectorySetNoRemove(
    void);


/*
 *  is_set = archiveDirectoryIsSet();
 *
 *    Return 1 if an archive directory has been specified.  Return -1
 *    if a post-archive-command has been set but the archive-directory
 *    is not set.  Return 0 if neither an archive-directory nor a
 *    post-archive-command has been specified.
 */
int
archiveDirectoryIsSet(
    void);


/*
 *  status = archiveDirectoryInsertOrRemove(filename, sub_directory);
 *
 *    When an archive-directory has NOT been specified, this function
 *    removes 'filename' (unless archiveDirectorySetNoRemove() was
 *    called) and returns 1.
 *
 *    When an archive-directory has been specified and
 *    archiveDirectorySetFlat() has been called, this function moves
 *    'filename' into the archive-directory itself, regardless of the
 *    value of 'sub_directory'.
 *
 *    When an archive-directory has been specified and
 *    archiveDirectorySetFlat() has NOT been called, this function
 *    moves 'filename' into a subdirectory under the
 *    archive-directory.  If 'sub_directory' is NULL, a subdirectory
 *    based on the current time is created.  Otherwise,
 *    'sub_directory' is treated as being relative to
 *    archive-directory and that subdirectory is created.  Note that
 *    'sub_directory' may contain directory separators.
 *
 *    If a post-archiving command has been specified, that command is
 *    run on the file after is has been copied into the
 *    archive-directory.
 *
 *    If everything succeeds, return 0.  If there is an error creating
 *    a subdirectory or moving a file, this function returns -1.
 *    Errors cased by the post-command are ignored.
 */
int
archiveDirectoryInsertOrRemove(
    const char         *filename,
    const char         *sub_directory);


#ifdef __cplusplus
}
#endif
#endif /* _RWFLOW_UTILS_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
