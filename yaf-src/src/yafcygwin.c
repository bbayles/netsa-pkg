/*
 *  Copyright 2011-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  yafcygwin.c
 *  YAF cygwin
 *
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

/* Microsoft says to define _WIN32_WINNT to get the right
   windows API version, but under Cygwin, you need to define
   WINVER - which are related, (but not the same?).  They
   are believed to be the same under Cygwin */

#ifdef __CYGWIN__
#define _WIN32_WINNT 0x0600
#define WINVER 0x0600
#include <windows.h>
#endif

#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <stdio.h>


#define INITIAL_BUFFER_SIZE     8192
#define BUFFER_INCREMENT_SIZE   4096

/* for testing
#define NETSA_WINDOWSREG_REGHOME        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
#define SILK_WINDOWSREG_DATA_DIR_KEY    "SystemRoot"
*/

/* registry location/key definitions */
#define NETSA_WINDOWSREG_REGHOME        "Software\\CERT\\NetSATools"
#define NETSA_WINDOWSREG_INSTALLDIR_KEY         "InstallDir"
#define SILK_WINDOWSREG_DATA_DIR_KEY            "SilkDataDir"
#define YAF_WINDOWSREG_CONF_DIR_KEY             "YafConfDir"

#define SILK_DEFAULT_CYGWIN_DATA_DIR            "/cygdrive/c/data"

#define CYGWIN_PATH_PREFIX                      "/cygdrive/"

static char *winRegDataDir = NULL;


/**
 * yfCygwinClean
 *
 * frees up allocated memory used as caching within this cygwin module
 * provided for future memory leak testing
 *
 */
void
yfCygwinClean(
    void)
{

    if (NULL != winRegDataDir) {
        free(winRegDataDir);
    }

    return;
}

/**
 *windowsToCygwinPath
 *
 * converts a "normal" windows path "C:\Windows\" into an equivalent
 * cygwin path "/cygdrive/c/Windows/"
 *
 * @note this function creates callee deallocated memory
 *
 * @param winPath a character string containing a windows path
 *
 * @return a malloced string converted into a cygwin path, on error
 *         this function returns NULL
 */
static
char *
windowsToCygwinPath(
    const char *winPath)
{

    char *resultStr = NULL;
    char *resultLoc = NULL;
    const char *workLoc = winPath;

    resultStr = (char *) malloc(strlen(winPath)+strlen(CYGWIN_PATH_PREFIX)+1);
    if (NULL == resultStr) {
        return NULL;
    }
    resultLoc = resultStr;

    /* include the default prefix */
    strcpy(resultLoc, CYGWIN_PATH_PREFIX);
    resultLoc += strlen(CYGWIN_PATH_PREFIX);

    /* first, let's try to find the drive prefix, e.g. c: or d: or z: */
    workLoc = strchr(winPath, ':');
    if (NULL == workLoc) {
        /* it's a relative path, run with it? */
        free(resultStr);
        return NULL;
    }

    /* the character before workLoc should be the drive letter */
    strncpy(resultLoc, (workLoc-1), 1);
    *resultLoc++ = (char) tolower((int)*(workLoc-1));
    workLoc++;

    /* now copy in the rest of the path, converting "\" into "/" */
    while (*workLoc) {
        if ('\\' == *workLoc) {
            *resultLoc = '/';
        } else {
            *resultLoc = *workLoc;
        }
        resultLoc++; workLoc++;
    }

    /* make sure resultLoc is terminated */
    *resultLoc = '\0';

    /* safety check, did we run off the end of resultLoc */
    if ((resultLoc - resultStr) > (strlen(winPath)+strlen(CYGWIN_PATH_PREFIX)+1)) {
        abort();
    }

    /* return the converted string */
    return resultStr;
}



/**
 * yfGetCygwinConfDir
 *
 * Gets the yaf config directory defined at INSTALLATION time on
 * Windows machines via reading the windows registry.
 * Caches the result in a file static.
 *
 * @return constant string with the data directory name
 *
 * @note must call yfCygwinClean to get rid of the memory
 *       for the cached result
 */
const char *
yfGetCygwinConfDir(
    void)
{

    char *dataBuffer = NULL;
    DWORD bufferSize = 0;
    DWORD rc;


    if (NULL != winRegDataDir) {
        return winRegDataDir;
    }

    /* allocate memory for the initial buffer,
       likely this is big enough */
    dataBuffer = (char *) malloc( sizeof(char) * INITIAL_BUFFER_SIZE);
    if (NULL == dataBuffer) {
        /* error couldn't allocate memory */
        return NULL;
    }
    bufferSize = INITIAL_BUFFER_SIZE;

    /* keeping asking the registry for the value until we have
       a buffer big enough to hold it */
    do {
        rc = RegGetValue ( HKEY_LOCAL_MACHINE,
                           NETSA_WINDOWSREG_REGHOME,
                           SILK_WINDOWSREG_DATA_DIR_KEY, RRF_RT_ANY,
                           NULL, (PVOID)dataBuffer, &bufferSize);

        if (ERROR_MORE_DATA == rc) {
            dataBuffer = (char *) realloc(dataBuffer,
                                          (bufferSize + BUFFER_INCREMENT_SIZE));
            if (NULL == dataBuffer) {
                return NULL;
            }
            bufferSize += BUFFER_INCREMENT_SIZE;
        }
    } while ( ERROR_MORE_DATA == rc);

    if ( ERROR_SUCCESS == rc ) {
        if ( 0 == bufferSize ) {
            /* What makes sense to do when we can't find the registry entry?
               In this case, we return a "sane" default for windows
            */
            winRegDataDir = SILK_DEFAULT_CYGWIN_DATA_DIR;
            free(dataBuffer);
            return SILK_DEFAULT_CYGWIN_DATA_DIR;
        } else {
            winRegDataDir = windowsToCygwinPath(dataBuffer);
            free(dataBuffer);
            return winRegDataDir;
        }

    } else {

        return NULL;
    }
}
