/*
** Copyright (C) 2011-2023 by Carnegie Mellon University.
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
**  skcygwin.h
**
**    Support for getting the default SiLK Data Root directory from
**    the Windows Registry
**
**    July 2011
**
*/
#ifndef _SKCYGWIN_H
#define _SKCYGWIN_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKCYGWIN_H, "$SiLK: skcygwin.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#ifdef __CYGWIN__

/* registry location/key definitions */
#ifndef  NETSA_WINDOWSREG_REGHOME
#ifndef  SK_CYGWIN_TESTING

#define NETSA_WINDOWSREG_REGHOME        "Software\\CERT\\NetSATools"
#define SILK_WINDOWSREG_DATA_DIR_KEY    "SilkDataDir"
#define SILK_WINDOWSREG_DATA_DIR_KEY_PATH                               \
    (NETSA_WINDOWSREG_REGHOME "\\" SILK_WINDOWSREG_DATA_DIR_KEY)

#else  /* SK_CYGWIN_TESTING */

/* values for testing the code without having to modify registry */

#define NETSA_WINDOWSREG_REGHOME                        \
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
#define SILK_WINDOWSREG_DATA_DIR_KEY  "SystemRoot"
#define SILK_WINDOWSREG_DATA_DIR_KEY_PATH                               \
    (NETSA_WINDOWSREG_REGHOME "\\" SILK_WINDOWSREG_DATA_DIR_KEY)

#endif  /* SK_CYGWIN_TESTING */
#endif  /* NETSA_WINDOWSREG_REGHOME */


/**
 *  skCygwinGetDataRootDir
 *
 *    Gets the data directory defined at INSTALLATION time on Windows
 *    machines via reading the windows registry.  Caches the result in
 *    a file static.
 *
 *    @param buf a character buffer to be filled with the directory
 *
 *    @param bufsize the size of the buffer
 *
 *    @return a pointer to buf is returned on success; on error this
 *    function returns NULL
 *
 *    @note must call skCygwinClean to get rid of the memory for the
 *    cached result
 */
const char *
skCygwinGetDataRootDir(
    char               *buf,
    size_t              bufsize);

#endif /* __CYGWIN__ */
#ifdef __cplusplus
}
#endif
#endif /* _SKCYGWIN_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
