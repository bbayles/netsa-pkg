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
#ifndef _RWIPA_H
#define _RWIPA_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_RWIPA_H, "$SiLK: rwipa.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/iptree.h>
#include <silk/skbag.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/skprefixmap.h>
#include <silk/sksite.h>
#include <silk/skstream.h>
#include <silk/utils.h>

#ifdef __cplusplus
extern "C" {
#endif

SK_DIAGNOSTIC_IGNORE_PUSH("-Wundef")
SK_DIAGNOSTIC_IGNORE_PUSH("-Wwrite-strings")

#include <ipa/ipa.h>

SK_DIAGNOSTIC_IGNORE_POP("-Wwrite-strings")
SK_DIAGNOSTIC_IGNORE_POP("-Wundef")

#ifdef __cplusplus
}
#endif

char *
get_ipa_config(
    void);

#ifdef __GNUC__
/* quiet warnings about unused variables symbols_main_p,
 * symbols_find_p, and symbols_none_p in ipa/ipa.h */

__attribute__((__unused__))
static int
quiet_unused_var_warnings(
    void)
{
    return ((int)symbols_main_p->symbol_token
            + (int)symbols_find_p->symbol_token
            + (int)symbols_none_p->symbol_token);
}
#endif  /* __GNUC__ */

#ifdef __cplusplus
}
#endif
#endif /* _RWIPA_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
