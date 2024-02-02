/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  privconfig.c
 *  Generic privilege configuration support.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Brian Trammell
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

#define _AIRFRAME_SOURCE_
#include <airframe/privconfig.h>

static char    *opt_user = NULL;
static char    *opt_group = NULL;

static uid_t    new_user = 0;
static gid_t    new_group = 0;

static gboolean did_become = FALSE;

#ifdef  USE_GOPTION
#define AF_OPTION_WRAP "\n\t\t\t\t"
#else
#define AF_OPTION_WRAP " "
#endif

static AirOptionEntry privc_optentries[] = {
    AF_OPTION("become-user", 'U', 0, AF_OPT_TYPE_STRING, &opt_user,
              AF_OPTION_WRAP "Become user after setup if started as root",
              "user"),
    AF_OPTION("become-group", (char)0, 0, AF_OPT_TYPE_STRING, &opt_group,
              AF_OPTION_WRAP "Become group after setup if started as root",
              "group"),
    AF_OPTION_END
};

gboolean
privc_add_option_group(
    AirOptionCtx  *aoctx)
{
    g_assert(aoctx != NULL);

    air_option_context_add_group(
        aoctx, "privilege", "Privilege Options:",
        AF_OPTION_WRAP "Show help for privilege options", privc_optentries);

    return TRUE;
}


gboolean
privc_setup(
    GError **err)
{
    struct passwd *pwe = NULL;
    struct group  *gre = NULL;

    if (geteuid() == 0) {
        /* We're root. Parse user and group names. */
        if (opt_user) {
            if (!(pwe = getpwnam(opt_user))) {
                g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_SETUP,
                            "Cannot become user %s: %s.",
                            opt_user, strerror(errno));
                return FALSE;
            }

            /* By default, become new user's user and group. */
            new_user = pwe->pw_uid;
            new_group = pwe->pw_gid;
            if (opt_group) {
                if (!(gre = getgrnam(opt_group))) {
                    g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_SETUP,
                                "Cannot become group %s: %s.",
                                opt_group, strerror(errno));
                    return FALSE;
                }

                /* Override new group if set */
                new_group = gre->gr_gid;
            }
        }
    } else {
        /* We're not root. If we have options, the user is confused, and
         * we should straighten him out by killing the process. */
        if (opt_user) {
            g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_SETUP,
                        "Cannot become user %s: not root.",
                        opt_user);
            return FALSE;
        }
        if (opt_group) {
            g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_SETUP,
                        "Cannot become group %s: not root.",
                        opt_user);
            return FALSE;
        }
    }

    /* All done. */
    return TRUE;
}


gboolean
privc_configured(
    void)
{
    return (new_user) ? TRUE : FALSE;
}


gboolean
privc_become(
    GError **err)
{
    /* Die if we've already become */
    if (did_become) {
        g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_ALREADY,
                    "not dropping privileges, already did so");
        return FALSE;
    }

    /* Short circuit if we're not root */
    if (geteuid() != 0) {return TRUE;}

    /* Allow app to warn if not dropping */
    if (new_user == 0) {
        g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_NODROP,
                    "not dropping privileges (use --become-user to do so)");
        return FALSE;
    }

    /* Okay. Do the drop. */

    /* Drop ancillary group privileges while we're still root */
    if (setgroups(1, &new_group) < 0) {
        g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_FAILED,
                    "couldn't drop ancillary groups: %s", strerror(errno));
        return FALSE;
    }

#if LINUX_PRIVHACK
    /* Change to group */
    if (setregid(new_group, new_group) < 0) {
        g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_FAILED,
                    "couldn't become group %u: %s", new_group, strerror(errno));
        return FALSE;
    }

    /* Lose root privileges */
    if (setreuid(new_user, new_user) < 0) {
        g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_FAILED,
                    "couldn't become user %u: %s", new_user, strerror(errno));
        return FALSE;
    }
#else /* if LINUX_PRIVHACK */
    /* Change to group */
    if (setgid(new_group) < 0) {
        g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_FAILED,
                    "couldn't become group %u: %s", new_group, strerror(errno));
        return FALSE;
    }

    /* Lose root privileges */
    if (setuid(new_user) < 0) {
        g_set_error(err, PRIVC_ERROR_DOMAIN, PRIVC_ERROR_FAILED,
                    "couldn't become user %u: %s", new_user, strerror(errno));
        return FALSE;
    }
#endif /* if LINUX_PRIVHACK */

    /* All done. */
    did_become = TRUE;
    return TRUE;
}
