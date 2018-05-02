/*
 ** autoinc.h
 ** Autotools-happy standard library include file
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2005-2018 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the fixbuf system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** Copyright 2018 Carnegie Mellon University. All Rights Reserved.
 **
 ** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
 ** ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
 ** BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
 ** EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
 ** EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
 ** MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 ** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
 ** COPYRIGHT INFRINGEMENT.
 **
 ** Released under a GNU-Lesser GPL 3.0-style license, please see
 ** License.txt or contact permission@sei.cmu.edu for full terms.
 **
 ** [DISTRIBUTION STATEMENT A] This material has been approved for
 ** public release and unlimited distribution.  Please see Copyright
 ** notice for non-US Government use and distribution.
 **
 ** Carnegie Mellon® and CERT® are registered in the U.S. Patent and
 ** Trademark Office by Carnegie Mellon University.
 **
 ** @OPENSOURCE_HEADER_END@
 ** ------------------------------------------------------------------------
 */

/** @file
 *  Convenience include file for libfixbuf.
 */

#ifndef _FIX_AUTOINC_H_
#define _FIX_AUTOINC_H_

#ifdef _FIXBUF_SOURCE_
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <glib.h>
#if GLIB_CHECK_VERSION(2,6,0)
#  include <glib/gstdio.h>
#else
#define g_debug(...)    g_log (G_LOG_DOMAIN,         \
                               G_LOG_LEVEL_DEBUG,    \
                               __VA_ARGS__)
#endif

#ifdef _FIXBUF_SOURCE_
#if !GLIB_CHECK_VERSION(2,10,0)
#define g_slice_new0(_t_) g_new0(_t_, 1)
#define g_slice_alloc0(_s_) g_malloc0(_s_)
#define g_slice_alloc(_s_) g_malloc(_s_)
#define g_slice_new(_t_) g_new(_t_, 1)
#define g_slice_free(_t_, _p_) g_free(_p_)
#define g_slice_free1(_s_, _p_) g_free(_p_)
#endif
#endif

#if HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#endif

#if FB_ENABLE_SCTP
#if FB_INCLUDE_SCTP_H
#include <netinet/sctp.h>
#endif
#if FB_INCLUDE_SCTP_UIO_H
#include <netinet/sctp_uio.h>
#endif
#endif

#endif
