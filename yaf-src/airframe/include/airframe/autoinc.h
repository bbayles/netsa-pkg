/*
** autoinc.h
** Autotools-happy standard library include file
**
** ------------------------------------------------------------------------
** Copyright (C) 2005-2023 Carnegie Mellon University. All Rights Reserved.
** ------------------------------------------------------------------------
** Authors: Brian Trammell
** ------------------------------------------------------------------------
** GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
** Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
** ------------------------------------------------------------------------
*/

/** @file
 *  Convenience include file for libairframe.
 */

#ifndef _AIR_AUTOINC_H_
#define _AIR_AUTOINC_H_

#ifdef _AIRFRAME_SOURCE_
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#endif

#include <stdio.h>

#if     HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

#if     STDC_HEADERS
#  include <stdlib.h>
#  include <stddef.h>
#else
#  if   HAVE_STDLIB_H
#    include <stdlib.h>
#  endif
#  if   HAVE_MALLOC_H
#    include <malloc.h>
#  endif
#endif /* if     STDC_HEADERS */

#if     HAVE_STRING_H
#  if   !STDC_HEADERS && HAVE_MEMORY_H
#    include <memory.h>
#  endif
#  include <string.h>
#endif /* if     HAVE_STRING_H */

#if     HAVE_INTTYPES_H
#  include <inttypes.h>
#else
#  if   HAVE_STDINT_H
#    include <stdint.h>
#  endif
#endif /* if     HAVE_INTTYPES_H */

#if     HAVE_UNISTD_H
#  include <unistd.h>
#endif
#if     HAVE_STDARG_H
#  include <stdarg.h>
#endif

#if     HAVE_ERRNO_H
#  include <errno.h>
#endif

#if     HAVE_FCNTL_H
#  include <fcntl.h>
#endif

#if     HAVE_NETDB_H
#  include <netdb.h>
#endif

#if     HAVE_SIGNAL_H
#  include <signal.h>
#endif

#if     HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif

#if     HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#if     HAVE_SYSLOG_H
#  include <syslog.h>
#endif

#if     HAVE_GLOB_H
#  include <glob.h>
#endif

#if     TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  if   HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif /* if     TIME_WITH_SYS_TIME */

#if     HAVE_DIRENT_H
#  include <dirent.h>
#else
#  define dirent direct
#  if   HAVE_SYS_NDIR_H
#    include <sys/ndir.h>
#  endif
#  if   HAVE_SYS_DIR_H
#    include <sys/dir.h>
#  endif
#  if   HAVE_NDIR_H
#    include <ndir.h>
#  endif
#endif /* if     HAVE_DIRENT_H */

#if     HAVE_SYS_WAIT_H
#  include <sys/wait.h>
#endif

#if     HAVE_PWD_H
#  include <pwd.h>
#endif

#if     HAVE_GRP_H
#  include <grp.h>
#endif

#include <glib.h>

#if HAVE_PCAP_H
#include <pcap.h>
#endif

#if WITH_DMALLOC
#include <dmalloc.h>
#endif

#endif /* ifndef _AIR_AUTOINC_H_ */
