dnl Copyright (C) 2004-2023 by Carnegie Mellon University.
dnl
dnl @OPENSOURCE_LICENSE_START@
dnl
dnl SiLK 3.22.0
dnl
dnl Copyright 2023 Carnegie Mellon University.
dnl
dnl NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
dnl INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
dnl UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
dnl AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
dnl PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
dnl THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
dnl ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
dnl INFRINGEMENT.
dnl
dnl Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
dnl contact permission@sei.cmu.edu for full terms.
dnl
dnl [DISTRIBUTION STATEMENT A] This material has been approved for public
dnl release and unlimited distribution.  Please see Copyright notice for
dnl non-US Government use and distribution.
dnl
dnl GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
dnl
dnl Contract No.: FA8702-15-D-0002
dnl Contractor Name: Carnegie Mellon University
dnl Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
dnl
dnl The Government's rights to use, modify, reproduce, release, perform,
dnl display, or disclose this software are restricted by paragraph (b)(2) of
dnl the Rights in Noncommercial Computer Software and Noncommercial Computer
dnl Software Documentation clause contained in the above identified
dnl contract. No restrictions apply after the expiration date shown
dnl above. Any reproduction of the software or portions thereof marked with
dnl this legend must also reproduce the markings.
dnl
dnl Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
dnl Trademark Office by Carnegie Mellon University.
dnl
dnl This Software includes and/or makes use of Third-Party Software each
dnl subject to its own license.
dnl
dnl DM23-0973
dnl
dnl @OPENSOURCE_LICENSE_END@

dnl RCSIDENT("$SiLK: ax_check_pthread.m4 b2b562f1ea39 2023-02-20 17:50:25Z mthomas $")


# ---------------------------------------------------------------------------
# AX_CHECK_PTHREAD
#
#    Determine how to use pthreads.  In addition, determine whether
#    pthreads supports read/write locks.
#
#    Output variables: PTHREAD_LDFLAGS
#    Output definition: HAVE_PTHREAD_RWLOCK
#
AC_DEFUN([AX_CHECK_PTHREAD],[
    AC_SUBST(PTHREAD_LDFLAGS)

    AC_MSG_CHECKING([for pthread linker flags])

    # cache current LIBS
    sk_save_LIBS="$LIBS"

    # pthreads requires libexc on OSF/1 or TruUNIX or Tru64 or
    # whatever it is called by DEC or Compaq or HP or whatever they
    # are calling themselves now

    for sk_pthread in "X" "X-pthread" "X-lpthread" "X-lpthread -lexc"
    do
        sk_pthread=`echo $sk_pthread | sed 's/^X//'`
        LIBS="$sk_pthread $sk_save_LIBS"

        # This is a RUN because Solaris will successfully link the
        # program and just leave out the pthread calls!
        AC_RUN_IFELSE([
            AC_LANG_PROGRAM([
#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_PTHREAD_H
#include <pthread.h>
#endif

static void *dummy(void *v)
{
  return v;
}
                ],[
pthread_t p;
int x = 0;
void *xp = NULL;

pthread_create(&p, NULL, dummy, &x);
pthread_join(p, &xp);
if (xp != &x) return 1;
])],[
            PTHREAD_LDFLAGS="$sk_pthread"
            if test "x$sk_pthread" = "x"
            then
                AC_MSG_RESULT([none required])
            else
                AC_MSG_RESULT([$PTHREAD_LDFLAGS])
            fi
            break])
    done


    AC_MSG_CHECKING([for pthread read/write locks])

    # add pthread library to the saved LIBS
    LIBS="$PTHREAD_LDFLAGS $sk_save_LIBS"

    # This is a RUN because Solaris will successfully link the
    # program and just leave out the pthread calls!
    AC_RUN_IFELSE([
        AC_LANG_PROGRAM([
#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_PTHREAD_H
#include <pthread.h>
#endif
#define FAILIF(x) ++test; if (x) { fprintf(stderr, "Failed test %d (%s) (rv = %d) on line %d\n", test, #x, rv, __LINE__); return 1; }
            ],[
    pthread_rwlock_t lock;
    int rv;
    int test;
    test = 0;
    rv = pthread_rwlock_init(&lock, NULL);
    FAILIF(rv != 0);
    rv = pthread_rwlock_tryrdlock(&lock);
    FAILIF(rv != 0);
    rv = pthread_rwlock_trywrlock(&lock);
    FAILIF(rv != EBUSY);
    rv = pthread_rwlock_tryrdlock(&lock);
    FAILIF(rv != 0);
    rv = pthread_rwlock_trywrlock(&lock);
    FAILIF(rv != EBUSY);
    rv = pthread_rwlock_unlock(&lock);
    FAILIF(rv != 0);
    rv = pthread_rwlock_trywrlock(&lock);
    FAILIF(rv != EBUSY);
    rv = pthread_rwlock_unlock(&lock);
    FAILIF(rv != 0);
    rv = pthread_rwlock_trywrlock(&lock);
    FAILIF(rv != 0);
    rv = pthread_rwlock_tryrdlock(&lock);
    FAILIF(rv != EDEADLK && rv != EBUSY);
    rv = pthread_rwlock_trywrlock(&lock);
    FAILIF(rv != EDEADLK && rv != EBUSY);
    rv = pthread_rwlock_unlock(&lock);
    FAILIF(rv != 0);
    rv = pthread_rwlock_tryrdlock(&lock);
    FAILIF(rv != 0);
    rv = pthread_rwlock_unlock(&lock);
    FAILIF(rv != 0);
    rv = pthread_rwlock_destroy(&lock);
    FAILIF(rv != 0);
    return 0;
            ])],[
           AC_MSG_RESULT([yes])
           AC_DEFINE([HAVE_PTHREAD_RWLOCK], 1,
                     [Define to 1 if your system has working pthread read/write locks])
            ],[
           AC_MSG_RESULT([no])
        ])

    # restore libs
    LIBS="$sk_save_LIBS"
])# AX_CHECK_PTHREAD



AC_DEFUN([AX_CHECK_PTHREAD_ATFORK],[
    AC_REQUIRE([AX_CHECK_PTHREAD])

    AC_MSG_CHECKING([for pthread_atfork()])

    # cache current LIBS
    sk_save_LIBS="$LIBS"

    # add pthread library to the saved LIBS
    LIBS="$PTHREAD_LDFLAGS $sk_save_LIBS"

    # This is a RUN because Solaris will successfully link the
    # program and just leave out the pthread calls!
    AC_RUN_IFELSE([
        AC_LANG_PROGRAM([
#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_PTHREAD_H
#include <pthread.h>
#endif
#define FAILIF(x) ++test; if (x) { fprintf(stderr, "Failed test %d (%s) (rv = %d) on line %d\n", test, #x, rv, __LINE__); return 1; }

pthread_mutex_t lock;

void sk_lock(void) { pthread_mutex_lock(&lock); }

void sk_unlock(void) { pthread_mutex_unlock(&lock); }
            ],[
    int rv;
    int pid;
    int test;
    test = 0;
    rv = pthread_mutex_init(&lock, NULL);
    FAILIF(rv != 0);
    rv = pthread_atfork(sk_lock, sk_unlock, sk_unlock);
    FAILIF(rv != 0);
    pid = fork();
    rv = pthread_mutex_destroy(&lock);
    FAILIF(rv != 0);
#if HAVE_SYS_WAIT_H
    if (pid > 0) {
        waitpid(pid, NULL, 0);
    }
#endif
    return 0;
            ])],[
           AC_MSG_RESULT([yes])
           AC_DEFINE([HAVE_PTHREAD_ATFORK], 1,
                     [Define to 1 if your system has working a pthread_atfork() function])
            ],[
           AC_MSG_RESULT([no])
        ])

    # restore libs
    LIBS="$sk_save_LIBS"
])



dnl Local Variables:
dnl mode:autoconf
dnl indent-tabs-mode:nil
dnl End:
