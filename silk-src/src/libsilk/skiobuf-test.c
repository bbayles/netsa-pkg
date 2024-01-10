/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
**  Test program for skiobuf.c
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skiobuf-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skstream.h>
#include "skiobuf.h"


static char g_data[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static int datalen;

#define FAIL do {assert(0); skAbort();} while (0)


static char
rval(
    void)
{
    int i = (int)((float)datalen * (rand() / (RAND_MAX + 1.0)));
    return g_data[i];
}

static char *
create_test_data(
    char              **filename,
    unsigned            recsize,
    unsigned            numrecs)
{
    int fd;
    unsigned i, j;
    ssize_t rv;
    off_t   ov;
    char c;
    void *map;
    char *name = strdup("/tmp/skiobuf-test.XXXXXX");
    char *buf;

    fd = mkstemp(name);
    if (fd == -1) {
        FAIL;
    }
    ov = lseek(fd, recsize * numrecs, SEEK_SET);
    if (ov == -1) {
        FAIL;
    }
    rv = write(fd, "", 1);
    if (rv != 1) {
        FAIL;
    }
    map = mmap(0, recsize * numrecs, PROT_READ | PROT_WRITE, MAP_SHARED,
               fd, 0);
    if (map == MAP_FAILED) {
        FAIL;
    }
    close(fd);

    buf = (char *)map;
    for (i = 0; i < numrecs; i++) {
        c = rval();
        for (j = 0; j < recsize; j++) {
            *buf++ = c;
        }
    }

    *filename = name;
    return (char *)map;
}

static void
delete_test_data(
    char               *name,
    char               *data,
    unsigned            recsize,
    unsigned            numrecs)
{
    munmap(data, recsize * numrecs);
    unlink(name);
    free(name);
}

static void
test(
    int                 method,
    char               *data,
    unsigned            recsize,
    unsigned            numrecs,
    uint32_t            blocksize,
    unsigned            skipafter,
    unsigned            skipfor)
{
    char *name = strdup("/tmp/skiobuf-test.XXXXXX");
    int fd;
    sk_iobuf_t *buf = NULL;
    int rv;
    off_t ov;
    unsigned i, j;
    unsigned skip;
    char *p;
    uint32_t i32;
    ssize_t out;
    off_t off;
    char c;
    int skipping;

    fd = mkstemp(name);
    if (fd == -1) {
        FAIL;
    }

    buf = skIOBufCreate(SK_IO_WRITE);
    if (buf == NULL) {
        FAIL;
    }

    rv = skIOBufSetRecordSize(buf, recsize);
    if (rv == -1) {
        FAIL;
    }

    rv = skIOBufSetBlockSize(buf, blocksize);
    if (rv == -1) {
        FAIL;
    }

    rv = skIOBufBind(buf, fd, method);
    if (rv == -1) {
        FAIL;
    }

    /* accept a max limit of 1MB */
    i32 = skIOBufUpperCompBlockSize(buf);
    fprintf(stderr, "%" PRIu32 "\n", i32);
    if (i32 > 1024 * 1024) {
        FAIL;
    }

    p = data;
    for (i = 0; i < numrecs; i++) {
        out = skIOBufWrite(buf, p, recsize);
        if (out != (int)recsize) {
            FAIL;
        }
        p += recsize;
    }
    off = skIOBufFlush(buf);
    if (off == -1) {
        FAIL;
    }

    off = skIOBufTotalUpperBound(buf);
    if (off == -1) {
        FAIL;
    }

    skIOBufDestroy(buf);
    buf = NULL;

    ov = lseek(fd, 0, SEEK_SET);
    if (ov == -1) {
        FAIL;
    }

    buf = skIOBufCreate(SK_IO_READ);
    if (buf == NULL) {
        FAIL;
    }

    rv = skIOBufBind(buf, fd, method);
    if (rv == -1) {
        FAIL;
    }

    p = data;
    skip = 1;
    skipping = 0;
    for (i = 0; i < numrecs; i++) {
        if (skipping) {
            if (skip == skipfor) {
                skip = 1;
                skipping = 0;
            }
        } else {
            if (skip == skipafter) {
                skip = 1;
                skipping = 1;
            }
        }
        for (j = 0; j < recsize; j++) {
            if (skipping) {
                out = skIOBufRead(buf, NULL, 1);
            } else {
                out = skIOBufRead(buf, &c, 1);
            }
            if (out != 1) {
                FAIL;
            }
            if (!skipping && c != *p) {
                FAIL;
            }
            p++;
        }
        skip++;
    }

    out = skIOBufRead(buf, &c, 1);
    if (out != 0) {
        FAIL;
    }

    skIOBufDestroy(buf);
    buf = NULL;

    close(fd);

    unlink(name);
    free(name);
}

int main()
{
    char *testfname;
    char *testfile;

    datalen = strlen(g_data);
    testfile = create_test_data(&testfname, 10, 100000);

    test(SK_COMPMETHOD_NONE, testfile, 10, 100000, SKIOBUF_DEFAULT_BLOCKSIZE,
         0, 0);
    test(SK_COMPMETHOD_NONE, testfile, 10, 100000, 100, 50, 200);
#if SK_ENABLE_ZLIB
    test(SK_COMPMETHOD_ZLIB, testfile, 10, 100000, SKIOBUF_DEFAULT_BLOCKSIZE,
         0, 0);
    test(SK_COMPMETHOD_ZLIB, testfile, 10, 100000, 100, 50, 200);
#endif
#if SK_ENABLE_LZO
    test(SK_COMPMETHOD_LZO1X, testfile, 10, 100000, SKIOBUF_DEFAULT_BLOCKSIZE,
         0, 0);
    test(SK_COMPMETHOD_LZO1X, testfile, 10, 100000, 100, 50, 200);
#endif

    delete_test_data(testfname, testfile, 10, 100000);

    return 0;
}

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
