/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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
**  Test functions for skvector.c
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skvector-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skvector.h>


#define TEST(s)    fprintf(stderr, s "...");
#define RESULT(b)                                                       \
    if ((b)) {                                                          \
        fprintf(stderr, "ok\n");                                        \
    } else {                                                            \
        fprintf(stderr,                                                 \
                "failed at %s:%d (rv=%d, i=%d, sz=%" SK_PRIuZ ")\n",    \
                __FILE__, __LINE__, rv, i, sz);                         \
        exit(EXIT_FAILURE);                                             \
    }

int main(int argc, char **argv)
{
#define ARRAY_SIZE 64
    sk_vector_t *v;
    int i = 0xFFFF;
    int rv = 0xFFFF;
    size_t sz = 0xFFFF;
    int int_array[ARRAY_SIZE];
    int *new_array;
    char char_array[ARRAY_SIZE];
    char c;
    const char *cp;
    size_t len;
    int exhaust_memory = 0;

    if (argc > 1) {
        if (0 == strncmp(argv[1], "--exhaust-memory", strlen(argv[1]))) {
            exhaust_memory = 1;
        } else {
            fprintf(stderr,
                    ("%s [--exhaust-memory]\n"
                     "\tWhen --memory-check given, run test that appends"
                     " elements until memory is exhausted\n"),
                    argv[0]);
            return 1;
        }
    }

    TEST("skVectorNew");
    v = skVectorNew(sizeof(int));
    RESULT(v != NULL);

    TEST("skVectorGetElementSize");
    sz = skVectorGetElementSize(v);
    RESULT(sz == sizeof(int));

    TEST("skVectorGetCapacity");
    sz = skVectorGetCapacity(v);
    RESULT(sz == 0);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 0);

    TEST("skVectorAppendValue");
    i = 100;
    rv = skVectorAppendValue(v, &i);
    RESULT(rv == 0);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 1);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 0);
    RESULT(rv == 0 && i == 100);

    TEST("skVectorGetMultipleValues");
    i = 345;
    sz = skVectorGetMultipleValues(&i, v, 0, 1);
    RESULT(sz == 1 && i == 100);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 1);
    RESULT(rv == -1 && i == 345);

    TEST("skVectorGetMultipleValues");
    i = 345;
    sz = skVectorGetMultipleValues(&i, v, 1, 1);
    RESULT(sz == 0 && i == 345);

    TEST("skVectorClear");
    skVectorClear(v);
    RESULT(1);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 0);
    RESULT(rv == -1 && i == 345);

    TEST("skVectorGetMultipleValues");
    i = 345;
    sz = skVectorGetMultipleValues(&i, v, 0, 1);
    RESULT(sz == 0 && i == 345);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 0);

    TEST("skVectorGetCapacity");
    sz = skVectorGetCapacity(v);
    RESULT(sz != 0);

    TEST("skVectorSetCapacity");
    rv = skVectorSetCapacity(v, 32);
    RESULT(rv == 0);

    TEST("skVectorGetCapacity");
    sz = skVectorGetCapacity(v);
    RESULT(sz == 32);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 0);

    TEST("skVectorSetValue");
    i = 231;
    rv = skVectorSetValue(v, 31, &i);
    RESULT(rv == 0);

    TEST("skVectorSetValue");
    i = 232;
    rv = skVectorSetValue(v, 32, &i);
    RESULT(rv == -1);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 31);
    RESULT(rv == 0 && i == 231);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 32);
    RESULT(rv == -1 && i == 345);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 16);
    RESULT(rv == 0 && i == 0);

    TEST("skVectorGetCapacity");
    sz = skVectorGetCapacity(v);
    RESULT(sz == 32);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 32);

    TEST("skVectorClear");
    skVectorClear(v);
    RESULT(1);

    TEST("skVectorAppendValue");
    for (sz = 0, i = 99; sz < 38; ++sz, ++i) {
        if (0 != skVectorAppendValue(v, &i)) {
            fprintf(stderr, "FAILED: skVectorAppendValue(v, %d)\n", i);
            RESULT(0);
        }
    }
    RESULT(1);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 38);

    TEST("skVectorRemoveValue");
    i = 345;
    rv = skVectorRemoveValue(v, 1, &i);
    RESULT(rv == 0 && i == 100);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 37);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 0);
    RESULT(rv == 0 && i == 99);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 1);
    RESULT(rv == 0 && i == 101);

    TEST("skVectorInsertValue");
    i = 100;
    rv = skVectorInsertValue(v, 1, &i);
    RESULT(rv == 0);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 38);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 0);
    RESULT(rv == 0 && i == 99);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 2);
    RESULT(rv == 0 && i == 101);

    TEST("skVectorRemoveValue");
    rv = skVectorRemoveValue(v, 0, NULL);
    RESULT(rv == 0);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 37);

    TEST("skVectorRemoveValue");
    i = 345;
    rv = skVectorRemoveValue(v, 37, &i);
    RESULT(rv == -1 && i == 345);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 37);

    TEST("skVectorRemoveValue");
    i = 345;
    rv = skVectorRemoveValue(v, 36, &i);
    RESULT(rv == 0 && i == 136);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 36);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 36);
    RESULT(rv == -1 && i == 345);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 35);
    RESULT(rv == 0 && i == 135);

    TEST("skVectorInsertValue");
    i = 136;
    rv = skVectorInsertValue(v, 36, &i);
    RESULT(rv == 0);

    TEST("skVectorGetValue");
    for (sz = 0; sz < 37; ++sz) {
        i = 345;
        rv = skVectorGetValue(&i, v, sz);
        if (0 != rv || i != (int)(100+sz)) {
            fprintf(stderr,
                    "FAILED: skVectorGetValue(&i, v, %d) rv = %d, i = %d\n",
                    (int)sz, rv, i);
            RESULT(0);
        }
    }
    RESULT(1);

    for (i = 0; i < ARRAY_SIZE; ++i) {
        int_array[i] = 345;
    }
    TEST("skVectorToArray");
    skVectorToArray(&int_array, v);
    for (i = 0; i < 37; ++i) {
        if (int_array[i] != 100+i) {
            fprintf(stderr,
                    "FAILED: int_array[%d] != %d\n",
                    i, i+100);
            RESULT(0);
        }
    }
    for (; i < ARRAY_SIZE; ++i) {
        if (int_array[i] != 345) {
            fprintf(stderr,
                    "FAILED: int_array[%d] != %d\n",
                    i, 345);
            RESULT(0);
        }
    }
    RESULT(1);

    TEST("skVectorToArrayAlloc");
    new_array = (int*)skVectorToArrayAlloc(v);
    if (new_array == NULL) {
        fprintf(stderr,
                "FAILED: new_array is NULL\n");
        RESULT(0);
    }
    for (i = 0; i < 37; ++i) {
        if (new_array[i] != 100+i) {
            fprintf(stderr,
                    "FAILED: new_array[%d] != %d\n",
                    i, i+100);
            RESULT(0);
        }
    }
    RESULT(1);
    free(new_array);

    for (i = 0; i < ARRAY_SIZE; ++i) {
        int_array[i] = 345;
    }
    TEST("skVectorGetMultipleValues");
    sz = skVectorGetMultipleValues(&int_array, v, 10, 10);
    if (sz != 10) {
        fprintf(stderr,
                ("FAILED: skVectorGetMultipleValues(&int_array, v, 10, 10)"
                 " sz = %" SK_PRIuZ "\n"),
                sz);
        RESULT(0);
    }
    for (i = 0; i < 10; ++i) {
        if (int_array[i] != 100+10+i) {
            fprintf(stderr,
                    "FAILED: int_array[%d] != %d\n",
                    i, i+10+100);
            RESULT(0);
        }
    }
    for (; i < ARRAY_SIZE; ++i) {
        if (int_array[i] != 345) {
            fprintf(stderr,
                    "FAILED: int_array[%d] != %d\n",
                    i, 345);
            RESULT(0);
        }
    }
    RESULT(1);

    for (i = 0; i < ARRAY_SIZE; ++i) {
        int_array[i] = 345;
    }
    TEST("skVectorGetMultipleValues");
    sz = skVectorGetMultipleValues(&int_array, v, 30, 10);
    if (sz != 7) {
        fprintf(stderr,
                ("FAILED: skVectorGetMultipleValues(&int_array, v, 30, 10)"
                 " sz = %" SK_PRIuZ "\n"),
                sz);
        RESULT(0);
    }
    for (i = 0; i < 7; ++i) {
        if (int_array[i] != 100+30+i) {
            fprintf(stderr,
                    "FAILED: int_array[%d] != %d\n",
                    i, i+30+100);
            RESULT(0);
        }
    }
    for (; i < ARRAY_SIZE; ++i) {
        if (int_array[i] != 345) {
            fprintf(stderr,
                    "FAILED: int_array[%d] != %d\n",
                    i, 345);
            RESULT(0);
        }
    }
    RESULT(1);

    TEST("skVectorClear");
    skVectorClear(v);
    RESULT(1);

    TEST("skVectorGetValue");
    i = 345;
    rv = skVectorGetValue(&i, v, 36);
    RESULT(rv == -1 && i == 345);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 0);

    TEST("skVectorDestroy");
    skVectorDestroy(v);
    RESULT(1);

    v = NULL;

    TEST("skVectorClear");
    skVectorClear(v);
    RESULT(1);

    TEST("skVectorDestroy");
    skVectorDestroy(v);
    RESULT(1);

    TEST("skVectorNew");
    v = skVectorNew(sizeof(int));
    RESULT(v != NULL);

    TEST("skVectorSetCapacity");
    rv = skVectorSetCapacity(v, 32);
    RESULT(rv == 0);

    TEST("skVectorGetCapacity");
    sz = skVectorGetCapacity(v);
    RESULT(sz == 32);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 0);

    TEST("skVectorSetCapacity");
    rv = skVectorSetCapacity(v, 0);
    RESULT(rv == 0);

    TEST("skVectorGetCapacity");
    sz = skVectorGetCapacity(v);
    RESULT(sz == 0);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == 0);

    TEST("skVectorSetCapacity");
    rv = skVectorSetCapacity(v, 16);
    RESULT(rv == 0);

    TEST("skVectorGetCapacity");
    sz = skVectorGetCapacity(v);
    RESULT(sz == 16);

    TEST("skVectorDestroy");
    skVectorDestroy(v);
    RESULT(1);

    v = NULL;
    strncpy(char_array, "text", sizeof(char_array));
    len = 1+strlen(char_array);

    TEST("skVectorNewFromArray");
    v = skVectorNewFromArray(sizeof(char_array[0]), char_array, len);
    RESULT(v != NULL);

    memset(char_array, 0, ARRAY_SIZE);

    TEST("skVectorGetCount");
    sz = skVectorGetCount(v);
    RESULT(sz == len);

    TEST("skVectorGetCapacity");
    sz = skVectorGetCapacity(v);
    RESULT(sz == len);

    TEST("skVectorSetValue");
    c = 'n';
    rv = skVectorSetValue(v, 0, &c);
    RESULT(rv == 0);

    TEST("skVectorToArray");
    skVectorToArray(char_array, v);
    RESULT(rv == 0 && (0 == strcmp("next", char_array)));

    TEST("skVectorClear");
    skVectorClear(v);
    RESULT(1);

    cp = "test";
    len = strlen(cp);
    TEST("skVectorAppendFromArray");
    rv = skVectorAppendFromArray(v, cp, len);
    RESULT(rv == 0);

    TEST("skVectorToArray");
    skVectorToArray(char_array, v);
    RESULT(rv == 0 && (0 == strncmp("test", char_array, len)));

    TEST("skVectorAppendFromArray");
    rv = skVectorAppendFromArray(v, cp, len + 1);
    RESULT(rv == 0);

    TEST("skVectorToArray");
    skVectorToArray(char_array, v);
    RESULT(rv == 0 && (0 == strcmp("testtest", char_array)));

    TEST("skVectorDestroy");
    skVectorDestroy(v);
    RESULT(1);

    v = NULL;

    if (exhaust_memory) {
        /*
         * this sets of tests adds objects to the array until we run
         * out of memory.  The objects' size is BIG_NUMBER, and we set
         * the initial vector capacity to BIG_NUMBER as well.
         */
#define BIG_NUMBER  1024

        typedef struct big_object_st {
            uint64_t  count;
            uint8_t   space[BIG_NUMBER - sizeof(uint64_t)];
        } big_object_t;

        big_object_t obj;

        memset(&obj, 0, sizeof(big_object_t));

        TEST("skVectorNew");
        v = skVectorNew(sizeof(big_object_t));
        RESULT(v != NULL);

        TEST("skVectorGetElementSize");
        sz = skVectorGetElementSize(v);
        RESULT(sz == BIG_NUMBER);

        TEST("skVectorSetCapacity");
        rv = skVectorSetCapacity(v, BIG_NUMBER);
        RESULT(rv == 0);

        TEST("skVectorGetCapacity");
        sz = skVectorGetCapacity(v);
        RESULT(sz == BIG_NUMBER);

        TEST("skVectorAppendValue");
        obj.count = 1;
        rv = skVectorAppendValue(v, &obj);
        RESULT(rv == 0);

        TEST("Appending objects until memory exhausted");
        while (rv == 0) {
            ++obj.count;
            rv = skVectorAppendValue(v, &obj);
        }
        RESULT(rv == -1);

        TEST("skVectorGetCapacity");
        sz = skVectorGetCapacity(v);
        RESULT(1);

        fprintf(stderr, ("Memory exhausted after adding %" PRIu64
                         " objects and capacity of %" SK_PRIuZ "\n"),
                obj.count, sz);

        TEST("skVectorDestroy");
        skVectorDestroy(v);
        RESULT(1);

        v = NULL;
    }

    return 0;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
