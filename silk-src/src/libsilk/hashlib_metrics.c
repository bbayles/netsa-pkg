/*
** Copyright (C) 2001-2023 by Carnegie Mellon University.
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

/* File: hashlib_metrics.c: program for generating performance metrics */

#include <silk/silk.h>

RCSIDENT("$SiLK: hashlib_metrics.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/hashlib.h>


/* NOTE: normally these would not be changed by an application.  This
 * program is meant for tweaking of hashlib parameters. */
extern int32_t  SECONDARY_BLOCK_FRACTION;
extern uint32_t REHASH_BLOCK_COUNT;

/* Description of a test to run */
typedef struct TestDesc_st {
    uint8_t  load_factor;
    int32_t  secondary_block_fraction;
    uint32_t rehash_block_count;
    uint32_t num_entries;
    float    estimate_ratio;
} TestDesc;


static double
get_elapsed_secs(
    struct timeval     *start,
    struct timeval     *end)
{
    double start_time = ((double)start->tv_sec
                         + (((double) start->tv_usec) / 1000000));
    double end_time = (double)end->tv_sec + (((double)end->tv_usec) / 1000000);
    return end_time - start_time;
}


/* Run a test */
static HashTable *
do_test(
    TestDesc           *test_ptr)
{
    uint32_t i;
    uint32_t key;
    uint32_t *val_ptr;
    HashTable *table_ptr;
    uint32_t estimate = (uint32_t)(test_ptr->num_entries
                                   * test_ptr->estimate_ratio);
    struct timeval tv1, tv2;


    fprintf(stderr, "frac = %f, num=%u, estimate=%u\n",
            test_ptr->estimate_ratio, test_ptr->num_entries, estimate);

    /* Reconfigure the library */
    SECONDARY_BLOCK_FRACTION = test_ptr->secondary_block_fraction;
    REHASH_BLOCK_COUNT = test_ptr->rehash_block_count;

    fprintf(stderr, " -- BEFORE CREATE TABLE -- \n");
    gettimeofday(&tv1, NULL);

    /* Create the table */
    table_ptr = hashlib_create_table(sizeof(uint32_t),
                                     sizeof(uint32_t),
                                     HTT_INPLACE,  /* values, not pointers */
                                     NULL,         /* all 0 means empty */
                                     NULL, 0,      /* No user data */
                                     estimate,
                                     test_ptr->load_factor);
    gettimeofday(&tv2, NULL);

    fprintf(stderr, " == AFTER create table: ");
    fprintf(stderr, "took %f secs\n", get_elapsed_secs(&tv1,&tv2));

    /* Use the same sequence each time */
    srandom(0);
    for (i=0;i<test_ptr->num_entries;i++) {
      key = random();
      hashlib_insert(table_ptr, (uint8_t*) &key, (uint8_t**) &val_ptr);
      *val_ptr = 1; /* Don't care about value */
    }

    return table_ptr;
}

static double
run_test(
    FILE               *out_fp,
    TestDesc           *test_ptr)
{
#ifdef HASHLIB_RECORD_STATS
    hashlib_stats_t hashlib_stats;
#endif
    struct timeval start_time, end_time;
    double elapsed_time;
    HashTable *table_ptr;

    /* Run the test */
    fprintf(stderr, "Starting run: ");
    /* Print results */
    fprintf(stderr, "%u\t%d\t%u\t%u\t%f\n",
            test_ptr->load_factor,
            test_ptr->secondary_block_fraction,
            test_ptr->rehash_block_count,
            test_ptr->num_entries,
            test_ptr->estimate_ratio);

    gettimeofday(&start_time, NULL);
    table_ptr = do_test(test_ptr);
    gettimeofday(&end_time, NULL);
    elapsed_time = get_elapsed_secs(&start_time, &end_time);

#ifdef HASHLIB_RECORD_STATS
    /* Get the statistics */
    hashlib_get_stats(table_ptr, &hashlib_stats);
#endif

    /* Clean up after the test */
    hashlib_free_table(table_ptr);
    fprintf(stderr, "Run complete: %f seconds elapsed.\n", elapsed_time);

    /* Print results */
    fprintf(out_fp,
            ("%u\t%3.3f\t%" PRIu64 "\t%u\t%d\t%u\t%3.3f"
#ifdef HASHLIB_RECORD_STATS
             "\t%" PRIu64 "\t%" PRIu32 "\t%" PRIu64
             "\t%u\t%" PRIu64 "\t%" PRIu64
#endif
             "\n"),
            test_ptr->num_entries,
            test_ptr->estimate_ratio,
            (uint64_t) (test_ptr->estimate_ratio * test_ptr->num_entries),
            test_ptr->load_factor,
            test_ptr->secondary_block_fraction,
            test_ptr->rehash_block_count,
            elapsed_time
#ifdef HASHLIB_RECORD_STATS
            , hashlib_stats.inserts,
            hashlib_stats.rehashes,
            hashlib_stats.rehash_inserts,
            hashlib_stats.blocks_allocated,
            hashlib_stats.find_entries,
            hashlib_stats.find_collisions
#endif
            );
    fflush(out_fp);

    return elapsed_time;
}


int main()
{
    TestDesc test;
    int32_t fracs[] = { 3, 2, 1, 0, -1, -2 };
    uint32_t block_count[] = {2, 3, 4, 5};
    float ratios[] = { 0.01, 0.125, 0.25, 0.50, 0.75, 0.875, 1.0 };
    uint32_t i, j, k;
    FILE *out_fp;
    FILE *graph_fp;
    double elapsed_time;

    /* Data suitable for graphing, x is ratio, y is time for each set
     * of params */
    graph_fp = fopen("graph.csv", "w");

    /* Write to stdout */
    out_fp = stdout;

    fprintf(out_fp, ("Cnt\tRatio\tEst\tLF\tFrac\tBlks\tTime"
#ifdef HASHLIB_RECORD_STATS
                     "\tIns\tRehsh\tReInst\tAllocs\tFinds\tCollns"
#endif
                     "\n"));
    /* Setup test variables */
    test.load_factor = DEFAULT_LOAD_FACTOR;
    test.num_entries = (1<<20);
    test.num_entries = 419430;

    /* Print column headings for graph file */
    fprintf(graph_fp, "Frac\t(%u,%u)\t", 1, 1);
    for (i = 0; i < sizeof(fracs)/sizeof(fracs[0]); ++i) {
        for (j = 0; j < sizeof(block_count)/sizeof(block_count[0]); ++j) {
            fprintf(graph_fp, "(%d,%u)\t",  fracs[i], block_count[j]);
        }
    }
    fprintf(graph_fp, "\n");

    /* Loop through the different combinations */
    for (k = 0; k < sizeof(ratios)/sizeof(ratios[0]); ++k) {
        test.estimate_ratio = ratios[k];

        /* Baseline: one block */
        test.secondary_block_fraction = 1; /* ignored */
        test.rehash_block_count = 1; /* rehash when full */
        elapsed_time = run_test(out_fp, &test);

        fprintf(graph_fp, "%3.4f\t", test.estimate_ratio);
        fprintf(graph_fp, "%3.4f\t", elapsed_time);

        /* Try different combinations of block sizes & counts */
        for (i = 0; i < sizeof(fracs)/sizeof(fracs[0]); ++i) {
            for (j = 0; j < sizeof(block_count)/sizeof(block_count[0]); ++j) {
                /* Adjust test variables */
                test.secondary_block_fraction = fracs[i];
                test.rehash_block_count = block_count[j];
                elapsed_time = run_test(out_fp, &test);
                fprintf(graph_fp, "%3.3f\t", elapsed_time);
            }
        }
        fprintf(graph_fp, "\n");
        fflush(graph_fp);
    }

    fclose(graph_fp);
    return 1;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
