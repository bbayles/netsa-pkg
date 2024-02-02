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

#include <silk/silk.h>

RCSIDENT("$SiLK: skstringmap-test.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skstringmap.h>

static void
test_string(
    sk_dllist_t            *name_id_map,
    const char             *user_input,
    sk_stringmap_status_t   desired_parse_status,
    size_t                  desired_count);

static void
test_get_by_name(
    sk_stringmap_t     *name_id_map);

static void
test_get_by_id(
    sk_stringmap_t     *name_id_map);

static const char *status_string(sk_stringmap_status_t st);


int main()
{
    int i;
    const char *s;
    sk_stringmap_status_t err;
    sk_stringmap_t *name_id_map;
    sk_stringmap_entry_t add_entry;
    sk_stringmap_entry_t a_few_ids[] = {
        { "foo", 1, NULL, NULL },
        { "bar", 2, NULL, NULL }
    };

    sk_stringmap_entry_t a_few_more_ids[] = {
        { "baZ", 3, NULL, NULL },
        { "foo", 1, NULL, NULL },
        { "2", 3, NULL, NULL },
        { "3", 4, NULL, NULL },
        { "4", 5, NULL, NULL },
        { "5", 6, NULL, NULL },
        { "bar", 2, NULL, NULL },
        { "food", 4, NULL, NULL },
        { "bar-baz", 5, NULL, NULL },
        { "101", 101, NULL, NULL },
        { "suM", 45, NULL, NULL }
    };

    sk_stringmap_entry_t remove_these_ids[] = {
        { "2", 3, NULL, NULL },
        { "bar", 2, NULL, NULL }
    };

    struct {
        const char *name;
        int         count;
    } parseable[] = {
        {"foo", 1},
        {"foo,bar", 2},
        {",,,foo,,,,bar,,,,baz,,,,", 3},
        {"bar,foo", 2},
        {"foo,2", 2},
        {"2", 1},
        {"2-2", 1},
        {"2,2", 2},
        {"2-3", 2},
        {"2-4", 3},
        {"2-5", 4},
        {"4-5", 2},
        {"3-4", 2},
        {"sum", 1},
        {"suM", 1},
        {"su",  1},
        {"foo,foo,foo", 3},
        {NULL, 0}
    };

    const char *ambiguous[] = {
        "ba",
        "fo",
        NULL
    };

    const char *no_match[] = {
        "a",
        "1",
        "1,2",
        /* big number isn't parsed as a number by itself */
        "75984752347525734798875759887523794753927734927",
        "1-3",
        "2-6",
        "foo-bar",
        "1-3,foo",
        "foo,1-1",
        NULL
    };

    const char *unparseable[] = {
        "2-1",
        "foo,2-1",
        "1jjh-5000",
        "1-2-3-4",
        /* big number as part of a range is parsed as a number */
        "1-75984752347525734798875759887523794753927734927",
        "1--3",
        "2-",
        "-3",
        "5,2-,-3,4",
        NULL
    };


    err = skStringMapCreate(&name_id_map);
    if (err != SKSTRINGMAP_OK) {
        printf("error allocating list\n");
    }

    s = "baz";
    memset(&add_entry, 0, sizeof(add_entry));
    add_entry.name = s;
    add_entry.id = 3;
    err = skStringMapAddEntries(name_id_map, 1, &add_entry);
    if (err != SKSTRINGMAP_OK) {
        printf("error %d (%s) adding '%s' to\n\t",
               err, status_string(err), s);
        skStringMapPrintMap(name_id_map, stdout);
        printf("\n");
    }

    err = skStringMapAddEntries(name_id_map,
                                sizeof(a_few_ids)/sizeof(a_few_ids[0]),
                                a_few_ids);
    if (err != SKSTRINGMAP_OK) {
        printf("error %d (%s) adding list of a_few_ids to\n\t",
               err, status_string(err));
        skStringMapPrintMap(name_id_map, stdout);
        printf("\n");
    }

    s = "2";
    memset(&add_entry, 0, sizeof(add_entry));
    add_entry.name = s;
    add_entry.id = 8;
    err = skStringMapAddEntries(name_id_map, 1, &add_entry);
    if (err != SKSTRINGMAP_OK) {
        printf("error %d (%s) adding '%s' to\n\t",
               err, status_string(err), s);
        skStringMapPrintMap(name_id_map, stdout);
        printf("\n");
    }

    /* try dup */
    memset(&add_entry, 0, sizeof(add_entry));
    add_entry.id = 3;
    err = skStringMapAddEntries(name_id_map, 1, &add_entry);
    if (err != SKSTRINGMAP_OK) {
        printf("correctly got error %d (%s) adding '%s' to\n\t",
               err, status_string(err), s);
        skStringMapPrintMap(name_id_map, stdout);
        printf("\n");
    }

    s = "-cow";
    memset(&add_entry, 0, sizeof(add_entry));
    add_entry.name = s;
    add_entry.id = 6;
    err = skStringMapAddEntries(name_id_map, 1, &add_entry);
    if (err != SKSTRINGMAP_OK) {
        printf("correctly got error %d (%s) adding '%s' to\n\t",
               err, status_string(err), s);
        skStringMapPrintMap(name_id_map, stdout);
        printf("\n");
    }

    s = "35x";
    memset(&add_entry, 0, sizeof(add_entry));
    add_entry.name = s;
    add_entry.id = 7;
    err = skStringMapAddEntries(name_id_map, 1, &add_entry);
    if (err != SKSTRINGMAP_OK) {
        printf("correctly got error %d (%s) adding '%s' to\n\t",
               err, status_string(err), s);
        skStringMapPrintMap(name_id_map, stdout);
        printf("\n");
    }

    /* test removing items */
    printf("list should have "
           "{ \"baz\", \"foo\", \"bar\", \"2\" } \n\t");
    skStringMapPrintMap(name_id_map, stdout);
    printf("\n\n");

    skStringMapRemoveByName(name_id_map, "foo");

    printf("list should have "
           "{ \"baz\", \"bar\", \"2\" }\n\t");
    skStringMapPrintMap(name_id_map, stdout);
    printf("\n\n");

    if (skStringMapRemoveEntries(name_id_map,
                                 (sizeof(remove_these_ids)
                                  / sizeof(remove_these_ids[0])),
                                 remove_these_ids)
        != SKSTRINGMAP_OK)
    {
        printf("error removing list of ids");
        skStringMapPrintMap(name_id_map, stdout);
        printf("\n");
    }

    printf("list should have "
           "{ \"baz\" }\n\t");
    skStringMapPrintMap(name_id_map, stdout);
    printf("\n\n");

    if (skStringMapRemoveByID(name_id_map, 3)
        != SKSTRINGMAP_OK)
    {
        printf("error removing entry by id");
        skStringMapPrintMap(name_id_map, stdout);
        printf("\n");
    }

    printf("list should have "
           "{ }\n\t");
    skStringMapPrintMap(name_id_map, stdout);
    printf("\n\n");

    err = skStringMapAddEntries(name_id_map,
                                (sizeof(a_few_more_ids)
                                 / sizeof(a_few_more_ids[0])),
                                a_few_more_ids);
    if (err != SKSTRINGMAP_OK) {
        printf("error %d (%s) adding list of a_few_more to\n\t",
               err, status_string(err));
        skStringMapPrintMap(name_id_map, stdout);
        printf("\n");
    }


    /* test normal usage cases */
    printf("Testing lookups in the map:\n\t");
    skStringMapPrintMap(name_id_map, stdout);
    printf("\n\n");


    for (i = 0; parseable[i].name != NULL; ++i) {
        test_string(name_id_map, parseable[i].name,
                    SKSTRINGMAP_OK, parseable[i].count);
    }

    /* test no match cases */
    for (i = 0; ambiguous[i] != NULL; ++i) {
        test_string(name_id_map, ambiguous[i], SKSTRINGMAP_PARSE_AMBIGUOUS, 0);
    }
    for (i = 0; no_match[i] != NULL; ++i) {
        test_string(name_id_map, no_match[i], SKSTRINGMAP_PARSE_NO_MATCH, 0);
    }

    /* test unparsable cases */
    for (i = 0; unparseable[i] != NULL; ++i) {
        test_string(name_id_map, unparseable[i],
                    SKSTRINGMAP_PARSE_UNPARSABLE, 0);
    }

    test_get_by_name(name_id_map);

    test_get_by_id(name_id_map);

    /* cleanup list */
    if (skStringMapDestroy(name_id_map) != SKSTRINGMAP_OK) {
        printf("error deallocating list\n");
    }

    return 0;
}


static void
test_string(
    sk_dllist_t            *name_id_map,
    const char             *user_input,
    sk_stringmap_status_t   desired_parse_status,
    size_t                  desired_entryc)
{
    sk_stringmap_iter_t *results = NULL;
    char *bad_token = NULL;
    sk_stringmap_status_t rv;
    sk_stringmap_entry_t *entry;

    printf("TEST MATCH BEGIN: %s\n", user_input);
    rv = skStringMapMatch(name_id_map, user_input, &results, &bad_token);
    if ((rv != desired_parse_status)
        || ((desired_parse_status == SKSTRINGMAP_OK)
            && (skStringMapIterCountMatches(results) != desired_entryc)))
    {
        printf("  TEST FAILED, parse status %d (%s) entryc %u",
               rv,
               status_string(rv),
               (unsigned int)skStringMapIterCountMatches(results));
        if (bad_token != NULL) {
            printf(" failed-token '%s'", bad_token);
            free(bad_token);
        }
        printf("\n  WHILE MATCHING\n\t%s\nIN LIST\n\t", user_input);
        skStringMapPrintMap(name_id_map, stdout);
        printf("\n");
    } else {
        printf("  SUCCESS %d (%s)",
               desired_parse_status, status_string(desired_parse_status));
        if (desired_parse_status == SKSTRINGMAP_OK) {
            printf("  [");
            while (skStringMapIterNext(results, &entry, NULL)==SK_ITERATOR_OK){
                printf(" %d", entry->id);
            }
            printf(" ]");
        } else if (bad_token != NULL) {
            printf(" failed-token '%s'", bad_token);
            free(bad_token);
        }
        printf("\n");
    }

    printf("TEST END\n\n");
    if (results) {
        skStringMapIterDestroy(results);
    }
}


static void
test_get_by_name(
    sk_stringmap_t     *name_id_map)
{
    sk_stringmap_entry_t *entry;
    sk_stringmap_status_t rv;
    const char *name[] = {"baz", "BAZ", "Baz", "bAz", "baZ", "BaZ", NULL};
    int i;

    for (i = 0; name[i] != NULL; ++i) {
        printf("TEST GET_BY_NAME BEGIN: %s\n", name[i]);
        rv = skStringMapGetByName(name_id_map, name[i], &entry);
        if (rv != SKSTRINGMAP_OK) {
            printf("  TEST FAILED, parse status %d (%s)",
                   rv,
                   status_string(rv));
            printf("\n  WHILE MATCHING\n\t%s\nIN LIST\n\t", name[i]);
            skStringMapPrintMap(name_id_map, stdout);
        } else {
            printf("  SUCCESS %d (%s)",
                   rv, status_string(rv));
            printf(" [%d]", entry->id);
        }
        printf("\n");
        printf("TEST END\n\n");
    }
}


static void
test_get_by_id(
    sk_stringmap_t     *name_id_map)
{
    sk_stringmap_iter_t *iter;
    sk_stringmap_entry_t add_entry;
    sk_stringmap_entry_t *map_entry;
    const char *name;

    printf("list of names should be moo and orc\n");

    memset(&add_entry, 0, sizeof(add_entry));
    add_entry.name = "moo";
    add_entry.id = 999;
    if (skStringMapAddEntries(name_id_map, 1, &add_entry) != SKSTRINGMAP_OK) {
        printf("error adding moo\n");
    }
    add_entry.name = "orc";
    if (skStringMapAddEntries(name_id_map, 1, &add_entry) != SKSTRINGMAP_OK) {
        printf("error adding orc\n");
    }

    name = skStringMapGetFirstName(name_id_map, (sk_stringmap_id_t)999);
    if (name == NULL || 0 != strcmp("moo", name)) {
        printf("CRITICAL FAILURE getting first name for id 999\n");
        return;
    }

    if (skStringMapGetByID(name_id_map, (sk_stringmap_id_t)999, &iter)
        != SKSTRINGMAP_OK)
    {
        printf("CRITICAL FAILURE looking up names for id 999\n");
        return;
    }

    while (skStringMapIterNext(iter, &map_entry, NULL) == SK_ITERATOR_OK) {
        printf("  found name %s\n", map_entry->name);
    }

    skStringMapIterDestroy(iter);
}


static const char *
status_string(
    sk_stringmap_status_t   st)
{
    switch (st) {
      case SKSTRINGMAP_OK:
        return "OK";
      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        return "AMBIGUOUS";
      case SKSTRINGMAP_PARSE_NO_MATCH:
        return "NO_MATCH";
      case SKSTRINGMAP_PARSE_UNPARSABLE:
        return "UNPARSABLE";
      case SKSTRINGMAP_ERR_PARSER:
        return "PARSER_ERR";
      case SKSTRINGMAP_ERR_INPUT:
        return "INPUT";
      case SKSTRINGMAP_ERR_MEM:
        return "MEM";
      case SKSTRINGMAP_ERR_LIST:
        return "LIST";
      case SKSTRINGMAP_ERR_DUPLICATE_ENTRY:
        return "DUPLICATE_ENTRY";
      case SKSTRINGMAP_ERR_ZERO_LENGTH_ENTRY:
        return "ZERO_LENGTH_ENTRY";
      case SKSTRINGMAP_ERR_NUMERIC_START_ENTRY:
        return "NUMERIC_START_ENTRY";
      case SKSTRINGMAP_ERR_ALPHANUM_START_ENTRY:
        return "ALPHANUM_START_ENTRY";
      default:
        return "UNKNONW";
    }
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
