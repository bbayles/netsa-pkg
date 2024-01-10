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
**    The rwfiltertuple.c file allows one to partition data using a
**    text file that contains any subset of the members of the
**    standard 5-tuple {sIP,dIP,sPort,dPort,proto}.
**
**    The fields to use can be specified by labels in the file or from
**    the command line.
**
**    You may also swap the definitions of sIP/dIP and sPort/dPort by
**    providing a switch on the command line, or find data in either
**    direction.
**
**    The implemention reads the user's text file, creates one or more
**    tuples for each row, and stores the tuples in a red-black tree.
**    When partitioning the data, the values from the rwRec are used
**    to fill a tuple, and the red-black tree is searched for that
**    tuple.
**
**    Because the implemention uses a red-black tree to store the
**    data, we must search for individual points, and we cannot search
**    for a range of values.  If the user provides a CIDR block, the
**    red-black tree will contain an entry for every IP in the CIDR
**    block.
**
**    To allow for searching of ranges (so we don't need to explode
**    every CIDR block), we would need to use some other data
**    structure.  Some possible structures would be the R-Tree,
**    KD-Tree, Hilbert-R-Tree, or GiST.
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: rwfiltertuple.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skvector.h>
#include <silk/redblack.h>
#include <silk/rwascii.h>
#include <silk/skstringmap.h>
#include "rwfilter.h"


/* DEFINES AND TYPEDEFS */

/* Maximum number of fields we support */
#define TUPLE_MAX  5

/*
 *  As we read the user's text file, we create nodes and hand pointers
 *  those nodes to the redblack tree.  We want to avoid doing an
 *  allocation for every node, but we cannot create a large memory
 *  block and realloc() it later since that will make redblack's
 *  pointers invalid.  Instead, we'll use a vector of array of nodes,
 *  where each array contains NODE_ARRAY_SIZE nodes.
 */
#define NODE_ARRAY_SIZE  65536

/* the possible direction(s) for the user's test */
#define  TUPLE_FORWARD   (1 << 0)
#define  TUPLE_REVERSE   (1 << 1)

/* a CIDR block, used for sip and dip */
typedef struct tuple_cidr_st {
    skIPWildcard_t          ipwild;
    skIPWildcardIterator_t  iter;
} tuple_cidr_t;

/* a list of numbers, used for ports and protocols */
typedef struct number_list_st {
    /* the number list */
    uint32_t   *list;
    /* the length of the list */
    uint32_t    count;
    /* the current index into that list */
    uint32_t    idx;
} number_list_t;


/* LOCAL VARIABLES */

/* the vector of node arrays */
static sk_vector_t *array_vec = NULL;

/* the redblack tree */
static struct rbtree *rb = NULL;

/* the direction to test;  */
static int direction = TUPLE_FORWARD;

/* available directions, used when parsing */
static const sk_stringmap_entry_t direction_list[] = {
    {"forward",  TUPLE_FORWARD,                 NULL, NULL},
    {"reverse",  TUPLE_REVERSE,                 NULL, NULL},
    {"both",     TUPLE_FORWARD | TUPLE_REVERSE, NULL, NULL},
    SK_STRINGMAP_SENTINEL
};

/* the delimiter between columns */
static char delimiter = '|';

/* the name of the file to process */
static const char *input_file = NULL;

/* the number of fields in each input line */
static uint32_t num_fields = 0;

/* the total length of the byte-array for each node */
static size_t node_length = 0;

/* data about each field in the node */
static struct field_st {
    /* the type of this field (SIP, DIP, etc) */
    uint32_t    type;
    /* byte offset of this field from start of the node */
    size_t      offset;
    /* byte length of this field */
    size_t      length;
} field[TUPLE_MAX];

/* the field map is used when parsing field names */
static sk_stringmap_t *field_map = NULL;


/*
 * Options that get added to rwfilter.
 */
typedef enum tupleOptionsEnum_en {
    OPT_TUPLE_FILE, OPT_TUPLE_FIELDS,
    OPT_TUPLE_DIRECTION, OPT_TUPLE_DELIMITER
} tupleOptionsEnum;

static struct option tupleOptions[] = {
    {"tuple-file",          REQUIRED_ARG, 0, OPT_TUPLE_FILE},
    {"tuple-fields",        REQUIRED_ARG, 0, OPT_TUPLE_FIELDS},
    {"tuple-direction",     REQUIRED_ARG, 0, OPT_TUPLE_DIRECTION},
    {"tuple-delimiter",     REQUIRED_ARG, 0, OPT_TUPLE_DELIMITER},
    {0, 0, 0, 0}            /* sentinel */
};

static const char *tupleOptionsHelp[] = {
    ("File containing 1 to 5 columns (fields) from the set\n"
     "\t{sIP,dIP,sPort,dPort,proto} to compare against each record. Pass the\n"
     "\trecord if it matches"),
    "Field(s) in input. List fields separated by commas:",
    "Specify how the fields map to the records:",
    "Character separating the input fields. Def. '|'",
    (char*)NULL
};


/* LOCAL FUNCTION DECLARATIONS */

static int tupleCompare(const void *pa, const void *pb, const void *config);
static int tupleCreateFieldMap(void);
static uint8_t *tupleGrowMemory(void);
static int tupleInitializeMemory(void);
static int tupleOptionsHandler(clientData cData, int opt_index, char *opt_arg);
static int tupleParseFile(void);
static int tupleParseFieldNames(const char *field_string);
static int tupleParseDirection(const char *direction_str);


/* FUNCTION DEFINITIONS */


/*
 *  ok = tupleSetup();
 *
 *    Setup the tuple module and register its options.  Return 0 on
 *    success, or non-zero on error.
 */
int
tupleSetup(
    void)
{
    /* verify same number of options and help strings */
    assert((sizeof(tupleOptions)/sizeof(struct option))
           == (sizeof(tupleOptionsHelp)/sizeof(char*)));

    /* register the options */
    if (skOptionsRegister(tupleOptions, &tupleOptionsHandler, NULL)) {
        skAppPrintErr("Unable to register tuple options");
        return 1;
    }

    return 0;
}


/*
 *  tupleTeardown();
 *
 *    Teardown the module and free all memory it uses.
 */
void
tupleTeardown(
    void)
{
    static int teardownFlag = 0;
    size_t i;
    void **a;

    if (teardownFlag) {
        return;
    }
    teardownFlag = 1;

    /* destroy the string map */
    if (field_map) {
        skStringMapDestroy(field_map);
        field_map = NULL;
    }

    /* destroy the redblack trees */
    if (rb) {
        rbdestroy(rb);
        rb = NULL;
    }

    /* destroy the vector of array of nodes */
    if (array_vec) {
        for (i = 0;
             NULL != (a = (void**)skVectorGetValuePointer(array_vec, i));
             ++i)
        {
            free(*a);
        }
        skVectorDestroy(array_vec);
        array_vec = NULL;
    }

    return;
}


/*
 *  tupleUsage(fh);
 *
 *    Print the --help output for the options this module supports to
 *    the file handle 'fh'.
 */
void
tupleUsage(
    FILE               *fh)
{
    int i;
    int j;

    if (NULL == field_map) {
        tupleCreateFieldMap();
    }

    for (i = 0; tupleOptions[i].name != NULL; ++i) {
        fprintf(fh, "--%s %s. ", tupleOptions[i].name,
                SK_OPTION_HAS_ARG(tupleOptions[i]));
        switch (tupleOptions[i].val) {
          case OPT_TUPLE_FIELDS:
            fprintf(fh, "%s\n", tupleOptionsHelp[i]);
            if (field_map) {
                skStringMapPrintUsage(field_map, fh, 4);
            }
            break;

          case OPT_TUPLE_DIRECTION:
            fprintf(fh, "%s\n", tupleOptionsHelp[i]);
            for (j = 0; direction_list[j].name; ++j) {
                fprintf(fh, "\t%-8s- ", direction_list[j].name);
                if (direction_list[j].id == TUPLE_FORWARD) {
                    fprintf(fh, ("Map sIP,sPort to sIP,sPort;"
                                 " dIP,dPort to dIP,dPort. [Def]"));
                } else if (direction_list[j].id == TUPLE_REVERSE) {
                    fprintf(fh, ("Map sIP,sPort to dIP,dPort;"
                                 " dIP,dPort to sIP,sPort"));
                } else {
                    fprintf(fh,"Map sIP,sPort to sIP,sPort or dIP,dPort; etc");
                }
                fprintf(fh, "\n");
            }
            break;

          default:
            fprintf(fh, "%s\n", tupleOptionsHelp[i]);
            break;
        }
    }
}


/*
 *  ok = tupleOptionsHandler(cData, opt_index, opt_arg);
 *
 *    The options handler for the switches that this file registers.
 *
 *    Parses the user's values to the switches and fills in
 *    appropriate global variable(s).  Returns 0 on success or 1 on
 *    failure.
 */
static int
tupleOptionsHandler(
    clientData   UNUSED(cData),
    int                 opt_index,
    char               *opt_arg)
{
    switch (opt_index) {
      case OPT_TUPLE_FILE:
        if (input_file) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          tupleOptions[opt_index].name);
            return 1;
        }
        input_file = opt_arg;
        break;

      case OPT_TUPLE_DIRECTION:
        if (tupleParseDirection(opt_arg)) {
            skAppPrintErr("Invalid --%s value: '%s'",
                          tupleOptions[opt_index].name, opt_arg);
            return 1;
        }
        break;

      case OPT_TUPLE_DELIMITER:
        delimiter = opt_arg[0];
        if (delimiter == '\0') {
            skAppPrintErr("The empty string is not a valid delimiter");
            return 1;
        }
        break;

      case OPT_TUPLE_FIELDS:
        if (num_fields > 0) {
            skAppPrintErr("Invalid %s: Switch used multiple times",
                          tupleOptions[opt_index].name);
            return 1;
        }
        if (tupleParseFieldNames(opt_arg)) {
            return 1;
        }
        break;
    }

    return 0;
}


/*
 *  count = tupleGetCheckCount();
 *
 *    This function is called by rwfilter to determine if the module
 *    is active.  It should return 1 if the 'tupleCheck' function
 *    should be called to test a record, 0 if 'tupleCheck' should not
 *    be called, and -1 if there is an error.  This function calls the
 *    function to parse the tuple file.
 */
int
tupleGetCheckCount(
    void)
{
    /* Verify that we have a file name */
    if (input_file == NULL || input_file[0] == '\0') {
        return 0;
    }

    if (tupleParseFile()) {
        return -1;
    }

    return 1;
}


/*
 *  pass = tupleCheck(rwrec);
 *
 *    Return RWF_FAIL if the record's attributes DO NOT match those read
 *    from the tuple file.  Return RWF_PASS if they do match.
 */
checktype_t
tupleCheck(
    const rwRec        *rwrec)
{
    uint8_t key[SK_MAX_RECORD_SIZE];
    uint32_t i;

    if (direction & TUPLE_FORWARD) {
        for (i = 0; i < num_fields; ++i) {
            switch (field[i].type) {
              case RWREC_FIELD_SIP:
#if SK_ENABLE_IPV6
                rwRecMemGetSIPv6(rwrec, key + field[i].offset);
#else
                rwRecMemGetSIPv4(rwrec, key + field[i].offset);
#endif
                break;

              case RWREC_FIELD_DIP:
#if SK_ENABLE_IPV6
                rwRecMemGetDIPv6(rwrec, key + field[i].offset);
#else
                rwRecMemGetDIPv4(rwrec, key + field[i].offset);
#endif
                break;

              case RWREC_FIELD_SPORT:
                rwRecMemGetSPort(rwrec, key + field[i].offset);
                break;

              case RWREC_FIELD_DPORT:
                rwRecMemGetDPort(rwrec, key + field[i].offset);
                break;

              case RWREC_FIELD_PROTO:
                rwRecMemGetProto(rwrec, key + field[i].offset);
                break;

              default:
                skAbortBadCase(field[i].type);
            }
        }

        if (rbfind(&key, rb) != NULL) {
            /* found it */
            return RWF_PASS;
        }
    }

    if (direction & TUPLE_REVERSE) {
        for (i = 0; i < num_fields; ++i) {
            switch (field[i].type) {
              case RWREC_FIELD_SIP:
#if SK_ENABLE_IPV6
                rwRecMemGetDIPv6(rwrec, key + field[i].offset);
#else
                rwRecMemGetDIPv4(rwrec, key + field[i].offset);
#endif
                break;

              case RWREC_FIELD_DIP:
#if SK_ENABLE_IPV6
                rwRecMemGetSIPv6(rwrec, key + field[i].offset);
#else
                rwRecMemGetSIPv4(rwrec, key + field[i].offset);
#endif
                break;

              case RWREC_FIELD_SPORT:
                rwRecMemGetDPort(rwrec, key + field[i].offset);
                break;

              case RWREC_FIELD_DPORT:
                rwRecMemGetSPort(rwrec, key + field[i].offset);
                break;

              case RWREC_FIELD_PROTO:
                rwRecMemGetProto(rwrec, key + field[i].offset);
                break;

              default:
                skAbortBadCase(field[i].type);
            }
        }

        if (rbfind(&key, rb) != NULL) {
            /* found it */
            return RWF_PASS;
        }
    }

    /* no match */
    return RWF_FAIL;
}


/*
 *  gt_lt_eq = tupleCompare(key_a, key_b, config);
 *
 *    Comparison function for the redblack tree; compares the
 *    keyortpair_t's key_a and key_b, returning -1 if key_a comes
 *    before key_b.
 */
static int
tupleCompare(
    const void         *pa,
    const void         *pb,
    const void  UNUSED(*config))
{
    return memcmp(pa, pb, node_length);
}


/*
 *  ok = tupleInitializeMemory();
 *
 *    Create a redblack tree to hold information about the tuples.
 *
 *    Create the global 'array_vec' that is used to store pointers to
 *    arrays of nodes that we feed to redblack.
 *
 *    Return 0 on success, or non-zero on allocation failure.
 */
static int
tupleInitializeMemory(
    void)
{
    /* Create the vectory to store the array of nodes */
    array_vec = skVectorNew(sizeof(uint8_t**));
    if (array_vec == NULL) {
        skAppPrintErr("Insufficient memory to create vector");
        return -1;
    }

    /* Create the redblack tree */
    rb = rbinit(&tupleCompare, NULL);
    if (rb == NULL) {
        skAppPrintErr("Insufficient memory to create redblack tree");
        return -1;
    }

    return 0;
}


/*
 *  new_mem = tupleGrowMemory();
 *
 *    Create a new array of nodes for the redblack tree, put a pointer
 *    to that array into the global 'array_vec', and return the array.
 *    Return NULL for an allocation error.
 */
static uint8_t *
tupleGrowMemory(
    void)
{
    uint8_t *new_mem;

    assert(array_vec != NULL);
    new_mem = (uint8_t*)calloc(NODE_ARRAY_SIZE, node_length);
    if (new_mem == NULL) {
        return NULL;
    }

    if (skVectorAppendValue(array_vec, &new_mem)) {
        free(new_mem);
        return NULL;
    }

    return new_mem;
}


/*
 *  ok = tupleCreateFieldMap();
 *
 *    Create the global field map 'field_map' used to parse the names
 *    of the fields or names of columns from the input file.  Return 0
 *    on success, or -1 on failure.
 */
static int
tupleCreateFieldMap(
    void)
{
    /* the list of fields we support.  copied from rwascii.c. */
    static const sk_stringmap_entry_t entries[] = {
        {"sIP",          RWREC_FIELD_SIP,   NULL, NULL},
        {"1",            RWREC_FIELD_SIP,   NULL, NULL},
        {"dIP",          RWREC_FIELD_DIP,   NULL, NULL},
        {"2",            RWREC_FIELD_DIP,   NULL, NULL},
        {"sPort",        RWREC_FIELD_SPORT, NULL, NULL},
        {"3",            RWREC_FIELD_SPORT, NULL, NULL},
        {"dPort",        RWREC_FIELD_DPORT, NULL, NULL},
        {"4",            RWREC_FIELD_DPORT, NULL, NULL},
        {"protocol",     RWREC_FIELD_PROTO, NULL, NULL},
        {"5",            RWREC_FIELD_PROTO, NULL, NULL}
    };

    /* return if the map already exists */
    if (field_map) {
        return 0;
    }

    /* Create the mapping of field names to value */
    if (SKSTRINGMAP_OK != skStringMapCreate(&field_map)) {
        skAppPrintErr("Cannot create tuple field-name map");
        return -1;
    }

    /* add entries */
    if (skStringMapAddEntries(field_map,
                              (sizeof(entries)/sizeof(sk_stringmap_entry_t)),
                              entries)
        != SKSTRINGMAP_OK)
    {
        skAppPrintErr("Cannot fill tuple field-name map");
        return -1;
    }

    return 0;
}


/* parse the user's direction string */
static int
tupleParseDirection(
    const char         *direction_str)
{
    sk_stringmap_t *str_map = NULL;
    sk_stringmap_status_t rv_map;
    sk_stringmap_entry_t *map_entry;
    int rv = -1;

    /* create a stringmap of the available entries */
    if (SKSTRINGMAP_OK != skStringMapCreate(&str_map)) {
        skAppPrintErr("Unable to create stringmap");
        goto END;
    }
    if (skStringMapAddEntries(str_map, -1, direction_list) != SKSTRINGMAP_OK)
    {
        goto END;
    }

    /* attempt to match */
    rv_map = skStringMapGetByName(str_map, direction_str, &map_entry);
    switch (rv_map) {
      case SKSTRINGMAP_OK:
        direction = map_entry->id;
        rv = 0;
        break;

      case SKSTRINGMAP_PARSE_AMBIGUOUS:
        skAppPrintErr("The %s value '%s' is ambiguous",
                      tupleOptions[OPT_TUPLE_DIRECTION].name, direction_str);
        goto END;

      case SKSTRINGMAP_PARSE_NO_MATCH:
        skAppPrintErr(("The %s value '%s' is not complete path and\n"
                       "\tdoes not match known keys"),
                      tupleOptions[OPT_TUPLE_DIRECTION].name, direction_str);
        goto END;

      default:
        skAppPrintErr("Unexpected return value from string-map parser (%d)",
                      rv_map);
        goto END;
    }

  END:
    if (str_map) {
        skStringMapDestroy(str_map);
    }
    return rv;
}


/*
 *  status = tupleParseFieldNames(fields_string);
 *
 *    Parse the user's option for the --fields switch (or the fields
 *    determined from the first line of input) and fill in the global
 *    'field[]' array and 'num_fields' variables with the result.
 *    This function will also set the values in the
 *    'rwrec_offset_fwd[]' and 'rwrec_offset_rev[]' arrays.
 *
 *    Return 0 on success; -1 on failure.
 */
static int
tupleParseFieldNames(
    const char         *field_string)
{
    sk_stringmap_iter_t *iter = NULL;
    sk_stringmap_entry_t *entry;
    char *errmsg;
    int rv = -1;

    assert(0 == num_fields);

    if (NULL == field_map) {
        if (tupleCreateFieldMap()) {
            goto END;
        }
    }

    if (skStringMapParse(field_map, field_string, SKSTRINGMAP_DUPES_ERROR,
                         &iter, &errmsg))
    {
        skAppPrintErr("Invalid %s: %s",
                      tupleOptions[OPT_TUPLE_FIELDS].name, errmsg);
        goto END;
    }

    while (skStringMapIterNext(iter, &entry, NULL) == SK_ITERATOR_OK) {
        if (num_fields >= TUPLE_MAX) {
            skAppPrintErr("Only %d tuple-fields are supported",
                          TUPLE_MAX);
            goto END;
        }

        switch (entry->id) {
          case RWREC_FIELD_SIP:
          case RWREC_FIELD_DIP:
#if SK_ENABLE_IPV6
            field[num_fields].length = RWREC_SIZEOF_SIPv6;
#else
            field[num_fields].length = RWREC_SIZEOF_SIPv4;
#endif
            break;

          case RWREC_FIELD_SPORT:
          case RWREC_FIELD_DPORT:
            field[num_fields].length = RWREC_SIZEOF_SPORT;
            break;

          case RWREC_FIELD_PROTO:
            field[num_fields].length = RWREC_SIZEOF_PROTO;
            break;

          default:
            skAbortBadCase(field[num_fields].type);
        }

        field[num_fields].type = entry->id;
        field[num_fields].offset = node_length;
        node_length += field[num_fields].length;
        ++num_fields;
    }

    rv = 0;

  END:
    if (iter) {
        skStringMapIterDestroy(iter);
    }
    return rv;
}


/*
 *  ok = tupleGetFieldsFromFirstLine(firstline);
 *
 *    Determine the fields in the data stream by parsing the first
 *    line of the input contained in the C-string 'firstline'.  Return
 *    0 if we are able to parse the fields, and -1 otherwise.
 *
 *    This function calls parseFieldNames() to do the parsing of the
 *    names.
 */
static int
tupleGetFieldsFromFirstLine(
    char               *first_line)
{
    char *cp = first_line;
    char *ep = first_line;

    assert(0 == num_fields);

    /* need to get fields from the first line. convert the first line
     * in place to a list of fields by converting the delimiter to a
     * comma and removing whitespace.  if the delimiter is whitespace,
     * we will get a lot of extra commas in the input, but
     * tupleParseFieldNames() will just ignore them. */
    while (*cp) {
        if (*cp == delimiter) {
            /* convert delimiter to comma for tupleParseFieldNames() */
            *ep++ = ',';
            ++cp;
        } else if (isspace((int)*cp)) {
            /* ignore spaces */
            ++cp;
        } else {
            /* copy character */
            *ep++ = *cp++;
        }
    }
    /* copy the '\0' */
    *ep = *cp;

    /* attempt to parse */
    if (tupleParseFieldNames(first_line)) {
        skAppPrintErr("Unable to guess fields from first line of file");
        return -1;
    }

    return 0;
}


/*
 *  is_title = tupleFirstLineIsTitle(first_string_array);
 *
 *    Determine if the input line in the first line of input is a
 *    title line.  This function gets an array of C-string pointers,
 *    with one pointing to each field from first line of input.  That
 *    array will hold 'num_fields' values.
 *
 *    Return 1 this line looks like a title, or 0 if it is not.
 */
static int
tupleFirstLineIsTitle(
    char               *field_val[])
{
    sk_stringmap_entry_t *entry;
    uint32_t i;
    char *cp;
    int is_title = 0;

    for (i = 0; i < num_fields; ++i) {
        /* see if the value in this column maps to the name of a valid
         * stringmap-entry; if so, assume the row is a title row */
        cp = field_val[i];
        while (isdigit((int)*cp) || isspace((int)*cp)) {
            /* don't allow a value to be treated as a field */
            ++cp;
        }
        if (*cp) {
            if (skStringMapGetByName(field_map, field_val[i], &entry)
                == SKSTRINGMAP_OK)
            {
                is_title = 1;
                break;
            }
        }
    }

    return is_title;
}


/*
 *  ok = tupleProcessFields(field_string);
 *
 *    Parse the fields whose C-string values are given in the
 *    'field_string' array.  That array will hold 'num_fields' values.
 *
 *    Return 0 on success, non-zero on failure.
 */
static int
tupleProcessFields(
    char               *field_val[])
{
    static uint8_t *node_array = NULL;
    static uint8_t *cur_node = NULL;
    static uint8_t *final_node = NULL;
    const uint8_t *dup_check;
    uint32_t cidr;
    uint32_t i;
    tuple_cidr_t sip;
    tuple_cidr_t dip;
    number_list_t sport;
    number_list_t dport;
    number_list_t proto;
    skipaddr_t sip_cur;
    skipaddr_t dip_cur;
    uint16_t sport_cur, dport_cur;
    uint8_t proto_cur;
    uint32_t incremented;
    int rv = -1;
#if !SK_ENABLE_IPV6
    uint32_t ipv4;
#endif

    memset(&sport, 0, sizeof(number_list_t));
    memset(&dport, 0, sizeof(number_list_t));
    memset(&proto, 0, sizeof(number_list_t));

    if (node_array == NULL) {
        /* create an array of nodes */
        node_array = tupleGrowMemory();
        if (node_array == NULL) {
            skAppPrintErr("Cannot create array of nodes");
            return -1;
        }
        cur_node = node_array;
        final_node = node_array + (NODE_ARRAY_SIZE * node_length);
    }

    /* parse the fields */
    for (i = 0; i < num_fields; ++i) {

        switch (field[i].type) {
          case RWREC_FIELD_SIP:
            /* parse as CIDR notation since that is the only format
             * supported, but then parse again as an IP wildcard,
             * since IP wildcards provide us with iteration. */
            if (skStringParseCIDR(&sip_cur, &cidr, field_val[i])) {
                return 1;
            }
            if (skStringParseIPWildcard(&sip.ipwild, field_val[i])) {
                return 1;
            }
#if SK_ENABLE_IPV6
            /* force addresses to be IPv6 */
            skIPWildcardIteratorBindV6(&sip.iter, &sip.ipwild);
#else
            skIPWildcardIteratorBind(&sip.iter, &sip.ipwild);
#endif
            skIPWildcardIteratorNext(&sip.iter, &sip_cur);
            break;

          case RWREC_FIELD_DIP:
            if (skStringParseCIDR(&dip_cur, &cidr, field_val[i])) {
                return 1;
            }
            if (skStringParseIPWildcard(&dip.ipwild, field_val[i])) {
                return 1;
            }
#if SK_ENABLE_IPV6
            /* force addresses to be IPv6 */
            skIPWildcardIteratorBindV6(&dip.iter, &dip.ipwild);
#else
            skIPWildcardIteratorBind(&dip.iter, &dip.ipwild);
#endif
            skIPWildcardIteratorNext(&dip.iter, &dip_cur);
            break;

          case RWREC_FIELD_SPORT:
            if (skStringParseNumberList(&sport.list, &sport.count,
                                        field_val[i], 0, UINT16_MAX, 0))
            {
                return 3;
            }
            sport.idx = 0;
            sport_cur = (uint16_t)(sport.list[sport.idx]);
            break;

          case RWREC_FIELD_DPORT:
            if (skStringParseNumberList(&dport.list, &dport.count,
                                        field_val[i], 0, UINT16_MAX, 0))
            {
                return 4;
            }
            dport.idx = 0;
            dport_cur = (uint16_t)(dport.list[dport.idx]);
            break;

          case RWREC_FIELD_PROTO:
            if (skStringParseNumberList(&proto.list, &proto.count,
                                        field_val[i], 0, UINT8_MAX, 0))
            {
                return 5;
            }
            proto.idx = 0;
            proto_cur = (uint8_t)(proto.list[proto.idx]);
            break;

          default:
            skAbortBadCase(field[i].type);
        }
    }

    /* now create the entries from the parsed values */
    do {
        /* To see all permutations, each of the following checks
         * whether incremented has been set.  If so, it does nothing.
         * Else, it tries to increment its counter and sets
         * incremented if it can, but if its counter is at its max, it
         * resets itself and does not set incremented.  We exit the
         * loop when no one is able to increment. */
        incremented = 0;

        for (i = 0; i < num_fields; ++i) {
            switch (field[i].type) {
              case RWREC_FIELD_SIP:
#if SK_ENABLE_IPV6
                skipaddrGetV6(&sip_cur, cur_node + field[i].offset);
#else
                ipv4 = skipaddrGetV4(&sip_cur);
                memcpy(cur_node + field[i].offset, &ipv4, field[i].length);
#endif
                if (incremented == 0) {
                    if (skIPWildcardIteratorNext(&sip.iter, &sip_cur)
                        == SK_ITERATOR_OK)
                    {
                        incremented = 1;
                    } else {
                        skIPWildcardIteratorReset(&sip.iter);
                        skIPWildcardIteratorNext(&sip.iter, &sip_cur);
                    }
                }
                break;

              case RWREC_FIELD_DIP:
#if SK_ENABLE_IPV6
                skipaddrGetV6(&dip_cur, cur_node + field[i].offset);
#else
                ipv4 = skipaddrGetV4(&dip_cur);
                memcpy(cur_node + field[i].offset, &ipv4, field[i].length);
#endif
                if (incremented == 0) {
                    if (skIPWildcardIteratorNext(&dip.iter, &dip_cur)
                        == SK_ITERATOR_OK)
                    {
                        incremented = 2;
                    } else {
                        skIPWildcardIteratorReset(&dip.iter);
                        skIPWildcardIteratorNext(&dip.iter, &dip_cur);
                    }
                }
                break;

              case RWREC_FIELD_SPORT:
                memcpy(cur_node + field[i].offset, &sport_cur,field[i].length);
                if (incremented == 0 && sport.count != 1) {
                    ++sport.idx;
                    if (sport.idx == sport.count) {
                        /* reset */
                        sport.idx = 0;
                    } else {
                        incremented = 3;
                    }
                }
                sport_cur = (uint16_t)(sport.list[sport.idx]);
                break;

              case RWREC_FIELD_DPORT:
                memcpy(cur_node + field[i].offset, &dport_cur,field[i].length);
                if (incremented == 0 && dport.count != 1) {
                    ++dport.idx;
                    if (dport.idx == dport.count) {
                        /* reset */
                        dport.idx = 0;
                    } else {
                        incremented = 4;
                    }
                }
                dport_cur = (uint16_t)(dport.list[dport.idx]);
                break;

              case RWREC_FIELD_PROTO:
                memcpy(cur_node + field[i].offset, &proto_cur,field[i].length);
                if (incremented == 0 && proto.count != 1) {
                    ++proto.idx;
                    if (proto.idx == proto.count) {
                        /* reset */
                        proto.idx = 0;
                    } else {
                        incremented = 5;
                    }
                }
                proto_cur = (uint16_t)(proto.list[proto.idx]);
                break;

              default:
                skAbortBadCase(field[i].type);
            } /* switch */
        }

        dup_check = (const uint8_t*)rbsearch(cur_node, rb);
        if (dup_check == cur_node) {
            /* new node added */
            cur_node += node_length;

            if (cur_node >= final_node) {
                assert(cur_node == final_node);

                /* need more entries */
                node_array = tupleGrowMemory();
                if (node_array == NULL) {
                    skAppPrintErr("Cannot create array of nodes");
                    goto END;
                }
                cur_node = node_array;
                final_node = node_array + (NODE_ARRAY_SIZE * node_length);
            }


        }
        /* else key was duplicate and we ignore it */

    } while (incremented != 0);

    rv = 0;

  END:
    if (sport.list) {
        free(sport.list);
    }
    if (dport.list) {
        free(dport.list);
    }
    if (proto.list) {
        free(proto.list);
    }

    return rv;
}


/*
 *  ok = tupleParseFile();
 *
 *    Parse the file contained in the global 'input_path' variable.
 *
 *    This functions opens the file, then reads lines from it, parsing
 *    the lines into fields.  It calls tupleProcessFields() to parse each
 *    individual field.
 *
 *    Return 0 on success, or non-zero otherwise.
 */
static int
tupleParseFile(
    void)
{
#define MAX_ERRORS 12
    static const char *field_name[TUPLE_MAX+1] = {
        "","sIP","dIP","sPort","dPort","proto"
    };
    char line_buf[1024];
    char *field_string[TUPLE_MAX];
    char *cp;
    char *ep;
    int lc = 0;
    int err_count = 0;
    uint32_t i;
    skstream_t *stream;
    int rv;
    int saw_title = 0;

    if (NULL == field_map) {
        if (tupleCreateFieldMap()) {
            return 1;
        }
    }

    if (tupleInitializeMemory()) {
        return 1;
    }

    rv = filterOpenInputData(&stream, SK_CONTENT_TEXT, input_file);
    if (rv == -1) {
        skAppPrintErr("Problem with input file %s", input_file);
        return 1;
    }
    if (rv == 1) {
        /* Ignore the file */
        return 0;
    }

    if ((rv = skStreamSetCommentStart(stream, "#"))) {
        goto END;
    }

    /* read until end of file */
    while (((rv = skStreamGetLine(stream, line_buf, sizeof(line_buf), &lc))
            != SKSTREAM_ERR_EOF)
           && (err_count < MAX_ERRORS))
    {
        switch (rv) {
          case SKSTREAM_OK:
            /* good, we got our line */
            break;
          case SKSTREAM_ERR_LONG_LINE:
            /* bad: line was longer than sizeof(line_buf) */
            skAppPrintErr("Input line %s:%d too long. ignored",
                          input_file, lc);
            continue;
          default:
            /* unexpected error */
            skStreamPrintLastErr(stream, rv, &skAppPrintErr);
            goto END;
        }

        if (num_fields == 0) {
            /* must determine fields from first line of input */
            assert(saw_title == 0);
            saw_title = tupleGetFieldsFromFirstLine(line_buf);
            if (saw_title < 0) {
                /* error */
                return 1;
            }
            saw_title = 1;
            continue;
        }

        /* We have a line; process it */
        cp = line_buf;
        i = 0;

        /* find each field and set pointers in field_string[] to the
         * field's text */
        while (*cp) {
            /* eat any leading whitespace in case whitespace is the
             * delimiter */
            while (isspace((int)*cp)) {
                ++cp;
            }
            if (*cp == '\0') {
                break;
            }
            field_string[i] = cp;
            ++i;

            /* find end of current field */
            ep = strchr(cp, delimiter);
            if (NULL == ep) {
                /* at end of line; break out of while() */
                break;
            }
            *ep = '\0';

            /* goto next field */
            cp = ep + 1;
        } /* inner while over fields */

        if (i != num_fields) {
            skAppPrintErr(("Too %s fields (found %" PRIu32
                           ", expected %" PRIu32 ") at %s:%d"),
                          ((i < num_fields) ? "few" : "many"),
                          i, num_fields, input_file, lc);
            ++err_count;
            continue;
        }

        if (saw_title == 0) {
            assert(num_fields > 0);
            /* the user already provided us with the fields, so we
             * just need to determine if we should ignore the first
             * line of input because it contains the titles. */
            if (tupleFirstLineIsTitle(field_string)) {
                continue;
            }
            saw_title = 1;
        }

        /* process fields */
        rv = tupleProcessFields(field_string);
        if (rv != 0) {
            if (rv > 0) {
                skAppPrintErr("Error parsing %s field at %s:%d",
                              field_name[rv], input_file, lc);
                ++err_count;
            } else {
                /* fatal */
                ++err_count;
                goto END;
            }
        }
    }

  END:
    skStreamDestroy(&stream);
    /* return error code if we did not get to the end of the stream */
    if (rv != SKSTREAM_ERR_EOF) {
        return -1;
    }
    /* return error code if we encountered errors */
    if (err_count) {
        return -1;
    }
    /* return error code if we do not have any entries */
    if (array_vec == NULL
        || 0 == skVectorGetCount(array_vec))
    {
        skAppPrintErr("No valid entries read from input file '%s'",
                      input_file);
        return -1;
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
