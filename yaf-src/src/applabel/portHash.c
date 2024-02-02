/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  portHash.c
 *
 *  This creates a really simple hash table to store a mapping between
 *  port numbers and rules.  The hash is really an implementation of
 *  a sparse array.
 *
 *  Also in the hash table are the DPI rules and index numbers to the
 *  structures defined in dpacketplugin.c.  Try to avoid collisions by
 *  not using well-known ports used in the applabel plug-in:
 *  80, 22, 25, 6346, 5050, 53, 21, 443, 427, 143, 194
 *
 *  ------------------------------------------------------------------------
 *  Authors: Chris Inacio
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



#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include "portHash.h"

#if YAF_ENABLE_APPLABEL

/** defining unit test makes this into a self compilable file and tries
 *  to do some (very minimal) testing of the hash functions */
#ifdef UNIT_TEST
typedef struct GError_st {
    int   foo;
} GError;
typedef uint8_t gboolean;

static int primaryHash;
static int secondaryHash;
static int linearChaining;

#endif /* ifdef UNIT_TEST */

static int linearChainingMax;

#include "payloadScanner.h"


/*
 * local types
 */
typedef struct portRuleHash_st {
    uint16_t   portNumber;
    uint16_t   ruleIndex;
} portRuleHash_t;


/*
 * file locals
 */
static portRuleHash_t portRuleHash[MAX_PAYLOAD_RULES];


/**
 * ycPortHashInitialize
 *
 * initializes the port hash to mark each entry as empty
 *
 *
 */
void
ycPortHashInitialize(
    void)
{
    int loop;

    for (loop = 0; loop < MAX_PAYLOAD_RULES; loop++) {
        portRuleHash[loop].ruleIndex = MAX_PAYLOAD_RULES + 1;
    }
#ifdef UNIT_TEST
    primaryHash = 0;
    secondaryHash = 0;
    linearChaining = 0;
#endif
    linearChainingMax = 0;
}


/**
 * ycPortHashInsert
 *
 * this inserts a mapping between port numbers and rule processing into
 * a hash.  The hash is used as a sparse array mechanism, although it
 * does take into account getting less sparse somewhat.  The hash can
 * hold as many elements as there are rules.  This might be somewhat
 * less efficient than a direct array if it gets full enough.
 * (Always a problem with sparse representations when they become
 * un-sparse.)
 * It uses a primary hash, a secondary hash, and then linear chaining
 * for its insert mechanism.
 *
 * @param portNum the TCP/UDP port number for the protocol (we use
 *        the label given in the rules file)
 * @param ruleNum the entry number in the rule table, this is the
 *        order the rule was declared in
 *
 */
void
ycPortHashInsert(
    uint16_t   portNum,
    uint16_t   ruleNum)
{
    uint16_t insertLoc = portNum % MAX_PAYLOAD_RULES;
    int      linChain = 0;

    /* primary hash function insert, check for collision */
    if ((MAX_PAYLOAD_RULES + 1) == portRuleHash[insertLoc].ruleIndex) {
        portRuleHash[insertLoc].portNumber = portNum;
        portRuleHash[insertLoc].ruleIndex = ruleNum;
#ifdef UNIT_TEST
        primaryHash++;
#endif
        return;
    }
    /* secondary hash function, insert with collision check */
    insertLoc = ((MAX_PAYLOAD_RULES - portNum) ^ (portNum >> 8));
    insertLoc %= MAX_PAYLOAD_RULES;
    if ((MAX_PAYLOAD_RULES + 1) == portRuleHash[insertLoc].ruleIndex) {
        portRuleHash[insertLoc].portNumber = portNum;
        portRuleHash[insertLoc].ruleIndex = ruleNum;
#ifdef UNIT_TEST
        secondaryHash++;
#endif
        return;
    }

    /* linear chaining from secondary hash function */
    do {
        insertLoc = (insertLoc + 1) % MAX_PAYLOAD_RULES;
        if ((MAX_PAYLOAD_RULES + 1) == portRuleHash[insertLoc].ruleIndex) {
            portRuleHash[insertLoc].portNumber = portNum;
            portRuleHash[insertLoc].ruleIndex = ruleNum;
#ifdef UNIT_TEST
            linearChaining++;
#endif
            if (linChain > linearChainingMax) {
                linearChainingMax = linChain;
            }
            return;
        }
        linChain++;
    } while ((portNum ^ (portNum >> 8)) % MAX_PAYLOAD_RULES != insertLoc);

    /* hash table must be full */
    /*
     * currently the hash table being full is an error, but I want to add
     * "alias" commands into the rule file so that a single rule can
     * be hinted to operate on multiple ports, e.g. SSL/TLS for 993
     * IMAPS as well as 443 HTTPS
     *
     */
}


/**
 * ycPortHashSearch
 *
 * searches the port number to scan rule hash to find the appropriate
 * rule based on the port number, uses the same hashing mechanism as
 * ycPortHashInsert.
 *
 * @param portNum the TCP/UDP port number to search for a detection
 *        rule index on
 *
 * @return the rule index to the scan rule table to use to try to
 *         payload detect if a match is found, otherwise it
 *         returns MAX_PAYLOAD_RULES+1 if there is no match
 */
uint16_t
ycPortHashSearch(
    uint16_t   portNum)
{
    uint16_t searchLoc = portNum % MAX_PAYLOAD_RULES;
    int      linChain = 0;

    /* primary hash search */
    if (portRuleHash[searchLoc].portNumber == portNum) {
        return portRuleHash[searchLoc].ruleIndex;
    }

    /* secondary hash function and search */
    searchLoc = ((MAX_PAYLOAD_RULES - portNum) ^ (portNum >> 8));
    searchLoc %= MAX_PAYLOAD_RULES;
    if (portRuleHash[searchLoc].portNumber == portNum) {
        return portRuleHash[searchLoc].ruleIndex;
    }

    /* drop down to linear chaining from secondary hash function */
    do {
        searchLoc = (searchLoc + 1) % MAX_PAYLOAD_RULES;
        if (portRuleHash[searchLoc].portNumber == portNum) {
            return portRuleHash[searchLoc].ruleIndex;
        }
        linChain++;
    } while (((portNum ^ (portNum >> 8)) % MAX_PAYLOAD_RULES != searchLoc)
             && (linChain <= linearChainingMax));

    /* no match found */
    return (MAX_PAYLOAD_RULES + 1);
}


#ifdef UNIT_TEST
/**
 * main
 *
 * this is only used when unit testing the hash.  For production everything
 * within the #ifdef for UNIT_TEST should be ignored
 *
 */
int
main(
    int    argc,
    char  *argv[])
{
    ycPortHashInitialize();

    /* first lets do a "practical" example to see how the hash functions */
    /* operate */
    printf("inserting: {80,0}, {25,1}, {53,2}, {21,3}, {143,4}, {443,5}\n");
    ycPortHashInsert(80, 0);
    ycPortHashInsert(25, 1);
    ycPortHashInsert(53, 2);
    ycPortHashInsert(21, 3);
    ycPortHashInsert(143, 4);
    ycPortHashInsert(443, 5);

    printf("searching:\n");
    printf("21, %d\n", ycPortHashSearch(21));
    printf("25, %d\n", ycPortHashSearch(25));
    printf("53, %d\n", ycPortHashSearch(53));
    printf("143, %d\n", ycPortHashSearch(143));
    printf("80, %d\n", ycPortHashSearch(80));
    printf("443, %d\n", ycPortHashSearch(443));

    printf("hashing functions used: primary: %d secondary: %d linear: %d\n",
           primaryHash, secondaryHash, linearChaining);

    printf("inserting conflicts:\n");
    ycPortHashInsert(80 + MAX_PAYLOAD_RULES, 6);
    ycPortHashInsert(25 + MAX_PAYLOAD_RULES, 7);
    ycPortHashInsert(53 + MAX_PAYLOAD_RULES, 8);

    printf("searching:\n");
    printf("%d, %d\n", (80 + MAX_PAYLOAD_RULES),
           ycPortHashSearch(80 + MAX_PAYLOAD_RULES));
    printf("%d, %d\n", (25 + MAX_PAYLOAD_RULES),
           ycPortHashSearch(25 + MAX_PAYLOAD_RULES));
    printf("%d, %d\n", (53 + MAX_PAYLOAD_RULES),
           ycPortHashSearch(53 + MAX_PAYLOAD_RULES));

    printf("hashing functions used: primary: %d secondary: %d linear: %d\n",
           primaryHash, secondaryHash, linearChaining);

    printf("testing wrap around + linear chaining\n");
    ycPortHashInsert((MAX_PAYLOAD_RULES - 3) + (0 * MAX_PAYLOAD_RULES), 9);
    ycPortHashInsert((MAX_PAYLOAD_RULES - 3) + (1 * MAX_PAYLOAD_RULES), 10);
    ycPortHashInsert((MAX_PAYLOAD_RULES - 3) + (2 * MAX_PAYLOAD_RULES), 11);
    ycPortHashInsert((MAX_PAYLOAD_RULES - 3) + (3 * MAX_PAYLOAD_RULES), 12);
    ycPortHashInsert((MAX_PAYLOAD_RULES - 3) + (4 * MAX_PAYLOAD_RULES), 13);
    ycPortHashInsert((MAX_PAYLOAD_RULES - 3) + (5 * MAX_PAYLOAD_RULES), 14);

    printf("searching:\n");
    printf("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (0 * MAX_PAYLOAD_RULES),
           ycPortHashSearch((MAX_PAYLOAD_RULES - 3) +
                            (0 * MAX_PAYLOAD_RULES)));
    printf("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (1 * MAX_PAYLOAD_RULES),
           ycPortHashSearch((MAX_PAYLOAD_RULES - 3) +
                            (1 * MAX_PAYLOAD_RULES)));
    printf("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (2 * MAX_PAYLOAD_RULES),
           ycPortHashSearch((MAX_PAYLOAD_RULES - 3) +
                            (2 * MAX_PAYLOAD_RULES)));
    printf("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (3 * MAX_PAYLOAD_RULES),
           ycPortHashSearch((MAX_PAYLOAD_RULES - 3) +
                            (3 * MAX_PAYLOAD_RULES)));
    printf("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (4 * MAX_PAYLOAD_RULES),
           ycPortHashSearch((MAX_PAYLOAD_RULES - 3) +
                            (4 * MAX_PAYLOAD_RULES)));
    printf("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (5 * MAX_PAYLOAD_RULES),
           ycPortHashSearch((MAX_PAYLOAD_RULES - 3) +
                            (5 * MAX_PAYLOAD_RULES)));

    printf("hashing functions used: primary: %d secondary: %d linear: %d\n",
           primaryHash, secondaryHash, linearChaining);

    return 0;
}


#endif /* UNIT_TEST */


#endif /* if YAF_ENABLE_APPLABEL */
