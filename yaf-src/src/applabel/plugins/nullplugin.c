/*
 *  Copyright 2007-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  null plugin
 *
 *  these plugins do nothing, they don't recognize any protocols, they
 *  are useful for testing the shared library loading and argument
 *  passing to the plugins
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
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <payloadScanner.h>

YC_SCANNER_PROTOTYPE(nullplugin_LTX_ycNullScanScan);
YC_SCANNER_PROTOTYPE(nullplugin_LTX_ycNullScanScan2);
YC_SCANNER_PROTOTYPE(nullplugin_LTX_ycNullScanScan3);
YC_SCANNER_PROTOTYPE(nullplugin_LTX_ycNullScanScan4);

/* #define DEBUG_VERBOSITY */


/**
 * nullplugin_LTX_ycNullScanScan
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return always 0
 */
uint16_t
nullplugin_LTX_ycNullScanScan(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#ifdef DEBUG_VERBOSITY
    int loop;
#endif

    /* supress compiler warnings about unused arguments */
    (void)payload;
    (void)payloadSize;
    (void)argc;
    (void)argv;
    (void)flow;
    (void)val;

#ifdef DEBUG_VERBOSITY
    for (loop = 0; loop < argc; loop++) {
        printf("arg %d is \"%s\"\n", loop, argv[loop]);
    }
#endif

    return 0;
}


/**
 * nullplugin_LTX_ycNullScanScan2
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return always 0
 */
uint16_t
nullplugin_LTX_ycNullScanScan2(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#ifdef DEBUG_VERBOSITY
    int loop;
#endif

    /* supress compiler warnings about unused arguments */
    (void)payload;
    (void)payloadSize;
    (void)argc;
    (void)argv;
    (void)flow;
    (void)val;

#ifdef DEBUG_VERBOSITY
    for (loop = 0; loop < argc; loop++) {
        printf("arg %d is \"%s\"\n", loop, argv[loop]);
    }
#endif

    return 0;
}


/**
 * nullplugin_LTX_ycNullScanScan3
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return always 0
 */
uint16_t
nullplugin_LTX_ycNullScanScan3(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#ifdef DEBUG_VERBOSITY
    int loop;
#endif

    /* supress compiler warnings about unused arguments */
    (void)payload;
    (void)payloadSize;
    (void)argc;
    (void)argv;
    (void)flow;
    (void)val;

#ifdef DEBUG_VERBOSITY
    for (loop = 0; loop < argc; loop++) {
        printf("arg %d is \"%s\"\n", loop, argv[loop]);
    }
#endif

    return 0;
}


/**
 * nullplugin_LTX_ycNullScanScan4
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return always 0
 */
uint16_t
nullplugin_LTX_ycNullScanScan4(
    int             argc,
    char           *argv[],
    const uint8_t  *payload,
    unsigned int    payloadSize,
    yfFlow_t       *flow,
    yfFlowVal_t    *val)
{
#ifdef DEBUG_VERBOSITY
    int loop;
#endif

    /* supress compiler warnings about unused arguments */
    (void)payload;
    (void)payloadSize;
    (void)argc;
    (void)argv;
    (void)flow;
    (void)val;

#ifdef DEBUG_VERBOSITY
    for (loop = 0; loop < argc; loop++) {
        printf("arg %d is \"%s\"\n", loop, argv[loop]);
    }
#endif

    return 0;
}
