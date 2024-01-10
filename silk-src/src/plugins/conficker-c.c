/*
** Copyright (C) 2009-2023 by Carnegie Mellon University.
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

RCSIDENT("$SiLK: conficker-c.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skplugin.h>
#include <silk/utils.h>
#include <silk/rwrec.h>


/*
**  conficker-c.c
**
**    A SiLK plug-in for rwfilter/rwcut to locate possible Conficker.C
**    traffic.
**
**    Note that the plugin identifies the _targets_ of Conficker.C
**    scanning.  When a Conficker.C infected machine starts scanning
**    for other peers, it targets a somewhat random port on the
**    destination host; that is, dPort = f (dIP, time).  The plug-in
**    implements that function and returns dconf=1 if the dPort from
**    the function matches the observed dport; it returns sconf=1 if
**    the observed sPort = f (sIP, time).  If the source or
**    destination matches, that indicates that the destination or
**    source, respectively, may be infected.
**
**    The plug-in must be loaded explicitly; i.e.,
**
**        rwfilter --plugin=conficker-c.so --help
**        rwcut    --plugin=conficker-c.so --help
**        rwgroup  --plugin=conficker-c.so --help
**        rwsort   --plugin=conficker-c.so --help
**        rwstats  --plugin=conficker-c.so --help
**        rwuniq   --plugin=conficker-c.so --help
**
**    The plug-in ignores any non-UDP/non-TCP traffic.
**
**    The plug-in adds the following fields to rwfilter.  You can
**    check for Conficker.C traffic on a particular side of the flow,
**    or for either side:
**
**    --s-conficker No Arg. Pass flow if source IP and port match those
**      targeted by Conficker.C (indicating that the destination IP may
**      be infected)
**    --d-conficker No Arg. Pass flow if destination IP and port match
**      those targeted by Conficker.C (indicating that the source IP may
**      be infected)
**    --a-conficker No Arg. Pass flow if either source IP and port or
**      destination IP and port match those targeted by Conficker.C
**    --conficker-seed Req Arg. Use this value to seed Conficker.C checker.
**      Typically the flow's start time is used as the basis for the seed
**
**    The plug-in adds the --conficker-seed switch to rwcut, rwgroup,
**    rwsort, rwstats, and rwuniq, and it adds the following values to
**    fields:
**
**    sconficker -- This field contains a "1" if the sIP/sPort
**    match the values targeted by Conficker.C, indicating that the
**    destination IP may be infected.  It contains a "0" otherwise.
**
**    dconficker -- This field contains a "1" if the dIP/dPort
**    match the values targeted by Conficker.C, indicating that the
**    source IP may be infected.  It contains a "0" otherwise.
**
**
**    Conficker.C uses the time as part of its seed to generate the
**    port.  The plug-in uses the start time of the flow record as the
**    time.  You may specify a specific seed using the
**    --conficker-seed switch that the plug-in provides.
**
**    If you want to find infected hosts on your network, you
**    typically want to find hosts that are scanning for infected
**    peers; i.e., they're targeting conficker _destination_ ports.
**    So you'd use the --d-conficker flag.
**
**    To further refine the query & eliminate most false positives,
**    we've found it useful to eliminate common service ports (the
**    packets from a scanner will have sport=ephemeral,
**    dport=conficker-chosen).  So here's what I'd suggest:
**
**    rwfilter --pass=stdout \
**       --start-date=2009/05/01 --end-date=2009/05/31 --type=out \
**       --plugin=conficker-c.so --d-conficker \
**       --sport=1024- --dport=1024- \
**    | rwuniq --fields=sip --flows=10 --sort-output
**
**    We have also seen false positives from VPN traffic; depending on
**    your network, you might have to filter out UDP 500 or 10000.  In
**    any case, infected hosts are scanning so the traffic should
**    stick out like a sore thumb.
**
**
**    March 2009
*/

/* Plugin protocol version */
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0



/* EXPORTED FUNCTIONS */



/* DEFINES AND TYPEDEFS */

/* preferred width of textual columns in rwcut */
#define CONFICKER_TEXT_WIDTH   5

/* binary size */
#define CONFICKER_BINARY_SIZE  1

/* number of possible Conficker.C ports */
#define NUM_PORTS  4

/* max number of seeds to check against */
#define MAX_SEEDS  2

/* try both seeds if stime is within this many seconds of the roll-over */
#define SEED_SLOP_SECONDS  (15 * 60)

typedef struct plugin_option_st {
    struct option   opt;
    const char     *help;
} plugin_option_t;


/* LOCAL VARIABLES */

/* the seed will vary with the flow's time, unless the user sets a
 * particular value */
static uint32_t conficker_seed;
static int fixed_seed = 0;

/* which things to check in rwfilter */
static uint32_t conficker_check = 0;


/* OPTIONS SETUP */

typedef enum plugin_options_en {
    OPT_CONFICKER_SEED, S_CONFICKER, D_CONFICKER, A_CONFICKER
} plugin_options_enum;

/* options to use for rwfilter, rwcut, rwuniq, etc. */
static const plugin_option_t common_options[] =  {
    {{"conficker-seed", REQUIRED_ARG, 0, OPT_CONFICKER_SEED},
     "Use this value to seed Conficker.C checker. Typically\n"
     "\tthe flow's start time is used as the basis for the seed"},
    {{0, 0, 0, 0}, NULL}        /* sentinel */
};

/* options for rwfilter only */
static const plugin_option_t filter_options[] = {
    {{"s-conficker",    NO_ARG,       0, S_CONFICKER},
     "Pass flow if source IP and port match those targeted by\n"
     "\tConficker.C (indicating that the destination IP may be infected)"},
    {{"d-conficker",    NO_ARG,       0, D_CONFICKER},
     "Pass flow if destination IP and port match those targeted\n"
     "\tby Conficker.C (indicating that the source IP may be infected)"},
    {{"a-conficker",    NO_ARG,       0, A_CONFICKER},
     "Pass flow if either source IP and port or\n"
     "\tdestination IP and port match those targeted by Conficker.C"},
    {{0, 0, 0, 0}, NULL}        /* sentinel */
};


/* fields for rwcut, rwuniq, etc. */
static struct plugin_fields_st {
    const char *name;
    uint32_t    val;
} plugin_fields[] = {
    {"sconficker",      S_CONFICKER},
    {"dconficker",      D_CONFICKER},
    {NULL,              UINT32_MAX}     /* sentinel */
};


/* LOCAL FUNCTION PROTOTYPES */

static skplugin_err_t optionsHandler(const char *opt_arg, void *cbdata);
static skplugin_err_t
filter(
    const rwRec        *rwrec,
    void               *cbdata,
    void              **extra);
static skplugin_err_t
recToText(
    const rwRec        *rwrec,
    char               *dest,
    size_t              width,
    void               *cbdata,
    void              **extra);
static skplugin_err_t
recToBin(
    const rwRec        *rec,
    uint8_t            *dest,
    void               *cbdata,
    void              **extra);
static skplugin_err_t
binToText(
    const uint8_t      *bin,
    char               *dest,
    size_t              width,
    void               *cbdata);


/* FUNCTION DEFINITIONS */

/* the registration function called by skplugin.c */
skplugin_err_t
SKPLUGIN_SETUP_FN(
    uint16_t            major_version,
    uint16_t            minor_version,
    void        UNUSED(*pi_data))
{
    int i;
    skplugin_field_t *field;
    skplugin_err_t rv;
    skplugin_callbacks_t regdata;

    /* Check API version */
    rv = skpinSimpleCheckVersion(major_version, minor_version,
                                 PLUGIN_API_VERSION_MAJOR,
                                 PLUGIN_API_VERSION_MINOR,
                                 skAppPrintErr);
    if (rv != SKPLUGIN_OK) {
        return rv;
    }

    /* register the options to use for rwfilter.  when the option is
     * given, we will call skpinRegFilter() to register the filter
     * function. */
    for (i = 0; filter_options[i].opt.name; ++i) {
        rv = skpinRegOption2(filter_options[i].opt.name,
                             filter_options[i].opt.has_arg,
                             filter_options[i].help, NULL,
                             &optionsHandler,
                             (void*)&filter_options[i].opt.val,
                             1, SKPLUGIN_FN_FILTER);
        if (SKPLUGIN_OK != rv && SKPLUGIN_ERR_DID_NOT_REGISTER != rv) {
            return rv;
        }
    }

    /* register the options to use for all applications that we
     * support. */
    for (i = 0; common_options[i].opt.name; ++i) {
        rv = skpinRegOption2(common_options[i].opt.name,
                             common_options[i].opt.has_arg,
                             common_options[i].help, NULL,
                             &optionsHandler,
                             (void*)&common_options[i].opt.val,
                             3, SKPLUGIN_FN_FILTER, SKPLUGIN_FN_REC_TO_TEXT,
                             SKPLUGIN_FN_REC_TO_BIN);
        if (SKPLUGIN_OK != rv && SKPLUGIN_ERR_DID_NOT_REGISTER != rv) {
            return rv;
        }
    }

    /* register the fields to use for rwcut, rwuniq, rwsort */
    memset(&regdata, 0, sizeof(regdata));
    regdata.column_width = CONFICKER_TEXT_WIDTH;
    regdata.bin_bytes    = CONFICKER_BINARY_SIZE;
    regdata.rec_to_text  = recToText;
    regdata.rec_to_bin   = recToBin;
    regdata.bin_to_text  = binToText;

    for (i = 0; plugin_fields[i].name; ++i) {
        rv = skpinRegField(&field, plugin_fields[i].name, NULL,
                           &regdata, (void*)&plugin_fields[i].val);
        if (SKPLUGIN_OK != rv) {
            return rv;
        }
    }

    return SKPLUGIN_OK;
}




/*
 *  count = confickerSeeds(stime, seed_array);
 *
 *    Computes the seed(s) for Conficker.C; puts the seeds into the
 *    seed_array, and returns the number of seeds.  seed_array MUST be
 *    large enough to hold at least MAX_SEEDS seed values.
 *
 *    If a fixed_seed has been specified, it is used.  Otherwise, the
 *    flow's start-time is used compute the seed(s).
 */
static int
confickerSeeds(
    uint32_t            s_time,
    uint32_t           *seed)
{
    imaxdiv_t d;

    if (fixed_seed) {
        seed[0] = conficker_seed;
        return 1;
    }

    /* seed = int(( #days (flow stime - [1/1/1970 00:00:00])-4)/7) */
    d = imaxdiv((s_time - (4 * 86400)), (86400 * 7));
    seed[0] = (uint32_t)(d.quot);
    if (d.rem < SEED_SLOP_SECONDS) {
        /* just rolled over */
        seed[1] = seed[0] - 1;
        return 2;
    }
    if (d.rem > ((7 * 86400) - SEED_SLOP_SECONDS)) {
        /* about to roll over */
        seed[1] = seed[0] + 1;
        return 2;
    }

    return 1;
}


static const uint32_t array[] = {
    4294967295UL, 4294967295UL, 4042702779UL, 3143262195UL,
    4086788113UL, 3949445055UL, 1604057800UL,  886603921UL,
     505578207UL, 1463026372UL, 3221225604UL,   50332169UL,
      23068674UL,      20480UL, 2148532416UL,    5242944UL,
           161UL,   16777216UL,   16777216UL,     141856UL,
           128UL,   67108864UL, 1073872896UL, 2281701376UL,
           384UL,     528384UL,  142612736UL,    8391553UL,
           640UL,  134218432UL,   11010048UL,      32768UL,
       1048640UL,    1048576UL,          0UL,          0UL,
     268435464UL,          0UL,          0UL,          4UL,
             2UL,          0UL,      40000UL,          0UL,
             0UL,          0UL,    4259840UL, 2181038080UL,
             0UL,          0UL,          1UL,          0UL,
             0UL,          0UL,          0UL,          0UL,
             0UL,          0UL,          0UL,          0UL,
             0UL,          0UL,          8UL, 2147483648UL
};


/*
 *  ip2ports(ip, port_array, seed);
 *
 *    Takes an IPv4 address and a Conficker.C seed and fills
 *    port_array with the ports on which Conficker.C would
 *    communicate.  port_array MUST be large enough to hold NUM_PORTS
 *    ports.
 */
static void
ip2ports(
    const uint32_t      ip,
    uint32_t           *ports,
    const uint32_t      seed)
{
    uint64_t temp;
    int done;
    int i, j;
    uint32_t t1, t2;

    memset(ports, 0, NUM_PORTS * sizeof(uint32_t));

    temp = ~htonl(ip);

    for (j = 0; j < NUM_PORTS; j += 2) {

        done = 0;
        while (!done) {
            for (i = 0; i < 10; ++i) {
                temp = (0x15A4E35 * (temp & 0xffffffff)) + 1;
                ports[(i & 1) + j] ^= (((temp >> 32) >> i) & 0xffff);
            }

            t1 = 1 << (((ports[j] >> 5) & 0x1f) & 0xff);
            t2 = 1 << (((ports[j+1] >> 5) & 0x1f) & 0xff);
            if ((t1 & array[ports[j] >> 10])
                || (t2 & array[ports[j+1] >> 10])
                || (ports[j] == ports[j+1]))
            {
                /* no-op */
            } else {
                done = 1;
            }
        }

        temp = (temp & 0xFFFFFFFF) ^ seed;
    }
}


/*
 *  maybe_conficker_c = confickerCheck(seed_array, num_seeds, ip, port);
 *
 *    Given the seed value(s) specified in 'seed_array', return 1 if
 *    'ip' and 'port' could be an indication of Conficker.C traffic.
 *    Return 0 ohterwise.
 */
static int
confickerCheck(
    const uint32_t     *seed,
    const int           num_seeds,
    const uint32_t      rec_ip,
    const uint32_t      rec_port)
{
    uint32_t ports[NUM_PORTS * MAX_SEEDS];
    int i;

    for (i = 0; i < num_seeds; ++i) {
        ip2ports(rec_ip, &ports[i*NUM_PORTS], seed[i]);
    }
    for (i = 0; i < num_seeds * NUM_PORTS; ++i) {
        if (rec_port == ports[i]) {
            /* matches */
            return 1;
        }
    }

    /* failed */
    return 0;
}


/*
 *  status = optionsHandler(opt_arg, cddata);
 *
 *    Handles options for the plugin.  'opt_arg' is the argument the
 *    user passed to the switch, or NULL if no argument was given.
 *    'cbdata' is the callback that was specified with the option was
 *    registered.
 *
 *    Returns SKPLUGIN_OK on success, or SKPLUGIN_ERR if there was a
 *    problem.
 */
static skplugin_err_t
optionsHandler(
    const char         *opt_arg,
    void               *cbdata)
{
    static int filter_registered = 0;
    skplugin_callbacks_t regdata;
    plugin_options_enum opt_index = *((plugin_options_enum*)cbdata);
    int rv;

    switch (opt_index) {
      case S_CONFICKER:
      case D_CONFICKER:
      case A_CONFICKER:
        conficker_check |= (1 << opt_index);
        break;

      case OPT_CONFICKER_SEED:
        rv = skStringParseUint32(&conficker_seed, opt_arg, 0, 0);
        if (rv) {
            skAppPrintErr("Invalid %s '%s': %s",
                          common_options[opt_index].opt.name, opt_arg,
                          skStringParseStrerror(rv));
            return SKPLUGIN_ERR;
        }
        fixed_seed = 1;
        break;
    }

    /* register filter if we haven't */
    if (filter_registered) {
        return SKPLUGIN_OK;
    }
    filter_registered = 1;

    memset(&regdata, 0, sizeof(regdata));
    regdata.filter = filter;
    return skpinRegFilter(NULL, &regdata, NULL);
}


/*
 *  status = filter(rwrec, cbdata, extra);
 *
 *    The function actually used to implement filtering for the
 *    plugin.  Returns SKPLUGIN_FILTER_PASS if the record passes the
 *    filter, SKPLUGIN_FILTER_FAIL if it fails the filter.
 */
static skplugin_err_t
filter(
    const rwRec            *rwrec,
    void   UNUSED(         *cbdata),
    void           UNUSED(**extra))
{
    uint32_t seed[2];
    int num_seeds = 0;

    /* ignore non-TCP/non-UDP traffic */
    if ((rwRecGetProto(rwrec) != 17) && (rwRecGetProto(rwrec) != 6)) {
        return SKPLUGIN_FILTER_FAIL;
    }

    /* determine the seed */
    num_seeds = confickerSeeds(rwRecGetStartSeconds(rwrec), seed);

    /* check the source address if requested */
    if (conficker_check & ((1 << S_CONFICKER) | (1 << A_CONFICKER))) {
        if (!confickerCheck(seed, num_seeds,
                            rwRecGetSIPv4(rwrec), rwRecGetSPort(rwrec)))
        {
            /* no match, fail if source match was required */
            if (conficker_check & (1 << S_CONFICKER)) {
                return SKPLUGIN_FILTER_FAIL;
            }
        } else {
            /* matches, return pass unless must also check dest */
            if ( !(conficker_check & (1 << D_CONFICKER))) {
                return SKPLUGIN_FILTER_PASS;
            }
        }
    }

    if (conficker_check & ((1 << D_CONFICKER) | (1 << A_CONFICKER))) {
        if (confickerCheck(seed, num_seeds,
                           rwRecGetDIPv4(rwrec), rwRecGetDPort(rwrec)))
        {
            return SKPLUGIN_FILTER_PASS;
        }
    }

    return SKPLUGIN_FILTER_FAIL;
}


/*
 *  status = recToBin(rwrec, dest, cbdata, extra);
 *
 *    Depending on the value in 'cbdata', determine whether the source
 *    or destination appears to be a target of Conficker.C scanning.
 *    Write a '1' into dest if it is; a '0' otherwise.
 */
static skplugin_err_t
recToBin(
    const rwRec            *rwrec,
    uint8_t                *dest,
    void                   *cbdata,
    void           UNUSED(**extra))
{
    uint32_t seed[2];
    int num_seeds = 0;

    if ((rwRecGetProto(rwrec) == 17) || (rwRecGetProto(rwrec) == 6)) {
        /* determine the seed */
        num_seeds = confickerSeeds(rwRecGetStartSeconds(rwrec), seed);

        switch (*((unsigned int*)(cbdata))) {
          case S_CONFICKER:
            if (confickerCheck(seed, num_seeds,
                               rwRecGetSIPv4(rwrec), rwRecGetSPort(rwrec)))
            {
                /* matches */
                *dest = (uint8_t)'1';
                return SKPLUGIN_OK;
            }
            break;

          case D_CONFICKER:
            if (confickerCheck(seed, num_seeds,
                               rwRecGetDIPv4(rwrec), rwRecGetDPort(rwrec))) {
                /* matches */
                *dest = (uint8_t)'1';
                return SKPLUGIN_OK;
            }
            break;
        }
    }

    *dest = (uint8_t)'0';
    return SKPLUGIN_OK;
}


/*
 *  status = recToText(rwrec, dest, dest_size, cbdata, extra);
 *
 *    Depending on the value in 'cbdata', determine whether the source
 *    or destination appears to be a target of Conficker.C scanning.
 *    Write the string "1" into dest if it is, or "0" otherwise.
 */
static skplugin_err_t
recToText(
    const rwRec        *rwrec,
    char               *dest,
    size_t              dest_size,
    void               *cbdata,
    void              **extra)
{
    if (dest_size < 2) {
        return SKPLUGIN_ERR_FATAL;
    }

    recToBin(rwrec, (uint8_t*)dest, cbdata, extra);
    dest[1] = '\0';
    return SKPLUGIN_OK;
}


/*
 *  status = recToText(bin, dest, dest_size, cbdata);
 *
 *    Convert the binary value in 'bin' to a textual value.
 */
static skplugin_err_t
binToText(
    const uint8_t          *bin,
    char                   *dest,
    size_t                  dest_size,
    void            UNUSED(*cbdata))
{
    if (dest_size < 2) {
        return SKPLUGIN_ERR_FATAL;
    }

    dest[0] = (char)(bin[0]);
    dest[1] = '\0';
    return SKPLUGIN_OK;
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
