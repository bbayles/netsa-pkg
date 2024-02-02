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

/*
**  sku-string.c
**
**  A collection of utility routines to manipulate strings
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: sku-string.c c3cb530920e1 2023-04-26 14:50:25Z mthomas $");

#include <silk/utils.h>
#include <silk/skipaddr.h>
#include <silk/skvector.h>
#include <silk/rwrec.h>

#ifndef USE_GETADDRINFO
#  ifdef SK_HAVE_GETADDRINFO
#    define USE_GETADDRINFO 1
#  else
#    define USE_GETADDRINFO 0
#  endif
#endif
#if !USE_GETADDRINFO && SK_ENABLE_INET6_NETWORKING
#  undef SK_ENABLE_INET6_NETWORKING
#  define SK_ENABLE_INET6_NETWORKING 0
#endif


#define STRING_PARSE_MIN_YEAR   1970
#define STRING_PARSE_MAX_YEAR   2039
#define STRING_PARSE_MIN_EPOCH  (1 << 29)       /* Mon Jan  5 18:48:32 1987 */
#define STRING_PARSE_MAX_EPOCH  ((1u << 31)-1)  /* Tue Jan 19 03:14:07 2038 */


static const struct signal_name2num_st {
    const char *name;
    int         number;
} signal_name2num[] = {
#ifdef SIGABRT
    {"ABRT",    SIGABRT},
#endif
#ifdef SIGALRM
    {"ALRM",    SIGALRM},
#endif
#ifdef SIGBUS
    {"BUS",     SIGBUS},
#endif
#ifdef SIGCANCEL
    {"CANCEL",  SIGCANCEL},
#endif
#ifdef SIGCHLD
    {"CHLD",    SIGCHLD},
#endif
#ifdef SIGCLD
    {"CLD",     SIGCLD},
#endif
#ifdef SIGCONT
    {"CONT",    SIGCONT},
#endif
#ifdef SIGEMT
    {"EMT",     SIGEMT},
#endif
#ifdef SIGEXIT
    {"EXIT",    SIGEXIT},
#endif
#ifdef SIGFPE
    {"FPE",     SIGFPE},
#endif
#ifdef SIGFREEZE
    {"FREEZE",  SIGFREEZE},
#endif
#ifdef SIGHUP
    {"HUP",     SIGHUP},
#endif
#ifdef SIGILL
    {"ILL",     SIGILL},
#endif
#ifdef SIGINFO
    {"INFO",    SIGINFO},
#endif
#ifdef SIGINT
    {"INT",     SIGINT},
#endif
#ifdef SIGIO
    {"IO",      SIGIO},
#endif
#ifdef SIGIOT
    {"IOT",     SIGIOT},
#endif
#ifdef SIGKILL
    {"KILL",    SIGKILL},
#endif
#ifdef SIGLOST
    {"LOST",    SIGLOST},
#endif
#ifdef SIGPIPE
    {"PIPE",    SIGPIPE},
#endif
#ifdef SIGPOLL
    {"POLL",    SIGPOLL},
#endif
#ifdef SIGPROF
    {"PROF",    SIGPROF},
#endif
#ifdef SIGPWR
    {"PWR",     SIGPWR},
#endif
#ifdef SIGQUIT
    {"QUIT",    SIGQUIT},
#endif
#ifdef SIGSEGV
    {"SEGV",    SIGSEGV},
#endif
#ifdef SIGSTKFLT
    {"STKFLT",  SIGSTKFLT},
#endif
#ifdef SIGSTOP
    {"STOP",    SIGSTOP},
#endif
#ifdef SIGSYS
    {"SYS",     SIGSYS},
#endif
#ifdef SIGTERM
    {"TERM",    SIGTERM},
#endif
#ifdef SIGTHAW
    {"THAW",    SIGTHAW},
#endif
#ifdef SIGTRAP
    {"TRAP",    SIGTRAP},
#endif
#ifdef SIGTSTP
    {"TSTP",    SIGTSTP},
#endif
#ifdef SIGTTIN
    {"TTIN",    SIGTTIN},
#endif
#ifdef SIGTTOU
    {"TTOU",    SIGTTOU},
#endif
#ifdef SIGUNUSED
    {"UNUSED",  SIGUNUSED},
#endif
#ifdef SIGURG
    {"URG",     SIGURG},
#endif
#ifdef SIGUSR1
    {"USR1",    SIGUSR1},
#endif
#ifdef SIGUSR2
    {"USR2",    SIGUSR2},
#endif
#ifdef SIGVTALRM
    {"VTALRM",  SIGVTALRM},
#endif
#ifdef SIGWAITING
    {"WAITING", SIGWAITING},
#endif
#ifdef SIGWINCH
    {"WINCH",   SIGWINCH},
#endif
#ifdef SIGXCPU
    {"XCPU",    SIGXCPU},
#endif
#ifdef SIGXFSZ
    {"XFSZ",    SIGXFSZ},
#endif
#ifdef SIGXRES
    {"XRES",    SIGXRES},
#endif
    {"",        0}
};

static const int signal_name2num_count =
    ((sizeof(signal_name2num)/sizeof(struct signal_name2num_st)) - 1);


/* Structure used when parsing a comma-separated list of numbers and ranges */
typedef struct sk_number_parser_st {
    const char *sp;
    const char *end_chars;
    int         base;
    uint32_t    min;
    uint32_t    max;
} sk_number_parser_t;

/* Values used by numberListParser*() to indicate success.  Error
 * values are given by silk_utils_errcode_t. */
typedef enum {
    /* Indicates numberListParserInit() initialized successfully */
    SK_NUM_PARSER_OK = 0,

    /* Indicates numberListParserNext() parsed a single number and
     * an optional trailing comma, e.g. "3" or "5," */
    SK_NUM_PARSER_NUMBER,

    /* Indicates numberListParserNext() parsed a range and an
     * optional trailing comma, e.g., "3-4" or "5-6," */
    SK_NUM_PARSER_RANGE,

    /* Indicates numberListParserNext() parsed an open-ended range
     * and an optional trailing comma, e.g., "3-" or "5-,".  Ranges
     * with open-beginnings (e.g., "-7") are not allowed. */
    SK_NUM_PARSER_RANGE_OPENMAX,

    /* Indicates numberListParserInit() or
     * numberListParserNext() reached the end of the number list;
     * that is, current character is NUL, or whitespace, or a
     * character specified in the end_chars. */
    SK_NUM_PARSER_END_OF_STRING
} sk_number_parser_result_t;


/*
 *  pos = numberParserCurrentChar(p);
 *
 *    Returns the beginning of the token that the parser was parsing
 *    when it encountered the error.
 */
#define numberParserCurrentChar(parser) ((parser)->sp)


/*
 *   The following macros, variables, and functions are used to set
 *   error messages encountered when parsing something, and they work
 *   with the silk_utils_errcode_t enumeration defined in utils.h.
 *
 *   The parseError() function stores an error message in the
 *   parse_error_buf[] array, where we maintain the most recent error
 *   for each error code.
 *
 *   The caller can access the messages in the array with the
 *   skStringParseStrerror() function.
 */

/* this should be same magnitude as the last error code specified in
 * silk_utils_errcode_t */
#define PARSE_ERRORCODE_COUNT  ((silk_utils_errcode_t)13)

/* convert silk_utils_errcode_t 'errcode' to a positive index used to
 * index into parse_error_buf[] and parse_error_default[].  Value with
 * largest magnitude becomes 0; the "succcess" value of 0 becomes
 * PARSE_ERRORCODE_COUNT. */
#define PARSE_ERRORCODE_TO_INDEX(errcode)       \
    (((errcode) < -PARSE_ERRORCODE_COUNT)       \
     ? (-1)                                     \
     : ((errcode) + PARSE_ERRORCODE_COUNT))

/* return default error message for silk_utils_errcode_t 'errcode' */
#define PARSE_ERRORCODE_MSG(errcode)                            \
    (((errcode) < -PARSE_ERRORCODE_COUNT || (errcode) > 0)      \
     ? ""                                                       \
     : parse_error_default[PARSE_ERRORCODE_TO_INDEX(errcode)])

/* hold the most recent error for each silk_utils_errcode_t */
static char parse_error_buf[PARSE_ERRORCODE_COUNT+1][2048];

/* these are in reverse order of how they appear in the definition of
 * silk_utils_errcode_t */
static const char *parse_error_default[PARSE_ERRORCODE_COUNT+1] = {
    "Could not resolve hostname or port",   /* SKUTILS_ERR_RESOLVE */
    "Value is above maximum",               /* SKUTILS_ERR_MAXIMUM */
    "Value is below minimum",               /* SKUTILS_ERR_MINIMUM */
    "Miscellaneous error",                  /* SKUTILS_ERR_OTHER */
    "Out of memory",                        /* SKUTILS_ERR_ALLOC */
    "Too many fields provided",             /* SKUTILS_ERR_TOO_MANY_FIELDS */
    "Unexpected end-of-input",              /* SKUTILS_ERR_SHORT */
    "Range is invalid (min > max)",         /* SKUTILS_ERR_BAD_RANGE */
    "Value underflows the parser",          /* SKUTILS_ERR_UNDERFLOW */
    "Value overflows the parser",           /* SKUTILS_ERR_OVERFLOW */
    "Unexpected character",                 /* SKUTILS_ERR_BAD_CHAR */
    "Input is empty or all whitespace",     /* SKUTILS_ERR_EMPTY */
    "Invalid input to function",            /* SKUTILS_ERR_INVALID */
    "Command successful"                    /* SKUTILS_OK */
};


#ifdef TEST_PRINTF_FORMATS
#  define parseError(errcode, ...) printf(__VA_ARGS__)
#  define PE_NULL  "ERROR"
#else
#  define PE_NULL  NULL
static int
parseError(
    silk_utils_errcode_t    errcode,
    const char             *fmt,
    ...)
    SK_CHECK_PRINTF(2, 3);

static int
parseError(
    silk_utils_errcode_t    errcode,
    const char             *fmt,
    ...)
{
    va_list args;
    int idx;
    char *buf;

    idx = PARSE_ERRORCODE_TO_INDEX(errcode);

    if (idx < 0 || idx > PARSE_ERRORCODE_COUNT) {
        return errcode;
    }
    buf = parse_error_buf[idx];

    if (fmt == PE_NULL) {
        snprintf(buf, sizeof(parse_error_buf[0]), "%s",
                 parse_error_default[idx]);
        buf[sizeof(parse_error_buf[0])-1] = '\0';
        return errcode;
    }

    va_start(args, fmt);
    vsnprintf(buf, sizeof(parse_error_buf[0]), fmt, args);
    buf[sizeof(parse_error_buf[0])-1] = '\0';
    va_end(args);
    return errcode;
}
#endif /* TEST_PRINTF_FORMATS */


const char *
skStringParseStrerror(
    int                 errorcode)
{
    static char tmpbuf[2048];
    int idx = PARSE_ERRORCODE_TO_INDEX(errorcode);

    if (errorcode > 0) {
        return "Extra text follows value";
    }
    if (idx < 0 || idx > PARSE_ERRORCODE_COUNT) {
        snprintf(tmpbuf, sizeof(tmpbuf), "Unrecognized error (%d)", errorcode);
        tmpbuf[sizeof(tmpbuf)-1] = '\0';
        return tmpbuf;
    }

    return parse_error_buf[idx];
}


/* Convert integer 0 to string "0.0.0.0"; uses static buffer */
char *
num2dot(
    uint32_t            ip)
{
    static char outbuf[SKIPADDR_STRLEN];
    skipaddr_t ipaddr;

    skipaddrSetV4(&ipaddr, &ip);
    return skipaddrString(outbuf, &ipaddr, SKIPADDR_CANONICAL);
}


/* Convert integer 0 to string "0.0.0.0"; uses caller's buffer */
char *
num2dot_r(
    uint32_t            ip,
    char               *outbuf)
{
    skipaddr_t ipaddr;

    skipaddrSetV4(&ipaddr, &ip);
    return skipaddrString(outbuf, &ipaddr, SKIPADDR_CANONICAL);
}


/* Convert integer 0 to string "000.000.000.000"; uses static buffer */
char *
num2dot0(
    uint32_t            ip)
{
    static char outbuf[SKIPADDR_STRLEN];
    skipaddr_t ipaddr;

    skipaddrSetV4(&ipaddr, &ip);
    return skipaddrString(outbuf, &ipaddr,
                          SKIPADDR_CANONICAL | SKIPADDR_ZEROPAD);
}


/* Convert integer 0 to string "000.000.000.000"; uses caller's buffer */
char *
num2dot0_r(
    uint32_t            ip,
    char               *outbuf)
{
    skipaddr_t ipaddr;

    skipaddrSetV4(&ipaddr, &ip);
    return skipaddrString(outbuf, &ipaddr,
                          SKIPADDR_CANONICAL | SKIPADDR_ZEROPAD);
}


/* Convert integer to FSRPAUEC string.  Uses caller's buffer. */
char *
skTCPFlagsString(
    uint8_t             flags,
    char               *outbuf,
    unsigned int        print_flags)
{
    if (print_flags & SK_PADDED_FLAGS) {
        outbuf[0] = (flags & FIN_FLAG) ? 'F' : ' ';
        outbuf[1] = (flags & SYN_FLAG) ? 'S' : ' ';
        outbuf[2] = (flags & RST_FLAG) ? 'R' : ' ';
        outbuf[3] = (flags & PSH_FLAG) ? 'P' : ' ';
        outbuf[4] = (flags & ACK_FLAG) ? 'A' : ' ';
        outbuf[5] = (flags & URG_FLAG) ? 'U' : ' ';
        outbuf[6] = (flags & ECE_FLAG) ? 'E' : ' ';
        outbuf[7] = (flags & CWR_FLAG) ? 'C' : ' ';
        outbuf[8] = '\0';
    } else {
        char *c = outbuf;
        if (flags & FIN_FLAG) { *c = 'F'; ++c; }
        if (flags & SYN_FLAG) { *c = 'S'; ++c; }
        if (flags & RST_FLAG) { *c = 'R'; ++c; }
        if (flags & PSH_FLAG) { *c = 'P'; ++c; }
        if (flags & ACK_FLAG) { *c = 'A'; ++c; }
        if (flags & URG_FLAG) { *c = 'U'; ++c; }
        if (flags & ECE_FLAG) { *c = 'E'; ++c; }
        if (flags & CWR_FLAG) { *c = 'C'; ++c; }
        *c = '\0';
    }
    return outbuf;
}

/* Deprecated */
char *
tcpflags_string_r(
    uint8_t             flags,
    char               *outbuf)
{
    return skTCPFlagsString(flags, outbuf, SK_PADDED_FLAGS);
}

/* Deprecated */
char *
tcpflags_string(
    uint8_t             flags)
{
    static char flag_string[SK_TCPFLAGS_STRLEN];
    return skTCPFlagsString(flags, flag_string, SK_PADDED_FLAGS);
}


/* Convert integer to TCP state string.  Uses caller's buffer. */
char *
skTCPStateString(
    uint8_t             state,
    char               *outbuf,
    unsigned int        print_flags)
{
    if (print_flags & SK_PADDED_FLAGS) {
        outbuf[0] = (state & SK_TCPSTATE_TIMEOUT_KILLED      ) ? 'T' : ' ';
        outbuf[1] = (state & SK_TCPSTATE_TIMEOUT_STARTED     ) ? 'C' : ' ';
        outbuf[2] = (state & SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK) ? 'F' : ' ';
        outbuf[3] = (state & SK_TCPSTATE_UNIFORM_PACKET_SIZE ) ? 'S' : ' ';
        outbuf[4] = ' ';
        outbuf[5] = ' ';
        outbuf[6] = ' ';
        outbuf[7] = ' ';
        outbuf[8] = '\0';
    } else {
        char *c = outbuf;
        if (state & SK_TCPSTATE_TIMEOUT_KILLED      ) { *c = 'T'; ++c; }
        if (state & SK_TCPSTATE_TIMEOUT_STARTED     ) { *c = 'C'; ++c; }
        if (state & SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK) { *c = 'F'; ++c; }
        if (state & SK_TCPSTATE_UNIFORM_PACKET_SIZE ) { *c = 'S'; ++c; }
        *c = '\0';
    }
    return outbuf;
}


/* strip whitespace of line in-place; return length */
int
skStrip(
    char               *line)
{
    char *sp, *ep;
    int len;

    sp  = line;
    while ( *sp && isspace((int)*sp) ) {
        sp++;
    }
    /* at first non-space char OR at end of line */
    if (*sp == '\0') {
        /* line full of white space. nail at beginning and return with 0 */
        line[0] = '\0';
        return 0;
    }

    /* figure out where to stop the line */
    ep = sp + strlen(sp) - 1;
    while ( isspace((int)*ep) && (ep > sp) ) {
        ep--;
    }
    /* ep at last non-space char. Nail after */
    ep++;
    *ep = '\0';

    len = (int)(ep - sp);
    if (sp == line) {
        /* no shifting required */
        return(len);
    }

    memmove(line, sp, len+1);
    return(len);
}


/* Down-case 'cp' in place */
void
skToLower(
    char               *cp)
{
    while (*cp) {
        if (isupper((int)*cp)) {
            *cp = *cp + 32;
        }
        cp++;
    }
    return;
}


/* Up-case 'cp' in place */
void
skToUpper(
    char               *cp)
{
    while (*cp) {
        if (islower((int)*cp)) {
            *cp = *cp - 32;
        }
        cp++;
    }
    return;
}


/*
 *  result = numberListParserInit(&p,input,base,end_chars,minimum,maximum);
 *
 *    Fills in the sk_number_parser_t data structure---which should
 *    have been declared and allocated by the caller---pointed at by
 *    'p' with state necessary to call numberListParserNext().
 *
 *    The caller must not modify 'input' while the
 *    numberListParserNext() function is in use.
 *
 *    'end_chars' should be NULL or a string listing characters to be
 *    considered, in addition to whitespace, as end-of-input markers.
 *
 *    'mimimum' and 'maximum' define the allowable range for numbers
 *    in the list.
 *
 *    On success, SK_NUM_PARSER_OK is returned.  If the string is
 *    empty or begins with a character listed in 'end_chars',
 *    SK_NUM_PARSER_END_OF_STRING is returned.  Otherwise, this
 *    function returns a silk_utils_errcode_t value.
 */
static int
numberListParserInit(
    sk_number_parser_t *parser,
    const char         *input,
    int                 base,
    const char         *end_chars,
    uint32_t            minimum,
    uint32_t            maximum)
{
    /* check input */
    assert(parser);
    assert(input);
    assert(base == 10 || base == 16);

    if (maximum == 0) {
        maximum = UINT32_MAX;
    } else if (minimum > maximum) {
        return parseError(SKUTILS_ERR_INVALID,
                          ("Range maximum (%" PRIu32 ") is less than"
                           " range minimum (%" PRIu32 ")"),
                          maximum, minimum);
    }

    if (*input == '\0') {
        return SK_NUM_PARSER_END_OF_STRING;
    }
    if (isspace((int)*input)) {
        return SK_NUM_PARSER_END_OF_STRING;
    }
    if (end_chars && (strchr(end_chars, *input))) {
        return SK_NUM_PARSER_END_OF_STRING;
    }

    if (base == 10 && !isdigit((int)*input)) {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s at '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *input);
    } else if (base == 16 && !isxdigit((int)*input)) {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s at '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *input);
    }

    parser->min = minimum;
    parser->max = maximum;
    parser->sp = input;
    parser->end_chars = end_chars;
    parser->base = base;
    return SK_NUM_PARSER_OK;
}


/*
 *  result = numberListParserNext(&out_val, &out_length, p);
 *
 *    Parse the next number or range in the 'input' that was used to
 *    initialize the sk_number_parser_t 'p'.
 *
 *    If the next token is a single number ("3,"), its value is stored
 *    in 'out_val', 1 is stored in 'out_length', and
 *    SK_NUM_PARSER_NUMBER is returned.
 *
 *    If the next token is a range ("2-4,"), the starting value (2) is
 *    stored in 'out_val', the number of elements in the range (3) is
 *    stored in 'out_length', and SK_NUM_PARSER_RANGE is returned.
 *
 *    When there are no more tokens in 'input',
 *    SK_NUM_PARSER_END_OF_STRING is returned.
 *
 *    Any other return value indicates an error.
 */
static int
numberListParserNext(
    uint64_t           *range_length,
    uint32_t           *value,
    sk_number_parser_t *parser)
{
    unsigned long n = 0;
    const char *sp;
    char *ep;
    int rv;

    /* check input */
    assert(parser);
    assert(value);
    assert(range_length);

    /* initialize vars */
    *value = 0;
    *range_length = 0;
    sp = parser->sp;

    /* are we at end of list? */
    if (*sp == '\0') {
        return SK_NUM_PARSER_END_OF_STRING;
    }
    if (isspace((int)*sp)) {
        return SK_NUM_PARSER_END_OF_STRING;
    }
    if (parser->end_chars && (strchr(parser->end_chars, *sp))) {
        return SK_NUM_PARSER_END_OF_STRING;
    }

    while (*sp) {
        /* parse the number */
        errno = 0;
        n = strtoul(sp, &ep, parser->base);
        if (sp == ep) {
            rv = parseError(SKUTILS_ERR_BAD_CHAR, "%s at '%c'",
                            PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *sp);
            goto END;
        }
        if (n == ULONG_MAX && errno == ERANGE) {
            rv = parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
            goto END;
        }
        if (n < parser->min) {
            rv = parseError(SKUTILS_ERR_MINIMUM, "%s of %" PRIu32,
                            PARSE_ERRORCODE_MSG(SKUTILS_ERR_MINIMUM),
                            parser->min);
            goto END;
        }
        if (n > parser->max) {
            rv = parseError(SKUTILS_ERR_MAXIMUM, "%s of %" PRIu32,
                            PARSE_ERRORCODE_MSG(SKUTILS_ERR_MAXIMUM),
                            parser->max);
            goto END;
        }

        /* parsed the number; move pointer to next token */
        sp = ep;

        /* see if we are parsing a range; if so, store the first
         * number (lower limit) and loop through the while again in
         * order to parse the second number (upper limit). */
        if (*sp != '-') {
            break;
        } else if (*range_length != 0) {
            /* second pass through the while loop yet we're looking at
             * another hyphen.  We've got something like "1-2-".  An
             * error */
            rv = parseError(SKUTILS_ERR_BAD_CHAR, "%s at '%c'",
                            PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *sp);
            goto END;
        } else {
            /* first pass, we just parsed lower limit */
            ++sp;
            if ((parser->base == 10 && isdigit((int)*sp))
                || (parser->base == 16 && isxdigit((int)*sp)))
            {
                /* looks like a good range; store the value we just
                 * parsed, set range_length so we know we're in a
                 * range, and loop again */
                *value = n;
                *range_length = 1;
                continue;
            } else if (*sp == '\0' || *sp == ',') {
                /* open-ended range, store current value, use
                 * range_length to denote open-ended range, set n to
                 * the max */
                *value = n;
                *range_length = 2;
                n = parser->max;
                break;
            } else {
                rv = parseError(SKUTILS_ERR_BAD_CHAR, "%s at '%c'",
                                PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                *sp);
                goto END;
            }
        }
    }

    /* we've parsed a number or a range */
    if (*range_length == 0) {
        /* single number */
        *value = n;
        *range_length = 1;
        rv =  SK_NUM_PARSER_NUMBER;
    } else if (*range_length == 2) {
        *range_length = (n - *value + 1);
        rv = SK_NUM_PARSER_RANGE_OPENMAX;
    } else if (n == *value) {
        /* range of 3-3; treat as single number */
        rv =  SK_NUM_PARSER_NUMBER;
    } else if (n < *value) {
        rv = parseError(SKUTILS_ERR_BAD_RANGE,
                        ("%s (%" PRIu32 "-%lu)"),
                        PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_RANGE),
                        *value, n);
        goto END;
    } else {
        *range_length = (n - *value + 1);
        rv =  SK_NUM_PARSER_RANGE;
    }

    /* move forward to the start of the next number. */
    while (*sp) {
        if (isspace((int)*sp)) {
            /* this marks the end of the number list */
            break;
        }
        if (parser->end_chars && (strchr(parser->end_chars, *sp))) {
            /* this also marks the end of the number list */
            break;
        }
        if ((parser->base == 10 && isdigit((int)*sp))
            || (parser->base == 16 && isxdigit((int)*sp)))
        {
            /* this is what we expect*/
            break;
        }
        if (*sp == ',') {
            /* duplicate comma is allowed */
            ++sp;
            continue;
        }
        if (*sp == '-') {
            /* error */
            rv = parseError(SKUTILS_ERR_BAD_CHAR, "%s at '%c'",
                            PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                            *sp);
            goto END;
        }

        /* error */
        rv = parseError(SKUTILS_ERR_BAD_CHAR, "%s at '%c'",
                        PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                        *sp);
        goto END;
    }

  END:
    /* store our current location */
    parser->sp = sp;
    return rv;
}


/* parse string "4,3,2-6" to array {4,3,2,3,4,5,6}.  See header for details */
int
skStringParseNumberList(
    uint32_t          **number_list,
    uint32_t           *number_count,
    const char         *input,
    uint32_t            min_value,
    uint32_t            max_value,
    uint32_t            max_number_count)
{
    uint64_t range_length;
    uint64_t i;
    uint32_t range_start;
    uint32_t *out_array_list = NULL; /* returned array */
    uint32_t out_count = 0; /* returned count */
    uint32_t array_size;
    sk_number_parser_t parser;
    const char *sp;
    int rv = SKUTILS_OK;

    /* check input */
    assert(number_list);
    assert(number_count);
    if (input == NULL) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    /* eat leading whitespace */
    sp = input;
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' == *sp) {
        /* whitespace only or empty string */
        return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
    }

    rv = numberListParserInit(&parser, sp, 10, NULL, min_value, max_value);
    if (rv != SK_NUM_PARSER_OK) {
        return rv;
    }

    /* If no max count was given, assume the user is only allowed to
     * choose each item one time, and set the max_number_count to the
     * number of items. */
    if (max_number_count == 0) {
        if (max_value != 0) {
            max_number_count = 1 + max_value - min_value;
        } else {
            /* something big */
            max_number_count = (1 << 24);
        }
    }

    /* Create the array to hold the list of values.  If
     * max_number_count is greater than 256, use half of it as the
     * initial size; otherwise, create an array of max_number_count
     * entries. */
    if (max_number_count <= 256) {
        array_size = max_number_count;
    } else {
        array_size = max_number_count / 2;
    }
    out_array_list = (uint32_t*)calloc(array_size, sizeof(uint32_t));
    if (!out_array_list) {
        rv = parseError(SKUTILS_ERR_ALLOC, PE_NULL);
        goto ERROR;
    }

    while ((rv = numberListParserNext(&range_length, &range_start, &parser))
           != SK_NUM_PARSER_END_OF_STRING)
    {
        if (rv < 0) {
            goto ERROR;
        }
        switch ((sk_number_parser_result_t)rv) {
          case SK_NUM_PARSER_OK:
          case SK_NUM_PARSER_END_OF_STRING:
            /* these should not occur */
            skAbortBadCase(rv);

          case SK_NUM_PARSER_RANGE_OPENMAX:
            rv = parseError(SKUTILS_ERR_BAD_CHAR,
                            ("Range is missing its upper limit"
                             " (open-ended ranges are not supported)"));
            goto ERROR;

          case SK_NUM_PARSER_NUMBER:
          case SK_NUM_PARSER_RANGE:
            /* check number of fields user gave */
            if ((out_count + range_length) > max_number_count) {
                rv = parseError(SKUTILS_ERR_TOO_MANY_FIELDS,
                                ("Too many fields (%" PRIu64 ") provided;"
                                 " only %" PRIu32 " fields allowed"),
                                (range_length + out_count), max_number_count);
                goto ERROR;
            }

            /* check if we need to grow array?  If so, realloc the array
             * to double its size and memset the new section to 0. */
            while ((out_count + range_length) > array_size) {
                size_t old_size = array_size;
                uint32_t *old_array = out_array_list;
                array_size *= 2;
                if (array_size > max_number_count) {
                    array_size = max_number_count;
                }
                out_array_list = (uint32_t*)realloc(
                    out_array_list, array_size * sizeof(uint32_t));
                if (!out_array_list) {
                    out_array_list = old_array;
                    rv = parseError(SKUTILS_ERR_ALLOC, PE_NULL);
                    goto ERROR;
                }
                memset((out_array_list+old_size), 0,
                       (array_size-old_size) * sizeof(uint32_t));
            }

            /* add the entries */
            for (i = 0; i < range_length; ++i, ++range_start, ++out_count) {
                out_array_list[out_count] = range_start;
            }
            break;
        }
    }

    assert(rv == SK_NUM_PARSER_END_OF_STRING);
    rv = SKUTILS_OK;

    /* handle any whitespace at end of string */
    sp = numberParserCurrentChar(&parser);
    while (isspace((int)*sp)) {
        ++sp;
    }
    if (*sp != '\0') {
        rv = parseError(SKUTILS_ERR_BAD_CHAR,
                        "%s--embedded whitespace found in input",
                        PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR));
        goto ERROR;
    }

    *number_count = out_count;
    *number_list = out_array_list;
    return rv;

  ERROR:
    if (out_array_list) {
        free(out_array_list);
    }
    *number_count = 0;
    return rv;
}


/* parse string "4,3,2-6" to skbitmap.  See header for details */
int
skStringParseNumberListToBitmap(
    sk_bitmap_t        *out_bitmap,
    const char         *input)
{
    uint64_t range_length;
    uint64_t i;
    uint32_t value;
    uint32_t bitmap_size;
    sk_number_parser_t parser;
    const char *sp;
    int rv;

    memset(&parser, 0, sizeof(parser));

    /* check input */
    assert(out_bitmap);
    if (input == NULL) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    /* check bitmap size */
    bitmap_size = skBitmapGetSize(out_bitmap);
    if (bitmap_size < 1) {
        /* bitmap too small */
        return parseError(SKUTILS_ERR_INVALID, "Bitmap is too small");
    }

    /* eat leading whitespace */
    sp = input;
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' == *sp) {
        /* whitespace only or empty string */
        return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
    }

    rv = numberListParserInit(&parser, sp, 10, NULL, 0, bitmap_size-1);
    if (rv != SK_NUM_PARSER_OK) {
        return rv;
    }

    while ((rv = numberListParserNext(&range_length, &value, &parser))
           != SK_NUM_PARSER_END_OF_STRING)
    {
        if (rv < 0) {
            return rv;
        }
        switch ((sk_number_parser_result_t)rv) {
          case SK_NUM_PARSER_NUMBER:
          case SK_NUM_PARSER_RANGE:
          case SK_NUM_PARSER_RANGE_OPENMAX:
            /* add the entries */
            for (i = 0; i < range_length; ++i, ++value) {
                skBitmapSetBit(out_bitmap, value);
            }
            break;

          case SK_NUM_PARSER_OK:
          case SK_NUM_PARSER_END_OF_STRING:
            /* impossible */
            skAbortBadCase(rv);
        }
    }

    assert(rv == SK_NUM_PARSER_END_OF_STRING);

    /* handle any whitespace at end of string */
    sp = numberParserCurrentChar(&parser);
    while (isspace((int)*sp)) {
        ++sp;
    }
    if (*sp != '\0') {
        return parseError(SKUTILS_ERR_BAD_CHAR,
                          "%s--embedded whitespace found in input",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR));
    }

    return SKUTILS_OK;
}


/*
 *  status = parseIPv4(&ip_value, ip_string);
 *
 *    A helper function for skStringParseIP().
 *
 *    Parse the IPv4 address at 'ip_string' and put the result--in
 *    native byte order--into the memory pointed at by 'ip_value'.
 *    Return a negative (silk_utils_errcode_t) value on error;
 *    otherwise return a positive value specifying the number of
 *    characters that were parsed.
 */
static int
parseIPv4(
    uint32_t           *ip,
    const char         *ip_string)
{
    unsigned long final = 0;
    unsigned long val;
    const char *sp = ip_string;
    char *ep;
    int i;

    *ip = 0;

    /* number that begins with '-' is not unsigned */
    if ('-' == *sp) {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                          *sp);
    }

    for (i = 3; i >= 0; --i) {
        /* parse the number */
        errno = 0;
        val = strtoul(sp, &ep, 10);
        if (sp == ep) {
            /* parse error */
            return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *sp);
        }
        if (val == ULONG_MAX && errno == ERANGE) {
            /* overflow */
            if (i == 3) {
                /* entire value is too large */
                return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
            }
            /* octet value is too large */
            return parseError(SKUTILS_ERR_OVERFLOW,
                              "IP octet %d is too large", (4 - i));
        }
        if (val > UINT8_MAX) {
            if (i == 3 && *ep != '.') {
                /* treat as a single integer */
#if (SK_SIZEOF_LONG > 4)
                if (val > UINT32_MAX) {
                    return parseError(SKUTILS_ERR_MAXIMUM,
                                      "Integer too large for IPv4: %lu", val);
                }
#endif
                sp = ep;
                final = val;
                break;
            }
            /* value too big for octet */
            return parseError(SKUTILS_ERR_MAXIMUM,
                              "IP octet %d is too large: %lu", (4 - i), val);
        }

        sp = ep;
        if (*sp != '.') {
            if (i == 3) {
                /* treat as a single integer */
                assert(val <= UINT8_MAX);
                final = val;
                break;
            }
            if (i != 0) {
                if (*sp == '\0') {
                    return parseError(SKUTILS_ERR_SHORT, PE_NULL);
                }
                /* need a '.' between octets */
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *sp);
            }
            /* else i == 0 and we've finished parsing */
        } else if (i == 0) {
            /* found a trailing '.' */
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "Found '%c' after fourth octet", *sp);
        } else {
            /* move to start of next octet */
            ++sp;
            if (!isdigit((int)*sp)) {
                /* error: only '.' and digits are allowed */
                if (*sp == '\0') {
                    return parseError(SKUTILS_ERR_SHORT, PE_NULL);
                }
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *sp);
            }
        }

        final |= val << (8 * i);
    }

    *ip = (uint32_t)final;
    return (sp - ip_string);
}

#if SK_ENABLE_IPV6
/*
 *  status = parseIPv6(&ipaddr, ip_string);
 *
 *    A helper function for skStringParseIP().
 *
 *    Parse the IPv6 address at 'ip_string' and put the result--in
 *    native byte order--into the memory pointed at by 'ip_value'.
 *    Return a negative (silk_utils_errcode_t) value on error;
 *    otherwise return a positive value specifying the number of
 *    characters that were parsed.
 */
static int
parseIPv6(
    skipaddr_t         *ipaddr,
    const char         *ip_string)
{
    uint8_t ipv6[16];
    unsigned int double_colon = UINT_MAX;
    unsigned long val;
    unsigned int i;
    const char *sp = ip_string;
    char *ep;

    /* handle a "::" at the start of the address */
    if (':' == *sp) {
        if (':' != *(sp + 1)) {
            /* address cannot begin with single ':' */
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "IP address cannot begin with single ':'");
        }
        if (':' == *(sp + 2)) {
            /* triple colon */
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "Unexpected character :::");
        }
        double_colon = 0;
        sp += 2;
    }

    for (i = 0; i < 8; ++i) {
        /* expecting a base-16 number */
        if (!isxdigit((int)*sp)) {
            if (double_colon != UINT_MAX) {
                /* treat as end of string */
                break;
            }
            if (*sp == '\0') {
                return parseError(SKUTILS_ERR_SHORT,
                                  "Too few IP sections given");
            }
            return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                              *sp);
        }

        /* parse the number */
        errno = 0;
        val = strtoul(sp, &ep, 16);
        if (sp == ep) {
            if (double_colon != UINT_MAX) {
                /* treat as end of string */
                break;
            }
            /* parse error */
            return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                              *sp);
        }
        if (val == ULONG_MAX && errno == ERANGE) {
            /* overflow */
            return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
        }
        if (val > UINT16_MAX) {
            /* value too big for octet */
            return parseError(SKUTILS_ERR_MAXIMUM,
                              "Value in IP section %u is too large",
                              i + 1);
        }

        /* if a dot follows the number we just parsed, treat that
         * number as the start of an embedded IPv4 address. */
        if (*ep == '.') {
            unsigned int j;
            uint32_t ipv4;
            int rv;

            if (i > 6) {
                return parseError(SKUTILS_ERR_BAD_CHAR,
                                  ("Too many sections before"
                                   " embedded IPv4"));
            }
            /* IPv4 address */
            rv = parseIPv4(&ipv4, sp);
            if (rv < 0) {
                return rv;
            }

            for (j = 0; j < 4; ++j) {
                ipv6[2*i+j] = ((ipv4 >> (8 * (3 - j))) & 0xFF);
            }
            sp += rv;
            i += 2;
            if (*sp == ':') {
                /* Must not have more IPv6 after the IPv4 addr */
                return parseError(SKUTILS_ERR_BAD_CHAR,
                                  "Found '%c' after final section", *sp);
            }
            break;
        }

        ipv6[2*i] = ((val >> 8) & 0xFF);
        ipv6[2*i+1] = (val & 0xFF);
        sp = ep;

        /* handle section separator */
        if (*sp != ':') {
            if (i != 7) {
                if (double_colon != UINT_MAX) {
                    /* treat as end of string */
                    ++i;
                    break;
                }
                if (*sp == '\0') {
                    return parseError(SKUTILS_ERR_SHORT,
                                      "Too few IP sections given");
                }
                /* need a ':' between sections */
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *sp);
            }
            /* else i == 7 and we've finished parsing */
        } else if (i == 7) {
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "Found '%c' after final section", *sp);
        } else {
            /* move to start of next section */
            ++sp;
            if (':' == *sp) {
                if (double_colon != UINT_MAX) {
                    /* parse error */
                    return parseError(SKUTILS_ERR_BAD_CHAR,
                                      "Only one :: instance allowed");
                }
                if (':' == *(sp + 1)) {
                    /* triple colon */
                    return parseError(SKUTILS_ERR_BAD_CHAR,
                                      "Unexpected character :::");
                }
                double_colon = i + 1;
                ++sp;
            } else if (*sp == '\0') {
                return parseError(SKUTILS_ERR_SHORT,
                                  "Expecting IP section value after ':'");
            } else if (!isxdigit((int)*sp)) {
                /* number must follow lone ':' */
                return
                    parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                               PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                               *sp);
            }
        }
    }

    if (double_colon != UINT_MAX) {
        if (i == 8) {
            /* error */
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "Cannot have '::' in IP with 8 sections");
        }
        memmove(&ipv6[2*(8+double_colon-i)], &ipv6[2*double_colon],
                2*(i-double_colon));
        memset(&ipv6[2*double_colon], 0, 2*(8-i));
    } else if (i != 8) {
        /* error */
        return parseError(SKUTILS_ERR_SHORT,
                          "Only %u/8 IP sections specified", i);
    }

    skipaddrSetV6(ipaddr, ipv6);
    return (sp - ip_string);
}
#endif /* SK_ENABLE_IPV6 */

/* Parse a string as an IPv4 or IPv6 address.  If the string is a
 * single integer, treat is an an IPv4 address. */
int
skStringParseIP(
    skipaddr_t         *out_val,
    const char         *ip_string)
{
    const char *sp;
    const char *dot;
    const char *colon;
    int rv;

    /* verify input */
    if (!ip_string) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    /* skip leading whitespace */
    sp = ip_string;
    while (isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' == *sp) {
        /* whitespace only or empty string */
        return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
    }

    /* determine if IPv4 or IPv6 */
    dot = strchr(sp, '.');
    colon = strchr(sp, ':');
    if (colon == NULL) {
        /* no ':', so must be IPv4 or an integer */
    } else if (dot == NULL) {
        /* no '.', so must be IPv6 */
    } else if ((dot - sp) < (colon - sp)) {
        /* dot appears first, assume IPv4 */
        colon = NULL;
    } else {
        /* colon appears first, assume IPv6 */
        dot = NULL;
    }

    /* parse the address */
    if (NULL == colon) {
        /* an IPv4 address */
        uint32_t ipv4;

        rv = parseIPv4(&ipv4, sp);
        if (rv < 0) {
            return rv;
        }
        skipaddrSetV4(out_val, &ipv4);
    } else
#if SK_ENABLE_IPV6
    {
        /* an IPv6 address */
        rv = parseIPv6(out_val, sp);
        if (rv < 0) {
            return rv;
        }
    }
#else  /* SK_ENABLE_IPV6 */
    {
        /* an IPv6 address but no IPv6 support */
        return parseError(SKUTILS_ERR_BAD_CHAR,
                          "%s ':'--IPv6 addresses not supported",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR));
    }
#endif  /* #else of #if SK_ENABLE_IPV6 */

    sp += rv;

    /* ignore trailing whitespace, but only if we reach the end of the
     * string.  cache the current position. */
    rv = (sp - ip_string);
    while (isspace((int)*sp)) {
        ++sp;
    }

    if ('\0' != *sp) {
        /* text after IP, return the cached position */
        return rv;
    }
    return SKUTILS_OK;
}


int
skStringParseIPWildcard(
    skIPWildcard_t     *ipwild,
    const char         *ip_string)
{
    /* number of octets (or hexadectets for IPv6) */
    uint32_t num_blocks = 4;
    /* number of bits per octet/hexadectet */
    uint32_t block_size = 8;
    /* max value for any octet/hexadectet */
    uint32_t block_max_value = ((1 << block_size) - 1);
    /* base to use for parsing octet/hexadectet values */
    int block_base;
    /* character string between octets/hexadectets */
    const char *block_sep;
    uint64_t i;
    uint32_t range_start = 0;
    uint64_t range_length = 0;
    unsigned long val = 0;
    uint32_t block = 0;
    uint32_t double_colon = UINT32_MAX;
    sk_number_parser_t parser;
    skipaddr_t ipaddr;
    uint32_t cidr = 0;
    const char *sp;
    int rv;
#if SK_ENABLE_IPV6
    const char *v4_in_v6 = NULL;
#endif

    /* try to parse as an ordinary IP address */
    rv = skStringParseIP(&ipaddr, ip_string);

    /* return if we get any error other than BAD_CHAR */
    if (rv < 0 && rv != SKUTILS_ERR_BAD_CHAR) {
        return rv;
    }

    /* If rv > 0, we parsed an IP but there is extra text.  We could
     * be looking at the slash for CIDR notation or at a list for the
     * final block; e.g., "0.0.0.1-100" or "0.0.0.1,2".  If we are on
     * the slash, reset rv to SKUTILS_OK; otherwise, if we are looking
     * at anything other than ',' or '-', return error.  For IPv6, we
     * may be looking at "0::x". */
    if (rv > 0) {
        sp = &ip_string[rv];
        if (*sp == '/') {
            ++sp;
            if (*sp == '\0') {
                return parseError(SKUTILS_ERR_BAD_CHAR,
                                  "%s '%c'--expected CIDR after slash",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *sp);
            }
            if (!isdigit((int)*sp)) {
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *sp);
            }

            /* parse the CIDR value */
            rv = skStringParseUint32(&cidr, sp, 1,
                                     (skipaddrIsV6(&ipaddr) ? 128 : 32));
            if (rv != 0) {
                if (rv < 0) {
                    return rv;
                }
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  sp[rv]);
            }
        } else if (isspace((int)*sp)) {
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "%s '%c' embedded whitespace is not allowed",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                              *sp);
#if SK_ENABLE_IPV6
        } else if (skipaddrIsV6(&ipaddr) && (*sp == 'x' || *sp == 'X')) {
            /* try to parse as wildcard */
#endif /* SK_ENABLE_IPV6 */
        } else if (*sp != '-' && *sp != ',') {
            return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                              *sp);
        }
    }

    /* clear the ipwildcard */
    skIPWildcardClear(ipwild);

    if (rv == SKUTILS_OK) {
#if SK_ENABLE_IPV6
        if (skipaddrIsV6(&ipaddr)) {
            uint8_t ip6[16];

            skipaddrGetV6(&ipaddr, &ip6);
            ipwild->num_blocks = 8;

            num_blocks = 8;
            block_size = 16;
            block_max_value = (1 << block_size) - 1;

            /* set each block as if no CIDR */
            for (block = 0; block < num_blocks; ++block) {
                val = (ip6[2*block] << 8 | ip6[1+2*block]);
                ipwild->m_blocks[block][_BMAP_INDEX(val)] = _BMAP_OFFSET(val);
                ipwild->m_min[block] = val;
                ipwild->m_max[block] = val;
            }
        } else
#endif /* SK_ENABLE_IPV6 */
        {
            ipwild->num_blocks = 4;

            /* set each block as if no CIDR */
            for (block = 0; block < num_blocks; ++block) {
                val = (block_max_value
                       & (skipaddrGetV4(&ipaddr)
                          >> ((num_blocks - block - 1) * block_size)));
                ipwild->m_blocks[block][_BMAP_INDEX(val)] = _BMAP_OFFSET(val);
                ipwild->m_min[block] = val;
                ipwild->m_max[block] = val;
            }
        }

        if (cidr == 0 || cidr == (num_blocks * block_size)) {
            return SKUTILS_OK;
        }

        for (block = 0; block < num_blocks; ++block) {
            if (cidr <= (block_size * block)) {
                /* this block is all ones */
                memset(ipwild->m_blocks[block], 0xFF,
                       sizeof(ipwild->m_blocks[0]));
                ipwild->m_min[block] = 0;
                ipwild->m_max[block] = block_max_value;
            } else if (cidr < (block_size * (1 + block))) {
                /* partial effect on this block */
                range_length = 1 << ((block_size * (1 + block)) - cidr);
                val = (ipwild->m_min[block] & ~(range_length - 1));
                ipwild->m_min[block] = val;
                for (i = 0; i < range_length; ++i, ++val) {
                    ipwild->m_blocks[block][_BMAP_INDEX(val)]
                        |= _BMAP_OFFSET(val);
                }
                ipwild->m_max[block] = val - 1;
            }
            /* else (cidr >= (block_size*(1+block))) and no effect */
        }
        return SKUTILS_OK;
    }

    /* Parse the input ip from the beginning */
    sp = ip_string;

    /* ignore leading whitespace */
    while (isspace((int)*sp)) {
        ++sp;
    }

    if (strchr(sp, ':')) {
#if !SK_ENABLE_IPV6
        return parseError(SKUTILS_ERR_BAD_CHAR,
                          "%s '%c'--IPv6 addresses not supported",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                          *sp);
#else
        ipwild->num_blocks = 8;
        block_sep = ":";
        num_blocks = 8;
        block_size = 16;
        block_base = 16;

        /* check for a v4 section, for example "::ffff:x.x.x.x".  if
         * we find a '.', move backward to find the ':' and as
         * v4_in_v6 to the character following the ':'. */
        v4_in_v6 = strchr(sp, '.');
        if (v4_in_v6) {
            while (v4_in_v6 > sp) {
                if (*(v4_in_v6 - 1) == ':') {
                    break;
                }
                --v4_in_v6;
            }
            if (v4_in_v6 == sp) {
                /* must have something with ':' following '.' */
                return parseError(SKUTILS_ERR_BAD_CHAR,
                                  "Found ':' after '.' in IPv6 address");
            }
        }
#endif /* SK_ENABLE_IPV6 */
    } else {
        block_sep = ".";
        ipwild->num_blocks = 4;
        num_blocks = 4;
        block_size = 8;
        block_base = 10;
    }
    block_max_value = (1 << block_size) - 1;

    for (block = 0; block < num_blocks; ++block) {
        if (*sp == ':') {
            ++sp;
            if (*sp == ':') {
                if (double_colon != UINT32_MAX) {
                    /* parse error */
                    return parseError(SKUTILS_ERR_BAD_CHAR,
                                      "Only one :: instance allowed");
                }
                ++sp;
                double_colon = block;
            } else if (block == 0) {
                /* address cannot begin with single ':' */
                return parseError(SKUTILS_ERR_BAD_CHAR,
                                  "IP address cannot begin with single ':'");
            } else if (*sp == '\0') {
                return parseError(SKUTILS_ERR_SHORT,
                                  "Expecting IP block value after ':'");
            }
        } else if (*sp == '.') {
            assert(block_base == 10);
            if (block == 0) {
                return parseError(SKUTILS_ERR_BAD_CHAR,
                                  "%s--found leading separator '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *sp);
            }
            ++sp;
        } else if (*sp == '\0') {
            if (double_colon != UINT32_MAX) {
                /* treat as end of the IP */
                break;
            }
            return parseError(SKUTILS_ERR_SHORT,
                              "Too few IP blocks given");
        } else if (block != 0) {
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "%s '%c' expecting '%s' between IP blocks",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *sp,
                              block_sep);
        }

#if SK_ENABLE_IPV6
        /* determine if we are at beginning of an embedded IPv4 address */
        if (sp == v4_in_v6) {
            skIPWildcard_t ipwv4;
            uint32_t j, k;

            /* verify we don't have too many IPv6 sections */
            if (block > 6) {
                return parseError(SKUTILS_ERR_BAD_CHAR,
                                  "Too many sections before embedded IPv4");
            }

            /* parse the remaining part of the address as IPv4 wildcard */
            rv = skStringParseIPWildcard(&ipwv4, sp);
            if (rv < 0) {
                return rv;
            }

            /* move sp to the end of the string */
            sp += strlen(sp);

            /* take the ipv4 wildcard and map it into ipv6 */
            for (i = 0; i < 4; i += 2, ++block) {
                ipwild->m_min[block] = (ipwv4.m_min[i]<<8) | ipwv4.m_min[i+1];
                ipwild->m_max[block] = (ipwv4.m_max[i]<<8) | ipwv4.m_max[i+1];

                /* shortcut the "x.x" case */
                if ((ipwild->m_min[block] == 0)
                    && (ipwild->m_max[block] == 0xFFFF))
                {
                    memset(ipwild->m_blocks[block], 0xFF,
                           sizeof(ipwild->m_blocks[0]));
                    if (memcmp(ipwild->m_blocks[block],
                               ipwv4.m_blocks[i],
                               sizeof(ipwild->m_blocks[0]))
                        && memcmp(ipwild->m_blocks[block],
                               ipwv4.m_blocks[i+1],
                               sizeof(ipwild->m_blocks[0])))
                    {
                        continue;
                    } else {
                        memset(ipwild->m_blocks[block], 0,
                               sizeof(ipwild->m_blocks[0]));
                    }
                }

                for (j = ipwv4.m_min[i]; j <= ipwv4.m_max[i]; ++j) {
                    for (k = ipwv4.m_min[i+1]; k <= ipwv4.m_max[i+1]; ++k) {
                        if (_IPWILD_BLOCK_IS_SET(&ipwv4, i, j)
                            && _IPWILD_BLOCK_IS_SET(&ipwv4, i+1, k))
                        {
                            ipwild->m_blocks[block][_BMAP_INDEX((j << 8) | k)]
                                |= _BMAP_OFFSET((j << 8) | k);
                        }
                    }
                }
            }

            /* done */
            break;
        }
#endif /* SK_ENABLE_IPV6 */

        if (*sp == 'x' || *sp == 'X') {
            /* all ones */
            memset(ipwild->m_blocks[block], 0xFF, sizeof(ipwild->m_blocks[0]));
            ipwild->m_min[block] = 0;
            ipwild->m_max[block] = block_max_value;
            ++sp;
            continue;
        }

        rv = numberListParserInit(&parser, sp, block_base, block_sep,
                                  0, block_max_value);
        if (rv != SK_NUM_PARSER_OK) {
            if (rv != SK_NUM_PARSER_END_OF_STRING) {
                return rv;
            }
            if (*sp == *block_sep) {
                return parseError(SKUTILS_ERR_BAD_CHAR,
                                  "%s--found double '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *sp);
            }
            if (double_colon == block) {
                /* treat as end of string */
                break;
            }
            if (isspace((int)*sp)) {
                return parseError(SKUTILS_ERR_BAD_CHAR,
                                  "%s--embedded whitespace found in input",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR));
            }
            return parseError(SKUTILS_ERR_SHORT, "Too few blocks given");
        }

        while ((rv = numberListParserNext(&range_length, &range_start,&parser))
               != SK_NUM_PARSER_END_OF_STRING)
        {
            switch (rv) {
              case SK_NUM_PARSER_OK:
                /* this should not occur */
                skAbortBadCase(rv);

              case SK_NUM_PARSER_RANGE_OPENMAX:
                return parseError(SKUTILS_ERR_BAD_CHAR,
                                  ("Range is missing its upper limit"
                                   " (open-ended ranges are not supported)"));

              case SK_NUM_PARSER_NUMBER:
              case SK_NUM_PARSER_RANGE:
                /* add the entries */
                if (range_start < ipwild->m_min[block]) {
                    ipwild->m_min[block] = range_start;
                }
                for (i = 0; i < range_length; ++i, ++range_start) {
                    ipwild->m_blocks[block][_BMAP_INDEX(range_start)]
                        |= _BMAP_OFFSET(range_start);
                }
                --range_start;
                if (range_start > ipwild->m_max[block]) {
                    ipwild->m_max[block] = range_start;
                }
                break;

              case SKUTILS_ERR_BAD_CHAR:
              default:
                return rv;
            }
        }

        sp = numberParserCurrentChar(&parser);
    }

    if (double_colon != UINT32_MAX) {
        if (block == num_blocks) {
            /* error */
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "Cannot have '::' in IP with 8 blocks");
        }
        memmove(&ipwild->m_min[8 + double_colon - block],
                &ipwild->m_min[double_colon],
                sizeof(ipwild->m_min[0]) * (block - double_colon));
        memmove(&ipwild->m_max[8 + double_colon - block],
                &ipwild->m_max[double_colon],
                sizeof(ipwild->m_max[0]) * (block - double_colon));
        memmove(ipwild->m_blocks[8 + double_colon - block],
                ipwild->m_blocks[double_colon],
                sizeof(ipwild->m_blocks[0]) * (block - double_colon));
        for (i = double_colon; i < (8 + double_colon - block); ++i) {
            memset(ipwild->m_blocks[i], 0, sizeof(ipwild->m_blocks[0]));
            ipwild->m_blocks[i][_BMAP_INDEX(0)] = _BMAP_OFFSET(0);
            ipwild->m_min[i] = 0;
            ipwild->m_max[i] = 0;
        }
    } else if (block != num_blocks) {
        /* error */
        return parseError(SKUTILS_ERR_SHORT,
                          ("Only %" PRIu32 "/%" PRIu32 " IP blocks specified"),
                          block, num_blocks);
    }

    /* ignore trailing whitespace */
    while (isspace((int)*sp)) {
        ++sp;
    }
    if (*sp != '\0') {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *sp);
    }

    return SKUTILS_OK;
}


/* parse an IP with an optional CIDR designation */
int
skStringParseCIDR(
    skipaddr_t         *out_val,
    uint32_t           *out_cidr,
    const char         *ip_string)
{
    const char *sp;
    int rv;

    /* try to parse as an ordinary IP address */
    rv = skStringParseIP(out_val, ip_string);

    /* return if we get an error */
    if (rv < 0) {
        return rv;
    }

    /* check if we only got the IP address */
    if (rv == 0) {
        *out_cidr = (skipaddrIsV6(out_val) ? 128 : 32);
        return SKUTILS_OK;
    }

    /* When rv > 0, we parsed an IP but there is extra text,
     * presumably '/' for the CIDR designation.  Error if it isn't. */
    sp = &ip_string[rv];
    if (*sp != '/') {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *sp);
    }

    ++sp;
    if (*sp == '\0') {
        return parseError(SKUTILS_ERR_BAD_CHAR,
                          "%s '%c'--expected CIDR after slash",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                          *sp);
    }

    /* parse the CIDR value */
    rv = skStringParseUint32(out_cidr, sp, 1,
                             (skipaddrIsV6(out_val) ? 128 : 32));
    if (rv > 0) {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                          sp[rv]);
    }

    return rv;
}


int
skStringParseHostPortPair(
    sk_sockaddr_array_t   **sockaddr,
    const char             *host_port,
    uint8_t                 flags)
{
    sk_sockaddr_array_t *sa;
    const char *sp = host_port;
    const char *cp;
    const char *ep;
    const char *colon;
    const char *port;
    char *host;
    uint32_t port_val = 0;
    sk_sockaddr_t addr;
    int two_colons;
    int rv;

    if (NULL == sockaddr || NULL == host_port
        || ((flags & (PORT_REQUIRED | PORT_PROHIBITED)) ==
            (PORT_REQUIRED | PORT_PROHIBITED))
        || ((flags & (HOST_REQUIRED | HOST_PROHIBITED)) ==
            (HOST_REQUIRED | HOST_PROHIBITED))
        || ((flags & (IPV6_REQUIRED | IPV6_PROHIBITED)) ==
            (IPV6_REQUIRED | IPV6_PROHIBITED))
        || ((flags & (HOST_PROHIBITED | PORT_PROHIBITED)) ==
            (HOST_PROHIBITED | PORT_PROHIBITED)))
    {
        return parseError(SKUTILS_ERR_INVALID,
                          "Programmer error: Invalid flag combination");
    }

#if !SK_ENABLE_INET6_NETWORKING
    if (flags & IPV6_REQUIRED) {
        return parseError(SKUTILS_ERR_INVALID,
                          ("IPv6 address required yet"
                           " IPv6 addresses not supported"));
    }
#endif  /* !SK_ENABLE_INET6_NETWORKING */

    /* ignore leading whitespace */
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' == *sp) {
        /* whitespace only or empty string */
        return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
    }

    /* move 'ep' forward to next whitespace char or to end of string */
    ep = sp + 1;
    while (*ep && !isspace((int)*ep)) {
        ++ep;
    }
    if ('\0' != *ep) {
        /* found whitespace; ensure it is only trailing whitespace and
         * not embedded whitespace */
        cp = ep;
        while (*cp && isspace((int)*cp)) {
            ++cp;
        }
        if ('\0' != *cp) {
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "%s--embedded whitespace found in input",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR));
        }
    }

    /* get possible host:port separator ':', which could be part of an
     * IPv6 address if there is no port */
    colon = strrchr(sp, ':');
    two_colons = (colon && colon != strchr(sp, ':'));

    /* set 'ep' to end of the host portion of input */
    if ('[' == *sp) {
        cp = strrchr(sp, ']');
        if (cp == NULL) {
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "Cannot find closing ']' character");
        }
        /* character after ']' must be end of string or the ':' that
         * separates the host from the port */
        if ((cp + 1 != ep) && (cp + 1 != colon)) {
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "%s--unexpected character after ']': %c",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                              *(cp+1));
        }
        if (colon && (colon < cp)) {
            /* if final ':' occurs before ']', assume function was
             * passed an IPv6 address with no port */
            colon = NULL;
        }
        ++sp;
        ep = cp;

    } else if (two_colons) {
        /* assume we have an IPv6 address not contained in [...] */
        colon = NULL;

    } else if (colon) {
        ep = colon;
    }

    /* Check to see if the presumed host is actually a port */
    if (colon == NULL && (sp + strspn(sp, "0123456789") == ep)) {
        if (flags & HOST_REQUIRED) {
            return parseError(SKUTILS_ERR_OTHER,
                              "Expected a host name or IP address");
        }
        colon = sp - 1;          /* -1 due to increment below */
        ep = sp;
    }

    /* Parse the port */
    if (colon) {
        port = colon + 1;
        if (flags & PORT_PROHIBITED) {
            return parseError(SKUTILS_ERR_OTHER,
                              "Expected a host name or IP only");
        }

        rv = skStringParseUint32(&port_val, port, 0, UINT16_MAX);
        if (rv < 0) {
            /* bad parse */
            if (SKUTILS_ERR_EMPTY == rv) {
                return parseError(SKUTILS_ERR_SHORT, "Missing port value");
            }
            return parseError((silk_utils_errcode_t)rv,
                              "Error parsing port: %s",
                              PARSE_ERRORCODE_MSG(rv));
        }
        if (rv > 0) {
            /* text after port */
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "Error parsing port: Unexpected text after port");
        }
    } else if (flags & PORT_REQUIRED) {
        return parseError(SKUTILS_ERR_OTHER,
                          "Cannot find port and port is required");
    } else {
        port = NULL;
    }

    if (ep == sp) {
        /* no host */
        host = NULL;
    } else if (flags & HOST_PROHIBITED) {
        return parseError(SKUTILS_ERR_OTHER,
                          "Found a host name when host was prohibited");
    } else {
        /* copy the hostname or IP so we can lop off the port */
        host = (char*)malloc((ep - sp + 1u) * sizeof(char));
        if (NULL == host) {
            return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
        }
        memcpy(host, sp, (ep - sp + 1u) * sizeof(char));
        host[ep - sp] = '\0';
    }

    /* fill an sk_vector_t with sk_sockaddr_t structures that are
     * obtained by using either getaddrinfo() to parse the host:port
     * pair or gethostbyname() to parse the host */
    {
        sk_vector_t *vec;
#if USE_GETADDRINFO
        const char *resolv_constraint = "";
        struct addrinfo *addrinfo;
        struct addrinfo *current;
        struct addrinfo hints;
        char port_buf[7];
        char *port_str;

        memset(&hints, 0, sizeof(hints));
        if (!SK_ENABLE_INET6_NETWORKING || (flags & IPV6_PROHIBITED)) {
            resolv_constraint = " as an IPv4 address";
            hints.ai_family = AF_INET;
        } else if (flags & IPV6_REQUIRED) {
            resolv_constraint = " as an IPv6 address";
            hints.ai_family = AF_INET6;
        } else {
            hints.ai_family = AF_UNSPEC;
        }
        if (host == NULL) {
            hints.ai_flags = AI_PASSIVE;
        }
        /* hints.ai_flags |= AI_ADDRCONFIG; */
        if (port == NULL) {
            port_str = NULL;
        } else {
            snprintf(port_buf, sizeof(port_buf), "%" PRIu32, port_val);
            port_str = port_buf;
        }

        /* The following is a lie, but a white one.  We need a
         * non-zero socktype in order for Solaris to agree with
         * numeric ports that aren't in the /etc/services file. */
        hints.ai_socktype = SOCK_STREAM;

        rv = getaddrinfo(host, port_str, &hints, &addrinfo);
        if (rv != 0) {
            if (host) {
                rv = parseError(SKUTILS_ERR_RESOLVE,
                                "Unable to resolve '%s'%s: %s",
                                host, resolv_constraint, gai_strerror(rv));
                free(host);
            } else {
                rv = parseError(SKUTILS_ERR_RESOLVE,
                                "Could not register passive port %s: %s",
                                port_str, gai_strerror(rv));
            }
            return rv;
        }

        vec = skVectorNew(sizeof(addr));
        if (vec == NULL) {
            freeaddrinfo(addrinfo);
            if (host) {
                free(host);
            }
            return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
        }

        current = addrinfo;
        while (current) {
            switch (current->ai_addr->sa_family) {
#if SK_ENABLE_INET6_NETWORKING
              case AF_INET6:
                addr.v6 = *(struct sockaddr_in6 *)(current->ai_addr);
                break;
#endif  /* SK_ENABLE_INET6_NETWORKING */
              case AF_INET:
                addr.v4 = *(struct sockaddr_in *)(current->ai_addr);
                break;
              default:
                current = current->ai_next;
                continue;
            }
            rv = skVectorAppendValue(vec, &addr);
            if (rv != 0) {
                skVectorDestroy(vec);
                if (host) {
                    free(host);
                }
                freeaddrinfo(addrinfo);
                return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
            }
            current = current->ai_next;
        }
        freeaddrinfo(addrinfo);

#else  /* #if !USE_GETADDRINFO */
        vec = skVectorNew(sizeof(addr));
        if (vec == NULL) {
            return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
        }
        memset(&addr, 0, sizeof(addr));
        addr.v4.sin_family = AF_INET;
        addr.v4.sin_port = htons((uint16_t)port_val);
        if (!host) {
            addr.v4.sin_addr.s_addr = htonl(INADDR_ANY);
            rv = skVectorAppendValue(vec, &addr);
            if (rv != 0) {
                skVectorDestroy(vec);
                return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
            }
        } else {
            struct hostent *he;
            char **current;

            he = gethostbyname(host);
            if (he == NULL || (he->h_addrtype != AF_INET)) {
                rv = parseError(SKUTILS_ERR_RESOLVE,
                                "Unable to resolve '%s' as an IPv4 address",
                                host);
                free(host);
                skVectorDestroy(vec);
                return rv;
            }

            current = he->h_addr_list;
            while (*current) {
                memcpy(&addr.v4.sin_addr, *current, he->h_length);
                rv = skVectorAppendValue(vec, &addr);
                if (rv != 0) {
                    free(host);
                    skVectorDestroy(vec);
                    return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
                }
                current++;
            }
        }
#endif  /* USE_GETADDRINFO */

        sa = (sk_sockaddr_array_t*)calloc(1, sizeof(sk_sockaddr_array_t));
        if (sa == NULL) {
            free(host);
            skVectorDestroy(vec);
            return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
        }
        sa->name = host;

        sa->num_addrs = skVectorGetCount(vec);
        sa->addrs = (sk_sockaddr_t*)skVectorToArrayAlloc(vec);
        skVectorDestroy(vec);
        if (sa->addrs == NULL) {
            skSockaddrArrayDestroy(sa);
            return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
        }

        if (host || (flags & HOST_PROHIBITED)) {
            /* grab the value that was provided */
            sa->host_port_pair = strdup(host_port);
            if (!sa->host_port_pair) {
                skSockaddrArrayDestroy(sa);
                return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
            }
        } else {
            const size_t buf_size = 12;
            sa->host_port_pair = (char *)malloc(buf_size * sizeof(char));
            if (!sa->host_port_pair) {
                skSockaddrArrayDestroy(sa);
                return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
            }
            if (flags & IPV6_PROHIBITED) {
                rv = snprintf(sa->host_port_pair,buf_size, "*:%u", port_val);
            } else {
                rv = snprintf(sa->host_port_pair,buf_size, "[*]:%u", port_val);
            }
            if ((size_t)rv > buf_size) {
                skAbort();
            }
        }

        *sockaddr = sa;
    }

    return SKUTILS_OK;
}


/*
 *    Helper function for skStringParseDatetime() to handle parsing of
 *    the fractional seconds.
 *
 *    Fractional seconds begin in 'start_char'.  'end_char' is set to
 *    the character following the fractional seconds, and 'end_char'
 *    must be provided.  The fractional seconds are stored in the
 *    value referenced by 'msec'.  Return SKUTILS_OK or a negative
 *    skutils-parse-error value.
 */
static int
parseDatetimeFractionalSeconds(
    const char         *start_char,
    char              **end_char,
    long               *msec)
{
    long val;
    size_t num_digits;

    if (!isdigit((int)*start_char)) {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                          *start_char);
    }
    /* parse the value */
    errno = 0;
    val = strtol(start_char, end_char, 10);
    num_digits = (*end_char - start_char);
    if (0 == num_digits) {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                          *start_char);
    }
    if (val == LONG_MAX && errno == ERANGE) {
        return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
    }
    if (val < 0) {
        return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
    }
    /* multiply or divide as needed given the number of digits parsed */
    switch (num_digits) {
      case 0:  skAbortBadCase(num_digits);
      case 1:  *msec = val * 100; break;
      case 2:  *msec = val * 10; break;
      case 3:  *msec = val; break;
      case 4:  *msec = val / 10; break;
      case 5:  *msec = val / 100; break;
      case 6:  *msec = val / 1000; break;
      case 7:  *msec = val / 10000; break;
      case 8:  *msec = val / 100000; break;
      case 9:  *msec = val / 1000000; break;
      case 10: *msec = val / 10000000; break;
      case 11: *msec = val / 100000000; break;
      case 12:
      default:
        val /= 1000000000;
        for ( ; num_digits > 12; --num_digits) {
            val /= 10;
        }
        *msec = val;
        break;
    }
    return SKUTILS_OK;
}


/*  time string to struct sktime_st; see utils.h for details */
int
skStringParseDatetime(
    sktime_t           *date_val,
    const char         *date_string,
    unsigned int       *out_flags)
{
    const unsigned int min_precision = SK_PARSED_DATETIME_DAY;
    struct tm ts;
    time_t t;
    const char *sp;
    char *ep;
    const char delim[] = {'\0', '/', '/', ':', ':', ':', '.'};
    long val;
    long msec = 0;
    unsigned int i;
    int rv;

    /* check inputs */
    assert(date_val);
    if (NULL == date_string) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    /* initialize */
    sp = date_string;
    memset(&ts, 0, sizeof(struct tm));

    /* use "unknown" value for Daylight Saving Time flag */
    ts.tm_isdst = -1;

    /* ignore leading whitespace */
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' == *sp) {
        /* whitespace only or empty string */
        return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
    }

    /* if the date contains only digits and a decimal point(s) and is
     * at least 9 digits long, treat it as an epoch time */
    if (strspn(sp, ".0123456789") > 8) {
        long epoch;

        /* parse the seconds */
        errno = 0;
        val = strtol(sp, &ep, 10);
        if (sp == ep) {
            return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *sp);
        }
        if (val == LONG_MAX && errno == ERANGE) {
            return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
        }
        if (val < 0) {
            return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
        }

        /* make sure value is in range */
        if ((val < STRING_PARSE_MIN_EPOCH)
            || ((unsigned long)val > STRING_PARSE_MAX_EPOCH))
        {
            return parseError(((val < STRING_PARSE_MIN_EPOCH)
                               ? SKUTILS_ERR_MINIMUM
                               : SKUTILS_ERR_MAXIMUM),
                              ("Epoch value (%ld) out of range:"
                               " use %d <= epoch <= %u"),
                              val,
                              STRING_PARSE_MIN_EPOCH, STRING_PARSE_MAX_EPOCH);
        }

        epoch = val;
        if ('.' == *ep && isdigit((int)*(ep+1))) {
            /* parse fractional seconds */
            sp = ep + 1;
            rv = parseDatetimeFractionalSeconds(sp, &ep, &msec);
            if (rv) {
                return rv;
            }
        }

        /* handle the end of the string, to see if we are attempting
         * to parse something as epoch that we shouldn't */
        if (*ep != '\0' && !isspace((int)*ep)) {
            return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *ep);
        }

        /* ignore trailing whitespace */
        sp = ep;
        while (*sp && isspace((int)*sp)) {
            ++sp;
        }
        if ('\0' != *sp) {
            return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *sp);
        }
        if (out_flags) {
            if (strchr(date_string, '.')) {
                *out_flags = SK_PARSED_DATETIME_FRACSEC;
            } else if (0 == epoch % 3600) {
                /* at least hour precision */
                if (0 == epoch % 86400) {
                    *out_flags = SK_PARSED_DATETIME_DAY;
                } else {
                    *out_flags = SK_PARSED_DATETIME_HOUR;
                }
            } else if (0 == epoch % 60) {
                *out_flags = SK_PARSED_DATETIME_MINUTE;
            } else {
                *out_flags = SK_PARSED_DATETIME_SECOND;
            }
            *out_flags |= SK_PARSED_DATETIME_EPOCH;
        }
        *date_val = sktimeCreate(epoch, msec);
        return SKUTILS_OK;
    }

    /* 'i' is the part of the date we have successfully parsed;
     * 1=year, 2=month, 3=day, 4=hour, 5=min, 6=sec, 7=msec */
    i = 0;
    while (*sp && (i < (sizeof(delim)/sizeof(char)))) {
        /* this will catch things like double ':' in the string */
        if ( !isdigit((int)*sp)) {
            return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *sp);
        }

        if (6 == i) {
            rv = parseDatetimeFractionalSeconds(sp, &ep, &msec);
            if (rv) {
                return rv;
            }
        } else {
            /* parse the digit */
            errno = 0;
            val = strtol(sp, &ep, 10);

            if (sp == ep) {
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *sp);
            }
            if (val == LONG_MAX && errno == ERANGE) {
                return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
            }
            if (val < 0) {
                return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
            }
        }

        /* check that value is valid given what we are parsing */
        switch (i) {
          case 0: /* year */
            if (val < STRING_PARSE_MIN_YEAR || val > STRING_PARSE_MAX_YEAR) {
                return parseError(((val < STRING_PARSE_MIN_YEAR)
                                   ? SKUTILS_ERR_MINIMUM
                                   : SKUTILS_ERR_MAXIMUM),
                                  ("Year value (%ld) out of range:"
                                   " use %d <= year <= %d"),
                                  val, STRING_PARSE_MIN_YEAR,
                                  STRING_PARSE_MAX_YEAR);
            }
            ts.tm_year = val - 1900;
            break;
          case 1: /* month */
            if (val < 1 || val > 12) {
                return parseError(((val < 1)
                                   ? SKUTILS_ERR_MINIMUM
                                   : SKUTILS_ERR_MAXIMUM),
                                  ("Month value (%ld) out of range:"
                                   " use %d <= month <= %d"),
                                  val, 1, 12);
            }
            ts.tm_mon = val - 1;
            break;
          case 2: /* day */
            if (val < 1
                || val > skGetMaxDayInMonth((1900 + ts.tm_year),
                                            (1 + ts.tm_mon)))
            {
                return parseError(((val < 1)
                                   ? SKUTILS_ERR_MINIMUM
                                   : SKUTILS_ERR_MAXIMUM),
                                  ("Day value (%ld) out of range:"
                                   " use %d <= day <= %d"),
                                  val, 1,
                                  skGetMaxDayInMonth((1900 + ts.tm_year),
                                                     (1 + ts.tm_mon)));
            }
            ts.tm_mday = val;
            break;
          case 3: /* hour */
            if (val > 23) {
                return parseError(SKUTILS_ERR_MAXIMUM,
                                  ("Hour value (%ld) out of range:"
                                   " use %d <= hour <= %d"),
                                  val, 0, 23);
            }
            ts.tm_hour = val;
            break;
          case 4: /* minute */
            if (val > 59) {
                return parseError(SKUTILS_ERR_MAXIMUM,
                                  ("Minute value (%ld) out of range:"
                                   " use %d <= minute <= %d"),
                                  val, 0, 59);
            }
            ts.tm_min = val;
            break;
          case 5: /* second */
            if (val > 59) {
                return parseError(SKUTILS_ERR_MAXIMUM,
                                  ("Second value (%ld) out of range:"
                                   " use %d <= second <= %d"),
                                  val, 0, 59);
            }
            ts.tm_sec = val;
            break;
          case 6: /* fractional seconds; handled above */
            break;
          default:
            /* should never get here */
            skAbortBadCase(i);
        }

        /* we parsed the number; move to the delimiter */
        ++i;
        sp = ep;

        /* check for whitespace or end of string */
        if (('\0' == *sp) || isspace((int)*sp)) {
            break;
        }

        /* check that delimiter is what we expect; if so move over it
         * to next character */
        if (delim[i]) {
            if (*sp == delim[i]) {
                ++sp;
            } else if (i == 3 && (*sp == 'T')) {
                /* allow a ':' or a 'T' to separate the day and hour */
                ++sp;
            } else {
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *sp);
            }
        }
    }

    /* space is allowed at end of string; eat it */
    ep = (char*)sp;
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }

    /* check for junk at end of string; if so, report error at 'ep' */
    if ('\0' != *sp) {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *ep);
    }

    /* if the caller wants to know the last state parsed, we update
     * their variable. */
    if (out_flags != NULL) {
        *out_flags = i;
    }

    /* need at least year/month/day */
    if (i < min_precision) {
        return parseError(SKUTILS_ERR_SHORT,
                          "Date '%s' does not have at least day precision",
                          date_string);
    }

    /* convert the time */
#if  SK_ENABLE_LOCALTIME
    t = mktime(&ts);
#else
    t = timegm(&ts);
#endif
    if (t == (time_t)-1) {
        return -1;
    }

    *date_val = sktimeCreate(t, msec);
    return SKUTILS_OK;
}


/* parses string of the form DATETIME[-DATETIME], where DATETIME is
 * parsed by skStringParseDatetime().  see header for details. */
int
skStringParseDatetimeRange(
    sktime_t           *start,
    sktime_t           *end,
    const char         *s_datetime,
    unsigned int       *start_precision,
    unsigned int       *end_precision)
{
    char *s_start_time;
    char *s_end_time;
    int rv = 0;

    /* check inputs */
    assert(start);
    assert(end);
    if (s_datetime == NULL) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    /* copy the string, since we are going to modify it */
    s_start_time = strdup(s_datetime);
    if (!s_start_time) {
        return parseError(SKUTILS_ERR_ALLOC, PE_NULL);
    }

    /* search for dash.  if dash does not exist, parse entire string
     * as start date.  if dash does exist, parse string on left as
     * start date and string on right as end date.
     */
    s_end_time = strchr(s_start_time, '-');
    if (s_end_time != NULL) {
        /* change the dash to a NUL to create two separate strings */
        *s_end_time = '\0';
        /* set the s_end_time pointer to be the char after the dash */
        ++s_end_time;
        /* treat missing end-time as infinity */
        if (*s_end_time == '\0') {
            s_end_time = NULL;
        }
    }

    /* parse start */
    rv = skStringParseDatetime(start, s_start_time, start_precision);
    if (s_end_time == NULL) {
        *end = INT64_MAX;
    } else if (rv == 0) {
        rv = skStringParseDatetime(end, s_end_time, end_precision);
    }

    free(s_start_time);

    /* check error conditions and return error if necessary */
    if (rv) {
        return rv;
    }

    if (*end < *start) {
        return parseError(SKUTILS_ERR_BAD_RANGE, PE_NULL);
    }

    return SKUTILS_OK;
}


/* set 'ceiling_time' to the greatest value that does not change the
 * 'precision' of 't'.  see header for details. */
int
skDatetimeCeiling(
    sktime_t           *ceiling_time,
    const sktime_t     *t,
    unsigned int        precision)
{
    struct tm ts;
    struct tm *rv;
    time_t t_sec;

    assert(t);
    assert(ceiling_time);

    if ((precision
         & ~(SK_PARSED_DATETIME_MASK_PRECISION | SK_PARSED_DATETIME_EPOCH))
        || (0 == precision))
    {
        return -1;
    }
    precision &= SK_PARSED_DATETIME_MASK_PRECISION;

    t_sec = (time_t)sktimeGetSeconds(*t);

#if  SK_ENABLE_LOCALTIME
    rv = localtime_r(&t_sec, &ts);
#else
    rv = gmtime_r(&t_sec, &ts);
#endif
    if (NULL == rv) {
        return -1;
    }

    /* 'precision' is what we know; we need to set everything that is
     * "finer" than that value. */
    switch (precision) {
      case SK_PARSED_DATETIME_YEAR: /* know year, set month */
        ts.tm_mon = 11;
        /* FALLTHROUGH */

      case SK_PARSED_DATETIME_MONTH: /* know month, set month-day */
        ts.tm_mday = skGetMaxDayInMonth((1900 + ts.tm_year), (1 + ts.tm_mon));
        /* FALLTHROUGH */

      case SK_PARSED_DATETIME_DAY: /* know month-day, set hour */
        ts.tm_hour = 23;
        /* FALLTHROUGH */

      case SK_PARSED_DATETIME_HOUR: /* know hour, set min */
        ts.tm_min = 59;
        /* FALLTHROUGH */

      case SK_PARSED_DATETIME_MINUTE: /* know min, set sec */
        ts.tm_sec = 59;
        break;

      case SK_PARSED_DATETIME_SECOND:
        /* know sec, just set fractional-seconds */
        *ceiling_time = sktimeCreate(t_sec, 999);
        return 0;

      case SK_PARSED_DATETIME_FRACSEC:
        /* already at max precision, just return what we were given */
        *ceiling_time = *t;
        return 0;

      default:
        skAbortBadCase(precision);
    }

    /* we have reports of the following causing problems on some
     * versions of Solaris, but we cannot re-create... */
    ts.tm_isdst = -1;

    /* convert the time */
#if  SK_ENABLE_LOCALTIME
    t_sec = mktime(&ts);
#else
    t_sec = timegm(&ts);
#endif
    if (t_sec == (time_t)-1) {
        return -1;
    }

    /* convert seconds to milliseconds */
    *ceiling_time = sktimeCreate(t_sec, 999);

    return 0;
}


/* set 'floor_time' to the lowest value that does not change the
 * 'precision' of 't'.  see header for details. */
int
skDatetimeFloor(
    sktime_t           *floor_time,
    const sktime_t     *t,
    unsigned int        precision)
{
    struct tm ts;
    struct tm *rv;
    time_t t_sec;

    assert(t);
    assert(floor_time);

    if ((precision
         & ~(SK_PARSED_DATETIME_MASK_PRECISION | SK_PARSED_DATETIME_EPOCH))
        || (0 == precision))
    {
        return -1;
    }
    precision &= SK_PARSED_DATETIME_MASK_PRECISION;

    t_sec = (time_t)sktimeGetSeconds(*t);

#if  SK_ENABLE_LOCALTIME
    rv = localtime_r(&t_sec, &ts);
#else
    rv = gmtime_r(&t_sec, &ts);
#endif
    if (NULL == rv) {
        return -1;
    }

    /* 'precision' is what we know; we need to clear everything that is
     * "finer" than that value. */
    switch (precision) {
      case SK_PARSED_DATETIME_YEAR: /* know year, set month */
        ts.tm_mon = 0;
        /* FALLTHROUGH */

      case SK_PARSED_DATETIME_MONTH: /* know month, set month-day */
        ts.tm_mday = 1;
        /* FALLTHROUGH */

      case SK_PARSED_DATETIME_DAY: /* know month-day, set hour */
        ts.tm_hour = 0;
        /* FALLTHROUGH */

      case SK_PARSED_DATETIME_HOUR: /* know hour, set min */
        ts.tm_min = 0;
        /* FALLTHROUGH */

      case SK_PARSED_DATETIME_MINUTE: /* know min, set sec */
        ts.tm_sec = 0;
        break;

      case SK_PARSED_DATETIME_SECOND:
        /* know sec, just set fractional-seconds */
        *floor_time = sktimeCreate(t_sec, 0);
        return 0;

      case SK_PARSED_DATETIME_FRACSEC:
        /* already at max precision, just return what we were given */
        *floor_time = *t;
        return 0;

      default:
        skAbortBadCase(precision);
    }

    /* we have reports of the following causing problems on some
     * versions of Solaris, but we cannot re-create... */
    ts.tm_isdst = -1;

    /* convert the time */
#if  SK_ENABLE_LOCALTIME
    t_sec = mktime(&ts);
#else
    t_sec = timegm(&ts);
#endif
    if (t_sec == (time_t)-1) {
        return -1;
    }

    /* convert seconds to milliseconds */
    *floor_time = sktimeCreate(t_sec, 0);

    return 0;
}


/* parse string as TCP flags.  see header for details. */
int
skStringParseTCPFlags(
    uint8_t            *result,
    const char         *flag_string)
{
    const char *cp = flag_string;

    /* check inputs */
    assert(result);
    if (flag_string == NULL) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    /* parse each character, unless it is a terminating NULL or an
     * illegal character.
     */
    *result = 0;
    while (*cp) {
        switch (*cp) {
          case '-':
            TCP_FLAG_SET_FLAG(*result,
                              (FIN_FLAG | SYN_FLAG | RST_FLAG | PSH_FLAG |
                               ACK_FLAG | URG_FLAG | ECE_FLAG | CWR_FLAG ));
            break;
          case 'f':
          case 'F':
            TCP_FLAG_SET_FLAG(*result, FIN_FLAG);
            break;
          case 's':
          case 'S':
            TCP_FLAG_SET_FLAG(*result, SYN_FLAG);
            break;
          case 'r':
          case 'R':
            TCP_FLAG_SET_FLAG(*result, RST_FLAG);
            break;
          case 'p':
          case 'P':
            TCP_FLAG_SET_FLAG(*result, PSH_FLAG);
            break;
          case 'a':
          case 'A':
            TCP_FLAG_SET_FLAG(*result, ACK_FLAG);
            break;
          case 'u':
          case 'U':
            TCP_FLAG_SET_FLAG(*result, URG_FLAG);
            break;
          case 'e':
          case 'E':
            TCP_FLAG_SET_FLAG(*result, ECE_FLAG);
            break;
          case 'c':
          case 'C':
            TCP_FLAG_SET_FLAG(*result, CWR_FLAG);
            break;
          case ' ':
            break;
          default:
            if (!isspace((int)*cp)) {
                /* reached illegal, non-space character */
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *cp);
            }
            break;
        }
        ++cp;
    }

    return SKUTILS_OK;
}


/* parse flag definition in the form high/mask.  see header for
 * details. */
int
skStringParseTCPFlagsHighMask(
    uint8_t            *high,
    uint8_t            *mask,
    const char         *flag_string)
{
    const char *cp = flag_string;
    uint8_t *result;

    /* check inputs */
    assert(high);
    assert(mask);
    if (flag_string == NULL) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    *high = 0;
    *mask = 0;
    result = high;

    /* parse each character, unless it is a terminating NULL or an
     * illegal character.
     */
    while (*cp) {
        switch (*cp) {
          case '-':
            TCP_FLAG_SET_FLAG(*result,
                              (FIN_FLAG | SYN_FLAG | RST_FLAG | PSH_FLAG |
                               ACK_FLAG | URG_FLAG | ECE_FLAG | CWR_FLAG ));
            break;
          case 'f':
          case 'F':
            TCP_FLAG_SET_FLAG(*result, FIN_FLAG);
            break;
          case 's':
          case 'S':
            TCP_FLAG_SET_FLAG(*result, SYN_FLAG);
            break;
          case 'r':
          case 'R':
            TCP_FLAG_SET_FLAG(*result, RST_FLAG);
            break;
          case 'p':
          case 'P':
            TCP_FLAG_SET_FLAG(*result, PSH_FLAG);
            break;
          case 'a':
          case 'A':
            TCP_FLAG_SET_FLAG(*result, ACK_FLAG);
            break;
          case 'u':
          case 'U':
            TCP_FLAG_SET_FLAG(*result, URG_FLAG);
            break;
          case 'e':
          case 'E':
            TCP_FLAG_SET_FLAG(*result, ECE_FLAG);
            break;
          case 'c':
          case 'C':
            TCP_FLAG_SET_FLAG(*result, CWR_FLAG);
            break;
          case '/':
            if (result == mask) {
                /* double slash */
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *cp);
            }
            result = mask;
            break;
          case ' ':
            break;
          default:
            if (!isspace((int)*cp)) {
                /* reached illegal, non-space character */
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *cp);
            }
            break;
        }
        ++cp;
    }

    /* check if we reached end of string before '/' character was found */
    if (result == high) {
        if (*high == 0) {
            return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
        }
        return parseError(SKUTILS_ERR_SHORT, "Missing '/' character");
    }

    if (*mask == 0) {
        return parseError(SKUTILS_ERR_SHORT, "Missing masks flags value");
    }

    /* make sure high is a proper subset of mask */
    if ((*high & *mask) != *high) {
        return parseError(SKUTILS_ERR_BAD_RANGE,
                          "High flags is not subset of mask flags");
    }

    /* success */
    return SKUTILS_OK;
}


/* parse string as TCP state flags.  see header for details. */
int
skStringParseTCPState(
    uint8_t            *result,
    const char         *flag_string)
{
    const char *cp = flag_string;

    /* check inputs */
    assert(result);
    if (flag_string == NULL) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    /* parse each character, unless it is a terminating NULL or an
     * illegal character.
     */
    *result = 0;
    while (*cp) {
        switch (*cp) {
          case '-':
            *result |= (SK_TCPSTATE_TIMEOUT_KILLED
                        | SK_TCPSTATE_TIMEOUT_STARTED
                        | SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK
                        | SK_TCPSTATE_UNIFORM_PACKET_SIZE);
            break;
          case 't':
          case 'T':
            *result |= SK_TCPSTATE_TIMEOUT_KILLED;
            break;
          case 'c':
          case 'C':
            *result |= SK_TCPSTATE_TIMEOUT_STARTED;
            break;
          case 'f':
          case 'F':
            *result |= SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK;
            break;
          case 's':
          case 'S':
            *result |= SK_TCPSTATE_UNIFORM_PACKET_SIZE;
            break;
          case ' ':
            break;
          default:
            if (!isspace((int)*cp)) {
                /* reached illegal, non-space character */
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *cp);
            }
            break;
        }
        ++cp;
    }

    return SKUTILS_OK;
}


/* parse TCP state flag definition in the form high/mask.  see header
 * for details. */
int
skStringParseTCPStateHighMask(
    uint8_t            *high,
    uint8_t            *mask,
    const char         *flag_string)
{
    const char *cp = flag_string;
    uint8_t *result;

    /* check inputs */
    assert(high);
    assert(mask);
    if (flag_string == NULL) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    *high = 0;
    *mask = 0;
    result = high;

    /* parse each character, unless it is a terminating NULL or an
     * illegal character.
     */
    while (*cp) {
        switch (*cp) {
          case '-':
            *result |= (SK_TCPSTATE_TIMEOUT_KILLED
                        | SK_TCPSTATE_TIMEOUT_STARTED
                        | SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK
                        | SK_TCPSTATE_UNIFORM_PACKET_SIZE);
            break;
          case 't':
          case 'T':
            *result |= SK_TCPSTATE_TIMEOUT_KILLED;
            break;
          case 'c':
          case 'C':
            *result |= SK_TCPSTATE_TIMEOUT_STARTED;
            break;
          case 'f':
          case 'F':
            *result |= SK_TCPSTATE_FIN_FOLLOWED_NOT_ACK;
            break;
          case 's':
          case 'S':
            *result |= SK_TCPSTATE_UNIFORM_PACKET_SIZE;
            break;
          case '/':
            if (result == mask) {
                /* double slash */
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *cp);
            }
            result = mask;
            break;
          case ' ':
            break;
          default:
            if (!isspace((int)*cp)) {
                /* reached illegal, non-space character */
                return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                                  PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                                  *cp);
            }
            break;
        }
        ++cp;
    }

    /* check if we reached end of string before '/' character was found */
    if (result == high) {
        if (*high == 0) {
            return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
        }
        return parseError(SKUTILS_ERR_SHORT, "Missing '/' character");
    }

    if (*mask == 0) {
        return parseError(SKUTILS_ERR_SHORT,
                          "Missing masks state flags value");
    }

    /* make sure high is a proper subset of mask */
    if ((*high & *mask) != *high) {
        return parseError(SKUTILS_ERR_BAD_RANGE,
                          ("High state flags is not subset"
                           " of mask state flags"));
    }

    /* success */
    return SKUTILS_OK;
}


/* parse string as uint32_t.  see header for details */
int
skStringParseUint32(
    uint32_t           *result_val,
    const char         *int_string,
    uint32_t            min_val,
    uint32_t            max_val)
{
    uint64_t tmp = UINT64_MAX;
    int rv;

    rv = skStringParseUint64(&tmp, int_string, min_val,
                             ((max_val == 0) ? UINT32_MAX : max_val));
    if (rv >= 0 || rv == SKUTILS_ERR_MINIMUM || rv == SKUTILS_ERR_MAXIMUM){
        if (tmp > UINT32_MAX) {
            return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
        }
        *result_val = UINT32_MAX & (uint32_t)tmp;
    }
    return rv;
}


/* parse string as uint64_t.  see header for details */
int
skStringParseUint64(
    uint64_t           *result_val,
    const char         *int_string,
    uint64_t            min_val,
    uint64_t            max_val)
{
    const char *sp;
    char *ep;
#if (SK_SIZEOF_LONG >= 8)
#define  U64_OVERFLOW ULONG_MAX
    unsigned long val;
#else
#define  U64_OVERFLOW ULLONG_MAX
    unsigned long long val;
#endif

    /* check inputs */
    assert(result_val);
    assert(max_val == 0 || min_val <= max_val);
    if (!int_string) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    sp = int_string;

    /* ignore leading whitespace */
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' == *sp) {
        /* whitespace only or empty string */
        return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
    }

    /* number that begins with '-' is not unsigned */
    if ('-' == *sp) {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                          *sp);
    }

    /* parse the string */
    errno = 0;
#if (SK_SIZEOF_LONG >= 8)
    val = strtoul(sp, &ep, 10);
#else
    val = strtoull(sp, &ep, 10);
#endif
    if (sp == ep) {
        /* parse error */
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                          *sp);
    }
    if (val == U64_OVERFLOW && errno == ERANGE) {
        /* overflow */
        return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
    }
#if (U64_OVERFLOW > UINT64_MAX)
    if (val > UINT64_MAX) {
        /* too big */
        return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
    }
#endif

    *result_val = (uint64_t)val;
    if (*result_val < min_val) {
        /* too small */
        return parseError(SKUTILS_ERR_MINIMUM, ("%s of %" PRIu64),
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_MINIMUM),
                          min_val);
    }
    if (max_val > 0 && *result_val > max_val) {
        /* too big */
        return parseError(SKUTILS_ERR_MAXIMUM, ("%s of %" PRIu64),
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_MAXIMUM),
                          max_val);
    }

    /* ignore trailing whitespace, but only if we reach the end of the
     * string. */
    sp = ep;
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' != *sp) {
        /* junk at end, return position of 'ep' */
        return ep - int_string;
    }

    return 0;
}


int
skStringParseHumanUint64(
    uint64_t           *result_val,
    const char         *int_string,
    unsigned int        parse_flags)
{
    const char *sp;             /* Current parse position */
    const char *tp;             /* Temporary pointer */
    const char *hv;             /* Index into sk_human_value_list */
    char *ep;                   /* End of parsed number */
    int val_index;
    double tmp_val;
    struct {
        const char  c;
        double      si;
        double      trad;
    } sk_human_values[] = {
        {'k', 1.0e3,           1024.0},
        {'m', 1.0e6,        1048576.0},
        {'g', 1.0e9,     1073741824.0},
        {'t', 1.0e12, 1099511627776.0}
    };
    const char sk_human_value_list[] = "kmgt";

    /* check inputs */
    assert(result_val);
    if (!int_string) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    /* allow parse_flags of 0 to be default */
    if (parse_flags == 0) {
        parse_flags = SK_HUMAN_NORMAL;
    }

    sp = int_string;

    /* ignore leading whitespace */
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' == *sp) {
        /* whitespace only or empty string */
        return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
    }

    /* parse the string */
    errno = 0;
    tmp_val = strtod(sp, &ep);
    if (sp == ep) {
        /* parse error */
        return parseError(SKUTILS_ERR_BAD_CHAR, PE_NULL);
    }
    if (errno == ERANGE) {
        if (tmp_val == HUGE_VAL || tmp_val == -HUGE_VAL) {
            /* overflow */
            return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
        }
        return parseError(SKUTILS_ERR_UNDERFLOW, PE_NULL);
    }
    if (tmp_val < 0) {
        /* underflow */
        return parseError(SKUTILS_ERR_UNDERFLOW, PE_NULL);
    }
    if (isnan(tmp_val)) {
        /* NAN */
        return parseError(SKUTILS_ERR_BAD_CHAR, PE_NULL);
    }

    tp = sp = ep;

    /* Possibly eat trailing whitespace (Parse with tp because it
     * might be space at the end (no suffix) when we are not supposed
     * to parse that.) */
    if ((parse_flags & SK_HUMAN_MID_WS)
        || !(parse_flags & SK_HUMAN_END_NO_WS))
    {
        while (*tp && isspace((int)*tp)) {
            ++tp;
        }
    }

    /* No suffix? */
    if ('\0' == *tp) {
        if (!(parse_flags & SK_HUMAN_END_NO_WS)) {
            /* If there was no suffix, and we are supposed to parse
             * trailing whitespace, set pointer to the end. */
            sp = tp;
        }
        goto parsed;
    }

    /* Spaces before suffix allowed? */
    if ((tp != sp) && !(parse_flags & SK_HUMAN_MID_WS)) {
        /* If there is a suffix, and white space in the middle is
         * illegal, treat the suffix as junk at the end of the
         * input. */
        sp = tp;
        goto parsed;
    }

    /* Possible suffix */
    hv = strchr(sk_human_value_list, tolower((int)*tp));
    if (hv != NULL) {
        /* Valid suffix found, set the parse pointer to the end of it */
        sp = tp + 1;

        /* Find suffix information */
        val_index = hv - sk_human_value_list;
        assert((int)sk_human_values[val_index].c == tolower((int)*tp));

        /* Use suffix value */
        if (((parse_flags & SK_HUMAN_LOWER_SI) && islower((int)*tp)) ||
            ((parse_flags & SK_HUMAN_UPPER_SI) && isupper((int)*tp)))
        {
            tmp_val *= sk_human_values[val_index].si;
        } else {
            tmp_val *= sk_human_values[val_index].trad;
        }

        /* eat trailing whitespace */
        if (!(parse_flags & SK_HUMAN_END_NO_WS)) {
            while (*sp && isspace((int)*sp)) {
                ++sp;
            }
        }
    } else if (!(parse_flags & SK_HUMAN_END_NO_WS)) {
        /* No valid suffix, but we allow trailing spaces. */
        sp = tp;
    }

  parsed:
    if (tmp_val > UINT64_MAX) {
        /* overflow */
        return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
    }

    *result_val = (uint64_t)tmp_val;

    if ('\0' != *sp) {
        /* junk at end */
        return 1 + (sp - int_string);
    }

    return 0;
}


int
skStringParseRange32(
    uint32_t           *range_lower,
    uint32_t           *range_upper,
    const char         *range_string,
    uint32_t            min_val,
    uint32_t            max_val,
    unsigned int        flags)
{
    uint64_t tmp_lower = 0;
    uint64_t tmp_upper = 0;
    int rv;

    rv = skStringParseRange64(&tmp_lower, &tmp_upper, range_string, min_val,
                             ((max_val == 0) ? UINT32_MAX : max_val), flags);

    /* these return codes indicate that at least one value was set */
    if (rv >= 0 || rv == SKUTILS_ERR_BAD_RANGE
        || rv == SKUTILS_ERR_MINIMUM || rv == SKUTILS_ERR_MAXIMUM)
    {
        /* return overflow error if appropriate */
        if ((tmp_lower > UINT32_MAX) || (tmp_upper > UINT32_MAX)) {
            return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
        }
        /* convert numbers back to uint32 */
        *range_lower = UINT32_MAX & (uint32_t)tmp_lower;
        *range_upper = UINT32_MAX & (uint32_t)tmp_upper;
    }
    return rv;
}


/* parse a single number '3' or a single range '3-5' */
int
skStringParseRange64(
    uint64_t           *range_lower,
    uint64_t           *range_upper,
    const char         *range_string,
    uint64_t            min_val,
    uint64_t            max_val,
    unsigned int        flags)
{
    const char *cp;
    int rv;

    assert(range_lower);
    assert(range_upper);
    assert(range_string);

    /* parse first part of range; rv, if positive, will be location of
     * the first non-digit following the value---should be a hyphen */
    rv = skStringParseUint64(range_lower, range_string, min_val, max_val);
    if (rv < 0) {
        /* an error */
        return rv;
    }

    if (rv == 0) {
        /* got a single value */
        if (flags & SKUTILS_RANGE_NO_SINGLE) {
            /* missing upper half */
            return parseError(SKUTILS_ERR_SHORT,
                              ("Range is missing hyphen"
                               " (single value is not supported)"));
        }
        /* single value ok; set upper and return */
        if (flags & SKUTILS_RANGE_MAX_SINGLE) {
            /* a missing range_upper is always the maximum */
            *range_upper = ((max_val == 0) ? UINT64_MAX : max_val);
        } else {
            /* set range_upper to the same value as lower */
            *range_upper = *range_lower;
        }
        return SKUTILS_OK;
    }

    /* get the character where parsing stopped---hopefully a hyphen */
    cp = &(range_string[rv]);

    /* check for the hyphen */
    if (*cp != '-') {
        /* stopped on non-hyphen */
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *cp);
    }

    /* goto start of upper bound */
    ++cp;
    ++rv;

    /* make certain character after '-' is a digit */
    if (!isdigit((int)*cp)) {
        /* check for open-ended range, permit whitespace between '-'
         * and end-of-string */
        while (isspace((int)*cp)) {
            ++cp;
        }
        if (*cp == '\0') {
            if (flags & SKUTILS_RANGE_NO_OPEN) {
                /* missing upper half */
                return parseError(SKUTILS_ERR_SHORT,
                                  ("Range is missing its upper limit"
                                   " (open-ended ranges are not supported)"));
            }
            /* set upper bound to maximum allowed value */
            *range_upper = ((max_val == 0) ? UINT64_MAX : max_val);
            return SKUTILS_OK;
        }
        /* got some junk char or embedded whitespace */
        return parseError(SKUTILS_ERR_BAD_CHAR,
                          "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                          range_string[rv]);
    }

    /* parse upper part of range */
    rv = skStringParseUint64(range_upper, cp, min_val, max_val);
    if (rv < 0) {
        /* parse error */
        return rv;
    }
    if (rv > 0) {
        /* extra chars after range */
        return parseError(SKUTILS_ERR_BAD_CHAR,
                          "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), cp[rv]);
    }

    if (*range_upper < *range_lower) {
        return parseError(SKUTILS_ERR_BAD_RANGE, PE_NULL);
    }

    return SKUTILS_OK;
}


/* parse string as a double.  see header for details */
int
skStringParseDouble(
    double             *result_val,
    const char         *dbl_string,
    double              min_val,
    double              max_val)
{
    const char *sp;
    char *ep;
    double val;

    /* check inputs */
    assert(result_val);
    assert(max_val == 0 || min_val <= max_val);
    if (!dbl_string) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    sp = dbl_string;

    /* ignore leading whitespace */
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' == *sp) {
        /* whitespace only or empty string */
        return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
    }

    /* parse the string */
    errno = 0;
    val = strtod(sp, &ep);
    if (sp == ep) {
        /* parse error */
        return parseError(SKUTILS_ERR_BAD_CHAR, PE_NULL);
    }
    if (errno == ERANGE) {
        if (val == 0) {
            /* underflow */
            return parseError(SKUTILS_ERR_UNDERFLOW, PE_NULL);
        }
        /* overflow */
        assert(val == HUGE_VAL || val == -HUGE_VAL);
        return parseError(SKUTILS_ERR_OVERFLOW, PE_NULL);
    }
    if (isnan(val)) {
        /* NAN */
        return parseError(SKUTILS_ERR_BAD_CHAR, PE_NULL);
    }

    *result_val = val;
    if (*result_val < min_val) {
        /* too small */
        return parseError(SKUTILS_ERR_MINIMUM, "%s of %f",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_MINIMUM),
                          min_val);
    }
    if (max_val > 0.0 && *result_val > max_val) {
        /* too big */
        return parseError(SKUTILS_ERR_MAXIMUM, "%s of %f",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_MAXIMUM),
                          max_val);
    }

    /* ignore trailing whitespace, but only if we reach the end of the
     * string. */
    sp = ep;
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' != *sp) {
        /* junk at end, return position of 'ep' */
        return ep - dbl_string;
    }

    return 0;
}


/* parse string as a range of doubles.  see header for details */
int
skStringParseDoubleRange(
    double             *range_lower,
    double             *range_upper,
    const char         *range_string,
    double              min_val,
    double              max_val,
    unsigned int        flags)
{
    const char *cp;
    int rv;

    /* parse first part of range; rv, if positive, will be location of
     * the first non-digit following the value---should be a hyphen */
    rv = skStringParseDouble(range_lower, range_string, min_val, max_val);
    if (rv < 0) {
        /* an error */
        return rv;
    }

    if (rv == 0) {
        /* got a single value */
        if (flags & SKUTILS_RANGE_NO_SINGLE) {
            /* missing upper half */
            return parseError(SKUTILS_ERR_SHORT,
                              ("Range is missing hyphen"
                               " (single value is not supported)"));
        }
        /* single value ok.  set range_upper to the same value and
         * return */
        *range_upper = *range_lower;
        return SKUTILS_OK;
    }

    /* get the character where parsing stopped---hopefully a hyphen */
    cp = &(range_string[rv]);

    /* check for the hyphen */
    if (*cp != '-') {
        /* stopped on non-hyphen */
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *cp);
    }

    /* goto start of upper bound */
    ++cp;
    ++rv;

    /* if *cp is on a '+' or '-', make certain the following character
     * is a digit.  Otherwise, make certain we're on a digit, or
     * handle an open-ended range. */
    if (*cp == '+' || *cp == '-') {
        if (!isdigit((int) *(cp + 1))) {
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "%s '%c'",
                              PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                              range_string[rv]);
        }

    } else if (!isdigit((int)*cp)) {
        /* check for open-ended range, permit whitespace between '-'
         * and end-of-string */
        while (isspace((int)*cp)) {
            ++cp;
        }
        if (*cp == '\0') {
            if (flags & SKUTILS_RANGE_NO_OPEN) {
                /* missing upper half */
                return parseError(SKUTILS_ERR_SHORT,
                                  ("Range is missing its upper limit"
                                   " (open-ended ranges are not supported)"));
            }
            /* set upper bound to maximum allowed value */
            *range_upper = ((max_val == 0.0) ? HUGE_VAL : max_val);
            return SKUTILS_OK;
        }
        /* got some junk char or embedded whitespace */
        return parseError(SKUTILS_ERR_BAD_CHAR,
                          "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR),
                          range_string[rv]);
    }

    /* parse upper part of range */
    rv = skStringParseDouble(range_upper, cp, min_val, max_val);
    if (rv < 0) {
        /* parse error */
        return rv;
    }
    if (rv > 0) {
        /* extra chars after range */
        return parseError(SKUTILS_ERR_BAD_CHAR,
                          "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), cp[rv]);
    }

    if (*range_upper < *range_lower) {
        return parseError(SKUTILS_ERR_BAD_RANGE, PE_NULL);
    }

    return SKUTILS_OK;
}


const char *
skSignalToName(
    int                 signal_num)
{
    int i;

    for (i = 0; i < signal_name2num_count; ++i) {
        if (signal_num == signal_name2num[i].number) {
            return signal_name2num[i].name;
        }
    }
    return "?";
}


int
skStringParseSignal(
    int                *signal_num,
    const char         *signal_name)
{
    char buf[16];
    const char *sp = signal_name;
    const char *ep;
    int i;

    /* check inputs */
    assert(signal_num);
    if (signal_name == NULL) {
        return parseError(SKUTILS_ERR_INVALID, PE_NULL);
    }

    /* ignore leading whitespace */
    while (*sp && isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' == *sp) {
        /* whitespace only or empty string */
        return parseError(SKUTILS_ERR_EMPTY, PE_NULL);
    }

    /* if it looks like a number, treat it as such */
    if (isdigit((int)*sp)) {
        uint32_t tmp32 = 0;
        int max_sig = 0;
        int rv;

        for (i = 0; i < signal_name2num_count; ++i) {
            if (max_sig < signal_name2num[i].number) {
                max_sig = signal_name2num[i].number;
            }
        }

        rv = skStringParseUint32(&tmp32, signal_name, 1, max_sig);
        /* should we search for 'tmp32' in signal_name2num[] to
         * determine whether it is a usable value? */
        *signal_num = (int)tmp32;
        return rv;
    }

    /* skip leading "SIG" prefix, if any */
    if (0 == strncmp("SIG", sp, 3)) {
        sp += 3;
    }

    /* find end of signal name.  if extra text follows name, copy name
     * into 'buf'. */
    ep = sp;
    while (isalnum((int)*ep)) {
        ++ep;
    }
    if (ep == sp) {
        return parseError(SKUTILS_ERR_BAD_CHAR, "%s '%c'",
                          PARSE_ERRORCODE_MSG(SKUTILS_ERR_BAD_CHAR), *sp);
    }
    if ('\0' != *ep) {
        if ((ep - sp) > (int)(sizeof(buf) - 1)) {
            /* name too long */
            return parseError(SKUTILS_ERR_BAD_CHAR,
                              "Value too long to be valid signal name");
        }
        strncpy(buf, sp, sizeof(buf));
        buf[ep - sp] = '\0';
        sp = buf;
    }

    /* linear search to find a match */
    for (i = 0; i < signal_name2num_count; ++i) {
        if (0 == strcasecmp(sp, signal_name2num[i].name)) {
            /* found a match */
            *signal_num = signal_name2num[i].number;
            while (isspace((int)*ep)) {
                ++ep;
            }
            if ('\0' == *ep) {
                return 0;
            }
            return (ep - signal_name);
        }
    }

    return parseError(SKUTILS_ERR_BAD_CHAR, "Unknown signal name '%s'", sp);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
