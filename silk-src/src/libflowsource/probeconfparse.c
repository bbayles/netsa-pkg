/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     ACCEPT_FROM_HOST_T = 258,
     COMMA = 259,
     END_GROUP_T = 260,
     END_PROBE_T = 261,
     END_SENSOR_T = 262,
     EOL = 263,
     GROUP_T = 264,
     INCLUDE_T = 265,
     INTERFACES_T = 266,
     INTERFACE_VALUES_T = 267,
     IPBLOCKS_T = 268,
     IPSETS_T = 269,
     ISP_IP_T = 270,
     LISTEN_AS_HOST_T = 271,
     LISTEN_ON_PORT_T = 272,
     LISTEN_ON_USOCKET_T = 273,
     LOG_FLAGS_T = 274,
     POLL_DIRECTORY_T = 275,
     PRIORITY_T = 276,
     PROBE_T = 277,
     PROTOCOL_T = 278,
     QUIRKS_T = 279,
     READ_FROM_FILE_T = 280,
     REMAINDER_T = 281,
     SENSOR_T = 282,
     ID = 283,
     NET_NAME_INTERFACE = 284,
     NET_NAME_IPBLOCK = 285,
     NET_NAME_IPSET = 286,
     PROBES = 287,
     QUOTED_STRING = 288,
     NET_DIRECTION = 289,
     FILTER = 290,
     ERR_STR_TOO_LONG = 291
   };
#endif
/* Tokens.  */
#define ACCEPT_FROM_HOST_T 258
#define COMMA 259
#define END_GROUP_T 260
#define END_PROBE_T 261
#define END_SENSOR_T 262
#define EOL 263
#define GROUP_T 264
#define INCLUDE_T 265
#define INTERFACES_T 266
#define INTERFACE_VALUES_T 267
#define IPBLOCKS_T 268
#define IPSETS_T 269
#define ISP_IP_T 270
#define LISTEN_AS_HOST_T 271
#define LISTEN_ON_PORT_T 272
#define LISTEN_ON_USOCKET_T 273
#define LOG_FLAGS_T 274
#define POLL_DIRECTORY_T 275
#define PRIORITY_T 276
#define PROBE_T 277
#define PROTOCOL_T 278
#define QUIRKS_T 279
#define READ_FROM_FILE_T 280
#define REMAINDER_T 281
#define SENSOR_T 282
#define ID 283
#define NET_NAME_INTERFACE 284
#define NET_NAME_IPBLOCK 285
#define NET_NAME_IPSET 286
#define PROBES 287
#define QUOTED_STRING 288
#define NET_DIRECTION 289
#define FILTER 290
#define ERR_STR_TOO_LONG 291




/* Copy the first part of user declarations.  */
#line 1 "probeconfparse.y"

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
**  Parser for probe configuration file
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: probeconfparse.y b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/libflowsource.h>
#include <silk/probeconf.h>
#include <silk/skipaddr.h>
#include <silk/skipset.h>
#include <silk/sklog.h>
#include <silk/sksite.h>
#include "probeconfscan.h"


/* LOCAL DEFINES AND TYPEDEFS */

/* Set DEBUG to 1 to enable debugging printf messasges, 0 otherwise.
 * Generally best to leave this commented out so gcc -DDEBUG=1 will
 * work */
/* #define DEBUG 1 */

/* Verify DEBUG is set */
#ifndef DEBUG
#  define DEBUG 0
#endif

/* For printing messages when DEBUG is non-zero.  Use as:
 *    DEBUG_PRINTF(("x is %d\n", x));
 * Note ((double parens)) */
#if DEBUG
#  define DEBUG_PRINTF(x) printf x
#else
#  define DEBUG_PRINTF(x)
#endif


/* magic value used to denote that a uint16_t---which are stored in
 * uint32_t's in the parser---has not yet been given a value. */
#define UINT16_NO_VALUE  0x10000  /* 0xFFFF + 1 */

/*
 * sk_vector_t of IDs are created as they are needed, but to avoid
 * repeatedly creating and destroying the vectors, "deleted" vectors are
 * added to a pool.  When creating a vector, the code will check the
 * pool before allocating.  This macro is the size of the pool; if a
 * vector is "deleted" and the pool is full, the vector is free()ed.
 */
#define VECTOR_POOL_CAPACITY  16


typedef struct vector_pool_st {
    sk_vector_t    *pool[VECTOR_POOL_CAPACITY];
    size_t          element_size;
    int             count;
} vector_pool_t;


/* LOCAL VARIABLES */

/* number of errors in current defn */
static int defn_errors = 0;

/* the vector pools */
static vector_pool_t ptr_vector_pool;
static vector_pool_t *ptr_pool = &ptr_vector_pool;
static vector_pool_t u32_vector_pool;
static vector_pool_t *u32_pool = &u32_vector_pool;

/* The parser works on a single global probe, sensor, or group */
static skpc_probe_t *probe = NULL;
static skpc_sensor_t *sensor = NULL;
static skpc_group_t *group = NULL;

/* Place to stash listen_as address and port until end of probe is
 * reached */
static char *listen_as_address = NULL;
static char *listen_port = NULL;

/* LOCAL FUNCTION PROTOTYPES */

static sk_vector_t *vectorPoolGet(vector_pool_t *pool);
static void vectorPoolPut(vector_pool_t *pool, sk_vector_t *v);
static void vectorPoolEmpty(vector_pool_t *pool);


static void missing_value(void);


/* include a file */
static void include_file(char *name);

/* functions to set attributes of a probe_attr_t */
static void
probe_begin(
    char               *probe_name,
    char               *probe_type);
static void probe_end(void);
static void probe_priority(sk_vector_t *v);
static void probe_protocol(sk_vector_t *v);
static void probe_listen_as_host(sk_vector_t *v);
static void probe_listen_on_port(sk_vector_t *v);
static void probe_listen_on_usocket(sk_vector_t *v);
static void probe_read_from_file(sk_vector_t *v);
static void probe_poll_directory(sk_vector_t *v);
static void probe_accept_from_host(sk_vector_t *v);
static void probe_log_flags(sk_vector_t *v);
static void probe_interface_values(sk_vector_t *v);
static void probe_quirks(sk_vector_t *v);

static void
sensor_begin(
    char               *sensor_name);
static void sensor_end(void);
static void sensor_isp_ip(sk_vector_t *v);
static void sensor_interface(char *name, sk_vector_t *list);
static void
sensor_ipblock(
    char               *name,
    sk_vector_t        *wl);
static void
sensor_ipset(
    char               *name,
    sk_vector_t        *wl);
static void sensor_filter(skpc_filter_t filter, sk_vector_t *v, int is_files);
static void sensor_network(skpc_direction_t direction, char *name);
static void sensor_probes(char *probe_type, sk_vector_t *v);

static void
group_begin(
    char               *group_name);
static void group_end(void);
static void
group_add_data(
    sk_vector_t        *v,
    skpc_group_type_t   g_type);

static skpc_group_t *
get_group(
    const char         *g_name,
    skpc_group_type_t   g_type);
static int
add_values_to_group(
    skpc_group_t       *g,
    sk_vector_t        *v,
    skpc_group_type_t   g_type);


/* functions to convert string input to another form */
static uint32_t parse_int_u16(char *s);
static int vectorSingleString(sk_vector_t *v, char **s);
static int parse_ip_addr(char *s, uint32_t *ip);
static skipset_t *parse_ipset_filename(char *s);
static skIPWildcard_t *parse_wildcard_addr(char *s);




/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 212 "probeconfparse.y"
{
    char               *string;
    sk_vector_t        *vector;
    uint32_t            u32;
    skpc_direction_t    net_dir;
    skpc_filter_t       filter;
}
/* Line 193 of yacc.c.  */
#line 388 "probeconfparse.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 401 "probeconfparse.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int i)
#else
static int
YYID (i)
    int i;
#endif
{
  return i;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   227

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  37
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  42
/* YYNRULES -- Number of rules.  */
#define YYNRULES  116
/* YYNRULES -- Number of states.  */
#define YYNSTATES  189

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   291

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,    10,    13,    16,    18,    22,
      25,    29,    34,    38,    41,    44,    47,    50,    51,    54,
      56,    58,    60,    62,    64,    66,    68,    70,    72,    74,
      76,    78,    82,    85,    89,    92,    96,    99,   103,   106,
     110,   113,   117,   120,   124,   127,   131,   134,   138,   141,
     145,   148,   152,   155,   159,   160,   163,   165,   167,   169,
     171,   173,   175,   177,   179,   183,   186,   189,   192,   195,
     199,   202,   206,   210,   213,   217,   221,   224,   228,   232,
     236,   239,   243,   247,   250,   254,   257,   261,   264,   268,
     269,   272,   274,   276,   278,   280,   284,   287,   290,   293,
     296,   300,   303,   307,   310,   314,   318,   321,   323,   326,
     330,   332,   335,   339,   342,   346,   348
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      38,     0,    -1,    -1,    38,    40,    -1,    38,    56,    -1,
      38,    68,    -1,    38,    39,    -1,     1,    -1,    10,    33,
       8,    -1,    10,     8,    -1,    41,    43,    42,    -1,    22,
      28,    28,     8,    -1,    22,    28,     8,    -1,    22,     8,
      -1,     6,     8,    -1,     5,     8,    -1,     7,     8,    -1,
      -1,    43,    44,    -1,    45,    -1,    46,    -1,    47,    -1,
      48,    -1,    49,    -1,    50,    -1,    51,    -1,    52,    -1,
      53,    -1,    54,    -1,    55,    -1,     1,    -1,    21,    76,
       8,    -1,    21,     8,    -1,    23,    76,     8,    -1,    23,
       8,    -1,    16,    76,     8,    -1,    16,     8,    -1,    17,
      76,     8,    -1,    17,     8,    -1,    18,    76,     8,    -1,
      18,     8,    -1,    25,    76,     8,    -1,    25,     8,    -1,
      20,    76,     8,    -1,    20,     8,    -1,     3,    76,     8,
      -1,     3,     8,    -1,    19,    76,     8,    -1,    19,     8,
      -1,    12,    76,     8,    -1,    12,     8,    -1,    24,    76,
       8,    -1,    24,     8,    -1,    59,    57,    60,    -1,    -1,
      57,    58,    -1,    61,    -1,    62,    -1,    63,    -1,    64,
      -1,    65,    -1,    66,    -1,    67,    -1,     1,    -1,    27,
      28,     8,    -1,    27,     8,    -1,     7,     8,    -1,     5,
       8,    -1,     6,     8,    -1,    15,    76,     8,    -1,    15,
       8,    -1,    29,    76,     8,    -1,    29,    26,     8,    -1,
      29,     8,    -1,    30,    76,     8,    -1,    30,    26,     8,
      -1,    30,     8,    -1,    31,    76,     8,    -1,    31,    77,
       8,    -1,    31,    26,     8,    -1,    31,     8,    -1,    35,
      76,     8,    -1,    35,    77,     8,    -1,    35,     8,    -1,
      34,    28,     8,    -1,    34,     8,    -1,    32,    76,     8,
      -1,    32,     8,    -1,    71,    69,    72,    -1,    -1,    69,
      70,    -1,    73,    -1,    74,    -1,    75,    -1,     1,    -1,
       9,    28,     8,    -1,     9,     8,    -1,     5,     8,    -1,
       6,     8,    -1,     7,     8,    -1,    11,    76,     8,    -1,
      11,     8,    -1,    13,    76,     8,    -1,    13,     8,    -1,
      14,    76,     8,    -1,    14,    77,     8,    -1,    14,     8,
      -1,    28,    -1,    76,    28,    -1,    76,     4,    28,    -1,
      33,    -1,    76,    33,    -1,    76,     4,    33,    -1,    77,
      78,    -1,    77,     4,    78,    -1,    28,    -1,    33,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   267,   267,   268,   269,   270,   271,   272,   283,   287,
     297,   300,   304,   309,   315,   319,   325,   333,   334,   337,
     338,   339,   340,   341,   342,   343,   344,   345,   346,   347,
     348,   357,   361,   366,   370,   375,   379,   384,   388,   393,
     397,   402,   406,   411,   415,   420,   424,   430,   434,   439,
     443,   448,   452,   462,   465,   466,   469,   470,   471,   472,
     473,   474,   475,   476,   485,   489,   494,   498,   504,   511,
     515,   520,   524,   528,   536,   540,   544,   552,   556,   560,
     564,   572,   578,   584,   589,   593,   598,   602,   615,   618,
     619,   622,   623,   624,   625,   634,   638,   643,   647,   653,
     660,   664,   669,   673,   678,   682,   686,   697,   704,   710,
     724,   731,   737,   743,   749,   756,   756
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "ACCEPT_FROM_HOST_T", "COMMA",
  "END_GROUP_T", "END_PROBE_T", "END_SENSOR_T", "EOL", "GROUP_T",
  "INCLUDE_T", "INTERFACES_T", "INTERFACE_VALUES_T", "IPBLOCKS_T",
  "IPSETS_T", "ISP_IP_T", "LISTEN_AS_HOST_T", "LISTEN_ON_PORT_T",
  "LISTEN_ON_USOCKET_T", "LOG_FLAGS_T", "POLL_DIRECTORY_T", "PRIORITY_T",
  "PROBE_T", "PROTOCOL_T", "QUIRKS_T", "READ_FROM_FILE_T", "REMAINDER_T",
  "SENSOR_T", "ID", "NET_NAME_INTERFACE", "NET_NAME_IPBLOCK",
  "NET_NAME_IPSET", "PROBES", "QUOTED_STRING", "NET_DIRECTION", "FILTER",
  "ERR_STR_TOO_LONG", "$accept", "input", "include_stmt", "probe_defn",
  "probe_begin", "probe_end", "probe_stmts", "probe_stmt",
  "stmt_probe_priority", "stmt_probe_protocol", "stmt_probe_listen_host",
  "stmt_probe_listen_port", "stmt_probe_listen_usocket",
  "stmt_probe_read_file", "stmt_probe_poll_directory",
  "stmt_probe_accept_host", "stmt_probe_log_flags",
  "stmt_probe_interface_values", "stmt_probe_quirks", "sensor_defn",
  "sensor_stmts", "sensor_stmt", "sensor_begin", "sensor_end",
  "stmt_sensor_isp_ip", "stmt_sensor_interface", "stmt_sensor_ipblock",
  "stmt_sensor_ipset", "stmt_sensor_filter", "stmt_sensor_network",
  "stmt_sensor_probes", "group_defn", "group_stmts", "group_stmt",
  "group_begin", "group_end", "stmt_group_interfaces",
  "stmt_group_ipblocks", "stmt_group_ipsets", "id_list", "filename_list",
  "filename", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    37,    38,    38,    38,    38,    38,    38,    39,    39,
      40,    41,    41,    41,    42,    42,    42,    43,    43,    44,
      44,    44,    44,    44,    44,    44,    44,    44,    44,    44,
      44,    45,    45,    46,    46,    47,    47,    48,    48,    49,
      49,    50,    50,    51,    51,    52,    52,    53,    53,    54,
      54,    55,    55,    56,    57,    57,    58,    58,    58,    58,
      58,    58,    58,    58,    59,    59,    60,    60,    60,    61,
      61,    62,    62,    62,    63,    63,    63,    64,    64,    64,
      64,    65,    65,    65,    66,    66,    67,    67,    68,    69,
      69,    70,    70,    70,    70,    71,    71,    72,    72,    72,
      73,    73,    74,    74,    75,    75,    75,    76,    76,    76,
      77,    77,    77,    77,    77,    78,    78
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     2,     2,     2,     1,     3,     2,
       3,     4,     3,     2,     2,     2,     2,     0,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     3,     2,     3,     2,     3,     2,     3,     2,     3,
       2,     3,     2,     3,     2,     3,     2,     3,     2,     3,
       2,     3,     2,     3,     0,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     3,     2,     2,     2,     2,     3,
       2,     3,     3,     2,     3,     3,     2,     3,     3,     3,
       2,     3,     3,     2,     3,     2,     3,     2,     3,     0,
       2,     1,     1,     1,     1,     3,     2,     2,     2,     2,
       3,     2,     3,     2,     3,     3,     2,     1,     2,     3,
       1,     2,     3,     2,     3,     1,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     7,     0,     1,     0,     0,     0,     0,     6,     3,
      17,     4,    54,     5,    89,    96,     0,     9,     0,    13,
       0,    65,     0,     0,     0,     0,    95,     8,    12,     0,
      64,    30,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    10,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    63,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      55,    53,    56,    57,    58,    59,    60,    61,    62,    94,
       0,     0,     0,     0,     0,     0,    90,    88,    91,    92,
      93,    11,    46,   107,     0,    15,    14,    16,    50,     0,
      36,     0,    38,     0,    40,     0,    48,     0,    44,     0,
      32,     0,    34,     0,    52,     0,    42,     0,    67,    68,
      66,    70,     0,    73,     0,     0,    76,     0,     0,    80,
       0,   110,     0,     0,    87,     0,    85,     0,    83,     0,
       0,    97,    98,    99,   101,     0,   103,     0,   106,     0,
       0,     0,    45,   108,    49,    35,    37,    39,    47,    43,
      31,    33,    51,    41,    69,    72,    71,    75,    74,    79,
       0,    77,   111,     0,    78,   115,   116,   113,    86,    84,
      81,    82,   100,   102,   104,   105,   109,   112,   114
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     2,     8,     9,    10,    46,    23,    47,    48,    49,
      50,    51,    52,    53,    54,    55,    56,    57,    58,    11,
      24,    70,    12,    71,    72,    73,    74,    75,    76,    77,
      78,    13,    25,    86,    14,    87,    88,    89,    90,    94,
     133,   177
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -52
static const yytype_int16 yypact[] =
{
      63,   -52,    65,   -52,    61,     4,    73,   150,   -52,   -52,
     -52,   -52,   -52,   -52,   -52,   -52,     3,   -52,     5,   -52,
     157,   -52,    11,    93,     9,   213,   -52,   -52,   -52,    12,
     -52,   -52,   158,    15,    27,    44,   160,   165,   166,   168,
     171,   172,   173,   174,   179,   181,   -52,   -52,   -52,   -52,
     -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,
      62,    72,    87,   182,   143,   149,    34,   183,   184,    58,
     -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,
      89,   114,   115,   187,   189,    60,   -52,   -52,   -52,   -52,
     -52,   -52,   -52,   -52,    98,   -52,   -52,   -52,   -52,    99,
     -52,   100,   -52,   111,   -52,   116,   -52,   117,   -52,   125,
     -52,   126,   -52,   127,   -52,   128,   -52,   133,   -52,   -52,
     -52,   -52,   134,   -52,   132,   139,   -52,   141,   142,   -52,
     196,   -52,    17,    18,   -52,   144,   -52,   197,   -52,    28,
      49,   -52,   -52,   -52,   -52,   155,   -52,   156,   -52,    50,
      51,   -11,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,
     -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,
      43,   -52,   -52,   170,   -52,   -52,   -52,   -52,   -52,   -52,
     -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,
     -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,
     -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,
     -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -52,   -36,
     -51,    33
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -3
static const yytype_int16 yytable[] =
{
      99,   101,   103,   105,   107,   109,   111,   113,   115,   117,
      59,    26,    17,    27,    60,    61,    62,   186,   140,    30,
      91,   170,   173,    95,    63,   171,   174,   122,   125,   128,
     132,   135,   170,   139,   150,    96,   180,    18,    64,    65,
      66,    67,   129,    68,    69,   153,   175,   145,   147,   149,
     172,   176,    97,   173,   170,   173,   153,   181,   184,   185,
     130,   172,    93,    -2,     1,     3,   138,   131,   148,    15,
     118,   186,    -2,    -2,     4,     5,   187,   175,   153,   175,
     119,    19,   176,   172,   176,    -2,    93,     6,    93,    16,
      -2,   131,     7,   131,    31,   120,    32,   141,    33,    34,
      35,    20,   151,   151,   151,    36,   152,   154,   155,    37,
      38,    39,    40,    41,    42,   151,    43,    44,    45,   156,
     151,   151,   142,   143,   157,   158,   153,   153,   153,   151,
     151,   151,   151,   159,   160,   161,   162,   151,   151,   153,
     165,   163,   164,   151,   153,   153,   151,   166,   151,   167,
     168,   123,   178,   153,   153,   153,   153,   126,    21,   151,
     151,   153,   153,   182,   183,    28,    92,   153,    98,   124,
     153,    93,   153,   100,   102,   127,   104,    93,    22,   106,
     108,   110,   112,   153,   153,    29,    93,   114,    93,   116,
     121,   134,   136,    93,    93,   144,    93,   146,   175,    93,
      93,    93,    93,   176,   169,   179,   188,    93,     0,    93,
      93,    93,   137,     0,    79,    93,     0,    93,    80,    81,
      82,     0,     0,     0,    83,     0,    84,    85
};

static const yytype_int16 yycheck[] =
{
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
       1,     8,     8,     8,     5,     6,     7,    28,    69,     8,
       8,     4,     4,     8,    15,     8,     8,    63,    64,    65,
      66,    67,     4,    69,    85,     8,     8,    33,    29,    30,
      31,    32,     8,    34,    35,    28,    28,    83,    84,    85,
      33,    33,     8,     4,     4,     4,    28,     8,     8,     8,
      26,    33,    28,     0,     1,     0,     8,    33,     8,     8,
       8,    28,     9,    10,     9,    10,    33,    28,    28,    28,
       8,     8,    33,    33,    33,    22,    28,    22,    28,    28,
      27,    33,    27,    33,     1,     8,     3,     8,     5,     6,
       7,    28,     4,     4,     4,    12,     8,     8,     8,    16,
      17,    18,    19,    20,    21,     4,    23,    24,    25,     8,
       4,     4,     8,     8,     8,     8,    28,    28,    28,     4,
       4,     4,     4,     8,     8,     8,     8,     4,     4,    28,
       8,     8,     8,     4,    28,    28,     4,     8,     4,     8,
       8,     8,     8,    28,    28,    28,    28,     8,     8,     4,
       4,    28,    28,     8,     8,     8,     8,    28,     8,    26,
      28,    28,    28,     8,     8,    26,     8,    28,    28,     8,
       8,     8,     8,    28,    28,    28,    28,     8,    28,     8,
       8,     8,     8,    28,    28,     8,    28,     8,    28,    28,
      28,    28,    28,    33,     8,     8,   173,    28,    -1,    28,
      28,    28,    28,    -1,     1,    28,    -1,    28,     5,     6,
       7,    -1,    -1,    -1,    11,    -1,    13,    14
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     1,    38,     0,     9,    10,    22,    27,    39,    40,
      41,    56,    59,    68,    71,     8,    28,     8,    33,     8,
      28,     8,    28,    43,    57,    69,     8,     8,     8,    28,
       8,     1,     3,     5,     6,     7,    12,    16,    17,    18,
      19,    20,    21,    23,    24,    25,    42,    44,    45,    46,
      47,    48,    49,    50,    51,    52,    53,    54,    55,     1,
       5,     6,     7,    15,    29,    30,    31,    32,    34,    35,
      58,    60,    61,    62,    63,    64,    65,    66,    67,     1,
       5,     6,     7,    11,    13,    14,    70,    72,    73,    74,
      75,     8,     8,    28,    76,     8,     8,     8,     8,    76,
       8,    76,     8,    76,     8,    76,     8,    76,     8,    76,
       8,    76,     8,    76,     8,    76,     8,    76,     8,     8,
       8,     8,    76,     8,    26,    76,     8,    26,    76,     8,
      26,    33,    76,    77,     8,    76,     8,    28,     8,    76,
      77,     8,     8,     8,     8,    76,     8,    76,     8,    76,
      77,     4,     8,    28,     8,     8,     8,     8,     8,     8,
       8,     8,     8,     8,     8,     8,     8,     8,     8,     8,
       4,     8,    33,     4,     8,    28,    33,    78,     8,     8,
       8,     8,     8,     8,     8,     8,    28,    33,    78
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *bottom, yytype_int16 *top)
#else
static void
yy_stack_print (bottom, top)
    yytype_int16 *bottom;
    yytype_int16 *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      fprintf (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      fprintf (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  int yystate;
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;
#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  yytype_int16 yyssa[YYINITDEPTH];
  yytype_int16 *yyss = yyssa;
  yytype_int16 *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     look-ahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to look-ahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 7:
#line 273 "probeconfparse.y"
    {
    skpcParseErr("Misplaced or unrecognized keyword");
    ++pcscan_errors;
}
    break;

  case 8:
#line 284 "probeconfparse.y"
    {
    include_file((yyvsp[(2) - (3)].string));
}
    break;

  case 9:
#line 288 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 11:
#line 301 "probeconfparse.y"
    {
    probe_begin((yyvsp[(2) - (4)].string), (yyvsp[(3) - (4)].string));
}
    break;

  case 12:
#line 305 "probeconfparse.y"
    {
    /* error */
    probe_begin(NULL, (yyvsp[(2) - (3)].string));
}
    break;

  case 13:
#line 310 "probeconfparse.y"
    {
    /* error */
    probe_begin(NULL, NULL);
}
    break;

  case 14:
#line 316 "probeconfparse.y"
    {
    probe_end();
}
    break;

  case 15:
#line 320 "probeconfparse.y"
    {
    ++defn_errors;
    skpcParseErr("%s used to close probe", pcscan_clause);
    probe_end();
}
    break;

  case 16:
#line 326 "probeconfparse.y"
    {
    ++defn_errors;
    skpcParseErr("%s used to close probe", pcscan_clause);
    probe_end();
}
    break;

  case 30:
#line 349 "probeconfparse.y"
    {
    ++defn_errors;
    skpcParseErr(("Error in probe %s:"
                  " Missing \"end probe\" or invalid keyword or value"),
                 (probe ? skpcProbeGetName(probe) : "block"));
}
    break;

  case 31:
#line 358 "probeconfparse.y"
    {
    probe_priority((yyvsp[(2) - (3)].vector));
}
    break;

  case 32:
#line 362 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 33:
#line 367 "probeconfparse.y"
    {
    probe_protocol((yyvsp[(2) - (3)].vector));
}
    break;

  case 34:
#line 371 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 35:
#line 376 "probeconfparse.y"
    {
    probe_listen_as_host((yyvsp[(2) - (3)].vector));
}
    break;

  case 36:
#line 380 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 37:
#line 385 "probeconfparse.y"
    {
    probe_listen_on_port((yyvsp[(2) - (3)].vector));
}
    break;

  case 38:
#line 389 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 39:
#line 394 "probeconfparse.y"
    {
    probe_listen_on_usocket((yyvsp[(2) - (3)].vector));
}
    break;

  case 40:
#line 398 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 41:
#line 403 "probeconfparse.y"
    {
    probe_read_from_file((yyvsp[(2) - (3)].vector));
}
    break;

  case 42:
#line 407 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 43:
#line 412 "probeconfparse.y"
    {
    probe_poll_directory((yyvsp[(2) - (3)].vector));
}
    break;

  case 44:
#line 416 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 45:
#line 421 "probeconfparse.y"
    {
    probe_accept_from_host((yyvsp[(2) - (3)].vector));
}
    break;

  case 46:
#line 425 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 47:
#line 431 "probeconfparse.y"
    {
    probe_log_flags((yyvsp[(2) - (3)].vector));
}
    break;

  case 48:
#line 435 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 49:
#line 440 "probeconfparse.y"
    {
    probe_interface_values((yyvsp[(2) - (3)].vector));
}
    break;

  case 50:
#line 444 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 51:
#line 449 "probeconfparse.y"
    {
    probe_quirks((yyvsp[(2) - (3)].vector));
}
    break;

  case 52:
#line 453 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 63:
#line 477 "probeconfparse.y"
    {
    ++defn_errors;
    skpcParseErr(("Error in sensor %s:"
                  " Missing \"end sensor\" or invalid keyword or value"),
                 (sensor ? skpcSensorGetName(sensor) : "block"));
}
    break;

  case 64:
#line 486 "probeconfparse.y"
    {
    sensor_begin((yyvsp[(2) - (3)].string));
}
    break;

  case 65:
#line 490 "probeconfparse.y"
    {
    sensor_begin(NULL);
}
    break;

  case 66:
#line 495 "probeconfparse.y"
    {
    sensor_end();
}
    break;

  case 67:
#line 499 "probeconfparse.y"
    {
    ++defn_errors;
    skpcParseErr("%s used to close sensor", pcscan_clause);
    sensor_end();
}
    break;

  case 68:
#line 505 "probeconfparse.y"
    {
    ++defn_errors;
    skpcParseErr("%s used to close sensor", pcscan_clause);
    sensor_end();
}
    break;

  case 69:
#line 512 "probeconfparse.y"
    {
    sensor_isp_ip((yyvsp[(2) - (3)].vector));
}
    break;

  case 70:
#line 516 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 71:
#line 521 "probeconfparse.y"
    {
    sensor_interface((yyvsp[(1) - (3)].string), (yyvsp[(2) - (3)].vector));
}
    break;

  case 72:
#line 525 "probeconfparse.y"
    {
    sensor_interface((yyvsp[(1) - (3)].string), NULL);
}
    break;

  case 73:
#line 529 "probeconfparse.y"
    {
    missing_value();
    if ((yyvsp[(1) - (2)].string)) {
        free((yyvsp[(1) - (2)].string));
    }
}
    break;

  case 74:
#line 537 "probeconfparse.y"
    {
    sensor_ipblock((yyvsp[(1) - (3)].string), (yyvsp[(2) - (3)].vector));
}
    break;

  case 75:
#line 541 "probeconfparse.y"
    {
    sensor_ipblock((yyvsp[(1) - (3)].string), NULL);
}
    break;

  case 76:
#line 545 "probeconfparse.y"
    {
    missing_value();
    if ((yyvsp[(1) - (2)].string)) {
        free((yyvsp[(1) - (2)].string));
    }
}
    break;

  case 77:
#line 553 "probeconfparse.y"
    {
    sensor_ipset((yyvsp[(1) - (3)].string), (yyvsp[(2) - (3)].vector));
}
    break;

  case 78:
#line 557 "probeconfparse.y"
    {
    sensor_ipset((yyvsp[(1) - (3)].string), (yyvsp[(2) - (3)].vector));
}
    break;

  case 79:
#line 561 "probeconfparse.y"
    {
    sensor_ipset((yyvsp[(1) - (3)].string), NULL);
}
    break;

  case 80:
#line 565 "probeconfparse.y"
    {
    missing_value();
    if ((yyvsp[(1) - (2)].string)) {
        free((yyvsp[(1) - (2)].string));
    }
}
    break;

  case 81:
#line 573 "probeconfparse.y"
    {
    /* discard-{when,unless}
     * {source,destination,any}-{interfaces,ipblocks,ipsets} */
    sensor_filter((yyvsp[(1) - (3)].filter), (yyvsp[(2) - (3)].vector), 0);
}
    break;

  case 82:
#line 579 "probeconfparse.y"
    {
    /* discard-{when,unless}
     * {source,destination,any}-ipsets */
    sensor_filter((yyvsp[(1) - (3)].filter), (yyvsp[(2) - (3)].vector), 1);
}
    break;

  case 83:
#line 585 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 84:
#line 590 "probeconfparse.y"
    {
    sensor_network((yyvsp[(1) - (3)].net_dir), (yyvsp[(2) - (3)].string));
}
    break;

  case 85:
#line 594 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 86:
#line 599 "probeconfparse.y"
    {
    sensor_probes((yyvsp[(1) - (3)].string), (yyvsp[(2) - (3)].vector));
}
    break;

  case 87:
#line 603 "probeconfparse.y"
    {
    missing_value();
    if ((yyvsp[(1) - (2)].string)) {
        free((yyvsp[(1) - (2)].string));
    }
}
    break;

  case 94:
#line 626 "probeconfparse.y"
    {
    ++defn_errors;
    skpcParseErr(("Error in group %s:"
                  " Missing \"end group\" or invalid keyword or value"),
                 (group ? skpcGroupGetName(group) : "block"));
}
    break;

  case 95:
#line 635 "probeconfparse.y"
    {
    group_begin((yyvsp[(2) - (3)].string));
}
    break;

  case 96:
#line 639 "probeconfparse.y"
    {
    group_begin(NULL);
}
    break;

  case 97:
#line 644 "probeconfparse.y"
    {
    group_end();
}
    break;

  case 98:
#line 648 "probeconfparse.y"
    {
    ++defn_errors;
    skpcParseErr("%s used to close group", pcscan_clause);
    group_end();
}
    break;

  case 99:
#line 654 "probeconfparse.y"
    {
    ++defn_errors;
    skpcParseErr("%s used to close group", pcscan_clause);
    group_end();
}
    break;

  case 100:
#line 661 "probeconfparse.y"
    {
    group_add_data((yyvsp[(2) - (3)].vector), SKPC_GROUP_INTERFACE);
}
    break;

  case 101:
#line 665 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 102:
#line 670 "probeconfparse.y"
    {
    group_add_data((yyvsp[(2) - (3)].vector), SKPC_GROUP_IPBLOCK);
}
    break;

  case 103:
#line 674 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 104:
#line 679 "probeconfparse.y"
    {
    group_add_data((yyvsp[(2) - (3)].vector), SKPC_GROUP_IPSET);
}
    break;

  case 105:
#line 683 "probeconfparse.y"
    {
    group_add_data((yyvsp[(2) - (3)].vector), SKPC_GROUP_IPSET);
}
    break;

  case 106:
#line 687 "probeconfparse.y"
    {
    missing_value();
}
    break;

  case 107:
#line 698 "probeconfparse.y"
    {
    sk_vector_t *v = vectorPoolGet(ptr_pool);
    char *s = (yyvsp[(1) - (1)].string);
    skVectorAppendValue(v, &s);
    (yyval.vector) = v;
}
    break;

  case 108:
#line 705 "probeconfparse.y"
    {
    char *s = (yyvsp[(2) - (2)].string);
    skVectorAppendValue((yyvsp[(1) - (2)].vector), &s);
    (yyval.vector) = (yyvsp[(1) - (2)].vector);
}
    break;

  case 109:
#line 711 "probeconfparse.y"
    {
    char *s = (yyvsp[(3) - (3)].string);
    skVectorAppendValue((yyvsp[(1) - (3)].vector), &s);
    (yyval.vector) = (yyvsp[(1) - (3)].vector);
}
    break;

  case 110:
#line 725 "probeconfparse.y"
    {
    sk_vector_t *v = vectorPoolGet(ptr_pool);
    char *s = (yyvsp[(1) - (1)].string);
    skVectorAppendValue(v, &s);
    (yyval.vector) = v;
}
    break;

  case 111:
#line 732 "probeconfparse.y"
    {
    char *s = (yyvsp[(2) - (2)].string);
    skVectorAppendValue((yyvsp[(1) - (2)].vector), &s);
    (yyval.vector) = (yyvsp[(1) - (2)].vector);
}
    break;

  case 112:
#line 738 "probeconfparse.y"
    {
    char *s = (yyvsp[(3) - (3)].string);
    skVectorAppendValue((yyvsp[(1) - (3)].vector), &s);
    (yyval.vector) = (yyvsp[(1) - (3)].vector);
}
    break;

  case 113:
#line 744 "probeconfparse.y"
    {
    char *s = (yyvsp[(2) - (2)].string);
    skVectorAppendValue((yyvsp[(1) - (2)].vector), &s);
    (yyval.vector) = (yyvsp[(1) - (2)].vector);
}
    break;

  case 114:
#line 750 "probeconfparse.y"
    {
    char *s = (yyvsp[(3) - (3)].string);
    skVectorAppendValue((yyvsp[(1) - (3)].vector), &s);
    (yyval.vector) = (yyvsp[(1) - (3)].vector);
}
    break;


/* Line 1267 of yacc.c.  */
#line 2395 "probeconfparse.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yymsg);
	  }
	else
	  {
	    yyerror (YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse look-ahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


#line 759 "probeconfparse.y"


/*
 * *******************   SUPPORTING CODE  ******************************
 */


/*
 *  *****  Pool of sk_vector_t  ****************************************
 */


/* get a new vector from the free-pool; if pool is empty, create
 * a new vector */
static sk_vector_t *
vectorPoolGet(
    vector_pool_t      *pool)
{
    sk_vector_t *v;

    /* if there are any in the pool, return one.  Otherwise create one. */
    if (pool->count) {
        --pool->count;
        v = pool->pool[pool->count];
        skVectorClear(v);
    } else {
        v = skVectorNew(pool->element_size);
    }

    return v;
}


/* add the vector to the free-pool.  If the pool is full, just
 * destroy the vector. */
static void
vectorPoolPut(
    vector_pool_t      *pool,
    sk_vector_t        *v)
{
    assert(pool);
    assert(v);
    assert(pool->element_size == skVectorGetElementSize(v));

    /* If the pool is full, destroy the list we were handed; otherwise
     * add it to the pool. */
    if (pool->count == VECTOR_POOL_CAPACITY) {
        skVectorDestroy(v);
    } else {
        pool->pool[pool->count] = v;
        ++pool->count;
    }
}


/* remove all vector's from the pool and destroy them */
static void
vectorPoolEmpty(
    vector_pool_t      *pool)
{
    int i;

    for (i = 0; i < pool->count; ++i) {
        skVectorDestroy(pool->pool[i]);
    }
    pool->count = 0;
}


static void
missing_value(
    void)
{
    ++defn_errors;
    skpcParseErr("Missing arguments for %s statement", pcscan_clause);
}


static void
include_file(
    char               *filename)
{
    skpcParseIncludePush(filename);
}



/*
 *  *****  Probes  *****************************************************
 */


static void
set_listen_data(
    void)
{
    char buf[1024];
    int rv;
    sk_sockaddr_array_t *sa = NULL;

    if (listen_port == NULL) {
        if (listen_as_address == NULL) {
            sa = NULL;
        } else {
            rv = skStringParseHostPortPair(&sa, listen_as_address,
                                           HOST_REQUIRED | PORT_PROHIBITED);
            if (rv != 0) {
                skpcParseErr("Invalid listen-as-host '%s': %s",
                             listen_as_address, skStringParseStrerror(rv));
                ++defn_errors;
                return;
            }
        }
    } else {
        if (listen_as_address == NULL) {
            rv = skStringParseHostPortPair(&sa, listen_port,
                                           PORT_REQUIRED | HOST_PROHIBITED);
            if (rv != 0) {
                skpcParseErr("Invalid listen-on-port '%s': %s",
                             listen_port, skStringParseStrerror(rv));
                ++defn_errors;
                return;
            }
        } else {
            rv = snprintf(buf, sizeof(buf), "[%s]:%s",
                          listen_as_address, listen_port);
            if ((size_t)rv >= sizeof(buf)) {
                skpcParseErr("Length of listen-as-host or listen-on-port "
                             "is too large");
                ++defn_errors;
                return;
            }
            rv = skStringParseHostPortPair(&sa, buf, PORT_REQUIRED);
            if (rv != 0) {
                skpcParseErr(("Invalid listen-as-host or listen-on-port"
                              " '%s': %s"),
                             buf, skStringParseStrerror(rv));
                ++defn_errors;
                return;
            }
        }
    }
    rv = skpcProbeSetListenOnSockaddr(probe, sa);
    if (rv != 0) {
        skpcParseErr("Error setting listen address or port");
        ++defn_errors;
    }
}


/* complete the current probe */
static void
probe_end(
    void)
{
    if (!probe) {
        skpcParseErr("No active probe in %s statement", pcscan_clause);
        goto END;
    }

    if (defn_errors) {
        goto END;
    }

    if (skpcProbeVerify(probe, 0)) {
        skpcParseErr("Unable to verify probe '%s'",
                     skpcProbeGetName(probe));
        ++defn_errors;
        goto END;
    }

    /* Probe is valid and now owned by probeconf.  Set to NULL so it
     * doesn't get free()'ed. */
    probe = NULL;

  END:
    if (defn_errors) {
        skAppPrintErr("Encountered %d error%s while processing probe '%s'",
                      defn_errors, ((defn_errors == 1) ? "" : "s"),
                      (probe ? skpcProbeGetName(probe) : ""));
        pcscan_errors += defn_errors;
        defn_errors = 0;
    }
    if (probe) {
        skpcProbeDestroy(&probe);
        probe = NULL;
    }
    if (listen_as_address) {
        free(listen_as_address);
        listen_as_address = NULL;
    }
    if (listen_port) {
        free(listen_port);
        listen_port = NULL;
    }
}


/* Begin a new probe by setting the memory of the global probe_attr_t
 * into its initial state. */
static void
probe_begin(
    char               *probe_name,
    char               *probe_type)
{
    const char *dummy_name = "<NONAME>";
    skpc_probetype_t t;

    if (probe) {
        skpcParseErr("Found active probe in %s statement", pcscan_clause);
        skpcProbeDestroy(&probe);
        probe = NULL;
    }
    defn_errors = 0;

    /* probe_name will only be NULL on bad input from user */
    if (NULL == probe_name) {
        skpcParseErr("%s requires a name and a type", pcscan_clause);
        ++defn_errors;
        t = PROBE_ENUM_NETFLOW_V5;
    } else {
        if (skpcProbeLookupByName(probe_name)) {
            skpcParseErr("A probe named '%s' already exists", probe_name);
            ++defn_errors;
        }

        t = skpcProbetypeNameToEnum(probe_type);
        if (t == PROBE_ENUM_INVALID) {
            skpcParseErr("Do not recognize probe type '%s'", probe_type);
            ++defn_errors;
            t = PROBE_ENUM_NETFLOW_V5;
        }
    }

    if (skpcProbeCreate(&probe, t)) {
        skpcParseErr("Fatal: Unable to create probe");
        exit(EXIT_FAILURE);
    }

    /* probe_name will only be NULL on bad input from user */
    if (probe_name == NULL) {
        if (probe_type == NULL) {
            skpcProbeSetName(probe, dummy_name);
        } else if (skpcProbeSetName(probe, probe_type)) {
            skpcParseErr("Error setting probe name to %s", probe_type);
            ++defn_errors;
        }
        goto END;
    }

    if (skpcProbeSetName(probe, probe_name)) {
        skpcParseErr("Error setting probe name to %s", probe_name);
        ++defn_errors;
    }
    free(probe_name);

    if (listen_as_address != NULL) {
        free(listen_as_address);
        listen_as_address = NULL;
    }
    if (listen_port) {
        free(listen_port);
        listen_port = NULL;
    }

  END:
    free(probe_type);
}


/*
 *  probe_priority(s);
 *
 *    Set the priority of the global probe to s.
 */
static void
probe_priority(
    sk_vector_t        *v)
{
    uint32_t n;
    char *s;

    if (vectorSingleString(v, &s)) {
        return;
    }

    n = parse_int_u16(s);
    if (n == UINT16_NO_VALUE) {
        ++defn_errors;
        return;
    }

    /* Priority is no longer used; just ignore it */
}


/*
 *  probe_protocol(s);
 *
 *    Set the probe-type of the global probe to 's'.
 */
static void
probe_protocol(
    sk_vector_t        *v)
{
    skpc_proto_t proto;
    char *s;

    if (vectorSingleString(v, &s)) {
        return;
    }

    proto = skpcProtocolNameToEnum(s);
    if (proto == SKPC_PROTO_UNSET) {
        skpcParseErr("Do not recognize protocol '%s'", s);
        ++defn_errors;
    } else if (skpcProbeSetProtocol(probe, proto)) {
        skpcParseErr("Error setting %s value for probe '%s' to '%s'",
                     pcscan_clause, skpcProbeGetName(probe), s);
        ++defn_errors;
    }

    free(s);
}


/*
 *  probe_listen_as_host(s);
 *
 *    Set the global probe to listen for flows as the host IP 's'.
 */
static void
probe_listen_as_host(
    sk_vector_t        *v)
{
    char *s;

    if (vectorSingleString(v, &s)) {
        return;
    }
    if (listen_as_address != NULL) {
        free(listen_as_address);
    }
    listen_as_address = s;

    set_listen_data();
}


/*
 *  probe_listen_on_port(s);
 *
 *    Set the global probe to listen for flows on port 's'.
 */
static void
probe_listen_on_port(
    sk_vector_t        *v)
{
    char *s;

    if (vectorSingleString(v, &s)) {
        return;
    }
    if (listen_port != NULL) {
        free(listen_port);
    }
    listen_port = s;

    set_listen_data();
}


/*
 *  probe_listen_on_usocket(s);
 *
 *    Set the global probe to listen for flows on the unix domain socket 's'.
 */
static void
probe_listen_on_usocket(
    sk_vector_t        *v)
{
    char *s;

    if (vectorSingleString(v, &s)) {
        return;
    }
    if (skpcProbeSetListenOnUnixDomainSocket(probe, s)) {
        skpcParseErr("Error setting %s value for probe '%s'",
                     pcscan_clause, skpcProbeGetName(probe));
        ++defn_errors;
    }
    free(s);
}


/*
 *  probe_read_from_file(s);
 *
 *    Set the global probe to read flows from the file 's'.
 */
static void
probe_read_from_file(
    sk_vector_t        *v)
{
    char *s;

    if (vectorSingleString(v, &s)) {
        return;
    }
    if (skpcProbeSetFileSource(probe, s)) {
        skpcParseErr("Error setting %s value for probe '%s'",
                     pcscan_clause, skpcProbeGetName(probe));
        ++defn_errors;
    }
    free(s);
}


/*
 *  probe_poll_directory(s);
 *
 *    Set the global probe to read flows from files that appear in the
 *    directory 's'.
 */
static void
probe_poll_directory(
    sk_vector_t        *v)
{
    char *s;

    if (vectorSingleString(v, &s)) {
        return;
    }
    if (skpcProbeSetPollDirectory(probe, s)) {
        skpcParseErr("Error setting %s value for probe '%s'",
                     pcscan_clause, skpcProbeGetName(probe));
        ++defn_errors;
    }
    free(s);
}


/*
 *  probe_accept_from_host(list);
 *
 *    Set the global probe to accept data from the hosts in 'list'.
 */
static void
probe_accept_from_host(
    sk_vector_t        *v)
{
    sk_vector_t *addr_vec;
    sk_sockaddr_array_t *sa;
    size_t count = skVectorGetCount(v);
    size_t i;
    int rv = -1;
    char *s;

    /* get a vector to use for the sockaddr_array objects */
    addr_vec = vectorPoolGet(ptr_pool);
    if (addr_vec == NULL) {
        skpcParseErr("Allocation error near %s", pcscan_clause);
        ++defn_errors;
        goto END;
    }

    /* parse each address */
    for (i = 0; i < count; ++i) {
        skVectorGetValue(&s, v, i);
        rv = skStringParseHostPortPair(&sa, s, HOST_REQUIRED | PORT_PROHIBITED);
        if (rv != 0) {
            skpcParseErr("Unable to resolve %s value '%s': %s",
                         pcscan_clause, s, skStringParseStrerror(rv));
            ++defn_errors;
            goto END;
        }
        if (skVectorAppendValue(addr_vec, &sa)) {
            skpcParseErr("Allocation error near %s", pcscan_clause);
            ++defn_errors;
            goto END;
        }
    }

    rv = skpcProbeSetAcceptFromHost(probe, addr_vec);
    if (rv != 0) {
        skpcParseErr("Error setting %s value for probe '%s'",
                     pcscan_clause, skpcProbeGetName(probe));
        ++defn_errors;
        goto END;
    }

  END:
    for (i = 0; i < count; ++i) {
        skVectorGetValue(&s, v, i);
        free(s);
    }
    if (addr_vec) {
        /* free the sockaddr-array elements on error */
        if (rv != 0) {
            count = skVectorGetCount(addr_vec);
            for (i = 0; i < count; ++i) {
                skVectorGetValue(&sa, addr_vec, i);
                skSockaddrArrayDestroy(sa);
            }
        }
        vectorPoolPut(ptr_pool, addr_vec);
    }
    vectorPoolPut(ptr_pool, v);
}


/*
 *  probe_log_flags(list);
 *
 *    Set the log flags on the probe to 'n';
 */
static void
probe_log_flags(
    sk_vector_t        *v)
{
    const char none[] = "none";
    size_t count = skVectorGetCount(v);
    size_t i;
    char **s;
    int rv;
    int none_seen = 0;

    /* clear any existing log flags */
    skpcProbeClearLogFlags(probe);

    /* loop over the list of log-flags and add each to the probe */
    for (i = 0; i < count; ++i) {
        s = (char**)skVectorGetValuePointer(v, i);
        rv = skpcProbeAddLogFlag(probe, *s);
        switch (rv) {
          case -1:
            skpcParseErr("Do not recognize %s value '%s' on probe '%s'",
                         pcscan_clause, *s, skpcProbeGetName(probe));
            ++defn_errors;
            break;
          case 0:
            if (0 == strcmp(*s, none)) {
                none_seen = 1;
                break;
            }
            if (0 == none_seen) {
                break;
            }
            /* FALLTHROUGH */
          case -2:
            skpcParseErr("Cannot mix %s '%s' with other values on probe '%s'",
                         pcscan_clause, none, skpcProbeGetName(probe));
            ++defn_errors;
            break;
          default:
            skAbortBadCase(rv);
        }
        free(*s);
    }
    vectorPoolPut(ptr_pool, v);
}


/*
 *  probe_interface_values(s);
 *
 *    Set the global probe to store either snmp or vlan values in the
 *    'input' and 'output' interface fields on SiLK Flow records.
 */
static void
probe_interface_values(
    sk_vector_t        *v)
{
    skpc_ifvaluetype_t ifvalue = SKPC_IFVALUE_SNMP;
    char *s;

    if (vectorSingleString(v, &s)) {
        return;
    }

    if (0 == strcmp(s, "snmp")) {
        ifvalue = SKPC_IFVALUE_SNMP;
    } else if (0 == strcmp(s, "vlan")) {
        ifvalue = SKPC_IFVALUE_VLAN;
    } else {
        skpcParseErr("Invalid %s value '%s'",
                     pcscan_clause, s);
        ++defn_errors;
        goto END;
    }

    if (skpcProbeSetInterfaceValueType(probe, ifvalue)) {
        skpcParseErr("Unable to set %s value '%s'",
                     pcscan_clause, s);
        ++defn_errors;
        goto END;
    }

  END:
    free(s);
}


/*
 *  probe_quirks(list);
 *
 *    Set the "quirks" field on the global probe to the values in list.
 */
static void
probe_quirks(
    sk_vector_t        *v)
{
    size_t count = skVectorGetCount(v);
    size_t i;
    char **s;
    int rv;
    int none_seen = 0;

    /* clear any existing quirks */
    skpcProbeClearQuirks(probe);

    /* loop over the list of quirks and add to the probe */
    for (i = 0; i < count; ++i) {
        s = (char**)skVectorGetValuePointer(v, i);
        if (0 == strcmp(*s, "none")) {
            none_seen = 1;
        } else {
            rv = skpcProbeAddQuirk(probe, *s);
            switch (rv) {
              case -1:
                skpcParseErr("Invalid %s value '%s'",
                             pcscan_clause, *s);
                ++defn_errors;
                break;
              case 0:
                if (0 == none_seen) {
                    break;
                }
                /* FALLTHROUGH */
              case -2:
                skpcParseErr("Invalid %s combination",
                             pcscan_clause);
                ++defn_errors;
                break;
              default:
                skAbortBadCase(rv);
            }
        }
        free(*s);
    }
    vectorPoolPut(ptr_pool, v);
}


/*
 *  *****  Sensors  ****************************************************
 */


static void
sensor_end(
    void)
{
    if (!sensor) {
        skpcParseErr("No active sensor in %s statement", pcscan_clause);
        goto END;
    }

    if (defn_errors) {
        goto END;
    }

    if (skpcSensorVerify(sensor, extra_sensor_verify_fn)) {
        skpcParseErr("Unable to verify sensor '%s'",
                     skpcSensorGetName(sensor));
        ++defn_errors;
        goto END;
    }

    /* Sensor is valid and now owned by probeconf.  Set to NULL so it
     * doesn't get free()'ed. */
    sensor = NULL;

  END:
    if (defn_errors) {
        skAppPrintErr("Encountered %d error%s while processing sensor '%s'",
                      defn_errors, ((defn_errors == 1) ? "" : "s"),
                      (sensor ? skpcSensorGetName(sensor) : ""));
        pcscan_errors += defn_errors;
        defn_errors = 0;
    }
    if (sensor) {
        skpcSensorDestroy(&sensor);
        sensor = NULL;
    }
}


/* Begin a new sensor by setting the memory of the global probe_attr_t
 * into its initial state. */
static void
sensor_begin(
    char               *sensor_name)
{
    const char *dummy_name = "<ERROR>";

    if (sensor) {
        skpcParseErr("Found active sensor in %s statement", pcscan_clause);
        skpcSensorDestroy(&sensor);
        sensor = NULL;
    }
    defn_errors = 0;

    if (skpcSensorCreate(&sensor)) {
        skpcParseErr("Fatal: Unable to create sensor");
        exit(EXIT_FAILURE);
    }

    /* sensor_name will only be NULL on bad input from user */
    if (sensor_name == NULL) {
        skpcParseErr("%s requires a sensor name", pcscan_clause);
        ++defn_errors;
        skpcSensorSetName(sensor, dummy_name);
    } else {
#if 0
        if (skpcSensorLookupByName(sensor_name)) {
            skpcParseErr("A sensor named '%s' already exists", sensor_name);
            ++defn_errors;
        }
#endif

        if (skpcSensorSetName(sensor, sensor_name)) {
            skpcParseErr("Error setting sensor name to %s", sensor_name);
            ++defn_errors;
        }

        if (SK_INVALID_SENSOR == skpcSensorGetID(sensor)) {
            skpcParseErr("There is no known sensor named %s", sensor_name);
            ++defn_errors;
        }

        free(sensor_name);
    }
}


/*
 *  sensor_isp_ip(list);
 *
 *    Set the isp-ip's on the global sensor to 'list'.
 */
static void
sensor_isp_ip(
    sk_vector_t        *v)
{
    sk_vector_t *nl;
    size_t count = skVectorGetCount(v);
    size_t i;
    uint32_t ip;
    char **s;

    /* error on overwrite */
    if (skpcSensorGetIspIps(sensor, NULL) != 0) {
        skpcParseErr("Attempt to overwrite previous %s value for sensor '%s'",
                     pcscan_clause, skpcSensorGetName(sensor));
        ++defn_errors;
        vectorPoolPut(ptr_pool, v);
        return;
    }

    nl = vectorPoolGet(u32_pool);
    if (nl == NULL) {
        skpcParseErr("Allocation error near %s", pcscan_clause);
        ++defn_errors;
        return;
    }

    /* convert string list to a list of numerical IPs */
    for (i = 0; i < count; ++i) {
        s = (char**)skVectorGetValuePointer(v, i);
        if (parse_ip_addr(*s, &ip)) {
            ++defn_errors;
        }
        skVectorAppendValue(nl, &ip);
    }
    vectorPoolPut(ptr_pool, v);

    skpcSensorSetIspIps(sensor, nl);
    vectorPoolPut(u32_pool, nl);
}


/*
 *  sensor_interface(name, list);
 *
 *    Set the interface list for the network whose name is 'name' on
 *    the global sensor to 'list'.
 *
 *    If 'list' is NULL, set the interface list to all the indexes NOT
 *    listed on other interfaces---set it to the 'remainder' of the
 *    interfaces.
 */
static void
sensor_interface(
    char               *name,
    sk_vector_t        *v)
{
    const skpc_network_t *network = NULL;
    const size_t count = (v ? skVectorGetCount(v) : 0);
    skpc_group_t *g;
    char **s;
    size_t i;

    if (name == NULL) {
        skpcParseErr("Interface list '%s' gives a NULL name", pcscan_clause);
        skAbort();
    }

    /* convert the name to a network */
    network = skpcNetworkLookupByName(name);
    if (network == NULL) {
        skpcParseErr(("Cannot set %s for sensor '%s' because\n"
                      "\tthe '%s' network is not defined"),
                     pcscan_clause, skpcSensorGetName(sensor), name);
        ++defn_errors;
        goto END;
    }

    /* NULL vector indicates want to set network to 'remainder' */
    if (v == NULL) {
        if (skpcSensorSetNetworkRemainder(
                sensor, network->id, SKPC_GROUP_INTERFACE))
        {
            ++defn_errors;
        }
    } else {
        /* determine if we are using a single existing group */
        if (1 == count) {
            s = (char**)skVectorGetValuePointer(v, 0);
            if ('@' == **s) {
                g = get_group((*s) + 1, SKPC_GROUP_INTERFACE);
                if (NULL == g) {
                    goto END;
                }
                if (skpcSensorSetNetworkGroup(sensor, network->id, g)) {
                    ++defn_errors;
                }
                goto END;
            }
        }

        /* not a single group, so need to create a new group */
        if (skpcGroupCreate(&g)) {
            skpcParseErr("Allocation error near %s", pcscan_clause);
            ++defn_errors;
            goto END;
        }
        skpcGroupSetType(g, SKPC_GROUP_INTERFACE);

        /* parse the strings and add them to the group */
        if (add_values_to_group(g, v, SKPC_GROUP_INTERFACE)) {
            v = NULL;
            goto END;
        }
        v = NULL;

        /* add the group to the sensor */
        if (skpcGroupFreeze(g)) {
            ++defn_errors;
            goto END;
        }
        if (skpcSensorSetNetworkGroup(sensor, network->id, g)) {
            ++defn_errors;
        }
    }

  END:
    if (name) {
        free(name);
    }
    if (v) {
        for (i = 0; i < count; ++i) {
            s = (char**)skVectorGetValuePointer(v, i);
            free(*s);
        }
        vectorPoolPut(ptr_pool, v);
    }
}


/*
 *  sensor_ipblock(name, ip_list);
 *
 *    When 'ip_list' is NULL, set a flag for the network 'name' noting
 *    that its ipblock list should be set to any IP addresses not
 *    covered by other IP blocks; ie., the remaining ipblocks.
 *
 *    Otherwise, set the ipblocks for the 'name'
 *    network of the global sensor to the inverse of 'ip_list'.
 */
static void
sensor_ipblock(
    char               *name,
    sk_vector_t        *v)
{
    const size_t count = (v ? skVectorGetCount(v) : 0);
    const skpc_network_t *network = NULL;
    skpc_group_t *g;
    size_t i;
    char **s;

    if (name == NULL) {
        skpcParseErr("IP Block list '%s' gives a NULL name", pcscan_clause);
        skAbort();
    }

    /* convert the name to a network */
    network = skpcNetworkLookupByName(name);
    if (network == NULL) {
        skpcParseErr(("Cannot set %s for sensor '%s' because\n"
                      "\tthe '%s' network is not defined"),
                     pcscan_clause, skpcSensorGetName(sensor), name);
        ++defn_errors;
        goto END;
    }

    /* NULL vector indicates want to set network to 'remainder' */
    if (v == NULL) {
        if (skpcSensorSetNetworkRemainder(
                sensor, network->id, SKPC_GROUP_IPBLOCK))
        {
            ++defn_errors;
        }
    } else {
        /* determine if we are using a single existing group */
        if (1 == count) {
            s = (char**)skVectorGetValuePointer(v, 0);
            if ('@' == **s) {
                g = get_group((*s)+1, SKPC_GROUP_IPBLOCK);
                if (NULL == g) {
                    goto END;
                }
                if (skpcSensorSetNetworkGroup(sensor, network->id, g)) {
                    ++defn_errors;
                }
                goto END;
            }
        }

        /* not a single group, so need to create a new group */
        if (skpcGroupCreate(&g)) {
            skpcParseErr("Allocation error near %s", pcscan_clause);
            ++defn_errors;
            goto END;
        }
        skpcGroupSetType(g, SKPC_GROUP_IPBLOCK);

        /* parse the strings and add them to the group */
        if (add_values_to_group(g, v, SKPC_GROUP_IPBLOCK)) {
            v = NULL;
            goto END;
        }
        v = NULL;

        /* add the group to the sensor */
        if (skpcGroupFreeze(g)) {
            ++defn_errors;
            goto END;
        }
        if (skpcSensorSetNetworkGroup(sensor, network->id, g)) {
            ++defn_errors;
            goto END;
        }
    }

  END:
    if (name) {
        free(name);
    }
    if (v) {
        for (i = 0; i < count; ++i) {
            s = (char**)skVectorGetValuePointer(v, i);
            free(*s);
        }
        vectorPoolPut(ptr_pool, v);
    }
}


/*
 *  sensor_ipset(name, ip_list);
 *
 *    When 'ip_list' is NULL, set a flag for the network 'name' noting
 *    that its ipset list should be set to any IP addresses not
 *    covered by other IP sets; ie., the remaining ipsets.
 *
 *    Otherwise, set the ipsets for the 'name' network of the global
 *    sensor to the inverse of 'ip_list'.
 */
static void
sensor_ipset(
    char               *name,
    sk_vector_t        *v)
{
    const size_t count = (v ? skVectorGetCount(v) : 0);
    const skpc_network_t *network = NULL;
    skpc_group_t *g;
    size_t i;
    char **s;

    if (name == NULL) {
        skpcParseErr("IP Set list '%s' gives a NULL name", pcscan_clause);
        skAbort();
    }

    /* convert the name to a network */
    network = skpcNetworkLookupByName(name);
    if (network == NULL) {
        skpcParseErr(("Cannot set %s for sensor '%s' because\n"
                      "\tthe '%s' network is not defined"),
                     pcscan_clause, skpcSensorGetName(sensor), name);
        ++defn_errors;
        goto END;
    }

    /* NULL vector indicates want to set network to 'remainder' */
    if (v == NULL) {
        if (skpcSensorSetNetworkRemainder(
                sensor, network->id, SKPC_GROUP_IPSET))
        {
            ++defn_errors;
        }
    } else {
        /* determine if we are using a single existing group */
        if (1 == count) {
            s = (char**)skVectorGetValuePointer(v, 0);
            if ('@' == **s) {
                g = get_group((*s)+1, SKPC_GROUP_IPSET);
                if (NULL == g) {
                    goto END;
                }
                if (skpcSensorSetNetworkGroup(sensor, network->id, g)) {
                    ++defn_errors;
                }
                goto END;
            }
        }

        /* not a single group, so need to create a new group */
        if (skpcGroupCreate(&g)) {
            skpcParseErr("Allocation error near %s", pcscan_clause);
            ++defn_errors;
            goto END;
        }
        skpcGroupSetType(g, SKPC_GROUP_IPSET);

        /* parse the strings and add them to the group */
        if (add_values_to_group(g, v, SKPC_GROUP_IPSET)) {
            v = NULL;
            goto END;
        }
        v = NULL;

        /* add the group to the sensor */
        if (skpcGroupFreeze(g)) {
            ++defn_errors;
            goto END;
        }
        if (skpcSensorSetNetworkGroup(sensor, network->id, g)) {
            ++defn_errors;
            goto END;
        }
    }

  END:
    if (name) {
        free(name);
    }
    if (v) {
        for (i = 0; i < count; ++i) {
            s = (char**)skVectorGetValuePointer(v, i);
            free(*s);
        }
        vectorPoolPut(ptr_pool, v);
    }
}


static void
sensor_filter(
    skpc_filter_t       filter,
    sk_vector_t        *v,
    int                 is_files)
{
    const size_t count = (v ? skVectorGetCount(v) : 0);
    skpc_group_t *g;
    size_t i;
    char **s;

    if (count < 1) {
        skpcParseErr("Missing arguments for %s on sensor '%s'",
                     pcscan_clause, skpcSensorGetName(sensor));
        ++defn_errors;
        goto END;
    }

    if (is_files && SKPC_GROUP_IPSET != filter.f_group_type) {
        skpcParseErr(("Error in %s on sensor '%s':"
                      " Only IPset filenames may be quoted"),
                     pcscan_clause, skpcSensorGetName(sensor));
        ++defn_errors;
        goto END;
    }

    /* determine if we are using a single existing group */
    if (1 == count) {
        s = (char**)skVectorGetValuePointer(v, 0);
        if ('@' == **s) {
            g = get_group((*s) + 1, filter.f_group_type);
            if (NULL == g) {
                goto END;
            }
            if (skpcSensorAddFilter(sensor, g, filter.f_type,
                                    filter.f_discwhen, filter.f_group_type))
            {
                ++defn_errors;
            }
            goto END;
        }
    }

    /* not a single group, so need to create a new group */
    if (skpcGroupCreate(&g)) {
        skpcParseErr("Allocation error near %s", pcscan_clause);
        ++defn_errors;
        goto END;
    }
    skpcGroupSetType(g, filter.f_group_type);

    /* parse the strings in 'v' and add them to the group */
    if (add_values_to_group(g, v, filter.f_group_type)) {
        v = NULL;
        goto END;
    }
    v = NULL;

    /* add the group to the filter */
    if (skpcGroupFreeze(g)) {
        ++defn_errors;
        goto END;
    }
    if (skpcSensorAddFilter(sensor, g, filter.f_type, filter.f_discwhen,
                            filter.f_group_type))
    {
        ++defn_errors;
    }

  END:
    if (v) {
        for (i = 0; i < count; ++i) {
            s = (char**)skVectorGetValuePointer(v, i);
            free(*s);
        }
        vectorPoolPut(ptr_pool, v);
    }
}


static void
sensor_network(
    skpc_direction_t    direction,
    char               *name)
{
    const skpc_network_t *network = NULL;

    if (name == NULL) {
        skpcParseErr("Missing network name in %s on sensor '%s'",
                     pcscan_clause, skpcSensorGetName(sensor));
        ++defn_errors;
        goto END;
    }

    /* convert the name to a network */
    network = skpcNetworkLookupByName(name);
    if (network == NULL) {
        skpcParseErr(("Cannot set %s for sensor '%s' because\n"
                      "\tthe '%s' network is not defined"),
                     pcscan_clause, skpcSensorGetName(sensor), name);
        ++defn_errors;
        goto END;
    }

    if (skpcSensorSetNetworkDirection(sensor, network->id, direction)) {
        skpcParseErr("Cannot set %s for sensor '%s' to %s",
                     pcscan_clause, skpcSensorGetName(sensor), name);
        ++defn_errors;
        goto END;
    }

  END:
    if (name) {
        free(name);
    }
}


static void
sensor_probes(
    char               *probe_type,
    sk_vector_t        *v)
{
    sk_vector_t *pl;
    size_t i = 0;
    char **s;
    const skpc_probe_t *p;
    skpc_probetype_t t;

    /* get a vector to use for the probe objects */
    pl = vectorPoolGet(ptr_pool);

    /* get the probe-type */
    t = skpcProbetypeNameToEnum(probe_type);
    if (t == PROBE_ENUM_INVALID) {
        skpcParseErr("Do not recognize probe type '%s'", probe_type);
        ++defn_errors;
        goto END;
    }

    while (NULL != (s = (char**)skVectorGetValuePointer(v, i))) {
        ++i;
        p = skpcProbeLookupByName(*s);
        if (p) {
            if (skpcProbeGetType(p) != t) {
                skpcParseErr("Attempt to use %s probe '%s' in a %s statement",
                             skpcProbetypeEnumtoName(skpcProbeGetType(p)),
                             *s, pcscan_clause);
                ++defn_errors;
            }
        } else {
            /* Create a new probe with the specified name and type */
            skpc_probe_t *new_probe;
            if (skpcProbeCreate(&new_probe, t)) {
                skpcParseErr("Fatal: Unable to create ephemeral probe");
                exit(EXIT_FAILURE);
            }
            if (skpcProbeSetName(new_probe, *s)) {
                skpcParseErr("Error setting ephemeral probe name to %s", *s);
                ++defn_errors;
                goto END;
            }
            if (skpcProbeVerify(new_probe, 1)) {
                skpcParseErr("Error verifying ephemeral probe '%s'",
                             *s);
                ++defn_errors;
                goto END;
            }
            p = skpcProbeLookupByName(*s);
            if (p == NULL) {
                skpcParseErr("Cannot find newly created ephemeral probe '%s'",
                             *s);
                skAbort();
            }
        }
        skVectorAppendValue(pl, &p);
        free(*s);
    }

    if (skpcSensorSetProbes(sensor, pl)) {
        ++defn_errors;
    }

  END:
    free(probe_type);
    while (NULL != (s = (char**)skVectorGetValuePointer(v, i))) {
        ++i;
        free(*s);
    }
    vectorPoolPut(ptr_pool, v);
    vectorPoolPut(ptr_pool, pl);
}


/*
 *  *****  Groups  ****************************************************
 */


static void
group_end(
    void)
{
    if (!group) {
        skpcParseErr("No active group in %s statement", pcscan_clause);
        goto END;
    }

    if (defn_errors) {
        goto END;
    }

    if (skpcGroupFreeze(group)) {
        skpcParseErr("Unable to freeze group '%s'",
                     skpcGroupGetName(group));
        ++defn_errors;
        goto END;
    }

    /* Group is valid and now owned by probeconf.  Set to NULL so it
     * doesn't get free()'ed. */
    group = NULL;

  END:
    if (defn_errors) {
        skAppPrintErr("Encountered %d error%s while processing group '%s'",
                      defn_errors, ((defn_errors == 1) ? "" : "s"),
                      (group ? skpcGroupGetName(group) : ""));
        pcscan_errors += defn_errors;
        defn_errors = 0;
    }
    if (group) {
        skpcGroupDestroy(&group);
        group = NULL;
    }
}


/* Begin a new group by setting the memory of the global probe_attr_t
 * into its initial state. */
static void
group_begin(
    char               *group_name)
{
    const char *dummy_name = "<ERROR>";

    if (group) {
        skpcParseErr("Found active group in %s statement", pcscan_clause);
        skpcGroupDestroy(&group);
        group = NULL;
    }
    defn_errors = 0;

    if (skpcGroupCreate(&group)) {
        skpcParseErr("Fatal: Unable to create group");
        exit(EXIT_FAILURE);
    }

    /* group_name will only be NULL on bad input from user */
    if (group_name == NULL) {
        skpcParseErr("%s requires a group name", pcscan_clause);
        ++defn_errors;
        skpcGroupSetName(group, dummy_name);
    } else {
        if (skpcGroupLookupByName(group_name)) {
            skpcParseErr("A group named '%s' already exists", group_name);
            ++defn_errors;
        }
        if (skpcGroupSetName(group, group_name)) {
            skpcParseErr("Error setting group name to %s", group_name);
            ++defn_errors;
        }
        free(group_name);
    }
}


/*
 *  group_add_data(v, g_type);
 *
 *   Verify that the global group has a type of 'g_type'.  If so,
 *   parse the string values in 'v' and add the values to the global
 *   group.
 *
 *   If the global group's type is not set, the value to 'g_type' and
 *   append the values.
 *
 *   Used by 'stmt_group_interfaces', 'stmt_group_ipblocks', and
 *   'stmt_group_ipsets'
 */
static void
group_add_data(
    sk_vector_t        *v,
    skpc_group_type_t   g_type)
{
    const char *g_type_str = "unknown data";
    size_t i = 0;
    char **s;

    switch (skpcGroupGetType(group)) {
      case SKPC_GROUP_UNSET:
        skpcGroupSetType(group, g_type);
        break;
      case SKPC_GROUP_INTERFACE:
        g_type_str = "interface values";
        break;
      case SKPC_GROUP_IPBLOCK:
        g_type_str = "ipblocks";
        break;
      case SKPC_GROUP_IPSET:
        g_type_str = "ipsets";
        break;
    }

    if (g_type != skpcGroupGetType(group)) {
        skpcParseErr(("Cannot add %s to group because\n"
                      "\tthe group already contains %s"),
                     pcscan_clause, g_type_str);
        ++defn_errors;
        goto END;
    }

    add_values_to_group(group, v, g_type);
    v = NULL;

  END:
    if (v) {
        i = skVectorGetCount(v);
        while (i > 0) {
            --i;
            s = (char**)skVectorGetValuePointer(v, i);
            free(*s);
        }
        vectorPoolPut(ptr_pool, v);
    }
}


static int
add_values_to_group(
    skpc_group_t       *g,
    sk_vector_t        *v,
    skpc_group_type_t   g_type)
{
    const size_t count = (v ? skVectorGetCount(v) : 0);
    skpc_group_t *named_group;
    vector_pool_t *pool;
    sk_vector_t *vec = NULL;
    char **s;
    size_t i = 0;
    uint32_t n;
    skIPWildcard_t *ipwild;
    skipset_t *ipset;
    int rv = -1;

    /* determine the vector pool to use for the parsed values */
    if (SKPC_GROUP_INTERFACE == g_type) {
        /* parse numbers and/or groups */
        pool = u32_pool;
    } else if (SKPC_GROUP_IPBLOCK == g_type) {
        /* parse ipblocks and/or groups */
        pool = ptr_pool;
    } else if (SKPC_GROUP_IPSET == g_type) {
        /* parse ipsets and/or groups */
        pool = ptr_pool;
    } else {
        skAbortBadCase(g_type);
    }

    /* get a vector from the pool */
    vec = vectorPoolGet(pool);
    if (vec == NULL) {
        skpcParseErr("Allocation error near %s", pcscan_clause);
        ++defn_errors;
        goto END;
    }

    /* process the strings in the vector 'v' */
    for (i = 0; i < count; ++i) {
        s = (char**)skVectorGetValuePointer(v, i);

        /* is this a group? */
        if ('@' == **s) {
            named_group = get_group((*s)+1, g_type);
            free(*s);
            if (NULL == named_group) {
                ++i;
                goto END;
            }
            if (skpcGroupAddGroup(g, named_group)) {
                ++defn_errors;
                ++i;
                goto END;
            }
        } else if (g_type == SKPC_GROUP_IPBLOCK) {
            assert(pool == ptr_pool);
            ipwild = parse_wildcard_addr(*s);
            if (ipwild == NULL) {
                ++defn_errors;
                ++i;
                goto END;
            }
            skVectorAppendValue(vec, &ipwild);
        } else if (g_type == SKPC_GROUP_IPSET) {
            assert(pool == ptr_pool);
            ipset = parse_ipset_filename(*s);
            if (ipset == NULL) {
                ++defn_errors;
                ++i;
                goto END;
            }
            skVectorAppendValue(vec, &ipset);
        } else if (SKPC_GROUP_INTERFACE == g_type) {
            assert(g_type == SKPC_GROUP_INTERFACE);
            assert(pool == u32_pool);
            n = parse_int_u16(*s);
            if (n == UINT16_NO_VALUE) {
                ++defn_errors;
                ++i;
                goto END;
            }
            skVectorAppendValue(vec, &n);
        }
    }

    /* add values to the group */
    if (skpcGroupAddValues(g, vec)) {
        ++defn_errors;
    }

    rv = 0;

  END:
    for ( ; i < count; ++i) {
        s = (char**)skVectorGetValuePointer(v, i);
        free(*s);
    }
    if (v) {
        vectorPoolPut(ptr_pool, v);
    }
    if (vec) {
        if (g_type == SKPC_GROUP_IPSET) {
            for (i = 0; i < skVectorGetCount(vec); ++i) {
                skVectorGetValue(&ipset, vec, i);
                if (ipset) {
                    skIPSetDestroy(&ipset);
                }
            }
        }
        vectorPoolPut(pool, vec);
    }
    return rv;
}


static skpc_group_t *
get_group(
    const char         *g_name,
    skpc_group_type_t   g_type)
{
    skpc_group_t *g;

    g = skpcGroupLookupByName(g_name);
    if (!g) {
        skpcParseErr("Error in %s: group '%s' is not defined",
                     pcscan_clause, g_name);
        ++defn_errors;
        return NULL;
    }
    if (skpcGroupGetType(g) != g_type) {
        skpcParseErr(("Error in %s: the '%s' group does not contain %ss"),
                     pcscan_clause, g_name, skpcGrouptypeEnumtoName(g_type));
        ++defn_errors;
        return NULL;
    }
    return g;
}


/*
 *  *****  Parsing Utilities  ******************************************
 */


/*
 *  val = parse_int_u16(s);
 *
 *    Parse 's' as a integer from 0 to 0xFFFF inclusive.  Returns the
 *    value on success.  Prints an error and returns UINT16_NO_VALUE
 *    if parsing is unsuccessful or value is out of range.
 */
static uint32_t
parse_int_u16(
    char               *s)
{
    uint32_t num;
    int rv;

    rv = skStringParseUint32(&num, s, 0, 0xFFFF);
    if (rv) {
        skpcParseErr("Invalid %s '%s': %s",
                     pcscan_clause, s, skStringParseStrerror(rv));
        num = UINT16_NO_VALUE;
    }

    free(s);
    return num;
}


/*
 *  ok = vectorSingleString(v, &s);
 *
 *    If the vector 'v' contains a single value, set 's' to point at
 *    that value, put 'v' into the vector pool, and return 0.
 *
 *    Otherwise, print an error message, increment the error count,
 *    destroy all the strings in 'v', put 'v' into the vector pool,
 *    and return -1.
 */
static int
vectorSingleString(
    sk_vector_t        *v,
    char              **s)
{
    int rv = 0;

    if (1 == skVectorGetCount(v)) {
        skVectorGetValue(s, v, 0);
    } else {
        size_t i = 0;
        while (NULL != (s = (char**)skVectorGetValuePointer(v, i))) {
            ++i;
            free(*s);
        }
        skpcParseErr("The %s clause takes a single argument", pcscan_clause);
        ++defn_errors;
        rv = -1;
    }

    vectorPoolPut(ptr_pool, v);
    return rv;
}


/*
 *  ipwild = parse_wildcard_addr(ip);
 *
 *    Parse 'ip' as an IP address block in SiLK wildcard notation.
 *    Because the scanner does not allow comma as part of an ID, we
 *    will never see things like  "10.20.30.40,50".
 *
 *    Return the set of ips as an skIPWildcard_t*, or NULL on error.
 */
static skIPWildcard_t *
parse_wildcard_addr(
    char               *s)
{
    skIPWildcard_t *ipwild;
    int rv;

    ipwild = (skIPWildcard_t*)malloc(sizeof(skIPWildcard_t));
    if (ipwild) {
        rv = skStringParseIPWildcard(ipwild, s);
        if (rv) {
            skpcParseErr("Invalid IP address block '%s': %s",
                         s, skStringParseStrerror(rv));
            free(ipwild);
            ipwild = NULL;
        }
    }

    free(s);
    return ipwild;
}


/*
 *  ok = parse_ip_addr(ip_string, ip_val);
 *
 *    Parse 'ip_string' as an IP address and put result into 'ip_val'.
 *    Return 0 on success, -1 on failure.
 */
static int
parse_ip_addr(
    char               *s,
    uint32_t           *ip)
{
    skipaddr_t addr;
    int rv;

    rv = skStringParseIP(&addr, s);
    if (rv) {
        skpcParseErr("Invalid IP addresses '%s': %s",
                     s, skStringParseStrerror(rv));
        free(s);
        return -1;
    }
#if SK_ENABLE_IPV6
    if (skipaddrIsV6(&addr)) {
        skpcParseErr("Invalid IP address '%s': IPv6 addresses not supported",
                     s);
        free(s);
        return -1;
    }
#endif /* SK_ENABLE_IPV6 */

    free(s);
    *ip = skipaddrGetV4(&addr);
    return 0;
}


/*
 *  ipset = parse_ipset_filename(filename);
 *
 *    Treat 'filename' as the name of an IPset file.  Load the file
 *    and return a pointer to it.  Return NULL on failure.
 */
static skipset_t *
parse_ipset_filename(
    char               *s)
{
    skipset_t *ipset;
    ssize_t rv;

    /* reject standard input */
    if (0 == strcmp(s, "-") || (0 == strcmp(s, "stdin"))) {
        skpcParseErr("May not read an IPset from the standard input");
        ipset = NULL;
        goto END;
    }

    rv = skIPSetLoad(&ipset, s);
    if (rv) {
        skpcParseErr("Unable to read IPset from '%s': %s",
                     s, skIPSetStrerror(rv));
        ipset = NULL;
    }
    if (skIPSetCountIPs(ipset, NULL) == 0) {
        skpcParseErr("May not use the IPset in '%s': IPset is empty", s);
        skIPSetDestroy(&ipset);
        ipset = NULL;
    }

  END:
    free(s);
    return ipset;
}


int
yyerror(
    char               *s)
{
    SK_UNUSED_PARAM(s);
    return 0;
}


int
skpcParseSetup(
    void)
{
    memset(ptr_pool, 0, sizeof(vector_pool_t));
    ptr_pool->element_size = sizeof(char*);

    memset(u32_pool, 0, sizeof(vector_pool_t));
    u32_pool->element_size = sizeof(uint32_t);

    return 0;
}


void
skpcParseTeardown(
    void)
{
    if (probe) {
        ++defn_errors;
        skpcParseErr("Missing \"end probe\" statement");
        skpcProbeDestroy(&probe);
        probe = NULL;
    }
    if (sensor) {
        ++defn_errors;
        skpcParseErr("Missing \"end sensor\" statement");
        skpcSensorDestroy(&sensor);
        sensor = NULL;
    }
    if (group) {
        ++defn_errors;
        skpcParseErr("Missing \"end group\" statement");
        skpcGroupDestroy(&group);
        group = NULL;
    }

    pcscan_errors += defn_errors;
    vectorPoolEmpty(ptr_pool);
    vectorPoolEmpty(u32_pool);
}


/*
** Local variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/

