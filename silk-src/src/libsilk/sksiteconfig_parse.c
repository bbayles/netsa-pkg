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
     TOK_NL = 258,
     TOK_CLASS = 259,
     TOK_DEF_CLASS = 260,
     TOK_DEF_TYPES = 261,
     TOK_END_CLASS = 262,
     TOK_END_GROUP = 263,
     TOK_GROUP = 264,
     TOK_INCLUDE = 265,
     TOK_PATH_FORMAT = 266,
     TOK_PACKING_LOGIC = 267,
     TOK_SENSOR = 268,
     TOK_SENSORS = 269,
     TOK_TYPE = 270,
     TOK_VERSION = 271,
     ERR_UNREC = 272,
     ERR_UNTERM_STRING = 273,
     ERR_STR_TOO_LONG = 274,
     ERR_INVALID_OCTAL_ESCAPE = 275,
     TOK_ATOM = 276,
     TOK_INTEGER = 277,
     TOK_STRING = 278,
     ERR_UNK_CMD = 279
   };
#endif
/* Tokens.  */
#define TOK_NL 258
#define TOK_CLASS 259
#define TOK_DEF_CLASS 260
#define TOK_DEF_TYPES 261
#define TOK_END_CLASS 262
#define TOK_END_GROUP 263
#define TOK_GROUP 264
#define TOK_INCLUDE 265
#define TOK_PATH_FORMAT 266
#define TOK_PACKING_LOGIC 267
#define TOK_SENSOR 268
#define TOK_SENSORS 269
#define TOK_TYPE 270
#define TOK_VERSION 271
#define ERR_UNREC 272
#define ERR_UNTERM_STRING 273
#define ERR_STR_TOO_LONG 274
#define ERR_INVALID_OCTAL_ESCAPE 275
#define TOK_ATOM 276
#define TOK_INTEGER 277
#define TOK_STRING 278
#define ERR_UNK_CMD 279




/* Copy the first part of user declarations.  */
#line 1 "sksiteconfig_parse.y"

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
**  Parser for silk toolset configuration file
**
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: sksiteconfig_parse.y b94afc02f4c5 2023-09-07 14:09:10Z mthomas $");

#include "sksiteconfig.h"
#include <silk/sksite.h>

/* TYPEDEFS AND MACROS */

/* current version of the silk.conf file */
#define SKSITECONFIG_VERSION_CURRENT 2

/* default version to use if there is no 'version' command in the
 * file.  the default value is equivalent to the currect version, but
 * we use a different value to determine whether the 'version' has
 * been set explicitly */
#define SKSITECONFIG_VERSION_DEFAULT 0


/* EXPORTED VARIABLES */

/*
 * set to 1 to use the test handlers, which output what they think
 * they're seeing, for testing purposes.  This will be set to 1 when
 * the SKSITECONFIG_TESTING environment variable is set to a non-empty
 * value (whose first character is not '0')
 */
int sksiteconfig_testing = 0;


/* LOCAL VARIABLES */

/* current group or class being filled in--only one should be non-NULL
 * at a time. */
static char *current_group = NULL;
static sk_sensorgroup_id_t current_group_id = SK_INVALID_SENSORGROUP;
static char *current_class = NULL;
static sk_class_id_t current_class_id = SK_INVALID_CLASS;
static int site_file_version = SKSITECONFIG_VERSION_DEFAULT;


/* LOCAL FUNCTION PROTOTYPES */

/* Handle config file version */
static int do_version(int version);

/* Define sensor */
static void do_sensor(int id, char *name, char *description);

/* Define path-format */
static void do_path_format(char *fmt);

/* Define packing-logic */
static void do_packing_logic(char *fmt);

/* Include a file */
static void do_include(char *filename);

/* Begin defining a group */
static void do_group(char *groupname);

/* Add sensors to a group definition */
static void do_group_sensors(sk_vector_t *sensors);

/* Finish defining a group */
static void do_end_group(void);

/* Begin defining a class */
static void do_class(char *classname);

/* Add sensors to a class definition */
static void do_class_sensors(sk_vector_t *sensors);

/* Define type within a class definition */
static void do_class_type(int id, char *name, char *prefix);

/* Define the default types for a class */
static void do_class_default_types(sk_vector_t *types);

/* Finish defining a class */
static void do_end_class(void);

/* Set the default class */
static void do_default_class(char *classname);

/* Report an error while parsing (printf style) */
#define do_err sksiteconfigErr

/* Report a context error, like trying to define a sensor in a class */
static void do_err_ctx(const char *ctx, const char *cmd);

/* Report an argument error: too many, too few, or the wrong args */
static void do_err_args(const char *cmd);

/* Report an argument error: shouldn't be any arguments */
static void do_err_args_none(const char *cmd);




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
#line 157 "sksiteconfig_parse.y"
{
    int integer;
    char *str;
    sk_vector_t *str_list;
}
/* Line 193 of yacc.c.  */
#line 306 "sksiteconfig_parse.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 319 "sksiteconfig_parse.c"

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
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   207

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  25
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  29
/* YYNRULES -- Number of rules.  */
#define YYNRULES  91
/* YYNRULES -- Number of states.  */
#define YYNSTATES  194

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   279

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
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,    10,    14,    18,    19,    22,
      25,    29,    33,    34,    37,    40,    42,    44,    46,    48,
      50,    52,    54,    56,    58,    60,    62,    64,    66,    68,
      70,    74,    78,    82,    86,    90,    94,    98,   102,   106,
     110,   114,   118,   122,   126,   130,   134,   138,   142,   146,
     150,   154,   158,   162,   166,   170,   174,   178,   182,   186,
     190,   194,   198,   202,   206,   210,   214,   218,   222,   227,
     233,   237,   241,   245,   249,   253,   256,   260,   264,   268,
     272,   276,   281,   287,   291,   294,   298,   300,   302,   304,
     306,   307
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      26,     0,    -1,    -1,    26,     3,    -1,    26,    31,    -1,
      37,    28,    50,    -1,     4,     1,     3,    -1,    -1,    28,
       3,    -1,    28,    32,    -1,    39,    30,    46,    -1,     9,
       1,     3,    -1,    -1,    30,     3,    -1,    30,    33,    -1,
      27,    -1,    38,    -1,    29,    -1,    40,    -1,    41,    -1,
      42,    -1,    43,    -1,    44,    -1,    34,    -1,    47,    -1,
      48,    -1,    49,    -1,    36,    -1,    45,    -1,    35,    -1,
       7,     1,     3,    -1,     8,     1,     3,    -1,    14,     1,
       3,    -1,    15,     1,     3,    -1,    24,     1,     3,    -1,
      17,     1,     3,    -1,     4,     1,     3,    -1,     5,     1,
       3,    -1,     7,     1,     3,    -1,     9,     1,     3,    -1,
      10,     1,     3,    -1,    11,     1,     3,    -1,    12,     1,
       3,    -1,    13,     1,     3,    -1,    15,     1,     3,    -1,
      16,     1,     3,    -1,    24,     1,     3,    -1,    17,     1,
       3,    -1,     4,     1,     3,    -1,     5,     1,     3,    -1,
       8,     1,     3,    -1,     9,     1,     3,    -1,    10,     1,
       3,    -1,    11,     1,     3,    -1,    12,     1,     3,    -1,
      13,     1,     3,    -1,    16,     1,     3,    -1,    24,     1,
       3,    -1,    17,     1,     3,    -1,     4,    52,     3,    -1,
       5,    52,     3,    -1,     9,    52,     3,    -1,    10,    52,
       3,    -1,    10,     1,     3,    -1,    11,    52,     3,    -1,
      11,     1,     3,    -1,    12,    52,     3,    -1,    12,     1,
       3,    -1,    13,    51,    52,     3,    -1,    13,    51,    52,
      23,     3,    -1,    13,     1,     3,    -1,    16,    51,     3,
      -1,    16,     1,     3,    -1,    14,    53,     3,    -1,    14,
       1,     3,    -1,     8,     3,    -1,     8,     1,     3,    -1,
       6,    53,     3,    -1,     6,     1,     3,    -1,    14,    53,
       3,    -1,    14,     1,     3,    -1,    15,    51,    52,     3,
      -1,    15,    51,    52,    52,     3,    -1,    15,     1,     3,
      -1,     7,     3,    -1,     7,     1,     3,    -1,    22,    -1,
      21,    -1,    23,    -1,    22,    -1,    -1,    53,    52,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   183,   183,   185,   186,   190,   191,   194,   196,   197,
     201,   202,   205,   207,   208,   214,   215,   216,   217,   218,
     219,   220,   221,   222,   226,   227,   228,   229,   233,   234,
     240,   241,   242,   243,   244,   246,   250,   251,   252,   253,
     254,   255,   256,   257,   258,   259,   260,   262,   266,   267,
     268,   269,   270,   271,   272,   273,   274,   275,   276,   280,
     286,   290,   296,   297,   301,   302,   306,   307,   311,   312,
     313,   317,   318,   322,   323,   327,   328,   332,   333,   337,
     338,   342,   343,   344,   348,   349,   354,   360,   361,   362,
     366,   367
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "TOK_NL", "TOK_CLASS", "TOK_DEF_CLASS",
  "TOK_DEF_TYPES", "TOK_END_CLASS", "TOK_END_GROUP", "TOK_GROUP",
  "TOK_INCLUDE", "TOK_PATH_FORMAT", "TOK_PACKING_LOGIC", "TOK_SENSOR",
  "TOK_SENSORS", "TOK_TYPE", "TOK_VERSION", "ERR_UNREC",
  "ERR_UNTERM_STRING", "ERR_STR_TOO_LONG", "ERR_INVALID_OCTAL_ESCAPE",
  "TOK_ATOM", "TOK_INTEGER", "TOK_STRING", "ERR_UNK_CMD", "$accept",
  "top_cmd_list", "block_class", "class_cmd_list", "block_group",
  "group_cmd_list", "top_cmd", "class_cmd", "group_cmd", "err_top",
  "err_grp", "err_cls", "cmd_class", "cmd_default_class", "cmd_group",
  "cmd_include", "cmd_path_format", "cmd_packing_logic", "cmd_sensor",
  "cmd_version", "cmd_group_sensors", "cmd_end_group",
  "cmd_class_default_types", "cmd_class_sensors", "cmd_class_type",
  "cmd_end_class", "int", "str", "str_list", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    25,    26,    26,    26,    27,    27,    28,    28,    28,
      29,    29,    30,    30,    30,    31,    31,    31,    31,    31,
      31,    31,    31,    31,    32,    32,    32,    32,    33,    33,
      34,    34,    34,    34,    34,    34,    35,    35,    35,    35,
      35,    35,    35,    35,    35,    35,    35,    35,    36,    36,
      36,    36,    36,    36,    36,    36,    36,    36,    36,    37,
      38,    39,    40,    40,    41,    41,    42,    42,    43,    43,
      43,    44,    44,    45,    45,    46,    46,    47,    47,    48,
      48,    49,    49,    49,    50,    50,    51,    52,    52,    52,
      53,    53
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     2,     3,     3,     0,     2,     2,
       3,     3,     0,     2,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     4,     5,
       3,     3,     3,     3,     3,     2,     3,     3,     3,     3,
       3,     4,     5,     3,     2,     3,     1,     1,     1,     1,
       0,     2
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,     3,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    15,    17,
       4,    23,     7,    16,    12,    18,    19,    20,    21,    22,
       0,    87,    89,    88,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    86,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     6,    59,    60,
      30,    31,    11,    61,    63,    62,    65,    64,    67,    66,
      70,     0,    32,    33,    72,    71,    35,    34,     8,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     9,    27,    24,    25,    26,     5,
      13,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    14,    29,    28,    10,    68,
       0,     0,     0,     0,     0,     0,    84,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    75,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    69,    48,    49,    78,
      77,    91,    85,    50,    51,    52,    53,    54,    55,    80,
      79,    83,     0,    56,    58,    57,    36,    37,    38,    76,
      39,    40,    41,    42,    43,    74,    73,    44,    45,    47,
      46,    81,     0,    82
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,    18,    55,    19,    56,    20,    94,   115,    21,
     116,    95,    22,    23,    24,    25,    26,    27,    28,    29,
     117,   118,    96,    97,    98,    99,    48,   161,   124
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -81
static const yytype_int16 yypact[] =
{
     -81,     8,   -81,   -81,    35,    47,     2,     9,    38,    41,
      44,    51,    92,    26,    36,    94,    70,    74,   -81,   -81,
     -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,
      73,   -81,   -81,   -81,    91,   110,   112,   116,   117,   119,
     120,   122,   123,   124,   125,   131,   132,   -81,    47,   142,
     143,   144,   145,   146,   147,    75,    93,   -81,   -81,   -81,
     -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,
     -81,    11,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   150,
     151,    25,    37,   152,   153,   154,   155,   156,   157,    28,
     111,   158,   159,   160,   -81,   -81,   -81,   -81,   -81,   -81,
     -81,   161,   162,   163,    40,   164,   165,   166,   168,   169,
      32,   170,   171,   172,   173,   -81,   -81,   -81,   -81,   -81,
     174,   175,   176,   177,   108,   178,   -81,   179,   180,   181,
     182,   183,   184,   185,   115,   186,    47,   187,   188,   189,
     190,   191,   192,   193,   -81,   194,   195,   196,   197,   198,
     199,   118,   200,   201,   202,   203,   -81,   -81,   -81,   -81,
     -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,
     -81,   -81,   121,   -81,   -81,   -81,   -81,   -81,   -81,   -81,
     -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,
     -81,   -81,   204,   -81
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,
     -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,   -81,
     -81,   -81,   -81,   -81,   -81,   -81,   -13,    -4,   -80
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -91
static const yytype_int16 yytable[] =
{
      34,    35,    52,    36,    39,    41,    43,    45,     2,   134,
      37,     3,     4,     5,   119,     6,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,   123,    49,   -90,   133,
     151,   -90,    17,   150,   120,   -90,    30,    50,   125,    38,
     126,   143,    40,   144,    71,    42,   -90,   -90,   -90,   -90,
     -90,   -90,    44,   -90,   -90,   -90,    31,    32,    33,    31,
      32,    33,    31,    32,    33,    31,    32,    33,    31,    32,
      33,    53,    31,    32,    33,    54,    57,   136,    78,    79,
      80,    81,    82,    83,    84,    85,    86,    87,    88,    89,
      90,    91,    92,    46,    58,    51,   100,   101,   102,    93,
     103,   104,   105,   106,   107,   108,   109,   110,   111,   112,
     113,   160,   135,    59,    47,    60,    47,   114,   170,    61,
      62,   186,    63,    64,   191,    65,    66,    67,    68,    31,
      32,    33,   172,    47,    69,    70,    31,    32,    33,    31,
      32,    33,    31,    32,    33,    72,    73,    74,    75,    76,
      77,   121,   122,   127,   128,   129,   130,   131,   132,   137,
     138,   139,   140,   141,   142,   145,   146,   147,   192,   148,
     149,   152,   153,   154,   155,     0,     0,   156,   157,   158,
     159,   162,   163,   164,   165,   166,   167,   168,   169,   171,
     173,   174,   175,   176,   177,   178,   179,   180,   181,   182,
     183,   184,   185,   187,   188,   189,   190,   193
};

static const yytype_int16 yycheck[] =
{
       4,     5,    15,     1,     8,     9,    10,    11,     0,    89,
       1,     3,     4,     5,     3,     7,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,     1,     1,     3,     1,
     110,     3,    24,     1,    23,     3,     1,     1,     1,     1,
       3,     1,     1,     3,    48,     1,    21,    22,    23,    21,
      22,    23,     1,    21,    22,    23,    21,    22,    23,    21,
      22,    23,    21,    22,    23,    21,    22,    23,    21,    22,
      23,     1,    21,    22,    23,     1,     3,    90,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,     1,     3,     1,     3,     4,     5,    24,
       7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
      17,     3,     1,     3,    22,     3,    22,    24,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,    21,
      22,    23,   136,    22,     3,     3,    21,    22,    23,    21,
      22,    23,    21,    22,    23,     3,     3,     3,     3,     3,
       3,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,   172,     1,
       1,     1,     1,     1,     1,    -1,    -1,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    26,     0,     3,     4,     5,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    24,    27,    29,
      31,    34,    37,    38,    39,    40,    41,    42,    43,    44,
       1,    21,    22,    23,    52,    52,     1,     1,     1,    52,
       1,    52,     1,    52,     1,    52,     1,    22,    51,     1,
       1,     1,    51,     1,     1,    28,    30,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,    52,     3,     3,     3,     3,     3,     3,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    24,    32,    36,    47,    48,    49,    50,
       3,     4,     5,     7,     8,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    24,    33,    35,    45,    46,     3,
      23,     1,     1,     1,    53,     1,     3,     1,     1,     1,
       1,     1,     1,     1,    53,     1,    51,     1,     1,     1,
       1,     1,     1,     1,     3,     1,     1,     1,     1,     1,
       1,    53,     1,     1,     1,     1,     3,     3,     3,     3,
       3,    52,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,    52,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,    52,     3
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
        case 6:
#line 191 "sksiteconfig_parse.y"
    { do_err_args("class"); }
    break;

  case 11:
#line 202 "sksiteconfig_parse.y"
    { do_err_args("group"); }
    break;

  case 30:
#line 240 "sksiteconfig_parse.y"
    { do_err_ctx("top level", "end class"); }
    break;

  case 31:
#line 241 "sksiteconfig_parse.y"
    { do_err_ctx("top level", "end group"); }
    break;

  case 32:
#line 242 "sksiteconfig_parse.y"
    { do_err_ctx("top level", "sensors"); }
    break;

  case 33:
#line 243 "sksiteconfig_parse.y"
    { do_err_ctx("top level", "type"); }
    break;

  case 34:
#line 244 "sksiteconfig_parse.y"
    { do_err("Unknown command '%s'", (yyvsp[(1) - (3)].str));
                                    free((yyvsp[(1) - (3)].str)); }
    break;

  case 35:
#line 246 "sksiteconfig_parse.y"
    { do_err("Unrecognizable command"); }
    break;

  case 36:
#line 250 "sksiteconfig_parse.y"
    { do_err_ctx("group", "class"); }
    break;

  case 37:
#line 251 "sksiteconfig_parse.y"
    { do_err_ctx("group", "default-class"); }
    break;

  case 38:
#line 252 "sksiteconfig_parse.y"
    { do_err_ctx("group", "end class"); }
    break;

  case 39:
#line 253 "sksiteconfig_parse.y"
    { do_err_ctx("group", "group"); }
    break;

  case 40:
#line 254 "sksiteconfig_parse.y"
    { do_err_ctx("group", "include"); }
    break;

  case 41:
#line 255 "sksiteconfig_parse.y"
    { do_err_ctx("group", "path-format"); }
    break;

  case 42:
#line 256 "sksiteconfig_parse.y"
    {do_err_ctx("group", "packing-logic"); }
    break;

  case 43:
#line 257 "sksiteconfig_parse.y"
    { do_err_ctx("group", "sensor"); }
    break;

  case 44:
#line 258 "sksiteconfig_parse.y"
    { do_err_ctx("group", "type"); }
    break;

  case 45:
#line 259 "sksiteconfig_parse.y"
    { do_err_ctx("group", "version"); }
    break;

  case 46:
#line 260 "sksiteconfig_parse.y"
    { do_err("Unknown command '%s'", (yyvsp[(1) - (3)].str));
                                    free((yyvsp[(1) - (3)].str)); }
    break;

  case 47:
#line 262 "sksiteconfig_parse.y"
    { do_err("Unrecognizable command"); }
    break;

  case 48:
#line 266 "sksiteconfig_parse.y"
    { do_err_ctx("class", "class"); }
    break;

  case 49:
#line 267 "sksiteconfig_parse.y"
    { do_err_ctx("class", "default-class"); }
    break;

  case 50:
#line 268 "sksiteconfig_parse.y"
    { do_err_ctx("class", "end group"); }
    break;

  case 51:
#line 269 "sksiteconfig_parse.y"
    { do_err_ctx("class", "group"); }
    break;

  case 52:
#line 270 "sksiteconfig_parse.y"
    { do_err_ctx("class", "include"); }
    break;

  case 53:
#line 271 "sksiteconfig_parse.y"
    { do_err_ctx("class", "path-format"); }
    break;

  case 54:
#line 272 "sksiteconfig_parse.y"
    {do_err_ctx("class","packing-logic");}
    break;

  case 55:
#line 273 "sksiteconfig_parse.y"
    { do_err_ctx("class", "sensor"); }
    break;

  case 56:
#line 274 "sksiteconfig_parse.y"
    { do_err_ctx("class", "version"); }
    break;

  case 57:
#line 275 "sksiteconfig_parse.y"
    { do_err("Unknown command '%s'", (yyvsp[(1) - (3)].str)); }
    break;

  case 58:
#line 276 "sksiteconfig_parse.y"
    { do_err("Unrecognizable command"); }
    break;

  case 59:
#line 280 "sksiteconfig_parse.y"
    { do_class((yyvsp[(2) - (3)].str)); }
    break;

  case 60:
#line 286 "sksiteconfig_parse.y"
    { do_default_class((yyvsp[(2) - (3)].str)); }
    break;

  case 61:
#line 290 "sksiteconfig_parse.y"
    { do_group((yyvsp[(2) - (3)].str)); }
    break;

  case 62:
#line 296 "sksiteconfig_parse.y"
    { do_include((yyvsp[(2) - (3)].str)); }
    break;

  case 63:
#line 297 "sksiteconfig_parse.y"
    { do_err_args("include"); }
    break;

  case 64:
#line 301 "sksiteconfig_parse.y"
    { do_path_format((yyvsp[(2) - (3)].str)); }
    break;

  case 65:
#line 302 "sksiteconfig_parse.y"
    { do_err_args("path-format"); }
    break;

  case 66:
#line 306 "sksiteconfig_parse.y"
    { do_packing_logic((yyvsp[(2) - (3)].str)); }
    break;

  case 67:
#line 307 "sksiteconfig_parse.y"
    { do_err_args("packing-logic"); }
    break;

  case 68:
#line 311 "sksiteconfig_parse.y"
    { do_sensor((yyvsp[(2) - (4)].integer), (yyvsp[(3) - (4)].str), NULL); }
    break;

  case 69:
#line 312 "sksiteconfig_parse.y"
    { do_sensor((yyvsp[(2) - (5)].integer), (yyvsp[(3) - (5)].str), (yyvsp[(4) - (5)].str)); }
    break;

  case 70:
#line 313 "sksiteconfig_parse.y"
    { do_err_args("sensor"); }
    break;

  case 71:
#line 317 "sksiteconfig_parse.y"
    { if (do_version((yyvsp[(2) - (3)].integer))) { YYABORT; } }
    break;

  case 72:
#line 318 "sksiteconfig_parse.y"
    { do_err_args("version"); }
    break;

  case 73:
#line 322 "sksiteconfig_parse.y"
    { do_group_sensors((yyvsp[(2) - (3)].str_list)); }
    break;

  case 74:
#line 323 "sksiteconfig_parse.y"
    { do_err_args("sensors"); }
    break;

  case 75:
#line 327 "sksiteconfig_parse.y"
    { do_end_group(); }
    break;

  case 76:
#line 328 "sksiteconfig_parse.y"
    { do_err_args_none("end group"); }
    break;

  case 77:
#line 332 "sksiteconfig_parse.y"
    { do_class_default_types((yyvsp[(2) - (3)].str_list)); }
    break;

  case 78:
#line 333 "sksiteconfig_parse.y"
    { do_err_args("default-types"); }
    break;

  case 79:
#line 337 "sksiteconfig_parse.y"
    { do_class_sensors((yyvsp[(2) - (3)].str_list)); }
    break;

  case 80:
#line 338 "sksiteconfig_parse.y"
    { do_err_args("sensors"); }
    break;

  case 81:
#line 342 "sksiteconfig_parse.y"
    { do_class_type((yyvsp[(2) - (4)].integer), (yyvsp[(3) - (4)].str), NULL); }
    break;

  case 82:
#line 343 "sksiteconfig_parse.y"
    { do_class_type((yyvsp[(2) - (5)].integer), (yyvsp[(3) - (5)].str), (yyvsp[(4) - (5)].str)); }
    break;

  case 83:
#line 344 "sksiteconfig_parse.y"
    { do_err_args("type"); }
    break;

  case 84:
#line 348 "sksiteconfig_parse.y"
    { do_end_class(); }
    break;

  case 85:
#line 349 "sksiteconfig_parse.y"
    { do_err_args_none("end class"); }
    break;

  case 86:
#line 354 "sksiteconfig_parse.y"
    { (yyval.integer) = atoi((yyvsp[(1) - (1)].str)); free((yyvsp[(1) - (1)].str)); }
    break;

  case 90:
#line 366 "sksiteconfig_parse.y"
    { (yyval.str_list) = skVectorNew(sizeof(char*)); }
    break;

  case 91:
#line 367 "sksiteconfig_parse.y"
    { skVectorAppendValue((yyvsp[(1) - (2)].str_list), &(yyvsp[(2) - (2)].str)); (yyval.str_list) = (yyvsp[(1) - (2)].str_list); }
    break;


/* Line 1267 of yacc.c.  */
#line 1987 "sksiteconfig_parse.c"
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


#line 370 "sksiteconfig_parse.y"


/* SUPPORTING CODE */

int
yyerror(
    char        UNUSED(*s))
{
    /* do nothing, we handle error messages ourselves */
    return 0;
}

/* Handle config file version */
static int
do_version(
    int                 version)
{
    if ( sksiteconfig_testing ) {
        fprintf(stderr, "version \"%d\"\n", version);
    }
    if (( SKSITECONFIG_VERSION_DEFAULT != site_file_version )
        && ( version != site_file_version ))
    {
        sksiteconfigErr("Multiple version commands specified");
    }
    if ( version < 1 || version > SKSITECONFIG_VERSION_CURRENT ) {
        sksiteconfigErr("Unsupported version '%d'", version);
        return 1;
    }
    site_file_version = version;
    return 0;
}

/* Define sensor */
static void
do_sensor(
    int                 id,
    char               *name,
    char               *description)
{
    const int sensor_desc_first_version = 2;

    if ( sksiteconfig_testing ) {
        fprintf(stderr, "sensor %d \"%s\"", id, name);
        if ( description ) {
            fprintf(stderr, " \"%s\"", description);
        }
        fprintf(stderr, "\n");
    }
    if ( id >= SK_MAX_NUM_SENSORS ) {
        sksiteconfigErr("Sensor id '%d' is greater than maximum of %d",
                        id, SK_MAX_NUM_SENSORS-1);
    } else if ( strlen(name) > SK_MAX_STRLEN_SENSOR ) {
        sksiteconfigErr("Sensor name '%s' is longer than maximum of %d",
                        name, SK_MAX_STRLEN_SENSOR);
    } else if ( sksiteSensorExists(id) ) {
        sksiteconfigErr("A sensor with id '%d' already exists", id);
    } else if ( sksiteSensorLookup(name) != SK_INVALID_SENSOR ) {
        sksiteconfigErr("A sensor with name '%s' already exists", name);
    } else if ( sksiteSensorCreate(id, name) ) {
        sksiteconfigErr("Failed to create sensor");
    } else if ( description ) {
        if (( site_file_version != SKSITECONFIG_VERSION_DEFAULT )
            && ( site_file_version < sensor_desc_first_version ))
        {
            sksiteconfigErr(("Sensor descriptions only allowed when"
                             " file's version is %d or greater"),
                            sensor_desc_first_version);
        } else if ( sksiteSensorSetDescription(id, description) ) {
            sksiteconfigErr("Failed to set sensor description");
        }
    }
    if ( description ) {
        free(description);
    }
    free(name);
}

/* Define path-format */
static void
do_path_format(
    char               *fmt)
{
    const char *cp;
    int final_x = 0;

    if ( sksiteconfig_testing ) {
        fprintf(stderr, "path-format \"%s\"\n", fmt);
    }
    cp = fmt;
    while (NULL != (cp = strchr(cp, '%'))) {
        ++cp;
        if (!*cp) {
            sksiteconfigErr("The path-format '%s' ends with a single '%%'",
                            fmt);
            break;
        }
        if (NULL == strchr(path_format_conversions, *cp)) {
            sksiteconfigErr(
                "The path-format '%s' contains an unknown conversion '%%%c'",
                fmt, *cp);
        } else if ('x' == *cp && '\0' == *(cp+1)) {
            /* Found %x at the end; confirm that either the entire fmt
             * is "%x" or that "%x" is preceeded by '/'  */
            if ((cp-1 == fmt) || ('/' == *(cp-2))) {
                final_x = 1;
            }
        }
        ++cp;
    }
    if (!final_x) {
        sksiteconfigErr("The path-format '%s' does not end with '/%%x'", fmt);
    }
    if ( sksiteSetPathFormat(fmt) ) {
        sksiteconfigErr("Failed to set path-format");
    }
    free(fmt);
}

/* Define the packing-logic file */
static void
do_packing_logic(
    char               *fmt)
{
    if ( sksiteconfig_testing ) {
        fprintf(stderr, "packing-logic \"%s\"\n", fmt);
    }
    if ( sksiteSetPackingLogicPath(fmt) ) {
        sksiteconfigErr("Failed to set packing-logic");
    }
    free(fmt);
}

/* Include a file */
static void
do_include(
    char               *filename)
{
    if ( sksiteconfig_testing ) {
        fprintf(stderr, "include \"%s\"\n", filename);
    }
    sksiteconfigIncludePush(filename);
}

/* Begin defining a group */
static void
do_group(
    char               *groupname)
{
    assert(current_group == NULL);
    assert(current_class == NULL);
    if ( sksiteconfig_testing ) {
        fprintf(stderr, "group \"%s\"\n", groupname);
    }
    current_group = groupname;
    current_group_id = sksiteSensorgroupLookup(current_group);
    if ( current_group_id == SK_INVALID_SENSORGROUP ) {
        current_group_id = sksiteSensorgroupGetMaxID() + 1;
        if ( sksiteSensorgroupCreate(current_group_id, groupname) ) {
            current_group_id = SK_INVALID_SENSORGROUP;
            sksiteconfigErr("Failed to create sensorgroup");
        }
    }
}

/* Add sensors to a group definition */
static void
do_group_sensors(
    sk_vector_t        *sensors)
{
    size_t i;
    size_t len;
    char *str;
    sk_sensor_id_t sensor_id;
    sk_sensorgroup_id_t sensorgroup_id;

    assert(current_group != NULL);
    assert(current_class == NULL);
    len = skVectorGetCount(sensors);
    if ( sksiteconfig_testing ) {
        fprintf(stderr, "[group \"%s\"] sensors", current_group);
        for ( i = 0; i < len; i++ ) {
            skVectorGetValue(&str, sensors, i);
            fprintf(stderr, " %s", str);
        }
        fprintf(stderr, "\n");
    }
    if ( current_group_id != SK_INVALID_SENSORGROUP ) {
        for ( i = 0; i < len; i++ ) {
            skVectorGetValue(&str, sensors, i);
            if ( str[0] == '@' ) {
                sensorgroup_id = sksiteSensorgroupLookup(&str[1]);
                if ( sensorgroup_id == SK_INVALID_SENSORGROUP ) {
                    sksiteconfigErr(("Cannot add group to group '%s':"
                                     " group '%s' is not defined"),
                                    current_group, str);
                } else {
                    sksiteSensorgroupAddSensorgroup(current_group_id,
                                                    sensorgroup_id);
                }
            } else {
                sensor_id = sksiteSensorLookup(str);
                if ( sensor_id == SK_INVALID_SENSOR ) {
                    sksiteconfigErr(("Cannot add sensor to group '%s':"
                                     " sensor '%s' is not defined"),
                                    current_group, str);
                } else {
                    sksiteSensorgroupAddSensor(current_group_id, sensor_id);
                }
            }
        }
    }
    /* free the vector and its contents */
    for (i = 0; i < len; ++i) {
        skVectorGetValue(&str, sensors, i);
        free(str);
    }
    skVectorDestroy(sensors);
}

/* Finish defining a group */
static void
do_end_group(
    void)
{
    assert(current_group != NULL);
    assert(current_class == NULL);
    if ( sksiteconfig_testing ) {
        fprintf(stderr, "[group \"%s\"] end group\n", current_group);
    }
    free(current_group);
    current_group = NULL;
}

/* Begin defining a class */
static void
do_class(
    char               *classname)
{
    assert(current_group == NULL);
    assert(current_class == NULL);
    if ( sksiteconfig_testing ) {
        fprintf(stderr, "class \"%s\"\n", classname);
    }
    current_class = classname;
    current_class_id = sksiteClassLookup(current_class);
    /* We're okay on "duplicates": just more info on existing class */
    if ( current_class_id == SK_INVALID_CLASS ) {
        if ( strlen(classname) > SK_MAX_STRLEN_FLOWTYPE ) {
            sksiteconfigErr(("The class-name '%s'"
                             " is longer than the maximum of %d"),
                            classname, SK_MAX_STRLEN_FLOWTYPE);
        }
        current_class_id = sksiteClassGetMaxID() + 1;
        if ( sksiteClassCreate(current_class_id, classname) ) {
            current_class_id = SK_INVALID_CLASS;
            sksiteconfigErr("Failed to create class");
        }
    }
}

/* Add sensors to a class definition */
static void
do_class_sensors(
    sk_vector_t        *sensors)
{
    size_t i;
    size_t len;
    char *str;
    sk_sensor_id_t sensor_id;
    sk_sensorgroup_id_t sensorgroup_id;

    assert(current_class != NULL);
    assert(current_group == NULL);
    len = skVectorGetCount(sensors);
    if ( sksiteconfig_testing ) {
        fprintf(stderr, "[class \"%s\"] sensors", current_class);
        for ( i = 0; i < len; i++ ) {
            skVectorGetValue(&str, sensors, i);
            fprintf(stderr, " %s", str);
        }
        fprintf(stderr, "\n");
    }
    if ( current_class_id != SK_INVALID_CLASS ) {
        for ( i = 0; i < len; i++ ) {
            skVectorGetValue(&str, sensors, i);
            if ( str[0] == '@' ) {
                sensorgroup_id = sksiteSensorgroupLookup(&str[1]);
                if ( sensorgroup_id == SK_INVALID_SENSORGROUP ) {
                    sksiteconfigErr(("Cannot add group to class '%s':"
                                     " group '%s' is not defined"),
                                    current_class, str);
                } else {
                    sksiteClassAddSensorgroup(current_class_id,
                                              sensorgroup_id);
                }
            } else {
                sensor_id = sksiteSensorLookup(str);
                if ( sensor_id == SK_INVALID_SENSOR ) {
                    sksiteconfigErr(("Cannot add sensor to class '%s':"
                                     " sensor '%s' is not defined"),
                                    current_class, str);
                } else {
                    sksiteClassAddSensor(current_class_id, sensor_id);
                }
            }
        }
    }
    /* free the vector and its contents */
    for (i = 0; i < len; ++i) {
        skVectorGetValue(&str, sensors, i);
        free(str);
    }
    skVectorDestroy(sensors);
}

/* Define type within a class definition */
static void
do_class_type(
    int                 id,
    char               *type,
    char               *name)
{
    char flowtype_name_buf[SK_MAX_STRLEN_FLOWTYPE+1];

    assert(current_class != NULL);
    assert(type);

    if ( sksiteconfig_testing ) {
        fprintf(stderr, "[class \"%s\"] type %d %s",
                current_class, id, type);
        if (name) {
            fprintf(stderr, " %s", name);
        }
        fprintf(stderr, "\n");
    }

    if ( strlen(type) > SK_MAX_STRLEN_FLOWTYPE ) {
        sksiteconfigErr(("The type-name '%s'"
                         " is longer than the maximum of %d"),
                        type, SK_MAX_STRLEN_FLOWTYPE);
    }
    if ( name ) {
        if ( strlen(name) > SK_MAX_STRLEN_FLOWTYPE ) {
            sksiteconfigErr(("The flowtype-name '%s'"
                             " is longer than the maximum of %d"),
                            name, SK_MAX_STRLEN_FLOWTYPE);
        }
    } else {
        if ( snprintf(flowtype_name_buf, SK_MAX_STRLEN_FLOWTYPE,
                      "%s%s", current_class, type)
             > SK_MAX_STRLEN_FLOWTYPE )
        {
            sksiteconfigErr(("The generated flowtype-name '%s%s'"
                             " is longer than the maximum of %d"),
                            current_class, type, SK_MAX_STRLEN_FLOWTYPE);
        }
        name = flowtype_name_buf;
    }
    if ( current_class_id != SK_INVALID_CLASS ) {
        if ( id >= SK_MAX_NUM_FLOWTYPES ) {
            sksiteconfigErr("Type id '%d' is greater than maximum of %d",
                            id, SK_MAX_NUM_FLOWTYPES-1);
        } else if ( sksiteFlowtypeExists(id) ) {
            sksiteconfigErr("A type with id '%d' already exists", id);
        } else if ( sksiteFlowtypeLookup(name) != SK_INVALID_FLOWTYPE ) {
            sksiteconfigErr("A type with prefix '%s' already exists", name);
        } else if ( sksiteFlowtypeLookupByClassIDType(current_class_id, type)
                    != SK_INVALID_CLASS ) {
            sksiteconfigErr("The type '%s' for class '%s' already exists",
                            type, current_class);
        } else if ( sksiteFlowtypeCreate(id, name, current_class_id, type) ) {
            sksiteconfigErr("Failed to create type");
        }
    }
    free(type);
    if ( name != flowtype_name_buf ) {
        free(name);
    }
}

/* Set the default types within a class definition */
static void
do_class_default_types(
    sk_vector_t        *types)
{
    size_t i;
    size_t len;
    char *str;
    sk_flowtype_id_t flowtype_id;

    assert(current_class != NULL);
    assert(current_group == NULL);
    len = skVectorGetCount(types);
    if ( sksiteconfig_testing ) {
        fprintf(stderr, "[class \"%s\"] default-types", current_class);
        for ( i = 0; i < len; i++ ) {
            skVectorGetValue(&str, types, i);
            fprintf(stderr, " %s", str);
        }
        fprintf(stderr, "\n");
    }
    if ( current_class_id != SK_INVALID_CLASS ) {
        for ( i = 0; i < len; i++ ) {
            skVectorGetValue(&str, types, i);
            flowtype_id =
                sksiteFlowtypeLookupByClassIDType(current_class_id, str);
            if ( flowtype_id == SK_INVALID_FLOWTYPE ) {
                sksiteconfigErr(("Cannot set default type in class '%s':"
                                 " type '%s' is not defined"),
                                current_class, str);
            } else if ( sksiteClassAddDefaultFlowtype(current_class_id,
                                                      flowtype_id) )
            {
                sksiteconfigErr("Failed to add default type");
            }
        }
    }
    /* free the vector and its contents */
    for (i = 0; i < len; ++i) {
        skVectorGetValue(&str, types, i);
        free(str);
    }
    skVectorDestroy(types);
}

/* Finish defining a class */
static void
do_end_class(
    void)
{
    assert(current_class != NULL);
    assert(current_group == NULL);
    if ( sksiteconfig_testing ) {
        fprintf(stderr, "[class \"%s\"] end class\n", current_class);
    }
    free(current_class);
    current_class = NULL;
}

static void
do_default_class(
    char               *name)
{
    sk_class_id_t class_id;
    sk_flowtype_iter_t ft_iter;
    sk_flowtype_id_t ft_id;

    if ( sksiteconfig_testing ) {
        fprintf(stderr, "default-class \"%s\"\n", name);
    }
    class_id = sksiteClassLookup(name);
    if ( class_id == SK_INVALID_CLASS ) {
        sksiteconfigErr("Cannot set default class: class '%s' is not defined",
                        name);
    } else {
        sksiteClassFlowtypeIterator(class_id, &ft_iter);
        if (!sksiteFlowtypeIteratorNext(&ft_iter, &ft_id)) {
            sksiteconfigErr(
                "Cannot set default class: class '%s' contains no types",
                name);
        } else if (sksiteClassSetDefault(class_id)) {
            sksiteconfigErr("Failed to set default class");
        }
    }
    free(name);
}

/* Report a context error, like trying to define a sensor in a class */
static void
do_err_ctx(
    const char         *ctx,
    const char         *cmd)
{
    do_err("Command '%s' not allowed in %s", cmd, ctx);
}

/* Report an argument error: too many, too few, or the wrong args */
static void
do_err_args(
    const char         *cmd)
{
    do_err("Bad arguments to command '%s'", cmd);
}

/* Report an argument error: shouldn't be any arguments */
static void
do_err_args_none(
    const char         *cmd)
{
    do_err("Command '%s' does take arguments", cmd);
}


/*
** Local variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/

