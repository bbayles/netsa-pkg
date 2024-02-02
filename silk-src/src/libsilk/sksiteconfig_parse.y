%{
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


%}

%union {
    int integer;
    char *str;
    sk_vector_t *str_list;
}

%token TOK_NL

%token TOK_CLASS TOK_DEF_CLASS TOK_DEF_TYPES TOK_END_CLASS TOK_END_GROUP
%token TOK_GROUP TOK_INCLUDE TOK_PATH_FORMAT TOK_PACKING_LOGIC
%token TOK_SENSOR TOK_SENSORS TOK_TYPE TOK_VERSION

%token ERR_UNREC ERR_UNTERM_STRING ERR_STR_TOO_LONG
%token ERR_INVALID_OCTAL_ESCAPE

%token <str> TOK_ATOM
%token <str> TOK_INTEGER
%token <str> TOK_STRING
%token <str> ERR_UNK_CMD

%type <integer> int
%type <str> str
%type <str_list> str_list

%%

top_cmd_list:
    /* nothing */
  | top_cmd_list TOK_NL
  | top_cmd_list top_cmd
;

block_class:
    cmd_class class_cmd_list cmd_end_class
  | TOK_CLASS error TOK_NL        { do_err_args("class"); }
;

class_cmd_list:
    /* nothing */
  | class_cmd_list TOK_NL
  | class_cmd_list class_cmd
;

block_group:
    cmd_group group_cmd_list cmd_end_group
  | TOK_GROUP error TOK_NL        { do_err_args("group"); }
;

group_cmd_list:
    /* nothing */
  | group_cmd_list TOK_NL
  | group_cmd_list group_cmd
;



top_cmd:
    block_class
  | cmd_default_class
  | block_group
  | cmd_include
  | cmd_path_format
  | cmd_packing_logic
  | cmd_sensor
  | cmd_version
  | err_top
;

class_cmd:
    cmd_class_default_types
  | cmd_class_sensors
  | cmd_class_type
  | err_cls
;

group_cmd:
    cmd_group_sensors
  | err_grp
;



err_top:
    TOK_END_CLASS error TOK_NL    { do_err_ctx("top level", "end class"); }
  | TOK_END_GROUP error TOK_NL    { do_err_ctx("top level", "end group"); }
  | TOK_SENSORS error TOK_NL      { do_err_ctx("top level", "sensors"); }
  | TOK_TYPE error TOK_NL         { do_err_ctx("top level", "type"); }
  | ERR_UNK_CMD error TOK_NL      { do_err("Unknown command '%s'", $1);
                                    free($1); }
  | ERR_UNREC error TOK_NL        { do_err("Unrecognizable command"); }
;

err_grp:
    TOK_CLASS error TOK_NL        { do_err_ctx("group", "class"); }
  | TOK_DEF_CLASS error TOK_NL    { do_err_ctx("group", "default-class"); }
  | TOK_END_CLASS error TOK_NL    { do_err_ctx("group", "end class"); }
  | TOK_GROUP error TOK_NL        { do_err_ctx("group", "group"); }
  | TOK_INCLUDE error TOK_NL      { do_err_ctx("group", "include"); }
  | TOK_PATH_FORMAT error TOK_NL  { do_err_ctx("group", "path-format"); }
  | TOK_PACKING_LOGIC error TOK_NL {do_err_ctx("group", "packing-logic"); }
  | TOK_SENSOR error TOK_NL       { do_err_ctx("group", "sensor"); }
  | TOK_TYPE error TOK_NL         { do_err_ctx("group", "type"); }
  | TOK_VERSION error TOK_NL      { do_err_ctx("group", "version"); }
  | ERR_UNK_CMD error TOK_NL      { do_err("Unknown command '%s'", $1);
                                    free($1); }
  | ERR_UNREC error TOK_NL        { do_err("Unrecognizable command"); }
;

err_cls:
    TOK_CLASS error TOK_NL        { do_err_ctx("class", "class"); }
  | TOK_DEF_CLASS error TOK_NL    { do_err_ctx("class", "default-class"); }
  | TOK_END_GROUP error TOK_NL    { do_err_ctx("class", "end group"); }
  | TOK_GROUP error TOK_NL        { do_err_ctx("class", "group"); }
  | TOK_INCLUDE error TOK_NL      { do_err_ctx("class", "include"); }
  | TOK_PATH_FORMAT error TOK_NL  { do_err_ctx("class", "path-format"); }
  | TOK_PACKING_LOGIC error TOK_NL {do_err_ctx("class","packing-logic");}
  | TOK_SENSOR error TOK_NL       { do_err_ctx("class", "sensor"); }
  | TOK_VERSION error TOK_NL      { do_err_ctx("class", "version"); }
  | ERR_UNK_CMD error TOK_NL      { do_err("Unknown command '%s'", $1); }
  | ERR_UNREC error TOK_NL        { do_err("Unrecognizable command"); }
;

cmd_class:
    TOK_CLASS str TOK_NL                { do_class($2); }
    /* error handling is in block_class so that the context stays at
       top-level when there's a problem with the command. */
;

cmd_default_class:
    TOK_DEF_CLASS str TOK_NL      { do_default_class($2); }
;

cmd_group:
    TOK_GROUP str TOK_NL          { do_group($2); }
    /* error handling is in block_class so that the context stays at
       top-level when there's a problem with the command. */
;

cmd_include:
    TOK_INCLUDE str TOK_NL        { do_include($2); }
  | TOK_INCLUDE error TOK_NL      { do_err_args("include"); }
;

cmd_path_format:
    TOK_PATH_FORMAT str TOK_NL    { do_path_format($2); }
  | TOK_PATH_FORMAT error TOK_NL  { do_err_args("path-format"); }
;

cmd_packing_logic:
    TOK_PACKING_LOGIC str TOK_NL   { do_packing_logic($2); }
  | TOK_PACKING_LOGIC error TOK_NL { do_err_args("packing-logic"); }
;

cmd_sensor:
    TOK_SENSOR int str TOK_NL             { do_sensor($2, $3, NULL); }
  | TOK_SENSOR int str TOK_STRING TOK_NL  { do_sensor($2, $3, $4); }
  | TOK_SENSOR error TOK_NL               { do_err_args("sensor"); }
;

cmd_version:
    TOK_VERSION int TOK_NL        { if (do_version($2)) { YYABORT; } }
  | TOK_VERSION error TOK_NL      { do_err_args("version"); }
;

cmd_group_sensors:
    TOK_SENSORS str_list TOK_NL   { do_group_sensors($2); }
  | TOK_SENSORS error TOK_NL      { do_err_args("sensors"); }
;

cmd_end_group:
    TOK_END_GROUP TOK_NL          { do_end_group(); }
  | TOK_END_GROUP error TOK_NL    { do_err_args_none("end group"); }
;

cmd_class_default_types:
    TOK_DEF_TYPES str_list TOK_NL { do_class_default_types($2); }
  | TOK_DEF_TYPES error TOK_NL    { do_err_args("default-types"); }
;

cmd_class_sensors:
    TOK_SENSORS str_list TOK_NL   { do_class_sensors($2); }
  | TOK_SENSORS error TOK_NL      { do_err_args("sensors"); }
;

cmd_class_type:
    TOK_TYPE int str TOK_NL       { do_class_type($2, $3, NULL); }
  | TOK_TYPE int str str TOK_NL   { do_class_type($2, $3, $4); }
  | TOK_TYPE error TOK_NL         { do_err_args("type"); }
;

cmd_end_class:
    TOK_END_CLASS TOK_NL          { do_end_class(); }
  | TOK_END_CLASS error TOK_NL    { do_err_args_none("end class"); }
;

/* For int, accept only things that look like integers, then atoi them. */
int:
    TOK_INTEGER                   { $$ = atoi($1); free($1); }
;

/* For str, take anything that looks like a quoted string, an identifier
 * (atom), or a number. */
str:
    TOK_ATOM
  | TOK_STRING
  | TOK_INTEGER
;

str_list:
    /* empty */                   { $$ = skVectorNew(sizeof(char*)); }
| str_list str                    { skVectorAppendValue($1, &$2); $$ = $1; }
;

%%

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
