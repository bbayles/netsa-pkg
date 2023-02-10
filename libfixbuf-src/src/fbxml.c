/*
 ** fbxml.c
 ** IPFIX Information Model and IE storage management
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2018-2023 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Michael Duggan
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_LICENSE_START@
 ** libfixbuf 2.0
 **
 ** Copyright 2018-2023 Carnegie Mellon University. All Rights Reserved.
 **
 ** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
 ** ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
 ** BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
 ** EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
 ** EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
 ** MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 ** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
 ** COPYRIGHT INFRINGEMENT.
 **
 ** Released under a GNU-Lesser GPL 3.0-style license, please see
 ** LICENSE.txt or contact permission@sei.cmu.edu for full terms.
 **
 ** [DISTRIBUTION STATEMENT A] This material has been approved for
 ** public release and unlimited distribution.  Please see Copyright
 ** notice for non-US Government use and distribution.
 **
 ** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent
 ** and Trademark Office by Carnegie Mellon University.
 **
 ** DM18-0325
 ** @OPENSOURCE_LICENSE_END@
 ** ------------------------------------------------------------------------
 */
#include <fixbuf/public.h>


/* for silencing unused parameter warnings */
#define UNUSED1(_x1)                 (void)_x1
#define UNUSED2(_x1, _x2)            (void)_x1;(void)_x2
#define UNUSED3(_x1, _x2, _x3)       (void)_x1;(void)_x2;(void)_x3
#define UNUSED4(_x1, _x2, _x3, _x4)  (void)_x1;(void)_x2;(void)_x3;(void)_x4

#define MP_FLAGS (G_MARKUP_TREAT_CDATA_AS_TEXT          \
                  | G_MARKUP_PREFIX_ERROR_POSITION)

static void create_mapping(
    GHashTable  **map,
    const gchar **strings,
    int           length)
{
    int i;
    *map = g_hash_table_new(g_str_hash, g_str_equal);
    for (i = 0; i < length; ++i) {
        g_hash_table_insert(*map, (gpointer)strings[i], GUINT_TO_POINTER(i));
    }
}

#define DATATYPE_REGISTRY_ID "ipfix-information-element-data-types"
static GHashTable *datatype_mapping;
static void init_datatype_mapping(
    void)
{
    static const gchar *strings[] = {
        "octetArray",
        "unsigned8",
        "unsigned16",
        "unsigned32",
        "unsigned64",
        "signed8",
        "signed16",
        "signed32",
        "signed64",
        "float32",
        "float64",
        "boolean",
        "macAddress",
        "string",
        "dateTimeSeconds",
        "dateTimeMilliseconds",
        "dateTimeMicroseconds",
        "dateTimeNanoseconds",
        "ipv4Address",
        "ipv6Address",
        "basicList",
        "subTemplateList",
        "subTemplateMultiList"
    };
    create_mapping(&datatype_mapping,
                   strings, sizeof(strings) / sizeof(const gchar *));
}

#define SEMANTIC_REGISTRY_ID "ipfix-information-element-semantics"
static GHashTable *semantic_mapping;
static void init_semantic_mapping(
    void)
{
    static const gchar *strings[] = {
        "default",
        "quantity",
        "totalCounter",
        "deltaCounter",
        "identifier",
        "flags",
        "list",
        "snmpCounter",
        "snmpGauge"
    };
    create_mapping(&semantic_mapping,
                   strings, sizeof(strings) / sizeof(const gchar *));
}

#define UNIT_REGISTRY_ID "ipfix-information-element-units"
static GHashTable *unit_mapping;
static void init_unit_mapping(
    void)
{
    static const gchar *strings[] = {
        "none",
        "bits",
        "octets",
        "packets",
        "flows",
        "seconds",
        "milliseconds",
        "microseconds",
        "nanoseconds",
        "4-octet words",
        "messages",
        "hops",
        "entries",
        "frames",
        "ports",
        "inferred"
    };
    create_mapping(&unit_mapping,
                   strings, sizeof(strings) / sizeof(const gchar *));
}

static void init_mappings(
    void)
{
    static gboolean initialized = FALSE;
    if (!initialized) {
        init_datatype_mapping();
        init_semantic_mapping();
        init_unit_mapping();
        initialized = TRUE;
    }
}

static const char *ename(
    const char *name)
{
    const char *colon = strchr(name, ':');
    if (colon) {
        return colon + 1;
    }
    return name;
}

typedef enum parse_state_en {
    SEARCHING_FOR_REGISTRY,
    PARSING_REGISTRY,
    RECORD_SEARCHING,
    IN_RECORD,
    GATHER_TEXT
} parse_state_t;

static const GMarkupParser mappings_locator_parser;

typedef struct valdesc_data_st {
    GHashTable    *map;
    GString       *text;
    const gchar   *description;
    guint64        value;
    parse_state_t  state;
} valdesc_data_t;

static const GMarkupParser valdesc_parser;

static valdesc_data_t *alloc_valdesc_data(
    GHashTable *map)
{
    valdesc_data_t *data = g_new(valdesc_data_t, 1);
    data->map = map;
    data->text = g_string_sized_new(32);
    data->state = RECORD_SEARCHING;
    return data;
}

static void destroy_valdesc_data(
    gpointer p)
{
    valdesc_data_t *data = (valdesc_data_t *)p;
    if (data->text) {
        g_string_free(data->text, TRUE);
    }
    g_free(p);
}

static void parse_valdesc_text(
    GMarkupParseContext  *ctx,
    const gchar          *text,
    gsize                 len,
    gpointer              user_data,
    GError              **error)
{
    valdesc_data_t *data = (valdesc_data_t *)user_data;
    UNUSED2(ctx, error);
    if (data->state == GATHER_TEXT) {
        g_string_append_len(data->text, text, len);
    }
}

static void parse_valdesc_start(
    GMarkupParseContext  *ctx,
    const gchar          *element_name,
    const gchar         **attribute_names,
    const gchar         **attribute_values,
    gpointer              user_data,
    GError              **error)
{
    valdesc_data_t *data = (valdesc_data_t *)user_data;
    UNUSED4(ctx, error, attribute_names, attribute_values);
    element_name = ename(element_name);
    if (strcmp(element_name, "record") == 0) {
        data->value = G_MAXUINT64;
        data->description = NULL;
        data->state = IN_RECORD;
    } else if (data->state == IN_RECORD
               && (strcmp(element_name, "value") == 0
                   || strcmp(element_name, "description") == 0))
    {
        g_string_truncate(data->text, 0);
        data->state = GATHER_TEXT;
    }
}

static void parse_valdesc_end(
    GMarkupParseContext  *ctx,
    const gchar          *element_name,
    gpointer              user_data,
    GError              **error)
{
    valdesc_data_t *data = (valdesc_data_t *)user_data;
    UNUSED2(ctx, error);
    element_name = ename(element_name);
    if (strcmp(element_name, "record") == 0) {
        if (data->value != G_MAXUINT64 && data->description) {

            g_hash_table_insert(data->map, (gpointer)data->description,
                                GUINT_TO_POINTER(data->value));
        }
        data->state = RECORD_SEARCHING;
    }
    if (data->state == RECORD_SEARCHING) {
        return;
    }
    if (strcmp(element_name, "value") == 0) {
        gchar *end;
        data->value = g_ascii_strtoull(data->text->str, &end, 10);
        if (*end != '\0' || end == data->text->str) {
            data->value = G_MAXUINT64;
        }
    } else if (strcmp(element_name, "description") == 0) {
        data->description = g_intern_string(data->text->str);
    } else {
        return;
    }
    data->state = IN_RECORD;
}

static void parse_valdesc_error(
    GMarkupParseContext *ctx,
    GError              *error,
    gpointer             user_data)
{
    UNUSED2(ctx, error);
    destroy_valdesc_data(user_data);
}


static const GMarkupParser valdesc_parser = {
    parse_valdesc_start,
    parse_valdesc_end,
    parse_valdesc_text,
    NULL,
    parse_valdesc_error
};

static void ipfix_mappings_locator_start(
    GMarkupParseContext  *ctx,
    const gchar          *element_name,
    const gchar         **attribute_names,
    const gchar         **attribute_values,
    gpointer              user_data,
    GError              **error)
{
    element_name = ename(element_name);
    UNUSED1(error);
    if (strcmp(element_name, "registry") == 0) {
        while (*attribute_names) {
            if (strcmp(*attribute_names, "id") == 0) {
                GHashTable *map = NULL;
                if (strcmp(*attribute_values, DATATYPE_REGISTRY_ID) == 0) {
                    map = datatype_mapping;
                } else if (strcmp(*attribute_values,
                                  SEMANTIC_REGISTRY_ID) == 0)
                {
                    map = semantic_mapping;
                } else if (strcmp(*attribute_values, UNIT_REGISTRY_ID) == 0) {
                    map = unit_mapping;
                }
                if (map) {
                    valdesc_data_t *data = alloc_valdesc_data(map);
                    g_markup_parse_context_push(ctx, &valdesc_parser, data);
                    *(parse_state_t *)user_data = PARSING_REGISTRY;
                }
                break;
            }
            ++attribute_names;
            ++attribute_values;
        }
    }
}

static void ipfix_mappings_locator_end(
    GMarkupParseContext  *ctx,
    const gchar          *element_name,
    gpointer              user_data,
    GError              **error)
{
    element_name = ename(element_name);
    UNUSED1(error);
    if (strcmp(element_name, "registry") == 0) {
        if (*(parse_state_t *)user_data == PARSING_REGISTRY) {
            destroy_valdesc_data(g_markup_parse_context_pop(ctx));
            *(parse_state_t *)user_data = SEARCHING_FOR_REGISTRY;
        }
    }
}

static const GMarkupParser mappings_locator_parser = {
    ipfix_mappings_locator_start,
    ipfix_mappings_locator_end,
    NULL,
    NULL,
    NULL,
};

static gboolean ipfix_mappings_parse(
    const gchar  *xml_data,
    gssize        xml_data_len,
    GError      **error)
{
    parse_state_t *state;
    GMarkupParseContext *ctx;
    gboolean result;

    init_mappings();
    state = g_new(parse_state_t, 1);
    *state = SEARCHING_FOR_REGISTRY;
    ctx = g_markup_parse_context_new(
        &mappings_locator_parser, MP_FLAGS, state, g_free);
    result = g_markup_parse_context_parse(
        ctx, xml_data, xml_data_len, error);
    if (result) {
        result = g_markup_parse_context_end_parse(ctx, error);
    }
    g_markup_parse_context_free(ctx);
    return result;
}

enum validity_en {
    NOT_FOUND = 0, FOUND_VALID, FOUND_INVALID
};

typedef struct validity_st {
    enum validity_en  validity;
    gint              line;
    gint              character;
    const gchar      *message;
} validity_t;

typedef struct element_data_st {
    fbInfoModel_t   *model;
    GString         *text;
    fbInfoElement_t  ie;
    gchar           *group;
    gboolean         reversible;
    validity_t       name_validity;
    validity_t       enterpriseId_validity;
    validity_t       elementId_validity;
    validity_t       dataType_validity;
    validity_t       dataTypeSemantics_validity;
    validity_t       units_validity;
    validity_t       range_validity;
    validity_t       reversible_validity;
    validity_t       group_validity;
    parse_state_t    state;
} element_data_t;

static element_data_t *alloc_element_data(
    fbInfoModel_t *model)
{
    element_data_t *data = g_new0(element_data_t, 1);
    data->model = model;
    data->text = g_string_sized_new(32);
    data->state = RECORD_SEARCHING;
    return data;
}

static void destroy_element_data(
    gpointer p)
{
    element_data_t *data = (element_data_t *)p;
    if (data->text) {
        g_string_free(data->text, TRUE);
    }
    g_free((void *)data->ie.ref.name);
    g_free(p);
}

static void parse_element_text(
    GMarkupParseContext  *ctx,
    const gchar          *text,
    gsize                 len,
    gpointer              user_data,
    GError              **error)
{
    element_data_t *data = (element_data_t *)user_data;
    UNUSED2(ctx, error);
    if (data->state == GATHER_TEXT) {
        g_string_append_len(data->text, text, len);
    }
}

static void parse_element_start(
    GMarkupParseContext  *ctx,
    const gchar          *element_name,
    const gchar         **attribute_names,
    const gchar         **attribute_values,
    gpointer              user_data,
    GError              **error)
{
    element_data_t *data = (element_data_t *)user_data;
    UNUSED4(ctx, error, attribute_names, attribute_values);
    element_name = ename(element_name);
    if (strcmp(element_name, "record") == 0) {
        fbInfoModel_t *model = data->model;
        GString *text = data->text;
        g_free((void *)data->ie.ref.name);
        g_free((void *)data->group);
        memset(data, 0, sizeof(*data));
        data->model = model;
        data->text = text;
        data->state = IN_RECORD;
    } else if (data->state == IN_RECORD
               && (strcmp(element_name, "name") == 0
                   || strcmp(element_name, "enterpriseId") == 0
                   || strcmp(element_name, "elementId") == 0
                   || strcmp(element_name, "dataType") == 0
                   || strcmp(element_name, "dataTypeSemantics") == 0
                   || strcmp(element_name, "units") == 0
                   || strcmp(element_name, "reversible") == 0
                   || strcmp(element_name, "range") == 0
                   || strcmp(element_name, "group") == 0))
    {
        g_string_truncate(data->text, 0);
        data->state = GATHER_TEXT;
    }
}

static void set_invalid(
    GMarkupParseContext *ctx,
    validity_t          *validity,
    const gchar         *message)
{
    validity->validity = FOUND_INVALID;
    validity->message = message;
    g_markup_parse_context_get_position(
        ctx, &validity->line, &validity->character);
}

static gboolean parse_as_integer(
    GMarkupParseContext *ctx,
    const GString       *str,
    guint64             *val,
    validity_t          *validity)
{
    gchar *end;
    *val = g_ascii_strtoull(str->str, &end, 0);
    if (end == str->str || *end != '\0') {
        set_invalid(ctx, validity, "Could not parse as integer");
        return FALSE;
    }
    validity->validity = FOUND_VALID;
    return TRUE;
}

static gboolean parse_from_map(
    GMarkupParseContext *ctx,
    GHashTable          *map,
    const GString       *str,
    guint64             *val,
    validity_t          *validity)
{
    gpointer p;
    if (g_hash_table_lookup_extended(map, str->str, NULL, &p)) {
        *val = GPOINTER_TO_UINT(p);
        validity->validity = FOUND_VALID;
        return TRUE;
    }
    *val = 0;
    set_invalid(ctx, validity, "Unrecognized value");
    return FALSE;
}

static gboolean warn_invalid(
    const validity_t *v)
{
    if (v->validity == FOUND_INVALID) {
        g_warning("Parse error: (%d:%d) %s",
                  v->line, v->character, v->message);
        return TRUE;
    }
    return FALSE;
}

static gboolean warn_required(
    const char          *name,
    const validity_t    *v,
    GMarkupParseContext *ctx)

{
    if (warn_invalid(v)) {
        return TRUE;
    }
    if (v->validity == NOT_FOUND) {
        gint line, character;
        g_markup_parse_context_get_position(
            ctx, &line, &character);
        g_warning("Missing %s field for record ending at %d:%d",
                  name, line, character);
        return TRUE;
    }
    return FALSE;
}

static void update_ie(
    element_data_t *data)
{
    static uint16_t default_lengths[] = {
        FB_IE_VARLEN,           /* octetArray */
        1, 2, 4, 8,             /* unsigned */
        1, 2, 4, 8,             /* signed */
        4, 8,                   /* float */
        1,                      /* boolean */
        6,                      /* macAddress */
        FB_IE_VARLEN,           /* string */
        4, 8, 8, 8,             /* dateTime */
        4, 16,                  /* address */
        FB_IE_VARLEN, FB_IE_VARLEN, FB_IE_VARLEN /* list */
    };
    static const gchar *non_reversible_groups[] = {
        "config", "processCounter", "netflow v9"
    };

    fbInfoElement_t *ie = &data->ie;

    /* Handle reverse flag */
    if (!ie->ent && data->reversible_validity.validity == NOT_FOUND) {
        size_t i;
        data->reversible = TRUE;
        if (data->group) {
            for (i = 0; i < (sizeof(non_reversible_groups)
                             / sizeof(*non_reversible_groups)); ++i)
            {
                if (strcmp(data->group, non_reversible_groups[i]) == 0) {
                    data->reversible = FALSE;
                    break;
                }
            }
        }
        if (data->reversible) {
            switch (ie->num) {
              case 137: case 148: case 145:
              case 149: case 210: case 239:
                data->reversible = FALSE;
                break;
              default:
                break;
            }
        }
    }
    if (data->reversible) {
        ie->flags |= FB_IE_F_REVERSIBLE;
    }

    /* Handle endian flag */
    if ((ie->type >= FB_UINT_16 && ie->type <= FB_UINT_64)
        || (ie->type >= FB_INT_16 && ie->type <= FB_FLOAT_64)
        || (ie->type >= FB_DT_SEC && ie->type <= FB_IP4_ADDR))
    {
        ie->flags |= FB_IE_F_ENDIAN;
    }

    /* Handle default dataTypeSemantics */
    if (data->dataTypeSemantics_validity.validity == NOT_FOUND) {
        if (ie->type >= FB_UINT_8 && ie->type <= FB_FLOAT_64) {
            /* RFC 7012, 3.2.1 : Quantity is the default semantic of all
             * numeric data types */
            ie->flags |= FB_IE_QUANTITY;
        } else if (ie->type >= FB_BASIC_LIST
                   && ie->type <= FB_SUB_TMPL_MULTI_LIST)
        {
            ie->flags |= FB_IE_LIST;
        }
    }

    /* Default length */
    if (ie->type < sizeof(default_lengths) / sizeof(*default_lengths)) {
        ie->len = default_lengths[ie->type];
    } else {
        ie->len = FB_IE_VARLEN;
    }
}

static void parse_element_end(
    GMarkupParseContext  *ctx,
    const gchar          *element_name,
    gpointer              user_data,
    GError              **error)
{
    guint64 val;
    element_data_t *data = (element_data_t *)user_data;
    UNUSED1(error);
    element_name = ename(element_name);
    if (strcmp(element_name, "record") == 0) {
        if (data->dataType_validity.validity != NOT_FOUND) {
            if (!warn_required("name", &data->name_validity, ctx)
                && !warn_required("elementId", &data->elementId_validity, ctx)
                && !warn_invalid(&data->enterpriseId_validity))
            {
                warn_invalid(&data->dataType_validity);
                warn_invalid(&data->dataTypeSemantics_validity);
                warn_invalid(&data->units_validity);
                warn_invalid(&data->range_validity);
                warn_invalid(&data->reversible_validity);
                warn_invalid(&data->reversible_validity);
                /*g_debug("%s: Adding info element %s",
                        __FILE__, data->ie.ref.name);*/
                update_ie(data);
                fbInfoModelAddElement(data->model, &data->ie);
            }
        }
        data->state = RECORD_SEARCHING;
    }
    if (data->state == RECORD_SEARCHING) {
        return;
    }
    if (data->state == GATHER_TEXT && data->text->len == 0) {
        data->state = IN_RECORD;
        return;
    }

    if (strcmp(element_name, "name") == 0) {
        g_free((void *)data->ie.ref.name);
        data->ie.ref.name = g_strstrip(g_string_free(data->text, FALSE));
        data->text = g_string_sized_new(32);
        data->name_validity.validity = FOUND_VALID;
    } else if (strcmp(element_name, "enterpriseId") == 0) {
        if (parse_as_integer(ctx, data->text, &val,
                             &data->enterpriseId_validity))
        {
            data->ie.ent = val;
        }
    } else if (strcmp(element_name, "elementId") == 0) {
        if (parse_as_integer(ctx, data->text, &val,
                             &data->elementId_validity))
        {
            data->ie.num = val;
        }
    } else if (strcmp(element_name, "dataType") == 0) {
        if (parse_from_map(ctx, datatype_mapping, data->text, &val,
                             &data->dataType_validity))
        {
            data->ie.type = val;
        }
    } else if (strcmp(element_name, "dataTypeSemantics") == 0) {
        if (parse_from_map(ctx, semantic_mapping, data->text, &val,
                             &data->dataTypeSemantics_validity))
        {
            data->ie.flags |= (val & 0xff) << 8;
        }
    } else if (strcmp(element_name, "units") == 0) {
        if (parse_from_map(ctx, unit_mapping, data->text, &val,
                             &data->units_validity))
        {
            data->ie.flags |= (val & 0xffff) << 16;
        }
    } else if (strcmp(element_name, "reversible") == 0) {
        if (strcmp(data->text->str, "1") == 0
            || g_ascii_strcasecmp(data->text->str, "true") == 0
            || g_ascii_strcasecmp(data->text->str, "yes") == 0
            || g_ascii_strcasecmp(data->text->str, "t") == 0
            || g_ascii_strcasecmp(data->text->str, "y") == 0)

        {
            data->reversible = TRUE;
            data->reversible_validity.validity = FOUND_VALID;
        } else if (strcmp(data->text->str, "0") == 0
            || g_ascii_strcasecmp(data->text->str, "false") == 0
            || g_ascii_strcasecmp(data->text->str, "no") == 0
            || g_ascii_strcasecmp(data->text->str, "f") == 0
            || g_ascii_strcasecmp(data->text->str, "n") == 0)
        {
            data->reversible = FALSE;
            data->reversible_validity.validity = FOUND_VALID;
        } else {
            set_invalid(ctx, &data->reversible_validity, "Invalid boolean");
        }
    } else if (strcmp(element_name, "range") == 0) {
        gchar *end;
        guint64 low, high;
        low = g_ascii_strtoull(data->text->str, &end, 0);
        if (end == data->text->str || *end != '-') {
            set_invalid(ctx, &data->range_validity,
                        "Could not parse range");
        } else {
            gchar *loc = end + 1;
            high = g_ascii_strtoull(loc, &end, 0);
            if (end == loc || *end != '\0') {
                set_invalid(ctx, &data->range_validity,
                            "Could not parse range");
            } else {
                data->ie.min = low;
                data->ie.max = high;
                data->range_validity.validity = FOUND_VALID;
            }
        }
    } else if (strcmp(element_name, "group") == 0) {
        g_free(data->group);
        data->group = g_string_free(data->text, FALSE);
        data->text = g_string_sized_new(32);
        data->group_validity.validity = FOUND_VALID;
    } else {
        return;
    }
    data->state = IN_RECORD;
}

static const GMarkupParser element_parser = {
    parse_element_start,
    parse_element_end,
    parse_element_text,
    NULL,
    NULL
};

static gboolean ipfix_elements_parse(
    fbInfoModel_t  *model,
    const gchar    *xml_data,
    gssize          xml_data_len,
    GError        **error)
{
    element_data_t *data;
    GMarkupParseContext *ctx;
    gboolean result;

    init_mappings();
    data = alloc_element_data(model);
    ctx = g_markup_parse_context_new(
        &element_parser, MP_FLAGS, data, destroy_element_data);
    result = g_markup_parse_context_parse(
        ctx, xml_data, xml_data_len, error);
    if (result) {
        result = g_markup_parse_context_end_parse(ctx, error);
    }
    g_markup_parse_context_free(ctx);
    return result;
}

gboolean fbInfoModelReadXMLData(
    fbInfoModel_t  *model,
    const gchar    *xml_data,
    gssize          xml_data_len,
    GError        **error)
{
    g_assert(xml_data);
    if (ipfix_mappings_parse(xml_data, xml_data_len, error)) {
        return ipfix_elements_parse(model, xml_data, xml_data_len, error);
    }
    return FALSE;
}

gboolean fbInfoModelReadXMLFile(
    fbInfoModel_t  *model,
    const gchar    *filename,
    GError        **error)
{
    gchar *buffer;
    gsize len;

    g_assert(filename);
    if (g_file_get_contents(filename, &buffer, &len, error)) {
        gboolean rv = fbInfoModelReadXMLData(model, buffer, len, error);
        g_free(buffer);
        return rv;
    }
    return FALSE;
}
