/*
 * parser.c  --  Protocol config parser (platform-independent)
 *
 * Grammar reference: src/parser_syntax.md
 *
 * Rule syntax:
 *     {<filter>,...} [<field>] [<field>] ... # <rule-label>
 *
 * Field syntax:
 *     [<type>(<label>)<modifier>...]
 *
 *   modifiers (any order, any count):
 *     @<num>                scale factor   (multiply)
 *     +<num> / -<num>       offset         (added after scale)
 *     =<unit>               unit string suffix
 *     %<c>                  display format:  x/d/b/o/c
 *     |<v>=<name>           enum mapping   (repeatable)
 *
 * All error output goes through usp_err().
 */

#include "uspy.h"

/* ── string helpers ──────────────────────────────────────────────────────── */

static void str_trim(char *s) {
    int i = 0;
    while (s[i] == ' ' || s[i] == '\t') i++;
    if (i) memmove(s, s + i, strlen(s + i) + 1);
    int n = (int)strlen(s);
    while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' ||
                     s[n-1] == '\r' || s[n-1] == '\n'))
        s[--n] = '\0';
}

static int str_starts(const char *s, const char *p) {
    return strncmp(s, p, strlen(p)) == 0;
}

/* Safe bounded copy guaranteeing NUL termination. */
static void str_copy_bounded(char *dst, size_t dst_sz,
                             const char *src, size_t src_len) {
    if (dst_sz == 0) return;
    if (src_len >= dst_sz) src_len = dst_sz - 1;
    if (src_len) memcpy(dst, src, src_len);
    dst[src_len] = '\0';
}

/* ── type parsing ────────────────────────────────────────────────────────── */

static int parse_base_type(const char *tok, DataType *out) {
    if      (!strcmp(tok, "u8"))     { *out = DT_U8;     return 1; }
    else if (!strcmp(tok, "s8"))     { *out = DT_S8;     return 1; }
    else if (!strcmp(tok, "u16"))    { *out = DT_U16;    return 2; }
    else if (!strcmp(tok, "s16"))    { *out = DT_S16;    return 2; }
    else if (!strcmp(tok, "u32"))    { *out = DT_U32;    return 4; }
    else if (!strcmp(tok, "s32"))    { *out = DT_S32;    return 4; }
    else if (!strcmp(tok, "float"))  { *out = DT_FLOAT;  return 4; }
    else if (!strcmp(tok, "double")) { *out = DT_DOUBLE; return 8; }
    return -1;
}

/* ── filter parsing ──────────────────────────────────────────────────────── */

static void parse_filters(const char *block, Rule *rule) {
    char tmp[MAX_LINE_LEN];
    str_copy_bounded(tmp, sizeof(tmp), block, strlen(block));

    char *ctx = NULL;
#ifdef _WIN32
    char *tok = strtok_s(tmp, ",", &ctx);
#else
    char *tok = strtok_r(tmp, ",", &ctx);
#endif
    while (tok) {
        while (*tok == ' ' || *tok == '\t') tok++;
        Filter f = {0};
        int added = 0;
        if (str_starts(tok, "len=")) {
            f.type  = FT_LEN;
            f.value = (int)strtol(tok + 4, NULL, 0);
            added = 1;
        } else if (str_starts(tok, "minlen=")) {
            f.type  = FT_MINLEN;
            f.value = (int)strtol(tok + 7, NULL, 0);
            added = 1;
        } else if (str_starts(tok, "maxlen=")) {
            f.type  = FT_MAXLEN;
            f.value = (int)strtol(tok + 7, NULL, 0);
            added = 1;
        } else if (str_starts(tok, "last=")) {
            f.type  = FT_LAST;
            f.value = (int)strtol(tok + 5, NULL, 0);
            added = 1;
        } else if (str_starts(tok, "first=")) {
            /* alias for idx0= */
            f.type  = FT_IDX;
            f.idx   = 0;
            f.value = (int)strtol(tok + 6, NULL, 0);
            added = 1;
        } else if (str_starts(tok, "idx")) {
            char *eq = strchr(tok, '=');
            if (eq) {
                f.type  = FT_IDX;
                f.idx   = atoi(tok + 3);
                f.value = (int)strtol(eq + 1, NULL, 0);
                added = 1;
            }
        } else {
            usp_err(YEL "[CFG] Unknown filter: '%s'\n" R, tok);
        }
        if (added && rule->filter_count < MAX_FILTERS)
            rule->filters[rule->filter_count++] = f;
#ifdef _WIN32
        tok = strtok_s(NULL, ",", &ctx);
#else
        tok = strtok_r(NULL, ",", &ctx);
#endif
    }
}

/* ── field modifier parsing ──────────────────────────────────────────────── */

/* Returns 1 if c marks the start of a new modifier (terminates a value). */
static int is_modifier_start(char c) {
    return c == '@' || c == '+' || c == '-' ||
           c == '=' || c == '%' || c == '|';
}

static void parse_field_modifiers(const char *src, Field *fld) {
    const char *p = src;
    while (*p) {
        char c = *p++;
        if (c == ' ' || c == '\t') continue;

        if (c == '@') {
            char *end = NULL;
            double v = strtod(p, &end);
            if (end != p) {
                fld->scale = v;
                p = end;
            }
        } else if (c == '+' || c == '-') {
            char *end = NULL;
            double v = strtod(p, &end);
            if (end != p) {
                fld->offset = (c == '-') ? -v : v;
                p = end;
            }
        } else if (c == '=') {
            const char *start = p;
            while (*p && !is_modifier_start(*p)) p++;
            int len = (int)(p - start);
            while (len > 0 && (start[len-1] == ' ' || start[len-1] == '\t')) len--;
            str_copy_bounded(fld->unit, sizeof(fld->unit), start, (size_t)len);
        } else if (c == '%') {
            if (*p) { fld->fmt = *p; p++; }
        } else if (c == '|') {
            /* enum entry: <value>=<name> */
            char *eq = strchr(p, '=');
            if (!eq) break;
            long v = strtol(p, NULL, 0);
            const char *name = eq + 1;
            const char *end = name;
            /* enum name extends until next '|' or other modifier */
            while (*end && *end != '|' && *end != '@' && *end != '%') end++;
            int len = (int)(end - name);
            while (len > 0 && (name[len-1] == ' ' || name[len-1] == '\t')) len--;
            if (fld->enum_count < MAX_ENUM_ENTRIES && len > 0) {
                EnumEntry *e = &fld->enums[fld->enum_count++];
                e->value = v;
                str_copy_bounded(e->name, sizeof(e->name), name, (size_t)len);
            }
            p = end;
        } else {
            /* unknown modifier char — skip silently */
        }
    }
}

/* ── field parsing ───────────────────────────────────────────────────────── */

static int parse_field(const char *block, Field *fld) {
    /* zero entire struct so leftover stack bytes can't leak into label/unit/etc. */
    memset(fld, 0, sizeof(*fld));
    fld->endian = EO_GLOBAL;
    fld->scale  = 1.0;
    fld->offset = 0.0;
    fld->fmt    = 0;

    char tmp[MAX_LINE_LEN];
    str_copy_bounded(tmp, sizeof(tmp), block, strlen(block));
    str_trim(tmp);

    /* Split into: type-part, label (inside parens), modifier-part (after ')') */
    char *mod_start = NULL;
    char *lp = strchr(tmp, '(');
    if (lp) {
        char *rp = strrchr(lp, ')');
        if (!rp) return -1;
        int llen = (int)(rp - lp - 1);
        if (llen > 0) {
            str_copy_bounded(fld->label, sizeof(fld->label),
                             lp + 1, (size_t)llen);
        }
        *lp = '\0';
        mod_start = rp + 1;
    }
    str_trim(tmp);

    /* type parsing — check array-/str-/bcd- prefixes before generic base type */
    if (str_starts(tmp, "array-")) {
        int n = atoi(tmp + 6);
        if (n <= 0) { usp_err(YEL "[CFG] Invalid array size: %s\n" R, tmp); return -1; }
        fld->type       = DT_ARRAY;
        fld->array_size = n;
    } else if (str_starts(tmp, "str-")) {
        int n = atoi(tmp + 4);
        if (n <= 0) { usp_err(YEL "[CFG] Invalid str size: %s\n" R, tmp); return -1; }
        fld->type       = DT_STRING;
        fld->array_size = n;
    } else if (str_starts(tmp, "bcd-")) {
        int n = atoi(tmp + 4);
        if (n <= 0) { usp_err(YEL "[CFG] Invalid bcd size: %s\n" R, tmp); return -1; }
        fld->type       = DT_BCD;
        fld->array_size = n;
    } else {
        char type_str[MAX_LABEL_LEN];
        str_copy_bounded(type_str, sizeof(type_str), tmp, strlen(tmp));

        DataType dt;
        if (parse_base_type(type_str, &dt) >= 0) {
            fld->type = dt;
        } else {
            /* try stripping endian suffix le/be (e.g. u16le, s32be) */
            int tlen = (int)strlen(type_str);
            if (tlen >= 2) {
                char *tail = type_str + tlen - 2;
                EndianOverride eo = EO_GLOBAL;
                if      (!strcmp(tail, "le")) { eo = EO_LE; *tail = '\0'; }
                else if (!strcmp(tail, "be")) { eo = EO_BE; *tail = '\0'; }
                else return -1;
                if (parse_base_type(type_str, &dt) < 0) return -1;
                fld->type   = dt;
                fld->endian = eo;
            } else {
                return -1;
            }
        }
    }

    /* parse modifiers (after closing paren) */
    if (mod_start && *mod_start) {
        parse_field_modifiers(mod_start, fld);
    }

    return 0;
}

/* ── rule line parsing ───────────────────────────────────────────────────── */

int parse_rule_line(const char *line, Rule *rule) {
    memset(rule, 0, sizeof(Rule));
    char tmp[MAX_LINE_LEN];
    str_copy_bounded(tmp, sizeof(tmp), line, strlen(line));

    /* extract optional rule-label after '#' */
    char *hash = strchr(tmp, '#');
    if (hash) {
        char *lbl = hash + 1;
        while (*lbl == ' ' || *lbl == '\t') lbl++;
        str_copy_bounded(rule->rule_label, sizeof(rule->rule_label),
                         lbl, strlen(lbl));
        str_trim(rule->rule_label);
        *hash = '\0';
    }
    str_trim(tmp);
    str_copy_bounded(rule->raw, sizeof(rule->raw), line, strlen(line));
    str_trim(rule->raw);

    const char *p = tmp;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (*p == '{') {
            const char *end = strchr(p, '}');
            if (!end) { usp_err(RED "[CFG] Unclosed '{'\n" R); return -1; }
            char block[MAX_LINE_LEN];
            int blen = (int)(end - p - 1);
            if (blen < 0) blen = 0;
            str_copy_bounded(block, sizeof(block), p + 1, (size_t)blen);
            parse_filters(block, rule);
            p = end + 1;
        } else if (*p == '[') {
            const char *end = strchr(p, ']');
            if (!end) { usp_err(RED "[CFG] Unclosed '['\n" R); return -1; }
            char block[MAX_LINE_LEN];
            int blen = (int)(end - p - 1);
            if (blen < 0) blen = 0;
            str_copy_bounded(block, sizeof(block), p + 1, (size_t)blen);
            if (rule->field_count < MAX_FIELDS) {
                Field f;
                if (parse_field(block, &f) == 0)
                    rule->fields[rule->field_count++] = f;
                else
                    usp_err(YEL "[CFG] Unknown field: [%s]\n" R, block);
            }
            p = end + 1;
        } else {
            p++;
        }
    }
    if (!rule->field_count && !rule->filter_count) return -1;
    return 0;
}

/* ── config file loading ─────────────────────────────────────────────────── */

int load_config_into(const char *path, RuleSet *rs) {
    rs->count = 0;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[MAX_LINE_LEN];
    int linenum = 0, loaded = 0;
    while (fgets(line, MAX_LINE_LEN, f)) {
        linenum++;
        str_trim(line);
        if (!line[0] || line[0] == ';') continue;
        /* leading '#' is a comment line, but '#' mid-line is a rule label */
        if (line[0] == '#') continue;
        if (rs->count >= MAX_RULES) break;
        Rule rule;
        if (parse_rule_line(line, &rule) == 0) {
            rs->rules[rs->count++] = rule;
            loaded++;
        } else {
            usp_err(YEL "[CFG] Line %d skipped: %s\n" R, linenum, line);
        }
    }
    fclose(f);
    return loaded;
}

/* ── runtime matching ────────────────────────────────────────────────────── */

int rule_matches(const Rule *rule, const unsigned char *data, unsigned len) {
    for (int i = 0; i < rule->filter_count; i++) {
        const Filter *f = &rule->filters[i];
        switch (f->type) {
        case FT_LEN:
            if ((int)len != f->value) return 0;
            break;
        case FT_MINLEN:
            if ((int)len < f->value) return 0;
            break;
        case FT_MAXLEN:
            if ((int)len > f->value) return 0;
            break;
        case FT_IDX:
            if (f->idx < 0 || (unsigned)f->idx >= len) return 0;
            if ((int)(unsigned char)data[f->idx] != f->value) return 0;
            break;
        case FT_LAST:
            if (len == 0) return 0;
            if ((int)(unsigned char)data[len - 1] != f->value) return 0;
            break;
        }
    }
    return 1;
}

int field_size(const Field *fld) {
    switch (fld->type) {
    case DT_U8: case DT_S8:    return 1;
    case DT_U16: case DT_S16:  return 2;
    case DT_U32: case DT_S32:
    case DT_FLOAT:             return 4;
    case DT_DOUBLE:            return 8;
    case DT_ARRAY:
    case DT_STRING:
    case DT_BCD:               return fld->array_size;
    default:                   return 0;
    }
}

const char *dtype_name(const Field *fld) {
    switch (fld->type) {
    case DT_U8:  return "u8";
    case DT_S8:  return "s8";
    case DT_U16: return fld->endian == EO_BE ? "u16be"
                        : fld->endian == EO_LE ? "u16le" : "u16";
    case DT_S16: return fld->endian == EO_BE ? "s16be"
                        : fld->endian == EO_LE ? "s16le" : "s16";
    case DT_U32: return fld->endian == EO_BE ? "u32be"
                        : fld->endian == EO_LE ? "u32le" : "u32";
    case DT_S32: return fld->endian == EO_BE ? "s32be"
                        : fld->endian == EO_LE ? "s32le" : "s32";
    case DT_FLOAT:  return "float";
    case DT_DOUBLE: return "double";
    case DT_ARRAY:  return "array";
    case DT_STRING: return "str";
    case DT_BCD:    return "bcd";
    default:        return "?";
    }
}

/* ── endian-aware byte readers ───────────────────────────────────────────── */

static unsigned short rd_u16le(const unsigned char *p) {
    return (unsigned short)(p[0] | (p[1] << 8));
}
static unsigned short rd_u16be(const unsigned char *p) {
    return (unsigned short)((p[0] << 8) | p[1]);
}
static unsigned rd_u32le(const unsigned char *p) {
    return (unsigned)(p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned)p[3] << 24));
}
static unsigned rd_u32be(const unsigned char *p) {
    return (unsigned)(((unsigned)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}
static int use_be(const Field *fld, int cfg_be) {
    if (fld->endian == EO_BE) return 1;
    if (fld->endian == EO_LE) return 0;
    return cfg_be;
}

void usp_parser_read_u16le(const unsigned char *p, unsigned short *v) { *v = rd_u16le(p); }
void usp_parser_read_u16be(const unsigned char *p, unsigned short *v) { *v = rd_u16be(p); }
void usp_parser_read_u32le(const unsigned char *p, unsigned *v)       { *v = rd_u32le(p); }
void usp_parser_read_u32be(const unsigned char *p, unsigned *v)       { *v = rd_u32be(p); }
int  usp_parser_use_be(const Field *fld, int cfg_be)                 { return use_be(fld, cfg_be); }
