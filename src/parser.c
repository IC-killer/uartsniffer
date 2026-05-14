/*
 * parser.c  --  Protocol config parser (platform-independent)
 *
 * Extracted from uspy.c.  All error output goes through usp_err().
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

/* ── type parsing ────────────────────────────────────────────────────────── */

static int parse_base_type(const char *tok, DataType *out) {
    if      (!strcmp(tok, "u8"))     { *out = DT_U8;    return 1; }
    else if (!strcmp(tok, "s8"))     { *out = DT_S8;    return 1; }
    else if (!strcmp(tok, "u16"))    { *out = DT_U16;   return 2; }
    else if (!strcmp(tok, "s16"))    { *out = DT_S16;   return 2; }
    else if (!strcmp(tok, "u32"))    { *out = DT_U32;   return 4; }
    else if (!strcmp(tok, "s32"))    { *out = DT_S32;   return 4; }
    else if (!strcmp(tok, "float"))  { *out = DT_FLOAT;  return 4; }
    else if (!strcmp(tok, "double")) { *out = DT_DOUBLE; return 8; }
    return -1;
}

/* ── filter parsing ──────────────────────────────────────────────────────── */

static void parse_filters(const char *block, Rule *rule) {
    char tmp[MAX_LINE_LEN];
    strncpy(tmp, block, MAX_LINE_LEN - 1);
    tmp[MAX_LINE_LEN - 1] = '\0';

    char *ctx = NULL;
#ifdef _WIN32
    char *tok = strtok_s(tmp, ",", &ctx);
#else
    char *tok = strtok_r(tmp, ",", &ctx);
#endif
    while (tok) {
        while (*tok == ' ') tok++;
        Filter f = {0};
        if (str_starts(tok, "len=")) {
            f.type  = FT_LEN;
            f.value = (int)strtol(tok + 4, NULL, 0);
            if (rule->filter_count < MAX_FILTERS)
                rule->filters[rule->filter_count++] = f;
        } else if (str_starts(tok, "idx")) {
            char *eq = strchr(tok, '=');
            if (eq) {
                f.type  = FT_IDX;
                f.idx   = atoi(tok + 3);
                f.value = (int)strtol(eq + 1, NULL, 0);
                if (rule->filter_count < MAX_FILTERS)
                    rule->filters[rule->filter_count++] = f;
            }
        } else {
            usp_err(YEL "[CFG] Unknown filter: '%s'\n" R, tok);
        }
#ifdef _WIN32
        tok = strtok_s(NULL, ",", &ctx);
#else
        tok = strtok_r(NULL, ",", &ctx);
#endif
    }
}

/* ── field parsing ───────────────────────────────────────────────────────── */

static int parse_field(const char *block, Field *fld) {
    char tmp[MAX_LINE_LEN];
    strncpy(tmp, block, MAX_LINE_LEN - 1);
    tmp[MAX_LINE_LEN - 1] = '\0';
    str_trim(tmp);

    fld->label[0]   = '\0';
    fld->array_size  = 0;
    fld->endian      = EO_GLOBAL;

    char *lp = strchr(tmp, '(');
    if (lp) {
        char *rp = strrchr(lp, ')');
        if (!rp) return -1;
        int llen = (int)(rp - lp - 1);
        if (llen > 0 && llen < MAX_LABEL_LEN)
            strncpy(fld->label, lp + 1, llen);
        *lp = '\0';
    }
    str_trim(tmp);

    if (str_starts(tmp, "array-")) {
        int n = atoi(tmp + 6);
        if (n <= 0) {
            usp_err(YEL "[CFG] Invalid array size: %s\n" R, tmp);
            return -1;
        }
        fld->type       = DT_ARRAY;
        fld->array_size = n;
        return 0;
    }

    char type_str[MAX_LABEL_LEN];
    strncpy(type_str, tmp, MAX_LABEL_LEN - 1);
    type_str[MAX_LABEL_LEN - 1] = '\0';
    int tlen = (int)strlen(type_str);
    if (tlen >= 2) {
        char *tail = type_str + tlen - 2;
        if (!strcmp(tail, "le")) { fld->endian = EO_LE; *tail = '\0'; }
        else if (!strcmp(tail, "be")) { fld->endian = EO_BE; *tail = '\0'; }
    }
    DataType dt;
    if (parse_base_type(type_str, &dt) < 0) return -1;
    fld->type = dt;
    return 0;
}

/* ── rule line parsing ───────────────────────────────────────────────────── */

int parse_rule_line(const char *line, Rule *rule) {
    memset(rule, 0, sizeof(Rule));
    char tmp[MAX_LINE_LEN];
    strncpy(tmp, line, MAX_LINE_LEN - 1);
    tmp[MAX_LINE_LEN - 1] = '\0';

    char *hash = strchr(tmp, '#');
    if (hash) {
        char *lbl = hash + 1;
        while (*lbl == ' ') lbl++;
        strncpy(rule->rule_label, lbl, MAX_LABEL_LEN - 1);
        rule->rule_label[MAX_LABEL_LEN - 1] = '\0';
        str_trim(rule->rule_label);
        *hash = '\0';
    }
    str_trim(tmp);
    strncpy(rule->raw, line, MAX_LINE_LEN - 1);
    rule->raw[MAX_LINE_LEN - 1] = '\0';
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
            if (blen > 0) {
                strncpy(block, p + 1, blen);
                block[blen] = '\0';
            } else {
                block[0] = '\0';
            }
            parse_filters(block, rule);
            p = end + 1;
        } else if (*p == '[') {
            const char *end = strchr(p, ']');
            if (!end) { usp_err(RED "[CFG] Unclosed '['\n" R); return -1; }
            char block[MAX_LINE_LEN];
            int blen = (int)(end - p - 1);
            if (blen < 0) blen = 0;
            strncpy(block, p + 1, blen);
            block[blen] = '\0';
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
        if (!line[0] || line[0] == '#' || line[0] == ';') continue;
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
        if (f->type == FT_LEN && (int)len != f->value) return 0;
        if (f->type == FT_IDX) {
            if (f->idx < 0 || (unsigned)f->idx >= len) return 0;
            if ((int)(unsigned char)data[f->idx] != f->value) return 0;
        }
    }
    return 1;
}

int field_size(const Field *fld) {
    switch (fld->type) {
    case DT_U8: case DT_S8:   return 1;
    case DT_U16: case DT_S16: return 2;
    case DT_U32: case DT_S32:
    case DT_FLOAT:            return 4;
    case DT_DOUBLE:           return 8;
    case DT_ARRAY:            return fld->array_size;
    default:                  return 0;
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

/* These helpers are used by uspy.c (the runtime); declare extern in uspy.h? */
/* We keep them here and forward-declare in uspy.c or include parser internals. */
/* For simplicity, we expose wrappers: */
void usp_parser_read_u16le(const unsigned char *p, unsigned short *v) { *v = rd_u16le(p); }
void usp_parser_read_u16be(const unsigned char *p, unsigned short *v) { *v = rd_u16be(p); }
void usp_parser_read_u32le(const unsigned char *p, unsigned *v)       { *v = rd_u32le(p); }
void usp_parser_read_u32be(const unsigned char *p, unsigned *v)       { *v = rd_u32be(p); }
int  usp_parser_use_be(const Field *fld, int cfg_be)                 { return use_be(fld, cfg_be); }
