#include "cjson.h"
#include <assert.h>  /* assert() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <stdio.h>   /* sprintf() */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <string.h>  /* memcpy() */

#ifndef CJSON_PARSE_STACK_INIT_SIZE
#define CJSON_PARSE_STACK_INIT_SIZE 256
#endif

#ifndef CJSON_PARSE_STRINGIFY_INIT_SIZE
#define CJSON_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')
#define PUTC(c, ch)         do { *(char*)cjson_context_push(c, sizeof(char)) = (ch); } while(0)
#define PUTS(c, s, len)     memcpy(cjson_context_push(c, len), s, len)

typedef struct {
    const char* json;
    char* stack;
    size_t size, top;
}cjson_context;

static void* cjson_context_push(cjson_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = CJSON_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;  /* c->size * 1.5 */
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* cjson_context_pop(cjson_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void cjson_parse_whitespace(cjson_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int cjson_parse_literal(cjson_context* c, cjson_value* v, const char* literal, cjson_type type) {
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i + 1]; i++)
        if (c->json[i] != literal[i + 1])
            return CJSON_PARSE_INVALID_VALUE;
    c->json += i;
    v->type = type;
    return CJSON_PARSE_OK;
}

static int cjson_parse_number(cjson_context* c, cjson_value* v) {
    const char* p = c->json;
    if (*p == '-') p++;
    if (*p == '0') p++;
    else {
        if (!ISDIGIT1TO9(*p)) return CJSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p)) return CJSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return CJSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL))
        return CJSON_PARSE_NUMBER_TOO_BIG;
    v->type = CJSON_NUMBER;
    c->json = p;
    return CJSON_PARSE_OK;
}

static const char* cjson_parse_hex4(const char* p, unsigned* u) {
    int i;
    *u = 0;
    for (i = 0; i < 4; i++) {
        char ch = *p++;
        *u <<= 4;
        if      (ch >= '0' && ch <= '9')  *u |= ch - '0';
        else if (ch >= 'A' && ch <= 'F')  *u |= ch - ('A' - 10);
        else if (ch >= 'a' && ch <= 'f')  *u |= ch - ('a' - 10);
        else return NULL;
    }
    return p;
}

static void cjson_encode_utf8(cjson_context* c, unsigned u) {
    if (u <= 0x7F)
        PUTC(c, u & 0xFF);
    else if (u <= 0x7FF) {
        PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
        PUTC(c, 0x80 | ( u       & 0x3F));
    }
    else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
    else {
        assert(u <= 0x10FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
}

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

static int cjson_parse_string_raw(cjson_context* c, char** str, size_t* len) {
    size_t head = c->top;
    unsigned u, u2;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                *len = c->top - head;
                *str = cjson_context_pop(c, *len);
                c->json = p;
                return CJSON_PARSE_OK;
            case '\\':
                switch (*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/' ); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = cjson_parse_hex4(p, &u)))
                            STRING_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX);
                        if (u >= 0xD800 && u <= 0xDBFF) { /* surrogate pair */
                            if (*p++ != '\\')
                                STRING_ERROR(CJSON_PARSE_INVALID_UNICODE_SURROGATE);
                            if (*p++ != 'u')
                                STRING_ERROR(CJSON_PARSE_INVALID_UNICODE_SURROGATE);
                            if (!(p = cjson_parse_hex4(p, &u2)))
                                STRING_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                STRING_ERROR(CJSON_PARSE_INVALID_UNICODE_SURROGATE);
                            u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                        }
                        cjson_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(CJSON_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\0':
                STRING_ERROR(CJSON_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20)
                    STRING_ERROR(CJSON_PARSE_INVALID_STRING_CHAR);
                PUTC(c, ch);
        }
    }
}

static int cjson_parse_string(cjson_context* c, cjson_value* v) {
    int ret;
    char* s;
    size_t len;
    if ((ret = cjson_parse_string_raw(c, &s, &len)) == CJSON_PARSE_OK)
        cjson_set_string(v, s, len);
    return ret;
}

static int cjson_parse_value(cjson_context* c, cjson_value* v);

static int cjson_parse_array(cjson_context* c, cjson_value* v) {
    size_t i, size = 0;
    int ret;
    EXPECT(c, '[');
    cjson_parse_whitespace(c);
    if (*c->json == ']') {
        c->json++;
        cjson_set_array(v, 0);
        return CJSON_PARSE_OK;
    }
    for (;;) {
        cjson_value e;
        cjson_init(&e);
        if ((ret = cjson_parse_value(c, &e)) != CJSON_PARSE_OK)
            break;
        memcpy(cjson_context_push(c, sizeof(cjson_value)), &e, sizeof(cjson_value));
        size++;
        cjson_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            cjson_parse_whitespace(c);
        }
        else if (*c->json == ']') {
            c->json++;
            cjson_set_array(v, size);
            memcpy(v->u.a.e, cjson_context_pop(c, size * sizeof(cjson_value)), size * sizeof(cjson_value));
            v->u.a.size = size;
            return CJSON_PARSE_OK;
        }
        else {
            ret = CJSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    /* Pop and free values on the stack */
    for (i = 0; i < size; i++)
        cjson_free((cjson_value *) cjson_context_pop(c, sizeof(cjson_value)));
    return ret;
}

static int cjson_parse_object(cjson_context* c, cjson_value* v) {
    size_t i, size;
    cjson_member m;
    int ret;
    EXPECT(c, '{');
    cjson_parse_whitespace(c);
    if (*c->json == '}') {
        c->json++;
        cjson_set_object(v, 0);
        return CJSON_PARSE_OK;
    }
    m.k = NULL;
    size = 0;
    for (;;) {
        char* str;
        cjson_init(&m.v);
        /* parse key */
        if (*c->json != '"') {
            ret = CJSON_PARSE_MISS_KEY;
            break;
        }
        if ((ret = cjson_parse_string_raw(c, &str, &m.klen)) != CJSON_PARSE_OK)
            break;
        memcpy(m.k = (char*)malloc(m.klen + 1), str, m.klen);
        m.k[m.klen] = '\0';
        /* parse ws colon ws */
        cjson_parse_whitespace(c);
        if (*c->json != ':') {
            ret = CJSON_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        cjson_parse_whitespace(c);
        /* parse value */
        if ((ret = cjson_parse_value(c, &m.v)) != CJSON_PARSE_OK)
            break;
        memcpy(cjson_context_push(c, sizeof(cjson_member)), &m, sizeof(cjson_member));
        size++;
        m.k = NULL; /* ownership is transferred to member on stack */
        /* parse ws [comma | right-curly-brace] ws */
        cjson_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            cjson_parse_whitespace(c);
        }
        else if (*c->json == '}') {
            c->json++;
            cjson_set_object(v, size);
            memcpy(v->u.o.m, cjson_context_pop(c, sizeof(cjson_member) * size), sizeof(cjson_member) * size);
            v->u.o.size = size;
            return CJSON_PARSE_OK;
        }
        else {
            ret = CJSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    /* Pop and free members on the stack */
    free(m.k);
    for (i = 0; i < size; i++) {
        cjson_member* m = (cjson_member*)cjson_context_pop(c, sizeof(cjson_member));
        free(m->k);
        cjson_free(&m->v);
    }
    v->type = CJSON_NULL;
    return ret;
}

static int cjson_parse_value(cjson_context* c, cjson_value* v) {
    switch (*c->json) {
        case 't':  return cjson_parse_literal(c, v, "true", CJSON_TRUE);
        case 'f':  return cjson_parse_literal(c, v, "false", CJSON_FALSE);
        case 'n':  return cjson_parse_literal(c, v, "null", CJSON_NULL);
        default:   return cjson_parse_number(c, v);
        case '"':  return cjson_parse_string(c, v);
        case '[':  return cjson_parse_array(c, v);
        case '{':  return cjson_parse_object(c, v);
        case '\0': return CJSON_PARSE_EXPECT_VALUE;
    }
}

int cjson_parse(cjson_value* v, const char* json) {
    cjson_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    cjson_init(v);
    cjson_parse_whitespace(&c);
    if ((ret = cjson_parse_value(&c, v)) == CJSON_PARSE_OK) {
        cjson_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = CJSON_NULL;
            ret = CJSON_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

static void cjson_stringify_string(cjson_context* c, const char* s, size_t len) {
    static const char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    size_t i, size;
    char* head, *p;
    assert(s != NULL);
    p = head = cjson_context_push(c, size = len * 6 + 2); /* "\u00xx..." */
    *p++ = '"';
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
            case '\"': *p++ = '\\'; *p++ = '\"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\b': *p++ = '\\'; *p++ = 'b';  break;
            case '\f': *p++ = '\\'; *p++ = 'f';  break;
            case '\n': *p++ = '\\'; *p++ = 'n';  break;
            case '\r': *p++ = '\\'; *p++ = 'r';  break;
            case '\t': *p++ = '\\'; *p++ = 't';  break;
            default:
                if (ch < 0x20) {
                    *p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
                    *p++ = hex_digits[ch >> 4];
                    *p++ = hex_digits[ch & 15];
                }
                else
                    *p++ = s[i];
        }
    }
    *p++ = '"';
    c->top -= size - (p - head);
}

static void cjson_stringify_value(cjson_context* c, const cjson_value* v) {
    size_t i;
    switch (v->type) {
        case CJSON_NULL:   PUTS(c, "null", 4); break;
        case CJSON_FALSE:  PUTS(c, "false", 5); break;
        case CJSON_TRUE:   PUTS(c, "true", 4); break;
        case CJSON_NUMBER: c->top -= 32 - sprintf(cjson_context_push(c, 32), "%.17g", v->u.n); break;
        case CJSON_STRING: cjson_stringify_string(c, v->u.s.s, v->u.s.len); break;
        case CJSON_ARRAY:
            PUTC(c, '[');
            for (i = 0; i < v->u.a.size; i++) {
                if (i > 0)
                    PUTC(c, ',');
                cjson_stringify_value(c, &v->u.a.e[i]);
            }
            PUTC(c, ']');
            break;
        case CJSON_OBJECT:
            PUTC(c, '{');
            for (i = 0; i < v->u.o.size; i++) {
                if (i > 0)
                    PUTC(c, ',');
                cjson_stringify_string(c, v->u.o.m[i].k, v->u.o.m[i].klen);
                PUTC(c, ':');
                cjson_stringify_value(c, &v->u.o.m[i].v);
            }
            PUTC(c, '}');
            break;
        default: assert(0 && "invalid type");
    }
}

char* cjson_stringify(const cjson_value* v, size_t* length) {
    cjson_context c;
    assert(v != NULL);
    c.stack = (char*)malloc(c.size = CJSON_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    cjson_stringify_value(&c, v);
    if (length)
        *length = c.top;
    PUTC(&c, '\0');
    return c.stack;
}

void cjson_copy(cjson_value *dst, const cjson_value *src)
{
    size_t i;
    assert(src != NULL && dst != NULL && src != dst);
    switch (src->type) {
        case CJSON_STRING:
            cjson_set_string(dst, src->u.s.s, src->u.s.len);
            break;
        case CJSON_ARRAY:
            cjson_set_array(dst, src->u.a.size);
            for(i = 0; i != src->u.a.size; ++i) {
                cjson_init(dst->u.a.e + i);
                cjson_copy(dst->u.a.e + i, src->u.a.e + i);
            }
            dst->u.a.size = src->u.a.size;
            break;
        case CJSON_OBJECT:
            cjson_set_object(dst, src->u.o.size);
            for(i = 0; i != src->u.o.size; ++i) {
                dst->u.o.m[i].klen = src->u.o.m[i].klen;
                dst->u.o.m[i].k = (char *)malloc(dst->u.o.m[i].klen + 1);
                memcpy(dst->u.o.m[i].k, src->u.o.m[i].k, dst->u.o.m[i].klen);
                dst->u.o.m[i].k[dst->u.o.m[i].klen] = '\0';
                cjson_init(&dst->u.o.m[i].v);
                cjson_copy(&dst->u.o.m[i].v, &src->u.o.m[i].v);
            }
            dst->u.o.size = src->u.o.size;
            break;
        default:
            cjson_free(dst);
            memcpy(dst, src, sizeof(cjson_value));
            break;
    }
}

void cjson_move(cjson_value* dst, cjson_value* src) {
    assert(dst != NULL && src != NULL && src != dst);
    cjson_free(dst);
    memcpy(dst, src, sizeof(cjson_value));
    cjson_init(src);
}

void cjson_swap(cjson_value* lhs, cjson_value* rhs) {
    assert(lhs != NULL && rhs != NULL);
    if (lhs != rhs) {
        cjson_value temp;
        memcpy(&temp, lhs, sizeof(cjson_value));
        memcpy(lhs,   rhs, sizeof(cjson_value));
        memcpy(rhs, &temp, sizeof(cjson_value));
    }
}

void cjson_free(cjson_value* v) {
    size_t i;
    assert(v != NULL);
    switch (v->type) {
        case CJSON_STRING:
            free(v->u.s.s);
            break;
        case CJSON_ARRAY:
            for (i = 0; i < v->u.a.size; i++)
                cjson_free(&v->u.a.e[i]);
            free(v->u.a.e);
            break;
        case CJSON_OBJECT:
            for (i = 0; i < v->u.o.size; i++) {
                free(v->u.o.m[i].k);
                cjson_free(&v->u.o.m[i].v);
            }
            free(v->u.o.m);
            break;
        default: break;
    }
    v->type = CJSON_NULL;
}

cjson_type cjson_get_type(const cjson_value* v) {
    assert(v != NULL);
    return v->type;
}

int cjson_is_equal(const cjson_value* lhs, const cjson_value* rhs) {
    size_t i;
    assert(lhs != NULL && rhs != NULL);
    if (lhs->type != rhs->type)
        return 0;
    switch (lhs->type) {
        case CJSON_STRING:
            return lhs->u.s.len == rhs->u.s.len &&
                   memcmp(lhs->u.s.s, rhs->u.s.s, lhs->u.s.len) == 0;
        case CJSON_NUMBER:
            return lhs->u.n == rhs->u.n;
        case CJSON_ARRAY:
            if (lhs->u.a.size != rhs->u.a.size)
                return 0;
            for (i = 0; i < lhs->u.a.size; i++)
                if (!cjson_is_equal(&lhs->u.a.e[i], &rhs->u.a.e[i]))
                    return 0;
            return 1;
        case CJSON_OBJECT:
            if (lhs->u.o.size != rhs->u.o.size) {
                return 0;
            }
            for (i = 0; i < lhs->u.o.size; i++) {
                cjson_value *v = cjson_find_object_value(rhs, lhs->u.o.m[i].k, lhs->u.o.m[i].klen);
                if (!v || !cjson_is_equal(&lhs->u.o.m[i].v, v)) {
                    return 0;
                }
            }
            return 1;
        default:
            return 1;
    }
}

int cjson_get_boolean(const cjson_value* v) {
    assert(v != NULL && (v->type == CJSON_TRUE || v->type == CJSON_FALSE));
    return v->type == CJSON_TRUE;
}

void cjson_set_boolean(cjson_value* v, int b) {
    cjson_free(v);
    v->type = b ? CJSON_TRUE : CJSON_FALSE;
}

double cjson_get_number(const cjson_value* v) {
    assert(v != NULL && v->type == CJSON_NUMBER);
    return v->u.n;
}

void cjson_set_number(cjson_value* v, double n) {
    cjson_free(v);
    v->u.n = n;
    v->type = CJSON_NUMBER;
}

const char* cjson_get_string(const cjson_value* v) {
    assert(v != NULL && v->type == CJSON_STRING);
    return v->u.s.s;
}

size_t cjson_get_string_length(const cjson_value* v) {
    assert(v != NULL && v->type == CJSON_STRING);
    return v->u.s.len;
}

void cjson_set_string(cjson_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    cjson_free(v);
    v->u.s.s = (char*)malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = CJSON_STRING;
}

void cjson_set_array(cjson_value* v, size_t capacity) {
    assert(v != NULL);
    cjson_free(v);
    v->type = CJSON_ARRAY;
    v->u.a.size = 0;
    v->u.a.capacity = capacity;
    v->u.a.e = capacity > 0 ? (cjson_value*)malloc(capacity * sizeof(cjson_value)) : NULL;
}

size_t cjson_get_array_size(const cjson_value* v) {
    assert(v != NULL && v->type == CJSON_ARRAY);
    return v->u.a.size;
}

size_t cjson_get_array_capacity(const cjson_value* v) {
    assert(v != NULL && v->type == CJSON_ARRAY);
    return v->u.a.capacity;
}

void cjson_reserve_array(cjson_value* v, size_t capacity) {
    assert(v != NULL && v->type == CJSON_ARRAY);
    if (v->u.a.capacity < capacity) {
        v->u.a.capacity = capacity;
        v->u.a.e = (cjson_value*)realloc(v->u.a.e, capacity * sizeof(cjson_value));
    }
}

void cjson_shrink_array(cjson_value* v) {
    assert(v != NULL && v->type == CJSON_ARRAY);
    if (v->u.a.capacity > v->u.a.size) {
        v->u.a.capacity = v->u.a.size;
        v->u.a.e = (cjson_value*)realloc(v->u.a.e, v->u.a.capacity * sizeof(cjson_value));
    }
}

void cjson_clear_array(cjson_value* v) {
    assert(v != NULL && v->type == CJSON_ARRAY);
    cjson_erase_array_element(v, 0, v->u.a.size);
}

cjson_value* cjson_get_array_element(cjson_value* v, size_t index) {
    assert(v != NULL && v->type == CJSON_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}

cjson_value* cjson_pushback_array_element(cjson_value* v) {
    assert(v != NULL && v->type == CJSON_ARRAY);
    if (v->u.a.size == v->u.a.capacity)
        cjson_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
    cjson_init(&v->u.a.e[v->u.a.size]);
    return &v->u.a.e[v->u.a.size++];
}

void cjson_popback_array_element(cjson_value* v) {
    assert(v != NULL && v->type == CJSON_ARRAY && v->u.a.size > 0);
    cjson_free(&v->u.a.e[--v->u.a.size]);
}

cjson_value* cjson_insert_array_element(cjson_value* v, size_t index) {
    size_t i;
    assert(v != NULL && v->type == CJSON_ARRAY && index <= v->u.a.size);
    if (v->u.a.size == v->u.a.capacity) {
        cjson_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
    }
    for(i = v->u.a.size++; i != index; --i) {
        v->u.a.e[i] = v->u.a.e[i - 1];
    }
    return &v->u.a.e[index];
}

void cjson_erase_array_element(cjson_value* v, size_t index, size_t count) {
    assert(v != NULL && v->type == CJSON_ARRAY && index + count <= v->u.a.size);
    size_t i;
    if(!count) {
        return;
    }
    for(i = index; i != index + count; ++i) {
        cjson_free(&v->u.a.e[i]);
        v->u.a.e[i] = v->u.a.e[i + count];
    }
    for(i = index + count; i != v->u.a.size; ++i) {
        v->u.a.e[i] = v->u.a.e[i + count];
    }
    v->u.a.size -= count;
}

void cjson_set_object(cjson_value* v, size_t capacity) {
    assert(v != NULL);
    cjson_free(v);
    v->type = CJSON_OBJECT;
    v->u.o.size = 0;
    v->u.o.capacity = capacity;
    v->u.o.m = capacity > 0 ? (cjson_member*)malloc(capacity * sizeof(cjson_member)) : NULL;
}

size_t cjson_get_object_size(const cjson_value* v) {
    assert(v != NULL && v->type == CJSON_OBJECT);
    return v->u.o.size;
}

size_t cjson_get_object_capacity(const cjson_value* v) {
    assert(v != NULL && v->type == CJSON_OBJECT);
    return v->u.o.capacity;
}

void cjson_reserve_object(cjson_value* v, size_t capacity) {
    assert(v != NULL && v->type == CJSON_OBJECT);
    if (v->u.o.capacity < capacity) {
        v->u.o.capacity = capacity;
        v->u.o.m = (cjson_member *)realloc(v->u.o.m, capacity * sizeof(cjson_member));
    }
}

void cjson_shrink_object(cjson_value* v) {
    assert(v != NULL && v->type == CJSON_OBJECT);
    if(v->u.o.size < v->u.o.capacity) {
        v->u.o.capacity = v->u.o.size;
        v->u.o.m = (cjson_member *)realloc(v->u.o.m, v->u.o.size * sizeof(cjson_member));
    }
}

void cjson_clear_object(cjson_value* v) {
    assert(v != NULL && v->type == CJSON_OBJECT);
    while(v->u.o.size > 0) {
        cjson_member *m = &v->u.o.m[--v->u.o.size];
        free(m->k);
        cjson_free(&m->v);
    }
}

const char* cjson_get_object_key(const cjson_value* v, size_t index) {
    assert(v != NULL && v->type == CJSON_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t cjson_get_object_key_length(const cjson_value* v, size_t index) {
    assert(v != NULL && v->type == CJSON_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

cjson_value* cjson_get_object_value(cjson_value* v, size_t index) {
    assert(v != NULL && v->type == CJSON_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}

size_t cjson_find_object_index(const cjson_value* v, const char* key, size_t klen) {
    size_t i;
    assert(v != NULL && v->type == CJSON_OBJECT && key != NULL);
    for (i = 0; i < v->u.o.size; i++)
        if (v->u.o.m[i].klen == klen && memcmp(v->u.o.m[i].k, key, klen) == 0)
            return i;
    return CJSON_KEY_NOT_EXIST;
}

cjson_value* cjson_find_object_value(cjson_value* v, const char* key, size_t klen) {
    size_t index = cjson_find_object_index(v, key, klen);
    return index != CJSON_KEY_NOT_EXIST ? &v->u.o.m[index].v : NULL;
}

cjson_value* cjson_set_object_value(cjson_value* v, const char* key, size_t klen) {
    assert(v != NULL && v->type == CJSON_OBJECT && key != NULL);
    size_t index = cjson_find_object_index(v, key, klen);
    if(index != CJSON_KEY_NOT_EXIST) {   /* avoid adding duplicate keys */
        return &v->u.o.m[index].v;
    }
    if(v->u.o.size == v->u.o.capacity) {
        cjson_reserve_object(v, v->u.o.capacity ? 2 * v->u.o.capacity : 1);
    }
    v->u.o.m[v->u.o.size].k = (char *)malloc((klen + 1) * sizeof(char));
    memcpy(v->u.o.m[v->u.o.size].k, key, klen);
    v->u.o.m[v->u.o.size].k[klen] = '\0';
    v->u.o.m[v->u.o.size].klen = klen;
    cjson_init(&v->u.o.m[v->u.o.size].v);
    return &v->u.o.m[v->u.o.size++].v;
}

void cjson_remove_object_value(cjson_value* v, size_t index) {
    assert(v != NULL && v->type == CJSON_OBJECT && index < v->u.o.size);
    free(v->u.o.m[index].k);
    cjson_free(&v->u.o.m[index].v);
    while(index <= v->u.o.size - 2) {
        v->u.o.m[index] = v->u.o.m[index + 1];
        ++index;
    }
    --v->u.o.size;
}
