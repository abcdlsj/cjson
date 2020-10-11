#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cjson.h"

static int main_ret = 0;
static int test_count = 0;
static int test_pass = 0;

#define EXPECT_EQ_BASE(equality, expect, actual, format) \
    do {\
        test_count++;\
        if (equality)\
            test_pass++;\
        else {\
            fprintf(stderr, "%s:%d: expect: " format " actual: " format "\n", __FILE__, __LINE__, expect, actual);\
            main_ret = 1;\
        }\
    } while(0)

#define EXPECT_EQ_INT(expect, actual) EXPECT_EQ_BASE((expect) == (actual), expect, actual, "%d")
#define EXPECT_EQ_DOUBLE(expect, actual) EXPECT_EQ_BASE((expect) == (actual), expect, actual, "%.17g")
#define EXPECT_EQ_STRING(expect, actual, alength) \
    EXPECT_EQ_BASE(sizeof(expect) - 1 == alength && memcmp(expect, actual, alength + 1) == 0, expect, actual, "%s")
#define EXPECT_TRUE(actual) EXPECT_EQ_BASE((actual) != 0, "true", "false", "%s")
#define EXPECT_FALSE(actual) EXPECT_EQ_BASE((actual) == 0, "false", "true", "%s")

#if defined(_MSC_VER)
#define EXPECT_EQ_SIZE_T(expect, actual) EXPECT_EQ_BASE((expect) == (actual), (size_t)expect, (size_t)actual, "%Iu")
#else
#define EXPECT_EQ_SIZE_T(expect, actual) EXPECT_EQ_BASE((expect) == (actual), (size_t)expect, (size_t)actual, "%zu")
#endif

static void test_parse_null() {
    cjson_value v;
    cjson_init(&v);
    cjson_set_boolean(&v, 0);
    EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v, "null"));
    EXPECT_EQ_INT(CJSON_NULL, cjson_get_type(&v));
    cjson_free(&v);
}

static void test_parse_true() {
    cjson_value v;
    cjson_init(&v);
    cjson_set_boolean(&v, 0);
    EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v, "true"));
    EXPECT_EQ_INT(CJSON_TRUE, cjson_get_type(&v));
    cjson_free(&v);
}

static void test_parse_false() {
    cjson_value v;
    cjson_init(&v);
    cjson_set_boolean(&v, 1);
    EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v, "false"));
    EXPECT_EQ_INT(CJSON_FALSE, cjson_get_type(&v));
    cjson_free(&v);
}

#define TEST_NUMBER(expect, json)\
    do {\
        cjson_value v;\
        cjson_init(&v);\
        EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v, json));\
        EXPECT_EQ_INT(CJSON_NUMBER, cjson_get_type(&v));\
        EXPECT_EQ_DOUBLE(expect, cjson_get_number(&v));\
        cjson_free(&v);\
    } while(0)

static void test_parse_number() {
    TEST_NUMBER(0.0, "0");
    TEST_NUMBER(0.0, "-0");
    TEST_NUMBER(0.0, "-0.0");
    TEST_NUMBER(1.0, "1");
    TEST_NUMBER(-1.0, "-1");
    TEST_NUMBER(1.5, "1.5");
    TEST_NUMBER(-1.5, "-1.5");
    TEST_NUMBER(3.1416, "3.1416");
    TEST_NUMBER(1E10, "1E10");
    TEST_NUMBER(1e10, "1e10");
    TEST_NUMBER(1E+10, "1E+10");
    TEST_NUMBER(1E-10, "1E-10");
    TEST_NUMBER(-1E10, "-1E10");
    TEST_NUMBER(-1e10, "-1e10");
    TEST_NUMBER(-1E+10, "-1E+10");
    TEST_NUMBER(-1E-10, "-1E-10");
    TEST_NUMBER(1.234E+10, "1.234E+10");
    TEST_NUMBER(1.234E-10, "1.234E-10");
    TEST_NUMBER(0.0, "1e-10000"); /* must underflow */

    TEST_NUMBER(1.0000000000000002, "1.0000000000000002"); /* the smallest number > 1 */
    TEST_NUMBER( 4.9406564584124654e-324, "4.9406564584124654e-324"); /* minimum denormal */
    TEST_NUMBER(-4.9406564584124654e-324, "-4.9406564584124654e-324");
    TEST_NUMBER( 2.2250738585072009e-308, "2.2250738585072009e-308");  /* Max subnormal double */
    TEST_NUMBER(-2.2250738585072009e-308, "-2.2250738585072009e-308");
    TEST_NUMBER( 2.2250738585072014e-308, "2.2250738585072014e-308");  /* Min normal positive double */
    TEST_NUMBER(-2.2250738585072014e-308, "-2.2250738585072014e-308");
    TEST_NUMBER( 1.7976931348623157e+308, "1.7976931348623157e+308");  /* Max double */
    TEST_NUMBER(-1.7976931348623157e+308, "-1.7976931348623157e+308");
}

#define TEST_STRING(expect, json)\
    do {\
        cjson_value v;\
        cjson_init(&v);\
        EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v, json));\
        EXPECT_EQ_INT(CJSON_STRING, cjson_get_type(&v));\
        EXPECT_EQ_STRING(expect, cjson_get_string(&v), cjson_get_string_length(&v));\
        cjson_free(&v);\
    } while(0)

static void test_parse_string() {
    TEST_STRING("", "\"\"");
    TEST_STRING("Hello", "\"Hello\"");
    TEST_STRING("Hello\nWorld", "\"Hello\\nWorld\"");
    TEST_STRING("\" \\ / \b \f \n \r \t", "\"\\\" \\\\ \\/ \\b \\f \\n \\r \\t\"");
    TEST_STRING("Hello\0World", "\"Hello\\u0000World\"");
    TEST_STRING("\x24", "\"\\u0024\"");         /* Dollar sign U+0024 */
    TEST_STRING("\xC2\xA2", "\"\\u00A2\"");     /* Cents sign U+00A2 */
    TEST_STRING("\xE2\x82\xAC", "\"\\u20AC\""); /* Euro sign U+20AC */
    TEST_STRING("\xF0\x9D\x84\x9E", "\"\\uD834\\uDD1E\"");  /* G clef sign U+1D11E */
    TEST_STRING("\xF0\x9D\x84\x9E", "\"\\ud834\\udd1e\"");  /* G clef sign U+1D11E */
}

static void test_parse_array() {
    size_t i, j;
    cjson_value v;

    cjson_init(&v);
    EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v, "[ ]"));
    EXPECT_EQ_INT(CJSON_ARRAY, cjson_get_type(&v));
    EXPECT_EQ_SIZE_T(0, cjson_get_array_size(&v));
    cjson_free(&v);

    cjson_init(&v);
    EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v, "[ null , false , true , 123 , \"abc\" ]"));
    EXPECT_EQ_INT(CJSON_ARRAY, cjson_get_type(&v));
    EXPECT_EQ_SIZE_T(5, cjson_get_array_size(&v));
    EXPECT_EQ_INT(CJSON_NULL, cjson_get_type(cjson_get_array_element(&v, 0)));
    EXPECT_EQ_INT(CJSON_FALSE, cjson_get_type(cjson_get_array_element(&v, 1)));
    EXPECT_EQ_INT(CJSON_TRUE, cjson_get_type(cjson_get_array_element(&v, 2)));
    EXPECT_EQ_INT(CJSON_NUMBER, cjson_get_type(cjson_get_array_element(&v, 3)));
    EXPECT_EQ_INT(CJSON_STRING, cjson_get_type(cjson_get_array_element(&v, 4)));
    EXPECT_EQ_DOUBLE(123.0, cjson_get_number(cjson_get_array_element(&v, 3)));
    EXPECT_EQ_STRING("abc", cjson_get_string(cjson_get_array_element(&v, 4)),
                     cjson_get_string_length(cjson_get_array_element(&v, 4)));
    cjson_free(&v);

    cjson_init(&v);
    EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v, "[ [ ] , [ 0 ] , [ 0 , 1 ] , [ 0 , 1 , 2 ] ]"));
    EXPECT_EQ_INT(CJSON_ARRAY, cjson_get_type(&v));
    EXPECT_EQ_SIZE_T(4, cjson_get_array_size(&v));
    for (i = 0; i < 4; i++) {
        cjson_value* a = cjson_get_array_element(&v, i);
        EXPECT_EQ_INT(CJSON_ARRAY, cjson_get_type(a));
        EXPECT_EQ_SIZE_T(i, cjson_get_array_size(a));
        for (j = 0; j < i; j++) {
            cjson_value* e = cjson_get_array_element(a, j);
            EXPECT_EQ_INT(CJSON_NUMBER, cjson_get_type(e));
            EXPECT_EQ_DOUBLE((double)j, cjson_get_number(e));
        }
    }
    cjson_free(&v);
}

static void test_parse_object() {
    cjson_value v;
    size_t i;

    cjson_init(&v);
    EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v, " { } "));
    EXPECT_EQ_INT(CJSON_OBJECT, cjson_get_type(&v));
    EXPECT_EQ_SIZE_T(0, cjson_get_object_size(&v));
    cjson_free(&v);

    cjson_init(&v);
    EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v,
                                              " { "
                                              "\"n\" : null , "
                                              "\"f\" : false , "
                                              "\"t\" : true , "
                                              "\"i\" : 123 , "
                                              "\"s\" : \"abc\", "
                                              "\"a\" : [ 1, 2, 3 ],"
                                              "\"o\" : { \"1\" : 1, \"2\" : 2, \"3\" : 3 }"
                                              " } "
    ));
    EXPECT_EQ_INT(CJSON_OBJECT, cjson_get_type(&v));
    EXPECT_EQ_SIZE_T(7, cjson_get_object_size(&v));
    EXPECT_EQ_STRING("n", cjson_get_object_key(&v, 0), cjson_get_object_key_length(&v, 0));
    EXPECT_EQ_INT(CJSON_NULL, cjson_get_type(cjson_get_object_value(&v, 0)));
    EXPECT_EQ_STRING("f", cjson_get_object_key(&v, 1), cjson_get_object_key_length(&v, 1));
    EXPECT_EQ_INT(CJSON_FALSE, cjson_get_type(cjson_get_object_value(&v, 1)));
    EXPECT_EQ_STRING("t", cjson_get_object_key(&v, 2), cjson_get_object_key_length(&v, 2));
    EXPECT_EQ_INT(CJSON_TRUE, cjson_get_type(cjson_get_object_value(&v, 2)));
    EXPECT_EQ_STRING("i", cjson_get_object_key(&v, 3), cjson_get_object_key_length(&v, 3));
    EXPECT_EQ_INT(CJSON_NUMBER, cjson_get_type(cjson_get_object_value(&v, 3)));
    EXPECT_EQ_DOUBLE(123.0, cjson_get_number(cjson_get_object_value(&v, 3)));
    EXPECT_EQ_STRING("s", cjson_get_object_key(&v, 4), cjson_get_object_key_length(&v, 4));
    EXPECT_EQ_INT(CJSON_STRING, cjson_get_type(cjson_get_object_value(&v, 4)));
    EXPECT_EQ_STRING("abc", cjson_get_string(cjson_get_object_value(&v, 4)),
                     cjson_get_string_length(cjson_get_object_value(&v, 4)));
    EXPECT_EQ_STRING("a", cjson_get_object_key(&v, 5), cjson_get_object_key_length(&v, 5));
    EXPECT_EQ_INT(CJSON_ARRAY, cjson_get_type(cjson_get_object_value(&v, 5)));
    EXPECT_EQ_SIZE_T(3, cjson_get_array_size(cjson_get_object_value(&v, 5)));
    for (i = 0; i < 3; i++) {
        cjson_value* e = cjson_get_array_element(cjson_get_object_value(&v, 5), i);
        EXPECT_EQ_INT(CJSON_NUMBER, cjson_get_type(e));
        EXPECT_EQ_DOUBLE(i + 1.0, cjson_get_number(e));
    }
    EXPECT_EQ_STRING("o", cjson_get_object_key(&v, 6), cjson_get_object_key_length(&v, 6));
    {
        cjson_value* o = cjson_get_object_value(&v, 6);
        EXPECT_EQ_INT(CJSON_OBJECT, cjson_get_type(o));
        for (i = 0; i < 3; i++) {
            cjson_value* ov = cjson_get_object_value(o, i);
            EXPECT_TRUE('1' + i == cjson_get_object_key(o, i)[0]);
            EXPECT_EQ_SIZE_T(1, cjson_get_object_key_length(o, i));
            EXPECT_EQ_INT(CJSON_NUMBER, cjson_get_type(ov));
            EXPECT_EQ_DOUBLE(i + 1.0, cjson_get_number(ov));
        }
    }
    cjson_free(&v);
}

#define TEST_PARSE_ERROR(error, json)\
    do {\
        cjson_value v;\
        cjson_init(&v);\
        v.type = CJSON_FALSE;\
        EXPECT_EQ_INT(error, cjson_parse(&v, json));\
        EXPECT_EQ_INT(CJSON_NULL, cjson_get_type(&v));\
        cjson_free(&v);\
    } while(0)

static void test_parse_expect_value() {
    TEST_PARSE_ERROR(CJSON_PARSE_EXPECT_VALUE, "");
    TEST_PARSE_ERROR(CJSON_PARSE_EXPECT_VALUE, " ");
}

static void test_parse_invalid_value() {
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "nul");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "?");

    /* invalid number */
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "+0");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "+1");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, ".123"); /* at least one digit before '.' */
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "1.");   /* at least one digit after '.' */
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "INF");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "inf");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "NAN");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "nan");

    /* invalid value in array */
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "[1,]");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_VALUE, "[\"a\", nul]");
}

static void test_parse_root_not_singular() {
    TEST_PARSE_ERROR(CJSON_PARSE_ROOT_NOT_SINGULAR, "null x");

    /* invalid number */
    TEST_PARSE_ERROR(CJSON_PARSE_ROOT_NOT_SINGULAR, "0123"); /* after zero should be '.' or nothing */
    TEST_PARSE_ERROR(CJSON_PARSE_ROOT_NOT_SINGULAR, "0x0");
    TEST_PARSE_ERROR(CJSON_PARSE_ROOT_NOT_SINGULAR, "0x123");
}

static void test_parse_number_too_big() {
    TEST_PARSE_ERROR(CJSON_PARSE_NUMBER_TOO_BIG, "1e309");
    TEST_PARSE_ERROR(CJSON_PARSE_NUMBER_TOO_BIG, "-1e309");
}

static void test_parse_miss_quotation_mark() {
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_QUOTATION_MARK, "\"");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_QUOTATION_MARK, "\"abc");
}

static void test_parse_invalid_string_escape() {
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_STRING_ESCAPE, "\"\\v\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_STRING_ESCAPE, "\"\\'\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_STRING_ESCAPE, "\"\\0\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_STRING_ESCAPE, "\"\\x12\"");
}

static void test_parse_invalid_string_char() {
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_STRING_CHAR, "\"\x01\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_STRING_CHAR, "\"\x1F\"");
}

static void test_parse_invalid_unicode_hex() {
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u0\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u01\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u012\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u/000\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\uG000\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u0/00\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u0G00\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u0/00\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u00G0\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u000/\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u000G\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_HEX, "\"\\u 123\"");
}

static void test_parse_invalid_unicode_surrogate() {
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uDBFF\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\\\\\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\\uDBFF\"");
    TEST_PARSE_ERROR(CJSON_PARSE_INVALID_UNICODE_SURROGATE, "\"\\uD800\\uE000\"");
}

static void test_parse_miss_comma_or_square_bracket() {
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1}");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1 2");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[[]");
}

static void test_parse_miss_key() {
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_KEY, "{:1,");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_KEY, "{1:1,");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_KEY, "{true:1,");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_KEY, "{false:1,");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_KEY, "{null:1,");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_KEY, "{[]:1,");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_KEY, "{{}:1,");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_KEY, "{\"a\":1,");
}

static void test_parse_miss_colon() {
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_COLON, "{\"a\"}");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_COLON, "{\"a\",\"b\"}");
}

static void test_parse_miss_comma_or_curly_bracket() {
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":1");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":1]");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":1 \"b\"");
    TEST_PARSE_ERROR(CJSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET, "{\"a\":{}");
}

static void test_parse() {
    test_parse_null();
    test_parse_true();
    test_parse_false();
    test_parse_number();
    test_parse_string();
    test_parse_array();
    test_parse_object();

    test_parse_expect_value();
    test_parse_invalid_value();
    test_parse_root_not_singular();
    test_parse_number_too_big();
    test_parse_miss_quotation_mark();
    test_parse_invalid_string_escape();
    test_parse_invalid_string_char();
    test_parse_invalid_unicode_hex();
    test_parse_invalid_unicode_surrogate();
    test_parse_miss_comma_or_square_bracket();
    test_parse_miss_key();
    test_parse_miss_colon();
    test_parse_miss_comma_or_curly_bracket();
}

#define TEST_ROUNDTRIP(json)\
    do {\
        cjson_value v;\
        char* json2;\
        size_t length;\
        cjson_init(&v);\
        EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v, json));\
        json2 = cjson_stringify(&v, &length);\
        EXPECT_EQ_STRING(json, json2, length);\
        cjson_free(&v);\
        free(json2);\
    } while(0)

static void test_stringify_number() {
    TEST_ROUNDTRIP("0");
    TEST_ROUNDTRIP("-0");
    TEST_ROUNDTRIP("1");
    TEST_ROUNDTRIP("-1");
    TEST_ROUNDTRIP("1.5");
    TEST_ROUNDTRIP("-1.5");
    TEST_ROUNDTRIP("3.25");
    TEST_ROUNDTRIP("1e+20");
    TEST_ROUNDTRIP("1.234e+20");
    TEST_ROUNDTRIP("1.234e-20");

    TEST_ROUNDTRIP("1.0000000000000002"); /* the smallest number > 1 */
    TEST_ROUNDTRIP("4.9406564584124654e-324"); /* minimum denormal */
    TEST_ROUNDTRIP("-4.9406564584124654e-324");
    TEST_ROUNDTRIP("2.2250738585072009e-308");  /* Max subnormal double */
    TEST_ROUNDTRIP("-2.2250738585072009e-308");
    TEST_ROUNDTRIP("2.2250738585072014e-308");  /* Min normal positive double */
    TEST_ROUNDTRIP("-2.2250738585072014e-308");
    TEST_ROUNDTRIP("1.7976931348623157e+308");  /* Max double */
    TEST_ROUNDTRIP("-1.7976931348623157e+308");
}

static void test_stringify_string() {
    TEST_ROUNDTRIP("\"\"");
    TEST_ROUNDTRIP("\"Hello\"");
    TEST_ROUNDTRIP("\"Hello\\nWorld\"");
    TEST_ROUNDTRIP("\"\\\" \\\\ / \\b \\f \\n \\r \\t\"");
    TEST_ROUNDTRIP("\"Hello\\u0000World\"");
}

static void test_stringify_array() {
    TEST_ROUNDTRIP("[]");
    TEST_ROUNDTRIP("[null,false,true,123,\"abc\",[1,2,3]]");
}

static void test_stringify_object() {
    TEST_ROUNDTRIP("{}");
    TEST_ROUNDTRIP("{\"n\":null,\"f\":false,\"t\":true,\"i\":123,\"s\":\"abc\",\"a\":[1,2,3],\"o\":{\"1\":1,\"2\":2,\"3\":3}}");
}

static void test_stringify() {
    TEST_ROUNDTRIP("null");
    TEST_ROUNDTRIP("false");
    TEST_ROUNDTRIP("true");
    test_stringify_number();
    test_stringify_string();
    test_stringify_array();
    test_stringify_object();
}

#define TEST_EQUAL(json1, json2, equality) \
    do {\
        cjson_value v1, v2;\
        cjson_init(&v1);\
        cjson_init(&v2);\
        EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v1, json1));\
        EXPECT_EQ_INT(CJSON_PARSE_OK, cjson_parse(&v2, json2));\
        EXPECT_EQ_INT(equality, cjson_is_equal(&v1, &v2));\
        cjson_free(&v1);\
        cjson_free(&v2);\
    } while(0)

static void test_equal() {
    TEST_EQUAL("true", "true", 1);
    TEST_EQUAL("true", "false", 0);
    TEST_EQUAL("false", "false", 1);
    TEST_EQUAL("null", "null", 1);
    TEST_EQUAL("null", "0", 0);
    TEST_EQUAL("123", "123", 1);
    TEST_EQUAL("123", "456", 0);
    TEST_EQUAL("\"abc\"", "\"abc\"", 1);
    TEST_EQUAL("\"abc\"", "\"abcd\"", 0);
    TEST_EQUAL("[]", "[]", 1);
    TEST_EQUAL("[]", "null", 0);
    TEST_EQUAL("[1,2,3]", "[1,2,3]", 1);
    TEST_EQUAL("[1,2,3]", "[1,2,3,4]", 0);
    TEST_EQUAL("[[]]", "[[]]", 1);
    TEST_EQUAL("{}", "{}", 1);
    TEST_EQUAL("{}", "null", 0);
    TEST_EQUAL("{}", "[]", 0);
    TEST_EQUAL("{\"a\":1,\"b\":2}", "{\"a\":1,\"b\":2}", 1);
    TEST_EQUAL("{\"a\":1,\"b\":2}", "{\"b\":2,\"a\":1}", 1);
    TEST_EQUAL("{\"a\":1,\"b\":2}", "{\"a\":1,\"b\":3}", 0);
    TEST_EQUAL("{\"a\":1,\"b\":2}", "{\"a\":1,\"b\":2,\"c\":3}", 0);
    TEST_EQUAL("{\"a\":{\"b\":{\"c\":{}}}}", "{\"a\":{\"b\":{\"c\":{}}}}", 1);
    TEST_EQUAL("{\"a\":{\"b\":{\"c\":{}}}}", "{\"a\":{\"b\":{\"c\":[]}}}", 0);
}

static void test_copy() {
    cjson_value v1, v2;
    cjson_init(&v1);
    cjson_parse(&v1, "{\"t\":true,\"f\":false,\"n\":null,\"d\":1.5,\"a\":[1,2,3]}");
    cjson_init(&v2);
    cjson_copy(&v2, &v1);
    EXPECT_TRUE(cjson_is_equal(&v2, &v1));
    cjson_free(&v1);
    cjson_free(&v2);
}

static void test_move() {
    cjson_value v1, v2, v3;
    cjson_init(&v1);
    cjson_parse(&v1, "{\"t\":true,\"f\":false,\"n\":null,\"d\":1.5,\"a\":[1,2,3]}");
    cjson_init(&v2);
    cjson_copy(&v2, &v1);
    cjson_init(&v3);
    cjson_move(&v3, &v2);
    EXPECT_EQ_INT(CJSON_NULL, cjson_get_type(&v2));
    EXPECT_TRUE(cjson_is_equal(&v3, &v1));
    cjson_free(&v1);
    cjson_free(&v2);
    cjson_free(&v3);
}

static void test_swap() {
    cjson_value v1, v2;
    cjson_init(&v1);
    cjson_init(&v2);
    cjson_set_string(&v1, "Hello", 5);
    cjson_set_string(&v2, "World!", 6);
    cjson_swap(&v1, &v2);
    EXPECT_EQ_STRING("World!", cjson_get_string(&v1), cjson_get_string_length(&v1));
    EXPECT_EQ_STRING("Hello", cjson_get_string(&v2), cjson_get_string_length(&v2));
    cjson_free(&v1);
    cjson_free(&v2);
}

static void test_access_null() {
    cjson_value v;
    cjson_init(&v);
    cjson_set_string(&v, "a", 1);
    cjson_set_null(&v);
    EXPECT_EQ_INT(CJSON_NULL, cjson_get_type(&v));
    cjson_free(&v);
}

static void test_access_boolean() {
    cjson_value v;
    cjson_init(&v);
    cjson_set_string(&v, "a", 1);
    cjson_set_boolean(&v, 1);
    EXPECT_TRUE(cjson_get_boolean(&v));
    cjson_set_boolean(&v, 0);
    EXPECT_FALSE(cjson_get_boolean(&v));
    cjson_free(&v);
}

static void test_access_number() {
    cjson_value v;
    cjson_init(&v);
    cjson_set_string(&v, "a", 1);
    cjson_set_number(&v, 1234.5);
    EXPECT_EQ_DOUBLE(1234.5, cjson_get_number(&v));
    cjson_free(&v);
}

static void test_access_string() {
    cjson_value v;
    cjson_init(&v);
    cjson_set_string(&v, "", 0);
    EXPECT_EQ_STRING("", cjson_get_string(&v), cjson_get_string_length(&v));
    cjson_set_string(&v, "Hello", 5);
    EXPECT_EQ_STRING("Hello", cjson_get_string(&v), cjson_get_string_length(&v));
    cjson_free(&v);
}

static void test_access_array() {
    cjson_value a, e;
    size_t i, j;

    cjson_init(&a);

    for (j = 0; j <= 5; j += 5) {
        cjson_set_array(&a, j);
        EXPECT_EQ_SIZE_T(0, cjson_get_array_size(&a));
        EXPECT_EQ_SIZE_T(j, cjson_get_array_capacity(&a));
        for (i = 0; i < 10; i++) {
            cjson_init(&e);
            cjson_set_number(&e, i);
            cjson_move(cjson_pushback_array_element(&a), &e);
            cjson_free(&e);
        }

        EXPECT_EQ_SIZE_T(10, cjson_get_array_size(&a));
        for (i = 0; i < 10; i++)
            EXPECT_EQ_DOUBLE((double)i, cjson_get_number(cjson_get_array_element(&a, i)));
    }

    cjson_popback_array_element(&a);
    EXPECT_EQ_SIZE_T(9, cjson_get_array_size(&a));
    for (i = 0; i < 9; i++)
        EXPECT_EQ_DOUBLE((double)i, cjson_get_number(cjson_get_array_element(&a, i)));

    cjson_erase_array_element(&a, 4, 0);
    EXPECT_EQ_SIZE_T(9, cjson_get_array_size(&a));
    for (i = 0; i < 9; i++)
        EXPECT_EQ_DOUBLE((double)i, cjson_get_number(cjson_get_array_element(&a, i)));

    cjson_erase_array_element(&a, 8, 1);
    EXPECT_EQ_SIZE_T(8, cjson_get_array_size(&a));
    for (i = 0; i < 8; i++)
        EXPECT_EQ_DOUBLE((double)i, cjson_get_number(cjson_get_array_element(&a, i)));

    cjson_erase_array_element(&a, 0, 2);
    EXPECT_EQ_SIZE_T(6, cjson_get_array_size(&a));
    for (i = 0; i < 6; i++)
        EXPECT_EQ_DOUBLE((double)i + 2, cjson_get_number(cjson_get_array_element(&a, i)));

    for (i = 0; i < 2; i++) {
        cjson_init(&e);
        cjson_set_number(&e, i);
        cjson_move(cjson_insert_array_element(&a, i), &e);
        cjson_free(&e);
    }

    EXPECT_EQ_SIZE_T(8, cjson_get_array_size(&a));
    for (i = 0; i < 8; i++)
        EXPECT_EQ_DOUBLE((double)i, cjson_get_number(cjson_get_array_element(&a, i)));

    EXPECT_TRUE(cjson_get_array_capacity(&a) > 8);
    cjson_shrink_array(&a);
    EXPECT_EQ_SIZE_T(8, cjson_get_array_capacity(&a));
    EXPECT_EQ_SIZE_T(8, cjson_get_array_size(&a));
    for (i = 0; i < 8; i++)
        EXPECT_EQ_DOUBLE((double)i, cjson_get_number(cjson_get_array_element(&a, i)));

    cjson_set_string(&e, "Hello", 5);
    cjson_move(cjson_pushback_array_element(&a), &e);     /* Test if element is freed */
    cjson_free(&e);

    i = cjson_get_array_capacity(&a);
    cjson_clear_array(&a);
    EXPECT_EQ_SIZE_T(0, cjson_get_array_size(&a));
    EXPECT_EQ_SIZE_T(i, cjson_get_array_capacity(&a));   /* capacity remains unchanged */
    cjson_shrink_array(&a);
    EXPECT_EQ_SIZE_T(0, cjson_get_array_capacity(&a));

    cjson_free(&a);
}

static void test_access_object() {
    cjson_value o, v, *pv;
    size_t i, j, index;

    cjson_init(&o);

    for (j = 0; j <= 5; j += 5) {
        cjson_set_object(&o, j);
        EXPECT_EQ_SIZE_T(0, cjson_get_object_size(&o));
        EXPECT_EQ_SIZE_T(j, cjson_get_object_capacity(&o));
        for (i = 0; i < 10; i++) {
            char key[2] = "a";
            key[0] += i;
            cjson_init(&v);
            cjson_set_number(&v, i);
            cjson_move(cjson_set_object_value(&o, key, 1), &v);
            cjson_free(&v);
        }
        EXPECT_EQ_SIZE_T(10, cjson_get_object_size(&o));
        for (i = 0; i < 10; i++) {
            char key[] = "a";
            key[0] += i;
            index = cjson_find_object_index(&o, key, 1);
            EXPECT_TRUE(index != CJSON_KEY_NOT_EXIST);
            pv = cjson_get_object_value(&o, index);
            EXPECT_EQ_DOUBLE((double)i, cjson_get_number(pv));
        }
    }

    index = cjson_find_object_index(&o, "j", 1);
    EXPECT_TRUE(index != CJSON_KEY_NOT_EXIST);
    cjson_remove_object_value(&o, index);
    index = cjson_find_object_index(&o, "j", 1);
    EXPECT_TRUE(index == CJSON_KEY_NOT_EXIST);
    EXPECT_EQ_SIZE_T(9, cjson_get_object_size(&o));

    index = cjson_find_object_index(&o, "a", 1);
    EXPECT_TRUE(index != CJSON_KEY_NOT_EXIST);
    cjson_remove_object_value(&o, index);
    index = cjson_find_object_index(&o, "a", 1);
    EXPECT_TRUE(index == CJSON_KEY_NOT_EXIST);
    EXPECT_EQ_SIZE_T(8, cjson_get_object_size(&o));

    EXPECT_TRUE(cjson_get_object_capacity(&o) > 8);
    cjson_shrink_object(&o);
    EXPECT_EQ_SIZE_T(8, cjson_get_object_capacity(&o));
    EXPECT_EQ_SIZE_T(8, cjson_get_object_size(&o));
    for (i = 0; i < 8; i++) {
        char key[] = "a";
        key[0] += i + 1;
        EXPECT_EQ_DOUBLE((double)i + 1, cjson_get_number(cjson_get_object_value(&o, cjson_find_object_index(&o, key, 1))));
    }

    cjson_set_string(&v, "Hello", 5);
    cjson_move(cjson_set_object_value(&o, "World", 5), &v); /* Test if element is freed */
    cjson_free(&v);

    pv = cjson_find_object_value(&o, "World", 5);
    EXPECT_TRUE(pv != NULL);
    EXPECT_EQ_STRING("Hello", cjson_get_string(pv), cjson_get_string_length(pv));

    i = cjson_get_object_capacity(&o);
    cjson_clear_object(&o);
    EXPECT_EQ_SIZE_T(0, cjson_get_object_size(&o));
    EXPECT_EQ_SIZE_T(i, cjson_get_object_capacity(&o)); /* capacity remains unchanged */
    cjson_shrink_object(&o);
    EXPECT_EQ_SIZE_T(0, cjson_get_object_capacity(&o));

    cjson_free(&o);
}

static void test_access() {
    test_access_null();
    test_access_boolean();
    test_access_number();
    test_access_string();
    test_access_array();
    test_access_object();
}

int main() {
    test_parse();
    test_stringify();
    test_equal();
    test_copy();
    test_move();
    test_swap();
    test_access();
    printf("%d/%d (%3.2f%%) passed\n", test_pass, test_count, test_pass * 100.0 / test_count);
    return main_ret;
}
