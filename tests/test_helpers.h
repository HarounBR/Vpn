#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

extern int tests_passed;
extern int tests_failed;

#define RUN_TEST(test_func) \
    do { \
        printf("Running: %s ... ", #test_func); \
        fflush(stdout); \
        if (test_func() == 0) { \
            printf("PASS\n"); \
            tests_passed++; \
        } else { \
            printf("FAIL\n"); \
            tests_failed++; \
        } \
    } while(0)

#define TEST_SUMMARY() \
    do { \
        printf("\n=== Test Summary ===\n"); \
        printf("Passed: %d\n", tests_passed); \
        printf("Failed: %d\n", tests_failed); \
        printf("Total:  %d\n", tests_passed + tests_failed); \
    } while(0)

#define TEST_ASSERT(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "\n  FAIL: Assertion failed at %s:%d\n", \
                    __FILE__, __LINE__); \
            fprintf(stderr, "    Condition: %s\n", #condition); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            fprintf(stderr, "\n  FAIL: Values not equal at %s:%d\n", \
                    __FILE__, __LINE__); \
            fprintf(stderr, "    Expected: %lld\n", (long long)(expected)); \
            fprintf(stderr, "    Actual:   %lld\n", (long long)(actual)); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_STRING_EQUAL(expected, actual) \
    do { \
        const char *__expected = (expected); \
        const char *__actual = (actual); \
        if (__expected == NULL || __actual == NULL || strcmp(__expected, __actual) != 0) { \
            fprintf(stderr, "\n  FAIL: Strings not equal at %s:%d\n", \
                    __FILE__, __LINE__); \
            fprintf(stderr, "    Expected: %s\n", \
                    __expected != NULL ? __expected : "(null)"); \
            fprintf(stderr, "    Actual:   %s\n", \
                    __actual != NULL ? __actual : "(null)"); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != NULL) { \
            fprintf(stderr, "\n  FAIL: Expected NULL at %s:%d\n", \
                    __FILE__, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            fprintf(stderr, "\n  FAIL: Expected non-NULL at %s:%d\n", \
                    __FILE__, __LINE__); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_ERROR(expr) \
    do { \
        int result = (expr); \
        if (result >= 0) { \
            fprintf(stderr, "\n  FAIL: Expected error at %s:%d\n", \
                    __FILE__, __LINE__); \
            fprintf(stderr, "    Got: %d (expected < 0)\n", result); \
            return 1; \
        } \
    } while(0)

#define TEST_ASSERT_SUCCESS(expr) \
    do { \
        int result = (expr); \
        if (result != 0) { \
            fprintf(stderr, "\n  FAIL: Expected success at %s:%d\n", \
                    __FILE__, __LINE__); \
            fprintf(stderr, "    Got: %d (expected 0)\n", result); \
            return 1; \
        } \
    } while(0)

// ============================================================
// Byte/hex comparison helpers
// ============================================================

static inline void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n    ");
    }
}

#define TEST_ASSERT_BYTES_EQUAL(expected, actual, len) \
    do { \
        size_t __len = (len); \
        if (memcmp((expected), (actual), __len) != 0) { \
            fprintf(stderr, "\n  FAIL: Bytes not equal at %s:%d\n", \
                    __FILE__, __LINE__); \
            fprintf(stderr, "    Expected: "); \
            print_hex((const uint8_t*)(expected), __len); \
            fprintf(stderr, "\n    Actual:   "); \
            print_hex((const uint8_t*)(actual), __len); \
            fprintf(stderr, "\n"); \
            return 1; \
        } \
    } while(0)

#endif // TEST_HELPERS_H
