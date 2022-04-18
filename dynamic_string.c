/**
 * ipk-sniffer
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dynamic-string.c
 *
 * @brief Dynamic string implementation
 */

#include "dynamic_string.h"
#include "errno.h"
#include <stdlib.h>
#include <string.h>

// allocates pre-defined amount for space for empty string
int str_create_empty(string_t *str) {
    // allocate initial space for string
    str->ptr = malloc(STRING_ALLOC_LENGTH);
    if(str->ptr == NULL) {
        return E_INT;
    }
    str->ptr[0] = '\0';
    str->alloc_length = STRING_ALLOC_LENGTH;
    str->length = 0;
    return E_OK;
}

// appends entire string s(ending with \0) to string content
int str_append_string(string_t *str, char *s) {
    for (int i = 0; i < strlen(s); i++) {
        if (str_append_char(str,s[i])) {
            return E_INT;
        }
    }
    return E_OK;
}

// appends one character to string content
int str_append_char(string_t *str, char ch) {
    // new_char + null byte = 2
    if(str->length + 2 > str->alloc_length) {
        /* allocate buffer twice as large
         * note: str->alloc_length can't be equal to 0 unless STRING_ALLOC_LENGTH is set to 0 or an
         * overflow happened
         */
        str->alloc_length *= 2;
        void *tmp = realloc(str->ptr, str->alloc_length);
        if(tmp == NULL) {
            return E_INT;
        }
        str->ptr = tmp;
    }
    str->ptr[str->length++] = ch;
    str->ptr[str->length] = '\0';
    return E_OK;
}

// free allocated space for string content
void str_free(string_t *str) {
    if(str->ptr) {
        free(str->ptr);
    }
}
