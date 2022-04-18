/**
 * ipk-sniffer
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dynamic_string.h
 *
 * @brief Dynamic string header file
 */

#pragma once

#include <stddef.h>
#include <errno.h>

#define STRING_ALLOC_LENGTH 16

typedef struct {
    char *ptr;
    size_t alloc_length;
    size_t length;
} string_t;


int str_create_empty(string_t *str);


int str_append_char(string_t *str, char ch);

int str_append_string(string_t *str, char *s);

void str_free(string_t *str);
