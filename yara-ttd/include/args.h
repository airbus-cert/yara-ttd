/*
Copyright (c) 2014-2021. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef ARGPARSE_H
#define ARGPARSE_H

#include <stdio.h>

#define MAX_LENGTH_PATH 256

#ifdef __cplusplus
extern "C"
{
#endif

  typedef enum _args_error_type
  {
    ARGS_ERROR_OK,
    ARGS_ERROR_UNKNOWN_OPT,
    ARGS_ERROR_TOO_MANY,
    ARGS_ERROR_REQUIRED_INTEGER_ARG,
    ARGS_ERROR_REQUIRED_STRING_ARG,
    ARGS_ERROR_UNEXPECTED_ARG,
  } args_error_type_t;

  typedef enum _args_option_type
  {
    // special
    ARGS_OPT_END,
    ARGS_OPT_GROUP,
    // options with no arguments
    ARGS_OPT_BOOLEAN,
    // options with arguments (optional or required)
    ARGS_OPT_LONG,
    ARGS_OPT_LONG_LONG,
    ARGS_OPT_STRING,
  } args_option_type_t;

  typedef struct _args_option
  {
    args_option_type_t type;
    const wchar_t short_name;
    const wchar_t *long_name;
    void *value;
    int max_count;
    const wchar_t *help;
    const wchar_t *type_help;
    int count;
  } args_option_t;

#define OPT_BOOLEAN(short_name, long_name, value, ...)             \
  {                                                                \
    ARGS_OPT_BOOLEAN, short_name, long_name, value, 1, __VA_ARGS__ \
  }

#define OPT_LONG(short_name, long_name, value, ...)             \
  {                                                             \
    ARGS_OPT_LONG, short_name, long_name, value, 1, __VA_ARGS__ \
  }

#define OPT_LONG_LONG(short_name, long_name, value, ...)             \
  {                                                                  \
    ARGS_OPT_LONG_LONG, short_name, long_name, value, 1, __VA_ARGS__ \
  }

#define OPT_STRING_MULTI(short_name, long_name, value, max_count, ...)    \
  {                                                                       \
    ARGS_OPT_STRING, short_name, long_name, value, max_count, __VA_ARGS__ \
  }

#define OPT_STRING(short_name, long_name, value, ...) \
  OPT_STRING_MULTI(short_name, long_name, value, 1, __VA_ARGS__)

#define OPT_END()   \
  {                 \
    ARGS_OPT_END, 0 \
  }

  int args_parse(args_option_t *options, int argc, const wchar_t **argv);

  void args_print_usage(args_option_t *options, int alignment);

  void args_free(args_option_t *options);

  int args_file_parse(wchar_t *path, wchar_t **arg, int len);

#ifdef __cplusplus
}
#endif

#endif
