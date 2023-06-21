/*
Copyright (c) 2007-2021. The YARA Authors. All Rights Reserved.

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

#include <fcntl.h>
#include <io.h>
#include <windows.h>

#include <ctype.h>
#include <libyarattd_common.h>
#include <libyarattd_scanner.h>
#include <libyarattd_scheduler.h>
#include <libyarattd_vect.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yara.h>

#include "args.h"
#include "threading.h"

#define ERROR_COULD_NOT_CREATE_THREAD 100

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

#ifndef min
#define min(x, y) ((x < y) ? (x) : (y))
#endif

#define MAX_ARGS_TAG         32
#define MAX_ARGS_IDENTIFIER  32
#define MAX_ARGS_EXT_VAR     32
#define MAX_ARGS_MODULE_DATA 32
#define MAX_QUEUED_FILES     64

#define exit_with_code(code) \
  {                          \
    result = code;           \
    goto _exit;              \
  }

typedef struct _MODULE_DATA
{
  const char *module_name;
  YR_MAPPED_FILE mapped_file;
  struct _MODULE_DATA *next;

} MODULE_DATA;

typedef struct _CALLBACK_ARGS
{
  const wchar_t *file_path;
  int current_count;

} CALLBACK_ARGS;

typedef struct _QUEUED_FILE
{
  wchar_t *path;

} QUEUED_FILE;

typedef struct COMPILER_RESULTS
{
  int errors;
  int warnings;

} COMPILER_RESULTS;

typedef struct SCAN_OPTIONS
{
  bool follow_symlinks;
  bool recursive_search;
  time_t deadline;

} SCAN_OPTIONS;

#define MAX_ARGS_TAG           32
#define MAX_ARGS_IDENTIFIER    32
#define MAX_ARGS_EXT_VAR       32
#define MAX_ARGS_MODULE_DATA   32
#define MAX_ARGS_SCAN_FUNCTION 32
#define MAX_ARGS_SCAN_CURSOR   32

static wchar_t *atom_quality_table;
static wchar_t *tags[MAX_ARGS_TAG + 1];
static wchar_t *identifiers[MAX_ARGS_IDENTIFIER + 1];
static wchar_t *ext_vars[MAX_ARGS_EXT_VAR + 1];
static wchar_t *modules_data[MAX_ARGS_MODULE_DATA + 1];
static wchar_t *scan_functions[MAX_ARGS_SCAN_FUNCTION + 1];
static wchar_t *scan_cursors[MAX_ARGS_SCAN_CURSOR + 1];
static wchar_t *scan_functions_file;
static wchar_t *scan_cursors_file;
static wchar_t *cache_file;

static bool follow_symlinks = true;
static bool recursive_search = false;
static bool scan_list_search = false;
static bool show_module_data = false;
static bool show_tags = false;
static bool show_stats = false;
static bool show_strings = false;
static bool show_string_length = false;
static bool show_xor_key = false;
static bool show_meta = false;
static bool show_module_names = false;
static bool show_namespace = false;
static bool show_version = false;
static bool show_help = false;
static bool ignore_warnings = false;
static bool fast_scan = false;
static bool negate = false;
static bool print_count_only = false;
static bool fail_on_warnings = false;
static bool rules_are_compiled = false;
static long total_count = 0;
static long limit = 0;
static long timeout = 1000000;
static long stack_size = DEFAULT_STACK_SIZE;
static long threads = YR_MAX_THREADS;
static long max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;
static long max_process_memory_chunk = DEFAULT_MAX_PROCESS_MEMORY_CHUNK;
static long long skip_larger = 0;
static long long scan_mode = 0;

#define USAGE_STRING \
  "Usage: yara-ttd [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR"

args_option_t options[] = {
    OPT_STRING(
        0,
        L"atom-quality-table",
        &atom_quality_table,
        L"path to a file with the atom quality table",
        L"FILE"),

    OPT_BOOLEAN(
        'C',
        L"compiled-rules",
        &rules_are_compiled,
        L"load compiled rules"),

    OPT_BOOLEAN(
        'c',
        L"count",
        &print_count_only,
        L"print only number of matches"),

    OPT_STRING_MULTI(
        'd',
        L"define",
        &ext_vars,
        MAX_ARGS_EXT_VAR,
        L"define external variable",
        L"VAR=VALUE"),

    OPT_BOOLEAN(0, L"fail-on-warnings", &fail_on_warnings, L"fail on warnings"),

    OPT_BOOLEAN(0, L"fast-scan", &fast_scan, L"fast matching mode"),

    OPT_BOOLEAN('h', L"help", &show_help, L"show this help and exit"),

    OPT_STRING_MULTI(
        'i',
        L"identifier",
        &identifiers,
        MAX_ARGS_IDENTIFIER,
        L"print only rules named IDENTIFIER",
        L"IDENTIFIER"),

    OPT_LONG(
        0,
        L"max-process-memory-chunk",
        &max_process_memory_chunk,
        L"set maximum chunk size while reading process memory"
        L" (default=1073741824)",
        L"NUMBER"),

    OPT_LONG(
        0,
        L"max-rules",
        &limit,
        L"abort scanning after matching a NUMBER of rules",
        L"NUMBER"),

    OPT_LONG(
        0,
        L"max-strings-per-rule",
        &max_strings_per_rule,
        L"set maximum number of strings per rule (default=10000)",
        L"NUMBER"),

    OPT_STRING_MULTI(
        'x',
        L"module-data",
        &modules_data,
        MAX_ARGS_MODULE_DATA,
        L"pass FILE's content as extra data to MODULE",
        L"MODULE=FILE"),

    OPT_BOOLEAN(
        'n',
        L"negate",
        &negate,
        L"print only not satisfied rules (negate)",
        NULL),

    OPT_BOOLEAN(
        'N',
        L"no-follow-symlinks",
        &follow_symlinks,
        L"do not follow symlinks when scanning"),

    OPT_BOOLEAN('w', L"no-warnings", &ignore_warnings, L"disable warnings"),

    OPT_BOOLEAN(0, L"print-meta", &show_meta, L"print metadata"),

    OPT_BOOLEAN(
        'D',
        L"print-module-data",
        &show_module_data,
        L"print module data"),

    OPT_BOOLEAN(0, L"module-names", &show_module_names, L"show module names"),

    OPT_BOOLEAN(
        'e',
        L"print-namespace",
        &show_namespace,
        L"print rules' namespace"),

    OPT_BOOLEAN('S', L"print-stats", &show_stats, L"print rules' statistics"),

    OPT_BOOLEAN(
        's',
        L"print-strings",
        &show_strings,
        L"print matching strings"),

    OPT_BOOLEAN(
        'L',
        L"print-string-length",
        &show_string_length,
        L"print length of matched strings"),

    OPT_BOOLEAN(
        'X',
        L"print-xor-key",
        &show_xor_key,
        L"print xor key and plaintext of matched strings"),

    OPT_BOOLEAN('g', L"print-tags", &show_tags, L"print tags"),

    OPT_BOOLEAN(
        'r',
        L"recursive",
        &recursive_search,
        L"recursively search directories"),

    OPT_BOOLEAN(
        'l',
        L"scan-list",
        &scan_list_search,
        L"scan files listed in FILE, one per line"),

    OPT_LONG_LONG(
        'z',
        L"skip-larger",
        &skip_larger,
        L"skip files larger than the given size when scanning a directory",
        L"NUMBER"),

    OPT_LONG(
        'k',
        L"stack-size",
        &stack_size,
        L"set maximum stack size (default=16384)",
        L"SLOTS"),

    OPT_STRING_MULTI(
        0,
        L"tag",
        &tags,
        MAX_ARGS_TAG,
        L"print only rules tagged as TAG",
        L"TAG"),

    OPT_LONG(
        'p',
        L"threads",
        &threads,
        L"use the specified NUMBER of threads to scan a directory",
        L"NUMBER"),

    OPT_LONG(
        'a',
        L"timeout",
        &timeout,
        L"abort scanning after the given number of SECONDS",
        L"SECONDS"),

    OPT_BOOLEAN('v', L"version", &show_version, L"show version information"),

    OPT_LONG(
        'm',
        L"memory-scan-mode",
        &scan_mode,
        L"scan mode for memory to use",
        L"NUMBER"),

    OPT_STRING_MULTI(
        'f',
        L"scan-function",
        &scan_functions,
        MAX_ARGS_SCAN_FUNCTION,
        L"function calls where you want to scan the trace",
        L"FUNCTION"),

    OPT_STRING_MULTI(
        't',
        L"scan-cursor",
        &scan_cursors,
        MAX_ARGS_SCAN_CURSOR,
        L"cursor where you want to scan the trace",
        L"CURSOR"),

    OPT_STRING(
        'F',
        L"scan-function-file",
        &scan_functions_file,
        L"file with function calls where you want to scan the trace",
        L"FUNCTION_FILE"),

    OPT_STRING(
        'T',
        L"scan-cursor-file",
        &scan_cursors_file,
        L"file with cursor where you want to scan the trace",
        L"CURSOR_FILE"),

    OPT_STRING(0, L"cache", &cache_file, L"cache file", L"CACHE_FILE"),

    OPT_END(),
};

MODULE_DATA *modules_data_list = NULL;

static bool is_directory(const wchar_t *path)
{
  DWORD attributes = GetFileAttributes(path);

  if (attributes != INVALID_FILE_ATTRIBUTES &&
      attributes & FILE_ATTRIBUTE_DIRECTORY)
    return true;
  else
    return false;
}

static int get_filenames_from_dir(
    Vect *filenames,
    const wchar_t *dir,
    SCAN_OPTIONS *scan_opts)
{
  int result = ERROR_SUCCESS;
  wchar_t path[MAX_PATH];

  // Create vect if it doesn't exist
  if (!filenames)
    vect_create(&filenames);

  _snwprintf(path, MAX_PATH, L"%s\\*", dir);
  path[MAX_PATH - 1] = L'\0';

  WIN32_FIND_DATA FindFileData;
  HANDLE hFind = FindFirstFile(path, &FindFileData);

  if (hFind != INVALID_HANDLE_VALUE)
  {
    do
    {
      // Skip files with extension .tmp, .idx, .out or .err
      // These files are most likely generated by yara-ttd or ttd
      size_t len = wcslen(FindFileData.cFileName);
      if (len > 4 && (wcscmp(&FindFileData.cFileName[len - 4], L".tmp") == 0 ||
                      wcscmp(&FindFileData.cFileName[len - 4], L".idx") == 0 ||
                      wcscmp(&FindFileData.cFileName[len - 4], L".out") == 0 ||
                      wcscmp(&FindFileData.cFileName[len - 4], L".err") == 0))
        continue;

      _snwprintf(path, MAX_PATH, L"%s\\%s", dir, FindFileData.cFileName);
      path[MAX_PATH - 1] = L'\0';

      if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
      {
        LARGE_INTEGER file_size;

        file_size.HighPart = FindFileData.nFileSizeHigh;
        file_size.LowPart = FindFileData.nFileSizeLow;

        if (skip_larger > file_size.QuadPart || skip_larger <= 0)
        {
          wchar_t *h_path = yr_calloc(wcslen(path), sizeof(wchar_t));
          if (!h_path)
            return ERROR_INTERNAL_FATAL_ERROR;

          wcscpy(h_path, path);
          result = vect_add_element(filenames, h_path);
        }
        else
        {
          fwprintf(
              stderr,
              L"skipping %s (%I64u bytes) because it's larger than %lld "
              L"bytes.\n",
              path,
              file_size.QuadPart,
              skip_larger);
        }
      }
      else if (
          scan_opts->recursive_search &&
          wcscmp(FindFileData.cFileName, L".") != 0 &&
          wcscmp(FindFileData.cFileName, L"..") != 0)
      {
        result = get_filenames_from_dir(filenames, path, scan_opts);
      }

    } while (result == ERROR_SUCCESS && FindNextFile(hFind, &FindFileData));

    FindClose(hFind);
  }

  return result;
}

#define LENGTH_TABLE 111
wchar_t *ljust(wchar_t *str, wchar_t pad, int length)
{
  wchar_t *out = (wchar_t *) yr_calloc(LENGTH_TABLE, sizeof(wchar_t));

  if (wcslen(str) >= length)
    return str;

  for (int i = 0; i < length; i++)
  {
    if (i < wcslen(str))
      out[i] = str[i];
    else
      out[i] = pad;
  }
  return out;
}

// Scan a trace file.
static int scan_ttd(YR_SCANNER *scanner, const wchar_t *filename)
{
  wprintf(L"Analyzing positions to scan for %s...\n\n", filename);

  YR_TTD_SCHEDULER *scheduler = NULL;
  TRY(scheduler_init(
      &scheduler,
      filename,
      scan_mode,
      scan_cursors,
      scan_functions,
      cache_file));
  if (!scheduler)
    return ERROR_INTERNAL_FATAL_ERROR;

  wprintf(L"Cursor(s) found:\n");
  for (int i = 0; i < scheduler->cursors->count; i++)
  {
    YR_TTD_SCAN_CURSOR *scan_cursor = scheduler->cursors->elements[i];
    wprintf(
        L"Scanning %llx:%llx (%s)\n",
        scan_cursor->position->major,
        scan_cursor->position->minor,
        scan_cursor->source);
  }

  if (scan_mode == SCAN_MODE_VIRTUAL_ALLOC)
  {
    wprintf(L"\nVirtual Allocated map:\n");
    for (int i = 0; i < scheduler->virtual_alloc_map->map->count; i++)
    {
      YR_TTD_EVENT *event =
          (YR_TTD_EVENT *) (scheduler->virtual_alloc_map->map->elements[i]);
      wprintf(
          L"@ %llx:%llx - Virtual memory allocated 0x%llx - 0x%llx\n",
          event->start->major,
          event->start->minor,
          event->range->start,
          event->range->end);
    }
  }

  wprintf(L"\nStarting scan...\n\n");

  for (int i = 0; i < scheduler->cursors->count; i++)
  {
    YR_TTD_SCAN_CURSOR *scan_cursor = scheduler->cursors->elements[i];
    TRY(yr_scanner_scan_ttd(scheduler, scanner, scan_cursor));
  }

  scheduler->engine->IReplayEngine->Destroy_Replay_Engine(scheduler->engine);

  return ERROR_SUCCESS;
}

static int get_filenames_from_scan_list(Vect *filenames, const wchar_t *path)
{
  wchar_t *context = NULL;
  DWORD nread = 0;
  int result = ERROR_SUCCESS;

  HANDLE hFile = CreateFile(
      path,
      GENERIC_READ,
      FILE_SHARE_READ,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL);

  if (hFile == INVALID_HANDLE_VALUE)
  {
    fwprintf(stderr, L"error: could not open file \"%s\".\n", path);
    return ERROR_COULD_NOT_OPEN_FILE;
  }

  DWORD fileSize = GetFileSize(hFile, NULL);

  if (fileSize == INVALID_FILE_SIZE)
  {
    fwprintf(
        stderr, L"error: could not determine size of file \"%s\".\n", path);
    CloseHandle(hFile);
    return ERROR_COULD_NOT_READ_FILE;
  }

  // INVALID_FILE_SIZE is 0xFFFFFFFF, so (+1) will not overflow
  char *buf = (char *) yr_malloc(fileSize + 1);

  if (buf == NULL)
  {
    fwprintf(
        stderr, L"error: could not allocate memory for file \"%s\".\n", path);
    CloseHandle(hFile);
    return ERROR_INSUFFICIENT_MEMORY;
  }

  DWORD total = 0;

  while (total < fileSize)
  {
    if (!ReadFile(hFile, buf + total, fileSize - total, &nread, NULL))
    {
      fwprintf(stderr, L"error: could not read file \"%s\".\n", path);
      CloseHandle(hFile);
      return ERROR_COULD_NOT_READ_FILE;
    }
    total += nread;
  }

  wchar_t *buf_w = yr_calloc(strlen(buf), sizeof(wchar_t));
  mbstowcs(buf_w, buf, nread);
  buf_w[nread] = L'\0';
  yr_free(buf);

  wchar_t *filename = wcstok_s(buf_w, L"\n", &context);

  while (result == ERROR_SUCCESS && filename != NULL)
  {
    // Remove trailing carriage return, if present.
    if (*filename != L'\0')
    {
      wchar_t *final = filename + wcslen(filename) - 1;

      if (*final == L'\r')
        *final = L'\0';
    }

    result = vect_add_element(filenames, filename);
    filename = wcstok_s(NULL, L"\n", &context);
  }

  CloseHandle(hFile);
  return result;
}

static void print_string(const uint8_t *data, int length, uint8_t xor_key)
{
  for (int i = 0; i < length; i++)
  {
    uint8_t c = data[i] ^ xor_key;
    if (c >= 32 && c <= 126)
      wprintf(L"%c", c);
    else
      wprintf(L"\\x%02X", c);
  }
}

static char cescapes[] = {
    0, 0, 0, 0, 0, 0, 0, 'a', 'b', 't', 'n', 'v', 'f', 'r', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,   0,   0,   0,   0,   0,   0,   0, 0,
};

static void print_escaped(const uint8_t *data, size_t length)
{
  for (size_t i = 0; i < length; i++)
  {
    switch (data[i])
    {
    case '\"':
    case '\'':
    case '\\':
      wprintf(L"\\%hc", data[i]);
      break;

    default:
      if (data[i] >= 127)
        wprintf(L"\\%03o", data[i]);
      else if (data[i] >= 32)
        wprintf(L"%hc", data[i]);
      else if (cescapes[data[i]] != 0)
        wprintf(L"\\%hc", cescapes[data[i]]);
      else
        wprintf(L"\\%03o", data[i]);
    }
  }
}

static void print_hex_string(const uint8_t *data, int length)
{
  for (int i = 0; i < min(64, length); i++)
    wprintf(L"%s%02X", (i == 0 ? L"" : L" "), data[i]);

  if (length > 64)
    wprintf(L" ...");
}

static void print_error(int error)
{
  switch (error)
  {
  case ERROR_SUCCESS:
    break;
  case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
    fprintf(stderr, "can not attach to process (try running as root)\n");
    break;
  case ERROR_INSUFFICIENT_MEMORY:
    fprintf(stderr, "not enough memory\n");
    break;
  case ERROR_SCAN_TIMEOUT:
    fprintf(stderr, "scanning timed out\n");
    break;
  case ERROR_COULD_NOT_OPEN_FILE:
    fprintf(stderr, "could not open file\n");
    break;
  case ERROR_UNSUPPORTED_FILE_VERSION:
    fprintf(stderr, "rules were compiled with a different version of YARA\n");
    break;
  case ERROR_INVALID_FILE:
    fprintf(stderr, "invalid compiled rules file.\n");
    break;
  case ERROR_CORRUPT_FILE:
    fprintf(stderr, "corrupt compiled rules file.\n");
    break;
  case ERROR_EXEC_STACK_OVERFLOW:
    fprintf(
        stderr,
        "stack overflow while evaluating condition "
        "(see --stack-size argument) \n");
    break;
  case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE:
    fprintf(stderr, "invalid type for external variable\n");
    break;
  case ERROR_TOO_MANY_MATCHES:
    fprintf(stderr, "too many matches\n");
    break;
  default:
    fprintf(stderr, "error: %d\n", error);
    break;
  }
}

static void print_scanner_error(YR_SCANNER *scanner, int error)
{
  YR_RULE *rule = yr_scanner_last_error_rule(scanner);
  YR_STRING *string = yr_scanner_last_error_string(scanner);

  if (rule != NULL && string != NULL)
  {
    fprintf(
        stderr,
        "string \"%s\" in rule \"%s\" caused ",
        string->identifier,
        rule->identifier);
  }
  else if (rule != NULL)
  {
    fprintf(stderr, "rule \"%s\" caused ", rule->identifier);
  }

  print_error(error);
}

static void print_compiler_error(
    int error_level,
    const char *file_name,
    int line_number,
    const YR_RULE *rule,
    const char *message,
    void *user_data)
{
  char *msg_type;
  if (error_level == YARA_ERROR_LEVEL_ERROR)
  {
    msg_type = "error";
  }
  else if (!ignore_warnings)
  {
    COMPILER_RESULTS *compiler_results = (COMPILER_RESULTS *) user_data;
    compiler_results->warnings++;
    msg_type = "warning";
  }
  else
  {
    return;
  }

  if (rule != NULL)
  {
    fprintf(
        stderr,
        "%s: rule \"%s\" in %s(%d): %s\n",
        msg_type,
        rule->identifier,
        file_name,
        line_number,
        message);
  }
  else
  {
    fprintf(
        stderr,
        "%s(%d): %s: %s\n",
        file_name,
        line_number,
        msg_type,
        message);
  }
}

static void print_rules_stats(YR_RULES *rules)
{
  YR_RULES_STATS stats;

  int t = sizeof(stats.top_ac_match_list_lengths) /
          sizeof(stats.top_ac_match_list_lengths[0]);

  int result = yr_rules_get_stats(rules, &stats);

  if (result != ERROR_SUCCESS)
  {
    print_error(result);
    return;
  }

  wprintf(L"size of AC transition table        : %d\n", stats.ac_tables_size);

  wprintf(
      L"average length of AC matches lists : %f\n",
      stats.ac_average_match_list_length);

  wprintf(L"number of rules                    : %d\n", stats.num_rules);

  wprintf(L"number of strings                  : %d\n", stats.num_strings);

  wprintf(L"number of AC matches               : %d\n", stats.ac_matches);

  wprintf(
      L"number of AC matches in root node  : %d\n",
      stats.ac_root_match_list_length);

  wprintf(L"number of AC matches in top %d longest lists\n", t);

  for (int i = 0; i < t; i++)
    wprintf(L" %3d: %d\n", i + 1, stats.top_ac_match_list_lengths[i]);

  wprintf(L"match list length percentiles\n");

  for (int i = 100; i >= 0; i--)
    wprintf(L" %3d: %d\n", i, stats.ac_match_list_length_pctls[i]);
}

static int handle_message(
    YR_SCAN_CONTEXT *context,
    int message,
    YR_RULE *rule,
    void *data)
{
  const char *tag;
  bool show = true;

  if (tags[0] != NULL)
  {
    // The user specified one or more -t <tag> arguments, let's show this rule
    // only if it's tagged with some of the specified tags.

    show = false;

    for (int i = 0; !show && tags[i] != NULL; i++)
    {
      char *tag_a = unicode_to_ansi(tags[i]);
      yr_rule_tags_foreach(rule, tag)
      {
        if (strcmp(tag, tag_a) == 0)
        {
          show = true;
          break;
        }
      }
    }
  }

  if (identifiers[0] != NULL)
  {
    // The user specified one or more -i <identifier> arguments, let's show
    // this rule only if it's identifier is among of the provided ones.

    show = false;

    for (int i = 0; !show && identifiers[i] != NULL; i++)
    {
      char *identifier = unicode_to_ansi(identifiers[i]);
      if (strcmp(identifier, rule->identifier) == 0)
      {
        show = true;
        break;
      }
    }
  }

  bool is_matching = (message == CALLBACK_MSG_RULE_MATCHING);

  show = show && ((!negate && is_matching) || (negate && !is_matching));

  if (show && !print_count_only)
  {
    Position *position = ((YR_TTD_ITERATOR_CTX *) context->iterator->context)
                             ->scan_cursor->position;
    wprintf(L"%llx:%llx @ ", position->major, position->minor);

    if (show_namespace)
      wprintf(L"%hs:", rule->ns->name);

    wprintf(L"%hs ", rule->identifier);

    if (show_tags)
    {
      wprintf(L"[");

      yr_rule_tags_foreach(rule, tag)
      {
        // print a comma except for the first tag
        if (tag != rule->tags)
          wprintf(L",");

        wprintf(L"%hs", tag);
      }

      wprintf(L"] ");
    }

    // Show meta-data.

    if (show_meta)
    {
      YR_META *meta;

      wprintf(L"[");

      yr_rule_metas_foreach(rule, meta)
      {
        if (meta != rule->metas)
          wprintf(L",");

        if (meta->type == META_TYPE_INTEGER)
        {
          wprintf(L"%hs =%I64d", meta->identifier, meta->integer);
        }
        else if (meta->type == META_TYPE_BOOLEAN)
        {
          wprintf(
              L"%hs=%hs", meta->identifier, meta->integer ? "true" : "false");
        }
        else
        {
          wprintf(L"%hs=\"", meta->identifier);
          print_escaped((uint8_t *) (meta->string), strlen(meta->string));
          wprintf(L"\"");
        }
      }

      wprintf(L"] ");
    }

    wprintf(L"%s\n", ((CALLBACK_ARGS *) data)->file_path);

    // Show matched strings.

    if (show_strings || show_string_length || show_xor_key)
    {
      YR_STRING *string;

      yr_rule_strings_foreach(rule, string)
      {
        YR_MATCH *match;

        yr_string_matches_foreach(context, string, match)
        {
          wprintf(L"%llx:%llx @ ", position->major, position->minor);

          if (show_string_length)
            wprintf(
                L"0x%I64x:%d:%hs",
                match->base + match->offset,
                match->data_length,
                string->identifier);
          else
            wprintf(
                L"0x%I64x:%hs",
                match->base + match->offset,
                string->identifier);

          if (show_xor_key)
          {
            wprintf(L":xor(0x%02x,", match->xor_key);
            print_string(match->data, match->data_length, match->xor_key);
            wprintf(L")");
          }

          if (show_strings)
          {
            wprintf(L": ");

            if (STRING_IS_HEX(string))
              print_hex_string(match->data, match->data_length);
            else
              print_string(match->data, match->data_length, 0);
          }

          wprintf(L"\n");
        }
      }
    }
  }

  if (is_matching)
  {
    ((CALLBACK_ARGS *) data)->current_count++;
    total_count++;
  }

  if (limit != 0 && total_count >= limit)
    return CALLBACK_ABORT;

  return CALLBACK_CONTINUE;
}

static int callback(
    YR_SCAN_CONTEXT *context,
    int message,
    void *message_data,
    void *user_data)
{
  YR_MODULE_IMPORT *mi;
  YR_STRING *string;
  YR_RULE *rule;
  YR_OBJECT *object;
  MODULE_DATA *module_data;

  switch (message)
  {
  case CALLBACK_MSG_RULE_MATCHING:
  case CALLBACK_MSG_RULE_NOT_MATCHING:
    return handle_message(
        context, message, (YR_RULE *) message_data, user_data);

  case CALLBACK_MSG_IMPORT_MODULE:

    mi = (YR_MODULE_IMPORT *) message_data;
    module_data = modules_data_list;

    while (module_data != NULL)
    {
      if (strcmp(module_data->module_name, mi->module_name) == 0)
      {
        mi->module_data = (void *) module_data->mapped_file.data;
        mi->module_data_size = module_data->mapped_file.size;
        break;
      }

      module_data = module_data->next;
    }

    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_MODULE_IMPORTED:

    if (show_module_data)
    {
      object = (YR_OBJECT *) message_data;

      // In Windows restore stdout to normal text mode as yr_object_print_data
      // calls printf which is not supported in UTF-8 mode.
      // Explicitly flush the buffer before the switch in case we already
      // printed something and it haven't been flushed automatically.
      fflush(stdout);
      _setmode(_fileno(stdout), _O_TEXT);
      yr_object_print_data(object, 0, 1);
      printf("\n");

      // Go back to UTF-8 mode.
      // Explicitly flush the buffer before the switch in case we already
      // printed something and it haven't been flushed automatically.
      fflush(stdout);
      _setmode(_fileno(stdout), _O_U8TEXT);
    }

    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_TOO_MANY_MATCHES:
    if (ignore_warnings)
      return CALLBACK_CONTINUE;

    string = (YR_STRING *) message_data;
    rule = &context->rules->rules_table[string->rule_idx];

    fprintf(
        stderr,
        "warning: rule \"%s\": too many matches for %s, results for this "
        "rule "
        "may be incorrect\n",
        rule->identifier,
        string->identifier);

    if (fail_on_warnings)
      return CALLBACK_ERROR;

    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_CONSOLE_LOG:
    wprintf(L"%hs\n", (char *) message_data);
    return CALLBACK_CONTINUE;
  }

  return CALLBACK_ERROR;
}

static int load_modules_data()
{
  for (int i = 0; modules_data[i] != NULL; i++)
  {
    wchar_t *equal_sign = wcschr(modules_data[i], L'=');

    if (!equal_sign)
    {
      fwprintf(stderr, L"error: wrong syntax for `-x` option.\n");
      return false;
    }

    *equal_sign = L'\0';

    MODULE_DATA *module_data = (MODULE_DATA *) malloc(sizeof(MODULE_DATA));

    if (module_data != NULL)
    {
      module_data->module_name = unicode_to_ansi(modules_data[i]);

      char *rem = unicode_to_ansi(equal_sign + 1);
      int result = yr_filemap_map(rem, &module_data->mapped_file);

      if (result != ERROR_SUCCESS)
      {
        free(module_data);

        fwprintf(
            stderr, L"error: could not open file \"%s\".\n", equal_sign + 1);

        return false;
      }

      module_data->next = modules_data_list;
      modules_data_list = module_data;
    }
  }

  return true;
}

static void unload_modules_data()
{
  MODULE_DATA *module_data = modules_data_list;

  while (module_data != NULL)
  {
    MODULE_DATA *next_module_data = module_data->next;

    yr_filemap_unmap(&module_data->mapped_file);
    free(module_data);

    module_data = next_module_data;
  }

  modules_data_list = NULL;
}

int wmain(int argc, const wchar_t **argv)
{
  COMPILER_RESULTS cr;

  YR_COMPILER *compiler = NULL;
  YR_RULES *rules = NULL;
  YR_SCANNER *scanner = NULL;
  SCAN_OPTIONS scan_opts;

  bool arg_is_dir = false;
  int flags = 0;
  int result;

  argc = args_parse(options, argc, argv);

  scan_opts.follow_symlinks = follow_symlinks;
  scan_opts.recursive_search = recursive_search;

  if (show_version)
  {
    printf("%s\n", YR_VERSION);
    return EXIT_SUCCESS;
  }

  if (show_help)
  {
    printf(
        "YARA %s, the pattern matching swiss army knife.\n"
        "%s\n\n"
        "Mandatory arguments to long options are mandatory for "
        "short options too.\n\n",
        YR_VERSION,
        USAGE_STRING);

    args_print_usage(options, 43);
    printf(
        "\nSend bug reports and suggestions to: vmalvarez@virustotal.com.\n");

    return EXIT_SUCCESS;
  }

  if (threads > YR_MAX_THREADS)
  {
    fprintf(stderr, "maximum number of threads is %d\n", YR_MAX_THREADS);
    return EXIT_FAILURE;
  }

  // This can be done before yr_initialize() because we aren't calling any
  // module functions, just accessing the name pointer for each module.
  if (show_module_names)
  {
    for (YR_MODULE *module = yr_modules_get_table(); module->name != NULL;
         module++)
    {
      printf("%s\n", module->name);
    }
    return EXIT_SUCCESS;
  }

  if (argc < 2)
  {
    // After parsing the command-line options we expect two additional
    // arguments, the rules file and the target file, directory or pid to
    // be scanned.

    fprintf(stderr, "yara-ttd: wrong number of arguments\n");
    fprintf(stderr, "%s\n\n", USAGE_STRING);
    fprintf(stderr, "Try `--help` for more options\n");

    return EXIT_FAILURE;
  }

#if defined(_WIN32) && defined(_UNICODE)
  // In Windows set stdout to UTF-8 mode.
  if (_setmode(_fileno(stdout), _O_U8TEXT) == -1)
  {
    return EXIT_FAILURE;
  }
#endif

  if (!load_modules_data())
    exit_with_code(EXIT_FAILURE);

  result = yr_initialize();

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "error: initialization error (%d)\n", result);
    exit_with_code(EXIT_FAILURE);
  }

  yr_set_configuration_uint32(YR_CONFIG_STACK_SIZE, (uint32_t) stack_size);

  yr_set_configuration_uint32(
      YR_CONFIG_MAX_STRINGS_PER_RULE, (uint32_t) max_strings_per_rule);

  yr_set_configuration_uint64(
      YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK, max_process_memory_chunk);

  if (scan_functions_file && args_file_parse(
                                 scan_functions_file,
                                 (wchar_t **) &scan_functions,
                                 MAX_ARGS_SCAN_FUNCTION))
  {
    exit_with_code(EXIT_FAILURE);
  }

  if (scan_cursors_file &&
      args_file_parse(
          scan_cursors_file, (wchar_t **) &scan_cursors, MAX_ARGS_SCAN_CURSOR))
  {
    exit_with_code(EXIT_FAILURE);
  }

  // Try to load the rules file as a binary file containing
  // compiled rules first

  if (rules_are_compiled)
  {
    // When a binary file containing compiled rules is provided, yara accepts
    // only two arguments, the compiled rules file and the target to be
    // scanned.

    if (argc != 2)
    {
      fprintf(
          stderr,
          "error: can't accept multiple rules files if one of them is in "
          "compiled form.\n");
      exit_with_code(EXIT_FAILURE);
    }

    // Not using yr_rules_load because it does not have support for unicode
    // file names. Instead use open _tfopen for openning the file and
    // yr_rules_load_stream for loading the rules from it.

    FILE *fh = _wfopen(argv[0], L"rb");

    if (fh != NULL)
    {
      YR_STREAM stream;

      stream.user_data = fh;
      stream.read = (YR_STREAM_READ_FUNC) fread;

      result = yr_rules_load_stream(&stream, &rules);

      fclose(fh);

      if (result == ERROR_SUCCESS)
        result = define_external_variables(ext_vars, rules, NULL);
    }
    else
    {
      result = ERROR_COULD_NOT_OPEN_FILE;
    }
  }
  else
  {
    // Rules file didn't contain compiled rules, let's handle it
    // as a text file containing rules in source form.

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
      exit_with_code(EXIT_FAILURE);

    result = define_external_variables(ext_vars, NULL, compiler);

    if (result != ERROR_SUCCESS)
    {
      print_error(result);
      exit_with_code(EXIT_FAILURE);
    }

    if (atom_quality_table != NULL)
    {
      result = yr_compiler_load_atom_quality_table(
          compiler, unicode_to_ansi(atom_quality_table), 0);

      if (result != ERROR_SUCCESS)
      {
        fprintf(stderr, "error loading atom quality table: ");
        print_error(result);
        exit_with_code(EXIT_FAILURE);
      }
    }

    cr.errors = 0;
    cr.warnings = 0;

    yr_compiler_set_callback(compiler, print_compiler_error, &cr);

    if (!compile_files(compiler, argc, argv))
      exit_with_code(EXIT_FAILURE);

    if (cr.errors > 0)
      exit_with_code(EXIT_FAILURE);

    if (fail_on_warnings && cr.warnings > 0)
      exit_with_code(EXIT_FAILURE);

    result = yr_compiler_get_rules(compiler, &rules);

    yr_compiler_destroy(compiler);

    compiler = NULL;
  }

  if (result != ERROR_SUCCESS)
  {
    print_error(result);
    exit_with_code(EXIT_FAILURE);
  }

  if (show_stats)
    print_rules_stats(rules);

  if (fast_scan)
    flags |= SCAN_FLAGS_FAST_MODE;

  scan_opts.deadline = time(NULL) + timeout;

  arg_is_dir = is_directory(argv[argc - 1]);

  Vect *filenames = NULL;
  if (vect_create(&filenames) != ERROR_SUCCESS)
  {
    fwprintf(stderr, L"[ERROR]: Cannot create filenames vector.\n");
    exit_with_code(EXIT_FAILURE);
  }

  if (scan_list_search && arg_is_dir)
  {
    fwprintf(stderr, L"[ERROR]: Cannot use a directory as scan list.\n");
    exit_with_code(EXIT_FAILURE);
  }
  else if (arg_is_dir)
  {
    if (get_filenames_from_dir(filenames, argv[argc - 1], &scan_opts) !=
        ERROR_SUCCESS)
    {
      fwprintf(stderr, L"[ERROR]: Cannot get filenames from directory.\n");
      exit_with_code(EXIT_FAILURE);
    }
  }
  else if (scan_list_search)
  {
    if (get_filenames_from_scan_list(filenames, argv[argc - 1]) !=
        ERROR_SUCCESS)
    {
      fwprintf(stderr, L"[ERROR]: Cannot get filenames from directory.\n");
      exit_with_code(EXIT_FAILURE);
    }
  }
  else
  {
    wchar_t *filename = yr_calloc(wcslen(argv[argc - 1]) + 1, sizeof(wchar_t));
    wcscpy(filename, argv[argc - 1]);
    if (vect_add_element(filenames, filename) != ERROR_SUCCESS)
    {
      fwprintf(stderr, L"[ERROR]: Cannot add filename to vector.\n");
      exit_with_code(EXIT_FAILURE);
    }
  }

  for (int k = 0; k < filenames->count; k++)
  {
    wchar_t *filename = filenames->elements[k];
    CALLBACK_ARGS user_data = {filename, 0};

    result = yr_scanner_create(rules, &scanner);

    if (result != ERROR_SUCCESS)
    {
      fwprintf(stderr, L"[ERROR]: %d\n", result);
      exit_with_code(EXIT_FAILURE);
    }

    yr_scanner_set_callback(scanner, callback, &user_data);
    yr_scanner_set_flags(scanner, flags);
    yr_scanner_set_timeout(scanner, timeout);

    // Assume the last argument is a trace file.
    result = scan_ttd(scanner, filename);
    if (result != ERROR_SUCCESS)
    {
      fwprintf(stderr, L"[ERROR]: error scanning %s: ", filename);
      print_scanner_error(scanner, result);
      exit_with_code(EXIT_FAILURE);
    }

    if (print_count_only)
      wprintf(L"%d\n", user_data.current_count);

#ifdef YR_PROFILING_ENABLED
    yr_scanner_print_profiling_info(scanner);
#endif

    if (k + 1 < filenames->count)
      wprintf(L"-----------------------------------------------\n\n");
  }

  result = EXIT_SUCCESS;

_exit:

  unload_modules_data();

  if (scanner != NULL)
    yr_scanner_destroy(scanner);

  if (compiler != NULL)
    yr_compiler_destroy(compiler);

  if (rules != NULL)
    yr_rules_destroy(rules);

  yr_finalize();

  args_free(options);

  return result;
}
