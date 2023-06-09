
#ifndef LIBYARATTD_SCHEDULER_H
#define LIBYARATTD_SCHEDULER_H

#include "libyarattd_types.h"

int init_scan_cursors(YR_TTD_SCHEDULER* scheduler, wchar_t** scan_cursor_arg);
int init_scan_functions(
    YR_TTD_SCHEDULER* scheduler,
    wchar_t** scan_function_arg);
int init_scan_default(YR_TTD_SCHEDULER* scheduler);
int init_virtual_alloc_mode(YR_TTD_SCHEDULER* scheduler, wchar_t* cache_file);

int scheduler_init(
    YR_TTD_SCHEDULER** out,
    const wchar_t* path,
    YR_TTD_SCAN_MODE scan_mode,
    wchar_t** cursors,
    wchar_t** functions,
    wchar_t* cache_file);
int scheduler_add_cursor(
    YR_TTD_SCHEDULER* scheduler,
    YR_TTD_POSITION* position);
int scheduler_add_function(
    YR_TTD_SCHEDULER* scheduler,
    YR_TTD_FUNCTION* new_function);
int scheduler_add_cursors_from_function(
    YR_TTD_SCHEDULER* scheduler,
    YR_TTD_FUNCTION* function);
int scheduler_delete(YR_TTD_SCHEDULER* scheduler);

#endif