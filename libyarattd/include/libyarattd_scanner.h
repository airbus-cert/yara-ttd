
#ifndef LIBYARATTD_SCANNER_H
#define LIBYARATTD_SCANNER_H

#include "libyarattd_utils.h"

YR_API int yr_scanner_scan_ttd(
    YR_TTD_SCHEDULER* scheduler,
    YR_SCANNER* scanner,
    YR_TTD_SCAN_CURSOR* scan_cursor);

YR_API int yr_ttd_open_iterator(
    YR_TTD_SCHEDULER* scheduler,
    YR_MEMORY_BLOCK_ITERATOR* iterator,
    YR_TTD_SCAN_CURSOR* scan_cursor);

YR_API YR_MEMORY_BLOCK* yr_ttd_get_first_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator);

YR_API YR_MEMORY_BLOCK* yr_ttd_get_next_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator);

YR_API const uint8_t* yr_ttd_fetch_memory_block_data(YR_MEMORY_BLOCK* block);

YR_API int yr_ttd_close_iterator(YR_MEMORY_BLOCK_ITERATOR* iterator);

#endif