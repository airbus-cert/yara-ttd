#ifndef LIBYARATTD_UTILS_H
#define LIBYARATTD_UTILS_H

#include "libyarattd_types.h"

int get_scan_all_range(YR_TTD_ITERATOR_CTX* ctx);

/*
  Function:  get_modules_memory_ranges
  --------------------
  fetches all the modules on the current cursor
  adds all the memory ranges of the modules found to the memory map

   memoryMap: memory map to update
   cursor: current cursor in the TTD trace
 */
int get_modules_memory_ranges(YR_TTD_ITERATOR_CTX* ctx);

/*
  Function:  get_qword_at_address
  --------------------
  fetches the memory at the given address and return the QWord (8 bytes) at
  that address Usefull to get the value inside a register, like [rdx]
 */
GuestAddress get_qword_at_address(
    TTD_Replay_ICursor* cursor,
    GuestAddress address);

int check_run_file(const wchar_t* filename);
int check_idx_file(const wchar_t* filename);

// const
static const unsigned char TRACE_MAGIC_BYTES[] = {
    0x54,
    0x54,
    0x44,
    0x4C,
    0x6F,
    0x67,
    0x00,
    0x18,
    0x42,
    0x97,
    0x57,
    0xD5,
    0x8B,
    0x05,
    0xC5,
    0x88};

#endif