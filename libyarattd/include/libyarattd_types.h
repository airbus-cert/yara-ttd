
#ifndef LIBYARATTD_TYPES_H
#define LIBYARATTD_TYPES_H

#include <Windows.h>

#include "libyarattd_ttd_types.h"
#include "libyarattd_vect.h"

// Used to bound the function names in the -F parameter
#define MAX_LENGTH_FUNCTION_NAME 256
#define MAX_LENGTH_PATH          256

#define TRY(error)                     \
  if (error != ERROR_SUCCESS)          \
  {                                    \
    return ERROR_INTERNAL_FATAL_ERROR; \
  }

// Describes a function name, module and address
typedef struct YR_TTD_FUNCTION
{
  wchar_t* module;
  wchar_t* name;
  GuestAddress address;
} YR_TTD_FUNCTION;

// Memory scan stategy that will be applied
typedef enum YR_TTD_SCAN_MODE
{
  SCAN_MODE_MODULES,        // only scan the loaded modules
  SCAN_MODE_VIRTUAL_ALLOC,  // scan the modules and the heap
  SCAN_MODE_ALL             // scan all the memory
} YR_TTD_SCAN_MODE;

// Describes a range in memory
typedef struct YR_TTD_MEMORY_RANGE
{
  GuestAddress start;
  GuestAddress end;
} YR_TTD_MEMORY_RANGE;

// Descibes an event with a time and space range in memory
typedef struct YR_TTD_EVENT
{
  // Space position
  YR_TTD_MEMORY_RANGE* range;

  // Time position
  Position* start;
  Position* end;
} YR_TTD_EVENT;

// Holds the virtual alloc map to keep track of the heap at a given time
typedef struct YR_TTD_VIRTUAL_ALLOC_MAP
{
  Vect* map;

  // Helpers for building the map
  GuestAddress ret_address;
  GuestAddress ret_value;
} YR_TTD_VIRTUAL_ALLOC_MAP;

// Scheduler that stores and launches scans at a given cursor depending on its
// cursors' map build during the init
typedef struct YR_TTD_SCHEDULER
{
  // Scheduler arguments
  const wchar_t* path;         // path of the trace file
  YR_TTD_SCAN_MODE scan_mode;  // memory scan mode stategy that will be used

  Vect* cursors;    // cursors to scan
  Vect* functions;  // functions to scan

  YR_TTD_FUNCTION*
      nt_allocate_virtual_memory;  // ntdll!NtAllocateVirtualMemory information
  YR_TTD_VIRTUAL_ALLOC_MAP*
      virtual_alloc_map;  // map to trace the heap at a given position

  TTD_Replay_ReplayEngine* engine;  // TTD engine
  TTD_Replay_ICursor* cursor;       // TTD cursor
} YR_TTD_SCHEDULER;

// Improved position to describe the cursors to scan
typedef struct YR_TTD_SCAN_CURSOR
{
  Position* position;
  wchar_t*
      source;  // A short string to describe where does this cursor come from
} YR_TTD_SCAN_CURSOR;

// Iterator context to keep track of scan data for yara
typedef struct _YR_TTD_ITERATOR_CTX
{
  // TTD internals
  TTD_Replay_ReplayEngine* engine;
  TTD_Replay_ICursor* cursor;

  // yara internals
  YR_MEMORY_BLOCK current_block;
  GuestAddress current_address;
  GuestAddress max_address;

  // buffers used to querry memory
  TBuffer* buffer;
  size_t buffer_size;
  struct MemoryBuffer* memory_buffer;

  // memory
  Vect* memory_map;  // Memory ranges that should be scan at a given position
  unsigned int
      current_memory_range;    // Current memory range index in the memory_map
  YR_TTD_SCAN_MODE scan_mode;  // Memory scan strategy
  YR_TTD_SCAN_CURSOR* scan_cursor;  // position of the scan cursor

  YR_TTD_VIRTUAL_ALLOC_MAP*
      virtual_alloc_map;  // map to trace the heap at a given position
} YR_TTD_ITERATOR_CTX;

#endif
