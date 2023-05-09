#ifndef LIBYARATTD_VIRTUAL_ALLOC_H
#define LIBYARATTD_VIRTUAL_ALLOC_H

#include "libyarattd_types.h"

#define STEP_FORWARD 10000

/*
  Function: virtual_alloc_callback
  --------------------
  Function to call when a callback is triggered
  callback_value: value passed at callback registering

  For the arguments, two cases:
  addr_func: called function address
  addr_ret: return address after the call
        OR
  addr_ret is 0
  addr_func is the current returned address
*/
int virtual_alloc_callback(
    unsigned long long callback_value,
    GuestAddress addr_func,
    GuestAddress addr_ret,
    struct TTD_Replay_IThreadView* thread_info);

/*
  Function:  get_virtual_alloc_ranges
  --------------------
  Fetches the heap memory ranges regarding the VirtualAlloc map
  The map will be built if needed
 */
int get_virtual_alloc_ranges(YR_TTD_ITERATOR_CTX* ctx);

/*
  Function:  build_virtual_alloc_map
  --------------------
  Builds the VirtualAlloc map by replaying the whole trace
  Traces the calls to VirtualAlloc/Free and store the state of the heap
  The result will be stored inside ctx->virtualAllocMap
 */
int build_virtual_alloc_map(YR_TTD_SCHEDULER* sch);

int build_virtual_alloc_map_from_cache(
    YR_TTD_SCHEDULER* scheduler,
    char* cache_file);

#endif