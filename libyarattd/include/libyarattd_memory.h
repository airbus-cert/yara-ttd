
#ifndef YR_TTD_MEMORY_H
#define YR_TTD_MEMORY_H

#include "ttd_types.h"

typedef struct MemoryRange
{
  GuestAddress start;
  GuestAddress end;
} MemoryRange;

/*
  Function:  get_qword_at_address
  --------------------
  fetches the memory at the given address and return the QWord (8 bytes) at
  that address Usefull to get the value inside a register, like [rdx]
 */
__int64 get_qword_at_address(TTD_Replay_ICursor* cursor, GuestAddress address);

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

#endif
