
#ifndef LIBYARATTD_PE_H
#define LIBYARATTD_PE_H

#include "libyarattd_types.h"

/*
  Function:  resolve_function_address
  --------------------
  Fetches the address of a given function in the PE headers of the loaded
  modules If not found, returns -1
 */
int resolve_function_address(YR_TTD_SCHEDULER* ctx, YR_TTD_FUNCTION* function);

#endif
