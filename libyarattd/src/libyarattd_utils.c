
#include "libyarattd_utils.h"
#include <windows.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/libyara.h>
#include <yara/mem.h>

// utils

int get_scan_all_range(YR_TTD_ITERATOR_CTX* ctx)
{
  SYSTEM_INFO* systemInfo = ctx->engine->IReplayEngine->GetSystemInfo(
      ctx->engine);
  YR_TTD_MEMORY_RANGE* range = (YR_TTD_MEMORY_RANGE*) yr_malloc(
      sizeof(YR_TTD_MEMORY_RANGE));
  range->start = (GuestAddress) systemInfo->lpMinimumApplicationAddress;
  range->end = (GuestAddress) systemInfo->lpMaximumApplicationAddress;
  if (vect_add_element(ctx->memory_map, range) != ERROR_SUCCESS)
    return ERROR_INTERNAL_FATAL_ERROR;

  return ERROR_SUCCESS;
}

int get_modules_memory_ranges(YR_TTD_ITERATOR_CTX* ctx)
{
  unsigned long long moduleCount = ctx->cursor->ICursor->GetModuleCount(
      ctx->cursor);
  TTD_Replay_ModuleInstance* modules = ctx->cursor->ICursor->GetModuleList(
      ctx->cursor);

  // Fetch the addresses of all the modules
  int k = 0;
  for (int i = 0; i < moduleCount; i++)
  {
    TTD_Replay_Module* module = modules[i].module;
    YR_TTD_MEMORY_RANGE* range = (YR_TTD_MEMORY_RANGE*) yr_malloc(
        sizeof(YR_TTD_MEMORY_RANGE));
    if (!range)
      return ERROR_INTERNAL_FATAL_ERROR;

    range->start = module->base_addr;
    range->end = module->base_addr + modules[i].module->image_size;
    if (vect_add_element(ctx->memory_map, range) != ERROR_SUCCESS)
      return ERROR_INTERNAL_FATAL_ERROR;

    k++;
  }

  return ERROR_SUCCESS;
}

GuestAddress get_qword_at_address(
    TTD_Replay_ICursor* cursor,
    GuestAddress address)
{
  MemoryBuffer memory_buffer;
  TBuffer buf;
  buf.size = sizeof(void*);
  buf.dst_buffer = yr_malloc(buf.size);

  if (!buf.dst_buffer)
    return 0;

  cursor->ICursor->QueryMemoryBuffer(cursor, &memory_buffer, address, &buf, 0);

  if (memory_buffer.data == NULL)
    return 0;

  GuestAddress value = *((GuestAddress*) memory_buffer.data);
  yr_free(memory_buffer.data);
  return value;
}

int check_run_file(const wchar_t* filename)
{
  YR_FILE_DESCRIPTOR fd = CreateFile(
      filename,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN,
      NULL);

  if (fd == INVALID_HANDLE_VALUE)
  {
    return ERROR_COULD_NOT_OPEN_FILE;
  }

  // check if it's a valid trace
  unsigned char buf[16] = {0};
  DWORD nread;

  if (GetFileSize(fd, NULL) < 16)
    return ERROR_COULD_NOT_OPEN_FILE;

  if (!ReadFile(fd, buf, 16, &nread, NULL))
    return ERROR_COULD_NOT_OPEN_FILE;

  for (int i = 0; i < 16; i++)
  {
    if (buf[i] != TRACE_MAGIC_BYTES[i])
      return ERROR_COULD_NOT_OPEN_FILE;
  }

  return ERROR_SUCCESS;
}

int check_idx_file(const wchar_t* filename)
{
  // Assumes that the filename is the one of the trace file
  // TODO use magic bytes instead of extension
  size_t len = wcslen(filename);
  if (len < 3)
    return ERROR_COULD_NOT_OPEN_FILE;

  wchar_t* idx_path = (wchar_t*) yr_calloc(MAX_PATH, sizeof(wchar_t));
  memset(idx_path, 0, MAX_PATH);
  wcscpy(idx_path, filename);
  idx_path[len - 3] = L'i';
  idx_path[len - 2] = L'd';
  idx_path[len - 1] = L'x';

  YR_FILE_DESCRIPTOR fd = CreateFile(
      idx_path,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN,
      NULL);

  yr_free(idx_path);
  if (fd == INVALID_HANDLE_VALUE)
    return ERROR_COULD_NOT_OPEN_FILE;

  return ERROR_SUCCESS;
}
