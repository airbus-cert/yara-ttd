
#include "libyarattd_virtual_alloc.h"
#include "libyarattd_utils.h"

int virtual_alloc_callback(
    unsigned long long callback_value,
    GuestAddress addr_func,
    GuestAddress addr_ret,
    struct TTD_Replay_IThreadView* thread_info)
{
  YR_TTD_SCHEDULER* sch = (YR_TTD_SCHEDULER*) callback_value;
  if (addr_func == sch->nt_allocate_virtual_memory->address)
  {
    Position save = *sch->cursor->ICursor->GetPosition(sch->cursor, 0);

    YR_TTD_EVENT* event = (YR_TTD_EVENT*) yr_malloc(sizeof(YR_TTD_EVENT));
    YR_TTD_MEMORY_RANGE* range = (YR_TTD_MEMORY_RANGE*) yr_malloc(
        sizeof(YR_TTD_MEMORY_RANGE));
    if (!event || !range)
      return CALLBACK_ERROR;
    event->start = (Position*) yr_malloc(sizeof(Position));
    // event->end = (Position*) yr_malloc(sizeof(Position));
    if (!event->start)
      return CALLBACK_ERROR;

    // Set the cursor at the callback position
    Position* current = thread_info->IThreadView->GetPosition(thread_info);
    sch->cursor->ICursor->SetPosition(sch->cursor, current);

    // Fetch context
    PCONTEXT ctxt = (PCONTEXT) yr_malloc(0xA70);
    if (!ctxt)
      return CALLBACK_ERROR;

    sch->cursor->ICursor->GetCrossPlatformContext(
        sch->cursor,
        ctxt,
        thread_info->IThreadView->GetThreadInfo(thread_info)->threadid);

    // size of VirtualAlloc in [r9] for this syscall
    range->end = get_qword_at_address(sch->cursor, ctxt->R9);

    // returned value will be in [rdx] for this syscall
    sch->virtual_alloc_map->ret_value = ctxt->Rdx;

    event->range = range;
    if (vect_add_element(sch->virtual_alloc_map->map, event) != ERROR_SUCCESS)
      return CALLBACK_ERROR;

    sch->cursor->ICursor->SetPosition(sch->cursor, &save);
    sch->virtual_alloc_map->ret_address = addr_ret;
  }

  else if (
      sch->virtual_alloc_map->ret_address &&
      sch->virtual_alloc_map->ret_address == addr_func)
  {
    Position save = *sch->cursor->ICursor->GetPosition(sch->cursor, 0);

    // Set the cursor at the callback position
    Position* current = thread_info->IThreadView->GetPosition(thread_info);
    sch->cursor->ICursor->SetPosition(sch->cursor, current);

    GuestAddress returned = get_qword_at_address(
        sch->cursor, sch->virtual_alloc_map->ret_value);

    YR_TTD_EVENT* event =
        sch->virtual_alloc_map->map
            ->elements[sch->virtual_alloc_map->map->count - 1];
    event->start->major = current->major;
    event->start->minor = current->minor;
    event->range->start = returned;
    event->range->end += returned;

    sch->virtual_alloc_map->ret_address = 0;
    sch->virtual_alloc_map->ret_value = 0;

    sch->cursor->ICursor->SetPosition(sch->cursor, &save);
  }

  return CALLBACK_CONTINUE;
}

int get_virtual_alloc_ranges(YR_TTD_ITERATOR_CTX* ctx)
{
  int k = 0;
  Position* current = ctx->cursor->ICursor->GetPosition(ctx->cursor, 0);
  for (int i = 0; i < ctx->virtual_alloc_map->map->count; i++)
  {
    YR_TTD_EVENT* event = (YR_TTD_EVENT*)
                              ctx->virtual_alloc_map->map->elements[i];
    Position* start = event->start;

    // Test if current is between start and end
    if (start->major == -1 || start->major < current->major ||
        (start->major == current->major && start->minor <= current->minor))
    {
      // Create a copy of the range
      YR_TTD_MEMORY_RANGE* range = (YR_TTD_MEMORY_RANGE*) yr_malloc(
          sizeof(YR_TTD_MEMORY_RANGE));
      range->start = event->range->start;
      range->end = event->range->end;

      // Add the memory range to the MemoryMap
      if (vect_add_element(ctx->memory_map, range) != ERROR_SUCCESS)
        return ERROR_INTERNAL_FATAL_ERROR;

      k++;
    }
  }

  return ERROR_SUCCESS;
}

int build_virtual_alloc_map_from_cache(
    YR_TTD_SCHEDULER* scheduler,
    char* cache_file)
{
  wchar_t cache_file_w[MAX_LENGTH_PATH];
  mbstowcs(cache_file_w, cache_file, MAX_LENGTH_PATH);

  YR_FILE_DESCRIPTOR fd = CreateFile(
      cache_file_w,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN,
      NULL);

  if (fd == INVALID_HANDLE_VALUE)
    return ERROR_FILE_NOT_FOUND;

  int nread;
  size_t size = GetFileSize(fd, NULL);
  wchar_t* buf = yr_calloc(size, sizeof(wchar_t));
  if (!buf)
  {
    CloseHandle(fd);
    return ERROR_FILE_NOT_FOUND;
  }

  if (!ReadFile(fd, buf, size, &nread, NULL))
  {
    CloseHandle(fd);
    return ERROR_FILE_NOT_FOUND;
  }

  wchar_t* line = NULL;
  int i = 0;
  int len = 4 * 0x10 + 4;

  Vect* lines = NULL;
  vect_create(&lines);

  line = wcstok(buf, L"\r\n", &buf);
  while (line != NULL)
  {
    vect_add_element(lines, line);
    line = wcstok(buf, L"\r\n", &buf);
  }

  wchar_t* arg = NULL;
  YR_TTD_VIRTUAL_ALLOC_MAP* virtual_alloc_map = yr_malloc(
      sizeof(YR_TTD_VIRTUAL_ALLOC_MAP));
  if (!virtual_alloc_map)
    return ERROR_INTERNAL_FATAL_ERROR;
  TRY(vect_create(&virtual_alloc_map->map));

  for (int i = 0; i < lines->count; i++)
  {
    Position* start = yr_malloc(sizeof(Position));
    YR_TTD_EVENT* event = yr_malloc(sizeof(YR_TTD_EVENT));
    YR_TTD_MEMORY_RANGE* range = yr_malloc(sizeof(YR_TTD_MEMORY_RANGE));
    arg = wcstok(lines->elements[i], L",", &lines->elements[i]);
    start->major = wcstoull(arg, NULL, 16);
    arg = wcstok(lines->elements[i], L",", &lines->elements[i]);
    start->minor = wcstoull(arg, NULL, 16);
    arg = wcstok(lines->elements[i], L",", &lines->elements[i]);
    range->start = wcstoull(arg, NULL, 16);
    arg = wcstok(lines->elements[i], L",", &lines->elements[i]);
    range->end = wcstoull(arg, NULL, 16);
    event->start = start;
    event->range = range;
    vect_add_element(virtual_alloc_map->map, event);
  }

  scheduler->virtual_alloc_map = virtual_alloc_map;

  // FIXME free
  CloseHandle(fd);
  return ERROR_SUCCESS;
}

int build_virtual_alloc_map(YR_TTD_SCHEDULER* scheduler)
{
  // Check that the idx file exists in the same path as the trace file
  // This file is needed by TTDReplay.dll to use
  // ICursor.GetCrossPlatformContext
  if (check_idx_file(scheduler->path) != ERROR_SUCCESS)
  {
    fwprintf(
        stderr,
        L"Error: idx file not found\nTo use the Virtual Alloc mode, you need "
        L"to have the idx file alongside the run file recored by TTD.\nIf "
        L"you "
        L"don't have this file, you can generate it automatically by "
        L"openning the .run file with WinDbg.\n");
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  // Save current cursor position
  Position* last = scheduler->engine->IReplayEngine->GetLastPosition(
      scheduler->engine);

  unsigned long long thread_created_count =
      scheduler->engine->IReplayEngine->GetThreadCreatedEventCount(
          scheduler->engine);
  TTD_Replay_ThreadCreatedEvent* threads_created =
      (TTD_Replay_ThreadCreatedEvent*) yr_malloc(
          thread_created_count * sizeof(TTD_Replay_ThreadInfo*));
  threads_created = scheduler->engine->IReplayEngine->GetThreadCreatedEventList(
      scheduler->engine);

  // set callback
  scheduler->cursor->ICursor->SetCallReturnCallback(
      scheduler->cursor,
      virtual_alloc_callback,
      (unsigned long long) scheduler);

  // loop through all the threads
  Position* start;
  TTD_Replay_ICursorView_ReplayResult replayrez;
  for (int i = 0; i < thread_created_count; i++)
  {
    start = &threads_created[i].pos;

    // set cursor to thread start
    scheduler->cursor->ICursor->SetPosition(scheduler->cursor, start);

    Position previous;
    unsigned long long step_count;

    for (;;)
    {
      Position* now = scheduler->cursor->ICursor->GetPosition(
          scheduler->cursor, 0);
      scheduler->cursor->ICursor->ReplayForward(
          scheduler->cursor, &replayrez, last, STEP_FORWARD);
      step_count = replayrez.stepCount;

      if (replayrez.stepCount < STEP_FORWARD)
      {
        scheduler->cursor->ICursor->SetPosition(scheduler->cursor, &previous);
        scheduler->cursor->ICursor->ReplayForward(
            scheduler->cursor, &replayrez, last, step_count - 1);
        break;
      }
      memcpy(
          &previous,
          scheduler->cursor->ICursor->GetPosition(scheduler->cursor, 0),
          sizeof(previous));
    }
  }

  // restore cursor
  scheduler->cursor->ICursor->SetCallReturnCallback(scheduler->cursor, 0, 0);

  // Save virtual alloc map
  int len = wcslen(scheduler->path);
  wchar_t* cache_path = yr_calloc(len, sizeof(wchar_t));
  wcscpy(cache_path, scheduler->path);
  cache_path[len - 3] = L't';
  cache_path[len - 2] = L'm';
  cache_path[len - 1] = L'p';
  HANDLE fd = CreateFile(
      cache_path,
      GENERIC_WRITE,
      0,
      NULL,
      CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL);

  if (fd == INVALID_HANDLE_VALUE)
    return ERROR_INTERNAL_FATAL_ERROR;

  int written = 0;
  int len_line = 4 * 0x10 + 4;
  int len_lines = len_line * scheduler->virtual_alloc_map->map->count;
  wchar_t* tmp = yr_calloc(len_lines + 1, sizeof(wchar_t));
  for (int i = 0; i < scheduler->virtual_alloc_map->map->count; i++)
  {
    YR_TTD_EVENT* event = scheduler->virtual_alloc_map->map->elements[i];
    wsprintf(
        &tmp[i * len_line],
        L"%p,%p,%p,%p\n",
        event->start->major,
        event->start->minor,
        event->range->start,
        event->range->end);
  }

  WriteFile(fd, tmp, len_lines * 2 + 1, &written, NULL);
  CloseHandle(fd);
  return ERROR_SUCCESS;
}
