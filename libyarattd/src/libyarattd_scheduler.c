
#include "libyarattd_scheduler.h"
#include "libyarattd_pe.h"
#include "libyarattd_ttd.h"
#include "libyarattd_utils.h"
#include "libyarattd_virtual_alloc.h"

int init_scan_cursors(YR_TTD_SCHEDULER* scheduler, wchar_t** scan_cursor_arg)
{
  if (!scheduler->cursors)
    return ERROR_INTERNAL_FATAL_ERROR;

  if (!scan_cursor_arg[0])
    return ERROR_SUCCESS;

  for (int i = 0; scan_cursor_arg[i]; i++)
  {
    Position* scan_cursor = (Position*) yr_malloc(sizeof(Position));
    if (!scan_cursor)
      return ERROR_INTERNAL_FATAL_ERROR;

    wchar_t* end;
    scan_cursor->major = wcstoull(scan_cursor_arg[i], &end, 16);
    scan_cursor->minor = wcstoull(end + 1, NULL, 16);
    TRY(scheduler_add_cursor(scheduler, scan_cursor, L"yara-ttd -T"));
  }

  return ERROR_SUCCESS;
}

int init_scan_functions(YR_TTD_SCHEDULER* scheduler, wchar_t** scan_functions)
{
  if (!scheduler->functions || !scheduler->cursors)
    return ERROR_INTERNAL_FATAL_ERROR;

  if (!scan_functions[0])
    return ERROR_SUCCESS;

  for (int i = 0; scan_functions[i]; i++)
  {
    YR_TTD_FUNCTION* scan_function = yr_malloc(sizeof(YR_TTD_FUNCTION));
    if (!scan_function)
      return ERROR_INTERNAL_FATAL_ERROR;

    wchar_t full_name[MAX_LENGTH_FUNCTION_NAME];
    wcscpy(full_name, scan_functions[i]);

    wchar_t* name = NULL;
    wchar_t* module = wcstok(full_name, L"!", &name);
    if (!module || !name)
    {
      fwprintf(
          stderr,
          L"[ERROR] Cannot parse function %s\nMake sure to use the format "
          L"module_name!function_name\n",
          scan_functions[i]);
      return ERROR_INTERNAL_FATAL_ERROR;
    }

    scan_function->module = yr_malloc(wcslen(module) * sizeof(wchar_t));
    scan_function->name = yr_malloc(wcslen(name) * sizeof(wchar_t));
    if (!scan_function->module || !scan_function->name)
      return ERROR_INTERNAL_FATAL_ERROR;

    wcscpy(scan_function->module, module);
    wcscpy(scan_function->name, name);

    TRY(resolve_function_address(scheduler, scan_function));
    if (!scan_function->address)
    {
      fwprintf(
          stdout,
          L"[WARNING] Unable to find %s!%s in %s\n",
          scan_function->module,
          scan_function->name,
          scheduler->path);
      continue;
    }

    TRY(scheduler_add_function(scheduler, scan_function));
  }

  return ERROR_SUCCESS;
}

// Default scan mode
int init_scan_default(YR_TTD_SCHEDULER* scheduler)
{
  Position pos;
  size_t exception_count = scheduler->engine->IReplayEngine
                               ->GetExceptionEventCount(scheduler->engine);
  const TTD_Replay_ExceptionEvent* exceptions =
      scheduler->engine->IReplayEngine->GetExceptionEventList(
          scheduler->engine);

  for (unsigned int i = 0; i < exception_count; i++)
  {
    int length = swprintf(
        NULL,
        0,
        L"Exception raised with code 0x%x",
        exceptions[i].info->ExceptionCode);
    wchar_t* source = (wchar_t*) yr_calloc(length + 1, sizeof(wchar_t));
    swprintf(
        source,
        length + 1,
        L"Exception raised with code 0x%x",
        exceptions[i].info->ExceptionCode);

    pos.major = exceptions[i].pos.major;
    pos.minor = exceptions[i].pos.minor;
    scheduler_add_cursor(scheduler, &pos, source);
  }

  size_t thread_created_count =
      scheduler->engine->IReplayEngine->GetThreadCreatedEventCount(
          scheduler->engine);
  const TTD_Replay_ThreadCreatedEvent* threads_created =
      scheduler->engine->IReplayEngine->GetThreadCreatedEventList(
          scheduler->engine);

  for (unsigned int i = 0; i < thread_created_count; i++)
  {
    Position pos = {
        threads_created[i].pos.major,
        threads_created[i].pos.minor,
    };
    scheduler->cursor->ICursor->SetPosition(scheduler->cursor, &pos);
    Position* current = scheduler->cursor->ICursor->GetPosition(
        scheduler->cursor, 0);

    int length = swprintf(
        NULL, 0, L"Thread 0x%x activated", threads_created[i].info->threadid);
    wchar_t* source = (wchar_t*) yr_calloc(length + 1, sizeof(wchar_t));
    swprintf(
        source,
        length + 1,
        L"Thread 0x%x activated",
        threads_created[i].info->threadid);

    pos.major = exceptions[i].pos.major;
    pos.minor = exceptions[i].pos.minor;
    scheduler_add_cursor(scheduler, &pos, source);
  }

  size_t module_count = scheduler->engine->IReplayEngine
                            ->GetModuleLoadedEventCount(scheduler->engine);
  const TTD_Replay_ModuleLoadedEvent* modules =
      scheduler->engine->IReplayEngine->GetModuleLoadedEventList(
          scheduler->engine);

  Position* first = scheduler->engine->IReplayEngine->GetFirstPosition(
      scheduler->engine);

  for (unsigned int i = 0; i < module_count; i++)
  {
    // If the module was loaded before the first cursor, skip it
    if (modules[i].pos.major <= first->major)
      continue;

    int length = swprintf(NULL, 0, L"Module %s loaded", modules[i].info->path);
    wchar_t* source = (wchar_t*) yr_calloc(length + 1, sizeof(wchar_t));
    swprintf(source, length + 1, L"Module %s loaded", modules[i].info->path);

    pos.major = exceptions[i].pos.major;
    pos.minor = exceptions[i].pos.minor;
    scheduler_add_cursor(scheduler, &pos, source);
  }

  return ERROR_SUCCESS;
}

int init_virtual_alloc_mode(YR_TTD_SCHEDULER* scheduler, wchar_t* cache_file)
{
  scheduler->virtual_alloc_map = (YR_TTD_VIRTUAL_ALLOC_MAP*) yr_malloc(
      sizeof(YR_TTD_VIRTUAL_ALLOC_MAP));
  if (!scheduler->virtual_alloc_map)
    return ERROR_INTERNAL_FATAL_ERROR;

  scheduler->virtual_alloc_map->ret_address = 0;
  scheduler->virtual_alloc_map->ret_value = 0;

  scheduler->nt_allocate_virtual_memory = (YR_TTD_FUNCTION*) yr_malloc(
      sizeof(YR_TTD_FUNCTION));
  if (!scheduler->nt_allocate_virtual_memory)
    return ERROR_INTERNAL_FATAL_ERROR;

  scheduler->nt_allocate_virtual_memory->module = L"ntdll";
  scheduler->nt_allocate_virtual_memory->name = L"NtAllocateVirtualMemory";
  TRY(resolve_function_address(
      scheduler, scheduler->nt_allocate_virtual_memory));
  TRY(vect_create(&scheduler->virtual_alloc_map->map));

  if (cache_file)
  {
    TRY(build_virtual_alloc_map_from_cache(scheduler, cache_file));
  }
  else
  {
    TRY(build_virtual_alloc_map(scheduler));
  }
  return ERROR_SUCCESS;
}

int scheduler_init(
    YR_TTD_SCHEDULER** out,
    const wchar_t* path,
    YR_TTD_SCAN_MODE scan_mode,
    wchar_t** cursors,
    wchar_t** functions,
    wchar_t* cache_file)
{
  int result = ERROR_SUCCESS;

  if (check_run_file(path) != ERROR_SUCCESS)
  {
    fwprintf(stderr, L"error: could not open file \"%s\".\n", path);
    return ERROR_COULD_NOT_OPEN_FILE;
  }

  YR_TTD_SCHEDULER* scheduler = (YR_TTD_SCHEDULER*) yr_malloc(
      sizeof(YR_TTD_SCHEDULER));
  if (!scheduler)
    return ERROR_INTERNAL_FATAL_ERROR;

  scheduler->path = path;
  scheduler->scan_mode = scan_mode;

  if (vect_create(&scheduler->cursors) != ERROR_SUCCESS ||
      vect_create(&scheduler->functions) != ERROR_SUCCESS)
  {
    scheduler_delete(scheduler);
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  result = init_ttd_engine(&scheduler->engine, scheduler->path);
  scheduler->cursor = scheduler->engine->IReplayEngine->NewCursor(
      scheduler->engine, GUID_CURSOR);

  result = init_scan_cursors(scheduler, cursors);
  result = init_scan_functions(scheduler, functions);
  if (!cursors[0] && !functions[0])
    result = init_scan_default(scheduler);

  if (scan_mode == SCAN_MODE_VIRTUAL_ALLOC)
    result = init_virtual_alloc_mode(scheduler, cache_file);

  if (result != ERROR_SUCCESS)
  {
    scheduler_delete(scheduler);
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  *out = scheduler;
  return ERROR_SUCCESS;
}

int scheduler_add_cursor(
    YR_TTD_SCHEDULER* scheduler,
    Position* position,
    wchar_t* source)
{
  // Check if it's possible to set the position
  scheduler->cursor->ICursor->SetPosition(scheduler->cursor, position);
  Position* check = scheduler->cursor->ICursor->GetPosition(
      scheduler->cursor, 0);
  if (check->major != position->major || check->minor != position->minor)
    memcpy(position, check, sizeof(Position));

  // If the scheduler is not empty, search for the cursor in the elements
  if (scheduler->cursors->count)
  {
    for (int i = 0; i < scheduler->cursors->count; i++)
    {
      YR_TTD_SCAN_CURSOR* cursor = scheduler->cursors->elements[i];
      if (cursor->position->major == position->major &&
          cursor->position->minor == position->minor)
      {
        int length = swprintf(NULL, 0, L"%s and %s", cursor->source, source);
        yr_realloc(cursor->source, (length + 1) * sizeof(wchar_t));
        swprintf(cursor->source, length, L"%s and %s", cursor->source, source);
        return ERROR_SUCCESS;
      }
    }
  }

  YR_TTD_SCAN_CURSOR* new_cursor = (YR_TTD_SCAN_CURSOR*) yr_malloc(
      sizeof(YR_TTD_SCAN_CURSOR));
  new_cursor->position = position;
  new_cursor->source = source;
  TRY(vect_add_element(scheduler->cursors, new_cursor));
  return ERROR_SUCCESS;
}

int scheduler_add_cursors_from_function(
    YR_TTD_SCHEDULER* scheduler,
    YR_TTD_FUNCTION* function)
{
  Position* first = scheduler->engine->IReplayEngine->GetFirstPosition(
      scheduler->engine);
  Position* last = scheduler->engine->IReplayEngine->GetLastPosition(
      scheduler->engine);

  // Set breakpoint at function address
  scheduler->cursor->ICursor->SetPosition(scheduler->cursor, first);
  TTD_Replay_MemoryWatchpointData data;
  data.addr = function->address;
  data.size = 1;
  data.flags = TTD_BP_FLAGS_EXEC;
  scheduler->cursor->ICursor->AddMemoryWatchpoint(scheduler->cursor, &data);

  Position* current = NULL;
  TTD_Replay_ICursorView_ReplayResult replayrez;

  // Save all the calls to the function
  for (;;)
  {
    // Move forward
    scheduler->cursor->ICursor->ReplayForward(
        scheduler->cursor, &replayrez, last, -1);
    current = scheduler->cursor->ICursor->GetPosition(scheduler->cursor, 0);

    if (current->minor == last->minor && current->major == last->major)
      break;

    // Add the current position to the map
    Position* position_to_scan = (Position*) yr_malloc(sizeof(Position));
    if (!position_to_scan)
      return ERROR_INTERNAL_FATAL_ERROR;
    position_to_scan->major = current->major;
    position_to_scan->minor = current->minor;

    // FIXME BUG MISSING 1 CHARACTER
    int length = swprintf(
        NULL, 0, L"Function %s!%s called", function->module, function->name);
    wchar_t* source = (wchar_t*) yr_calloc(length + 1, sizeof(wchar_t));
    swprintf(
        source,
        length,
        L"Function %s!%s called",
        function->module,
        function->name);

    TRY(scheduler_add_cursor(scheduler, position_to_scan, source));

    // Move forward of 1 instruction, otherwise sometimes the cursor is stuck on
    // the breakpoint
    scheduler->cursor->ICursor->ReplayForward(
        scheduler->cursor, &replayrez, last, 1);
  }

  scheduler->cursor->ICursor->RemoveMemoryWatchpoint(scheduler->cursor, &data);
  return ERROR_SUCCESS;
}

int scheduler_add_function(
    YR_TTD_SCHEDULER* scheduler,
    YR_TTD_FUNCTION* new_function)
{
  // If the scheduler is not empty, search for the function in the elements
  if (scheduler->functions->count)
  {
    YR_TTD_FUNCTION* function = scheduler->functions->elements[0];
    YR_TTD_FUNCTION* end = function + scheduler->functions->count;
    for (; function < end; function++)
    {
      if (function->module == new_function->module &&
          function->name == new_function->name)
        return ERROR_SUCCESS;
    }
  }

  TRY(scheduler_add_cursors_from_function(scheduler, new_function));
  TRY(vect_add_element(scheduler->functions, new_function));
  return ERROR_SUCCESS;
}

int scheduler_delete(YR_TTD_SCHEDULER* scheduler)
{
  if (scheduler->cursors)
    vect_delete(scheduler->cursors);

  if (scheduler->functions)
    vect_delete(scheduler->functions);

  yr_free(scheduler);
  return ERROR_SUCCESS;
}
