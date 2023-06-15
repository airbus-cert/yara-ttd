
#include "libyarattd_scanner.h"
#include "libyarattd_crypto.h"
#include "libyarattd_ttd.h"
#include "libyarattd_virtual_alloc.h"

YR_API int yr_scanner_scan_ttd(
    YR_TTD_SCHEDULER* scheduler,
    YR_SCANNER* scanner,
    YR_TTD_SCAN_CURSOR* scan_cursor)
{
  if (scheduler->scan_mode < 0 || scheduler->scan_mode > 2)
    return ERROR_WRONG_ARGUMENTS;

  YR_MEMORY_BLOCK_ITERATOR iterator;
  int result = yr_ttd_open_iterator(scheduler, &iterator, scan_cursor);

  if (result == ERROR_SUCCESS)
  {
    int prev_flags = scanner->flags;
    scanner->flags |= SCAN_FLAGS_PROCESS_MEMORY;
    result = yr_scanner_scan_mem_blocks(scanner, &iterator);
    scanner->flags = prev_flags;
    yr_ttd_close_iterator(&iterator);
  }
  return result;
}

YR_API int yr_ttd_open_iterator(
    YR_TTD_SCHEDULER* scheduler,
    YR_MEMORY_BLOCK_ITERATOR* iterator,
    YR_TTD_SCAN_CURSOR* scan_cursor)
{
  YR_TTD_ITERATOR_CTX* context = (YR_TTD_ITERATOR_CTX*) yr_malloc(
      sizeof(YR_TTD_ITERATOR_CTX));
  if (!context)
    return ERROR_INTERNAL_FATAL_ERROR;

  context->engine = scheduler->engine;
  context->cursor = scheduler->cursor;
  context->current_block.context = context;
  context->scan_mode = scheduler->scan_mode;
  context->virtual_alloc_map = scheduler->virtual_alloc_map;

  context->scan_cursor = scan_cursor;
  context->cursor->ICursor->SetPosition(context->cursor, scan_cursor->position);
  Position* check = context->cursor->ICursor->GetPosition(context->cursor, 0);
  if (check->major != scan_cursor->position->major ||
      check->minor != scan_cursor->position->minor)
    wprintf(
        L"[WARNING] Fail to set scan position, scanning %llx:%llx instead\n",
        check->major,
        check->minor);

  if (vect_create(&context->memory_map) != ERROR_SUCCESS)
    return ERROR_INTERNAL_FATAL_ERROR;

  iterator->context = context;
  iterator->first = yr_ttd_get_first_memory_block;
  iterator->next = yr_ttd_get_next_memory_block;
  iterator->last_error = ERROR_SUCCESS;
  iterator->file_size = NULL;

  return ERROR_SUCCESS;
}

YR_API const uint8_t* yr_ttd_fetch_memory_block_data(YR_MEMORY_BLOCK* block)
{
  YR_TTD_ITERATOR_CTX* ctx = (YR_TTD_ITERATOR_CTX*) block->context;
  if (!ctx->memory_buffer)
    ctx->memory_buffer = (MemoryBuffer*) yr_malloc(sizeof(MemoryBuffer));

  if (!ctx->buffer)
    ctx->buffer = (TBuffer*) yr_malloc(sizeof(TBuffer));

  if (ctx->buffer_size < block->size)
  {
    if (ctx->buffer->dst_buffer)
      yr_free(ctx->buffer->dst_buffer);

    ctx->buffer->dst_buffer = (void*) yr_malloc(block->size);
    if (NULL == ctx->buffer->dst_buffer)
    {
      ctx->buffer_size = 0;
      return NULL;
    }

    ctx->buffer->size = block->size;
  }

  ctx->cursor->ICursor->QueryMemoryBuffer(
      ctx->cursor, ctx->memory_buffer, ctx->current_address, ctx->buffer, 0);

  return ctx->memory_buffer->data;
}

YR_API YR_MEMORY_BLOCK* yr_ttd_get_next_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_TTD_ITERATOR_CTX* ctx = (YR_TTD_ITERATOR_CTX*) iterator->context;

  ctx->current_address += ctx->current_block.size;
  ctx->current_block.base = ctx->current_address;

  // If we reach the end of the current memory range
  if (ctx->current_address > ctx->max_address)
  {
    if (++ctx->current_memory_range == ctx->memory_map->count)
      return NULL;

    // Work on the next memory range in the map
    YR_TTD_MEMORY_RANGE* next =
        (YR_TTD_MEMORY_RANGE*) (ctx->memory_map->elements[ctx->current_memory_range]);
    ctx->max_address = next->end;
    ctx->current_address = next->start;
    ctx->current_block.base = ctx->current_address;
  }

  return &ctx->current_block;
}

YR_API YR_MEMORY_BLOCK* yr_ttd_get_first_memory_block(
    YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_TTD_ITERATOR_CTX* ctx = (YR_TTD_ITERATOR_CTX*) iterator->context;

  // Set scan mode for memory
  if (ctx->scan_mode == SCAN_MODE_ALL &&
      get_scan_all_range(ctx) != ERROR_SUCCESS)
  {
    fwprintf(stdout, L"[ERROR] Fail to fetch GetSystemInfo range\n\n");
    return NULL;
  }

  if ((ctx->scan_mode == SCAN_MODE_MODULES ||
       ctx->scan_mode == SCAN_MODE_VIRTUAL_ALLOC) &&
      get_modules_memory_ranges(ctx) != ERROR_SUCCESS)
  {
    fwprintf(stdout, L"[ERROR] Fail to fetch modules memory ranges\n\n");
    return NULL;
  }

  if (ctx->scan_mode == SCAN_MODE_VIRTUAL_ALLOC &&
      get_virtual_alloc_ranges(ctx) != ERROR_SUCCESS)
  {
    fwprintf(stdout, L"[ERROR] Fail to fetch virtual allocated ranges\n\n");
    return NULL;
  }

  if (ctx->memory_map->count == 0)
    return NULL;

  ctx->current_memory_range = 0;
  YR_TTD_MEMORY_RANGE* range =
      (YR_TTD_MEMORY_RANGE*) (ctx->memory_map->elements[ctx->current_memory_range]);
  ctx->max_address = range->end;
  ctx->current_address = range->start;
  ctx->current_block.base = ctx->current_address;
  ctx->current_block.size = 4096;
  ctx->current_block.fetch_data = yr_ttd_fetch_memory_block_data;

  return &ctx->current_block;
}

int yr_ttd_close_iterator(YR_MEMORY_BLOCK_ITERATOR* iterator)
{
  YR_TTD_ITERATOR_CTX* ctx = (YR_TTD_ITERATOR_CTX*) iterator->context;
  if (ctx->memory_buffer)
    yr_free(ctx->memory_buffer);

  if (ctx->buffer)
    yr_free(ctx->buffer);

  if (ctx->memory_map)
    vect_delete(ctx->memory_map);

  yr_free(ctx);
}