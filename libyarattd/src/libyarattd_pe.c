
#include "libyarattd_pe.h"

// Helpers

// get the VA of the modules NT Header
PIMAGE_DOS_HEADER get_dos_header(
    YR_TTD_SCHEDULER* sch,
    GuestAddress ui_library_address,
    MemoryBuffer* memory_buffer,
    TBuffer* buf)
{
  buf->size = sizeof(IMAGE_DOS_HEADER);
  buf->dst_buffer = yr_malloc(buf->size);
  sch->cursor->ICursor->QueryMemoryBuffer(
      sch->cursor, memory_buffer, (GuestAddress) ui_library_address, buf, 0);
  return (PIMAGE_DOS_HEADER) buf->dst_buffer;
}

PIMAGE_NT_HEADERS get_nt_headers(
    YR_TTD_SCHEDULER* sch,
    GuestAddress ui_library_address,
    PIMAGE_DOS_HEADER dos_header,
    MemoryBuffer* memory_buffer,
    TBuffer* buf)
{
  PIMAGE_NT_HEADERS p_nt_headers =
      (PIMAGE_NT_HEADERS) (ui_library_address + dos_header->e_lfanew);
  buf->size = sizeof(IMAGE_NT_HEADERS);
  buf->dst_buffer = yr_malloc(buf->size);
  sch->cursor->ICursor->QueryMemoryBuffer(
      sch->cursor, memory_buffer, (GuestAddress) p_nt_headers, buf, 0);

  return (PIMAGE_NT_HEADERS) buf->dst_buffer;
}

PIMAGE_DATA_DIRECTORY get_data_directory(PIMAGE_NT_HEADERS p_nt_headers)
{
  return (PIMAGE_DATA_DIRECTORY) &p_nt_headers->OptionalHeader
      .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
}

PIMAGE_EXPORT_DIRECTORY get_export_directory(
    YR_TTD_SCHEDULER* sch,
    GuestAddress ui_library_address,
    PIMAGE_DATA_DIRECTORY p_data_directory,
    MemoryBuffer* memory_buffer,
    TBuffer* buf)
{
  // get the VA of the export directory
  GuestAddress address =
      (GuestAddress) (ui_library_address + p_data_directory->VirtualAddress);

  buf->size = sizeof(IMAGE_EXPORT_DIRECTORY);
  buf->dst_buffer = yr_malloc(buf->size);
  sch->cursor->ICursor->QueryMemoryBuffer(
      sch->cursor, memory_buffer, address, buf, 0);

  return (PIMAGE_EXPORT_DIRECTORY) buf->dst_buffer;
}

DWORD* get_function_names(
    YR_TTD_SCHEDULER* sch,
    GuestAddress ui_name_array,
    PIMAGE_EXPORT_DIRECTORY p_export_directory,
    MemoryBuffer* memory_buffer,
    TBuffer* buf)
{
  buf->size = sizeof(DWORD*) * p_export_directory->NumberOfFunctions;
  buf->dst_buffer = yr_malloc(buf->size);
  sch->cursor->ICursor->QueryMemoryBuffer(
      sch->cursor, memory_buffer, ui_name_array, buf, 0);

  return (DWORD*) buf->dst_buffer;
}

GuestAddress get_given_function_address(
    YR_TTD_SCHEDULER* sch,
    YR_TTD_FUNCTION* function,
    GuestAddress ui_library_address,
    GuestAddress ui_name_ordinals,
    GuestAddress ui_address_array,
    DWORD* p_function_names,
    PIMAGE_EXPORT_DIRECTORY p_export_directory,
    MemoryBuffer* memory_buffer,
    TBuffer* buf)
{
  buf->size = sizeof(char) *
              MAX_LENGTH_FUNCTION_NAME;  // max function name length
  char* name_a = (char*) yr_malloc(buf->size);
  for (int j = 0; j < (int) p_export_directory->NumberOfNames; j++)
  {
    buf->dst_buffer = name_a;
    sch->cursor->ICursor->QueryMemoryBuffer(
        sch->cursor,
        memory_buffer,
        (GuestAddress) (ui_library_address + p_function_names[j]),
        buf,
        0);

    // convert name to wchar_t
    wchar_t name_w[MAX_LENGTH_FUNCTION_NAME];
    mbstowcs(name_w, name_a, MAX_LENGTH_FUNCTION_NAME);

    if (wcscmp(name_w, function->name) == 0)
    {
      buf->size = sizeof(DWORD);
      buf->dst_buffer = (void*) yr_malloc(buf->size);
      sch->cursor->ICursor->QueryMemoryBuffer(
          sch->cursor,
          memory_buffer,
          (GuestAddress) (ui_name_ordinals + j * sizeof(WORD)),
          buf,
          0);

      WORD* ordinal = buf->dst_buffer;
      buf->size = sizeof(LPVOID);
      sch->cursor->ICursor->QueryMemoryBuffer(
          sch->cursor,
          memory_buffer,
          (GuestAddress) (ui_address_array + *ordinal * sizeof(DWORD)),
          buf,
          0);

      DWORD* offset = buf->dst_buffer;
      GuestAddress address = (GuestAddress) (ui_library_address + *offset);

      yr_free(buf->dst_buffer);
      yr_free(name_a);

      return address;
    }
  }

  return 0;
}

int resolve_function_address(YR_TTD_SCHEDULER* sch, YR_TTD_FUNCTION* function)
{
  // Init the address to 0 ie not found
  function->address = 0;

  // Save current cursor position
  Position saved_position = *sch->cursor->ICursor->GetPosition(sch->cursor, 0);

  // Search if the module is used by the process
  unsigned int module_count =
      sch->engine->IReplayEngine->GetModuleLoadedEventCount(sch->engine);
  TTD_Replay_ModuleLoadedEvent* modules =
      sch->engine->IReplayEngine->GetModuleLoadedEventList(sch->engine);

  unsigned int i = 0;
  wchar_t* cpy = yr_calloc(MAX_LENGTH_FUNCTION_NAME, sizeof(wchar_t));
  while (i < module_count)
  {
    wchar_t* tmp = cpy;
    wcscpy(tmp, modules[i].info->path);

    wchar_t* buf = NULL;
    while (*tmp) buf = wcstok(tmp, L"\\", &tmp);

    buf = wcstok(buf, L".", NULL);

    if (wcscmp(buf, function->module) == NULL)
      break;

    i++;
  };

  yr_free(cpy);
  // If the module is not found, return an error
  if (i == module_count)
  {
    wprintf(L"Module %s not found\n", function->module);
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  sch->cursor->ICursor->SetPosition(sch->cursor, &modules[i].pos);

  UINT_PTR ui_library_address = (UINT_PTR) modules[i].info->base_addr;
  UINT_PTR ui_address_array = 0;
  UINT_PTR ui_name_array = 0;
  UINT_PTR ui_name_ordinals = 0;

  MemoryBuffer* memory_buffer = (struct MemoryBuffer*) yr_malloc(
      sizeof(struct MemoryBuffer));
  TBuffer* buf = (struct TBuffer*) yr_malloc(sizeof(struct TBuffer));
  if (buf == NULL || memory_buffer == NULL)
    return ERROR_INTERNAL_FATAL_ERROR;

  PIMAGE_DOS_HEADER dos_header = get_dos_header(
      sch, ui_library_address, memory_buffer, buf);

  PIMAGE_NT_HEADERS p_nt_headers = get_nt_headers(
      sch, ui_library_address, dos_header, memory_buffer, buf);

  PIMAGE_DATA_DIRECTORY p_data_directory = get_data_directory(p_nt_headers);

  PIMAGE_EXPORT_DIRECTORY p_export_directory = get_export_directory(
      sch, ui_library_address, p_data_directory, memory_buffer, buf);

  // get the VA for the array of addresses
  ui_address_array =
      (ui_library_address + p_export_directory->AddressOfFunctions);

  // get the VA for the array of name pointers
  ui_name_array = (ui_library_address + p_export_directory->AddressOfNames);

  // get the VA for the array of name ordinals
  ui_name_ordinals =
      (ui_library_address + p_export_directory->AddressOfNameOrdinals);

  DWORD* p_function_names = get_function_names(
      sch, ui_name_array, p_export_directory, memory_buffer, buf);

  function->address = get_given_function_address(
      sch,
      function,
      ui_library_address,
      ui_name_ordinals,
      ui_address_array,
      p_function_names,
      p_export_directory,
      memory_buffer,
      buf);

  yr_free(dos_header);
  yr_free(p_nt_headers);
  yr_free(p_export_directory);
  yr_free(p_function_names);
  yr_free(buf);
  yr_free(memory_buffer);

  sch->cursor->ICursor->SetPosition(sch->cursor, &saved_position);
  return ERROR_SUCCESS;
}
