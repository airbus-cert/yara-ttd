
#include <yara/error.h>
#include "libyarattd_utils.h"
#include "libyarattd_crypto.h"
#include "libyarattd_ttd.h"

int init_ttd_engine(TTD_Replay_ReplayEngine** engine, const wchar_t* filename)
{
  HINSTANCE h_ttd_replay_library;
  PROC_Initiate InitiateReplayEngineHandshake;
  PROC_Create CreateReplayEngineWithHandshake;
  BYTE source[48];
  char destination[336];
  yr_sha256_ctx ctx;
  unsigned char digest[YR_SHA256_LEN];

  h_ttd_replay_library = LoadLibrary(TEXT("TTDReplay.dll"));

  if (h_ttd_replay_library == NULL)
  {
    fwprintf(stderr, L"TTDReplay.dll not found\n");
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  InitiateReplayEngineHandshake = (PROC_Initiate) GetProcAddress(
      h_ttd_replay_library, "InitiateReplayEngineHandshake");
  CreateReplayEngineWithHandshake = (PROC_Create) GetProcAddress(
      h_ttd_replay_library, "CreateReplayEngineWithHandshake");

  int result = InitiateReplayEngineHandshake("DbgEng", source);

  strncpy(destination, (char*) source, 0x2F);
  for (int i = 0; i < 2; ++i)
  {
    strncat(
        destination,
        &A_SCOPE_OF_LICENSE[0x66 * ((source[i] - 48) % 0x11ui64)],
        0x65ui64);
  }
  strncat(
      destination,
      &A_TTD_ENGINE_KEY[79 * ((source[2] - 48i64) % 0xBui64)],
      0x4Eui64);

  yr_sha256_init(&ctx);
  yr_sha256_update(
      &ctx, (unsigned char*) destination, (DWORD) strlen(destination));
  yr_sha256_final(digest, &ctx);

  size_t sha_b64_size;
  char* sha_b64 = base64_encode(digest, 32, &sha_b64_size);
  char tmp[0x30];
  memset(tmp, 0, 0x30);
  memcpy(tmp, sha_b64, sha_b64_size);

  void* instance;
  result = CreateReplayEngineWithHandshake(tmp, &instance, VERSION_GUID);
  *engine = (TTD_Replay_ReplayEngine*) instance;

  if ((*engine)->IReplayEngine->Initialize((*engine), filename) != TRUE)
  {
    fwprintf(stdout, L"Failed to initialize ReplayEngine\n");
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  // Generate if needed the idx file of the trace file. This file is needed by
  // TTDReplay.dll to call some API endpoints like GetCrossPlatformContext
  build_index_from_engine(*engine);
  if (check_idx_file(filename) != ERROR_SUCCESS)
  {
    fwprintf(stderr, L"Failed to generate index file\n");
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  return ERROR_SUCCESS;
}

char* base64_encode(
    const unsigned char* data,
    size_t input_length,
    size_t* output_length)
{
  *output_length = 4 * ((input_length + 2) / 3);

  char* encoded_data = (char*) yr_malloc(*output_length);
  if (encoded_data == NULL)
    return NULL;

  for (int i = 0, j = 0; i < input_length;)
  {
    uint32_t octet_a = i < input_length ? (unsigned char) data[i++] : 0;
    uint32_t octet_b = i < input_length ? (unsigned char) data[i++] : 0;
    uint32_t octet_c = i < input_length ? (unsigned char) data[i++] : 0;

    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

    encoded_data[j++] = ENCODING_TABLE[(triple >> 3 * 6) & 0x3F];
    encoded_data[j++] = ENCODING_TABLE[(triple >> 2 * 6) & 0x3F];
    encoded_data[j++] = ENCODING_TABLE[(triple >> 1 * 6) & 0x3F];
    encoded_data[j++] = ENCODING_TABLE[(triple >> 0 * 6) & 0x3F];
  }

  // no padding
  for (int i = 0; i < MOD_TABLE[input_length % 3]; i++)
    encoded_data[*output_length - 1 - i] = '\x00';

  return encoded_data;
}

void dummy_callback() {}
void build_index_from_engine(TTD_Replay_ReplayEngine* engine)
{
  engine->IReplayEngine->BuildIndex(engine, &dummy_callback);
}
