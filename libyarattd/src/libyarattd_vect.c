
#include "libyarattd_vect.h"
#include <yara/error.h>
#include <yara/mem.h>

int vect_create(Vect** out)
{
  Vect* map = (Vect*) yr_malloc(sizeof(Vect));
  if (!map)
    return ERROR_INTERNAL_FATAL_ERROR;

  map->count = 0;
  map->capacity = 1;
  map->elements = yr_malloc(sizeof(void*) * map->capacity);
  if (!map->elements)
  {
    yr_free(map);
    return ERROR_INTERNAL_FATAL_ERROR;
  }

  *out = map;
  return ERROR_SUCCESS;
}

int vect_add_element(Vect* map, void* element)
{
  if (map->count + 1 >= map->capacity)
  {
    map->capacity = map->capacity * 2 + 1;
    map->elements = yr_realloc(map->elements, sizeof(void*) * map->capacity);
    if (!map->elements)
      return ERROR_INTERNAL_FATAL_ERROR;
  }

  map->elements[map->count++] = element;
  return ERROR_SUCCESS;
}

int vect_delete(Vect* map)
{
  for (int i = 0; i < map->count; i++)
  {
    yr_free(map->elements[i]);
    map->elements[i] = NULL;
  }

  yr_free(map->elements);
  yr_free(map);
  return ERROR_SUCCESS;
}

int vect_reset(Vect** map)
{
  int res;

  if (res = vect_delete(*map))
    return res;

  return vect_create(map);
}
