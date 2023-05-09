
#ifndef LIBYARATTD_VECT_H
#define LIBYARATTD_VECT_H

typedef struct Vect
{
  int count;
  int capacity;
  void **elements;
} Vect;

int vect_create(Vect **out);
int vect_add_element(Vect *vect, void *element);
int vect_delete(Vect *vect);
int vect_reset(Vect **vect);

#endif