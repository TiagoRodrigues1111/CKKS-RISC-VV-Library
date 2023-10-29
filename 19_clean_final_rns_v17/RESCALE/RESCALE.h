#ifndef RESCALE_H
#define RESCALE_H
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"




int RESCALE(struct ciphertext *Ciphertext_result,struct ciphertext Ciphertext1, int64_t scale_factor);
int RESCALE_auto_vect(struct ciphertext *Ciphertext_result,struct ciphertext Ciphertext1, int64_t scale_factor);
int RESCALE_vect(struct ciphertext *Ciphertext_result,struct ciphertext Ciphertext1, int64_t scale_factor);
int RESCALE_vect_unroll(struct ciphertext *Ciphertext_result,struct ciphertext Ciphertext1, int64_t scale_factor);



#endif
