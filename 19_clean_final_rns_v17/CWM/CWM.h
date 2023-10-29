#ifndef CWM_H
#define CWM_H


#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"


int CWM(struct ciphertext Ciphertext1,struct ciphertext Ciphertex2,struct ciphertext *Ciphertext_result);
int CWM_true(struct ciphertext Ciphertext1,struct ciphertext Ciphertex2,struct ciphertext *Ciphertext_result);
int CWM_true_vectorial(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2,struct ciphertext *Ciphertext_result);
int CWM_true_mod_comp(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2,struct ciphertext *Ciphertext_result);


int CWM_true_barrett(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2,struct ciphertext *Ciphertext_result);
int CWM_true_vectorial_barrett(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2,struct ciphertext *Ciphertext_result);

#endif
