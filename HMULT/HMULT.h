/*! 
* \file 
* \details      This file implements the different HMULT operations     
* \date         2023 
* \warning      None of the functions implemented here check if the values of the Ciphertexts belong to the ring. 
* \warning      None of the functions implemented here check if the Ciphertexts values arrays are correctly allocated.
* @param[in]    Ciphertext1, plaintext1         The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
#ifndef HMULT_H
#define HMULT_H

#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"

// int HMULT_naive_bad(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


int HMULT_naive(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);
int HMULT_naive_auto_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);
int HMULT_naive_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);
int HMULT_naive_vect_unroll(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


int HMULT_barrett(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);
int HMULT_barrett_auto_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);
int HMULT_barrett_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);
int HMULT_barrett_vect_unroll(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


#endif