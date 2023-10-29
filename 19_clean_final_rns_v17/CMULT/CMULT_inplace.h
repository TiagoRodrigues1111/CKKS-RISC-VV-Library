/*! 
* \file 
* \details      This file implements the different CMULT operations     
* \date         2023 
* \warning      None of the functions implemented here check if the values of Ciphertext1 belong to the ring. 
* \warning      None of the functions implemented here check if the Ciphertext1 values arrays are correctly allocated.
* @param[in]    Ciphertext1, plaintext1         The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
#ifndef CMULT_INPLACE_H
#define CMULT_INPLACE_H

#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"

// int CMULT_naive_bad(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);
int CMULT_naive_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);
int CMULT_naive_auto_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);
int CMULT_naive_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);
int CMULT_naive_vect_unroll_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);
int CMULT_naive_vect_unroll_2_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);


int CMULT_barrett_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);
int CMULT_barrett_auto_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);
int CMULT_barrett_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);
int CMULT_barrett_vect_unroll_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);


#endif