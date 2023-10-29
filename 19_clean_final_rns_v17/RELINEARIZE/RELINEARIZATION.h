/*! 
* \file 
* \details      This file implements the different Relinearization operations   
* \date         2023 
* \warning      None of the functions implemented here check if the values of Ciphertext1 belong to the ring. 
* \warning      None of the functions implemented here check if the Ciphertext1 values arrays are correctly allocated.
* @param[in]    Ciphertext, relinearization_keys   The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                   The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
#ifndef RELINEARIZATION_H
#define RELINEARIZATION_H

#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"



int relinearize_naive(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result);

int relinearize_naive_auto(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result);

int relinearize_naive_vect(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result);


// corrected
int relinearize_naive_vect_2(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result);


// outer vectorization
// int relinearize_naive_vect_3(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result);

int relinearize_naive_vect_unroll(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result);


int relinearize_barrett(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result);

int relinearize_barrett_auto(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result);


int relinearize_barrett_vect(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result);


int relinearize_barrett_vect_unroll(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result);


#endif