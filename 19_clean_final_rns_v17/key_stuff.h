#ifndef KEY_STUFF_H
#define KEY_STUFF_H


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "datastructures.h"


int rand_value_gen(void *input);
int err_function_gen(void *input);
        
int create_secret_key(struct secret_key * secret_key_to_create,uint32_t Polynomial_Degree_Modulus,int (*Rand_Gen_Func)(void*), void *seed_values);
        
int create_public_key_2(struct secret_key secret_key,struct public_key * public_key_to_create,uint32_t Polynomial_Degree_Modulus, uint32_t Coefficient_Modulus,int (*Rand_Gen_Func)(void*),int (*err_gen_func)(void*),void *seed_values);
        
        
int encrypt(struct plaintext plaintext,struct public_key public_key,struct ciphertext * ciphertext_res,int (*Rand_Gen_Func)(void*),int (*err_gen_func1)(void*),int (*err_gen_func2)(void*),void *seed_values);
        
int decrypt(struct ciphertext ciphertext,struct secret_key secret_key,struct plaintext *plaintext_res);
        
int Create_relinearization_keys(struct relinearization_keys *relinearization_keys_to_create, uint32_t Polynomial_Degree_Modulus, struct secret_key secret_key, uint32_t Coefficient_Modulus,int (*Rand_Gen_Func)(void*),int (*err_gen_func)(void*),void *seed_values);
 

int free_secret_key(struct secret_key * secret_key); 
        
#endif