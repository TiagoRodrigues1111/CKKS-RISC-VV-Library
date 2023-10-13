#ifndef INITIALIZATION_H
#define INITIALIZATION_H


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "datastructures.h"

/*
#define MATCH_CASE_SENSITIVE 0
#define MATCH_CASE_INSENSITIVE 1
*/


        /**
        * Calculates the Area of the circle.
        * Formula: Area = PI*r^2
        * @param[in] radius
        * @param[out] error codes
        */
        
        
        
int Create_ciphertext(struct ciphertext *Ciphertext_to_create, uint32_t Polynomial_Degree_Modulus, uint32_t *Coefficient_Modulus,uint64_t *barrett_aux_values, uint8_t number_of_polynomials, uint8_t rns_number);

int Create_plaintext(struct plaintext *plaintext, uint32_t Polynomial_Degree_Modulus);
//int Create_relinearization_keys(struct relinearization_keys *relinearization_key,uint32_t Polynomial_Degree_Modulus /*Add here secret*/);

int initiate_to_random_ciphertext(struct ciphertext *Ciphertext);
int initiate_to_constant_ciphertext(struct ciphertext *Ciphertext, uint64_t value);     
//      int initiate_to_specific_ciphertext(struct ciphertext *Ciphertext, long *values_to_put[2]);     
int initiate_to_random_plaintext(struct plaintext *plaintext,uint32_t Coefficient_Modulus);
int initiate_to_constant_plaintext(struct plaintext *plaintext, int64_t value); 
//      int initiate_to_specific_plaintext(struct plaintext *plaintext, long *values_to_put);   


int compare_ciphertext_values(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2);

int check_ciphertext_values(struct ciphertext ciphertext_to_check);

int free_ciphertext(struct ciphertext *Ciphertext);
int free_plaintext(struct plaintext *plaintext);
int free_relinearize_keys(struct relinearization_keys *relinearization_key);


int grab_console_values(int argc, char *argv[], uint32_t *Polynomial_Degree_Modulus, uint32_t *Coefficient_Modulus);


void start_timing(struct timing_variable *timing_variable1);
void end_timing(struct timing_variable *timing_variable1);

void print_timing(struct timing_variable timing_variable1);
void print_timing_excel(struct timing_variable timing_variable1);
int print_ciphertext(struct ciphertext Ciphertext);
int print_plaintext(struct plaintext plaintext);
        
        
//int power(int base, unsigned int exp);

int create_barret_values(int k, int m);

void print_timing_poly(struct timing_variable timing_variable1);


#endif