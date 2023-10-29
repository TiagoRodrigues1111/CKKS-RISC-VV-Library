#include <math.h>


/* includes */
#include "../initialization.h"
#include "../functions.h"
#include "../datastructures.h"
#include "../key_stuff.h"
#include "../flags.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

/* defines */
// #define VECTOR_OPERATIONS 1
// #define AUTO_VECTOR_OPERATIONS 1
#define OPTSTR "t:"

/* external declarations */

/* typedefs */
struct params{
        
        uint32_t polynomial_degree_modulus;
        uint32_t *coefficient_modulus;
        uint64_t *barrett_auxi_value;
        uint8_t rns_number;
};

struct options{
        
        uint32_t test_to_perform;
        uint32_t function_to_test[2];
        char *function;
};


/* global variable declarations */

/* function prototypes */






// HADD test 
int test_01(struct params params1)
{
        //int (*HADD_function[])(struct ciphertext, struct ciphertext,struct *ciphertext) = {HADD, HADD_auto_vect, HADD_naive_vect};
        
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
               
        // HADD scalar
        printf("function: HADD\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HADD(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }
        

        // HADD_auto_vect
        printf("function: HADD_auto_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HADD_auto_vect(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }       
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }

       
        // HADD_mod_comp
        printf("function: HADD_mod_comp\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HADD_mod_comp(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }       
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }


        // HADD_naive_vect
        printf("function: HADD_naive_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HADD_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }       
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }
        
              
        // HADD_naive_vect vl=128
        printf("function: HADD_naive_vect, vl=128\n");
        asm volatile("csrw 0x805, %0" :: "r"(128));  
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HADD_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }       
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }      
        


        // HADD scalar diferent Q
        printf("function: HADD diffent Q\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                params1.coefficient_modulus[0] = 20000;
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HADD(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }

         
        return 0;         
}




// HSUB test 
int test_02(struct params params1)
{
        //int (*HADD_function[])(struct ciphertext, struct ciphertext,struct *ciphertext) = {HADD, HADD_auto_vect, HADD_naive_vect};
        
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
               
        // HSUB scalar
        printf("function: HSUB\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HSUB(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }
        

        // HSUB_auto_vect
        printf("function: HSUB_auto_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HSUB_auto_vect(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }       
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }

        // HSUB_naive_vect
        printf("function: HSUB_naive_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HSUB_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }       
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }
        
              
        // HSUB_naive_vect vl=128
        printf("function: HSUB_naive_vect, vl=128\n");
        asm volatile("csrw 0x805, %0" :: "r"(128));  
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HSUB_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }       
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }      
        


        // HSUB scalar diferent Q
        printf("function: HSUB diffent Q\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                params1.coefficient_modulus[0] = 20000;
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 7000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        HSUB(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }

         
        return 0;         
}




// CADD test 
int test_03(struct params params1)
{
        //int (*HADD_function[])(struct ciphertext, struct ciphertext,struct *ciphertext) = {HADD, HADD_auto_vect, HADD_naive_vect};
        
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext, ciphertext_result;
        struct plaintext plaintext;
               
        // CADD_naive scalar
        printf("function: CADD_naive\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CADD_naive(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }
        

        // CADD_naive_auto_vect_2
        printf("function: CADD_naive_auto_vect_2\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CADD_naive_auto_vect_2(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }


        // CADD_mod_comp
        printf("function: CADD_mod_comp\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CADD_mod_comp(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }


        // CADD_barrett
        printf("function: CADD_barrett\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CADD_barrett(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }



        // CADD_barrett_auto_vect_2
        printf("function: CADD_barrett_auto_vect_2\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CADD_barrett_auto_vect_2(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }




        // CADD_barrett_vect
        printf("function: CADD_barrett_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CADD_barrett_vect(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }



        // CADD_barrett_vect
        printf("function: CADD_barrett_vect, vl=128\n");
        asm volatile("csrw 0x805, %0" :: "r"(128));   
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CADD_barrett_vect(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }


        // CADD_naive scalar
        printf("function: CADD_naive, Q=500\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                params1.coefficient_modulus[0] = 500;
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 230);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CADD_naive(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }

     
        return 0;         
}



// CSUB test 
int test_04(struct params params1)
{
        //int (*HADD_function[])(struct ciphertext, struct ciphertext,struct *ciphertext) = {HADD, HADD_auto_vect, HADD_naive_vect};
        
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext, ciphertext_result;
        struct plaintext plaintext;
               
        // CSUB_naive scalar
        printf("function: CSUB_naive\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CSUB_naive(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }
        
        // CSUB_barrett
        printf("function: CSUB_barrett\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CSUB_barrett(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }



        // CSUB_barrett_vect
        printf("function: CSUB_barrett_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CSUB_barrett_vect(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }



        // CSUB_barrett_vect
        printf("function: CSUB_barrett_vect, vl=128\n");
        asm volatile("csrw 0x805, %0" :: "r"(128));   
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CSUB_barrett_vect(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }

     
        return 0;         
}








// CWM test 
int test_05(struct params params1)
{
        //int (*HADD_function[])(struct ciphertext, struct ciphertext,struct *ciphertext) = {HADD, HADD_auto_vect, HADD_naive_vect};
        
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
               
        // CWM_true scalar
        printf("function: CWM_true\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 5000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CWM_true(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }
        

        // CWM_true_barrett scalar
        printf("function: CWM_true_barrett\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 5000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CWM_true_barrett(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }


        // CWM_true_vectorial_barrett scalar
        printf("function: CWM_true_vectorial_barrett\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 5000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        CWM_true_vectorial_barrett(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }

       
        return 0;         
}




// CMULT test 
int test_06(struct params params1)
{
        //int (*HADD_function[])(struct ciphertext, struct ciphertext,struct *ciphertext) = {HADD, HADD_auto_vect, HADD_naive_vect};
        
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext, ciphertext_result;
        struct plaintext plaintext;
               
        // CMULT_naive scalar
        printf("function: CMULT_naive\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<3;j++)
                {
                        start_timing(&(timing_variable1));
                        CMULT_naive(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }
        


        // CMULT_barrett scalar
        printf("function: CMULT_barrett\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<3;j++)
                {
                        start_timing(&(timing_variable1));
                        CMULT_barrett(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }



        // CMULT_barrett_vect scalar
        printf("function: CMULT_barrett_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<3;j++)
                {
                        start_timing(&(timing_variable1));
                        CMULT_barrett_vect(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }



        // CMULT_barrett_vect scalar
        printf("function: CMULT_barrett_vect, vl=128\n");
        asm volatile("csrw 0x805, %0" :: "r"(128));   
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_plaintext(&plaintext,params1.polynomial_degree_modulus);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_plaintext(&plaintext, 234567);  
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<3;j++)
                {
                        start_timing(&(timing_variable1));
                        CMULT_barrett_vect(ciphertext,plaintext,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_plaintext(&plaintext);
                free_ciphertext(&ciphertext_result);
                 
        }


    
        return 0;         
}



// HMULT test 
int test_07(struct params params1)
{
 
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
               
        // HMULT_naive scalar
        printf("function: HMULT_naive\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 5001);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<3;j++)
                {
                        start_timing(&(timing_variable1));
                        HMULT_naive(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }
        

        // HMULT_barrett scalar
        printf("function: HMULT_barrett\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 5001);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        HMULT_barrett(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }


        
        
        
         // HMULT_barrett_vect scalar
        printf("function: HMULT_barrett_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext2, 5001);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<5;j++)
                {
                        start_timing(&(timing_variable1));
                        HMULT_barrett_vect(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext2);
                free_ciphertext(&ciphertext_result);
                 
        }
        
     
       
        return 0;         
}





// Relinearize test 
int test_08(struct params params1)
{
        //int (*HADD_function[])(struct ciphertext, struct ciphertext,struct *ciphertext) = {HADD, HADD_auto_vect, HADD_naive_vect};
        
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext, ciphertext_result;
        struct secret_key secret_key1;
        struct relinearization_keys relin_keys;
               
        // relinearize_barrett scalar
        printf("function: relinearize_barrett\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
                create_secret_key(&secret_key1,params1.polynomial_degree_modulus,rand_value_gen, NULL);
                Create_relinearization_keys(&relin_keys,params1.polynomial_degree_modulus, secret_key1,params1.coefficient_modulus[0],rand_value_gen,err_function_gen,NULL);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        relinearize_barrett(ciphertext,relin_keys,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_relinearize_keys(&relin_keys);
                free_secret_key(&secret_key1);
                free_ciphertext(&ciphertext_result);
                 
        }




        // relinearize_barrett_vect scalar
        printf("function: relinearize_barrett_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
                create_secret_key(&secret_key1,params1.polynomial_degree_modulus,rand_value_gen, NULL);
                Create_relinearization_keys(&relin_keys,params1.polynomial_degree_modulus, secret_key1,params1.coefficient_modulus[0],rand_value_gen,err_function_gen,NULL);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext, 10000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        relinearize_barrett_vect(ciphertext,relin_keys,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext);
                free_relinearize_keys(&relin_keys);
                free_secret_key(&secret_key1);
                free_ciphertext(&ciphertext_result);
                 
        }

     

         
        return 0;         
}




// Rescale test 
int test_09(struct params params1)
{
        //int (*HADD_function[])(struct ciphertext, struct ciphertext,struct *ciphertext) = {HADD, HADD_auto_vect, HADD_naive_vect};
        
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext1, ciphertext_result;
               
        // Rescale scalar
        printf("function: RESCALE\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        RESCALE(ciphertext1,500,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext_result);
                 
        }
     

        // RESCALE_auto_vect
        printf("function: RESCALE_auto_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        RESCALE_auto_vect(ciphertext1,500,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext_result);
                 
        }


        // RESCALE_vect
        printf("function: RESCALE_vect\n");
        for(uint32_t i=1;i<=1024;i*=2)
        {
                params1.polynomial_degree_modulus = i;
                
                timing_variable1.polynomial_degree_modulus = params1.polynomial_degree_modulus;   
               
                // Create Ciphertexts  
                Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
                // Initiate ciphertexts with some values
                initiate_to_constant_ciphertext(&ciphertext1, 10000);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);


                for(uint8_t j=0; j<10;j++)
                {
                        start_timing(&(timing_variable1));
                        RESCALE_vect(ciphertext1,500,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing(timing_variable1);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
   
                // Free ciphertexts
                free_ciphertext(&ciphertext1);
                free_ciphertext(&ciphertext_result);
                 
        }        
        
         
        return 0;         
}




// Rescale test correct
int test_10(struct params params1)
{
        //int (*HADD_function[])(struct ciphertext, struct ciphertext,struct *ciphertext) = {HADD, HADD_auto_vect, HADD_naive_vect};
        
        struct ciphertext ciphertext1, ciphertext_result;
                     
        params1.polynomial_degree_modulus = 32;                
        
               
        // Create Ciphertexts  
        Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        // Initiate ciphertexts with some values
        initiate_to_constant_ciphertext(&ciphertext1, 10000);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);

        RESCALE(ciphertext1,500,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
              
   
        RESCALE_vect(ciphertext1,500,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);   
  

   
   
        // Free ciphertexts
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext_result);
        
        return 0;         
}





int main (int argc, char *argv[])
{   
                      
        int opt;
        struct params params1;
        params1.polynomial_degree_modulus = 1024;
        params1.rns_number = 1;      
        params1.coefficient_modulus = (uint32_t*) malloc(1*sizeof(uint32_t));
        params1.barrett_auxi_value = (uint64_t*) malloc(1*sizeof(uint64_t)); 

 
        struct options options1;
        options1.test_to_perform = 0;
        options1.function = NULL;
        
        int aux=0;
        params1.coefficient_modulus[0] = 12289;
        params1.barrett_auxi_value[0] = 2863078532;



        while ((opt = getopt(argc, argv, OPTSTR)) != EOF) 
                switch(opt) 
                {
                        case 't':
                                options1.test_to_perform = atoi(optarg);
                                        
                                break;
                        
                        default: /* '?' */
                              //  printf("Usage: %s [-p polynomial_degree_modulus] [-c coefficient_modulus] [-r rns_number] [-f function] [-t test] \n", argv[0]);
                                printf("Usage: %s [-p polynomial_degree_modulus] [-c coefficient_modulus] [-f function (not functional)] [-t test] [-o option_of_function] \n", argv[0]);
                  
      
                }



        

        switch(options1.test_to_perform) 
        {
                case 0:
                        test_01(params1);           
                        break;
                case 1:
                        test_02(params1);           
                        break; 
                case 2:
                        test_03(params1); 
                        break;
                case 3:
                        test_04(params1); 
                        break;
                case 4:
                        test_05(params1); 
                        break;
                case 5:
                        test_06(params1); 
                        break;
                case 6:
                        test_07(params1); 
                        break;
                case 7:       
                        test_08(params1);
                        break;
                case 8:       
                        test_09(params1); 
                        break;
                case 9:       
                        test_10(params1);
                        break;
                default:                        
                        break;       
        }

        free(params1.coefficient_modulus);

        return 0;
}