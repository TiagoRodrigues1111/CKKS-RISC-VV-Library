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
#define OPTSTR "p:c:f:t:o:"

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


/*      
        Prints the results of the function passed
*/
int HSUB_test_01(int (*HSUB_function)(struct ciphertext, struct ciphertext,struct ciphertext*),struct params params1)
{
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
                 
        // Create Ciphertexts  
        Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        
        // Initiate ciphertexts with some values
        initiate_to_constant_ciphertext(&ciphertext1, 10000);
        initiate_to_constant_ciphertext(&ciphertext2, 5000);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
               
        // Perform operation
        (*HSUB_function)(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
                
        // Free ciphertexts
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        
        return 0;         
}

/*      
        Prints information for an HSUB function passed 
*/
int HSUB_test_02(int (*HSUB_function)(struct ciphertext, struct ciphertext,struct ciphertext*),void (*print_timing_function)(struct timing_variable), struct params params1)
{
       
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
          
        // Create Ciphertexts  
        Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        
        // Initiate ciphertexts with some values
        initiate_to_constant_ciphertext(&ciphertext1, 10000);
        initiate_to_constant_ciphertext(&ciphertext2, 5000);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        
                
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                (*HSUB_function)(ciphertext1,ciphertext2,&ciphertext_result);
                end_timing(&(timing_variable1));
                (*print_timing_function)(timing_variable1);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }       
   
        // Free ciphertexts
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        
        return 0;         
}


/*      
        Compares two HSUB functions
*/
int HSUB_test_03(int (*HSUB_function_1)(struct ciphertext, struct ciphertext,struct ciphertext*),int (*HSUB_function_2)(struct ciphertext, struct ciphertext,struct ciphertext*), struct params params1)
{
         
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result1,ciphertext_result2;         
        // Create Ciphertexts  
        Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext_result1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext_result2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        
        // Initiate ciphertexts with some values
        initiate_to_constant_ciphertext(&ciphertext1, 10000);
        initiate_to_constant_ciphertext(&ciphertext2, 5000);
        initiate_to_constant_ciphertext(&ciphertext_result1, 0);
        initiate_to_constant_ciphertext(&ciphertext_result2, 0);
        
        (*HSUB_function_1)(ciphertext1,ciphertext2,&ciphertext_result1);
        
        // Perform operation
        (*HSUB_function_2)(ciphertext1,ciphertext2,&ciphertext_result2);
        
        if(compare_ciphertext_values(ciphertext_result1,ciphertext_result2) == 1)
                printf("Both ciphertexts are equal\n");
        
              
        // Free ciphertexts
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result1);
        free_ciphertext(&ciphertext_result2);

        return 0;         
}



int main (int argc, char *argv[])
{ 
      
      
        
        #if RISCV_VECTORIAL
                int (*HSUB_function[])(struct ciphertext, struct ciphertext,struct ciphertext*) = {HSUB, HSUB_auto_vect, HSUB_naive_vect};
        #else
                int (*HSUB_function[])(struct ciphertext, struct ciphertext,struct ciphertext*) = {HSUB, HSUB_auto_vect};
        #endif       
        
        
        int opt;     
        struct params params1;
        params1.polynomial_degree_modulus = 32;
        params1.rns_number = 0;      
        params1.coefficient_modulus = (uint32_t*) malloc(1*sizeof(uint32_t));
        params1.barrett_auxi_value = (uint64_t*) malloc(1*sizeof(uint64_t));
        
        struct options options1;
        options1.test_to_perform = 0;
        options1.function = NULL;
        
        int aux=0;

        while ((opt = getopt(argc, argv, OPTSTR)) != EOF) 
                switch(opt) 
                {
                        case 'p':
                                params1.polynomial_degree_modulus = atoi(optarg);
                                break;
                        case 'c':
                                
                                params1.rns_number++; 
                                params1.coefficient_modulus = (uint32_t*) realloc(params1.coefficient_modulus,params1.rns_number*sizeof(uint32_t));
                                params1.coefficient_modulus[params1.rns_number-1] = atoi(optarg);
                                break;
           
                        case 'o':
                                options1.function_to_test[aux] = atoi(optarg);
                                aux++;
                                break;
           
                        case 'f': // later implementation
                                
                                options1.function = (char*) malloc(strlen(optarg)*(sizeof(char)) + 1);
                                //functions=1;
                                strcpy(options1.function,optarg);
                                break;  
                        case 't':
                                options1.test_to_perform = atoi(optarg);
                                        
                                break;
                        
                        default: /* '?' */
                              //  printf("Usage: %s [-p polynomial_degree_modulus] [-c coefficient_modulus] [-r rns_number] [-f function] [-t test] \n", argv[0]);
                                printf("Usage: %s [-p polynomial_degree_modulus] [-c coefficient_modulus] [-f function (not functional)] [-t test] [-o option_of_function] \n", argv[0]);
                  
      
                }


        if(params1.rns_number ==0)
        {
                params1.rns_number = 1;
                params1.coefficient_modulus[0] = 12289;
                params1.barrett_auxi_value[0] = 2863078532;
        }

        switch(options1.test_to_perform) 
        {
                case 0:
                        HSUB_test_01((*HSUB_function[options1.function_to_test[0]]),params1);           
                        break;
                case 1:
                        HSUB_test_02((*HSUB_function[options1.function_to_test[0]]),print_timing,params1);           
                        break; 
                case 2:
                        HSUB_test_03((*HSUB_function[options1.function_to_test[0]]),(*HSUB_function[options1.function_to_test[1]]),params1);
                        break;  
                
                case 3:
                        // run a specific function passed in the -f param
                        break;


                default:
                        
                        break;     
        }


       //if(functions)
       //         free(options1.function);
        free(params1.coefficient_modulus);

        return 0;
}