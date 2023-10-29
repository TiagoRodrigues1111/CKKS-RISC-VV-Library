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


/*      
        
*/
int test_01(struct params params1)
{
        struct ciphertext ciphertext1, ciphertext2,ciphertext1_ntt,ciphertext2_ntt,ciphertext_result,ciphertext_result_ntt;
        uint32_t psi = 12282;                
        // Create Ciphertexts  
        Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext1_ntt,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext2_ntt,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        
        Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
        Create_ciphertext(&ciphertext_result_ntt,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
        
        
        // Initiate ciphertexts with some values
        initiate_to_constant_ciphertext(&ciphertext1, 10000);
        initiate_to_constant_ciphertext(&ciphertext2, 5001);
        initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        initiate_to_constant_ciphertext(&ciphertext_result_ntt, 0);
        
        ntt_cooley_tukey_3_barrett_no_times(ciphertext1,psi,&ciphertext1_ntt);   
        ntt_cooley_tukey_3_barrett_no_times(ciphertext2,psi,&ciphertext2_ntt);   
        
     
        CWM_true_barrett(ciphertext1_ntt,ciphertext2_ntt,&ciphertext_result_ntt);     
        
            
        // intt ope(ciphertext_result_ntt,psi,&ciphertext_result);
        print_ciphertext(ciphertext_result);
  






        initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        initiate_to_constant_ciphertext(&ciphertext_result_ntt, 0);  
        

        ntt_cooley_tukey_vectorial_masks_correct_3_barrett_no_times_taux(ciphertext1,psi,&ciphertext1_ntt);   
        ntt_cooley_tukey_vectorial_masks_correct_3_barrett_no_times_taux(ciphertext2,psi,&ciphertext2_ntt);  
        
        CWM_true_vectorial_barrett(ciphertext1_ntt,ciphertext2_ntt,&ciphertext_result_ntt);  
        
        
//         intt ope(ciphertext_result_ntt,psi,&ciphertext_result);              
        print_ciphertext(ciphertext_result);
    




    
        // Free ciphertexts
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);
        
        
        return 0;         
}



/*      
        
*/
int test_02(void (*print_timing_function)(struct timing_variable), struct params params1)
{
        //int (*HMULT_function[])(struct ciphertext, struct ciphertext,struct *ciphertext) = {HMULT, HMULT_auto_vect, HMULT_naive_vect};
        
        struct timing_variable timing_variable1;  
        struct ciphertext ciphertext1, ciphertext2,ciphertext1_ntt,ciphertext2_ntt,ciphertext_result,ciphertext_result_ntt;
        uint32_t psi = 12282;          
        // Create Ciphertexts  
        Create_ciphertext(&ciphertext1,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext2,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext1_ntt,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        Create_ciphertext(&ciphertext2_ntt,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,2,params1.rns_number);
        
        Create_ciphertext(&ciphertext_result,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
        Create_ciphertext(&ciphertext_result_ntt,params1.polynomial_degree_modulus,params1.coefficient_modulus,params1.barrett_auxi_value,3,params1.rns_number);
        
        // Initiate ciphertexts with some values
        initiate_to_constant_ciphertext(&ciphertext1, 10000);
        initiate_to_constant_ciphertext(&ciphertext2, 5001);
        initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        initiate_to_constant_ciphertext(&ciphertext_result_ntt, 0)
        
        

        
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                
                
                ntt_cooley_tukey_3_barrett_no_times(ciphertext1,psi,&ciphertext1_ntt);   
                ntt_cooley_tukey_3_barrett_no_times(ciphertext2,psi,&ciphertext2_ntt);   
             
                CWM_true_barrett(ciphertext1_ntt,ciphertext2_ntt,&ciphertext_result_ntt);            
            
                // intt ope(ciphertext_result_ntt,psi,&ciphertext_result);
        


                end_timing(&(timing_variable1));
                
                (*print_timing_function)(timing_variable1);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
                initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
                initiate_to_constant_ciphertext(&ciphertext_result_ntt, 0)
        }       
   
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                
                
                ntt_cooley_tukey_vectorial_masks_correct_3_barrett_no_times_taux(ciphertext1,psi,&ciphertext1_ntt);   
                ntt_cooley_tukey_vectorial_masks_correct_3_barrett_no_times_taux(ciphertext2,psi,&ciphertext2_ntt);  
        
                CWM_true_vectorial_barrett(ciphertext1_ntt,ciphertext2_ntt,&ciphertext_result_ntt);  
        
        
                // intt ope(ciphertext_result_ntt,psi,&ciphertext_result);              

                end_timing(&(timing_variable1));
                
                (*print_timing_function)(timing_variable1);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
                initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
                initiate_to_constant_ciphertext(&ciphertext_result_ntt, 0)
        }   
   
    
   
   
        // Free ciphertexts
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);
        
        return 0;         
}




int main (int argc, char *argv[])
{   
                      
        int opt;
        struct params params1;
        params1.polynomial_degree_modulus = 1024;
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
                        case 't':
                                options1.test_to_perform = atoi(optarg);
                                        
                                break;
                        
                        default: /* '?' */
                              //  printf("Usage: %s [-p polynomial_degree_modulus] [-c coefficient_modulus] [-r rns_number] [-f function] [-t test] \n", argv[0]);
                                printf("Usage: %s [-p polynomial_degree_modulus] [-c coefficient_modulus] [-f function (not functional)] [-t test] [-o option_of_function] \n", argv[0]);
                  
      
                }


        params1.rns_number = 1;
        params1.coefficient_modulus[0] = 12289;
        params1.barrett_auxi_value[0] = 2863078532;
        

        switch(options1.test_to_perform) 
        {
                case 0:
                        test_01(params1);           
                        break;
                case 1:
                        test_02(print_timing,params1);           
                        break; 
                case 2:
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