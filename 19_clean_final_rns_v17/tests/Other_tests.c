#include <math.h>

#include "../initialization.h"
#include "../functions.h"
#include "../datastructures.h"
#include "../key_stuff.h"
#include "../flags.h"



int barrett_test()
{
        uint32_t coefficient_modulus = 12289;
        
        struct barrett_values barrett_values;
        barrett_values.k = 32;
        barrett_values.m = pow(2,barrett_values.k);


        
        uint64_t V = 1000000;
        printf("V og: %d\n",V);      
        uint64_t auxq = ((V * barrett_values.m) >> barrett_values.k);
        printf("auxq : %d\n",auxq);
        if (coefficient_modulus<= V) 
                V -= auxq * coefficient_modulus;
        
        printf("V: %d\n",V);

        if(coefficient_modulus <= V) 
                V -= coefficient_modulus;        
   
        printf("final V: %d\n",V);


        V = 1000000; 
        while(V >= coefficient_modulus)
                V -= coefficient_modulus;
        printf("True Final V: %d\n",V);


        V = 1000000; 
        /*
        uint32_t gvl = __builtin_epi_vsetvl(1, __epi_e64, __epi_m1);
        __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(barrett_values.m, gvl);  
        __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
        __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);       


        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&V, gvl);
  
        // Reduction v_V
        __epi_1xi64 v_q = __builtin_epi_vmulhu_1xi64(v_V, v_m, gvl);
        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);

        __builtin_epi_vstore_unsigned_1xi64(&V, v_V, gvl);    
        
        */
        
        printf("Vectorial V: %d\n",V); 

        return 0;
}





/*
int template_func()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 1024;
        struct timing_variable timing_variable1;      
        
        timing_variable1.polynomial_degree_modulus = Polynomial_Degree_Modulus;
        uint32_t *Coefficient_Modulus = NULL;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 12289;
        
        uint32_t psi = 12282; 
        
        struct barrett_values barrett;
        barrett.k = 15;
        barrett.m = pow(2,barrett.k);
        
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct ciphertext ciphertext1_ntt, ciphertext2_ntt,ciphertext_result_ntt;
        struct ciphertext final_ciphertext;
        
        
        Create_ciphertext(&ciphertext1,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext2,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext_result,Polynomial_Degree_Modulus,Coefficient_Modulus,3,rns_number);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        initiate_to_constant_ciphertext(&ciphertext2, 6);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        
        
        Create_ciphertext(&ciphertext1_ntt,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext2_ntt,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext_result_ntt,Polynomial_Degree_Modulus,Coefficient_Modulus,3,rns_number);
        
        for(int i=0;i<2;i++)
                for(int j=0;j<rns_number;j++)
                        for(int k=0;k<Polynomial_Degree_Modulus;k++)
                        {
                                ciphertext1.values[i][j][k] = k+1;
                                ciphertext2.values[i][j][k] = k+5;
                             
                        }    
                        
        initiate_to_constant_ciphertext(&ciphertext1_ntt, 0); 
        initiate_to_constant_ciphertext(&ciphertext2_ntt, 0); 
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        
 

 
        
        
        start_timing(&(timing_variable1));
        ntt_cooley_tukey_vectorial_masks_correct_2_barrett(ciphertext1,psi,&ciphertext1_ntt, barrett);
        end_timing(&(timing_variable1));
        print_timing(timing_variable1);
        fflush(stdout);
        
  
        start_timing(&(timing_variable1));
        ntt_cooley_tukey_2(ciphertext1,psi,&ciphertext2_ntt);
        end_timing(&(timing_variable1));
        print_timing(timing_variable1);
        fflush(stdout);

        
        printf("correct?: %d\n",compare_ciphertext_values(ciphertext1_ntt,ciphertext2_ntt));
        
        
        initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
        

  
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);
        return 0;       
}
*/



int main (int argc, char *argv[])
{
 


        switch(atoi(argv[1]))
        {
                case 0:
                        barrett_test();
                        break;
                default:
                        barrett_test();
                        break;          
                
        }
        
        return 0;
}


