#include <math.h>

#include "initialization.h"
#include "functions.h"
#include "datastructures.h"
#include "key_stuff.h"



int benchmark_auto_vects()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 32;
        uint32_t *Coefficient_Modulus = NULL;
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 15;
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct plaintext plaintext1;

        struct barrett_values barrett;
        barrett.k = 15;
        barrett.m = pow(2,barrett.k);


        Create_ciphertext(&ciphertext1,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext2,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext_result,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_plaintext(&plaintext1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        initiate_to_constant_ciphertext(&ciphertext2, 6);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);     
        initiate_to_constant_plaintext(&plaintext1, 6);     
 
 
        printf("HADD operations\n");
        printf("HADD_naive\n");
        HADD_naive(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HADD_naive_auto_vect\n");
        HADD_naive_auto_vect(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HADD_naive_auto_vect_2\n");
        HADD_naive_auto_vect_2(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);


        printf("CADD operations\n");
        printf("CADD_naive\n");
        CADD_naive(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_naive_auto_vect\n");
        CADD_naive_auto_vect(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_naive_auto_vect_2\n");
        CADD_naive_auto_vect_2(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_naive_auto_vect_3\n");
        CADD_naive_auto_vect_3(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);

        printf("CADD_barrett_auto_vect\n");
        CADD_barrett_auto_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_barrett_auto_vect_2\n");
        CADD_barrett_auto_vect_2(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        
    
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_plaintext(&plaintext1);


    return 0;

         
         
        
        
        
        
        
}


int benchmark_ntt_1()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 4;
        
        uint32_t *Coefficient_Modulus = NULL;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 7681;
        
        uint32_t psi = 1925; 
        
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct ciphertext ciphertext1_ntt, ciphertext2_ntt,ciphertext_result_ntt;
        struct ciphertext final_ciphertext;
        struct plaintext plaintext1;
        
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
        
        ntt_cooley_tukey(ciphertext1,psi,&ciphertext1_ntt);
        print_ciphertext(ciphertext1_ntt);
        initiate_to_constant_ciphertext(&ciphertext1_ntt, 0); 
        ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext1_ntt);
        print_ciphertext(ciphertext1_ntt);
 //       ntt_cooley_tukey(ciphertext2,psi,&ciphertext2_ntt);
 //       print_ciphertext(ciphertext2_ntt);
        
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);

    return 0;       
}

int benchmark_ntt_times_1()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 4;
        struct timing_variable timing_variable1;      
        uint32_t *Coefficient_Modulus = NULL;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 7681;
        
        uint32_t psi = 1925; 
        
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct ciphertext ciphertext1_ntt, ciphertext2_ntt,ciphertext_result_ntt;
        struct ciphertext final_ciphertext;
        // struct plaintext plaintext1;
        
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
        
        
        printf("ntt_cooley_tukey\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                ntt_cooley_tukey(ciphertext1,psi,&ciphertext1_ntt);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        }
        printf("ntt_cooley_tukey_vectorial\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext1_ntt);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        } 
     
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);

    return 0;       
}

int benchmark_ntt_times_2()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 1024;
        struct timing_variable timing_variable1;      
        uint32_t *Coefficient_Modulus = NULL;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 12289;
        
        uint32_t psi = 12282; 
        
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct ciphertext ciphertext1_ntt, ciphertext2_ntt,ciphertext_result_ntt;
        struct ciphertext final_ciphertext;
        // struct plaintext plaintext1;
        
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
        
        
        ntt_cooley_tukey(ciphertext1,psi,&ciphertext1_ntt);
        ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext2_ntt);
        
        printf("correct?: %d\n",compare_ciphertext_values(ciphertext1_ntt,ciphertext2_ntt));
        
        initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
        
        printf("ntt_cooley_tukey\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                ntt_cooley_tukey(ciphertext1,psi,&ciphertext1_ntt);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        }
        printf("ntt_cooley_tukey_vectorial\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext1_ntt);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        } 

     
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);

    return 0;       
}

int benchmark_auto_vects_times()
{
        
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 1024;
        
        uint32_t *Coefficient_Modulus = NULL;
        struct timing_variable timing_variable1;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 15;
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct plaintext plaintext1;

        struct barrett_values barrett;
        barrett.k = 15;
        barrett.m = pow(2,barrett.k);


        Create_ciphertext(&ciphertext1,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext2,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext_result,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_plaintext(&plaintext1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        initiate_to_constant_ciphertext(&ciphertext2, 6);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);     
        initiate_to_constant_plaintext(&plaintext1, 6);     
        
        
        printf("HADD_naive");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                HADD_naive(ciphertext1,ciphertext2,&ciphertext_result);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        
        printf("HADD_naive_auto_vect");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                HADD_naive_auto_vect(ciphertext1,ciphertext2,&ciphertext_result);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        
        printf("HADD_naive_auto_vect_2");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                HADD_naive_auto_vect_2(ciphertext1,ciphertext2,&ciphertext_result);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }        
  
  
  
        printf("CADD operations\n");
        
        printf("CADD_naive\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                CADD_naive(ciphertext1,plaintext1,&ciphertext_result);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        } 
 
        printf("CADD_naive_auto_vect\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                CADD_naive_auto_vect(ciphertext1,plaintext1,&ciphertext_result);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }  
       
        printf("CADD_naive_auto_vect_2\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                CADD_naive_auto_vect_2(ciphertext1,plaintext1,&ciphertext_result);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        } 
   
        printf("CADD_naive_auto_vect_3\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                CADD_naive_auto_vect_3(ciphertext1,plaintext1,&ciphertext_result);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        } 
   
        printf("CADD_barrett_auto_vect\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                CADD_barrett_auto_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        } 
        printf("CADD_barrett_auto_vect_2\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                CADD_barrett_auto_vect_2(ciphertext1,plaintext1,&ciphertext_result,barrett);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }



    
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_plaintext(&plaintext1);
        
        return 0;
        
}



int benchmark_general()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 32;
        
        uint32_t *Coefficient_Modulus = NULL;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 15;
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct plaintext plaintext1;

        struct barrett_values barrett;
        barrett.k = 15;
        barrett.m = pow(2,barrett.k);


        Create_ciphertext(&ciphertext1,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext2,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext_result,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_plaintext(&plaintext1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        initiate_to_constant_ciphertext(&ciphertext2, 6);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);     
        initiate_to_constant_plaintext(&plaintext1, 6);     
 
 
        printf("HADD operations\n");
        printf("HADD_naive\n");
        HADD_naive(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HADD_naive_inplace\n");
        HADD_naive_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("HADD_naive_auto_vect\n");
        HADD_naive_auto_vect(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HADD_naive_auto_vect_2\n");
        HADD_naive_auto_vect_2(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HADD_naive_auto_vect_inplace\n");
        HADD_naive_auto_vect_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("HADD_naive_vect\n");
        HADD_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HADD_naive_vect_inplace\n");
        HADD_naive_vect_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("HADD_naive_vect_unroll\n");
        HADD_naive_vect_unroll(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HADD_naive_vect_unroll_inplace\n");
        HADD_naive_vect_unroll_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
    
        printf("HSUB operations\n");
        printf("HSUB_naive\n");
        HSUB_naive(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HSUB_naive_inplace\n");
        HSUB_naive_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("HSUB_naive_auto_vect\n");
        HSUB_naive_auto_vect(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HSUB_naive_auto_vect_inplace\n");
        HSUB_naive_auto_vect_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("HSUB_naive_vect\n");
        HSUB_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HSUB_naive_vect_inplace\n");
        HSUB_naive_vect_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("HSUB_naive_vect_unroll\n");
        HSUB_naive_vect_unroll(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HSUB_naive_vect_unroll_inplace\n");
        HSUB_naive_vect_unroll_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);   




        printf("CADD operations\n");
        printf("CADD_naive\n");
        CADD_naive(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_naive_inplace\n");
        CADD_naive_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CADD_naive_auto_vect\n");
        CADD_naive_auto_vect(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_naive_auto_vect_inplace\n");
        CADD_naive_auto_vect_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CADD_naive_vect\n");
        CADD_naive_vect(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_naive_vect_inplace\n");
        CADD_naive_vect_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CADD_naive_vect_unroll\n");
        CADD_naive_vect_unroll(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_naive_vect_unroll_inplace\n");
        CADD_naive_vect_unroll_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        printf("CADD_barrett\n");
        CADD_barrett(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_barrett_inplace\n");
        CADD_barrett_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CADD_barrett_auto_vect\n");
        CADD_barrett_auto_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_barrett_auto_vect_inplace\n");
        CADD_barrett_auto_vect_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CADD_barrett_vect\n");
        CADD_barrett_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_barrett_vect_inplace\n");
        CADD_barrett_vect_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CADD_barrett_vect_unroll\n");
        CADD_barrett_vect_unroll(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CADD_barrett_vect_unroll_inplace\n");
        CADD_barrett_vect_unroll_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 

 
        printf("CSUB operations\n");
        printf("CSUB_naive\n");
        CSUB_naive(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CSUB_naive_inplace\n");
        CSUB_naive_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CSUB_naive_auto_vect\n");
        CSUB_naive_auto_vect(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CSUB_naive_auto_vect_inplace\n");
        CSUB_naive_auto_vect_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CSUB_naive_vect\n");
        CSUB_naive_vect(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CSUB_naive_vect_inplace\n");
        CSUB_naive_vect_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CSUB_naive_vect_unroll\n");
        CSUB_naive_vect_unroll(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CSUB_naive_vect_unroll_inplace\n");
        CSUB_naive_vect_unroll_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);    
        printf("CSUB_barrett\n");
        CSUB_barrett(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CSUB_barrett_inplace\n");
        CSUB_barrett_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CSUB_barrett_auto_vect\n");
        CSUB_barrett_auto_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CSUB_barrett_auto_vect_inplace\n");
        CSUB_barrett_auto_vect_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CSUB_barrett_vect\n");
        CSUB_barrett_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CSUB_barrett_vect_inplace\n");
        CSUB_barrett_vect_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CSUB_barrett_vect_unroll\n");
        CSUB_barrett_vect_unroll(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CSUB_barrett_vect_unroll_inplace\n");
        CSUB_barrett_vect_unroll_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 

        printf("CWM\n");
        CWM(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
    
    
    
    
        printf("CMULT operations\n");
        printf("CMULT_naive\n");
        CMULT_naive(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CMULT_naive_inplace\n");
        CMULT_naive_inplace(&ciphertext1,plaintext1);
       print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CMULT_naive_auto_vect\n");
        CMULT_naive_auto_vect(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CMULT_naive_auto_vect_inplace\n");
       CMULT_naive_auto_vect_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
    
        #if VECTORIAL_OPERATIONS
        printf("CMULT_naive_vect\n");
        CMULT_naive_vect(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CMULT_naive_vect_inplace\n");
        CMULT_naive_vect_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CMULT_naive_vect_unroll\n");
        CMULT_naive_vect_unroll(ciphertext1,plaintext1,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CMULT_naive_vect_unroll_inplace\n");        
        CMULT_naive_vect_unroll_inplace(&ciphertext1,plaintext1);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        #endif
    
        printf("CMULT_barrett\n");
        CMULT_barrett(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CMULT_barrett_inplace\n");
        CMULT_barrett_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CMULT_barrett_auto_vect\n");
        CMULT_barrett_auto_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CMULT_barrett_auto_vect_inplace\n");
        CMULT_barrett_auto_vect_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        #if VECTORIAL_OPERATIONS
        printf("CMULT_barrett_vect\n");
        CMULT_barrett_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CMULT_barrett_vect_inplace\n");
        CMULT_barrett_vect_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("CMULT_barrett_vect_unroll\n");
        CMULT_barrett_vect_unroll(ciphertext1,plaintext1,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("CMULT_barrett_vect_unroll_inplace\n");
        CMULT_barrett_vect_unroll_inplace(&ciphertext1,plaintext1,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        #endif


        free_ciphertext(&ciphertext_result);
        Create_ciphertext(&ciphertext_result,Polynomial_Degree_Modulus,Coefficient_Modulus,3,rns_number);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
    
        printf("HMULT operations\n");
        printf("HMULT_naive\n");
        HMULT_naive(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HMULT_naive_inplace\n");
        HMULT_naive_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("HMULT_naive_auto_vect\n");
        HMULT_naive_auto_vect(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HMULT_naive_auto_vect_inplace\n");
        HMULT_naive_auto_vect_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
    
        #if VECTORIAL_OPERATIONS
        printf("HMULT_naive_vect\n");
        HMULT_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HMULT_naive_vect_inplace\n");
        HMULT_naive_vect_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("HMULT_naive_vect_unroll\n");
        HMULT_naive_vect_unroll(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HMULT_naive_vect_unroll_inplace\n");
        HMULT_naive_vect_unroll_inplace(&ciphertext1,ciphertext2);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        #endif
        printf("HMULT_barrett\n");
        HMULT_barrett(ciphertext1,ciphertext2,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HMULT_barrett_inplace\n");
        HMULT_barrett_inplace(&ciphertext1,ciphertext2,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("HMULT_barrett_auto_vect\n");
        HMULT_barrett_auto_vect(ciphertext1,ciphertext2,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HMULT_barrett_auto_vect_inplace\n");
        HMULT_barrett_auto_vect_inplace(&ciphertext1,ciphertext2,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        #if VECTORIAL_OPERATIONS
        printf("HMULT_barrett_vect\n");
        HMULT_barrett_vect(ciphertext1,ciphertext2,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HMULT_barrett_vect_inplace\n");
        HMULT_barrett_vect_inplace(&ciphertext1,ciphertext2,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        printf("HMULT_barrett_vect_unroll\n");
        HMULT_barrett_vect_unroll(ciphertext1,ciphertext2,&ciphertext_result,barrett);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        printf("HMULT_barrett_vect_unroll_inplace\n");
        HMULT_barrett_vect_unroll_inplace(&ciphertext1,ciphertext2,barrett);
        print_ciphertext(ciphertext1);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        #endif




 
    
    
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_plaintext(&plaintext1);


    return 0;

    
}



int benchmark_ntt_cwm_intt()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 4;
        
        uint32_t *Coefficient_Modulus = NULL;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 7681;
        
        uint32_t psi = 1925;
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct ciphertext ciphertext1_ntt, ciphertext2_ntt,ciphertext_result_ntt;
        struct ciphertext final_ciphertext;
        struct plaintext plaintext1;

        struct barrett_values barrett;
        barrett.k = 15;
        barrett.m = pow(2,barrett.k);


        Create_ciphertext(&ciphertext1,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext2,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext_result,Polynomial_Degree_Modulus,Coefficient_Modulus,3,rns_number);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        initiate_to_constant_ciphertext(&ciphertext2, 6);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
 
 
        printf("CWM_true\n");
        CWM_true(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
 
        printf("CWM_true_vectorial\n");
        CWM_true_vectorial(ciphertext1,ciphertext2,&ciphertext_result);
        print_ciphertext(ciphertext_result);
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
        
        ntt_cooley_tukey(ciphertext1,psi,&ciphertext1_ntt);
        print_ciphertext(ciphertext1_ntt);
        initiate_to_constant_ciphertext(&ciphertext1_ntt, 0); 
        ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext1_ntt);
        print_ciphertext(ciphertext1_ntt);
        ntt_cooley_tukey(ciphertext2,psi,&ciphertext2_ntt);
        print_ciphertext(ciphertext2_ntt);
        
        CWM_true(ciphertext1_ntt,ciphertext2_ntt,&ciphertext_result_ntt);
        intt_gentleman_sande(ciphertext_result_ntt,psi, &ciphertext_result);
        print_ciphertext(ciphertext_result);
        
 
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);


    return 0;

    
}





int benchmark_general_times()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 1024;
        
        uint32_t *Coefficient_Modulus = NULL;
        struct timing_variable timing_variable1;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 15;
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct plaintext plaintext1;

        struct barrett_values barrett;
        barrett.k = 15;
        barrett.m = pow(2,barrett.k);


        Create_ciphertext(&ciphertext1,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext2,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext_result,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_plaintext(&plaintext1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        initiate_to_constant_ciphertext(&ciphertext2, 6);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);     
        initiate_to_constant_plaintext(&plaintext1, 6);     
 
  
        //start_timing(&(timing_variable1));	

                        
        printf("HADD operations\n");
        printf("HADD_naive\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HADD_naive(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HADD_naive_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));	
        HADD_naive_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        
        printf("HADD_naive_auto_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));	
        HADD_naive_auto_vect(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HADD_naive_auto_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HADD_naive_auto_vect_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        
        printf("HADD_naive_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HADD_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HADD_naive_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HADD_naive_vect_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("HADD_naive_vect_unroll\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HADD_naive_vect_unroll(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HADD_naive_vect_unroll_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HADD_naive_vect_unroll_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        
        printf("HSUB operations\n");
        printf("HSUB_naive\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HSUB_naive(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HSUB_naive_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HSUB_naive_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("HSUB_naive_auto_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HSUB_naive_auto_vect(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HSUB_naive_auto_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HSUB_naive_auto_vect_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("HSUB_naive_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HSUB_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HSUB_naive_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HSUB_naive_vect_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("HSUB_naive_vect_unroll\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HSUB_naive_vect_unroll(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HSUB_naive_vect_unroll_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HSUB_naive_vect_unroll_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);   
        }
        */

        printf("CADD operations\n");
        printf("CADD_naive\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_naive(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CADD_naive_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_naive_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CADD_naive_auto_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_naive_auto_vect(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CADD_naive_auto_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_naive_auto_vect_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CADD_naive_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_naive_vect(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CADD_naive_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_naive_vect_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CADD_naive_vect_unroll\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_naive_vect_unroll(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CADD_naive_vect_unroll_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_naive_vect_unroll_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        }
        `*/
        printf("CADD_barrett\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_barrett(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CADD_barrett_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_barrett_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CADD_barrett_auto_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_barrett_auto_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CADD_barrett_auto_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_barrett_auto_vect_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CADD_barrett_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_barrett_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CADD_barrett_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_barrett_vect_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CADD_barrett_vect_unroll\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_barrett_vect_unroll(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CADD_barrett_vect_unroll_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CADD_barrett_vect_unroll_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        }
        */
        
        printf("CSUB operations\n");
        printf("CSUB_naive\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_naive(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CSUB_naive_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_naive_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CSUB_naive_auto_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_naive_auto_vect(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CSUB_naive_auto_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_naive_auto_vect_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CSUB_naive_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_naive_vect(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CSUB_naive_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_naive_vect_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CSUB_naive_vect_unroll\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_naive_vect_unroll(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CSUB_naive_vect_unroll_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_naive_vect_unroll_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);    
        }
        */
        printf("CSUB_barrett\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_barrett(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CSUB_barrett_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_barrett_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CSUB_barrett_auto_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_barrett_auto_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CSUB_barrett_auto_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_barrett_auto_vect_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CSUB_barrett_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_barrett_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CSUB_barrett_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_barrett_vect_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CSUB_barrett_vect_unroll\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_barrett_vect_unroll(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CSUB_barrett_vect_unroll_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CSUB_barrett_vect_unroll_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        }
        */
    
        printf("CMULT operations\n");
        printf("CMULT_naive\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_naive(ciphertext1,plaintext1,&ciphertext_result);
  	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CMULT_naive_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_naive_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CMULT_naive_auto_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_naive_auto_vect(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CMULT_naive_auto_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_naive_auto_vect_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */

        printf("CMULT_naive_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_naive_vect(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CMULT_naive_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_naive_vect_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CMULT_naive_vect_unroll\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_naive_vect_unroll(ciphertext1,plaintext1,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CMULT_naive_vect_unroll_inplace\n");        
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_naive_vect_unroll_inplace(&ciphertext1,plaintext1);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        }
        */
    
        printf("CMULT_barrett\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_barrett(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CMULT_barrett_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_barrett_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CMULT_barrett_auto_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_barrett_auto_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CMULT_barrett_auto_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_barrett_auto_vect_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */

        printf("CMULT_barrett_vect\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_barrett_vect(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CMULT_barrett_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_barrett_vect_inplace(&ciphertext1,plaintext1,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("CMULT_barrett_vect_unroll\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_barrett_vect_unroll(ciphertext1,plaintext1,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("CMULT_barrett_vect_unroll_inplace\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        CMULT_barrett_vect_unroll_inplace(&ciphertext1,plaintext1,barrett);
 	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        }
        */


        free_ciphertext(&ciphertext_result);
        Create_ciphertext(&ciphertext_result,Polynomial_Degree_Modulus,Coefficient_Modulus,3,rns_number);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
    
        printf("HMULT operations\n");
        printf("HMULT_naive\n");
        for(uint8_t i=0; i<10;i++){
        start_timing(&(timing_variable1));
        HMULT_naive(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HMULT_naive_inplace\n");
        for(uint8_t i=0; i<10;i++){
        HMULT_naive_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("HMULT_naive_auto_vect\n");
        for(uint8_t i=0; i<10;i++){
                start_timing(&(timing_variable1));
        HMULT_naive_auto_vect(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HMULT_naive_auto_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        HMULT_naive_auto_vect_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("HMULT_naive_vect\n");
        for(uint8_t i=0; i<10;i++){
                start_timing(&(timing_variable1));
        HMULT_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HMULT_naive_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        HMULT_naive_vect_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("HMULT_naive_vect_unroll\n");
        for(uint8_t i=0; i<10;i++){
                start_timing(&(timing_variable1));
        HMULT_naive_vect_unroll(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HMULT_naive_vect_unroll_inplace\n");
        for(uint8_t i=0; i<10;i++){
        HMULT_naive_vect_unroll_inplace(&ciphertext1,ciphertext2);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        }
        */
        printf("HMULT_barrett\n");
        for(uint8_t i=0; i<10;i++){
                start_timing(&(timing_variable1));
        HMULT_barrett(ciphertext1,ciphertext2,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HMULT_barrett_inplace\n");
        for(uint8_t i=0; i<10;i++){
        HMULT_barrett_inplace(&ciphertext1,ciphertext2,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("HMULT_barrett_auto_vect\n");
        for(uint8_t i=0; i<10;i++){
                start_timing(&(timing_variable1));
        HMULT_barrett_auto_vect(ciphertext1,ciphertext2,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HMULT_barrett_auto_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        HMULT_barrett_auto_vect_inplace(&ciphertext1,ciphertext2,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("HMULT_barrett_vect\n");
        for(uint8_t i=0; i<10;i++){
                start_timing(&(timing_variable1));
        HMULT_barrett_vect(ciphertext1,ciphertext2,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HMULT_barrett_vect_inplace\n");
        for(uint8_t i=0; i<10;i++){
        HMULT_barrett_vect_inplace(&ciphertext1,ciphertext2,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        }
        */
        printf("HMULT_barrett_vect_unroll\n");
        for(uint8_t i=0; i<10;i++){
                start_timing(&(timing_variable1));
        HMULT_barrett_vect_unroll(ciphertext1,ciphertext2,&ciphertext_result,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        /*
        printf("HMULT_barrett_vect_unroll_inplace\n");
        for(uint8_t i=0; i<10;i++){
        HMULT_barrett_vect_unroll_inplace(&ciphertext1,ciphertext2,barrett);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext1, 8); 
        }
        */

    
    
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_plaintext(&plaintext1);


    return 0;

 
}




int benchmark_ntt_times_troubleshooting()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 1024;
        struct timing_variable timing_variable1;      
        uint32_t *Coefficient_Modulus = NULL;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 12289;
        
        uint32_t psi = 12282; 
        
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct ciphertext ciphertext1_ntt, ciphertext2_ntt,ciphertext_result_ntt;
        struct ciphertext final_ciphertext;
        // struct plaintext plaintext1;
        
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
        
        
        ntt_cooley_tukey(ciphertext1,psi,&ciphertext1_ntt);
        ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext2_ntt);
        initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
        ntt_cooley_tukey_vectorial_2(ciphertext1,psi,&ciphertext2_ntt);
        
        printf("correct?: %d\n",compare_ciphertext_values(ciphertext1_ntt,ciphertext2_ntt));
        
        
        initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
        
        printf("ntt_cooley_tukey\n");
        for(uint8_t i=0; i<10;i++)
        {
                printf("Time_test: %d\n",i+1);
                start_timing(&(timing_variable1));
                ntt_cooley_tukey(ciphertext1,psi,&ciphertext1_ntt);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        }
        printf("ntt_cooley_tukey_vectorial\n");
        for(uint8_t i=0; i<10;i++)
        {
                printf("Time_test: %d\n",i+1);
                start_timing(&(timing_variable1));
                ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext1_ntt);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        } 
        printf("ntt_cooley_tukey_vectorial_2\n");
        for(uint8_t i=0; i<10;i++)
        {
                printf("Time_test: %d\n",i+1);
                start_timing(&(timing_variable1));
                ntt_cooley_tukey_vectorial_2(ciphertext1,psi,&ciphertext1_ntt);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        }


  
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);
    return 0;       
}

int benchmark_ntt_times_troubleshooting_2()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 1024;
        struct timing_variable timing_variable1;      
        uint32_t *Coefficient_Modulus = NULL;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 12289;
        
        uint32_t psi = 12282; 
        
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;
        struct ciphertext ciphertext1_ntt, ciphertext2_ntt,ciphertext_result_ntt;
        struct ciphertext final_ciphertext;
        // struct plaintext plaintext1;
        
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
        ntt_cooley_tukey_2(ciphertext1,psi,&ciphertext1_ntt);
        //ntt_cooley_tukey_no_times(ciphertext1,psi,&ciphertext1_ntt);
        end_timing(&(timing_variable1));
        print_timing(timing_variable1);
        //ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext2_ntt);
        //initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
        
        start_timing(&(timing_variable1));       
        //ntt_cooley_tukey_vectorial_4(ciphertext1,psi,&ciphertext2_ntt);
        test_stride(ciphertext1,psi,&ciphertext2_ntt);
        //ntt_cooley_tukey_vectorial_4_no_times(ciphertext1,psi,&ciphertext2_ntt);
        end_timing(&(timing_variable1));
        print_timing(timing_variable1);
        
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


int test_stride_function()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 1024;    
        uint32_t *Coefficient_Modulus = NULL;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 12289;
        
        uint32_t psi = 12282; 
        
        
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
        
          
        test_stride(ciphertext1,psi,&ciphertext2_ntt);

        

        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);
        
        
        return 0;       
}

int different_size_benchmarks(uint32_t poly_size)
{
       
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = poly_size;
        
        uint32_t *Coefficient_Modulus = NULL;
        struct timing_variable timing_variable1;
        uint64_t new_vl = 256;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 15;
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;

        Create_ciphertext(&ciphertext1,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext2,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext_result,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        initiate_to_constant_ciphertext(&ciphertext1, 8);
        initiate_to_constant_ciphertext(&ciphertext2, 10);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
 
  
        //start_timing(&(timing_variable1));	



                        


        asm volatile("csrw 0x805, %0" :: "r"(new_vl));  
        
        for (uint32_t j=0;j<5;j++)
        {
                printf("vl: %lu\n",new_vl);
                for(uint8_t i=0; i<5;i++)
                {
                        start_timing(&(timing_variable1));
                        HADD_naive_vect(ciphertext1,ciphertext2,&ciphertext_result);
                        end_timing(&(timing_variable1));
                        print_timing_poly(timing_variable1,Polynomial_Degree_Modulus);
                        initiate_to_constant_ciphertext(&ciphertext_result, 0);
                }
  
                new_vl /=2;   
                asm volatile("csrw 0x805, %0" :: "r"(new_vl)); 
        }










        //asm volatile("csrw 0x805, x0");
        
        
        
        
        
        
        
        
        
        
            
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        
        return 0;  
        
}






/*
int benchmark_general_times_limb()
{
        const int rns_number = 3;
        uint32_t Polynomial_Degree_Modulus = 1024;
        
        uint32_t *Coefficient_Modulus = NULL;
        struct timing_variable timing_variable1;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 15;
        
        struct ciphertext ciphertext1, ciphertext2, ciphertext_result;



        Create_ciphertext(&ciphertext1,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext2,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
        Create_ciphertext(&ciphertext_result,Polynomial_Degree_Modulus,Coefficient_Modulus,2,rns_number);
       
       initiate_to_constant_ciphertext(&ciphertext1, 8);
        initiate_to_constant_ciphertext(&ciphertext2, 6);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);     
 
  
        //start_timing(&(timing_variable1));	

                        
        printf("HADD operations\n");
        printf("HADD_naive\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                HADD_naive(ciphertext1,ciphertext2,&ciphertext_result);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
                initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }
        
        
        printf("HADD_limb_vectorization\n");
        for(uint8_t i=0; i<10;i++)
        {
        start_timing(&(timing_variable1));	
        HADD_limb_vect(ciphertext1,ciphertext2,&ciphertext_result);
	end_timing(&(timing_variable1));
	print_timing_excel(timing_variable1,Polynomial_Degree_Modulus);
        initiate_to_constant_ciphertext(&ciphertext_result, 0);
        }

    
    
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_plaintext(&plaintext1);


    return 0;

 
}
*/


int benchmark_ntt_times_masks()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 1024;
        struct timing_variable timing_variable1;      
        uint32_t *Coefficient_Modulus = NULL;
        
        Coefficient_Modulus = (uint32_t*) malloc(rns_number*sizeof(uint32_t));
        
        for(uint32_t i=0;i<rns_number;i++)
                Coefficient_Modulus[i] = 12289;
        
        uint32_t psi = 12282; 
        
        
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
        ntt_cooley_tukey_2(ciphertext1,psi,&ciphertext1_ntt);
        //ntt_cooley_tukey_no_times(ciphertext1,psi,&ciphertext1_ntt);
        end_timing(&(timing_variable1));
        print_timing(timing_variable1);
        fflush(stdout);
        //ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext2_ntt);
        //initiate_to_constant_ciphertext(&ciphertext2_ntt, 0);
        
        
        start_timing(&(timing_variable1));    
        //ntt_cooley_tukey_vectorial_masks(ciphertext1,psi,&ciphertext2_ntt);  
        ntt_cooley_tukey_vectorial_index(ciphertext1,psi,&ciphertext2_ntt);        
        //ntt_cooley_tukey_vectorial_4(ciphertext1,psi,&ciphertext2_ntt);
        //ntt_cooley_tukey_vectorial_4_no_times(ciphertext1,psi,&ciphertext2_ntt);
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




int main (int argc, char *argv[])
{
 
        //uint32_t poly_size;
        uint32_t array_values_test[] = {2048,4096,8192,16384,32768,65536,131072,262144,524288};
 
        //benchmark_general();
        //benchmark_ntt_cwm_intt();
        //benchmark_auto_vects();
        //benchmark_auto_vects_times();
        
        //benchmark_general_times();
        
        //benchmark_ntt_1();
        //benchmark_ntt_times_1();
        
        // benchmark_ntt_times_troubleshooting();
        //benchmark_ntt_times_troubleshooting_2();
        
        // test_stride_function();
        
       // for(int i=1;i<=1024;i++)
       //         different_size_benchmarks(i);

        //for(int i=0;i<9;i++)
        //        different_size_benchmarks(array_values_test[i]);
   

        benchmark_ntt_times_masks();
   
        return 0;
}