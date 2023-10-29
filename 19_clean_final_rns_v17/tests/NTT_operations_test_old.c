#include <math.h>

#include "../initialization.h"
#include "../functions.h"
#include "../datastructures.h"
#include "../key_stuff.h"


// #define VECTORIAL_OPERATIONS 1


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
        
        timing_variable1.polynomial_degree_modulus = Polynomial_Degree_Modulus;
        
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
                print_timing_excel(timing_variable1);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        }
        printf("ntt_cooley_tukey_vectorial\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext1_ntt);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1);
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
        
        timing_variable1.polynomial_degree_modulus = Polynomial_Degree_Modulus;
        
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
                print_timing_excel(timing_variable1);
                initiate_to_constant_ciphertext(&ciphertext1_ntt, 0);
        }
        printf("ntt_cooley_tukey_vectorial\n");
        for(uint8_t i=0; i<10;i++)
        {
                start_timing(&(timing_variable1));
                ntt_cooley_tukey_vectorial(ciphertext1,psi,&ciphertext1_ntt);
                end_timing(&(timing_variable1));
                print_timing_excel(timing_variable1);
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



int benchmark_ntt_times_troubleshooting_2()
{
        const int rns_number = 1;
        uint32_t Polynomial_Degree_Modulus = 1024;
        struct timing_variable timing_variable1;      
        uint32_t *Coefficient_Modulus = NULL;
        
        timing_variable1.polynomial_degree_modulus = Polynomial_Degree_Modulus;
        
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
        //test_stride(ciphertext1,psi,&ciphertext2_ntt);
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




int benchmark_ntt_times_masks()
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


int benchmark_ntt_masks_tests()
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
        
        
       
        ntt_cooley_tukey_2(ciphertext1,psi,&ciphertext1_ntt);    
        
        printf("test3\n");
        fflush(stdout);
        ntt_cooley_tukey_vectorial_masks_test_3(ciphertext1,psi,&ciphertext2_ntt);       
        fflush(stdout);
        printf("test2\n");
        fflush(stdout);
        ntt_cooley_tukey_vectorial_masks_test_2(ciphertext1,psi,&ciphertext2_ntt);
        fflush(stdout);
        printf("test1\n");
        fflush(stdout); 
        ntt_cooley_tukey_vectorial_masks_test_1(ciphertext1,psi,&ciphertext2_ntt);



        
        
        //ntt_cooley_tukey_vectorial_masks(ciphertext1,psi,&ciphertext2_ntt);      

        
       // printf("correct?: %d\n",compare_ciphertext_values(ciphertext1_ntt,ciphertext2_ntt));
        
        
        

  
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);
    return 0;       
}


int benchmark_ntt_barrett_tests()
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
        
        
       
        //ntt_cooley_tukey_2(ciphertext1,psi,&ciphertext1_ntt);    
        
        
        
        start_timing(&(timing_variable1));
        ntt_cooley_tukey_2_barrett(ciphertext1,psi,&ciphertext2_ntt, barrett);   
        end_timing(&(timing_variable1));
        print_timing(timing_variable1);
        fflush(stdout);
   
   
   
        start_timing(&(timing_variable1));
        ntt_cooley_tukey_vectorial_barrett(ciphertext1,psi,&ciphertext2_ntt, barrett);    
        end_timing(&(timing_variable1));
        print_timing(timing_variable1);
        fflush(stdout); 
  
        free_ciphertext(&ciphertext1);
        free_ciphertext(&ciphertext2);
        free_ciphertext(&ciphertext_result);
        free_ciphertext(&ciphertext1_ntt);
        free_ciphertext(&ciphertext2_ntt);
        free_ciphertext(&ciphertext_result_ntt);
        return 0;       
}



int benchmark_ntt_times_correct_1()
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
        ntt_cooley_tukey_vectorial_masks_correct_1(ciphertext1,psi,&ciphertext1_ntt);
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



int benchmark_ntt_times_correct_2()
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
        ntt_cooley_tukey_vectorial_masks_correct_2(ciphertext1,psi,&ciphertext1_ntt);
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



int benchmark_ntt_times_correct_2_barrett()
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
   

        
        
        switch(atoi(argv[1]))
        {
                case 0:
                        benchmark_ntt_barrett_tests();
                        break;
                case 1:
                        benchmark_ntt_times_correct_1();
                        break; 
                case 2:
                        benchmark_ntt_times_correct_2();
                        break;    
                case 3:
                        benchmark_ntt_times_correct_2_barrett();
                        break;                            
                default:
                        benchmark_ntt_masks_tests();
                        break;          
                
        }
        
        
        //benchmark_ntt_barrett_tests();
        //benchmark_ntt_times_correct_1();
        //benchmark_ntt_times_correct_2();
        return 0;
}