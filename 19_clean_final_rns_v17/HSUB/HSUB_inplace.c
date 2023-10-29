

#include "HSUB_inplace.h"

int HSUB_naive_inplace(struct ciphertext *Ciphertext1,struct ciphertext Ciphertext2)
{
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;
    
        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;       
        if(Ciphertext1->polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus)
                return 1;
 
 
        for(uint8_t i=0;i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        // Subtract Ciphertexts first polynomials, and reduce to ring 
                        Ciphertext1->values[0][i][j] -= Ciphertext2.values[0][i][j];
                        if(Ciphertext1->values[0][i][j] >= Ciphertext1->coefficient_modulus[i])
                                Ciphertext1->values[0][i][j] += Ciphertext1->coefficient_modulus[i];
                        
                        // Subtract Ciphertexts second polynomials, and reduce to ring 
                        Ciphertext1->values[1][i][j] -= Ciphertext2.values[1][i][j];
                        if(Ciphertext1->values[1][i][j] >= Ciphertext1->coefficient_modulus[i])  
                                Ciphertext1->values[1][i][j] += Ciphertext1->coefficient_modulus[i];
                }
        }
        return 0;
}

inline int HSUB_naive_inline_inplace(struct ciphertext *Ciphertext1,struct ciphertext Ciphertext2)
{
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;
    
        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;       
        if(Ciphertext1->polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus)
                return 1;
 
 
        for(uint8_t i=0;i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        // Subtract Ciphertexts first polynomials, and reduce to ring 
                        Ciphertext1->values[0][i][j] -= Ciphertext2.values[0][i][j];
                        if(Ciphertext1->values[0][i][j] >= Ciphertext1->coefficient_modulus[i])
                                Ciphertext1->values[0][i][j] += Ciphertext1->coefficient_modulus[i];
                        
                        // Subtract Ciphertexts second polynomials, and reduce to ring 
                        Ciphertext1->values[1][i][j] -= Ciphertext2.values[1][i][j];
                        if(Ciphertext1->values[1][i][j] >= Ciphertext1->coefficient_modulus[i])  
                                Ciphertext1->values[1][i][j] += Ciphertext1->coefficient_modulus[i];
                }
        }
        return 0;
}

int HSUB_naive_auto_vect_inplace(struct ciphertext *Ciphertext1,struct ciphertext Ciphertext2)
{
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;
    
        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;       
        if(Ciphertext1->polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus)
                return 1;
 
        #pragma clang loop vectorize(enable)
        for(uint8_t i=0;i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        // Subtract Ciphertexts first polynomials, and reduce to ring 
                        Ciphertext1->values[0][i][j] -= Ciphertext2.values[0][i][j];
                        if(Ciphertext1->values[0][i][j] >= Ciphertext1->coefficient_modulus[i])
                                Ciphertext1->values[0][i][j] += Ciphertext1->coefficient_modulus[i];
                        
                        // Subtract Ciphertexts second polynomials, and reduce to ring 
                        Ciphertext1->values[1][i][j] -= Ciphertext2.values[1][i][j];
                        if(Ciphertext1->values[1][i][j] >= Ciphertext1->coefficient_modulus[i])  
                                Ciphertext1->values[1][i][j] += Ciphertext1->coefficient_modulus[i];
                }
        }
        return 0;
}


#if RISCV_VECTORIAL

int HSUB_naive_vect_inplace(struct ciphertext *Ciphertext1,struct ciphertext Ciphertext2)
{
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;
               
        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;
        if(Ciphertext1->polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) 
                return 1;
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);      
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext1->coefficient_modulus[i], gvl);
                
                for(uint32_t j=0;j<stop_value;j+=gvl) 
                {  
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
        
                        // Load ciphertext1
                        __epi_1xi64 v_ciphertext1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext1_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[1][i][j], gvl);
        
                        // Load ciphertext2
                        __epi_1xi64 v_ciphertext2_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext2_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][j], gvl);
        
                        // Subtract ciphertexts
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_ciphertext1_0, v_ciphertext2_0, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_ciphertext1_1, v_ciphertext2_1, gvl);  
                        
                        // Reduction ciphertext_ans_1
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);
        
                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);

                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[1][i][j], v_res_2, gvl);
        
                }
        }
        return 0;
}

int HSUB_naive_vect_unroll_inplace(struct ciphertext *Ciphertext1,struct ciphertext Ciphertext2)
{
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;
        const uint8_t unroll = 2;
        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;
        if(Ciphertext1->polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus)
                return 1;
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        const uint32_t max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
        const uint32_t loops = stop_value/(max_gvl*2);
 
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext1->coefficient_modulus[i], max_gvl);
                
                
                uint32_t j=0;               
                for (j=0;j<loops;j++) 
                {
                        uint32_t aux1 = j*unroll;
                        // Load ciphertext1
                        __epi_1xi64 v_ciphertext1_0_0  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_ciphertext1_0_1  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+1)*max_gvl], max_gvl);                
                        __epi_1xi64 v_ciphertext1_1_0  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[1][i][(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_ciphertext1_1_1  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[1][i][(aux1+1)*max_gvl], max_gvl);

                        // Load ciphertext2             
                        __epi_1xi64 v_ciphertext2_0_0  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_ciphertext2_0_1  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][(aux1+1)*max_gvl], max_gvl);         
                        __epi_1xi64 v_ciphertext2_1_0  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_ciphertext2_1_1  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][(aux1+1)*max_gvl], max_gvl);
                        
                        // Subtract ciphertexts              
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_ciphertext1_0_0, v_ciphertext2_0_0, max_gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_ciphertext1_0_1, v_ciphertext2_0_1, max_gvl);
                        __epi_1xi64 v_res_3 = __builtin_epi_vsub_1xi64(v_ciphertext1_1_0, v_ciphertext2_1_0, max_gvl);
                        __epi_1xi64 v_res_4 = __builtin_epi_vsub_1xi64(v_ciphertext1_1_1, v_ciphertext2_1_1, max_gvl);                  
                
                
                        // Reduction ciphertext
                        __epi_1xi1 mask1 = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, max_gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask1, max_gvl);
                
                        // Reduction ciphertext
                        __epi_1xi1 mask2 = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, max_gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask2, max_gvl);
                
        
                        // Reduction ciphertext
                        __epi_1xi1 mask3 = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_3, max_gvl);
                        v_res_3 = __builtin_epi_vadd_1xi64_mask(v_res_3, v_res_3,v_coef_mod, mask3, max_gvl);
                
                        // Reduction ciphertext
                        __epi_1xi1 mask4 = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_4, max_gvl);
                        v_res_4 = __builtin_epi_vadd_1xi64_mask(v_res_4, v_res_4,v_coef_mod, mask4, max_gvl);
                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+0)*max_gvl], v_res_1, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+1)*max_gvl], v_res_2, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[1][i][(aux1+0)*max_gvl], v_res_3, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[1][i][(aux1+1)*max_gvl], v_res_4, max_gvl);
                }
                gvl = 0; 
                uint32_t start_remain = (j*unroll)*max_gvl;
        
                for (j = start_remain; j < stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                        // Load ciphertext1
                        __epi_1xi64 v_ciphertext1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext1_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[1][i][j], gvl);
        
                        // Load ciphertext2
                        __epi_1xi64 v_ciphertext2_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext2_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][j], gvl);
        
                        // Subtract ciphertexts
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_ciphertext1_0, v_ciphertext2_0, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_ciphertext1_1, v_ciphertext2_1, gvl);  
                
                
                        // Reduction ciphertext_ans_1
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);
        
                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);
                
                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[1][i][j], v_res_2, gvl);  
                }
        }
        return 0;
}

#endif
