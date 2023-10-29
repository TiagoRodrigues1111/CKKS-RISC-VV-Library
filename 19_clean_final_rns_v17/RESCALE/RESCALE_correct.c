
#include "RESCALE_correct.h"


int RESCALE(struct ciphertext Ciphertext1,uint64_t scale_factor, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number;  
        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;        
        if(Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) 
                return 1;
        
        for(uint8_t i=0;i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext1.values[0][i][j] / scale_factor;
                        if(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] -= Ciphertext_result->coefficient_modulus[i];
                        

                        Ciphertext_result->values[1][i][j] = Ciphertext1.values[1][i][j] / scale_factor;
                        if(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])           
                                Ciphertext_result->values[1][i][j] -= Ciphertext_result->coefficient_modulus[i];
                }
        }
        return 0;
}


int RESCALE_auto_vect(struct ciphertext Ciphertext1,uint64_t scale_factor, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number;  
        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;        
        if(Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) 
                return 1;
        
        for(uint8_t i=0;i<rns_number;i++)
        {
                #pragma clang loop vectorize(enable)
                for(uint32_t j=0;j<stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext1.values[0][i][j] / scale_factor;
                        if(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] -= Ciphertext_result->coefficient_modulus[i];
                        

                        Ciphertext_result->values[1][i][j] = Ciphertext1.values[1][i][j] / scale_factor;
                        if(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])           
                                Ciphertext_result->values[1][i][j] -= Ciphertext_result->coefficient_modulus[i];
                }
        }
        return 0;
}



#if RISCV_VECTORIAL

int RESCALE_vect(struct ciphertext Ciphertext1,uint64_t scale_factor, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number;
        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;       
        if(Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus)
                return 1;
       
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        __epi_1xi64 v_scale_factor = __builtin_epi_vbroadcast_1xi64(scale_factor, gvl);       
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl); 
                
                for(uint32_t j=0;j<stop_value;j+=gvl)
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
        
                        // Load ciphertext1
                        __epi_1xi64 v_ciphertext1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext1_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[1][i][j], gvl);
        
        
                        // Divide ciphertext with scale_factor
                        __epi_1xi64 v_res_1 = __builtin_epi_vdivu_1xi64(v_ciphertext1_0, v_scale_factor, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vdivu_1xi64(v_ciphertext1_1, v_scale_factor, gvl);
                        
                        // Reduction ciphertext_ans_1
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vsub_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);
        
                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vsub_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);

                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_res_2, gvl);                       
                }    
        }
        return 0;
}

/*
int RESCALE_vect_unroll(struct ciphertext *Ciphertext_result,struct ciphertext Ciphertext1, int64_t scale_factor)
{
        
        int i=0;
        int aux1=0;
        long gvl = __builtin_epi_vsetvl(Ciphertext_result->polynomial_degree_modulus, __epi_e64, __epi_m1);
        int start_remain = 0;
        const int unroll = 2;
        const long max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
        const int loops = Ciphertext_result->polynomial_degree_modulus/(max_gvl*2);
                
                
        if(Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus)
                return 1;
 
 
        __epi_1xi64 mask_comp = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus, max_gvl);
        __epi_1xi64 mask_comp_neg = __builtin_epi_vbroadcast_1xi64(0, max_gvl);   
        __epi_1xi64 v_coef_add  = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus, max_gvl);
        __epi_1xi64 v_scale_factor = __builtin_epi_vbroadcast_1xi64(scale_factor, max_gvl);
  
        for (i = 0; i < loops; i++) 
        {
                aux1 = i*unroll;
                
                
                // Load ciphertext1
                __epi_1xi64 v_ciphertext1_0_0  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[0][(aux1+0)*max_gvl], max_gvl);
                __epi_1xi64 v_ciphertext1_0_1  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[0][(aux1+1)*max_gvl], max_gvl);
                __epi_1xi64 v_ciphertext1_1_0  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[1][(aux1+0)*max_gvl], max_gvl);
                __epi_1xi64 v_ciphertext1_1_1  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[1][(aux1+1)*max_gvl], max_gvl);
                        
                // Divide ciphertexts by scale_factor
                __epi_1xi64 v_res_1 = __builtin_epi_vdivu_1xi64(v_ciphertext1_0_0, v_scale_factor, max_gvl);
                __epi_1xi64 v_res_2 = __builtin_epi_vdivu_1xi64(v_ciphertext1_0_1, v_scale_factor, max_gvl);
                __epi_1xi64 v_res_3 = __builtin_epi_vdivu_1xi64(v_ciphertext1_1_0, v_scale_factor, max_gvl);    
                __epi_1xi64 v_res_4 = __builtin_epi_vdivu_1xi64(v_ciphertext1_1_1, v_scale_factor, max_gvl);                    
                
                
                // Reduction ciphertext
                __epi_1xi1 mask1 = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_1, max_gvl);
                v_res_1 = __builtin_epi_vsub_1xi64_mask(v_res_1, v_res_1,v_coef_add, mask1, max_gvl);
                
                // Reduction ciphertext
                __epi_1xi1 mask2 = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_2, max_gvl);
                v_res_2 = __builtin_epi_vsub_1xi64_mask(v_res_2, v_res_2,v_coef_add, mask2, max_gvl);
                
        
                // Reduction ciphertext
                __epi_1xi1 mask3 = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_3, max_gvl);
                v_res_3 = __builtin_epi_vsub_1xi64_mask(v_res_3, v_res_3,v_coef_add, mask3, max_gvl);
                
                // Reduction ciphertext
                __epi_1xi1 mask4 = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_4, max_gvl);
                v_res_4 = __builtin_epi_vsub_1xi64_mask(v_res_4, v_res_4,v_coef_add, mask4, max_gvl);           
                
                
                //store results
                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][(i+0)*max_gvl], v_res_1, max_gvl);
                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][(i+1)*max_gvl], v_res_2, max_gvl);            
                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][(i+0)*max_gvl], v_res_3, max_gvl);
                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][(i+1)*max_gvl], v_res_4, max_gvl);    

        }
  
    gvl = 0; 

        start_remain = (i*unroll)*max_gvl;
        
        for (i = start_remain; i < Ciphertext_result->polynomial_degree_modulus; i += gvl) 
        {
                gvl = __builtin_epi_vsetvl(Ciphertext_result->polynomial_degree_modulus - i, __epi_e64, __epi_m1);
                
                // Load ciphertext1
                __epi_1xi64 v_ciphertext1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[0][i], gvl);
                __epi_1xi64 v_ciphertext1_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[1][i], gvl);
        
        
                // Divide Ciphertexts with scale_factor
                __epi_1xi64 v_res_1 = __builtin_epi_vdivu_1xi64(v_ciphertext1_0, v_scale_factor, gvl);
                __epi_1xi64 v_res_2 = __builtin_epi_vdivu_1xi64(v_ciphertext1_1, v_scale_factor, gvl);


                // Reduction ciphertext_ans_1
                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_1, gvl);
                v_res_1 = __builtin_epi_vsub_1xi64_mask(v_res_1, v_res_1,v_coef_add, mask, gvl);
        
                // Reduction ciphertext_ans_2
                mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_2, gvl);
                v_res_2 = __builtin_epi_vsub_1xi64_mask(v_res_2, v_res_2,v_coef_add, mask, gvl);
                
                
                //store results
                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i], v_res_1, gvl);
                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i], v_res_2, gvl);
                
        }
        return 0;
}
*/

#endif