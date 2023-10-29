
#include "CSUB_inplace.h"

int CSUB_naive_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1)
{
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;  

        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;
        if(Ciphertext1->polynomial_degree_modulus != plaintext1.polynomial_degree_modulus)
                return 1;
        
        for(uint8_t i=0;i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        int64_t plaintext_value_reduced_aux = plaintext1.values[j];
                        
                        // If plaintext value negative, increase it into the ring
                        while(plaintext_value_reduced_aux < 0)
                                plaintext_value_reduced_aux += Ciphertext1->coefficient_modulus[i];
        
                        // If plaintext value bigger than the ring, reduce it into the ring
                        while(plaintext_value_reduced_aux >= Ciphertext1->coefficient_modulus[i])
                                plaintext_value_reduced_aux -= Ciphertext1->coefficient_modulus[i];
                        
                        // Subtract Ciphertext and plaintext polynomials, and reduce to ring 
                        Ciphertext1->values[0][i][j] -= plaintext_value_reduced_aux;
                        if(Ciphertext1->values[0][i][j] >= Ciphertext1->coefficient_modulus[i])           
                                Ciphertext1->values[0][i][j] += Ciphertext1->coefficient_modulus[i];     
               }
        }
        return 0;
}

int CSUB_naive_auto_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1)
{
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;  

        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;
        if(Ciphertext1->polynomial_degree_modulus != plaintext1.polynomial_degree_modulus)
                return 1;
        
        
        #pragma clang loop vectorize(enable)
        for(uint8_t i=0;i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        int64_t plaintext_value_reduced_aux = plaintext1.values[j];
                        
                        // If plaintext value negative, increase it into the ring
                        while(plaintext_value_reduced_aux < 0)
                                plaintext_value_reduced_aux += Ciphertext1->coefficient_modulus[i];
        
                        // If plaintext value bigger than the ring, reduce it into the ring
                        while(plaintext_value_reduced_aux >= Ciphertext1->coefficient_modulus[i])
                                plaintext_value_reduced_aux -= Ciphertext1->coefficient_modulus[i];
                        
                        // Subtract Ciphertext and plaintext polynomials, and reduce to ring 
                        Ciphertext1->values[0][i][j] -= plaintext_value_reduced_aux;
                        if(Ciphertext1->values[0][i][j] >= Ciphertext1->coefficient_modulus[i])           
                                Ciphertext1->values[0][i][j] += Ciphertext1->coefficient_modulus[i];     
               }
        }
        return 0;
}




int CSUB_barrett_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1)
{             
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;  
        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;       
        if(Ciphertext1->polynomial_degree_modulus != plaintext1.polynomial_degree_modulus)
                return 1;
        
        for(uint8_t i=0;i<rns_number;i++)
        {       
                for(uint32_t j=0;j<stop_value;j++)
                {
                        
                        // Reduce plaintext into the ring
                        int64_t plaintext_value_reduced_aux = plaintext1.values[j];
                        
                        if(plaintext_value_reduced_aux<0)
                        {
                                plaintext_value_reduced_aux = -plaintext_value_reduced_aux; 
                                uint64_t auxq = ((plaintext_value_reduced_aux * Ciphertext1->barrett_auxi_value[i]) >> 45);
                                plaintext_value_reduced_aux -= auxq * Ciphertext1->coefficient_modulus[i];
                                if (Ciphertext1->coefficient_modulus[i] <= plaintext_value_reduced_aux) 
                                        plaintext_value_reduced_aux -= Ciphertext1->coefficient_modulus[i];
                                
                                if(plaintext_value_reduced_aux != 0)
                                        plaintext_value_reduced_aux -=  Ciphertext1->coefficient_modulus[i];
                                
                                plaintext_value_reduced_aux = -plaintext_value_reduced_aux;
                        }
                        else
                        {
                                uint64_t auxq = ((plaintext_value_reduced_aux * Ciphertext1->barrett_auxi_value[i]) >> 45);
                                plaintext_value_reduced_aux -= auxq * Ciphertext1->coefficient_modulus[i];
                                if (Ciphertext1->coefficient_modulus[i] <= plaintext_value_reduced_aux) 
                                        plaintext_value_reduced_aux -= Ciphertext1->coefficient_modulus[i]; 
                        }                        
                        // Subtract Ciphertext and plaintext polynomials, and reduce to ring 
                        Ciphertext1->values[0][i][j] -= plaintext_value_reduced_aux;
                        if(Ciphertext1->values[0][i][j] >= Ciphertext1->coefficient_modulus[i])           
                                Ciphertext1->values[0][i][j] += Ciphertext1->coefficient_modulus[i];
                }
        }                     
        return 0;
}

int CSUB_barrett_auto_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1)
{       
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;  
        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;       
        if(Ciphertext1->polynomial_degree_modulus != plaintext1.polynomial_degree_modulus)
       
                return 1;
        #pragma clang loop vectorize(enable)
        for(uint8_t i=0;i<rns_number;i++)
        {       
                for(uint32_t j=0;j<stop_value;j++)
                {
                        
                        // Reduce plaintext into the ring
                        int64_t plaintext_value_reduced_aux = plaintext1.values[j];
                        
                        if(plaintext_value_reduced_aux<0)
                        {
                                plaintext_value_reduced_aux = -plaintext_value_reduced_aux; 
                                uint64_t auxq = ((plaintext_value_reduced_aux * Ciphertext1->barrett_auxi_value[i]) >> 45);
                                plaintext_value_reduced_aux -= auxq * Ciphertext1->coefficient_modulus[i];
                                if (Ciphertext1->coefficient_modulus[i] <= plaintext_value_reduced_aux) 
                                        plaintext_value_reduced_aux -= Ciphertext1->coefficient_modulus[i];
                                
                                if(plaintext_value_reduced_aux != 0)
                                        plaintext_value_reduced_aux -=  Ciphertext1->coefficient_modulus[i];
                                
                                plaintext_value_reduced_aux = -plaintext_value_reduced_aux;
                        }
                        else
                        {
                                uint64_t auxq = ((plaintext_value_reduced_aux * Ciphertext1->barrett_auxi_value[i]) >> 45);
                                plaintext_value_reduced_aux -= auxq * Ciphertext1->coefficient_modulus[i];
                                if (Ciphertext1->coefficient_modulus[i] <= plaintext_value_reduced_aux) 
                                        plaintext_value_reduced_aux -= Ciphertext1->coefficient_modulus[i]; 
                        }
                        
                        // Subtract Ciphertext and plaintext polynomials, and reduce to ring 
                        Ciphertext1->values[0][i][j] -= plaintext_value_reduced_aux;
                        if(Ciphertext1->values[0][i][j] >= Ciphertext1->coefficient_modulus[i])           
                                Ciphertext1->values[0][i][j] += Ciphertext1->coefficient_modulus[i];
                }
        }                     
        return 0;
}



#if RISCV_VECTORIAL

int CSUB_naive_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1)
{
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;
        
        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;       
        if(Ciphertext1->polynomial_degree_modulus != plaintext1.polynomial_degree_modulus) 
                return 1;

        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);       
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 mask_comp_neg = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext1->coefficient_modulus[i], gvl);
                for(uint32_t j=0;j<stop_value;j+=gvl)
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
        
                        // Load ciphertext1
                        __epi_1xi64 v_ciphertext1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext1_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[1][i][j], gvl);
        
                        // Load plaintext
                        __epi_1xi64 v_plaintext = __builtin_epi_vload_1xi64(&plaintext1.values[j], gvl);
        
                        // Reduction plaintext part-1
                        __epi_1xi1 mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext,mask_comp_neg,gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,gvl))!=0)
                        {                       
                                v_plaintext = __builtin_epi_vadd_1xi64_mask(v_plaintext, v_plaintext,v_coef_mod, mask_pt_reduce, gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext,mask_comp_neg,gvl);
                        }
                        
                        // Reduction plaintext part-2
                         mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,gvl))!=0)
                        {                       
                                v_plaintext = __builtin_epi_vsub_1xi64_mask(v_plaintext, v_plaintext,v_coef_mod, mask_pt_reduce, gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext, gvl);
                        }
                       
                        // Subtract ciphertext and plaintext
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_ciphertext1_0, v_plaintext, gvl);
                        
                        // Reduction ciphertext_ans_1
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);
        
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[1][i][j], v_ciphertext1_1, gvl);
                }
        }
        return 0;
}

int CSUB_naive_vect_unroll_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1)
{
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;
        const uint8_t unroll = 2;        
        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;               
        if(Ciphertext1->polynomial_degree_modulus != plaintext1.polynomial_degree_modulus)
                return 1;
                     
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        const uint32_t max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
        const uint32_t loops = stop_value/(max_gvl*2);

        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 mask_comp_neg = __builtin_epi_vbroadcast_1xi64(0, max_gvl);   
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext1->coefficient_modulus[i], max_gvl);
                
                uint32_t j=0;
                for (j=0;j<loops;j++) 
                {
                        uint32_t aux1 = j*unroll;
                        // Load ciphertext1
                        __epi_1xi64 v_ciphertext1_0_0  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_ciphertext1_0_1  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+1)*max_gvl], max_gvl);         
                        __epi_1xi64 v_ciphertext1_1_0  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[1][i][(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_ciphertext1_1_1  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[1][i][(aux1+1)*max_gvl], max_gvl);

                        // Load plaintext             
                        __epi_1xi64 v_plaintext_0_0  = __builtin_epi_vload_1xi64(&plaintext1.values[(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_plaintext_0_1  = __builtin_epi_vload_1xi64(&plaintext1.values[(aux1+1)*max_gvl], max_gvl);            

                        // Reduction plaintext 1 part-1
                        __epi_1xi1 mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_0_0,mask_comp_neg,max_gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_0_0 = __builtin_epi_vadd_1xi64_mask(v_plaintext_0_0, v_plaintext_0_0,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_0_0,mask_comp_neg,max_gvl);
                        }
                        
                        // Reduction plaintext 1 part-2
                        mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_0_0, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_0_0 = __builtin_epi_vsub_1xi64_mask(v_plaintext_0_0, v_plaintext_0_0,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_0_0, max_gvl);
                        }

                        // Reduction plaintext 2 part-1
                        mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_0_1,mask_comp_neg,max_gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_0_1 = __builtin_epi_vadd_1xi64_mask(v_plaintext_0_1, v_plaintext_0_1,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_0_1,mask_comp_neg,max_gvl);
                        }
                        
                        // Reduction plaintext 2 part-2
                        mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_0_1, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_0_1 = __builtin_epi_vsub_1xi64_mask(v_plaintext_0_1, v_plaintext_0_1,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_0_1, max_gvl);
                        }

  
                        // Subtract ciphertext - plaintext           
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_ciphertext1_0_0, v_plaintext_0_0, max_gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_ciphertext1_0_1, v_plaintext_0_1, max_gvl);
        
           
                        // Reduction ciphertext
                        __epi_1xi1 mask1 = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, max_gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask1, max_gvl);
                
                        // Reduction ciphertext
                        __epi_1xi1 mask2 = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, max_gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask2, max_gvl);
                
            
                        
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+0)*max_gvl], v_res_1, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+1)*max_gvl], v_res_2, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[1][i][(aux1+0)*max_gvl], v_ciphertext1_1_0, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[1][i][(aux1+1)*max_gvl], v_ciphertext1_1_1, max_gvl);       

                }
                gvl = 0; 
                uint32_t start_remain = (j*unroll)*max_gvl;
        
        
                for (j = start_remain; j < Ciphertext1->polynomial_degree_modulus; j += gvl) 
                {               
                        gvl = __builtin_epi_vsetvl(Ciphertext1->polynomial_degree_modulus - j, __epi_e64, __epi_m1);
        
                        // Load ciphertext1
                        __epi_1xi64 v_ciphertext1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext1_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[1][i][j], gvl);
        
                        // Load plaintext
                        __epi_1xi64 v_plaintext = __builtin_epi_vload_1xi64(&plaintext1.values[i], gvl);
        
                        // Reduction plaintext part-1
                        __epi_1xi1 mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext,mask_comp_neg,gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,gvl))!=0)
                        {                       
                                v_plaintext = __builtin_epi_vadd_1xi64_mask(v_plaintext, v_plaintext,v_coef_mod, mask_pt_reduce, gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext,mask_comp_neg,gvl);
                        }
                        
                        // Reduction plaintext part-2
                        mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,gvl))!=0)
                        {                       
                                v_plaintext = __builtin_epi_vsub_1xi64_mask(v_plaintext, v_plaintext,v_coef_mod, mask_pt_reduce, gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext, gvl);
                        }

        
                        // Subtract ciphertext with plaintext
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_ciphertext1_0, v_plaintext, gvl);
                        
                        // Reduction ciphertext_ans_1
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);
                        
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[1][i][j], v_ciphertext1_1, gvl);
                
                }    
        }
        return 0;       
}


int CSUB_barrett_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1)
{
        
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;    

        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;               
        if(Ciphertext1->polynomial_degree_modulus != plaintext1.polynomial_degree_modulus)
                return 1;
        
        uint32_t gvl = __builtin_epi_vsetvl(Ciphertext1->polynomial_degree_modulus, __epi_e64, __epi_m1);  
        for(uint8_t i=0; i<rns_number;i++)
        {
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext1->barrett_auxi_value[i], gvl);   
                __epi_1xi64 mask_comp_neg = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext1->coefficient_modulus[i], gvl);              
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(13, gvl);
                for (uint32_t j=0; j<stop_value;j+=gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
        
                        // Load ciphertext1
                        __epi_1xi64 v_ciphertext1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][j], gvl);
        
                        // Load plaintext
                        __epi_1xi64 v_plaintext = __builtin_epi_vload_unsigned_1xi64((uint64_t*)&plaintext1.values[i], gvl);
        

                        // Make mask for negative values in plaintext 
                        
                        __epi_1xi1 v_mask = __builtin_epi_vmslt_1xi64(v_plaintext, mask_comp_neg, gvl);
                        __epi_1xi64 v_aux_neg = __builtin_epi_vsub_1xi64_mask(v_plaintext,mask_comp_neg,v_plaintext, v_mask, gvl);
                                                             
                        // Reduction plaintext
                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_aux_neg, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_neg = __builtin_epi_vsub_1xi64(v_aux_neg, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod, v_aux_neg, gvl);
                        v_aux_neg = __builtin_epi_vsub_1xi64_mask(v_aux_neg, v_aux_neg, v_coef_mod, mask, gvl);
                        
                        __epi_1xi1 zero_mask = __builtin_epi_vmseq_1xi64(v_aux_neg, mask_comp_neg, gvl);
                        __epi_1xi1 last_mask = __builtin_epi_vmandnot_1xi1(v_mask, zero_mask, gvl);
                               
                        v_aux_neg = __builtin_epi_vsub_1xi64_mask(v_aux_neg, v_aux_neg,v_coef_mod, last_mask, gvl);     
                        v_plaintext = __builtin_epi_vsub_1xi64_mask(v_aux_neg,mask_comp_neg,v_aux_neg,last_mask, gvl);   
                        
                        
                        // Subtract ciphertext with plaintext
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_ciphertext1_0, v_plaintext, gvl);
                        
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][j], v_res_1, gvl); 
                }             
        }
        return 0;
}

int CSUB_barrett_vect_unroll_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1)
{       
        const uint32_t stop_value = Ciphertext1->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1->rns_number;  
        const uint8_t unroll = 2;       
        if(Ciphertext1->polynomial_degree_modulus <= 0)
                return 2;                       
        if(Ciphertext1->polynomial_degree_modulus != plaintext1.polynomial_degree_modulus)
                return 1;       
       
       
        const uint32_t max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
        const uint32_t loops = stop_value/(max_gvl*2);
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);       
        for(uint8_t i=0;i<rns_number;i++ )
        {
                
                __epi_1xi64 mask_comp_neg = __builtin_epi_vbroadcast_1xi64(0, max_gvl);                              
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext1->barrett_auxi_value[i], gvl);
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl); 
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext1->coefficient_modulus[i], gvl);
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(13, gvl);
                uint32_t j;
                for (j = 0; j < loops; j++) 
                {
                        uint32_t aux1 = j*unroll;
                        // Load ciphertext1
                        __epi_1xi64 v_ciphertext1_0_0  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_ciphertext1_0_1  = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+1)*max_gvl], max_gvl);

                        // Load plaintext             
                        __epi_1xi64 v_plaintext_0_0  = __builtin_epi_vload_unsigned_1xi64((uint64_t*)&plaintext1.values[(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_plaintext_0_1  = __builtin_epi_vload_unsigned_1xi64((uint64_t*)&plaintext1.values[(aux1+1)*max_gvl], max_gvl);            
                

                        // Reduction plaintext_0
                        __epi_1xi64 v_q = __builtin_epi_vmulhu_1xi64(v_plaintext_0_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_plaintext_0_0 = __builtin_epi_vsub_1xi64(v_plaintext_0_0, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_plaintext_0_0, gvl);
                        v_plaintext_0_0 = __builtin_epi_vsub_1xi64_mask(v_plaintext_0_0, v_plaintext_0_0, v_coef_mod, mask, gvl);

                         // Reduction plaintext_1
                        v_q = __builtin_epi_vmulhu_1xi64(v_plaintext_0_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_plaintext_0_1 = __builtin_epi_vsub_1xi64(v_plaintext_0_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_plaintext_0_1, gvl);
                        v_plaintext_0_1 = __builtin_epi_vsub_1xi64_mask(v_plaintext_0_1, v_plaintext_0_1, v_coef_mod, mask, gvl);

                        // Subtract ciphertext with plaintext           
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_ciphertext1_0_0, v_plaintext_0_0, max_gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_ciphertext1_0_1, v_plaintext_0_1, max_gvl);
        
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);
 
                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl); 
            
                                
                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+0)*max_gvl], v_res_1, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][(aux1+1)*max_gvl], v_res_2, max_gvl);              

                }
                gvl = 0; 
                uint32_t start_remain = (j*unroll)*max_gvl;
                
                for (j = start_remain; j < stop_value; j += gvl) 
                {     
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
        
                        // Load ciphertext1
                        __epi_1xi64 v_ciphertext1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1->values[0][i][j], gvl);
        
                        // Load plaintext
                        __epi_1xi64 v_plaintext = __builtin_epi_vload_unsigned_1xi64((uint64_t*)&plaintext1.values[i], gvl);
        
                        // Reduction plaintext
                        __epi_1xi64 v_q = __builtin_epi_vmulhu_1xi64(v_plaintext, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_plaintext = __builtin_epi_vsub_1xi64(v_plaintext, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_plaintext, gvl);
                        v_plaintext = __builtin_epi_vsub_1xi64_mask(v_plaintext, v_plaintext, v_coef_mod, mask, gvl);
                        
                        // Subtract ciphertext with plaintext
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_ciphertext1_0, v_plaintext, gvl);
                        
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext1->values[0][i][j], v_res_1, gvl); 
                }
        }
        return 0;
}


#endif


