#include "CMULT.h"

int CMULT_naive(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
      
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if( (Ciphertext1.polynomial_degree_modulus != plaintext1.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;
 
 
        for(uint8_t i=0;i<rns_number;i++ )
        {
                
                uint64_t auxiliary_array[2][2 * stop_value];
                int64_t plaintext_values_reduced_aux[stop_value];            
                for (uint32_t j=0;j<stop_value;j++)
                {
                        auxiliary_array[0][j]=0;
                        auxiliary_array[0][j+stop_value]=0;
                        auxiliary_array[1][j]=0;
                        auxiliary_array[1][j+stop_value]=0;
                        
                        plaintext_values_reduced_aux[j] = plaintext1.values[j];                      
                        // If plaintext value negative, increase it into the ring
                        while(plaintext_values_reduced_aux[j] < 0)
                                plaintext_values_reduced_aux[j] += Ciphertext_result->coefficient_modulus[i];
        
                        // If plaintext value bigger than the ring, reduce it into the ring
                        while(plaintext_values_reduced_aux[j] >= Ciphertext_result->coefficient_modulus[i])
                                plaintext_values_reduced_aux[j] -= Ciphertext_result->coefficient_modulus[i];

                }  
                for (uint32_t j=0;j<stop_value;j++)
                {
                        for(uint32_t k=0;k<stop_value;k++)
                        {
                                auxiliary_array[0][j+k] += Ciphertext1.values[0][i][j] * plaintext_values_reduced_aux[k];  
                                auxiliary_array[1][j+k] += Ciphertext1.values[1][i][j] * plaintext_values_reduced_aux[k];      
                        }
                }
                for (uint32_t j=0;j<stop_value;j++)
                {
                        
                        while(auxiliary_array[0][j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[0][j] -= Ciphertext_result->coefficient_modulus[i];   
                                                 
                        while(auxiliary_array[0][stop_value+j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[0][stop_value+j] -= Ciphertext_result->coefficient_modulus[i];        
                             
                             
                        while(auxiliary_array[1][j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[1][j] -= Ciphertext_result->coefficient_modulus[i];   
                                                 
                        while(auxiliary_array[1][stop_value+j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[1][stop_value+j] -= Ciphertext_result->coefficient_modulus[i];  
        
                        Ciphertext_result->values[0][i][j] = auxiliary_array[0][j] - auxiliary_array[0][stop_value+j];
                        if(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[1][i][j] = auxiliary_array[1][j] - auxiliary_array[1][stop_value+j];
                        if(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] += Ciphertext_result->coefficient_modulus[i]; 
                }
        }
        return 0;       
}

int CMULT_naive_auto_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
      
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if( (Ciphertext1.polynomial_degree_modulus != plaintext1.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;
 
        #pragma clang loop vectorize(enable) 
        for(uint8_t i=0;i<rns_number;i++ )
        {
                
                uint64_t auxiliary_array[2][2 * stop_value];
                int64_t plaintext_values_reduced_aux[stop_value];            
                for (uint32_t j=0;j<stop_value;j++)
                {
                        auxiliary_array[0][j]=0;
                        auxiliary_array[0][j+stop_value]=0;
                        auxiliary_array[1][j]=0;
                        auxiliary_array[1][j+stop_value]=0;
                        
                        plaintext_values_reduced_aux[j] = plaintext1.values[j];                      
                        // If plaintext value negative, increase it into the ring
                        while(plaintext_values_reduced_aux[j] < 0)
                                plaintext_values_reduced_aux[j] += Ciphertext_result->coefficient_modulus[i];
        
                        // If plaintext value bigger than the ring, reduce it into the ring
                        while(plaintext_values_reduced_aux[j] >= Ciphertext_result->coefficient_modulus[i])
                                plaintext_values_reduced_aux[j] -= Ciphertext_result->coefficient_modulus[i];

                }  
                for (uint32_t j=0;j<stop_value;j++)
                {
                        for(uint32_t k=0;k<stop_value;k++)
                        {
                                auxiliary_array[0][j+k] += Ciphertext1.values[0][i][j] * plaintext_values_reduced_aux[k];  
                                auxiliary_array[1][j+k] += Ciphertext1.values[1][i][j] * plaintext_values_reduced_aux[k];      
                        }
                }
                for (uint32_t j=0;j<stop_value;j++)
                {
                        
                        while(auxiliary_array[0][j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[0][j] -= Ciphertext_result->coefficient_modulus[i];   
                                                 
                        while(auxiliary_array[0][stop_value+j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[0][stop_value+j] -= Ciphertext_result->coefficient_modulus[i];        
                             
                             
                        while(auxiliary_array[1][j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[1][j] -= Ciphertext_result->coefficient_modulus[i];   
                                                 
                        while(auxiliary_array[1][stop_value+j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[1][stop_value+j] -= Ciphertext_result->coefficient_modulus[i];  
        
                        Ciphertext_result->values[0][i][j] = auxiliary_array[0][j] - auxiliary_array[0][stop_value+j];
                        if(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[1][i][j] = auxiliary_array[1][j] - auxiliary_array[1][stop_value+j];
                        if(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] += Ciphertext_result->coefficient_modulus[i]; 
                }
        }
        return 0;       
}




int CMULT_barrett(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 

        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != plaintext1.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;


        for(uint8_t i=0;i<rns_number;i++ )
        {
                uint64_t auxiliary_array[2][2 * stop_value];
                int64_t plaintext_values_reduced_aux[stop_value];     
                for (uint32_t j=0;j<stop_value;j++)
                {
                        auxiliary_array[0][j]=0;
                        auxiliary_array[0][j+stop_value]=0;
                        auxiliary_array[1][j]=0;
                        auxiliary_array[1][j+stop_value]=0;
                        
                        plaintext_values_reduced_aux[j] = plaintext1.values[j];                      
                        
                        if(plaintext_values_reduced_aux[j]<0)
                        {
                                plaintext_values_reduced_aux[j] = -plaintext_values_reduced_aux[j]; 
                                uint64_t auxq = ((plaintext_values_reduced_aux[j] * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                                plaintext_values_reduced_aux[j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                                if (Ciphertext_result->coefficient_modulus[i] <= plaintext_values_reduced_aux[j]) 
                                        plaintext_values_reduced_aux[j] -= Ciphertext_result->coefficient_modulus[i];
                                
                                if(plaintext_values_reduced_aux[j] != 0)
                                        plaintext_values_reduced_aux[j] -=  Ciphertext_result->coefficient_modulus[i];
                                
                                plaintext_values_reduced_aux[j] = -plaintext_values_reduced_aux[j];
                        }
                        else
                        {
                                uint64_t auxq = ((plaintext_values_reduced_aux[j] * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                                plaintext_values_reduced_aux[j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                                if (Ciphertext_result->coefficient_modulus[i] <= plaintext_values_reduced_aux[j]) 
                                        plaintext_values_reduced_aux[j] -= Ciphertext_result->coefficient_modulus[i]; 
                        } 
                } 
 
 
                for (uint32_t j=0;j<stop_value;j++)
                {       
                        for(uint32_t k=0;k<stop_value;k++)
                        {       
                                auxiliary_array[0][j+k] += Ciphertext1.values[0][i][j] * plaintext_values_reduced_aux[k];  
                                auxiliary_array[1][j+k] += Ciphertext1.values[1][i][j] * plaintext_values_reduced_aux[k];                  
                        }                       
                }
                for (uint32_t j=0;j<stop_value;j++)
                {
        
                        uint64_t auxq = (auxiliary_array[0][j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[0][j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[0][j]) 
                               auxiliary_array[0][j] -= Ciphertext_result->coefficient_modulus[i];                       

                        auxq = (auxiliary_array[0][stop_value+j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[0][stop_value+j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[0][stop_value+j]) 
                               auxiliary_array[0][stop_value+j] -= Ciphertext_result->coefficient_modulus[i];    

                        auxq = (auxiliary_array[1][j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[1][j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[1][j]) 
                               auxiliary_array[1][j] -= Ciphertext_result->coefficient_modulus[i];                       

                        auxq = (auxiliary_array[1][stop_value+j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[1][stop_value+j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[1][stop_value+j]) 
                               auxiliary_array[1][stop_value+j] -= Ciphertext_result->coefficient_modulus[i]; 

        
                        Ciphertext_result->values[0][i][j] = auxiliary_array[0][j] - auxiliary_array[0][stop_value+j];
                        if(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[1][i][j] = auxiliary_array[1][j] - auxiliary_array[1][stop_value+j];
                        if(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] += Ciphertext_result->coefficient_modulus[i];
       
                }
        }
        return 0;       
}

int CMULT_barrett_auto_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 

        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != plaintext1.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;

        #pragma clang loop vectorize(enable)
        for(uint8_t i=0;i<rns_number;i++ )
        {
                uint64_t auxiliary_array[2][2 * stop_value];
                int64_t plaintext_values_reduced_aux[stop_value];     
                for (uint32_t j=0;j<stop_value;j++)
                {
                        auxiliary_array[0][j]=0;
                        auxiliary_array[0][j+stop_value]=0;
                        auxiliary_array[1][j]=0;
                        auxiliary_array[1][j+stop_value]=0;
                        
                        plaintext_values_reduced_aux[j] = plaintext1.values[j];                      
                        
                        if(plaintext_values_reduced_aux[j]<0)
                        {
                                plaintext_values_reduced_aux[j] = -plaintext_values_reduced_aux[j]; 
                                uint64_t auxq = ((plaintext_values_reduced_aux[j] * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                                plaintext_values_reduced_aux[j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                                if (Ciphertext_result->coefficient_modulus[i] <= plaintext_values_reduced_aux[j]) 
                                        plaintext_values_reduced_aux[j] -= Ciphertext_result->coefficient_modulus[i];
                                
                                if(plaintext_values_reduced_aux[j] != 0)
                                        plaintext_values_reduced_aux[j] -=  Ciphertext_result->coefficient_modulus[i];
                                
                                plaintext_values_reduced_aux[j] = -plaintext_values_reduced_aux[j];
                        }
                        else
                        {
                                uint64_t auxq = ((plaintext_values_reduced_aux[j] * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                                plaintext_values_reduced_aux[j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                                if (Ciphertext_result->coefficient_modulus[i] <= plaintext_values_reduced_aux[j]) 
                                        plaintext_values_reduced_aux[j] -= Ciphertext_result->coefficient_modulus[i]; 
                        }
                } 
 
 
                for (uint32_t j=0;j<stop_value;j++)
                {       
                        for(uint32_t k=0;k<stop_value;k++)
                        {       
                                auxiliary_array[0][j+k] += Ciphertext1.values[0][i][j] * plaintext_values_reduced_aux[k];  
                                auxiliary_array[1][j+k] += Ciphertext1.values[1][i][j] * plaintext_values_reduced_aux[k];                  
                        }                       
                }
                for (uint32_t j=0;j<stop_value;j++)
                {
        
                        uint64_t auxq = (auxiliary_array[0][j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[0][j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[0][j]) 
                               auxiliary_array[0][j] -= Ciphertext_result->coefficient_modulus[i];                       

                        auxq = (auxiliary_array[0][stop_value+j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[0][stop_value+j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[0][stop_value+j]) 
                               auxiliary_array[0][stop_value+j] -= Ciphertext_result->coefficient_modulus[i];    

                        auxq = (auxiliary_array[1][j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[1][j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[1][j]) 
                               auxiliary_array[1][j] -= Ciphertext_result->coefficient_modulus[i];                       

                        auxq = (auxiliary_array[1][stop_value+j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[1][stop_value+j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[1][stop_value+j]) 
                               auxiliary_array[1][stop_value+j] -= Ciphertext_result->coefficient_modulus[i]; 

        
                        Ciphertext_result->values[0][i][j] = auxiliary_array[0][j] - auxiliary_array[0][stop_value+j];
                        if(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[1][i][j] = auxiliary_array[1][j] - auxiliary_array[1][stop_value+j];
                        if(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] += Ciphertext_result->coefficient_modulus[i];
       
                }
        }
        return 0;       
}



#if RISCV_VECTORIAL 


int CMULT_naive_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result)
{       
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 

        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != plaintext1.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;

  
       
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);    
        for(uint8_t i=0;i<rns_number;i++)
        {
                      
                __epi_1xi64 v_zero = __builtin_epi_vbroadcast_1xi64(0, gvl); 
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);  uint64_t auxiliary_array[2][2 * stop_value];       
                uint64_t plaintext_values_reduced_aux[stop_value];
                for (uint32_t j=0;j<stop_value;j+=gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                                                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j],v_zero , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j],v_zero , gvl);    
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+stop_value],v_zero , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+stop_value],v_zero , gvl);  
                        
                        
                        // Load plaintext
                        __epi_1xi64 v_plaintext = __builtin_epi_vload_1xi64(&plaintext1.values[j], gvl);
        
                        // Reduction plaintext part-1
                        __epi_1xi1 mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext,v_zero,gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,gvl))!=0)
                        {                       
                                v_plaintext = __builtin_epi_vadd_1xi64_mask(v_plaintext, v_plaintext,v_coef_mod, mask_pt_reduce, gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext,v_zero,gvl);
                        }
                        
                        // Reduction plaintext part-2
                        
                        mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,gvl))!=0)
                        {                       
                                v_plaintext = __builtin_epi_vsub_1xi64_mask(v_plaintext, v_plaintext,v_coef_mod, mask_pt_reduce, gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext, gvl);
                        }
                        
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[j], v_plaintext, gvl);
                }
                for (uint32_t j=0;j<stop_value;j++)
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                        __epi_1xi64 v_ciphertext1_value_0 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext1_value_1 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[1][i][j], gvl);
                                 
                        for (uint32_t k=0;k<stop_value;k+=gvl)
                        {
                                gvl = __builtin_epi_vsetvl(stop_value - k, __epi_e64, __epi_m1);
                        
                        
                                // Load plaintext aux
                                __epi_1xi64 v_plaintext = __builtin_epi_vload_unsigned_1xi64(&plaintext_values_reduced_aux[k], gvl);
                        
                                __epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+k], gvl);
                                __epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+k], gvl);                  
                        
                                __epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext1_value_0, v_plaintext, gvl);     
                                __epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext1_value_1, v_plaintext, gvl);
        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+k],v_result_0 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+k],v_result_1 , gvl);        
                        }
                
                }
        
                for (uint32_t j=0; j<stop_value; j+=gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
        
                      
                      // Load aux_result0
                        __epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j], gvl);
                        __epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+j], gvl);
 
                        // Reduction aux_result0_0
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_0, v_aux_result_0_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_0, gvl);
                        }
                        
                        // Reduction aux_result0_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_1, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_0_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_1, v_aux_result_0_1,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_1, gvl);
                        }

 
                        // Load aux_result1
                        __epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j], gvl);
                        __epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+j], gvl);

                        // Reduction aux_result1_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_0, v_aux_result_1_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_0, gvl);
                        }
                        
                        // Reduction aux_result1_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_1, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_1_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_1, v_aux_result_1_1,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_1, gvl);
                        }
                        
                
                        // Sub auxiliary to result
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
                
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);  
                        
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_res_2, gvl);
                }      
        }       
        return 0;
}

int CMULT_naive_vect_unroll(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result)
{    
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        const uint8_t unroll = 2;
        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != plaintext1.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;       

        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        const uint32_t max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
        const uint32_t loops = stop_value/(max_gvl*2);
        
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 v_zero = __builtin_epi_vbroadcast_1xi64(0, gvl); 
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);                
                
                uint64_t auxiliary_array[2][2 * stop_value]; 
                uint64_t plaintext_values_reduced_aux[stop_value];                
                uint32_t j=0;
                for (j = 0; j<loops;j++) 
                {
                        uint32_t aux1 = j*unroll;
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+0)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+1)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+0)*max_gvl + stop_value],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+1)*max_gvl + stop_value],v_zero, max_gvl);
                        
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+0)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+1)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+0)*max_gvl + stop_value],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+1)*max_gvl + stop_value],v_zero, max_gvl);
                
                        // Load plaintext
                        __epi_1xi64 v_plaintext_0 = __builtin_epi_vload_1xi64(&plaintext1.values[(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_plaintext_1 = __builtin_epi_vload_1xi64(&plaintext1.values[(aux1+1)*max_gvl], max_gvl);
        
                        // Reduction plaintext part-1
                        __epi_1xi1 mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_0,v_zero,max_gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_0 = __builtin_epi_vadd_1xi64_mask(v_plaintext_0, v_plaintext_0,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_0,v_zero,max_gvl);
                        }
                        
                        // Reduction plaintext part-2
                        
                        mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_0, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_0 = __builtin_epi_vsub_1xi64_mask(v_plaintext_0, v_plaintext_0,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_0, max_gvl);
                        }
                        
                        
                        
                        
                        // Reduction plaintext 2 part-1
                        mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_1,v_zero,max_gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_1 = __builtin_epi_vadd_1xi64_mask(v_plaintext_1, v_plaintext_1,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_1,v_zero,max_gvl);
                        }
                        
                        // Reduction plaintext 2 part-2
                        
                        mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_1, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_1 = __builtin_epi_vsub_1xi64_mask(v_plaintext_1, v_plaintext_1,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_1, max_gvl);
                        }  
                        
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[(aux1+0)*max_gvl], v_plaintext_0, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[(aux1+1)*max_gvl], v_plaintext_1, max_gvl);
                   
                }
                gvl = 0; 
                uint32_t start_remain = (j*unroll)*max_gvl;
                for (j = start_remain; j <stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                                                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j],v_zero , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j],v_zero , gvl);    
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+stop_value],v_zero , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+stop_value],v_zero , gvl);  
                        
                        // Load plaintext
                        __epi_1xi64 v_plaintext = __builtin_epi_vload_1xi64(&plaintext1.values[j], gvl);
        
                        // Reduction plaintext part-1
                        __epi_1xi1 mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext,v_zero,gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,gvl))!=0)
                        {                       
                                v_plaintext = __builtin_epi_vadd_1xi64_mask(v_plaintext, v_plaintext,v_coef_mod, mask_pt_reduce, gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext,v_zero,gvl);
                        }
                        
                        // Reduction plaintext part-2
                        
                        mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,gvl))!=0)
                        {                       
                                v_plaintext = __builtin_epi_vsub_1xi64_mask(v_plaintext, v_plaintext,v_coef_mod, mask_pt_reduce, gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext, gvl);
                        }
                        
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[j], v_plaintext, gvl);

                }               
                for (j=0;j<stop_value;j++)
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                        __epi_1xi64 v_ciphertext1_value_0 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[0][i][j], gvl);  
                        __epi_1xi64 v_ciphertext1_value_1 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[1][i][j], gvl); 
                        
                        for (uint32_t k = 0; k < stop_value; k += gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(stop_value - k, __epi_e64, __epi_m1);
                        
                                // Load plaintext
                                __epi_1xi64 v_plaintext = __builtin_epi_vload_unsigned_1xi64(&plaintext_values_reduced_aux[k], gvl);
                        
                                __epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+k], gvl);
                                __epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+k], gvl);                  
                        
                                __epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext1_value_0, v_plaintext, gvl);     
                                __epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext1_value_1, v_plaintext, gvl);
        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+k],v_result_0 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+k],v_result_1 , gvl);
                                
                        }
                }
        
        
                for (j = 0; j < stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
         
                        // Load aux_result0
                        __epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j], gvl);
                        __epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+j], gvl);
 
                        // Reduction aux_result0_0
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_0, v_aux_result_0_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_0, gvl);
                        }
                        
                        // Reduction aux_result0_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_1, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_0_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_1, v_aux_result_0_1,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_1, gvl);
                        }

 
                        // Load aux_result1
                        __epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j], gvl);
                        __epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+j], gvl);

                        // Reduction aux_result1_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_0, v_aux_result_1_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_0, gvl);
                        }
                        
                        // Reduction aux_result1_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_1, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_1_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_1, v_aux_result_1_1,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_1, gvl);
                        }
                        
                
                        // Sub auxiliary to result
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
                
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);  
                        
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_res_2, gvl);
                }
  
        }
        return 0;
}

int CMULT_naive_vect_unroll_2(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        const uint8_t unroll = 2;
        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != plaintext1.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;
                 
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        const uint32_t max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
        const uint32_t loops = stop_value/(max_gvl*2);
        

        for(uint8_t i=0;i<rns_number;i++)
        {     
                __epi_1xi64 v_zero = __builtin_epi_vbroadcast_1xi64(0, gvl);              
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);              
                
                uint64_t auxiliary_array[2][2 * stop_value]; 
                uint64_t plaintext_values_reduced_aux[stop_value];                
                uint32_t j=0;
                for (j = 0; j<loops;j++) 
                {
                        uint32_t aux1 = j*unroll;
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+0)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+1)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+0)*max_gvl + stop_value],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+1)*max_gvl + stop_value],v_zero, max_gvl);
                        
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+0)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+1)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+0)*max_gvl + stop_value],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+1)*max_gvl + stop_value],v_zero, max_gvl);
                
                        // Load plaintext
                        __epi_1xi64 v_plaintext_0 = __builtin_epi_vload_1xi64(&plaintext1.values[(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_plaintext_1 = __builtin_epi_vload_1xi64(&plaintext1.values[(aux1+1)*max_gvl], max_gvl);
        
                        // Reduction plaintext part-1
                        __epi_1xi1 mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_0,v_zero,max_gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_0 = __builtin_epi_vadd_1xi64_mask(v_plaintext_0, v_plaintext_0,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_0,v_zero,max_gvl);
                        }
                        
                        // Reduction plaintext part-2
                        
                        mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_0, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_0 = __builtin_epi_vsub_1xi64_mask(v_plaintext_0, v_plaintext_0,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_0, max_gvl);
                        }
                        
                        
                        
                        
                        // Reduction plaintext 2 part-1
                        mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_1,v_zero,max_gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_1 = __builtin_epi_vadd_1xi64_mask(v_plaintext_1, v_plaintext_1,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext_1,v_zero,max_gvl);
                        }
                        
                        // Reduction plaintext 2 part-2
                        
                        mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_1, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,max_gvl))!=0)
                        {                       
                                v_plaintext_1 = __builtin_epi_vsub_1xi64_mask(v_plaintext_1, v_plaintext_1,v_coef_mod, mask_pt_reduce, max_gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext_1, max_gvl);
                        }  
                        
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[(aux1+0)*max_gvl], v_plaintext_0, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[(aux1+1)*max_gvl], v_plaintext_1, max_gvl);
                   
                }
                gvl = 0; 
                uint32_t start_remain = (j*unroll)*max_gvl;
                for (j = start_remain; j <stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                                                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j],v_zero , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j],v_zero , gvl);    
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+stop_value],v_zero , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+stop_value],v_zero , gvl);  
                        
                        // Load plaintext
                        __epi_1xi64 v_plaintext = __builtin_epi_vload_1xi64(&plaintext1.values[j], gvl);
        
                        // Reduction plaintext part-1
                        __epi_1xi1 mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext,v_zero,gvl);
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,gvl))!=0)
                        {                       
                                v_plaintext = __builtin_epi_vadd_1xi64_mask(v_plaintext, v_plaintext,v_coef_mod, mask_pt_reduce, gvl);
                                mask_pt_reduce = __builtin_epi_vmslt_1xi64(v_plaintext,v_zero,gvl);
                        }
                        
                        // Reduction plaintext part-2
                        
                        mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask_pt_reduce,gvl))!=0)
                        {                       
                                v_plaintext = __builtin_epi_vsub_1xi64_mask(v_plaintext, v_plaintext,v_coef_mod, mask_pt_reduce, gvl);
                                mask_pt_reduce = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_plaintext, gvl);
                        }
                        
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[j], v_plaintext, gvl);

                }    

                for (j=0;j<stop_value;j++)
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                        __epi_1xi64 v_ciphertext1_value_0 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[0][i][j], gvl);  
                        __epi_1xi64 v_ciphertext1_value_1 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[1][i][j], gvl); 
                
                        uint32_t k;
                        for (k = 0; k < loops; k++) 
                        {
                                uint32_t aux1 = k*unroll;                             
                                // Load plaintext
                                __epi_1xi64 v_plaintext_0 = __builtin_epi_vload_unsigned_1xi64(&plaintext_values_reduced_aux[(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_plaintext_1 = __builtin_epi_vload_unsigned_1xi64(&plaintext_values_reduced_aux[(aux1+1)*max_gvl], max_gvl);
                        
                        
                                __epi_1xi64 v_aux_array_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_aux_array_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+(aux1+1)*max_gvl], max_gvl);
                        
                                __epi_1xi64 v_aux_array_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+(aux1+0)*max_gvl], max_gvl);                     
                                __epi_1xi64 v_aux_array_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+(aux1+1)*max_gvl], max_gvl);     
                        
                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0_0, v_ciphertext1_value_0, v_plaintext_0, max_gvl);   
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vmacc_1xi64(v_aux_array_0_1, v_ciphertext1_value_0, v_plaintext_1, max_gvl);   
                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vmacc_1xi64(v_aux_array_1_0, v_ciphertext1_value_1, v_plaintext_0, max_gvl);
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1_1, v_ciphertext1_value_1, v_plaintext_1, max_gvl);
                        
                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+(aux1+0)*max_gvl],v_result_0_0 , max_gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+(aux1+1)*max_gvl],v_result_0_1 , max_gvl);
                        
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+(aux1+0)*max_gvl],v_result_1_0 , max_gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+(aux1+1)*max_gvl],v_result_1_1 , max_gvl);

                        }
                        gvl = 0;
                        
                        uint32_t start_remain = (k*unroll)*max_gvl;
                        
                        for (k = start_remain; k <stop_value; k += gvl) 
                        {

                                gvl = __builtin_epi_vsetvl(stop_value - k, __epi_e64, __epi_m1);
                                
                                // Load plaintext
                                __epi_1xi64 v_plaintext = __builtin_epi_vload_unsigned_1xi64(&plaintext_values_reduced_aux[k], gvl);
                        
                                __epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+k], gvl);
                                __epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+k], gvl);                  
                                
                                __epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext1_value_0, v_plaintext, gvl);     
                                __epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext1_value_1, v_plaintext, gvl);
        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+k],v_result_0 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+k],v_result_1 , gvl);
                        } 
                }

                for (j = 0; j < stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
         
                        // Load aux_result0
                        __epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j], gvl);
                        __epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+j], gvl);
 
                        // Reduction aux_result0_0
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_0, v_aux_result_0_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_0, gvl);
                        }
                        
                        // Reduction aux_result0_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_1, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_0_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_1, v_aux_result_0_1,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_0_1, gvl);
                        }

 
                        // Load aux_result1
                        __epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j], gvl);
                        __epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+j], gvl);

                        // Reduction aux_result1_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_0, v_aux_result_1_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_0, gvl);
                        }
                        
                        // Reduction aux_result1_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_1, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_1_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_1, v_aux_result_1_1,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_1_1, gvl);
                        }
                        
                
                        // Sub auxiliary to result
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
                
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);  
                        
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_res_2, gvl);
                }    
        }      
        return 0;                
}


int CMULT_barrett_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != plaintext1.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);     
                __epi_1xi64 v_zero = __builtin_epi_vbroadcast_1xi64(0, gvl); 
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(13, gvl);
                uint64_t auxiliary_array[2][2 * stop_value];             
                uint64_t plaintext_values_reduced_aux[stop_value];
                for (uint32_t j=0;j<stop_value;j+=gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                                                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j],v_zero , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j],v_zero , gvl);    
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+stop_value],v_zero , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+stop_value],v_zero , gvl);  
                        
                        
                        // Load plaintext
                        __epi_1xi64 v_plaintext = __builtin_epi_vload_1xi64(&plaintext1.values[j], gvl);
        
                        // Reduction plaintext
                        __epi_1xi64 v_q = __builtin_epi_vmulhu_1xi64(v_plaintext, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_plaintext = __builtin_epi_vsub_1xi64(v_plaintext, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_plaintext, gvl);
                        v_plaintext = __builtin_epi_vsub_1xi64_mask(v_plaintext, v_plaintext, v_coef_mod, mask, gvl);
                        
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[j], v_plaintext, gvl);
                        
                }  
                for (uint32_t j=0;j<stop_value;j++)
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                        __epi_1xi64 v_ciphertext1_value_0 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext1_value_1 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[1][i][j], gvl);
                                 
                        for (uint32_t k=0;k<stop_value;k+=gvl)
                        {
                                gvl = __builtin_epi_vsetvl(stop_value - k, __epi_e64, __epi_m1);
                        
                        
                                // Load plaintext aux
                                __epi_1xi64 v_plaintext = __builtin_epi_vload_unsigned_1xi64(&plaintext_values_reduced_aux[k], gvl);
                        
                                __epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+k], gvl);
                                __epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+k], gvl);                  
                        
                                __epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext1_value_0, v_plaintext, gvl);     
                                __epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext1_value_1, v_plaintext, gvl);
        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+k],v_result_0 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+k],v_result_1 , gvl);        
                        }
                
                }
        
        
                for (uint32_t j=0; j<stop_value; j+=gvl) 
                {
                        
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
        
                        // Load aux_result0
                        __epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j], gvl);
                        __epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+j], gvl);
  
                        // Reduction aux_result0_0
                        __epi_1xi64 v_q = __builtin_epi_vmulhu_1xi64(v_aux_result_0_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_0_0 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_0_0, gvl);
                        v_aux_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_0, v_aux_result_0_0, v_coef_mod, mask, gvl);

                         // Reduction aux_result0_1
                        v_q = __builtin_epi_vmulhu_1xi64(v_aux_result_0_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_0_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_0_1, gvl);
                        v_aux_result_0_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_1, v_aux_result_0_1, v_coef_mod, mask, gvl);

  
                        // Load aux_result1
                        __epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j], gvl);
                        __epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+j], gvl);
 

                        // Reduction aux_result1_0
                        v_q = __builtin_epi_vmulhu_1xi64(v_aux_result_1_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_1_0 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_1_0, gvl);
                        v_aux_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_0, v_aux_result_1_0, v_coef_mod, mask, gvl);

                         // Reduction aux_result1_1
                        v_q = __builtin_epi_vmulhu_1xi64(v_aux_result_1_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_1_1 = __builtin_epi_vsub_1xi64(v_aux_result_1_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_1_1, gvl);
                        v_aux_result_1_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_1, v_aux_result_1_1, v_coef_mod, mask, gvl);
                      
 
                        // Add both auxiliary to result
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
                
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);
                        
                        
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_res_2, gvl);
                
                }
        }
        return 0;       
}

int CMULT_barrett_vect_unroll(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        const uint8_t unroll = 2;
        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != plaintext1.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;

       
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        const uint32_t max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
        const uint32_t loops = stop_value/(max_gvl*2);
         
 
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);
                __epi_1xi64 v_zero = __builtin_epi_vbroadcast_1xi64(0, gvl); 
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(13, gvl);
                
                uint64_t auxiliary_array[2][2 * stop_value];
                uint64_t plaintext_values_reduced_aux[stop_value];
                uint32_t j=0;
                for (j = 0; j<loops;j++) 
                {
                        uint32_t aux1 = j*unroll;
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+0)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+1)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+0)*max_gvl + stop_value],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+1)*max_gvl + stop_value],v_zero, max_gvl);
                        
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+0)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+1)*max_gvl],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+0)*max_gvl + stop_value],v_zero, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+1)*max_gvl + stop_value],v_zero, max_gvl);
                
                        // Load plaintext
                        __epi_1xi64 v_plaintext_0 = __builtin_epi_vload_1xi64(&plaintext1.values[(aux1+0)*max_gvl], max_gvl);
                        __epi_1xi64 v_plaintext_1 = __builtin_epi_vload_1xi64(&plaintext1.values[(aux1+1)*max_gvl], max_gvl);
        

                        // Reduction plaintext
                        __epi_1xi64 v_q = __builtin_epi_vmulhu_1xi64(v_plaintext_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_plaintext_0 = __builtin_epi_vsub_1xi64(v_plaintext_0, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_plaintext_0, gvl);
                        v_plaintext_0 = __builtin_epi_vsub_1xi64_mask(v_plaintext_0, v_plaintext_0, v_coef_mod, mask, gvl);


                        // Reduction plaintext
                        v_q = __builtin_epi_vmulhu_1xi64(v_plaintext_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_plaintext_1 = __builtin_epi_vsub_1xi64(v_plaintext_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_plaintext_1, gvl);
                        v_plaintext_1 = __builtin_epi_vsub_1xi64_mask(v_plaintext_1, v_plaintext_1, v_coef_mod, mask, gvl);

                        
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[(aux1+0)*max_gvl], v_plaintext_0, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[(aux1+1)*max_gvl], v_plaintext_1, max_gvl);
                   
                }
                gvl = 0; 
                uint32_t start_remain = (j*unroll)*max_gvl;
                for (j = start_remain; j <stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                                                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j],v_zero , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j],v_zero , gvl);    
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+stop_value],v_zero , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+stop_value],v_zero , gvl);  
                        
                        // Load plaintext
                        __epi_1xi64 v_plaintext = __builtin_epi_vload_1xi64(&plaintext1.values[j], gvl);
        
                        // Reduction plaintext
                        __epi_1xi64 v_q = __builtin_epi_vmulhu_1xi64(v_plaintext, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_plaintext = __builtin_epi_vsub_1xi64(v_plaintext, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_plaintext, gvl);
                        v_plaintext = __builtin_epi_vsub_1xi64_mask(v_plaintext, v_plaintext, v_coef_mod, mask, gvl);
                        
                        __builtin_epi_vstore_unsigned_1xi64(&plaintext_values_reduced_aux[j], v_plaintext, gvl);

                }               
                
                
                for (j=0;j<stop_value;j++)
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                        __epi_1xi64 v_ciphertext1_value_0 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext1_value_1 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[1][i][j], gvl); 
                
                        uint32_t k;
                        for (k = 0; k < loops; k++) 
                        {
                                uint32_t aux1 = k*unroll;                             
                                // Load plaintext
                                __epi_1xi64 v_plaintext_0 = __builtin_epi_vload_unsigned_1xi64(&plaintext_values_reduced_aux[(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_plaintext_1 = __builtin_epi_vload_unsigned_1xi64(&plaintext_values_reduced_aux[(aux1+1)*max_gvl], max_gvl);
                        
                        
                                __epi_1xi64 v_aux_array_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_aux_array_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+(aux1+1)*max_gvl], max_gvl);
                        
                                __epi_1xi64 v_aux_array_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+(aux1+0)*max_gvl], max_gvl);                     
                                __epi_1xi64 v_aux_array_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+(aux1+1)*max_gvl], max_gvl);     
                        
                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0_0, v_ciphertext1_value_0, v_plaintext_0, max_gvl);   
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vmacc_1xi64(v_aux_array_0_1, v_ciphertext1_value_0, v_plaintext_1, max_gvl);   
                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vmacc_1xi64(v_aux_array_1_0, v_ciphertext1_value_1, v_plaintext_0, max_gvl);
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1_1, v_ciphertext1_value_1, v_plaintext_1, max_gvl);
                        
                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+(aux1+0)*max_gvl],v_result_0_0 , max_gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+(aux1+1)*max_gvl],v_result_0_1 , max_gvl);
                        
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+(aux1+0)*max_gvl],v_result_1_0 , max_gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+(aux1+1)*max_gvl],v_result_1_1 , max_gvl);

                        }
                        gvl = 0;
                        
                        uint32_t start_remain = (k*unroll)*max_gvl;
                        
                        for (k = start_remain; k <stop_value; k += gvl) 
                        {

                                gvl = __builtin_epi_vsetvl(stop_value - k, __epi_e64, __epi_m1);
                                
                                // Load plaintext
                                __epi_1xi64 v_plaintext = __builtin_epi_vload_unsigned_1xi64(&plaintext_values_reduced_aux[k], gvl);
                        
                                __epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+k], gvl);
                                __epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+k], gvl);                  
                                
                                __epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext1_value_0, v_plaintext, gvl);     
                                __epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext1_value_1, v_plaintext, gvl);
        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+k],v_result_0 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+k],v_result_1 , gvl);
                        } 
                }
           
                for (j=0; j<stop_value; j+=gvl) 
                {
                        
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
        
                        // Load aux_result0
                        __epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j], gvl);
                        __epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+j], gvl);
  
                        // Reduction aux_result0_0
                        __epi_1xi64 v_q = __builtin_epi_vmulhu_1xi64(v_aux_result_0_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_0_0 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_0_0, gvl);
                        v_aux_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_0, v_aux_result_0_0, v_coef_mod, mask, gvl);

                         // Reduction aux_result0_1
                        v_q = __builtin_epi_vmulhu_1xi64(v_aux_result_0_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_0_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_0_1, gvl);
                        v_aux_result_0_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_1, v_aux_result_0_1, v_coef_mod, mask, gvl);

  
                        // Load aux_result1
                        __epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j], gvl);
                        __epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+j], gvl);
 

                        // Reduction aux_result1_0
                        v_q = __builtin_epi_vmulhu_1xi64(v_aux_result_1_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_1_0 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_1_0, gvl);
                        v_aux_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_0, v_aux_result_1_0, v_coef_mod, mask, gvl);

                         // Reduction aux_result1_1
                        v_q = __builtin_epi_vmulhu_1xi64(v_aux_result_1_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_1_1 = __builtin_epi_vsub_1xi64(v_aux_result_1_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_1_1, gvl);
                        v_aux_result_1_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_1, v_aux_result_1_1, v_coef_mod, mask, gvl);
                      
 
                        // Add both auxiliary to result
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
                
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);
                        
                        
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_res_2, gvl);
                
                }
        }     
        return 0;
}


#endif