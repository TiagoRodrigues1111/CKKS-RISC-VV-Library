#include "HMULT.h"


int HMULT_naive(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result)
{       
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;
            
        for(uint8_t i=0;i<rns_number;i++ )
        {               
                uint64_t auxiliary_array[3][2 * stop_value];        
                for (uint32_t j=0;j<2*stop_value;j++)
                {
                        auxiliary_array[0][j]=0;
                        auxiliary_array[1][j]=0;
                        auxiliary_array[2][j]=0;
                } 
 
                for (uint32_t j=0;j<stop_value;j++)
                {       
                        for(uint32_t k=0;k<stop_value;k++)
                        {       
                                auxiliary_array[0][j+k] += Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][k];   
                                auxiliary_array[1][j+k] += (Ciphertext1.values[0][i][j] * Ciphertext2.values[1][i][k] + Ciphertext1.values[1][i][j] * Ciphertext2.values[0][i][k]);
                                auxiliary_array[2][j+k] += Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][k];
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

                       
                        while(auxiliary_array[2][j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[2][j] -= Ciphertext_result->coefficient_modulus[i];   
                                 
                        while(auxiliary_array[2][stop_value+j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[2][stop_value+j] -= Ciphertext_result->coefficient_modulus[i];  

          
                        Ciphertext_result->values[0][i][j] = auxiliary_array[0][j] - auxiliary_array[0][stop_value+j];
                        if(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[1][i][j] = auxiliary_array[1][j] - auxiliary_array[1][stop_value+j];
                        if(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[2][i][j] = auxiliary_array[2][j] - auxiliary_array[2][stop_value+j];
                        if(Ciphertext_result->values[2][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[2][i][j] += Ciphertext_result->coefficient_modulus[i];      
                }
        }
        return 0;       
}

int HMULT_naive_auto_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result)
{       
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;
         
        #pragma clang loop vectorize(enable) 
        for(uint8_t i=0;i<rns_number;i++ )
        {               
                uint64_t auxiliary_array[3][2 * stop_value];        
                for (uint32_t j=0;j<2*stop_value;j++)
                {
                        auxiliary_array[0][j]=0;
                        auxiliary_array[1][j]=0;
                        auxiliary_array[2][j]=0;
                } 
 
                for (uint32_t j=0;j<stop_value;j++)
                {       
                        for(uint32_t k=0;k<stop_value;k++)
                        {       
                                auxiliary_array[0][j+k] += Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][k];   
                                auxiliary_array[1][j+k] += (Ciphertext1.values[0][i][j] * Ciphertext2.values[1][i][k] + Ciphertext1.values[1][i][j] * Ciphertext2.values[0][i][k]);
                                auxiliary_array[2][j+k] += Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][k];
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

                       
                        while(auxiliary_array[2][j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[2][j] -= Ciphertext_result->coefficient_modulus[i];   
                                 
                        while(auxiliary_array[2][stop_value+j] >= Ciphertext_result->coefficient_modulus[i])
                                auxiliary_array[2][stop_value+j] -= Ciphertext_result->coefficient_modulus[i]; 

          
                        Ciphertext_result->values[0][i][j] = auxiliary_array[0][j] - auxiliary_array[0][stop_value+j];
                        if(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[1][i][j] = auxiliary_array[1][j] - auxiliary_array[1][stop_value+j];
                        if(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[2][i][j] = auxiliary_array[2][j] - auxiliary_array[2][stop_value+j];
                        if(Ciphertext_result->values[2][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[2][i][j] += Ciphertext_result->coefficient_modulus[i];      
                }
        }
        return 0;       
}


int HMULT_barrett(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;
                
                
        for(uint8_t i=0;i<rns_number;i++ )
        {   
                uint64_t auxiliary_array[3][2 * stop_value];       
                for (uint32_t j=0;j<2*stop_value;j++)
                {
                        auxiliary_array[0][j]=0;
                        auxiliary_array[1][j]=0;
                        auxiliary_array[2][j]=0;
                } 
 
                for (uint32_t j=0;j<stop_value;j++)
                {       
                        for(uint32_t k=0;k<stop_value;k++)
                        {       
                                auxiliary_array[0][j+k] += Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][k];   
                                auxiliary_array[1][j+k] += (Ciphertext1.values[0][i][j] * Ciphertext2.values[1][i][k] + Ciphertext1.values[1][i][j] * Ciphertext2.values[0][i][k]);
                                auxiliary_array[2][j+k] += Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][k];                
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


                        auxq = (auxiliary_array[2][j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[2][j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[2][j]) 
                               auxiliary_array[2][j] -= Ciphertext_result->coefficient_modulus[i];                       

                        auxq = (auxiliary_array[2][stop_value+j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[2][stop_value+j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[2][stop_value+j]) 
                               auxiliary_array[2][stop_value+j] -= Ciphertext_result->coefficient_modulus[i];
                       
        
                        Ciphertext_result->values[0][i][j] = auxiliary_array[0][j] - auxiliary_array[0][stop_value+j];
                        if(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[1][i][j] = auxiliary_array[1][j] - auxiliary_array[1][stop_value+j];
                        if(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[2][i][j] = auxiliary_array[2][j] - auxiliary_array[2][stop_value+j];
                        if(Ciphertext_result->values[2][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[2][i][j] += Ciphertext_result->coefficient_modulus[i];
                }                   
        }
        return 0;       
}

int HMULT_barrett_auto_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;
                
        #pragma clang loop vectorize(enable)     
        for(uint8_t i=0;i<rns_number;i++ )
        {   
                uint64_t auxiliary_array[3][2 * stop_value];       
                for (uint32_t j=0;j<2*stop_value;j++)
                {
                        auxiliary_array[0][j]=0;
                        auxiliary_array[1][j]=0;
                        auxiliary_array[2][j]=0;
                } 
 
                for (uint32_t j=0;j<stop_value;j++)
                {       
                        for(uint32_t k=0;k<stop_value;k++)
                        {       
                                auxiliary_array[0][j+k] += Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][k];   
                                auxiliary_array[1][j+k] += (Ciphertext1.values[0][i][j] * Ciphertext2.values[1][i][k] + Ciphertext1.values[1][i][j] * Ciphertext2.values[0][i][k]);
                                auxiliary_array[2][j+k] += Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][k];                
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


                        auxq = (auxiliary_array[2][j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[2][j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[2][j]) 
                               auxiliary_array[2][j] -= Ciphertext_result->coefficient_modulus[i];                       

                        auxq = (auxiliary_array[2][stop_value+j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
                        auxiliary_array[2][stop_value+j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if(Ciphertext_result->coefficient_modulus[i] <= auxiliary_array[2][stop_value+j]) 
                               auxiliary_array[2][stop_value+j] -= Ciphertext_result->coefficient_modulus[i];
                       
        
                        Ciphertext_result->values[0][i][j] = auxiliary_array[0][j] - auxiliary_array[0][stop_value+j];
                        if(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[1][i][j] = auxiliary_array[1][j] - auxiliary_array[1][stop_value+j];
                        if(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] += Ciphertext_result->coefficient_modulus[i];
                        
                        Ciphertext_result->values[2][i][j] = auxiliary_array[2][j] - auxiliary_array[2][stop_value+j];
                        if(Ciphertext_result->values[2][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[2][i][j] += Ciphertext_result->coefficient_modulus[i];
                }                   
        }
        return 0;       
}


#if RISCV_VECTORIAL

int HMULT_naive_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result)
{       
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 

        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;

       
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);

                uint64_t auxiliary_array[3][2 * stop_value];       
                for (uint32_t j = 0; j <2*stop_value;  j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(2*stop_value - j, __epi_e64, __epi_m1);
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j],v_initialize , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j],v_initialize , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j],v_initialize , gvl);
                                
                }
        
                for (uint32_t j=0;j<stop_value;j++)
                {
                        __epi_1xi64 v_ciphertext1_value_0 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[0][i][j], max_gvl);
                        __epi_1xi64 v_ciphertext1_value_1 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[1][i][j], max_gvl); 
               
                 
                        for (uint32_t k = 0; k < stop_value; k += gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(stop_value - k, __epi_e64, __epi_m1);
                        
                                __epi_1xi64 v_ciphertext2_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][k], gvl);
                                __epi_1xi64 v_ciphertext2_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][k], gvl);
                        
                                __epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+k], gvl);
                                __epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+k], gvl);
                                __epi_1xi64 v_aux_array_2 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j+k], gvl);
                        
                        

                                __epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext1_value_0, v_ciphertext2_0, gvl);
                
                                __epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext1_value_0, v_ciphertext2_1, gvl);                 
                                v_result_1 = __builtin_epi_vmacc_1xi64(v_result_1, v_ciphertext1_value_1, v_ciphertext2_0, gvl);
                        
                                __epi_1xi64 v_result_2 = __builtin_epi_vmacc_1xi64(v_aux_array_2, v_ciphertext1_value_1, v_ciphertext2_1, gvl);
        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+k],v_result_0 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+k],v_result_1 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j+k],v_result_2 , gvl);      
                        }      
                }

                for (uint32_t j = 0; j < stop_value; j += gvl) 
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

           
                        // Load aux_result2
                        __epi_1xi64 v_aux_result_2_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j], gvl);
                        __epi_1xi64 v_aux_result_2_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][stop_value+j], gvl);
 

                        // Reduction aux_result2_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_2_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_2_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_2_0, v_aux_result_2_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_2_0, gvl);
                        }
                        
                        // Reduction aux_result2_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_2_1, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_2_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_2_1, v_aux_result_2_1,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_2_1, gvl);
                        }


                        // Sub auxiliary to result
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
                        __epi_1xi64 v_res_3 = __builtin_epi_vsub_1xi64(v_aux_result_2_0, v_aux_result_2_1, gvl);
 
                        
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);
                        
                        
                        // Reduction ciphertext_ans_3
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_3, gvl);
                        v_res_3 = __builtin_epi_vadd_1xi64_mask(v_res_3, v_res_3,v_coef_mod, mask, gvl);                        

            
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_res_2, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[2][i][j], v_res_3, gvl);
                                
                }       
        }
        return 0;
        
}

int HMULT_naive_vect_unroll(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number;   
        const uint8_t unroll = 2;
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;
                      
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        const uint32_t max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
        const uint32_t loops = stop_value/(max_gvl*2);
              
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl); 
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);   
                
                uint64_t auxiliary_array[3][2 * stop_value];
                uint32_t j=0;
                for (j = 0; j < 2*loops; j++) 
                {
                        uint32_t aux1 = j*unroll;
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+0)*max_gvl],v_initialize, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+1)*max_gvl],v_initialize, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+0)*max_gvl],v_initialize, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+1)*max_gvl],v_initialize, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][(aux1+0)*max_gvl],v_initialize, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][(aux1+1)*max_gvl],v_initialize, max_gvl);

                }
                
                gvl = 0; 
                uint32_t start_remain = (j*unroll)*max_gvl;
                for (j = start_remain; j <2*stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(2*stop_value - j, __epi_e64, __epi_m1);
                                                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j],v_initialize , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j],v_initialize , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j],v_initialize , gvl);
                                
                }
                
                for (j=0;j<stop_value;j++)
                {
                
                        __epi_1xi64 v_ciphertext1_value_0 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[0][i][j], max_gvl);  
                        __epi_1xi64 v_ciphertext1_value_1 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[1][i][j], max_gvl); 
                
                        uint32_t k;
                        for (k=0; k < loops; k++) 
                        {
                                uint32_t aux1 = k*unroll;                                        
                                __epi_1xi64 v_ciphertext2_0_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_ciphertext2_0_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][(aux1+1)*max_gvl], max_gvl);
                                
                                
                                __epi_1xi64 v_ciphertext2_1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_ciphertext2_1_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][(aux1+1)*max_gvl], max_gvl);
                        
                                __epi_1xi64 v_aux_array_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_aux_array_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+(aux1+1)*max_gvl], max_gvl);
                        
                                __epi_1xi64 v_aux_array_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_aux_array_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+(aux1+1)*max_gvl], max_gvl);
                        
                                __epi_1xi64 v_aux_array_2_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j+(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_aux_array_2_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j+(aux1+1)*max_gvl], max_gvl);                     
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0_0, v_ciphertext1_value_0, v_ciphertext2_0_0, max_gvl);
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vmacc_1xi64(v_aux_array_0_1, v_ciphertext1_value_0, v_ciphertext2_0_1, max_gvl);
                
                
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vmacc_1xi64(v_aux_array_1_0, v_ciphertext1_value_0, v_ciphertext2_1_0, max_gvl);
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1_1, v_ciphertext1_value_0, v_ciphertext2_1_1, max_gvl);
                                
                                v_result_1_0 = __builtin_epi_vmacc_1xi64(v_result_1_0, v_ciphertext1_value_1, v_ciphertext2_0_0, max_gvl);
                                v_result_1_1 = __builtin_epi_vmacc_1xi64(v_result_1_1, v_ciphertext1_value_1, v_ciphertext2_0_1, max_gvl);
                        
                        
                                __epi_1xi64 v_result_2_0 = __builtin_epi_vmacc_1xi64(v_aux_array_2_0, v_ciphertext1_value_1, v_ciphertext2_1_0, max_gvl);
                                __epi_1xi64 v_result_2_1 = __builtin_epi_vmacc_1xi64(v_aux_array_2_1, v_ciphertext1_value_1, v_ciphertext2_1_1, max_gvl);
                                
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+(aux1+0)*max_gvl],v_result_0_0 , max_gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+(aux1+1)*max_gvl],v_result_0_1 , max_gvl);
                        
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+(aux1+0)*max_gvl],v_result_1_0 , max_gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+(aux1+1)*max_gvl],v_result_1_1 , max_gvl);

                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j+(aux1+0)*max_gvl],v_result_2_0 , max_gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j+(aux1+1)*max_gvl],v_result_2_1 , max_gvl);

                        }
                        gvl = 0; 
                        start_remain = (k*unroll)*max_gvl;
                        
                        for (k = start_remain; k <stop_value; k += gvl) 
                        {

                                gvl = __builtin_epi_vsetvl(stop_value- k, __epi_e64, __epi_m1);
                        
                                __epi_1xi64 v_ciphertext2_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][k], gvl);
                                __epi_1xi64 v_ciphertext2_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][k], gvl);
                        
                                __epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+k], gvl);
                                __epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+k], gvl);
                                __epi_1xi64 v_aux_array_2 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j+k], gvl);
                        
                        

                                __epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext1_value_0, v_ciphertext2_0, gvl);
                
                                __epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext1_value_0, v_ciphertext2_1, gvl);                 
                                v_result_1 = __builtin_epi_vmacc_1xi64(v_result_1, v_ciphertext1_value_1, v_ciphertext2_0, gvl);
                        
                                __epi_1xi64 v_result_2 = __builtin_epi_vmacc_1xi64(v_aux_array_2, v_ciphertext1_value_1, v_ciphertext2_1, gvl);
        
        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+k],v_result_0 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+k],v_result_1 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j+k],v_result_2 , gvl);

                        }
                }
        
                for (uint32_t j = 0; j < stop_value; j += gvl) 
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

           
                        // Load aux_result2
                        __epi_1xi64 v_aux_result_2_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j], gvl);
                        __epi_1xi64 v_aux_result_2_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][stop_value+j], gvl);
 

                        // Reduction aux_result2_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_2_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_2_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_2_0, v_aux_result_2_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_2_0, gvl);
                        }
                        
                        // Reduction aux_result2_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_2_1, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_aux_result_2_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_2_1, v_aux_result_2_1,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_aux_result_2_1, gvl);
                        }


                        // Sub auxiliary to result
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
                        __epi_1xi64 v_res_3 = __builtin_epi_vsub_1xi64(v_aux_result_2_0, v_aux_result_2_1, gvl);
 
                        
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);
                        
                        
                        // Reduction ciphertext_ans_3
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_3, gvl);
                        v_res_3 = __builtin_epi_vadd_1xi64_mask(v_res_3, v_res_3,v_coef_mod, mask, gvl);                        

            
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_res_2, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[2][i][j], v_res_3, gvl);
                                
                }        
        }
        return 0;
}


int HMULT_barrett_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1; 
       
       
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);             
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);     
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl); 
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl); 
                uint64_t auxiliary_array[3][2 * stop_value];
                for (uint32_t j = 0; j<2*stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(2*stop_value - j, __epi_e64, __epi_m1);
                                                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j],v_initialize , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j],v_initialize , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j],v_initialize , gvl);
                                
                }
        
                for (uint32_t j=0;j<stop_value;j++)
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                        __epi_1xi64 v_ciphertext1_value_0 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[0][i][j], gvl);  
                        __epi_1xi64 v_ciphertext1_value_1 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[1][i][j], gvl); 
                 
                        for (uint32_t k=0; k<stop_value; k+=gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(stop_value - k, __epi_e64, __epi_m1);
                        
                                __epi_1xi64 v_ciphertext2_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][k], gvl);
                                __epi_1xi64 v_ciphertext2_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][k], gvl);
                        
                                __epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+k], gvl);
                                __epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+k], gvl);
                                __epi_1xi64 v_aux_array_2 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j+k], gvl);
                        
                                                
                                __epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext1_value_0, v_ciphertext2_0, gvl);
                
                                __epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext1_value_0, v_ciphertext2_1, gvl);                 
                                v_result_1 = __builtin_epi_vmacc_1xi64(v_result_1, v_ciphertext1_value_1, v_ciphertext2_0, gvl);
                        
                                __epi_1xi64 v_result_2 = __builtin_epi_vmacc_1xi64(v_aux_array_2, v_ciphertext1_value_1, v_ciphertext2_1, gvl);
                        
        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+k],v_result_0 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+k],v_result_1 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j+k],v_result_2 , gvl);
                                
                        }
                }
                for (uint32_t j=0; j<stop_value; j+=gvl) 
                {  
                
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
        
                        // Load aux_result0
                        __epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j], gvl);
                        __epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+j], gvl);
  
                        // Reduction aux_result0_0
                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_aux_result_0_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_0_0 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_0_0, gvl);
                        v_aux_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_0, v_aux_result_0_0, v_coef_mod, mask, gvl);

                         // Reduction aux_result0_1
                        v_q = __builtin_epi_vmul_1xi64(v_aux_result_0_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_0_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_0_1, gvl);
                        v_aux_result_0_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_1, v_aux_result_0_1, v_coef_mod, mask, gvl);

  
                        // Load aux_result1
                        __epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j], gvl);
                        __epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+j], gvl);
 

                        // Reduction aux_result1_0
                        v_q = __builtin_epi_vmul_1xi64(v_aux_result_1_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_1_0 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_1_0, gvl);
                        v_aux_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_0, v_aux_result_1_0, v_coef_mod, mask, gvl);

                         // Reduction aux_result1_1
                        v_q = __builtin_epi_vmul_1xi64(v_aux_result_1_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_1_1 = __builtin_epi_vsub_1xi64(v_aux_result_1_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_1_1, gvl);
                        v_aux_result_1_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_1, v_aux_result_1_1, v_coef_mod, mask, gvl);

 
                        // Load aux_result2
                        __epi_1xi64 v_aux_result_2_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j], gvl);
                        __epi_1xi64 v_aux_result_2_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][stop_value+j], gvl);
                
 
                        // Reduction aux_result2_0
                        v_q = __builtin_epi_vmul_1xi64(v_aux_result_2_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_2_0 = __builtin_epi_vsub_1xi64(v_aux_result_2_0, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_2_0, gvl);
                        v_aux_result_2_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_2_0, v_aux_result_2_0, v_coef_mod, mask, gvl);

                         // Reduction aux_result2_1
                        v_q = __builtin_epi_vmul_1xi64(v_aux_result_2_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_2_1 = __builtin_epi_vsub_1xi64(v_aux_result_2_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_2_1, gvl);
                        v_aux_result_2_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_2_1, v_aux_result_2_1, v_coef_mod, mask, gvl);

 
                        // Add both auxiliary to result
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
                        __epi_1xi64 v_res_3 = __builtin_epi_vsub_1xi64(v_aux_result_2_0, v_aux_result_2_1, gvl);
                
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);
                        
                        // Reduction ciphertext_ans_3
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_3, gvl);
                        v_res_3 = __builtin_epi_vadd_1xi64_mask(v_res_3, v_res_3,v_coef_mod, mask, gvl);
                        
                        
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_res_2, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[2][i][j], v_res_3, gvl);
                
                }
        }
        return 0;     
}
        
int HMULT_barrett_vect_unroll(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result)   
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        const uint8_t unroll = 2;        
        if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;               
        if((Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
        (Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
                return 1;

       
        const uint32_t max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
        const uint32_t loops = stop_value/(max_gvl*2);
  
  
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl); 
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl);
                uint64_t auxiliary_array[3][2 * stop_value];   
                uint32_t j;
                for (j = 0; j < 2*loops; j++) 
                {
                        uint32_t aux1 = j*unroll;
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+0)*max_gvl],v_initialize, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+1)*max_gvl],v_initialize, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+0)*max_gvl],v_initialize, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+1)*max_gvl],v_initialize, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][(aux1+0)*max_gvl],v_initialize, max_gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][(aux1+1)*max_gvl],v_initialize, max_gvl);

                }
                gvl = 0; 
                uint32_t start_remain = (j*unroll)*max_gvl;
                for (j = start_remain; j <2*stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(2*stop_value - j, __epi_e64, __epi_m1);
                                                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j],v_initialize , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j],v_initialize , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j],v_initialize , gvl);
                                
                }
        
                for (j=0;j<stop_value;j++)
                {
                
                        __epi_1xi64 v_ciphertext1_value_0 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[0][i][j], max_gvl);
                        __epi_1xi64 v_ciphertext1_value_1 = __builtin_epi_vbroadcast_1xi64(Ciphertext1.values[1][i][j], max_gvl); 
              
                        uint32_t k;
                        for (k = 0; k < loops; k++) 
                        {
                                uint32_t aux1 = k*unroll;
                                
                                __epi_1xi64 v_ciphertext2_0_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_ciphertext2_0_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][(aux1+1)*max_gvl], max_gvl);                  
                                __epi_1xi64 v_ciphertext2_1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_ciphertext2_1_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][(aux1+1)*max_gvl], max_gvl);
                        
                                __epi_1xi64 v_aux_array_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_aux_array_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+(aux1+1)*max_gvl], max_gvl);
                        
                                __epi_1xi64 v_aux_array_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_aux_array_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+(aux1+1)*max_gvl], max_gvl);
                        
                                __epi_1xi64 v_aux_array_2_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j+(aux1+0)*max_gvl], max_gvl);
                                __epi_1xi64 v_aux_array_2_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j+(aux1+1)*max_gvl], max_gvl);                     
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0_0, v_ciphertext1_value_0, v_ciphertext2_0_0, max_gvl);
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vmacc_1xi64(v_aux_array_0_1, v_ciphertext1_value_0, v_ciphertext2_0_1, max_gvl);
                
                
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vmacc_1xi64(v_aux_array_1_0, v_ciphertext1_value_0, v_ciphertext2_1_0, max_gvl);
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1_1, v_ciphertext1_value_0, v_ciphertext2_1_1, max_gvl);
                                
                                v_result_1_0 = __builtin_epi_vmacc_1xi64(v_result_1_0, v_ciphertext1_value_1, v_ciphertext2_0_0, max_gvl);
                                v_result_1_1 = __builtin_epi_vmacc_1xi64(v_result_1_1, v_ciphertext1_value_1, v_ciphertext2_0_1, max_gvl);
                        
                        
                                __epi_1xi64 v_result_2_0 = __builtin_epi_vmacc_1xi64(v_aux_array_2_0, v_ciphertext1_value_1, v_ciphertext2_1_0, max_gvl);
                                __epi_1xi64 v_result_2_1 = __builtin_epi_vmacc_1xi64(v_aux_array_2_1, v_ciphertext1_value_1, v_ciphertext2_1_1, max_gvl);
                                
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+(aux1+0)*max_gvl],v_result_0_0 , max_gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+(aux1+1)*max_gvl],v_result_0_1 , max_gvl);
                        
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+(aux1+0)*max_gvl],v_result_1_0 , max_gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+(aux1+1)*max_gvl],v_result_1_1 , max_gvl);

                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j+(aux1+0)*max_gvl],v_result_2_0 , max_gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j+(aux1+1)*max_gvl],v_result_2_1 , max_gvl);


                        }
                        
                        gvl = 0; 
                        uint32_t start_remain = (k*unroll)*max_gvl;                        
                        for (k = start_remain; k <stop_value; k += gvl) 
                        {

                                gvl = __builtin_epi_vsetvl(stop_value - k, __epi_e64, __epi_m1);
                        
                                __epi_1xi64 v_ciphertext2_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][k], gvl);
                                __epi_1xi64 v_ciphertext2_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][k], gvl);
                        
                                __epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+k], gvl);
                                __epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+k], gvl);
                                __epi_1xi64 v_aux_array_2 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j+k], gvl);
                        
                                __epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext1_value_0, v_ciphertext2_0, gvl);
                
                                __epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext1_value_0, v_ciphertext2_1, gvl);                 
                                v_result_1 = __builtin_epi_vmacc_1xi64(v_result_1, v_ciphertext1_value_1, v_ciphertext2_0, gvl);
                        
                                __epi_1xi64 v_result_2 = __builtin_epi_vmacc_1xi64(v_aux_array_2, v_ciphertext1_value_1, v_ciphertext2_1, gvl);


                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j+k],v_result_0 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j+k],v_result_1 , gvl);
                                __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[2][j+k],v_result_2 , gvl);

                        }
                }     
                for (j=0; j<stop_value; j+=gvl) 
                {  
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
        
                        // Load aux_result0
                        __epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j], gvl);
                        __epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+j], gvl);
  
                        // Reduction aux_result0_0
                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_aux_result_0_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_0_0 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_0_0, gvl);
                        v_aux_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_0, v_aux_result_0_0, v_coef_mod, mask, gvl);

                         // Reduction aux_result0_1
                        v_q = __builtin_epi_vmul_1xi64(v_aux_result_0_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_0_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_0_1, gvl);
                        v_aux_result_0_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_0_1, v_aux_result_0_1, v_coef_mod, mask, gvl);

  
                        // Load aux_result1
                        __epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j], gvl);
                        __epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+j], gvl);
 

                        // Reduction aux_result1_0
                        v_q = __builtin_epi_vmul_1xi64(v_aux_result_1_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_1_0 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_1_0, gvl);
                        v_aux_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_0, v_aux_result_1_0, v_coef_mod, mask, gvl);

                         // Reduction aux_result1_1
                        v_q = __builtin_epi_vmul_1xi64(v_aux_result_1_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_1_1 = __builtin_epi_vsub_1xi64(v_aux_result_1_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_1_1, gvl);
                        v_aux_result_1_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_1_1, v_aux_result_1_1, v_coef_mod, mask, gvl);

 
                        // Load aux_result2
                        __epi_1xi64 v_aux_result_2_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][j], gvl);
                        __epi_1xi64 v_aux_result_2_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[2][stop_value+j], gvl);
                
 
                        // Reduction aux_result2_0
                        v_q = __builtin_epi_vmul_1xi64(v_aux_result_2_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_2_0 = __builtin_epi_vsub_1xi64(v_aux_result_2_0, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_2_0, gvl);
                        v_aux_result_2_0 = __builtin_epi_vsub_1xi64_mask(v_aux_result_2_0, v_aux_result_2_0, v_coef_mod, mask, gvl);

                         // Reduction aux_result2_1
                        v_q = __builtin_epi_vmul_1xi64(v_aux_result_2_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_aux_result_2_1 = __builtin_epi_vsub_1xi64(v_aux_result_2_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_aux_result_2_1, gvl);
                        v_aux_result_2_1 = __builtin_epi_vsub_1xi64_mask(v_aux_result_2_1, v_aux_result_2_1, v_coef_mod, mask, gvl);

 
                        // Add both auxiliary to result
                        __epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
                        __epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
                        __epi_1xi64 v_res_3 = __builtin_epi_vsub_1xi64(v_aux_result_2_0, v_aux_result_2_1, gvl);
                
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_1, gvl);
                        v_res_1 = __builtin_epi_vadd_1xi64_mask(v_res_1, v_res_1,v_coef_mod, mask, gvl);

                        // Reduction ciphertext_ans_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_2, gvl);
                        v_res_2 = __builtin_epi_vadd_1xi64_mask(v_res_2, v_res_2,v_coef_mod, mask, gvl);
                        
                        // Reduction ciphertext_ans_3
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_res_3, gvl);
                        v_res_3 = __builtin_epi_vadd_1xi64_mask(v_res_3, v_res_3,v_coef_mod, mask, gvl);
                        
                        
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_res_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_res_2, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[2][i][j], v_res_3, gvl);
                }
        }
        return 0;
}


#endif
