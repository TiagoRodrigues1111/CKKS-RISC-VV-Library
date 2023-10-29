#include "RELINEARIZATION_correct.h"


int relinearize_barrett(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result)
{
	
	int i=0, j=0,k=0;
        const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
	const uint8_t rns_number = Ciphertext_result->rns_number;  
        int auxq=0;
	int64_t auxiliary_array[2][2 * stop_value];	
	
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	
	if( (Ciphertext.polynomial_degree_modulus != relinearization_keys.polynomial_degree_modulus) || 
	(Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus))
		return 1;
	

        for(uint8_t i=0;i<rns_number;i++ )
        {  
                for (j=0;j<2*stop_value;j++)
                {
                        auxiliary_array[0][j]=0;
                        auxiliary_array[1][j]=0;
                }

                for(j=0;j<stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext.values[1][i][j];
                        for(k=0;k<stop_value;k++)
                        {
					
                                // Relin1 * CT3
                                auxiliary_array[0][j+k]	+= relinearization_keys.values[0][k] * Ciphertext.values[2][i][j];
			
                                // Relin2 * CT3
                                auxiliary_array[1][j+k]	+= relinearization_keys.values[1][k] * Ciphertext.values[2][i][j];
                        }		
                }
                
                
                //reduction
                for (j=0;j<stop_value;j++)
                {
                        
                        auxq = (auxiliary_array[0][j] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
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


int relinearize_barrett_vect(struct ciphertext Ciphertext,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_result->rns_number; 
        
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	
	if( (Ciphertext.polynomial_degree_modulus != relinearization_keys.polynomial_degree_modulus) || 
	(Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus))
		return 1;
       
       
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);             
        for(uint8_t i=0;i<rns_number;i++)
        {
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);     
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl); 
                __epi_1xi64 v_coef_mod  = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl); 
                uint64_t auxiliary_array[2][2 * stop_value];
                for (uint32_t j = 0; j<2*stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(2*stop_value - j, __epi_e64, __epi_m1);
                                                
                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][j],v_initialize , gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][j],v_initialize , gvl);
                                
                }
        
                for (uint32_t j=0;j<stop_value;j++)
                {
                        auxiliary_array[0][j]+=Ciphertext.values[0][i][j];
                        auxiliary_array[1][j]+=Ciphertext.values[1][i][j];
                        
                        
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                        
                        __epi_1xi64 v_ciphertext_res_value_2 = __builtin_epi_vbroadcast_1xi64(Ciphertext.values[2][i][j], gvl);  
                                         
                 
                        for (uint32_t k=0; k<stop_value; k+=gvl) 
                        {
                               
        			gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
			
                                __epi_1xi64 v_relin_value_0 = __builtin_epi_vload_1xi64(&relinearization_keys.values[0][k], gvl);
                                __epi_1xi64 v_relin_value_1 = __builtin_epi_vload_1xi64(&relinearization_keys.values[1][k], gvl);
			
                                __epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][j+k], gvl);
                                __epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][j+k], gvl);
			
					
                                __epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext_res_value_2, v_relin_value_0, gvl);
				
                                __epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext_res_value_2, v_relin_value_1, gvl);		
		
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






