#include "CWM.h"


int CWM(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2,struct ciphertext *Ciphertext_result)
{
	const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
	const uint8_t rns_number = Ciphertext_result->rns_number; 
        
	if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;	  	
	if( (Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
	(Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
        for(uint8_t i=0;i<rns_number;i++)
        {           
                for (uint32_t j=0;j<stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][j];

                        // Ciphertext_result->values[0][i] = Ciphertext1.values[0][i] * Ciphertext2.values[0][i];
                        // Ciphertext_result->values[1][i] = Ciphertext1.values[0][i] * Ciphertext2.values[1][i] + Ciphertext1.values[1][i] * Ciphertext2.values[0][i] ;
                        // Ciphertext_result->values[2][i] = Ciphertext1.values[1][i] * Ciphertext2.values[1][i];
        
                        /*
                        if( Ciphertext_result->values[0][i] >= coefficient_modulus )
                        {		
                                Ciphertext_result->values[0][i] -= coefficient_modulus;
                        }

                        if( Ciphertext_result->values[1][i] >= coefficient_modulus )
                        {		
                                Ciphertext_result->values[1][i] -= coefficient_modulus;
                        }
                        */
                }     
        }
	return 0;
}



int CWM_true(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2,struct ciphertext *Ciphertext_result)
{
	const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
	const uint8_t rns_number = Ciphertext_result->rns_number; 
        
	if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;	  	
	if( (Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
	(Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
        for(uint8_t i=0;i<rns_number;i++)
        {           
                for (uint32_t j=0;j<stop_value;j++)
                {
                //        Ciphertext_result->values[0][i][j] = Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][j];
                //        Ciphertext_result->values[1][i][j] = Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][j];

                         Ciphertext_result->values[0][i][j] = Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][j];
                         Ciphertext_result->values[1][i][j] = Ciphertext1.values[0][i][j] * Ciphertext2.values[1][i][j] + Ciphertext1.values[1][i][j] * Ciphertext2.values[0][i][j] ;
                         Ciphertext_result->values[2][i][j] = Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][j];
        
        
                        while(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] -= Ciphertext_result->coefficient_modulus[i];   
                                                 

                        while(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] -= Ciphertext_result->coefficient_modulus[i];   

                        while(Ciphertext_result->values[2][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[2][i][j] -= Ciphertext_result->coefficient_modulus[i];   
                        
                }     
        }
	return 0;
}


int CWM_true_mod_comp(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2,struct ciphertext *Ciphertext_result)
{
	const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
	const uint8_t rns_number = Ciphertext_result->rns_number; 
        
	if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;	  	
	if( (Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
	(Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
        for(uint8_t i=0;i<rns_number;i++)
        {           
                for (uint32_t j=0;j<stop_value;j++)
                {
                //        Ciphertext_result->values[0][i][j] = Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][j];
                //        Ciphertext_result->values[1][i][j] = Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][j];

                         Ciphertext_result->values[0][i][j] = Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][j];
                         Ciphertext_result->values[1][i][j] = Ciphertext1.values[0][i][j] * Ciphertext2.values[1][i][j] + Ciphertext1.values[1][i][j] * Ciphertext2.values[0][i][j] ;
                         Ciphertext_result->values[2][i][j] = Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][j];
        
        
                       
                        Ciphertext_result->values[0][i][j] = Ciphertext_result->values[0][i][j] % Ciphertext_result->coefficient_modulus[i];   
                        Ciphertext_result->values[1][i][j] = Ciphertext_result->values[1][i][j] % Ciphertext_result->coefficient_modulus[i];                           
                        Ciphertext_result->values[2][i][j] = Ciphertext_result->values[2][i][j] % Ciphertext_result->coefficient_modulus[i];   
                      
                        
                }     
        }
	return 0;
}




int CWM_true_barrett(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2,struct ciphertext *Ciphertext_result)
{
	const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
	const uint8_t rns_number = Ciphertext_result->rns_number; 
        
	if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;	  	
	if( (Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
	(Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
        for(uint8_t i=0;i<rns_number;i++)
        {           
                for (uint32_t j=0;j<stop_value;j++)
                {
                //        Ciphertext_result->values[0][i][j] = Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][j];
                //        Ciphertext_result->values[1][i][j] = Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][j];

                         Ciphertext_result->values[0][i][j] = Ciphertext1.values[0][i][j] * Ciphertext2.values[0][i][j];
                         Ciphertext_result->values[1][i][j] = Ciphertext1.values[0][i][j] * Ciphertext2.values[1][i][j] + Ciphertext1.values[1][i][j] * Ciphertext2.values[0][i][j] ;
                         Ciphertext_result->values[2][i][j] = Ciphertext1.values[1][i][j] * Ciphertext2.values[1][i][j];
        
        
                        uint64_t auxq = (( Ciphertext_result->values[0][i][j] * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                        Ciphertext_result->values[0][i][j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if (Ciphertext_result->coefficient_modulus[i] <= Ciphertext_result->values[0][i][j]) 
                                Ciphertext_result->values[0][i][j] -= Ciphertext_result->coefficient_modulus[i]; 

                        auxq = (( Ciphertext_result->values[1][i][j] * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                        Ciphertext_result->values[1][i][j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if (Ciphertext_result->coefficient_modulus[i] <= Ciphertext_result->values[1][i][j]) 
                                Ciphertext_result->values[1][i][j] -= Ciphertext_result->coefficient_modulus[i]; 
                                
                                
                        auxq = (( Ciphertext_result->values[2][i][j] * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                        Ciphertext_result->values[2][i][j] -= auxq * Ciphertext_result->coefficient_modulus[i];
                        if (Ciphertext_result->coefficient_modulus[i] <= Ciphertext_result->values[2][i][j]) 
                                Ciphertext_result->values[2][i][j] -= Ciphertext_result->coefficient_modulus[i];                                 
                        
                }     
        }
	return 0;
}




#if RISCV_VECTORIAL

int CWM_true_vectorial(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2,struct ciphertext *Ciphertext_result)
{
	const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
	const uint8_t rns_number = Ciphertext_result->rns_number; 
        
	if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;	  	
	if( (Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
	(Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);
                           
                for (uint32_t j = 0; j < stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                        
                        __epi_1xi64 v_ciphertext1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext1_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[1][i][j], gvl);
                        
                        __epi_1xi64 v_ciphertext2_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext2_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][j], gvl);

                        
                        __epi_1xi64 v_result_0 = __builtin_epi_vmul_1xi64(v_ciphertext1_0, v_ciphertext2_0, gvl);
                        
                        __epi_1xi64 v_result_1 = __builtin_epi_vmul_1xi64(v_ciphertext1_0, v_ciphertext2_1, gvl);
                        v_result_1 = __builtin_epi_vmacc_1xi64(v_result_1, v_ciphertext1_1, v_ciphertext2_0, gvl);
                        
                        __epi_1xi64 v_result_2 = __builtin_epi_vmul_1xi64(v_ciphertext1_1, v_ciphertext2_1, gvl);
                        
                        
                        // Reduction v_result_0
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_result_0 = __builtin_epi_vsub_1xi64_mask(v_result_0, v_result_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0, gvl);
                        }
                        
                        // Reduction v_result_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_result_1 = __builtin_epi_vsub_1xi64_mask(v_result_1, v_result_1,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1, gvl);
                        }
                        
                        // Reduction v_result_2
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_2, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_result_2 = __builtin_epi_vsub_1xi64_mask(v_result_2, v_result_2,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_2, gvl);
                        }
               

                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_result_0, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_result_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[2][i][j], v_result_2, gvl);     
                
                
                }
        }
	return 0;
}


int CWM_true_vectorial_barrett(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2,struct ciphertext *Ciphertext_result)
{
	const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
	const uint8_t rns_number = Ciphertext_result->rns_number; 
        
	if(Ciphertext1.polynomial_degree_modulus <= 0)
                return 2;	  	
	if( (Ciphertext1.polynomial_degree_modulus != Ciphertext2.polynomial_degree_modulus) || 
	(Ciphertext1.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);                  
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);          
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl);
                    
                for (uint32_t j = 0; j < stop_value; j += gvl) 
                {
                        gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
                        
                        __epi_1xi64 v_ciphertext1_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext1_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext1.values[1][i][j], gvl);
                        
                        __epi_1xi64 v_ciphertext2_0 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[0][i][j], gvl);
                        __epi_1xi64 v_ciphertext2_1 = __builtin_epi_vload_unsigned_1xi64(&Ciphertext2.values[1][i][j], gvl);

                        
                        __epi_1xi64 v_result_0 = __builtin_epi_vmul_1xi64(v_ciphertext1_0, v_ciphertext2_0, gvl);
                        
                        __epi_1xi64 v_result_1 = __builtin_epi_vmul_1xi64(v_ciphertext1_0, v_ciphertext2_1, gvl);
                        v_result_1 = __builtin_epi_vmacc_1xi64(v_result_1, v_ciphertext1_1, v_ciphertext2_0, gvl);
                        
                        __epi_1xi64 v_result_2 = __builtin_epi_vmul_1xi64(v_ciphertext1_1, v_ciphertext2_1, gvl);

                        // Reduction v_result_0
                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_result_0, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_result_0 = __builtin_epi_vsub_1xi64(v_result_0, v_aux1, gvl);
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod, v_result_0, gvl);
                        v_result_0 = __builtin_epi_vsub_1xi64_mask(v_result_0, v_result_0, v_coef_mod, mask, gvl);


                        // Reduction v_result_1
                        v_q = __builtin_epi_vmul_1xi64(v_result_1, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_result_1 = __builtin_epi_vsub_1xi64(v_result_1, v_aux1, gvl);
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod, v_result_1, gvl);
                        v_result_1 = __builtin_epi_vsub_1xi64_mask(v_result_1, v_result_1, v_coef_mod, mask, gvl);

 
                        // Reduction v_result_2
                        v_q = __builtin_epi_vmul_1xi64(v_result_2, v_m, gvl);
                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                        v_result_2 = __builtin_epi_vsub_1xi64(v_result_2, v_aux1, gvl);
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod, v_result_2, gvl);
                        v_result_2 = __builtin_epi_vsub_1xi64_mask(v_result_2, v_result_2, v_coef_mod, mask, gvl); 
 

                        //store results
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_result_0, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_result_1, gvl);
                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[2][i][j], v_result_2, gvl);     
                
                
                }
        }
	return 0;
}





#endif
