#include "RELINEARIZATION.h"


int relinearize_naive(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys,struct ciphertext *Ciphertext_result)
{
	int i=0, j=0;
    const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
	const uint32_t coefficient_modulus = Ciphertext_result->coefficient_modulus;
    
	int64_t auxiliary_array[2][2 * stop_value];	
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	  
	if( (Ciphertext.polynomial_degree_modulus != relinearization_keys.polynomial_degree_modulus) || 
	(Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus))
		return 1;
		
		
		
	for (i=0;i<2*stop_value;i++)
	{
		auxiliary_array[0][i]=0;
		auxiliary_array[1][i]=0;
	}
	for(i=0;i<stop_value;i++)
	{
		Ciphertext_result->values[0][i] = Ciphertext.values[0][i];
		Ciphertext_result->values[1][i] = Ciphertext.values[1][i];
		for(j=0;j<stop_value;j++)
		{
					
			// Relin1 * CT3
			auxiliary_array[0][i+j]	+= relinearization_keys.values[0][j] * Ciphertext.values[2][i];
			
			// Relin2 * CT3
			auxiliary_array[1][i+j]	+= relinearization_keys.values[1][j] * Ciphertext.values[2][i];
		}		
	}	
	//reduction
	for (i=0;i<stop_value;i++)
	{
		Ciphertext_result->values[0][i] += auxiliary_array[0][i] - auxiliary_array[0][stop_value+i];
		Ciphertext_result->values[1][i] += auxiliary_array[1][i] - auxiliary_array[1][stop_value+i];
			
		if(Ciphertext_result->values[0][i] > 0)
		{
			while(Ciphertext_result->values[0][i] >= coefficient_modulus)
				Ciphertext_result->values[0][i] -= coefficient_modulus;
		}
		else if (Ciphertext_result->values[0][i] < 0)
		{
			while(Ciphertext_result->values[0][i] < 0)
			Ciphertext_result->values[0][i] += coefficient_modulus;			
			
		}
		
		if(Ciphertext_result->values[1][i] > 0)
		{
			while(Ciphertext_result->values[1][i] >= coefficient_modulus)
				Ciphertext_result->values[1][i] -= coefficient_modulus;
		}
		else if (Ciphertext_result->values[1][i] < 0)
		{
			while(Ciphertext_result->values[1][i] < 0)
			Ciphertext_result->values[1][i] += coefficient_modulus;			
			
		}
					
	}			
	return 0;
}

int relinearize_naive_auto(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys,struct ciphertext *Ciphertext_result)
{
	int i=0, j=0;
    const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
	const uint32_t coefficient_modulus = Ciphertext_result->coefficient_modulus;    
	int64_t auxiliary_array[2][2 * stop_value];
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	
	if( (Ciphertext.polynomial_degree_modulus != relinearization_keys.polynomial_degree_modulus) || 
	(Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus))
		return 1;
		
	#pragma clang loop vectorize(enable)
	for (i=0;i<2*stop_value;i++)
	{
		auxiliary_array[0][i]=0;
		auxiliary_array[1][i]=0;
	}
	
	#pragma clang loop vectorize(enable)
	for(i=0;i<stop_value;i++)
	{
		Ciphertext_result->values[0][i] = Ciphertext.values[0][i];
		Ciphertext_result->values[1][i] = Ciphertext.values[1][i];
		for(j=0;j<stop_value;j++)
		{
					
			// Relin1 * CT3
			auxiliary_array[0][i+j]	+= relinearization_keys.values[0][j] * Ciphertext.values[2][i];
			
			// Relin2 * CT3
			auxiliary_array[1][i+j]	+= relinearization_keys.values[1][j] * Ciphertext.values[2][i];
		}
		
	}
	
	//reduction
	#pragma clang loop vectorize(enable)
	for (i=0;i<stop_value;i++)
	{
		Ciphertext_result->values[0][i] += auxiliary_array[0][i] - auxiliary_array[0][stop_value+i];
		Ciphertext_result->values[1][i] += auxiliary_array[1][i] - auxiliary_array[1][stop_value+i];
			
		if(Ciphertext_result->values[0][i] > 0)
		{
			while(Ciphertext_result->values[0][i] >= coefficient_modulus)
				Ciphertext_result->values[0][i] -= coefficient_modulus;
		}
		else if (Ciphertext_result->values[0][i] < 0)
		{
			while(Ciphertext_result->values[0][i] < 0)
			Ciphertext_result->values[0][i] += coefficient_modulus;			
			
		}
		
		if(Ciphertext_result->values[1][i] > 0)
		{
			while(Ciphertext_result->values[1][i] >= coefficient_modulus)
				Ciphertext_result->values[1][i] -= coefficient_modulus;
		}
		else if (Ciphertext_result->values[1][i] < 0)
		{
			while(Ciphertext_result->values[1][i] < 0)
			Ciphertext_result->values[1][i] += coefficient_modulus;			
			
		}			
	}	
	
	return 0;
}




int relinearize_barrett(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result)
{
	
	int i=0, j=0;
    const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
	const uint32_t coefficient_modulus = Ciphertext_result->coefficient_modulus;  
	int auxq=0;
	int64_t auxiliary_array[2][2 * stop_value];	
	
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	
	if( (Ciphertext.polynomial_degree_modulus != relinearization_keys.polynomial_degree_modulus) || 
	(Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus))
		return 1;
		
	for (i=0;i<2*stop_value;i++)
	{
		auxiliary_array[0][i]=0;
		auxiliary_array[1][i]=0;
	}
	
	for(i=0;i<stop_value;i++)
	{
		Ciphertext_result->values[0][i] = Ciphertext.values[0][i];
		Ciphertext_result->values[1][i] = Ciphertext.values[1][i];
		for(j=0;j<stop_value;j++)
		{
					
			// Relin1 * CT3
			auxiliary_array[0][i+j]	+= relinearization_keys.values[0][j] * Ciphertext.values[2][i];
			
			// Relin2 * CT3
			auxiliary_array[1][i+j]	+= relinearization_keys.values[1][j] * Ciphertext.values[2][i];
		}		
	}	
	//reduction
	for (i=0;i<stop_value;i++)
	{
		Ciphertext_result->values[0][i] += auxiliary_array[0][i] - auxiliary_array[0][stop_value+i];
		Ciphertext_result->values[1][i] += auxiliary_array[1][i] - auxiliary_array[1][stop_value+i];
			
			
		auxq = (Ciphertext_result->values[0][i] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
		Ciphertext_result->values[0][i] -= auxq * coefficient_modulus;
		if (coefficient_modulus <= Ciphertext_result->values[0][i]) 
		{
			Ciphertext_result->values[0][i] -= coefficient_modulus;
		}
	
		auxq = (Ciphertext_result->values[1][i] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
		Ciphertext_result->values[1][i] -= auxq * coefficient_modulus;
		if (coefficient_modulus <= Ciphertext_result->values[1][i]) 
		{
			Ciphertext_result->values[1][i] -= coefficient_modulus;
		}

	}			
	return 0;		
}


int relinearize_barrett_auto(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result)
{
	
	int i=0, j=0;
    const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
	const uint32_t coefficient_modulus = Ciphertext_result->coefficient_modulus;  
	int auxq=0;
	int64_t auxiliary_array[2][2 * stop_value];	
	
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	
	if( (Ciphertext.polynomial_degree_modulus != relinearization_keys.polynomial_degree_modulus) || 
	(Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus))
		return 1;
	
	#pragma clang loop vectorize(enable)
	for (i=0;i<2*stop_value;i++)
	{
		auxiliary_array[0][i]=0;
		auxiliary_array[1][i]=0;
	}
	
	#pragma clang loop vectorize(enable)
	for(i=0;i<stop_value;i++)
	{
		Ciphertext_result->values[0][i] = Ciphertext.values[0][i];
		Ciphertext_result->values[1][i] = Ciphertext.values[1][i];
		for(j=0;j<stop_value;j++)
		{
					
			// Relin1 * CT3
			auxiliary_array[0][i+j]	+= relinearization_keys.values[0][j] * Ciphertext.values[2][i];
			
			// Relin2 * CT3
			auxiliary_array[1][i+j]	+= relinearization_keys.values[1][j] * Ciphertext.values[2][i];
		}		
	}	
	//reduction
	for (i=0;i<stop_value;i++)
	{
		Ciphertext_result->values[0][i] += auxiliary_array[0][i] - auxiliary_array[0][stop_value+i];
		Ciphertext_result->values[1][i] += auxiliary_array[1][i] - auxiliary_array[1][stop_value+i];
			
			
		auxq = (Ciphertext_result->values[0][i] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
		Ciphertext_result->values[0][i] -= auxq * coefficient_modulus;
		if (coefficient_modulus <= Ciphertext_result->values[0][i]) 
		{
			Ciphertext_result->values[0][i] -= coefficient_modulus;
		}
	
		auxq = (Ciphertext_result->values[1][i] * Ciphertext_result->barrett_auxi_value[i]) >> 45;
		Ciphertext_result->values[1][i] -= auxq * coefficient_modulus;
		if (coefficient_modulus <= Ciphertext_result->values[1][i]) 
		{
			Ciphertext_result->values[1][i] -= coefficient_modulus;
		}

	}			
	return 0;		
}



#if RISCV_VECTORIAL


int relinearize_naive_vect(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result)
{
	int i=0,j=0;
	const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
	const uint32_t coefficient_modulus = Ciphertext_result->coefficient_modulus;  
	uint64_t auxiliary_array[2][2 * stop_value];

	long gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
	long max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
	
	__epi_1xi64 mask_comp = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 mask_comp_neg = __builtin_epi_vbroadcast_1xi64(0, gvl);   
	__epi_1xi64 v_coef_add  = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	
 	if((Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
	
	for (i=0;i<2*stop_value;i++)
	{
		auxiliary_array[0][i]=0;
		auxiliary_array[1][i]=0;
	}
	
	for (i=0;i<stop_value;i++)
	{
		auxiliary_array[0][i]+=Ciphertext.values[0][i];
		auxiliary_array[1][i]+=Ciphertext.values[1][i];
	
	
		__epi_1xi64 v_ciphertext_res_value_2 = __builtin_epi_vbroadcast_1xi64(Ciphertext.values[2][i], max_gvl);  


		for (j = 0; j < stop_value; j += gvl) 
		{
			gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
			
			__epi_1xi64 v_relin_value_0 = __builtin_epi_vload_1xi64(&relinearization_keys.values[0][i], gvl);
			__epi_1xi64 v_relin_value_1 = __builtin_epi_vload_1xi64(&relinearization_keys.values[1][i], gvl);
			
			__epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i+j], gvl);
			__epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i+j], gvl);
			
					
			__epi_1xi64 v_aux_1 = __builtin_epi_vmul_1xi64(v_ciphertext_res_value_2,v_relin_value_0,gvl);
			__epi_1xi64 v_result_0 = __builtin_epi_vadd_1xi64(v_aux_array_0,v_aux_1, gvl);
			//__epi_1xi64 v_result_0 = __builtin_epi_vfmacc_1xf64(v_aux_array_0, v_ciphertext_res_value_2, v_relin_value_0, gvl);			
			
			__epi_1xi64 v_aux_2 = __builtin_epi_vmul_1xi64(v_ciphertext_res_value_2,v_relin_value_1,gvl);
			__epi_1xi64 v_result_1 = __builtin_epi_vadd_1xi64(v_aux_array_1,v_aux_2, gvl);			
			//__epi_1xi64 v_result_1 = __builtin_epi_vfmacc_1xf64(v_aux_array_1, v_ciphertext_res_value_2, v_relin_value_1, gvl);		
		
			//store results
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i+j],v_result_0 , gvl);
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i+j],v_result_1 , gvl);
		}
		
	}
	
	
	for (i = 0; i < stop_value; i += gvl) 
	{  	
		gvl = __builtin_epi_vsetvl(stop_value- i, __epi_e64, __epi_m1);
	
		// Load aux_result1
		__epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i], gvl);
		__epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+i], gvl);
		// Load aux_result2
		__epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i], gvl);
		__epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+i], gvl);
		
		// Add both auxiliary to result
		__epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
		__epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
			
		// Reduction ciphertext_ans_1
		__epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_1, gvl);			
		while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
		{			
			v_res_1 = __builtin_epi_vsub_1xi64_mask(v_res_1, v_res_1,v_coef_add, mask, gvl);
			mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_1, gvl);
		}

		// Reduction ciphertext_ans_2
		mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_2, gvl);	
		while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
		{			
			v_res_2 = __builtin_epi_vsub_1xi64_mask(v_res_2, v_res_2,v_coef_add, mask, gvl);
			mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_2, gvl);
		}
				
		//store results
			__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i], v_res_1, gvl);
			__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i], v_res_2, gvl);	
	}
	return 0;
}

int relinearize_naive_vect_2(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result)
{
 	int i=0,j=0;   
    const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
	const uint32_t coefficient_modulus = Ciphertext_result->coefficient_modulus;  
	uint64_t auxiliary_array[2][2 * stop_value];

	long gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
	long max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
	
	__epi_1xi64 mask_comp = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 mask_comp_neg = __builtin_epi_vbroadcast_1xi64(0, gvl);   
	__epi_1xi64 v_coef_add  = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl); 
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	
 	if((Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
	
	for (i = 0; i<2*stop_value; i += gvl) 
	{
		gvl = __builtin_epi_vsetvl(2*stop_value - i, __epi_e64, __epi_m1);
						
		//store results
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i],v_initialize , gvl);
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i],v_initialize , gvl);
				
	}
	
	for (i=0;i<stop_value;i++)
	{
		auxiliary_array[0][i]+=Ciphertext.values[0][i];
		auxiliary_array[1][i]+=Ciphertext.values[1][i];
	
	
		__epi_1xi64 v_ciphertext_res_value_2 = __builtin_epi_vbroadcast_1xi64(Ciphertext.values[2][i], max_gvl);  


		for (j = 0; j < stop_value; j += gvl) 
		{
			gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
			
			__epi_1xi64 v_relin_value_0 = __builtin_epi_vload_1xi64(&relinearization_keys.values[0][j], gvl);
			__epi_1xi64 v_relin_value_1 = __builtin_epi_vload_1xi64(&relinearization_keys.values[1][j], gvl);
			
			__epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i+j], gvl);
			__epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i+j], gvl);
			
					
			__epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext_res_value_2, v_relin_value_0, gvl);			
				
			__epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext_res_value_2, v_relin_value_1, gvl);		
		
			//store results
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i+j],v_result_0 , gvl);
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i+j],v_result_1 , gvl);
		}
		
	}
	
	
	for (i = 0; i < stop_value; i += gvl) 
	{  	
		gvl = __builtin_epi_vsetvl(stop_value - i, __epi_e64, __epi_m1);
	
		// Load aux_result1
		__epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i], gvl);
		__epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+i], gvl);
		// Load aux_result2
		__epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i], gvl);
		__epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+i], gvl);
		
		// Add both auxiliary to result
		__epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
		__epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
			
		// Reduction ciphertext_ans_1
		__epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_1, gvl);			
		while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
		{			
			v_res_1 = __builtin_epi_vsub_1xi64_mask(v_res_1, v_res_1,v_coef_add, mask, gvl);
			mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_1, gvl);
		}

		// Reduction ciphertext_ans_2
		mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_2, gvl);	
		while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
		{			
			v_res_2 = __builtin_epi_vsub_1xi64_mask(v_res_2, v_res_2,v_coef_add, mask, gvl);
			mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_2, gvl);
		}
				
		//store results
			__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i], v_res_1, gvl);
			__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i], v_res_2, gvl);	
	}
	return 0;
}

int relinearize_naive_vect_unroll(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result)
{
	
 	int i=0,j=0;   
    const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
	const uint32_t coefficient_modulus = Ciphertext_result->coefficient_modulus;  
	uint64_t auxiliary_array[2][2 * stop_value];

	long gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
	int aux1=0;
	int start_remain = 0;
	const int unroll = 2;
	const long max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
	const int loops = stop_value/(max_gvl*2);
	
	
	__epi_1xi64 mask_comp = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 mask_comp_neg = __builtin_epi_vbroadcast_1xi64(0, gvl);   
	__epi_1xi64 v_coef_add  = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl); 
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	
 	if((Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
	
	
	for (i = 0; i < 2*loops; i++) 
	{
		aux1 = i*unroll;
		//store results
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+0)*max_gvl],v_initialize, max_gvl);
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+1)*max_gvl],v_initialize, max_gvl);
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+0)*max_gvl],v_initialize, max_gvl);
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+1)*max_gvl],v_initialize, max_gvl);
	}
	gvl = 0; 

	start_remain = (i*unroll)*max_gvl;
	
	for (i = start_remain; i <2*stop_value; i += gvl) 
	{
		gvl = __builtin_epi_vsetvl(2*stop_value - i, __epi_e64, __epi_m1);
						
		//store results
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i],v_initialize , gvl);
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i],v_initialize , gvl);
				
	}
	
	for (i=0;i<stop_value;i++)
	{
		auxiliary_array[0][i]+=Ciphertext.values[0][i];
		auxiliary_array[1][i]+=Ciphertext.values[1][i];
	
	
		__epi_1xi64 v_ciphertext_res_value_2 = __builtin_epi_vbroadcast_1xi64(Ciphertext.values[2][i], max_gvl);  


		for (j = 0; j < loops; j++) 
		{
			aux1 = j*unroll;
			
			__epi_1xi64 v_relin_value_0_0 = __builtin_epi_vload_1xi64(&relinearization_keys.values[0][(aux1+0)*max_gvl], max_gvl);
			__epi_1xi64 v_relin_value_0_1 = __builtin_epi_vload_1xi64(&relinearization_keys.values[0][(aux1+1)*max_gvl], max_gvl);
			
			__epi_1xi64 v_relin_value_1_0 = __builtin_epi_vload_1xi64(&relinearization_keys.values[1][(aux1+0)*max_gvl], max_gvl);
			__epi_1xi64 v_relin_value_1_1 = __builtin_epi_vload_1xi64(&relinearization_keys.values[1][(aux1+1)*max_gvl], max_gvl);
			
			__epi_1xi64 v_aux_array_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i+(aux1+0)*max_gvl], max_gvl);
			__epi_1xi64 v_aux_array_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i+(aux1+1)*max_gvl], max_gvl);
			
			__epi_1xi64 v_aux_array_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i+(aux1+0)*max_gvl], max_gvl);
			__epi_1xi64 v_aux_array_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i+(aux1+1)*max_gvl], max_gvl);
					

			__epi_1xi64 v_result_0_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0_0, v_ciphertext_res_value_2, v_relin_value_0_0, max_gvl);
			__epi_1xi64 v_result_0_1 = __builtin_epi_vmacc_1xi64(v_aux_array_0_1, v_ciphertext_res_value_2, v_relin_value_0_1, max_gvl);			
					
			__epi_1xi64 v_result_1_0 = __builtin_epi_vmacc_1xi64(v_aux_array_1_0, v_ciphertext_res_value_2, v_relin_value_1_0, max_gvl);
			__epi_1xi64 v_result_1_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1_1, v_ciphertext_res_value_2, v_relin_value_1_1, max_gvl);	
		
		
		
			//store results
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i+(aux1+0)*max_gvl],v_result_0_0 , max_gvl);
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i+(aux1+1)*max_gvl],v_result_0_1 , max_gvl);		
			
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i+(aux1+0)*max_gvl],v_result_1_0 , max_gvl);
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i+(aux1+1)*max_gvl],v_result_1_1 , max_gvl);
		}
		gvl = 0; 

		start_remain = (j*unroll)*max_gvl;
		
		for (j = start_remain; j <stop_value; j += gvl) 
		{
			gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
			
			__epi_1xi64 v_relin_value_0 = __builtin_epi_vload_1xi64(&relinearization_keys.values[0][j], gvl);
			__epi_1xi64 v_relin_value_1 = __builtin_epi_vload_1xi64(&relinearization_keys.values[1][j], gvl);
			
			__epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i+j], gvl);
			__epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i+j], gvl);
			
					
			__epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext_res_value_2, v_relin_value_0, gvl);			
				
			__epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext_res_value_2, v_relin_value_1, gvl);		
		
			//store results
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i+j],v_result_0 , gvl);
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i+j],v_result_1 , gvl);
		
		}	
	}
	
	
	for (i = 0; i < stop_value; i += gvl) 
	{  	
		gvl = __builtin_epi_vsetvl(stop_value - i, __epi_e64, __epi_m1);
	
		// Load aux_result1
		__epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i], gvl);
		__epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+i], gvl);
		// Load aux_result2
		__epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i], gvl);
		__epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+i], gvl);
		
		// Add both auxiliary to result
		__epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
		__epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
			
		// Reduction ciphertext_ans_1
		__epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_1, gvl);			
		while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
		{			
			v_res_1 = __builtin_epi_vsub_1xi64_mask(v_res_1, v_res_1,v_coef_add, mask, gvl);
			mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_1, gvl);
		}

		// Reduction ciphertext_ans_2
		mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_2, gvl);	
		while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
		{			
			v_res_2 = __builtin_epi_vsub_1xi64_mask(v_res_2, v_res_2,v_coef_add, mask, gvl);
			mask = __builtin_epi_vmsleu_1xi64(mask_comp,v_res_2, gvl);
		}
				
		//store results
			__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i], v_res_1, gvl);
			__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i], v_res_2, gvl);	
	}
	return 0;
}


int relinearize_barrett_vect(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result)
{
	
	int i=0,j=0;
    const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
	const uint32_t coefficient_modulus = Ciphertext_result->coefficient_modulus;  	
	uint64_t auxiliary_array[2][2 * stop_value];

	long gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
	long max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
	
	__epi_1xi64 mask_comp = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 mask_comp_neg = __builtin_epi_vbroadcast_1xi64(0, gvl);   
	__epi_1xi64 v_coef_add  = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl); 
	
	__epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);
	__epi_1xi64 v_n = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 v_q;
	__epi_1xi64 v_aux1;  
	__epi_1xi64 vres_processed;	
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	
 	if((Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
	
	for (i = 0; i<2*stop_value; i += gvl) 
	{
		gvl = __builtin_epi_vsetvl(2*stop_value - i, __epi_e64, __epi_m1);
						
		//store results
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i],v_initialize , gvl);
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i],v_initialize , gvl);
				
	}
	
	for (i=0;i<stop_value;i++)
	{
		auxiliary_array[0][i]+=Ciphertext.values[0][i];
		auxiliary_array[1][i]+=Ciphertext.values[1][i];
	
	
		__epi_1xi64 v_ciphertext_res_value_2 = __builtin_epi_vbroadcast_1xi64(Ciphertext.values[2][i], max_gvl);  


		for (j = 0; j < stop_value; j += gvl) 
		{
			gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
			
			__epi_1xi64 v_relin_value_0 = __builtin_epi_vload_1xi64(&relinearization_keys.values[0][j], gvl);
			__epi_1xi64 v_relin_value_1 = __builtin_epi_vload_1xi64(&relinearization_keys.values[1][j], gvl);
			
			__epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i+j], gvl);
			__epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i+j], gvl);
			
					
			__epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext_res_value_2, v_relin_value_0, gvl);			
				
			__epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext_res_value_2, v_relin_value_1, gvl);		
		
			//store results
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i+j],v_result_0 , gvl);
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i+j],v_result_1 , gvl);
		}
		
	}
	
	
	for (i = 0; i < stop_value; i += gvl) 
	{  	
		gvl = __builtin_epi_vsetvl(stop_value - i, __epi_e64, __epi_m1);
	
		// Load aux_result1
		__epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i], gvl);
		__epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+i], gvl);
		// Load aux_result2
		__epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i], gvl);
		__epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+i], gvl);
		
		// Add both auxiliary to result
		__epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
		__epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
			
		// Reduction ciphertext_ans_1
		v_q = __builtin_epi_vmulhu_1xi64(v_res_1, v_m, gvl);
		v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_n, gvl);
		vres_processed = __builtin_epi_vsub_1xi64(v_res_1, v_aux1, gvl);

		__epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_n, vres_processed, gvl);
		v_res_1 = __builtin_epi_vsub_1xi64_mask(vres_processed, vres_processed, v_n, mask, gvl);
	
		// Reduction ciphertext_ans_2
		v_q = __builtin_epi_vmulhu_1xi64(v_res_2, v_m, gvl);
		v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_n, gvl);
		vres_processed = __builtin_epi_vsub_1xi64(v_res_2, v_aux1, gvl);

		mask = __builtin_epi_vmsle_1xi64(v_n, vres_processed, gvl);
		v_res_2 = __builtin_epi_vsub_1xi64_mask(vres_processed, vres_processed, v_n, mask, gvl);		

				
		//store results
			__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i], v_res_1, gvl);
			__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i], v_res_2, gvl);	
	}
	return 0;
	
}


int relinearize_barrett_vect_unroll(struct ciphertext Ciphertext ,struct relinearization_keys relinearization_keys, struct ciphertext *Ciphertext_result)
{
	int i=0,j=0;
    const uint32_t stop_value = Ciphertext.polynomial_degree_modulus;
	const uint32_t coefficient_modulus = Ciphertext_result->coefficient_modulus;  
	uint64_t auxiliary_array[2][2 * stop_value];
	long gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);	
	int start_remain = 0;
	const int unroll = 2;
	int aux1=0;
	const long max_gvl = __builtin_epi_vsetvlmax(__epi_e64, __epi_m1);
	const int loops = stop_value/(max_gvl*2);
	__epi_1xi64 mask_comp = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 mask_comp_neg = __builtin_epi_vbroadcast_1xi64(0, gvl);   
	__epi_1xi64 v_coef_add  = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl); 
		__epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);
	__epi_1xi64 v_n = __builtin_epi_vbroadcast_1xi64(coefficient_modulus, gvl);
	__epi_1xi64 v_q;
	__epi_1xi64 v_aux1;  
	__epi_1xi64 vres_processed;	
	if(Ciphertext.polynomial_degree_modulus <= 0)
        return 2;	
 	if((Ciphertext.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus) )
		return 1;
	
	for (i = 0; i < 2*loops; i++) 
	{
		aux1 = i*unroll;
		//store results
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+0)*max_gvl],v_initialize, max_gvl);
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][(aux1+1)*max_gvl],v_initialize, max_gvl);
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+0)*max_gvl],v_initialize, max_gvl);
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][(aux1+1)*max_gvl],v_initialize, max_gvl);
	}
	gvl = 0; 

	start_remain = (i*unroll)*max_gvl;
	
	for (i = start_remain; i <2*stop_value; i += gvl) 
	{
		gvl = __builtin_epi_vsetvl(2*stop_value - i, __epi_e64, __epi_m1);
						
		//store results
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i],v_initialize , gvl);
		__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i],v_initialize , gvl);
				
	}
	
	for (i=0;i<stop_value;i++)
	{
		auxiliary_array[0][i]+=Ciphertext.values[0][i];
		auxiliary_array[1][i]+=Ciphertext.values[1][i];
	
	
		__epi_1xi64 v_ciphertext_res_value_2 = __builtin_epi_vbroadcast_1xi64(Ciphertext.values[2][i], max_gvl);  


		for (j = 0; j < loops; j++) 
		{
			aux1 = j*unroll;
			
			__epi_1xi64 v_relin_value_0_0 = __builtin_epi_vload_1xi64(&relinearization_keys.values[0][(aux1+0)*max_gvl], max_gvl);
			__epi_1xi64 v_relin_value_0_1 = __builtin_epi_vload_1xi64(&relinearization_keys.values[0][(aux1+1)*max_gvl], max_gvl);
			
			__epi_1xi64 v_relin_value_1_0 = __builtin_epi_vload_1xi64(&relinearization_keys.values[1][(aux1+0)*max_gvl], max_gvl);
			__epi_1xi64 v_relin_value_1_1 = __builtin_epi_vload_1xi64(&relinearization_keys.values[1][(aux1+1)*max_gvl], max_gvl);
			
			__epi_1xi64 v_aux_array_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i+(aux1+0)*max_gvl], max_gvl);
			__epi_1xi64 v_aux_array_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i+(aux1+1)*max_gvl], max_gvl);
			
			__epi_1xi64 v_aux_array_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i+(aux1+0)*max_gvl], max_gvl);
			__epi_1xi64 v_aux_array_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i+(aux1+1)*max_gvl], max_gvl);
					

			__epi_1xi64 v_result_0_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0_0, v_ciphertext_res_value_2, v_relin_value_0_0, max_gvl);
			__epi_1xi64 v_result_0_1 = __builtin_epi_vmacc_1xi64(v_aux_array_0_1, v_ciphertext_res_value_2, v_relin_value_0_1, max_gvl);			
					
			__epi_1xi64 v_result_1_0 = __builtin_epi_vmacc_1xi64(v_aux_array_1_0, v_ciphertext_res_value_2, v_relin_value_1_0, max_gvl);
			__epi_1xi64 v_result_1_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1_1, v_ciphertext_res_value_2, v_relin_value_1_1, max_gvl);	
		
		
		
			//store results
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i+(aux1+0)*max_gvl],v_result_0_0 , max_gvl);
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i+(aux1+1)*max_gvl],v_result_0_1 , max_gvl);		
			
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i+(aux1+0)*max_gvl],v_result_1_0 , max_gvl);
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i+(aux1+1)*max_gvl],v_result_1_1 , max_gvl);
		}
		gvl = 0; 

		start_remain = (j*unroll)*max_gvl;
		
		for (j = start_remain; j <stop_value; j += gvl) 
		{
			gvl = __builtin_epi_vsetvl(stop_value - j, __epi_e64, __epi_m1);
			
			__epi_1xi64 v_relin_value_0 = __builtin_epi_vload_1xi64(&relinearization_keys.values[0][j], gvl);
			__epi_1xi64 v_relin_value_1 = __builtin_epi_vload_1xi64(&relinearization_keys.values[1][j], gvl);
			
			__epi_1xi64 v_aux_array_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i+j], gvl);
			__epi_1xi64 v_aux_array_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i+j], gvl);
			
					
			__epi_1xi64 v_result_0 = __builtin_epi_vmacc_1xi64(v_aux_array_0, v_ciphertext_res_value_2, v_relin_value_0, gvl);			
				
			__epi_1xi64 v_result_1 = __builtin_epi_vmacc_1xi64(v_aux_array_1, v_ciphertext_res_value_2, v_relin_value_1, gvl);		
		
			//store results
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[0][i+j],v_result_0 , gvl);
			__builtin_epi_vstore_unsigned_1xi64(&auxiliary_array[1][i+j],v_result_1 , gvl);
		
		}	
	}
	
	
	for (i = 0; i < stop_value; i += gvl) 
	{  	
		gvl = __builtin_epi_vsetvl(stop_value - i, __epi_e64, __epi_m1);
	
		// Load aux_result1
		__epi_1xi64 v_aux_result_0_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][i], gvl);
		__epi_1xi64 v_aux_result_0_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[0][stop_value+i], gvl);
		// Load aux_result2
		__epi_1xi64 v_aux_result_1_0 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][i], gvl);
		__epi_1xi64 v_aux_result_1_1 = __builtin_epi_vload_unsigned_1xi64(&auxiliary_array[1][stop_value+i], gvl);
		
		// Add both auxiliary to result
		__epi_1xi64 v_res_1 = __builtin_epi_vsub_1xi64(v_aux_result_0_0, v_aux_result_0_1, gvl);
		__epi_1xi64 v_res_2 = __builtin_epi_vsub_1xi64(v_aux_result_1_0, v_aux_result_1_1, gvl);
			

		// Reduction ciphertext_ans_1
		v_q = __builtin_epi_vmulhu_1xi64(v_res_1, v_m, gvl);
		v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_n, gvl);
		vres_processed = __builtin_epi_vsub_1xi64(v_res_1, v_aux1, gvl);

		__epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_n, vres_processed, gvl);
		v_res_1 = __builtin_epi_vsub_1xi64_mask(vres_processed, vres_processed, v_n, mask, gvl);
	
		// Reduction ciphertext_ans_2
		v_q = __builtin_epi_vmulhu_1xi64(v_res_2, v_m, gvl);
		v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_n, gvl);
		vres_processed = __builtin_epi_vsub_1xi64(v_res_2, v_aux1, gvl);

		mask = __builtin_epi_vmsle_1xi64(v_n, vres_processed, gvl);
		v_res_2 = __builtin_epi_vsub_1xi64_mask(vres_processed, vres_processed, v_n, mask, gvl);	


				
		//store results
			__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i], v_res_1, gvl);
			__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i], v_res_2, gvl);	
	}
	return 0;
		
}


#endif






