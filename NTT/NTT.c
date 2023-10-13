#include "NTT.h"
#include "../initialization.h"


// TABLE OF P Values

int long pow_mod( uint32_t x,  int32_t y,  int z)
{
    uint64_t number = 1;
    if(y<0)
    {
        y = -y;
        for(int i=0;i<z;i++)
        {
            if( (x*i) % z == 1)
            {
                if(y==1)
                {
                    return i;
                }
                else
                {
                    x=i; 
                    break;
                }
            }
            else if(i==(z-1))   // inverse not found
                return -1;
        }   
    }   

    if(z==-1)
    {
        while (y)
        {
        
            if (y & 1)
                number = number * x;
            y >>= 1;
            x = (uint64_t)x * x;
        }     
    }
    else
    {
        while (y)
        {
            if (y & 1)
                number = number * x % z;
            y >>= 1;
            x = (uint64_t)x * x % z;
        }
    }
    return number;
}


uint8_t reverseBits(uint32_t num)
{
        uint32_t NO_OF_BITS = 2;//sizeof(num);
        uint32_t reverse_num = 0;
        uint32_t i;
        for (i = 0; i < NO_OF_BITS; i++) 
        {
                if ((num & (1 << i)))
                        reverse_num |= 1 << ((NO_OF_BITS - 1) - i);
        }
        return reverse_num;
}


int copy_and_fill_with_zeros(struct ciphertext Ciphertext_to_transform, struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;
        
        for(uint8_t i=0;i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[i][0][j];         
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[i][1][j];                       
                        Ciphertext_result->values[0][i][stop_value+j] = 0;
                        Ciphertext_result->values[1][i][stop_value+j] = 0;
                }
        }
        return 0; 
}


int calculate_psi(uint32_t modulus,  uint64_t root, uint32_t Polynomial_Degree_Modulus)
{
        for(uint32_t i=0;i<modulus;i++)
        {
                if( pow_mod(i,2,modulus) == root && (pow_mod(i,Polynomial_Degree_Modulus,modulus)==(modulus-1)) )
                        return i;
                
        }
        return -1;
}


int is_prime(uint64_t n)
{    
    if((n % 2) == 0)
        return 0;
    for(int i=3;i*i<=n;i+=2)
    {
        if((n % i) == 0)
        {
            return 0;
        }
    }
    return 1;
}


int find_mod(uint32_t polynomial_degree_modulus,uint32_t minmod)
{
    int start = (minmod - 1 + ( polynomial_degree_modulus) - 1) /polynomial_degree_modulus; //floor
    int aux=1;
    int n;
    if (start>1)
        aux = start;
    do{
        n =  aux * polynomial_degree_modulus + 1;
        if (is_prime(n))
        {
            return n;  
        }         
        aux++;
    }while(1);

    
}


// could be sqrt(n)
int is_primitive_root(int test, uint32_t modulus)
{
    int n = modulus-1;
    for(int i=2;i*i<=n;i++)
    {
        if ((n % i) == 0)
        {    
            n = n / i;
			if(pow_mod(test, (modulus-1) / i, modulus) == 1)
                return 0;
            
			while ((n % i) == 0)
				n = n / i;
        }
    }
    if(n>1)
        if(pow_mod(test, (modulus-1) / n, modulus) == 1)
            return 0; 
    
    return (pow_mod(test, (modulus-1), modulus) == 1);
}


int find_generator(uint32_t modulus)
{
    for(int i=1;i<modulus;i++)
    {
        if (is_primitive_root(i, modulus))
            return i;
        
    }
    return 0;
}


int find_primitive_root(uint32_t polynomial_degree_modulus,uint32_t modulus)
{
    return pow_mod(find_generator(modulus), (modulus-1) / (polynomial_degree_modulus), modulus);
}


int create_root_table(uint32_t ***table , uint32_t modulus,  uint64_t root, uint32_t Polynomial_Degree_Modulus)
{
        
        (*table) = (uint32_t **) malloc(Polynomial_Degree_Modulus*sizeof(uint32_t*));
        
        for(uint32_t i=0; i<Polynomial_Degree_Modulus;i++)
        {
                (*table)[i] = (uint32_t *) malloc(Polynomial_Degree_Modulus*sizeof(uint32_t));
                for(uint32_t j=0; j<Polynomial_Degree_Modulus;j++)
                {
                        (*table)[i][j] = pow_mod(root,i*j,modulus);                  
                }
        }
      
        
        return 0;
}


/*
int create_special_psi_table(uint32_t ***table , uint32_t modulus,  uint64_t psi, uint32_t Polynomial_Degree_Modulus)
{
        
        (*table) = (uint32_t **) malloc(Polynomial_Degree_Modulus*sizeof(uint32_t*));
        
        for(uint32_t i=0; i<Polynomial_Degree_Modulus;i++)
        {
                (*table)[i] = (uint32_t *) malloc(Polynomial_Degree_Modulus*sizeof(uint32_t));
                for(uint32_t j=0; j<Polynomial_Degree_Modulus;j++)
                {
                        (*table)[i][j] = pow_mod(root,2*(i*j)+j,modulus);                  
                }
        }
      
        
        return 0;
}
*/



/*2N algoritmn*/
int ntt_transform_naive(struct ciphertext *Ciphertext_to_transform,uint32_t root,uint32_t modulus)
{
        const uint32_t stop_value = Ciphertext_to_transform->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform->rns_number;

        if(Ciphertext_to_transform->polynomial_degree_modulus <= 0)
                return 2;
        
        uint64_t auxiliary[2][stop_value];
        for(uint8_t i=0;i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        auxiliary[0][j] = 0;
                        auxiliary[1][j] = 0;
                        for(uint32_t k=0;k<stop_value;k++)
                        {
                                auxiliary[0][j] += Ciphertext_to_transform->values[0][i][k] * pow_mod(root,j*k,modulus);
                                auxiliary[1][j] += Ciphertext_to_transform->values[1][i][k] * pow_mod(root,j*k,modulus);
                        }
                        if(auxiliary[0][i]>= modulus)
                        {
                                while(auxiliary[0][i] >= modulus)
                                        auxiliary[0][i]-= modulus;     
                        }
                        if(auxiliary[1][i]>= modulus)
                        {
                                while(auxiliary[1][i] >= modulus)
                                        auxiliary[1][i]-= modulus;     
                        }
                        
                }
                for(uint32_t j=0;j<stop_value;j++)
                {
                        Ciphertext_to_transform->values[0][i][j] =  auxiliary[0][j]; 
                        Ciphertext_to_transform->values[1][i][j] =  auxiliary[1][j];   
                }
        }
        return 0;
}

/*2N algoritmn*/
int ntt_transform_naive_2(struct ciphertext Ciphertext_to_transform,uint32_t root,uint32_t modulus,struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;

        if(Ciphertext_to_transform.polynomial_degree_modulus <= 0)
                return 2;
        if(Ciphertext_to_transform.polynomial_degree_modulus != Ciphertext_result->polynomial_degree_modulus)
                return 1;
       
        for(uint8_t i=0;i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = 0;
                        Ciphertext_result->values[1][i][j] = 0;
                        for(uint32_t k=0;k<stop_value;k++)
                        {
                                Ciphertext_result->values[0][i][j] += Ciphertext_to_transform.values[0][i][k] * pow_mod(root,j*k,modulus);
                                Ciphertext_result->values[1][i][j] += Ciphertext_to_transform.values[1][i][k] * pow_mod(root,j*k,modulus);
                        }
                        if(Ciphertext_result->values[0][i][j]>= modulus)
                        {
                                while(Ciphertext_result->values[0][i][j] >= modulus)
                                        Ciphertext_result->values[0][i][j]-= modulus;     
                        }
                        if(Ciphertext_result->values[1][i][j]>= modulus)
                        {
                                while(Ciphertext_result->values[1][i][j] >= modulus)
                                        Ciphertext_result->values[1][i][j]-= modulus;     
                        } 
                }
        }
        return 0;
}

/*2N algoritmn*/
int intt_transform_naive(struct ciphertext *Ciphertext_to_transform,uint32_t root,uint32_t modulus)
{ 
        const uint32_t stop_value = Ciphertext_to_transform->polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform->rns_number;
        const uint32_t scalar = pow_mod(Ciphertext_to_transform->polynomial_degree_modulus,-1, modulus); 
        const uint32_t intt_root = pow_mod(root,-1,modulus);
    
        if(Ciphertext_to_transform->polynomial_degree_modulus <= 0)
                return 2;
        

        uint64_t auxiliary[2][Ciphertext_to_transform->polynomial_degree_modulus];
        for(uint8_t i=0; i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        auxiliary[0][j] = 0;                       
                        auxiliary[1][j] = 0;
                        
                        for(uint32_t k=0;k<stop_value;k++)
                        {
                                auxiliary[0][j] += Ciphertext_to_transform->values[0][i][k] * pow_mod(intt_root,j*k,modulus);
                                auxiliary[1][j] += Ciphertext_to_transform->values[1][i][k] * pow_mod(intt_root,j*k,modulus);
                        }
                        
                        if(auxiliary[0][j]>= modulus)
                        {
                                while(auxiliary[0][j] >= modulus)
                                        auxiliary[0][j]-= modulus;     
                        }
                        if(auxiliary[1][j]>= modulus)
                        {
                                while(auxiliary[1][j] >= modulus)
                                        auxiliary[1][j]-= modulus;     
                        }
                       
                        auxiliary[0][j] = auxiliary[0][j]*scalar;
                        auxiliary[1][j] = auxiliary[1][j]*scalar;
                        
   
                        if(auxiliary[0][j]>= modulus)
                        {
                                while(auxiliary[0][j] >= modulus)
                                        auxiliary[0][j]-= modulus;     
                        }
                        if(auxiliary[1][j]>= modulus)
                        {
                                while(auxiliary[1][j] >= modulus)
                                        auxiliary[1][j]-= modulus;     
                        }
                }
                for(uint32_t j=0;j<stop_value;j++)
                {
                        Ciphertext_to_transform->values[0][i][j] = auxiliary[0][j];
                        Ciphertext_to_transform->values[1][i][j] = auxiliary[1][j];      
                }
        }
        return 0;
}

/*
int ntt_cooley_tukey(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;
             
        struct timing_variable timing_variable_ntt_1, timing_variable_ntt_2,timing_variable_ntt_3;   
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_3.polynomial_degree_modulus = stop_value;
        
        int S_psi[stop_value];
        
 
        for(int i=0;i<rns_number;i++)
        {
                int t = stop_value;        
                for(uint32_t j=0;j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
                
                
                for(uint32_t m=1; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);
                        start_timing(&(timing_variable_ntt_1));
                        
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {
                                printf("\t\t loop2 : j = %d\n",j);
                                start_timing(&(timing_variable_ntt_2));
                               
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                        
                                int S = S_psi[m + j];
                                //int S = pow_mod(psi,reverseBits(m + j),mod);   
                        
                                for(uint32_t k = auxj1; k <= auxj2;k++)
                                {
                                        printf("\t\t\t loop3 : k = %d\n",k);
                                        start_timing(&(timing_variable_ntt_3));
                                        
                                        int U = Ciphertext_result->values[0][i][k];  
                                        int V = Ciphertext_result->values[0][i][k + t] * S;
                                        Ciphertext_result->values[0][i][k] = U + V;
                                        if(Ciphertext_result->values[0][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                while(Ciphertext_result->values[0][i][k] >= Ciphertext_result->coefficient_modulus[i])
                                                        Ciphertext_result->values[0][i][k]-= Ciphertext_result->coefficient_modulus[i];    
                                        
                                        int32_t auxiliary = U-V;
                                        if(auxiliary<0)
                                                while(auxiliary < 0)
                                                        auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                        if(auxiliary>= Ciphertext_result->coefficient_modulus[0])
                                                while(auxiliary >= Ciphertext_result->coefficient_modulus[i])
                                                        auxiliary-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        Ciphertext_result->values[0][i][k+t] = auxiliary;
                                        U = Ciphertext_result->values[1][i][k];  
                                        V = Ciphertext_result->values[1][i][k+ t] * S;
                                        Ciphertext_result->values[1][i][k] = U + V;
                                        if(Ciphertext_result->values[1][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                while(Ciphertext_result->values[1][i][k] >= Ciphertext_result->coefficient_modulus[i])
                                                        Ciphertext_result->values[1][i][k]-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        auxiliary = U-V;
                                        if(auxiliary<0)
                                                while(auxiliary < 0)
                                                        auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                        if(auxiliary>= Ciphertext_result->coefficient_modulus[i])
                                                while(auxiliary >= Ciphertext_result->coefficient_modulus[i])
                                                        auxiliary-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        Ciphertext_result->values[1][i][k+t] = auxiliary;        
                                
                                        
                                        end_timing(&(timing_variable_ntt_3));
                                        printf("\t\t\t");
                                        print_timing_excel(timing_variable_ntt_3);
                                
                                
                                }
                                end_timing(&(timing_variable_ntt_2));
                                printf("\t\t");
                                print_timing_excel(timing_variable_ntt_2);
                                
                        }
                        
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing_excel(timing_variable_ntt_1);
                }
                
        }
        
        return 0;
}

*/

int ntt_cooley_tukey_2(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;
             
        #if SECTIONS_TIMES_INFO     
             
        struct timing_variable timing_variable_ntt_1, timing_variable_ntt_2,timing_variable_ntt_3,timing_variable_ntt_4;   
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_3.polynomial_degree_modulus = stop_value;
        
        #endif
        
        int S_psi[stop_value];
        
 
        for(int i=0;i<rns_number;i++)
        {
                int t = stop_value;        
                for(uint32_t j=0;j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
                
                
                for(uint32_t m=1; m < stop_value; m=2*m)
                {
                        #if SECTIONS_TIMES_INFO     
                        printf("\tloop1 : m = %d\n",m);
                        start_timing(&(timing_variable_ntt_1));
                        #endif
                        
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {
                         
                                #if SECTIONS_TIMES_INFO    
                                printf("\t\tloop2 : j = %d\n",j);
                                start_timing(&(timing_variable_ntt_2));
                                #endif
                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                        
                                int S = S_psi[m + j];
                                //int S = pow_mod(psi,reverseBits(m + j),mod);   
                        
                                for(uint32_t k = auxj1; k <= auxj2;k++)
                                {
                                        #if SECTIONS_TIMES_INFO    
                                        printf("\t\t\tloop3 : k = %d\n",k);
                                        start_timing(&(timing_variable_ntt_3));
                                        #endif
                                        
                                        #if SECTIONS_TIMES_INFO    
                                        printf("\t\t\tLoad,and mult by S : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        int U = Ciphertext_result->values[0][i][k];  
                                        int V = Ciphertext_result->values[0][i][k + t] * S;
                                                                              
                                        #if SECTIONS_TIMES_INFO    
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                        
                                        
                                        #if SECTIONS_TIMES_INFO                                            
                                        printf("\t\t\tReduce V: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        if(V >= Ciphertext_result->coefficient_modulus[i])
                                                while(V >= Ciphertext_result->coefficient_modulus[i])
                                                        V-= Ciphertext_result->coefficient_modulus[i];                                      
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                        
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tAdd U and V : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        Ciphertext_result->values[0][i][k] = U + V;
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tReduce result : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        if(Ciphertext_result->values[0][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                Ciphertext_result->values[0][i][k]-= Ciphertext_result->coefficient_modulus[i];
                                                                               
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tSub U and V : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        int32_t auxiliary = U-V;
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tReduce auxiliary : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        if(auxiliary<0)
                                                auxiliary += Ciphertext_result->coefficient_modulus[i];           
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tPut value in ciphertext : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        Ciphertext_result->values[0][i][k+t] = auxiliary;
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tLoad,and mult in V,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        U = Ciphertext_result->values[1][i][k];                                         
                                        V = Ciphertext_result->values[1][i][k+ t] * S;
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif

                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tReduce V,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        if(V >= Ciphertext_result->coefficient_modulus[i])
                                                while(V >= Ciphertext_result->coefficient_modulus[i])
                                                        V-= Ciphertext_result->coefficient_modulus[i];      
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tAdd U and V,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        Ciphertext_result->values[1][i][k] = U + V;
                                                                               
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                                                               
                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tReduce result,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        if(Ciphertext_result->values[1][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                Ciphertext_result->values[1][i][k]-= Ciphertext_result->coefficient_modulus[i];
                                                                                
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif                
                                        
                                        #if SECTIONS_TIMES_INFO                 
                                        printf("\t\t\tSub U and V,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        auxiliary = U-V;
                                        
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tReduce auxiliary,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        if(auxiliary<0)
                                                auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                       
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                        
                                        #if SECTIONS_TIMES_INFO 
                                        printf("\t\t\tPut value in ciphertext,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        #endif
                                        
                                        Ciphertext_result->values[1][i][k+t] = auxiliary;        
                                
                                        #if SECTIONS_TIMES_INFO 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        #endif
                                                                               
                                        #if SECTIONS_TIMES_INFO    
                                        end_timing(&(timing_variable_ntt_3));
                                        printf("\t\t\t");
                                        print_timing(timing_variable_ntt_3);
                                        #endif
                                
                                }
                                
                                #if SECTIONS_TIMES_INFO    
                                end_timing(&(timing_variable_ntt_2));
                                printf("\t\t");
                                print_timing(timing_variable_ntt_2);
                                #endif
                        }
                        
                        #if SECTIONS_TIMES_INFO            
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);
                        #endif
                }
                
        }      
        return 0;
}


int ntt_cooley_tukey_2_barrett(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
   
   
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;            
        struct timing_variable timing_variable_ntt_1, timing_variable_ntt_2,timing_variable_ntt_3,timing_variable_ntt_4;   
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_3.polynomial_degree_modulus = stop_value;
        
        int S_psi[stop_value];
        
 
        for(int i=0;i<rns_number;i++)
        {
                int t = stop_value;        
                for(uint32_t j=0;j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
                
                
                for(uint32_t m=1; m < stop_value; m=2*m)
                {
                        printf("\tloop1 : m = %d\n",m);
                        start_timing(&(timing_variable_ntt_1));
                        
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {
                                printf("\t\tloop2 : j = %d\n",j);
                                start_timing(&(timing_variable_ntt_2));
                               
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                        
                                int S = S_psi[m + j];
                                //int S = pow_mod(psi,reverseBits(m + j),mod);   
                        
                                for(uint32_t k = auxj1; k <= auxj2;k++)
                                {
                                        printf("\t\t\tloop3 : k = %d\n",k);
                                        start_timing(&(timing_variable_ntt_3));
                                        
                                        printf("\t\t\tLoad,and mult in V : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        int U = Ciphertext_result->values[0][i][k];  
                                        int V = Ciphertext_result->values[0][i][k + t] * S;
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tReduce V: ");
                                        start_timing(&(timing_variable_ntt_4));                                        
                                        uint64_t auxq = ((V * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                                        V -= auxq * Ciphertext_result->coefficient_modulus[i];
                                        if(Ciphertext_result->coefficient_modulus[i] <= V) 
                                                V -= Ciphertext_result->coefficient_modulus[i]; 
                                                                             
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tAdd U and V : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        Ciphertext_result->values[0][i][k] = U + V;
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tReduce result : ");
                                        start_timing(&(timing_variable_ntt_4));
                                                                               
                                        if(Ciphertext_result->values[0][i][k]>= Ciphertext_result->coefficient_modulus[i])           
                                                Ciphertext_result->values[0][i][k]-= Ciphertext_result->coefficient_modulus[i];
                                                                               
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                                                                
                                        printf("\t\t\tSub U and V : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        int32_t auxiliary = U-V;
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        
                                        printf("\t\t\tReduce auxiliary : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        if(auxiliary<0)
                                                auxiliary += Ciphertext_result->coefficient_modulus[i];
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        
                                        printf("\t\t\tPut value in ciphertext : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        Ciphertext_result->values[0][i][k+t] = auxiliary;
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tLoad,and mult in V,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        U = Ciphertext_result->values[1][i][k];  
                                        
                                        V = Ciphertext_result->values[1][i][k+ t] * S;
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);

                                        printf("\t\t\tReduce V,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
 
                                        auxq = ((V * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                                        V -= auxq * Ciphertext_result->coefficient_modulus[i];
                                        if(Ciphertext_result->coefficient_modulus[i] <= V) 
                                                V -= Ciphertext_result->coefficient_modulus[i];       
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tAdd U and V,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        Ciphertext_result->values[1][i][k] = U + V;
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tReduce result,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        if(Ciphertext_result->values[1][i][k]>= Ciphertext_result->coefficient_modulus[i])           
                                                Ciphertext_result->values[1][i][k]-= Ciphertext_result->coefficient_modulus[i];
                                        
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                                
                                        printf("\t\t\tSub U and V,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        auxiliary = U-V;
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        
                                        printf("\t\t\tReduce auxiliary,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        if(auxiliary<0)
                                               auxiliary += Ciphertext_result->coefficient_modulus[i];           
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tPut value in ciphertext,2 : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        Ciphertext_result->values[1][i][k+t] = auxiliary;        
                                
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        
                                        end_timing(&(timing_variable_ntt_3));
                                        printf("\t\t\t");
                                        print_timing(timing_variable_ntt_3);
                                
                                
                                }
                                end_timing(&(timing_variable_ntt_2));
                                printf("\t\t");
                                print_timing(timing_variable_ntt_2);
                                
                        }
                        
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);
                }
                
        }
        
        return 0;
}


int ntt_cooley_tukey_3_barrett_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
   
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;            
        struct timing_variable timing_variable_ntt_1, timing_variable_ntt_2,timing_variable_ntt_3,timing_variable_ntt_4;   
        int S_psi[stop_value];
        
 
        for(int i=0;i<rns_number;i++)
        {
                int t = stop_value;        
                for(uint32_t j=0;j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
                
                start_timing(&(timing_variable_ntt_1));
                
                for(uint32_t m=1; m < stop_value; m=2*m)
                {
                        
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {
                               
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                        
                                int S = S_psi[m + j];
                                //int S = pow_mod(psi,reverseBits(m + j),mod);   
                        
                                for(uint32_t k = auxj1; k <= auxj2;k++)
                                {
                                       
                                        int U = Ciphertext_result->values[0][i][k];  
                                        int V = Ciphertext_result->values[0][i][k + t] * S;
                                                                                                                    
                                        uint64_t auxq = ((V * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                                        V -= auxq * Ciphertext_result->coefficient_modulus[i];
                                        if(Ciphertext_result->coefficient_modulus[i] <= V) 
                                                V -= Ciphertext_result->coefficient_modulus[i]; 

                                        Ciphertext_result->values[0][i][k] = U + V;
                                                                              
                                        if(Ciphertext_result->values[0][i][k]>= Ciphertext_result->coefficient_modulus[i])           
                                                Ciphertext_result->values[0][i][k]-= Ciphertext_result->coefficient_modulus[i];
                                                                               
                                      
                                        int32_t auxiliary = U-V;
                                   
                                        if(auxiliary<0)
                                                auxiliary += Ciphertext_result->coefficient_modulus[i];

                                        
                                        Ciphertext_result->values[0][i][k+t] = auxiliary;
                                       
                                        U = Ciphertext_result->values[1][i][k];                                         
                                        V = Ciphertext_result->values[1][i][k+ t] * S;


                                        auxq = ((V * Ciphertext_result->barrett_auxi_value[i]) >> 45);
                                        V -= auxq * Ciphertext_result->coefficient_modulus[i];
                                        if(Ciphertext_result->coefficient_modulus[i] <= V) 
                                                V -= Ciphertext_result->coefficient_modulus[i];       
                                        
                                        
                                        Ciphertext_result->values[1][i][k] = U + V;
                                                                              
                                        if(Ciphertext_result->values[1][i][k]>= Ciphertext_result->coefficient_modulus[i])           
                                                Ciphertext_result->values[1][i][k]-= Ciphertext_result->coefficient_modulus[i];
                                        
                                        
                                        auxiliary = U-V;
                                        

                                        if(auxiliary<0)
                                               auxiliary += Ciphertext_result->coefficient_modulus[i];           

                                        Ciphertext_result->values[1][i][k+t] = auxiliary;        
                                
                                }                                
                        }                        
                } 
                end_timing(&(timing_variable_ntt_1));
                printf("\t\t");
                print_timing(timing_variable_ntt_1);


                
        }       
        return 0;
}


int ntt_cooley_tukey_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;
                    
        int S_psi[stop_value];
        
        for(int i=0;i<rns_number;i++)
        {
                int t = stop_value;        
                for(uint32_t j=0;j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
                
                for(uint32_t m=1; m < stop_value; m=2*m)
                {                       
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {                             
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                        
                                int S = S_psi[m + j];
                                //int S = pow_mod(psi,reverseBits(m + j),mod);                           
                                for(uint32_t k = auxj1; k <= auxj2;k++)
                                {
                                        uint32_t U = Ciphertext_result->values[0][i][k];  
                                        uint64_t V = Ciphertext_result->values[0][i][k + t] * S;                                                                               
                                        if(V >= Ciphertext_result->coefficient_modulus[i])
                                                while(V >= Ciphertext_result->coefficient_modulus[i])
                                                        V-= Ciphertext_result->coefficient_modulus[i];                                      

                                        Ciphertext_result->values[0][i][k] = U + V;                                                                                
                                        if(Ciphertext_result->values[0][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                Ciphertext_result->values[0][i][k]-= Ciphertext_result->coefficient_modulus[i];
                                                                                
                                        int32_t auxiliary = U-V;                                                                              
                                        if(auxiliary<0)
                                                auxiliary += Ciphertext_result->coefficient_modulus[i];           
                                                  
                                        Ciphertext_result->values[0][i][k+t] = auxiliary;

                                                                                                                        
                                        U = Ciphertext_result->values[1][i][k];                                          
                                        V = Ciphertext_result->values[1][i][k+ t] * S; 
                                        if(V >= Ciphertext_result->coefficient_modulus[i])
                                                while(V >= Ciphertext_result->coefficient_modulus[i])
                                                        V-= Ciphertext_result->coefficient_modulus[i];      
                                                                                                                       
                                        Ciphertext_result->values[1][i][k] = U + V;                                                                                
                                        if(Ciphertext_result->values[1][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                Ciphertext_result->values[1][i][k]-= Ciphertext_result->coefficient_modulus[i];
                                                                            
                                        auxiliary = U-V;                                        
                                        if(auxiliary<0)
                                                auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                                                          
                                        Ciphertext_result->values[1][i][k+t] = auxiliary;
                                }
                        }
                }            
        }
        
        return 0;
}


/*for the inverse, put psi as pow_mod(psi,-1,mod)*/
int multiply_by_psi(struct ciphertext Ciphertext1 ,struct ciphertext *Ciphertext_result, uint32_t psi)
{
        const uint32_t stop_value = Ciphertext1.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext1.rns_number;

        for(uint8_t i=0;i<rns_number;i++)
        {
                for(uint32_t j=0;j<stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext1.values[0][i][j] * pow_mod(psi,i,Ciphertext_result->coefficient_modulus[i]);                 
                        while(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] -= Ciphertext_result->coefficient_modulus[i];
       

                        Ciphertext_result->values[1][i][j] = Ciphertext1.values[1][i][j] * pow_mod(psi,i,Ciphertext_result->coefficient_modulus[i]);                
                        while(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                        Ciphertext_result->values[1][i][j] -= Ciphertext_result->coefficient_modulus[i];
      
                }
        }
        return 0;    

}


int intt_gentleman_sande(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;
                   
        uint32_t S_psi[stop_value];
        
       
       for(int i=0;i<rns_number;i++)
       {
                uint32_t i_psi = pow_mod(psi,-1,Ciphertext_result->coefficient_modulus[i]);
                uint32_t scalar = pow_mod(stop_value,-1, Ciphertext_result->coefficient_modulus[i]);   
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];           
                        S_psi[j] = pow_mod(i_psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
                uint32_t t=1;        
                for(uint32_t m = stop_value;m>1;m=m/2)
                {
                        uint32_t auxj1 = 0;   
                        uint32_t h = m/2;
                        for(uint32_t j=0;j<h;j++)
                        {
                                uint32_t auxj2 = auxj1+t-1;   
                                int S = S_psi[h + j];    
                                //int S = pow_mod(i_psi,reverseBits(h + j),mod);
                                
                                for(uint32_t k= auxj1;k<=auxj2;k++)
                                {
                                        uint32_t U = Ciphertext_result->values[0][i][k];
                                        uint32_t V = Ciphertext_result->values[0][i][k+t];
                                
                                        Ciphertext_result->values[0][i][k] = U + V;
                                        if(Ciphertext_result->values[0][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                while(Ciphertext_result->values[0][i][k] >= Ciphertext_result->coefficient_modulus[i])
                                                        Ciphertext_result->values[0][i][k]-= Ciphertext_result->coefficient_modulus[i];
                                        int auxiliary = (U-V) * S;
                                        if(auxiliary<0)
                                                while(auxiliary < 0)
                                                        auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                        if(auxiliary>= Ciphertext_result->coefficient_modulus[i])
                                                while(auxiliary >= Ciphertext_result->coefficient_modulus[i])
                                                        auxiliary-= Ciphertext_result->coefficient_modulus[i];
                                        Ciphertext_result->values[0][0][k+t] = auxiliary;   
                             
                                        U = Ciphertext_result->values[1][i][k];
                                        V = Ciphertext_result->values[1][i][k+t];
                                        Ciphertext_result->values[1][i][k] = U + V;
                                        if(Ciphertext_result->values[1][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                while(Ciphertext_result->values[1][i][k] >= Ciphertext_result->coefficient_modulus[i])
                                                        Ciphertext_result->values[1][i][k]-= Ciphertext_result->coefficient_modulus[i];
                                        auxiliary = (U-V) * S;
                                        if(auxiliary<0)
                                                while(auxiliary < 0)
                                                        auxiliary += Ciphertext_result->coefficient_modulus[i];
                                        if(auxiliary>= Ciphertext_result->coefficient_modulus[i])
                                                while(auxiliary >= Ciphertext_result->coefficient_modulus[i])
                                                        auxiliary-= Ciphertext_result->coefficient_modulus[i];
                                        Ciphertext_result->values[1][i][k+t] = auxiliary;   

                                }
                                auxj1 = auxj1 + 2*t;     
                        }
                        t = 2*t;    
                }
                for(uint32_t j=0; j< stop_value;j++)
                {
                Ciphertext_result->values[0][i][j] = Ciphertext_result->values[0][i][j] * scalar;    
                if(Ciphertext_result->values[0][i][j]>= Ciphertext_result->coefficient_modulus[i])
                        while(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] -= Ciphertext_result->coefficient_modulus[i];     
                                                               
                Ciphertext_result->values[1][i][j] = Ciphertext_result->values[1][i][j] * scalar;   
                if(Ciphertext_result->values[1][i][j]>= Ciphertext_result->coefficient_modulus[i])
                        while(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] -= Ciphertext_result->coefficient_modulus[i];     
                }            
         
        }
        return 0;
}


#if RISCV_VECTORIAL


int ntt_cooley_tukey_vectorial(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1, timing_variable_ntt_2,timing_variable_ntt_3; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_3.polynomial_degree_modulus = stop_value;
        
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       
                
                
                for(uint32_t m=1; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);
                        start_timing(&(timing_variable_ntt_1));

                
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {
                                printf("\t\t loop2 : j = %d\n",j);
                                start_timing(&(timing_variable_ntt_2));
                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                                      
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                        printf("\t\t\t loop3 : k = %d | ",k);
                                        start_timing(&(timing_variable_ntt_3));
                                        
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                         printf("gvl = %d \n",gvl);
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                        } 
 
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        }
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                              
                                              
                                              
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                         v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   

                                        // Second polynomial
   
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                        } 
 
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                        // Reduction result0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        }
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);      
                                              
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                         
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                
                                        end_timing(&(timing_variable_ntt_3));
                                        printf("\t\t\t");
                                        print_timing_excel(timing_variable_ntt_3);
                                
                                }
                                end_timing(&(timing_variable_ntt_2));
                                printf("\t\t");
                                print_timing_excel(timing_variable_ntt_2);
                                
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing_excel(timing_variable_ntt_1);
                }
        }
        return 0;
}

int ntt_cooley_tukey_vectorial_2(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1, timing_variable_ntt_2,timing_variable_ntt_3,timing_variable_ntt_4; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_3.polynomial_degree_modulus = stop_value;
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       
                
                
                for(uint32_t m=1; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
                        
                        
                        if(m>8)
                        {
                        for(uint32_t j=0;j<m;j++)
                        {
                                printf("\t\t loop2 : j = %d\n",j);
                                start_timing(&(timing_variable_ntt_2));
                               
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                        
                                int S = S_psi[m + j];
                                //int S = pow_mod(psi,reverseBits(m + j),mod);   
                        
                                for(uint32_t k = auxj1; k <= auxj2;k++)
                                {
                                        printf("\t\t\t loop3 : k = %d\n",k);
                                        start_timing(&(timing_variable_ntt_3));
                                        
                                        int U = Ciphertext_result->values[0][i][k];  
                                        int V = Ciphertext_result->values[0][i][k + t] * S;
                                        Ciphertext_result->values[0][i][k] = U + V;
                                        if(Ciphertext_result->values[0][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                while(Ciphertext_result->values[0][i][k] >= Ciphertext_result->coefficient_modulus[i])
                                                        Ciphertext_result->values[0][i][k]-= Ciphertext_result->coefficient_modulus[i];    
                                        
                                        int32_t auxiliary = U-V;
                                        if(auxiliary<0)
                                                while(auxiliary < 0)
                                                        auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                        if(auxiliary>= Ciphertext_result->coefficient_modulus[0])
                                                while(auxiliary >= Ciphertext_result->coefficient_modulus[i])
                                                        auxiliary-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        Ciphertext_result->values[0][i][k+t] = auxiliary;
                                        U = Ciphertext_result->values[1][i][k];  
                                        V = Ciphertext_result->values[1][i][k+ t] * S;
                                        Ciphertext_result->values[1][i][k] = U + V;
                                        if(Ciphertext_result->values[1][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                while(Ciphertext_result->values[1][i][k] >= Ciphertext_result->coefficient_modulus[i])
                                                        Ciphertext_result->values[1][i][k]-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        auxiliary = U-V;
                                        if(auxiliary<0)
                                                while(auxiliary < 0)
                                                        auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                        if(auxiliary>= Ciphertext_result->coefficient_modulus[i])
                                                while(auxiliary >= Ciphertext_result->coefficient_modulus[i])
                                                        auxiliary-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        Ciphertext_result->values[1][i][k+t] = auxiliary;        
                                
                                        
                                        end_timing(&(timing_variable_ntt_3));
                                        printf("\t\t\t");
                                        print_timing(timing_variable_ntt_3);
                                
                                
                                }
                                end_timing(&(timing_variable_ntt_2));
                                printf("\t\t");
                                print_timing(timing_variable_ntt_2);
                                
                        }
                        }
                        else
                        {
                        for(uint32_t j=0;j<m;j++)
                        {
                                printf("\t\t loop2 : j = %d\n",j);
                                start_timing(&(timing_variable_ntt_2));
                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                                      
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                        printf("\t\t\t loop3 : k = %d | ",k);
                                        start_timing(&(timing_variable_ntt_3));
                                        
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                         printf("gvl = %d \n",gvl);
                                        
                                        
                                        printf("\t\t\tLoad: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tMult V : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tReduce v_V: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        // Reduction v_V
                                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                        } 
 
                                        end_timing(&(timing_variable_ntt_4));;
                                        print_timing(timing_variable_ntt_4);
 
                                        
                                        
                                        printf("\t\t\tAdd U and V : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                         printf("\t\t\tReduce result: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        }
                                              
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                              
                                               
                                           
                                        printf("\t\t\tStore result: ");
                                        start_timing(&(timing_variable_ntt_4));
                                           
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);                        
                                              
                                              
                                           
                                        printf("\t\t\tSubtract U and V: ");
                                        start_timing(&(timing_variable_ntt_4));      
                                              
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tReduce other : ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                         // Reduction ciphertext_ans_1
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         
                                         
                                        printf("\t\t\tStore results : ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                         
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   

                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);

                                        // Second polynomial
                                        
                                        printf("\t\t\tLoad values, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        
                                        printf("\t\t\tMult V and S, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tReduce V, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        // Reduction v_V
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                        } 
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
 
 
                                        printf("\t\t\tAdd U and V, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        
                                        printf("\t\t\tReduce values, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        // Reduction result0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        }
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                               
                                        
                                        printf("\t\t\tStore results, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    

                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         

                                        printf("\t\t\tSubtract U and V, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         
                                         printf("\t\t\tReduce, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                         
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                         end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         
                                        printf("\t\t\tStore values, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                         
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                         end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         
                                
                                        end_timing(&(timing_variable_ntt_3));
                                        printf("\t\t\t");
                                        print_timing(timing_variable_ntt_3);
                                
                                }
                                end_timing(&(timing_variable_ntt_2));
                                printf("\t\t");
                                print_timing(timing_variable_ntt_2);
                                
                        }
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);
                        
                }
        }
        return 0;
}

int ntt_cooley_tukey_vectorial_barrett(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1, timing_variable_ntt_2,timing_variable_ntt_3,timing_variable_ntt_4; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_3.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_4.polynomial_degree_modulus = stop_value;
        
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);  
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl);  
                
                for(uint32_t m=1; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);
                        start_timing(&(timing_variable_ntt_1));

                
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {
                                printf("\t\t loop2 : j = %d\n",j);
                                start_timing(&(timing_variable_ntt_2));
                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                                      
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                        printf("\t\t\t loop3 : k = %d | ",k);
                                        start_timing(&(timing_variable_ntt_3));
                                        
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                         printf("gvl = %d \n",gvl);
                                         
                                         
                                        printf("\t\t\tLoad: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         
                                         
                                         printf("\t\t\tMult V: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        

                                        printf("\t\t\tReduce v_V: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        // Reduction v_V
                                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
 

                                        printf("\t\t\tAdd U and V: ");
                                        start_timing(&(timing_variable_ntt_4)); 
 
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);


                                          
                                          
                                        printf("\t\t\tReduce result: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
 
 
                                        printf("\t\t\tStore result: ");
                                        start_timing(&(timing_variable_ntt_4)); 

                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      


                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);                                              
                                              

                                        printf("\t\t\tSubtract U and V: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                              
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);  

                                        printf("\t\t\tReduce other: ");
                                        start_timing(&(timing_variable_ntt_4));

                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                         v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);


                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);  

                                        printf("\t\t\tStore Results: ");
                                        start_timing(&(timing_variable_ntt_4));

                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   

                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);  

                                        // Second polynomial
   
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val, gvl);
                                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
 
 
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);                                       
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);      
                                              
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                         
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                
                                        end_timing(&(timing_variable_ntt_3));
                                        printf("\t\t\t");
                                        print_timing_excel(timing_variable_ntt_3);
                                
                                }
                                end_timing(&(timing_variable_ntt_2));
                                printf("\t\t");
                                print_timing_excel(timing_variable_ntt_2);
                                
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing_excel(timing_variable_ntt_1);
                }
        }
        return 0;
}

int ntt_cooley_tukey_vectorial_barrett_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
               
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);  
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl); 
                
                for(uint32_t m=1; m < stop_value; m=2*m)
                {
              
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {
                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                                      
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                       
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                        
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                                                                                                      
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                                                               
                                        // Reduction v_V
                                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);

                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
 
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);

                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                     
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                         v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);

                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   

                                        // Second polynomial
   
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val, gvl);
                                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
  
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);                                       
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);      
                                              
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                                                                
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                                                
                                }
                        }
                }
        }
        return 0;
}

int ntt_cooley_tukey_vectorial_masks_correct_3_barrett(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        struct timing_variable timing_variable_ntt_1, timing_variable_ntt_2,timing_variable_ntt_3,timing_variable_ntt_4; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_3.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_4.polynomial_degree_modulus = stop_value;
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);    
        uint64_t mask_aux[max_gvl];
        uint64_t array_zero[max_gvl];
        uint64_t S_psi[stop_value];
        uint64_t S_values_psi[1024];
    
        const uint32_t stop_value_aux = stop_value/gvl;
        
        printf("stage %d\n",stop_value_aux);
        printf("gvl is : %d \n",gvl);
        printf("stop_value_aux is : %d \n",stop_value_aux);
        fflush(stdout);         
        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, max_gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], max_gvl);       
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], max_gvl);  
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl); 
                uint32_t m;
                
                
                
                for(m=1; m < stop_value_aux; m=2*m)
                {
                        //stage_aux *= 2;
                        printf("\t loop1 : m = %d\n",m);
                        start_timing(&(timing_variable_ntt_1));

                
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {
                                printf("\t\t loop2 : j = %d\n",j);
                                start_timing(&(timing_variable_ntt_2));
                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                                      
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                        printf("\t\t\t loop3 : k = %d | ",k);
                                        start_timing(&(timing_variable_ntt_3));
                                        
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                         printf("gvl = %d \n",gvl);
                                         
                                         
                                        printf("\t\t\tLoad: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         
                                         
                                         printf("\t\t\tMult V: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        

                                        printf("\t\t\tReduce v_V: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        // Reduction v_V
                                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
 

                                        printf("\t\t\tAdd U and V: ");
                                        start_timing(&(timing_variable_ntt_4)); 
 
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);


                                          
                                          
                                        printf("\t\t\tReduce result: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
 
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
 
 
                                        printf("\t\t\tStore result: ");
                                        start_timing(&(timing_variable_ntt_4)); 

                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      


                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);                                              
                                              

                                        printf("\t\t\tSubtract U and V: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                              
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);  

                                        printf("\t\t\tReduce other: ");
                                        start_timing(&(timing_variable_ntt_4));

                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                         v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);


                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);  

                                        printf("\t\t\tStore Results: ");
                                        start_timing(&(timing_variable_ntt_4));

                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   

                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);  

                                        // Second polynomial
   
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
 
 
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);                                       
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);      
                                              
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                         
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                
                                        end_timing(&(timing_variable_ntt_3));
                                        printf("\t\t\t");
                                        print_timing_excel(timing_variable_ntt_3);
                                
                                }
                                end_timing(&(timing_variable_ntt_2));
                                printf("\t\t");
                                print_timing_excel(timing_variable_ntt_2);
                                
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing_excel(timing_variable_ntt_1);
                }
                
                
                printf("stageee\n");
                fflush(stdout);
                for(; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);                      
                        fflush(stdout);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
                        
                        fflush(stdout);
                        for(int j=0;j<max_gvl;j++)
                        {
                                array_zero[j]=0;
                                mask_aux[j] = !(1 & (j/t));
                        }
                        //for(int j=0;j<512;j++)
                        //        index_values_S[j]= m + j/(t*2);   // (/2??? or *2)   
                        
                         for(int j=0;j<1024;j++) // check if correct
                                S_values_psi[j]= S_psi[m + j/(t*2)];  
                        
                         fflush(stdout);
                        // S_values_psi
                        
                        __epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);    
                        __epi_1xi1 v_mask_zero = __builtin_epi_vload_1xi1(&array_zero[0]);                        
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                                               
                        for (uint32_t k = 0; k < 1024; k+=max_gvl) 
                        {

                                __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(&S_values_psi[k], max_gvl);                               
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k],v_mask_not,max_gvl);
                                
                                gvl = __builtin_epi_vsetvl(stop_value - (k+t), __epi_e64, __epi_m1); 
                                printf("gvl: %d\n",gvl);
                                                               
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k + t],v_mask_not,gvl);
                                
                                printf("stop1\n"); 
                                fflush(stdout);
                                
                                v_V = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_S,v_mask_not, max_gvl);
                                
                                
                                // Reduction v_V
                                __epi_1xi64 v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, gvl);
                                __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                        
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);

                                
                                                              
                                printf("stop2\n");              
                                fflush(stdout);
                                   
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64_mask(v_initialize,v_U, v_V,v_mask_not,max_gvl);   
                                
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k], v_result_0_0,v_mask_not, max_gvl);

                                                
                                 printf("stop3\n");
                                fflush(stdout);                                 
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                         
                                       
                                //store results
                               __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k+t], v_result_0_1,v_mask_not, gvl);  
                                 
                                printf("stop4\n");      
                                fflush(stdout);
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k],v_mask_not,max_gvl);
                                
                                v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k+t],v_mask_not,gvl);   
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                       
                                 printf("stop5\n");
                                fflush(stdout);   

                                // Reduction v_V
                                // Reduction v_V
                                v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                 v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, gvl);
                                v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                        
                                mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                    
                                printf("stop6\n");   
                                fflush(stdout);         
                                
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);
                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, max_gvl);
                                 

                                 //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k], v_result_1_0,v_mask_not, max_gvl);                                 
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, max_gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, max_gvl);
                                         
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k+t], v_result_1_1,v_mask_not, gvl);
                        
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);      
                        fflush(stdout);
                        
                }
                
        }
        return 0;
}

int ntt_cooley_tukey_vectorial_masks_correct_3_barrett_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1,timing_variable_ntt_2; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);    
        
        uint64_t mask_aux[256];
        uint64_t array_zero[256];
        uint64_t S_psi[stop_value];
        uint64_t S_values_psi[1024];
    
        uint32_t stop_value_aux = stop_value/gvl;
        // const uint32_t stop_value_aux = stop_value/gvl;
    
        // printf("gvl is : %d \n",gvl);
        // printf("stop_value_aux is : %d \n",stop_value_aux);
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
           
                start_timing(&(timing_variable_ntt_1));
           
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);  
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl); 
                uint32_t m;
                
                start_timing(&(timing_variable_ntt_2));
                
                for(m=1; m < stop_value_aux; m=2*m)
                {
                        //stage_aux *= 2;
                
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                                                                 
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                         
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);

                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);

                                              
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                         v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
 
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
  

                                        // Second polynomial
   
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
 
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);                                       
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);      
                                              
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                         
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                                                
                                }
                        }
                }
                
                end_timing(&(timing_variable_ntt_2));
                printf("\t");
                print_timing(timing_variable_ntt_2);
                
                
              //  printf("test\n\n");
                
                for(; m < stop_value; m=2*m)
                {

                        start_timing(&(timing_variable_ntt_2));
                        

                        t = t/2;                        
                        for(int j=0;j<max_gvl;j++)
                        {
                                array_zero[j]=0;
                                mask_aux[j] = !(1 & (j/t));
                        }

                        
                        for(int j=0;j<1024;j++) // check if correct
                                S_values_psi[j]= S_psi[m + j/(t*2)];  


                        
                        // S_values_psi
                        
                        __epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);    
                        __epi_1xi1 v_mask_zero = __builtin_epi_vload_1xi1(&array_zero[0]);                        
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                          
                        end_timing(&(timing_variable_ntt_2));
                        printf("\t");
                        print_timing(timing_variable_ntt_2);
                          
                          
                        start_timing(&(timing_variable_ntt_2));  
                          
                        for (uint32_t k = 0; k < 1024; k+=max_gvl) 
                        {

                                __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(&S_values_psi[k], max_gvl);
                                
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k],v_mask_not,max_gvl);
                                
                                gvl = __builtin_epi_vsetvl(stop_value - (k+t), __epi_e64, __epi_m1); 
                                                               
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k + t],v_mask_not,gvl);
                                
                                v_V = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_S,v_mask_not, max_gvl);
                                                      
                                // Reduction v_V
                                __epi_1xi64 v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, gvl);
                                __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                        
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                   
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64_mask(v_initialize,v_U, v_V,v_mask_not,max_gvl);   
                                
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k], v_result_0_0,v_mask_not, max_gvl);
                                
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                                                 
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k+t], v_result_0_1,v_mask_not, gvl);  
                                 
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k],v_mask_not,max_gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k+t],v_mask_not,gvl);   
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                       
                                // Reduction v_V
                                // Reduction v_V
                                v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, gvl);
                                v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                        
                                mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                         
                                
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);
                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, max_gvl);
                                 
                                 //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k], v_result_1_0,v_mask_not, max_gvl);
                                
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, max_gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, max_gvl);
                                                                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k+t], v_result_1_1,v_mask_not, gvl);
                        
                        }
                        
                        end_timing(&(timing_variable_ntt_2));
                        printf("\t");
                        print_timing(timing_variable_ntt_2);
                        
                }
                
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);
                
                
                
        }
        return 0;
}


int ntt_cooley_tukey_vectorial_masks_correct_3_barrett_no_times_taux(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1,timing_variable_ntt_2; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);    
        
        uint64_t mask_aux[256];
        uint64_t array_zero[256];
        uint64_t S_psi[stop_value];
        uint64_t S_values_psi[1024];
    
        uint32_t stop_value_aux = stop_value/gvl;
        // const uint32_t stop_value_aux = stop_value/gvl;
    
        // printf("gvl is : %d \n",gvl);
        // printf("stop_value_aux is : %d \n",stop_value_aux);
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                int t_aux = 10;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
           
                start_timing(&(timing_variable_ntt_1));
           
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);  
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl); 
                uint32_t m;
                
                start_timing(&(timing_variable_ntt_2));
                
                for(m=1; m < stop_value_aux; m=2*m)
                {
                        //stage_aux *= 2;
                
                        t = t/2;
                        t_aux--;
                        for(uint32_t j=0;j<m;j++)
                        {
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                                                                 
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                         
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);

                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);

                                              
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                         v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
 
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
  

                                        // Second polynomial
   
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
 
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);                                       
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);      
                                              
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                         
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                                                
                                }
                        }
                }
                
                end_timing(&(timing_variable_ntt_2));
                printf("\t");
                print_timing(timing_variable_ntt_2);
                
                
              //  printf("test\n\n");
                
                for(; m < stop_value; m=2*m)
                {

                        start_timing(&(timing_variable_ntt_2));
                        

                        t = t/2;  
                        t_aux--;                        
                        for(int j=0;j<max_gvl;j++)
                        {
                                array_zero[j]=0;
                                mask_aux[j] = !(1 & (j>>t_aux));
                        }

                        
                        for(int j=0;j<1024;j++) // check if correct
                                S_values_psi[j]= S_psi[m + (j>>(t_aux+1))];  


                        
                        // S_values_psi
                        
                        __epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);    
                        __epi_1xi1 v_mask_zero = __builtin_epi_vload_1xi1(&array_zero[0]);                        
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                          
                        end_timing(&(timing_variable_ntt_2));
                        printf("\t");
                        print_timing(timing_variable_ntt_2);
                          
                          
                        start_timing(&(timing_variable_ntt_2));  
                          
                        for (uint32_t k = 0; k < 1024; k+=max_gvl) 
                        {

                                __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(&S_values_psi[k], max_gvl);
                                
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k],v_mask_not,max_gvl);
                                
                                gvl = __builtin_epi_vsetvl(stop_value - (k+t), __epi_e64, __epi_m1); 
                                                               
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k + t],v_mask_not,gvl);
                                
                                v_V = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_S,v_mask_not, max_gvl);
                                                      
                                // Reduction v_V
                                __epi_1xi64 v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, gvl);
                                __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                        
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                   
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64_mask(v_initialize,v_U, v_V,v_mask_not,max_gvl);   
                                
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k], v_result_0_0,v_mask_not, max_gvl);
                                
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                                                 
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k+t], v_result_0_1,v_mask_not, gvl);  
                                 
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k],v_mask_not,max_gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k+t],v_mask_not,gvl);   
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                       
                                // Reduction v_V
                                // Reduction v_V
                                v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, gvl);
                                v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                        
                                mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                         
                                
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);
                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, max_gvl);
                                 
                                 //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k], v_result_1_0,v_mask_not, max_gvl);
                                
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, max_gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, max_gvl);
                                                                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k+t], v_result_1_1,v_mask_not, gvl);
                        
                        }
                        
                        end_timing(&(timing_variable_ntt_2));
                        printf("\t");
                        print_timing(timing_variable_ntt_2);
                        
                }
                
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);
                
                
                
        }
        return 0;
}


int ntt_cooley_tukey_vectorial_masks_correct_4_barrett_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
   
        //asm volatile("csrw 0x805, %0" :: "r"(256));  
   
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);    
  

  
        //printf("gvl is : %d \n",gvl);
  
        uint64_t mask_aux[256];
        uint64_t array_zero[256];
        uint64_t S_psi[stop_value];
        uint64_t S_values_psi[stop_value];
    
        uint32_t stop_value_aux = stop_value/gvl;
        // const uint32_t stop_value_aux = stop_value/gvl;
    

        //printf("stop_value_aux is : %d \n",stop_value_aux);
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
                
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);  
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl); 
                uint32_t m;
                
                for(m=1; m < stop_value_aux; m=2*m)
                {
                        //stage_aux *= 2;
                
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                                                                 
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                         
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);

                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);

                                              
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                         v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
 
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
  

                                        // Second polynomial
   
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
 
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);                                       
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);      
                                              
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                         
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                                                
                                }
                        }
                }
                
               // printf("test\n\n");
               // fflush(stdout);
                for(; m < stop_value; m=2*m)
                {

                        t = t/2;                        
                        for(int j=0;j<max_gvl;j++)
                        {
                                array_zero[j]=0;
                                mask_aux[j] = !(1 & (j/t));
                        }
                        
                        for(int j=0;j<1024;j++) // check if correct
                                S_values_psi[j]= S_psi[m + j/(t*2)];  
                        
                        // S_values_psi
                        
                        __epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);    
                        
                        __epi_1xi1 v_mask_zero = __builtin_epi_vload_1xi1(&array_zero[0]);                        
                        
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                                               
                        for (uint32_t k = 0; k < 1024; k+=max_gvl) 
                        {

                                __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(&S_values_psi[k], max_gvl);
                                
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k],max_gvl);
                                
                                gvl = __builtin_epi_vsetvl(stop_value - (k+t), __epi_e64, __epi_m1); 
                                                               
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t],gvl);
                                
                                v_V = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_S,v_mask_not, max_gvl);
                                                      
                                // Reduction v_V
                                __epi_1xi64 v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, gvl);
                                __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                        
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                   
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64_mask(v_initialize,v_U, v_V,v_mask_not,max_gvl);   
                                
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k], v_result_0_0,v_mask_not, max_gvl);
                                
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                                                 
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k+t], v_result_0_1,v_mask_not, gvl);  
                                 
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k],max_gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t],gvl);   
                                         
                                v_V = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_S,v_mask_not, max_gvl);
                                       
                                // Reduction v_V
                                // Reduction v_V
                                v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, gvl);
                                v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                        
                                mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                         
                                
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);
                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, max_gvl);
                                 
                                 //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k], v_result_1_0,v_mask_not, max_gvl);
                                
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, max_gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, max_gvl);
                                                                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k+t], v_result_1_1,v_mask_not, gvl);
                        
                        }
                }
                
        }
        return 0;
}


int ntt_cooley_tukey_vec_mask_5_bar_nt(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
   
       // asm volatile("csrw 0x805, %0" :: "r"(256));  
   
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);    
  

  
        //printf("gvl is : %d \n",gvl);
  
        uint64_t mask_aux[256];
        uint64_t array_zero[256];
        uint64_t S_psi[stop_value];
        uint64_t S_values_psi[stop_value];
    
        uint32_t stop_value_aux = stop_value/gvl;
        // const uint32_t stop_value_aux = stop_value/gvl;
    
        
        //printf("stop_value_aux is : %d \n",stop_value_aux);
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                uint32_t t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
                

                
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64((int64_t)0, gvl);   
                

                
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       

                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);  

                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl); 

                uint32_t m;
                
                
                for(m=1; m < stop_value_aux; m=2*m)
                {

                        //stage_aux *= 2;
                
                
                        t = t/2;
                        for(uint32_t j=0;j<m;j++)
                        {                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                                                                 
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                         
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);

                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);

                                              
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                         v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
 
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
  

                                        // Second polynomial
   
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        // Reduction v_V
                                        v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                        v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                        v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
 
 
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);                                       
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);      
                                              
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                         
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                                                
                                }
                        }
                }
                

                for(; m < stop_value; m=2*m)
                {

                        t = t/2;                        
                        for(int j=0;j<max_gvl;j++)
                        {
                                array_zero[j]=0;
                                mask_aux[j] = !(1 & (j/t));
                        }
                        
                        for(int j=0;j<1024;j++)
                                S_values_psi[j]= S_psi[m + j/(t*2)];  
                        
 
                        
                        // S_values_psi
                        
                        __epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);    
                        
                        __epi_1xi1 v_mask_zero = __builtin_epi_vload_1xi1(&array_zero[0]);                        
                        
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                                               
                        for (uint32_t k = 0; k < 1024; k+=max_gvl) 
                        {

                                __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(&S_values_psi[k], max_gvl);
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k],max_gvl);
                                
                                gvl = __builtin_epi_vsetvl(stop_value - (k+t), __epi_e64, __epi_m1); 
                                        
                                  
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t],gvl);
                                // for max_gvl, can also be with the shift 
                                
                                v_V = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_S,v_mask_not, max_gvl);
                                                      
                                // Reduction v_V
                                __epi_1xi64 v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, gvl);
                                __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                        
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                   
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64_mask(v_initialize,v_U, v_V,v_mask_not,max_gvl);   
                                
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k], v_result_0_0,v_mask_not, max_gvl);
                                
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                                                 
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k+t], v_result_0_1,v_mask_not, gvl);  
                                 
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k],max_gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t],gvl);   
                                         
                                v_V = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_S,v_mask_not, max_gvl);
                                       
                                // Reduction v_V
                                // Reduction v_V
                                v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, gvl);
                                v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                        
                                mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                         
                                
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);
                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, max_gvl);
                                 
                                 //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k], v_result_1_0,v_mask_not, max_gvl);
                                
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, max_gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, max_gvl);
                                                                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k+t], v_result_1_1,v_mask_not, gvl);
                        
                        }
                }
                
        }
        return 0;
}








// ntt for only 1024
int ntt_cooley_tukey_vectorial_masks_correct_2_barrett(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        uint64_t mask_aux[256];
        int index_values_S[512];
        uint64_t array_zero[256];
        uint64_t S_psi[stop_value];
        uint64_t S_values_psi[1024];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, max_gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], max_gvl);       
                __epi_1xi64 v_m = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->barrett_auxi_value[i], gvl);  
                __epi_1xi64 v_shift_val = __builtin_epi_vbroadcast_1xi64(45, gvl);
                uint32_t m =1;
                
                printf("\t loop1 : m = %d\n",m);
                fflush(stdout);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);                      
                fflush(stdout);
        
        
                m = 2;
                printf("\t loop1 : m = %d\n",m);
                        
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {                
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi64 v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);                   
                                
                                
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                v_q = __builtin_epi_vmul_1xi64(v_V, v_m, gvl);
                                v_q =  __builtin_epi_vsrl_1xi64(v_q, v_shift_val , gvl);
                                v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);  
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);      
                fflush(stdout);
        
                for(m=4; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);                      
                        fflush(stdout);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
                        
                        fflush(stdout);
                        for(int j=0;j<256;j++)
                        {
                                array_zero[j]=0;
                                mask_aux[j] = !(1 & (j/t));
                        }
                        //for(int j=0;j<512;j++)
                        //        index_values_S[j]= m + j/(t*2);   // (/2??? or *2)   
                        
                         for(int j=0;j<1024;j++) // check if correct
                                S_values_psi[j]= S_psi[m + j/(t*2)];  
                        
                         fflush(stdout);
                        // S_values_psi
                        
                        __epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);    
                        __epi_1xi1 v_mask_zero = __builtin_epi_vload_1xi1(&array_zero[0]);                        
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                                               
                        for (uint32_t k = 0; k < 1024; k+=max_gvl) 
                        {

                                __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(&S_values_psi[k], max_gvl);
                                
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k],v_mask_not,max_gvl);
                                
                                gvl = __builtin_epi_vsetvl(stop_value - (k+t), __epi_e64, __epi_m1); 
                                printf("gvl: %d\n",gvl);
                                                               
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k + t],v_mask_not,gvl);
                                
                                printf("stop1\n"); 
                                fflush(stdout);
                                
                                v_V = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_S,v_mask_not, max_gvl);
                                
                                
                                // Reduction v_V
                                __epi_1xi64 v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, max_gvl);
                                __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);

                                
                                                              
                                printf("stop2\n");              
                                fflush(stdout);
                                   
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64_mask(v_initialize,v_U, v_V,v_mask_not,max_gvl);   
                                
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k], v_result_0_0,v_mask_not, max_gvl);

                                                
                                 printf("stop3\n");
                                fflush(stdout);                                 
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                         
                                       
                                //store results
                               __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k+t], v_result_0_1,v_mask_not, gvl);  
                                 
                                printf("stop4\n");      
                                fflush(stdout);
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k],v_mask_not,max_gvl);
                                
                                v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k+t],v_mask_not,gvl);   
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                       
                                 printf("stop5\n");
                                fflush(stdout);   

                                // Reduction v_V
                                v_q = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_m,v_mask_not,max_gvl);
                                v_q =  __builtin_epi_vsrl_1xi64_mask(v_initialize,v_q, v_shift_val,v_mask_not, max_gvl);
                                v_aux1 = __builtin_epi_vmul_1xi64_mask(v_initialize,v_q, v_coef_mod,v_mask_not,max_gvl);
                                v_V = __builtin_epi_vsub_1xi64_mask(v_initialize,v_V, v_aux1,v_mask_not,max_gvl);
                                mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                    
                                printf("stop6\n");   
                                fflush(stdout);         
                                
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);
                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, max_gvl);
                                 

                                 //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k], v_result_1_0,v_mask_not, max_gvl);                                 
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, max_gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, max_gvl);
                                         
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k+t], v_result_1_1,v_mask_not, gvl);
                        
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);      
                        fflush(stdout);
                        
                }
        }
        return 0;
}



int intt_gentleman_sande_vectorial(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;          
        uint64_t S_psi[stop_value];
        
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
             
       for(int i=0;i<rns_number;i++)
       {
                uint32_t t=1;   
                uint32_t i_psi = pow_mod(psi,-1,Ciphertext_result->coefficient_modulus[i]);
                uint32_t scalar = pow_mod(stop_value,-1, Ciphertext_result->coefficient_modulus[i]);   
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(i_psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }
      
                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);  
      
                for(uint32_t m = stop_value;m>1;m=m/2)
                {
                        uint32_t auxj1 = 0;   
                        uint32_t h = m/2;
                        for(uint32_t j=0;j<h;j++)
                        {
                                uint32_t auxj2 = auxj1+t-1;
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[h + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                       
                                
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                        // Reduction v_result_0_0
                                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        }
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                
                                        
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                         // Reduction ciphertext_ans_1
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                        
                                        
                                        v_result_0_1 = __builtin_epi_vmul_1xi64(v_result_0_1, v_S, gvl);
                                        
                                           
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_0_1 = __builtin_epi_vsub_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                        }
                                                                                      

                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl); 
                                        
                                        
                                        // Second Polynomial
                                        
                                         v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                         v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        
                                
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                        // Reduction v_result_1_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        }
                                               
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);      
                                                                       
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                         // Reduction ciphertext_ans_1
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                        v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);                                       
                                        v_result_1_1 = __builtin_epi_vmul_1xi64(v_result_1_1, v_S, gvl);
                                                                                  
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_1_1 = __builtin_epi_vsub_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                        }
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);
                                }
                                auxj1 = auxj1 + 2*t;     
                        }
                        t = 2*t;    
                }
                for(uint32_t j=0; j< stop_value;j++)
                {
                Ciphertext_result->values[0][i][j] = Ciphertext_result->values[0][i][j] * scalar;    
                if(Ciphertext_result->values[0][i][j]>= Ciphertext_result->coefficient_modulus[i])
                        while(Ciphertext_result->values[0][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[0][i][j] -= Ciphertext_result->coefficient_modulus[i];     
                                                               
                Ciphertext_result->values[1][i][j] = Ciphertext_result->values[1][i][j] * scalar;   
                if(Ciphertext_result->values[1][i][j]>= Ciphertext_result->coefficient_modulus[i])
                        while(Ciphertext_result->values[1][i][j] >= Ciphertext_result->coefficient_modulus[i])
                                Ciphertext_result->values[1][i][j] -= Ciphertext_result->coefficient_modulus[i];     
                }
       }
        return 0;
}

/*
int ntt_cooley_tukey_vectorial_4(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint32_t aux_stop_value = stop_value/2;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1, timing_variable_ntt_2,timing_variable_ntt_3,timing_variable_ntt_4; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_3.polynomial_degree_modulus = stop_value;
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        printf("max gvl: %d\n", max_gvl);
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       
                
                uint32_t m =1;
                for(m=1; m < aux_stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
                        
                        
                        if(m>8)
                        {
                        for(uint32_t j=0;j<m;j++)
                        {
                                printf("\t\t loop2 : j = %d\n",j);
                                start_timing(&(timing_variable_ntt_2));
                               
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                        
                                int S = S_psi[m + j];
                                //int S = pow_mod(psi,reverseBits(m + j),mod);   
                        
                                for(uint32_t k = auxj1; k <= auxj2;k++)
                                {
                                        printf("\t\t\t loop3 : k = %d\n",k);
                                        start_timing(&(timing_variable_ntt_3));
                                        
                                        int U = Ciphertext_result->values[0][i][k];  
                                        int V = Ciphertext_result->values[0][i][k + t] * S;
                                        Ciphertext_result->values[0][i][k] = U + V;
                                        if(Ciphertext_result->values[0][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                while(Ciphertext_result->values[0][i][k] >= Ciphertext_result->coefficient_modulus[i])
                                                        Ciphertext_result->values[0][i][k]-= Ciphertext_result->coefficient_modulus[i];    
                                        
                                        int32_t auxiliary = U-V;
                                        if(auxiliary<0)
                                                while(auxiliary < 0)
                                                        auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                        if(auxiliary>= Ciphertext_result->coefficient_modulus[0])
                                                while(auxiliary >= Ciphertext_result->coefficient_modulus[i])
                                                        auxiliary-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        Ciphertext_result->values[0][i][k+t] = auxiliary;
                                        U = Ciphertext_result->values[1][i][k];  
                                        V = Ciphertext_result->values[1][i][k+ t] * S;
                                        Ciphertext_result->values[1][i][k] = U + V;
                                        if(Ciphertext_result->values[1][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                while(Ciphertext_result->values[1][i][k] >= Ciphertext_result->coefficient_modulus[i])
                                                        Ciphertext_result->values[1][i][k]-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        auxiliary = U-V;
                                        if(auxiliary<0)
                                                while(auxiliary < 0)
                                                        auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                        if(auxiliary>= Ciphertext_result->coefficient_modulus[i])
                                                while(auxiliary >= Ciphertext_result->coefficient_modulus[i])
                                                        auxiliary-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        Ciphertext_result->values[1][i][k+t] = auxiliary;        
                                
                                        
                                        end_timing(&(timing_variable_ntt_3));
                                        printf("\t\t\t");
                                        print_timing(timing_variable_ntt_3);
                                
                                
                                }
                                end_timing(&(timing_variable_ntt_2));
                                printf("\t\t");
                                print_timing(timing_variable_ntt_2);
                                
                        }
                        }
                        else
                        {
                        for(uint32_t j=0;j<m;j++)
                        {
                                printf("\t\t loop2 : j = %d\n",j);
                                start_timing(&(timing_variable_ntt_2));
                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                                      
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {
                                        printf("\t\t\t loop3 : k = %d | ",k);
                                        start_timing(&(timing_variable_ntt_3));
                                        
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                         printf("gvl = %d \n",gvl);
                                        
                                        
                                        printf("\t\t\tLoad: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tMult V : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tReduce v_V: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        // Reduction v_V
                                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                        } 
 
                                        end_timing(&(timing_variable_ntt_4));;
                                        print_timing(timing_variable_ntt_4);
 
                                        
                                        
                                        printf("\t\t\tAdd U and V : ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                         printf("\t\t\tReduce result: ");
                                        start_timing(&(timing_variable_ntt_4));
                                        
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        }
                                              
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                              
                                               
                                           
                                        printf("\t\t\tStore result: ");
                                        start_timing(&(timing_variable_ntt_4));
                                           
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);                        
                                              
                                              
                                           
                                        printf("\t\t\tSubtract U and V: ");
                                        start_timing(&(timing_variable_ntt_4));      
                                              
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tReduce other : ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                         // Reduction ciphertext_ans_1
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         
                                         
                                        printf("\t\t\tStore results : ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                         
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   

                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);

                                        // Second polynomial
                                        
                                        printf("\t\t\tLoad values, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        
                                        printf("\t\t\tMult V and S, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        printf("\t\t\tReduce V, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        // Reduction v_V
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                        } 
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
 
 
                                        printf("\t\t\tAdd U and V, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                        
                                        
                                        printf("\t\t\tReduce values, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        // Reduction result0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        }
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                               
                                        
                                        printf("\t\t\tStore results, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    

                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         

                                        printf("\t\t\tSubtract U and V, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                        
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                        end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         
                                         printf("\t\t\tReduce, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                         
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                         end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         
                                        printf("\t\t\tStore values, 2: ");
                                        start_timing(&(timing_variable_ntt_4)); 
                                         
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                         end_timing(&(timing_variable_ntt_4));
                                        print_timing(timing_variable_ntt_4);
                                         
                                
                                        end_timing(&(timing_variable_ntt_3));
                                        printf("\t\t\t");
                                        print_timing(timing_variable_ntt_3);
                                
                                }
                                end_timing(&(timing_variable_ntt_2));
                                printf("\t\t");
                                print_timing(timing_variable_ntt_2);
                                
                        }
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);
                        
                }
                
                
                
                // new loop -1
                
                

                
                printf("\t loop1 : m = %d\n",m);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                
                __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(S_psi[m + 0], max_gvl);  
                
                for (uint32_t j=0;j<2; j++)
                {
                                
                        __epi_1xi64 v_U = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j],4,max_gvl);
                        __epi_1xi64 v_V = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j+t],4,max_gvl);
                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                        // Reduction v_V
                        
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                        } 
                        
                        
                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                        
                        // Reduction v_result_0_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                        }                 
                        
                        //store results 
                        __builtin_epi_vstore_strided_1xi64(&Ciphertext_result->values[0][i][j], v_result_0_0, 4, max_gvl);
                 
                 
                 
                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                             
                             
                        //store results
                        __builtin_epi_vstore_strided_1xi64(&Ciphertext_result->values[0][i][j+t], v_result_0_1, 4, max_gvl);
               

      
                        v_U = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j],4,max_gvl);          
                        v_V = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j+t],4,max_gvl);
                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                        // Reduction v_V
                        
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                        } 
                        
                        
                        v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                        
                        // Reduction v_result_0_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                        }                 
                        
                        //store results 
                        __builtin_epi_vstore_strided_1xi64(&Ciphertext_result->values[1][i][j], v_result_0_0, 4, max_gvl);
                 
                 
                 
                        v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                             
                             
                        //store results
                        __builtin_epi_vstore_strided_1xi64(&Ciphertext_result->values[1][i][j+t], v_result_0_1, 4, max_gvl);        
                        
                
                        
               
                }
               
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);
                
                m=2*m
                
                
                
                

                
                
                
                
                
                
                
            
                // new loop
                printf("\t loop1 : m = %d\n",m);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                
                printf("t value:%d\n",t);
                uint32_t max_gvl_test =  max_gvl/2; 
                
                for(uint32_t j=0;j<stop_value; j+=512)
                {
                        __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(&S_psi[m + (j/2)], max_gvl_test);         
                        __epi_1xi64 v_U = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j],2,max_gvl_test);
                        
                        __epi_1xi64 v_V = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j+1],2,max_gvl_test);
                        

                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                        
                        // Reduction v_V
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                        {                       
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                        } 
                         
 

                        
                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl_test);

                        // Reduction v_result_0_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                        {                       
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                        }   

                        
                        //store results 
                        __builtin_epi_vstore_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_result_0_0, 2,max_gvl_test);
                        //__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_result_0_0, max_gvl);
                 
                        
                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                        

                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                             
                        
                        
                        //store results
                        __builtin_epi_vstore_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j+t], v_result_0_1, 2, max_gvl);
               

                        
                        
                        
                        v_U = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j],2,max_gvl);          
                        v_V = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j+t],2,max_gvl);
                        
                        //v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                        
                        // Reduction v_V

                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                        {                       
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                        } 

                        
                        v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);

                        // Reduction v_result_0_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                        {                       
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                        }                 
                        
                        //store results 
                        __builtin_epi_vstore_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_result_0_0, 2, max_gvl);
                 

                 
                        v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);

                        
                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                             
                             
                        //store results
                        __builtin_epi_vstore_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j+t], v_result_0_1, 2, max_gvl);
                        
                        
                        
               
                }
               
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);       
                
                
        }
        return 0;
}

*/

/*
int ntt_cooley_tukey_vectorial_4_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint32_t aux_stop_value = stop_value/2;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1, timing_variable_ntt_2,timing_variable_ntt_3,timing_variable_ntt_4; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_2.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_3.polynomial_degree_modulus = stop_value;
        timing_variable_ntt_4.polynomial_degree_modulus = stop_value;
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       
                
                uint32_t m =1;
                for(m=1; m < aux_stop_value; m=2*m)
                {

                        printf("\t loop1 : m = %d\n",m);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
                        
                        
                        if(m>8)
                        {
                        for(uint32_t j=0;j<m;j++)
                        {

                               
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                        
                                int S = S_psi[m + j];
                                //int S = pow_mod(psi,reverseBits(m + j),mod);   
                        
                                for(uint32_t k = auxj1; k <= auxj2;k++)
                                {

                                        
                                        int U = Ciphertext_result->values[0][i][k];  
                                        int V = Ciphertext_result->values[0][i][k + t] * S;
                                        Ciphertext_result->values[0][i][k] = U + V;
                                        if(Ciphertext_result->values[0][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                while(Ciphertext_result->values[0][i][k] >= Ciphertext_result->coefficient_modulus[i])
                                                        Ciphertext_result->values[0][i][k]-= Ciphertext_result->coefficient_modulus[i];    
                                        
                                        int32_t auxiliary = U-V;
                                        if(auxiliary<0)
                                                while(auxiliary < 0)
                                                        auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                        if(auxiliary>= Ciphertext_result->coefficient_modulus[0])
                                                while(auxiliary >= Ciphertext_result->coefficient_modulus[i])
                                                        auxiliary-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        Ciphertext_result->values[0][i][k+t] = auxiliary;
                                        U = Ciphertext_result->values[1][i][k];  
                                        V = Ciphertext_result->values[1][i][k+ t] * S;
                                        Ciphertext_result->values[1][i][k] = U + V;
                                        if(Ciphertext_result->values[1][i][k]>= Ciphertext_result->coefficient_modulus[i])
                                                while(Ciphertext_result->values[1][i][k] >= Ciphertext_result->coefficient_modulus[i])
                                                        Ciphertext_result->values[1][i][k]-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        auxiliary = U-V;
                                        if(auxiliary<0)
                                                while(auxiliary < 0)
                                                        auxiliary += Ciphertext_result->coefficient_modulus[i];          
                                        if(auxiliary>= Ciphertext_result->coefficient_modulus[i])
                                                while(auxiliary >= Ciphertext_result->coefficient_modulus[i])
                                                        auxiliary-= Ciphertext_result->coefficient_modulus[i];     
                                        
                                        Ciphertext_result->values[1][i][k+t] = auxiliary;        
                                
                                        

                                
                                
                                }

                                
                        }
                        }
                        else
                        {
                        for(uint32_t j=0;j<m;j++)
                        {

                                
                                uint32_t auxj1 = 2*j*t; 
                                uint32_t auxj2 = auxj1+t-1;
                                                      
                                __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                                for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                                {

                                        
                                        gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);
                                    
                                        
                                        
                                
                                        
                                        __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                        __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);
                                        
                             
                                        
                                 
                                        
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                        
                                        
                                      
                                        
                                        // Reduction v_V
                                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                        } 
 
                                        
                                        
                                    
                                        
                                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                       
                                  
                                        
                                        // Reduction v_result_0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                        }
                                              
                                       
                                              
                                               
                                           
                                       
                                           
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                        
                                                      
                                              
                                              
                                           
                                       
                                              
                                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                       
                                        
                                         // Reduction ciphertext_ans_1
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                         
                                         
                                      
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   

                                      

                                        // Second polynomial
                                        
                                      
                                        
                                        v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                        v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                    
                                        
                                      
                                        
                                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                      
                                        
                                    
                                        // Reduction v_V
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                        } 
                                        
                                        
 
 
                                       
                                        
                                        __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                                        
                                       
                                        
                                        
                                      
                                        
                                        // Reduction result0_0
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                        {                       
                                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                        }
                                        
                                       
                                               
                                        
                                       
                                        
                                        //store results
                                        __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    

                                       
                                         

                                        
                                        __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                        
                                       
                                         
                                       
                                         
                                         // Reduction ciphertext_ans_1
                                         mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                         v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                       
                                         
                                      
                                         
                                         //store results
                                         __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                                        
                                
                                       
                                
                                }
                               
                                
                        }
                        }
                    

                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);
                        
                }
                
                
                
                // new loop -1
                
                
                
                
                printf("\t loop1 : m = %d\n",m);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                
                __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(S_psi[m + 0], max_gvl);  
                
                for (uint32_t j=0;j<2; j++)
                {
                                
                        __epi_1xi64 v_U = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j],4,max_gvl);
                        __epi_1xi64 v_V = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j+t],4,max_gvl);
                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                        // Reduction v_V
                        
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                        } 
                        
                        
                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                        
                        // Reduction v_result_0_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                        }                 
                        
                        //store results 
                        __builtin_epi_vstore_strided_1xi64(&Ciphertext_result->values[0][i][j], v_result_0_0, 4, max_gvl);
                 
                 
                 
                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                             
                             
                        //store results
                        __builtin_epi_vstore_strided_1xi64(&Ciphertext_result->values[0][i][j+t], v_result_0_1, 4, max_gvl);
               

      
                        v_U = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j],4,max_gvl);          
                        v_V = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j+t],4,max_gvl);
                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                        // Reduction v_V
                        
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                        } 
                        
                        
                        v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);
                        
                        // Reduction v_result_0_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                        {                       
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                        }                 
                        
                        //store results 
                        __builtin_epi_vstore_strided_1xi64(&Ciphertext_result->values[1][i][j], v_result_0_0, 4, max_gvl);
                 
                 
                 
                        v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);

                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                             
                             
                        //store results
                        __builtin_epi_vstore_strided_1xi64(&Ciphertext_result->values[1][i][j+t], v_result_0_1, 4, max_gvl);        
                        
                
                        
               
                }
               
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);
                
                m=2*m
                
                
                
                
                
                
                
                
                
                
                
                
                
                // last loop
                printf("\t loop1 : m = %d\n",m);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                
                for(uint32_t j=0;j<m; j+=max_gvl) 
                {
                        __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(&S_psi[m + j], max_gvl);         
                        __epi_1xi64 v_U = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j],2,max_gvl);
                        __epi_1xi64 v_V = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j+t],2,max_gvl);
                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                        // Reduction v_V
                        
                        __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                        {                       
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                        } 
                           
                        __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);
                        
                        // Reduction v_result_0_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                        {                       
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                        }                 
                        
                        //store results 
                        __builtin_epi_vstore_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j], v_result_0_0, 2, max_gvl);
                     
                        __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);

                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                             
                             
                        //store results
                        __builtin_epi_vstore_strided_unsigned_1xi64(&Ciphertext_result->values[0][i][j+t], v_result_0_1, 2, max_gvl);
               
      
                        v_U = __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j],2,max_gvl);          
                        v_V =  __builtin_epi_vload_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j+t],2,max_gvl);
                        v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                        // Reduction v_V
                        
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                        {                       
                                v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                        }                       
                        
                        v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);
                        
                        // Reduction v_result_0_0
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);   
                        while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                        {                       
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                        }                 
                        
                        //store results 
                        __builtin_epi_vstore_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j], v_result_0_0, 2, max_gvl);
                                 
                        v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);

                        // Reduction ciphertext_ans_1
                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                        v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                                          
                        //store results
                        __builtin_epi_vstore_strided_unsigned_1xi64(&Ciphertext_result->values[1][i][j+t], v_result_0_1, 2, max_gvl);
               
                }
               
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);            
                
        }
        return 0;
}
*/

/*

// This test consists of checking if the segmentation fault is caused by v_V
int ntt_cooley_tukey_vectorial_masks_test_1(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        int mask_aux[256];
        int index_values_S[512];
        
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, max_gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], max_gvl);       
                
                uint32_t m =1;
                
                printf("\t loop1 : m = %d\n",m);
                fflush(stdout);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);                      
                fflush(stdout);
        
        
                m = 2;
                printf("\t loop1 : m = %d\n",m);
                        
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {                
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);      
                fflush(stdout);
        
                for(m=4; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);                      
                        fflush(stdout);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
             
                        for(int j=0;j<256;j++)
                                mask_aux[j] = !(1 & (j/t));
                        
                        for(int j=0;j<512;j++)
                                index_values_S[j]= m + j/(t*2);   // (/2??? or *2)   
                        
                        __epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);                      
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                                               
                        for (uint32_t k = 0; k < 1024; k+=max_gvl) 
                        {
                                __epi_1xi64 v_S_index = __builtin_epi_vload_unsigned_1xi64(&index_values_S[k], max_gvl); 
                                __epi_1xi64 v_S = __builtin_epi_vload_indexed_1xi64(&S_psi[0], v_S_index, max_gvl);
                                
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k],v_mask_not,max_gvl);
                                
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k],v_mask_not,max_gvl);   
                                
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                                }
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k], v_result_0_0,v_mask_not, max_gvl);

                                                
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                         
                                       
                                //store results
                               // __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k+t], v_result_0_1,v_mask_not, max_gvl);  
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k],v_mask_not,max_gvl);
                                
                                v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k],v_mask_not,max_gvl);   
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);
                                }  
                                 

                                 //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k], v_result_1_0,v_mask_not, max_gvl);                                 
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, max_gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, max_gvl);
                                         
                                         
                                //store results
                                //__builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k+t], v_result_1_1,v_mask_not, max_gvl);
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);      
                        fflush(stdout);
                        
                }
        }
        return 0;
}

*/

/*
// This test consists of checking if the segmentation fault is caused by the two first loops
int ntt_cooley_tukey_vectorial_masks_test_2(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;

        int mask_aux[256];
        int index_values_S[512];
        
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, max_gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], max_gvl);       
                
                uint32_t m =1;
                
                printf("\t loop1 : m = %d\n",m);
                fflush(stdout);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);                      
                fflush(stdout);
        
        
                m = 2;
                printf("\t loop1 : m = %d\n",m);
                        
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {                
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);      
                fflush(stdout);
        
        }
        return 0;
}
*/

/*
// This test consists of checking the values of the masks and indexes
int ntt_cooley_tukey_vectorial_masks_test_3(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;

        
        
        int mask_aux[256];
        int index_values_S[512];
        
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, max_gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], max_gvl);       
                
                uint32_t m =1;
                
                printf("\t loop1 : m = %d\n",m);
                fflush(stdout);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);                      
                fflush(stdout);
        
        
                m = 2;
                printf("\t loop1 : m = %d\n",m);
                        
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {                
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);      
                fflush(stdout);
        
                for(m=4; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);                      
                        fflush(stdout);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
                        
                        printf("mask_for_processing:\n");
                        printf("[");
                        for(int j=0;j<256;j++)
                        {
                                mask_aux[j] = !(1 & (j/t));
                                printf("%d ", mask_aux[j]);
                                
                        }
                        printf("]\n");
                        
                        
                        
                        
                         printf("Indexes_for_S:\n");
                        printf("[");
                        for(int j=0;j<512;j++)
                        {
                                index_values_S[j]= m + j/(t*2);   // (/2??? or *2)   
                                printf("%d ",index_values_S[j]);
                        }
                        printf("]\n");
                        
                        //__epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);                      
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                                               
                       
                       
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);      
                        fflush(stdout);
                        
                }
        }
        return 0;
}
*/

/*
int ntt_cooley_tukey_vectorial_index(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;

        int index_values_U[512];
        int index_values_V[512];
        int index_values_S[512];
        
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        //uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], gvl);       
                
                uint32_t m =1;
                
                printf("\t loop1 : m = %d\n",m);
                        
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);                      
                fflush(stdout);
        
        
                m = 2;
                printf("\t loop1 : m = %d\n",m);
                        
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {                
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);      
                fflush(stdout);
        
        
                gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
                for(m=4; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);                      
                        fflush(stdout);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
        
                        for(int j=0;j<512;j++)
                               index_values_S[j]= m + j/t;
                        
                        for(int j=0;j<t;j++)
                        {
                                for(int k=0;k<(m);k++)
                                {
                                        index_values_U[k*t + i] = k*t*2 + i;    
                                        index_values_V[k*t + i] = t + k*t*2 + i;
                                }
                        }                        
                        for (uint32_t k = 0; k < 2; k ++) 
                        {
                                __epi_1xi64 v_U_index = __builtin_epi_vload_unsigned_1xi64(&index_values_U[k*256], gvl);
                                __epi_1xi64 v_V_index = __builtin_epi_vload_unsigned_1xi64(&index_values_V[k*256], gvl);
                                __epi_1xi64 v_S_index = __builtin_epi_vload_unsigned_1xi64(&index_values_S[k*256], gvl);
                                
                                __epi_1xi64 v_U = __builtin_epi_vload_indexed_1xi64(&Ciphertext_result->values[0][i][0], v_U_index, gvl);    
                                __epi_1xi64 v_V = __builtin_epi_vload_indexed_1xi64(&Ciphertext_result->values[0][i][0], v_V_index, gvl);  
                                __epi_1xi64 v_S = __builtin_epi_vload_indexed_1xi64(&S_psi[0], v_S_index, gvl);  
                                
                                
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                //__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, max_gvl);      
                                __builtin_epi_vstore_indexed_1xi64(&Ciphertext_result->values[0][i][0],v_result_0_0, v_U_index, gvl);
                                
                                
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                //__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, max_gvl);   
                                __builtin_epi_vstore_indexed_1xi64(&Ciphertext_result->values[0][i][0],v_result_0_1, v_V_index, gvl);

                                
                                       
                                v_U = __builtin_epi_vload_indexed_1xi64(&Ciphertext_result->values[1][i][0], v_U_index, gvl);    
                                v_V = __builtin_epi_vload_indexed_1xi64(&Ciphertext_result->values[1][i][0], v_V_index, gvl); 
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                //__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, max_gvl);    
                                __builtin_epi_vstore_indexed_1xi64(&Ciphertext_result->values[1][i][0],v_result_1_0, v_U_index, gvl);
                                
                                
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                //__builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, max_gvl);  
                                __builtin_epi_vstore_indexed_1xi64(&Ciphertext_result->values[1][i][0],v_result_1_1, v_V_index, gvl);      
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);   
                        fflush(stdout);
                }
        }
        return 0;
}

*/


/*
int ntt_cooley_tukey_vectorial_masks(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        int mask_aux[256];
        int index_values_S[512];
        
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, max_gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], max_gvl);       
                
                uint32_t m =1;
                
                printf("\t loop1 : m = %d\n",m);
                fflush(stdout);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);                      
                fflush(stdout);
        
        
                m = 2;
                printf("\t loop1 : m = %d\n",m);
                        
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {                
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);      
                fflush(stdout);
        
                for(m=4; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);                      
                        fflush(stdout);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
             
                        for(int j=0;j<256;j++)
                                mask_aux[j] = !(1 & (j/t));
                        
                        for(int j=0;j<512;j++)
                                index_values_S[j]= m + j/(t*2);   // (/2??? or *2)   
                        
                        __epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);                      
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                                               
                        for (uint32_t k = 0; k < 1024; k+=max_gvl) 
                        {
                                __epi_1xi64 v_S_index = __builtin_epi_vload_unsigned_1xi64(&index_values_S[k], max_gvl); 
                                __epi_1xi64 v_S = __builtin_epi_vload_indexed_1xi64(&S_psi[0], v_S_index, max_gvl);
                                
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k],v_mask_not,max_gvl);
                                
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k+t],v_mask_not,max_gvl);   
                                
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                                }
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k], v_result_0_0,v_mask_not, max_gvl);

                                                
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k+t], v_result_0_1,v_mask_not, max_gvl);  
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k],v_mask_not,max_gvl);
                                
                                v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k+t],v_mask_not,max_gvl);   
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);
                                }  
                                 

                                 //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k], v_result_1_0,v_mask_not, max_gvl);                                 
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, max_gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, max_gvl);
                                         
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k+t], v_result_1_1,v_mask_not, max_gvl);
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);      
                        fflush(stdout);
                        
                }
        }
        return 0;
}
*/

/*

// This function tries to work with the gvl change in the V and stores
int ntt_cooley_tukey_vectorial_masks_correct_1(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        int mask_aux[256];
        int index_values_S[512];
        
        int S_psi[stop_value];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, max_gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], max_gvl);       
                
                uint32_t m =1;
                
                printf("\t loop1 : m = %d\n",m);
                fflush(stdout);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);                      
                fflush(stdout);
        
        
                m = 2;
                printf("\t loop1 : m = %d\n",m);
                        
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {                
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);      
                fflush(stdout);
        
                for(m=4; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);                      
                        fflush(stdout);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
             
                        for(int j=0;j<256;j++)
                                mask_aux[j] = !(1 & (j/t));
                        
                        for(int j=0;j<512;j++)
                                index_values_S[j]= m + j/(t*2);   // (/2??? or *2)   
                        
                        __epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);                      
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                                               
                        for (uint32_t k = 0; k < 1024; k+=max_gvl) 
                        {
                                __epi_1xi64 v_S_index = __builtin_epi_vload_unsigned_1xi64(&index_values_S[k], max_gvl); 
                                __epi_1xi64 v_S = __builtin_epi_vload_indexed_1xi64(&S_psi[0], v_S_index, max_gvl);
                                
                                
                                
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k],v_mask_not,max_gvl);
                                
                                gvl = __builtin_epi_vsetvl(stop_value - (k+t), __epi_e64, __epi_m1); 
                                
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k + t],v_mask_not,gvl);   
                                
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                                }
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k], v_result_0_0,v_mask_not, max_gvl);

                                                
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                         
                                       
                                //store results
                               __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k+t], v_result_0_1,v_mask_not, gvl);  
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k],v_mask_not,max_gvl);
                                
                                v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k+t],v_mask_not,gvl);   
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);
                                }  
                                 

                                 //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k], v_result_1_0,v_mask_not, max_gvl);                                 
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, max_gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, max_gvl);
                                         
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k+t], v_result_1_1,v_mask_not, gvl);
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);      
                        fflush(stdout);
                        
                }
        }
        return 0;
}

*/


// This function tries to work with the gvl change in the V and stores and changes the mask stuff
int ntt_cooley_tukey_vectorial_masks_correct_2(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result)
{
       
        const uint32_t stop_value = Ciphertext_to_transform.polynomial_degree_modulus;
        const uint8_t rns_number = Ciphertext_to_transform.rns_number;        
        
        struct timing_variable timing_variable_ntt_1; 
        timing_variable_ntt_1.polynomial_degree_modulus = stop_value;
        uint64_t mask_aux[256];
        int index_values_S[512];
        uint64_t array_zero[256];
        uint64_t S_psi[stop_value];
        uint64_t S_values_psi[1024];
        uint32_t gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);
        uint32_t max_gvl = __builtin_epi_vsetvl(stop_value, __epi_e64, __epi_m1);        
        
        for(uint8_t i=0; i<rns_number;i++)
        {
                int t = stop_value;
                for(uint32_t j=0; j< stop_value;j++)
                {
                        Ciphertext_result->values[0][i][j] = Ciphertext_to_transform.values[0][i][j];
                        Ciphertext_result->values[1][i][j] = Ciphertext_to_transform.values[1][i][j];
                        S_psi[j] = pow_mod(psi,reverseBits(j),Ciphertext_result->coefficient_modulus[i]);
                }   
                

                __epi_1xi64 v_initialize = __builtin_epi_vbroadcast_1xi64(0, max_gvl);   
                __epi_1xi64 v_coef_mod = __builtin_epi_vbroadcast_1xi64(Ciphertext_result->coefficient_modulus[i], max_gvl);       
                
                uint32_t m =1;
                
                printf("\t loop1 : m = %d\n",m);
                fflush(stdout);
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);                      
                fflush(stdout);
        
        
                m = 2;
                printf("\t loop1 : m = %d\n",m);
                        
                start_timing(&(timing_variable_ntt_1));
                t = t/2;
                                              
                for(uint32_t j=0;j<m;j++)
                {  
                        uint32_t auxj1 = 2*j*t; 
                        uint32_t auxj2 = auxj1+t-1;                     
                        __epi_1xi64 v_S = __builtin_epi_vbroadcast_1xi64(S_psi[m + j], gvl); 
                        for (uint32_t k = auxj1; k <= auxj2; k += gvl) 
                        {                
                                gvl = __builtin_epi_vsetvl(auxj2 - k + 1, __epi_e64, __epi_m1);                 
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k], gvl);
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[0][i][k + t], gvl);   
                                        
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                }                      
                                        
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);   
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k], v_result_0_0, gvl);      
                                                                                               
                                                                                               
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, gvl);
                                         
                                       
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[0][i][k+t], v_result_0_1, gvl);   
                                       
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k], gvl);
                                v_V = __builtin_epi_vload_unsigned_1xi64(&Ciphertext_result->values[1][i][k + t], gvl);
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, gvl);
                                } 
                                           
                                        
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,gvl))!=0)
                                {                       
                                        v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, gvl);
                                }  
                                        
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k], v_result_1_0, gvl);    
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, gvl);
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64(&Ciphertext_result->values[1][i][k+t], v_result_1_1, gvl);   
                              
                        }         
                }
                end_timing(&(timing_variable_ntt_1));
                printf("\t");
                print_timing(timing_variable_ntt_1);      
                fflush(stdout);
        
                for(m=4; m < stop_value; m=2*m)
                {
                        printf("\t loop1 : m = %d\n",m);                      
                        fflush(stdout);
                        start_timing(&(timing_variable_ntt_1));
                        t = t/2;
                        
                        fflush(stdout);
                        for(int j=0;j<256;j++)
                        {
                                array_zero[j]=0;
                                mask_aux[j] = !(1 & (j/t));
                        }
                        //for(int j=0;j<512;j++)
                        //        index_values_S[j]= m + j/(t*2);   // (/2??? or *2)   
                        
                         for(int j=0;j<1024;j++) // check if correct
                                S_values_psi[j]= S_psi[m + j/(t*2)];  
                        
                         fflush(stdout);
                        // S_values_psi
                        
                        __epi_1xi1 v_mask_not = __builtin_epi_vload_1xi1(&mask_aux[0]);    
                        __epi_1xi1 v_mask_zero = __builtin_epi_vload_1xi1(&array_zero[0]);                        
                        //__epi_1xi1 v_mask_not = __builtin_epi_vmnand_1xi1(v_mask, v_initialize,max_gvl);
                                               
                        for (uint32_t k = 0; k < 1024; k+=max_gvl) 
                        {

                                __epi_1xi64 v_S = __builtin_epi_vload_unsigned_1xi64(&S_values_psi[k], max_gvl);
                                
                                __epi_1xi64 v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k],v_mask_not,max_gvl);
                                
                                gvl = __builtin_epi_vsetvl(stop_value - (k+t), __epi_e64, __epi_m1); 
                                printf("gvl: %d\n",gvl);
                                                               
                                __epi_1xi64 v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[0][i][k + t],v_mask_not,gvl);
                                
                                printf("stop1\n"); 
                                fflush(stdout);
                                
                                v_V = __builtin_epi_vmul_1xi64_mask(v_initialize,v_V, v_S,v_mask_not, max_gvl);
                                
                                // Reduction v_V
                                __epi_1xi1 mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64_mask(v_mask_zero,v_coef_mod,v_V,v_mask_not, max_gvl);
                                }   


                                /*
                                        // Reduction v_V
                                        __epi_1xi64 v_q = __builtin_epi_vmulhu_1xi64(v_V, v_m, gvl);
                                        __epi_1xi64 v_aux1 = __builtin_epi_vmul_1xi64(v_q, v_coef_mod, gvl);
                                        v_V = __builtin_epi_vsub_1xi64(v_V, v_aux1, gvl);
                                        __epi_1xi1 mask = __builtin_epi_vmsle_1xi64(v_coef_mod, v_V, gvl);
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V, v_coef_mod, mask, gvl);
                                */
                                
                                
                                
                                printf("stop2\n");              
                                fflush(stdout);
                                   
                                __epi_1xi64 v_result_0_0 = __builtin_epi_vadd_1xi64_mask(v_initialize,v_U, v_V,v_mask_not,max_gvl);   
                                
                                // Reduction v_result_0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_0, max_gvl);
                                v_result_0_0 = __builtin_epi_vsub_1xi64_mask(v_result_0_0, v_result_0_0,v_coef_mod, mask, max_gvl);
                                
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k], v_result_0_0,v_mask_not, max_gvl);

                                                
                                 printf("stop3\n");
                                fflush(stdout);                                 
                                __epi_1xi64 v_result_0_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl);
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_0_1, max_gvl);
                                v_result_0_1 = __builtin_epi_vadd_1xi64_mask(v_result_0_1, v_result_0_1,v_coef_mod, mask, max_gvl);
                                         
                                       
                                //store results
                               __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[0][i][k+t], v_result_0_1,v_mask_not, gvl);  
                                 
                                printf("stop4\n");      
                                fflush(stdout);
                                // Second polynomial                                          
                                v_U = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k],v_mask_not,max_gvl);
                                
                                v_V = __builtin_epi_vload_unsigned_1xi64_mask(v_initialize,&Ciphertext_result->values[1][i][k+t],v_mask_not,gvl);   
                                         
                                v_V = __builtin_epi_vmul_1xi64(v_V, v_S, max_gvl);
                                       
                                // Reduction v_V
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);   
                                while((__builtin_epi_vmpopc_1xi1(mask,max_gvl))!=0)
                                {                       
                                        v_V = __builtin_epi_vsub_1xi64_mask(v_V, v_V,v_coef_mod, mask, max_gvl);
                                        mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_V, max_gvl);
                                } 
                                    
                                printf("stop5\n");   
                                fflush(stdout);         
                                
                                __epi_1xi64 v_result_1_0 = __builtin_epi_vadd_1xi64(v_U, v_V, max_gvl);    
                                // Reduction result0_0
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_0, max_gvl);
                                v_result_1_0 = __builtin_epi_vsub_1xi64_mask(v_result_1_0, v_result_1_0,v_coef_mod, mask, max_gvl);
                                 

                                 //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k], v_result_1_0,v_mask_not, max_gvl);                                 
                                        
                                        
                                __epi_1xi64 v_result_1_1 = __builtin_epi_vsub_1xi64(v_U, v_V, max_gvl); 
                                // Reduction ciphertext_ans_1
                                mask = __builtin_epi_vmsleu_1xi64(v_coef_mod,v_result_1_1, max_gvl);
                                v_result_1_1 = __builtin_epi_vadd_1xi64_mask(v_result_1_1, v_result_1_1,v_coef_mod, mask, max_gvl);
                                         
                                         
                                //store results
                                __builtin_epi_vstore_unsigned_1xi64_mask(&Ciphertext_result->values[1][i][k+t], v_result_1_1,v_mask_not, gvl);
                        
                        }
                        end_timing(&(timing_variable_ntt_1));
                        printf("\t");
                        print_timing(timing_variable_ntt_1);      
                        fflush(stdout);
                        
                }
        }
        return 0;
}



#endif






