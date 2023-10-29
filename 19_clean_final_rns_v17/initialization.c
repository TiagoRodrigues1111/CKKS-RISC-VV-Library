
#include "initialization.h"
#include "flags.h"
// #include <inttypes.h>
// #include <stdint.h>
#define getName(var)  #var

#if WINDOWS
        #include <intrin.h>
        #pragma intrinsic(__rdtsc)      
#endif


int Create_ciphertext(struct ciphertext *Ciphertext_to_create, uint32_t Polynomial_Degree_Modulus, uint32_t *Coefficient_Modulus,uint64_t *barrett_aux_values, uint8_t number_of_polynomials, uint8_t rns_number)
{
        if(Polynomial_Degree_Modulus <= 0)
                return 1;
        if(Coefficient_Modulus == NULL)
                return 2;
        for(int i=0;i<rns_number;i++)
                if(Coefficient_Modulus[i]<=0)
                        return 3;
        if(number_of_polynomials <= 0)
                return 4;
        if(rns_number <= 0)
                return 5;
        
        Ciphertext_to_create->values = (uint64_t***) malloc(number_of_polynomials * sizeof(uint64_t**));
    
        Ciphertext_to_create->coefficient_modulus = (uint32_t*) malloc(rns_number * sizeof(uint32_t));
    
        Ciphertext_to_create->barrett_auxi_value = (uint64_t*) malloc(rns_number * sizeof(uint64_t));
    
        for(int i=0;i<number_of_polynomials;i++)
        {
                Ciphertext_to_create->values[i] = (uint64_t**) malloc(rns_number*sizeof(uint64_t*));
                /*
                if(Ciphertext_to_create->values[i] == NULL)
                {
                        for(int j=(i-1);j>=0;j--)
                        {
                                for(int l=();l>=0;l--)
                                {
                                        free(Ciphertext_to_create->values[j][l]);
                                }
                                free(Ciphertext_to_create->values[j]);
                        }
                        return (3+i);
                } 
                */        
                for(int k=0;k<rns_number;k++)
                {
                        Ciphertext_to_create->values[i][k] = (uint64_t*) malloc(Polynomial_Degree_Modulus*sizeof(uint64_t));
                        /*
                        if(Ciphertext_to_create->values[i][k] == NULL)
                        {
                                for(int j=(i-1);j>=0;j--)
                                {
                                        for(int l=();l>=0;l--)
                                        {
                                                free(Ciphertext_to_create->values[j][l]);
                                        }     
                                        free(Ciphertext_to_create->values[j]);
                                }
                                return (3+i);
                        }
                        */            
                } 
        }
     
        for(int i=0;i<rns_number;i++)
        {
                Ciphertext_to_create->coefficient_modulus[i] = Coefficient_Modulus[i];    

        }                
        for(int i=0;i<rns_number;i++)
        {
                Ciphertext_to_create->barrett_auxi_value[i] = barrett_aux_values[i];    
        }           
            
        
    
        Ciphertext_to_create->polynomial_degree_modulus = Polynomial_Degree_Modulus;
        Ciphertext_to_create->number_of_polynomials = number_of_polynomials;
        Ciphertext_to_create->rns_number = rns_number;
        return 0;
}

int Create_plaintext(struct plaintext *Plaintext_to_create, uint32_t Polynomial_Degree_Modulus)
{
    
        if(Polynomial_Degree_Modulus <= 0)
                return 1;
    
        Plaintext_to_create->values = (int64_t*) malloc(Polynomial_Degree_Modulus*sizeof(int64_t));
        if(Plaintext_to_create->values == NULL)
                return 2;   
    
        Plaintext_to_create->polynomial_degree_modulus = Polynomial_Degree_Modulus;     
        return 0;
}

/*
int Create_relinearization_keys_testt(struct relinearization_keys *relinearization_keys_to_create, uint32_t Polynomial_Degree_Modulus)
{
    int i=0;
    
    if(Polynomial_Degree_Modulus <= 0)
        return 1;
    
    relinearization_keys_to_create->values[0] = (int64_t*) malloc(Polynomial_Degree_Modulus*sizeof(int64_t));
    if(relinearization_keys_to_create->values[0] == NULL)
        return 3;   
    
    relinearization_keys_to_create->values[1] = (int64_t*) malloc(Polynomial_Degree_Modulus*sizeof(int64_t));
    if(relinearization_keys_to_create->values[1] == NULL)
    {
        free(relinearization_keys_to_create->values[0]);
        return 4;
    }   
    
    for(i=0;i<Polynomial_Degree_Modulus;i++)
    {
        relinearization_keys_to_create->values[0][i] = 1;
        relinearization_keys_to_create->values[1][i] = 1;   
    }
    relinearization_keys_to_create->Polynomial_Degree_Modulus = Polynomial_Degree_Modulus;  
    return 0;
    
}
*/


int check_ciphertext_values(struct ciphertext ciphertext_to_check)
{
    for (int i=0;i<ciphertext_to_check.number_of_polynomials;i++)
    {
        for(int j=0;j<ciphertext_to_check.rns_number;j++)
        {
            for(int k=0;k<ciphertext_to_check.polynomial_degree_modulus;k++)
            {
                if(ciphertext_to_check.values[i][j][k] >= ciphertext_to_check.coefficient_modulus[j])
                return 0;
            }
            
        }
    }
    return 1;
}

int initiate_to_random_ciphertext(struct ciphertext *Ciphertext_to_randomize)
{
    
    if (Ciphertext_to_randomize == NULL)
        return 1;
    
    for (int i=0;i<Ciphertext_to_randomize->number_of_polynomials;i++)
        for (int j=0;j<Ciphertext_to_randomize->rns_number;j++)
            for(int k=0;k<Ciphertext_to_randomize->polynomial_degree_modulus;k++)
                Ciphertext_to_randomize->values[i][j][k] = rand() % Ciphertext_to_randomize->coefficient_modulus[j];

    
    return 0;
}

int initiate_to_constant_ciphertext(struct ciphertext *Ciphertext_to_initialize,uint64_t value)
{
    if (Ciphertext_to_initialize == NULL)
        return 2;
    
    if(value <0)
        return 1;
    for(int i=0;i<Ciphertext_to_initialize->rns_number;i++)
        if(value >= Ciphertext_to_initialize->coefficient_modulus[i])
            return 2;
    
    
    for (int i=0;i<Ciphertext_to_initialize->number_of_polynomials;i++)
        for (int j=0;j<Ciphertext_to_initialize->rns_number;j++)
            for(int k=0;k<Ciphertext_to_initialize->polynomial_degree_modulus;k++)
                Ciphertext_to_initialize->values[i][j][k] = value;

    
    return 0;
}

int initiate_from_file_ciphertext(struct ciphertext *Ciphertext_to_initialize /*, char[] or file* */)
{
        
        
        
        return 0;
}

int initiate_to_random_plaintext(struct plaintext *plaintext_to_randomize,uint32_t Coefficient_Modulus)
{
    int i=0;    
    if(plaintext_to_randomize == NULL)
        return 2;
    
    for (i=0;i<plaintext_to_randomize->polynomial_degree_modulus;i++)
    {
        //plaintext_to_randomize->values[i] = (rand() % 4294967296) - 2147483648;
        plaintext_to_randomize->values[i] = rand() - (RAND_MAX/2);
        //plaintext_to_randomize->values[i] = rand()>> 16;
        //plaintext_to_randomize->values[i] += rand()>> 1;
        //plaintext_to_randomize->values[i] += (rand() & (1));
        
    }
    
    return 0;   
}

int initiate_to_constant_plaintext(struct plaintext *plaintext_to_initialize,int64_t value)
{
    int i=0;
    
    if(plaintext_to_initialize == NULL)
        return 2;
    
    if(value <0)
        return 1;
    
    for (i=0;i<plaintext_to_initialize->polynomial_degree_modulus;i++)
    {
        plaintext_to_initialize->values[i] = value;
    }
    
    return 0;
}


int print_ciphertext(struct ciphertext Ciphertext)
{
    int i=0;    
    printf("___________________________\n");
    printf("PRINTING CIPHERTEXT:\n");
//  printf("Name : %s", getName(Ciphertext));

    printf("Size:\t\t\t%d\n",Ciphertext.polynomial_degree_modulus);
    
    printf("Coefficent Modulus: [");
    for(int i=0;i<Ciphertext.rns_number;i++)
    {
        printf("%u",Ciphertext.coefficient_modulus[i]);
        if(i!=Ciphertext.rns_number-1)
            printf(" ");  
    }
    printf("]\n");
    
    
    printf("Number of polynomials:\t%d\n",Ciphertext.number_of_polynomials);
    for(int i=0;i<Ciphertext.number_of_polynomials;i++)
    {
        printf("Polynomial number %d:\n", i);

        for(int j=0;j<Ciphertext.rns_number;j++)
        {
            printf("[");
            for(int k=0;k<Ciphertext.polynomial_degree_modulus;k++)
            {
                printf("%lu",Ciphertext.values[i][j][k]);
                if(k!=Ciphertext.polynomial_degree_modulus-1)
                   printf(" ");     
            }
            printf("]\n");                 
        }
        printf("\n");
    }   
    return 0;
}

int print_plaintext(struct plaintext plaintext)
{   
    int i=0;    
    printf("___________________________\n");
    printf("PRINTING PLAINTEXT:\n");
//  printf("Name : %s", getName(Ciphertext));

    printf("Size: %d\n",plaintext.polynomial_degree_modulus);
    printf("[");
    for(i=0;i<plaintext.polynomial_degree_modulus;i++)
        {
            printf("%ld ",plaintext.values[i]);           
        }
        printf("\b]\n");

    
    return 0;
}

int free_ciphertext(struct ciphertext *Ciphertext)
{
    for(int i=0;i<Ciphertext->number_of_polynomials;i++)
    {
        if (Ciphertext->values[i] == NULL)
            printf("free_ciphertext: already free\n");
        else
        {
            for(int j=0;j<Ciphertext->rns_number;j++)
            {
                if (Ciphertext->values[i][j] == NULL)
                    printf("free_ciphertext: already free\n");
                else
                    free(Ciphertext->values[i][j]);        
            }
            free(Ciphertext->values[i]);    
        }    
    }
    return 0;
}

int free_plaintext(struct plaintext *plaintext)
{
    free(plaintext->values);
    
    
    return 0;
}

int free_relinearize_keys(struct relinearization_keys *relinearization_key)
{   
    if (relinearization_key->values[0] == NULL)
        printf("free_relinearize_keys: already free\n");
    else
        free(relinearization_key->values[0]);

    if (relinearization_key->values[1] == NULL)
        printf("free_relinearize_keys: already free\n");
    else    
        free(relinearization_key->values[1]);   
    
    return 0;
}

/*
int grab_console_values(int argc, char *argv[], uint32_t *Polynomial_Degree_Modulus, uint32_t *Coefficient_Modulus)
{


}
*/

int compare_ciphertext_values(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2)
{
    if(Ciphertext1.polynomial_degree_modulus !=Ciphertext2.polynomial_degree_modulus)
        return 2;
    if(Ciphertext1.number_of_polynomials != Ciphertext2.number_of_polynomials)
        return 3;
    if(Ciphertext1.rns_number != Ciphertext2.rns_number)
        return 4;
    
    for(int i=0;i<Ciphertext1.number_of_polynomials;i++)
        for(int j=0;j<Ciphertext1.rns_number;j++)
            for(int k=0;k<Ciphertext1.polynomial_degree_modulus;k++)
                if(Ciphertext1.values[i][j][k]!=Ciphertext2.values[i][j][k])
                    return 5;
    return 1;
}

#if RISCV_VECTORIAL

inline void start_timing(struct timing_variable *timing_variable1)
{
    __asm__ __volatile__("rdinstret %0" : "=r"(timing_variable1->start_instructions));
    __asm__ __volatile__("rdcycle %0"   : "=r"(timing_variable1->start_cycles));            
}

inline void end_timing(struct timing_variable *timing_variable1)
{
    __asm__ __volatile__("rdinstret %0" : "=r"(timing_variable1->end_instructions));
    __asm__ __volatile__("rdcycle %0"   : "=r"(timing_variable1->end_cycles));
}

#elif WINDOWS
        
inline void start_timing(struct timing_variable *timing_variable1)
{
        timing_variable1->start_cycles = __rdtsc();           
}

inline void end_timing(struct timing_variable *timing_variable1)
{
        timing_variable1->end_cycles = __rdtsc();
}

#else
        
inline void start_timing(struct timing_variable *timing_variable1)
{
                
}


inline void end_timing(struct timing_variable *timing_variable1)
{

}


#endif

/*
inline void start_timing(struct timing_variable *timing_variable1)
{
           
}

inline void end_timing(struct timing_variable *timing_variable1)
{

}
*/




void print_timing(struct timing_variable timing_variable1)
{
    
    printf("%lu\n", (timing_variable1.end_cycles-timing_variable1.start_cycles));
}

void print_timing_excel(struct timing_variable timing_variable1)
{
    printf("%d\t%lu\t%lu\n",timing_variable1.polynomial_degree_modulus,(timing_variable1.end_cycles-timing_variable1.start_cycles),(timing_variable1.end_instructions-timing_variable1.start_instructions));
}

void print_timing_poly(struct timing_variable timing_variable1)
{
    
    printf("%d\t%lu\n",timing_variable1.polynomial_degree_modulus,(timing_variable1.end_cycles-timing_variable1.start_cycles));
}




/* 
int barret_reduction(long ciphertext_value,int m, int k)
{
    int auxq=0;
    
    auxq = (ciphertext_value * m) >> k;
    ciphertext_value -= auxq * Ciphertext_result->Coefficient_Modulus;
    if (Ciphertext_result->Coefficient_Modulus <= Ciphertext_result->values[0][i]) 
    {
        Ciphertext_result->values[0][i] -= Ciphertext_result->Coefficient_Modulus;
    }
    
    return 0;
}
*/


