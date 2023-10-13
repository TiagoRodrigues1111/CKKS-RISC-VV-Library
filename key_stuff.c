
#include "key_stuff.h"



int create_public_key(struct secret_key secret_key,struct public_key * public_key_to_create,uint32_t Polynomial_Degree_Modulus, uint32_t Coefficient_Modulus)
{
        srand(0); // srand((unsigned) time(&t));
        
        int a[Polynomial_Degree_Modulus];
        int i=0,j=0;
        
        if(Polynomial_Degree_Modulus <= 0)
                return 1;
        if(Coefficient_Modulus <= 0)
                return 2;
        
        public_key_to_create->values[0] = (int64_t*) malloc(Polynomial_Degree_Modulus*sizeof(int64_t));
        if(public_key_to_create->values[0] == NULL)
                return 3;       
        
        public_key_to_create->values[1] = (int64_t*) malloc(Polynomial_Degree_Modulus*sizeof(int64_t));
        if(public_key_to_create->values[1] == NULL)
        {
                free(public_key_to_create->values[0]);
                return 4;
        }       
        
        for (i=0; i<Polynomial_Degree_Modulus;i++)
        {
                a[i] = rand() % Coefficient_Modulus ;
                public_key_to_create->values[0][i] = 0;
                public_key_to_create->values[1][i] = a[i];
        }
        
        for (i=0;i<Polynomial_Degree_Modulus;i++)
        {
                for(j=0;j<Polynomial_Degree_Modulus;j++)
                {       
                        public_key_to_create->values[0][((i+j) % Polynomial_Degree_Modulus)] += (-a[i]) * secret_key.values[j];                 
                }                       
        }
        
        for (i=0;i<Polynomial_Degree_Modulus;i++)
        {
                // public_key_to_create->values[0][i] += error;
                
                if (public_key_to_create->values[0][i]>0)
                {       
                        while(public_key_to_create->values[0][i] >= Coefficient_Modulus)
                                public_key_to_create->values[0][i] -= Coefficient_Modulus;
                }
                if (public_key_to_create->values[0][i]<0)
                {       
                        while(public_key_to_create->values[0][i] < 0)
                                public_key_to_create->values[0][i] += Coefficient_Modulus;
                }

        }
        
        public_key_to_create->polynomial_degree_modulus = Polynomial_Degree_Modulus;
        public_key_to_create->coefficient_modulus = Coefficient_Modulus;
        
        return 0;
};

int create_public_key_2(struct secret_key secret_key,struct public_key * public_key_to_create,uint32_t Polynomial_Degree_Modulus, uint32_t Coefficient_Modulus)
{
        srand(0); // srand((unsigned) time(&t));
        
        int a[Polynomial_Degree_Modulus];
        uint64_t auxiliary_array[2 * Polynomial_Degree_Modulus];
        
        int i=0,j=0;
        
        if(Polynomial_Degree_Modulus <= 0)
                return 1;
        if(Coefficient_Modulus <= 0)
                return 2;
        
        
        for (i=0;i<2*Polynomial_Degree_Modulus;i++)
        {
                auxiliary_array[i]=0;
        }       
        
        
        public_key_to_create->values[0] = (int64_t*) malloc(Polynomial_Degree_Modulus*sizeof(int64_t));
        if(public_key_to_create->values[0] == NULL)
                return 3;       
        
        public_key_to_create->values[1] = (int64_t*) malloc(Polynomial_Degree_Modulus*sizeof(int64_t));
        if(public_key_to_create->values[1] == NULL)
        {
                free(public_key_to_create->values[0]);
                return 4;
        }       
        
        for (i=0; i<Polynomial_Degree_Modulus;i++)
        {
                a[i] = rand() % Coefficient_Modulus ;
                public_key_to_create->values[0][i] = 0;
                public_key_to_create->values[1][i] = a[i];
        }
        
        for (i=0;i<Polynomial_Degree_Modulus;i++)
        {
                for(j=0;j<Polynomial_Degree_Modulus;j++)
                {       
                        auxiliary_array[i+j] += (-a[i]) * secret_key.values[j];                                 
                }                       
        }
        
        for (i=0;i<Polynomial_Degree_Modulus;i++)
        {
                public_key_to_create->values[0][i] = auxiliary_array[i] - auxiliary_array[Polynomial_Degree_Modulus+i];
                
                // public_key_to_create->values[0][i] += error;
                
                if (public_key_to_create->values[0][i]>0)
                {       
                        while(public_key_to_create->values[0][i] >= Coefficient_Modulus)
                                public_key_to_create->values[0][i] -= Coefficient_Modulus;
                }
                if (public_key_to_create->values[0][i]<0)
                {       
                        while(public_key_to_create->values[0][i] < 0)
                                public_key_to_create->values[0][i] += Coefficient_Modulus;
                }

        }
        public_key_to_create->polynomial_degree_modulus = Polynomial_Degree_Modulus;
        public_key_to_create->coefficient_modulus = Coefficient_Modulus;
        return 0;
};


int create_secret_key(struct secret_key * secret_key_to_create,uint32_t Polynomial_Degree_Modulus)
{
        srand(0); // srand((unsigned) time(&t));
        int i;
        if(Polynomial_Degree_Modulus <= 0)
                return 1;
        
        secret_key_to_create->values = (int8_t*) malloc(Polynomial_Degree_Modulus*sizeof(int8_t));
        if(secret_key_to_create->values == NULL)
                return 2;       
        
        
        for (i=0;i<Polynomial_Degree_Modulus;i++)
        {
                secret_key_to_create->values[i] = rand() % 3 - 1;
        }
        
        secret_key_to_create->polynomial_degree_modulus = Polynomial_Degree_Modulus;    
        return 0;
};


int encrypt(struct plaintext plaintext,struct public_key public_key,struct ciphertext * ciphertext_res)
{
        srand(0);
        
        int i=0,j=0;
        int u[ciphertext_res->polynomial_degree_modulus];
        uint64_t auxiliary_array[2][2 * ciphertext_res->polynomial_degree_modulus];
        // u ;
        // error1, error2;
        for(i=0;i<ciphertext_res->polynomial_degree_modulus;i++)
        {
                        u[i] = rand() % 2;      
        }
        
        for (i=0;i<2*ciphertext_res->polynomial_degree_modulus;i++)
        {
                auxiliary_array[0][i]=0;
                auxiliary_array[1][i]=0;
        }       
        

        for (i=0;i<ciphertext_res->polynomial_degree_modulus;i++)
        {
                for(j=0;j<ciphertext_res->polynomial_degree_modulus;j++)
                {       
                        auxiliary_array[0][i+j] += public_key.values[0][i] * u[j]; 
                        auxiliary_array[1][i+j] += public_key.values[1][i] * u[j];
                }
        }

        for (i=0;i<ciphertext_res->polynomial_degree_modulus;i++)
        {
                 
                ciphertext_res->values[0][i] = auxiliary_array[0][i] - auxiliary_array[0][ciphertext_res->polynomial_degree_modulus+i];
                ciphertext_res->values[1][i] = auxiliary_array[1][i] - auxiliary_array[1][ciphertext_res->polynomial_degree_modulus+i];
                ciphertext_res->values[0][i] += plaintext.values[i];     
                
                if (ciphertext_res->values[0][i]>0)
                {       
                        while(ciphertext_res->values[0][i] >= ciphertext_res->coefficient_modulus)
                                ciphertext_res->values[0][i] -= ciphertext_res->coefficient_modulus;
                }
                if (ciphertext_res->values[0][i]<0)
                {       
                        while(ciphertext_res->values[0][i] < 0)
                                ciphertext_res->values[0][i] += ciphertext_res->coefficient_modulus;
                }       
                if (ciphertext_res->values[1][i]>0)
                {       
                        while(ciphertext_res->values[1][i] >= ciphertext_res->coefficient_modulus)
                                ciphertext_res->values[1][i] -= ciphertext_res->coefficient_modulus;
                }
                if (ciphertext_res->values[1][i]<0)
                {       
                        while(ciphertext_res->values[1][i] < 0)
                                ciphertext_res->values[1][i] += ciphertext_res->coefficient_modulus;
                }
        }       
        return 0;
};
        
int decrypt(struct ciphertext ciphertext,struct secret_key secret_key,struct plaintext *plaintext_res)
{
        int i=0,j=0;
        uint64_t auxiliary_array[2 * plaintext_res->polynomial_degree_modulus];
        
        for (i=0;i<2*plaintext_res->polynomial_degree_modulus;i++)
        {
                auxiliary_array[i]=0;
        }
        
        
        
        for (i=0;i<plaintext_res->polynomial_degree_modulus;i++)
        {
                for(j=0;j<plaintext_res->polynomial_degree_modulus;j++)
                {
                        auxiliary_array[i+j] += ciphertext.values[1][i] * secret_key.values[j]; 
                }
        }
        
        for (i=0;i<plaintext_res->polynomial_degree_modulus;i++)
        {
                plaintext_res->values[i] = auxiliary_array[i] - auxiliary_array[plaintext_res->polynomial_degree_modulus+i];
                plaintext_res->values[i] += ciphertext.values[0][i];            
                if (plaintext_res->values[i]>0)
                {       
                        while(plaintext_res->values[i] >= ciphertext.coefficient_modulus)
                                plaintext_res->values[i] -= ciphertext.coefficient_modulus;
                }
                if (plaintext_res->values[i]<0)
                {       
                        while(plaintext_res->values[i] < 0)
                                plaintext_res->values[i] += ciphertext.coefficient_modulus;
                }
        }
        return 0;
};
        
                
int Create_relinearization_keys(struct relinearization_keys *relinearization_keys_to_create, uint32_t Polynomial_Degree_Modulus, struct secret_key secret_key, uint32_t Coefficient_Modulus)
{
        
        int a[Polynomial_Degree_Modulus];
        uint64_t auxiliary_array[2 * Polynomial_Degree_Modulus];
        
        int i=0,j=0;
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
        
        for (i=0;i<2*Polynomial_Degree_Modulus;i++)
        {
                auxiliary_array[i]=0;
        }
        
        
        for(i=0;i<Polynomial_Degree_Modulus;i++)
        {
                a[i] = rand() % Coefficient_Modulus ;
                relinearization_keys_to_create->values[0][i] = 0;
                relinearization_keys_to_create->values[1][i] = a[i];    
        }
        
        
        for (i=0;i<Polynomial_Degree_Modulus;i++)
        {
                for(j=0;j<Polynomial_Degree_Modulus;j++)
                {       
                        auxiliary_array[i+j] += (-a[i]) * secret_key.values[j];
                        auxiliary_array[i+j] += secret_key.values[i] * secret_key.values[j];
                        
                                        
                }                       
        }
        for (i=0;i<Polynomial_Degree_Modulus;i++)
        {
                relinearization_keys_to_create->values[0][i] = auxiliary_array[i] - auxiliary_array[Polynomial_Degree_Modulus+i];
                
                
                if (relinearization_keys_to_create->values[0][i]>0)
                {       
                        while(relinearization_keys_to_create->values[0][i] >= Coefficient_Modulus)
                                relinearization_keys_to_create->values[0][i] -= Coefficient_Modulus;
                }
                if (relinearization_keys_to_create->values[0][i]<0)
                {       
                        while(relinearization_keys_to_create->values[0][i] < 0)
                                relinearization_keys_to_create->values[0][i] += Coefficient_Modulus;
                }
        }
        relinearization_keys_to_create->polynomial_degree_modulus = Polynomial_Degree_Modulus;  
        return 0;
}