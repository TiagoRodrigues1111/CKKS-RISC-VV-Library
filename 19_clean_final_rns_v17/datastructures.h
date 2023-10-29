#ifndef DATASTRUCTURES_H
#define DATASTRUCTURES_H






// #include <complex.h>    /* Standard Library of Complex Numbers */

struct ciphertext{
        uint64_t ***values;
        uint32_t polynomial_degree_modulus;
        uint32_t *coefficient_modulus;
        uint64_t *barrett_auxi_value;
        uint8_t number_of_polynomials;
        uint8_t rns_number;
        
        // char *ct_name;
};


struct plaintext{
        int64_t *values;
        uint32_t polynomial_degree_modulus;
        
        // char *pt_name;
};





struct relinearization_keys{
        int64_t *values[2];
        uint32_t polynomial_degree_modulus;
        
};


struct timing_variable{
        uint64_t start_cycles;  
        uint64_t end_cycles;
        uint64_t start_instructions;    
        uint64_t end_instructions;
        uint32_t polynomial_degree_modulus;
        // char *timing_name;
        
};

struct barrett_values{
        uint64_t m;
        uint64_t k;     
};


struct public_key{
        int64_t *values[2];
        uint32_t polynomial_degree_modulus;
        uint32_t coefficient_modulus;
};

struct secret_key{
        int8_t *values;
        uint32_t polynomial_degree_modulus;
};


struct complex_number
{
        double real; 
        double imaginary;
        
        
        
};

struct message
{
        struct complex_number *values;
        uint32_t polynomial_degree_modulus;     
};





#endif