
// C++ code for the above approach:

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
 
 /*
// Calculates (a * b) % mod
uint64_t mul_mod(uint64_t a, uint64_t b,uint64_t mod)
{
    uint64_t res = 0;
    while (b > 0) {
        if (b & 1) {
            res = (res + a) % mod;
        }
        a = (a * 2) % mod;
        b >>= 1;
    }
    return res;
}
 
// Calculates (a^b) % mod
uint64_t pow_mod(uint64_t a, uint64_t b, uint64_t mod)
{
    uint64_t res = 1;
    a %= mod;
    while (b > 0) {
        if (b & 1) {
            res = mul_mod(res, a, mod);
        }
        a = mul_mod(a, a, mod);
        b >>= 1;
    }
    return res;
}
 
// Calculates Barrett reduction
// of x modulo mod
uint64_t barrett_reduce(uint64_t x,uint64_t mod, uint64_t mu)
{
    uint64_t q1 = x >> 32;
    uint64_t q2 = ((mu * q1) >> 32) * mod;
    uint64_t r1 = x & 0xffffffff;
    uint64_t r2 = mu * r1;
    uint64_t q3 = r2 >> 32;
    uint64_t r3 = r1 - q3 * mod;
    uint64_t res = r3 + ((r3 >> 63) & mod);
    if (res >= mod) {
        res -= mod;
    }
    return res;
}

*/



uint32_t barrett_reduction_unsigned(uint32_t value_to_reduce, uint32_t coefficient)
{
        if (coefficient ==12289)
        {
                uint64_t aux = 2863078532;                     
                uint64_t aux2 = (aux*value_to_reduce)>>45;
                uint32_t final = value_to_reduce - aux2*coefficient;
                if(final>= coefficient)
                        final -= coefficient;
               
                return final;
        
        }
        else
        {
                uint64_t test = (uint64_t) 1 << 45;
                uint64_t aux =   test / coefficient;      
                               
                uint64_t aux2 = (aux*value_to_reduce)>>45;
                uint32_t final = value_to_reduce - aux2*coefficient;
                if(final>= coefficient)
                        final -= coefficient;
               
                return final;   
                                
        }
}
 

uint32_t barrett_reduction_signed(int64_t value_to_reduce, uint32_t coefficient)
{
        uint32_t final = 0; 
        
        if(value_to_reduce>=0)        
        {
                if (coefficient ==12289)
                {
                        uint64_t aux = 2863078532;                     
                        uint64_t aux2 = (aux*(uint32_t)value_to_reduce)>>45;
                        final = value_to_reduce - aux2*coefficient;
                        if(final>= coefficient)
                                final -= coefficient;
               
                        return final;
        
                }
                else
                {
                        uint64_t test = (uint64_t) 1 << 45;
                        uint64_t aux = test / coefficient;                      
                        uint64_t aux2 = (aux*(uint32_t)value_to_reduce)>>45;
                        final = value_to_reduce - aux2*coefficient;
                        if(final>= coefficient)
                                final -= coefficient;
               
                        return final;   
                                
                }
        }
        else 
        {
                value_to_reduce = -value_to_reduce;
                
                if (coefficient ==12289)
                {
                        uint64_t aux = 2863078532;                     
                        uint64_t aux2 = (aux*(uint32_t)value_to_reduce)>>45;
                        final = value_to_reduce - aux2*coefficient;
                        if(final>= coefficient)
                                final -= coefficient;           
        
                }
                else
                {
                        uint64_t test = (uint64_t) 1 << 45;
                        uint64_t aux = test / coefficient;      
                               
                        uint64_t aux2 = (aux*(uint32_t)value_to_reduce)>>45;
                        final = value_to_reduce - aux2*coefficient;
                        if(final>= coefficient)
                                final -= coefficient;
                                
                }


                if(final != 0)
                        final -=  coefficient;
                
                return final;
   
        }
} 
 
 
 
 
 

int main()
{
       
        uint32_t q = 12289;
        uint64_t x = 1;     
        uint32_t final = 0;
        uint32_t compare_value = 0;
   
   
   
        for(uint64_t i=10000;i<100000;i++)
        {
                q += i;
                for(uint64_t j=q;j<q+10000;j++)
                {
                        x += j;
                        
                        final = barrett_reduction_signed(x,q);
                        //final = barrett_reduction_unsigned(x,q);
                        //compare_value = x % q;
                                               
                        //compare_value = x - (x/q)*q;
                        
                        compare_value = x ;
                        while(compare_value >= q)
                                compare_value -= q;
                        
                        
                        if(final == compare_value)
                                continue;
                        else 
                                printf("x:%lu q:%lu , barrett:%lu gcc mod:%lu\n",x,q, final, compare_value);
                
                
                }
        }
    



        
        /*
        uint32_t x2= 1804;
        uint32_t q2 = 92317;
        uint32_t compare_value_2 =0;
        compare_value_2 = x2 - (x2/q2)*q2;
        printf("%lu\n",compare_value_2);    


         //compare_value_2 = x2 % q2; 
        */



        /*
        for(uint64_t j=0;j<10000000;j++)
        {
                x += 1;
                final = barrett_reduction_signed(x,q);
                
                compare_value = x ;
                while(compare_value >= q)
                        compare_value -= q;
                        
             //   compare_value = x - (x/q)*q;
                
                if(final == compare_value)
                        continue;
                else 
                        printf("%lu , %lu H\n", final,compare_value);

        }
        */
        
 
    return 0;
}