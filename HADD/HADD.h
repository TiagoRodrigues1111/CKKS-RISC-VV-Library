/** 
* @file 
* @details      Implements the different HADD operations    
* @date         2023 
* @warning      None of the functions implemented here check if the values of Ciphertext1 and Ciphertext2 belong to the ring. 
* @warning      None of the functions implemented here check if the Ciphertexts values arrays are correctly allocated.
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result               The Ciphertext obtained after the operation
* @return       Return an error code, where 0 is success and anything else is failure
*/
#ifndef HADD_H
#define HADD_H

#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"

/** 
* @brief        Performs the HADD operation
* @details      Performs the HADD operation, which consists of adding two Ciphertexts together, and afterwards performing a reduction to garantee that the result stays in the accepted ring.
*
* @version      1.1
* @date         2023 
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result               The Ciphertext obtained after the operation
* @return                                       Return an error code, where 0 is success and anything else is failure
*/
int HADD(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


/*! 
* @brief        Performs the HADD Inline operation
* @details      Performs the HADD Inline operation, which is the inline version of the HADD_naive function
* @version      1.0
* @date         2023 
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* @return Return an error code, where 0 is success and anything else is failure
*/
extern int HADD_naive_inline(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


/*! 
* @brief        Auto-vectorized version of the HADD operation
* @version      1.1
* @date         2023 
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int HADD_auto_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);

int HADD_naive_auto_vect_2(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


/*!  
* @brief        Vectorized version of the HADD operation using intrisics
* @version      1.2
* @date         2023 
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int HADD_naive_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


/*! 
* @brief        Version of HADD_naive_vect but with loop unrolling
* @version      1.2
* @date         2023 
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int HADD_naive_vect_unroll(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


#endif


