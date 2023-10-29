/*! 
* \file 
* \details      This file implements the different HSUB operations
* \version      1.5
* \date         2023 
* \warning      None of the functions implemented here check if the values of Ciphertext1 and Ciphertext2 belong to the ring. 
* \warning      None of the functions implemented here check if the Ciphertexts values arrays are correctly allocated.
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
#ifndef HSUB_H
#define HSUB_H

#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"



// It does + because it wraps to positives, IF it is uint64_t


/*! 
* \brief        Performs the HSUB operation
* \details      Performs the HSUB operation, which consists of subtracting one Ciphertext to another, and afterwards performing a reduction to garantee that the result stays in the accepted ring.
*
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int HSUB(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


/*! 
* \brief        Performs the HSUB Inline operation
* \details      Performs the HSUB Inline operation, which is the inline version of the HSUB_naive function
* \version      1.0
* \date         2023 
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int HSUB_naive_inline(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


/*! 
* \brief        Auto-vectorized version of the HSUB operation
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int HSUB_auto_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


/*!  
* \brief        Vectorized version of the HSUB operation using intrisics
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int HSUB_naive_vect(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);


/*! 
* \brief        Version of HSUB_naive_vect but with loop unrolling
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, Ciphertext2        The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int HSUB_naive_vect_unroll(struct ciphertext Ciphertext1,struct ciphertext Ciphertext2, struct ciphertext *Ciphertext_result);

#endif