/*! 
* \file 
* \details      This file implements the different CSUB operations      
* \date         2023 
* \warning      None of the functions implemented here check if the values of Ciphertext1 belong to the ring. 
* \warning      None of the functions implemented here check if the Ciphertext1 values arrays are correctly allocated.
* @param[in]    Ciphertext1, plaintext1         The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
#ifndef CSUB_H
#define CSUB_H



#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"

/*! 
* \brief        Performs the CSUB operation
* \details      Performs the CSUB operation, which consists of subtracting to a Ciphertext a plaintext, and afterwards performing a reduction to garantee that the result stays in the accepted ring.
*
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CSUB_naive(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);


/*! 
* \brief        Auto-vectorized version of the CSUB operation
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CSUB_naive_auto_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);


// MIGHT NOT WORK FOR NEGATIVE VALUES CAREFULL

/*! 
* \brief        Performs the CSUB barrett operation
* \details      Performs the CSUB barrett operation, which uses barrett reduction to acelerate the reduction of the final values.
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CSUB_barrett(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);


/*! 
* \brief        Auto-vectorized version of the CSUB_barrett operation
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CSUB_barrett_auto_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);








/*!  
* \brief        Vectorized version of the CSUB operation using intrisics
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CSUB_naive_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);


/*! 
* \brief        Version of CSUB_naive_vect but with loop unrolling
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CSUB_naive_vect_unroll(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);



/*!  
* \brief        Vectorized version of the CSUB_barrett operation using intrisics
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CSUB_barrett_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);


/*! 
* \brief        Version of CSUB_barrett_vect but with loop unrolling
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CSUB_barrett_vect_unroll(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);





#endif