/*! 
* \file 
* \details      This file implements the different CADD operations as inplace
* \date         2023 
* \warning      None of the functions implemented here check if the values of Ciphertext1 belong to the ring. 
* \warning      None of the functions implemented here check if the Ciphertext1 values arrays are correctly allocated.
* @param[in]    Ciphertext1, plaintext1         The Ciphertexts to be used in the operation
* @param[out]   Ciphertext1                             The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
#ifndef CADD_INPLACE_H
#define CADD_INPLACE_H


#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"

/*! 
* \brief        Performs the CADD_inplace operation
* \details      Performs the CADD operation, which consists of adding a Ciphertext and a plaintext together, and afterwards performing a reduction to garantee that the result stays in the accepted ring.
*
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext1                         The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_naive_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);



/*! 
* \brief        Auto-vectorized version of the CADD operation
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext1                             The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_naive_auto_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);



/*! 
* \brief        Performs the CADD barrett operation
* \details      Performs the CADD barrett operation, which uses barrett reduction to acelerate the reduction of the final values.
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext1                             The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_barrett_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);


/*! 
* \brief        Auto-vectorized version of the CADD_barrett operation
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext1                             The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_barrett_auto_vect_inplace(struct ciphertext *Ciphertext1, struct plaintext plaintext1);






/*!  
* \brief        Vectorized version of the CADD operation using intrisics
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext1                             The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_naive_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);

/*! 
* \brief        Version of CADD_naive_vect but with loop unrolling
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext1                             The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_naive_vect_unroll_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);


/*!  
* \brief        Vectorized version of the CADD_barrett operation using intrisics
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext1                             The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_barrett_vect_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);


/*! 
* \brief        Version of CADD_barrett_vect but with loop unrolling
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext1                             The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_barrett_vect_unroll_inplace(struct ciphertext *Ciphertext1,struct plaintext plaintext1);






#endif


