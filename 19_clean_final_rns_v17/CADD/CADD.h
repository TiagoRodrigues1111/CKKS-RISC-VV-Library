/*! 
* @file 
* @details      Implements the different CADD operations        
* @date         2023 
* @note         None of the functions implemented check if the values of Ciphertext1 belong to the ring. 
* @note         None of the functions implemented check if the Ciphertext1 values' arrays are correctly allocated.
* @param[in]    Ciphertext1, plaintext1         The Ciphertexts to be used in the operation
* @param[out]   Ciphertext_result               The Ciphertext obtained after the operation
* @return       Return an error code, where 0 is success and anything else is failure
*/
#ifndef CADD_H
#define CADD_H



#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"




/*! 
* \brief        Performs the CADD operation
* \details      Performs the CADD operation, which consists of adding a Ciphertext and a plaintext together, and afterwards performing a reduction to garantee that the result stays in the accepted ring.
*
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_naive(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);



/*! 
* \brief        Auto-vectorized version of the CADD operation
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_naive_auto_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);

int CADD_naive_auto_vect_2(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);

int CADD_naive_auto_vect_3(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);




/*! 
* \brief        Performs the CADD barrett operation
* \details      Performs the CADD barrett operation, which uses barrett reduction to acelerate the reduction of the final values.
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_barrett(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);


/*! 
* \brief        Auto-vectorized version of the CADD_barrett operation
* \version      1.1
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_barrett_auto_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);


int CADD_barrett_auto_vect_2(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);






/*!  
* \brief        Vectorized version of the CADD operation using intrisics
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_naive_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);

/*! 
* \brief        Version of CADD_naive_vect but with loop unrolling
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_naive_vect_unroll(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);



/*!  
* \brief        Vectorized version of the CADD_barrett operation using intrisics
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_barrett_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);


/*! 
* \brief        Version of CADD_barrett_vect but with loop unrolling
* \version      1.2
* \date         2023 
* @param[in]    Ciphertext1, plaintext1         The Ciphertext and plaintext to be used in the operation
* @param[out]   Ciphertext_result                       The Ciphertext obtained after the operation
* \return Return an error code, where 0 is success and anything else is failure
*/
int CADD_barrett_vect_unroll(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);


//int CADD_barrett_vect_test1(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);
//int CADD_barrett_vect_test2(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);
//int CADD_barrett_vect_test3(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);
//int CADD_barrett_vect_test4(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);
//int CADD_barrett_vect_test5(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);


// int CADD_naive_vect_test1(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);
// int CADD_naive_vect_test2(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);

int CADD_mod_comp(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);
int CADD_mod_comp_auto_vect(struct ciphertext Ciphertext1,struct plaintext plaintext1, struct ciphertext *Ciphertext_result);

#endif