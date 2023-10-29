#ifndef NTT_H
#define NTT_H


#include "../initialization.h"
#include "../datastructures.h"
#include "../flags.h"


// int ntt_and_intt_naive(struct ciphertext *Ciphertext_out,struct ciphertext Ciphertext1,);
// int ntt_ct_std2rev_naive(struct ciphertext *Ciphertext, const uint16_t *p) ;
// int test_stride(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
// int ntt_cooley_tukey_vectorial_masks_test_1(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
// int ntt_cooley_tukey_vectorial_masks_test_2(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
// int ntt_cooley_tukey_vectorial_masks_test_3(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
// int ntt_cooley_tukey_vectorial_index(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
// int ntt_cooley_tukey_vectorial_4(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
// int ntt_cooley_tukey_vectorial_masks(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
//int ntt_cooley_tukey_vectorial_masks_correct_3_barrett_seg_test(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);


int ntt_transform_naive(struct ciphertext *Ciphertext_to_transform,uint32_t root,uint32_t modulus);
int ntt_transform_naive_2(struct ciphertext Ciphertext_to_transform,uint32_t root,uint32_t modulus,struct ciphertext *Ciphertext_result);

int intt_transform_naive(struct ciphertext *Ciphertext_to_transform,uint32_t root,uint32_t modulus);
// int intt_transform_naive_2(struct ciphertext Ciphertext_to_transform,uint32_t root,uint32_t modulus,struct ciphertext *Ciphertext_result);

// int ntt_cooley_tukey(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
int ntt_cooley_tukey_2(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
int ntt_cooley_tukey_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);

int ntt_cooley_tukey_2_barrett(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
int ntt_cooley_tukey_3_barrett_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);


int intt_gentleman_sande(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);



int ntt_cooley_tukey_vectorial(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
int ntt_cooley_tukey_vectorial_2(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
int ntt_cooley_tukey_vectorial_masks_correct_2(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);


int ntt_cooley_tukey_vectorial_masks_correct_3_barrett(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);



int ntt_cooley_tukey_vectorial_masks_correct_3_barrett_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
int ntt_cooley_tukey_vectorial_masks_correct_3_barrett_no_times_taux(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
int ntt_cooley_tukey_vectorial_masks_correct_3_barrett_taux(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);

int ntt_cooley_tukey_vectorial_masks_correct_2_barrett(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);

int ntt_cooley_tukey_vectorial_masks_correct_4_barrett_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);

int ntt_cooley_tukey_vec_mask_5_bar_nt(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);


int ntt_cooley_tukey_vectorial_barrett(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
int ntt_cooley_tukey_vectorial_barrett_no_times(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);



int intt_gentleman_sande_vectorial(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);












// int ntt_cooley_tukey_vectorial_masks_correct_1(struct ciphertext Ciphertext_to_transform,uint32_t psi,struct ciphertext *Ciphertext_result);
















#endif