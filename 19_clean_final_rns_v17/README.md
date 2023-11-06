# 19_clean_final_rns_v17
  This is the original uploaded library that followed the development process of the dissertation. The different server-side operations are divided by directories for ease of developement. All of the client-side operations developed are coded in the keys implementation <a href=key_stuff.c>.c file</a> and declared in the corresponding <a href=key_stuff.h>.h file</a>. 

The implemented server-side functions are presented as follows:
<table class="tg">
<thead>
  <tr>
    <th class="tg-c3ow" colspan="5">Server side operations</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-0pky">Type:</td>
    <td class="tg-0pky">Operation:</td>
    <td class="tg-0pky">Given name:</td>
    <td class="tg-0pky">Scalar function name:</td>
    <td class="tg-0pky">Vector function name:</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-CT</td>
    <td class="tg-0pky">Addition</td>
    <td class="tg-0pky"><a href="HADD">HADD </a></td>
    <td class="tg-0pky">HADD</td>
    <td class="tg-0pky">HADD_naive_vect</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-PT</td>
    <td class="tg-0pky">Addition</td>
    <td class="tg-0pky"><a href="CADD">CADD </a></td>
    <td class="tg-0pky">CADD_mod_comp</td>
    <td class="tg-0pky">CADD_barrett_vect</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-CT</td>
    <td class="tg-0pky">Subtraction</td>
    <td class="tg-0pky"><a href="HSUB">HSUB </a></td>
    <td class="tg-0pky">HSUB</td>
    <td class="tg-0pky">HSUB_naive_vect</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-PT</td>
    <td class="tg-0pky">Subtraction</td>
    <td class="tg-0pky"><a href="CSUB">CSUB </a></td>
    <td class="tg-0pky">CSUB_barrett</td>
    <td class="tg-0pky">CSUB_barrett_vect</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-CT</td>
    <td class="tg-0pky">Diadic Multiplication</td>
    <td class="tg-0pky"><a href="HMULT">HMULT </a></td>
    <td class="tg-0pky">HMULT_barrett</td>
    <td class="tg-0pky">HMULT_barrett_vect</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-PT</td>
    <td class="tg-0pky">Diadic Multiplication</td>
    <td class="tg-0pky"><a href="CMULT">CMULT </a></td>
    <td class="tg-0pky">CMULT_barrett</td>
    <td class="tg-0pky">CMULT_barrett_vect</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-EK</td>
    <td class="tg-0pky">Relinearization/ Keyswitching</td>
    <td class="tg-0pky"><a href="RELINEARIZE">RELINEARIZE </a></td>
    <td class="tg-0pky">relinearize_barrett</td>
    <td class="tg-0pky">relinearize_barrett_vect</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-∆</td>
    <td class="tg-0pky">Rescaling</td>
    <td class="tg-0pky"><a href="RESCALE">RESCALE </a></td>
    <td class="tg-0pky">RESCALE</td>
    <td class="tg-0pky">RESCALE_vect</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-ψ</td>
    <td class="tg-0pky">Number Theoretic Transform</td>
    <td class="tg-0pky"><a href="NTT">NTT </a></td>
    <td class="tg-0pky">ntt_cooley_tukey_3_barrett_no_times</td>
    <td class="tg-0pky">ntt_cooley_tukey_vectorial_masks_correct_3_barrett_no_times_taux</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-ψ</td>
    <td class="tg-0pky">Inverse NTT</td>
    <td class="tg-0pky"><a href="NTT">INTT </a></td>
    <td class="tg-0pky">intt_gentleman_sande_barrett</td>
    <td class="tg-0pky">intt_gentleman_sande_vectorial_barrett</td>
  </tr>
  <tr>
    <td class="tg-0pky">CT-CT</td>
    <td class="tg-0pky">Coefficient Wise Multiplication</td>
    <td class="tg-0pky"><a href="CWM">CWM </a></td>
    <td class="tg-0pky">CWM_true_barrett</td>
    <td class="tg-0pky">CWM_true_vectorial_barrett</td>
  </tr>
</tbody>
</table>

The implemented client-side functions are presented as follows:

<table class="tg">
<thead>
  <tr>
    <th class="tg-0lax" colspan="3">client-side&nbsp;&nbsp;&nbsp;operation</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-0lax">Type:</td>
    <td class="tg-0lax">Operation:</td>
    <td class="tg-0lax">Given function name:</td>
  </tr>
  <tr>
    <td class="tg-0lax">SK-gen</td>
    <td class="tg-0lax">Secret key generation</td>
    <td class="tg-0lax">create_secret_key</td>
  </tr>
  <tr>
    <td class="tg-0lax">PK-gen</td>
    <td class="tg-0lax">Public key generation</td>
    <td class="tg-0lax">create_public_key_2</td>
  </tr>
  <tr>
    <td class="tg-0lax">EK-gen</td>
    <td class="tg-0lax">Evaluation key generation</td>
    <td class="tg-0lax">Create_relinearization_keys</td>
  </tr>
  <tr>
    <td class="tg-0lax">PT-PK</td>
    <td class="tg-0lax">Plaintext encryption</td>
    <td class="tg-0lax">encrypt</td>
  </tr>
  <tr>
    <td class="tg-0lax">CT-SK</td>
    <td class="tg-0lax">Ciphertext decryption</td>
    <td class="tg-0lax">decrypt</td>
  </tr>
</tbody>
</table>

In the directory <a href=tests>"tests"</a> a variety of prototype tests are presented for different operations, which allow the analysis of the output of a particular function, the comparison with another function, and the benchmarking of the operation time for a particular function.

The different files not present in specific directories are as follows:
+ <strong><a href=datastructures.h>datastructures.h</a></strong> : File containing the implementation of the different key structures.
+ <strong><a href=flags.h>flags.h</a></strong> : File containing the declaration of the different global flags. These flags can be turned on or off depending on enviroment.
+ <strong><a href=functions.h>functions.h</a></strong> : File containing the pointers to the different .h function files that were implemented. Can be changed depending on operation.
+  <strong><a href=initialization.h>initialization.h</a></strong> : File containing the declaration of different auxiliary functions to the library.
+  <strong><a href=initialization.c>initialization.c</a></strong> : File containing the implementation of the auxiliary functions to the library.
+  <strong><a href=key_stuff.c>key_stuff.c</a></strong> : File containing the implementation of the client-side operations, as well as their corresponding auxiliary functions.
+  <strong><a href=key_stuff.h>key_stuff.h</a></strong> : File containing the declaration of the client-side operations.
+ <strong><a href=benchmark_general_operations.c>benchmark_general_operations.c</a></strong> : deprecated file for testing previously implemented functions



