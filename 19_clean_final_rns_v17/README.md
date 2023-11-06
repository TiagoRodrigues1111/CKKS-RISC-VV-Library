# 19_clean_final_rns_v17
  This is the original uploaded library that followed the development process of the disertation.

  
  

  
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


