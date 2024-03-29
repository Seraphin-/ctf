# Bioengeering 101 (bio 1496)

For this challenge, we had to design an mRNA hantavirus vaccine and explain it to the challenge admin. I ended up discussing a lot with the admin, but I will give a breakdown of what I submmited here:

## 5' UTR
The first thing in the sequence is the nucleotides `GA` representing the 5' cap (these are not actually standard nucleotides).

The 5' UTR is from a human muscle cell, HSPB2, and was taken from the dataset in this paper: https://www.nature.com/articles/s41467-021-24436-7

Then there is the Kozak consensus sequence.

## Gene
I used the G1=G2 glycoprotein, from https://www.ncbi.nlm.nih.gov/nuccore/NC_005219.1. The N protein may also have been a good choice.

https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7002362/ `During hantavirus infection, the Gn and Gc glycoproteins, but not nucleocapsid proteins (NP) are considered the major antigens in inducing neutralizing antibodies (nAb) production (Jiang et al., 2016).`

https://www.ncbi.nlm.nih.gov/pmc/articles/PMC8157935/  `We speculate that the intriguing observation of strong acute phase antibody response to N, an internal protein, similar to or even stronger than the membrane surface proteins Gn and Gc, might be explained by this conceptualization.`

https://virologyj.biomedcentral.com/articles/10.1186/s12985-020-1290-x `HTNV-NP, Gn and Gc have been shown to be strongly immunogenic, but the specific immune responses to HTNV-NP and GP are not completely consistent among different individuals.`

https://web.archive.org/web/20211105074424/https://journals.asm.org/doi/10.1128/mBio.02531-20 `The mature hantavirus surface presents higher-order tetrameric assemblies of two glycoproteins, Gn and Gc, which are responsible for negotiating host cell entry and constitute key therapeutic targets. Here, we demonstrate that recombinantly derived Gn from Hantaan virus (HTNV) elicits a neutralizing antibody response (serum dilution that inhibits 50% infection [ID50], 1:200 to 1:850) in an animal model.`

https://apps.dtic.mil/sti/citations/ADA448467 `The bunyavirus vaccines [...] HTNV expressed Gn and Gc genes, [...] although in general, the HTNV and CCHFV DNA vaccines were not very immunogenic in mice, there were no major differences in performance when given alone or in combination with the other vaccines.`

https://www.tandfonline.com/doi/pdf/10.4161/hv.7.6.15197 `Similar to the humoral response virus-reactive CD8 + T cells are mostly directed against immunodominant epitopes of the N protein although all hantaviral structural proteins (Gn, Gc, N) serve as a source for epitopes. 60 This may be due to the fact that the N protein represents the most conserved and abundant hanta-viral protein produced during infection.`

## 3' UTR

The 3' UTR was taken from the Pfizer covid vaccine. It is created by splicing together 3' UTRs from the human mtRNR1 and AES genes. https://www.ncbi.nlm.nih.gov/pmc/articles/PMC8310186/

## Final sequence
GATAAACTTAAGCTTGGTACCGCAACAACAAGCTTCACAAGACTGCATATATAAGGGGCTGGCTGTAGCTGCAGCTGAAGGAGCTGACCAGCCAGCTGACCCCGGAAGCGCCAGCCTGAACCGCCACCATGGGCATCTGGAAGTGGCTGGTGATGGCCAGCCTGGTGTGGCCCGTGCTGACCCTGAGAAACGTGTACGACATGAAGATCGAGTGCCCCCACACCGTGAGCTTCGGCGAGAACAGCGTGATCGGCTACGTGGAGCTGCCCCCCGTGCCCCTGGCCGACACCGCCCAGATGGTGCCCGAGAGCAGCTGCAACATGGACAACCACCAGAGCCTGAACACCATCACCAAGTACACCCAGGTGAGCTGGAGAGGCAAGGCCGACCAGAGCCAGAGCAGCCAGAACAGCTTCGAGACCGTGAGCACCGAGGTGGACCTGAAGGGCACCTGCGTGCTGAAGCACAAGATGGTGGAGGAGAGCTACAGAAGCAGAAAGAGCGTGACCTGCTACGACCTGAGCTGCAACAGCACCTACTGCAAGCCCACCCTGTACATGATCGTGCCCATCCACGCCTGCAACATGATGAAGAGCTGCCTGATCGCCCTGGGCCCCTACAGAGTGCAGGTGGTGTACGAGAGAAGCTACTGCATGACCGGCGTGCTGATCGAGGGCAAGTGCTTCGTGCCCGACCAGAGCGTGGTGAGCATCATCAAGCACGGCATCTTCGACATCGCCAGCGTGCACATCGTGTGCTTCTTCGTGGCCGTGAAGGGCAACACCTACAAGATCTTCGAGCAGGTGAAGAAGAGCTTCGAGAGCACCTGCAACGACACCGAGAACAAGGTGCAGGGCTACTACATCTGCATCGTGGGCGGCAACAGCGCCCCCATCTACGTGCCCACCCTGGACGACTTCAGAAGCATGGAGGCCTTCACCGGCATCTTCAGAAGCCCCCACGGCGAGGACCACGACCTGGCCGGCGAGGAGATCGCCAGCTACAGCATCGTGGGCCCCGCCAACGCCAAGGTGCCCCACAGCGCCAGCAGCGACACCCTGAGCCTGATCGCCTACAGCGGCATCCCCAGCTACAGCAGCCTGAGCATCCTGACCAGCAGCACCGAGGCCAAGCACGTGTTCAGCCCCGGCCTGTTCCCCAAGCTGAACCACACCAACTGCGACAAGAGCGCCATCCCCCTGATCTGGACCGGCATGATCGACCTGCCCGGCTACTACGAGGCCGTGCACCCCTGCACCGTGTTCTGCGTGCTGAGCGGCCCCGGCGCCAGCTGCGAGGCCTTCAGCGAGGGCGGCATCTTCAACATCACCAGCCCCATGTGCCTGGTGAGCAAGCAGAACAGATTCAGACTGACCGAGCAGCAGGTGAACTTCGTGTGCCAGAGAGTGGACATGGACATCGTGGTGTACTGCAACGGCCAGAGAAAGGTGATCCTGACCAAGACCCTGGTGATCGGCCAGTGCATCTACACCATCACCAGCCTGTTCAGCCTGCTGCCCGGCGTGGCCCACAGCATCGCCGTGGAGCTGTGCGTGCCCGGCTTCCACGGCTGGGCCACCGCCGCCCTGCTGGTGACCTTCTGCTTCGGCTGGGTGCTGATCCCCGCCATCACCTTCATCATCCTGACCGTGCTGAAGTTCATCGCCAACATCTTCCACACCAGCAACCAGGAGAACAGACTGAAGAGCGTGCTGAGAAAGATCAAGGAGGAGTTCGAGAAGACCAAGGGCAGCATGGTGTGCGACGTGTGCAAGTACGAGTGCGAGACCTACAAGGAGCTGAAGGCCCACGGCGTGAGCTGCCCCCAGAGCCAGTGCCCCTACTGCTTCACCCACTGCGAGCCCACCGAGGCCGCCTTCCAGGCCCACTACAAGGTGTGCCAGGTGACCCACAGATTCAGAGACGACCTGAAGAAGACCGTGACCCCCCAGAACTTCACCCCCGGCTGCTACAGAACCCTGAACCTGTTCAGATACAAGAGCAGATGCTACATCTTCACCATGTGGATCTTCCTGCTGGTGCTGGAGAGCATCCTGTGGGCCGCCAGCGCCAGCGAGACCCCCCTGACCCCCGTGTGGAACGACAACGCCCACGGCGTGGGCAGCGTGCCCATGCACACCGACCTGGAGCTGGACTTCAGCCTGACCAGCAGCAGCAAGTACACCTACAGAAGAAAGCTGACCAACCCCCTGGAGGAGGCCCAGAGCATCGACCTGCACATCGAGATCGAGGAGCAGACCATCGGCGTGGACGTGCACGCCCTGGGCCACTGGTTCGACGGCAGACTGAACCTGAAGACCAGCTTCCACTGCTACGGCGCCTGCACCAAGTACGAGTACCCCTGGCACACCGCCAAGTGCCACTACGAGAGAGACTACCAGTACGAGACCAGCTGGGGCTGCAACCCCAGCGACTGCCCCGGCGTGGGCACCGGCTGCACCGCCTGCGGCCTGTACCTGGACCAGCTGAAGCCCGTGGGCAGCGCCTACAAGATCATCACCATCAGATACAGCAGAAGAGTGTGCGTGCAGTTCGGCGAGGAGAACCTGTGCAAGATCATCGACATGAACGACTGCTTCGTGAGCAGACACGTGAAGGTGTGCATCATCGGCACCGTGAGCAAGTTCAGCCAGGGCGACACCCTGCTGTTCTTCGGCCCCCTGGAGGGCGGCGGCCTGATCTTCAAGCACTGGTGCACCAGCACCTGCCAGTTCGGCGACCCCGGCGACATCATGAGCCCCAGAGACAAGGGCTTCCTGTGCCCCGAGTTCCCCGGCAGCTTCAGAAAGAAGTGCAACTTCGCCACCACCCCCATCTGCGAGTACGACGGCAACATGGTGAGCGGCTACAAGAAGGTGATGGCCACCATCGACAGCTTCCAGAGCTTCAACACCAGCACCATGCACTTCACCGACGAGAGAATCGAGTGGAAGGACCCCGACGGCATGCTGAGAGACCACATCAACATCCTGGTGACCAAGGACATCGACTTCGACAACCTGGGCGAGAACCCCTGCAAGATCGGCCTGCAGACCAGCAGCATCGAGGGCGCCTGGGGCAGCGGCGTGGGCTTCACCCTGACCTGCCTGGTGAGCCTGACCGAGTGCCCCACCTTCCTGACCAGCATCAAGGCCTGCGACAAGGCCATCTGCTACGGCGCCGAGAGCGTGACCCTGACCAGAGGCCAGAACACCGTGAAGGTGAGCGGCAAGGGCGGCCACAGCGGCAGCACCTTCAGATGCTGCCACGGCGAGGACTGCAGCCAGATCGGCCTGCACGCCGCCGCCCCCCACCTGGACAAGGTGAACGGCATCAGCGAGATCGAGAACAGCAAGGTGTACGACGACGGCGCCCCCCAGTGCGGCATCAAGTGCTGGTTCGTGAAGAGCGGCGAGTGGATCAGCGGCATCTTCAGCGGCAACTGGATCGTGCTGATCGTGCTGTGCGTGTTCCTGCTGTTCAGCCTGGTGCTGCTGAGCATCCTGTGCCCCGTGAGAAAGCACAAGAAGAGCTAGCTCGAGCTGGTACTGCATGCACGCAATGCTAGCTGCCCCTTTCCCGTCCTGGGTACCCCGAGTCTCCCCCGACCTCGGGTCCCAGGTATGCTCCCACCTCCACCTGCCCCACTCACCACCTCTGCTAGTTCCAGACACCTCCCAAGCACGCAGCAATGCAGCTCAAAACGCTTAGCCTAGCCACACCCCCACGGGAAACAGCAGTGATTAACCTTTAGCAATAAACGAAAGTTTAACTAAGCTATACTAACCCCAGGGTTGGTCAATTTCGTGCCAGCCACACCCTGGAGCTAGC

## Flag
`X-MAS{f1v3-pr1m3-congr4tul4t1on5!!!-y0u_4r3_r34dy_f0r_pr3cl1n1nc4l-tr14ls!-c12ucr198c-thr33-pr1m3-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}`


