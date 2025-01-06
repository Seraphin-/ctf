
//
//  Based on PQCgenKAT_sign.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/param.h>
#include "rng.h"
#include "api.h"

const char giveflag[] = "give me the flag";
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

int main(void) {
    FILE* fp_req;
    unsigned char       entropy_input[48];
    unsigned char       *sm, *m1;
    unsigned long long  smlen, mlen1;
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    FILE* urandom = fopen("/dev/urandom", "r");
    fread(entropy_input, 1, 48, urandom);
    fclose(urandom);
    randombytes_init(entropy_input, NULL);

    fp_req = fopen("solve_graftkey", "r");
    fread(pk, 1, CRYPTO_PUBLICKEYBYTES, fp_req);
    //fread(sk, 1, CRYPTO_SECRETKEYBYTES, fp_req);

    fclose(fp_req);

    fp_req = fopen("ver", "r");
    fseek(fp_req, 0L, SEEK_END);
    smlen = ftell(fp_req);
    rewind(fp_req);
  
    m1 = (unsigned char *)calloc(smlen, sizeof(unsigned char));
    sm = (unsigned char *)calloc(smlen, sizeof(unsigned char));
    size_t rd = fread(sm, 1, smlen, fp_req);

    ret_val = crypto_sign_open(m1, &mlen1, sm, smlen, pk);
    printf("crypto_sign_open returned <%d> for len %llu\n", ret_val, mlen1);

    /*if(ret_val == 0 && mlen1 == (sizeof(giveflag)-1) && memcmp(m1, giveflag, sizeof(giveflag)-1) == 0) {
        system("cat /flag");
        exit(0);
    }
    */

    fclose(fp_req);

    free(sm);
    free(m1);
    return ret_val;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

