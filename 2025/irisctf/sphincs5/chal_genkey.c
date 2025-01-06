
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

void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

int main(void) {
    FILE                *fp_req;
    unsigned char       entropy_input[48];
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    FILE* urandom = fopen("/dev/urandom", "r");
    fread(entropy_input, 1, 48, urandom);
    fclose(urandom);
    randombytes_init(entropy_input, NULL);

    printf(" === Params === \n");
    printf("SPX_N = %lu\n", SPX_N);
    printf("SPX_D = %lu\n", SPX_D);
    printf("SPX_FORS_BYTES = %lu\n", SPX_FORS_BYTES);
    printf("SPX_WOTS_BYTES = %lu\n", SPX_WOTS_BYTES);
    printf("SPX_WOTS_W = %lu\n", SPX_WOTS_W);
    printf("SPX_WOTS_LEN = %lu\n", SPX_WOTS_LEN);
    printf("SPX_WOTS_LEN1 = %lu\n", SPX_WOTS_LEN1);
    printf("SPX_WOTS_LEN2 = %lu\n", SPX_WOTS_LEN2);
    printf("SPX_WOTS_LOGW = %lu\n", SPX_WOTS_LOGW);
    printf("SPX_TREE_HEIGHT = %lu\n", SPX_TREE_HEIGHT);
    printf(" === ------ === \n");

    // Generate the public/private keypair
    if ( (ret_val = crypto_sign_keypair(pk, sk)) != 0) {
        printf("crypto_sign_keypair returned <%d>\n", ret_val);
        return -1;
    }
    fprintBstr(stdout, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);

    fp_req = fopen("key", "w");
    fwrite(pk, 1, CRYPTO_PUBLICKEYBYTES, fp_req);
    fwrite(sk, 1, CRYPTO_SECRETKEYBYTES, fp_req);
    fclose(fp_req);

    return 0;
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

