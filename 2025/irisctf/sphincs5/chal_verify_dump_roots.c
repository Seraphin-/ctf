
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
#include "params.h"
#include "wots.h"
#include "fors.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
//#include "randombytes.h"
#include "utils.h"
#include "merkle.h"

void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

/**
 * Verifies a detached signature and message under a given public key.
 */
int x_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        fprintBstr(stdout, "\"", root, SPX_N);
        printf("\",");
        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
        fprintBstr(stdout, "\"", wots_pk, SPX_WOTS_BYTES);
        printf("\",[%u,%lu,", idx_leaf, tree);
        fprintBstr(stdout, "\"", wots_addr, sizeof(wots_addr));
        printf("\"],");
        sig += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);
        //fprintBstr(stdout, "\n! tree_addr= ", tree_addr, sizeof(tree_addr));
        //printf("\n");

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    fprintBstr(stdout, "\"", root, SPX_N);
    printf("\"");
    if (memcmp(root, pub_root, SPX_N)) {
        return -1;
    }

    return 0;
}


/**
 * Verifies a given signature-message pair under a given public key.
 */
int x_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smlen < SPX_BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - SPX_BYTES;

    if (x_crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, (size_t)*mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }
    return 0;
}

int main(int argc, const char** argv) {
    FILE* fp_req;
    unsigned char       entropy_input[48];
    unsigned char       *sm, *m1;
    unsigned long long  smlen, mlen1;
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;

    if(argc < 3) return -1;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    FILE* urandom = fopen("/dev/urandom", "r");
    fread(entropy_input, 1, 48, urandom);
    fclose(urandom);
    randombytes_init(entropy_input, NULL);

    fp_req = fopen(argv[1], "r");
    fread(pk, 1, CRYPTO_PUBLICKEYBYTES, fp_req);
    fread(sk, 1, CRYPTO_SECRETKEYBYTES, fp_req);

    fclose(fp_req);

    fp_req = fopen(argv[2], "r");
    fseek(fp_req, 0L, SEEK_END);
    smlen = ftell(fp_req);
    rewind(fp_req);
  
    m1 = (unsigned char *)calloc(smlen, sizeof(unsigned char));
    sm = (unsigned char *)calloc(smlen, sizeof(unsigned char));
    size_t rd = fread(sm, 1, smlen, fp_req);

    printf("[");
    ret_val = x_crypto_sign_open(m1, &mlen1, sm, smlen, pk);
    printf("]");

    fclose(fp_req);

    free(sm);
    free(m1);
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
}

