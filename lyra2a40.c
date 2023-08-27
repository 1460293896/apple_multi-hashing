#include "lyra2a40.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "crypto/sph_blake.h"
#include "crypto/sph_bmw.h"
#include "crypto/sph_groestl.h"
#include "crypto/sph_jh.h"
#include "crypto/sph_keccak.h"
#include "crypto/sph_skein.h"
#include "crypto/sph_luffa.h"
#include "crypto/sph_cubehash.h"
#include "crypto/sph_shavite.h"
#include "crypto/sph_simd.h"
#include "crypto/sph_echo.h"
#include "crypto/sph_hamsi.h"
#include "crypto/sph_fugue.h"
#include "crypto/sph_shabal.h"
#include "crypto/sph_whirlpool.h"
#include "crypto/sph_sha2.h"
#include "crypto/sph_haval.h"
#include "crypto/sph_streebog.h"
#include "crypto/sph_radiogatun.h"
#include "crypto/sph_panama.h"
#include "crypto/lyra2/Lyra2.h"

void lyra2a40_hash(const char* input, char* output, uint32_t len)
{
	
    unsigned char hash[128] = { 0 };
        unsigned char hashA[64] = { 0 };
        unsigned char hashB[64] = { 0 };
        static unsigned char pblank[1];
        uint512 output;
        int len = (pend - pbegin) * sizeof(pbegin[0]);

        sph_bmw512_context       ctx_bmw;
        sph_jh512_context        ctx_jh;
        sph_luffa512_context     ctx_luffa;
        sph_cubehash512_context  ctx_cubehash;
        sph_shavite512_context   ctx_shavite;
        sph_simd512_context      ctx_simd;
        sph_echo512_context      ctx_echo;
        sph_hamsi512_context     ctx_hamsi;
        sph_fugue512_context     ctx_fugue;
        sph_whirlpool_context    ctx_whirlpool;
        sph_gost512_context      ctx_gost;
        sph_skein512_context     ctx_skein;
        sph_shabal512_context    ctx_shabal;
        sph_sha256_context       ctx_sha;

        sph_cubehash512_init(&ctx_cubehash);
        sph_cubehash512(&ctx_cubehash, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), len);
        sph_cubehash512_close(&ctx_cubehash, (void*)hashB);

        LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
        LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

        sph_luffa512_init(&ctx_luffa);
        sph_luffa512(&ctx_luffa, (const void*) hashA, 64);
        sph_luffa512_close (&ctx_luffa, hash);

        if (hash[0] & 1) {
            sph_gost512_init(&ctx_gost);
            sph_gost512(&ctx_gost, (const void*)hash, 64);
            sph_gost512_close(&ctx_gost, (void*)hash);
        } else {
            sph_echo512_init(&ctx_echo);
            sph_echo512(&ctx_echo, (const void*)hash, 64);
            sph_echo512_close(&ctx_echo, (void*)hash);

            sph_echo512_init(&ctx_echo);
            sph_echo512(&ctx_echo, (const void*)hash, 64);
            sph_echo512_close(&ctx_echo, (void*)hash);
        }

        sph_simd512_init(&ctx_simd);
        sph_simd512(&ctx_simd, (const void*) hash, 64);
        sph_simd512_close(&ctx_simd, hash);

        sph_echo512_init(&ctx_echo);
        sph_echo512(&ctx_echo, (const void*) hash, 64);
        sph_echo512_close(&ctx_echo, hashB);

        LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
        LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

        sph_cubehash512_init(&ctx_cubehash);
        sph_cubehash512(&ctx_cubehash, (const void*) hashA, 64);
        sph_cubehash512_close(&ctx_cubehash, hash);

        sph_shavite512_init(&ctx_shavite);
        sph_shavite512(&ctx_shavite, (const void*) hash, 64);
        sph_shavite512_close(&ctx_shavite, hashB);

        LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
        LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

        sph_hamsi512_init(&ctx_hamsi);
        sph_hamsi512(&ctx_hamsi, (const void*) hashA, 64);
        sph_hamsi512_close(&ctx_hamsi, hash);

        sph_fugue512_init(&ctx_fugue);
        sph_fugue512(&ctx_fugue, (const void*) hash, 64);
        sph_fugue512_close(&ctx_fugue, hashB);

        LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
        LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

        sph_whirlpool_init(&ctx_whirlpool);
        sph_whirlpool (&ctx_whirlpool, (const void*) hashA, 64);
        sph_whirlpool_close(&ctx_whirlpool, hash);

        sph_skein512_init(&ctx_skein);
        sph_skein512(&ctx_skein, (const void*)hash, 64);
        sph_skein512_close(&ctx_skein, (void*)hashB);

        LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
        LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

        sph_shabal512_init(&ctx_shabal);
        sph_shabal512(&ctx_shabal, (const void*) hashA, 64);
        sph_shabal512_close(&ctx_shabal, hash);

        sph_sha256_init(&ctx_sha);
        sph_sha256(&ctx_sha, (const void*)hash, 64);
        sph_sha256_close(&ctx_sha, (void*)hash);

        sph_sha256_init(&ctx_sha);
        sph_sha256(&ctx_sha, (const void*)hash, 64);
        sph_sha256_close(&ctx_sha, (void*)hash);

        sph_bmw512_init(&ctx_bmw);
        sph_bmw512(&ctx_bmw, (const void*) hash, 64);
        sph_bmw512_close(&ctx_bmw, hash);

        sph_jh512_init(&ctx_jh);
        sph_jh512(&ctx_jh, (const void*) hash, 64);
        sph_jh512_close(&ctx_jh, hash);

        for (int i=0; i<32; i++)
            hash[i] ^= hash[i+32];

    memcpy(output, hash, 32);
}
