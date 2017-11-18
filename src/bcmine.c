/* BCMine.c */ 
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdint.h>
#include <gmp.h>
#include <time.h>
#include "sha256.h"

struct bc_header {
	uint32_t nVer;
	uint8_t prev_blk_hash[32];
	uint8_t merkle_root_hash[32];
	uint32_t nTime;
	uint32_t nBits;
	uint32_t nNonce;
};

//convert hexstring to len bytes of data
//returns 0 on success, -1 on error
//data is a buffer of at least len bytes
//hexstring is upper or lower case hexadecimal, NOT prepended with "0x"
int hex2data(unsigned char *data, const unsigned char *hexstring, unsigned int len, int direction)
{
    unsigned const char *pos = hexstring;
    char *endptr;
    size_t count = 0;
    unsigned int limit;

    if ((hexstring[0] == '\0') || (strlen(hexstring) % 2)) {
        //hexstring contains no data
        //or hexstring has an odd length
        return -1;
    }
    limit = len/2;
	if (direction == 0) /* forwards */ 
	{
	    for(count = 0; count < limit; count++) {
	        char buf[5] = {'0', 'x', pos[0], pos[1], 0};
	        data[count] = strtol(buf, &endptr, 0);
	        pos += 2 * sizeof(char);
	
	        if (endptr[0] != '\0') {
	            //non-hexadecimal character encountered
	            return -1;
        	}
	     }
	}
	else /* backwards */
	{
	     for(count = 0; count < limit; count++) {
	        char buf[5] = {'0', 'x', pos[0], pos[1], 0};
	        data[(limit) - (count+1)] = strtol(buf, &endptr, 0);
	        pos += 2 * sizeof(char);
	
	        if (endptr[0] != '\0') {
	            //non-hexadecimal character encountered
	            return -1;
        	}
	     }
	}

    return 0;
}
 
struct bc_header bch;

int printf_array_hex(uint8_t *array, int len, int direction)
{
	uint8_t * pos;
	uint8_t * end;	
	if (direction == 0) /* forwards */ 
	{
		pos = array;
		end = pos + len;
		for ( ; pos != end; ++pos )
		{
   			printf("%02x", *pos);
		}
	}
	else /* backwards */
	{
		pos = array+(len -1);
		for ( ; pos >= array; --pos )
		{
   			printf("%02x", *pos);
		}
	}			

printf("\n");

}


int main()
{

char p_blk_hash[]="000000000000000117c80378b8da0e33559b5997f2ad55e2f7d18ec1975b9717";
char mkl_root_hash[]="871714dcbae6c8193a2bb9b2a69fe1c0440399f38d94b3a0f1b447275a29978a";

/*initialise block header */

bch.nVer = 2;
hex2data(bch.prev_blk_hash , p_blk_hash, strlen(p_blk_hash),1);
hex2data(bch.merkle_root_hash , mkl_root_hash, strlen(mkl_root_hash),1);
bch.nTime=0x53058b35;
bch.nBits=0x19015f53;
bch.nNonce=0;
/*bch.nNonce=856192328;*/   /*correct nonce */
/*            475000000 */ 
/*bch.nNonce=(856192328 - 1000001);*/
/*bch.nNonce=(856192328 - 1000); */
/* print out for check */
printf("Ver   = %u \n", bch.nVer);
printf("nTime = 0x%x \n", bch.nTime);
printf("nBits = 0x%x \n", bch.nBits);
printf("starting nNonce  = 0x%x %d  \n", bch.nNonce, bch.nNonce);
printf("prev_blk_hash    = 0x");
printf_array_hex(bch.prev_blk_hash, sizeof(bch.prev_blk_hash),1);
printf("merkle_root_hash = 0x");
printf_array_hex(bch.merkle_root_hash, sizeof(bch.merkle_root_hash),1);

/* Now do some work */
/* gmp multiple precision integer */
mpz_t target,zmant;
mpz_init (target);
mpz_init (zmant);
mp_bitcnt_t lshift;
/* Calculate target */
uint32_t exp, mant;
exp = bch.nBits >> 24;
mant = bch.nBits & 0x00ffffff;

mpz_set_ui (zmant, mant);
lshift = (8*(exp - 3));
mpz_mul_2exp (target, zmant, lshift);

gmp_printf ("Target           = 0x%064Zx\n", target);
/* gmp_printf ("Target = %Zd\n", target); */
/*
target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
mant * 2**(8*(exp - 3))
Function: void mpz_mul_2exp (mpz_t rop, const mpz_t op1, mp_bitcnt_t op2)

    Set rop to op1 times 2 raised to op2. This operation can also be defined as a left shift by op2 bits. 
*/
SHA256_CTX ctx1,ctx2,ctx3;

	int res;
	int idx;
	int pass = 1;
	BYTE hash1[SHA256_BLOCK_SIZE];
	BYTE hash2[SHA256_BLOCK_SIZE];
	
/* first hash */
	/* printf("Raw block Header\n"); */
	/*printf_array_hex((uint8_t *)&bch, sizeof(bch),0); */
	/*printf("\n"); */
int loop_count = 0;
clock_t start,end;
double cpu_time_used;

	mpz_t zhash;
	mpz_init (zhash);

	sha256_init(&ctx1);
	sha256_first(&ctx1, (const BYTE *) &bch);
	ctx2 = ctx1;	

start = clock();
 	while (!(res > 0))
	{
/*	sha256_init(&ctx1); 
	sha256_update(&ctx1, (const BYTE *) &bch, sizeof(bch)); 
	sha256_final(&ctx1, hash1); */ 
	sha256_second(&ctx2, hash1, (const BYTE *) &bch);
	ctx2 = ctx1; 

/* second hash */

	sha256_init(&ctx3);
	sha256_update(&ctx3, hash1, SHA256_BLOCK_SIZE);
	sha256_final(&ctx3, hash2);

/*Function: void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op) */
	mpz_import (zhash, 32, -1, 1, 0, 0, hash2);

	res = mpz_cmp (target, zhash);

	bch.nNonce = bch.nNonce + 1;
/*Compare op1 and op2. Return a positive value if op1 > op2, zero if op1 = op2, or a negative value if op1 < op2. */
/*	if (res > 0) {printf("Success\n");} else {printf("Fail\n");} */
	if(++loop_count == 1000000) {
		end=clock();
		loop_count=0;
		cpu_time_used = ((double) (end - start))/CLOCKS_PER_SEC;
		printf("End = %d Start= %d Clocks = %d\n",end,start, (end - start));
		printf("CPU secs per Mega hash = %f Mega hash per sec = %f\n",cpu_time_used, (1/cpu_time_used));
		printf("%d, ",bch.nNonce); 
		gmp_printf ("0x%064Zx\n", zhash); 
		start=clock();
	}
	}

 	gmp_printf ("Hash             = 0x%064Zx\n", zhash);
}

 

