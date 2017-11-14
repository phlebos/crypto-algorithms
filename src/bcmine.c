/* BCMine.c */ 
#include "config.h"
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdint.h>
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
int hex2data(unsigned char *data, const unsigned char *hexstring, unsigned int len)
{
    unsigned const char *pos = hexstring;
    char *endptr;
    size_t count = 0;

    if ((hexstring[0] == '\0') || (strlen(hexstring) % 2)) {
        //hexstring contains no data
        //or hexstring has an odd length
        return -1;
    }

    for(count = 0; count < len; count++) {
        char buf[5] = {'0', 'x', pos[0], pos[1], 0};
        data[count] = strtol(buf, &endptr, 0);
        pos += 2 * sizeof(char);

        if (endptr[0] != '\0') {
            //non-hexadecimal character encountered
            return -1;
        }
    }

    return 0;
}
 
struct bc_header bch;

int printf_array_hex(uint8_t *array, int len)
{
	uint8_t * pos;
	uint8_t * end;	
	pos = array;
	end = pos + len;

	for ( ; pos != end; ++pos )
	{
   		printf("%02x", *pos);
	}
printf("\n");

}


int main()
{

char p_blk_hash[]="000000000000000117c80378b8da0e33559b5997f2ad55e2f7d18ec1975b9717";
char mkl_root_hash[]="871714dcbae6c8193a2bb9b2a69fe1c0440399f38d94b3a0f1b447275a29978a";

/*initialise block header */

bch.nVer = 2;
hex2data(bch.prev_blk_hash , p_blk_hash, strlen(p_blk_hash));
hex2data(bch.merkle_root_hash , mkl_root_hash, strlen(mkl_root_hash));
bch.nTime=0x53058b35;
bch.nBits=0x19015f53;
bch.nNonce=0;

/* print out for check */
printf("Ver = %u \n", bch.nVer);
printf("nTime = 0x%x \n", bch.nTime);
printf("nBits = 0x%x \n", bch.nBits);
printf("nNonce = 0x%x \n", bch.nNonce);
printf("prev_blk_hash = 0x");
printf_array_hex(bch.prev_blk_hash, sizeof(bch.prev_blk_hash));
printf("merkle_root_hash = 0x");
printf_array_hex(bch.merkle_root_hash, sizeof(bch.merkle_root_hash));

/* Now do some work */

SHA256_CTX ctx;

uint32_t Nonce;

	int idx;
	int pass = 1;
	BYTE buf[SHA256_BLOCK_SIZE];

	sha256_init(&ctx);
	sha256_update(&ctx, bch.prev_blk_hash, sizeof(bch.prev_blk_hash));
	sha256_final(&ctx, buf);
/*	pass = pass && !memcmp(hash2, buf, SHA256_BLOCK_SIZE); */

	printf("Hash = 0x");
	printf_array_hex(buf, sizeof(buf));
/*
	sha256_init(&ctx);
	for (idx = 0; idx < 100000; ++idx)
	   sha256_update(&ctx, text3, strlen(text3));
	sha256_final(&ctx, buf);
	pass = pass && !memcmp(hash3, buf, SHA256_BLOCK_SIZE);

	return(pass);
*/
}

 
/*

ver = 2
prev_block = "000000000000000117c80378b8da0e33559b5997f2ad55e2f7d18ec1975b9717"
mrkl_root = "871714dcbae6c8193a2bb9b2a69fe1c0440399f38d94b3a0f1b447275a29978a"
time_ = 0x53058b35 # 2014-02-20 04:57:25
bits = 0x19015f53
 
# https://en.bitcoin.it/wiki/Difficulty
exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
target_str = target_hexstr.decode('hex')
 
nonce = 0
while nonce < 0x100000000:
    header = ( struct.pack("<L", ver) + prev_block.decode('hex')[::-1] +
          mrkl_root.decode('hex')[::-1] + struct.pack("<LLL", time_, bits, nonce))
    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    print nonce, hash[::-1].encode('hex')
    if hash[::-1] < target_str:
        print 'success'
        break
    nonce += 1
view rawmine.py hosted with ❤ by GitHub
*/

