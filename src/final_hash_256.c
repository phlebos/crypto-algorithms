/* BCMine.c */ 
#include "config.h"
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdint.h>
#include <gmp.h>
#include <time.h>
#include "sha256.h"

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
/* char p_first_hash[]="e6d91555891f9c0d0313625ff8cbfecc917063ade047c2eaf73e7a28862b127c"; */
char p_first_hash[]="7c122b86287a3ef7eac247e0ad637091ccfecbf85f6213030d9c1f895515d9e6";
	BYTE hash1[SHA256_BLOCK_SIZE];
	hex2data(hash1 , p_first_hash, strlen(p_first_hash),0);

	BYTE hash2[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx1;
	
	mpz_t zhash;
	mpz_init (zhash);

	mpz_import (zhash, 32, -1, 1, 0, 0, hash1);
        gmp_printf ("Hashing          = 0x%064Zx\n", zhash);
/*	sha256_init(&ctx1);
	sha256_first(&ctx1, p_first_hash);
	sha256_second(&ctx1, hash2, (const BYTE *) &bch);*/

	sha256_init(&ctx1); 
	sha256_update(&ctx1, hash1, SHA256_BLOCK_SIZE); 
	sha256_final(&ctx1, hash2);  

	mpz_import (zhash, 32, -1, 1, 0, 0, hash2);

        gmp_printf ("Hash             = 0x%064Zx\n", zhash);
}

 

