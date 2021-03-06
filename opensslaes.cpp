// opensslaes.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
/*
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

static void hex_print(const void* pv, size_t len)
{
	const unsigned char * p = (const unsigned char*)pv;
	if (NULL == pv)
		printf("NULL");
	else
	{
		size_t i = 0;
		for (; i < len; ++i)
			printf("%02X ", *p++);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	int keylength;
	printf("Give a key length [only 128 or 192 or 256!]:\n");
	scanf_s("%d", &keylength);

	unsigned char *aes_key = (unsigned char*)malloc(sizeof(unsigned char) *keylength);
	memset(aes_key, 'X', keylength);
	if (!RAND_bytes(aes_key, keylength / 8))
		exit(-1);

	size_t inputslength = 0;
	printf("Give an input's length:\n");
	scanf_s("%lu", &inputslength);


	unsigned char *aes_input = (unsigned char*)malloc(sizeof(unsigned char) *inputslength);
	memset(aes_input, 'X', inputslength);

	unsigned char *iv_enc = (unsigned char*)malloc(sizeof(unsigned char) *AES_BLOCK_SIZE), *iv_dec = (unsigned char*)malloc(sizeof(unsigned char) *AES_BLOCK_SIZE);
	RAND_bytes(iv_enc, AES_BLOCK_SIZE);
	memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);


	const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char *enc_out = (unsigned char*)malloc(sizeof(unsigned char) *encslength);
	unsigned char *dec_out = (unsigned char*)malloc(sizeof(unsigned char) *inputslength);
	memset(enc_out, 0, sizeof(enc_out));
	memset(dec_out, 0, sizeof(dec_out));


	AES_KEY enc_key, dec_key;
	AES_set_encrypt_key(aes_key, keylength, &enc_key);
	AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);

	AES_set_decrypt_key(aes_key, keylength, &dec_key);
	AES_cbc_encrypt(enc_out, dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);

	printf("original:\t");
	hex_print(aes_input, inputslength);

	printf("encrypt:\t");
	hex_print(enc_out, encslength);

	printf("decrypt:\t");
	hex_print(dec_out, inputslength);

	return 0;
}
*/