#pragma once
#ifndef RSA_ALGORITHM_H
#define RSA_ALGORITHM_H

#define KEY_LENGTH 2048
#define PUBLIC_EXPONENT 59
#define PUBLIC_KEY_PEM 1
#define PRIVATE_KEY_PEM 0

#define LOG(x) cout<<x<<endl;

RSA *create_RSA(RSA *keypair, int pem_type, char *file_name);

int public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding);

int private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding);

void create_encrypted_file(char* encrypted, RSA * key_pair);
#endif 