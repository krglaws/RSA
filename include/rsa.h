
#ifndef _RSA_H_
#define _RSA_H_


// Public key type definition
typedef struct
{
  char m[64];
  char e[64];
} __rsa_publickey_struct;

typedef __rsa_publickey_struct rsa_pubkey_t[1];


// Private key type definition
typedef struct
{
  char m[64];
  char e[64];
} __rsa_privatekey_struct;

typedef __rsa_privatekey_struct rsa_privkey_t[1];


/* 
  Initializes a public and a private key for use
  in rsa_encrypt() and rsa_decrypt().

  param pub - public key
  param priv - private key
  param keylen - the approximate length in bits of the keys
  returns int, 0 on success, -1 on failure.

  NB: This procedure may fail for one of two reasons:
      1. The file '/dev/urandom' could not be opened, or
      2. An inverse of the public exponent does not exist.
*/
int rsa_init(rsa_pubkey_t pub, rsa_privkey_t priv, unsigned keylen);


/* Encrypts a character and stores the encrypted value
   into  a string. */
void rsa_encrypt(char* buffer, char c, rsa_pubkey_t pub);


/* Decrypts a string and returns the result as a char. */
char rsa_decrypt(char* buffer, rsa_privkey_t priv);


#endif

