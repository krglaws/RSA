
#ifndef _RSA_H_
#define _RSA_H_

#include <gmp.h>


// Public key type definition
typedef struct
{
  mpz_t m;
  mpz_t e;
} __rsa_publickey_struct;

typedef __rsa_publickey_struct rsa_pubkey_t[1];


// Private key type definition
typedef struct
{
  mpz_t m;
  mpz_t e;
} __rsa_privatekey_struct;

typedef __rsa_privatekey_struct rsa_privkey_t[1];


/* Called by rand_prime(). Reads in
   a byte from /dev/urandom */
static unsigned char rand_byte();


/* Called by rsa_init(). Generates a random
   prime number of a specified bit length */
static int rand_prime(mpz_t p, unsigned bits);


/* Initializes a public and a private key for use
   in rsa_encrypt() and rsa_decrypt() */
void rsa_init(rsa_pubkey_t pub, rsa_privkey_t priv);


/* Encrypts a character and stores the encrypted value
   into  a string. */
void rsa_encrypt(char* buffer, char c, rsa_pubkey_t pub);


/* Decrypts a string and returns the result as a char. */
char rsa_decrypt(char* buffer, rsa_privkey_t priv);


#endif

