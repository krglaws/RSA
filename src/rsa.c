
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <gmp.h>

#include <rsa.h>


/* Called by rand_prime(). Reads in
   a byte from /dev/urandom */
static unsigned char rand_byte()
{
  unsigned char byte = 0;
  FILE *urandom = fopen("/dev/urandom", "r");

  while (byte == 0)
    fread(&byte, 1, 1, urandom);

  fclose(urandom);

  return byte;
}


/* Called by rsa_init(). Generates a random
   prime number of a specified bit length */
static int rand_prime(mpz_t p, unsigned bits)
{
  mpz_init(p);

  uint64_t r;
  uint8_t *byte_arr = (uint8_t*) &r;

  for (int i = 0; i < 8; i++)
    byte_arr[i] = rand_byte();

  r >>= (64 - bits);
  r |= 1ULL << (bits - 1);

  mpz_set_ui(p, r);
  mpz_nextprime(p, p);
}


/* Initializes a public and a private key for use
   in rsa_encrypt() and rsa_decrypt(). */
int rsa_init(rsa_pubkey_t pub, rsa_privkey_t priv)
{
  mpz_t P, Q, N, L, E, D;

  mpz_init(P);
  mpz_init(Q);
  mpz_init(N);
  mpz_init(L);
  mpz_init(E);
  mpz_init(D);

  // Generate two random primes
  rand_prime(P, 64);
  rand_prime(Q, 64);

  // Multiply them to create modulus
  mpz_mul(N, P, Q);

  // Calculate lcm(P-1, Q-1)
  mpz_sub_ui(P, P, 1);
  mpz_sub_ui(Q, Q, 1);
  mpz_lcm(L, P, Q);

  // Set public exponent
  mpz_set_ui(E, 65537);

  /* Generate private exponent. If mpz_invert() returns '0',
     an inverse value could not be found, return error */
  int stat = 0 != mpz_invert(D, E, L);

  mpz_get_str(pub->e, 32, E);
  mpz_get_str(pub->m, 32, N);
  mpz_get_str(priv->e, 32, D);
  mpz_get_str(priv->m, 32, N);

  mpz_clear(P);
  mpz_clear(Q);
  mpz_clear(N);
  mpz_clear(L);
  mpz_clear(E);
  mpz_clear(D);

  return stat;
}


/* Encrypts a character and stores the encrypted value
   into  a string. */
void rsa_encrypt(char* buffer, char c, rsa_pubkey_t pub)
{
  mpz_t message, mod, exp;

  mpz_init(message);
  mpz_init(mod);
  mpz_init(exp);

  mpz_set_ui(message, c);
  mpz_set_str(mod, pub->m, 32);
  mpz_set_str(exp, pub->e, 32);

  mpz_powm(message, message, exp, mod);
  mpz_get_str(buffer, 32, message);

  mpz_clear(message);
  mpz_clear(mod);
  mpz_clear(exp);
}


/* Decrypts a string and returns the result as a char. */
char rsa_decrypt(char* buffer, rsa_privkey_t priv)
{
  mpz_t message, mod, exp;

  mpz_init(message);
  mpz_init(mod);
  mpz_init(exp);

  mpz_set_str(message, buffer, 32);
  mpz_set_str(mod, priv->m, 32);
  mpz_set_str(exp, priv->e, 32);

  mpz_powm(message, message, exp, mod);
  char c = (char) mpz_get_ui(message);

  mpz_clear(message);
  mpz_clear(mod);
  mpz_clear(exp);

  return c;
}

