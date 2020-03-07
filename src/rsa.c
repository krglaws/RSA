
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
void rsa_init(rsa_pubkey_t pub, rsa_privkey_t priv)
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

  // Generate private exponent
  assert(mpz_invert(D, E, L) != 0);

  mpz_init(pub->e);
  mpz_init(pub->m);
  mpz_init(priv->e);
  mpz_init(priv->m);

  mpz_set(pub->e, E);
  mpz_set(pub->m, N);
  mpz_set(priv->e, D);
  mpz_set(priv->m, N);

  mpz_clear(P);
  mpz_clear(Q);
  mpz_clear(N);
  mpz_clear(L);
  mpz_clear(E);
  mpz_clear(D);
}


/* Encrypts a character and stores the encrypted value
   into  a string. */
void rsa_encrypt(char* buffer, char c, rsa_pubkey_t pub)
{
  mpz_t message;
  mpz_init(message);
  mpz_set_ui(message, c);

  mpz_powm(message, message, pub->e, pub->m);

  mpz_get_str(buffer, 32, message);

  mpz_clear(message);
}


/* Decrypts a string and returns the result as a char. */
char rsa_decrypt(char* buffer, rsa_privkey_t priv)
{

  mpz_t message;
  mpz_init(message);
  mpz_set_str(message, buffer, 32);

  mpz_powm(message, message, priv->e, priv->m);

  char c = (char) mpz_get_ui(message);

  mpz_clear(message);

  return c;
}

