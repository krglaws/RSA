
#include <stdio.h>
#include <inttypes.h>
#include <gmp.h>

#include <rsa.h>


/* Called by rsa_init(). Generates a random
   prime number of a specified bit length */
static int rand_prime(mpz_t p, unsigned bits, FILE *randfile)
{
  // # of bits in most significant byte
  int sig_bits = bits % 8;

  // total number of bytes
  int num_bytes = (bits / 8) + (sig_bits > 0);

  // Get most significant byte
  uint8_t byte;
  fread(&byte, 1, 1, randfile);

  if (sig_bits)
    byte = byte >> (8 - sig_bits);

  // add byte to p, and bit shift 8 bits to the left
  mpz_add_ui(p, p, byte);

  // Get remaining bytes
  for (int i = 1; i < num_bytes; i++)
  {
    fread(&byte, 1, 1, randfile);
    mpz_mul_ui(p, p, 256);
    mpz_add_ui(p, p, byte);
  }

  // find next prime above p
  mpz_nextprime(p, p);
}


/* Initializes a public and a private key for use
   in rsa_encrypt() and rsa_decrypt(). */
int rsa_init(rsa_pubkey_t pub, rsa_privkey_t priv, unsigned keylen)
{
  FILE *urandom;
  mpz_t P, Q, N, L, E, D;

  // Open '/dev/urandom' for secure random number generation.
  if (NULL == (urandom = fopen("/dev/urandom", "r")))
    return -1;

  // Initialize mpz_t's
  mpz_inits(P, Q, N, L, E, D);

  // Generate two random primes
  rand_prime(P, keylen/2, urandom);
  rand_prime(Q, keylen/2, urandom);

  fclose(urandom);

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

  // Convert E, D, and N to char* and store into keys.
  mpz_get_str(pub->e, 32, E);
  mpz_get_str(pub->m, 32, N);
  mpz_get_str(priv->e, 32, D);
  mpz_get_str(priv->m, 32, N);

  // Free up mpz_t's
  mpz_clears(P, Q, N, L, E, D);

  return stat;
}


/* Encrypts a character and stores the encrypted value
   into  a string. */
void rsa_encrypt(char* buffer, char c, rsa_pubkey_t pub)
{
  // Declare and initialize mpz_t's
  mpz_t message, mod, exp;

  mpz_inits(message, mod, exp);

  // Set message, mod, and exp to public modulus and exponent
  mpz_set_ui(message, c);
  mpz_set_str(mod, pub->m, 32);
  mpz_set_str(exp, pub->e, 32);

  // Encrypt and store string value into buffer
  mpz_powm(message, message, exp, mod);
  mpz_get_str(buffer, 32, message);

  // free up mpz_t's
  mpz_clears(message, mod, exp);
}


/* Decrypts a string and returns the result as a char. */
char rsa_decrypt(char* buffer, rsa_privkey_t priv)
{
  // Declare and initialize mpz_t's
  mpz_t message, mod, exp;

  mpz_inits(message, mod, exp);

  // Set message, mod, and exp to private modulus and exponent
  mpz_set_str(message, buffer, 32);
  mpz_set_str(mod, priv->m, 32);
  mpz_set_str(exp, priv->e, 32);

  // Decrypt
  mpz_powm(message, message, exp, mod);
  char c = (char) mpz_get_ui(message);

  // free up mpz_t's
  mpz_clears(message, mod, exp);

  return c;
}

