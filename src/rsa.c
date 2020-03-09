
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
int rsa_init(rsa_pubkey_t pub, rsa_privkey_t priv, unsigned keylen, unsigned base)
{
  FILE *urandom;
  mpz_t P, Q, N, L, E, D, M;

  // Open '/dev/urandom' for secure random number generation.
  if (NULL == (urandom = fopen("/dev/urandom", "r")))
    return -1;

  // Initialize mpz_t's
  mpz_inits(P, Q, N, L, E, D, NULL);

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

  // set key base encoding
  pub->b = base;
  priv->b = base;

  // Allocate key space
  int len = mpz_sizeinbase(E, base);
  pub->e = malloc(len + 1);

  len = mpz_sizeinbase(D, base);
  priv->e = malloc(len + 1);

  len = mpz_sizeinbase(N, base);
  pub->m = malloc(len + 1);
  priv->m = malloc(len + 1);

  // Convert E, D, and N to char* and store into keys.
  mpz_get_str(pub->e, base, E);
  mpz_get_str(pub->m, base, N);
  mpz_get_str(priv->e, base, D);
  mpz_get_str(priv->m, base, N);

  // Free up mpz_t's
  mpz_clears(P, Q, N, L, E, D, NULL);

  return stat;
}


/* Encrypts 'count' bytes from char* raw and stores the encrypted value
   into char* enc */
void rsa_encrypt(char* enc, unsigned count, char* raw, rsa_pubkey_t pub)
{
  // Declare and initialize mpz_t's
  mpz_t msg, mod, exp;
  mpz_inits(msg, mod, exp, NULL);

  // Convert raw data into mpz_t
  mpz_add_ui(msg, msg, raw[0]);
  for (int i = 1; i < count; i++)
  {
    mpz_mul_ui(msg, msg, 256); // same as msg <<= 8
    mpz_add_ui(msg, msg, raw[i]);
  }

  // Set mod and exp to public modulus and exponent
  mpz_set_str(mod, pub->m, pub->b);
  mpz_set_str(exp, pub->e, pub->b);

  // Encrypt and store into enc buffer
  mpz_powm(msg, msg, exp, mod);
  mpz_get_str(enc, pub->b, msg);

  // free up mpz_t's
  mpz_clears(msg, mod, exp, NULL);
}


/* Decrypts a string and returns the result as a char. */
void rsa_decrypt(char* raw, char* enc, rsa_privkey_t priv)
{
  // Declare and initialize mpz_t's
  mpz_t msg, mod, exp, rem;
  mpz_inits(msg, mod, exp, rem, NULL);

  // Set msg to enc value
  mpz_set_str(msg, enc, priv->b);

  // Set mod and exp to private modulus and exponent
  mpz_set_str(mod, priv->m, priv->b);
  mpz_set_str(exp, priv->e, priv->b);

  // Decrypt
  mpz_powm(msg, msg, exp, mod);

  // Store decrypted bytes into raw
  int i = 0;
  while (mpz_cmp_ui(msg, 0) != 0)
  {
    mpz_tdiv_qr_ui(msg, rem, msg, 256);
    raw[i++] = mpz_get_ui(rem);
  }
  raw[i] = 0;

  // Reverse raw
  char* end = raw + i - 1;
  while (raw < end)
  {
    *raw ^= *end;
    *end ^= *raw;
    *raw ^= *end;

    raw++;
    end--;
  }

  // free up mpz_t's
  mpz_clears(msg, mod, exp, rem, NULL);
}

