
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <kbil.h>
#include <sys/time.h>
#include <time.h>
#include "rsa.h"


static bool is_prime(bigint* bi)
{
  bigint* i = BI_new_i(5);
  bigint* rem = BI_new_i(0);
  bigint* prod = BI_new_i(0);

  if (BI_cmp_bi(bi, 3) == BI_EQUAL)
  {
    if (BI_cmp_bi(bi, 1) == BI_GREATERTHAN)
    {
      goto prime;
    }
    else
    {
      goto notprime;
    }
  }

  BI_mod_bi(rem, bi, 2);
  if (BI_cmp_bi(rem, 0) == BI_EQUAL)
  {
    goto notprime;
  }

  BI_mod_bi(rem, bi, 3);
  if (BI_cmp_bi(rem, 0) == BI_EQUAL)
  {
    goto notprime;
  }

  BI_mul_bb(prod, i, i);
  enum BI_comparison cmp = BI_cmp_bb(prod, bi);
  while (cmp == BI_LESSTHAN || cmp == BI_EQUAL)
  {
    BI_mod_bb(rem, bi, i);
    if (BI_cmp_bi(rem, 0) == BI_EQUAL)
    {
      goto notprime;
    }

    BI_add_bi(i, i, 2);
    BI_mod_bb(rem, bi, i);
    if (BI_cmp_bi(rem, 0) == BI_EQUAL)
    {
      goto notprime;
    }
    BI_add_bi(i, i, 4);
    BI_mul_bb(prod, i, i);
    cmp = BI_cmp_bb(prod, bi);
  }

 prime:
  BI_free(i);
  BI_free(rem);
  BI_free(prod);
  return true;

 notprime:
  BI_free(i);
  BI_free(rem);
  BI_free(prod);
  return false;
}


static int rand_prime(bigint* bi, unsigned int bits)
{
  if (bi == NULL)
  {
    return -1;
  }

  bigint* rem = BI_new_i(0);

  do
  {
    BI_rand(bi, bits);
  } while (BI_cmp_bi(bi, 0) == BI_EQUAL);
  bi->sign = 1;

  BI_mod_bi(rem, bi, 2);
  if (BI_cmp_bi(rem, 1) != BI_EQUAL)
  {
    BI_sub_bi(bi, bi, 1);
  }

  while (is_prime(bi) == false && BI_cmp_bi(bi, 0) == BI_GREATERTHAN)
  {
    BI_sub_bi(bi, bi, 2);
  }

  BI_free(rem);

  return 0;
}


static int gcd(bigint* res, bigint* a, bigint* b)
{
  if (res == NULL || a == NULL || b == NULL)
    return -1;

  bigint* a_copy = BI_new_b(a);
  bigint* b_copy = BI_new_b(b);

  while (BI_cmp_bi(a_copy, 0) == BI_GREATERTHAN &&
         BI_cmp_bi(b_copy, 0) == BI_GREATERTHAN)
  {
    if (BI_cmp_bb(a_copy, b_copy) == BI_GREATERTHAN)
      BI_mod_bb(a_copy, a_copy, b_copy);
    else
      BI_mod_bb(b_copy, b_copy, a_copy);
  }
  if (BI_cmp_bb(a_copy, b_copy) == BI_GREATERTHAN)
    BI_set_b(res, a_copy);
  else BI_set_b(res, b_copy);

  BI_free(a_copy);
  BI_free(b_copy);

  return 0;
}


static int lcm(bigint* res, bigint* a, bigint* b)
{
  if (res == NULL || a == NULL || b == NULL)
    return -1;

  bigint* prod = BI_new_i(0);
  BI_mul_bb(prod, a, b);

  bigint* g = BI_new_i(0);
  gcd(g, a, b);

  BI_div_bb(res, prod, g);

  BI_free(prod);
  BI_free(g);

  return 0;
}


static int mod_inv(bigint* res, bigint* a, bigint* n)
{
  bigint* t = BI_new_i(0);
  bigint* r = BI_new_b(n);
  bigint* newt = BI_new_i(1);
  bigint* newr = BI_new_b(a);

  bigint* quotient = BI_new_i(0);
  bigint* temp = BI_new_i(0);

  while (BI_cmp_bi(newr, 0) != BI_EQUAL)
  {
    BI_div_bb(quotient, r, newr);

    BI_mul_bb(temp, quotient, newt);
    BI_sub_bb(temp, t, temp);

    BI_set_b(t, newt);
    BI_set_b(newt, temp);

    BI_mul_bb(temp, quotient, newr);
    BI_sub_bb(temp, t, temp);

    BI_set_b(r, newr);
    BI_set_b(newr, temp);
  }

  BI_free(newt);
  BI_free(newr);
  BI_free(quotient);
  BI_free(temp);

  if (BI_cmp_bi(r, 1) == BI_GREATERTHAN)
  {
    BI_free(r);
    BI_free(t);
    return -1;
  }

  BI_free(r);
  if (BI_cmp_bi(t, 0) == BI_LESSTHAN)
  {
    BI_add_bb(res, t, n);
    BI_free(t);
    return 0;
  }

  BI_set_b(res, t);
  BI_free(t);
  return 0; 
}


int inverse(int a, int n)
{
  int t = 0;
  int r = n;
  int newt = 1;
  int newr = a;

  while (newr != 0)
  {
    int quotient = r / newr;

    int temp = t - quotient * newt;
    t = newt;
    newt = temp;

    temp = r - quotient * newr;
    r = newr;
    newr = temp;
  }

  if (r > 1)
    return -1;

  if (t < 0)
    t = t + n;

  return t;
}


int rsa_init(struct public_key* pub, struct private_key* priv)
{
  if (pub == NULL || priv == NULL)
    return -1;

  bigint* P = BI_new_i(0);
  rand_prime(P,  16);

  bigint* Q = BI_new_i(0);
  do
  {
    rand_prime(Q, 16);
  } while (BI_cmp_bb(P, Q) == BI_EQUAL);

  bigint* N = BI_new_i(0);
  BI_mul_bb(N, P, Q);

  BI_sub_bi(P, P, 1);
  BI_sub_bi(Q, Q, 1);

  bigint* L = BI_new_i(0);
  lcm(L, P, Q);

  int bitlen = 0;
  unsigned char tail = L->val[L->len-1];
  for (int i = 0; i < 8; i++)
  {
    if (tail & 1) bitlen = (i + 1);
    tail >>= 1;
  }
  bitlen += 8 * (L->len - 1);

  if (bitlen > 17)
    bitlen = 17;

  bigint* E = BI_new_i(0);
  rand_prime(E, bitlen - 1);

  bigint* D = BI_new_i(0);
  mod_inv(D, E, L);

  BI_free(P);
  BI_free(Q);

  pub->m = N;
  pub->e = E;

  priv->m = N;
  priv->e = BI_new_i(0);
  BI_set_b(priv->e, D);

  return 0;
}


int rsa_encrypt(struct enc_data* enc, struct raw_data* raw, struct public_key* pub)
{
  if (enc == NULL || raw == NULL || pub == NULL)
    return -1;

  return 0;
}


int rsa_decrypt(struct raw_data* raw, struct enc_data* enc, struct private_key* priv)
{
  if (raw == NULL || enc == NULL || priv == NULL)
    return -1;

  return 0;
}


int main()
{
/*  bigint* bi = BI_new(0);
  rand_prime(bi, 32);
  BI_print(bi);
  BI_free(bi);*/
  srand(time(NULL));
  struct public_key pubkey;
  struct private_key privkey;

  rsa_init(&pubkey, &privkey);

  char* modulus = BI_to_str(pubkey.m, 16);
  char* pubex = BI_to_str(pubkey.e, 16);
  char* privex = BI_to_str(privkey.e, 16);

  printf("m = %s\n", modulus);
  printf("e = %s\n", pubex);
  printf("d = %s\n", privex);

  BI_free(pubkey.m);
  BI_free(pubkey.e);
  BI_free(privkey.m);
  BI_free(privkey.e);
}

