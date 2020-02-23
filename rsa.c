
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <kbil.h>
#include <sys/time.h>
#include <time.h>
#include "rsa.h"


static int gcd(bigint* res, bigint* a, bigint* b)
{
  if (res == NULL || a == NULL || b == NULL)
    return -1;

  bigint* a_copy = BI_new(0);
  BI_set_bi(a_copy, a);

  bigint* b_copy = BI_new(0);
  BI_set_bi(b_copy, b);

  bigint* zero = BI_new(0);
  while (BI_cmp(a_copy, zero) == BI_GREATERTHAN &&
         BI_cmp(b_copy, zero) == BI_GREATERTHAN)
  {
    if (BI_cmp(a_copy, b_copy) == BI_GREATERTHAN)
      BI_mod(a_copy, a_copy, b_copy);
    else
      BI_mod(b_copy, b_copy, a_copy);
  }
  if (BI_cmp(a_copy, b_copy) == BI_GREATERTHAN)
    BI_set_bi(res, a_copy);
  else BI_set_bi(res, b_copy);

  BI_free(a_copy);
  BI_free(b_copy);
  BI_free(zero);

  return 0;
}


static int lcm(bigint* res, bigint* a, bigint* b)
{
  if (res == NULL || a == NULL || b == NULL)
    return -1;

  bigint* prod = BI_new(0);
  BI_mul(prod, a, b);

  bigint* g = BI_new(0);
  gcd(g, a, b);

  BI_div(res, prod, g);

  BI_free(prod);
  BI_free(g);

  return 0;
}


int rsa_init(struct public_key* pub, struct private_key* priv)
{
  if (pub == NULL || priv == NULL)
    return -1;

  bigint* P = BI_new(0);
  rand_prime(P,  32);

  bigint* Q = BI_new(0);
  do
  {
    rand_prime(Q, 32);
  } while (BI_cmp(P, Q) == BI_EQUAL);

  bigint* N = BI_new(0);
  BI_mul(N, P, Q);

  bigint* one = BI_new(1);
  BI_sub(P, P, one);
  BI_sub(Q, Q, one);

  bigint* L = BI_new(0);
  lcm(L, P, Q);

  int bitlen = 0;
  unsigned char tail = L->val[L->len-1];
  for (int i = 0; i < 8; i++)
  {
    if (tail & 1) bitlen = (i + 1);
    tail >>= 1;
  }
  bitlen += 8 * (L->val - 1);

  bigint* E = BI_new(0);
  rand_prime(E, bitlen - 1);

  bigint* a = BI_new(0);
  BI_set_bi(a, E);
  BI_mod(a, a, L);

  bigint* D = BI_new(0);
  bigint* I = BI_new(1);
  bigint* temp = BI_new(0);
  for (; BI_cmp(I, L) == BI_LESSTHAN; BI_add(I, I, one))
  {
    BI_mul(temp, a, I);
    BI_mod(temp, temp, L);
    if (BI_cmp(temp, one) == BI_EQUAL)
    {
      BI_set_bi(D, temp);
      break;
    }
  }

  BI_free(P);
  BI_free(Q);
  BI_free(one);
  BI_free(a);
  BI_free(I);
  BI_free(temp);

  pub->m = N;
  pub->e = E;

  priv->m = N;
  priv->e = D;

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


static bool is_prime1(bigint* bi)
{
  bigint* zero = BI_new(0);
  bigint* one = BI_new(1);
  bigint* two = BI_new(2);

  bigint* temp = BI_new(0);
  BI_div(temp, bi, two);

  bigint* rem = BI_new(0);

  for (; BI_cmp(temp, one) == BI_GREATERTHAN; BI_sub(temp, temp, one))
  {
    BI_mod(rem, bi, temp);
    if (BI_cmp(rem, zero) == BI_EQUAL)
    {
      return false;
    }
  }

  BI_free(zero);
  BI_free(one);
  BI_free(two);
  BI_free(temp);
  BI_free(rem);

  return true;
}


static bool is_prime2(bigint* bi)
{
  bigint* zero = BI_new(0);
  bigint* one = BI_new(1);
  bigint* two = BI_new(2);
  bigint* three = BI_new(3);
  bigint* four = BI_new(4);
  bigint* i = BI_new(5);
  bigint* rem = BI_new(0);
  bigint* prod = BI_new(0);

  if (BI_cmp(bi, three) == BI_EQUAL)
  {
    if (BI_cmp(bi, one) == BI_GREATERTHAN)
    {
      goto prime;
    }
    else
    {
      goto notprime;
    }
  }

  BI_mod(rem, bi, two);
  if (BI_cmp(rem, zero) == BI_EQUAL)
  {
    goto notprime;
  }

  BI_mod(rem, bi, three);
  if (BI_cmp(rem, zero) == BI_EQUAL)
  {
    goto notprime;
  }

  BI_mul(prod, i, i);
  enum BI_comparison cmp = BI_cmp(prod, bi);
  while (cmp == BI_LESSTHAN || cmp == BI_EQUAL)
  {
    BI_mod(rem, bi, i);
    if (BI_cmp(rem, zero) == BI_EQUAL)
    {
      goto notprime;
    }

    BI_add(i, i, two);
    BI_mod(rem, bi, i);
    if (BI_cmp(rem, zero) == BI_EQUAL)
    {
      goto notprime;
    }
    BI_add(i, i, four);
    BI_mul(prod, i, i);
    cmp = BI_cmp(prod, bi);
  }

 prime:
  BI_free(zero);
  BI_free(one);
  BI_free(two);
  BI_free(three);
  BI_free(four);
  BI_free(i);
  BI_free(rem);
  BI_free(prod);
  return true;

 notprime:
  BI_free(zero);
  BI_free(one);
  BI_free(two);
  BI_free(three);
  BI_free(four);
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

  bigint* rem = BI_new(0);
  bigint* zero = BI_new(0);
  bigint* one = BI_new(1);
  bigint* two = BI_new(2);

  do
  {
    BI_rand(bi, bits);
  } while (BI_cmp(bi, zero) == BI_EQUAL);
  bi->sign = 1;

  BI_mod(rem, bi, two);
  if (BI_cmp(rem, one) != BI_EQUAL)
  {
    BI_sub(bi, bi, one);
  }

  while (is_prime2(bi) == false && BI_cmp(bi, zero) == BI_GREATERTHAN)
  {
    BI_sub(bi, bi, two);
  }

  BI_free(rem);
  BI_free(one);
  BI_free(two);

  return 0;
}


int main()
{
  srand(time(NULL));
  bigint* bi = BI_new(0);
  rand_prime(bi, 32);
  BI_print(bi);
  BI_free(bi);
}

