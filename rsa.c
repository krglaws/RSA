
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <kbil.h>
#include <sys/time.h>
#include <time.h>
#include "rsa.h"


int rsa_init(struct public_key* pub, struct private_key* priv)
{}

int rsa_encrypt(struct enc_data* enc, struct raw_data* raw, struct public_key* pub)
{}

int rsa_decrypt(struct raw_data* raw, struct enc_data* enc, struct private_key* priv)
{}

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
/*  struct timeval start, stop;
  srand(time(NULL));

  double avg1 = 0;
  double avg2 = 0;

  for (int i = 0; i < 256*256; i++)
  {
    bigint* bi = BI_new(i);

    gettimeofday(&start, NULL);
    is_prime1(bi);
    gettimeofday(&stop, NULL);

    avg1 += (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;

    gettimeofday(&start, NULL);
    is_prime2(bi);
    gettimeofday(&stop, NULL);

    avg2 += (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;

    BI_free(bi);
  }

  avg1 /= (256*256);
  avg2 /= (256*256);

  printf("avg1 = %f microseconds\navg2 = %f microseconds\n", avg1, avg2);
*/
  srand(time(NULL));
  bigint* bi = BI_new(0);
  rand_prime(bi, 64);
  BI_print(bi);
  BI_free(bi);
}

