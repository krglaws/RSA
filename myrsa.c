
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <bigint.h>


struct public_key
{
  bigint* e;
  bigint* m;
};

struct private_key
{
  bigint* e;
  bigint* m;
};


bool is_prime(bigint* bi);

uint64_t my_pow(uint8_t base, uint8_t exp);

uint64_t rand_prime(int bits);

uint64_t gcd(uint64_t num1, uint64_t num2);

uint64_t lcm(uint64_t num1, uint64_t num2);

int coprime(uint64_t num1, uint64_t num2);

uint64_t find_exp(uint64_t L);

uint64_t mod_mul_inv(uint64_t a, uint64_t m);


int main(int argc, char** argv)
{
  int bits = 8;

  bigint *P, *Q, *N, *L, *E, *D;

  if (argc > 1)
    bits = strtol(argv[1], NULL, 10);

  else 
    printf("Using default %d bits\n", bits);

  if (bits <= 0)
  {
    fprintf(stderr, "Error: bits must be > 0\n");
    exit(EXIT_FAILURE);
  }

  srand(time(NULL));

  P = rand_prime(bits);
  do {
    Q = rand_prime(bits);
  } while (Q == P);
 
  bigint* p = BI_new(p);
  bigint* q = BI_new(q);
  bigint* n = BI_new(0);
  BI_mul(n, p, q);
 
  N = P * Q;
  L = lcm(P-1, Q-1);//(P - 1) * (Q - 1);
  E = find_exp(L);

  bigint* e = BI_new(e);

  D = mod_mul_inv(E, L);

  printf("P = %u\n", P);
  printf("Q = %u\n", Q);
  printf("N = %ld\n", N);
  printf("L = %ld\n", L);
  printf("E = %ld\n", E);
  printf("D = %ld\n", D);

  uint32_t m = 123;
  printf("Message = %u\n", m);

  uint32_t c = my_pow(m, E) %  N;
  printf("Encrypted = %u\n", c);

  uint32_t u = my_pow(c, D) % N;
  printf("Unencrypted = %u\n", u);
}


/* MAKE THIS BETTER */
int is_prime(uint64_t num)
{
  uint64_t c = num - 1;

  for (; c > 1; c--)
    if (num % c == 0)
      return FALSE;

  return TRUE;
}


uint64_t my_pow(uint8_t base, uint8_t exp)
{
  if (exp < 0)
  {
    exit(EXIT_FAILURE);
    fprintf(stderr, "Error: no negative exponents\n");
  }

  if (exp == 0)
    return 1;

  uint64_t result = base;

  while (--exp)
    result *= base;

  return result;
}


uint64_t rand_prime(int bits)
{
  float r = (float) rand() / RAND_MAX;

  uint64_t num;

  do {
    num = (uint64_t) (r * my_pow(2, bits));
  } while (num == 0);

  num -= num % 2 == 0; // make num odd

  while (!is_prime(num)) num -= 2; // skip all evens

  return num;
}


uint64_t gcd(uint64_t num1, uint64_t num2)
{
  while (num1 != 0 && num2 != 0)
  {
    if (num1 > num2)
      num1 %= num2;
    else
      num2 %= num1;
  }
  return num1 > num2 ? num1 : num2;
}


uint64_t lcm(uint64_t num1, uint64_t num2)
{
  return (num1 * num2) / gcd(num1, num2);
}


int coprime(uint64_t num1, uint64_t num2)
{
  return gcd(num1, num2) == 1;
}


uint64_t find_exp(uint64_t L)
{
  uint64_t E = L/2;

  while (!(coprime(E, L)))
  {
    E++;
    if (E == L)
    {
      printf("Failed to find E\n");
      exit(EXIT_FAILURE);
    }
  }

  return E;
}


uint64_t mod_mul_inv(uint64_t a,  uint64_t m)
{
  a = a%m; 
  for (int x=1; x<m; x++) 
    if ((a*x) % m == 1) 
      return x;

  fprintf(stderr, "Failed to find modular multiplicative inverse\n");
  exit(EXIT_FAILURE);
}


