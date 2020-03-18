# RSA
This is a simple RSA library I wrote while working on an small terminal chat application. It is fast (thanks to the GNU MP bigint library), easy to use, and can handle practically any key length. I originally tried to write my own bigint library for this, but it was simply too slow when dealing with huge numbers, so I swallowed my pride and used GNU's library instead.

The documentation for this library can be found in `include/rsa.h`.

## Demo
```c

// gcc demo.c -lrsa -lgmp

#include <stdio.h>
#include <string.h>
#include <rsa.h>


int main()
{
  rsa_key_t privkey, pubkey;
  rsa_init(privkey, pubkey, 1024, 62);

  char msg[32];
  char enc[1025];
  char dec[1025];

  scanf("%31s", msg);

  rsa_encrypt(enc, strlen(msg), msg, pubkey);

  printf("Encrypt(%s) = %s\n", msg, enc);

  rsa_decrypt(dec, strlen(enc), enc, privkey);

  printf("Decrypt(%s) = %s\n", enc, dec);

  rsa_clear_key(pubkey);
  rsa_clear_key(privkey);
}
```

## Build and Install
```sh
/home/user> git clone https://github.com/krglaws/RSA
/home/user> cd RSA
/home/user/RSA> make
/home/user/RSA> sudo make install
```

## Dependencies
[The GNU Multiple Precision Arithmetic Library](https://gmplib.org/)

