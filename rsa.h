
#ifndef _RSA_H_
#define _RSA_H_


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


struct raw_data
{
  int len;
  unsigned char* bytes;
};


struct enc_data
{
  int len;
  unsigned char* bytes;
};


/* these are the only non-static procedures made available by this library */


/* rsa_init(): initializes a public and private key
 *
 * pub - a pointer to a public_key struct
 * priv - a pointer to a private_key struct
 *
 * returns:
 *   0 on success
 *   -1 on failure
 */
int rsa_init(struct public_key* pub, struct private_key* priv);


/* rsa_encrypt(): encrypts the data contained within a raw_data struct using
 * a public key, and stores the encrypted data into an enc_data struct
 *
 * enc - struct in which to store encrypted data
 * raw - struct containing data to be encrypted
 * pub - public key used to encrypt the data
 *
 * returns:
 *   0 on success
 *   -1 on failure
 */
int rsa_encrypt(struct enc_data* enc, struct raw_data* raw, struct public_key* pub);


/* rsa_decrypt(): decrypts the data contained in an enc_data struct using a
 * public key, and stores the result into a raw_data struct
 *
 * raw - struct in which to store decrypted data
 * enc - struct containing data to be decrypted
 * priv - private key used to decrypt the data
 *
 * returns:
 *   0 on success
 *   -1 on failure
 */
int rsa_decrypt(struct raw_data* raw, struct enc_data* enc, struct private_key* priv);


#endif

