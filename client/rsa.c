#include "rsa.h"
#include "../include/debug.h"
#include "../include/defines.h"
#include "../include/net.h"
#include "../include/err.h"
#include <assert.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bio.h>

int rsa_encrypt_message(struct keypair *kst, unsigned char *input, int ilen,
    unsigned char *output, int *olen);

int rsa_decrypt_message(struct keypair *kst, unsigned char *input, int ilen, 
    unsigned char *output, int *olen);

int rsa_operation(struct keypair *kst, unsigned char *input, int ilen, 
    unsigned char *output, int *olen, int op)
{
  fstart("kst: %p, input: %p, ilen: %d, output: %p, olen: %p, op: %d", 
      kst, input, ilen, output, olen, op);

  assert(kst != NULL);
  assert(input != NULL);
  assert(output != NULL);
  assert(ilen > 0);
  assert(olen != NULL);

  if (op == RSA_ENCRYPT)
    return rsa_encrypt_message(kst, input, ilen, output, olen);
  else if (op == RSA_DECRYPT)
    return rsa_decrypt_message(kst, input, ilen, output, olen);
  else
    return FAILURE;
}

struct keypair *init_rsa_keypair(const char *skname, const char *pkname)
{
  fstart("skname: %p, pkname: %p", skname, pkname);

  struct keypair *ret;
  int klen;
  BIO *b;

  b = BIO_new_fp(stdout, BIO_NOCLOSE);
  ret = (struct keypair *)malloc(sizeof(struct keypair));
  if (!ret)
  {
    emsg("Out of memory during a keypair malloc");
    goto err;
  }
  memset(ret, 0x0, sizeof(struct keypair));


  // TODO: Please implement the following (Load the private key from the file)
  if (skname)
  {
    // The key should be loaded on ret->priv
  }

  // TODO: Please implement the following (Load the public key from the file)
  if (pkname)
  {
    // The key should be loaded on ret->pub
  }

  ffinish("ret: %p", ret);
  return ret;
err:
  if (ret)
  {
    free_rsa_keypair(ret);
  }
  ffinish("ret: %p", ret);
  return NULL;
}

void free_rsa_keypair(struct keypair *kst)
{
  fstart("kst: %p", kst);

  if (kst)
  {
    if (kst->pub)
      RSA_free(kst->pub);

    if (kst->priv)
      RSA_free(kst->priv);

    free(kst);
    kst = NULL;
  }

  ffinish("kst: %p", kst);
}

// TODO: RSA public key -> bytes
int make_rsa_pubkey_to_bytes(struct keypair *kst, unsigned char *pk, int *len)
{
  fstart("kst: %p, pk: %p, len: %p", kst, pk, len);

  assert(kst != NULL);
  assert(kst->pub != NULL);
  assert(pk != NULL);
  assert(len != NULL);
  
  ffinish("ret: %d", ret);
  return ret;
}

// TODO: bytes -> RSA public key
int make_bytes_to_rsa_pubkey(struct keypair *kst, unsigned char *buf, int len)
{
  fstart("kst: %p, buf: %p, len: %d", kst, buf, len);

  assert(kst != NULL);
  assert(buf != NULL);
  assert(len > 0);

  ffinish("ret: %d", ret);
  return ret;
}

// TODO: RSA encryption
int rsa_encrypt_message(struct keypair *kst, unsigned char *input, int ilen,
    unsigned char *output, int *olen)
{
  fstart("kst: %p, input: %p, ilen: %d, output: %p, olen: %p",
      kst, input, ilen, output, olen);

  assert(kst != NULL);
  assert(input != NULL);
  assert(ilen > 0);
  assert(output != NULL);
  assert(olen != NULL);
  
  //*olen =;

  ffinish("ret: %d", ret);
  return ret;
}

// TODO: RSA decryption
int rsa_decrypt_message(struct keypair *kst, unsigned char *input, int ilen, 
    unsigned char *output, int *olen)
{
  fstart("kst: %p, input: %p, ilen: %d, output: %p, olen: %p",
      kst, input, ilen, output, olen);

  assert(kst != NULL);
  assert(input != NULL);
  assert(ilen > 0);
  assert(output != NULL);
  assert(olen != NULL);

  // *olen =;

  ffinish("ret: %d", ret);
  return ret;
}
