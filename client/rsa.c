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

  if (!(ret->priv) || !(ret->pub))
  {
    emsg("RSA keypair is not correctly initialized");
    goto err;
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

int make_rsa_pubkey_to_bytes(struct keypair *kst, unsigned char *pk, int *len)
{
  fstart("kst: %p, pk: %p, len: %p", kst, pk, len);

  int ret;
  unsigned char *buf;
  BIO *b;
  BUF_MEM *pk_mem;

  assert(kst != NULL);
  assert(kst->pub != NULL);
  assert(pk != NULL);
  assert(len != NULL);
  
  b = BIO_new(BIO_s_mem());
  PEM_write_bio_RSA_PUBKEY(b, kst->pub);
  BIO_get_mem_ptr(b, &pk_mem);

  dmsg("Length of the RSA public key: %d", pk_mem->length);

  if (pk_mem->length > 0)
  {
    memcpy(pk, pk_mem->data, pk_mem->length);
    *len = pk_mem->length;
    dprint("RSA public key", pk, 0, *len, ONE_LINE);
    ret = SUCCESS;
  }
  else
  {
    emsg("i2d_RSAPublicKey failed");
    ret = FAILURE;
  }

  ffinish("ret: %d", ret);
  return ret;
}

int make_bytes_to_rsa_pubkey(struct keypair *kst, unsigned char *buf, int len)
{
  fstart("kst: %p, buf: %p, len: %d", kst, buf, len);

  int ret;
  BIO *b;

  assert(kst != NULL);
  assert(buf != NULL);
  assert(len > 0);

  dprint("RSA bytes", buf, 0, len, ONE_LINE);

  b = BIO_new(BIO_s_mem());
  BIO_write(b, buf, len);
  
  kst->pub = PEM_read_bio_RSA_PUBKEY(b, NULL, NULL, NULL);
  if (kst->pub)
  {
    ret = SUCCESS;
  }
  else
  {
    ret = FAILURE;
  }

  ffinish("ret: %d", ret);
  return ret;
}

// TODO: RSA encryption
int rsa_encrypt_message(struct keypair *kst, unsigned char *input, int ilen,
    unsigned char *output, int *olen)
{
  fstart("kst: %p, input: %p, ilen: %d, output: %p, olen: %p",
      kst, input, ilen, output, olen);

  int ret;

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

  int ret;

  assert(kst != NULL);
  assert(input != NULL);
  assert(ilen > 0);
  assert(output != NULL);
  assert(olen != NULL);

  // *olen =;

  ffinish("ret: %d", ret);
  return ret;
}
