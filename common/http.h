#ifndef __HTTP_H__
#define __HTTP_H__

#include <stdio.h>
#include <stdint.h>

#define INDEX_FILE "/index.html"
#define INDEX_FILE_LEN 12

struct rinfo
{
  FILE *fp;
  uint8_t *domain;
  uint32_t dlen;
  uint8_t *content;
  uint32_t clen;
  uint32_t size; // total size including the header size
  uint32_t sent; // actual sent size
  uint32_t rlen; // header size
};

int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content, uint32_t clen,
    uint8_t *msg, uint32_t *mlen);
int http_parse_request(char *msg, uint32_t mlen, struct rinfo *r);
int http_parse_response(char *msg, uint32_t mlen);

#endif /* __HTTP_H__ */
