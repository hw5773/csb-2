#ifndef __DEFINES_H__
#define __DEFINES_H__

#include <time.h>
#include <openssl/ssl.h>

#define SUCCESS 1
#define FAILURE -1

#define BUF_SIZE 512
#define MAX_KEY_LENGTH 128
#define MAX_CHALLENGE_NUM 10000
#define MAX_HOST_LEN 256
#define MAX_FILE_NAME_LEN 256
#define MAX_THREADS 100
#define TIMEOUT 10

#define SERIAL_LENGTH 32
#define LENGTH_INFO_LEN 2
#define TIMESTAMP_LEN sizeof(time_t)

#define PTR_TO_VAR_2BYTES(p, v) \
  v = (((p[0] & 0xff) << 8) | (p[1] & 0xff)); p += 2;
#define VAR_TO_PTR_2BYTES(v, p) \
  p[0] = (v >> 8) & 0xff; p[1] = (v & 0xff); p += 2;

#define PTR_TO_VAR_4BYTES(p, v) \
  v = (((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)); \
      p += 4;
#define VAR_TO_PTR_4BYTES(v, p) \
  p[0] = (v >> 24) & 0xff; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff; \
      p += 4;

#define PTR_TO_VAR_8BYTES(p, v) \
  v = (((p[0] & 0xff) << 56) | ((p[1] & 0xff) << 48) | ((p[2] & 0xff) << 40) \
    | ((p[3] & 0xff) << 32) | ((p[4] & 0xff) << 24) | ((p[5] & 0xff) << 16) \
    | ((p[6] & 0xff) << 8) | (p[7] & 0xff)); p += 8;
#define VAR_TO_PTR_8BYTES(v, p) \
  p[0] = (v >> 56) & 0xff; p[1] = (v >> 48) & 0xff; p[2] = (v >> 40) & 0xff; \
      p[3] = (v >> 32) & 0xff; p[4] = (v >> 24) & 0xff; p[5] = (v >> 16) & 0xff; \
      p[6] = (v >> 8) & 0xff; p[7] = v & 0xff; p += 8;

struct info
{
  int fd;
  const char *skname;
  const char *pkname;
};

#endif /* __DEFINES_H__ */
