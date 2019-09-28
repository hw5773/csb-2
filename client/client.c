#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <openssl/ssl.h>
#include <sys/time.h>
#include <pthread.h>
#include <getopt.h>

#include "rsa.h"
#include "../include/debug.h"
#include "../include/defines.h"
#include "../include/setting.h"
#include "../include/conn.h"
#include "../include/http.h"
#include "../include/net.h"
#include "../include/err.h"

int usage(const char *pname)
{
  emsg(">> usage: %s [-h <domain>] [--host <domain>] [-p <portnum>] [--port <portnum>] [--sk <private key file>] [--pk <public key file>]", pname);
  emsg(">> example: %s -h www.alice.com -p 5555 --sk ../key/client_priv.pem --pk ../key/client_pub.pem", pname);
  exit(0);
}

// Client Prototype Implementation
int main(int argc, char *argv[])
{   
  const char *domain, *skname, *pkname, *pname;
	int port, server;
  struct keypair *kst, *peer;
  unsigned char buf[BUF_SIZE] = {0, };
  unsigned char my_pk[BUF_SIZE] = {0, };
  unsigned char peer_pk[BUF_SIZE] = {0, };
  unsigned char plain[BUF_SIZE] = {0, };
  unsigned char ciph[BUF_SIZE] = {0, };
  unsigned char verified;
  const char *start = "Start";
  int ret, len, clen, rlen, plen, klen, c, err;

  pname = argv[0];
  domain = NULL;
  port = -1;
  skname = NULL;
  pkname = NULL;
  err = 0;

  SSL_library_init();
  OpenSSL_add_all_algorithms();

  /* Get command line arguments */
  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"host", required_argument, 0, 'h'},
      {"port", required_argument, 0, 'p'},
      {"sk", required_argument, 0, 'a'},
      {"pk", required_argument, 0, 'b'},
      {0, 0, 0, 0}
    };

    c = getopt_long(argc, argv, "a:b:h:p:0", long_options, &option_index);

    if (c == -1)
      break;

    switch (c)
    {
      case 'h':
        domain = optarg;
        imsg("Domain: %s", domain);
        break;
      case 'p':
        port = atoi(optarg);
        imsg("Port: %d", port);
        break;
      case 'a':
        if (access(optarg, F_OK) != -1)
        {
          skname = optarg;
          imsg("Private Key File Path: %s", skname);
        }
        else
        {
          skname = NULL;
          emsg("Wrong private key file: %s", optarg);
        }
        break;
      case 'b':
        if (access(optarg, F_OK) != -1)
        {
          pkname = optarg;
          imsg("Public Key File Path: %s", pkname);
        }
        else
        {
          pkname = NULL;
          emsg("Wrong public key file: %s", optarg);
        }
        break;
      default:
        usage(pname);
    }
  }

  /* Handle errors */
  if (!domain)
  {
    err |= ERR_DOMAIN_NAME;
  }
  
  if (port < 0)
  {
    err |= ERR_PORT_NUMBER;
  }

  if (!skname)
  {
    err |= ERR_PRIV_KEY_FILE;
  }

  if (!pkname)
  {
    err |= ERR_PUB_KEY_FILE;
  }

  if (err)
  {
    emsg("Error in arguments");
    if (err & ERR_DOMAIN_NAME)
      emsg("Please insert the domain name (or IP address) of the server with the '-h' or '--host' flag.");

    if (err & ERR_PORT_NUMBER)
      emsg("Please insert the port number of the server with the '-p' or '--port' flag.");

    if (err & ERR_PRIV_KEY_FILE)
      emsg("Please insert the RSA private key for the client with the '--sk' flag.");

    if (err & ERR_PUB_KEY_FILE)
      emsg("Please insert the RSA public key for the client with the '--pk' flag.");

    usage(pname);
  }

  /* TODO: Initialize the RSA keypair */
  kst = init_rsa_keypair(skname, pkname);
  if (!kst)
  {
    emsg("Initialize the RSA keypair failed");
    abort();
  }

  /* Set the TCP connection with the server */
	server = open_connection(domain, port);
  if (server <= 2)
  {
    emsg("Open TCP connection failed");
    abort();
  }


  /* Send the Start message to Server */
  ret = send_message(server, start, strlen(start));
  if (ret == FAILURE)
  {
    emsg("Send the Start message failed");
    abort();
  }

  /* TODO: Make the RSA public key to bytes */
  ret = make_rsa_pubkey_to_bytes(kst, my_pk, &len);
  if (ret == FAILURE)
  {
    emsg("Translate the RSA public key into the bytes");
    abort();
  }

  /* Send the RSA public key bytes to Server */
  ret = send_message(server, my_pk, len);
  if (ret == FAILURE)
  {
    emsg("Send the key bytes failed");
    abort();
  }
  iprint("Client's public key", my_pk, 0, len, ONE_LINE);

  /* Receive the Server's RSA public key */
  ret = receive_message(server, buf, BUF_SIZE);
  if (ret == FAILURE)
  {
    emsg("Receive the Server's public key failed");
    abort();
  }
  rlen = ret;

  /* Initialize the RSA keypair */
  peer = init_rsa_keypair(NULL, NULL);
  if (!peer)
  {
    emsg("Initialize the RSA keypair failed");
    abort();
  }

  /* TODO: Make the bytes to the Server's public key */
  ret = make_bytes_to_rsa_pubkey(peer, buf, rlen);
  if (ret == FAILURE)
  {
    emsg("Translate the bytes to the RSA public key");
    abort();
  }

  /* Receive the challenge message from Server */
  ret = receive_message(server, buf, BUF_SIZE);
  if (ret == FAILURE)
  {
    emsg("Receive the challenge message failed");
    abort();
  }
  rlen = ret;
  
  /* TODO: Decrypt the challenge message (encrypted with Client's public key) */
  ret = rsa_operation(kst, buf, rlen, plain, &plen, RSA_DECRYPT);
  if (ret == FAILURE)
  {
    emsg("Decrypt the challenge message failed");
    abort();
  }
  iprint("Received message", buf, 0, rlen, ONE_LINE);
  imsg("Challenge (%d bytes): %s", plen, plain);

  /* TODO: Encrypt the challenge message with Server's public key */
  ret = rsa_operation(peer, plain, plen, ciph, &clen, RSA_ENCRYPT);
  if (ret == FAILURE)
  {
    emsg("Encrypt the challenge message failed");
    abort();
  }

  /* Send the challenge message to Server */
  ret = send_message(server, ciph, clen);
  if (ret == FAILURE)
  {
    emsg("Send the challenge message failed");
    abort();
  }
  iprint("Sent message", ciph, 0, clen, ONE_LINE);

  /* Receive the result from Server */
  ret = receive_message(server, buf, BUF_SIZE);
  if (ret == FAILURE)
  {
    emsg("Receive the result failed");
    abort();
  }
  rlen = ret;
  verified = buf[0];

  if (verified)
  {
    imsg("Success!");
  }
  else
  {
    imsg("Failed!");
  }

  free_rsa_keypair(kst);
  free_rsa_keypair(peer);

	return 0;
}
