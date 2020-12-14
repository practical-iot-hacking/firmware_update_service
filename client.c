/* Vulnerable update service - client
 * ithilgore@sock-raw.org
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/hmac.h>
#include <syslog.h>

#define PORT 31337
#define FIRMWARE_NAME "./received_firmware.gz"
#define KEY "jUiq1nzpIOaqrWa8R21"

static void fatal(char *fmt, ...)
  __attribute__ ((format (printf, 1, 2)));

static void fatal(char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fflush(stdout);
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\nQUITTING!\n");
  va_end(ap);
  exit(1);
}


int main(int argc, char **argv) {
  struct sockaddr_in servaddr;
  int sockfd, filelen, remaining_bytes;
  ssize_t bytes_received;
  size_t offset;
  unsigned char received_hash[16], calculated_hash[16];
  unsigned char *hash_p, *fw_p;
  unsigned int hash_len;
  uint32_t hdr_fwlen;
  char server_ip[16] = "127.0.0.1";
  FILE *file;

  if (argc > 1)
    strncpy((char *)server_ip, argv[1], sizeof(server_ip) - 1);

  openlog("firmware_update", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog(LOG_NOTICE, "firmware update process started with PID: %d", getpid());

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  inet_pton(AF_INET, server_ip, &(servaddr.sin_addr));
  servaddr.sin_port = htons(PORT);

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    fatal("Could not open socket %s\n", strerror(errno));

  if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(struct sockaddr)) == -1)
    fatal("Could not connect to server %s: %s\n", server_ip, strerror(errno));

  /* send the key to authenticate */
  write(sockfd, &KEY, sizeof(KEY));
  syslog(LOG_NOTICE, "Authenticating with %s using key %s", server_ip, KEY);

  /* receive firmware length */
  recv(sockfd, &hdr_fwlen, sizeof(hdr_fwlen), 0);
  filelen = ntohl(hdr_fwlen);
  printf("filelen: %d\n", filelen);

  /* receive hash */
  recv(sockfd, received_hash, sizeof(received_hash), 0);
  
  /* receive file */
  if (!(fw_p = malloc(filelen)))
    fatal("cannot allocate memory for incoming firmware\n");

  remaining_bytes = filelen;
  offset = 0;
  while (remaining_bytes > 0) {
    bytes_received = recv(sockfd, fw_p + offset, remaining_bytes, 0);
    offset += bytes_received; 
    remaining_bytes -= bytes_received;
#ifdef DEBUG
    printf("Received bytes %ld\n", bytes_received);
#endif
  }

  /* validate firmware by comparing received hash and calculated hash */
  hash_p = calculated_hash;
  hash_p = HMAC(EVP_md5(), &KEY, sizeof(KEY) - 1, fw_p, filelen, hash_p, &hash_len);

  printf("calculated hash: ");
  for (int i = 0; i < hash_len; i++)
    printf("%x", hash_p[i]);
  printf("\nreceived hash: ");
  for (int i = 0; i < sizeof(received_hash); i++)
    printf("%x", received_hash[i]);
  printf("\n");

  if (!memcmp(calculated_hash, received_hash, sizeof(calculated_hash)))
    printf("hashes match\n");
  else {
    fatal("hash mismatch\n");
  }

  /* write received firmware to disk */
  if (!(file = fopen(FIRMWARE_NAME, "w")))
    fatal("Can't open file for writing %s\n", strerror(errno));
  fwrite(fw_p, filelen, 1, file);

  syslog(LOG_NOTICE, "Firmware downloaded successfully");
  /* clean up */
  free(fw_p);
  fclose(file);
  close(sockfd);
  closelog();
  return 0;
}
