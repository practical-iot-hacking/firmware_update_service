/* Vulnerable firmware update service - server
 * ithilgore@sock-raw.org
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdarg.h>
#include <openssl/hmac.h>

#define PORT 31337
#define FIRMWARE_NAME "./firmware.gz"
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

char *mmapfile(char *fname, int *length, int openflags) {
  struct stat st;
  int fd;
  char *fileptr;

  if (!length || !fname) {
    errno = EINVAL;
    return NULL;
  }
  *length = -1;

  if (stat(fname, &st) == -1) {
    errno = ENOENT;
    return NULL;
  }

  fd = open(fname, openflags);
  if (fd == -1) {
    return NULL;
  }

  fileptr = (char *)mmap(0, st.st_size, (openflags == O_RDONLY)? PROT_READ :
      (openflags == O_RDWR)? (PROT_READ|PROT_WRITE) 
      : PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);

  if (fileptr == (char *) -1)
    return NULL;

  *length = st.st_size;
  return fileptr;
}

void handle_request(int client_fd) {
  unsigned char *fp;
  int filelen, remaining_bytes;
  ssize_t bytes_sent;
  size_t offset; 
  char buf[32];
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned char *hash_p;
  unsigned int hash_len;
  uint32_t hdr_fwlen;

  /* Validate the client is authorized to access firmware */
  if (recv(client_fd, &buf, sizeof(buf), 0) < 0)
    fatal("Couldn't receive key from client\n");
  if (strncmp(buf, KEY, sizeof(KEY)-1))
    fatal("Incorrect key\n");
  printf("Credentials accepted.\n");

  /* map whole firmware file to memory */
  if (!(fp = (unsigned char *)mmapfile(FIRMWARE_NAME, &filelen, O_RDONLY)))
    fatal("Could not mmap() %s", FIRMWARE_NAME);
  
  /* calculate md5 hash of firmware file */
  hash_p = hash;
  hash_p = HMAC(EVP_md5(), &KEY, sizeof(KEY) - 1, fp, filelen, hash_p, &hash_len);
  printf("hash: ");
  for (int i = 0; i < hash_len; i++)
    printf("%x", hash[i]);
  printf("\n");

  /* send the firmware length */
  printf("filelen: %d\n", filelen);
  hdr_fwlen = htonl(filelen);
  write(client_fd, &hdr_fwlen, sizeof(hdr_fwlen));

  /* send the checksum */
  write(client_fd, hash_p, hash_len);

  /* Now send the firmware file */
  remaining_bytes = filelen;
  offset = 0;
  while (remaining_bytes > 0) {
    if (remaining_bytes >= BUFSIZ)
      bytes_sent = write(client_fd, fp + offset, BUFSIZ);
    else
      bytes_sent = write(client_fd, fp + offset, remaining_bytes);
#ifdef DEBUG
    printf("sent bytes: %ld\n", bytes_sent);
#endif
    remaining_bytes -= bytes_sent;
    offset += bytes_sent;
  }
  exit(0);
}

int main(int argc, char **argv) {
  struct sockaddr_in servaddr;
  char client_str[INET_ADDRSTRLEN];
  int sockfd;
  
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    fatal("Could not open socket\n");

  int enable = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    perror("setsockopt(SO_REUSEADDR) failed");

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_port = htons(PORT);
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) != 0)
    fatal("Socket bind failed\n");

  if (listen(sockfd, 128) != 0)
    fatal("Could not listen\n");

  printf("Listening on port %d\n", PORT);

  while (1) {
    struct sockaddr_in client_sa;
    socklen_t size = sizeof(client_sa);
    int client_fd = accept(sockfd, (struct sockaddr *) &client_sa, &size);
    if (client_fd < 0) {
      perror("Accept failed\n");
    } else {
      inet_ntop(AF_INET, &(client_sa.sin_addr), client_str, INET_ADDRSTRLEN);
      printf("Connection from %s\n", client_str);

      int pid = fork();
      if (pid == -1) {
        perror("Could not fork\n");
      } else if (pid == 0) {
        handle_request(client_fd);
      }
    }
  }
}
