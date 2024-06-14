#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <liburing.h>
#include <arpa/inet.h>

#define QUEUE_DEPTH 1
#define BLOCK_SZ    1024
#define MAX_HOST_NAME 1024

struct request {
	int event_type;
	int iovec_count;
	int client_socket;
	struct iovec iov[];
};


int *create_sockets(int n, const char* ips[]) {
	int* result = malloc(n * sizeof(int));
	for (int i = 0; i < n; ++i) result[i] = -1;
	
	
	if (!result) return result;

	for (int i = 0; i < n; ++i) {
		result[i] = socket(PF_INET, SOCK_STREAM, 0);
		if (result[i] < 0)
			goto err_cleanup;
	}

	return result;
err_cleanup:
	return NULL;
}


struct sockaddr_in *create_sockaddrs(int n, const char *ips[]) {
	int i;
	ssize_t size = sizeof(struct sockaddr_in) * n;
	struct sockaddr_in *result = malloc(size);
	memset(result, 0, size);

	char ip[MAX_HOST_NAME];
	int port;
	const char *pos;
	for (i = 0; i < n; ++i) {
		char *server_ip = NULL;
		result[i].sin_family = AF_INET; // Use IPv4
	        result[i].sin_port = htons(port);
		pos = strchr(ips[i], ':');

		if (pos == NULL) goto err;
		int index = pos - ips[i];
		if (index < MAX_HOST_NAME - 1) {
			strncpy(ip, ips[i], index);
			ip[index + 1] = '\0';
			server_ip = ip;
		}


		if (inet_pton(AF_INET, server_ip, &result[i].sin_addr) <= 0) {
			goto err;
		}
	}


	return result;
err:
	return NULL;
}

int main(int argc, const char *argv[]) {
	if (argc == 1) return 0;

	struct io_uring ring;

	io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
	
	io_uring_queue_exit(&ring);
}


