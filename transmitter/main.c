#include <asm-generic/errno-base.h>
#include <liburing/io_uring.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <liburing.h>
#include <arpa/inet.h>

 #define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

 #define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })



#define __must_check __attribute__((warn_unused_result))

#define QUEUE_DEPTH 1
#define BLOCK_SZ    1024
#define MAX_HOST_NAME 1024

#define EV_CONNECT 1
#define EV_SEND 2
#define EV_READ 3
#define EV_CLOSE 4

struct connection_info;
struct input_node;
struct read_buff;

struct request {
	int event_type;
	struct connection_info *cp;
	char padding[4];
};

struct read_request {
	int event_type;
	struct read_buff* read_buff;
	char padding[4];
};

struct read_buff {
        char buff[2048];
	unsigned length;
	unsigned size;
};
	
struct list {
	struct input_node *head;
	struct input_node *tail;
};

struct input_node {
	char *input_string;
	unsigned int len;
	unsigned int pending_sends;
	struct input_node *next;
};

struct connection_info {
	int socket;
	struct sockaddr_in address;
	int state;
	struct list * list;
	struct input_node *node;
};

struct ring_buf {
        struct connection_info **buf;
	unsigned r_offset;
	unsigned w_offset;
	unsigned len;
};

struct string_builder {
	char *s;
	unsigned offset;
	int size;
};

struct ring_buf *rb_allocate(unsigned n) {
	void * buf = malloc(n  * sizeof(void *));
	if (!buf) return NULL;
        struct ring_buf *res = calloc(1, sizeof(struct ring_buf));
	if (!res) {
		free(buf);
		return NULL;
	}
	res->len = n;
	res->buf = buf;
	return res;
}

void rb_free(struct ring_buf *rb) {
	free(rb->buf);
	free(rb);
}



struct string_builder *alloc_string_builder() {
	char *s = malloc(2048);
	struct string_builder *sb = malloc(sizeof(struct string_builder));
	if (sb) {
		sb->offset = 0;
		sb->s = s;
		sb->size = 2048;
	} else {
		free(s);
	}
	
	return sb;
}


int sb_append(struct string_builder *sb, char *buff, unsigned len) {
	if (sb->offset + len >= sb->size) {
		size_t new_size = max(sb->offset + len, sb->size * 2);
		void * s = realloc(sb->s, new_size);
		if (!buff) return -ENOMEM;
		sb->s = s;
		sb->size = new_size;
	
	}
	strncpy(sb->s + sb->offset, buff, len);
	sb->offset += len;
	
	return 0;
}

char *sb_build(struct string_builder *sb, unsigned int *len) {
	unsigned int size = min(sb->offset + 2, 16);
	char * res = malloc(size);
	if (!res) {
		fprintf(stderr, "sb_build - Could not allocate memory for string of length %d", size);
		return NULL;
	}

	strncpy(res, sb->s, sb->offset + 1);
	res[sb->offset + 1] = '\0';
	*len = sb->offset + 2;
	sb->offset = 0;
	
	return res;
}

void sb_free(struct string_builder *sb) {
	if (sb->s) free(sb->s);
	free(sb);
}

int slist_add(struct list *slist, char *buf, unsigned len, int n)
{
	struct input_node* node = malloc(sizeof(struct input_node));
	if (!node) return -ENOMEM;
	
	node->next = NULL;
	node->input_string = buf;
	node->len = len;
	node->pending_sends = n;
	if (slist->head == NULL)
		slist->head = node;
	if (slist->tail) {
		slist->tail->next = node;
	}
	slist->tail = node;

	return 0;
}

int slist_pop(struct list *slist) {
	if (!slist->head || !slist->tail)
		fprintf(stderr, "slist_pop - null-value head %p tail %p ", slist->head, slist->tail);
	struct input_node *old = slist->head;
	void *next = slist->head->next;
	if (old == slist->tail) slist->tail = next;
	slist->head = next;

	free(old->input_string);
	free(old);
}

int ci_has_job(struct connection_info *ci) {
	if (ci->node != NULL) return 1;
	return 0;
}

void ci_release_job(struct connection_info *ci) {
	if (!ci->node) {
		fprintf(stderr, "release_job - ci->node == NULL");
	}
	void *next = ci->node->next;
	ci->node->pending_sends -= 1;
	
	if (ci->node->pending_sends == 0){
		slist_pop(ci->list);
	}
	ci->node = next;
}


struct connection_info *rb_pop(struct ring_buf *rb) {
	void *res;
	if (rb->r_offset == rb->w_offset)
		fprintf(stderr, "Reading from empty buffer");
        res = rb->buf[rb->r_offset++];
	if (rb->r_offset >= rb->len) rb->r_offset -= rb->len;
	return res;
}

void rb_add(struct ring_buf *rb, struct connection_info *ci) {
	if (rb->w_offset == rb->len) rb->w_offset = 0;
	rb->buf[rb->w_offset++] = ci;
}

bool rb_empty(struct ring_buf *rb) {
	return rb->r_offset != rb->w_offset;
}

__must_check int add_connect_request(struct io_uring *ring, struct connection_info *cp)
{
	struct io_uring_sqe *sqe;
	struct request *req;
	size_t size = sizeof(struct request);
	
	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -ENOMEM;
	req = calloc(1, size);
	if (!req)
		return -ENOMEM;

	req->event_type = EV_CONNECT;
	req->cp = cp;
	io_uring_prep_connect(sqe, cp->socket, (const struct sockaddr*) &cp->address, sizeof(cp->address));
	io_uring_sqe_set_data(sqe, req);
	return 0;
}

__must_check int add_close_request(struct io_uring *ring, struct connection_info *cp)
{
	struct io_uring_sqe *sqe;
	struct request *req;
	size_t size = sizeof(struct request);
	
	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -ENOMEM;
	req = calloc(1, size);
	if (!req)
		return -ENOMEM;

	req->event_type = EV_CLOSE;
	req->cp = cp;
	io_uring_prep_close(sqe, cp->socket);

	return 0;
}

__must_check int add_send_request(struct io_uring *ring, struct connection_info *cp)
{
	struct io_uring_sqe *sqe;
	struct request *req;
	size_t size = sizeof(struct request);
	
	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -ENOMEM;
	req = calloc(1, size);
	if (!req)
		return -ENOMEM;

	req->event_type = EV_SEND;
	req->cp = cp;
	io_uring_prep_send(sqe, cp->socket, cp->node->input_string, cp->node->len, 0);
	io_uring_sqe_set_data(sqe, req);
	return 0;
}

__must_check int add_read_request(struct io_uring *ring, struct read_buff *rbp)
{
	struct io_uring_sqe *sqe;
	struct read_request *req;
	size_t size = sizeof(struct read_request);
	
	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -ENOMEM;
	req = calloc(1, size);
	if (!req)
		return -ENOMEM;

	req->event_type = EV_READ;
	req->read_buff = rbp;
	io_uring_prep_read(sqe, STDIN_FILENO, rbp->buff, 256, 0);
	io_uring_sqe_set_data(sqe, req);
	return 0;
}

int move_to_(struct connection_info *cp, struct list *list)
{
}

#define RQ_TYPE(req)                       { *((int *)req) }

int read_aftermath(struct io_uring_cqe *cqe, struct list *s_list, struct string_builder *sb, int n,
		   struct ring_buf *sq, struct ring_buf *wq)
{
	if (cqe->res < 0  || cqe->res == 0) {
		free((void *) cqe->user_data);
		return 0;
	}
	//Brak zwolnienia pamięci;

	unsigned len = cqe->res;
	struct read_request *rq = (struct read_request *) cqe->user_data;
	char *buf = rq->read_buff->buff;
	unsigned i = 0;
	unsigned offset = 0;
	struct input_node *next = NULL;
	
	while (i < len) {
		for (; buf[i] != '\n' && i < len; ++i);
		sb_append(sb, buf + offset, (i + 1) - offset);
		offset = i + 1;
		if (i < len) {
			unsigned len = 0;
			char *res = sb_build(sb, &len);
			fprintf(stderr, "read_aftermath - read string: %s", res);
			if (!res) {
				free(rq);
				return 0;
			}
			slist_add(s_list, res, len, n);
			if (!next) next = s_list->tail;
			i++;
		}
	}

	if (next) {
		while (!rb_empty(sq)) {
			fprintf(stderr, "read_aftermath - moving process to waiting queue");
			struct connection_info *ci = rb_pop(sq);
			ci->node = next;
			rb_add(wq, ci);
		}
	}
	
	free(rq);
	return 1;
}

void send_aftermath(struct io_uring_cqe *cqe, struct ring_buf *wq, struct ring_buf *sq) {
	fprintf(stderr, "send-aftermath - sent res %d", cqe->res);
	struct request *rq = (struct request *) cqe->user_data;
	
	if (cqe->res < 0) {
		return;
	} else if (cqe->res >= 0) {
		
	}

	ci_release_job(rq->cp);
	rq->cp->state = EV_SEND;
	
	if (ci_has_job(rq->cp)) {
		rb_add(wq, rq->cp);
	} else {
		rb_add(sq, rq->cp);
	}

	free(rq);

}

void connect_aftermath(struct request *rq, struct ring_buf *wq, struct ring_buf *sq)
{
	rq->cp->state = EV_SEND;
	
	if (ci_has_job(rq->cp)) {
		rb_add(wq, rq->cp);
	} else {
		rb_add(sq, rq->cp);
	}

	free(rq);
}

void close_aftermath(struct io_uring_cqe *cqe) {
	if (cqe->res < 0) {
		"TODO";
	}
}

void main_loop(struct io_uring *ring, struct connection_info* cip, int n) {
	void *waiting_queue[n+1];
	unsigned int submissions = 0;
	waiting_queue[0] = NULL;

	struct list slist = {0,0};
	struct read_buff read_buf = {.length = 0, .size = 2048};
	struct ring_buf *waiting_q = rb_allocate(n);
	struct ring_buf *sleeping_q = rb_allocate(n);
	struct string_builder *sb = alloc_string_builder();

	int rc = 0;
	
	for (int i = 0; i < n; ++i) {
		cip[i].state = EV_CONNECT;
		rb_add(waiting_q, &cip[i]);
	}

	fprintf(stderr, "main_loop - r: %d, w: %d", waiting_q->r_offset, waiting_q->w_offset);

	rc = add_read_request(ring, &read_buf);
	++submissions;
	
	bool schedule_read = true;
	struct io_uring_cqe *cqe;
	int continue_loop = 0;
	int close_cnt = 0;
	while (1) {
		int ret = io_uring_wait_cqe(ring, &cqe);
		struct request *rq = (struct request *) cqe->user_data;
		int event = RQ_TYPE(rq);

		switch (event) {
		case EV_READ:
			continue_loop = read_aftermath(cqe, &slist, sb, n, sleeping_q, waiting_q);
			if (continue_loop) schedule_read = true;
			break;
		case EV_CONNECT:
			connect_aftermath(rq, waiting_q, sleeping_q);
			break;
		case EV_SEND:
			send_aftermath(cqe, waiting_q, sleeping_q);
			break;
		case EV_CLOSE:
			close_aftermath(cqe);
			++close_cnt;
			break;
		default:
			fprintf(stderr, "main_loop - unkonwn event type: %d", event);
		}

		io_uring_cqe_seen(ring, cqe);
		
		unsigned x = io_uring_sq_space_left(ring);
		fprintf(stderr, "main_loop - sq_space_left %d", x);
		int rc;
		if (x > 0 && schedule_read) {
			rc = add_read_request(ring, &read_buf);
			x--;
			schedule_read = false;
			submissions++;
		}
		while (x > 0 && !rb_empty(waiting_q)) {
			struct connection_info *ci = rb_pop(waiting_q);
			switch(ci->state) {
			case EV_CONNECT:
				rc = add_connect_request(ring, ci);
				break;
			case EV_SEND:
				rc = add_send_request(ring, ci);
				break;
			case EV_CLOSE:
				rc = add_close_request(ring, ci);
				break;
			}
			--x;
			submissions++;
		}

		if (submissions > 0) {
			io_uring_submit(ring);
		}

		if (!continue_loop && close_cnt != n)
			break;
	}

}


int *create_sockets(int n, const char* ips[])
{
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


