#include <asm-generic/errno-base.h>
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

#define pr_log(s, ...)				\
  {						\
    fprintf(log_file, s, ##__VA_ARGS__);	\
    fflush(log_file);				\
  }

#define free(x)                                                                \
  {                                                                            \
    pr_log("freeing_memory at %p\n", x);                                       \
    free(x);                                                                   \
  }

#define calloc(x, y) ({void *r = malloc(x * y); \
  if (r) memset(r, 0, x*y); \
  r;\
  })

#define malloc(x)  ({				\
      void* r = malloc(x);			\
      pr_log("malloc(%d) = %p\n", x, r);	\
      r;					\
    })

#define __must_check __attribute__((warn_unused_result))

#define QUEUE_DEPTH 1
#define BLOCK_SZ    1024
#define MAX_HOST_NAME 1024

#define EV_RECONNECT 0
#define EV_CONNECT 1
#define EV_SEND 2
#define EV_READ 3
#define EV_CLOSE 4

FILE*  log_file;

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
	const char *string_name;
	int state;
	struct input_node *node;
	struct list       *list;
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

int ci_reopen_socket(struct connection_info *ci);

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
	unsigned int size = min(sb->offset + 1, 16);
	char * res = malloc(size);
	if (!res) {
	        fprintf(log_file, "sb_build - Could not allocate memory for string of length %d\n", size);
		return NULL;
	}

	strncpy(res, sb->s, sb->offset);
	res[sb->offset] = '\0';
	*len = sb->offset;
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
	if (!slist->head || !slist->tail) {
		fprintf(log_file, "slist_pop - null-value head %p tail %p \n", slist->head, slist->tail);
		fflush(log_file);
	}
	struct input_node *old = slist->head;
	void *next = slist->head->next;
	if (old == slist->tail) slist->tail = next;
	slist->head = next;

        pr_log("slist_pop - freeing input_string \n");
	free(old->input_string);
	free(old);
	pr_log("slist_pop - end \n");
	return 0;
}

int ci_has_job(struct connection_info *ci) {
	if (ci->node != NULL) return 1;
	return 0;
}

void ci_release_job(struct connection_info *ci) {
	if (!ci->node) {
		fprintf(log_file, "release_job - ci->node == NULL\n");
		fflush(log_file);
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
		fprintf(log_file, "Reading from empty buffer\n");
        res = rb->buf[rb->r_offset++];
	if (rb->r_offset >= rb->len){
	    rb->r_offset -= rb->len;
	    if (rb->w_offset >= rb->len) rb->w_offset -= rb->len;
	}
	return res;
}

void rb_add(struct ring_buf *rb, struct connection_info *ci) {
	if (rb->w_offset == rb->len) rb->w_offset = 0;
	rb->buf[rb->w_offset++] = ci;
}

bool rb_empty(struct ring_buf *rb) {
  return rb->r_offset == rb->w_offset;
}

__must_check int add_connect_request(struct io_uring *ring, struct connection_info *cp)
{
	fprintf(log_file, "add_connect_request\n");
	fflush(log_file);
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
	fprintf(log_file, "add_connect_request - prep connect\n");
	io_uring_prep_connect(sqe, cp->socket, (const struct sockaddr*) &cp->address, sizeof(cp->address));
	io_uring_sqe_set_data(sqe, req);
	return 0;
}

__must_check int add_close_request(struct io_uring *ring, struct connection_info *cp)
{
	fprintf(log_file, "add_close_request\n");
	fflush(log_file);

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
	io_uring_sqe_set_data(sqe, req);
	return 0;
}

__must_check int add_send_request(struct io_uring *ring, struct connection_info *cp)
{
	fprintf(log_file, "add_close_request\n");
	fflush(log_file);
	
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
	fprintf(log_file, "add_read_request - start");
	fflush(log_file);
	struct io_uring_sqe *sqe;
	struct read_request *req;
	size_t size = sizeof(struct read_request);
	
	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -ENOMEM;
	req = calloc(1, size);
	fprintf(log_file, "add_read_request - %p", req);
	if (!req)
		return -ENOMEM;

	req->event_type = EV_READ;
	req->read_buff = rbp;
	io_uring_sqe_set_data(sqe, req);
	io_uring_prep_read(sqe, STDIN_FILENO, rbp->buff, 256, -1);
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

	fprintf(log_file, "read_aftermath - cqe->res: %d %s", cqe->res, buf);
	fflush(log_file);
	
	while (i < len) {
		for (; buf[i] != '\n' && i < len; ++i);

		if (buf[i] == '\n') {
			sb_append(sb, buf + offset, (i + 1) - offset);
			fprintf(log_file, "read_aftermath - i: %d, offset %d\n", i, offset);
			fflush(log_file);
			unsigned len = 0;
			char *res = sb_build(sb, &len);
			fprintf(log_file, "read_aftermath - len: %d, str: %s\n", i, res);
			fflush(log_file);
			if (!res) {
				free(rq);
				return 0;
			}
			slist_add(s_list, res, len, n);
			if (!next) next = s_list->tail;
		} else {
			fprintf(log_file, "read_aftermath - else hit");
			fflush(log_file);
			/* sb_append(sb, buf + offset, i - offset); //<i == len */
		}
		offset = i + 1;
		i = i+1;
		
	}

	fprintf(log_file, "read_aftermath - waking_up\n");
	fflush(log_file);
	if (next) {
		while (!rb_empty(sq)) {
			struct connection_info *ci = rb_pop(sq);
			fprintf(log_file, "read_aftermath - moving process to waiting queue - state %d\n", ci->state);
			fflush(stdout);
			ci->node = next;
			rb_add(wq, ci);
		}
	}
	
	fprintf(log_file, "read_aftermath - freeing, %p\n", rq);
	fflush(log_file);

        free((void *)cqe->user_data);

	fprintf(log_file, "read_aftermath - end %d\n", cqe->res);
	fflush(log_file);
	return 1;
}

void send_aftermath(struct io_uring_cqe *cqe, struct ring_buf *wq, struct ring_buf *sq) {
	fprintf(log_file, "send-aftermath - sent res %d\n", cqe->res);
	fflush(log_file);
	struct request *rq = (struct request *) cqe->user_data;
	
	if (cqe->res < 0) {
		fprintf(stderr, "%s - send error: %s\n", rq->cp->string_name, strerror(-cqe->res));
		rq->cp->state = EV_RECONNECT;
	} else if (cqe->res >= 0) {
		rq->cp->state = EV_SEND;
	}

	ci_release_job(rq->cp);

	
	if (ci_has_job(rq->cp)) {
		rb_add(wq, rq->cp);
	} else {
		rb_add(sq, rq->cp);
	}

	fprintf(log_file, "send-aftermath - sent res %d\n", cqe->res);
	fflush(log_file);

        free(rq);

        fprintf(log_file, "send-aftermath - end %d\n", cqe->res);
	fflush(log_file);
}

void connect_aftermath(struct io_uring_cqe *cqe, struct ring_buf *wq, struct ring_buf *sq, struct list *slist)
{
	struct request *rq = (struct request *) cqe->user_data;

	fprintf(log_file, "connect_aftermath res %d\n", cqe->res);
	fflush(log_file);
	
        if (cqe->res < 0) {
		fprintf(stderr, "%s - connect error: %s\n", rq->cp->string_name, strerror(-cqe->res));
		rq->cp->state = EV_RECONNECT;
		if (rq->cp->list == slist && ci_has_job(rq->cp)) {
			//Jesteśmy już po raz drugi w connect,
			//więc skipujemy linię, dla której nie udało się nam połączyć.
			ci_release_job(rq->cp);
		}
	} else {
		rq->cp->state = EV_SEND;
	}

	if (rq->cp->list != slist) {
		rq->cp->node = slist->head;
		rq->cp->list = slist;
	}

	if (ci_has_job(rq->cp)) {
		rb_add(wq, rq->cp);
	} else {
		rb_add(sq, rq->cp);
	}

	free(rq);
}

void close_aftermath(struct io_uring_cqe *cqe) {
	if (cqe->res < 0) {
	  struct request* req = (void *) cqe->user_data;
	  fprintf(stderr, "%s - close error: %s\n", req->cp->string_name, strerror(-cqe->res));
	}

	free((void *) cqe->user_data);
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

	if (!waiting_q) {
		fprintf(log_file, "main_loop - waiting_q == null\n");
	}
	if (!sleeping_q) {
		fprintf(log_file, "main_loop - sleeping_q == null\n");
	}
	if (!sb) {
		fprintf(log_file, "main_loop - sb == null\n");
	}
	
	int rc = 0;
	
	fprintf(log_file, "main_loop\n");
	fflush(log_file);
	
	for (int i = 0; i < n; ++i) {
		cip[i].state = EV_CONNECT;
		rb_add(waiting_q, &cip[i]);
	}

	fprintf(log_file, "main_loop - r: %d, w: %d\n", waiting_q->r_offset, waiting_q->w_offset);
	fflush(log_file);

	bool schedule_read = true;
	struct io_uring_cqe *cqe;
	int continue_loop = 1;
	int close_cnt = 0;
	int sched_open_cnt = 0;
	int open_cnt = 0;
	int pending = 0;
	while (1) {
		fprintf(log_file, "main_loop - main_loop r: %d, w: %d\n",
			waiting_q->r_offset, waiting_q->w_offset);
		fflush(log_file);

		unsigned x = io_uring_sq_space_left(ring);
		int rc;
		while (x > 0 && !rb_empty(waiting_q)) {
			struct connection_info *ci = rb_pop(waiting_q);
			switch(ci->state) {
			case EV_RECONNECT:
				rc = ci_reopen_socket(ci);
				if (rc < 0) continue;
				ci->state = EV_CONNECT;
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
			pending++;
		}
		if (x > 0 && schedule_read) {
			rc = add_read_request(ring, &read_buf);
			x--;
			schedule_read = false;
			submissions++;
			fprintf(log_file, "main_loop - scheduling read\n");
			pending++;
		}

		if (submissions > 0) {
			submissions = 0;
			io_uring_submit(ring);
		}

		if (!continue_loop) {
			while (!rb_empty(sleeping_q)){
				struct connection_info *ci = rb_pop(sleeping_q);
				if (ci->state == EV_CONNECT || ci->state == EV_RECONNECT)
				{
					++close_cnt;
				} else
				{
					ci->state = EV_CLOSE;
					rb_add(waiting_q, ci);
					fprintf(log_file, "main_loop - %s socket to close\n", ci->string_name);
				}
				
			}
			
			if (close_cnt == n)
				break;
			/* else */
			/* 	fprintf(stderr, "main_loop - close_cnt %d \n", close_cnt); */
		}
		
		/* fprintf(stderr, "main_loop - pending %d\n", pending); */

		if (pending == 0) {
			continue;
		}
		int ret = io_uring_wait_cqe(ring, &cqe);
		--pending;
		if (ret < 0) {
			/* fprintf(stderr, "main-loop - io_uring_wait_cqe < 0 - %d\n", ret); */
			abort();
		}
		fprintf(log_file, "main_loop - cqe\n");
                fflush(log_file);
		struct request *rq = (struct request *) cqe->user_data;
		int event = RQ_TYPE(rq);
		switch (event) {
		case EV_READ:
			continue_loop = read_aftermath(cqe, &slist, sb, n, sleeping_q, waiting_q);
			if (continue_loop) schedule_read = true;
			break;
		case EV_CONNECT:
			connect_aftermath(cqe, waiting_q, sleeping_q, &slist);
			break;
		case EV_SEND:
			send_aftermath(cqe, waiting_q, sleeping_q);
			break;
		case EV_CLOSE:
			close_aftermath(cqe);
			++close_cnt;
			break;
		default:
			/* fprintf(stderr, "main_loop - unkonwn event type: %d\n", event); */
			break;
		}
		fprintf(log_file, "main_loop - io_uring_cqe_seen: %d\n", event);
		io_uring_cqe_seen(ring, cqe);
		
	}

}


int sockaddr_init(struct sockaddr_in *sockadrr_in, char *input) {
	char ip[MAX_HOST_NAME];
	int port;
	const char *pos;

	char *server_ip = NULL;
	sockadrr_in->sin_family = AF_INET; // Use IPv4
	pos = strchr(input, ':');
	if (pos == NULL) goto err;
	int index = pos - input;
	if (index < MAX_HOST_NAME - 1) {
		strncpy(ip, input, index);
		ip[index] = '\0';
		server_ip = ip;
	} else {
		goto err;
	}

	sscanf(pos, ":%d", &port);
	sockadrr_in->sin_port = htons(port);

	if (inet_pton(AF_INET, server_ip, &sockadrr_in->sin_addr) <= 0) {
		fprintf(stderr, "sockadddr_init - could not resolve name: %s\n", ip);
		return  -1;
	}

	return  0;

err:
	return -1;
}


int ci_reopen_socket(struct connection_info *ci) {
	int rc = 0;
	if (ci->socket >= 0) close(ci->socket);
	ci->socket = socket(PF_INET, SOCK_STREAM, 0);
	if (ci->socket < 0) {
		rc = -1;
		fprintf(stderr, "%s - socket error %s\n", ci->string_name, strerror(errno));
	}
	rc = sockaddr_init(&ci->address, (char *) ci->string_name);
	if (rc < 0) {
		close(ci->socket);
	        ci->socket = -1;
		fprintf(stderr, "%s - socket error %s\n", ci->string_name, strerror(errno));
	}

	return rc;
};

struct connection_info *ci_alloc_and_init_table(unsigned n, char *input_strings[]) {
	struct connection_info * result = calloc(n, sizeof(struct connection_info));
	if (!result) return result;

	int rc = 0;
	for (int i = 0; i < n; ++i) {
		result[i].socket = socket(PF_INET, SOCK_STREAM, 0);
		if (result[i].socket < 0) {
		  fprintf(stderr, "%s - socket error %s\n", input_strings[i], strerror(errno));
		}
		rc = sockaddr_init(&result[i].address, input_strings[i]);
		if (rc < 0) {
		  close(result[i].socket);
		  result[i].socket = -1;
		  fprintf(stderr, "%s - socket error %s\n", input_strings[i], strerror(errno));
		}
		result[i].string_name = input_strings[i];
	}

	return result;
}

struct connection_info *ci_free_table(struct connection_info *table, int n) {
	free(table);
}



int main(int argc, const char *argv[]) {
	if (argc == 1) return 0;

	log_file = fopen("transmitter.log", "w+");

	struct io_uring ring;

	io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
	struct connection_info* ci_table = ci_alloc_and_init_table(argc -1, (char **) &argv[1]);

	if (!ci_table) goto uring_exit;

	main_loop(&ring, ci_table, argc - 1);
	ci_free_table(ci_table, argc - 1);


 uring_exit:
	io_uring_queue_exit(&ring);
}


