#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#define BIND_PORT (5000)
#define MAXEVENTS (16)
#define MAXCONS (16)
#define TIMEOUT (10)

typedef struct
{
	int used;
	struct sockaddr_in addr;
	int addrlen;
	int tfd;

} cxn_ctx;

typedef void(*event_handler)(int, void *);

typedef struct
{
	int fd;
	event_handler handler;
	void *user_data;

} event_parcel;

static cxn_ctx cxns[MAXCONS];
static int efd;
static int sfd;

void do_error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int get_cxn(struct sockaddr_in src_addr, int len, cxn_ctx **out)
{
	int i;
	for(i = 0; i < MAXCONS; i++)
		if(cxns[i].used && (0 == memcmp(&cxns[i].addr, &src_addr, len)))
			break;

	if(i != MAXCONS)
	{
		if(out)
			*out = &cxns[i];
		return 0;
	}
	else
		return -1;
}

cxn_ctx *add_cxn(struct sockaddr_in src_addr, int len)
{
	int i;
	for(i = 0; i < MAXCONS; i++)
	{
		if(cxns[i].used)
			continue;

		cxns[i].used = 1;
		cxns[i].addr = src_addr;
		cxns[i].addrlen = len;

		return &cxns[i];
	}
}

void del_cxn(cxn_ctx *cxn)
{
	cxn->used = 0;
}

void add_event(int fd, event_handler handler, void *user_data)
{
	event_parcel *parcel;
	if(NULL == (parcel = malloc(sizeof(event_parcel))))
		do_error("malloc() error");

	parcel->fd = fd;
	parcel->handler = handler;
	parcel->user_data = user_data;

	struct epoll_event event;
	event.data.ptr = parcel;
	event.events = EPOLLIN | EPOLLET;
	if(-1 == epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event))
		do_error("epoll_ctl");
}

void handle_timeout(int fd, void *user_data)
{
	cxn_ctx *cxn = (cxn_ctx*)user_data;
	printf("Timeout happened - removing connection\n");
	del_cxn(cxn);

	uint64_t exp;
	read(fd, &exp, sizeof(uint64_t));
}

void handle_stdin(int fd, void *user_data)
{
	char buf[1500];

	int len = read(fd, buf, 1500);

	int i;
	for(i = 0; i < MAXCONS; i++)
	{
		if(cxns[i].used)
		{
			if(-1 == sendto(sfd, buf, len, 0, &cxns[i].addr, cxns[i].addrlen))
				do_error("sendto");
		}
	}
}

void handle_udp_socket(int fd, void *user_data)
{
	struct sockaddr_in src_addr;
	int server_len = sizeof(struct sockaddr_in);
	ssize_t msg_len;
	char recv_buf[1500] = {0, };
	int tfd;

	if(-1 == (msg_len = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, &src_addr, &server_len)))
		do_error("Error while receiving a message");

	// Write the message to stdout
	fwrite(recv_buf, msg_len, 1, stdout);

	cxn_ctx *cxn;

	if(-1 == get_cxn(src_addr, server_len, &cxn))
	{
		printf("New source, adding...\n");
		cxn_ctx *cxn;
		if(NULL == (cxn = add_cxn(src_addr, server_len)))
			do_error("No more room for connections!");

		// Set up a timer to timeout this connection eventually
		if(-1 == (tfd = timerfd_create(CLOCK_REALTIME, 0)))
			do_error("timerfd_create");

		struct itimerspec itval;
		itval.it_interval.tv_sec = 0;
		itval.it_interval.tv_nsec = 0;
		itval.it_value.tv_sec = TIMEOUT;
		itval.it_value.tv_nsec = 0;

		if (timerfd_settime(tfd, 0, &itval, NULL) == -1)
			do_error("timerfd_settime");

		add_event(tfd, handle_timeout, (void*)cxn);

		cxn->tfd = tfd;
	}
	else
	{
		struct itimerspec itval;
		itval.it_interval.tv_sec = 0;
		itval.it_interval.tv_nsec = 0;
		itval.it_value.tv_sec = TIMEOUT;
		itval.it_value.tv_nsec = 0;

		// Existing connection - reset the timeout
		if (timerfd_settime(cxn->tfd, 0, &itval, NULL) == -1)
			do_error("timerfd_settime");
	}
}

int main(int argc, char *argv[])
{
	memset(cxns, 0, sizeof(cxns));

	// Create a new epoll fd
	if(-1 == (efd = epoll_create1(0)))
		do_error("epoll_create1()");

	// Open a UDP socket
	if(-1 == (sfd = socket(AF_INET, SOCK_DGRAM, 0)))
		do_error("Unable to open socket");

	// Configure the bind address and port
	struct sockaddr_in serv_addr;

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(BIND_PORT);

	// Bind to local address and port
	if(-1 == bind(sfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)))
		do_error("Unable to bind");

	add_event(sfd, handle_udp_socket, NULL);
	add_event(0, handle_stdin, NULL);

	struct epoll_event *events;
	if(NULL == (events = calloc(MAXEVENTS, sizeof(struct epoll_event))))
		do_error("calloc error");

	// Spin forever listening for messages
	while(1)
	{
		int nevents, i;

		if(-1 == (nevents = epoll_wait(efd, events, MAXEVENTS, -1)))
			do_error("Error waiting for epoll events");

		for (i = 0; i < nevents; i++)
		{
			struct epoll_event *evt = &events[i];

			if ((evt->events & EPOLLERR) ||
			   (evt->events & EPOLLHUP) ||
			   (!(evt->events & EPOLLIN)))
			{
				/* An error has occurred on this fd, or the socket is not
				 ready for reading (why were we notified then?) */
				fprintf (stderr, "epoll error\n");
				close (evt->data.fd);
				continue;
			}
			else if(evt->events & EPOLLIN)
			{
				event_parcel *parcel = (event_parcel*)evt->data.ptr;
				parcel->handler(parcel->fd, parcel->user_data);
			}
		}

	}

	// Mr clean
	close(sfd);
	close(efd);
}
