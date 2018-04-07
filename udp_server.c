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
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <argp.h>		// Intelligent argument parsing
#include <netdb.h>

#define BIND_PORT (5000)
#define MAXEVENTS (16)
#define MAXCONS (16)
#define TIMEOUT (10)
#define SERVER_SCRIPT "server.sh"
#define CLIENT_SCRIPT "client.sh"
#define APP_NAME "mptunnel"
#define VERSION "0.1.0"
#define MAX_IPS (16)

#define WITH_DEBUG

#ifdef WITH_DEBUG
	#define mptunnel_debug(...) fprintf (stdout, __VA_ARGS__)
#else
	#define mptunnel_debug(...) /**/
#endif

typedef struct
{
	int used;
	int fd;
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

typedef struct
{
	int server;
	char *host;
	char *tun;
	char *ips[MAX_IPS];
	int ip_count;
	int foreground;

} args_t;

static cxn_ctx cxns[MAXCONS];
static int efd;
static int server_sockfd;
static int tun_fd;

/**
 * Client version string
 */
const char *argp_program_version = APP_NAME " v" VERSION;

static char doc[] = "Push-to-talk application";
static char args_doc[] = "";

/**
 * List of supported options.
 */
static struct argp_option options[] = {
	{ "server", 's', NULL, 0, "Run as a server." },
	{ "client", 'c', "HOSTNAME", 0, "Run as a client. Default = localhost" },
	{ "tun", 't', "TUN", 0, "Tun name. Default = 'tun0'"},
	{ "src", 'i', "SOURCE", 0, "Source IP to send from. Client mode only. Can (and should) specify multiple interfaces."},
	{ "foreground", 'f', NULL, 0, "Run in the foreground."},
	{ NULL } // Needs to be NULL terminated
};

/**
 * @brief	Called by argp to parse out options from the command line arguments.
 *
 * @param[in]	key			Character representing the option specified.
 * @param[in]	arg			Pointer to the string containing the value of the option.
 * @param[in]	argp_state	The context structure.
 *
 * @returns		error_t		Error code enum.
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	args_t *args = (args_t *)state->input;

	switch (key)
	{
		case 's':
		{
			args->server = 1;
			args->host = NULL;
			break;
		}
		case 'c':
		{
			args->server = 0;
			args->host = arg;
			break;
		}
		case 't':
		{
			args->tun = arg;
			break;
		}
		case 'i':
		{
			args->ips[args->ip_count] = arg;
			mptunnel_debug("[DEBUG] Binding to %s\n", arg);
			break;
		}
		case 'f':
		{
			args->foreground = 1;
			break;
		}
		case ARGP_KEY_ARG:
		{
			return 0;
		}
		default:
		{
			return ARGP_ERR_UNKNOWN;
		}
	}
	return 0;
}

/**
 * This structure holds the option passed to the argp library to configure the arguments this application supports.
 */
static struct argp argp = { options, parse_opt, args_doc, doc };

/**
 * Prints errno description using perror then exits with failure.
 * @param[in]	msg		Error message.
 */
static void do_error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

/**
 * Configure the tun interface using a script.
 * @param[in]	server	0 if we are a client otherwise server.
 */
static void configure_network(int server)
{
  int pid, status;
  char path[100];
  char *const args[] = {path, NULL};

  mptunnel_debug("configure_network...");

  if (server) {
    if (sizeof(SERVER_SCRIPT) > sizeof(path)){
      perror("Server script path is too long\n");
      exit(EXIT_FAILURE);
    }
    strncpy(path, SERVER_SCRIPT, strlen(SERVER_SCRIPT) + 1);
  }
  else {
    if (sizeof(CLIENT_SCRIPT) > sizeof(path)){
      perror("Client script path is too long\n");
      exit(EXIT_FAILURE);
    }
    strncpy(path, CLIENT_SCRIPT, strlen(CLIENT_SCRIPT) + 1);
  }

  mptunnel_debug("Forking...");
  pid = fork();

  if (pid == -1) {
    perror("Unable to fork\n");
    exit(EXIT_FAILURE);
  }

  if (pid==0) {
    // Child process, run the script
    exit(execv(path, args));
  }
  else {
    // Parent process
    waitpid(pid, &status, 0);
    if (WEXITSTATUS(status) == 0) {
      // Script executed correctly
    	mptunnel_debug("[DEBUG] Script ran successfully\n");
    }
    else {
      // Some error
    	mptunnel_debug("[DEBUG] Error in running script\n");
    }
  }
}

/**
 * Allocates a tunnel.
 */
static int tun_alloc(char *dev, int flags)
{
	struct ifreq ifr;
	int tun_fd, err;
	char *clonedev = "/dev/net/tun";
	mptunnel_debug("[DEBUG] Allocating tunnel\n");

	// Open the tunnel device
	if(-1 == (tun_fd = open(clonedev, O_RDWR)))
		do_error("[ERROR] Unable to open clone device\n");

	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_flags = flags;

	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (0 > (err = ioctl(tun_fd, TUNSETIFF, (void *)&ifr)))
	{
		close(tun_fd);
		do_error("[ERROR] ioctl");
	}

	mptunnel_debug("[DEBUG] Allocating tunnel2");
	mptunnel_debug("[DEBUG] Created tunnel %s\n", dev);

	return tun_fd;
}

static int get_cxn(struct sockaddr_in src_addr, int len, cxn_ctx **out)
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

static cxn_ctx *add_cxn(struct sockaddr_in *src_addr, int len, int fd)
{
	int i;
	for(i = 0; i < MAXCONS; i++)
	{
		if(cxns[i].used)
			continue;

		cxns[i].used = 1;
		memcpy(&cxns[i].addr, src_addr, len);
		cxns[i].addrlen = len;
		cxns[i].fd = fd;

		return &cxns[i];
	}

	mptunnel_debug("[WARNING] Unable to allocate this connection... out of space\n");
	return NULL;
}

void del_cxn(cxn_ctx *cxn)
{
	cxn->used = 0;
}

static void add_event(int fd, event_handler handler, void *user_data)
{
	event_parcel *parcel;
	if(NULL == (parcel = malloc(sizeof(event_parcel))))
		do_error("[ERROR] malloc() error");

	parcel->fd = fd;
	parcel->handler = handler;
	parcel->user_data = user_data;

	struct epoll_event event;
	event.data.ptr = parcel;
	event.events = EPOLLIN | EPOLLET;
	if(-1 == epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event))
		do_error("[ERROR] epoll_ctl");
}

static void handle_timeout(int fd, void *user_data)
{
	cxn_ctx *cxn = (cxn_ctx*)user_data;
	mptunnel_debug("[DEBUG] Timeout happened - removing connection\n");
	del_cxn(cxn);

	uint64_t exp;
	read(fd, &exp, sizeof(uint64_t));
}

static void handle_tun(int fd, void *user_data)
{
	char buf[1500];

	int len = read(fd, buf, 1500);

	mptunnel_debug("[DEBUG] READ %d bytes from the tun\n", len);

	int i;
	for(i = 0; i < MAXCONS; i++)
	{
		if(cxns[i].used)
		{
			if(-1 == sendto(cxns[i].fd, buf, len, 0, (struct sockaddr*)&cxns[i].addr, cxns[i].addrlen))
				do_error("[ERROR] sendto()");
		}
	}
}

static void handle_udp_socket_client(int fd, void *user_data)
{
	struct sockaddr_in src_addr;
	int server_len = sizeof(struct sockaddr_in);
	ssize_t msg_len;
	char recv_buf[1500] = {0, };
	int tfd;

	if(-1 == (msg_len = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&src_addr, &server_len)))
		do_error("[ERROR] Error while receiving a message");

	// Write the message to the tun for debug
	write(tun_fd, recv_buf, msg_len);

	mptunnel_debug("[DEBUG] WROTE %d bytes to the tun\n", msg_len);
	//fwrite(recv_buf, msg_len, 1, stdout);
}

static void handle_udp_socket(int fd, void *user_data)
{
	struct sockaddr_in src_addr;
	int server_len = sizeof(struct sockaddr_in);
	ssize_t msg_len;
	char recv_buf[1500] = {0, };
	int tfd;

	if(-1 == (msg_len = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&src_addr, &server_len)))
		do_error("[ERROR] Error while receiving a message");

	// Write the message to stdout
	//fwrite(recv_buf, msg_len, 1, stdout);
	write(tun_fd, recv_buf, msg_len);

	mptunnel_debug("[DEBUG] WROTE %d bytes to the tun\n", msg_len);

	cxn_ctx *cxn;

	if(-1 == get_cxn(src_addr, server_len, &cxn))
	{
		mptunnel_debug("[DEBUG] New source, adding...\n");
		cxn_ctx *cxn;
		if(NULL == (cxn = add_cxn(&src_addr, server_len, server_sockfd)))
			do_error("[ERROR] No more room for connections!");

		// Set up a timer to timeout this connection eventually
		if(-1 == (tfd = timerfd_create(CLOCK_REALTIME, 0)))
			do_error("[ERROR] timerfd_create()");

		struct itimerspec itval;
		itval.it_interval.tv_sec = 0;
		itval.it_interval.tv_nsec = 0;
		itval.it_value.tv_sec = TIMEOUT;
		itval.it_value.tv_nsec = 0;

		if (timerfd_settime(tfd, 0, &itval, NULL) == -1)
			do_error("[ERROR] timerfd_settime");

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
			do_error("[ERROR] timerfd_settime");
	}
}

static void configure_server(void)
{
	// Reset down the list of connections
	memset(cxns, 0, sizeof(cxns));

	// Open a UDP socket
	if(-1 == (server_sockfd = socket(AF_INET, SOCK_DGRAM, 0)))
		do_error("[ERROR] Unable to open socket");

	// Configure the bind address and port
	struct sockaddr_in serv_addr;
	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(BIND_PORT);

	// Bind to local address and port
	if(-1 == bind(server_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)))
		do_error("[ERROR] Unable to bind");

	fcntl(server_sockfd, F_SETFL, O_NONBLOCK);
	add_event(server_sockfd, handle_udp_socket, NULL);

	mptunnel_debug("[DEBUG] Listening on port %d\n", BIND_PORT);
}

static int create_socket(const char *node, const char *service) /* {{{ */
{
	struct addrinfo  ai_hint;
	struct addrinfo *ai_list;
	struct addrinfo *ai_ptr;
	int status;

	mptunnel_debug ("[DEBUG] create_socket (node = %s, service = %s);\n",
			node, service);

	memset (&ai_hint, 0, sizeof (ai_hint));

	ai_hint.ai_family = AF_UNSPEC;
	ai_hint.ai_socktype = SOCK_DGRAM;
	ai_hint.ai_protocol = 0;
#ifdef AI_ADDRCONFIG
	ai_hint.ai_flags |= AI_ADDRCONFIG;
#endif

	ai_list = NULL;
	status = getaddrinfo(node, service, &ai_hint, &ai_list);
	if (status != 0)
		return (-1);

	if(ai_list == NULL)
		do_error("Bad address");

	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next)
	{
		mptunnel_debug("[DEBUG] Attempting to connect.\n");

		int fd;
		int status;

		fd = socket (ai_ptr->ai_family, ai_ptr->ai_socktype,
				ai_ptr->ai_protocol);
		if (fd < 0)
		{
			mptunnel_debug ("[DEBUG] create_socket: socket(2) failed.\n");
			continue;
		}

		// Configure the bind address and port
		struct sockaddr_in serv_addr;
		memset(&serv_addr, '0', sizeof(serv_addr));

		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(BIND_PORT);

		// Bind to local address and port
		if(-1 == bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)))
			do_error("[ERROR] Unable to bind");

		fcntl(fd, F_SETFL, O_NONBLOCK);

		// Add this as a connection in the connection list
		add_cxn(ai_ptr->ai_addr, ai_ptr->ai_addrlen, fd);

		freeaddrinfo (ai_list);
		mptunnel_debug("[DEBUG] Socket OK\n");
		return (fd);
	}

	freeaddrinfo (ai_list);
	do_error("No addresses to be found...");

	return -1;
}

/**
 * Configure as a client.
 * @param[in]	args	Arguments.
 */
void configure_client(args_t *args)
{
	int fd = create_socket(args->host, "5000");
	add_event(fd, handle_udp_socket_client, NULL);
}

int main(int argc, char *argv[])
{
	// Configure default arguments and parse
	args_t args;
	memset((void*)&args, 0, sizeof(args_t));
	argp_parse(&argp, argc, argv, 0, 0, (void*)&args);

	// Create a new epoll fd
	if(-1 == (efd = epoll_create1(0)))
		do_error("[ERROR] epoll_create1()");

	struct epoll_event *events;
	if(NULL == (events = calloc(MAXEVENTS, sizeof(struct epoll_event))))
		do_error("[ERROR] calloc error");

	// Allocate the tunnel
	tun_fd = tun_alloc("tun0", IFF_TUN | IFF_NO_PI);
	fcntl(tun_fd, F_SETFL, O_NONBLOCK);
	add_event(tun_fd, handle_tun, NULL);

	configure_network(args.server);

	if(args.server)
	{
		mptunnel_debug("Running as server");
		configure_server();
	}
	else
	{
		mptunnel_debug("Running as client");
		configure_client(&args);
	}

	// Spin forever listening for messages
	while(1)
	{
		int nevents, i;

		if(-1 == (nevents = epoll_wait(efd, events, MAXEVENTS, -1)))
			do_error("[ERROR] Error waiting for epoll events");

		for (i = 0; i < nevents; i++)
		{
			struct epoll_event *evt = &events[i];

			if ((evt->events & EPOLLERR) ||
			   (evt->events & EPOLLHUP) ||
			   (!(evt->events & EPOLLIN)))
			{
				/* An error has occurred on this fd, or the socket is not
				 ready for reading (why were we notified then?) */
				perror("epoll error");
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
	close(server_sockfd);
	close(efd);
}
