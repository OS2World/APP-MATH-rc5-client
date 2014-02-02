#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#define MAXHOSTNAMELEN  20

#include "common.h"

#ifdef SOCKS
#include "socks.h"
#endif

struct in_addr keyserver_addr;
unsigned short keyserver_port = 2000 + RC5_KEYSIZE;

unsigned int inet_address(host)
	const char *host;
{
	unsigned int addr;
	struct hostent *hp;

	if ((int) (addr = inet_addr(host)) == -1) {
		if (!(hp = gethostbyname(host))) {
			perror("gethostbyname");
			return (-1);
		}

		memcpy((void *) &addr, (void *) hp->h_addr, sizeof(addr));
	}

	return (addr);
}

char *inet_name(struct in_addr in)
{
	register char *cp;
	static char line[50];
	struct hostent *hp;
	static char domain[MAXHOSTNAMELEN + 1];
	static int first = 1;

	if (first) {
		first = 0;
		if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
			(cp = strchr(domain, '.')))
			(void) strcpy(domain, cp + 1);
		else
			domain[0] = 0;
	}

	cp = 0;

	if (in.s_addr != INADDR_ANY) {
		hp = gethostbyaddr((char *)&in, sizeof (in), AF_INET);
		if (hp) {
			if ((cp = strchr(hp->h_name, '.')) && !strcmp(cp + 1, domain))
				*cp = 0;

			cp = hp->h_name;
		}
	}

	if (cp)
		(void) strcpy(line, cp);
	else {
		in.s_addr = ntohl(in.s_addr);
		sprintf(line, "%u.%u.%u.%u",
			(unsigned char) ((in.s_addr >> 24) & 0xFF),
			(unsigned char) ((in.s_addr >> 16) & 0xFF),
			(unsigned char) ((in.s_addr >>  8) & 0xFF),
			(unsigned char) ((in.s_addr      ) & 0xFF));
	}

	return (line);
}

int open_server()
{
	static int on = 1;
	int sock;
	struct sockaddr_in sin;

	memset((void *) &sin, 0, sizeof(sin));

	sin.sin_family		= AF_INET;
	sin.sin_addr.s_addr	= keyserver_addr.s_addr;
	sin.sin_port		= htons(keyserver_port);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return (-1);

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		close(sock);
		return (-1);
	}

	if (connect(sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		close(sock);
		return (-1);
	}

	return(sock);
}

