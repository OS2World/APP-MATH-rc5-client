#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include "common.h"
#include "client.h"

#ifdef SOCKS
#include "socks.h"
#endif

int get_keyspace(key, iv, pt, ct, n)
	RC5_WORD	*key;
	RC5_WORD 	*iv;
	RC5_WORD 	*pt;
	RC5_WORD 	*ct;
	unsigned 	int *n;
{
	int sock;
	static Packet pkt;

	if ((sock = open_server()) < 0)
		return (-1);

	memset((void *) &pkt, 0, sizeof(Packet));

	pkt.op = htonl(OP_REQUEST);

	strncpy(pkt.id, client_id, PKT_STRLEN);

	if (write(sock, (void *) &pkt, sizeof(Packet)) != sizeof(Packet)) {
		close(sock);
		return (-1);
	}

	if (read(sock, (void *) &pkt, sizeof(Packet)) != sizeof(Packet)) {
		close(sock);
		return (-1);
	}

	close(sock);

	/* Begin processing packet we got from the server */

	if (ntohl(pkt.op) != OP_DATA)
		return (-1);

	key[0] = (RC5_WORD) ntohl(pkt.key[0]);
	key[1] = (RC5_WORD) ntohl(pkt.key[1]);

	iv[0] = (RC5_WORD) ntohl(pkt.iv[0]);
	iv[1] = (RC5_WORD) ntohl(pkt.iv[1]);

	pt[0] = (RC5_WORD) ntohl(pkt.pt[0]);
	pt[1] = (RC5_WORD) ntohl(pkt.pt[1]);

	ct[0] = (RC5_WORD) ntohl(pkt.ct[0]);
	ct[1] = (RC5_WORD) ntohl(pkt.ct[1]);

	*n = ntohl(pkt.numkeys);

	printf("rc5-56-client: %s\n", pkt.id);

	return (0);
}

int end_keyspace(key, iv, pt, ct, n)
	RC5_WORD	*key;
	RC5_WORD 	*iv;
	RC5_WORD 	*pt;
	RC5_WORD 	*ct;
	unsigned 	int n;
{
	int 		sock;
	static Packet 	pkt;

	/* Open socket and connect to server */

	printf("rc5-56-client: Notifying Key Server ``%s''\n",
		inet_name(keyserver_addr));

	if ((sock = open_server()) < 0)
		return (-1);

	/* clear and build packet to send to server */

	memset((void *) &pkt, '\0', sizeof(Packet));

	pkt.op = htonl(OP_DONE);

	pkt.key[0] = (RC5_WORD) htonl(key[0]);
	pkt.key[1] = (RC5_WORD) htonl(key[1]);

	pkt.numkeys = htonl(n);

	strncpy(pkt.id, client_id, PKT_STRLEN);

	if (write(sock, (void *) &pkt, sizeof(Packet)) != sizeof(Packet)) {
		close(sock);
		return (-1);
	}

	close(sock);

	return (0);
}

int notify_server(key, numkeys, iter)
	RC5_WORD *key;
	register int numkeys;
	register int iter;
{
	RC5_WORD	out[2] = { 0, 0 };
	int 		sock;
	static Packet 	pkt;

	out[1] = ((key[1] >> 16) & 0x000000FF) |
			 ((key[1])       & 0x0000FF00) |
			 ((key[1] << 16) & 0x00FF0000) |
			 ((key[0])       & 0xFF000000);
	out[0] = ((key[0] >> 16) & 0x000000FF) |
			 ((key[0])       & 0x0000FF00) |
			 ((key[0] << 16) & 0x00FF0000);

	printf("rc5-56-client: Possible Solution: "
		"0x%.06X%.08X (%u attempts)\n", 
		out[0], out[1], (numkeys - iter));

	/* Open socket and connect to server */

	if ((sock = open_server()) < 0)
		return (-1);

	/* clear and build packet to send to server */

	memset((void *) &pkt, '\0', sizeof(Packet));

	pkt.op = htonl(OP_SUCCESS);

	pkt.key[0] = (RC5_WORD) htonl(out[0]);
	pkt.key[1] = (RC5_WORD) htonl(out[1]);

	strncpy(pkt.id, client_id, PKT_STRLEN);

	if (write(sock, (void *) &pkt, sizeof(Packet)) != sizeof(Packet)) {
		close(sock);
		return (-1);
	}

	close(sock);

	return (0);
}

