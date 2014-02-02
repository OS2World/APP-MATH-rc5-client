#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "client.h"

#ifdef SOCKS
#include "socks.h"
#endif

#if !defined(lint)
static char rcsid[] = "@(#)rc5-client.c, v2.01a 1997/00/00 earle (genx)\n";
#endif /* ! lint */

static RC5_WORD L0[LL];
static RC5_WORD S0[T];
static RC5_WORD S[T];

char *client_id = "#root";
int exiting = 0;
int counting = 0;
int count = 0;
time_t stop_time = (time_t) 0;
struct timeval start;

void sig_handler(int sig)
{
	exiting = 1;

	printf("rc5-56-client: Exiting after next block.\n");
	fflush(stdout);


	return;
}

static int RC5_KEY_CHECK(key, iv, plain, cipher, numkeys)
	RC5_WORD *key;
	RC5_WORD *iv;
	RC5_WORD *plain;
	RC5_WORD *cipher;
	unsigned int numkeys;
{
	register unsigned int i;

	register RC5_WORD A, B;
	register RC5_WORD L_0, L_1;

	/* Plaintext and Ciphertext word pairs */
	register RC5_WORD P_0, P_1;
	register RC5_WORD C_0, C_1;

	L0[0] = ((key[1] >> 16) & 0x000000FF) |
			((key[1])       & 0x0000FF00) |
			((key[1] << 16) & 0x00FF0000) |
			((key[0])       & 0xFF000000);
	L0[1] = ((key[0] >> 16) & 0x000000FF) |
			((key[0])       & 0x0000FF00) |
			((key[0] << 16) & 0x00FF0000);

	P_0 = plain[0] ^ iv[0];
	P_1 = plain[1] ^ iv[1];

	C_0 = cipher[0];
	C_1 = cipher[1];

	S0[0] = P;

	for(i = 1; i < T; i++)
		S0[i] = S0[i - 1] + Q;

	i = numkeys;

	while (i--) {
		A = B = 0;

		L_0 = L0[0];
		L_1 = L0[1];

		/* Begin round 1 of key expansion */

		A = S[0] = ROTL3(S0[0]);
		B = L_0 = ROTL(L_0 + A, A);

		A = S[1] = ROTL3(S0[1] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[2] = ROTL3(S0[2] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[3] = ROTL3(S0[3] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[4] = ROTL3(S0[4] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[5] = ROTL3(S0[5] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[6] = ROTL3(S0[6] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[7] = ROTL3(S0[7] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[8] = ROTL3(S0[8] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[9] = ROTL3(S0[9] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[10] = ROTL3(S0[10] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[11] = ROTL3(S0[11] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[12] = ROTL3(S0[12] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[13] = ROTL3(S0[13] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[14] = ROTL3(S0[14] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[15] = ROTL3(S0[15] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[16] = ROTL3(S0[16] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[17] = ROTL3(S0[17] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[18] = ROTL3(S0[18] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[19] = ROTL3(S0[19] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[20] = ROTL3(S0[20] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[21] = ROTL3(S0[21] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[22] = ROTL3(S0[22] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[23] = ROTL3(S0[23] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[24] = ROTL3(S0[24] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[25] = ROTL3(S0[25] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		/* Begin round 2 of key expansion */

		A = S[0] = ROTL3(S[0] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[1] = ROTL3(S[1] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[2] = ROTL3(S[2] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[3] = ROTL3(S[3] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[4] = ROTL3(S[4] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[5] = ROTL3(S[5] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[6] = ROTL3(S[6] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[7] = ROTL3(S[7] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[8] = ROTL3(S[8] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[9] = ROTL3(S[9] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[10] = ROTL3(S[10] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[11] = ROTL3(S[11] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[12] = ROTL3(S[12] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[13] = ROTL3(S[13] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[14] = ROTL3(S[14] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[15] = ROTL3(S[15] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[16] = ROTL3(S[16] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[17] = ROTL3(S[17] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[18] = ROTL3(S[18] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[19] = ROTL3(S[19] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[20] = ROTL3(S[20] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[21] = ROTL3(S[21] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[22] = ROTL3(S[22] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[23] = ROTL3(S[23] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[24] = ROTL3(S[24] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[25] = ROTL3(S[25] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		/* Begin round 3 of key expansion */

		A = S[0] = ROTL3(S[0] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[1] = ROTL3(S[1] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[2] = ROTL3(S[2] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[3] = ROTL3(S[3] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[4] = ROTL3(S[4] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[5] = ROTL3(S[5] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[6] = ROTL3(S[6] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[7] = ROTL3(S[7] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[8] = ROTL3(S[8] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[9] = ROTL3(S[9] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[10] = ROTL3(S[10] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[11] = ROTL3(S[11] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[12] = ROTL3(S[12] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[13] = ROTL3(S[13] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[14] = ROTL3(S[14] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[15] = ROTL3(S[15] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[16] = ROTL3(S[16] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[17] = ROTL3(S[17] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[18] = ROTL3(S[18] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[19] = ROTL3(S[19] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[20] = ROTL3(S[20] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[21] = ROTL3(S[21] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[22] = ROTL3(S[22] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[23] = ROTL3(S[23] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		A = S[24] = ROTL3(S[24] + A + B);
		B = L_0 = ROTL(L_0 + A + B, A + B);

		A = S[25] = ROTL3(S[25] + A + B);
		B = L_1 = ROTL(L_1 + A + B, A + B);

		/* Begin the encryption */

		A = P_0 + S[0];
		B = P_1 + S[1];

		A = ROTL(A ^ B, B) + S[2];
		B = ROTL(B ^ A, A) + S[3];

		A = ROTL(A ^ B, B) + S[4];
		B = ROTL(B ^ A, A) + S[5];

		A = ROTL(A ^ B, B) + S[6];
		B = ROTL(B ^ A, A) + S[7];

		A = ROTL(A ^ B, B) + S[8];
		B = ROTL(B ^ A, A) + S[9];

		A = ROTL(A ^ B, B) + S[10];
		B = ROTL(B ^ A, A) + S[11];

		A = ROTL(A ^ B, B) + S[12];
		B = ROTL(B ^ A, A) + S[13];

		A = ROTL(A ^ B, B) + S[14];
		B = ROTL(B ^ A, A) + S[15];

		A = ROTL(A ^ B, B) + S[16];
		B = ROTL(B ^ A, A) + S[17];

		A = ROTL(A ^ B, B) + S[18];
		B = ROTL(B ^ A, A) + S[19];

		A = ROTL(A ^ B, B) + S[20];
		B = ROTL(B ^ A, A) + S[21];

		A = ROTL(A ^ B, B) + S[22];
		B = ROTL(B ^ A, A) + S[23];

		A = ROTL(A ^ B, B) + S[24];

		/* an 'if' is less expensive than a rotation, which we
		 * will avoid if the first part fails.
		 */

		if (C_0 == A && C_1 == ROTL(B ^ A, A) + S[25])
			while(notify_server(L0, numkeys, i) < 0) {
				printf("rc5-56-client: Can't talk to "
				       "keyserver!  Sleeping 2 minutes\n");
				fflush(stdout);
				sleep(120);
			}

		L0[1] = (L0[1] + 0x00010000) & 0x00FFFFFF;

		if (!(L0[1] & 0x00FF0000)) {
			L0[1] = (L0[1] + 0x00000100) & 0x0000FFFF;

			if (!(L0[1] & 0x0000FF00)) {
				L0[1] = (L0[1] + 0x00000001) & 0x000000FF;

				if (!(L0[1] & 0x000000FF)) {
					L0[1] = 0x00000000;
					L0[0] = L0[0] + 0x01000000;

					if (!(L0[0] & 0xFF000000)) {
						L0[0] = (L0[0] + 0x00010000) & 0x00FFFFFF;

						if (!(L0[0] & 0x00FF0000)) {
							L0[0] = (L0[0] + 0x00000100) & 0x0000FFFF;

							if (!(L0[0] & 0x0000FF00)) {
								L0[0] = (L0[0] + 0x00000001) & 0x000000FF;
							}
						}
					}
				}
			}
		}
	}

	return (0);
}

static void do_test()
{
	RC5_WORD key[2] = { 0, 0 };
	RC5_WORD iv[2] = { 0, 0 };
	RC5_WORD pt[2] = { 0, 0 };
	RC5_WORD ct[2] = { 0, 0 };
	unsigned int numkeys = 1000000;
	struct timeval stop;
	struct timezone dummy;
	double len;

	printf("rc5-56-client: Performance testing with %d crypts\n", 
	      numkeys);

	fflush(stdout);

	if (gettimeofday(&stop, &dummy) < 0) {
		perror("gettimeofday");
		return;
	}

	len = stop.tv_sec * 1000000.0 + stop.tv_usec;

	RC5_KEY_CHECK(key, iv, pt, ct, numkeys);

	if (gettimeofday(&stop, &dummy) < 0) {
		perror("gettimeofday");
		return;
	}

	len = (((double) (stop.tv_sec * 1000000.0 + stop.tv_usec)) - len)
		/ 1000000.0;

	printf("rc5-56-client: Complete in %4.3f seconds. (%.2f keys/sec)\n", 
		len, ((double) numkeys / len));
}

static void do_cipher()
{
	RC5_WORD key[2];
	RC5_WORD iv[2];
	RC5_WORD pt[2];
	RC5_WORD ct[2];
	RC5_WORD out[2] = { 0, 0 };
	unsigned int numkeys;
	struct timeval stop;
	struct timezone dummy;
	double len;

	if(gettimeofday(&start, &dummy) < 0) {
		perror("gettimeofday");
		return;
	}

	for (;;) {
		if (gettimeofday(&stop, &dummy) < 0) {
			perror("gettimeofday");
			return;
		}

		len = stop.tv_sec * 1000000.0 + stop.tv_usec;

		printf("rc5-56-client: Obtaining Key Mask from ``%s:%u''.\n",
			inet_name(keyserver_addr), keyserver_port);

		fflush(stdout);

		while (get_keyspace(key, iv, pt, ct, &numkeys) < 0) {
			perror("get_keyspace");
			printf("rc5-56-client: Error getting key.\n");
			printf("rc5-56-client: Sleeping 2 minutes...\n");
			sleep(120);
			continue;
		}

		printf("rc5-56-client: Received Keyspace Mask 0x%.14X\n", 
			numkeys - 1);

		printf("rc5-56-client: Start Key 0x%.6X%.8X, trying %u keys.\n", 
			key[1], key[0], numkeys);

		fflush(stdout);

		RC5_KEY_CHECK(key, iv, pt, ct, numkeys);

		out[1] = ((L0[1] >> 16) & 0x000000FF) |
		 	 ((L0[1])       & 0x0000FF00) |
		 	 ((L0[1] << 16) & 0x00FF0000) |
		 	 ((L0[0])       & 0xFF000000);
		out[0] = ((L0[0] >> 16) & 0x000000FF) |
		 	 ((L0[0])       & 0x0000FF00) |
		 	 ((L0[0] << 16) & 0x00FF0000);

		if (gettimeofday(&stop, &dummy) < 0) {
			perror("gettimeofday");
			return;
		}

		len = (((double) (stop.tv_sec * 1000000.0 + stop.tv_usec)) 
			- len) / 1000000.0;

		printf("rc5-56-client: Processed %.2f keys per second.\n",
			(double) ((double) numkeys / len));

		printf("rc5-56-client: Keyspace Exhausted in %4.2f minutes.\n", 
			(double) (len / 60));

		printf("rc5-56-client: [0x%.06X%.08X -> 0x%.06X%.08X]\n",
			      key[1], key[0], out[0], out[1] - 1);

		fflush(stdout);

		while (end_keyspace(key, iv, pt, ct, numkeys) < 0) {
			perror("end_keyspace");
			printf("rc5-56-client: Error notifying server.\n");
			printf("rc5-56-client: Sleeping 1 minute...\n");
			fflush(stdout);
			sleep(60);
		}

		if(exiting) {
			printf("rc5-56-client: Exiting upon request.\n");
			fflush(stdout);
			exit(0);
		}
		if(counting) {
			if(--count < 1) {
				printf("rc5-56-client: Key Blocks Complete.\n");
				exit(0);
			}
		}

		if (stop_time && time(NULL) > stop_time) {
			float hours = (float) ((time(NULL) - (float) stop_time) / 3600.00);
			printf("rc5-56-client: Exiting after %2.2f hours work.\n",
				hours);
			exit(0);
		}
	}
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [-m] [-n level] [-c count] [-h hours]\n"
		        "       [-a <address>] [-p <port>] <identity>\n", 
		progname);

	exit(-1);
}

int main(int argc, char *argv[])
{
	register char *cp;
	char *progname;
	int arg;
	int nicelevel;
	extern int optind;
	extern char *optarg;

	progname = ((cp = strrchr(argv[0], '/')) ? (cp + 1) : argv[0]);

	keyserver_addr.s_addr = inet_addr("206.64.4.18");

	while ((arg = getopt(argc, argv, "c:h:n:ma:p:H?")) != EOF) {
		switch (arg) {
		case 'a':
			keyserver_addr.s_addr = inet_address(optarg);
			break;

		case 'c':
			counting = 1;
			count = atoi(optarg);
			break;

		case 'h':
			stop_time = time(NULL) + (time_t) (atof(optarg) * 3600.0);
			break;

/* 		case 'n':
			nicelevel = atoi(optarg);
			if(nice(nicelevel) == -1) {
				perror("nice");
				exit(0);
			}
			break; */

		case 'm':
			do_test();
			exit(0);


		case 'p':
			keyserver_port = (unsigned short) atoi(optarg);
			break;

		default:
		case 'H': case '?':
			usage(progname);
			/* NOTREACHED */
			break;
		}
	}

	argc -= optind - 1;
	argv += optind - 1;

	if (argc != 2)
		usage(progname);

	client_id = strdup(argv[1]);

#ifdef SOCKS
	LIBPREFIX(init)(progname);
#endif

	signal(SIGHUP, sig_handler);

	
	do_cipher();

	exit(0);
}

