#ifndef COMMON_H
#define COMMON_H

#include <netinet/in.h>

#define RC5_WORD			unsigned int

#define RC5_ROUNDS			12

#define RC5_WORDSIZE		32
#define RC5_WORDBYTES		4	/* (RC5_WORDSIZE / 8) */
#define RC5_ROTMASK			31	/* (RC5_WORDSIZE - 1) */
#define RC5_BLOCKSIZE		8	/* ((2 * RC5_WORDSIZE) / 8) */

#define RC5_KEYSIZE			56
#define RC5_KEYBYTES		7	/* (RC5_KEYSIZE / 8) */
#define RC5_KEYWORDS		2	/* (8 * RC5_KEYBYTES / RC5_WORDSIZE + 1) */

#define RC5_MAXKEYLEN		16
#define RC5_MAXPLAINLEN		72
#define RC5_MAXCIPHERLEN	(RC5_MAXPLAINLEN + RC5_BLOCKSIZE)
#define RC5_MAXROUNDS		20

#define P16			0xB7E1
#define Q16			0x9E37
#define P32			0xB7E15163
#define Q32			0x9E3779B9
#define P64			0xB7E151628AED2A6B
#define Q64			0x9E3779B97F4A7C15

typedef enum {
	OP_REQUEST,
	OP_DATA,
	OP_SUCCESS,
	OP_DONE,
	OP_FAIL,
	OP_MAX
} Operation;

#define PKT_STRLEN 128

typedef struct Packet {
	signed int op;			/* operation code */
	RC5_WORD key[2];		/* the Key starting point */
	RC5_WORD iv[2];			/* the IV */
	RC5_WORD pt[2];			/* the Plaintext */
	RC5_WORD ct[2];			/* the Ciphertext */
	RC5_WORD numkeys;		/* number of iterations */
	char id[PKT_STRLEN];	/* identifier */
} Packet;

/* common.c */
extern struct in_addr keyserver_addr;
extern unsigned short keyserver_port;

extern unsigned int inet_address(const char *);
extern char *inet_name(struct in_addr);
extern int open_server();

#endif

