#ifndef CLIENT_H
#define CLIENT_H

#define SHL(x, s) ((RC5_WORD) ((x) << ((s) & RC5_ROTMASK)))
#define SHR(x, s) ((RC5_WORD) ((x) >> ((RC5_WORDSIZE) - ((s) & RC5_ROTMASK))))

#if defined(ASM_I486) && defined(__GNUC__)

static __inline__ RC5_WORD ROTL(RC5_WORD x, RC5_WORD y)
{
	register RC5_WORD res;

	__asm__ __volatile(
		"roll %%cl,%0\n\t"
		:"=g" (res)
		:"0" (x), "cx" (y)
		:"cx");

	return res;
}

static __inline__ RC5_WORD ROTL3(RC5_WORD x)
{
	register RC5_WORD res;

	__asm__ __volatile(
		"roll $3,%0\n\t"
		:"=g" (res)
		:"0" (x));

	return res;
}

#elif defined(ASM_SPARC) && defined(__GNUC__)

# define ROTL(x, s) ((RC5_WORD) (SHL((x), (s)) | SHR((x), (s))))
# define ROTL3(x) ROTL(x, 3)

#elif defined(ASM_MIPS) && defined(__GNUC__)

# define ROTL(x, s) ((RC5_WORD) (SHL((x), (s)) | SHR((x), (s))))
# define ROTL3(x) ROTL(x, 3)

#else

# define ROTL(x, s) ((RC5_WORD) (SHL((x), (s)) | SHR((x), (s))))
# define ROTL3(x) ROTL(x, 3)

#endif

#define P		P32
#define Q		Q32

/* These precomputed values are in case our compiler doesn't
 * precompute them for us
 */
#if 0
#define LL		((RC5_KEYBYTES + RC5_WORDBYTES - 1) / RC5_WORDBYTES)
#else
/* two words is ok for up to a 64-bit key */
#define	LL		(2)
#endif

#if 0
#define	T 		(2 * (RC5_ROUNDS + 1))
#else
#define	T		(26)
#endif

/* client.c */
extern char *client_id;

/* cliops.c */
extern int open_sock();
extern int get_keyspace(RC5_WORD *, RC5_WORD *, RC5_WORD *, RC5_WORD *,
						unsigned int *);
extern int end_keyspace(RC5_WORD *, RC5_WORD *, RC5_WORD *, RC5_WORD *,
						unsigned int);
extern int notify_server(RC5_WORD *, int, int);

#endif

