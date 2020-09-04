#include "psec-crypt.h"
#ifdef LX_BUILD
#ifdef OP_TEST
#include <sys/time.h>
#endif

#ifdef OP_TEST
#define TEST_ITERS 100000

double timediff(struct timeval x , struct timeval y)
{
	double x_ms , y_ms , diff;
	
	x_ms = (double)x.tv_sec*1000000 + (double)x.tv_usec;
	y_ms = (double)y.tv_sec*1000000 + (double)y.tv_usec;
	
	diff = (double)y_ms - (double)x_ms;
	
	return diff;
}
#endif

#ifndef BUILD_LIB
int main(void)
{
		/* initialize working buffers */
		unsigned char msg[MSG_SIZE];
		unsigned char key[KEY_SIZE];
		unsigned char exp_key[EXP_KEY_SIZE];
		unsigned char exp_key_hex[EXP_KEY_SIZE * 2 + 2];

		unsigned char msg_in[MSG_SIZE * 2 + 1]; // for hex input
		unsigned char key_in[KEY_SIZE * 2 + 1]; // for hex input
		unsigned char choice[16];

		//unsigned char exp_key[BLK_SIZE * ROUNDS];
		unsigned char response[MSG_SIZE * 2 + 2];
		unsigned char hex[MSG_SIZE * 2 + 2];
		size_t a;
		size_t b;
		#ifdef OP_TEST
		unsigned char exp_key[EXP_KEY_SIZE];
		unsigned char tmp[MSG_SIZE];
		struct timeval start, end;
		#endif
		
		//msg = "Hello";
		//key = "world";
	//	fgets(msg, MSG_SIZE, STDIN);
	//	fgets(key, KEY_SIZE, STDIN);
	/*
		printf("Msg: ");
		gets(msg_in);
		printf("Key: ");
		gets(key_in);
		printf("E/D: ");
		gets(choice);
	*/

		/* Clear the homescreen */
		os_ClrHome();
		//           ("PARSEC Encryption123456789");
		printf("PARSEC Statistics\n");
		printf("--------------------------\n");
		printf("%i-byte (128 bit) block\n", BLK_SIZE);
		printf("%i-byte (256 bit) key\n", KEY_SIZE);
		printf("%i rounds\n", ROUNDS);
		printf("\n");

		for(a=0; a<MSG_SIZE * 2 + 2; ++a){
			msg_in[a] = '0';
		}
		for(a=0; a<KEY_SIZE * 2 + 2; ++a){
			key_in[a] = '0';
		}
		os_GetStringInput("Msg:", msg_in, MSG_SIZE * 2 + 2);
		os_GetStringInput("Key:", key_in, KEY_SIZE * 2 + 2);
		//           ("PARSEC Encryption123456789");

		//os_GetStringInput("Mode (E/D/H):", choice, 16);
		
		from_hex(msg_in, msg, MSG_SIZE);
		from_hex(key_in, key, KEY_SIZE);
		to_hex(msg, msg_in, MSG_SIZE);
		to_hex(key, key_in, KEY_SIZE);
		
		expand_key(key, exp_key);
		to_hex(exp_key, exp_key_hex, EXP_KEY_SIZE);
		
		printf("MSG         \t= %s\n", msg_in);
		printf("KEY         \t= %s\n", key_in);
		printf("EXPANDED KEY\t= %s\n", exp_key_hex);
		
		for(a=0; a<EXP_KEY_SIZE; a += BLK_SIZE){
			to_hex(&exp_key[a], msg_in, BLK_SIZE);
			printf("ROUND KEY %i\t= %s\n", a / BLK_SIZE, msg_in);
		}
		
	return 0;
}
#endif

#endif
// Nothing to do unless we're on Linux
