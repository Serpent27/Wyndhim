#include "psec-crypt.h"
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
	for(;;){
		/* initialize working buffers */
		unsigned char msg[MSG_SIZE + 1];
		unsigned char key[KEY_SIZE + 1];

		unsigned char msg_in[MSG_IN_SIZE]; // for hex input
		unsigned char key_in[KEY_IN_SIZE]; // for hex input
		unsigned char choice[16];

		//unsigned char exp_key[BLK_SIZE * ROUNDS];
		unsigned char response[MSG_SIZE * 2 + 1];
		unsigned char hex[MSG_SIZE * 2 + 1];
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
		os_PutStrFull("Wyndhim Encryption        ");
		os_PutStrFull("--------------------------");
		os_PutStrFull("16-byte (128 bit) block   ");
		os_PutStrFull("32-byte (256 bit) key     ");
		os_PutStrFull("32 rounds                 ");
		os_PutStrFull("                          ");

		/* Waits for a key */
		while (!os_GetCSC());
		
		/* Clear the homescreen */
		os_ClrHome();

		/* Ask the user to type a string, which gets stored in `inputBuf` */
		for(a=0; a<MSG_IN_SIZE; ++a){
			msg_in[a] = 0;
		}
		os_GetStringInput("Msg:", msg_in, MSG_IN_SIZE);
		os_ClrHome();
		msg_in[MSG_IN_SIZE - 1] = 0;
		for(a=0; a<KEY_IN_SIZE; ++a){
			key_in[a] = 0;
		}
		os_GetStringInput("Key:", key_in, KEY_IN_SIZE);
		os_ClrHome();
		key_in[KEY_IN_SIZE - 1] = 0;
		//           ("PARSEC Encryption123456789");
		os_PutStrFull("E = Encrypt               ");
		os_PutStrFull("D = Decrypt               ");
		os_PutStrFull("H = Hash                  ");
		for(a=0; a<16; ++a){
			choice[a] = 0;
		}
		os_GetStringInput("Mode (E/D/H):", choice, 16);
		os_ClrHome();
		
		//MAKE_KEY(key);
		from_hex(key_in, key, KEY_SIZE);

	//	from_hex(key_in, key, KEY_SIZE);
		
		//           ("PARSEC Encryption123456789");
		os_PutStrFull("Working...");
		#ifdef ENCRYPT
			#ifdef ENCDEC_CHOICE
			if(choice[0] == 'e' || choice[0] == 'E'){
			#endif
			for(a=0; a<MSG_SIZE; ++a){
				msg[a] = msg_in[a];
			}
			#ifdef IGNORE_KEY
			for(a=0; a<KEY_SIZE; ++a){
				key[a] = 0;
			}
			#endif
			encrypt(msg, key);
			
			to_hex(msg, hex, MSG_SIZE);
			hex[MSG_SIZE * 2] = 0;
			sprintf(response, "%s", hex);

			/* Build the user response */
			
			
			/* Clear the homescreen and display the built response */
			os_ClrHome();
	//		printf(response);
	//		for(a=0; a<MSG_SIZE; ++a){
	//			msg_in[a * 2] = response[a * 2];
	//			msg_in[a * 2 + 1] = response[a * 2 + 1];
	//		}

			os_PutStrFull(response);

			/* Waits for a key */
			while (!os_GetCSC());
			#ifdef ENCDEC_CHOICE
			}
			#endif
		#endif
		#ifdef DECRYPT
			#ifdef ENCDEC_CHOICE
			if(choice[0] == 'd' || choice[0] == 'D'){
			#endif
			#ifdef IGNORE_KEY
			for(a=0; a<KEY_SIZE; ++a){
				key[a] = 0;
			}
			#endif
			from_hex(msg_in, msg, MSG_SIZE);
			decrypt(msg, key);
			//to_hex(msg, hex, MSG_SIZE);
			for(a=0; a<MSG_SIZE; ++a){
				hex[a] = msg[a];
				hex[a + MSG_SIZE] = 0;
			}

			/* Build the user response */
			sprintf(response, "%s", hex);
			
			
			/* Clear the homescreen and display the built response */
			os_ClrHome();
	//		printf(response);
	//		for(a=0; a<MSG_SIZE; ++a){
	//			msg_in[a * 2] = response[a * 2];
	//			msg_in[a * 2 + 1] = response[a * 2 + 1];
	//		}

			os_PutStrFull(response);

			/* Waits for a key */
			while (!os_GetCSC());
			#ifdef ENCDEC_CHOICE
			}
			#endif
		#endif
		
		#ifdef OP_TEST
			#ifdef ENCDEC_CHOICE
			if(choice[0] == 't' || choice[0] == 'T'){
			#endif
			#ifdef IGNORE_KEY
			for(a=0; a<KEY_SIZE; ++a){
				key[a] = 0;
			}
			#endif
			from_hex(msg_in, msg, MSG_SIZE);
			printf("\n");
			
			expand_key(key, exp_key);
			
			gettimeofday(&start, NULL);
			for(a=0; a<TEST_ITERS; ++a){
				enc(msg, exp_key, tmp);
			}
			gettimeofday(&end, NULL);
			/* Build the user response */
			printf("Encryption (constant key) took %f seconds for %i iters [%i bytes]\nEncryption speed: %lf bytes/second\n", timediff(start, end)/1000000, TEST_ITERS, TEST_ITERS * MSG_SIZE, TEST_ITERS * MSG_SIZE / timediff(start, end) * 1000000);
			expand_key(key, exp_key);
			
			gettimeofday(&start, NULL);
			for(a=0; a<TEST_ITERS; ++a){
				dec(msg, exp_key, tmp);
			}
			gettimeofday(&end, NULL);
			/* Build the user response */
			printf("Decryption (constant key) took %f seconds for %i iters [%i bytes]\nEncryption speed: %lf bytes/second\n", timediff(start, end)/1000000, TEST_ITERS, TEST_ITERS * MSG_SIZE, TEST_ITERS * MSG_SIZE / timediff(start, end) * 1000000);
			
			
			gettimeofday(&start, NULL);
			for(a=0; a<TEST_ITERS; ++a){
				expand_key(key, exp_key);
				enc(msg, exp_key, tmp);
			}
			gettimeofday(&end, NULL);
			/* Build the user response */
			printf("Encryption (dynamic key) took %f seconds for %i iters [%i bytes]\nEncryption speed: %lf bytes/second\n", timediff(start, end)/1000000, TEST_ITERS, TEST_ITERS * MSG_SIZE, TEST_ITERS * MSG_SIZE / timediff(start, end) * 1000000);
			gettimeofday(&start, NULL);
			for(a=0; a<TEST_ITERS; ++a){
				expand_key(key, exp_key);
				dec(msg, exp_key, tmp);
			}
			gettimeofday(&end, NULL);
			/* Build the user response */
			printf("Decryption (dynamic key) took %f seconds for %i iters [%i bytes]\nEncryption speed: %lf bytes/second\n", timediff(start, end)/1000000, TEST_ITERS, TEST_ITERS * MSG_SIZE, TEST_ITERS * MSG_SIZE / timediff(start, end) * 1000000);
			
	
			
			/* Clear the homescreen and display the built response */
			os_ClrHome();
	//		printf(response);
	//		for(a=0; a<MSG_SIZE; ++a){
	//			msg_in[a * 2] = response[a * 2];
	//			msg_in[a * 2 + 1] = response[a * 2 + 1];
	//		}

			os_PutStrFull(response);
			/* Waits for a key */
			while (!os_GetCSC());
			#ifdef ENCDEC_CHOICE
			}
			#endif
		#endif
		
		#ifdef ENCDEC_CHOICE
			if(choice[0] == 'x' || choice[0] == 'X'){
			for(a=0; a<MSG_SIZE; ++a){
				msg[a] = msg_in[a];
			}
			for(a=0; a<KEY_SIZE; ++a){
				key[a] = key_in[a];
			}
			key[KEY_SIZE] = 0;
			
			#ifdef IGNORE_KEY
			for(a=0; a<KEY_SIZE; ++a){
				key[a] = 0;
			}
			#endif
			
			to_hex(msg, msg_in, MSG_SIZE);
			to_hex(key, key_in, KEY_SIZE);

			/* Build the user response */
			
			
			/* Clear the homescreen and display the built response */
			os_ClrHome();
	//		printf(response);
	//		for(a=0; a<MSG_SIZE; ++a){
	//			msg_in[a * 2] = response[a * 2];
	//			msg_in[a * 2 + 1] = response[a * 2 + 1];
	//		}
			
			// Cleanup
				for(a=0; a<KEY_SIZE; ++a){
					key[a] = 0;
				}
				for(a=0; a<MSG_SIZE; ++a){
					msg[a] = 0;
				}
				for(a=0; a<16; ++a){
					choice[a] = 0;
				}
				for(a=0; a<MSG_SIZE * 2 + 1; ++a){
					hex[a] = 0;
				}
				for(a=0; a<MSG_SIZE * 2 + 1; ++a){
					response[a] = 0;
				}
				
				os_PutStrFull(msg_in);
				/* Waits for a key */
				while (!os_GetCSC());
				os_ClrHome();
				os_PutStrFull(key_in);
			/* Waits for a key */
			while (!os_GetCSC());
			}
		#endif
		#ifdef ENCDEC_CHOICE
			if(choice[0] == 'u' || choice[0] == 'U'){
			for(a=0; a<MSG_SIZE; ++a){
				msg[a] = msg_in[a];
			}
			for(a=0; a<KEY_SIZE; ++a){
				key[a] = key_in[a];
			}
			key[KEY_SIZE] = 0;
			
			#ifdef IGNORE_KEY
			for(a=0; a<KEY_SIZE; ++a){
				key[a] = 0;
			}
			#endif
			
			from_hex(msg_in, msg, MSG_SIZE);
			from_hex(key_in, key, KEY_SIZE);

			/* Build the user response */
			
			
			/* Clear the homescreen and display the built response */
			os_ClrHome();
	//		printf(response);
	//		for(a=0; a<MSG_SIZE; ++a){
	//			msg_in[a * 2] = response[a * 2];
	//			msg_in[a * 2 + 1] = response[a * 2 + 1];
	//		}
			
			// Cleanup
				for(a=0; a<16; ++a){
					choice[a] = 0;
				}
				for(a=0; a<MSG_SIZE * 2 + 1; ++a){
					hex[a] = 0;
				}
				for(a=0; a<MSG_SIZE * 2 + 1; ++a){
					response[a] = 0;
				}
				
				os_PutStrFull(msg);
				/* Waits for a key */
				while (!os_GetCSC());
				os_ClrHome();
				os_PutStrFull(key);
			/* Waits for a key */
			while (!os_GetCSC());
			}
		#endif
		/*
		
		unsigned char msg[MSG_SIZE];
		unsigned char key[KEY_SIZE];

		unsigned char msg_in[MSG_IN_SIZE]; // for hex input
		unsigned char key_in[KEY_IN_SIZE]; // for hex input
		unsigned char choice[16];

		//unsigned char exp_key[BLK_SIZE * ROUNDS];
		unsigned char response[MSG_SIZE * 2 + 1];
		unsigned char hex[MSG_SIZE * 2 + 1];
		size_t a;
		size_t b;
		#ifdef OP_TEST
		unsigned char exp_key[EXP_KEY_SIZE];
		unsigned char tmp[MSG_SIZE];
		#endif
		
		*/
				for(a=0; a<KEY_SIZE; ++a){
					key[a] = 0;
				}
				for(a=0; a<MSG_SIZE; ++a){
					msg[a] = 0;
					#ifdef OP_TEST
					tmp[a] = 0;
					#endif
				}
				for(a=0; a<KEY_IN_SIZE; ++a){
					key_in[a] = 0;
				}
				for(a=0; a<MSG_IN_SIZE; ++a){
					msg_in[a] = 0;
				}
				for(a=0; a<16; ++a){
					choice[a] = 0;
				}
				for(a=0; a<MSG_SIZE * 2 + 1; ++a){
					hex[a] = 0;
					response[a] = 0;
				}
				#ifdef OP_TEST
				for(a=0; a<EXP_KEY_SIZE; ++a){
					exp_key[a] = 0;
				}
				#endif
		a = 0;
		b = 0;
		
		os_ClrHome();
		os_GetStringInput("Another? (y/N):", choice, 16);
		if(choice[0] != 'y' && choice[0] != 'Y'){
			for(a=0; a<16; ++a){
				choice[a] = 0;
			}
			a = 0;
			break;
		}
	}
	return 0;
}
#endif
