/*
 * asymmetrickey_decr.c
 *
 *  Created on: Mar 20, 2017
 *      Author: Richard Humphrey
 *
 *  Last edited: 2017-04-05
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <gmp.h>

struct PublicKey {
	mpz_t e;
	mpz_t n;
};

void print_help();
void print_try_help();
struct PublicKey *read_keyfile (char *keyfile);

int main (int argc, char **argv) {

	char *plaintext_file;
	char *key_file;
	int c;

	if (argc == 1) {
			printf("Error: Provide file containing key and plaintext file.\n");
			print_try_help();
			exit(0);
	}

	while ((c = getopt (argc, argv, "h")) != -1) {
		// Option argument
		switch (c) {
		case 'h':
			print_help();
			exit(1);
		default:
			break;
		}
	}

	key_file = argv[optind];

	struct PublicKey *public_key = read_keyfile(key_file);

	gmp_printf ("key e = %Zd\n", public_key->e);
	gmp_printf ("key n = %Zd\n", public_key->n);

	long unsigned int n_size = mpz_sizeinbase(public_key->n, 2);

	int max_blocksize = n_size / 2;

	printf ("max_blocksize = %i\n", max_blocksize);

	optind++;

	plaintext_file = argv[optind];

	if (!plaintext_file) {
		printf("Error: Provide the file containing the plaintext.\n");
		print_try_help();
		exit(0);
	}
	optind++;

	// Read from the file into a buffer
	char *buffer;
	unsigned long fileLen;

	//Open the file
	FILE *fp = fopen(plaintext_file,"r");
	if(!fp) {
		perror ("Unable to read ciphertext file");
		return 0;
	}

	//Get file length
	fseek(fp, 0, SEEK_END);
	fileLen=ftell(fp);
	fseek(fp, 0, SEEK_SET);

	printf("filesize = %lu\n", fileLen);

	//Allocate memory
	buffer=(char *)malloc(fileLen+1);
	if (!buffer) {
		printf("Unable to allocate memory for buffer\n");
		fclose(fp);
		return 0;
	}

	//Read file contents into buffer
	fread(buffer, fileLen, 1, fp);
	fclose(fp);

	// allocate block to max size possible
	char *block;
	block = (char *)malloc(max_blocksize);

	// write to output file
	char *output_filename = "Richard-Humphrey.plaintext";
	FILE *wp;
	wp = fopen(output_filename,"w");

	// Now loop through the buffer, blocks are delimited by the null char
	for (int i = 0; i < fileLen; i++) {

		block[0] = '\0';

		while (buffer[i] != '\0') {
			strncat(block, &buffer[i], 1);
			i++;
		}

		//printf ("i = %i\n", i);
		//block[i] = '\0';

		printf ("block = %s\n", block);

		mpz_t buffer_int;
		mpz_init(buffer_int);

		mpz_set_str(buffer_int, block, 10);
		gmp_printf ("Buffer Int: |%Zd|\n", buffer_int);

		mpz_t decrypted;
		mpz_init(decrypted);

		mpz_powm(decrypted, buffer_int, public_key->e, public_key->n);

		gmp_printf ("Decr number: |%Zd|\n", decrypted);

		char *output;

		output = (char *)malloc(mpz_sizeinbase (decrypted, 2) + 2);

		mpz_get_str(output, 2, decrypted);

		printf ("binary out: %s\n", output);

		int binary_length = strlen(output);

		printf ("num_bits = %i\n", binary_length);

		// problem is, mpz doesn't pad leading zeros :(
		int remainder = 8 - (binary_length % 8);
		printf ("Missing zeros = %i\n", remainder);

		int string_size = binary_length / 8;

		if (remainder) {
			string_size++;
		}

		printf ("string size = %i\n", string_size);

		char *char_output = (char *) malloc(string_size);

		// now rebuild the ascii chars
		char ch = '\0';			// the temporary character
		int location = 0;   	// the location of the bit in the bit string
		int bitposition = 0;	// the position of the bit in the pending character
		int chlocation = 0;		// the location of the character in the output

		char_output[0] = '\0';

		for (int i = 0; i < binary_length; i++) {

			// pad first char with remainder leading zeros
			for (int j = 0; j < remainder; j++) {
				ch |= 0;
				//printf ("adding 0 at location %i\n", location);
				location++;
				ch <<= 1;
			}

			remainder = 0;
			bitposition = location % 8;

			//printf ("bitposition is %i - ", bitposition);

			// output is 0 or 1 in ascii
			int digit = output[i] - '0';
			ch |= digit;

			//printf ("add output[%i] to ch - %c - %i\n ", i, output[i], digit);

			if (bitposition == 7) {
				//printf ("appending %c to char_output: in position %i %s\n", ch, chlocation, char_output);
				char_output[chlocation] = ch;
				char_output[chlocation+1] = '\0';
				chlocation++;
				ch = '\0';
			} else {
				ch <<= 1;
			}
			location++;

		}

		//printf("\n");

		fwrite(char_output,string_size,1,wp);

		free(output);
		mpz_clear(decrypted);
		mpz_clear(buffer_int);


	}


	fclose(wp);

	return 0;

}

// Functions:
void print_help() {
	printf("Usage:\n");
	printf("./asymmetrickey_decr <key_file> <plaintext_file>\n");
}

void print_try_help() {
	printf("Try asymmetrickey_decr -h for help.\n");
}

struct PublicKey *read_keyfile (char *key_file){
	// Reads the keyfile and created the Publickey struct

	if (!key_file) {
		printf("Error: Provide the file containing the key pair.\n");
		print_try_help();
		exit(0);
	}

	// Read from the binary file into a buffer
	char *keybuffer;
	unsigned long keyfileLen;
	struct PublicKey *key = (struct PublicKey *) malloc (sizeof(struct PublicKey));

	char *e_str;
	char *n_str;
	int e_length = 0;
	int n_length = 0;

	mpz_init(key->e);
	mpz_init(key->n);

	//Open the file
	FILE *kfp = fopen(key_file,"r");
	if(!kfp) {
		printf ("Unable to read file %s", key_file);
		exit(0);
	}

	//Get file length
	fseek(kfp, 0, SEEK_END);
	keyfileLen=ftell(kfp);
	fseek(kfp, 0, SEEK_SET);

	//Allocate memory
	keybuffer=(char *)malloc(keyfileLen+1);
	if (!keybuffer) {
		printf("Unable to allocate memory to read keyfile");
		fclose(kfp);
		exit(0);
	}

	for (int i = 0; i < keyfileLen; i++) {
		int c = fgetc(kfp);

		if (!feof(kfp)) {
			if (c == '\n') {
				keybuffer[i] = '\0';
				break;
			} else {
				keybuffer[i] = c;
				// remember the location of the comma
				if (c == ',') {
					e_length = i;
				}
			}
		} else {
			keybuffer[i] = '\0';
			break;
		}

	}

	if (e_length == 0) {
		printf ("Error, file should be comma delimited\n");
		exit(0);
	}

	int keylength = strlen(keybuffer);

	printf ("File buffer is: |%s|\n", keybuffer);

	e_str = malloc(sizeof(char) * e_length + 1);

	n_length = (keylength - e_length - 2);

	n_str = malloc(sizeof (char) * n_length + 1);

	//printf ("size of keys are e = %i, n = %i\n", e_length, n_length);

	strncpy (e_str, keybuffer, e_length);
	strncpy (n_str, &keybuffer[e_length+2], n_length);

	//printf ("e = %s\n", e_str);
	//printf ("n = %s\n", n_str);

	mpz_set_str(key->e, e_str, 10);
	mpz_set_str(key->n, n_str, 10);


	free(e_str);
	free(n_str);
	free(keybuffer);

	return (key);

}

