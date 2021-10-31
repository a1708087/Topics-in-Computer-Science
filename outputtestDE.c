#include <stdio.h>

int main() {
	FILE *fp;

  	#define CHUNKSIZE 1024

	fp = fopen("test2.txt", "w+");
	//fprintf(fp, "u8 output[64];\n\
u32 x[16];\n");
	for(int i = 0; i < CHUNKSIZE; i++){
		//for each block
		if(i%64 == 0){
			//word to byte
			for(int j = 0; j < 16; j++){
				fprintf(fp, "x[%d] = ctx.input[%d]; \n", j, j);
			}
			for(int j = 0; j < 4; j++){
				fprintf(fp, "QUARTERROUND( 0, 4, 8,12);\n\
QUARTERROUND( 1, 5, 9,13);\n\
QUARTERROUND( 2, 6,10,14);\n\
QUARTERROUND( 3, 7,11,15);\n\
QUARTERROUND( 0, 5,10,15);\n\
QUARTERROUND( 1, 6,11,12);\n\
QUARTERROUND( 2, 7, 8,13);\n\
QUARTERROUND( 3, 4, 9,14);\n");
			}
			for(int j = 0; j < 16; j++){
				fprintf(fp, "x[%d] = PLUS(x[%d],ctx.input[%d]); \n", j, j, j);
			}
			for(int j = 0; j < 16; j++){
				fprintf(fp, "U32TO8_LITTLE(output + 4 * %d,x[%d]); \n", j, j);
			}
			//ECRYPT BYTES
			fprintf(fp, "ctx.input[12] = PLUSONE(ctx.input[12]); \n\
if (!ctx.input[12]) { \n\
ctx.input[13] = PLUSONE(ctx.input[13]); \n\
}\n");
		}

		fprintf(fp, "result[%d] = ciphertext[%d] ^ output[%d];\n", i, i, i%64);
		//moving along 64 bytes at a time
		if((i+1)%64 == 0){
			//fprintf(fp, "result += 64;\n");
		}
	}
	fclose(fp);
}


	