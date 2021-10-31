/*
chacha-ref.c version 20080118
D. J. Bernstein
Public domain.
*/
#include <stdio.h>

#include "ecrypt-sync.h"

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

static void salsa20_wordtobyte(u8 output[64],const u32 input[16])
{
  u32 x[16];

  //unfurling this loop
  x[0] = input[0];
  x[1] = input[1];
  x[2] = input[2];
  x[3] = input[3];
  x[4] = input[4];
  x[5] = input[5];
  x[6] = input[6];
  x[7] = input[7];
  x[8] = input[8];
  x[9] = input[9];
  x[10] = input[10];
  x[11] = input[11];
  x[12] = input[12];
  x[13] = input[13];
  x[14] = input[14];
  x[15] = input[15];


    QUARTERROUND( 0, 4, 8,12); //first round 1
    QUARTERROUND( 1, 5, 9,13);
    QUARTERROUND( 2, 6,10,14);
    QUARTERROUND( 3, 7,11,15); 
    QUARTERROUND( 0, 5,10,15); //second round 1
    QUARTERROUND( 1, 6,11,12);
    QUARTERROUND( 2, 7, 8,13);
    QUARTERROUND( 3, 4, 9,14);
    QUARTERROUND( 0, 4, 8,12); //first round 2
    QUARTERROUND( 1, 5, 9,13);
    QUARTERROUND( 2, 6,10,14);
    QUARTERROUND( 3, 7,11,15); 
    QUARTERROUND( 0, 5,10,15); //second round 2
    QUARTERROUND( 1, 6,11,12);
    QUARTERROUND( 2, 7, 8,13);
    QUARTERROUND( 3, 4, 9,14);
    QUARTERROUND( 0, 4, 8,12); //first round 3
    QUARTERROUND( 1, 5, 9,13);
    QUARTERROUND( 2, 6,10,14);
    QUARTERROUND( 3, 7,11,15); 
    QUARTERROUND( 0, 5,10,15); //second round 3 
    QUARTERROUND( 1, 6,11,12);
    QUARTERROUND( 2, 7, 8,13);
    QUARTERROUND( 3, 4, 9,14);
    QUARTERROUND( 0, 4, 8,12); //first round 4
    QUARTERROUND( 1, 5, 9,13);
    QUARTERROUND( 2, 6,10,14);
    QUARTERROUND( 3, 7,11,15); 
    QUARTERROUND( 0, 5,10,15); //second round 4
    QUARTERROUND( 1, 6,11,12);
    QUARTERROUND( 2, 7, 8,13);
    QUARTERROUND( 3, 4, 9,14);

  x[0] = PLUS(x[0],input[0]);
  x[1] = PLUS(x[1],input[1]);
  x[2] = PLUS(x[2],input[2]);
  x[3] = PLUS(x[3],input[3]);
  x[4] = PLUS(x[4],input[4]);
  x[5] = PLUS(x[5],input[5]);
  x[6] = PLUS(x[6],input[6]);
  x[7] = PLUS(x[7],input[7]);
  x[8] = PLUS(x[8],input[8]);
  x[9] = PLUS(x[9],input[9]);
  x[10] = PLUS(x[10],input[10]);
  x[11] = PLUS(x[11],input[11]);
  x[12] = PLUS(x[12],input[12]);
  x[13] = PLUS(x[13],input[13]);
  x[14] = PLUS(x[14],input[14]);
  x[15] = PLUS(x[15],input[15]);

  U32TO8_LITTLE(output + 4 * 0,x[0]);
  U32TO8_LITTLE(output + 4 * 1,x[1]);
  U32TO8_LITTLE(output + 4 * 2,x[2]);
  U32TO8_LITTLE(output + 4 * 3,x[3]);
  U32TO8_LITTLE(output + 4 * 4,x[4]);
  U32TO8_LITTLE(output + 4 * 5,x[5]);
  U32TO8_LITTLE(output + 4 * 6,x[6]);
  U32TO8_LITTLE(output + 4 * 7,x[7]);
  U32TO8_LITTLE(output + 4 * 8,x[8]);
  U32TO8_LITTLE(output + 4 * 9,x[9]);
  U32TO8_LITTLE(output + 4 * 10,x[10]);
  U32TO8_LITTLE(output + 4 * 11,x[11]);
  U32TO8_LITTLE(output + 4 * 12,x[12]);
  U32TO8_LITTLE(output + 4 * 13,x[13]);
  U32TO8_LITTLE(output + 4 * 14,x[14]);
  U32TO8_LITTLE(output + 4 * 15,x[15]);
}

void ECRYPT_init(void)
{
  return;
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void ECRYPT_keysetup(ECRYPT_ctx *x,const u8 *k,u32 kbits,u32 ivbits)
{
  const char *constants;

  //***Key row 1 (2nd row of matrix)
  x->input[4] = U8TO32_LITTLE(k + 0);
  x->input[5] = U8TO32_LITTLE(k + 4);
  x->input[6] = U8TO32_LITTLE(k + 8);
  x->input[7] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  //***Key row 2 (3rd row of matrix)
  x->input[8] = U8TO32_LITTLE(k + 0);
  x->input[9] = U8TO32_LITTLE(k + 4);
  x->input[10] = U8TO32_LITTLE(k + 8);
  x->input[11] = U8TO32_LITTLE(k + 12);
  //***Constant row (1st row of matrix)
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[1] = U8TO32_LITTLE(constants + 4);
  x->input[2] = U8TO32_LITTLE(constants + 8);
  x->input[3] = U8TO32_LITTLE(constants + 12);
}

void ECRYPT_ivsetup(ECRYPT_ctx *x,const u8 *iv)
{
  //***4th row of matrix
  //***Block counter
  x->input[12] = 0;
  x->input[13] = 0;
  //***NONCE
  x->input[14] = U8TO32_LITTLE(iv + 0);
  x->input[15] = U8TO32_LITTLE(iv + 4);
}

void ECRYPT_encrypt_bytes(ECRYPT_ctx *x,const u8 *m,u8 *c,u32 bytes)
{
  u8 output[64];
  int i;
  if (!bytes) return;
  for (;;) {
    //***conducts the quarter rounds, then adds original and new matrices. output is now the keystream
    salsa20_wordtobyte(output,x->input);
    x->input[12] = PLUSONE(x->input[12]);
    if (!x->input[12]) {
      x->input[13] = PLUSONE(x->input[13]);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }

    //***XORS the keystream with the message (plaintext) to form the ciphertext
    //***loops back to the top of the for loop until <= 64 bytes left (last block)
    if (bytes <= 64) {
      for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
      //***Print how many blocks were mixed
      //printf("Blocks:%d\n", x->input[12] + x->input[13]);
      return;
    }
    //***unfurling this loop two xor TWO values each loop
    //in this case, the loop is removed intirely
      c[0] = m[0] ^ output[0];
      c[1] = m[1] ^ output[1];
      c[2] = m[2] ^ output[2];
      c[3] = m[3] ^ output[3];
      c[4] = m[4] ^ output[4];
      c[5] = m[5] ^ output[5];
      c[6] = m[6] ^ output[6];
      c[7] = m[7] ^ output[7];
      c[8] = m[8] ^ output[8];
      c[9] = m[9] ^ output[9];
      c[10] = m[10] ^ output[10];
      c[11] = m[11] ^ output[11];
      c[12] = m[12] ^ output[12];
      c[13] = m[13] ^ output[13];
      c[14] = m[14] ^ output[14];
      c[15] = m[15] ^ output[15];
      c[16] = m[16] ^ output[16];
      c[17] = m[17] ^ output[17];
      c[18] = m[18] ^ output[18];
      c[19] = m[19] ^ output[19];  
      c[20] = m[20] ^ output[20];
      c[21] = m[21] ^ output[21];
      c[22] = m[22] ^ output[22];
      c[23] = m[23] ^ output[23];
      c[24] = m[24] ^ output[24];
      c[25] = m[25] ^ output[25];
      c[26] = m[26] ^ output[26];
      c[27] = m[27] ^ output[27];
      c[28] = m[28] ^ output[28];
      c[29] = m[29] ^ output[29];  
      c[30] = m[30] ^ output[30];
      c[31] = m[31] ^ output[31];
      c[32] = m[32] ^ output[32];
      c[33] = m[33] ^ output[33];
      c[34] = m[34] ^ output[34];
      c[35] = m[35] ^ output[35];
      c[36] = m[36] ^ output[36];
      c[37] = m[37] ^ output[37];
      c[38] = m[38] ^ output[38];
      c[39] = m[39] ^ output[39];  
      c[40] = m[40] ^ output[40];
      c[41] = m[41] ^ output[41];
      c[42] = m[42] ^ output[42];
      c[43] = m[43] ^ output[43];
      c[44] = m[44] ^ output[44];
      c[45] = m[45] ^ output[45];
      c[46] = m[46] ^ output[46];
      c[47] = m[47] ^ output[47];
      c[48] = m[48] ^ output[48];
      c[49] = m[49] ^ output[49];  
      c[50] = m[50] ^ output[50];
      c[51] = m[51] ^ output[51];
      c[52] = m[52] ^ output[52];
      c[53] = m[53] ^ output[53];
      c[54] = m[54] ^ output[54];
      c[55] = m[55] ^ output[55];
      c[56] = m[56] ^ output[56];
      c[57] = m[57] ^ output[57];
      c[58] = m[58] ^ output[58];
      c[59] = m[59] ^ output[59];  
      c[60] = m[60] ^ output[60];
      c[61] = m[61] ^ output[61];
      c[62] = m[62] ^ output[62];
      c[63] = m[63] ^ output[63];   
    bytes -= 64;
    c += 64;
    m += 64;
  }
}

void ECRYPT_decrypt_bytes(ECRYPT_ctx *x,const u8 *c,u8 *m,u32 bytes)
{
  ECRYPT_encrypt_bytes(x,c,m,bytes);
}

void ECRYPT_keystream_bytes(ECRYPT_ctx *x,u8 *stream,u32 bytes)
{
  //**
  u32 i;
  for (i = 0;i < bytes;++i) stream[i] = 0;
  ECRYPT_encrypt_bytes(x,stream,stream,bytes);
}

//************************************************************************
//below is main gathered from https://stackoverflow.com/questions/11176998/how-to-use-salsa20-or-chacha

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ecrypt-sync.h"

//***This is how big the message is (bytes)
#define CHUNKSIZE 1024

void showData(u8 *data, u8 *header);
static inline uint64_t rdtscp64();

int main(int argc, char** argv)
{
    char plaintext[CHUNKSIZE] = "THIS IS A TEST";
    ECRYPT_ctx ctx;
    u8 *key, *IV, *ciphertext, *result;

    showData(plaintext, "PLAINTEXT");

    key = (u8 *)calloc((size_t)ECRYPT_MAXKEYSIZE/8, sizeof(u8));
    IV = (u8 *)calloc((size_t)ECRYPT_MAXIVSIZE/8, sizeof(u8));

    //***Produce a random Key
    ECRYPT_keystream_bytes(&ctx, key, (size_t)ECRYPT_MAXKEYSIZE/8 * sizeof(u8));
    //***produce a manual key
    //key = "This is a key";

    showData(key, "KEY");
    showData(IV, "IV");

    printf("Encrypting [%s] using random %d bit key and %d bit IV:\n", plaintext, ECRYPT_MAXKEYSIZE, ECRYPT_MAXIVSIZE);

    //**repeat and gather averages for time taken
      ECRYPT_init();
      ECRYPT_keysetup(&ctx, key, ECRYPT_MAXKEYSIZE, ECRYPT_MAXIVSIZE);
      ECRYPT_ivsetup(&ctx, IV);

      ciphertext = (u8 *)calloc((size_t)CHUNKSIZE, sizeof(u8));

      //***The chacha ciphering. Produces a ciphertext.
      //***collect the time before and after
      uint64_t startT = rdtscp64();
      ECRYPT_encrypt_bytes(&ctx, plaintext, ciphertext, CHUNKSIZE);
      uint64_t endT = rdtscp64();
      //printf("Time after: [%ld]\n", endT);
      //printf("Total time: [%ld]\n\n", endT - startT);
    printf("Total time: [%ld]\n", endT - startT);

    showData(ciphertext, "CIPHERTEXT");

    result = (u8 *)calloc((size_t)CHUNKSIZE, sizeof(u8));

    //Using the same key matrix (ctx), decrypts the message by xoring in the other direction
    ECRYPT_ivsetup(&ctx, IV);
    ECRYPT_decrypt_bytes(&ctx, ciphertext, result, CHUNKSIZE);
    printf("And now decrypting back: [%s]\n", result);

    return 0;
}

void showData(u8 *data, u8 *header) {
    printf("\n-----BEGIN %s-----\n%s\n-----END %s-----\n\n", header, data, header);

}

//***provided by supervisor. Returns the number of cycles at the current moment.
static inline uint64_t rdtscp64() {
  uint32_t low, high;
  asm volatile ("rdtscp": "=a" (low), "=d" (high) :: "ecx");
  return (((uint64_t)high) << 32) | low;
}
