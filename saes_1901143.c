#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ENCRYPT  0
#define DECRYPT 1

uint8_t ENC_SBox[4][4] = { 0x9, 0x4, 0xA, 0XB,
					   0XD, 0X1, 0X8, 0X5,
					   0X6, 0X2, 0x0, 0X3,
					   0XC, 0XE, 0xF, 0x7
					 };

uint8_t DEC_SBox[4][4] = { 0xA, 0x5, 0x9, 0XB,
					   0X1, 0X7, 0X8, 0XF,
					   0X6, 0X0, 0x2, 0X3,
					   0XC, 0X4, 0xD, 0xE
};


uint16_t perform_sBox(uint16_t input, uint8_t mode)
{
	uint8_t temp;
	uint16_t sBox_output = 0;
	for (int i = 0; i < 4; i++)
	{
		temp = (input >> (16 - (i + 1) * 4)) & 0xf;
		//printf("temp = 0x%x\n", temp);

		if(mode == ENCRYPT)
			sBox_output |= (ENC_SBox[temp >> 2][temp & 0x3] << (16 - (i + 1) * 4));
		else if (mode == DECRYPT)
			sBox_output |= (DEC_SBox[temp >> 2][temp & 0x3] << (16 - (i + 1) * 4));
	}
	return sBox_output;
}

void print_sBox()
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			printf("%0X\t", ENC_SBox[i][j]);
		}
		printf("\n");
	}
}

uint8_t RotNib(uint8_t input)
{
	return ((input << 4) | (input >> 4));
}

uint16_t preform_addRound(uint16_t input, uint16_t key)
{
	return (input^key);
}

uint16_t preform_shiftRow(uint16_t input)
{
	/* Nibble1  Nibble2  Nibble3  Nibble4 */

	uint16_t nibble2_mask = (input >>8) & 0xf;
	uint16_t nibble4_mask = (input & 0x0f) << 8;
	return( (input & 0xf0f0) | nibble2_mask | nibble4_mask);
}

uint8_t preform_mul(uint8_t a, uint8_t b) 
{
	// Initialise
	uint8_t product = 0;

	// While both multiplicands are non-zero
	while (a && b) 
	{
		// If LSB of b is 1
		if (b & 1) {
			product = product ^ a;	// Add current a to product
		}

		// Update a to a * 2
		a = a << 1;

		// If a overflows beyond 4th bit
		if (a & (1 << 4)) {
			// XOR with irreducible polynomial with high term eliminated
			a = a ^ 0b10011;
		}

		// Update b to b // 2
		b = b >> 1;
	}

	return product;
}

uint16_t preform_mixColumn(uint16_t input, uint8_t mode)
{
	if (mode == ENCRYPT)
	{
		uint8_t nibble1 = (input >> 12);
		uint8_t nibble2 = (input >> 8) & 0x0f;
		uint8_t nibble3 = (input >> 4) & 0x0f;
		uint8_t nibble4 = input & 0x0f;

		uint8_t nibble1_afterMul = nibble1 ^ preform_mul(4, nibble2);
		uint8_t nibble2_afterMul = preform_mul(4, nibble1) ^ nibble2;
		uint8_t nibble3_afterMul = nibble3 ^ preform_mul(4, nibble4);
		uint8_t nibble4_afterMul = preform_mul(4, nibble3) ^ nibble4;

		/*
		printf("nibble1_afterMul = 0x%X\n", nibble1_afterMul);
		printf("nibble2_afterMul = 0x%X\n", nibble2_afterMul);
		printf("nibble3_afterMul = 0x%X\n", nibble3_afterMul);
		printf("nibble4_afterMul = 0x%X\n", nibble4_afterMul);
		*/

		return ((nibble1_afterMul << 12) | (nibble2_afterMul << 8) | (nibble3_afterMul << 4) | (nibble4_afterMul));
	}
	else if (mode == DECRYPT)
	{
		uint8_t nibble1 = (input >> 12);
		uint8_t nibble2 = (input >> 8) & 0x0f;
		uint8_t nibble3 = (input >> 4) & 0x0f;
		uint8_t nibble4 = input & 0x0f;

		uint8_t nibble1_afterMul = preform_mul(9, nibble1) ^ preform_mul(2, nibble2);
		uint8_t nibble2_afterMul = preform_mul(2, nibble1) ^ preform_mul(9, nibble2);
		uint8_t nibble3_afterMul = preform_mul(9, nibble3) ^ preform_mul(2, nibble4);
		uint8_t nibble4_afterMul = preform_mul(2, nibble3) ^ preform_mul(9, nibble4);

		/*
		printf("nibble1_afterMul = 0x%X\n", nibble1_afterMul);
		printf("nibble2_afterMul = 0x%X\n", nibble2_afterMul);
		printf("nibble3_afterMul = 0x%X\n", nibble3_afterMul);
		printf("nibble4_afterMul = 0x%X\n", nibble4_afterMul);
		*/

		return ((nibble1_afterMul << 12) | (nibble2_afterMul << 8) | (nibble3_afterMul << 4) | (nibble4_afterMul));
	}
}

void generateKeys(uint16_t input, uint16_t *key1, uint16_t *key2)
{
	uint8_t w0 = input >> 8;
	uint8_t w1 = input & 0xff;
	uint8_t w2 = w0 ^ 0b10000000 ^ perform_sBox(RotNib(w1),ENCRYPT);
	uint8_t w3 = w2 ^ w1;
	uint8_t w4 = w2 ^ 0b00110000 ^ perform_sBox(RotNib(w3), ENCRYPT);
	uint8_t w5 = w4 ^ w3;

	/*
	printf("w0 = 0x%X\n", w0);
	printf("w1 = 0x%X\n", w1);
	printf("w2 = 0x%X\n", w2);
	printf("w3 = 0x%X\n", w3);
	printf("w4 = 0x%X\n", w4);
	printf("w5 = 0x%X\n", w5);
	*/

	*key1 = (w2 << 8) | w3;
	*key2 = (w4 << 8) | w5;
}

uint16_t ENC(uint16_t Plaintext, uint16_t key0)
{
	/******** generate the sub-keys *******/
	uint16_t Key1, key2;
	generateKeys(key0, &Key1, &key2);
	//printf("Key1 = 0x%X\n", Key1);
	//printf("Key2 = 0x%X\n", key2);


	/******** add round key0 *******/
	uint16_t addRoundKey0_output = preform_addRound(Plaintext, key0);
	//printf("addRoundKey0_output = 0x%X\n", addRoundKey0_output);


	/******** perform sBox0 *******/
	uint16_t sBox_output0 = perform_sBox(addRoundKey0_output, ENCRYPT);
	//printf("sBox_output0 = 0x%X\n", sBox_output0);


	/******** perform shiftRow0 *******/
	uint16_t shiftRow0_output = preform_shiftRow(sBox_output0);
	//printf("shiftRow_output = 0x%X\n", shiftRow0_output);


	/******** perform mixColum *******/
	uint16_t mixColumn_output = preform_mixColumn(shiftRow0_output, ENCRYPT);
	//printf("mixColumn_output = 0x%X\n", mixColumn_output);


	/******** add round key1 *******/
	uint16_t addRoundKey1_output = preform_addRound(mixColumn_output, Key1);
	//printf("addRoundKey1_output = 0x%X\n", addRoundKey1_output);


	/******** perform sBox1 *******/
	uint16_t sBox_output1 = perform_sBox(addRoundKey1_output, ENCRYPT);
	//printf("sBox_output1 = 0x%X\n", sBox_output1);


	/******** perform shiftRow1 *******/
	uint16_t shiftRow1_output = preform_shiftRow(sBox_output1);
	//printf("shiftRow1_output = 0x%X\n", shiftRow1_output);

	/******** add round key2 *******/
	uint16_t addRoundKey2_output = preform_addRound(shiftRow1_output, key2);
	//printf("addRoundKey2_output = 0x%X\n", addRoundKey2_output);


	return addRoundKey2_output;
}

uint16_t DEC(uint16_t Ciphertext, uint16_t key0)
{
	/******** generate the sub-keys *******/
	uint16_t Key1, key2;
	generateKeys(key0, &Key1, &key2);
	//printf("Key1 = 0x%X\n", Key1);
	//printf("Key2 = 0x%X\n", key2);


	/******** add round key2 *******/
	uint16_t addRoundKey2_output = preform_addRound(Ciphertext, key2);
	//printf("addRoundKey2_output = 0x%X\n", addRoundKey2_output);

	/******** perform shiftRow1 *******/
	uint16_t shiftRow1_output = preform_shiftRow(addRoundKey2_output);
	//printf("shiftRow1_output = 0x%X\n", shiftRow1_output);


	/******** perform sBox1 *******/
	uint16_t sBox_output1 = perform_sBox(shiftRow1_output,DECRYPT);
	//printf("sBox_output1 = 0x%X\n", sBox_output1);


	/******** add round key1 *******/
	uint16_t addRoundKey1_output = preform_addRound(sBox_output1, Key1);
	//printf("addRoundKey1_output = 0x%X\n", addRoundKey1_output);

	
	/******** perform mixColum *******/
	uint16_t mixColumn_output = preform_mixColumn(addRoundKey1_output,DECRYPT);
	//printf("mixColumn_output = 0x%X\n", mixColumn_output);


	/******** perform shiftRow0 *******/
	uint16_t shiftRow0_output = preform_shiftRow(mixColumn_output);
	//printf("shiftRow_output = 0x%X\n", shiftRow0_output);


	/******** perform sBox0 *******/
	uint16_t sBox_output0 = perform_sBox(shiftRow0_output, DECRYPT);
	//printf("sBox_output0 = 0x%X\n", sBox_output0);


	/******** add round key0 *******/
	uint16_t addRoundKey0_output = preform_addRound(sBox_output0, key0);
	//printf("addRoundKey0_output = 0x%X\n", addRoundKey0_output);


	return addRoundKey0_output;
}

int main(int argc, char* argv[])
{
	if (argc != 4) {
		printf("invalid arguments\n");
		return -1;
	}

	/******** read mode, text and key *******/ 
	char* mode = argv[1];
	uint16_t key0 = (uint16_t)strtol(argv[2], NULL, 16);
	uint16_t text = (uint16_t)strtol(argv[3], NULL, 16);

	/******** print entered text and key *******/
	printf("text = 0x%X\n", text);
	printf("key = 0x%X\n", key0);
	printf("-------------------\n");
	
	/******** preform encryption *******/
	if (strcmp(mode, "ENC") == 0)
	{
		uint16_t encry_output = ENC(text, key0);
		printf("encryption = 0x%X\n", encry_output);
	}
	/******** preform decryption *******/
	else if (strcmp(mode, "DEC") == 0)
	{
		uint16_t decry_output = DEC(text, key0);
		printf("decryption = 0x%X\n", decry_output);
	}
	
	return 0;
}