//Mohamed Mostafa Shaban Mohamed
//1901650
/***************************      Simplified AES implementation in pure C programming         ******************************/

// Simplified_AES.c: This file contains the 'main' function. Program execution begins and ends there.
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
// Implementation: S-Box
/**
 * @brief Substitute the given nibble using the given 4x4 S-box table
 *
 * @param nibble
 * @param _tab
 * @return uint8_t
 */
static inline uint8_t _sub(uint8_t nibble, uint8_t _tab[4][4]) {

    /* Get the row value */
    int row = (nibble & 0b1100) >> 2;
    int col = (nibble & 0b0011);

    /* Return the substitution */
    return _tab[row][col];
}
/**
 * @brief Substitute the given array of four nibbles with another four nibbles
 *        (for encryption)
 *
 * @param block
 */
void sub_nibbles(uint8_t block[4]) {

    static uint8_t _tab[4][4] = {
        // 00    01     02     03   
          0x9,  0x4,   0xA,   0xB ,     // 00
          0xD,  0x1,   0x8,   0x5,      // 01
          0x6,  0x2,   0x0,   0x3,      // 02
          0xC,  0xE,   0xF,   0x7       // 03
    };

    for (int i = 0; i < 4; i++) {

        block[i] = _sub(block[i], _tab);
    }
}
/**
 * @brief Substitute the given array of four nibbles with another four nibbles
 *        (for decryption)
 *
 * @param block
 */
void inv_sub_nibbles(uint8_t block[4]) {

    static uint8_t _tab[4][4] = {
        // 00    01     02     03   
          0xA,  0x5,   0x9,   0xB ,     // 00
          0x1,  0x7,   0x8,   0xF,      // 01
          0x6,  0x0,   0x2,   0x3,      // 02
          0xC,  0x4,   0xD,   0xE       // 03
    };

    for (int i = 0; i < 4; i++) {

        block[i] = _sub(block[i], _tab);
    }
}
/*********************  key Expansion *********************/


/* Round constants for two rounds */
#define R_CON_1 0x80
#define R_CON_2 0x30
/**
 * @brief Find the temporary word given the previous word and the round constant
 *
 * @param w
 * @param r_con
 * @return uint8_t
 */
static uint8_t _find_tmp_word(uint8_t w, uint8_t r_con) {

    uint8_t tmp;
    uint8_t row;
    uint8_t col;

    /* Substitution box table */
    static uint8_t _tab[4][4] = {
        // 00    01     02     03   
          0x9,  0x4,   0xA,   0xB ,     // 00
          0xD,  0x1,   0x8,   0x5,      // 01
          0x6,  0x2,   0x0,   0x3,      // 02
          0xC,  0xE,   0xF,   0x7       // 03
    };

    /* Rotate the nibbles of the given word */
    tmp = ((w & 0x0F) << 4) | ((w & 0xF0) >> 4);

    /* Substitute the first nibble */
    row = (tmp & 0x0C) >> 2;
    col = (tmp & 0x03);
    tmp = (tmp & 0xF0);
    tmp = (tmp | _tab[row][col]);

    /* Substitute the second nibble */
    row = (tmp & 0xC0) >> 6;
    col = (tmp & 0x30) >> 4;
    tmp = (tmp & 0x0F);
    tmp = (tmp | _tab[row][col] << 4);

    /* Exor with the round constant */
    tmp = tmp ^ r_con;

    return tmp;
}
/**
 * @brief Expand the given 16 bit key into nibble arrays for each of the three
 *        subkeys
 *
 * @param key
 * @param subkey
 */
void key_exp(uint16_t key, uint8_t subkey[3][4]) {

    uint8_t w0;
    uint8_t w1;
    uint8_t w2;
    uint8_t w3;
    uint8_t w4;
    uint8_t w5;
    uint8_t t2;
    uint8_t t4;

    /* Get the pre-round subkey */
    w0 = (key & 0xFF00) >> 8;
    w1 = (key & 0x00FF);

    /* Get the first round subkey */
    t2 = _find_tmp_word(w1, R_CON_1);
    w2 = t2 ^ w0;
    w3 = w2 ^ w1;

    /* Get the second round subkey */
    t4 = _find_tmp_word(w3, R_CON_2);
    w4 = t4 ^ w2;
    w5 = w4 ^ w3;

    /* Convert the 16 bit keys to the nibble arrays */
    subkey[0][0] = (w1 & 0x0F);
    subkey[0][1] = (w1 & 0xF0) >> 4;
    subkey[0][2] = (w0 & 0x0F);
    subkey[0][3] = (w0 & 0xF0) >> 4;

    subkey[1][0] = (w3 & 0x0F);
    subkey[1][1] = (w3 & 0xF0) >> 4;
    subkey[1][2] = (w2 & 0x0F);
    subkey[1][3] = (w2 & 0xF0) >> 4;

    subkey[2][0] = (w5 & 0x0F);
    subkey[2][1] = (w5 & 0xF0) >> 4;
    subkey[2][2] = (w4 & 0x0F);
    subkey[2][3] = (w4 & 0xF0) >> 4;
}

/******************** shift rows ************************/

/**
 * @brief Shift the second row to the left/right by one nibble, i.e. swap the
 *        nibbles
 *
 * @param block
 */
 /* shift rows operation encryption */
void shft_rows(uint8_t block[4]) {

    /* Swap the nibbles n1 and n3, which are the elements 0 and 2 of the
     * nibble array
     */
    uint8_t temp = block[0];
    block[0] = block[2];
    block[2] = temp;
}
/* Inverse shift rows operation decryption */
#define inv_shft_rows shft_rows



/****************** GF(2^4) operations **********************************/
/**
 * @brief Return the galois field addition of a and b in GF(2^4)
 *
 * @param a
 * @param b
 * @return uint8_t
 */
uint8_t gf_add(uint8_t a, uint8_t b) {

    return (a & 0x0F) ^ (b & 0x0F);
}
/* Galois Field Degree */
#define GF_DEGREE        (0x04)
/* Reducing polynomial for GF(2^4) */
#define GF_REDUCING_POLY (0x13)
/**
 * @brief Return the galois field multiplication of a and b in GF(2^4)
 *
 * @param a
 * @param b
 * @return uint8_t
 */
uint8_t gf_mul(uint8_t a, uint8_t b) {

    uint8_t p = 0;

    /* Mask the unwanted bits */
    a = a & 0x0F;
    b = b & 0x0F;

    /* While both the multiplicands are non-zero */
    while (a && b) {

        /* If LSB of b is 1 */
        if (b & 1) {
            /* Add the current a to p */
            p = p ^ a;
        }

        /* Update both a and b */
        a = a << 1;
        b = b >> 1;

        /* If a overflows beyond the 4th bit */
        if (a & (1 << GF_DEGREE)) {

            a = a ^ GF_REDUCING_POLY;
        }
    }

    return p;
}


/************************** mix colmuns **************************/
/**
 * @brief Matrix muliply two 2x2 matrices under GF(2^4) field
 *
 * @param _tab
 * @param block
 */
void _mat_mul(uint8_t const_mat[4], uint8_t block[4]) {

    /* Get the constant matrix nibbles */
    uint8_t c0 = const_mat[3];
    uint8_t c1 = const_mat[2];
    uint8_t c2 = const_mat[1];
    uint8_t c3 = const_mat[0];

    /* Get the block matrix nibbles */
    uint8_t n0 = block[3];
    uint8_t n1 = block[2];
    uint8_t n2 = block[1];
    uint8_t n3 = block[0];

    /* Compute each element and store the result in the block array */
    block[3] = gf_add(gf_mul(c0, n0), gf_mul(c2, n1));
    block[2] = gf_add(gf_mul(c1, n0), gf_mul(c3, n1));
    block[1] = gf_add(gf_mul(c0, n2), gf_mul(c2, n3));
    block[0] = gf_add(gf_mul(c1, n2), gf_mul(c3, n3));
}

/**
 * @brief Mix the columns of the given 4 nibbles, used for encryption
 *        using galois field matrix multiplication
 *
 * @param block
 */
void mix_cols(uint8_t block[4]) {

    static uint8_t _tab[4] = { 1, 4, 4, 1 };

    _mat_mul(_tab, block);
}

/**
 * @brief Mix the columns of the given 4 nibbles, used for decryption
 *        using galois field matrix multiplication
 *
 * @param block
 */
void inv_mix_cols(uint8_t block[4]) {

    static uint8_t _tab[4] = { 9, 2, 2, 9 };

    _mat_mul(_tab, block);
}



/**************************** Add Round Key *****************************/
/**
 * @brief Add the four nibbles of round key nibble by nibble to the block
 *
 * @param block
 * @param rnd_key
 */
void add_rnd_key(uint8_t block[4], uint8_t rnd_key[4]) {

    *((int*)block) ^= *((int*)rnd_key);
}


/******************************* S_AES Encryption *****************************/
uint16_t _saes_enc_block(uint16_t plainblock, uint8_t subkey[3][4]) {

    uint8_t block[4];

    /* Convert the 16 bits to 4 nibble array */
    block[0] = (plainblock & 0x000F);
    block[1] = (plainblock & 0x00F0) >> 4;
    block[2] = (plainblock & 0x0F00) >> 8;
    block[3] = (plainblock & 0xF000) >> 12;

    /* Pre-round */

    /* Add round key */
    add_rnd_key(block, subkey[0]);

    /* Round 1 */

    /* Nibble Substitution */
    sub_nibbles(block);
    /* Shift rows */
    shft_rows(block);
    /* Mix columns */
    mix_cols(block);
    /* Add round key */
    add_rnd_key(block, subkey[1]);

    /* Round 2 */

    /* Nibble Substitution */
    sub_nibbles(block);
    /* Shift rows */
    shft_rows(block);
    /* Add round key */
    add_rnd_key(block, subkey[2]);
    /* Check if the most significant bit is 0 and return 0 with remaining bits set to 0 */


    printf("Encryption Worked!\n");
    /* Combine the 4 nibbles and return the 16 bits */
    return (((uint16_t)block[3] << 12) |
        ((uint16_t)block[2] << 8) |
        ((uint16_t)block[1] << 4) |
        ((uint16_t)block[0]));
}


/*********************** S-AES Decryption ****************************/
uint16_t _saes_dec_block(uint16_t cipherblock, uint8_t subkey[3][4]) {

    uint8_t block[4];

    /* Convert the 16 bits to 4 nibble array */
    block[0] = (cipherblock & 0x000F);
    block[1] = (cipherblock & 0x00F0) >> 4;
    block[2] = (cipherblock & 0x0F00) >> 8;
    block[3] = (cipherblock & 0xF000) >> 12;

    /* Pre-round */

    /* Add round key */
    add_rnd_key(block, subkey[2]);

    /* First round */

    /* Inverse shift rows */
    inv_shft_rows(block);
    /* Inverse nibble substitution */
    inv_sub_nibbles(block);
    /* Add round key */
    add_rnd_key(block, subkey[1]);
    /* Inverse mix columns */
    inv_mix_cols(block);

    /* Second round */

    /* Inverse shift rows */
    inv_shft_rows(block);
    /* Inverse nibble substitution */
    inv_sub_nibbles(block);
    /* Add round key */
    add_rnd_key(block, subkey[0]);

    printf("Decryption Worked!\n");
    /* Combine the 4 nibbles and return the 16 bits */
    return (((uint16_t)block[3] << 12) |
        ((uint16_t)block[2] << 8) |
        ((uint16_t)block[1] << 4) |
        ((uint16_t)block[0]));
}


/******************************* test Encryption & Decryption *****************************/
int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s <ENC/DEC> <key> <plaintext>\n", argv[0]);
        return 1;
    }

    char* mode = argv[1]; // Get the mode argument

    uint8_t subkey[3][4];
    uint16_t key = strtol(argv[2], NULL, 16); // Convert the second argument to a hexadecimal key
    key_exp(key, subkey);

    uint16_t input = strtol(argv[3], NULL, 16); // Convert the third argument to a hexadecimal input

    uint16_t output;
    if (strcmp(mode, "ENC") == 0) {
        output = _saes_enc_block(input, subkey);
        printf("The Encryption Output: \nPlaintext = 0x%04hhX\nCiphertext = 0x%04hhX\n", input, output);
    }
    else if (strcmp(mode, "DEC") == 0) {
        output = _saes_dec_block(input, subkey);
        printf("The Decryption Output: \nCiphertext = 0x%04hhX\nPlaintext = 0x%04hhX\n", input, output);
    }
    else {
        printf("Invalid mode. Use ENC for encryption or DEC for decryption.\n");
        return 1;
    }

    return 0;
}