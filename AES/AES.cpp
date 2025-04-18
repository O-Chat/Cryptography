#include "AES.h"
#include <vector>         
#include <cstdint>        
#include <iostream> 

AES::AES(const std::vector<unsigned char>& key) {
	roundKeys.resize(176); 
    keyExpansion(key, roundKeys);              // Call key expansion
}
 
inline const uint8_t AES::sbox[256] = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
  0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
  0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
  0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
  0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
  0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
  0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
  0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
  0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
  0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
  0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
  0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
  0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
  0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
  0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
  0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
  0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

inline const uint8_t AES::rsbox[256] = {
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
  0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
  0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
  0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
  0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
  0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
  0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
  0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
  0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
  0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
  0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
  0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
  0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
  0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
  0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
  0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
  0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

uint8_t AES::xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

uint8_t AES::multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return result;
}

void AES::subBytes(std::vector<uint8_t>& state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}


void AES::invSubBytes(std::vector<uint8_t>& state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = rsbox[state[i]];
    }
}

void AES::shiftRows(std::vector<uint8_t>& state) {
    temp = state[4 + 0];  // state[1][0]
    state[4 + 0] = state[4 + 1];  // state[1][1]
    state[4 + 1] = state[4 + 2];  // state[1][2]
    state[4 + 2] = state[4 + 3];  // state[1][3]
    state[4 + 3] = temp;

    // Row 2 (shift left by 2)
    temp = state[8 + 0];  // state[2][0]
    uint8_t temp2 = state[8 + 1];  // state[2][1]
    state[8 + 0] = state[8 + 2];  // state[2][2]
    state[8 + 1] = state[8 + 3];  // state[2][3]
    state[8 + 2] = temp;
    state[8 + 3] = temp2;

    // Row 3 (shift left by 3)
    temp = state[12 + 0];  // state[3][0]
    temp2 = state[12 + 1];  // state[3][1]
    uint8_t temp3 = state[12 + 2];  // state[3][2]
    state[12 + 0] = state[12 + 3];  // state[3][3]
    state[12 + 1] = temp;
    state[12 + 2] = temp2;
    state[12 + 3] = temp3;
}

void AES::invShiftRows(std::vector<uint8_t>& state) {
    uint8_t temp;

    // Row 1 (shift right by 1)
    temp = state[4 + 3];  // state[1][3]
    state[4 + 3] = state[4 + 2];  // state[1][2]
    state[4 + 2] = state[4 + 1];  // state[1][1]
    state[4 + 1] = state[4 + 0];  // state[1][0]
    state[4 + 0] = temp;

    // Row 2 (shift right by 2)
    temp = state[8 + 0];  // state[2][0]
    uint8_t temp2 = state[8 + 1];  // state[2][1]
    state[8 + 0] = state[8 + 2];  // state[2][2]
    state[8 + 1] = state[8 + 3];  // state[2][3]
    state[8 + 2] = temp;
    state[8 + 3] = temp2;

    // Row 3 (shift right by 3)
    temp = state[12 + 0];  // state[3][0]
    temp2 = state[12 + 1];  // state[3][1]
    uint8_t temp3 = state[12 + 2];  // state[3][2]
    state[12 + 0] = state[12 + 1];  // state[3][1]
    state[12 + 1] = state[12 + 2];  // state[3][2]
    state[12 + 2] = state[12 + 3];  // state[3][3]
    state[12 + 3] = temp;           // state[3][0]
}

void AES::mixColumns(std::vector<uint8_t>& state) {
    for (int i = 0; i < 4; ++i) {
        uint8_t t = state[i] ^ state[4 + i] ^ state[8 + i] ^ state[12 + i];
        uint8_t tmp = state[i];
        uint8_t tm = state[i] ^ state[4 + i]; tm = xtime(tm); state[i] ^= tm ^ t;
        tm = state[4 + i] ^ state[8 + i]; tm = xtime(tm); state[4 + i] ^= tm ^ t;
        tm = state[8 + i] ^ state[12 + i]; tm = xtime(tm); state[8 + i] ^= tm ^ t;
        tm = state[12 + i] ^ tmp;         tm = xtime(tm); state[12 + i] ^= tm ^ t;
    }
}

void AES::invMixColumns(std::vector<uint8_t>& state) {
    uint8_t a, b, c, d;
    for (int i = 0; i < 4; ++i) {
        a = state[i];
        b = state[4 + i];
        c = state[8 + i];
        d = state[12 + i];

        state[i] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        state[4 + i] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        state[8 + i] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        state[12 + i] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}


void AES::addRoundKey(std::vector<uint8_t>& state, const uint8_t* roundKey) {
    for (int i = 0; i < 4; ++i) {         // rows
        for (int j = 0; j < 4; ++j) {     // columns
            state[i + 4 * j] ^= roundKey[i + 4 * j];  // column-major order
        }
    }
}



void AES::keyExpansion(const std::string &keyStr) {
    uint8_t key[16];
    for (int i = 0; i < 16; ++i) {
        key[i] = keyStr[i];
    }

    for (int i = 0; i < 4; ++i) {
        roundKeys[4*i+0] = key[4 * i];
        roundKeys[4*i+1] = key[4 * i + 1];
        roundKeys[4*i+2] = key[4 * i + 2];
        roundKeys[4*i+3] = key[4 * i + 3];
    }

    uint8_t temp[4];
    for (int i = 4; i < 44; ++i) {
        temp[0] = roundKeys[4*(i-1)+0];
        temp[1] = roundKeys[4*(i - 1)+1];
        temp[2] = roundKeys[4*(i - 1)+2];
        temp[3] = roundKeys[4*(i - 1)+3];

        if (i % 4 == 0) {
            // Rotate left
            uint8_t k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            // Sub bytes using sbox
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            // XOR with round constant
            temp[0] ^= Rcon[i / 4];
        }

        roundKeys[4*i+0] = roundKeys[4*(i - 4)+0] ^ temp[0];
        roundKeys[4*i+1] = roundKeys[4*(i - 4)+1] ^ temp[1];
        roundKeys[4*i+2] = roundKeys[4*(i - 4)+2] ^ temp[2];
        roundKeys[4*i+3] = roundKeys[4*(i - 4)+3] ^ temp[3];
    }
}
void AES::keyExpansion(const std::vector<unsigned char> &key, std::vector<unsigned char>& expandedKey) {
    std::string keyStr(key.begin(), key.end());
    keyExpansion(keyStr);
}

 std::vector<uint8_t> AES::encryptBlock(const std::vector<uint8_t>& inputBlock){
    std::vector<unsigned char> state(16);

    // Copy plaintext to state array (column-major order)
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
      //      state[i][j] = inputBlock[i + j * 4];
      state[j * 4 + i] = inputBlock[i + j * 4];
        }
    }

    std::vector<unsigned char> expandedKey(176);
    keyExpansion(key, expandedKey); // Expand the key
    addRoundKey(state, expandedKey.data());
    // Rounds 1 to 9
    for (int round = 1; round < 10; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expandedKey.data() + round * 4 * 4);
    }

    // Final round (no MixColumns)
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expandedKey.data() + 4 * 4 * 4);

    // Prepare the ciphertext as a vector
    std::vector<uint8_t> ciphertext(4 * 4);
    
    // Copy state to ciphertext (column-major order)
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            ciphertext[i + j * 4] = state[i+j*4];
        }
    }

    return ciphertext;
}


std::vector<uint8_t> AES::decryptBlock(const std::vector<uint8_t>& inputBlock){
    std::vector<unsigned char> state(16);
    // Copy ciphertext to state array (column-major order)
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
	      state[j * 4 + i] = inputBlock[i + j * 4];

        }
    }

    std::vector<unsigned char> expandedKey(176);
    keyExpansion(key, expandedKey); 

    addRoundKey(state, expandedKey.data() + 4 * 4 * 4); 

    //Round 1 to 10
    for (int round = 9; round > 0; --round) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, expandedKey.data() + round * 4 * 4);
        invMixColumns(state);
    }

    // Final round (no InvMixColumns)
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, expandedKey.data()); // First round key

    // Prepare the plaintext as a vector
    std::vector<uint8_t> plaintext(4 * 4);

    // Copy state to plaintext (column-major order)
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            plaintext[i + j * 4] = state[i+j*4];
        }
    }

    return plaintext;
}

void AES::stringToBytes(const std::string &input, uint8_t *output) {
    for (size_t i = 0; i < input.size(); i++) {
        output[i] = static_cast<uint8_t>(input[i]);
    }
}

std::string AES::bytesToString(const uint8_t *input, size_t length) {
    std::string result;
    for (size_t i = 0; i < length; i++) {
        result += static_cast<char>(input[i]);
    }
    return result;
}
void AES::generateKey(const std::string &passphrase, uint8_t *keyOut) {
    size_t len = passphrase.size();
    for (int i = 0; i < 16; i++) {
        keyOut[i] = i < len ? static_cast<uint8_t>(passphrase[i]) : 0x00;
    }
}
std::vector<uint8_t> AES::readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void AES::writeFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}
void AES::encryptFile(const std::string& inputFilename, const std::string& outputFilename) {
    auto input = readFile(inputFilename);
    std::vector<uint8_t> output;

    for (size_t i = 0; i < input.size(); i += 16) {
        std::vector<uint8_t> block(16, 0x00);
        size_t copySize = std::min<size_t>(16, input.size() - i);
        std::copy(input.begin() + i, input.begin() + i + copySize, block.begin());
        auto encrypted = encryptBlock(block);
        output.insert(output.end(), encrypted.begin(), encrypted.end());
    }

    writeFile(outputFilename, output);
}

void AES::decryptFile(const std::string& inputFilename, const std::string& outputFilename) {
    auto input = readFile(inputFilename);
    std::vector<uint8_t> output;

    for (size_t i = 0; i < input.size(); i += 16) {
        std::vector<uint8_t> block(input.begin() + i, input.begin() + i + 16);
        auto decrypted = decryptBlock(block);
        output.insert(output.end(), decrypted.begin(), decrypted.end());
    }

    writeFile(outputFilename, output);
}

AES::~AES() {
}

