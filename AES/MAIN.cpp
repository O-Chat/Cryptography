#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include "AES.h"  // Include your class header

using namespace std;

void generateRandomKey(std::vector<uint8_t>& key) {
    key.resize(16);
    for (int i = 0; i < 16; ++i)
        key[i] = rand() % 256;
}


int main(int argc, char* argv[]) {
    if (argc != 5) {
        cerr << "Usage: " << argv[0] << " <encrypt/decrypt> <input file> <output file> <key file>\n";
        return 1;
    }

    string mode = argv[1];
    string inputFileName = argv[2];
    string outputFileName = argv[3];
    string keyFileName = argv[4];

    //uint8_t key[16];
    std::vector<uint8_t> key(16);

    if (mode == "encrypt") {
        // Use AES class to generate key
        generateRandomKey(key);
        ofstream keyFile(keyFileName, ios::binary);
        keyFile.write(reinterpret_cast<const char*>(key.data()), 16);
        keyFile.close();

        // Read input file
        ifstream inputFile(inputFileName);
        if (!inputFile) {
            cerr << "Error: Could not open input file!\n";
            return 1;
        }
        string input((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
        inputFile.close();

        // Padding
        size_t originalLength = input.length();
        size_t paddingLength = 16 - (originalLength % 16);
        if (paddingLength == 0) paddingLength = 16;

        for (size_t i = 0; i < paddingLength; ++i) {
            input += static_cast<char>(paddingLength);
        }

        size_t numBlocks = input.length() / 16;
        vector<uint8_t> ciphertext(numBlocks * 16);

        cout << "\nEncrypting...\n";
        AES aes(key);

        for (size_t block = 0; block < numBlocks; ++block) {
            vector<uint8_t> inputBlock(input.begin() + block * 16, input.begin() + (block + 1) * 16);
            vector<uint8_t> encryptedBlock = aes.encryptBlock(inputBlock);
            copy(encryptedBlock.begin(), encryptedBlock.end(), ciphertext.begin() + block * 16);
        }

        ofstream outputFile(outputFileName, ios::binary);
        outputFile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        outputFile.close();

        cout << "Encryption done. Ciphertext written to " << outputFileName << endl;
        cout << "Key saved to " << keyFileName << endl;
    }

    else if (mode == "decrypt") {
        ifstream keyFile(keyFileName, ios::binary);
        if (!keyFile) {
            cerr << "Error: Could not open key file!\n";
            return 1;
        }
        keyFile.read(reinterpret_cast<char*>(key.data()), 16);
        keyFile.close();

        ifstream inputFile(inputFileName, ios::binary);
        vector<uint8_t> ciphertext((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
        inputFile.close();

        size_t numBlocks = ciphertext.size() / 16;
        vector<uint8_t> decryptedtext;

        cout << "\nDecrypting...\n";
        AES aes(key);

        for (size_t block = 0; block < numBlocks; ++block) {
            vector<uint8_t> inputBlock(ciphertext.begin() + block * 16, ciphertext.begin() + (block + 1) * 16);
            vector<uint8_t> decryptedBlock = aes.decryptBlock(inputBlock);
            decryptedtext.insert(decryptedtext.end(), decryptedBlock.begin(), decryptedBlock.end());
        }

        // Remove PKCS#7 padding
        uint8_t pad = decryptedtext.back();
        if (pad > 0 && pad <= 16) {
            decryptedtext.resize(decryptedtext.size() - pad);
        }

        ofstream outputFile(outputFileName);
        outputFile << string(decryptedtext.begin(), decryptedtext.end());
        outputFile.close();

        cout << "Decryption done. Output written to " << outputFileName << endl;
    }

    else {
        cerr << "Invalid mode! Use 'encrypt' or 'decrypt'.\n";
        return 1;
    }

    return 0;
}

