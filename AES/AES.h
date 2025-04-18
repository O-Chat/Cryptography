#ifndef AES_H
#define AES_H


#include <cstdint>
#include<iostream>
#include<string>
#include<vector>
#include<fstream>


class AES {
private:
	static const uint8_t sbox[256];
       static const uint8_t rsbox[256];
       static constexpr uint8_t Rcon[11]= {
    0x00, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36};


    std::vector<std::vector<uint8_t>> state;
     std::vector<uint8_t> roundKeys;


    std::vector<uint8_t> key;
    int Nb = 4;
    int Nk = 4;
    int Nr = 10;

    uint8_t xtime(uint8_t x);
    uint8_t multiply(uint8_t a, uint8_t b);
    void subBytes(std::vector<uint8_t>& state); 
    void shiftRows(std::vector<uint8_t>& state);
    void mixColumns(std::vector<uint8_t>& state);
    void addRoundKey(std::vector<uint8_t>& state, const uint8_t* roundKey);

    void keyExpansion(const std::string &keyStr);
    void keyExpansion(const std::vector<unsigned char> &key, std::vector<unsigned char>& expandedKey);

    std::vector<uint8_t> subWord(const std::vector<uint8_t>& word);
    std::vector<uint8_t> rotWord(const std::vector<uint8_t>& word);

    void invSubBytes(std::vector<uint8_t>& state);
    void invShiftRows(std::vector<uint8_t>& state);
    void invMixColumns(std::vector<uint8_t>& state);

    static void stringToBytes(const std::string &input, uint8_t *output);
    static std::string bytesToString(const uint8_t *input, size_t length);
    static void generateKey(const std::string &passphrase, uint8_t *keyOut);

    std::vector<uint8_t> readFile(const std::string& filename);
    void writeFile(const std::string& filename, const std::vector<uint8_t>& data);

    public:
    AES(const std::vector<uint8_t>& key);

    std::vector<uint8_t> encryptBlock(const std::vector<uint8_t>& inputBlock);
    std::vector<uint8_t> decryptBlock(const std::vector<uint8_t>& inputBlock);

    void encryptFile(const std::string& inputFilename, const std::string& outputFilename);
    void decryptFile(const std::string& inputFilename, const std::string& outputFilename);
    ~AES();

};

#endif
