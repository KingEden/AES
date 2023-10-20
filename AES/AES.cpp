// AES ENCRYPTION //
// AES DECRYPTION //
// Uzair Asif 20I-2392///
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif
#include <iostream>
#include <fstream>
#include <string> 
#include <cstring>
#include <sstream>
#include <cstdlib>
using namespace std;

// Key Length Constants
const int AES_256_KEY_LENGTH = 32; // 256 bits
// File names
const string keyFileName = "Key.txt";
const string encryptedFileName = "Encrypted.txt";
const string decryptedFileName = "Decrypted.txt";

//State Matrix
 unsigned char stateMatrix[16];
//14 Round Keys for 256 Bit Encryption 
unsigned char RoundKey[16]; unsigned char RoundKey1[15][16];
//Declared S Box For Byte Substitution
unsigned char s_box[256] =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
//Declared Fixed Matrix For Mix Column
unsigned char mix_c[4][4] =
{
    {0x02,0x03,0X01,0X01},
    {0x01,0x02,0X03,0X01},
    {0x01,0x01,0X02,0X03},
    {0x03,0x01,0X01,0X02},


};
//Declared Fixed Matrix For Inverse Mix Column
unsigned char inv_mix_c[4][4] =
{
    {0x02,0x03,0X01,0X01},
    {0x01,0x02,0X03,0X01},
    {0x01,0x01,0X02,0X03},
    {0x03,0x01,0X01,0X02},


};
unsigned char xtime(unsigned char x) {
    return ((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}



//Class for Encryption
class AES_encrypt {
public:

// Function to expand the key into round keys
    void KeyExpansion(const unsigned char* originalKey) {
        // Initialize RoundKey1 with the original key
        for (int i = 0; i < 16; i++) {
            RoundKey1[0][i] = originalKey[i];
        }

        unsigned char rcon = 0x01;  // Initialize round constant
        int round = 1;

        while (round <= 14) {
            // Calculate the new word (temp) by rotating and substituting
            unsigned char temp[4];
            for (int i = 0; i < 4; i++) {
                temp[i] = RoundKey1[round - 1][i + 12];  // Take the last word from the previous round
            }

            if (round % 4 == 0) {
                // Perform key schedule core (rotate and substitute)
                const unsigned char temp_byte = temp[0];
                temp[0] = s_box[temp[1]];
                temp[1] = s_box[temp[2]];
                temp[2] = s_box[temp[3]];
                temp[3] = s_box[temp_byte];

                // XOR with the round constant
                temp[0] ^= rcon;
                rcon = xtime(rcon);  // Implement xtime function as described in AES
            }

            // XOR with the word (4 bytes) from the previous round
            for (int i = 0; i < 4; i++) {
                RoundKey1[round][i] = RoundKey1[round - 1][i] ^ temp[i];
            }

            // XOR the next three words with the words from the previous round
            for (int i = 4; i < 16; i++) {
                RoundKey1[round][i] = RoundKey1[round - 1][i] ^ RoundKey1[round][i - 4];
            }

            round++;
        }
    }

    //First Round Key , Takes in Key 
    void Round_Key(string K)
    {
        // Temp 
        unsigned char temp[16];
        unsigned char temp2[16];
        unsigned char w4[4]; unsigned char w5[4]; unsigned char w6[4]; unsigned char w7[4];
        //Key Into temp
        for (int i = 0; i < 16; i++)
        {
            temp[i] = K[i];
        }
        //Left Shift T[3]
        temp2[15] = temp[12];
        temp2[14] = temp[15];
        temp2[13] = temp[14];
        temp2[12] = temp[13];
        for (int i = 0; i < 12; i++)
        {
            temp2[i] = K[i];
        }
        //S-Box on T [3]
        for (int i = 0; i < 12; i++)
        {
            temp2[i] = s_box[temp2[i]];
        }
        //Adding Round Constant
        temp2[8] = temp2[8] + 0x01; temp2[9] = temp2[9] + 0x00;
        temp2[10] = temp2[10] + 0x00; temp2[11] = temp2[11] + 0x00;
        //w[4]=w[0]^g[w[3]]
        for (int i = 0; i < 4; i++)
        {
            w4[0] = temp2[12 + i] ^ temp[i];
        }
        //W[5]
        for (int i = 0; i < 4; i++)
        {
            w5[0] = w4[0] ^ temp[4];
        }
        //W[6]
        for (int i = 0; i < 4; i++)
        {
            w6[0] = w5[0] ^ temp[8];
        }
        //W[7]
        for (int i = 0; i < 4; i++)
        {
            w7[0] = w6[0] ^ temp[12];
        }
        // W[4],W[5],W[6],W[7] into RoundKey
        for (int i = 0; i < 4; i++)
        {
            RoundKey[i] = w4[i];
        }
        for (int i = 0; i < 4; i++)
        {
            RoundKey[i + 4] = w5[i];
        }
        for (int i = 0; i < 4; i++)
        {
            RoundKey[i + 8] = w6[i];
        }
        for (int i = 0; i < 4; i++)
        {
            RoundKey[i + 11] = w7[i];
        }
        //XOR b/w RoundKey and stateMatrix
        for (int i = 0; i < 16; i++)
        {
           stateMatrix[i] = stateMatrix[i] ^ RoundKey[i];
        }
    }
    // ADD Round KEY , XORs the RoundKey with State Matrix
    void Add_RoundKey(unsigned char* R)
    {
        //XOR b/w RoundKey and stateMatrix
        for (int i = 0; i < 16; i++)
        {
            stateMatrix[i] = stateMatrix[i] ^ R[i];
        }

    }
    // Byte Substitution ,Uses S-Box (Decleared Above)
    void Byte_Substitution()
    {
        for (int i = 0; i < 16; i++) {
            stateMatrix[i] = s_box[stateMatrix[i]];
        }

    }
    //Shift Row , Shifts the Row in State Matrix
    void shift_row() {
        unsigned char temp[16];
        for (int i = 0; i < 16; i++) {
            temp[i] = stateMatrix[i];
        }

        // Perform the AES row shift for encryption
        stateMatrix[1] = temp[5];
        stateMatrix[5] = temp[9];
        stateMatrix[9] = temp[13];
        stateMatrix[13] = temp[1];

        stateMatrix[2] = temp[10];
        stateMatrix[6] = temp[14];
        stateMatrix[10] = temp[2];
        stateMatrix[14] = temp[6];

        stateMatrix[3] = temp[15];
        stateMatrix[7] = temp[3];
        stateMatrix[11] = temp[7];
        stateMatrix[15] = temp[11];
    }

    // MIX COLUMMN, Calculating
    void mix_column() 
    {
        unsigned char temp[4][4];
        unsigned char m_c[4][4] = {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
        };

        int count1 = 0;
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                unsigned char result = 0;
                for (int k = 0; k < 4; ++k) {
                    result ^= xtime(stateMatrix[i * 4 + k]) ^ m_c[k][j];
                }
                temp[i][j] = result;
            }
        }

        // Copy temp back to stateMatrix
        int count2 = 0;
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                stateMatrix[count2] = temp[i][j];
                count2++;
            }
        }
    }

};

//Class For Decryption
class AES_decrypt
{
public:


    // Function to expand the key into round keys
    void KeyExpansion(const unsigned char* originalKey) {
        // Initialize RoundKey1 with the original key
        for (int i = 0; i < 16; i++) {
            RoundKey1[0][i] = originalKey[i];
        }

        unsigned char rcon = 0x01;  // Initialize round constant
        int round = 1;

        while (round <= 14) {
            // Calculate the new word (temp) by rotating and substituting
            unsigned char temp[4];
            for (int i = 0; i < 4; i++) {
                temp[i] = RoundKey1[round - 1][i + 12];  // Take the last word from the previous round
            }

            if (round % 4 == 0) {
                // Perform key schedule core (rotate and substitute)
                const unsigned char temp_byte = temp[0];
                temp[0] = s_box[temp[1]];
                temp[1] = s_box[temp[2]];
                temp[2] = s_box[temp[3]];
                temp[3] = s_box[temp_byte];

                // XOR with the round constant
                temp[0] ^= rcon;
                rcon = xtime(rcon);  // Implement xtime function as described in AES
            }

            // XOR with the word (4 bytes) from the previous round
            for (int i = 0; i < 4; i++) {
                RoundKey1[round][i] = RoundKey1[round - 1][i] ^ temp[i];
            }

            // XOR the next three words with the words from the previous round
            for (int i = 4; i < 16; i++) {
                RoundKey1[round][i] = RoundKey1[round - 1][i] ^ RoundKey1[round][i - 4];
            }

            round++;
        }
    }
    // SUB Round KEY , XORs the RoundKey with State Matrix
    void Sub_RoundKey(unsigned char* R)
    {
        //XOR b/w RoundKey and stateMatrix
        for (int i = 0; i < 16; i++)
        {
            stateMatrix[i] = stateMatrix[i] ^ R[i];
        }

    }
    //// INVERSE MIX COLUMMN, Calculating
    void inv_mix_column() 
    {
        unsigned char temp[4][4];

        unsigned char inv_m_c[4][4] = {
            {0x0E, 0x0B, 0x0D, 0x09},
            {0x09, 0x0E, 0x0B, 0x0D},
            {0x0D, 0x09, 0x0E, 0x0B},
            {0x0B, 0x0D, 0x09, 0x0E}
        };

        int count1 = 0;
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                unsigned char result = 0;
                for (int k = 0; k < 4; ++k) {
                    result ^= xtime(stateMatrix[i * 4 + k]) ^ inv_m_c[k][j];
                }
                temp[i][j] = result;
            }
        }

        // Copy temp back to stateMatrix
        int count2 = 0;
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                stateMatrix[count2] = temp[i][j];
                count2++;
            }
        }
    }



    /// Shift Rows to Right
    void shift_row() {
        unsigned char temp2[16];
        for (int i = 4; i < 16; i++) {
            temp2[i] = stateMatrix[i];
        }
        // Row 2
        stateMatrix[4] = temp2[7];
        stateMatrix[5] = temp2[11];
        stateMatrix[6] = temp2[15];
        stateMatrix[7] = temp2[3];

        // Row 3
        stateMatrix[8] = temp2[10];
        stateMatrix[9] = temp2[14];
        stateMatrix[10] = temp2[2];
        stateMatrix[11] = temp2[6];

        // Row 4
        stateMatrix[12] = temp2[13];
        stateMatrix[13] = temp2[1];
        stateMatrix[14] = temp2[5];
        stateMatrix[15] = temp2[9];
    }

    // Byte Substitution ,Uses S-Box (Decleared Above)
    void Byte_Substitution()
    {
        for (int i = 0; i < 16; i++) {
            stateMatrix[i] = s_box[stateMatrix[i]];
        }

    }
};


//File Reading Function
//For Key
string Read_File(const string& fileName) {
    string text;
    ifstream file(fileName);

    if (file.is_open()) {
        getline(file, text);
    }
    else {
        cout << "Reading file unsuccessful. The file may not exist." << endl;
    }

    return text;
}
string Read_Encrypted_File()
{
    string Text;
    ifstream File("Key.txt");

    if (File.is_open())
    {
        getline(File, Text);//Taking data from fill  // Storing it in a variable
    }
    // If Reading from File Fails 
    // Then Error is displayed
    else
    {
        cout << "\nReading file unsuccessful\n";
        cout << "File that you are trying to access may not exist\n";

    }

    return Text;

}

// Function to input plaintext from the user, which can be in hexadecimal format or plain text
void InputPlaintext(unsigned char plaintext[16]) {
    string input;
    cout << "Enter plaintext (in hexadecimal format or plain text): ";
    getline(cin, input);

    if (input.size() == 32) {
        // If the input is 32 characters long, assume it's in hexadecimal format
        istringstream hexStream(input);
        hexStream >> hex;
        for (int i = 0; i < 16; ++i) {
            int byte;
            hexStream >> byte;
            plaintext[i] = static_cast<unsigned char>(byte);
        }
    }
    else if (input.size() == 16) {
        // If the input is 16 characters long, assume it's plain text (ASCII)
        for (int i = 0; i < 16; ++i) {
            plaintext[i] = input[i];
        }
    }
    else {
        cout << "Invalid input format. Please enter 16 bytes of plaintext (32 hexadecimal characters or 16 ASCII characters)." << endl;
        InputPlaintext(plaintext); // Recursive call to get valid input
    }
}

//Main Function 

int main() {
    AES_encrypt AS;
    AES_decrypt DS;

    cout << "================================" << endl;
    cout << "================================" << endl;
    cout << "=====AES 256-Bit Encryption=====" << endl;
    cout << "=====AES 256-Bit Decryption=====" << endl;
    cout << "================================" << endl;
    cout << "================================" << endl;
    Sleep(1000);
    system("cls");
    cout << "==============================" << endl;
    cout << "==========Encryption==========" << endl;
    cout << "==============================" << endl;

    // Read or manually input the encryption key
    string key = Read_File(keyFileName);
    if (key.length() == 0) {
        cout << "Enter the 256-bit encryption key manually (in hexadecimal format): ";
        cin >> key;
    }

    // Validate the key
    if (key.length() != AES_256_KEY_LENGTH) {
        cout << "Invalid key length. The key must be 256 bits (32 bytes) long." << endl;
        return 1;
    }

    // Check if the key is in a valid hexadecimal format
    for (char c : key) {
        if (!isxdigit(c)) {
            cout << "Invalid key format. The key must be in hexadecimal format." << endl;
            return 1;
        }
    }

    // Convert the hex string key to binary
    unsigned char aesKey[AES_256_KEY_LENGTH];
    istringstream hexCharsStream(key);
    for (int i = 0; i < AES_256_KEY_LENGTH; i++) {
        int c;
        hexCharsStream >> hex >> c;
        aesKey[i] = static_cast<unsigned char>(c);
    }

    // Number of rounds
    int numRounds = 10;  

    unsigned char plaintext[16];
    InputPlaintext(plaintext); // Get the plaintext from the user

    // Encrypt the provided plaintext using AES with the given key
    
    AS.KeyExpansion(aesKey); // Key expansion for encryption
    for (int round = 0; round < numRounds; ++round) {
        AS.Round_Key(key); // Calculate the initial round key
        AS.Add_RoundKey(aesKey);
        AS.Byte_Substitution();
        AS.shift_row();
        AS.mix_column();
    }
    AS.Add_RoundKey(aesKey);

    // Save the encrypted data to a file
    ofstream encryptedFile(encryptedFileName, ios::binary);
    if (encryptedFile.is_open()) {
        encryptedFile.write(reinterpret_cast<const char*>(stateMatrix), 16);
        encryptedFile.close();
    }

    cout << "\nEncryption completed. Encrypted data saved to '" << encryptedFileName << "'." << endl;
    Sleep(1000);
    system("cls");

    cout << "==============================" << endl;
    cout << "==========Decryption==========" << endl;
    cout << "==============================" << endl;
    // Decrypt the ciphertext using AES with the given key
    DS.KeyExpansion(aesKey); // Key expansion for decryption
    for (int round = 0; round < numRounds; ++round) {
        DS.Sub_RoundKey(aesKey);
        DS.inv_mix_column();
        DS.shift_row();
        DS.Byte_Substitution();
    }
    DS.Sub_RoundKey(aesKey);

    // Save the decrypted data to a file
    ofstream decryptedFile(decryptedFileName, ios::binary);
    if (decryptedFile.is_open()) {
        decryptedFile.write(reinterpret_cast<const char*>(stateMatrix), 16);
        decryptedFile.close();
    }

    cout << "\nDecryption completed. Decrypted data saved to '" << decryptedFileName << "'." << endl;

    return 0;
}
