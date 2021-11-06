// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include "ccm.h"

namespace HW::AES {

    namespace {

        // 3DS uses a non-standard AES-CCM algorithm, so we need to derive a sub class from the standard one
        // and override with the non-standard part.
        using CryptoPP::AES;
        using CryptoPP::CCM_Base;
        using CryptoPP::CCM_Final;
        using CryptoPP::lword;
        template <bool T_IsEncryption>
        class CCM_3DSVariant_Final : public CCM_Final<AES, CCM_MAC_SIZE, T_IsEncryption> {
        public:
            void UncheckedSpecifyDataLengths(lword header_length, lword message_length,
                                             lword footer_length) override {
                // 3DS uses the aligned size to generate B0 for authentication, instead of the original size
                lword aligned_message_length = message_length + (AES_BLOCK_SIZE - message_length % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
                CCM_Base::UncheckedSpecifyDataLengths(header_length, aligned_message_length, footer_length);
                CCM_Base::m_messageLength = message_length; // restore the actual message size
            }
        };

        class CCM_3DSVariant {
        public:
            using Encryption = CCM_3DSVariant_Final<true>;
            using Decryption = CCM_3DSVariant_Final<false>;
    };

    } // namespace

    std::vector<u8> EncryptSignCCM(const std::vector<u8>& pdata, const CCMNonce& nonce,
                                   AESKey normal) {
        std::vector<u8> cipher(pdata.size() + CCM_MAC_SIZE);

        try {
            CCM_3DSVariant::Encryption e;
            e.SetKeyWithIV(normal.data(), AES_BLOCK_SIZE, nonce.data(), CCM_NONCE_SIZE);
            e.SpecifyDataLengths(0, pdata.size(), 0);
            CryptoPP::ArraySource as(pdata.data(), pdata.size(), true,
                                     new CryptoPP::AuthenticatedEncryptionFilter(
                                         e, new CryptoPP::ArraySink(cipher.data(), cipher.size())));
        } catch (const CryptoPP::Exception& e) {
            printf("Failed : %s\n", e.what());
        }
        return cipher;
    }

    std::vector<u8> DecryptVerifyCCM(const std::vector<u8>& cipher, const CCMNonce& nonce,
                                     AESKey normal) {
        const std::size_t pdata_size = cipher.size() - CCM_MAC_SIZE;
        std::vector<u8> pdata(pdata_size);

        try {
            CCM_3DSVariant::Decryption d;
            d.SetKeyWithIV(normal.data(), AES_BLOCK_SIZE, nonce.data(), CCM_NONCE_SIZE);
            d.SpecifyDataLengths(0, pdata_size, 0);
            CryptoPP::AuthenticatedDecryptionFilter df(
                d, new CryptoPP::ArraySink(pdata.data(), pdata_size));
            CryptoPP::ArraySource as(cipher.data(), cipher.size(), true, new CryptoPP::Redirector(df));
            if (!df.GetLastResult()) {
                printf("Unhandled crypto error\n");
                return {};
            }
        } catch (const CryptoPP::Exception& e) {
            printf("%s\n", e.what());
            return {};
        }
        return pdata;
}

} // namespace HW::AES

namespace Helpers {

    int char2int(char input)
    {
        if(input >= '0' && input <= '9')
            return input - '0';
        if(input >= 'A' && input <= 'F')
            return input - 'A' + 10;
        if(input >= 'a' && input <= 'f')
            return input - 'a' + 10;
        throw std::invalid_argument("Invalid input string");
    }

    void hex2bin(std::string src, u8* target)
    {
        u32 size = src.size() / 2;
        u32 i = 0;
        while(i < size)
        {
            target[i] = char2int(src[2*i])*16 + char2int(src[2*i+1]);
            i++;
        }
    }

    char int2char(u8 input)
    {
        if (input < 10) {
            return input + '0';
        }
        return input + 'A' - 10;
    }

    void bin2hex(u8* src, std::string& target, u32 size)
    {
        u32 i = 0;
        while(i < size)
        {
            target.push_back(int2char(src[i] >> 4));
            target.push_back(int2char(src[i] & 0xf));
            i++;
        }
    }

    std::vector<u8> readFile(const char* filename)
    {
        // open the file:
        std::streampos fileSize;
        std::ifstream file(filename, std::ios::binary);

        // get its size:
        file.seekg(0, std::ios::end);
        fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        // read the data:
        std::vector<u8> fileData(fileSize);
        file.read((char*) &fileData[0], fileSize);
        return fileData;
    }

    void writeFile(const char* filename, std::vector<u8>& fileBytes){
        std::ofstream file(filename, std::ios::out|std::ios::binary);
        std::copy(fileBytes.cbegin(), fileBytes.cend(),
            std::ostream_iterator<unsigned char>(file));
    }

    void copy(u8* dst, u32 dst_offset, u8* src, u32 src_offset, u32 size)
    {
        for (u32 i = 0; i < size; i++) {
            dst[i+dst_offset] = src[i+src_offset];
        }
    }

} // namespace Helpers

namespace APT {

    namespace {

        using Helpers::copy;
    }

    std::vector<u8> Wrap(std::vector<u8> input, u32 nonce_offset, u32 nonce_size, HW::AES::AESKey key)
    {
        if (nonce_size > 12) {
            nonce_size = 12;
        } else {
            // Ask Nintendo, not me
            nonce_size &= ~3;
        }

        // Nonce
        HW::AES::CCMNonce nonce{};
        copy(nonce.data(), 0, input.data(), nonce_offset, nonce_size);
        
        // Cleartext
        u32 cleartext_size = input.size() - nonce_size;
        std::vector<u8> cleartext(cleartext_size);
        copy(cleartext.data(), 0, input.data(), 0, nonce_offset);
        copy(cleartext.data(), nonce_offset, input.data(), nonce_offset + nonce_size, cleartext_size - nonce_offset);

        // Encrypt
        std::vector<u8> cipher = HW::AES::EncryptSignCCM(cleartext, nonce, key);
        if (!cipher.size()) {
            return {};
        }

        // Stich back together
        u32 output_size = cipher.size();
        std::vector<u8> output(output_size + nonce_size);
        copy(output.data(), 0, nonce.data(), 0, nonce_size);
        copy(output.data(), nonce_size, cipher.data(), 0, output_size);

        return output;
    }

    std::vector<u8> Unwrap(std::vector<u8> input, u32 nonce_offset, u32 nonce_size, HW::AES::AESKey key)
    {
        if (nonce_size > 12) {
            nonce_size = 12;
        } else {
            // Ask Nintendo, not me
            nonce_size &= ~3;
        }

        // Nonce
        HW::AES::CCMNonce nonce{};
        copy(nonce.data(), 0, input.data(), 0, nonce_size);
        
        // Cipher
        u32 cipher_size = input.size() - nonce_size;
        std::vector<u8> cipher(cipher_size);
        copy(cipher.data(), 0, input.data(), nonce_size, cipher_size);

        // Decrypt
        std::vector<u8> cleartext = HW::AES::DecryptVerifyCCM(cipher, nonce, key);
        if (!cleartext.size()) {
            return {};
        }

        // Stich back together
        u32 output_size = cleartext.size();
        std::vector<u8> output(output_size + nonce_size);
        copy(output.data(), 0, cleartext.data(), 0, nonce_offset);
        copy(output.data(), nonce_offset, nonce.data(), 0, nonce_size);
        copy(output.data(), nonce_offset + nonce_size, cleartext.data(), nonce_offset, output_size - nonce_offset);

        return output;
    }

} // namespace APT

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 4) {
        printf("Usage: %s <wrap | unwrap> [nonce_offset [nonce_size]]\n", argv[0]);
        return 1;
    }

    u8 mode = MODE_INVALID;
    if (strcmp(argv[1], "wrap") == 0)
        mode = MODE_WRAP;
    if (strcmp(argv[1], "unwrap") == 0)
        mode = MODE_UNWRAP;
    if (mode == MODE_INVALID) {
        printf("Invalid action, must be 'wrap' to encrypt or 'unwrap' to decrypt.\n");
        return 1;
    }

    // Nonce offset
    u32 nonce_offset = 0;
    if (argc > 2)
        nonce_offset = std::stoul(argv[2]);

    // Nonce Size
    u32 nonce_size = HW::AES::CCM_NONCE_SIZE;
    if (argc > 3)
        nonce_size = std::stoul(argv[3]);

    // Parse key
    std::string hex_key;
    std::getline(std::cin, hex_key);
    if (hex_key.size() < HW::AES::AES_BLOCK_SIZE * 2) {
        printf("Key is too short.\n");
        return 1;
    }
    HW::AES::AESKey key{};
    Helpers::hex2bin(hex_key, key.data());

    // Parse raw
    std::string hex_raw;
    std::getline(std::cin, hex_raw);
    std::vector<u8> raw(hex_raw.length() / 2);
    Helpers::hex2bin(hex_raw, raw.data());

    // Decrypt
    std::vector<u8> out;
    if (mode == MODE_WRAP)
        out = APT::Wrap(raw, nonce_offset, nonce_size, key);
    
    if (mode == MODE_UNWRAP)
        out = APT::Unwrap(raw, nonce_offset, nonce_size, key);

    if (!out.size()) {
        return 2;
    }

    // Output
    std::string hex_out;
    Helpers::bin2hex(out.data(), hex_out, out.size());
    std::cout << hex_out << std::endl;

    return out.size() == 0;
}
