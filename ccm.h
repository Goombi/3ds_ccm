// Copyright 2017 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <array>
#include <cstddef>
#include <vector>

#define MODE_INVALID 0
#define MODE_WRAP    1
#define MODE_UNWRAP  2

typedef std::uint8_t u8;   ///< 8-bit unsigned byte
typedef std::uint16_t u16; ///< 16-bit unsigned short
typedef std::uint32_t u32; ///< 32-bit unsigned word
typedef std::uint64_t u64; ///< 64-bit unsigned int

namespace HW::AES {

constexpr std::size_t AES_BLOCK_SIZE = 16;
constexpr std::size_t AES_HEX_KEY_SIZE = AES_BLOCK_SIZE * 2;
constexpr std::size_t CCM_NONCE_SIZE = 12;
constexpr std::size_t CCM_MAC_SIZE = 16;

using AESKey = std::array<u8, AES_BLOCK_SIZE>;
using CCMNonce = std::array<u8, CCM_NONCE_SIZE>;

/**
 * Encrypts and adds a MAC to the given data using AES-CCM algorithm.
 * @param pdata The plain text data to encrypt
 * @param nonce The nonce data to use for encryption
 * @param slot_id The slot ID of the key to use for encryption
 * @returns a vector of u8 containing the encrypted data with MAC at the end
 */
std::vector<u8> EncryptSignCCM(const std::vector<u8>& pdata, const CCMNonce& nonce,
                               AESKey normal);

/**
 * Decrypts and verify the MAC of the given data using AES-CCM algorithm.
 * @param cipher The cipher text data to decrypt, with MAC at the end to verify
 * @param nonce The nonce data to use for decryption
 * @param slot_id The slot ID of the key to use for decryption
 * @returns a vector of u8 containing the decrypted data; an empty vector if the verification fails
 */
std::vector<u8> DecryptVerifyCCM(const std::vector<u8>& cipher, const CCMNonce& nonce,
                                 AESKey normal);

} // namespace HW::AES
