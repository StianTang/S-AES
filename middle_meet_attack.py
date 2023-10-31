from saes import encrypt, decrypt
import time

def meet_in_the_middle_attack(known_plain_texts, known_ciphers):
    all_possible_keys = []

    start_time = time.time()

    possible_keys_enc = {}
    possible_keys_dec = {}

    # 步骤1：使用已知明文构建加密字典
    for k1 in range(0, 2**16):
        k1_binary = format(k1, '016b')
        for plain_text in known_plain_texts:
            candidate_cipher = encrypt(plain_text, k1_binary)
            if candidate_cipher not in possible_keys_enc:
                possible_keys_enc[candidate_cipher] = k1_binary
            else:
                # 如果发生冲突，只有在与存储的密钥匹配时才存储密钥
                if possible_keys_enc[candidate_cipher] == k1_binary:
                    possible_keys_enc[candidate_cipher] = k1_binary

    # 步骤2：使用已知密文构建解密字典
    for k2 in range(0, 2**16):
        k2_binary = format(k2, '016b')
        for cipher_text in known_ciphers:
            candidate_plain = decrypt(cipher_text, k2_binary)
            if candidate_plain not in possible_keys_dec:
                possible_keys_dec[candidate_plain] = k2_binary
            else:
                # 如果发生冲突，只有在与存储的密钥匹配时才存储密钥
                if possible_keys_dec[candidate_plain] == k2_binary:
                    possible_keys_dec[candidate_plain] = k2_binary

    # 步骤3：查找同时匹配两个字典的潜在密钥
    for cipher in possible_keys_enc:
        if cipher in possible_keys_dec:
            key1 = possible_keys_enc[cipher]
            key2 = possible_keys_dec[cipher]
            all_possible_keys.append(key1 + key2)

    end_time = time.time()
    elapsed_time = end_time - start_time

    if all_possible_keys:
        all_possible_keys = list(set(all_possible_keys))  # 删除重复的密钥
        all_possible_keys.sort()
        print("Top 5 possible keys:")
        for i, key in enumerate(all_possible_keys[:5]):
            print(f"Key {i+1}: {key}")
        print(f"Number of potential keys: {len(all_possible_keys)}")
    else:
        print("No matching key found.")

    print(f"Time spent on attack: {elapsed_time} seconds")
    return all_possible_keys

# # Assuming known plaintexts and known ciphertexts are separate lists
# known_plain_texts = [
#     "0110101110100011",    # Add more known plaintexts if available
# ]
#
# known_ciphers = [
#     "0011110000111011",   # Add more known ciphertexts if available
# ]
# # Perform meet-in-the-middle attack on known plaintexts and known ciphertexts
# found_keys = meet_in_the_middle_attack(known_plain_texts, known_ciphers)
