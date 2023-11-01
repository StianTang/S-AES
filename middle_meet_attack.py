from saes import encrypt, decrypt
import time


def meet_in_the_middle_attack(pairs):
    # 存储所有明密文对的交集
    possible_keys_set = None
    start_time = time.time()

    for plaintext, ciphertext in pairs:
        encrypt_dict = {}
        current_possible_keys = set()

        #  从明文开始加密
        for key1 in range(2**16):
            key1_binary = format(key1, '016b')
            intermediate_ciphertext = encrypt(plaintext, key1_binary)
            encrypt_dict[intermediate_ciphertext] = key1_binary

        #  从密文开始解密
        for key2 in range(2**16):
            key2_binary = format(key2, '016b')
            intermediate_plaintext = decrypt(ciphertext, key2_binary)
            # 查找是否有匹配
            if intermediate_plaintext in encrypt_dict:
                current_possible_keys.add((encrypt_dict[intermediate_plaintext], key2_binary))

        if possible_keys_set is None:
            possible_keys_set = current_possible_keys
        else:
            possible_keys_set &= current_possible_keys

    end_time = time.time()
    time_taken = end_time - start_time

    return list(possible_keys_set), time_taken


