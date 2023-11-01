from saes import encrypt, decrypt, xor_operation


# CBC模式加密
def cbc_encrypt(plaintext, iv, key):
    block_size = 16  # 分块大小为16位
    ciphertext = ""
    previous_block = iv  # 初始化前一个加密块为初始向量（IV）

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        # 按位异或明文块和前一个加密块（或IV）
        xored_block = xor_operation(block, previous_block)
        # 对异或结果进行加密
        encrypted_block = encrypt(xored_block, key)
        ciphertext += encrypted_block
        # 更新前一个加密块为当前加密结果
        previous_block = encrypted_block

    return ciphertext


# CBC模式解密
def cbc_decrypt(ciphertext, iv, key):
    block_size = 16  # 分块大小为16位
    plaintext = ""
    previous_block = iv  # 初始化前一个加密块为初始向量（IV）

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        # 解密得到明文块
        decrypted_block = decrypt(block, key)
        # 按位异或解密结果和前一个加密块（或IV）
        xored_block = xor_operation(decrypted_block, previous_block)
        plaintext += xored_block
        # 更新前一个加密块为当前解密结果
        previous_block = block

    return plaintext


