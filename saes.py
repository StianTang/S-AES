# S-AES（Simplified Advanced Encryption Standard）简化的高级加密标准
from key import *

S = [[9, 4, 10, 11],
     [13, 1, 8, 5],
     [6, 2, 0, 3],
     [12, 14, 15, 7]]
S_inv = [[10, 5, 9, 11],
         [1, 7, 8, 15],
         [6, 0, 2, 3],
         [12, 4, 13, 14]]

Row = [[1,4],
       [4,1]]
Row_inv = [[9,2],
          [2,9]]


# 将输入的文本和密钥进行按位异或运算
def xor_operation(text, key):
    text_2 = xor(text, key)
    return text_2


# 将输入的文本按照半字节（4位）进行处理
def half_byte(text,S):
    t11=to_decimal(text[:2])
    t12=to_decimal(text[2:4])
    t21=to_decimal(text[4:6])
    t22=to_decimal(text[6:8])
    t31=to_decimal(text[8:10])
    t32=to_decimal(text[10:12])
    t41=to_decimal(text[12:14])
    t42=to_decimal(text[14:])
    # 文本分为8个半字节,根据S盒进行替换操作
    t1 = to_binary_4(S[t11][t12])
    t2 = to_binary_4(S[t21][t22])
    t3 = to_binary_4(S[t31][t32])
    t4 = to_binary_4(S[t41][t42])
    text_2 = t1+t2+t3+t4
    return text_2


# 交换行和列
def swap_rows_and_columns(text):
    te0 = text[:4]
    te1 = text[4:8]
    te2 = text[8:12]
    te3 = text[12:]
    text_2 = te0+te3+te2+te1
    return text_2


# 根据输入的两个参数a和b，以及输入的两个半字节te1和te2，计算它们的乘积
def n_Cheng(a, b, te1, te2):
    # 4 bits
    a = int(a)
    b = int(b)
    if a == 2 and b == 0:
        te1, te2 = te2, te1
    i = 0
    xte1 = []
    xte2 = []
    while i < 4:
        xte1.append(te1[i])
        xte2.append(te2[i])
        i = i+1
    xin = xte1+xte2
    xe = ""
    xe = xe + xor(xin[0], xin[6])
    xe = xe + xor(xor(xin[1], xin[4]), xin[7])
    xe = xe + xor(xor(xin[2], xin[4]), xin[5])
    xe = xe + xor(xin[3], xin[5])
    return xe


# 行变换操作
def row_mix(text):
    t11 = text[:4]
    t21 = text[4:8]
    t12 = text[8:12]
    t22 = text[12:]
    t110 = n_Cheng(0, 2, t11, t21)
    t210 = n_Cheng(2, 0, t11, t21)
    t120 = n_Cheng(0, 2, t12, t22)
    t220 = n_Cheng(2, 0, t12, t22)
    return t110+t210+t120+t220


li_hun2 = [0,2,4,6,8,10,12,14,3,1,7,5,11,9,15,13]
li_hun9 = [0,9,1,8,2,11,3,10,4,13,5,12,6,15,7,14]


# 列逆变换
def row_mix_inv(text):
    t11 = to_decimal(text[:4])
    t21 = to_decimal(text[4:8])
    t12 = to_decimal(text[8:12])
    t22 = to_decimal(text[12:])
    li11 = to_binary_4(li_hun9[t11])
    li12 = to_binary_4(li_hun2[t21])
    li21 = to_binary_4(li_hun2[t11])
    li22 = to_binary_4(li_hun9[t21])
    li31 = to_binary_4(li_hun9[t12])
    li32 = to_binary_4(li_hun2[t22])
    li41 = to_binary_4(li_hun2[t12])
    li42 = to_binary_4(li_hun9[t22])
    yi1 = xor(li11,li12)
    yi2 = xor(li21, li22)
    yi3 = xor(li31, li32)
    yi4 = xor(li41, li42)
    return yi1+yi2+yi3+yi4


# 加密
def encrypt(text, key):
    text = xor_operation(text, key)  # 第一轮密钥加密
    text = half_byte(text, S)  # 第一轮半字节替换
    text = swap_rows_and_columns(text)  # 第一轮行列交换
    text = row_mix(text)  # 第一轮行变换
    text = xor_operation(text, key_aes(key, char1))  # 第二轮密钥加密
    text = half_byte(text, S)  # 第二轮半字节替换
    text = swap_rows_and_columns(text)  # 第二轮行列交换
    text = xor_operation(text, key_aes(key_aes(key, char1), char2))  # 第三轮密钥加密
    return text


# 解密
def decrypt(text, key):
    text = xor_operation(text, key_aes(key_aes(key, char1), char2))  # 第一轮密钥解密
    text = swap_rows_and_columns(text)  # 第一轮行列交换
    text = half_byte(text, S_inv)  # 第一轮半字节替换
    text = xor_operation(text, key_aes(key, char1))  # 第二轮密钥解密
    text = row_mix_inv(text)  # 第二轮行变换
    text = swap_rows_and_columns(text)  # 第二轮行列交换
    text = half_byte(text, S_inv)  # 第二轮半字节替换
    text = xor_operation(text, key)  # 第三轮密钥解密
    return text


# 双重加密
def double_encrypt(plaintext, key):
    # 拆分32位密钥为两个16位的子密钥
    k1 = key[:16]
    k2 = key[16:]
    # 使用 K1 进行加密
    ciphertext = encrypt(plaintext, k1)
    # 使用 K2 进行解密
    ciphertext = encrypt(ciphertext, k2)
    return ciphertext


def double_decrypt(ciphertext, key):
    # 拆分32位密钥为两个16位的子密钥
    k1 = key[:16]
    k2 = key[16:]
    # 使用 K2 进行解密
    plaintext = decrypt(ciphertext, k2)
    # 使用 K1 进行加密
    plaintext = decrypt(plaintext, k1)
    return plaintext


# 三重加密
def triple_encrypt(plaintext, key):
    # 拆分48位密钥为三个16位的子密钥
    k1 = key[:16]
    k2 = key[16:32]
    k3 = key[32:]
    # 使用 K1 进行加密
    ciphertext = encrypt(plaintext, k1)
    # 使用 K2 进行解密
    ciphertext = decrypt(ciphertext, k2)
    # 使用 K3 进行加密
    ciphertext = encrypt(ciphertext, k3)
    return ciphertext


def triple_decrypt(ciphertext, key):
    # 拆分48位密钥为三个16位的子密钥
    k1 = key[:16]
    k2 = key[16:32]
    k3 = key[32:]
    # 使用 K3 进行解密
    plaintext = decrypt(ciphertext, k3)
    # 使用 K2 进行加密
    plaintext = encrypt(plaintext, k2)
    # 使用 K1 进行解密
    plaintext = decrypt(plaintext, k1)
    return plaintext









