# 定义一个二维列表S，表示AES算法中的S盒
S = [[9, 4, 10, 11],
     [13, 1, 8, 5],
     [6, 2, 0, 3],
     [12, 14, 15, 7]]

# 定义两个字符串变量char1和char2
char1 = "10000000"
char2 = "00110000"

# 定义一个异或函数，用于比较两个字符串的每个对应位置的字符，并返回一个新的字符串
def xor(x, y):
    len1 = len(x)
    len2 = len(y)
    z = ""
    if len2 == len1:
        i = 0
        while i < len1:
            if x[i] != y[i]:
                z = z + "1"
            else:
                z = z + "0"
            i = i + 1
    return z

# 定义一个函数，将二进制字符串转换为十进制数
def to_decimal(x):
    i = len(x)
    j = 0
    y = 0
    while i > 0:
        y = y + int(x[i - 1]) * 2 ** j
        i = i - 1
        j = j + 1
    return y

# 定义一个函数，将十进制数转换为4位的二进制字符串
def to_binary_4(x):
    y = ""
    while 1:
        y = str(int(x) % 2) + y
        x = int(x) // 2
        if x == 0:
            y = str("{:04d}".format(int(y)))
            break
    return y

# 定义一个函数，用于AES密钥扩展
def g_aes(you, char):
    # 将输入的字符串分为两部分
    you1 = you[:4]
    you2 = you[4:]
    # 交换两部分的位置
    you1, you2 = you2, you1
    # 将每个部分转换为对应的十进制数
    you11 = to_decimal(you1[0] + you1[1])
    you12 = to_decimal(you1[2] + you1[3])
    you21 = to_decimal(you2[0] + you2[1])
    you22 = to_decimal(you2[2] + you2[3])
    # 从S盒中选择对应的零件，并转换为二进制字符串
    s1 = to_binary_4(S[you11][you12])
    s2 = to_binary_4(S[you21][you22])
    s = s1 + s2
    # 将选择的零件与输入的char字符串进行异或操作
    char_co = xor(s, char)
    return char_co

# 定义一个函数，根据前一个密钥和轮常数生成下一个密钥
def key_aes(key, char):
    # 将输入的字符串分为两部分
    key1 = key[:8]
    key2 = key[8:]
    # 使用g_aes函数处理每个部分，并得到新的零件（引擎部分）
    key1_2 = g_aes(key2, char)
    key01 = xor(key1, key1_2)
    key02 = xor(key2, key01)
    # 将新的零件组合在一起，得到下一个密钥
    key = key01 + key02
    return key
