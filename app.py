from flask import Flask, render_template, request
from saes import encrypt, decrypt, double_encrypt, double_decrypt, triple_encrypt, triple_decrypt
from middle_meet_attack import meet_in_the_middle_attack
from cbc import cbc_encrypt, cbc_decrypt


app = Flask(__name__)


def pad_data(data):
    pad_length = 0
    if len(data) % 16 != 0:
        pad_length = 16 - (len(data) % 16)

    if pad_length > 0:
        if pad_length % 2 != 0:
            data += "\x01" * pad_length
        else:
            data += "\x02" * pad_length

    return data


def unpad_data(data):
    last_byte = data[-1:]
    pad_length = 0

    if last_byte == "\x01":
        pad_length = 1
    elif last_byte == "\x02" * 2:
        pad_length = 2

    if pad_length > 0:
        data = data[:-pad_length]

    return data.rstrip("\x01\x02")


def determine_encryption_mode(key):
    key_length = len(key)
    if key_length == 16:
        return "single"
    elif key_length == 32:
        return "double"
    elif key_length == 48:
        return "triple"
    else:
        return "invalid"


def encrypt_decrypt():
    input_text = request.form['input']
    key = request.form['key']
    mode = request.form['mode']
    input_type = request.form['input_type']
    output_text = ""

    encryption_mode = determine_encryption_mode(key)

    if encryption_mode == "invalid":
        return render_template('index.html', error_message="Invalid key length.")

    if input_type == "Binary":
        input_data = input_text
        if mode == "Encrypt":
            if encryption_mode == "single":
                result = encrypt(input_data, key)
            elif encryption_mode == "double":
                result = double_encrypt(input_data, key)
            elif encryption_mode == "triple":
                result = triple_encrypt(input_data, key)
        else:
            if encryption_mode == "single":
                result = decrypt(input_data, key)
            elif encryption_mode == "double":
                result = double_decrypt(input_data, key)
            elif encryption_mode == "triple":
                result = triple_decrypt(input_data, key)
        output_text = result
    elif input_type == "ASCII":
        binary_text = ''.join(format(ord(char), '08b') for char in input_text)
        binary_text = pad_data(binary_text)
        for i in range(0, len(binary_text), 16):
            binary_group = binary_text[i:i + 16]
            if mode == "Encrypt":
                if encryption_mode == "single":
                    result = encrypt(binary_group, key)
                elif encryption_mode == "double":
                    result = double_encrypt(binary_group, key)
                elif encryption_mode == "triple":
                    result = triple_encrypt(binary_group, key)
            else:
                if encryption_mode == "single":
                    result = decrypt(binary_group, key)
                elif encryption_mode == "double":
                    result = double_decrypt(binary_group, key)
                elif encryption_mode == "triple":
                    result = triple_decrypt(binary_group, key)
            output_text += result
        output_text = "".join([chr(int(output_text[i:i + 8], 2)) for i in range(0, len(output_text), 8)])
        output_text = unpad_data(output_text)
    else:
        return render_template('index.html', error_message="Invalid input type.")

    return render_template('index.html', input_text=input_text, key=key, mode=mode,
                           input_type=input_type, output_text=output_text)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        return encrypt_decrypt()

    return render_template('index.html')


@app.route('/middle_attack', methods=['GET', 'POST'])
def middle_attack():
    potential_keys = None
    time_taken = None
    known_plain_texts = ''
    known_ciphers = ''

    if request.method == 'POST':
        known_plain_texts = request.form.get('known_plain_texts')
        known_ciphers = request.form.get('known_ciphers')

        # Split the input into separate known plaintexts and ciphertexts
        plain_texts_list = known_plain_texts.split(',')
        cipher_texts_list = known_ciphers.split(',')

        # Form pairs from input
        pairs = []
        for i in range(min(len(plain_texts_list), len(cipher_texts_list))):
            pairs.append((plain_texts_list[i], cipher_texts_list[i]))

        # Perform meet-in-the-middle attack
        potential_keys, time_taken = meet_in_the_middle_attack(pairs)

    return render_template('middle_attack.html', potential_keys=potential_keys, time_taken=time_taken,
                           known_plain_texts=known_plain_texts, known_ciphers=known_ciphers)


@app.route('/cbc', methods=['GET', 'POST'])
def cbc():
    if request.method == 'POST':
        # 获取表单数据
        input_text = request.form['input']
        key = request.form['key']
        iv = request.form['iv']
        mode = request.form['mode']
        input_type = request.form['input_type']
        output_text = ""

        if input_type == "Binary":
            input_data = input_text
            # 根据模式选择加密或解密
            if mode == "Encrypt":
                result = cbc_encrypt(input_data, iv, key)
            else:
                result = cbc_decrypt(input_data, iv, key)
            output_text = result
        elif input_type == "ASCII":
            # 将 ASCII 转换为二进制
            binary_text = ''.join(format(ord(char), '08b') for char in input_text)
            # 填充数据
            binary_text = pad_data(binary_text)
            for i in range(0, len(binary_text), 16):
                binary_group = binary_text[i:i + 16]
                # 根据模式选择加密或解密
                if mode == "Encrypt":
                    result = cbc_encrypt(binary_group, iv, key)
                else:
                    result = cbc_decrypt(binary_group, iv, key)
                output_text += result
            # 将二进制转换回 ASCII
            output_text = "".join([chr(int(output_text[i:i + 8], 2)) for i in range(0, len(output_text), 8)])
            output_text = unpad_data(output_text)
        else:
            return render_template('cbc.html', error_message="Invalid input type")

        return render_template('cbc.html', input_text=input_text, key=key, iv=iv, mode=mode,
                               input_type=input_type, output_text=output_text)

    # GET 请求时渲染页面
    return render_template('cbc.html')


if __name__ == '__main__':
    app.run()
