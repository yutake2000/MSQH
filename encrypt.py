import hashlib
from Crypto.Cipher import AES
import random
import sys
import os
import getpass
from argparse import ArgumentParser

major_version = 1
minor_version = 0
hash_description = "SHA3-256"
enc_description = "AES-256"

argparser = ArgumentParser()
argparser.add_argument('-i', '--input', metavar='filename', required=True, help="input filename")
argparser.add_argument('-o', '--output', metavar='filename', required=True, help="output filename")
args = argparser.parse_args()

input_file = args.input
input_file_basename = os.path.basename(input_file)
output_file = args.output

def confirm(question):
    print(question)
    print("> ", end="")

def write_number(f, val, blen):
    f.write(val.to_bytes(blen, "little"))

def write_short(f, val):
    write_number(f, val, 2)

def write_int(f, val):
    write_number(f, val, 4)

def write_str_len(f, s):
    s = s.encode("utf-8")
    write_short(f, len(s))

def write_str(f, s):
    s = s.encode("utf-8")
    f.write(s)

def ctz(b):
    cnt = 0
    while b != 0 and (b & 1) == 0:
        cnt += 1
        b >>= 1
    return cnt

def hash(b):
    return int(hashlib.sha3_256(b).hexdigest(), 16)

questions = []
while True:
    confirm("質問を入力してください。質問を追加しない場合はそのままEnterを押してください。")
    q = input()
    if q == "":
        break
    questions.append(q)

n = len(questions)
answers = [None] * n

print("答えを入力してください。")

for i in range(n):
    print(questions[i])
    answers[i] = getpass.getpass("> ")

print("それぞれもう一度答えを入力してください。")

for i in range(n):
    print(questions[i])
    ans = getpass.getpass("> ")
    if ans != answers[i]:
        print("1回目の答えと異なります。もう一度入力してください。")
        ans2 = getpass.getpass("> ")
        if ans2 == answers[i]:
            print("一致しました。")
        else:
            if ans2 == ans:
                answers[i] = ans2
                print("答えを更新しました。")
            else:
                print("答えが一致しませんでした。もう一度最初からお試しください。")
                exit()

confirm(f"{n}個の質問を登録しました。何問正解で復号可能にしますか？")
m = int(input())

# 答えをハッシュ値に変換
answers_hashed = []
for ans in answers:
    a = hashlib.sha3_256(ans.encode('utf-8'))
    a = int(a.hexdigest(), 16)
    answers_hashed.append(a)

# 暗号鍵を生成
key = random.randint(0, 1<<256)

# 暗号鍵とハッシュ値のハッシュ値の排他的論理和を計算  
keys_hashed = []

# サイズ m の集合を昇順に列挙する
BM = 1<<m
BN = 1<<n
b = BM - 1
while b < BN:

    xor = key
    for i in range(n):
        if ((b >> i) & 1) == 1:
            xor ^= answers_hashed[i]

    keys_hashed.append(xor)

    t = b | (b - 1)
    b = (t+1) | (((~t & -~t) - 1) >> (ctz(b) + 1))

# 入力ファイルの読み込み
with open(input_file, mode="rb") as f:
    data_raw = f.read()

# 暗号化の準備
key_bytes = key.to_bytes(32, "little")
iv = random.randint(0, 1<<128).to_bytes(16, "little")
cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
len_raw = len(data_raw)

# データサイズを 16 の倍数にして暗号化する
if len_raw % 16 != 0:
    data_raw += int().to_bytes(16 - len_raw % 16, "little")
data_encrypted = cipher.encrypt(data_raw)
len_encrypted = len(data_encrypted)

# 出力ファイルへの書き込み
with open(output_file, mode='wb') as f:

    # ファイルシグネチャ
    f.write(b"MSQH")

    # バージョン
    write_short(f, major_version)
    write_short(f, minor_version)

    # n, m
    write_short(f, n)
    write_short(f, m)

    # 鍵
    for k in keys_hashed:
        write_number(f, k, 32)

    # 初期ベクトル
    f.write(iv) 

    # 先頭 16 バイトのハッシュ値
    write_number(f, hash(data_raw[0:16]), 32)

    # 元のデータサイズ
    write_int(f, len_raw)

    # 文字数
    write_str_len(f, hash_description)
    write_str_len(f, enc_description)
    write_str_len(f, input_file_basename)

    # 質問の文字数
    for q in questions:
        write_str_len(f, q)

    # パディング後のファイルサイズ
    write_int(f, len_encrypted)

    # ハッシュ化・暗号化の情報
    write_str(f, hash_description)
    write_str(f, enc_description)

    # ファイル名
    write_str(f, input_file_basename)

    # 質問
    for q in questions:
        write_str(f, q)

    # 暗号化データ
    f.write(data_encrypted)

