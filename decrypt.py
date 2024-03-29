#!/opt/anaconda3/bin/python3

import hashlib
from Crypto.Cipher import AES
import random
import sys
import getpass
from argparse import ArgumentParser
from collections import defaultdict

argparser = ArgumentParser()
argparser.add_argument('-i', '--input', metavar='filename', required=True, help="input filename")
argparser.add_argument('-o', '--output', metavar='filename', help="output filename or '-' for standard output")
argparser.add_argument('-c', '--check', metavar='src',
                       help='check whether encryption completed correctly')
argparser.add_argument('-z', '--zenkaku', action='store_true', help="use two-byte characters for answers")
args = argparser.parse_args()

input_file = args.input
output_file = args.output
src_file = args.check

def read_number(f, blen):
    return int.from_bytes(f.read(blen), "little")

def read_short(f):
    return read_number(f, 2)

def read_int(f):
    return read_number(f, 4) 

def read_str(f, strlen):
    return f.read(strlen).decode("utf-8")

def get_answer():
    if args.zenkaku:
        print("> ", end="")
        return input()
    else:
        return getpass.getpass("> ")

def ctz(b):
    cnt = 0
    while b != 0 and (b & 1) == 0:
        cnt += 1
        b >>= 1
    return cnt

def hash(b):
    return int(hashlib.sha3_256(b).hexdigest(), 16)

def comb(n, r):
    c = 1
    if n-r < r:
        r = n-r
    for i in range(r):
        c *= n-i
    for i in range(r):
        c //= r-i
    return c

with open(input_file, mode='rb') as f:
    signature = f.read(4).decode("ASCII")
    if signature != "MSQH":
        print("Not supported")
        exit()

    major_version = read_short(f)
    minor_version = read_short(f)
    n = read_short(f)
    m = read_short(f)

    nCm = comb(n, m)

    keys_hashed = []
    for i in range(nCm):
        keys_hashed.append(read_number(f, 32))

    iv = f.read(16)

    head_hashed = read_number(f, 32)

    len_raw = read_int(f)

    L1, L2, L3 = read_short(f), read_short(f), read_short(f)

    L4 = []
    for i in range(n):
        L4.append(read_short(f))

    L5 = read_int(f)

    hash_description = read_str(f, L1)
    enc_description = read_str(f, L2)
    file_basename = read_str(f, L3)

    questions = []
    for i in range(n):
        questions.append(read_str(f, L4[i]))

    data_encrypted = f.read(L5)

    print(f"version: {major_version}.{minor_version}")
    print(f"hash function: {hash_description}")
    print(f"encryption: {enc_description}")
    print()

    answers = [""] * n
    answers_hashed = [0] * n

for i in range(n):
    print(questions[i])
    answers[i] = get_answer()

for i in range(n):
    a = hashlib.sha3_256(answers[i].encode('utf-8'))
    a = int(a.hexdigest(), 16)
    answers_hashed[i] = a

keys = defaultdict(int)
sets = defaultdict(list)

# サイズ m の集合を昇順に列挙する
khi = 0
BM = 1<<m
BN = 1<<n
b = BM - 1
while b < BN:

    xor = keys_hashed[khi]
    for i in range(n):
        if ((b >> i) & 1) == 1:
            xor ^= answers_hashed[i]

    keys[xor] += 1
    sets[xor].append(b)

    khi += 1
    t = b | (b - 1)
    b = (t+1) | (((~t & -~t) - 1) >> (ctz(b) + 1))

keys = sorted(keys.items(), key=lambda kv:kv[1], reverse=True)
data_decrypted = None
key = None

for k, cnt in keys:
    # すべての候補について先頭のみ復号し、合っていればすべてを復号する
    key_bytes = k.to_bytes(32, "little")
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    head_decrypted = cipher.decrypt(data_encrypted[0:16])

    if hash(head_decrypted) == head_hashed:
        key = k
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        data_decrypted = cipher.decrypt(data_encrypted)
        break

if data_decrypted == None:
    print("復号できませんでした。")
    exit(0)

# 最後がパディングされている場合は取り除く
data_decrypted = data_decrypted[0:len_raw]

if src_file != None:

    hashOut = hash(data_decrypted)
    with open(src_file, "rb") as f:
        hashSrc = hash(f.read())

    if hashOut == hashSrc:

        is_correct = [False] * n
        for s in sets[key]:
            for i in range(n):
                if ((s >> i) & 1) == 1:
                    is_correct[i] = True
        c = is_correct.count(True)

        print(f"復号可能です({n}問中{c}問正解)。")

        for i in range(n):
            print("o" if is_correct[i] else "x", end="")
        print()

    else:
        print("一部復号できませんでした。")

elif output_file == "-":

    print(data_decrypted.decode("utf-8"))

else:

    if output_file == None:
        output_file = "[decrypted]" + file_basename

    with open(output_file, "wb") as f:
        f.write(data_decrypted)

    print("復号が完了しました。")
