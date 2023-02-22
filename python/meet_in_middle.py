"""
Name: Kyle Dell
Class: CMSC487
Date: 2/17/2023
Professor: Edward Zieglar
Email: kdell1@umbc.edu
Description: Implentation of Meet in the Middle Attack by using SDES
"""

from sdes import SDES
from bitstring import BitArray

if __name__ == "__main__":
    # given plaintext and cipher texts to find intermediate values for
    plaintext = ["0x42", "0x72", "0x75", "0x74", "0x65"]
    cipher = ["0x11", "0x6d", "0xfa", "0xa9", "0x34"]
    # dictionary to hold all the encryption keys for teach intermediary values
    encrypt_dic_list = [{}, {}, {}, {}, {}]
    possible_keys = [[], [], [], [], []]
    for i in range(len(plaintext)):
        for k in range(1024):
            key = BitArray(uint=k, length=10)
            s_des = SDES()
            s_des.set_plaintext(plaintext[i])
            s_des.set_keys([key.bin])
            s_des.run_des_encryption()
            temp_cipher = s_des.get_cipher()
            if temp_cipher in encrypt_dic_list[i]:
                encrypt_dic_list[i][temp_cipher].append(key.bin)
            else:
                encrypt_dic_list[i][temp_cipher] = [key.bin]

        for k in range(1024):
            key = BitArray(uint=k, length=10)
            s_des = SDES()
            s_des.set_cipher(cipher[i])
            s_des.set_keys([key.bin])
            s_des.run_des_decryption()
            temp_plaintext = s_des.get_plaintext()
            if temp_plaintext in encrypt_dic_list[i]:
                for j in encrypt_dic_list[i][temp_plaintext]:
                    possible_keys[i].append([j, key.bin])
        
    true_keys = []
    for i in possible_keys:
        for k in i:
            in_all = True
            for j in possible_keys:
                if k not in j:
                    in_all = False
            if in_all and k not in true_keys:
                true_keys.append(k)
    print(true_keys)


            
    
