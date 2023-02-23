"""
Name: Kyle Dell
Class: CMSC487
Date: 2/17/2023
Professor: Edward Zieglar
Email: kdell1@umbc.edu
Description: Implentation of S-DES to show how the encryption algorithm works also meant for using with Meet in the Middle Attack
"""

from bitstring import BitArray

class SDES:
    def __init__(self):
        """
            Used for constructing the SDES object
        """
        self.keys = []
        self.cipher = ""
        self.plaintext = ""
        self.iv = ""
        # constants for S functions for going from 4 to 2 bits
        self.S1 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 3, 2]
        ]
        self.S2 = [
            [0, 1, 2, 3],
            [2, 0, 1, 3],
            [3, 0, 1, 0],
            [2, 1, 0, 3]
        ]
    
    def reset(self):
        """
            Resets the variables to be empty
        """
        self.keys = []
        self.cipher = ""
        self.plaintext = ""
        self.iv = ""
    
    def set_plaintext(self, plaintext):
        """
            Set the plaintext for the encryption side of the algorithm
        """
        # verify that the plaintext text is divisible by 2 hex
        if len(plaintext.replace("0x", "")) % 2 == 0:
            self.plaintext = plaintext
        else:
            print("The plaintext must be divisible by 8 bits")

    def set_cipher(self, cipher):
        """
            Set the cipher text for the decryption algorithm
        """
        # verify that the cipher text is divisible by 2 hex
        if len(cipher.replace("0x", "")) % 2 == 0:
            self.cipher = cipher
        else:
            print("The ciphertext must be divisible by 8 bits")

    def set_iv(self, iv):
        if len(iv) == 4:
            self.iv =  iv.replace("0x", "")
        else:
            print("The input is a one byte hex value")
        

    def get_plaintext(self):
        return self.plaintext

    def get_cipher(self):
        return self.cipher

    def get_keys(self):
        return self.keys

    def get_iv(self):
        return self.iv

    def print_plaintext(self):
        print(self.plaintext)

    def print_cipher(self):
        print(self.cipher)

    def print_keys(self):
        print(self.keys)

    def print_iv(self):
        print(self.iv)

    def set_keys(self, keys):
        """
            Set the keys or just single key either do [key], or [key1, key2]
        """
        self.keys = keys

    def run_des_encryption(self):
        """
            Run the single DES encryption algorithm using the key or first key and the plaintext provided
        """
        temp_plaintext = self.plaintext.replace("0x", "")
        # go through and encrypt one byte or two hex at a time
        cipher = "0x"
        for i in range(0, len(temp_plaintext), 2):
            cipher = cipher + self.encrypt(temp_plaintext[i:i+2], self.keys[0])
        self.cipher = cipher

    def run_d_des_encryption(self):
        temp_plaintext = self.plaintext.replace("0x", "")
        # go through and encrypt one byte or two hex at a time
        cipher = ""
        # encrypt first time
        for i in range(0, len(temp_plaintext), 2):
            cipher = cipher + self.encrypt(temp_plaintext[i:i+2], self.keys[0])
        temp_plaintext = cipher
        cipher = "0x"
        # encrypt second time
        for i in range(0, len(temp_plaintext), 2):
            cipher = cipher + self.encrypt(temp_plaintext[i:i+2], self.keys[1])
        self.cipher = cipher
    
    def run_cbc_d_des_encryption(self):
        temp_plaintext = self.plaintext.replace("0x", "")
        # go through and encrypt one byte or two hex at a time
        iv = self.iv
        cipher = ""
        # encrypt first time
        for i in range(0, len(temp_plaintext), 2):
            iv = (BitArray(hex=iv)^BitArray(hex=temp_plaintext[i:i+2])).hex
            iv = self.encrypt(iv, self.keys[0])
            cipher = cipher + iv
            #self.encrypt(iv, self.keys[0])
        temp_plaintext = cipher
        iv = self.iv
        cipher = "0x"
        # encrypt second time
        for i in range(0, len(temp_plaintext), 2):
            iv = (BitArray(hex=iv)^BitArray(hex=temp_plaintext[i:i+2])).hex
            iv = self.encrypt(iv, self.keys[1])
            cipher = cipher + iv
        self.cipher = cipher
        return 0

    
    def encrypt(self, byte, key):
        """
            Runs encrypt on one byte using the key provided
        """
        # get the binary for the hex
        bits = BitArray(hex="0x" + byte).bin
        # get the initial permutation
        init_perm = self.init_perm(bits)
        # get the left and right sides
        left = init_perm[:4]
        right = init_perm[4:]
        # n is the round we are sending the encryption through
        for n in range(4):
            # get the key to xor with
            temp_key = self.ks(n + 1, key)
            # extend the right side and xor it with the 8 bit key
            temp = (BitArray(bin=self.extend(right)) ^ BitArray(bin=temp_key)).bin
            # get the prim from S1 and S2 function
            temp = self.prim(self.fun_s1(temp[:4]) + self.fun_s2(temp[4:]))
            # xor to get the left side 
            left = (BitArray(bin=left) ^ BitArray(bin=temp)).bin
            temp = left
            left = right
            right = temp
        # do the final swap to take from left to right
        temp = left
        left = right
        right = temp
        # do final permutation
        bits = self.init_perm(left + right, IP=False)
        # return the hex for the bits
        return (BitArray(bin=bits).hex).replace("0x", "")

    def run_des_decryption(self):
        """
            Run the single DES encryption algorithm using the key or first key and the plaintext provided
        """
        temp_cipher = self.cipher.replace("0x", "")
        # go through and encrypt one byte or two hex at a time
        plaintext = "0x"
        for i in range(0, len(temp_cipher), 2):
            plaintext = plaintext + self.decrypt(temp_cipher[i:i+2], self.keys[0])
        self.plaintext = plaintext

    def run_d_des_decryption(self):
        temp_cipher = self.cipher.replace("0x", "")
        # go through and encrypt one byte or two hex at a time
        plaintext = ""
        # run decrpyt on second key
        for i in range(0, len(temp_cipher), 2):
            plaintext = plaintext + self.decrypt(temp_cipher[i:i+2], self.keys[1])
        temp_cipher = plaintext
        plaintext = "0x"
        # run decrypt on fisrt key
        for i in range(0, len(temp_cipher), 2):
            plaintext = plaintext + self.decrypt(temp_cipher[i:i+2], self.keys[0])
        self.plaintext = plaintext

    def run_cbc_d_des_decryption(self):
        temp_cipher = self.cipher.replace("0x", "")
        # go through and encrypt one byte or two hex at a time
        plaintext = ""
        # run decrpyt on second key
        for i in range(len(temp_cipher) - 2, -1, -2):
            temp_plaintext = self.decrypt(temp_cipher[i:i+2], self.keys[1])
            if i == 0:
                iv = BitArray(hex=self.iv)
            else:
                iv = BitArray(hex=temp_cipher[i-2:i])
            plaintext = (iv^BitArray(hex=temp_plaintext)).hex + plaintext
        temp_cipher = plaintext
        plaintext = ""
        # run decrypt on fisrt key
        for i in range(len(temp_cipher) - 2, -1, -2):
            temp_plaintext = self.decrypt(temp_cipher[i:i+2], self.keys[0])
            if i == 0:
                iv = BitArray(hex=self.iv)
            else:
                iv = BitArray(hex=temp_cipher[i-2:i])
            plaintext = (iv^BitArray(hex=temp_plaintext)).hex + plaintext
        self.plaintext = "0x" + plaintext
        return 0

    def decrypt(self, byte, key):
        """
            Runs encrypt on one byte using the key provided
        """
        # get the binary for the hex
        bits = BitArray(hex="0x" + byte).bin
        # get the initial permutation
        init_perm = self.init_perm(bits)
        # get the left and right sides
        left = init_perm[:4]
        right = init_perm[4:]
        # n is the round we are sending the encryption through
        for n in range(4):
            # get the key to xor with
            temp_key = self.ks(4 - n, key)
            # extend the right side and xor it with the 8 bit key
            temp = (BitArray(bin=self.extend(right)) ^ BitArray(bin=temp_key)).bin
            # get the prim from S1 and S2 function
            temp = self.prim(self.fun_s1(temp[:4]) + self.fun_s2(temp[4:]))
            # xor to get the left side 
            left = (BitArray(bin=left) ^ BitArray(bin=temp)).bin
            temp = left
            left = right
            right = temp
        # do the final swap to take from left to right
        temp = left
        left = right
        right = temp
        # do final permutation
        bits = self.init_perm(left + right, IP=False)
        # return the hex for the bits
        return (BitArray(bin=bits).hex).replace("0x", "")
    
    def extend(self, bits):
        """
            Extends four bits to eight bits using a set pattern
        """
        return bits[3] + bits[0] + bits[1] + bits[2] + bits[1] + bits[2] + bits[3] + bits[0]
    
    def fun_s1(self, bits):
        """
            Using the row of the first and last bit and the column of the second and third bit get a 2 bit number
        """
        i = int(BitArray(bin=bits[0] + bits[3]).u)
        j = int(BitArray(bin=bits[1] + bits[2]).u)
        return BitArray(uint=self.S1[i][j], length=2).bin

    def fun_s2(self, bits):
        """
            Using the row of the first and last bit and the column of the second and third bit get a 2 bit number
        """
        i = int(BitArray(bin=bits[0] + bits[3]).u)
        j = int(BitArray(bin=bits[1] + bits[2]).u)
        return BitArray(uint=self.S2[i][j], length=2).bin
    
    def ks(self, n, bits):
        """
            Depending on the n, left shift the c, and d a certain amount of times and then do a second permutation on c and d
        """
        c, d = self.perm_choice1(bits)
        if n > 0:
            c = c[1:] + c[0]
            d = d[1:] + d[0]
        if n > 1:
            c = c[2:] + c[:2]
            d = d[2:] + d[:2]
        if n > 2:
            c = c[2:] + c[:2]
            d = d[2:] + d[:2]
        if n > 3:
            c = c[2:] + c[:2]
            d = d[2:] + d[:2]
        return self.perm_choice2(c + d)
    
    def perm_choice1(self, key):
        """
            Split the key into 2 different bit strings while permutating them
        """
        c = key[8] + key[6] + key[1] + key[4] + key[5]
        d = key[0] + key[3] + key[9] + key[7] + key[2]
        return c, d

    def perm_choice2(self, key):
        """
            Permutate the ending into an 8 bit bitstring
        """
        return key[1] + key[6] + key[7] + key[9] + key[0] + key[8] + key[2] + key[3]

    def prim(self, bits):
        """
            Primitive function that rearranges the bits
        """
        return bits[1] + bits[3] + bits[2] + bits[0]
    
    def init_perm(self, bits, IP=True):
        """
            Initial permutation and also the inverse initial permutation
        """
        if IP:
            return bits[1] + bits[5] + bits[2] + bits[0] + bits[3] + bits[7] + bits[4] + bits[6]
        else:
            return bits[3] + bits[0] + bits[2] + bits[4] + bits[6] + bits[1] + bits[7] + bits[5]
    
if __name__ == "__main__":
    s_des = SDES()
    s_des.set_plaintext("0x00")
    s_des.print_plaintext()
    s_des.set_keys(["1010101010", "0101010101"])
    s_des.print_keys()
    s_des.run_des_encryption()
    s_des.print_cipher()
    s_des.set_plaintext("0xtest")
    s_des.print_plaintext()
    s_des.run_des_decryption()
    s_des.print_plaintext()

    s_des.set_plaintext("0x8040201008040201")
    s_des.print_plaintext()
    s_des.run_d_des_encryption()
    s_des.print_cipher()
    s_des.set_plaintext("0xtest")
    s_des.print_plaintext()
    s_des.run_d_des_decryption()
    s_des.print_plaintext()

    s_des.set_iv("0x6a")
    #s_des.run_cbc_d_des_encryption()
    s_des.run_cbc_d_des_encryption()
    s_des.print_cipher()
    s_des.run_cbc_d_des_decryption()
    s_des.print_plaintext()
