import timeit
import unittest
import shutil
import os
import string
import random
import cProfile

shutil.copy("../aes.py", "./aes.py")
import aes
os.remove("./aes.py")

def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    print("Random string of length", length, "is:", result_str)

class TestAES(unittest.TestCase):
    def test_encryption(self):
        encoding = "utf-8"
        key = (
            "thisisjustarandomstring",
            "djaw412$)J!@)sAWF#",
            "24917209"
        )

        message = "Hello, world!"

        with open("test.jpg", 'rb') as f:
            binary = f.read()

        print("\n[TEST] Encrypting `{0}` with key #1 (length {1})".format(message, len(key[0])))
        aes.AES256(key[0], encoding).encrypt(message)

        print("[TEST] Encrypting `{0}` with key #2 (length {1})".format(message, len(key[1])))
        aes.AES256(key[1], encoding).encrypt(message)

        print("[TEST] Encrypting `{0}` with key #3 (length {1})".format(message, len(key[2])))
        aes.AES256(key[2], encoding).encrypt(message)

    def test_decryption(self):
        encoding = "utf-8"
        key = (
            "thisisjustarandomstring",
            "djaw412$)J!@)sAWF#",
            "24917209"
        )

        message = "Hello, world!"

        message_results = (
            b'JoFMbUq9p1NvSUhqKTZQ2SgyEZnBJEDmubY3ovrx8JI=',
            b'3dukAu56w4WvaIZBqsg/pVxypRRiLHK7AV9bGT+dBvo=',
            b'wIr5brdZqhzHHZTjqHvVChZ4hW9QIQgqHO6nfj0Igis='
        )

        with open("test.jpg", 'rb') as f:
            binary = f.read()

        print("\n[TEST] Decrypting `{0}` with key #1 (length {1})".format(message, len(key[0])))
        assert aes.AES256(key[0], encoding).decrypt(message_results[0]) == message

        print("[TEST] Decrypting `{0}` with key #2 (length {1})".format(message, len(key[1])))
        assert aes.AES256(key[1], encoding).decrypt(message_results[1]) == message

        print("[TEST] Decrypting `{0}` with key #3 (length {1})".format(message, len(key[2])))
        assert aes.AES256(key[2], encoding).decrypt(message_results[2]) == message

    def test_encryption_time(self):
        print("\n[TEST] Testing AES-256 encryption speed...\n")
        cProfile.run("aes.AES256('password').encrypt('Hello, world!')")
        results = timeit.timeit("aes.AES256('password').encrypt('Hello, world!')", setup="import aes", number=100)
        print()
        """
        round = 0
        average = 0
        while round < len(results):
            print("+ Call #{0}: {1}".format((round + 1), results[round]))
            average += results[round]
            round += 1

        average = average / len(results)
        print("\nAverage: ".format(average))
        """
        print("Average Run Time: " + str(results))

if __name__ == "__main__":
    unittest.main()