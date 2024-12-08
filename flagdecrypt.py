import os
import concurrent.futures


class Reg:
    def __init__(self, length, mask):
        self.tap = [0, 0]
        self.length = length
        self.value = 0
        i = 0
        for x in range(length):
            if (mask >> x) & 1:
                self.tap[i] = x
                i += 1

    def next(self):
        xor = ((self.value >> self.tap[0]) ^ (self.value >> self.tap[1])) & 1
        self.value = (self.value >> 1) ^ (xor << (self.length - 1))
        return self.value & 1

    def set(self, value):
        self.value = value


def get_encrypted_png():
    with open("flag.enc", "rb") as file:
        return file.read()


def attempt_decrypt(i, j, r1, r2, png, enc, len_enc):
    bytes_data = []  # List for decrypted data
    r1.set(i)
    r2.set(j)

    for level in range(len_enc):
        res = 0
        for k in range(8):
            res += (1 << k) * (r1.next() + r2.next())
        res %= 255
        value = res
        if level < 4 and value ^ enc[level] != png[level]:
            return None  # Decryption failed at this stage
        if level == 3:
            bytes_data.extend(png[:4])
        if level > 3:
            bytes_data.append(value ^ enc[level])

    # If successful decryption
    return bytes_data


def batch_decrypt(start_i, end_i, start_j, end_j, png, enc, len_enc, l1, m1, l2, m2):
    # Create local instances of Reg inside the batch_decrypt function
    r1_local = Reg(l1, m1)
    r2_local = Reg(l2, m2)

    for i in range(start_i, end_i):
        for j in range(start_j, end_j):
            result = attempt_decrypt(i, j, r1_local, r2_local, png, enc, len_enc)
            if result is not None:
                with open("lfsr.png", "wb") as file:
                    file.write(bytes(result))
                print("Decryption successful!")
                return True
    return False


def main():
    png = [0x89, 0x50, 0x4E, 0x47]  # PNG magic bytes
    l1, m1 = 12, 0b10000100000
    l2, m2 = 19, 0b100000100000000
    enc = get_encrypted_png()  # Encrypted data as byte array
    len_enc = len(enc)  # Length of encrypted data

    # Using ThreadPoolExecutor to parallelize the search
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:  # Limit the number of threads
        futures = []
        batch_size = 100  # Adjust based on available resources
        for i in range(0, 1 << l1, batch_size):
            for j in range(0, 1 << l2, batch_size):
                futures.append(
                    executor.submit(batch_decrypt, i, min(i + batch_size, 1 << l1), j, min(j + batch_size, 1 << l2),
                                    png, enc, len_enc, l1, m1, l2, m2))

        for future in concurrent.futures.as_completed(futures):
            if future.result():
                break


if __name__ == "__main__":
    main()
