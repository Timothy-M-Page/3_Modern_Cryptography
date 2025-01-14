"""
A hash function maps input data to unique fixed-size outputs, typically 
represented as hex strings. This allows data to be stored efficiently and
data integrity to be checked easily.
 
Hash functions satisfy the following properties:

1. Injective/Deterministic: The same input will always produce the same output.

2. Fixed Size: Independent of input size, the output has a fixed length.

3. Efficient: A good hash function computes the hash quickly for any input.

4. Pre-image Resistance: It is difficult to deduce the inverse function.

5. Collision Resistance: It’s rare for different inputs to give the same hash.

6. Uniform Distribution: Distribute output values evenly across the hash space.


Below the sha256 function from the sha2 family is implemented without the use
of packages.
"""


def sigma_0(x: str) -> str:
    # xor sum of right-rotates and right-shifts
    y1 = x[-7:] + x[:-7]
    y2 = x[-18:] + x[:-18]
    y3 = '0' * 3 + x[:-3]
    z1 = xor_32_str(y1, y2)
    z2 = xor_32_str(z1, y3)
    return z2


def sigma_1(x: str) -> str:
    # xor sum of right-rotates and right-shifts
    y1 = x[-17:] + x[:-17]
    y2 = x[-19:] + x[:-19]
    y3 = '0' * 10 + x[:-10]
    z1 = xor_32_str(y1, y2)
    z2 = xor_32_str(z1, y3)
    return z2


def new_word(schedule: list[str]) -> str:
    """
    New words of the message schedule formed as a sum of previous
    words and sigma functions, given the first 16 words of a block.
    """
    a = int(sigma_0(schedule[-15]), 2)
    b = int(schedule[-7], 2)
    c = int(sigma_1(schedule[-2]), 2)
    d = int(schedule[-16], 2)
    return f'{(a + b + c + d) % (2 ** 32):032b}'


# K_values used in the 64 rounds of the compression step
# values based on the cube roots of the first 64 primes.
K_values = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


def xor_32_str(x: str, y: str) -> str:
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(x, y))


def xor_32_int(x: int, y: int) -> int:
    return int(bin(x ^ y)[2:].zfill(32), 2)


def and_32(x: int, y: int) -> int:
    result = x & y
    return int(bin(result)[2:].zfill(32), 2)


def not_32(x: int) -> int:
    # Inverting the bits in a 32 bit string is equivalent to (2**32 - 1) - x.
    return 2**32 - 1 - x


def sum_0(x: int) -> int:
    # xor sum of right-rotates.
    x = format(x, '032b')
    y1 = x[-2:] + x[:-2]
    y2 = x[-13:] + x[:-13]
    y3 = x[-22:] + x[:-22]
    z1 = xor_32_str(y1, y2)
    z2 = xor_32_str(z1, y3)
    return int(z2, 2)


def sum_1(x: int) -> int:
    # xor sum of right-rotates.
    x = format(x, '032b')
    y1 = x[-6:] + x[:-6]
    y2 = x[-11:] + x[:-11]
    y3 = x[-25:] + x[:-25]
    z1 = xor_32_str(y1, y2)
    z2 = xor_32_str(z1, y3)
    return int(z2, 2)


def ch(x: int, y: int, z: int) -> int:
    # New string, i-th positions of x tells which i-th of y or z to choose.
    return xor_32_int(and_32(x, y), (and_32(not_32(x), z)))


def maj(x: int, y: int, z: int) -> int:
    # New string, i-th entry is the majority bit in the i-th place of x y and z
    a = and_32(x, y)
    b = and_32(x, z)
    c = and_32(y, z)
    d = xor_32_int(a, b)
    e = xor_32_int(d, c)
    return e


def sha_256(message: str):

    try:
        if not isinstance(message, str):
            raise TypeError("Input must be a string.")

        # Eight initial values based of square roots of first 8 primes.
        h0 = 0x6a09e667
        h1 = 0xbb67ae85
        h2 = 0x3c6ef372
        h3 = 0xa54ff53a
        h4 = 0x510e527f
        h5 = 0x9b05688c
        h6 = 0x1f83d9ab
        h7 = 0x5be0cd19

        bin_string = ''.join(format(ord(char), '08b') for char in message)

        length = len(bin_string)

        length_64bit = format(length, '064b')

        bin_string += '1'

        length_mod = len(bin_string) % 512

        if length_mod < 448:
            zeros = 512 - 64 - length_mod
            bin_string += '0' * zeros + length_64bit
        if length_mod >= 448:
            zeros = 1024 - 64 - length_mod
            bin_string += '0' * zeros + length_64bit

        blocks = [bin_string[i:i+512] for i in range(0, len(bin_string), 512)]

        for block in blocks:

            a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

            message_schedule = [block[i:i + 32] for i
                                in range(0, len(block), 32)]

            for i in range(16, 64):
                message_schedule.append(new_word(message_schedule))

            message_schedule = [int(b, 2) for b in message_schedule]

            for i in range(64):

                temp1 = (h + sum_1(e) + ch(e, f, g) + K_values[i]
                         + message_schedule[i]) % 2**32

                temp2 = (sum_0(a) + maj(a, b, c)) % 2**32

                h = g % 2**32
                g = f % 2**32
                f = e % 2**32
                e = (d + temp1) % 2**32
                d = c % 2**32
                c = b % 2**32
                b = a % 2**32
                a = (temp1 + temp2) % 2**32

            h0 += a % 2**32
            h1 += b % 2**32
            h2 += c % 2**32
            h3 += d % 2**32
            h4 += e % 2**32
            h5 += f % 2**32
            h6 += g % 2**32
            h7 += h % 2**32

        final_h_values = [h0, h1, h2, h3, h4, h5, h6, h7]
        h_values_mod = [h % (2 ** 32) for h in final_h_values]
        hex_values = [hex(num) for num in h_values_mod]
        filled_hex_values = [f"0x{value[2:].zfill(8)}" for value in hex_values]

        return ''.join(value[2:] for value in filled_hex_values)

    except TypeError as e:
        print(f"Error: {e}")
        return None  # Gracefully handle the error by returning None


