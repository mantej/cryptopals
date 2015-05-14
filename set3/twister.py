"""
Implement the MT19937 Mersenne Twister RNG
"""

MT = [0]*624
index = 0

# Initialize the generator from a seed
def initialize_generator(seed):
    global index
    global MT
    index = 0
    MT[0] = seed & 0xffffffff
    for i in range(1, 624):
        MT[i] = (0x6c078965 * (MT[i-1] ^ (MT[i-1] >> 30)) + i) & 0xffffffff


# Extract a tempered pseudorandom number based on the index-th value,
# calling generate_numbers() every 624 numbers
def extract_number():
    global index
    global MT
    if index == 0:
        generate_numbers()
    y = MT[index]
    y ^= (y >> 11)
    y ^= ((y << 7) & 0x9d2c5680)
    y ^= ((y << 15) & 0xefc60000)
    y ^= (y >> 18)

    index = (index + 1) % 624
    return y


# Generate an array of 624 untempered numbers
def generate_numbers():
    global MT
    for i in range(624):
        y = (MT[i] & 0x80000000) + (MT[(i+1) % 624] & 0x7fffffff)
        MT[i] = MT[(i+397) % 624] ^ (y >> 1)
        if y%2 != 0:
            MT[i] ^= 0x9908b0df