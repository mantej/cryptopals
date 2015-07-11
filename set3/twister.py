"""
Implement the MT19937 Mersenne Twister RNG
"""

class Twister:
    # accepts an optional state arguement if you'd like to clone the
    # state of a generator (untempered values)
    def __init__(self, state=[0]*624):
        self.MT = state
        self.index = 0


    # Initialize the generator from a seed
    def initialize_generator(self, seed):
        self.index = 0
        self.MT[0] = seed & 0xffffffff
        for i in range(1, 624):
            self.MT[i] = (0x6c078965 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i) & 0xffffffff


    # Extract a tempered pseudorandom number based on the index-th value,
    # calling generate_numbers() every 624 numbers
    def extract_number(self):
        if self.index == 0:
            self.generate_numbers()
        y = self.MT[self.index]
        y ^= (y >> 11)
        y ^= ((y << 7) & 0x9d2c5680)
        y ^= ((y << 15) & 0xefc60000)
        y ^= (y >> 18)

        self.index = (self.index + 1) % 624
        return y


    # Generate an array of 624 untempered numbers
    def generate_numbers(self):
        for i in range(624):
            y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % 624] & 0x7fffffff)
            self.MT[i] = self.MT[(i+397) % 624] ^ (y >> 1)
            if y%2 != 0:
                self.MT[i] ^= 0x9908b0df
