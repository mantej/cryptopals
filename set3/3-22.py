"""
Crack an MT19937 seed
"""

import twister

# Given the first 32 bit output, returns the seed value
def reverse_twister(out):
	out ^= (out >> 18)
	out ^= ((out << 15) & 0xefc60000)
	out ^= ((out << 7) & 0x9d2c5680)
	out ^= (out >> 11)
	return out

twister.initialize_generator(12345)
first_32bit_output = twister.extract_number()
print reverse_twister(first_32bit_output)