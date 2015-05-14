"""
Implement the MT19937 Mersenne Twister RNG
"""

import twister

twister.initialize_generator(12345)
print twister.extract_number()
