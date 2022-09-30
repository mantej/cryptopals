"""
Implement the MT19937 Mersenne Twister RNG
"""

from twister import Twister

twister = Twister()
twister.initialize_generator(12345)
print twister.extract_number()
