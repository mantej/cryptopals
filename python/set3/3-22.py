"""
Crack an MT19937 seed
"""

from twister import Twister
import time
import random

# key = first 32-bit output
# value = seed (timestamp)
seeds = {}

def crack_seed(output):
	current_timestamp = int(time.time())
	for i in range(current_timestamp-2001, current_timestamp):
		twister.initialize_generator(i)
		out = twister.extract_number()
		seeds[out] = i
	print "Guessed seed:", seeds[output]

time.sleep(random.randint(40, 1000))

timestamp = int(time.time())
print "Actual seed: ", timestamp

time.sleep(random.randint(40, 1000))

twister = Twister()
twister.initialize_generator(timestamp)
first_32bit_output = twister.extract_number()
crack_seed(first_32bit_output)
