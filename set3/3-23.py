"""
Clone an MT19937 RNG from its output
"""

from twister import Twister
import time

# untempers an MT19937 output
def untemper(out):
    out ^= (out >> 18)
    out ^= ((out << 15) & 0xefc60000)
    temp = out
    out = temp ^ ((out << 7) & 0x9d2c5680)
    out = temp ^ ((out << 7) & 0x9d2c5680)
    out = temp ^ ((out << 7) & 0x9d2c5680)
    out = temp ^ ((out << 7) & 0x9d2c5680)
    temp = out
    out = temp ^ (out >> 11)
    out = temp ^ (out >> 11)
    return out

# initialize generator with unix timestamp
timestamp = int(time.time())
twister = Twister()
twister.initialize_generator(timestamp)

# MT19937 state array (untempered values)
state = [0]*624
for i in range(0, 624):
    state[i] = untemper(twister.extract_number())

# clone generator from untempered values
twister_clone = Twister(state)

print twister.extract_number()
print twister_clone.extract_number()
