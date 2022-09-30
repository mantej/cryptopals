"""
Break HMAC-SHA1 with a slightly less artificial timing leak
"""

import requests
import time
import sys

hex_values = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]

def timing_leak_attack():
    sig = "0000000000000000000000000000000000000000"
    for i in range(40):
        longest_time = 0
        for h in hex_values:
            s = sig[:i]+h+sig[i+1:]
            start = time.time()
            for x in range(500):
                r = requests.get('http://localhost:8081/test?file='+sys.argv[1]+'&signature='+s)
            t = time.time()-start
            if t > longest_time:
                longest_time = t
                sig = s
        print sig


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "[*] Usage: python 4-31.py filename"
        exit(0)
    timing_leak_attack()
