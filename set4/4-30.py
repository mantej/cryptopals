"""
Break an MD4 keyed MAC using length extension
"""

from md4 import authMD4
from random import randint
import binascii
import os

print authMD4("a", "bc")
