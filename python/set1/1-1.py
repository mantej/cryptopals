"""
Convert hex to base64
"""

hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
base64_string = hex_string.decode('hex').encode('base64')

print base64_string

print base64_string.decode('base64').encode('hex')