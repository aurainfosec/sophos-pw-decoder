#!/usr/bin/env python

import base64
import binascii
import hashlib
import sys


def warn(msg):
    print >>sys.stderr, 'Warning: ' + msg

def err(msg):
    print >>sys.stderr, 'ERROR: ' + msg
    sys.exit(1)


try:
    import pyDes
except ImportError:
    err('pyDes not found')


# This magic data is XOR'd with 0xA3 in ObfuscationUtil.exe
# (https://www.sophos.com/en-us/support/knowledgebase/13094.aspx)
MAGIC = (
    '\x56\x44\xb2\x62\x91\x12\xc5\xfa\xcf\xd1\x59\x23\xe8\xf0\x97\x49'
    '\x3b\x73\x45\x5e\xae\x61\x34\x54\x48\x5b\xc6\x1f\x78\x5f\x00\x08'
    '\xb3\x40\xfc\x34\xe0\x5a\xd9\x8b\x71\xae\xd7\x0d\xab\x3e\x97\xc9'
)
assert len(MAGIC) == 0x30


if len(sys.argv) < 1 + 1:
    err('Usage: %s <base64-encoded-string>' % sys.argv[0])

try:
    s = base64.decodestring(sys.argv[1])
except binascii.Error:
    err("Couldn't decode input string as base64")

if len(s) < 10:
    err('Input string too short')

if s[0] != '\x07':
    warn("Unknown password version? Probably can't decode, but will try "
         "anyway")
if s[1] != '\x08':
    warn("Unexpected magic second byte? Probably can't decode, but will "
         "try anyway")

salt = s[2 : 2 + 8]
val = s[2 + 8 :]

if len(val) % 8:
    warn("Your input string appears to be truncated. Probably can't "
         "decode, but will try anyway")

md5s = ['']
for i in range((0x18 + 8 + 15) / 16):
    md5s.append(hashlib.md5(''.join([md5s[-1], MAGIC, salt])).digest())
md5str = ''.join(md5s)

decoded = pyDes.triple_des(md5str[:0x18], pyDes.CBC, md5str[0x18 : 0x18 + 8],
                           padmode=pyDes.PAD_PKCS5).decrypt(val)

print 'Decoded password: %s (%s)' % (decoded, ' '.join('%02x' % ord(c)
                                                       for c in decoded))
