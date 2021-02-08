from merkle import MerkleTree
from nacl.encoding import RawEncoder
from nacl.hash import sha256
from binascii import hexlify
from random import randint

'''
    Copyright (c) 2021 Jonathan Voss

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
    SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
    OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
    CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''

messages = [b'hello world', b'world hello', b'BTC', b'ETH', b'XLM', b'RawEncoder', b'encoder', b'sha256']
# messages = messages[0:-1]
# messages = messages[0:-4]
# messages = messages[0:-randint(1, 5)]
leaves = [sha256(messages[i], encoder=RawEncoder) for i in range(len(messages))]

print("Messages: ", messages)
print()

print("MerkleTree:")
m = MerkleTree.from_leaves(leaves) # base=2
# m = MerkleTree.from_messages(messages) # base=2
# m = MerkleTree.from_leaves(leaves, 3) # base=3
# m = MerkleTree.from_messages(messages, 5) # base=5
m.print_hex()
print()

index = randint(0, len(messages)-1)
print("Proof that message ", messages[index], "(", str(hexlify(leaves[index])), ") is part of the tree:")
proof = m.prove(messages[index])
MerkleTree.print_hex_proof(proof)
print()

print("Proof verified" if MerkleTree.verify(messages[index], proof) else "Proof failed verification")
