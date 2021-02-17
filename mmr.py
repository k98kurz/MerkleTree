from nacl.encoding import RawEncoder
from nacl.hash import sha256
from binascii import hexlify
from math import log, ceil, floor
from copy import deepcopy

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

null_node = b''.join(b'\x00' for i in range(32))

class MerkleMountainRange(list):
    def __init__ (self, capacity, hashfunc = lambda data: sha256(data, encoder=RawEncoder)):
        self.capacity = capacity
        self.hashfunc = hashfunc
        # create an appropriate structure of empty nodes, from leaves to root
        pairs = 1
        while pairs > 0:
            pairs = floor(capacity/2)
            remainder = capacity % 2
            t = [null_node for c in range(0, 2**pairs + remainder)] if pairs > 0 else [null_node]
            self.append(t)
            capacity = pairs + remainder

    @classmethod
    def from_leaves (cls, leaves, hashfunc = lambda data: sha256(data, encoder=RawEncoder)):
        tree = cls(len(leaves), hashfunc)
        tree.fill(leaves)
        return tree

    @classmethod
    def from_messages (cls, messages, base = 2, hashfunc = lambda data: sha256(data, encoder=RawEncoder)):
        leaves = [hashfunc(messages[i]) for i in range(len(messages))]
        return cls.from_leaves(leaves, base, hashfunc)

    def calculate_tree(self):
        self.print_hex()
        print()
        # first calculate normal trees
        for i in range(0, len(self)-1):
            remainder = len(self[i]) % 2
            for j in range(0, len(self[i])-remainder, 2):
                combined = b''.join(self[i][j:j+2])
                self[i+1][int(j/2)] = self.hashfunc(combined)
            if remainder is 1:
                self[i+1][-1] = self[i][-1]
        # bag trees into a mountain range
        # log_2(leaves) recursively?
        # trees = [self[0][0:floor(log(len(self[0]))/log(2))]]

    def put(self, leaf, index):
        self[0][index] = leaf
        self.calculate_tree()

    def fill(self, leaves):
        if len(leaves) > self.capacity:
            raise BaseException('too many leaves')
        self[0] = leaves
        self.calculate_tree()

    def print_hex(self):
        for i in range(len(self)-1, -1, -1):
            l = self[i][:]
            for c in range(0, len(l)):
                l[c] = hexlify(l[c])
            print(i, l)

    def prove(self, message):
        hash = self.hashfunc(message)
        index = self[0].index(hash)
        proof = []
        for l in range(0, self.levels-1):
            cohort = int(floor(index/self.base))
            placement = index - cohort*self.base
            round = [self[l][i] for i in range(cohort*self.base, (cohort+1)*self.base)]
            del round[placement]
            round.insert(0, placement)
            index = cohort
            proof.append(round)
        proof.append(self[-1])
        return proof

    @staticmethod
    def print_hex_proof(proof):
        for i in range(0, len(proof)):
            l = proof[i][:]
            for c in range(0, len(l)):
                l[c] = hexlify(l[c]) if isinstance(l[c], bytes) else l[c]
            print(l)

    @staticmethod
    def verify(message, proof, hashfunc = lambda data: sha256(data, encoder=RawEncoder)):
        hash = hashfunc(message)
        working = deepcopy(proof)
        for i in range(len(proof)-1):
            index = proof[i][0]
            del working[i][0]
            working[i].insert(index, hash)
            hash = hashfunc(b''.join(working[i]))

        return hash == proof[-1][0]
