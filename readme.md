# About

This is a basic, simple implementation of the Merkle Tree with flexible
configuration for base (number of leaves per node) because it was possible.
I do not have a formal mathematical proof that base 2 is most efficient in
terms of proof size for a given leaf capacity, but I'm fairly confident it is.

By default, this uses 2 as its base and sha256 as its hashing function, but
both can be manually specified if needed. The most practical way to use this
module is to generate the leaves from a pre-computed set of messages, and then
call the `from_leaves` class method to create an instance. I have not included
a serializer.

Note that any leaf or node without a computed value will be 32 null bytes.
Unlike a Merkle Mountain Range, where trees of variable depth are combined
dynamically ("bagging peaks"), this implementation instead scales to any
number of messages and fills in the gaps in the tree along incomplete paths
with strings of null bytes. Thus, imperfect trees still guarantee the validity
of inclusion proofs.


# Primitives

This uses sha256 from the PyNaCl library as the default hash function.


# Setup / Usage

1. Install the `python3-nacl` library if you wish to use the default configuration.
2. Put `merkle.py` somewhere in the project files.
3. `from [path/to/merkle] import MerkleTree`

See `sample.py` for some sample code.


# Data Structure

`MerkleTree` inherits from list and is essentially a list of lists, with
the root as the only element of the 0th list, the leaves as the contents of
`self[-1]`, and the intermediate nodes in the lists between.


# Methods

- Constructors
  1. `__ini__`
  2. from_leaves
  3. from_messages

- Instance methods
  1. calculate_tree
  2. put
  3. fill
  4. print_hex
  5. prove

- Static methods
  1. print_hex_proof
  2. verify

## `__init__` (base, levels, hashfunc = lambda data: sha256(data, encoder=RawEncoder))

Parameters:
- `base`: the number of children per node
- `levels`: the depth of the tree
- `hashfunc`: a function used to compute hashes

Returns a MerkleTree with the given parameters and `base**levels` leaves. Each
node and leaf will be 32 null bytes.

## @classmethod from_leaves (leaves, base = 2, hashfunc = lambda data: sha256(data, encoder=RawEncoder))

Parameters:
- `leaves`: the hashes of all messages for the tree
- `base`: the number of children per node
- `hashfunc`: a function used to compute hashes

Returns a MerkleTree with the given `leaves`, `base`, and `hashfunc`. Note that the
number of leaves will be a multiple of the base but not necessarily base**levels.
Nodes that have children will have their values computed, and others will be
32 null bytes.

## @classmethod from_messages (messages, base = 2, hashfunc = lambda data: sha256(data, encoder=RawEncoder))

Parameters:
- `messages`: a list of all messages (bytes) for the tree
- `base`: the number of children per node
- `hashfunc`: a function used to compute hashes

Computes the hashes of the messages and returns the result of from_leaves.

## calculate_tree ()

Computes all the nodes from the leaves up to the root.

## put (leaf, index)

Parameters:
- `leaf`: the hash of a message that has been replaced
- `index`: the index of the leaf being replaced

Replaces the hash at the given index with the given `leaf` and then calls calculate_tree.

## fill (leaves)

Parameter:
- `leaves`: a list of all message hashes for the tree

Replaces the leaves with the given `leaves` (as long as they are not in excess of
base**levels), then calls calculate_tree.

## print_hex()

Prints out the MerkleTree in a human-readable, hexidecimal format.

## prove (message)

Parameter:
- `message`: a message in bytes included somewhere in the tree

Generates and returns an inclusion proof for a given message. This proof takes
the form of a list of lists, where each list (except the last) has the index
for the child hash and all other child hashes used to compute the next node.
The final list is simply the root node. The first child hash is the hash of the
message.

## @staticmethod print_hext_proof (proof)

Prints out a proof in a human-readable, hexidecimal format.

## @staticmethod verify (message, proof, hashfunc = lambda data: sha256(data, encoder=RawEncoder))

Parameters:
- `message`: a message in bytes supposedly included in a tree
- `proof`: a list of lists, ostensibly the output of `prove`
- `hashfunc`: a function used to compute hashes

Verifies that the given inclusion proof for the given message is valid.
Returns a boolean.
