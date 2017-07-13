#!/usr/bin/env python2
import argparse
from binascii import unhexlify
from pyblake2 import blake2b
import struct

from convert import expand_array
from pow import (
    hash_xi,
    print_hash,
    xor,
    zcash_person,
)


class node(object):
    def __init__(self, h, children=[], xi=None):
        self.hash = h
        self.children = children
        self.xi = xi

    def __repr__(self, level=[]):
        ret = ('\t' if level else '') + \
              ''.join(['|\t' if x else '\t' for x in level[:-1]]) + \
              print_hash(self.hash) + \
              (' (%d)' % self.xi if self.xi is not None else '') + \
              '\n'
        for child in self.children[:-1]:
            ret += child.__repr__(level+[True])
        for child in self.children[-1:]:
            ret += child.__repr__(level+[False])
        return ret

def get_indices_from_minimal(minimal, bit_len):
    eh_index_size = 4
    assert (bit_len+7)/8 <= eh_index_size
    len_indices = 8*eh_index_size*len(minimal)/bit_len
    byte_pad = eh_index_size - (bit_len+7)/8
    expanded = expand_array(minimal, len_indices, bit_len, byte_pad)
    return [struct.unpack('>I', expanded[i:i+4])[0] for i in range(0, len_indices, eh_index_size)]

def generate_hashes(n, k, header):
    collision_length = n/(k+1)
    bit_len = collision_length + 1
    hash_length = (k+1)*((collision_length+7)//8)
    indices_per_hash_output = 512/n
    num_indices = 2**k

    digest = blake2b(digest_size=(512/n)*n/8, person=zcash_person(n, k))
    digest.update(header[:140])
    num_bytes = ord(header[140]) if ord(header[140]) < 253 else struct.unpack('<H', header[141:143])[0]
    assert num_bytes == bit_len*num_indices/8, 'Block header does not match Equihash parameters'
    i = 143 if ord(header[140]) == 253 else 141
    soln = get_indices_from_minimal(bytearray(header[i:i+num_bytes]), bit_len)

    hashes = []
    for xi in soln:
        r = xi % indices_per_hash_output
        # X_i = H(I||V||x_i)
        curr_digest = digest.copy()
        hash_xi(curr_digest, xi/indices_per_hash_output)
        tmp_hash = curr_digest.digest()
        hashes.append(
            expand_array(bytearray(tmp_hash[r*n/8:(r+1)*n/8]),
                         hash_length, collision_length)
        )
    return soln, hashes

def print_hashes(soln, hashes):
    nodes = [node(x, xi=y) for x, y in zip(hashes, soln)]
    while len(nodes) > 1:
        nodes = [node(xor(nodes[i].hash, nodes[i+1].hash), nodes[i:i+2]) for i in range(0, len(nodes), 2)]
    print soln
    print nodes[0]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Visualise an Equihash solution')
    parser.add_argument('n', type=int,
                        help='Equihash parameter N')
    parser.add_argument('k', type=int,
                        help='Equihash parameter K')
    parser.add_argument('header', help='a block or block header in hexadecimal')
    args = parser.parse_args()

    print_hashes(*generate_hashes(args.n, args.k, unhexlify(args.header)))
