#!/usr/bin/env python2
import argparse
from binascii import unhexlify
from pyblake2 import blake2b
import struct

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

def generate_hashes(n, k, header):
    digest = blake2b(digest_size=n/8, person=zcash_person(n, k))
    digest.update(header[:140])
    i = 143 if ord(header[140]) == 256 else 141
    soln = [struct.unpack('<I', header[i:i+4])[0] for i in range(i, len(header), 4)]
    hashes = [hash_xi(digest.copy(), xi).digest() for xi in soln]
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
    parser.add_argument('header', help='the block header in hexadecimal')
    args = parser.parse_args()

    print_hashes(*generate_hashes(args.n, args.k, unhexlify(args.header)))
