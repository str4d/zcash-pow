#!/usr/bin/env python
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime
from operator import itemgetter

DEBUG = False
VERBOSE = False


def hash_nonce(digest, nonce):
    # TODO update when digest format confirmed
    digest.update(bytes(nonce))

def hash_xi(digest, xi):
    # TODO update when digest format confirmed
    digest.update(bytes(xi))

def count_zeroes(h):
    # Convert to binary string
    h = ''.join('{0:08b}'.format(ord(x), 'b') for x in h)
    # Count leading zeroes
    return (h+'1').index('1')

def has_collision(ha, hb, i, l):
    res = [ha[j] == hb[j] for j in range((i-1)*l/8, i*l/8)]
    return reduce(lambda x, y: x and y, res)

def xor(ha, hb):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(ha,hb))

def gbp_basic(digest, n, k):
    '''Implementation of Basic Wagner's algorithm for the GBP.'''
    collision_length = n/(k+1)

    # 1) Generate first list
    if DEBUG: print 'Generating first list'
    X = []
    for i in range(0, 2**(collision_length+1)):
        # X_i = H(I||V||x_i)
        curr_digest = digest.copy()
        # TODO convert i to x_i
        hash_xi(curr_digest, i)
        X.append((curr_digest.finalize()[:n/8], (i,)))

    # 3) Repeat step 2 until 2n/(k+1) bits remain
    for i in range(1, k):
        if DEBUG: print 'Round %d:' % i

        # 2a) Sort the list
        if DEBUG: print '- Sorting list'
        X.sort(key=itemgetter(0))
        if DEBUG and VERBOSE:
            for Xi in X[-32:]:
                print '%s %s' % (print_hash(Xi[0]), Xi[1])

        if DEBUG: print '- Finding collisions'
        Xc = []
        j = 0
        while j < len(X):
            # 2b) Find next set of unordered pairs with collisions on first n/(k+1) bits
            k = j + 1
            while k < len(X):
                if not has_collision(X[j][0], X[k][0], i, collision_length):
                    break
                k += 1

            # 2c) Store tuples (X_i ^ X_j, (i, j)) on the table
            for l in range(j, k-1):
                for m in range(l+1, k):
                    if reduce(lambda x,y: x and y, [x not in X[m][1] for x in X[l][1]]):
                        Xc.append((xor(X[l][0], X[m][0]),
                                   tuple(sorted(list(X[l][1] + X[m][1])))))

            # 2d) Skip over this set
            j = k
        # 2e) Replace previous list with new list
        X = Xc

        # Note that 2d) and 2e) mean that this implementation uses more memory
        # than necessary, having the lists for two rounds in memory at the same
        # time. This strategy was taken over using list.pop(0) and list.append()
        # to reduce runtimes by a factor of ~10,000 on my Asus Aspire One (for
        # development ease :P).

    # k+1) Find a collision on last 2n(k+1) bits
    if DEBUG:
        print 'Final round:'
        print '- Sorting list'
    X.sort(key=itemgetter(0))
    if DEBUG and VERBOSE:
        for Xi in X[-32:]:
            print '%s %s' % (print_hash(Xi[0]), Xi[1])
    if DEBUG: print '- Finding collision'
    for i in range(0, len(X)-1):
        res = xor(X[i][0], X[i+1][0])
        if count_zeroes(res) == n and X[i][1] != X[i+1][1]:
            if DEBUG and VERBOSE:
                print '%s %s' % (print_hash(X[i][0]), X[i][1])
                print '%s %s' % (print_hash(X[i+1][0]), X[i+1][1])
            return list(X[i][1] + X[i+1][1])
    return None

def difficulty_filter(digest, x, d):
    # H(I||V||x_1||x_2||...|x_2^k)
    for xi in x:
        hash_xi(digest, xi)
    h = digest.finalize()
    count = count_zeroes(h)
    if DEBUG: print 'Leading zeroes: %d' % count
    return count >= d


#
# Demo miner
#

def print_hash(h):
    return ''.join('{0:02x}'.format(ord(x), 'x') for x in h)

def validate_params(n, k):
    if (k >= n):
        raise ValueError('n must be larger than k')
    if ((n/(k+1)) % 8 != 0):
        raise ValueError('Parameters must satisfy n/(k+1) = 0 mod 8')

def mine(n, k, d):
    print 'Miner starting'
    validate_params(n, k)
    print '- n: %d' % n
    print '- k: %d' % k
    print '- d: %d' % d
    # Genesis
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    prev_hash = digest.finalize()
    while True:
        start = datetime.today()
        # H(I||...
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(prev_hash)
        nonce = 0
        x = []
        while (nonce >> 161 == 0):
            if DEBUG:
                print
                print 'Nonce: %d' % nonce
            # H(I||V||...
            curr_digest = digest.copy()
            hash_nonce(curr_digest, nonce)
            # (x_1, x_2, ...) = A(I, V, n, k)
            if DEBUG:
                gbp_start = datetime.today()
            x = gbp_basic(curr_digest, n, k)
            if DEBUG:
                print 'GBP took %s' % str(datetime.today() - gbp_start)
                if not x: print 'No solution found'
            if x and difficulty_filter(curr_digest.copy(), x, d):
                break
            nonce += 1
        duration = datetime.today() - start

        if not x:
            raise RuntimeError('Could not find any valid nonce. Wow.')

        # H(I||V||x_1||x_2||...|x_2^k)
        hash_nonce(digest, nonce)
        for xi in x:
            hash_xi(digest, xi)
        curr_hash = digest.finalize()
        print '-----------------'
        print 'Mined block!'
        print 'Previous hash: %s' % print_hash(prev_hash)
        print 'Current hash:  %s' % print_hash(curr_hash)
        print 'Nonce:         %s' % nonce
        print 'Time to find:  %s' % str(duration)
        print '-----------------'
        prev_hash = curr_hash


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=int, default=96,
                        help='length of the strings to be XORed')
    parser.add_argument('-k', type=int, default=5,
                        help='number of strings needed for a solution')
    parser.add_argument('-d', type=int, default=3,
                        help='the difficulty (higher is more difficult)')
    parser.add_argument('-v', '--verbosity', action='count')
    args = parser.parse_args()

    DEBUG = args.verbosity > 0
    VERBOSE = args.verbosity > 1
    try:
        mine(args.n, args.k, args.d)
    except KeyboardInterrupt:
        pass
