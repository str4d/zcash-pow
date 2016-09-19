#!/usr/bin/env python2
import binascii

word_size = 32
word_mask = (1<<word_size)-1

def expand_array(inp, out_len, bit_len, byte_pad=0):
    assert bit_len >= 8 and word_size >= 7+bit_len
    bit_len_mask = (1<<bit_len)-1

    out_width = (bit_len+7)/8 + byte_pad
    assert out_len == 8*out_width*len(inp)/bit_len
    out = bytearray(out_len)

    bit_len_mask = (1 << bit_len) - 1

    # The acc_bits least-significant bits of acc_value represent a bit sequence
    # in big-endian order.
    acc_bits = 0;
    acc_value = 0;

    j = 0
    for i in xrange(len(inp)):
        acc_value = ((acc_value << 8) & word_mask) | inp[i]
        acc_bits += 8

        # When we have bit_len or more bits in the accumulator, write the next
        # output element.
        if acc_bits >= bit_len:
            acc_bits -= bit_len
            for x in xrange(byte_pad, out_width):
                out[j+x] = (
                    # Big-endian
                    acc_value >> (acc_bits+(8*(out_width-x-1)))
                ) & (
                    # Apply bit_len_mask across byte boundaries
                    (bit_len_mask >> (8*(out_width-x-1))) & 0xFF
                )
            j += out_width

    return out

def compress_array(inp, out_len, bit_len, byte_pad=0):
    assert bit_len >= 8 and word_size >= 7+bit_len

    in_width = (bit_len+7)/8 + byte_pad
    assert out_len == bit_len*len(inp)/(8*in_width)
    out = bytearray(out_len)

    bit_len_mask = (1 << bit_len) - 1

    # The acc_bits least-significant bits of acc_value represent a bit sequence
    # in big-endian order.
    acc_bits = 0;
    acc_value = 0;

    j = 0
    for i in xrange(out_len):
        # When we have fewer than 8 bits left in the accumulator, read the next
        # input element.
        if acc_bits < 8:
            acc_value = ((acc_value << bit_len) & word_mask) | inp[j]
            for x in xrange(byte_pad, in_width):
                acc_value = acc_value | (
                    (
                        # Apply bit_len_mask across byte boundaries
                        inp[j+x] & ((bit_len_mask >> (8*(in_width-x-1))) & 0xFF)
                    ) << (8*(in_width-x-1))); # Big-endian
            j += in_width
            acc_bits += bit_len

        acc_bits -= 8
        out[i] = (acc_value >> acc_bits) & 0xFF

    return out
