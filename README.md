# Python reference implementation of the Zcash proof-of-work

The PoW currently being used by Zcash is Equihash, a memory-hard algorithm
based on the Generalised Birthday Problem.

## Requirements

* `cryptography`
* `pyblake2`
* `progressbar2` (optional for progress bars in `-v` and `-vv` modes)

## Demo miner

To run:

```python
./pow.py
```

Details about available options:

```python
./pow.py -h
```

## Test vectors

```python
./test-pow.py
```

These are the same as in [Zcash](https://github.com/str4d/zcash/blob/a6dcf2ee6f628876b0f365942b3fff624041aebb/src/test/equihash_tests.cpp#L86).
