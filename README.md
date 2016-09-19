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

These are the same as in Zcash
([here](https://github.com/zcash/zcash/blob/caa0348f0426de7f853ad0a930f934a68fe54efc/src/test/equihash_tests.cpp#L96)
and [here](https://github.com/zcash/zcash/blob/80259d4b4f193c7c438f3c057ce70af3beb1a099/src/gtest/test_equihash.cpp#L24)).
