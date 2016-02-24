# Python reference implementation of the Zcash proof-of-work

The PoW used by Zcash is a memory-hard algorithm based on the Generalised
Birthday Problem.

Requirements:

* `cryptography`
* `progressbar2` (optional for progress bars in `-v` and `-vv` modes)

To run:

```python
./pow.py
```

Details about available options:

```python
./pow.py -h
```
