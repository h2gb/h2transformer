# h2transformer

**NOTE: THIS REPO IS DEPRECATED! I've combined this code with libh2gb**

(I don't really think anybody is using this, but I just don't want there to be any confusion :)

---

H2Transformer is a library for transforming raw data between encodings.

As part of [h2gb](https://github.com/h2gb), it's common to extract a buffer
from a binary that's encoded in some format - Base64, hex string, etc.

This library can detect and transform common formats. It can also
transform back to the original data with a constant length and without
saving any context (while the length is constant, the data isn't always
identical - like the case of Base32 and hex strings). If proper undo/redo
is needed, this won't fit the bill.

Check out the definition of the `H2Transformation` enum for full details on
everything it can do!

## Usage

The public API is pretty straight forward. Here's an example that transforms
then untransforms some hex data:


```rust
use h2transformer::H2Transformation;

// Input (note that some are uppercase and some are lower - that's allowed)
let i: Vec<u8> = b"48656c6C6F2c20776f726c64".to_vec();

// Output
let o = H2Transformation::FromHex.transform(&i).unwrap();

// It's "Hello, world"
assert_eq!(b"Hello, world".to_vec(), o);

// Transform back to the original
let i = H2Transformation::FromHex.untransform(&o).unwrap();

// Get the original back - note that it's the same length, but the case has
// been normalized
assert_eq!(b"48656c6c6f2c20776f726c64".to_vec(), i);
```

License: MIT
