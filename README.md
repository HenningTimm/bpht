# BPHT - A Bitpacked Hopscotch Hash Table

BPHT is a specialized hash table aimed to offer fast access to 32-bit integer values by using bit-packing and quotienting.
It uses hopscotch hashing __[1]__ to resolve collisions and stores hop bits bit-packed into the data array to avoid compulsory cache misses.
To maintain resizability without explicitly saving keys, it uses quotienting __[2]__ to be able to restore hash values.
This architecture allows efficient resize operations with constant additional memory, but imposes some restrictions:

* Stored values have to be `u32`
* Hash values (keys) have to be `u32`
* Hash values (keys) should be well distributed between 0 and 2^{32}
* Hash table sizes (`u`) have to be a power of 2

Note that this is **not** a general purpose hash table.
It requires you to pre-compute hash values and have at least a rough idea of the number of entries you want to insert.



## Usage

A BPHT requires to explicitly pass key-value pairs to the table.
There are two possible way to use a BPHT, hash table mode and counter mode.

For hash table mode use the `insert(key, value)` method to put entries into the table and the `get.(key)` method to retrieve all values inserted for the given key.

```rust
let h = 8;  // hopscotch neighborhood size
let u = 2_u64.pow(25) as usize;  // Initial hash table address space size
let mut ht = bpht::BPHT::new(h, u);

// these should be hash values
let keys: Vec<u64> = vec![339383137916411693, 339383137916411693, 9570299963413069330, 11149767687988377925];
let values =  vec![42, 23, 47, 11];
for  (key, value) in  keys.iter().zip(values.iter()){
    ht.insert(key, value);
}

ht.get(339383137916411693);
// returns Some([42, 23])
ht.get(9570299963413069330);
// returns Some([47])
ht.get(0);
// returns None
```

In counting mode, you do not need to pass a value.
Use the `increment_count(key)` and `get_count(key)` methods:

```rust
let h = 8;  // hopscotch neighborhood size
let u = 2_u64.pow(25) as usize;  // Initial hash table address space size
let mut ht = bpht::BPHT::new(h, u);

// these should be hash values
let keys: Vec<u64> = vec![339383137916411693, 339383137916411693, 9570299963413069330, 11149767687988377925];
let values =  vec![42, 23, 47, 11];
for  (key, value) in  keys.iter().zip(values.iter()){
    ht.increment_count(key, value);
}

ht.get_count(339383137916411693);
// returns Some(2)
ht.get(9570299963413069330);
// returns Some(1)
ht.get(0);
// returns None
```



## Implementation Details

### Quotienting
Keys are split into address (`log_2(u)` high bits) and remainder (also referred to as fingerprint; `32 - log_2(u)` low bits.)

```
Example: u = 2^{22}
=> 22           address bits (a)
=> 32 - 22 = 10 remainder bits (r)

Key as
Bit vector: 0b_00000000_00000000_00000000_00000000
               |-----------22---------||---10----|
Quotiented: 0b_aaaaaaaa_aaaaaaaa_aaaaaarr_rrrrrrrr
```
This setup was chosen since it allows efficient resize operations by just moving one remainder bit to the address bits.
Note, however, that entering small keys can easily result in overflowing hopscotch neighborhoods.


### Bit-packing 
Each entry of the underlying array of a BPHT contains the following information packed into 64 bits:
```
|        32 bits value           | up to (32 - H) remainder bits | H hop bits |
|vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv|rrrrrrr.............rrrrrrrrrrr|hhh......hhh|
```
Due to this design, the size of the hash table introduces a maximum number of possible hop bits.




## References

[1] Herlihy et al.: http://people.csail.mit.edu/shanir/publications/disc2008_submission_98.pdf

[2] Knuth, Donald E. The Art of Computer Programming: Sorting and Searching. Vol. 3. Pearson Education, 1997.

