[![Build Status](https://github.com/HenningTimm/bpht/workflows/Rust/badge.svg)](https://github.com/HenningTimm/bpht/actions)
[![creates.io-version](https://img.shields.io/crates/v/bpht.svg)](https://crates.io/crates/bpht)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![docs.rs](https://docs.rs/bpht/badge.svg)](https://docs.rs/bpht)

# BPHT - A Bitpacked Hopscotch Hash Table

BPHT is a specialized hash table aimed to offer fast access to 32-bit integer values by using bit-packing and quotienting.
It uses hopscotch hashing __[1]__ to resolve collisions and stores hop bits bit-packed into the data array to avoid compulsory cache misses.
To maintain resizability without explicitly saving keys, it uses quotienting __[2]__ to be able to restore hash values.
This architecture allows efficient resize operations with constant additional memory, but imposes some restrictions:

* Stored values have to be `u32`
* Hash values (keys) have to be `u32`
* Hash values (keys) should be well distributed between 0 and 2^{32} - 1
* Hash table sizes (`u`) have to be a power of 2

Note that this is **not** a general purpose hash table.
It requires you to pre-compute hash values and have at least a ballpark estimate of the number of entries you want to insert.



## Usage

A BPHT requires to explicitly pass key-value pairs to the table.
There are two possible way to use a BPHT, hash table mode and counter mode.

For hash table mode use the `insert(key, value)` method to put entries into the table and the `get.(key)` method to retrieve all values inserted for the given key.
In counting mode, you do not need to pass a value.
Use the `increment_count(key)` and `get_count(key)` methods:


```rust
use bpht;


fn test_hash_table_mode() -> Result<(), &'static str>{
    let h = 8;  // Hopscotch neighborhood size
    let u = 2_u64.pow(25) as usize;  // Initial hash table address space size
    let allow_resize = true;  // Allow the table to perform resize operations
    let mut ht = bpht::BPHT::new(h, u, allow_resize)?;
    
    // these should be hash values
    let keys: Vec<u32> = vec![681141441, 681141441, 4274363488, 2008780323];
    let values =  vec![42, 23, 47, 11];
    for  (key, value) in  keys.iter().zip(values.iter()){
        ht.insert(*key, *value)?;
    }

    assert_eq!(ht.get(681141441), Some(vec![42, 23]));
    assert_eq!(ht.get(4274363488), Some(vec![47]));
    assert_eq!(ht.get(17), None);
    Ok(())
}


fn test_counting_mode() -> Result<(), &'static str>{
    let h = 8;  // Hopscotch neighborhood size
    let u = 2_u64.pow(25) as usize;  // Initial hash table address space size
    let allow_resize = true;  // Allow the table to perform resize operations
    let mut ht = bpht::BPHT::new(h, u, allow_resize)?;
    
    // these should be hash values
    let keys: Vec<u32> = vec![681141441, 681141441, 4274363488, 2008780323];
    // Count the number of times keys are encountered
    for  key in keys {
        ht.increment_count(key)?;
    }

    assert_eq!(ht.get_count(681141441), Some(2));
    assert_eq!(ht.get_count(4274363488), Some(1));
    assert_eq!(ht.get_count(17), None);
    Ok(())
}


fn main() -> Result<(), &'static str>{
    test_hash_table_mode()?;
    test_counting_mode()?;
    Ok(())
}

```



## Implementation Details

### Quotienting
Keys are split into address (`log_2(u)` high bits) and remainder (also referred to as fingerprint; `32 - log_2(u)` low bits.)

```
Example: u = 2^{22}
=> 22           address bits (a)
=> 32 - 22 = 10 remainder bits (r)

Key as
Bit vector: 0b_00000000_00000000_11111100_00101010
               |-----------22---------||---10----|
Quotiented: 0b_aaaaaaaa_aaaaaaaa_aaaaaarr_rrrrrrrr

Address:   0b_111111
Remainder: 0b_101010
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

