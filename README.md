# BPHT -- A Bitpacked Hopscotch Hash Table

BPHT is a specialized hash table aimed to offer fast acces to 32-bit integer values by using bit-packing and quotienting.
It uses hopscotch hashing[1] to resolve collisions and stores hop bits bit-packed into the data array to avoid compulsory cache misses.
To maintain resizability without explicitly saving keys, it uses quotienting[2] to be able to restore hash values.
This architecture allows efficient resize operations with constant additonal memory, but imposes some restrictions:

* Stored values have to be `u32`
* Hash values (keys) have to be `u32`
* Hash values (keys) should be well distributed between 0 and 2^{32}
* Hash table sizes (`u`) have to be a power of 2

Note that this is **not** a general purpose hash table.
It requires you to pre-compute hash values and have at least a rough idea of the number of entries you want to insert.



## Usage
Explicitly pass key-value pairs to the table

```
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


## Implementation Details


### Quotienting
Keys are split into address (`log_2(u)` high bits) and remainder (also referred to as fingerprint; `32 - log_2(u)` low bits.)



### Bit-packing 
Each entry of the underlying array of a BPHT contains the following information packed into 64 bits:
```
|  32 bit  value  | up to (32 - H) remainder bits | H hop bits |
```




== References ==

[1] Herlihy et al.: http://people.csail.mit.edu/shanir/publications/disc2008_submission_98.pdf
[2] Knuth, Donald E. The Art of Computer Programming: Sorting and Searching. Vol. 3. Pearson Education, 1997.

