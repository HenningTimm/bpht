#[cfg(test)]
mod tests {
    use crate::*;
    use itertools::iproduct;
    use rand::seq::SliceRandom;
    use std::collections::HashSet;
    use std::iter::FromIterator;

    /// Test implementing debug methods for a Bitpacked Hopscotch Table
    trait HopscotchDebug {
        fn count_total_hop_bits(&self) -> u32;
        fn print_ht_fw(&self);
        fn print_ht(&self);
        fn is_valid(&self) -> bool;
        fn nonzero_entries(&self) -> usize;
        fn key_from_parts(&self, address: u32, remainder: u32) -> u32;
    }

    impl HopscotchDebug for BPHT {
        fn count_total_hop_bits(&self) -> u32 {
            let mut total_hop_bits = 0;
            for (addr, _value) in self.table.iter().enumerate() {
                let hop_bits = self.get_hop_bits(addr);
                total_hop_bits += hop_bits.count_ones();
            }
            total_hop_bits
        }

        /// Print the hash table, showing only filled buckets
        /// formatted into 64 bits
        fn print_ht_fw(&self) {
            let mut last_empty = false;
            for (i, entry) in self.table.iter().enumerate() {
                match (*entry == 0, last_empty) {
                    (false, true) => {
                        println!("{:3}  {:>64b}", i, entry);
                        last_empty = false;
                    }
                    (false, false) => {
                        println!("{:3}  {:>64b}", i, entry);
                    }
                    (true, true) => (),
                    (true, false) => {
                        println!("{:3}  {:>64b}\n[...]", i, entry);
                        last_empty = true;
                    }
                }
            }
        }

        /// Print a full hash table, formatted into 42 bits.
        fn print_ht(&self) {
            for (i, entry) in self.table.iter().enumerate() {
                println!("{:3}  {:>42b}", i, entry);
            }
        }

        /// Check if the following things hold for the hash table:
        ///
        /// - There are no invalid hop bits, i.e. no two hop bits point to
        ///   the same bucket.
        ///
        fn is_valid(&self) -> bool {
            // check that no conflicting hop-bits are present
            let mut shifting_hop_bits = 0;

            for (addr, _value) in self.table.iter().enumerate() {
                shifting_hop_bits = shifting_hop_bits >> 1;
                let hop_bits = self.get_hop_bits(addr);
                if (shifting_hop_bits & hop_bits) != 0 {
                    panic!("Invalid hop bits!");
                }
            }

            // NOTE: Consider checking that no data is in the unused part of entries
            // i.e. the slots for fingerprint bits that are no longer required
            // due to large hash table size.

            // if this is reached, no conflicting hop bits were found
            true

            // when done, add this as last step to all tests.
        }

        /// count the non-zero entries in the HT by counting
        /// all slots that contain a 1-bit that is not part of the hop
        /// bits.
        /// Note that this can miss counting the value 0 with remainder 0.
        fn nonzero_entries(&self) -> usize {
            let mut nonzero = 0;
            for (_addr, value) in self.table.iter().enumerate() {
                if (value & (!self.hop_bits_mask)) != 0 {
                    nonzero += 1;
                }
            }
            nonzero
        }

        /// assemble a key that will be split into the given address and
        /// remainder for this HT configuration
        fn key_from_parts(&self, address: u32, remainder: u32) -> u32 {
            (address << self.fp_bits_in_key) | remainder
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Test cases
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    #[test]
    fn test_split_key_simple() {
        let h = 4;
        let size = 32;
        let ht = BPHT::new(h, size, true).unwrap();

        // this is for the |addr|fp| version
        let (addr, fp) = ht.split_key(0b_00011_000_00000000_00000000_00000101);
        assert_eq!(addr, 0b11);
        assert_eq!(fp, 0b101);
        ht.is_valid();
    }

    #[test]
    fn test_split_key_automated() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for (size_power, h) in iproduct!(3..16, 3..8) {
            if let Ok(ht) = BPHT::new(h, 2_usize.pow(size_power as u32), true) {
                // generate random keys
                let keys: Vec<u32> = (0..1000)
                    .map(|_| rng.gen_range(0, (2_u64.pow(32) - 1) as u32))
                    .collect();

                for key in keys {
                    let (addr, fp) = ht.split_key(key);

                    // |addr|fp| version
                    assert_eq!(((addr as u32) << (32 - size_power)) | fp, key);
                }
            } else {
                assert!(
                    h > size_power,
                    "An instance that should be possible could not be build."
                );
            }
        }
    }

    #[test]
    fn test_restore_key_simple() {
        let h = 4;
        let size = 32;
        let ht = BPHT::new(h, size, true).unwrap();

        // this is for the |addr|fp| version
        let key = ht._restore_key(0b11, 0b101);
        assert_eq!(key, 0b_00011_000_00000000_00000000_00000101);

        let key = BPHT::restore_key_with(0b11, 0b101, ht.fp_bits_in_key, ht.key_fp_mask);
        assert_eq!(key, 0b_00011_000_00000000_00000000_00000101);
    }

    #[test]
    fn test_split_restore_key_identity_automated() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for (size_power, h) in iproduct!(3..16, 3..8) {
            if let Ok(ht) = BPHT::new(h, 2_usize.pow(size_power as u32), true) {
                // generate random keys
                let keys: Vec<u32> = (0..1000)
                    .map(|_| rng.gen_range(0, (2_u64.pow(32) - 1) as u32))
                    .collect();

                for key in keys {
                    let (addr, fp) = ht.split_key(key);
                    let restored_key = ht._restore_key(addr, fp);
                    assert_eq!(key, restored_key);

                    let manually_restored_key =
                        BPHT::restore_key_with(addr, fp, ht.fp_bits_in_key, ht.key_fp_mask);
                    assert_eq!(key, manually_restored_key);
                }
            } else {
                assert!(
                    h > size_power,
                    "An instance that should be possible could not be build."
                );
            }
        }
    }

    #[test]
    fn creation() {
        let h = 4;
        let size = 32;
        let ht = BPHT::new(h, size, true).unwrap();
        for i in 0..size {
            assert_eq!(ht.table[i], 0);
        }
    }

    #[test]
    /// Are hop bits extracted correctly?
    fn get_hop_bits() {
        let h = 4;
        // NOTE this table configuration is invalid and is just used to have
        // a small test instance
        let ht = BPHT {
            h,
            u: 8,
            table: vec![
                0,
                0,
                0,
                0b000011_00000000_00000000_00000000_00110111,
                0b101011_00000000_00000000_00000010_10100000,
                0b101010_00000000_00000000_00000000_00110010,
                0b101010_00000000_00000000_00000000_00111111,
                0b101010_00000000_00000000_00000000_00111010,
                0,
                0,
                0,
            ],
            hop_bits_mask: 0b_1111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11110000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 29,
            key_fp_mask: 0b_00011111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: true,
        };
        let expected_hop_bits = vec![0, 0, 0, 7, 0, 2, 15, 10, 0, 0, 0];
        for (i, expected) in expected_hop_bits.iter().enumerate() {
            assert_eq!(ht.get_hop_bits(i), *expected);
        }
    }

    #[test]
    /// Are hop bits extracted correctly?
    fn get_starting_hop_bits() {
        color_backtrace::install();
        let h = 4;
        // NOTE this table configuration is invalid and is just used to have
        // a small test instance
        let ht = BPHT {
            h,
            u: 16,
            table: vec![
                0b000001_00000000_00000000_00000000_0000_0111, // 0
                0b000001_00000000_00000000_00000000_0000_0000, // 1
                0b000001_00000000_00000000_00000000_0000_0000, // 2
                0b000000_00000000_00000000_00000000_0000_0010, // 3 <- this slot is empty due to deletion
                0b000001_00000000_00000000_00000000_0000_0000, // 4
                0,                                             // 5
                0b000001_00000000_00000000_00000000_0000_1101, // 6
                0b000001_00000000_00000000_00000000_0000_0001, // 7
                0b000001_00000000_00000000_00000000_0000_0000, // 8
                0b000001_00000000_00000000_00000000_0000_0000, // 9
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            hop_bits_mask: 0b_1111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11110000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 28,
            key_fp_mask: 0b_00001111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: true,
        };

        assert_eq!(ht.initialize_insert_hop_bits(0), 0b_0111); // no previous info
        assert_eq!(ht.initialize_insert_hop_bits(1), 0b_0011); // addr 1 and 2 are blocked by 0
        assert_eq!(ht.initialize_insert_hop_bits(2), 0b_0001); // addr 2 is blocked by 0
        assert_eq!(ht.initialize_insert_hop_bits(3), 0b_0010); // this slot is free, but the next is full
        assert_eq!(ht.initialize_insert_hop_bits(4), 0b_0001); // this slot is filled by 3
        assert_eq!(ht.initialize_insert_hop_bits(5), 0b_0000); // empty, nothing before
        assert_eq!(ht.initialize_insert_hop_bits(6), 0b_1101); // this slot has three entries
        assert_eq!(ht.initialize_insert_hop_bits(7), 0b_0111); // filled by 7, next two are overflow from 6
        assert_eq!(ht.initialize_insert_hop_bits(8), 0b_0011); // overflow from 6
        ht.is_valid();

        let h = 3;
        // NOTE this table is nonesensical and just for testing
        let ht = BPHT {
            h,
            u: 16,
            table: vec![
                0,
                0,
                0,
                0,
                0,
                0,                                             // 0-5
                0b000001_00000000_00000000_00000000_00001_011, // 6  <- full with 6
                0b000001_00000000_00000000_00000000_00000_010, // 7  <- full with 6
                0b000001_00000000_00000000_00000000_00000_000, // 8  <- full with 7
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            hop_bits_mask: 0b_111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11111000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 28,
            key_fp_mask: 0b_00001111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: true,
        };
        for i in 0..9 {
            eprintln!("i = {}: {}", i, ht.initialize_insert_hop_bits(i));
        }
        assert_eq!(ht.initialize_insert_hop_bits(4), 0b_000);
        assert_eq!(ht.initialize_insert_hop_bits(5), 0b_000);
        assert_eq!(ht.initialize_insert_hop_bits(6), 0b_011);
        assert_eq!(ht.initialize_insert_hop_bits(7), 0b_011);
        assert_eq!(ht.initialize_insert_hop_bits(8), 0b_001);
        ht.is_valid();
    }

    #[test]
    fn insert_simple() {
        let h = 4;
        let size = 32;
        let mut ht = BPHT::new(h, size, true).unwrap();

        // |addr|fp|
        ht.insert(0b00011_000_00000000_00000000_00000011, 1)
            .unwrap();
        assert_eq!(ht.table[3], 0b001_00000000_00000000_00000000_0011_0001);

        // this requires a shift
        // |addr|fp|
        ht.insert(0b00011_000_00000000_00000000_00000101, 3)
            .unwrap();
        assert_eq!(ht.table[3], 0b001_00000000_00000000_00000000_0011_0011);
        assert_eq!(ht.table[4], 0b011_00000000_00000000_00000000_0101_0000);

        // this requires another shift
        // |addr|fp|
        ht.insert(0b00100_000_00000000_00000000_00001001, 7)
            .unwrap();
        assert_eq!(ht.table[3], 0b001_00000000_00000000_00000000_0011_0011);
        assert_eq!(ht.table[4], 0b011_00000000_00000000_00000000_0101_0010);
        assert_eq!(ht.table[5], 0b111_00000000_00000000_00000000_1001_0000);
        ht.is_valid();
    }

    #[test]
    fn get_simple() {
        let h = 4;
        let ht = BPHT {
            h,
            u: 16,
            table: vec![
                0,
                0,
                0,
                0b000011_00000000_00000000_00000000_00110111,
                0b101011_00000000_00000000_00000010_10100000,
                0b101010_00000000_00000000_00000000_00110000,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            hop_bits_mask: 0b_1111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11110000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 28,
            key_fp_mask: 0b_00001111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: true,
        };
        // |addr|fp|
        assert_eq!(
            ht.get(0b_0011_0000_00000000_00000000_00000011),
            Some(vec![3, 42])
        );
        assert_eq!(
            ht.get(0b_0011_0000_00000000_00000000_00101010),
            Some(vec![43])
        );
        ht.is_valid();
    }

    #[test]
    fn delete_simple() {
        let h = 4;
        let mut ht = BPHT {
            h,
            u: 16,
            table: vec![
                0,                                            // 0
                0,                                            // 1
                0,                                            // 2
                0b000011_00000000_00000000_00000000_00110111, // 3
                0b101010_00000000_00000000_00000010_10100000, // 4
                0b101010_00000000_00000000_00000000_00110000, // 5
                0,                                            // 6
                0,                                            // 7
                0,                                            // 8
                0,                                            // 9
                0,                                            // 10
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            hop_bits_mask: 0b_1111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11110000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 28,
            key_fp_mask: 0b_00001111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: true,
        };
        // |addr|fp|
        ht.delete(0b_0011_0000_00000000_00000000_00000011).unwrap(); // address 0b11 with fingerprint 0b11
        assert_eq!(
            ht.table,
            vec![
                0,
                0,
                0,
                0b0_00000000_00000000_00000000_00000010,
                0b101010_00000000_00000000_00000010_10100000,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        );
        ht.is_valid();
    }

    #[test]
    fn delete_till_empty() {
        let h = 4;
        let size = 512;
        let mut ht = BPHT::new(h, size, true).unwrap();
        let keys = vec![0, 8, 15, 47, 11];
        // insert some keys
        for key in &keys {
            // shift key out of the fp bits
            // |addr|fp| KLUDGE
            ht.insert(*key << (32 - 9), *key).unwrap();
        }
        // remove the same keys again
        for key in &keys {
            // |addr|fp| KLUDGE
            ht.delete(*key << (32 - 9)).unwrap();
            ht.is_valid();
        }

        // all entries must be zero after this
        for entry in ht.table.iter() {
            assert_eq!(*entry, 0);
        }
        ht.is_valid();
    }

    #[test]
    fn insert_with_shift() {
        let h = 4;
        let mut ht = BPHT {
            h,
            u: 16,
            table: vec![
                0,                                             // 0
                0,                                             // 1
                0,                                             // 2
                0b000011_00000000_00000000_00000000_0011_1011, // 3; address: 3
                0b101010_00000000_00000000_00000010_1010_0000, // 4; address: 3
                0b010001_00000000_00000000_00000000_0011_0001, // 5; address: 5  <- this will be shifted to position 7
                0b101010_00000000_00000000_00000010_1010_0000, // 6; address: 3
                0,                                             // 7
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            hop_bits_mask: 0b_1111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11110000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 28,
            key_fp_mask: 0b_00001111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: true,
        };

        ht.is_valid();

        // |addr|fp|
        ht.insert(0b_0011_0000_00000000_00000000_00000011, 0b_11)
            .unwrap();
        ht.print_ht();

        ht.is_valid();

        assert_eq!(
            ht.table,
            vec![
                0,                                             // 0
                0,                                             // 1
                0,                                             // 2
                0b000011_00000000_00000000_00000000_0011_1111, // 3  // address: 3
                0b101010_00000000_00000000_00000010_1010_0000, // 4  // address: 3
                0b000011_00000000_00000000_00000000_0011_0100, // 5  // address: 3  <- newly inserted item
                0b101010_00000000_00000000_00000010_1010_0000, // 6  // address: 3
                0b010001_00000000_00000000_00000000_0011_0000, // 7  // address: 5, <- item shifted here from position 5
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        );
    }

    #[test]
    fn compact() {
        let h = 5;
        let mut ht = BPHT {
            h,
            u: 32,
            table: vec![
                0,                                              // 0
                0,                                              // 1
                0,                                              // 2
                0b_101010_00000000_00000000_00000101_010_10101, // 3
                0,                                              // 4
                0b_101011_00000000_00000000_00000101_011_00000, // 5
                0,                                              // 6
                0b_101100_00000000_00000000_00000101_100_00000, // 7
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            hop_bits_mask: 0b_11111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11100000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 27,
            key_fp_mask: 0b_00000111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: false,
        };
        ht.compact(3);
        ht.print_ht();
        assert_eq!(
            ht.table,
            vec![
                0,                                              // 0
                0,                                              // 1
                0,                                              // 2
                0b_101010_00000000_00000000_00000101_010_00111, // 3
                0b_101100_00000000_00000000_00000101_100_00000, // 4  <- target address. Has one slot that can be freed by moving entry from 5 to 3
                0b_101011_00000000_00000000_00000101_011_00000, // 5
                0,                                              // 6
                0,                                              // 7
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        );
    }

    #[test]
    fn compact_multiple() {
        color_backtrace::install();
        let h = 7_usize;

        let mut table = vec![0_u64; (128 + h - 1) as usize];
        eprintln!("{:?}", table);
        {
            table[3] = 0b_001__00000000_00000000_00000000_1__1110101;
            table[5] = 0b_010__00000000_00000000_00000001_0__0000000;
            table[7] = 0b_011__00000000_00000000_00000001_1__0000000;
            table[8] = 0b_100__00000000_00000000_00000010_0__0000000;
            table[9] = 0b_101__00000000_00000000_00000010_1__0000000;
        }
        // after this: 3,9,5,8,7
        let mut ht = BPHT {
            h,
            u: 128,
            table,
            hop_bits_mask: 0b_1111111,
            fingerprint_mask: 0b_11111111_11111111_11111111_10000000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 25,
            key_fp_mask: 0b_00000001_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: false,
        };

        ht.compact(3);

        let mut expected_table = vec![0_u64; (128 + h - 1) as usize];
        expected_table[3] = 0b_001__00000000_00000000_00000000_1__0011111;
        expected_table[5] = 0b_010__00000000_00000000_00000001_0__0000000;
        expected_table[7] = 0b_011__00000000_00000000_00000001_1__0000000;
        expected_table[6] = 0b_100__00000000_00000000_00000010_0__0000000;
        expected_table[4] = 0b_101__00000000_00000000_00000010_1__0000000;
        assert_eq!(ht.table, expected_table,);
    }

    #[test]
    fn compact_multiple_with_other_entries() {
        color_backtrace::install();
        let h = 7_usize;

        let mut table = vec![0_u64; (128 + h - 1) as usize];
        eprintln!("{:?}", table);
        {
            table[3] = 0b_001__00000000_00000000_00000000_1__1110101;
            table[4] = 0b_010__00000000_00000000_00000001_0__0000001;
            table[5] = 0b_010__00000000_00000000_00000001_0__0000000;
            table[7] = 0b_011__00000000_00000000_00000001_1__0000000;
            table[8] = 0b_100__00000000_00000000_00000010_0__0000000;
            table[9] = 0b_101__00000000_00000000_00000010_1__0000000;
        }
        // after this: 3,9,5,8,7
        let mut ht = BPHT {
            h,
            u: 128,
            table,
            hop_bits_mask: 0b_1111111,
            fingerprint_mask: 0b_11111111_11111111_11111111_10000000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 25,
            key_fp_mask: 0b_00000001_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: false,
        };

        ht.print_ht_fw();
        ht.compact(3);
        ht.print_ht_fw();
        let mut expected_table = vec![0_u64; (128 + h - 1) as usize];
        expected_table[3] = 0b_001__00000000_00000000_00000000_1__0111101;
        expected_table[4] = 0b_010__00000000_00000000_00000001_0__0000001;
        expected_table[5] = 0b_010__00000000_00000000_00000001_0__0000000;
        expected_table[7] = 0b_011__00000000_00000000_00000001_1__0000000;
        expected_table[8] = 0b_100__00000000_00000000_00000010_0__0000000;
        expected_table[6] = 0b_101__00000000_00000000_00000010_1__0000000;
        assert_eq!(ht.table, expected_table,);
    }

    /// Do items before the target address successfully get shifted?
    #[test]
    fn insert_with_back_influence_shift() {
        let h = 4;
        let mut ht = BPHT {
            h,
            u: 16,
            table: vec![
                0,                                             // 0
                0,                                             // 1
                0,                                             // 2
                0b000000_00000000_00000000_00000000_0000_0100, // 3
                0b101010_00000000_00000000_00000010_1010_1101, // 4  <- target address. Has one slot that can be freed by moving entry from 5 to 3
                0b010001_00000000_00000000_00000000_0011_0000, // 5  <- overflow from 3
                0b101011_00000000_00000000_00000010_1011_0000, // 6
                0b101100_00000000_00000000_00000010_1100_0000, // 7
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            hop_bits_mask: 0b_1111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11110000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 28,
            key_fp_mask: 0b_00001111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: false,
        };

        ht.is_valid();
        eprintln!("Compact {:?}", ht.compact(3));
        ht.print_ht();
        ht.insert(0b_0100__0000_00000000_00000000_00101101, 0b_101101)
            .unwrap();
        ht.print_ht();

        ht.is_valid();

        assert_eq!(
            ht.table,
            vec![
                0,                                             // 0
                0,                                             // 1
                0,                                             // 2
                0b010001_00000000_00000000_00000000_0011_0001, // 3
                0b101010_00000000_00000000_00000010_1010_1111, // 4  <- target address. Has one slot that can be freed by moving entry from 5 to 3
                0b101101_00000000_00000000_00000010_1101_0000, // 5
                0b101011_00000000_00000000_00000010_1011_0000, // 6
                0b101100_00000000_00000000_00000010_1100_0000, // 7
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        );
    }

    #[test]
    fn insert_with_long_shift() {
        let h = 4;
        let mut ht = BPHT {
            h,
            u: 16,
            table: vec![
                0b0000011_00000000_00000000_00000000_0011_1011, // 0; address: 0, can't be shifted
                0b0101010_00000000_00000000_00000010_1010_0000, // 1; address: 0, can't be shifted
                0b0011111_00000000_00000000_00000000_0011_0001, // 2; address: 2, can be shifted after 4 is freed  <- this needs to be shifted
                0b0101010_00000000_00000000_00000010_1010_0000, // 3; address: 0, can't be shifted
                0b0010011_00000000_00000000_00000000_0011_0011, // 4; address: 4, can be shifted  <- this will be moved to make room for the content of slot 2
                0b0010001_00000000_00000000_00000000_0011_0000, // 5; address: 4, can be shifted
                0,                                              // 6;
                0,                                              // 7;
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            hop_bits_mask: 0b_1111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11110000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 28,
            key_fp_mask: 0b_00001111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: true,
        };
        ht.print_ht();

        // |addr|fp|
        ht.insert(0b_00000000_00000000_00000000_00110011, 0b_1110111)
            .unwrap();

        ht.print_ht();

        assert_eq!(
            ht.table,
            vec![
                0b0000011_00000000_00000000_00000000_0011_1111, // 0; address: 0
                0b0101010_00000000_00000000_00000010_1010_0000, // 1; address: 0
                0b1110111_00000000_00000000_00000011_0011_0100, // 2; address: 0, can't be shifted  <-  newly inserted item
                0b0101010_00000000_00000000_00000010_1010_0000, // 3; address: 0
                0b0011111_00000000_00000000_00000000_0011_0110, // 4; address: 2, moved into slot opened by address 4
                0b0010001_00000000_00000000_00000000_0011_0000, // 5; address: 4,
                0b0010011_00000000_00000000_00000000_0011_0000, // 6; address: 4, <- shifted here from slot 4
                0,                                              // 7;
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        )
        // NOTE: This test might require a rework.
    }

    #[test]
    fn insert_with_shift_semiautomated() {
        let h = 3;
        let mut ht = BPHT::new(h, 8, true).unwrap();

        // |addr|fp|
        ht.insert(0b_011_00000_00000000_00000000_00001111, 0b_11)
            .unwrap(); // at address 3
        ht.insert(0b_100_00000_00000000_00000000_00001011, 0b_100)
            .unwrap(); // at address 4
        ht.insert(0b_101_00000_00000000_00000000_00001101, 0b_101)
            .unwrap(); // at address 5

        // assert insertions without shifting work fine
        assert_eq!(
            ht.table,
            vec![
                0,                                             // 0
                0,                                             // 1
                0,                                             // 2
                0b000011_00000000_00000000_00000000_01111_001, // 3
                0b000100_00000000_00000000_00000000_01011_001, // 4
                0b000101_00000000_00000000_00000000_01101_001, // 5
                0,                                             // 6
                0,                                             // 7
                0,                                             // 8
                0,                                             // 9
            ],
        );

        ht.is_valid();
        // |addr|fp|
        ht.insert(0b_011_00000_00000000_00000000_00000011, 0b_101010)
            .unwrap(); // at address 3

        assert_eq!(
            ht.table,
            vec![
                0,                                             // 0
                0,                                             // 1
                0,                                             // 2
                0b000011_00000000_00000000_00000000_01111_011, // 3
                0b101010_00000000_00000000_00000000_00011_100, // 4 overflow of 3
                0b000101_00000000_00000000_00000000_01101_001, // 5
                0b000100_00000000_00000000_00000000_01011_000, // 6 shifted from 4
                0,                                             // 7
                0,                                             // 8
                0,                                             // 9
            ],
        );
        ht.is_valid();
    }

    /// test that resizes are not performed, when allow_resize == false
    #[test]
    fn resize_prevention() {
        let h = 4;
        let mut ht = BPHT::new(h, 64, false).unwrap();
        let keys = vec![
            ht.key_from_parts(42, 23),
            ht.key_from_parts(42, 17),
            ht.key_from_parts(42, 13),
            ht.key_from_parts(42, 0),
        ];
        let resizing_key = ht.key_from_parts(42, 4711);

        for key in keys {
            ht.insert(key, 0).unwrap();
        }
        assert!(ht.insert(resizing_key, 0).is_err());
    }

    #[test]
    fn find_offset_to_replace() {
        let h = 4;
        let mut ht = BPHT::new(h, 16, true).unwrap();
        ht.table[0] = 0b_1011;
        assert_eq!(ht.get_hop_bits(0), 0b_1011);

        // this should return f, f, 1, f, since 3 means moving
        // the free spot away instead of towards the target!
        assert_eq!(ht.find_offset_to_replace(0, 0), None);
        assert_eq!(ht.find_offset_to_replace(0, 1), None);
        assert_eq!(ht.find_offset_to_replace(0, 2), Some(0));
        assert_eq!(ht.find_offset_to_replace(0, 3), None);

        ht.table[4] = 0b_0011;
        assert_eq!(ht.get_hop_bits(4), 0b_0011);

        assert_eq!(ht.find_offset_to_replace(4, 0), None);
        assert_eq!(ht.find_offset_to_replace(4, 1), None);
        assert_eq!(ht.find_offset_to_replace(4, 2), Some(0));
        assert_eq!(ht.find_offset_to_replace(4, 3), Some(0));

        ht.table[8] = 0b_0010;
        assert_eq!(ht.get_hop_bits(8), 0b_0010);

        assert_eq!(ht.find_offset_to_replace(8, 0), None);
        assert_eq!(ht.find_offset_to_replace(8, 1), None);
        assert_eq!(ht.find_offset_to_replace(8, 2), Some(1));
        assert_eq!(ht.find_offset_to_replace(8, 3), Some(1));

        // this case should not arise in the first place
        // since the empty slot is as close to the insert
        // point as this address can manage
        ht.table[12] = 0b_1110;
        assert_eq!(ht.get_hop_bits(12), 0b_1110);

        assert_eq!(ht.find_offset_to_replace(12, 0), None);
        assert_eq!(ht.find_offset_to_replace(12, 1), None);
        assert_eq!(ht.find_offset_to_replace(12, 2), None);
        assert_eq!(ht.find_offset_to_replace(12, 3), None);

        // make sure that a page containing no elements never returns Some
        ht.table[16] = 0b_0000;
        assert_eq!(ht.get_hop_bits(16), 0b_0000);

        assert_eq!(ht.find_offset_to_replace(16, 0), None);
        assert_eq!(ht.find_offset_to_replace(16, 1), None);
        assert_eq!(ht.find_offset_to_replace(16, 2), None);
        assert_eq!(ht.find_offset_to_replace(16, 3), None);
        ht.is_valid();
    }

    #[test]
    fn pack_unpack_identity() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for h in 3..16 {
            let ht = BPHT::new(h, 2_usize.pow(18), true).unwrap();

            // generate random keys
            let keys: Vec<u64> = (0..1000)
                .map(|_| rng.gen_range(0, (2_u128.pow(64) - 1) as u64))
                .collect();

            for key in keys {
                let (val, fp, hop) = ht.unpack(key);
                let repacked = ht.pack(val, fp, hop);
                eprintln!("h: {}\nkey:      {:b}\nrepacked: {:b}\n", h, key, repacked);
                assert_eq!(key, repacked);
            }
        }
    }

    #[test]
    fn unset_hop_bits() {
        let h = 4;
        let ht = BPHT::new(h, 2_usize.pow(18), true).unwrap();
        assert_eq!(0b_0000, ht.unset_hop_bit(0b0001, 0));

        assert_eq!(0b_1110, ht.unset_hop_bit(0b1111, 0));
        assert_eq!(0b_1101, ht.unset_hop_bit(0b1111, 1));
        assert_eq!(0b_1011, ht.unset_hop_bit(0b1111, 2));
        assert_eq!(0b_0111, ht.unset_hop_bit(0b1111, 3));

        // 0-bits stay zero
        assert_eq!(0b_1010, ht.unset_hop_bit(0b1010, 0));
    }

    #[test]
    fn resize_crafted() {
        color_backtrace::install();
        let h = 3;
        let u = 8;

        let mut ht = BPHT {
            h,
            u,
            table: vec![
                0,                                             //  0
                0,                                             //  1
                0,                                             //  2
                0,                                             //  3
                0b000001_00000000_00000000_00000000_00001_111, //  4; address: 4  goes to 8
                0b000010_10000000_00000000_00000000_00010_000, //  5; address: 4  goes to 9
                0b000011_00000000_00000000_00000000_00011_110, //  6; address: 4  goes to 8
                0b101010_10000000_00000000_00000010_01010_000, //  7; address: 6  goes to 13
                0b101010_00000000_00000000_00000010_01010_000, //  8; address: 6  gors to 12
                0,
                0, // 10 = u + h - 1 = 8 + 2 - 1
            ],
            hop_bits_mask: 0b_111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11111000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 29,
            key_fp_mask: 0b_00011111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: true,
        };

        let key = ht.key_from_parts(0b100, 0b_11111111_11111111_11111111_11111);
        ht.insert(key, 0b_11111111).unwrap(); // this inserts the value 255 with key 4, triggering a resize

        // Keys in the table are inserted in reverse order.
        // order within multiple copies of a key is preserved
        // since they are removed in hop bit order from proximal to distal
        // and reinserted in the same way
        let expected_ht = BPHT {
            h,
            u: 2 * u,
            table: vec![
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,                                               // 0 - 7
                0b000001_00000000_00000000_00000000_00001_101,   // 8
                0b000010_00000000_00000000_00000000_00010_101,   // 9
                0b000011_00000000_00000000_00000000_00011_000,   // 10
                0b11111111_01111111_11111111_11111111_11111_000, // 11
                0b101010_00000000_00000000_00000010_01010_001,   // 12
                0b101010_00000000_00000000_00000010_01010_001,   // 13
                0,                                               // 14
                0,                                               // 15
                0,                                               // 16
                0,                                               // 17
                0,                                               // 18 = 2u + h - 1 = 16 + 2 - 1
            ],
            hop_bits_mask: 0b_111,
            fingerprint_mask: 0b_11111111_11111111_11111111_11110000,
            fingerprint_shift: h,
            admin_bits: 0b_11111111_11111111_11111111_11111111,
            fp_bits_in_key: 28,
            key_fp_mask: 0b_00001111_11111111_11111111_11111111,
            in_resize: false,
            allow_resize: true,
        };
        ht.is_valid();
        assert_eq!(ht.table, expected_ht.table)
    }

    #[test]
    fn resize_automated() {
        color_backtrace::install();
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for (size_power, h) in iproduct!(5..16, 3..16) {
            eprintln!("Parameter Set: u = 2^{}  h = {}", size_power, h);
            let initial_u = 2_usize.pow(size_power);

            let mut ht = match BPHT::new(h, initial_u, true) {
                Ok(ht) => ht,
                Err(_) => continue, // skip all invalid configurations
            };
            // let mut ht = BPHT::new(h, initial_u);

            // generate somewhat random keys
            // that force the HT into resizing
            // by adding >= h items with identical hash value

            // add as many items as possible without resize
            let mut values: Vec<u32> = (0..=h)
                .map(|_| rng.gen_range(0, (2_u64.pow(32) - 1) as u32))
                .collect();

            // extract the value that will trigger the resize (the last one)
            let overflow_value = values.pop().unwrap();

            // Assemble test keys. Target setup:
            // |0..0aaa|fff0...0| so that the next resize
            // disperses the clumped keys.
            // Shift left until the msb of the largest
            // fp is next to the current  addr|fp interface
            // so that at least on key will be redistributed
            // to a new address after resize
            let address = rng.gen_range(0, ht.u);
            let addr_shift = 32 - size_power;

            let largest_fp = h - 1;
            let largest_fp_bit_length = (largest_fp as f64).log2().floor() as u32;
            let fp_shift = addr_shift - (1 + largest_fp_bit_length);

            // insert keys
            for (fp, _) in values.iter().enumerate() {
                // |old|
                // let key = (fp << size_power) | address;

                // new
                let key = (address << addr_shift) | (fp << fp_shift);

                // ht.insert(key as u32, *value).unwrap();
                ht.insert(key as u32, (fp + 1) as u32).unwrap();
            }

            // ht before resize
            eprintln!("right before resize");
            ht.print_ht_fw();
            // assemble a key that will trigger a resize
            let key = (address << (32 - size_power)) | (2_u32.pow(32 - size_power) - 1) as usize;
            ht.insert(key as u32, overflow_value).unwrap();
            eprintln!("after resize");
            ht.print_ht_fw();

            // test that the table is twice as big (plus the h overflow slots)
            eprintln!(
                "\nht.u: {}\ninitial_u: {}\n2*initial_u: {}\n",
                ht.u,
                initial_u,
                initial_u * 2
            );
            assert_eq!(ht.u, initial_u * 2);
            assert_eq!(ht.table.len(), (initial_u * 2) + h - 1);
            // assert_eq!(values, ht.get(key));

            ht.is_valid();
        }
    }

    #[test]
    fn insert_get_identity_unique_keys_automated() {
        color_backtrace::install();
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut nr_evaluated = 0;
        for (size_power, h) in iproduct!(5..16, 3..16) {
            let initial_u = 2_usize.pow(size_power);

            let mut ht = match BPHT::new(h, initial_u, true) {
                Ok(ht) => {
                    eprintln!(
                        "\n\n\nParameter Set: u = 2^{}  h = {} is valid",
                        size_power, h
                    );
                    nr_evaluated += 1;
                    ht
                }
                Err(_) => {
                    eprintln!(
                        "\n\n\nParameter Set: u = 2^{}  h = {} SKIPPED",
                        size_power, h
                    );
                    continue; // skip all invalid configurations
                }
            };

            // generate somewhat random keys
            // that force the HT into resizing
            // by adding >= h items with identical hash value

            // aim for a number of keys that would fill the initial hash table to 90%
            let n = (0.9 * 2_u32.pow(size_power) as f64) as usize;
            // add as many items as possible without resize
            let keys: HashSet<u32> = (0..n)
                .map(|_| rng.gen_range(0, (2_u64.pow(32) - 1) as u32))
                .collect();

            let values: Vec<u32> = (0..keys.len())
                .map(|_| rng.gen_range(0, (2_u64.pow(32) - 1) as u32))
                .collect();

            for (_step, (key, value)) in keys.iter().zip(values.iter()).enumerate() {
                ht.insert(*key, *value).unwrap();
            }

            for (key, exp_value) in keys.iter().zip(values.iter()) {
                if let Some(value) = ht.get(*key) {
                    assert_eq!(value, vec![*exp_value]);
                } else {
                    eprintln!("\n\n==========================================================================================\n\n");
                    eprintln!(
                        "Error! Could not find a value for key {} with expected value {:b}",
                        key, exp_value
                    );
                    eprintln!("Parameter Set: u = 2^{}  h = {}", size_power, h);
                    let (addr, fp) = ht.split_key(*key);
                    eprintln!("addr: {} fp: {:b}", addr, fp);
                    eprintln!("\n");
                    ht.print_ht_fw();
                    panic!("COULD NOT FIND PREVIOUSLY INSERTED KEY.")
                }
            }
            ht.is_valid();
            assert_eq!(keys.len(), ht.count_total_hop_bits() as usize);
            assert_eq!(keys.len(), ht.nonzero_entries());
        }
        // there are 88 valid parameter combinations that can be evaluated
        // for the parameters iproduct!(5..16, 3..16)
        // assert that they are all visited
        assert_eq!(nr_evaluated, 88);
    }

    #[test]
    fn increment_simple() {
        color_backtrace::install();
        let mut ht = BPHT::new(3, 2_usize.pow(7), true).unwrap();
        let keys = vec![
            0b_0000001_0_00000000_00000000_00000000,
            0b_0000001_0_00000000_00000000_00000000,
            0b_0000001_0_00000000_00000000_00000000,
            0b_0000001_0_00000000_00000000_00000000,
            0b_0000010_0_00000000_00000000_00000000,
            0b_0000010_0_00000000_00000000_00000000,
            0b_0000011_0_00000000_00000000_00000000,
        ];
        for key in keys {
            ht.increment_count(key).unwrap();
        }
        ht.print_ht_fw();
        assert_eq!(
            ht.table[1],
            0b_00000000_00000000_00000000_00000100__00000000_00000000_00000000_00000001
        );
        assert_eq!(
            ht.table[2],
            0b_00000000_00000000_00000000_00000010__00000000_00000000_00000000_00000001
        );
        assert_eq!(
            ht.table[3],
            0b_00000000_00000000_00000000_00000001__00000000_00000000_00000000_00000001
        );
        assert_eq!(ht.table[42], 0);
    }

    #[test]
    fn counting_simple() {
        color_backtrace::install();
        let mut ht = BPHT::new(3, 2_usize.pow(7), true).unwrap();
        let keys = vec![42, 42, 42, 42, 23, 23, 17];
        for key in keys {
            ht.increment_count(key).unwrap();
        }
        ht.print_ht_fw();
        assert_eq!(ht.get_count(42), Some(4));
        assert_eq!(ht.get_count(23), Some(2));
        assert_eq!(ht.get_count(17), Some(1));
        assert!(ht.get_count(0815).is_none());
    }

    /// Test if multiplicities are counter correctly.
    #[test]
    fn counting_automated() {
        color_backtrace::install();
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut nr_evaluated = 0;
        for (size_power, h) in iproduct!(5..16, 3..16) {
            let initial_u = 2_usize.pow(size_power);

            let mut ht = match BPHT::new(h, initial_u, true) {
                Ok(ht) => {
                    eprintln!(
                        "\n\n\nParameter Set: u = 2^{}  h = {} is valid",
                        size_power, h
                    );
                    nr_evaluated += 1;
                    ht
                }
                Err(_) => {
                    eprintln!(
                        "\n\n\nParameter Set: u = 2^{}  h = {} SKIPPED",
                        size_power, h
                    );
                    continue; // skip all invalid configurations
                }
            };

            // aim for a number of keys that would fill the initial hash table to 90%
            let n = (0.5 * 2_u32.pow(size_power) as f64) as usize;
            // add as many items as possible without resize
            let keys: HashSet<u32> = (0..n)
                .map(|_| rng.gen_range(0, (2_u64.pow(32) - 1) as u32))
                .collect();

            let multiplicities: Vec<usize> = (0..n).map(|_| rng.gen_range(1, 100)).collect();

            for (_step, (key, multiplicity)) in keys.iter().zip(multiplicities.iter()).enumerate() {
                for _ in 0..*multiplicity {
                    ht.increment_count(*key).unwrap();
                }
            }

            for (_step, (key, multiplicity)) in keys.iter().zip(multiplicities.iter()).enumerate() {
                assert_eq!(ht.get_count(*key), Some(*multiplicity as u32));
            }
        }
        // there are 88 valid parameter combinations that can be evaluated
        // for the parameters iproduct!(5..16, 3..16)
        // assert that they are all visited
        assert_eq!(nr_evaluated, 88);
    }

    #[test]
    fn insert_delete_empty() {
        // inserts certain number of keys
        // delete them all
        // check that all slots are absolutely empty

        color_backtrace::install();
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut nr_evaluated = 0;
        for (size_power, h) in iproduct!(5..16, 3..16) {
            let initial_u = 2_usize.pow(size_power);

            let mut ht = match BPHT::new(h, initial_u, true) {
                Ok(ht) => {
                    eprintln!(
                        "\n\n\nParameter Set: u = 2^{}  h = {} is valid",
                        size_power, h
                    );
                    nr_evaluated += 1;
                    ht
                }
                Err(_) => {
                    eprintln!(
                        "\n\n\nParameter Set: u = 2^{}  h = {} SKIPPED",
                        size_power, h
                    );
                    continue; // skip all invalid configurations
                }
            };

            // aim for a number of keys that would fill the initial hash table to 90%
            let n = (0.9 * 2_u32.pow(size_power) as f64) as usize;
            // add as many items as possible without resize
            let keys: HashSet<u32> = (0..n)
                .map(|_| rng.gen_range(0, (2_u64.pow(32) - 1) as u32))
                .collect();

            let values: Vec<u32> = (0..keys.len())
                .map(|_| rng.gen_range(0, (2_u64.pow(32) - 1) as u32))
                .collect();

            // insert a certain number of key-value pairs
            for (_step, (key, value)) in keys.iter().zip(values.iter()).enumerate() {
                ht.insert(*key, *value).unwrap();
            }

            // remove all key value pairs
            for key in keys.iter() {
                ht.delete(*key).unwrap();
            }

            // assert that the table is completely empty
            assert_eq!(ht.table, vec![0; ht.u + h - 1]);
        }

        // there are 88 valid parameter combinations that can be evaluated
        // for the parameters iproduct!(5..16, 3..16)
        // assert that they are all visited
        assert_eq!(nr_evaluated, 88);
    }

    #[test]
    fn insert_delete_validity() {
        // inserts certain number of keys
        // delete some of them
        // check if the expected keys are contained and/ or removed

        color_backtrace::install();
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut nr_evaluated = 0;
        for (size_power, h) in iproduct!(5..16, 3..16) {
            let initial_u = 2_usize.pow(size_power);

            let mut ht = match BPHT::new(h, initial_u, true) {
                Ok(ht) => {
                    eprintln!(
                        "\n\n\nParameter Set: u = 2^{}  h = {} is valid",
                        size_power, h
                    );
                    nr_evaluated += 1;
                    ht
                }
                Err(_) => {
                    eprintln!(
                        "\n\n\nParameter Set: u = 2^{}  h = {} SKIPPED",
                        size_power, h
                    );
                    continue; // skip all invalid configurations
                }
            };

            // aim for a number of keys that would fill the initial hash table to 90%
            let n = (0.9 * 2_u32.pow(size_power) as f64) as usize;
            // add as many items as possible without resize
            let keys: HashSet<u32> = (0..n)
                .map(|_| rng.gen_range(0, (2_u64.pow(32) - 1) as u32))
                .collect();

            let mut candidate_keys_to_delete: Vec<&u32> = Vec::from_iter(keys.iter());
            candidate_keys_to_delete.shuffle(&mut rng);

            let values: Vec<u32> = (0..keys.len())
                .map(|_| rng.gen_range(0, (2_u64.pow(32) - 1) as u32))
                .collect();

            let m = rng.gen_range(0, n);

            let keys_to_delete: HashSet<u32> = candidate_keys_to_delete
                .iter()
                .take(m)
                .map(|x| **x)
                .collect();

            let remaining_keys: HashSet<u32> = candidate_keys_to_delete
                .iter()
                .skip(m)
                .map(|x| **x)
                .collect();

            // insert a certain number of key-value pairs
            for (_step, (key, value)) in keys.iter().zip(values.iter()).enumerate() {
                ht.insert(*key, *value).unwrap();
            }

            // remove all key value pairs
            for key in keys_to_delete.iter() {
                ht.delete(*key).unwrap();
            }

            for (key, value) in keys.iter().zip(values.iter()) {
                // assert that the two hash sets are a partition of the keys
                match (keys_to_delete.contains(key), remaining_keys.contains(key)) {
                    (true, true) => {
                        panic!("A key cannot be contained in both deleted and not deleted keys!");
                    }
                    (true, false) => {
                        assert!(ht.get(*key).is_none());
                    }
                    (false, true) => {
                        assert_eq!(ht.get(*key).unwrap(), vec![*value]);
                    }
                    (false, false) => {
                        panic!("A key has to be contained in either deleted or not deleted keys!");
                    }
                }
            }
        }

        // there are 88 valid parameter combinations that can be evaluated
        // for the parameters iproduct!(5..16, 3..16)
        // assert that they are all visited
        assert_eq!(nr_evaluated, 88);
    }

    #[test]
    fn complete_saturation() {
        color_backtrace::install();

        let mut rng = rand::thread_rng();

        let mut nr_evaluated = 0;
        for (size_power, h) in iproduct!(5..16, 3..16) {
            let initial_u = 2_usize.pow(size_power);

            let mut ht = match BPHT::new(h, initial_u, false) {
                Ok(ht) => {
                    eprintln!(
                        "\n\n\nParameter Set: u = 2^{}  h = {} is valid",
                        size_power, h
                    );
                    nr_evaluated += 1;
                    ht
                }
                Err(_) => {
                    eprintln!(
                        "\n\n\nParameter Set: u = 2^{}  h = {} SKIPPED",
                        size_power, h
                    );
                    continue; // skip all invalid configurations
                }
            };

            let mut keys: Vec<u32> = (0..2_u32.pow(size_power))
                .map(|x| x << (32 - size_power))
                .collect();
            keys.shuffle(&mut rng);

            for key in keys.iter() {
                if let Ok(()) = ht.insert(*key, 42) {
                } else {
                    // ht._print_ht_fw();
                    eprintln!("Crashed with fill rate: {}", ht.fill_rate());

                    ht.insert(*key, 42).unwrap();
                    panic!("Overflow")
                };
            }
            eprintln!(
                "Expected fill rate: {}\nGot: {}",
                ht.fill_rate(),
                (initial_u as f64) / ((initial_u as u64 + h as u64 - 1) as f64)
            );
            assert_eq!(
                ht.fill_rate(),
                (initial_u as f64) / (initial_u as u64 + h as u64 - 1) as f64
            );
        }
        // there are 88 valid parameter combinations that can be evaluated
        // for the parameters iproduct!(5..16, 3..16)
        // assert that they are all visited
        assert_eq!(nr_evaluated, 88);
    }
}
