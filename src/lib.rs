//! An implementation of the FIPS-202-defined SHA-3 and SHAKE functions.
//!
//! The `Keccak-f[1600]` permutation is fully unrolled; it's nearly as fast
//! as the Keccak team's optimized permutation.
//!
//! ## Building
//!
//! ```bash
//! cargo build
//! ```
//!
//! ## Usage
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! tiny-keccak = "1.0"
//! ```
//!
//! and this to your crate root:
//!
//! ```rust
//! extern crate tiny_keccak;
//! ```
//!
//! Original implemntation in C:
//! https://github.com/coruus/keccak-tiny
//!
//! Implementor: David Leon Gil
//!
//! Port to rust:
//! Marek Kotewicz (marek.kotewicz@gmail.com)
//!
//! License: CC0, attribution kindly requested. Blame taken too,
//! but not liability.

#![no_std]
#![feature(const_fn, const_let)]

#[macro_use]
extern crate crunchy;

const RHO: [u32; 24] = [
     1,  3,  6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44
];

const PI: [usize; 24] = [
    10,  7, 11, 17, 18, 3,
     5, 16,  8, 21, 24, 4,
    15, 23, 19, 13, 12, 2,
    20, 14, 22,  9,  6, 1
];

const RC: [u64; 24] = [
    1u64, 0x8082u64, 0x800000000000808au64, 0x8000000080008000u64,
    0x808bu64, 0x80000001u64, 0x8000000080008081u64, 0x8000000000008009u64,
    0x8au64, 0x88u64, 0x80008009u64, 0x8000000au64,
    0x8000808bu64, 0x800000000000008bu64, 0x8000000000008089u64, 0x8000000000008003u64,
    0x8000000000008002u64, 0x8000000000000080u64, 0x800au64, 0x800000008000000au64,
    0x8000000080008081u64, 0x8000000000008080u64, 0x80000001u64, 0x8000000080008008u64
];

#[allow(unused_assignments)]
/// keccak-f[1600]
pub fn keccakf(a: &mut [u64; PLEN]) {
    for i in 0..24 {
        let mut array: [u64; 5] = [0; 5];

        // Theta
        unroll! {
            for x in 0..5 {
                unroll! {
                    for y_count in 0..5 {
                        let y = y_count * 5;
                        array[x] ^= a[x + y];
                    }
                }
            }
        }

        unroll! {
            for x in 0..5 {
                unroll! {
                    for y_count in 0..5 {
                        let y = y_count * 5;
                        a[y + x] ^= array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
                    }
                }
            }
        }

        // Rho and pi
        let mut last = a[1];
        unroll! {
            for x in 0..24 {
                array[0] = a[PI[x]];
                a[PI[x]] = last.rotate_left(RHO[x]);
                last = array[0];
            }
        }

        // Chi
        unroll! {
            for y_step in 0..5 {
                let y = y_step * 5;

                unroll! {
                    for x in 0..5 {
                        array[x] = a[y + x];
                    }
                }

                unroll! {
                    for x in 0..5 {
                        a[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
                    }
                }
            }
        };

        // Iota
        a[0] ^= RC[i];
    }
}

/// `const fn` to set the `n`th element of a `[T; 5]`, returning the new array.
/// We can't mutate arrays in-place in constant functions but we can assign
/// new values to mutable variables, this is a hack to get around that.
const fn set5<T: Copy>(arr: [T; 5], n: usize, v: T) -> [T; 5] {
    let arrays = [
        [v, arr[1], arr[2], arr[3], arr[4]],
        [arr[0], v, arr[2], arr[3], arr[4]],
        [arr[0], arr[1], v, arr[3], arr[4]],
        [arr[0], arr[1], arr[2], v, arr[4]],
        [arr[0], arr[1], arr[2], arr[3], v],
    ];

    arrays[n]
}

/// `const fn` to set the `n`th element of a `[T; 25]`, returning the new array.
/// We can't mutate arrays in-place in constant functions but we can assign
/// new values to mutable variables, this is a hack to get around that.
const fn set25<T: Copy>(arr: [T; 25], n: usize, v: T) -> [T; 25] {
    let arrays = [
        [
            v, arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9], arr[10],
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], v, arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9], arr[10],
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], v, arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9], arr[10],
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], v, arr[4], arr[5], arr[6], arr[7], arr[8], arr[9], arr[10],
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], v, arr[5], arr[6], arr[7], arr[8], arr[9], arr[10],
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], v, arr[6], arr[7], arr[8], arr[9], arr[10],
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], v, arr[7], arr[8], arr[9], arr[10],
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], v, arr[8], arr[9], arr[10],
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], v, arr[9], arr[10],
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], v, arr[10],
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9], v,
            arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], v, arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], v, arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], v, arr[14], arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], v, arr[15], arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], arr[14], v, arr[16], arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], arr[14], arr[15], v, arr[17], arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], v, arr[18], arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], v, arr[19],
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18], v,
            arr[20], arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18],
            arr[19], v, arr[21], arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18],
            arr[19], arr[20], v, arr[22], arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18],
            arr[19], arr[20], arr[21], v, arr[23], arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18],
            arr[19], arr[20], arr[21], arr[22], v, arr[24],
        ],
        [
            arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9],
            arr[10], arr[11], arr[12], arr[13], arr[14], arr[15], arr[16], arr[17], arr[18],
            arr[19], arr[20], arr[21], arr[22], arr[23], v,
        ],
    ];

    arrays[n]
}

const fn rotate_left(a: u64, n: u32) -> u64 {
    const BITS: u32 = 64;

    // Protect against undefined behaviour for over-long bit shifts
    let n = n % BITS;
    (a << n) | (a >> ((BITS - n) % BITS))
}

#[allow(unused_assignments)]
/// keccak-f[1600]
pub const fn keccakf_const(mut a: [u64; PLEN]) -> [u64; PLEN] {
    unroll! {
        for i in 0..24 {
            let mut array: [u64; 5] = [0; 5];

            // Theta
            unroll! {
                for x in 0..5 {
                    unroll! {
                        for y_count in 0..5 {
                            let y = y_count * 5;
                            array = set5(array, x, array[x] ^ a[x + y]);
                        }
                    }
                }
            }

            unroll! {
                for x in 0..5 {
                    unroll! {
                        for y_count in 0..5 {
                            let y = y_count * 5;
                            a = set25(a, y + x, a[y + x] ^ array[(x + 4) % 5] ^ rotate_left(array[(x + 1) % 5], 1));
                        }
                    }
                }
            }

            // Rho and pi
            let mut last = a[1];
            unroll! {
                for x in 0..24 {
                    array = set5(array, 0, a[PI[x]]);
                    a = set25(a, PI[x], rotate_left(last, RHO[x]));
                    last = array[0];
                }
            }

            // Chi
            unroll! {
                for y_step in 0..5 {
                    let y = y_step * 5;

                    unroll! {
                        for x in 0..5 {
                            array = set5(array, x, a[y + x]);
                        }
                    }

                    unroll! {
                        for x in 0..5 {
                            a = set25(a, y + x, array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5])));
                        }
                    }
                }
            };

            // Iota
            a = set25(a, 0, a[0] ^ RC[i]);
        }
    }

    a
}

fn setout(src: &[u8], dst: &mut [u8], len: usize) {
    dst[..len].copy_from_slice(&src[..len]);
}

fn xorin(dst: &mut [u8], src: &[u8]) {
    assert!(dst.len() <= src.len());
    let len = dst.len();
    let mut dst_ptr = dst.as_mut_ptr();
    let mut src_ptr = src.as_ptr();
    for _ in 0..len {
        unsafe {
            *dst_ptr ^= *src_ptr;
            src_ptr = src_ptr.offset(1);
            dst_ptr = dst_ptr.offset(1);
        }
    }
}

/// Total number of lanes.
const PLEN: usize = 25;

/// This structure should be used to create keccak/sha3 hash.
///
/// ```rust
/// extern crate tiny_keccak;
/// use tiny_keccak::Keccak;
///
/// fn main() {
///     let mut sha3 = Keccak::new_sha3_256();
///     let data: Vec<u8> = From::from("hello");
///     let data2: Vec<u8> = From::from("world");
///
///     sha3.update(&data);
///     sha3.update(&[b' ']);
///     sha3.update(&data2);
///
///     let mut res: [u8; 32] = [0; 32];
///     sha3.finalize(&mut res);
///
///     let expected = vec![
///         0x64, 0x4b, 0xcc, 0x7e, 0x56, 0x43, 0x73, 0x04,
///         0x09, 0x99, 0xaa, 0xc8, 0x9e, 0x76, 0x22, 0xf3,
///         0xca, 0x71, 0xfb, 0xa1, 0xd9, 0x72, 0xfd, 0x94,
///         0xa3, 0x1c, 0x3b, 0xfb, 0xf2, 0x4e, 0x39, 0x38
///     ];
///
///     let ref_ex: &[u8] = &expected;
///     assert_eq!(&res, ref_ex);
/// }
/// ```
pub struct Keccak<K: KeccakParams = RuntimeKeccakParams> {
    a: [u64; PLEN],
    offset: usize,
    params: K,
}

pub trait KeccakParams {
    fn rate(&self) -> usize;
    fn delim(&self) -> u8;
}

pub struct RuntimeKeccakParams {
    rate: usize,
    delim: u8,
}

impl KeccakParams for RuntimeKeccakParams {
    #[inline(always)]
    fn rate(&self) -> usize {
        self.rate
    }

    #[inline(always)]
    fn delim(&self) -> u8 {
        self.delim
    }
}

impl<K: KeccakParams + Clone> Clone for Keccak<K> {
    fn clone(&self) -> Self {
        let mut res = Keccak::with_params(self.params.clone());
        res.a.copy_from_slice(&self.a);
        res.offset = self.offset;
        res
    }
}

macro_rules! impl_constructor {
    ($params_name:ident, $name:ident, $alias:ident, $bits:expr, $delim:expr) => {
        #[derive(Debug, Copy, Clone)]
        pub struct $params_name;

        impl KeccakParams for $params_name {
            #[inline(always)]
            fn rate(&self) -> usize {
                200 - $bits / 4
            }

            #[inline(always)]
            fn delim(&self) -> u8 {
                $delim
            }
        }

        impl Keccak<$params_name> {
            pub fn $name() -> Self {
                Keccak::with_params($params_name)
            }
    
            pub fn $alias(data: &[u8], result: &mut [u8]) {
                let mut keccak = Keccak::$name();
                keccak.update(data);
                keccak.finalize(result);
            }
        }
    };
}

macro_rules! impl_global_alias {
    ($alias:ident, $size:expr) => {
        pub fn $alias(data: &[u8]) -> [u8; $size / 8] {
            let mut result = [0u8; $size / 8];
            Keccak::$alias(data, &mut result);
            result
        }
    };
}

impl_global_alias!(shake128, 128);
impl_global_alias!(shake256, 256);
impl_global_alias!(keccak224, 224);
impl_global_alias!(keccak256, 256);
impl_global_alias!(keccak384, 384);
impl_global_alias!(keccak512, 512);
impl_global_alias!(sha3_224, 224);
impl_global_alias!(sha3_256, 256);
impl_global_alias!(sha3_384, 384);
impl_global_alias!(sha3_512, 512);

impl Keccak {
    pub fn new(rate: usize, delim: u8) -> Keccak {
        Self::with_params(RuntimeKeccakParams { rate, delim })
    }
}

impl_constructor!(ShakeParams128, new_shake128, shake128, 128, 0x1f);
impl_constructor!(ShakeParams256, new_shake256, shake256, 256, 0x1f);
impl_constructor!(KeccakParams224, new_keccak224, keccak224, 224, 0x01);
impl_constructor!(KeccakParams256, new_keccak256, keccak256, 256, 0x01);
impl_constructor!(KeccakParams384, new_keccak384, keccak384, 384, 0x01);
impl_constructor!(KeccakParams512, new_keccak512, keccak512, 512, 0x01);
impl_constructor!(Sha3Params224, new_sha3_224, sha3_224, 224, 0x06);
impl_constructor!(Sha3Params256, new_sha3_256, sha3_256, 256, 0x06);
impl_constructor!(Sha3Params384, new_sha3_384, sha3_384, 384, 0x06);
impl_constructor!(Sha3Params512, new_sha3_512, sha3_512, 512, 0x06);

impl<K: KeccakParams> Keccak<K> {
    pub fn with_params(params: K) -> Self {
        Keccak {
            a: [0; PLEN],
            offset: 0,
            params,
        }
    }

    fn a_bytes(&self) -> &[u8; PLEN * 8] {
        unsafe { ::core::mem::transmute(&self.a) }
    }

    fn a_mut_bytes(&mut self) -> &mut [u8; PLEN * 8] {
        unsafe { ::core::mem::transmute(&mut self.a) }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.absorb(input);
    }

    #[inline]
    pub fn keccakf(&mut self) {
        keccakf(&mut self.a);
    }

    pub fn finalize(mut self, output: &mut [u8]) {
        self.pad();

        // apply keccakf
        keccakf(&mut self.a);

        // squeeze output
        self.squeeze(output);
    }

    // Absorb input
    pub fn absorb(&mut self, input: &[u8]) {
        //first foldp
        let mut ip = 0;
        let mut l = input.len();
        let mut rate = self.params.rate() - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            xorin(&mut self.a_mut_bytes()[offset..][..rate], &input[ip..]);
            keccakf(&mut self.a);
            ip += rate;
            l -= rate;
            rate = self.params.rate();
            offset = 0;
        }

        // Xor in the last block
        xorin(&mut self.a_mut_bytes()[offset..][..l], &input[ip..]);
        self.offset = offset + l;
    }

    pub fn pad(&mut self) {
        let offset = self.offset;
        let rate = self.params.rate();
        let delim = self.params.delim();
        let aa = self.a_mut_bytes();
        aa[offset] ^= delim;
        aa[rate - 1] ^= 0x80;
    }

    pub fn fill_block(&mut self) {
        self.keccakf();
        self.offset = 0;
    }

    // squeeze output
    pub fn squeeze(&mut self, output: &mut [u8]) {
        // second foldp
        let mut op = 0;
        let mut l = output.len();
        while l >= self.params.rate() {
            setout(self.a_bytes(), &mut output[op..], self.params.rate());
            keccakf(&mut self.a);
            op += self.params.rate();
            l -= self.params.rate();
        }

        setout(self.a_bytes(), &mut output[op..], l);
    }

    #[inline]
    pub fn xof(mut self) -> XofReader<K> {
        self.pad();

        keccakf(&mut self.a);

        XofReader {
            keccak: self,
            offset: 0,
        }
    }
}

pub struct XofReader<K: KeccakParams = RuntimeKeccakParams> {
    keccak: Keccak<K>,
    offset: usize,
}

impl<K: KeccakParams> XofReader<K> {
    pub fn squeeze(&mut self, output: &mut [u8]) {
        // second foldp
        let mut op = 0;
        let mut l = output.len();
        let mut rate = self.keccak.params.rate() - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            setout(&self.keccak.a_bytes()[offset..], &mut output[op..], rate);
            self.keccak.keccakf();
            op += rate;
            l -= rate;
            rate = self.keccak.params.rate();
            offset = 0;
        }

        setout(&self.keccak.a_bytes()[offset..], &mut output[op..], l);
        self.offset = offset + l;
    }
}
