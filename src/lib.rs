// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! Implementation of [libsodium's `randombytes`]
//! (https://download.libsodium.org/doc/advanced/custom_rng.html) which allows a seeded pseudorandom
//! number generator (PRNG) to be used.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/sodiumoxide_extras")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]
#![cfg_attr(feature="clippy", allow(single_match))]

#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate rand;
#[cfg(test)]
extern crate sodiumoxide;
#[macro_use]
extern crate unwrap;

use std::cell::RefCell;
use std::ffi::CString;
use std::rc::Rc;
use std::sync::Mutex;

use rand::{Rng, SeedableRng, XorShiftRng};

lazy_static! {
    static ref INIT_RESULT: Mutex<Option<i32>> = Mutex::new(None);
    static ref RANDOM_BYTES_IMPL: Mutex<RandomBytesImpl> = Mutex::new(RandomBytesImpl::default());
}

thread_local!(static RNG: Rc<RefCell<XorShiftRng>> =
    Rc::new(RefCell::new(XorShiftRng::from_seed(unwrap!(RANDOM_BYTES_IMPL.lock()).seed))));

struct RandomBytesImpl {
    function_pointers: ffi::FunctionPointers,
    name: CString,
    seed: [u32; 4],
}

impl Default for RandomBytesImpl {
    fn default() -> RandomBytesImpl {
        let seed = [rand::random(), rand::random(), rand::random(), rand::random()];
        RandomBytesImpl {
            function_pointers: ffi::FunctionPointers::default(),
            name: unwrap!(CString::new("Rust XorShiftRng")),
            seed: seed,
        }
    }
}

mod ffi {
    use libc::{c_char, c_int, c_void, size_t, uint32_t};
    use rand::Rng;

    #[repr(C)]
    pub struct FunctionPointers {
        implementation_name: extern "C" fn() -> *const c_char,
        random: extern "C" fn() -> uint32_t,
        stir: Option<extern "C" fn()>,
        uniform: Option<extern "C" fn(upper_bound: uint32_t) -> uint32_t>,
        buf: extern "C" fn(buf: *mut c_void, size: size_t),
        close: Option<extern "C" fn() -> c_int>,
    }

    impl Default for FunctionPointers {
        fn default() -> FunctionPointers {
            FunctionPointers {
                implementation_name: implementation_name,
                random: random,
                stir: None,
                uniform: None,
                buf: buf,
                close: None,
            }
        }
    }

    #[link(name="sodium")]
    extern "C" {
        pub fn randombytes_set_implementation(function_pointers: *mut FunctionPointers) -> c_int;
        pub fn sodium_init() -> c_int;
    }

    extern "C" fn implementation_name() -> *const c_char {
        unwrap!(super::RANDOM_BYTES_IMPL.lock()).name.as_ptr()
    }

    extern "C" fn random() -> uint32_t {
        super::RNG.with(|rng| rng.borrow_mut().gen())
    }

    #[cfg_attr(feature="clippy", allow(cast_possible_wrap))]
    #[allow(unsafe_code)]
    extern "C" fn buf(buf: *mut c_void, size: size_t) {
        unsafe {
            let ptr = buf as *mut u8;
            let rng_ptr = super::RNG.with(|rng| rng.clone());
            let rng = &mut *rng_ptr.borrow_mut();
            for i in 0..size {
                *ptr.offset(i as isize) = rng.gen();
            }
        }
    }
}

/// Sets [libsodium `randombytes`](https://download.libsodium.org/doc/advanced/custom_rng.html) to
/// use a seeded PRNG implementation and initialises libsodium.
///
/// This function is safe to call multiple times concurrently from different threads.  It will
/// either always return `Ok` or will always return `Err`.
///
/// The error will contain either `-1` or `1`.  If the error is `-1`, the initialisation of
/// libsodium has failed.  If the error is `1`, libsodium has been successfully initialised
/// elsewhere (e.g. via [`sodiumoxide::init()`]
/// (http://dnaq.github.io/sodiumoxide/sodiumoxide/fn.init.html)) but this means that our attempt to
/// apply this seeded RNG to libsodium has not been actioned.
///
/// Each sodiumoxide function which uses the random generator in a new thread will cause a new
/// thread-local instance of the PRNG to be created.  Each such instance will be seeded with the
/// same value, meaning for example that two newly-spawned threads calling `box_::gen_keypair()`
/// will generate identical keys.
#[allow(unsafe_code)]
pub fn init_with_rng<T: Rng>(rng: &mut T) -> Result<(), i32> {
    let seed = [rng.gen(), rng.gen(), rng.gen(), rng.gen()];
    let mut init_result = &mut *unwrap!(INIT_RESULT.lock());
    if let Some(ref existing_result) = *init_result {
        return if *existing_result == 0 {
            Ok(RNG.with(|rng| *rng.borrow_mut() = XorShiftRng::from_seed(seed)))
        } else {
            Err(*existing_result)
        };
    }
    let mut sodium_result;
    {
        let random_bytes = &mut *unwrap!(RANDOM_BYTES_IMPL.lock());
        random_bytes.seed = seed;
        sodium_result =
            unsafe { ffi::randombytes_set_implementation(&mut random_bytes.function_pointers) };
    }
    match sodium_result {
        0 => sodium_result = unsafe { ffi::sodium_init() },
        _ => (),
    };
    // Since `ffi::sodium_init()` makes a call to `buf()`, reset the thread-local `RNG` so that it
    // yields consistent results with calls from new threads.
    RNG.with(|rng| *rng.borrow_mut() = XorShiftRng::from_seed(seed));
    *init_result = Some(sodium_result);
    match sodium_result {
        0 => Ok(()),
        result => Err(result),
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::Builder;
    use rand::{SeedableRng, XorShiftRng};
    use sodiumoxide::crypto::box_;

    #[test]
    fn seeded() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3]);
        unwrap!(init_with_rng(&mut rng));

        // Initialise again - should succeed.
        unwrap!(init_with_rng(&mut rng));

        let expected_public_key = [116, 196, 172, 118, 77, 124, 253, 254, 156, 51, 141, 193, 20,
                                   160, 227, 232, 231, 20, 24, 151, 207, 45, 202, 250, 85, 96,
                                   206, 144, 170, 185, 192, 101];
        let expected_private_key = [24, 74, 130, 137, 89, 75, 193, 8, 153, 136, 7, 141, 220, 198,
                                    207, 232, 228, 74, 189, 36, 9, 209, 239, 95, 69, 207, 163, 2,
                                    37, 237, 255, 64];
        let (public_key, private_key) = box_::gen_keypair();
        assert_eq!(expected_public_key, public_key.0);
        assert_eq!(expected_private_key, private_key.0);

        let child1 = unwrap!(Builder::new().name("child1".to_string()).spawn(move || {
            let (public_key, private_key) = box_::gen_keypair();
            assert_eq!(expected_public_key, public_key.0);
            assert_eq!(expected_private_key, private_key.0);
        }));
        let child2 = unwrap!(Builder::new().name("child2".to_string()).spawn(move || {
            let (public_key, private_key) = box_::gen_keypair();
            assert_eq!(expected_public_key, public_key.0);
            assert_eq!(expected_private_key, private_key.0);
        }));
        unwrap!(child1.join());
        unwrap!(child2.join());
    }
}
