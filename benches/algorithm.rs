#![feature(test)]

extern crate test;
use egistec_eh575::{
    algorithm::algorithm::{local_orientation_map, normalize},
    common::{Dimension, Matrix},
};
use rand::Rng;
use test::Bencher;

#[bench]
fn bench_normalize(b: &mut Bencher) {
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..5000).map(|_| rng.gen_range(0..255)).collect();

    let mut matrix = Matrix::<u8> {
        dimension: Dimension { x: 100, y: 50 },
        data: data.into_boxed_slice(),
    };

    b.iter(|| {
        normalize(&mut matrix, 160., 4000.);
    });
}

#[bench]
fn bench_local_orientation_map(b: &mut Bencher) {
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..5000).map(|_| rng.gen_range(0..255)).collect();

    let matrix = Matrix::<u8> {
        dimension: Dimension { x: 100, y: 50 },
        data: data.into_boxed_slice(),
    };

    b.iter(|| {
        local_orientation_map(&matrix, 2);
    });
}
