#![feature(test)]

extern crate test;
use egistec_eh575::{
    algorithm::algorithm::LAPLACIAN_OPERATOR,
    common::{Dimension, Matrix},
    util::convolve2d_full,
};
use rand::Rng;
use test::Bencher;

#[bench]
fn bench_convolve2d_full(b: &mut Bencher) {
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..5000).map(|_| rng.gen_range(0..255)).collect();

    let matrix = Matrix::<u8> {
        dimension: Dimension { x: 100, y: 50 },
        data: data.into_boxed_slice(),
    };

    b.iter(|| {
        let _output: Matrix<i32> = convolve2d_full(&matrix, &LAPLACIAN_OPERATOR);
    });
}
