use num::{cast::AsPrimitive, Integer, Num};

use crate::common::{Coordinate, Dimension, Matrix};
use std::{fmt::Debug, iter::Iterator};

/// Convolve `matrix` with the `filter` provided fully, i.e. size(output) = size(matrix) + size(filter) - 1
/// output[x,y] = ΣΣᵢⱼ matrix[x-i,y-j] * filter[i,j]
pub fn convolve2d_full<T, U, V>(matrix: &Matrix<T>, filter: &Matrix<U>) -> Matrix<V>
where
    T: Copy + Debug + Num + AsPrimitive<V>,
    U: Copy + Debug + Num + AsPrimitive<V>,
    V: Copy + Debug + Num + 'static + std::fmt::Display,
{
    let dimension = Dimension {
        x: matrix.dimension.x + filter.dimension.x - 1,
        y: matrix.dimension.y + filter.dimension.y - 1,
    };

    let mut output = Matrix::<V> {
        dimension,
        data: vec![num::zero(); dimension.x as usize * dimension.y as usize].into_boxed_slice(),
    };

    for y in 0..dimension.y {
        for x in 0..dimension.x {
            let sum = &mut output[Coordinate { x, y }];

            for j in 0..filter.dimension.y {
                if !(j > y || y - j >= matrix.dimension.y) {
                    *sum = (0..filter.dimension.x).fold(*sum, |acc, i| {
                        if !(i > x || x - i >= matrix.dimension.x) {
                            acc + matrix[Coordinate { x: x - i, y: y - j }].as_()
                                * filter[Coordinate { x: i, y: j }].as_()
                        } else {
                            acc
                        }
                    });
                }
            }
        }
    }

    output
}

/// Convolve `matrix` with the `filter` provided
/// output[x,y] = ΣΣᵢⱼ matrix[x-i,y-j] * filter[i,j]
pub fn convolve2d_same_sized<T, U, V>(matrix: &Matrix<T>, filter: &Matrix<U>) -> Matrix<V>
where
    T: Copy + Debug + Num + AsPrimitive<V>,
    U: Copy + Debug + Num + AsPrimitive<V>,
    V: Copy + Debug + Num + 'static + std::fmt::Display,
    u8: AsPrimitive<V>,
{
    let mut output = Matrix::<V> {
        dimension: matrix.dimension,
        data: vec![num::zero(); matrix.data.len()].into_boxed_slice(),
    };

    for y in 0..matrix.dimension.y {
        for x in 0..matrix.dimension.x {
            let sum = &mut output[Coordinate { x, y }];

            for j in 0..filter.dimension.y {
                if !(j > y || y - j >= matrix.dimension.y) {
                    *sum = (0..filter.dimension.x).fold(*sum, |acc, i| {
                        if !(i > x || x - i >= matrix.dimension.x) {
                            acc + matrix[Coordinate { x: x - i, y: y - j }].as_()
                                * filter[Coordinate { x: i, y: j }].as_()
                        } else {
                            acc
                        }
                    });
                }
            }
        }
    }

    output
}

#[inline]
pub fn mean<'a, T, V>(data: impl Iterator<Item = &'a T>) -> V
where
    T: Num + AsPrimitive<u64> + 'static,
    V: Copy + 'static,
    f64: AsPrimitive<V>,
{
    let size = data.size_hint().0;
    if size == 0 {
        panic!("Size must be non-zero in order to calculate mean");
    }

    let sum: u64 = data.map(|&x| x.as_()).sum();
    (sum as f64 / size as f64).as_()
}

#[inline]
pub fn variance<'a, T, V>(data: impl Iterator<Item = &'a T>, mean: f64) -> V
where
    T: Num + AsPrimitive<f64> + 'static,
    V: Copy + 'static,
    f64: AsPrimitive<V>,
{
    let size = data.size_hint().0;
    if size == 0 {
        panic!("Size must be non-zero in order to calculate variance");
    }

    let sum_of_deviations: f64 = data
        .map(|&x| x.as_())
        .map(|x| x - mean)
        .map(|x| x * x)
        .sum();
    (sum_of_deviations / size as f64).as_()
}

#[inline(always)]
pub fn ceiling_division<T>(num: T, den: T) -> T
where
    T: Copy + Integer + 'static,
    bool: AsPrimitive<T>,
{
    num / den + (num % den != num::zero()).as_()
}
