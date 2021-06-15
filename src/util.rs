use std::f64;

use lazy_static::lazy_static;

use crate::common::{Coordinate, Dimension, GreyscaleImage, Matrix};

lazy_static! {
    static ref LAPLACIAN_OPERATOR: Matrix<i8> = Matrix {
        dimension: Dimension { x: 3, y: 3 },
        data: Box::new([1, -2, 1, -2, 4, -2, 1, -2, 1]),
    };
}

/// Calculates standard variance of noise in the given Image
/// Ref: https://stackoverflow.com/a/25436112/11377112
pub fn noise(image: &GreyscaleImage) -> f64 {
    let supressed_image = convolve2d_full(image, &LAPLACIAN_OPERATOR);

    let sum: u32 = supressed_image.data.iter().map(|&x| x as u32).sum();
    let sigma = sum as f64 * (0.5 * f64::consts::PI).sqrt()
        / (6 * (image.dimension.x - 2) * (image.dimension.y - 2)) as f64;

    sigma
}

/// Convolve `image` with the `filter` provided
/// output[x,y] = ΣΣᵢⱼ image[x-i,y-j] * filter[i,j]
fn convolve2d_full(image: &GreyscaleImage, filter: &Matrix<i8>) -> Matrix<i16> {
    let dimension = Dimension {
        x: image.dimension.x + filter.dimension.x - 1,
        y: image.dimension.y + filter.dimension.y - 1,
    };

    let mut output = Matrix::<i16> {
        dimension,
        data: vec![0; dimension.x as usize * dimension.y as usize].into_boxed_slice(),
    };

    for y in 0..dimension.y {
        for x in 0..dimension.x {
            let sum = &mut output[Coordinate { x, y }];

            for j in 0..filter.dimension.y {
                if !(j > y || y - j >= image.dimension.y) {
                    *sum = (0..filter.dimension.x).fold(*sum, |acc, i| {
                        if !(i < x || x - i >= image.dimension.x) {
                            acc + image[Coordinate { x: x - i, y: y - j }] as i16
                                * filter[Coordinate { x: i, y: j }] as i16
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
