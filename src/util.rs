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
            let sum = output.mut_value_ref_at(Coordinate { x, y }).unwrap();
            let mut indices: Vec<Option<&u8>> = vec![None; filter.dimension.x as usize];

            for j in 0..filter.dimension.y {
                let ind0 = y as i16 - j as i16;

                // Simplify by borrowing indices directly from Image/Matrix<u8>
                if ind0 < 0 || ind0 >= image.dimension.y as i16 {
                    for k in 0..filter.dimension.x {
                        indices[k as usize] = None;
                    }
                } else {
                    for k in 0..filter.dimension.x {
                        let ind1 = x as i16 - k as i16;
                        if ind1 < 0 || ind1 >= image.dimension.x as i16 {
                            indices[k as usize] = None;
                        } else {
                            indices[k as usize] = match image.value_ref_at(Coordinate { x: ind1 as u8, y: ind0 as u8 }) {
                                Some(pixel) => Some(&*pixel),
                                None => None,
                            };
                        }
                    }
                }

                let mut dsum = *sum;
                for k in 0..filter.dimension.x {
                    let tmp = *filter.value_ref_at(Coordinate { x: k, y: j }).unwrap();
                    let x = match indices[k as usize] {
                        Some(&x) => x,
                        None => 0,
                    };
                    dsum += tmp as i16 * x as i16;
                }
                *sum = dsum;
            }
        }
    }

    output
}
