use std::{f64};

use lazy_static::lazy_static;

use crate::common::{Dimension, GreyscaleImage, Matrix};

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
    let sigma = sum as f64 * (0.5 * f64::consts::PI).sqrt() / (6*(image.dimension.x-2)*(image.dimension.y-2)) as f64;
    
    sigma
}

/// Convolve `image` with the `filter` provided
fn convolve2d_full(image: &GreyscaleImage, filter: &Matrix<i8>) -> GreyscaleImage {
    todo!()
}
