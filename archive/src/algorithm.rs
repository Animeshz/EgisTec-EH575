use ordered_float::OrderedFloat;

use crate::{
    common::{Dimension, GreyscaleImage, Point},
    util::mean,
};

#[derive(Copy, Clone, Debug)]
pub enum MinutiaKind {
    Ending,
    Bifurcation,
    Enclosure,
    Intersection,
}

#[derive(Clone, Debug)]
pub struct Minutia {
    position: Point,
    direction: f64, // In radians
    kind: MinutiaKind,
}

#[derive(Clone, Debug)]
pub struct FingerprintFeatures {
    dimension: Dimension,
    minutiae: Box<[Minutia]>,
}

impl FingerprintFeatures {
    /// Extracts features from burst of images selecting best ones
    /// automatically by rejection based on threshold lightining and
    /// image selection based on minimum noise in image by [`LAPLACIAN_OPERATOR`].
    pub fn extract_features(images: &[GreyscaleImage]) -> Option<FingerprintFeatures> {
        // Filter up too dark image
        let mut filtered_images: Vec<&GreyscaleImage> = images
            .iter()
            .filter(|&image| {
                let mean: f32 = mean(image.data.iter());
                mean >= 150.
            })
            .collect();

        filtered_images.sort_by_key(|&img| OrderedFloat(algorithm::noise(img)));

        // If more than 25% of image has noise > 8.0, it means finger was moving and possibly very less details in further images
        if algorithm::noise(filtered_images[3 * filtered_images.len() / 4]) > 8. {
            return None;
        }

        // Will most probably run single time as long as there's no empty blocks (13x13)
        for i in 0..filtered_images.len() {
            let mut selected_image: GreyscaleImage = filtered_images[i].clone();

            if !algorithm::all_blocks_have_fingerprint(&selected_image) {
                continue;
            }

            algorithm::normalize(&mut selected_image, 160., 4000.);
            let _local_orientation_map = algorithm::local_orientation_map(&selected_image, 2);
        }

        todo!()
    }
}

pub mod algorithm {
    use core::f32;
    use std::{cmp::max, usize};

    use crate::{
        common::{Coordinate, Dimension, GreyscaleImage, Matrix},
        util::{convolve2d_full, convolve2d_same_sized, mean, variance},
    };
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref LAPLACIAN_OPERATOR: Matrix<i8> = Matrix {
            dimension: Dimension { x: 3, y: 3 },
            data: Box::new([1, -2, 1, -2, 4, -2, 1, -2, 1]),
        };
        pub static ref SOBEL_OPERATOR_X: Matrix<i8> = Matrix {
            dimension: Dimension { x: 3, y: 3 },
            data: Box::new([-1, 0, 1, -2, 0, 2, -1, 0, 1]),
        };
        pub static ref SOBEL_OPERATOR_Y: Matrix<i8> = SOBEL_OPERATOR_X.transpose();
    }

    /// Constructs a Gaussian operator for convulsion
    pub fn gaussian_operator(size: u8) -> Matrix<f32> {
        let mut data = Vec::with_capacity((size as usize).pow(2));

        // https://stackoverflow.com/a/62002971/11377112
        let sigma_squared = max(1, ((size - 1) / 6).pow(2));
        let sigma_squared = f32::from(sigma_squared);

        // For loops not allowed in `const fn`
        for x in 0..size {
            for y in 0..size {
                data.push(
                    1. / (2. * f32::consts::PI * sigma_squared)
                        * ((-f32::from(x * x + y * y) / (2. * sigma_squared)).exp()),
                );
            }
        }

        Matrix {
            dimension: Dimension { x: size, y: size },
            data: data.into_boxed_slice(),
        }
    }

    /// Calculates standard variance of noise in the given Image.
    /// sigma = Σ|supressed_image[i,j]| * sqrt(pi/2) / (6 * w-2 * h-2)
    /// Ref: https://stackoverflow.com/a/25436112/11377112
    pub fn noise(image: &GreyscaleImage) -> f32 {
        let supressed_image: Matrix<i32> = convolve2d_full(image, &LAPLACIAN_OPERATOR);

        let sum: u32 = supressed_image.data.iter().map(|&x| x.abs() as u32).sum();
        let sigma = sum as f32 * (0.5 * f32::consts::PI).sqrt()
            / (6 * (image.dimension.x - 2) as u32 * (image.dimension.y - 2) as u32) as f32;

        sigma
    }

    /// Checks if all the blocks have fingerprint or not.
    pub fn all_blocks_have_fingerprint(_image: &GreyscaleImage) -> bool {
        todo!()
    }

    /// Normalizes image to `desired_mean` and `desired_variance`.
    /// `normalized_image[i,j] = desired_mean +- sqrt(desired_variance * (image[i,j] - original_mean)^2 / original_variance)`
    pub fn normalize(image: &mut GreyscaleImage, desired_mean: f64, desired_variance: f64) {
        let original_mean: f64 = mean(image.data.iter());
        let original_variance: f64 = variance(image.data.iter(), original_mean);

        for pixel in image.data.as_mut() {
            let pixel_value = *pixel as f64;
            let deviation = pixel_value - original_mean;
            let deviation_coefficient =
                (desired_variance * deviation * deviation / original_variance).sqrt();

            *pixel = if pixel_value > desired_mean {
                desired_mean + deviation_coefficient
            } else {
                desired_mean - deviation_coefficient
            } as u8;
        }
    }

    /// Extracts orientation of each local pixel
    /// direction_x = supressed cos(tan-1(ΣΣ 2 * supressed_image_x * supressed_image_y))
    /// direction_y = supressed sin(tan-1(ΣΣ supressed_image_x^2 + supressed_image_y^2))
    /// angle[i,j] = 1/2 * tan-1 (direction_y/direction_x)

    pub fn local_orientation_map(image: &GreyscaleImage, ridge_width: u8) -> Matrix<f32> {
        let half_ridge_width = ridge_width / 2;

        let gradient_x: Matrix<i32> = convolve2d_full(image, &SOBEL_OPERATOR_X);
        let gradient_y: Matrix<i32> = convolve2d_full(image, &SOBEL_OPERATOR_Y);

        let mut direction_x = Matrix::<f64> {
            dimension: image.dimension,
            data: vec![0.; image.data.len()].into_boxed_slice(),
        };
        let mut direction_y = direction_x.clone();

        let gradient_starting_dimension = Dimension {
            x: (SOBEL_OPERATOR_X.dimension.x - 1) / 2,
            y: (SOBEL_OPERATOR_X.dimension.y - 1) / 2,
        };

        // Grab directions
        for y in 0..image.dimension.y {
            for x in 0..image.dimension.x {
                let mut sum_x = 0;
                let mut sum_y = 0;

                let gd_x_start = gradient_starting_dimension.x + x;
                let gd_y_start = gradient_starting_dimension.y + y;
                for j in gd_y_start - half_ridge_width..=gd_y_start + half_ridge_width {
                    if !(j > y || y - j >= gradient_y.dimension.y) {
                        for i in gd_x_start - half_ridge_width..=gd_x_start + half_ridge_width {
                            if !(i > x || x - i >= gradient_x.dimension.x) {
                                let gx = gradient_x[Coordinate { x: i, y: j }];
                                let gy = gradient_y[Coordinate { x: i, y: j }];

                                sum_x += 2 * gx * gy;
                                sum_y += gx * gx - gy * gy;
                            }
                        }
                    }
                }

                direction_x[Coordinate { x, y }] = f64::from(sum_x).atan().cos();
                direction_y[Coordinate { x, y }] = f64::from(sum_y).atan().sin();
            }
        }

        // Smoothen directions
        let guassian_operator = &gaussian_operator(5);
        let direction_x: Matrix<f32> = convolve2d_same_sized(&direction_x, guassian_operator);
        let direction_y: Matrix<f32> = convolve2d_same_sized(&direction_y, guassian_operator);

        let mut angles: Vec<f32> = Vec::with_capacity(image.data.len());
        for i in 0..image.data.len() {
            angles.push(0.5 * (direction_x.data[i] / direction_y.data[i]).atan())
        }

        Matrix {
            dimension: image.dimension,
            data: angles.into_boxed_slice(),
        }
    }
}
