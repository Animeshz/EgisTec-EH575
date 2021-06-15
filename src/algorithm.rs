use std::cmp::min;
use ordered_float::OrderedFloat;

use crate::{common::{Dimension, GreyscaleImage, Point}, util::noise};

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
            let sum: u32 = image.data.iter().map(|&x| x as u32).sum();
            let avg: f32 = sum as f32 / image.data.len() as f32;
            avg >= 150.
        }).collect();

        filtered_images.sort_by_key(|&img| OrderedFloat(noise(img)));
        let best_image: &GreyscaleImage = &filtered_images[0];

        

        todo!()
    }
}
