use crate::common::{Dimension, Point, Image};

#[derive(Copy, Clone, Debug)]
pub enum MinutiaKind {
    Ending,
    Bifurcation,
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
    pub fn new(image: &Image) -> Self {
        FingerprintFeatures {
            dimension: image.dimension,
            minutiae: Self::extractFeatures(image),
        }
    }

    fn extractFeatures(image: &Image) -> Box<[Minutia]> {
        

        todo!()
    }
}
