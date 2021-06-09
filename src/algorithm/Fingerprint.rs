use crate::common::{Dimension, Point};

#[derive(Debug)]
enum MinutiaType {
    Ending,
    Bifurcation
}

#[derive(Debug)]
struct Minutia {
    position: Point,
    direction: f64, // In radians
    typ: MinutiaType
}

#[derive(Debug)]
struct Fingerprint {
    dimension: Dimension,
    minutae: Box<[Minutia]>,
}
