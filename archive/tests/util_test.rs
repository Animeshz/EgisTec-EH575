#[cfg(test)]
mod util_test {
    use egistec_eh575::common::{Dimension, GreyscaleImage, Matrix};
    use egistec_eh575::util::{convolve2d_full};
    use egistec_eh575::algorithm::algorithm;
    use std::fs::File;
    use tiff::decoder::{Decoder, DecodingResult};

    macro_rules! assert_delta {
        ($x:expr, $y:expr, $d:expr) => {
            if !($x - $y < $d || $y - $x < $d) {
                panic!();
            }
        };
    }

    #[test]
    fn convolve2d_full_test() {
        let a = Matrix::<u8> {
            dimension: Dimension { x: 3, y: 2 },
            data: Box::new([1, 2, 3, 3, 4, 5]),
        };
        let b = Matrix::<i8> {
            dimension: Dimension { x: 3, y: 2 },
            data: Box::new([2, 3, 4, 4, 5, 6]),
        };
        let result = Matrix::<i32> {
            dimension: Dimension { x: 5, y: 3 },
            data: Box::new([2, 7, 16, 17, 12, 10, 30, 62, 58, 38, 12, 31, 58, 49, 30]),
        };
        let calculated = convolve2d_full(&a, &b);
        assert_eq!(calculated.data, result.data);
    }

    #[test]
    fn noise_test() {
        let file: File = File::open("resources/test/register/1.tiff").unwrap();
        let mut decoder = Decoder::new(file).unwrap();
        if let DecodingResult::U8(image_data) = decoder.read_image().unwrap() {
            let image = GreyscaleImage::new(image_data.into_boxed_slice());

            let noise = algorithm::noise(&image);
            assert_delta!(noise, 5.066, 0.01);
        }
    }
}
