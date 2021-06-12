use std::{
    fs::{self, File},
    path::Path,
    thread,
    time::{Duration, SystemTime},
};

use egistec_eh575::io::FingerprintCapture;
use promptly::{prompt, prompt_default};
use tiff::encoder::{colortype, TiffEncoder};

/// Captures a burst of images
/// and save them to {rootProject}/burst_capture/capture_{num}/xxxx.

fn main() {
    let to_capture = prompt("How many images to capture in a burst").unwrap();
    let delay =
        Duration::from_millis(prompt_default("Delay between captures in milliseconds", 0).unwrap());

    let directory: String = (0u32..)
        .map(|i| format!("burst_capture/{:03x}", i))
        .find(|name| !Path::new(name).exists())
        .unwrap();
    fs::create_dir_all(&directory).expect("Cannot create directory to put the captured images.");

    let capture = FingerprintCapture::new();

    let mut iter_start_time;
    for (i, image) in capture.take(to_capture).enumerate() {
        iter_start_time = SystemTime::now();

        let mut file: File = File::create(directory.clone() + &format!("/{:03}.tiff", i)).unwrap();
        let mut encoder = TiffEncoder::new(&mut file).unwrap();

        encoder
            .write_image::<colortype::Gray8>(
                image.dimension.x.into(),
                image.dimension.y.into(),
                &*image.data,
            )
            .expect("Cannot write image file");

        let iter_end_time = SystemTime::now();
        let iter_duration = iter_end_time.duration_since(iter_start_time).unwrap();
        if delay > iter_duration {
            thread::sleep(delay - iter_duration);
        }
    }
}
