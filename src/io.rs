use crate::common::{Dimension, Image};
use hex_literal::hex;
use rusb::{Device, DeviceHandle, GlobalContext};
use std::time::Duration;

const OUT_ENDPOINT: u8 = 0x01;
const IN_ENDPOINT: u8 = 0x82;

pub const INIT_SEQUENCE: [&[u8]; 18] = [
    &hex!("45 47 49 53 60 00 fc"),
    &hex!("45 47 49 53 60 01 fc"),
    &hex!("45 47 49 53 60 40 fc"),
    &hex!("45 47 49 53 63 09 0b 83 24 00 44 0f 08 20 20 01 05 12"),
    &hex!("45 47 49 53 63 26 06 06 60 06 05 2f 06"),
    &hex!("45 47 49 53 61 23 00"),
    &hex!("45 47 49 53 61 24 33"),
    &hex!("45 47 49 53 61 20 00"),
    &hex!("45 47 49 53 61 21 66"),
    &hex!("45 47 49 53 60 00 66"),
    &hex!("45 47 49 53 60 01 66"),
    &hex!("45 47 49 53 63 2c 02 00 57"),
    &hex!("45 47 49 53 60 2d 02"),
    &hex!("45 47 49 53 62 67 03"),
    &hex!("45 47 49 53 60 0f 03"),
    &hex!("45 47 49 53 63 2c 02 00 13"),
    &hex!("45 47 49 53 60 00 02"),
    &hex!("45 47 49 53 64 14 ec"),
];

const REPEAT_SEQUENCE: [&[u8]; 9] = [
    &hex!("45 47 49 53 61 2d 20"),
    &hex!("45 47 49 53 60 00 20"),
    &hex!("45 47 49 53 60 01 20"),
    &hex!("45 47 49 53 63 2c 02 00 57"),
    &hex!("45 47 49 53 60 2d 02"),
    &hex!("45 47 49 53 62 67 03"),
    &hex!("45 47 49 53 63 2c 02 00 13"),
    &hex!("45 47 49 53 60 00 02"),
    &hex!("45 47 49 53 64 14 ec"),
];

/// FingerprintCapture is used to poll fingerprint images from the scanner
pub struct FingerprintCapture {
    /// Device is reference
    device: Device<GlobalContext>,
    device_handle: Option<DeviceHandle<GlobalContext>>,
    first: bool,
    image_holder: [u8; 5356],
}

impl FingerprintCapture {
    /// Creates a new FingerprintCapture object
    ///
    /// The device is identified at this step.
    ///
    /// The device is first opened when first Image is requested by `Iterator::next` on this.
    /// For subsequent `Iterator::next` calls, the opened device is polled for next images.
    pub fn new() -> Self {
        let device = rusb::devices()
            .unwrap()
            .iter()
            .find(|device| {
                let device_desc = device.device_descriptor().unwrap();
                device_desc.vendor_id() == 0x1c7a && device_desc.product_id() == 0x575
            })
            .expect("EgisTec EH575 (1c7a:0575) is not detected on the system!");

        FingerprintCapture {
            device,
            device_handle: None,
            first: true,
            image_holder: [0; 5356],
        }
    }

    /// The first call to `Iterator::next` delegates here.
    /// This opens the device and returns first Image
    /// This also sets the `device_handle` for further image polls.
    fn first(&mut self) -> Option<Image> {
        self.first = false;

        let mut fp_handle = match self.device.open() {
            Ok(v) => v,
            Err(e) => panic!("Cannot open EgisTec EH575 (1c7a:0575). Reason: {}", e),
        };

        // Try detach, if already claimed by a kernel driver.
        // Set the only possible configuration (device_desc.num_configurations()), to make sure device is usable.
        // Claim the only possible interface to receive the images from the scanner.
        if fp_handle.kernel_driver_active(0).unwrap() == true {
            fp_handle.detach_kernel_driver(0).unwrap();
        }
        fp_handle
            .set_active_configuration(1)
            .expect("Could not set configuration");
        fp_handle
            .claim_interface(0)
            .expect("Could not claim device interface");

        fp_handle.reset().expect("Could not reset device");

        for i in 0..INIT_SEQUENCE.len() {
            fp_handle
                .write_bulk(OUT_ENDPOINT, INIT_SEQUENCE[i], Duration::from_nanos(0))
                .expect("Out transfer error");
            fp_handle
                .read_bulk(IN_ENDPOINT, &mut self.image_holder, Duration::from_nanos(0))
                .expect("In transfer error");
        }

        self.device_handle = Some(fp_handle);

        Some(Image {
            dimension: Dimension { x: 103, y: 52 },
            data: Box::new(self.image_holder.clone()),
        })
    }
}

impl Iterator for FingerprintCapture {
    type Item = Image;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            return self.first();
        }

        let fp_handle = self.device_handle.as_ref().unwrap();

        for i in 0..REPEAT_SEQUENCE.len() {
            fp_handle
                .write_bulk(OUT_ENDPOINT, REPEAT_SEQUENCE[i], Duration::from_nanos(0))
                .expect("Out transfer error");
            fp_handle
                .read_bulk(IN_ENDPOINT, &mut self.image_holder, Duration::from_nanos(0))
                .expect("In transfer error");
        }

        Some(Image {
            dimension: Dimension { x: 103, y: 52 },
            data: Box::new(self.image_holder.clone()),
        })
    }
}
