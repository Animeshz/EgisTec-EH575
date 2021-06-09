use crate::common::{Dimension, Worker};
use lazy_static::lazy_static;
use std::sync::mpsc::{channel, Receiver, Sender};

lazy_static! {
    // A single-threaded rusb pull worker so that two different thread
    // requesting authentication don't clash in between.
    static ref pull_worker: Worker = Worker::new();
}

const OUT_ENDPOINT: u8 = 0x01;
const IN_ENDPOINT: u8 = 0x82;

#[derive(Debug)]
pub struct Image {
    dimension: Dimension,
    data: Box<[u8]>,
}

pub struct FingerprintCapture {
    pub receiver: Receiver<Image>,
}

impl FingerprintCapture {
    pub fn new() -> Self {
        let (sender, receiver) = channel();

        pull_worker.execute(move || {
            Self::start_pull(sender);
        });

        FingerprintCapture { receiver }
    }

    fn start_pull(send_channel: Sender<Image>) {
        let device = rusb::devices()
            .unwrap()
            .iter()
            .find(|device| {
                let device_desc = device.device_descriptor().unwrap();
                device_desc.vendor_id() == 0x1c7a && device_desc.product_id() == 0x575
            })
            .expect("EgisTec EH575 (1c7a:0575) is not detected on the system!");

        let device_desc = device.device_descriptor().unwrap();

        // println!(
        //     "Bus {:03} Device {:03} ID 0x{:04x}:0x{:04x}",
        //     device.bus_number(),
        //     device.address(),
        //     device_desc.vendor_id(),
        //     device_desc.product_id()
        // );

        let mut fp_handle = match device.open() {
            Ok(v) => v,
            Err(e) => panic!("Cannot open EgisTec EH575 (1c7a:0575). Reason: {}", e),
        };

        // Try detach, if already claimed by a kernel driver.
        if fp_handle.kernel_driver_active(0).unwrap() == true {
            fp_handle.detach_kernel_driver(0).unwrap();
        }
        // Set the only possible configuration (device_desc.num_configurations()), to make sure device is usable.
        fp_handle
            .set_active_configuration(1)
            .expect("Could not set configuration");
        fp_handle
            .claim_interface(0)
            .expect("Could not claim device interface");

        fp_handle.reset().expect("Could not reset device");

        // TODO: Pull the images by sequence and push them to send_channel
    }
}
