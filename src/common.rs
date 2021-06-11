use flume::Sender;
use std::thread;

#[derive(Copy, Clone, Debug)]
pub struct Coordinate {
    pub x: u8,
    pub y: u8,
}

pub type Point = Coordinate;
pub type Dimension = Coordinate;

// Represents an Image sent by the sensor

#[derive(Clone, Debug)]
pub struct Image {
    pub dimension: Dimension,
    pub data: Box<[u8]>,
}

// A single threaded worker, for internal purpose.

type BoxFn<'a> = Box<dyn FnOnce() + Send + 'a>;

pub struct Worker {
    task_send_channel: Sender<BoxFn<'static>>,
}

impl Worker {
    pub fn new() -> Self {
        let (sender, receiver) = flume::unbounded::<BoxFn>();

        thread::spawn(move || {
            for task in receiver.into_iter() {
                task();
            }
        });

        Worker {
            task_send_channel: sender,
        }
    }

    pub fn execute<F>(&self, task: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.task_send_channel
            .send(Box::new(task))
            .expect("Worker::execute unable to send task into queue.");
    }
}
