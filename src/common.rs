use flume::Sender;
use std::thread;

#[derive(Copy, Clone, Debug)]
pub struct Coordinate {
    pub x: u8,
    pub y: u8,
}

pub type Point = Coordinate;
pub type Dimension = Coordinate;

// Represents a Matrix of T, and GreyscaleImage is [`Matrix<u8>`] sent by the sensor

const IMAGE_DIMENSION: Dimension = Dimension { x: 103, y: 52 };

#[derive(Clone, Debug)]
pub struct Matrix<T: Copy> {
    pub dimension: Dimension,
    pub data: Box<[T]>,
}

impl<T: Copy> Matrix<T> {
    pub fn value_at(&self, coordinate: Coordinate) -> Option<T> {
        if coordinate.x >= IMAGE_DIMENSION.x || coordinate.y >= IMAGE_DIMENSION.y {
            return None;
        }

        let idx = coordinate.x as usize + coordinate.y as usize * IMAGE_DIMENSION.y as usize;
        Some(self.data[idx])
    }
}

pub type GreyscaleImage = Matrix<u8>;

impl GreyscaleImage {
    pub fn new(data: Box<[u8]>) -> Self {
        GreyscaleImage {
            dimension: IMAGE_DIMENSION,
            data,
        }
    }
}

// A single threaded worker, for internal purpose.

pub type BoxFn<'a> = Box<dyn FnOnce() + Send + 'a>;

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
