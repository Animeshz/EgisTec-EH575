use flume::Sender;
use std::cmp::max;
use std::fmt;
use std::fmt::Debug;
use std::ops;
use std::ops::Index;
use std::ops::IndexMut;
use std::thread;

#[derive(Copy, Clone, Debug)]
pub struct Coordinate {
    pub x: u8,
    pub y: u8,
}

impl ops::Add<Coordinate> for Coordinate {
    type Output = Coordinate;

    fn add(self, another: Coordinate) -> Self::Output {
        Coordinate {
            x: self.x + another.x,
            y: self.y + another.y,
        }
    }
}

impl ops::Sub<Coordinate> for Coordinate {
    type Output = Coordinate;

    fn sub(self, another: Coordinate) -> Self::Output {
        Coordinate {
            x: self.x - another.x,
            y: self.y - another.y,
        }
    }
}

impl fmt::Display for Coordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Coordinate {{ x: {}, y: {} }}", self.x, self.y)
    }
}

pub type Point = Coordinate;
pub type Dimension = Coordinate;
// pub type IntRectangle = Coordinate;

// Represents a Matrix of T, and GreyscaleImage is [`Matrix<u8>`] sent by the sensor

const IMAGE_DIMENSION: Dimension = Dimension { x: 103, y: 52 };

#[derive(Clone, Debug)]
pub struct Matrix<T: Copy + Debug> {
    pub dimension: Dimension,
    pub data: Box<[T]>,
}

impl<T: Copy + Debug> Matrix<T> {
    pub fn transpose(&self) -> Matrix<T> {
        let mut transpose_data = Vec::with_capacity(self.data.len());
        for i in 0..self.dimension.x {
            for j in 0..self.dimension.y {
                transpose_data.push(self.data[i as usize + j as usize * self.dimension.x as usize]);
            }
        }

        Matrix {
            dimension: self.dimension,
            data: transpose_data.into_boxed_slice(),
        }
    }

    // pub fn block_view(&self, rectangle: IntRectangle) -> {

    // }
}

impl<T: Copy + Debug> Index<Coordinate> for Matrix<T> {
    type Output = T;

    #[inline]
    fn index(&self, coordinate: Coordinate) -> &Self::Output {
        if coordinate.x >= self.dimension.x || coordinate.y >= self.dimension.y {
            panic!("Index out of bounds: the dimensions of matrix is {} but the requested coordinate is {}", self.dimension, coordinate);
        }

        let idx = coordinate.x as usize + coordinate.y as usize * self.dimension.x as usize;
        &self.data[idx]
    }
}

impl<T: Copy + Debug> IndexMut<Coordinate> for Matrix<T> {
    #[inline]
    fn index_mut(&mut self, coordinate: Coordinate) -> &mut Self::Output {
        if coordinate.x >= self.dimension.x || coordinate.y >= self.dimension.y {
            panic!("Index out of bounds: the dimensions of matrix is {} but the requested coordinate is {}", self.dimension, coordinate);
        }

        let idx = coordinate.x as usize + coordinate.y as usize * self.dimension.x as usize;
        &mut self.data[idx]
    }
}

impl<T: Copy + Debug> ops::Index<ops::RangeInclusive<Coordinate>> for Matrix<T> {
    type Output = [T];

    #[inline]
    fn index(&self, index: ops::RangeInclusive<Coordinate>) -> &Self::Output {
        let start = index.start();
        let end = index.end();
        if max(start.x, end.x) >= self.dimension.x || max(start.y, end.y) >= self.dimension.y {
            panic!("Index out of bounds: the dimensions of matrix is {} but the requested coordinates needs from {} to {}", self.dimension, start, end);
        }

        let start_idx = start.x as usize + start.y as usize * self.dimension.x as usize;
        let end_idx = end.x as usize + end.y as usize * self.dimension.x as usize;

        &self.data[start_idx..=end_idx]
    }
}

impl<T: Copy + Debug> ops::IndexMut<ops::RangeInclusive<Coordinate>> for Matrix<T> {
    #[inline]
    fn index_mut(&mut self, index: ops::RangeInclusive<Coordinate>) -> &mut Self::Output {
        let start = index.start();
        let end = index.end();
        if max(start.x, end.x) >= self.dimension.x || max(start.y, end.y) >= self.dimension.y {
            panic!("Index out of bounds: the dimensions of matrix is {} but the requested coordinates needs from {} to {}", self.dimension, start, end);
        }

        let start_idx = start.x as usize + start.y as usize * self.dimension.x as usize;
        let end_idx = end.x as usize + end.y as usize * self.dimension.x as usize;

        &mut self.data[start_idx..=end_idx]
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
