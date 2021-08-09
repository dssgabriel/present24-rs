use std::thread;
use std::sync::{ Arc, Mutex, mpsc };

mod utils;
mod encrypt;
mod decrypt;
pub mod attack;

type Job = Box<dyn FnOnce() + Send + 'static>;

enum Task {
    NewJob(Job),
    Terminate,
}

struct Worker {
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    fn new(receiver: Arc<Mutex<mpsc::Receiver<Task>>>) -> Self {
        let thread = thread::spawn(move || loop {
            let task = receiver
                .lock()
                .expect("Failed to take the lock")
                .recv()
                .expect("Could not receive the message");

            match task {
                Task::NewJob(job) => job(),
                Task::Terminate => break,
            }
        });

        Worker { thread: Some(thread) }
    }
}

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: mpsc::Sender<Task>,
}

impl ThreadPool {
    pub fn new(size: usize) -> Self {
        assert!(size > 0);

        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));

        let mut workers = Vec::with_capacity(size);
        for _ in 0..size {
            workers.push(Worker::new(Arc::clone(&receiver)));
        }

        ThreadPool {
            workers,
            sender,
        }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        self.sender.send(Task::NewJob(job)).expect("Failed to send new job");
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        for _ in &self.workers {
            self.sender.send(Task::Terminate).expect("Failed to send terminate signal");
        }

        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                thread.join().expect("Failed to join the thread");
            }
        }
    }
}
