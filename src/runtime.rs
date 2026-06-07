use tokio::sync::watch;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Handle {
    pub handle: tokio::runtime::Handle,
    pub watcher: watch::Receiver<Option<bool>>
}
impl Handle {
    pub fn new() -> (Self, watch::Sender<Option<bool>>) {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
        let guard = runtime.enter();

        let (tx, mut watcher) = watch::channel(Some(true));
        let handle = Handle{handle: runtime.handle().clone(), watcher: watcher.clone()};

        std::thread::spawn(move || {
            runtime.block_on(async move {
                loop {
                    if watcher.changed().await.is_ok()
                    && watcher.borrow_and_update().is_none() {
                        return;
                    }
                }
            })
        });
        (handle, tx)
    }

    pub fn spawn_task<T: FnMut() -> F + Send + 'static, F: Future<Output = Option<Duration>> + Send + 'static>(&self, mut task: T) {
        let mut handle = self.clone();
        self.handle.spawn(async move { loop {
            while !handle.watcher.borrow_and_update().unwrap_or_default() {
                if handle.watcher.changed().await.is_ok() {return;}
                if handle.watcher.borrow_and_update().is_none() {return;}
                continue;
            }

            match task().await {
                Some(duration) => tokio::time::sleep(duration).await,
                None => {return;}
            }
        }});
    }

    pub fn spawn<F: Future<Output: Send + 'static> + Send + 'static>(&self, future: F) -> tokio::task::JoinHandle<F::Output> {
        self.handle.spawn(future)
    }
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {self.handle.block_on(future)}
}
