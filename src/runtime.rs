use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct Handle {
    pub handle: tokio::runtime::Handle,
    pub watcher: watch::Receiver<Option<bool>>
}
impl Handle {
    pub fn new() -> (Self, watch::Sender<Option<bool>>) {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_time().enable_io().build().unwrap();
        let _guard = runtime.enter();

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

    pub fn spawn<F: Future<Output: Send + 'static> + Send + 'static>(&self, future: F) -> tokio::task::JoinHandle<F::Output> {
        self.handle.spawn(future)
    }
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {self.handle.block_on(future)}
}
