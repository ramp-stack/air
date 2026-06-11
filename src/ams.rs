use std::sync::Arc;
use std::marker::PhantomData;
use std::fmt::Debug;

use std::sync::Mutex;

use arc_swap::ArcSwap;
use postage::broadcast::{channel, Sender, Receiver};
use postage::prelude::{Sink, Stream};

pub enum Ref<'a, T> {
    Arc(PhantomData::<fn(&'a ())>, Arc<T>),
    Map(PhantomData::<fn(&'a ())>, Box<dyn Fn() -> &'a T + Send + Sync + 'a>)
}
impl<'a, T> AsRef<T> for Ref<'a, T> {fn as_ref(&self) -> &T {self}}
impl<'a, T: Debug> std::fmt::Debug for Ref<'a, T> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    (**self).fmt(f)
}}

impl<'a, T> std::ops::Deref for Ref<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {match self {
        Self::Arc(_, arc) => arc.as_ref(),
        Self::Map(_, f) => f()
    }}
}
impl<'a, T: Send + Sync> Ref<'a, T> {
    pub fn map<R>(self, access: impl for<'b> Fn(&'b T) -> &'b R + Sync + Send + 'a) -> Ref<'a, R> {match self {
        Ref::Arc(p, a) => Ref::Map(p, Box::new(move || {
            let r: &R = access(a.as_ref());
            unsafe { &*(r as *const R) }
        })),
        Ref::Map(p, f) => Ref::Map(p, Box::new(move || {
            let r: &R = access(f());
            unsafe { &*(r as *const R) }
        })),
    }}
}

///This is an extension of the arc_swap which allows locking via tokio::sync::Mutex to preform
///concurrent writes keeping the reads lockless. And provides a broadcast system for updates.
///
///Cases where this is slower than possible other systems:
///Locking Reads: We have to create a copy of the data to allow you to edit a version of it while
///not blocking reads. This could have a lot of over head if T::clone() is expensive. Using
///structures from im or im_rc are recommended for large sets where writes are often smaller than half of
///the total structure.
#[derive(Debug, Clone)]
pub struct Ams<T: Clone + Send + Sync, U: Clone + Debug + Send + Sync>(Arc<(Mutex<()>, ArcSwap<T>)>, Sender<U>, Receiver<U>);
impl<T: Clone + Send + Sync, U: Clone + Debug + Send + Sync> Ams<T, U> {
    pub fn new(init: T) -> Self {
        let (tx, rx) = channel(10000);
        Ams(Arc::new((Mutex::new(()), ArcSwap::from(Arc::new(init)))), tx, rx)
    }

    pub fn clear_updates(&mut self) {self.2 = self.1.subscribe();}
    pub fn get_update(&mut self) -> Option<U> {self.2.try_recv().ok()}

    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn listen(&mut self) -> U {
        self.2.recv().await.unwrap()
    }

    ///Warning: Only use this if there is a single writer thread and you want to avoid sending a message,
    ///otherwise use lock/commit to avoid mismatch between update messages and updates themselves
    pub fn store(&self, new: T) {
        self.0.1.store(Arc::new(new));
    }

    pub fn try_lock<E>(&mut self, callback: impl FnOnce(&mut T) -> Result<U, E>, clear: bool) -> Result<U, E> {
        let _lock = self.0.0.lock().unwrap(); 
        let mut t = self.0.1.load_full().as_ref().clone();
        let update = callback(&mut t)?;
        self.1.try_send(update.clone()).unwrap();
        self.0.1.store(Arc::new(t));
        if clear {self.2 = self.1.subscribe();}
        Ok(update)
    }

    pub fn lock(&mut self, callback: impl FnOnce(&mut T) -> U, clear: bool) -> U {
        let _lock = self.0.0.lock().unwrap(); 
        let mut t = self.0.1.load_full().as_ref().clone();
        let update = callback(&mut t);
        self.1.try_send(update.clone()).unwrap();
        self.0.1.store(Arc::new(t));
        if clear {self.2 = self.1.subscribe();}
        update
    }

    ///We reset update channel to head before reading, its possible an update will occure
    ///between clearing the updates and reading the latest version
    pub fn load(&self) -> Ref<'_, T> {
        Ref::Arc(PhantomData::<fn(&'_ ())>, self.0.1.load_full().clone())
    }

    pub fn load_partial<'a, C: Sync>(&'a self, access: impl for<'b> Fn(&'b T) -> &'b C + Sync + Send + 'a) -> Ref<'a, C> {
        let guard = self.0.1.load();
        Ref::Map(PhantomData::<fn(&'a ())>, Box::new(move || {
            let r: &C = access(&**guard);
            unsafe { &*(r as *const C) }
        }))
    }
}
