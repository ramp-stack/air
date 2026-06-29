use std::sync::Arc;
use std::fmt::Debug;

use std::sync::Mutex;
use std::sync::MutexGuard;

use arc_swap::ArcSwap;
use postage::broadcast::{channel, Sender, Receiver};
use postage::prelude::{Sink, Stream};

pub enum Ref<T> {
    Arc(Arc<T>),
    Map(Box<dyn for<'a> Fn(&'a ()) -> &'a T + Send + Sync>)
}
impl<T> AsRef<T> for Ref<T> {fn as_ref(&self) -> &T {self}}
impl<T: Debug> std::fmt::Debug for Ref<T> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    (**self).fmt(f)
}}

impl<T> std::ops::Deref for Ref<T> {
    type Target = T;
    fn deref(&self) -> &T {match self {
        Self::Arc(arc) => arc.as_ref(),
        Self::Map(f) => f(&())
    }}
}
impl<T: Send + Sync + 'static> Ref<T> {
    pub fn map<R>(self, access: impl for<'a> Fn(&'a T) -> &'a R + Sync + Send + 'static) -> Ref<R> {match self {
        Ref::Arc(a) => Ref::Map(Box::new(move |_: &()| {
            let r: &R = access(a.as_ref());
            unsafe { &*(r as *const R) }
        })),
        Ref::Map(f) => Ref::Map(Box::new(move |t: &()| {
            let r: &R = access(f(t));
            unsafe { &*(r as *const R) }
            
        })),
    }}
}

pub struct RefMut<'a, T, U>(MutexGuard<'a, Sender<U>>, T, &'a ArcSwap<T>);
impl<'a, T, U: Clone + Debug> RefMut<'a, T, U> {
    ///If commit is not called then the changes made will be discarded
    pub fn commit(mut self, update: U) {
        self.2.store(Arc::new(self.1));
        self.0.try_send(update).unwrap();
        drop(self.0);
    }
}
impl<'a, T, U> std::ops::Deref for RefMut<'a, T, U> {
    type Target = T;
    fn deref(&self) -> &T {&self.1}
}
impl<'a, T, U> std::ops::DerefMut for RefMut<'a, T, U> {
    fn deref_mut(&mut self) -> &mut T {&mut self.1}
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
pub struct Ams<T: Clone + Send + Sync, U: Clone + Debug + Send + Sync>(Arc<(Mutex<Sender<U>>, ArcSwap<T>)>, Receiver<U>);
impl<T: Clone + Send + Sync, U: Clone + Debug + Send + Sync> PartialEq for Ams<T, U> {
    fn eq(&self, other: &Self) -> bool {Arc::ptr_eq(&self.0, &other.0)}
}
impl<T: Clone + Send + Sync + 'static, U: Clone + Debug + Send + Sync> Ams<T, U> {
    pub fn new(init: T) -> Self {
        let (tx, rx) = channel(10000);
        Ams(Arc::new((Mutex::new(tx), ArcSwap::from(Arc::new(init)))), rx)
    }

    pub fn clear_updates(&mut self) {self.1 = self.0.0.lock().unwrap().subscribe();}
    pub fn get_update(&mut self) -> Option<U> {self.1.try_recv().ok()}

    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn listen(&mut self) -> U {
        self.1.recv().await.unwrap()
    }

    ///Warning: Only use this if there is a single writer thread and you want to avoid sending a message,
    ///otherwise use lock/commit to avoid mismatch between update messages and updates themselves
    pub fn store(&self, new: T) {
        self.0.1.store(Arc::new(new));
    }

    pub fn lock(&self) -> RefMut<'_, T, U> {
        let guard = self.0.0.lock().unwrap(); 
        RefMut(guard, self.0.1.load_full().as_ref().clone(), &self.0.1)
    }

    pub fn load(&self) -> Ref<T> {Ref::Arc(self.0.1.load_full().clone())}

    pub fn load_partial<C: Sync>(&self, access: impl for<'a> Fn(&'a T) -> &'a C + Sync + Send + 'static) -> Ref<C> {
        let arc = self.0.1.load_full().clone();
        Ref::Map(Box::new(move |_: &()| {
            let r: &C = access(arc.as_ref());
            unsafe { &*(r as *const C) }
        }))
    }
}
