use std::sync::Arc;
use std::fmt::Debug;
use std::borrow::Borrow;
use std::ops::Index;
use std::marker::PhantomData;
use std::collections::HashSet;
use std::sync::{MutexGuard, Mutex};

//use tokio::sync::broadcast::{channel, Sender, Receiver};
use postage::broadcast::{channel, Sender, Receiver};
use postage::prelude::{Sink, Stream};
use arc_swap::ArcSwap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

type Inner<T> = (T, u32);
type Guard<T> = arc_swap::Guard<Arc<Inner<T>>, arc_swap::DefaultStrategy>;

pub enum Ref<'a, T> {
    Arc(Guard<T>, PhantomData::<&'a ()>),
    #[allow(clippy::type_complexity)]
    Map(Arc<Box<dyn for<'b> Fn(&'b ()) -> &'b T + Send + Sync>>, PhantomData::<&'a ()>)
}
impl<'a, T: Send + Sync + 'static> Ref<'a, T> {
    pub fn new(arc: Guard<T>) -> Self {Ref::Arc(arc, PhantomData::<&'a ()>)}
    pub fn map<R>(self, access: impl for<'b> Fn(&'b T) -> &'b R + Sync + Send + 'static) -> Ref<'a, R> {match self {
        Ref::Arc(a, p) => Ref::Map(Arc::new(Box::new(move |_: &()| {
            let r: &R = access(&a.as_ref().0);
            unsafe { &*(r as *const R) }
        })), p),
        Ref::Map(f, p) => Ref::Map(Arc::new(Box::new(move |t: &()| {
            let r: &R = access(f(t));
            unsafe { &*(r as *const R) }
        })), p),
    }}
}
impl<'a, T> AsRef<T> for Ref<'a, T> {fn as_ref(&self) -> &T {self}}
impl<'a, T: Debug> Debug for Ref<'a, T> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {(**self).fmt(f)}}
impl<'a, T> std::ops::Deref for Ref<'a, T> {type Target = T; fn deref(&self) -> &T {match self {Self::Arc(arc, _) => &arc.as_ref().0, Self::Map(f, _) => f(&())}}}
impl<'a, T> Clone for Ref<'a, T> {fn clone(&self) -> Self {match self {Ref::Arc(a, p) => Ref::Arc(Guard::from_inner(Arc::clone(a)), *p), Ref::Map(f, p) => Ref::Map(f.clone(), *p)}}}

pub struct RefMut<'a, T, U>(T, u32, MutexGuard<'a, ()>, &'a ArcSwap<Inner<T>>, &'a mut Sender<(U, u32)>);
impl<'a, T, U: Clone + Debug> RefMut<'a, T, U> {
    pub fn commit(mut self, update: U) {
        let idx = self.1+1;
        self.4.try_send((update, idx)).unwrap();
        self.3.store(Arc::new((self.0, idx)));
        drop(self.2);
    }
}
impl<'a, T: Debug, U> Debug for RefMut<'a, T, U> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {self.0.fmt(f)}}
impl<'a, T, U> std::ops::Deref for RefMut<'a, T, U> {type Target = T; fn deref(&self) -> &T {&self.0}}
impl<'a, T, U> std::ops::DerefMut for RefMut<'a, T, U> {fn deref_mut(&mut self) -> &mut T {&mut self.0}}

pub trait Change: Debug + Clone + Send + Sync {
    fn merge(&mut self, other: Self);
}

impl<C: Debug + Clone + Send + Sync> Change for Vec<C> {
    fn merge(&mut self, other: Self) {self.extend(other);}
}


//Single writer handle but clonable reader handle
//Notifications and request/response for reader handle to write thread

#[derive(Clone, Debug)]
pub struct Shared<T: Clone + Send + Sync, C: Change>{
    #[allow(clippy::type_complexity)]
    locker: Arc<Mutex<()>>,
    shared: Arc<ArcSwap<(T, u32)>>,
    sender: Sender<(C, u32)>,
    receiver: Receiver<(C, u32)>,
    changed: (Option<C>, u32)
}
impl<T: Clone + Send + Sync + 'static, U: Update> Ams<T, U> {
    pub fn new(init: T) -> Self {
        let (sender, receiver) = channel(10000);
        Ams{
            locker: Arc::new(Mutex::new(())),
            shared: Arc::new(ArcSwap::from(Arc::new((init, 0)))),
            sender,
            receiver,
            seen: 0
        }
    }

    pub fn load(&self) -> (Ref<'_, T>, Option<C>) {

    }

    pub fn load_change(&mut self) -> Option<(Ref<'_, T>, U)> {
        loop {
            let (update, index) = self.receiver.try_recv().ok()?;
            if index > self.seen {break Some(self.merge(update, index));}
        }
    }

    pub async fn load_on_change(&mut self) -> (Ref<'_, T>, U) {
        loop {
            let (update, index) = self.receiver.recv().await.unwrap();
            if index > self.seen {break self.merge(update, index);}
        }
    }

    fn merge(&mut self, mut update: U, mut index: u32) -> (Ref<'_, T>, U) {
        let guard = self.shared.load();
        let seen = guard.1;
        while index < seen {
            let (u, i) = self.receiver.try_recv().ok().unwrap();
            index = i;
            update.merge(u);
        }
        (Ref::new(guard), update)
    }

    pub fn lock(&mut self, clear: bool) -> RefMut<'_, T, U> {
        let guard = self.locker.lock().unwrap(); 
        let g = self.shared.load();
        if clear {self.seen = g.1;}
        RefMut(g.0.clone(), g.1, guard, &self.shared, &mut self.sender)
    }

    pub fn load(&self) -> Ref<'_, T> {Ref::new(self.shared.load())}
    pub fn load_clear(&mut self) -> Ref<'_, T> {
        let guard = self.shared.load();
        self.seen = guard.1;
        Ref::new(guard)
    }
}
//  impl<'a, K, V, T: Index<&'a Q> + Extend<(K, V)> + Clone + Send + Sync + 'static, U: Update> Ams<T, U> {
//      pub fn get_or_insert_with<F: FnOnce() -> V>(key: K, insert_with: F) -> &V {
//          self.load().
//      }
//  }


impl<T: Clone + Send + Sync, U: Update> PartialEq for Ams<T, U> {fn eq(&self, other: &Self) -> bool {Arc::ptr_eq(&self.shared, &other.shared)}}
impl<T: Default + Clone + Send + Sync + 'static, U: Update> Default for Ams<T, U> {fn default() -> Self {Self::new(T::default())}}
impl<T: Serialize + Clone + Send + Sync, U: Update> Serialize for Ams<T, U> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {self.shared.load().serialize(serializer)}
}
impl<'de, T: Deserialize<'de> + Clone + Send + Sync + 'static, U: Update> Deserialize<'de> for Ams<T, U> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {Ok(Ams::new(T::deserialize(deserializer)?))}
}

#[cfg(test)]
mod test {
    use super::Ams;

    #[test]
    fn test() {
        let mut a = Ams::<Vec<String>, Vec<usize>>::new(vec![]);
        let mut lock = a.lock(false);
        lock.push("Hello".to_string());
        lock.commit(vec![5]);

        assert_eq!(a.load_change().map(|i| ((*i.0).clone(), i.1)), Some((vec!["Hello".to_string()], vec![5])));

        let mut b = a.clone();
        let mut lock = b.lock(false);
        lock.push("Hi".to_string());
        lock.commit(vec![2]);

        assert_eq!(a.load_change().map(|i| ((*i.0).clone(), i.1)), Some((vec!["Hello".to_string(), "Hi".to_string()], vec![2])));

        let mut lock = b.lock(false);
        lock.push("Hey".to_string());
        lock.commit(vec![3]);
        assert_eq!(b.load_change().map(|i| ((*i.0).clone(), i.1)), Some((vec!["Hello".to_string(), "Hi".to_string(), "Hey".to_string()], vec![2, 3])));

      //let mut lock = b.lock();
      //lock.push("Whispers Goodbye".to_string());
      //lock.commit_silent();

      //assert_eq!(a.get_update(), None);
    }
}

#[derive(Clone, Debug)]
pub struct Cache {}


























































