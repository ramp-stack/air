use std::sync::Arc;
use std::fmt::Debug;
use std::collections::HashSet;
use std::sync::{MutexGuard, Mutex};

use tokio::sync::broadcast::{channel, Sender, Receiver};
use arc_swap::ArcSwap;

pub enum Ref<T> {
    Arc(Arc<(T, u32)>),
    Map(Box<dyn for<'a> Fn(&'a ()) -> &'a T + Send + Sync>)
}
impl<T> AsRef<T> for Ref<T> {fn as_ref(&self) -> &T {self}}
impl<T: Debug> std::fmt::Debug for Ref<T> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    (**self).fmt(f)
}}

impl<T> std::ops::Deref for Ref<T> {
    type Target = T;
    fn deref(&self) -> &T {match self {
        Self::Arc(arc) => &arc.as_ref().0,
        Self::Map(f) => f(&())
    }}
}
impl<T: Send + Sync + 'static> Ref<T> {
    pub fn map<R>(self, access: impl for<'a> Fn(&'a T) -> &'a R + Sync + Send + 'static) -> Ref<R> {match self {
        Ref::Arc(a) => Ref::Map(Box::new(move |_: &()| {
            let r: &R = access(&a.as_ref().0);
            unsafe { &*(r as *const R) }
        })),
        Ref::Map(f) => Ref::Map(Box::new(move |t: &()| {
            let r: &R = access(f(t));
            unsafe { &*(r as *const R) }
            
        })),
    }}
}

pub struct RefMut<'a, T, U>(MutexGuard<'a, (Sender<(U, u32)>, u32)>, T, &'a ArcSwap<(T, u32)>, &'a mut HashSet<u32>);
impl<'a, T: Debug, U: Clone + Debug> std::fmt::Debug for RefMut<'a, T, U> {fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    self.1.fmt(f)
}}
impl<'a, T, U: Clone + Debug> RefMut<'a, T, U> {
    ///If commit is not called then the changes made will be discarded
    pub fn commit(mut self, update: U) {
        self.0.1 += 1;
        let idx = self.0.1;
        self.0.0.send((update, idx)).unwrap();
        self.2.store(Arc::new((self.1, idx)));
        self.3.insert(idx);
        drop(self.0);
    }

    pub fn commit_silent(mut self) {
        self.0.1 += 1;
        let idx = self.0.1;
        self.2.store(Arc::new((self.1, idx)));
        self.3.insert(idx);
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

#[derive(Debug)]
pub struct Ams<T: Clone + Send + Sync, U: Clone + Debug + Send + Sync>{
    #[allow(clippy::type_complexity)]
    sender: Arc<(Mutex<(Sender<(U, u32)>, u32)>, ArcSwap<(T, u32)>)>,
    receiver: Receiver<(U, u32)>,
    sent: HashSet<u32>,
    seen: u32
}
impl<T: Clone + Send + Sync, U: Clone + Debug + Send + Sync> Clone for Ams<T, U> {fn clone(&self) -> Self {
    Ams{sender: self.sender.clone(), receiver: self.receiver.resubscribe(), sent: self.sent.clone(), seen: self.seen}
}}
impl<T: Clone + Send + Sync, U: Clone + Debug + Send + Sync> PartialEq for Ams<T, U> {
    fn eq(&self, other: &Self) -> bool {Arc::ptr_eq(&self.sender, &other.sender)}
}
impl<T: Clone + Send + Sync + 'static, U: Clone + Debug + Send + Sync> Ams<T, U> {
    pub fn new(init: T) -> Self {
        let (tx, receiver) = channel(10000);
        Ams{
            sender: Arc::new((Mutex::new((tx, 0)), ArcSwap::from(Arc::new((init, 0))))),
            receiver, sent: HashSet::new(), seen: 0
        }
    }

    pub fn get_update(&mut self) -> Option<U> {
        loop {
            let (data, idx) = self.receiver.try_recv().ok()?;
            if idx > self.seen && !self.sent.contains(&idx) {
                self.seen = self.seen.max(idx);
                break Some(data);
            }
        }
    }
    pub async fn listen(&mut self) -> U {
        loop {
            let (data, idx) = self.receiver.recv().await.unwrap();
            if idx > self.seen && !self.sent.contains(&idx) {
                self.seen = self.seen.max(idx);
                break data;
            }
        }
    }

    pub fn lock(&mut self) -> RefMut<'_, T, U> {
        let guard = self.sender.0.lock().unwrap(); 
        self.receiver = self.receiver.resubscribe();
        let arc = self.sender.1.load_full().clone();
        self.seen = arc.1;
        RefMut(guard, arc.0.clone(), &self.sender.1, &mut self.sent)
    }

    pub fn load(&mut self) -> Ref<T> {Ref::Arc(self.load_inner())}

    pub fn load_partial<C: Sync>(&mut self, access: impl for<'a> Fn(&'a T) -> &'a C + Sync + Send + 'static) -> Ref<C> {
        let arc = self.load_inner();
        Ref::Map(Box::new(move |_: &()| {
            let r: &C = access(&arc.as_ref().0);
            unsafe { &*(r as *const C) }
        }))
    }

    fn load_inner(&mut self) -> Arc<(T, u32)> {
        self.receiver = self.receiver.resubscribe();
        let arc = self.sender.1.load_full().clone();
        self.seen = arc.1;
        arc
    }
}

#[cfg(test)]
mod test {
    use super::Ams;

    #[test]
    fn test() {
        let mut a = Ams::<Vec<String>, usize>::new(vec![]);
        let mut lock = a.lock();
        lock.push("Hello".to_string());
        lock.commit(5);

        assert_eq!(a.get_update(), None);
        assert_eq!(*a.load(), vec!["Hello".to_string()]);

        let mut b = a.clone();
        let mut lock = b.lock();
        lock.push("Hi".to_string());
        lock.commit(2);

        assert_eq!(a.get_update(), Some(2));
        assert_eq!(*a.load(), vec!["Hello".to_string(), "Hi".to_string()]);
        assert_eq!(*b.load(), vec!["Hello".to_string(), "Hi".to_string()]);

        let mut lock = b.lock();
        lock.push("Whispers Goodbye".to_string());
        lock.commit_silent();

        assert_eq!(a.get_update(), None);
    }
}
