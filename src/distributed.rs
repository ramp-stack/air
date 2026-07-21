use crate::storage::{Request, Response};
use crate::channel::{Channel, Location, Midstate, Item};
use crate::names::{Resolver, Secret, Name};

use serde::{Serialize, Deserialize};

use std::collections::VecDeque;
use std::hash::Hash;
use std::fmt::Debug;

pub trait Change {
    fn merge(&mut self, other: Self);
}

pub trait Distributable: Hash + Default {
    type Message: Serialize + for<'a> Deserialize<'a> + Clone + Debug + Hash + Eq;
    type Change: Change;

    fn apply(&mut self, me: &Name, queue: &mut VecDeque<Self::Message>, message: Event<Self::Message>) -> Self::Change;
}

pub enum Event<M> {
    Pending(M),
    ConfirmedPending(M, u64),
    NewConfirmed(M, u64, Name),
    EmptyResponse(u64),
}

pub struct Distributed<D: Distributable>(Channel<D::Message>, VecDeque<D::Message>, D, Name);
impl<D: Distributable> Distributed<D> {
    pub fn new(me: Name, location: Location) -> Self {
        Distributed(Channel::new(location), VecDeque::default(), D::default(), me)
    }

    pub fn apply(&mut self, message: D::Message) -> D::Change {
        self.1.push_back(message.clone());
        self.2.apply(&self.3, &mut self.1, Event::Pending(message))
    }

    pub fn request(&self, secret: &Secret) -> (Midstate, Request) {
        self.0.request(secret, self.1.front())
    }

    pub async fn response<R: Resolver>(&mut self, resolver: &mut R, midstate: &Midstate, response: Response) -> D::Change {
        self.0.response(resolver, midstate, response).await.into_iter().fold(None, |c, item| {
            let event = match item {
                Item::Created(time) => Event::ConfirmedPending(self.1.pop_front().unwrap(), time),
                Item::Received(time, name, msg) => Event::NewConfirmed(msg, time, name),
                Item::Empty(time) => Event::EmptyResponse(time)
            };
            let mut change = self.2.apply(&self.3, &mut self.1, event);
            if let Some(c) = c {change.merge(c)}
            Some(change)
        }).unwrap()
    }
}
