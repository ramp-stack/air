use crate::names::{Secret, Encrypted, Name, Id, Resolver, Error, now};
use crate::names::secp256k1::{SecretKey, PublicKey, Signed};
use crate::storage::{Request, Response};
use crate::channel::{self, Channel, Location};
use crate::contract::{self, Metadata, Contract, Instance};

use std::any::Any;
use std::fmt::Debug;
use std::ops::Deref;
use std::hash::{Hash, Hasher};
use std::collections::{HashSet, HashMap, BTreeMap, VecDeque, hash_map::Entry};

use serde::{Serialize, Deserialize};

const MINUTE: u64 = 60_000_000_000;
const SECOND: u64 = 1_000_000_000;

#[derive(PartialEq)]
enum Status { Locked(u64), Obtained(Option<u64>), Expired }
#[derive(Serialize, Deserialize, Default, Clone, Debug, Hash)]
struct Lock<const L: u64, const M: u64>(u64, Option<PublicKey>);
impl<const L: u64, const M: u64> Lock<L, M> {
    pub fn lock(&mut self, key: PublicKey, time: u64) -> Option<u64> {
        if self.0+L > time && self.1 != Some(key) {Some(self.0+L)} else {
            self.0 = time;
            self.1 = Some(key);
            None
        }
    }

    pub fn status(&self, key: PublicKey, time: u64) -> Status {
        match (self.0+L > time, self.1 == Some(key)) {
            (true, false) => Status::Locked(self.0+L - time),
            (true, true) => Status::Obtained((self.0+M > time).then_some(self.0+M - time)),
            (false, _) => Status::Expired
        }
    }
}


#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub enum Receipt<R> { Obtained, Result(R), Released }


//A Locking contract does not make much sense because every action can only work on the confirmed
//version. You can only send one action at a time so there is no pending.

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
#[serde(bound = "C: Contract")]
pub struct Locking<C: Contract>(Lock<MINUTE, SECOND>, C);
impl<C: Contract> Deref for Locking<C> {type Target = C; fn deref(&self) -> &Self::Target {&self.1}}
impl<C: Contract> Contract for Locking<C> {
    type Init = C::Init;
    type Message = Signed<Message<C::Message>>;
    type Result = Result<Receipt<C::Result>, Message<C::Message>>;
    
    fn id() -> Id {Id::hash(&("LOCKED", C::id()))}

    fn init(init: Self::Init, metadata: Metadata) -> Self {Locking(Lock::default(), C::init(init, metadata))}

    fn apply(&mut self, message: Self::Message, metadata: Metadata) -> Self::Result {
        if message.verify().is_err() {return Err(message.payload);}
        match (self.0.lock(message.key, metadata.timestamp).is_none(), message.payload) {
            (true, Message::Message(msg)) => Ok(Receipt::Result(self.1.apply(msg, metadata))),
            (true, Message::Release) => {self.0 = Lock::default(); Ok(Receipt::Released)},
            (true, Message::Lock) => Ok(Receipt::Obtained),
            (false, msg) => Err(msg)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub enum Message<M> { Lock, Message(M), Release }

pub enum Mode { Locking, Releasing }

pub struct Locking<M>(Channel<Signed<Message<M>>>, Lock<MINUTE, SECOND>, SecretKey, Mode);
impl<M> Locking<M> {
    pub fn new() -> Self {}

    pub fn request(&mut self) -> Request {
        match (self.3, self.0.outgoing().as_ref().map(|p| &p.payload), self.0.queue().front()) {
            (Mode::Locking, None, None) => {
                self.0.queue_mut().push_back(Signed::new(&self.2, Message::Lock));
            },
            (Mode::Locking, Message::Message

        }
        self.0.request()
    }

    pub fn send(&mut self, message: M) -> Result<(), M> {
        
    }

    pub fn response(&mut self, response: Response) -> Output {
        match self.0.response(response) {
            Output::Subscribed => Output::Subscribed,
            Output::Created(time, msg) => self.process(time, msg.key, msg.payload),
            Output::Read(time, msg) if msg.verify.is_ok() => {
                self.process(time, msg.key, msg.payload)
            }
            _ => Output::Garbage
        }
    }

    fn process(&mut self, time: u64, key: PublicKey, msg: Message) -> Output {
        match (self.1.lock(key, time), key == self.2.public_key(), msg) {
            //I own the lock and sent msg
            (None, true, Message::Message(msg)) => Output::Sent(time, msg),
            //Someone else owns the lock and sent msg
            (None, false, Message::Message(msg)) => Output::Received(time, msg),
            //Someone successfully released the lock
            (None, _, Message::Release) => {self.0 = Lock::default(); Output::Released},
            //I tried and failed to release my lock
            (Some(wait), true, Message::Release) => Output::Released,
            //Someone failed to release their lock
            (Some(wait), false, Message::Release) => Output::Garbage,
            //I tried and failed to send msg 
            (Some(wait), true, Message::Message(msg)) => Output::Locked(wait, Some(msg)),
            //Someone else tried and failed to lock
            (Some(wait), false, Message::Message(_)) => Output::Locked(wait, None),
        }
    }
}


pub struct Notifications{
    requests: ChannelSet<Name>,
    notified: (Locked<Name>, HashSet<Name>),
}
impl Notifications {
    pub fn new() -> Self {

    }

    ///Will notify the name that we are sending message to our shared channel
    pub fn notify(&mut self, name: Name) {
        if !self.notified.1.contains(name) {
            self.requests.insert(name);
        }
    }

    pub fn run(&mut self, notify: AsyncRx<mpsc::List<Name>>, client: Client) {
        //If notify is closed go into release mode
        let mut request = client.send(self.notified.0.request()).await.recv();
        loop {
            tokio::select!{
                result = notify.recv() => match result {
                    Ok(name) => self.requests.insert(name),
                    Err(_) => {
                        let mut lock = self.notified.0;
                        lock.release();
                        loop {
                            if Output::Released == client.send(lock.request()).await.recv().await {
                                return;
                            }
                        }
                    }
                },
                Ok(response) = request => {
                    match self.notified.0.response(response) {
                        Output::Locked => self.notified.0.send(
                    }
                }


            }

        }
    }


}









pub struct Locked<C: Contract>(Instance<Locking<C>>, SecretKey);
impl<C: Contract> Locked<C> {
    //I want to impl a bunch of client side behavior,
    //Modifing the queue when I send a message into the queue.
    //modifying the queue when I receive a confirmed Result
}















pub enum WalletMessage {
    RequestTransaction(Id, Address, u64),
    ReceivedTransaction(Option<Id>, Transaction),
    UsedAddress(usize)
}

pub enum Error {
    InsufficentFunds
}

pub struct Wallet{
    addresses: Vec<Option<Address>>,
    pending: Vec<(Address, u64)>,
    transactions: HashMap<Txid, Transaction>
};
impl Contract for Wallet {
    type Init = Secret;
    type Message = WalletMessage;
    type Result = Result<(), Error>;

    fn id() -> Id {Id::hash(&"Wallet")}

    fn init(init: Self::Init, metadata: Metadata) -> Self {
        //Create wallet and store
    }

    fn apply(&mut self, message: Self::Message, metadata: Metadata) -> Self::Result {

    }
}

//Upon realeasing or loosing the lock I need to remove all messages from the queue

pub enum Message<M> { Lock, Message(M), Release }

pub enum Mode {Obtaining, Obtained(Option<Action<R>>), Releasing }



pub struct BitcoinAction {
    SendingTransaction(Txid),
    SyncingWallet,
    GeneratingAddress
}

//syncing the wallet and generating the address are atomic actions meaning I don't have to log I am
//about to do them, I can just log when I have completed them and what the new state is. No new
//state the action never happend








#[derive(Debug, PartialEq)]
pub enum Output<M, R> {
    Init,
    Garbage,
    Obtained,
    Released,
    Subscribed,
    Created(R, Vec<R>),
    Unlocked(Option<Receipt<R>>, Vec<M>),
    Read(Receipt<R>)
}

#[derive(PartialEq, Default, Clone, Debug, Copy)]
pub enum Mode { #[default] Locking, Releasing }

#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "C: Contract")]
pub struct Locked<C: Contract>(Instance<Locking<C>>, SecretKey, #[serde(skip)] Mode);
impl<C: Contract> Deref for Locked<C> {type Target = Instance<Locking<C>>; fn deref(&self) -> &Self::Target {&self.0}}
impl<C: Contract> Locked<C> {
    pub fn new(name: Name, location: Location, init: Option<C::Init>) -> Self {
        Locked(Instance::new(name, location, init), SecretKey::new(), Mode::default())
    }

    pub fn is_locked(&self) -> bool {
        matches!(self.0.confirmed().map(|c| c.0.status(self.1.public_key(), now())), Some(Status::Obtained(Some(_))))
        && matches!(self.0.pending().map(|c| c.0.status(self.1.public_key(), now())), Some(Status::Obtained(Some(_))))
    }

    pub fn confirmed(&self) -> Option<&C> {self.0.confirmed().map(|l| &**l)}
    pub fn pending(&self) -> &C {self.0.pending().unwrap()}
    pub fn mode(&self) -> &Mode {&self.2}

    pub fn take_queue(&mut self) -> Vec<C::Message> {
        self.0.take_queue().into_iter().filter_map(|m| match m.payload {Message::Message(m) => Some(m), _ => None}).collect()
    }

    pub fn release(&mut self) -> Option<Vec<C::Message>> {
        //If there is outgoing it will be captured by the next response
        if self.2 == Mode::Locking {
            self.2 = Mode::Releasing;
            Some(self.take_queue())
        } else {None}
    }

    pub fn lock(&mut self) {
        if self.2 == Mode::Releasing {
            //We know there is nothing in the queue but a Release message but it might be outgoing
            self.0.take_queue();
        }
        self.2 = Mode::Locking;
    }

    /////You can only attempt to send messages while locked
    pub fn send(&mut self, message: C::Message) -> Result<C::Result, C::Message> {
        if self.2 == Mode::Locking
        && matches!(self.0.confirmed().map(|c| c.0.status(self.1.public_key(), now())), Some(Status::Obtained(Some(_))))
        && matches!(self.0.pending().map(|c| c.0.status(self.1.public_key(), now())), Some(Status::Obtained(Some(_)))) {
            let Receipt::Result(result) = self.0.send(Signed::new(&self.1, Message::Message(message))).unwrap().unwrap() else {panic!("_")};
            Ok(result)
        } else {Err(message)}
    }

    pub fn request(&mut self, secret: &Secret) -> Result<(Request, Option<u64>), Error> {
        Ok(match (self.2, self.status()) {
            (_, None) => (self.0.request(secret)?, None),
            (Mode::Locking, Some(Status::Locked(time))) => (self.0.request(secret)?, Some(time)),
            (Mode::Locking, Some(Status::Expired | Status::Obtained(None))) => {
                if self.0.all().is_empty() {
                    self.0.send(Signed::new(&self.1, Message::Lock)).unwrap().unwrap();
                }
                (self.0.request(secret)?, None)
            },
            (Mode::Locking, Some(Status::Obtained(Some(time)))) => {
                //It is locked but I might loose it after time
                (self.0.request(secret)?, Some(time))
            },
            (Mode::Releasing, Some(Status::Obtained(Some(time)))) => {
                //I will at most have a released in the queue or outgoing
                if self.0.all().is_empty() {
                    self.0.send(Signed::new(&self.1, Message::Release)).unwrap().unwrap();
                }
                (self.0.request(secret)?, Some(time))
            },
            (Mode::Releasing, Some(_)) => (self.0.request(secret)?, None)
        })
    }

    ///If I loose or release the lock what happens to the pending objects?
    ///If its just released I can wait till I have no pending not so with loosing it
    pub async fn response<R: Resolver>(&mut self, resolver: &mut R, response: Response) -> Output<C::Message, C::Result> {
        let r = match (&self.2, self.0.response(resolver, response).await) {
            (_, contract::Output::Garbage) => Output::Garbage,
            (_, contract::Output::Init(_)) => Output::Init,//There can be no pending unless I am locked
            (_, contract::Output::Subscribed) => Output::Subscribed,//No new information

            (_, contract::Output::Created(Ok(Receipt::Result(r)), p)) => Output::Created(r, p.into_iter().filter_map(|m|
                    match m {Ok(Receipt::Result(r)) => Some(r), _ => None}
            ).collect()),
            //Even If I am releasing this was outgoing and still created
            (_, contract::Output::Created(Err(Message::Message(m)), _)) => {
                let mut queue = vec![m];
                queue.extend(self.take_queue());
                Output::Unlocked(None, queue)
            },
            //Even if I am releasing and this was outgoing it was still attempted and failed because of an unlocked

            (Mode::Locking, contract::Output::Created(Ok(Receipt::Released), _)) => Output::Unlocked(None, vec![]),//NOTE not self.take_queue()
            //Even though I am releasing it would have been in my pending meaning nothing could be in my queue
            (Mode::Locking, contract::Output::Created(Ok(Receipt::Obtained), _)) => Output::Obtained,
            (Mode::Locking, contract::Output::Created(Err(_), _)) => Output::Garbage,
            //Failed to lock or release

            (Mode::Releasing, contract::Output::Created(Ok(Receipt::Released), _)) => Output::Released,
            (Mode::Releasing, contract::Output::Created(Ok(Receipt::Obtained), _)) => Output::Garbage,
            (Mode::Releasing, contract::Output::Created(Err(_), _)) => {self.0.take_queue(); Output::Released},
            //Could be a lock that failed to be created, either way I am released
            

            (_, contract::Output::Read(Ok(r), _)) if self.0.all().iter().any(|m| matches!(m.payload, Message::Message(_))) => Output::Unlocked(Some(r), self.take_queue()),
            //I had an outgoing message or lost the lock mid queue
            (_, contract::Output::Read(Ok(r), _)) => {self.take_queue(); Output::Read(r)},
            //Remove the Lock/Release messages when someone else has the lock
            (_, contract::Output::Read(Err(_), _)) => Output::Garbage,

            //p => {panic!("p: {:?}", p);}
        };
        if self.2 == Mode::Locking && self.0.all().iter().any(|m| matches!(m.payload, Message::Release)) {
            self.take_queue().into_iter().for_each(|m| {self.send(m).unwrap();});
        }
        r
    }

    fn status(&self) -> Option<Status> {self.0.confirmed().map(|c| c.0.status(self.1.public_key(), now()))}
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::names::DefaultResolver;
    use crate::websocket::Socket;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    pub struct Counter(u64);
    impl Contract for Counter {
        type Init = ();
        type Message = u64;
        type Result = u64;

        fn id() -> Id {Id::hash("Counter")}

        fn init(_init: Self::Init, _metadata: Metadata) -> Self {Counter(0)}

        fn apply(&mut self, message: Self::Message, _metadata: Metadata) -> Self::Result {
            self.0 = self.0.max(message);
            self.0
        }
    }

    #[tokio::test]
    async fn test() {
        let secret = Secret::new();

        let location = Location{
            key: secret.harden(),
            path: Vec::new(),
            server: Name::orange_me()
        };
        let mut counter = Locked::new(secret.name(), location.clone(), Some(()));
        let mut resolver = DefaultResolver::start();
        let mut socket = Socket::connect(&mut resolver, Name::orange_me()).await;
        let mut make_rr = async |r: Request| {
            socket.0.write(None, postcard::to_allocvec(&r).unwrap()).await;
            let (id, response) = socket.1.read().await;
            println!("request: {:?}", id);
            postcard::from_bytes::<Response>(&response).unwrap()
        };

        assert_eq!(counter.pending(), Some(&Counter(0)));
        assert_eq!(counter.confirmed(), None);

        let (request, None) = counter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(counter.response(&mut resolver, make_rr(request).await).await, Output::Init);

        assert_eq!(counter.confirmed(), Some(&Counter(0)));

        let (request, None) = counter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(counter.response(&mut resolver, make_rr(request).await).await, Output::Obtained);

        let expensive_sum = async {tokio::time::sleep(tokio::time::Duration::from_millis(100)).await; 39458285}.await;

        counter.send(expensive_sum).unwrap();

        assert_eq!(counter.pending(), Some(&Counter(expensive_sum)));

        let (request, Some(_)) = counter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(counter.response(&mut resolver, make_rr(request).await).await, Output::Created(expensive_sum, vec![]));

        assert_eq!(counter.confirmed(), Some(&Counter(expensive_sum)));



        let mut scounter = Locked::<Counter>::new(secret.name(), location, None);
        let (request, None) = scounter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(scounter.response(&mut resolver, make_rr(request).await).await, Output::Init);

        assert_eq!(scounter.pending(), Some(&Counter(0)));
        assert_eq!(scounter.confirmed(), Some(&Counter(0)));

        let (request, None) = scounter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(scounter.response(&mut resolver, make_rr(request).await).await, Output::Read(Receipt::Obtained));

        let (request, Some(_)) = scounter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(scounter.response(&mut resolver, make_rr(request).await).await, Output::Read(Receipt::Result(expensive_sum)));

        assert_eq!(scounter.pending(), Some(&Counter(expensive_sum)));
        assert_eq!(scounter.confirmed(), Some(&Counter(expensive_sum)));

        let (subscribe, Some(_)) = scounter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(scounter.response(&mut resolver, make_rr(subscribe.clone()).await).await, Output::Subscribed);



        counter.send(0).unwrap();
        counter.send(1).unwrap();
        counter.send(2).unwrap();

        assert_eq!(Some(vec![0, 1, 2]), counter.release());
        assert_eq!(Err(1010), counter.send(1010));

        let (request, Some(_)) = counter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(counter.response(&mut resolver, make_rr(request).await).await, Output::Released);

        assert_eq!(scounter.response(&mut resolver, make_rr(subscribe).await).await, Output::Read(Receipt::Released));

        let (request, None) = scounter.request(&secret).unwrap() else {panic!("_");};
        let response = make_rr(request).await;
        assert_eq!(scounter.response(&mut resolver, response).await, Output::Obtained);

        let max = 1000000000;
        scounter.send(max).unwrap();
        scounter.send(max+100).unwrap();

        let (request, Some(_)) = scounter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(scounter.response(&mut resolver, make_rr(request).await).await, Output::Created(max, vec![max+100]));

        let (request, Some(_)) = scounter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(scounter.response(&mut resolver, make_rr(request).await).await, Output::Created(max+100, vec![]));

        scounter.send(2).unwrap();
        assert_eq!(Some(vec![2]), scounter.release());
        assert_eq!(Err(2), scounter.send(2));
        let (delayed, Some(_)) = scounter.request(&secret).unwrap() else {panic!("_");};

        
        let (request, None) = counter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(counter.response(&mut resolver, make_rr(request).await).await, Output::Read(Receipt::Obtained));
        let (request, None) = counter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(counter.response(&mut resolver, make_rr(request).await).await, Output::Read(Receipt::Result(max)));
        let (request, None) = counter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(counter.response(&mut resolver, make_rr(request).await).await, Output::Read(Receipt::Result(max+100)));


        counter.lock();
        assert_eq!(Err(Message::Lock), counter.0.send(Signed::new(&counter.1, Message::Lock)).unwrap());
        println!("{:?}", counter.0.all());
        let garbage = counter.0.request(&secret).unwrap();
        assert_eq!(counter.response(&mut resolver, make_rr(garbage).await).await, Output::Garbage);

        scounter.lock();
        assert_eq!(scounter.response(&mut resolver, make_rr(delayed).await).await, Output::Garbage);
        println!("{:?}", scounter.0.all());
        assert!(scounter.is_locked());
        scounter.send(2).unwrap();

        let (request, Some(_)) = scounter.request(&secret).unwrap() else {panic!("_");};
        assert_eq!(scounter.response(&mut resolver, make_rr(request).await).await, Output::Created(max+100, vec![]));
    }
}
