use easy_secp256k1::{EasySecretKey, EasyHash, Hashable};
use secp256k1::{SecretKey, rand};
use dyn_clone::{DynClone, clone_trait_object};
use dyn_hash::{DynHash, hash_trait_object};
use dyn_eq::{DynEq, eq_trait_object};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, BTreeMap, VecDeque};
use std::collections::hash_map::Entry;
use std::hash::{Hasher, Hash};
use std::ops::Deref;
use std::fmt::Debug;
use std::any::Any;

use super::requests;
use super::records::{self, WSecretKey, Header, Protocol, SubKeySet, KeySet, Record, Id, Key, ValidationError};
use crate::server::{Purser, Request as RequestTrait, AnyRequest, BatchRequest, AnyResult};
use crate::did::Endpoint;

pub use typetag;

//  mod commands;
//  pub use commands::*;

pub type DateTime = chrono::DateTime::<chrono::Utc>;



#[derive(Serialize, Deserialize, Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Endpoints(Vec<Endpoint>);
impl Endpoints {
    pub fn new(mut endpoints: Vec<Endpoint>) -> Self {
        endpoints.sort_by_key(|e| e.1.to_string());
        endpoints.dedup();
        Endpoints(endpoints)
    }
}
impl std::ops::Deref for Endpoints {
    type Target = Vec<Endpoint>;
    fn deref(&self) -> &Self::Target {&self.0}
}



#[derive(PartialEq, Eq)]
pub enum Task {
    Run(Id, Box<dyn Command>, Vec<Result<Box<dyn AnyResult>, Error>>),
    Request(AnyRequest, Endpoint),
    Waiting(Id, Box<dyn Command>, Vec<Id>),
    Complete(Result<Box<dyn AnyResult>, Error>)
}
impl Hash for Task {fn hash<H: Hasher>(&self, state: &mut H) {state.write(self.id().as_ref())}}
impl Task {
    pub fn run(cmd: impl Command + Hash) -> Self {
        Task::Run(Id::from(rand::random::<[u8; 32]>()), Box::new(cmd), vec![])
    }
    pub fn request(req: AnyRequest, endpoint: Endpoint) -> Self {
        Task::Request(req, endpoint)
    }

    pub fn id(&self) -> Id {
        match self {
            Task::Run(id, _, _) => *id,
            Task::Waiting(id, _, _) => *id,
            Task::Complete(r) => Id::hash(&r),
            Task::Request(c, e) => Id::hash(&(c, e))
        }
    }
}

pub enum Processed {
    Waiting(Box<dyn Command>, Vec<Task>),
    Complete(Result<Box<dyn AnyResult>, Error>)
}

pub trait Command: DynHash + DynEq + Debug {
    type Output where Self: Sized;

    fn process(self: Box<Self>, cache: &mut Cache, key: &PathedKey, results: Vec<Result<Box<dyn AnyResult>, Error>>) -> Result<Processed, Error>;
}
hash_trait_object!(Command);
eq_trait_object!(Command);

#[derive(Debug)]
pub struct CompilerResult(VecDeque<Result<Box<dyn AnyResult>, Error>>);
impl CompilerResult {
    pub fn get<C: Command<Output = T>, T: 'static>(&mut self) -> Result<T, Error> {
        self.0.pop_front().expect("Results is Empty").map(|r| *(r as Box<dyn Any>).downcast().expect("Incorrect Command Please get them in the order they were subbmited"))
    }
}

pub struct Compiler<'a>{
    purser: &'a mut dyn Purser,
    cache: &'a mut Cache,
    key: &'a PathedKey,

    completed: HashMap<Id, Result<Box<dyn AnyResult>, Error>>,
    commands: Vec<Id>,
    tasks: HashSet<Task>,
}
impl<'a> Compiler<'a> {
    pub async fn run(purser: &'a mut dyn Purser, cache: &'a mut Cache, key: &'a PathedKey, commands: Vec<Box<dyn Command>>) -> CompilerResult {
        let (commands, tasks): (Vec<_>, HashSet<_>) = commands.into_iter().map(|c| {let id = Id::random(); (id, Task::Run(id, c, vec![]))}).unzip();
        CompilerResult(Compiler{purser, cache, key, completed: HashMap::new(), commands, tasks}._run().await.into())
    }

    fn process_run(&mut self) {
        self.tasks = self.tasks.drain().collect::<Vec<_>>().into_iter().flat_map(|t| {
            let id = t.id();
            self.completed.contains_key(&id).then_some(vec![]).unwrap_or_else(||match t {
                Task::Run(_, command, params) => match command.process(self.cache, self.key, params) {
                    Ok(Processed::Complete(r)) => {self.completed.insert(id, r); vec![]}
                    Ok(Processed::Waiting(c, t)) => {
                        let (h, mut t): (Vec<_>, Vec<_>) = t.into_iter().map(|t| (t.id(), t)).unzip();
                        t.push(Task::Waiting(id, c, h));
                        t
                    },
                    Err(e) => {self.completed.insert(id, Err(e)); vec![]}
                },
                task => vec![task]
            })
        }).collect::<HashSet<_>>();
    }

    async fn process_requests(&mut self) {
        let mut requests: HashMap<Endpoint, (BatchRequest, Vec<(Id, AnyRequest)>)> = HashMap::new();
        self.tasks = self.tasks.drain().flat_map(|t| {let id = t.id(); match t {
            Task::Request(r, e) => match requests.entry(e.clone()) {
                Entry::Occupied(mut entry) => {
                    let (batch, requests): &mut (BatchRequest, Vec<(Id, AnyRequest)>) = entry.get_mut();
                    batch.push(&r); requests.push((id, r));
                    None
                },
                Entry::Vacant(entry) => {entry.insert((BatchRequest::from([&r]), vec![(id, r)])); None}
            },
            task => Some(task)
        }}).collect::<HashSet<_>>();
        println!("requests: {:#?}", requests);
        for (endpoint, (batch, requests)) in requests {
            let response = self.purser.send_raw(&endpoint, batch.as_ref()).await;
            let mut bres = batch.process(response);
            requests.into_iter().for_each(|(h, r)| match bres.as_mut() {
                Ok(responses) => {self.completed.insert(h, responses.process_next(r).unwrap().map_err(|e| e.into()));},
                Err(e) => {self.completed.insert(h, Err(e.clone().into()));}
            });
        }
    }

    ///Waiting tasks are never put under completed since they turn into trival run statements which
    ///are checked for completed
    fn process_waiting(&mut self) -> bool {
        let mut processed_any = false;
        self.tasks = self.tasks.drain().map(|t| match t {
            Task::Waiting(id, c, h) if h.iter().all(|h| self.completed.contains_key(h)) => {
                processed_any = true; 
                Task::Run(id, c, h.iter().map(|h| self.completed.get(h).cloned().unwrap()).collect())
            },
            task => task
        }).collect::<HashSet<_>>();
        processed_any
    }

    async fn _run(mut self) -> Vec<Result<Box<dyn AnyResult>, Error>> {
        loop {
            //println!("Loop");
            //println!("tasks: {:#?}", self.tasks);
            if self.tasks.iter().any(|t| matches!(t, Task::Run(_, _, _))) {
                self.process_run();
            } else if !self.process_waiting() {
                if self.tasks.iter().any(|t| matches!(t, Task::Request(_, _))) {
                    self.process_requests().await; 
                } else {
                    //println!("com: {:?}", self.commands);
                    //println!("completed: {:#?}", self.completed);
                    break self.commands.into_iter().map(|h| self.completed.get(&h).cloned().unwrap()).collect();
                }
            }
        }
    }
}



impl std::fmt::Debug for Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Task::Run(id, cmd, params) => write!(f, "Run({:.10?}, {:?}, {:?})", id, cmd, params),
            Task::Request(req, ends) => write!(f, "Request({:?}, {:?})", req, ends),
            Task::Waiting(id, cmd, hashes) => write!(f, "Waiting({:.10?}, {:?}, {:?})", id, cmd, hashes.iter().map(|h| format!("{:.10?}", h)).collect::<Vec<_>>()),
            Task::Complete(res) => write!(f, "Complete({:?})", res),
        }
    }
}
