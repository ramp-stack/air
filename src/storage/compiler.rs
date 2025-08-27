use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hasher, Hash};
use std::any::Any;
use super::records::{self, Record, RecordPath, DefaultCache, ValidationError, Error, Permissions, Protocol};
use crate::storage;
use super::{Filter, Id, PublicItem, DateTime, OrangeResolver, OrangeName, OrangeSecret};
use crate::server::Purser;
use crate::server::{Request as ChandlerRequest, Response as ChandlerResponse};

#[derive(Hash)]
pub enum Request {
    Create(RecordPath, Protocol, Vec<u8>, Permissions, Vec<u8>)
    Read(RecordPath)
    DiscoverAll(RecordPath, Option<u32>),
    Find(RecordPath, Box<dyn Fn(&Header) -> bool>),
    Delete(RecordPath)
}

#[derive(Clone)]
pub enum Response {
    CreatePublic(Id),
    ReadPublic(Vec<(Id, OrangeName, PublicItem, DateTime)>),
    CreatePrivate(RecordPath, Option<(Result<Record, ValidationError>, DateTime)>),
    ReadPrivate(Option<(Record, DateTime)>),
    UpdatePrivate(bool),
    DeletePrivate(bool),
    Discover(Option<RecordPath>, Option<DateTime>),
    Receive(Vec<(OrangeName, RecordPath)>),
    Empty,
}

pub enum CommandOutput {
    Request(Vec<(Request, Vec<Endpoint>)>),
    Finished
}

pub trait Command: Any {
    fn run(&mut self, cache: &mut Cache, responses: Vec<Response>) -> Result<CommandOutput, Error>;
}

pub struct Compiler {
    resolver: OrangeResolver,
    secret: OrangeSecret,
    purser: Purser,
    cache: DefaultCache,

    commands: BTreeMap<Id, Box<dyn Command>>,
    responses: BTreeMap<Id, Vec<Response>>,

}

impl Compiler {
    pub fn new(secret: OrangeSecret, cache: Cache) -> Self {
        Compiler {
            resolver: OrangeResolver::new(),
            secret,
            purser: Purser::new(),
            cache,

            commands: BTreeMap::new(),
            responses: BTreeMap::new(),
        }
    }

    fn add_command(&mut self, command: impl Command + 'static) -> Id {
        let id = Id::random();
        self.commands.insert(id, Box::new(command));
        id
    }

    async fn tick(&mut self) -> BTreeMap<Id, Result<Box<dyn Command>, Error>> {
        let outputs: Vec<_> = self.commands.iter_mut().map(|(id, c)|
            (*id, c.run(&mut self.cache, self.responses.remove(id).unwrap_or_default()))
        ).collect();
        let mut requests = BTreeMap::default();
        let results = outputs.into_iter().flat_map(|(id, output)| {
            match output {
                Ok(CommandOutput::Finished) => Some((id, Ok(self.commands.remove(&id).unwrap()))),
                Err(e) => Some((id, Err(e))),
                Ok(CommandOutput::Request(r)) => {requests.insert(id, r); None}
            }
        }).collect();
        self.handle_requests(requests);
        results
    }


    async fn handle_requests(&mut self, requests: BTreeMap<Id, Vec<Request>>) -> Result<BTreeMap<Id, Result<Vec<Response>, Error>>, Error> {
        let mut dedup_requests = BTreeMap::new();
        let id_requests = requests.into_iter().map(|(id, requests)| {
            (id, requests.into_iter().map(|r| {
                let mut hasher = DefaultHasher::new();
                r.hash(&mut hasher);
                let hash = hasher.finish();
                dedup_requests.insert(hash, r);
                hash
            }).collect())
        }).collect::<BTreeMap<Id, Vec<u64>>>();
        let mut clients = Vec::new();
        let mut air_requests = Vec::new();
        for (hash, request) in dedup_requests {
            let client = Client::from_request(
                &mut self.resolver, &mut self.secret, &mut self.cache, request
            ).await?;
            air_requests.push(client.build_request());
            clients.push((hash, client));
        }
        let endpoint = self.resolver.endpoint(&self.secret.name(), None, None).await?;
        let res = self.purser.send(&mut self.resolver, &endpoint, ChandlerRequest::batch(air_requests)).await?.batch()?;
        let mut results = BTreeMap::new();
        for ((hash, client), res) in clients.into_iter().zip(res) {
            results.insert(hash, client.to_response(&mut self.resolver, &mut self.cache, res).await);
        }
        Ok(id_requests.into_iter().map(|(id, hashes)| {
            (id, hashes.into_iter().map(|hash| results.get(&hash).unwrap().clone()).collect())
        }).collect())
    }
}

//  pub enum Find {
//      Find(RecordPath, Box<dyn Fn(&Header) -> bool>),
//      Found(RecordPath, Header)
//  }

//  impl Command for Find {
//      pub fn run(&mut self, cache: &mut DefaultCache, responses: Vec<Response>) -> Result<CommandOutput, Error> {
//          Ok(match self {
//              Find(parent, pattern) => {
//                  if let Some(Response::Discover(Some(path), _)) = responses.pop() {
//                      let header = cache.get(path).ok_or(Err("Discovery not cached".into()))?;
//                      if pattern(header) {
//                          self = Find::Found(path, header.clone());
//                          return Ok(CommandOutput::Finished);
//                      }
//                  } else {
//                      for id in cache.get_children(parent) {
//                          let child_path = parent.join(id);
//                          let child = cache.get(child_path).ok_or(Err("Child listed but not found".into()))?;
//                          if pattern(child) {
//                              self = Find::Found(child_path, child.clone());
//                              return Ok(CommandOutput::Finished);
//                          }
//                      }
//                  }
//                  let lci = cache.get_latest_child_index(parent);
//                  CommandOutput::Request(vec![Request::Discover(parent, lci+1)])
//              },
//              Found(_, _) => CommandOutput::Finished
//          })
//      }
//  }


enum Client {
    Public(Box<storage::Client>),
    Private(Box<records::Client>)
}

impl From<storage::Client> for Client {fn from(c: storage::Client) -> Self {Client::Public(Box::new(c))}}
impl From<records::Client> for Client {fn from(c: records::Client) -> Self {Client::Private(Box::new(c))}}

impl Client {
    pub fn build_request(&self) -> ChandlerRequest {match self {
        Self::Public(client) => client.build_request(),
        Self::Private(client) => client.build_request(),
    }}

    pub async fn from_request(resolver: &mut OrangeResolver, secret: &OrangeSecret, cache: &mut DefaultCache, request: Request) -> Result<Client, Error> {
        Ok(match request {
            Request::CreatePublic(item) => storage::Client::create_public(resolver, secret, item).await?.into(),
            Request::ReadPublic(filter) => storage::Client::read_public(filter).into(),
            Request::UpdatePublic(id, item) => storage::Client::update_public(resolver, secret, id, item).await?.into(),
            Request::Discover(path, index) => records::Client::discover(cache, &path, index)?.into(),
            Request::CreatePrivate(parent, protocol, header_data, index, perms, payload) => records::Client::create(cache, &parent, protocol, header_data, index, &perms, payload)?.into(),
            Request::CreatePointer(parent, path, index) => records::Client::create_pointer(cache, &parent, &path, index)?.into(),
            Request::ReadPrivate(path) => records::Client::read(cache, &path)?.into(),
            Request::UpdatePrivate(path, perms, payload) => records::Client::update(cache, &path, &perms, payload)?.into(),
            Request::DeletePrivate(path) => records::Client::delete(cache, &path)?.into(),
            Request::Share(name, perms, path) => records::Client::share(cache, resolver, secret, &name, &perms, &path).await?.into(),
            Request::Receive(since) => records::Client::receive(resolver, secret, since).await?.into(),
        })
        //}
    }

    pub async fn to_response(&self, resolver: &mut OrangeResolver, cache: &mut DefaultCache, response: ChandlerResponse) -> Result<Response, Error> {
        match self {
            Client::Public(client) => match client.process_response(resolver, response).await {
                Ok(storage::Processed::CreatePublic(id)) => Ok(Response::CreatePublic(id)),
                Ok(storage::Processed::ReadPublic(results)) => Ok(Response::ReadPublic(results)),
                Ok(storage::Processed::Empty) => Ok(Response::Empty),
                Ok(r) => Err(Error::MaliciousResponse(format!("{:?}", r))),
                Err(e) => Err(e.into())
            },
            Client::Private(client) => client.process_response(cache, resolver, response).await.map(|r| match r {
                records::Processed::Discover(record, date) => Response::Discover(record, date),
                records::Processed::Create(path, conflict) => Response::CreatePrivate(path, conflict),
                records::Processed::Read(record) => Response::ReadPrivate(record),
                records::Processed::Update(s) => Response::UpdatePrivate(s),
                records::Processed::Delete(s) => Response::DeletePrivate(s),
                records::Processed::Receive(records) => Response::Receive(records),
                records::Processed::Empty => Response::Empty,
            }),
        }
    }
}

//Discover(parent, redundancy threashold(RT)) -> BTreeMap<Path, (Option<Header>, bool)> { //Discovered header and weather slot taken
//  //Gap limit is always one
//  //Read the Header from RT number of air servers
//  //If they agree on the header done otherwise read the rest of the air servers and choose the
//  header that has atleast RT number of agrements If there isnt at least RT number of agrements
//  return empty
//  //If RT number of air servers agree that a key has not been used then the bool is true
//}
//
//Create(parent, record) {
// First Discover parent, Then attemp to create under latest index
// If taken try again at the next index
//}
//
//Read(path, RT) -> Option<Record> {
//  //Read the record from RT number of air servers If the payloads agree finish
//  //Otherwise read from all Air Servers and see if RT agree and if not empty record
//}
//
//Update; Update does not exist when record keys cannot be reused and paths a refering to
//individual keys
//
//Delete(path) -> bool {
//  //Delete the record on all the Air Servers
//  //Return true if at least RT air servers returned true
//  //bool indicates a successful delete
//
//  //Some systems may after a false from a delete attempt a read and ensure it returns None
//}

//Find(parent, header_pattern) -> Option<Header> {
//  //Locate the first record that matches the header_pattern,
//  //Start with local cache, If found in cache need to confirm its still around do a read header
//  unless its undeletable, It could still expire???
//  //Then Discover New Records using Discover
//  //If still no match return None
//}
//
//
//
//
//
//PROTOCOL TEMPLATES
