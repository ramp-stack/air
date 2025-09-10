

pub struct Cache(BTreeMap<PathBuf, CachedChannel>);

pub struct CachedChannel {
    latest_index: u32,
    latest_timestamp: DateTime,
    children: BTreeSet<String>
}

pub struct Channel{
    path: PathBuf,
    payload: Option<Vec<u8>>,
    endpoints: Vec<Endpoint>,
    update: Vec<OrangeName>,
    delete_children: Vec<OrangeName>,
}

impl Channel {
    pub fn create() -> {}
    pub fn read(); 
    pub fn update(); 
    pub fn delete(); 
}

//1. Air servers need to keep track of delete time and only allow deleteing of payload
//2. Include Endpoints in the header data
//3. Include name in header data and validate header data name by looking in the previouse records
//   only
//4. Build a permission resolver that handles verification and resolution of permissions/headers
//   (Should eliminate all key handling from now on)
//5. 

pub enum Actor {
    Author,//Owner
    Group(String, Vec<OrangeName>),
    User(OrangeName),
    Anyone,

    And(Actor, Actor),
    Or(Actor, Actor),
}

pub enum Action {
    Delete,
    Read, //Discover and Read Self
    CreateChild(String, vec![Permission]), //Create a child with the given name (path and regex accepted) Needs Discover and Read children
    ReadChild(String), //Read a child with the given name (path and regex accepted)
    DeleteChild(String), //Delete a child with the given name (path and regex accepted)
}

pub struct Permission(Actor, Action);

//When Permissioning a user or group of users to read or create they also need the ability to
//discover.
//
//Bob needs the whole header to know if he has access to something
//
//To Create or Delete you need Read Permissions of the header to verify that it exists or find it
//
//Discover Key will be a shared secret too where the author choose a unqiue one based on his path as
//usual(Unless the Discover Key is Secret always???)

let room = vec![
    Permission(Actor::User(bob), Action::Read),
    Permission(Actor::Author, Action::Read),
    Permission(Actor::Author, Action::CreateChild("messages", Some(messages))),
    Permission(Actor::Author, Action::DeleteChild("messages/regex#(0-9)*")),
    Permission(Actor::Anyone, Action::ReadChild("messages")),
];

let messages = vec![
    Permission(Actor::Anyone, Action::CreateChild("regex#(0-9)*", Some(message))),
    Permission(Actor::Anyone, Action::ReadChild("regex#(0-9)*")),
]

let message = vec![
    Permission(Actor::Author, Action::Delete),
    Permission(Actor::User(bob), Action::Read),//This means that bob can read this message but only
    //if he knows the discover key can he find it and to verify anything else he needs the header
]

//TODO: Given a vec of permission and a path provide me the permissions for the record
//Maybe provide an author key for derivation and do the and/or in the resolver



//Create Room {
//  groups: Vec<Group>
//}


    //Permissions are always on a child because you cannot see your own abilities revoked if you
    //require your abilities to see the status of them?
    //
    //A payload can be deleted but never replaced
    //
    //The payload of a record should contain its permissions and initial state
    //
    //further records inside of itself will contain payload updates?
    //
    //Updates to its permissions are status records
    //
    //Deleting a record requires notifing the parent? Or can the parent tell because the payload of
    //the first record was deleted? Then the delete key can not be updated after the fact
    //
    //If the delete can be update after the fact the record of that will have to be in the parent
    //not the child
    //
    //A Vector has additional validation with items required to be in order

//Actor of Location can Action
//
//Create, Update, Delete can be done using validation and signatures
//
//Nobody actually deletes a payload?


1. to delete a channel you actually have to remove its link from its parent



/abc/efg -> CRecord(Room)
/abc/efg/0 -> "my room name"
/abc/efg/1 -> "new room name"


When looking for /messages discover every record to find the first record with "messages" in the header data
When a gab limit of one is reached stop
When a records timestamp is older than a previous records timestamp ignore

Records that can be deleted need to be checked regularly


0 /0 = "messages" valid
1 /1 = "messages" invalid

later

0 /0 = deleted 
1 /1 = "messages" valid

/messages -> HeaderData/name = "messages"


0 /0 = bob -> "messages" valid
1 /1 = alice -> "messages" invalid
2 /2 = bob -> /0 deleted "messages" valid
3 /3 = charlie -> "messages" valid


0 /0 bob -> "messages" valid 
1 /2 alice -> "rooms" invalid
2 /1 charlie -> "rooms" valid

