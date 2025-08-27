
pub trait ActiveRecord {
    //Create(self, path)
    //Read(self, path)
    //Update(self, path)
    //Delete(self, path)
    //
    //Find(path) /Finds all the neccasry parent nodes 
    //Discover(path) /Discovers struct nodes or map items
    //
    //Register(self) / Registers active record for regular discovery of map items
}

pub struct Protocol {
    children: Option<(bool, bool, bool, bool)>, //anyone can C, R, D, Pointers
    deletable: Option<bool>,//Deleteable (bool anyone can)
    //Permissions
    //Merge
    //Discover Delay

}



Protocol{
    children: Some((true, true, true, true)),


}


pub type Rooms = Folder<Room>;

#[derive(ActiveRecord)]
pub struct Room {
    id: Id,
    name: String,
    #[active_record(child)]
    messages: HashMap<Message>
}

impl HasProtocol for Room {
    fn protocol() -> Protocol {
        Protocol {
            children: Some((true, true, false, false)),
            deletable: None
        }
    }
}

#[derive(ActiveRecord)]
pub struct Message {
    body: Signed<String>,
}

impl HasProtocol for Message {
    fn protocol() -> Protocol {
        Protocol {
            children: None,
            deletable: None
        }
    }
}


#[derive(ActiveRecord)]
pub struct Profile {
    #[active_record(child)]
    fields: BTreeMap<String, Publishable<SerdeJson<String>>>,
}

impl HasProtocol for Profile {
    fn protocol() -> Protocol {
        Protocol {
            children: Some((true, true, true, true))
        }
    }
}

impl Profile {
    pub fn get<T: for<'a> Deserialize<'a>>(&self, name: &str) -> Option<T> {
        self.fields.get(name).and_then(|t| serde_json::from_str(t).ok())
    }
    
}

enum Type {
    Struct(bool, BTreeMap<String, Self>),
    Map(Box<Self>)
}

//Struct self values cannot be updated in the normal sense but the old version deleted and the new
//version created in a channel

//Create() {
//  Start by finding the headers for every node,
//  If they already exist 
//}

//Actors:
//Anyone/Parent means anyone with access to the parent can

//Protocol {
//  CreateChild: 
//  Read:
//  Delete: 
//}

//RoomsProtocol {
//  Discover: Anyone
//  CreateChild: Anyone
//  Read: Author
//  Delete: None
//}
//
//RoomProtocol {
//  Create: 
//}
//
//RoomSelfProtocol {
//  Create: Inherit 
//}
//
//MessagesProtocol {
//
//}
//
//MessageProtocol {
//
//}
