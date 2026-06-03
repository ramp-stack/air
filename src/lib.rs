pub mod names;
pub use names::{Secret, Name};

mod storage;

mod server;
pub use server::Chandler;

mod channel;

pub mod contract;
pub use contract::{Contract, Reactant, Reactants, Air, Instance, Guard};

#[cfg(test)]
mod test {
    use crate::{Air, Contract, Reactant, Reactants, Instance};
    use crate::names::{Name, Id, Secret};
    use serde::{Serialize, Deserialize};
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Message {
        author: Name,
        timestamp: u64,
        body: String,
        id: Id
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Room {
        author: Name,
        name: String,
        messages: BTreeMap<u64, Message>
    }
    impl Contract for Room {
        type Init = String;

        fn id() -> Id {Id::hash("Room")}

        fn init(init: Self::Init, signer: Name, _timestamp: u64) -> Self {
            Room {
                author: signer,
                name: init, 
                messages: BTreeMap::new()
            }
        }

        fn reactants() -> Reactants<Room> {
            Reactants::default().add::<SendMessage>().add::<EditMessage>()
        }
    }

    #[allow(unused)]
    #[derive(Debug)]
    pub struct MessageExists(Id);
    impl std::error::Error for MessageExists {}
    impl std::fmt::Display for MessageExists {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "{:?}", self)}
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct SendMessage(Id, String);
    impl Reactant<Room> for SendMessage {
        type Ok = Id;
        type Err = MessageExists;

        fn id() -> Id {Id::hash("SendMessage")}

        fn apply(self, room: &mut Room, signer: Name, timestamp: u64) -> Result<Self::Ok, Self::Err> {
            if room.messages.values().any(|m| m.id == self.0) {Err(MessageExists(self.0))?}
            room.messages.entry(timestamp).or_insert(Message{author: signer, timestamp, body: self.1, id: self.0});
            Ok(self.0)
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct EditMessage(Id, String);
    impl Reactant<Room> for EditMessage {
        type Ok = bool;
        type Err = Infallible;

        fn id() -> Id {Id::hash("EditMessage")}

        fn apply(self, room: &mut Room, _signer: Name, _timestamp: u64) -> Result<Self::Ok, Self::Err> {
            Ok(room.messages.values_mut().find(|m| m.id == self.0).map(|m| {m.body = self.1; true}).unwrap_or_default())
        }
    }

    #[tokio::test]
    async fn test() {
        let air = tokio::task::spawn_blocking(|| {
            let secret = Secret::new();
            let air = Air::start(secret);

            let room: Instance<Room> = air.create::<Room>("MyRoom".to_string());
            let id = room.apply(SendMessage(Id::random(), "Hi Bob".to_string())).unwrap();
            assert!(room.apply(EditMessage(id, "GoodBye Bob".to_string())).unwrap());
            air
        }).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        air.list::<Room>().into_iter().for_each(|i| assert_eq!(*i.confirmed().unwrap(), *i.pending()));
    }
}
