pub mod names;

mod storage;
pub use storage::{Request, Response, Compare};

mod server;
pub use server::{Chandler, Purser, Connection};

mod inbox;
pub use inbox::{Inbox, InboxHandler};

mod channel;
pub use channel::Channel;

pub mod substance;

pub mod contract;

pub mod instance;

pub mod air;
pub use air::Air;

#[cfg(test)]
mod test {
    use crate::{Purser, Air};
    use crate::names::{Name, Id, Secret, Resolver};
    use crate::substance::{Substance, Beaker};
    use crate::contract::{Contract, Reactant, Contracts, Reactants};

    use serde::{Serialize, Deserialize};

    use std::collections::BTreeMap;
    use std::path::{PathBuf, Path};
    use std::convert::Infallible;

    #[derive(Serialize, Deserialize, Hash, Clone)]
    pub struct ChatRoom;
    impl ChatRoom {
        pub fn new(_name: &str) -> Self {ChatRoom}
    }
    impl Contract for ChatRoom {
        fn id() -> Id {Id::hash("ChatRoom2.5")}

        fn init(self, signer: &Name, _timestamp: u64) -> Substance {Substance::Map(BTreeMap::from([
            ("name".to_string(), Substance::String("myroom".to_string())),
            ("author".to_string(), Substance::String(signer.to_string())),
            ("messages".to_string(), Substance::Seq(im::Vector::new()))
        ]).into())}

        fn routes() -> BTreeMap<PathBuf, Reactants> {
            BTreeMap::from([
                (PathBuf::from("/name"), Reactants::default().add::<ChangeName>()),
                (PathBuf::from("/messages"), Reactants::default().add::<SendMessage>())
            ])
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct ChangeName(String);
    impl Reactant for ChangeName {
        type Error = Infallible;

        fn apply<B: Beaker>(self, _path: &Path, signer: &Name, _timestamp: u64, substance: &mut B) -> Result<(), Self::Error> {
            if substance.query("/author") == Ok(Substance::String(signer.to_string())) {
                let _ = substance.insert("/name", Substance::String(self.0));
            }
            Ok(())
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct SendMessage(String);
    impl Reactant for SendMessage {
        type Error = Infallible;

        fn apply<B: Beaker>(self, _path: &Path, signer: &Name, _timestamp: u64, substance: &mut B) -> Result<(), Self::Error> {
            let _ = substance.insert("/messages/-", Substance::Map(BTreeMap::from([
                ("author".to_string(), Substance::String(signer.to_string())),
                ("body".to_string(), Substance::String(self.0)),
            ]).into()));
            Ok(())
        }
    }


    #[tokio::test]
    async fn test() {
        let resolver = Resolver::start();
        let purser = Purser::start(resolver.clone());
        let air = Air::start(resolver.clone(), purser.clone(), Contracts::default().add::<ChatRoom>()).unwrap();

        let friend_air = Air::start(resolver, purser, Contracts::default().add::<ChatRoom>()).unwrap();
        let my_friend = friend_air.me();

        let id = air.create(ChatRoom::new("my_room")).unwrap();
        println!("SHARING");
        air.share(id, my_friend).unwrap();
        println!("SHARED");
        air.send(id, "/messages", SendMessage("Hello".to_string())).unwrap();

        let model = Substance::Map(BTreeMap::from([
            ("name".to_string(), Substance::String("myroom".to_string())),
            ("author".to_string(), Substance::String(air.me().to_string())),
            ("messages".to_string(), Substance::Seq(vec![
                Substance::Map(BTreeMap::from([
                    ("author".to_string(), Substance::String(air.me().to_string())),
                    ("body".to_string(), Substance::String("Hello".to_string())),
                ]).into())
            ].into()))
        ]).into());

        assert_eq!(air.get(&id).unwrap(), None);
        assert_eq!(air.get_pending(&id).unwrap(), model.clone());

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        assert_eq!(air.get(&id).unwrap(), Some(model.clone()));

        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        assert_eq!(friend_air.get(&id).unwrap(), Some(model));
    }
}
