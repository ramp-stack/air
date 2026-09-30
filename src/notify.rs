pub struct Notify(Channel);
impl Notify {
    pub fn new(me: Name, name: Name) -> Self {
        let writing = SecretKey::from_bytes(*Id::hash(name));
        let encryption = resolver.resolve(name).await.public_key().derive_risky(&[Id::hash("Notify")]);
        let channel = Channel::new(Location{server: Name::orange_me(), discovery: writing.public_key()}, Some(encryption));
        channel.enable_writing(writing);
        channel.queue().push_back(me);
    }

    pub fn run(mut self, purser: Purser) {
        loop {
            let response = purser.send(self.0.request()).recv().await;
            if matches!(self.0.response(response), Output::Created(_, _)) {
                break;
            }
        }
    }

    pub fn receive(secret: Secret) -> Self {
        let writing = SecretKey::from_bytes(*Id::hash(name));
        let encryption = resolver.resolve(name).await.public_key().derive_risky(&[Id::hash("Notify")]);
        let decryption = secret.public_key()
        let channel = Channel::new(Location{server: Name::orange_me(), discovery: writing.public_key()}, Some(encryption));
        channel.enable_writing(writing);
        channel.queue().push_back(me);

    }
}
