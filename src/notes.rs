


Channels are privacy barriers that require at least one layer of encryption

Reconciling channels requires extra reads per channel.

I want private states with out the full privacy barrier provided by channels,

I should be able to store encrypted payloads in a channel. But that requires extra encryption layers

//If contracts have a permissions setup to decide decryption and writers
//Signatures are manditory if the writers list is Some
//If someone is added a decryptor they must be provided with the keys to all previous messages
//
//I need a zero knowledge proof that the encrypted packet is:
//A. Encrypted to the new decryptor
//B. Contains the same key as everyone else
//OR concerned parties can send decryption keys themselves
//
//The contract defines the permissions based off of init. Meaning the inbox can be set so there is
//only one reader and that never changes. If someone rolls their keys in the list of names new keys
//for the channel should be issued from that point on.
//
//Nothing can be done about old decryption or leaked keys anyway.
//
//Anyone with write access can ask and issue a key roll. Which is why a zkp is required to not
//trust the writer but still get new keys. If a writer does not have decryption access they can't
//provide new keys to the decryptors...
//If a decryptor does not have write access they cannot issue a key roll.
//This means there must be at least one person who can decrypt and write or key rolls are not
//possible in the contract.
//
//A new decryption key could be issued by every writer since each writer is privy to their own
//writes...
//
//This would require a lot of keys to be provided to new decryptors. Unless writers encrypted the
//decryption key to a common XPriv. Which would then need to be rolled as often as anyone rolled
//their keys or decryptors we removed...
//
//Each writer could have their own XPriv which they encrypt to all the decryptors. Each writer when
//writing may need to provide a new XPriv if any decryptor changed/rolled. Otherwise they can use
//the old one.
//
//For now the inbox could be a contract with a known write key, But the encryption key would have
//to be published by the owner of the inbox. And rolled by the owner when they roll their keys.
//
//Could decryptors have write access when publishing a rolled key??? Technically different people
//would have access to write different things. The write key is only to prevent spam???
//
//No the write key was put in place to allow different writers their own sub channel
//
//In the future the contract would be a combination of channels for various purposes with different
//writers allowed in each of the sub channels
//
//So only decryption keys should roll? No writers can roll the write key.
//Decryptors can roll the decryption key.
//
//How do I get decryptors to do writes? The contract upon detecting a key roll for any given user
//will make the next request a write regardless of ability to write becuase decryptors would be
//rolling the decryption key.
//
//I am not going to handle rolling for now but I am switching to named permissions in the contract.
//Signing is optional unless a white list writers have been provided.

#[derive(Clone, Debug, Copy)]
pub struct Metadata {
    pub signer: Option<Name>,
    pub timestamp: u64,
    pub confirmed: bool
}
impl Metadata {
    fn pending(signer: Option<Name>) -> Self {Metadata{signer, timestamp: now(), confirmed: false}}
    fn confirmed(signer: Option<Name>, timestamp: u64) -> Self {Metadata{signer, timestamp, confirmed: true}}
}

//  #[derive(Serialize, Deserialize, Debug, Clone)]
//  pub enum Message<C: Contract> { Init(C::Init), Message(C::Message) }

#[derive(Debug, Clone, PartialEq)]
pub enum Output<R> {
    //Init(Vec<R>),
    Created(R, Vec<R>),
    Read(R, Vec<R>),
    Garbage,
    Subscribed,
}

//I need my own queue for the instance, because if a channel change request arrives I need to push
//each queued message into the new channel. 
//
//My out going message in a channel when I read gets put back into the queue. I should use the
//current channel as the queue and on switch extract and replace it in the new channel.
//The new channel needs no init.
//
//Permissions are generally part of the contract including having pending/confirmed behavior
//Only upon getting confirmed permission changes do i compare the previous and new permissions and
//decide what changes must be made on the channel.
//
//Writing on the channel is to allow each writer of a contract its own channel...
//Each writer would need to roll his own channel because encryption would have to be seperated from
//the channel to allow different encryption...
//
//Each contract could use channels how ever they wish as its only for discovery/writing
//
//Does it make sense to have a middle layer between channel and contract which handles the
//permissioning? It would have the service messages that communicate key changes. It would be name
//aware and handle signatures and decryption
//
//A system message would need to be triggered by the contract in some cases. Changing the names
//would require a system message to be sent? 
//OR would the permissioned channel handle the system messages? 
//
//Decryption there would need to be a different XPriv set for each channel no matter how many
//writers there are...
//Which would need to be encrypted to every decryptor
//
//The writer keys would be rolled via signing with your identity which would require an open
//channel to prevent lock outs.
//
//So in order to have a multiwriter channel It would have to be baked into a layer with an open
//channel to negotiate writer key changes...
//
//| Channel -> MultiWriter -> Contracted?      |
//|---------Vec<u8>---------|-Contract Message-|



//A middle ware layer could layer on encryption and other formats
//The channel already handles Garbage outputs


//The contract needs a channel that starts out encrypted ???
//No the contract decides what encryption scheme we use. The Id and Init message can contain any
//extra information.


///The contracted instance is more complex handleing channel managment, signatures, decryption,
///validation
///
///Declaring decryption schemes for messages is handled here. The inbox will require encrypting to
///at least one Name. Though with more than one name you would need an intermediate key. Which
///would be rolled anytime any of the Names are removed or rolled. And such a key would need to be
///passed on to added Names at any point in the future.
///
///Anyone who can decrypt could create such a message to roll the decryption key. This message
///would be handled in the root channel with conflicting decryption keys handled in order.
///
///The Location is the init location of the channel used to establish this contract instance.
///The channel can be switched out or split up any where down the line.
///
///Signatures can be optional except for establishing a writer channel to optimizie what kind of
///signatures are required for each message.

//If encryption keys are added and the writer is not a decryptor, Then there is a period of time
//where each writer needs to write to its own key and broadcast it encrypted to each decryptors
//identity
//
//Easy way out is to encrypt to each decryptor and generate a new key for each write as an overhead
//in the packets.
//
//Rooms: writing: Some(Vec<Members>), encryption: Some(Vec<Members>)
//Inbox: writing: None, encryption: Some(Vec<Recipient>)

//For the inbox I need a channel such that:
//discovery: Name + Id::hash("Inbox")
//encryption: Name. Every packet could be encrypted to name, Or a common key could be used...
//A common key would require re rolls where the name would automatically handle re rolls...
//The point of using names is to allow re rolls. But upon removing a name from a whitelist it would
//require a reroll message...
//
//To support rerolls I simply need a mem cache(which I have) and system messages
//Should encryption not be apart of the channel? And I should have a permissioned channel instead?
//The write key for a channel should/could also be rolled? That would essentially be switching
//channels. Could the permissioned channel do that?
//
//The contract cant do most of this because it can't change the encryption.
//If the contract can change the channel it can change the encryption.
//
//The inbox is a type of contract at a certian pre defined location

//Changing the Encryption key is a message not an internal thing but to determine if this is a
//valid action it has to be after the contract. Which means I need an internal way of switching the
//encryption 
//
//
//Each writer could establish their write and encryption keys. And they

//If its confirmed that the encryption key should change, change it, Don't do that before
//
///Each message has its own encryption key, A contract can establish a longer lasting encryption key
///Each message is encrypted with a key derived by index from the provided encryption key.
///
///How do I decrypt messages in this scheme?

///Very simple layer creates an ordered series of serilized messages ensuring timestamp and
///key signature validity


#[derive(Serialize, Deserialize, Clone, Copy, Hash, Debug, Default, PartialEq, Eq)]
pub struct XPriv(SecretKey, Id);
impl Deref for XPriv {type Target = SecretKey; fn deref(&self) -> &Self::Target {&self.0}}
impl XPriv {
    pub fn new(secret: SecretKey, chain: Id) -> Self {XPriv(secret, chain)}
    pub fn random() -> Self {XPriv(SecretKey::new(), Id::random())}

    pub fn public_key(&self) -> XPub {XPub(self.0.public_key(), self.1)}
    pub fn chain_id(&self) -> &Id {&self.1}
    pub fn derive(&self, path: &[Id]) -> Self {
        let (mut key, mut chain) = (self.0, self.1);
        for id in path {
            let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(self.1.as_ref());
            hmac_engine.input(&self.0.public_key().0.serialize()[..]);
            hmac_engine.input(id.as_ref());
            let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
            key = SecretKey(secp256k1::SecretKey::from_byte_array(hmac_result[..32].try_into().unwrap()).unwrap().add_tweak(&key.0.into()).unwrap());
            let bytes: [u8; 32] = hmac_result[32..].try_into().unwrap();
            chain = Id::from(bytes);
        }
        XPriv(key, chain)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Hash, Debug, PartialEq, Eq)]
pub struct XPub(PublicKey, Id);
impl Deref for XPub {type Target = PublicKey; fn deref(&self) -> &Self::Target {&self.0}}
impl XPub {
    pub fn new(public: PublicKey, chain: Id) -> Self {XPub(public, chain)}

    pub fn derive(&self, path: &[Id]) -> XPub {
        let (mut key, mut chain) = (self.0, self.1);
        for id in path {
            let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(self.1.as_ref());
            hmac_engine.input(&self.0.0.serialize()[..]);
            hmac_engine.input(id.as_ref());
            let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
            let sk = secp256k1::SecretKey::from_byte_array(hmac_result[..32].try_into().unwrap()).unwrap();
            key = PublicKey(key.0.add_exp_tweak(SECP256K1, &sk.into()).unwrap());
            let bytes: [u8; 32] = hmac_result[32..].try_into().unwrap();
            chain = Id::from(bytes);
        }
        XPub(key, chain)
    }
}



























Permissions {
    readers: Option<Vec<Name>>,
    writers: Option<Vec<Name>>
}





Permission {
    readers: vec![Grant],
    writers: anyone
}

Permission {
    readers: vec![Grant, Caleb],
    writers: anyone
}

discover: SecretKey = SecretKey::from_hash("Grand and Calebs public_key"),
encryption: PublicKey = Grants + Caleb




Grant's Notifications
discover: SecretKey, = SecretKey::from_hash("Grant's public_key");
encryption: PublicKey = PublicKey::derived_from("Grant's public_key");

Grant's/Caleb Inbox Channel
discover: SecretKey = SharedSecret(grant, caleb),
encryption: SecretKey = SharedSecret(grant, caleb),







discovery: PublicKey,//write
encryption: PublicKey,//read



Council Member:
    discovery: SecretKey,
    encryption: SecretKey,

Town Member:
    discovery: PublicKey,
    encryption: SecretKey,



Notify

Inbox

Admin-Share
















