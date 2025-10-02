use serde::{Serialize, Deserialize};
use orange_name::{Name, secp256k1::{SecretKey, Signed as KeySigned}, Id};

use crate::server::{Error as PurserError, Command, Context, PurserRequest};
use crate::storage::{CreatePrivate, ReadPrivate, ReadPrivateHash};

use std::time::Duration;

use crate::DateTime;

use super::{PrivateItem, File};

pub fn file_from_private_item(key: &SecretKey, item: KeySigned<PrivateItem>) -> Result<File, secp256k1::Error> {
    let discover = key.public_key();
    let item = item.verify().and_then(|signer|
        (signer != discover || item.as_ref().discover != discover)
        .then_some(item.into_inner()).ok_or(secp256k1::Error::InvalidMessage)
    )?;
    let payload = key.decrypt(&item.payload)?;
    let file: File = serde_json::from_slice(&payload).map_err(|_| secp256k1::Error::InvalidMessage)?;
    if file.key.public_key() != item.discover || file.key != *key {Err(secp256k1::Error::InvalidMessage)?}
    Ok(file)
}

pub fn file_to_private_item(file: &File) -> KeySigned<PrivateItem> {
    let discover = file.key.public_key();
    KeySigned::new(&file.key, PrivateItem{discover,
        payload: discover.encrypt(serde_json::to_vec(&file).unwrap()).unwrap()
    })
}

#[derive(Serialize, Deserialize)]
pub struct CreateFile(File);

impl Command<PurserRequest> for CreateFile {
    type Output = Result<Option<DateTime>, PurserError>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let request = CreatePrivate(file_to_private_item(&self.0));
        let r: Option<Result<Option<DateTime>, PurserError>> = majority(ctx.run((request, self.0.servers)).await);
        //TODO: If no majority was found entry recovery mode
        r.ok_or(PurserError::mr("No Majority Response")).flatten()
    }
}

type HashList = Vec<Result<Option<Id>, PurserError>>;
type HeaderList = Vec<Result<Option<(DateTime, Id, Name)>, PurserError>>;

pub struct ReadFile(pub SecretKey, pub Name, pub Vec<Name>, pub Option<Id>);
impl Command<PurserRequest> for ReadFile {
    type Output = Result<Option<File>, PurserError>;

    async fn run(self, mut ctx: Context) -> Self::Output {
        let min = self.2.len().div_ceil(2);
        //Read the payload from one server and the hashes from the others
        let (p, date_hashes) = ctx.run((
            (ReadPrivate(KeySigned::new(&self.0, ())), self.1),
            (ReadPrivateHash(KeySigned::new(&self.0, ())), self.2.clone())
        )).await;
        //Push the Result<Option<(DateTime, Id)>> to hashes
        let (mut hashes, mut dhs): (HashList, HeaderList) = date_hashes.into_iter().zip(self.2).map(|(r, n)| (
            r.as_ref().map(|p| p.as_ref().map(|(_, h)| (*h))).map_err(|e| e.clone()),
            r.map(|p| p.map(|(d, h)| (d, h, n)))
        )).unzip();
        hashes.push(p.as_ref().map(|p| p.as_ref().map(|(_, h, _)| (*h))).map_err(|e| e.clone()));
        dhs.push(p.as_ref().map(|p| p.as_ref().map(|(d, h, _)| (*d, *h, self.1))).map_err(|e| e.clone()));
        let payload = p.map(|p| p.map(|(_, i, p)| (i, p)));
        //TODO: Find the majority and error if none was found we will entry recovery mode in the future
        let hash = majority(hashes).ok_or(PurserError::mr("No Majority Response"))??;
        //majority is now Option<Id> We have a agreement on the hash IF its valid
        if let Some(hash) = hash {
            //If we were given a target hash that does not match the majority hash exit early
            if let Some(thash) = self.3 && hash != thash {return Ok(None);}
            //having some hash means that a majority of the responses in dhs is Ok(Some(_, h, _)) where h == hash
            let mut ds: Vec<(DateTime, Name)> = dhs.into_iter().filter_map(|i|
                i.ok().flatten().filter(|(_, h, _)| *h == hash).map(|(d, _, s)| (d, s))
            ).collect::<Vec<_>>();
            //Get all date ranges that are min size and are within 60 seconds of each other
            let date_combos = dates(ds.iter().map(|(d, _)| *d).collect(), min, Duration::from_secs(60));
            //Filter all my servers for ones that are in any min combo
            ds.retain(|(d, _)| date_combos.iter().any(|c| c.contains(d)));

            //Get the payload for the hash we have agreed on and is possibly valid
            let mut payload = payload.ok().flatten().filter(|(i, _)| *i == hash).map(|(_, p)| p);
            //Loop through the other servers
            if payload.is_none() {
                for (_, server) in ds {
                    let result = ctx.run((ReadPrivate(KeySigned::new(&self.0, ())), server)).await;
                    //Because were only looking up the ds list if we get an error not our fault
                    //blame the air servers
                    match result {
                        Ok(Some((_, id, p))) if id == hash => {payload = Some(p);},
                        Err(PurserError::Disconnected) => Err(PurserError::Disconnected)?,
                        Err(PurserError::ConnectionFailed(s)) => Err(PurserError::ConnectionFailed(s))?,
                        _ => {}//TODO: blame the air server
                    }
                }
            }
            let payload = payload.ok_or(PurserError::mr("All Air servers claimed to have a record hash and won't provide payload"))?;
            //Extract the file from the PrivateItem
            Ok(file_from_private_item(&self.0, payload).ok().and_then(|file| {
                //Check if the inner timestamp falls within a minute of any date combo range
                let ft = file.timestamp;
                date_combos.iter().any(|c| {
                    let start = c[0];
                    let end = c[c.len()-1];
                    let margin = end - start;
                    (ft >= start-margin && ft <= end) || (ft >= start && ft <= end+margin)
                }).then_some(file)
            }))
        } else {Ok(None)}
    }
}

pub fn majority<R: PartialEq>(responses: Vec<R>) -> Option<R> {
    let req = (responses.len() / 2) + 1;
    let (count, winner) = responses.into_iter().fold((0, None), |mut acc, p| {
        if acc.0 == 0 {acc.1 = Some(p);}
        else if acc.1 == Some(p) {acc.0 += 1;}
        else {acc.0 -= 1;}
        acc
    });
    if count >= req {Some(winner.unwrap())} else {None}
}

fn dates(mut dates: Vec<DateTime>, size: usize, margin: Duration) -> Vec<Vec<DateTime>> {
    dates.sort(); 
    (0..dates.len()).flat_map(|i| {
        let start = dates[i];
        let end = start+margin;
        let mut count = 0;
        Some(dates[i..].iter().take_while(|&&d| if d <= end {count+=1; count <= size} else {false}).copied().collect::<Vec<_>>())
            .filter(|d| d.len() == size)
    }).collect()
}
