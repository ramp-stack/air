

#[derive(Clone)]
pub struct Chandler {
    storage: Storage,
    secret: Secret,
}

impl Chandler {
    pub async fn start(secret: Secret) {
        let storage = Storage::start(&secret);
        let chandler = Chandler{storage, secret};

        let listener = TcpListener::bind("0.0.0.0:5702").await.unwrap();
        while let Ok((stream, _)) = listener.accept().await {
            spawn(chandler.clone().upgrade(stream));
        }
    }

    async fn upgrade(mut self, stream: TcpStream) {
        let mut public = None;
        #[allow(clippy::result_large_err)]
        match accept_hdr_async(stream, |req: &TungRequest, response: TungResponse| {
            match req.headers().get("X-Public-Key").and_then(|x| EncryptionStream::receive(&self.secret, postcard::from_bytes(&hex::decode(x.to_str().ok()?).ok()?).ok()?).ok()) {
                Some(init) => {
                    public = Some(init);
                    Ok(response)
                },
                None => {
                    let mut resp = ErrorResponse::new(Some("Invalid/Missing X-Public-Key".to_string()));
                    *resp.status_mut() = StatusCode::BAD_REQUEST;
                    Err(resp)
                }
            }
        }).await {
            Ok(stream) => self.socket(stream, public.unwrap()).await,
            Err(e) => println!("Invalid Socket: {e}")
        }
    }

    //Each Socket needs to handle request sequentially, paralization could be used to prepare
    //decrypted/deserialized responses for the read/write step
    async fn socket(&mut self, stream: WebSocketStream<TcpStream>, encryption: EncryptionStream) {
        let (mut write, mut read) = stream.split();
        let (mut sink, mut drain) = encryption.split();
        let mut index: usize = 0;
        let mut futures: FuturesUnordered<PBFut<(usize, Response, RReceiver)>> = FuturesUnordered::new();

        loop {
            tokio::select! {
                biased;
                Some((index, response, receiver)) = futures.next() => {
                    let _ = write.send(Message::Binary(postcard::to_allocvec(&sink.encrypt(postcard::to_allocvec(&(index, response)).unwrap())).unwrap().into())).await;
                    if receiver.get_tx_count() > 0 {
                        futures.push(Box::pin(async move {(index, receiver.recv().await.unwrap(), receiver)}) as _);
                    }
                },
                Some(ws_result) = read.next() => {
                    match ws_result {
                        Ok(message) => match message {
                            Message::Binary(payload) => {
                                let request = postcard::from_bytes(&drain.decrypt(postcard::from_bytes(&payload).unwrap()).unwrap()).unwrap();
                                let srx = self.storage.request(request).await;
                                futures.push(Box::pin(async move {(index, srx.recv().await.unwrap(), srx)}) as _);
                                index += 1;
                            },
                            Message::Close(_) => {
                                println!("Client disconnected");
                                break;
                            },
                            e => {println!("Ignored Request: {e:?}");}
                        },
                        Err(e) => {
                            println!("Client Errored: {:?}", e);
                            break;
                        },
                    }
                },
                else => {println!("unknown");}
            }
        }
    }
}
