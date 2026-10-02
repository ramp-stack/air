const ORANGE_ME_SECRET: &str = "{\"name\":\"037a581e7728ce94d3fd67bdb1309672c4884aae774f911d0cada94fc9e50c955f\",\"temporary\":\"bb8b147ff2b57f34d25f43ea40406ea326644f6eda7debb4f8c29786398469d6\",\"path\":[]}";


#[tokio::main]
async fn main() {
    let secret = serde_json::from_str(ORANGE_ME_SECRET).unwrap();
    air::server::Server::start(secret).await
}
