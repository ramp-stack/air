const ORANGE_ME_SECRET: &str = "{\"name\":[245,0,84,23,76,12,239,129,22,92,85,22,200,140,54,92,202,173,90,23,101,143,198,185,70,131,144,68,198,68,121,186,33,110,73,187,251,234,169,168,12,236,133,74,63,16,44,86,128,10,58,227,111,238,186,117,254,170,22,74,222,61,1,62], \"temporary\": \"0a7ded86a96f7d311145118e7fb67611f029bdaf1c11bee8fb1223235ef05ed4\", \"path\": []}";

#[tokio::main]
async fn main() {
    let secret = serde_json::from_str(ORANGE_ME_SECRET).unwrap();
    air::server::Server::start(secret).await
}
