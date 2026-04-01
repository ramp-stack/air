use air::Chandler;

const ORANGE_ME_SECRET: &str = "{\"name\":\"03273e58dff6f2e5334c526b0dd0100d20e1ac4bfa22dfd904725eef63931e4853\",\"path\":[],\"temporary\":\"299b59ea9707c448cc28e5fcdfbf459e6a5fb9f1f274329fd924900c12f16395\"}";

#[tokio::main]
async fn main() {
    let secret = serde_json::from_str(ORANGE_ME_SECRET).unwrap();
    Chandler::start(secret).await
}
