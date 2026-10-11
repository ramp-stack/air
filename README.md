# AIR

AIR is the RAMP stack's protocol for encrypted data storage and messaging. Its design is built around three benefits:

- **Accountless:** Servers store encrypted data without needing to know who you are or asking you to create an account, protecting your privacy.
- **Isolated:** Each piece of data has its own keys, with no shared account or identifier exposing its relationship to other data.
- **Redundant:** Keeping data on servers run by multiple companies keeps it available if one goes offline or blocks your access.

## Run the typing demo

The [typing demo](https://github.com/ramp-stack/maverick_os/tree/5841507e3eefd51a8ce852e8730d04b998877d35/demo) saves each character through AIR. Use **macOS**, current stable Rust with Cargo, and Xcode Command Line Tools. It needs internet access to `air.orange.me:5702`; no account, API key, or local server setup is required.

```sh
git clone https://github.com/ramp-stack/maverick_os.git
cd maverick_os
git checkout --detach 5841507e3eefd51a8ce852e8730d04b998877d35
cd demo
cargo run
```

Wait for the first **Confirm Room** output in the terminal. Click the blank window titled **orange** and type some sample text. Watch **Pending Room** and **Confirm Room** in the terminal as you type; they show the latest 20 characters. Close the window to quit.

Use sample text: this demo explicitly shares room access with Orange.

## What's happening

Each character press adds data locally, signs and encrypts it, and queues a separate save to the server. **Pending Room** reflects your local changes; **Confirm Room** advances when the server acknowledges them. You don't need to press Enter.

AIR derives separate storage and encryption keys for each piece of data. Clients with the room key can reconstruct the conversation, including Orange because this demo shares that key with it.

This demo uses a single server, but multiple servers will not increase latency.
