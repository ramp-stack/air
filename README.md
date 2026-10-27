# AIR

AIR is the RAMP stack's protocol for encrypted data storage and messaging. Its design is built around three benefits:

- **Accountless:** Servers store encrypted data without needing to know who you are or asking you to create an account, protecting your privacy.
- **Isolated:** Each piece of data has its own keys, with no shared account or identifier exposing its relationship to other data.
- **Redundant:** Keeping data on servers run by multiple companies keeps it available if one goes offline or blocks your access.

## Account state

`Air::new(secret)` owns the account's contract catalog and its encrypted storage
channel. `Air::create::<C>(init)` creates an instance and registers its location
immediately. `Air::list(&C::id())` lists known locations for that contract.
`Air::share(resolver, recipient, location)` sends access to another identity through
its `Inbox`. The inbox handles peer exchanges; it no longer stores the
account's catalog or accepts sends to the account itself. `Air` provides the account
entry point, with requests routed by `RequestType::Storage` or
`RequestType::Inbox(inbox::RequestType)`. The inbox retains its own request types
and protocol implementation independently of `Air`.

Drive `Air::start()`, `Air::requests()`, and `Air::response(...)` through the chosen
transport. A response returns a location when it becomes newly known. Received
shares join the catalog, which synchronizes across devices using the same secret.
The returned contract instances have their own request/response flow.

AIR owns protocol state without spawning tasks or requiring a shared-state runtime.
Cloning `Air` copies that state; runtime adapters provide shared handles. Creation
queues catalog storage and returns local instance state; the caller must persist
both states and drive their requests to complete remote storage. Serialized `Air`
state includes queued and outstanding catalog and inbox requests.

The `names`, `storage`, `channel`, `contract`, and `inbox` modules are public.
Callers can use their APIs directly, including cryptographic primitives under
`names::secp256k1`, encrypted streams, server storage, and standalone inboxes.
Identity, contract, and storage root re-exports remain available. Use `air::inbox::Inbox`
for standalone peer exchanges; account catalogs now belong to `air::Air`.

## Version 2.1.0

Transport clients and servers now live in
[`air_server`](https://github.com/ramp-stack/air_server). AIR provides the
identity, encryption, contract, inbox, and storage APIs shared by them.
This release changes public exports and removes the old transport modules
and `stream` feature. Applications using those APIs must update to the new
client. The new session protocol is not compatible with older clients.

## Historical typing demo

The pinned demo below uses the older API and requires a server running its
matching protocol. It cannot connect to the current `air.orange.me` server.

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
