## Precomputations server

The server generates precomputed bytecode for given X, Y coordinates of a certain public key associated with a Webauthn device. It uses the sagemath script from FreshCryptoLib project, and it generates the precomputations synchronously.

## Setup & Run

Create an .env file based on the .env.example, and set the env variables to your desire. 
Run `cargo build` to intall dependencies and build the project.
Run `cargo run` to start the server locally.