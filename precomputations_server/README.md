## Precomputations server

The server generates precomputed bytecode for given X, Y coordinates of a certain public key associated with a Webauthn device. It uses the sagemath script from FreshCryptoLib project, and it generates the precomputations synchronously.

## Setup & Run

Create an .env file based on the .env.example, and set the env variables to your desire. 
Run `cargo build` to intall dependencies and build the project.
Run `cargo run` to start the server locally.

## Run using docker

To run the server in docker, you first need to build a docker image using the following command:

```
docker build -t precomputations_server .
```

Then, run the image by binding the crypto folder which contains the `precompute.sage` script.

```
docker run -e HOST=0.0.0.0 -e PORT=8080 -e BASE_FOLDER=/crypto/ -p 8080:8080 -v /Users/njofce/Documents/Work/Encite/Blockchain/Ethereum/elliptic_algorithm/precomputations_server/crypto:/crypto precomputations_server
```
