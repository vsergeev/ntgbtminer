# ntgbtminer

ntgbtminer is a no thrills
[getblocktemplate](https://en.bitcoin.it/wiki/Getblocktemplate) Bitcoin miner.
It is not performant, but demonstrates basic use of the getblocktemplate
protocol for a standalone Bitcoin miner. It has no dependencies outside of
standard Python libraries and a JSON-HTTP connection to your local Bitcoin
daemon.

Donations are welcome at `15PKyTs3jJ3Nyf3i6R7D9tfGCY1ZbtqWdv` :)

## Usage

* Configure `rpcuser` and `rpcpass` in `~/.bitcoin/bitcoin.conf`

* Start bitcoind

```
$ bitcoind -testnet -daemon
```

* Run ntgbtminer

```
$ RPC_USER=bitcoinrpc RPC_PASS=foobar RPC_URL="http://127.0.0.1:18332" \
    python3 ntgbtminer.py "Hello from vsergeev!" "mr9zpiUkvGukpg1uZ99NdAxwJmuSYYmNA3"
```

## License

ntgbtminer is MIT licensed. See the provided [`LICENSE`](LICENSE) file.
