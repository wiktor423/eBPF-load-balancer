# simple UDP server

This applicaiton exposes a simple UDP server that returns the squared value of what it got.
Returns 0 on malformed input (default `atol` behavior).

Listens on port `4321` by default.


## build and run
```bash
gcc ./main.c -o udp-server
./udp-server
```

Test by running in another terminal:
```bash
echo "70" | nc -u 127.0.0.1 4321
```