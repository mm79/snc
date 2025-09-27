# snc

Simple test in Rust to write a netcat-style program that uses AES-256-GCM with PSK.

## Usage

### Generate key
```bash
matteo@mac % openssl rand -hex 32
236b85c8d045276de7f4f84bd235d564cfbd8c518dfc7ed88f618a3bb4208642
```
### Server
```bash
matteo@mac % ./snc --key 236b85c8d045276de7f4f84bd235d564cfbd8c518dfc7ed88f618a3bb4208642 listen --port 50000
```

### Client
```bash
matteo@mac % ./snc --key 236b85c8d045276de7f4f84bd235d564cfbd8c518dfc7ed88f618a3bb4208642 connect --port 50000 --host localhost
```
