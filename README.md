# stdx: Rust's extended standard library

Rust's biggest problem is its anemic standard library leading not only to a very fragmented ecosystem with multiple competing packages (so you end up with 10 different packages to handle time and 15 crypto libraries) but also to elevated supply chain risks (see [Supply chain nightmare: How Rust will be attacked and what we can do to mitigate the inevitable](https://kerkour.com/rust-supply-chain-nightmare)).

This is why we are creating Rust's extended standard library, inspired by Go's extensive standard library and `golang.org/x/...` packages.

The goal is that `stdx` only uses code from `std` and `stdx`. No third-party imports, no supply chain risks, no ecosystem fragmentation.

Once the idea has proven to be valuable, we plan to donate the entire codebase to the Rust Foundation to build trust and drive adoption.



## Usage

Import packages directly from git, for example:
```toml
base64 = { git = "https://github.com/rust-stdx/stdx", branch = "main" }
```

> **Warning ⚠️**: The project is moving fast, we can't provide any stability guarantees at this moment. Use at your own risk.


## Documentation

[Docs](https://rust-stdx.github.io/stdx)


## Contributing

Contributions are welcome, especially bug reports, improvement ideas and new package suggestions.

Other than for minor typos, no pull request will be accepted without a preliminary discussion. Please open an issue first.

## Development

See `.devcontainer/Dockerfile`.

then:

```bash
rustup default stable
```

And you are ready to <s>Go</s> Rust!

See `Makefile` for the most common commands used during development.


## License

MIT, see [LICENCE.txt](./LICENSE.txt)


### Forks

| Package | Forked from | Commit | Original License |
| --- | --- | --- | --- |
| `bel` | https://github.com/cel-rust/cel-rust | 8287d04156a1b31efe0dd53db78e943fef15c59a | MIT |
| `cron` | https://github.com/zslayton/cron | ?? | Apache 2.0 / MIT |
| `acme` | https://github.com/instant-labs/instant-acme | 5e12971830a5907f0aeba4dfd602ec26db4bc30c | Apache 2.0 |
| `anyerr` | https://github.com/dtolnay/anyhow | 5a88bc48ca18c9720be292487dcdcbc93004d15a | MIT |
| `constant_time_eq` | https://github.com/cesarb/constant_time_eq | 09a34625babf29e1b622ed46e959ea517986b12a | CC0-1.0 |
| `crc32fast` | https://github.com/srijs/rust-crc32fast | 479ecdf0174dd3a0f7d48b2f66a386d8d2369963 | MIT |
| `embed` | https://github.com/pyrossh/rust-embed | 105fdfebab5820ea0628149ee62b34f6d2df3bb8 | MIT |
| `derivative` | https://github.com/mcarton/rust-derivative | 5179a968ca6d70792f62dfe6727ab8d5b8b5cf5e | MIT |
| `form_urlencoded` | https://github.com/servo/rust-url | 54346fa288e16b25b71c45149d7067c752b450e0 | MIT |
| `httpdate` | https://github.com/pyfisch/httpdate | 63f723c6eae30ec130a6c5625ec38c4b49b0891c | MIT |
| `ipnetwork` | https://github.com/achanda/ipnetwork | f01575cbf2fc596c0a1761c122aa92525cbb7974 | MIT |
| `itoa` | https://github.com/dtolnay/itoa | 945f297a243887f66407fcd65088b3713a464851 | MIT |
| `maxminddb` | https://github.com/oschwald/maxminddb-rust | b5a6ccc2f1c8e990b54bbac648f524cdf043522a | ISC |
| `memmem` | https://github.com/jneem/memmem | d6e6a0b1fb391539cf8511e7a2de76016d86a870 | MIT |
| `mimeguess` | https://github.com/abonander/mime_guess | 1ae11679916b18fcced93c11104b7aed53bd35a2 | MIT |
| `num_cpus` | https://github.com/seanmonstar/num_cpus | 7c03fc930cc47a9b94e8ca66ca44ef1a454c8f51 | MIT |
| `percent_encoding` | https://github.com/servo/rust-url | 54346fa288e16b25b71c45149d7067c752b450e0 | MIT |
| `ryu` | https://github.com/dtolnay/ryu | 8234c4d95f97565bfa562cd1572bb0e8ed80cc44 | Apache 2.0 |
| `serde_urlencoded` | https://github.com/nox/serde_urlencoded | 0cca840185fa85b39e2cc8a0b2547fff5ace8e68 | MIT |
| `serde_yaml` | https://github.com/dtolnay/serde-yaml | 2009506d33767dfc88e979d6bc0d53d09f941c94 | MIT |
| `tld` | https://github.com/rushmorem/publicsuffix | 47958d65a3eab3a01e4a9cf46ccf40c11a7e8052 | MIT |
| `unsafe_libyaml` | https://crates.io/crates/unsafe-libyaml | 417668ce6565ece14bbd9b4a73137d9241ea1365 | MIT |
| `uuid` | https://github.com/uuid-rs/uuid | 98fc36df4d3f33669d54f1d7b999888f75d8b71f | MIT |
