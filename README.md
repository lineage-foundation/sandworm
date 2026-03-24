# Lineage sandworm

**Repository:** [lineage-foundation/sandworm](https://github.com/lineage-foundation/sandworm) — migrated from [AIBlockOfficial/Keccak-Prime](https://github.com/AIBlockOfficial/Keccak-Prime).

The hashing algorithm that keeps your PoW blockchain green. The Rust crate was historically published on crates.io as **`keccak_prime`**; this repository uses the package name **`sandworm`**.

To make use of CPU acceleration for AES, provide the following compilation flags:

```
RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
```

## Use in `Cargo.toml`

```toml
[dependencies]
sandworm = { git = "https://github.com/lineage-foundation/sandworm" }
```

Downstream crates that depended on `keccak_prime = "0.1.0"` should switch to **`sandworm`** (git/path) until a crates.io release under the new name.

## Links

- [Lineage Foundation](https://lineage.foundation)
- [GitHub organization](https://github.com/lineage-foundation)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
