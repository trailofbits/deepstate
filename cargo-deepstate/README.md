# cargo-deepstate

Integrates the DeepState framework for fuzzing and symbolic execution on Rust.

Using a `cargo` subcommand provides convenient control similar to `cargo-fuzz`, and also provides a common interface to all frontend executors.

## Usage

```
$ cargo deepstate init
$ cargo deepstate list
$ cargo deepstate afl -i in -o out
```


