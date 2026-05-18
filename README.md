# vanity-endpoint-id

Generate "vanity" iroh `EndpointId`s: Look for IDs that start with given hex-encoded prefixes.

Example usage:
```
$ vanity-endpoint-id --threads=16 becca
Estimated required iterations: 1048576
found becca93a719ad2c0a4accb99180c3a0d98ab3b4aa154d01a99b97bd2bab18ecb (secret key: 86ec8c66fadea89fb77f26e0d816385263b29f3af1a5906ee77b9efc5602e372) after 47103 iterations
```

This secret key can then be used in iroh:
```rs
let secret_encoded = "86ec8c66fadea89fb77f26e0d816385263b29f3af1a5906ee77b9efc5602e372";
let secret_key = SecretKey::from_str(secret_encoded).unwrap();
println!("{}", secret_key.public());
// Use with `Endpoint`:
let endpoint = Endpoint::builder(preset::Minimal).secret_key(secret_key).bind().await?;
```
## Options

See the help text:
```
Usage: vanity-endpoint-id [OPTIONS] <NEEDLE>

Arguments:
  <NEEDLE>  The needle prefix for the public key to search a secret key for

Options:
      --threads <THREADS>  The number of threads to use for search [default: 1]
      --keep-going         Whether to keep searching even after the first find
  -h, --help               Print help
```
