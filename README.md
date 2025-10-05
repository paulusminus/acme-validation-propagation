![main](https://github.com/paulusminus/acme-validation-propagation/actions/workflows/rust.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![docs.rs](https://img.shields.io/docsrs/acme-validation-propagation)

This library crate can be used to check if
an acme challenge record is propagated to all authoritive nameservers.

## Example

```no_run
# tokio_test::block_on(async {
    use acme_validation_propagation::wait;
    let result = wait("example.com", "89823875").await;
    match result {
        Ok(_) => println!("Propagation finished"),
        Err(error) => eprintln!("Error: {error}"),
    }
# })
```
