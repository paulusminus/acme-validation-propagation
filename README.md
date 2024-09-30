# acme-validation-propagation

![main](https://github.com/paulusminus/acme-validation-propagation/actions/workflows/rust.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![docs.rs](https://img.shields.io/docsrs/acme-validation-propagation)

This library crate can be used to check if
an acme challenge record is propagated to all authoritive nameservers.

## Example

```no_run
use acme_validation_propagation::wait;

match wait("example.com", "89823875") {
    Ok(_) => println!("Propagation finished"),
    Err(error) => eprintln!("Error: {error}"),
}
```
