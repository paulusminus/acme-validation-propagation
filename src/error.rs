use std::{io, net::AddrParseError};

use hickory_resolver::net::{DnsError, NetError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Ipv4")]
    Ipv4,

    #[error("ACME challenge")]
    AcmeChallege,

    #[error("IO: {0}")]
    IO(#[from] io::Error),

    #[error("Resolve: {0}")]
    Resolve(#[from] DnsError),

    #[error("Net: {0}")]
    Net(#[from] NetError),

    #[error("Parse: {0}")]
    Parse(#[from] AddrParseError),

    #[error("Multiple acme challenges")]
    MultipleAcme,
}
