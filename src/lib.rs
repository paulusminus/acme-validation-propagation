#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use futures_util::future::join_all;
use hickory_resolver::{
    Resolver,
    config::{LookupIpStrategy, NameServerConfigGroup, ResolveHosts, ResolverConfig, ResolverOpts},
    name_server::{GenericConnector, TokioConnectionProvider},
    proto::runtime::TokioRuntimeProvider,
};
use std::{convert::identity, net::IpAddr, thread::sleep, time::Duration};

use crate::error::Error;
use resolver::{RecursiveResolver, ResolverType};

mod error;
mod resolver;

pub type Result<T> = std::result::Result<T, Error>;

const MAX_RETRIES: usize = 720;
const WAIT_SECONDS: u64 = 5;

fn ipv6_resolver(
    group: NameServerConfigGroup,
    recursion: bool,
    ipv6_only: bool,
) -> Resolver<GenericConnector<TokioRuntimeProvider>> {
    let config = ResolverConfig::from_parts(None, vec![], group);
    let mut options = ResolverOpts::default();
    if ipv6_only {
        options.ip_strategy = LookupIpStrategy::Ipv6Only;
    }
    options.recursion_desired = recursion;
    options.use_hosts_file = ResolveHosts::Never;
    let resolver_builder = Resolver::builder_with_config(
        config,
        TokioConnectionProvider::new(TokioRuntimeProvider::new()),
    );
    resolver_builder.build()
    // Resolver::new(config, options).map_err(Error::from)
}

fn recursive_resolver(
    ips: &[IpAddr],
    ipv6_only: bool,
) -> Resolver<GenericConnector<TokioRuntimeProvider>> {
    let group = NameServerConfigGroup::from_ips_clear(ips, 53, false);
    ipv6_resolver(group, true, ipv6_only)
}

#[cfg(feature = "tokio")]
pub fn wait_sync<S>(domain_name: S, challenge: S) -> Result<()>
where
    S: AsRef<str> + Send + 'static,
{
    std::thread::spawn(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(Into::into)
            .and_then(|rt| rt.block_on(wait(domain_name, challenge)))
    })
    .join()
    .unwrap()
}

/// wait checks the authoritive nameservers periodically.
/// It returns Ok(()) when all nameservers have the challenge.
/// It returns an error after several attempts failed.
pub async fn wait<S>(domain_name: S, challenge: S) -> Result<()>
where
    S: AsRef<str>,
{
    let resolver: RecursiveResolver = ResolverType::Google.recursive_resolver(false);
    let resolvers = resolver.authoritive_resolvers(domain_name.as_ref()).await?;

    let mut i: usize = 0;

    sleep(Duration::from_secs(1));
    while !join_all(
        resolvers
            .iter()
            .map(|resolver| resolver.has_single_acme(domain_name.as_ref(), challenge.as_ref())),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .all(identity)
        && i < MAX_RETRIES
    {
        i += 1;
        tracing::warn!("Attempt {} failed", i);
        sleep(Duration::from_secs(WAIT_SECONDS));
    }
    if i >= MAX_RETRIES {
        tracing::error!("Timeout checking acme challenge record");
        Err(Error::AcmeChallege)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt::Display, net::IpAddr};

    use hickory_resolver::{
        lookup::{Ipv6Lookup, NsLookup},
        proto::rr::rdata::{AAAA, NS},
    };

    use crate::{ResolverType, error::Error};

    fn to_string<D: Display>(d: D) -> String {
        d.to_string()
    }

    fn aaaa_to_ipv6(aaaa: AAAA) -> IpAddr {
        IpAddr::V6(*aaaa)
    }

    // fn lookup(
    //     name: &str,
    // ) -> impl AsyncFn(Resolver<GenericConnector<TokioRuntimeProvider>>) -> Result<Ipv6Lookup, Error> + '_
    // {
    //     async move |resolver| resolver.ipv6_lookup(name).await.map_err(Error::from)
    // }

    // fn ns_lookup(
    //     name: &str,
    // ) -> impl AsyncFn(Resolver<GenericConnector<TokioRuntimeProvider>>) -> Result<NsLookup, Error> + '_
    // {
    //     async move |resolver| resolver.ns_lookup(name).await.map_err(Error::from)
    // }

    fn aaaa_mapper(f: fn(AAAA) -> IpAddr) -> impl Fn(Ipv6Lookup) -> Vec<IpAddr> {
        move |lookup| lookup.into_iter().map(f).collect()
    }

    fn ns_mapper(f: fn(NS) -> String) -> impl Fn(NsLookup) -> Vec<String> {
        move |lookup| lookup.into_iter().map(f).collect()
    }

    async fn ipv6_address_lookup(name: &str) -> Result<Vec<IpAddr>, Error> {
        let resolver = ResolverType::Google.resolver(true);
        resolver
            .ipv6_lookup(name)
            .await
            .map(aaaa_mapper(aaaa_to_ipv6))
            .map_err(Into::into)
    }

    async fn nameservers_lookup(name: &str) -> Result<Vec<String>, Error> {
        ResolverType::Google
            .resolver(true)
            .ns_lookup(name)
            .await
            .map(ns_mapper(to_string))
            .map_err(Into::into)
    }

    #[tokio::test]
    async fn test_www_paulmin_nl() {
        let addresses = ipv6_address_lookup("www.paulmin.nl.").await.unwrap();
        assert!(addresses.contains(&"2606:50c0:8000::153".parse::<IpAddr>().unwrap()),);
        assert!(addresses.contains(&"2606:50c0:8001::153".parse::<IpAddr>().unwrap()),);
        assert!(addresses.contains(&"2606:50c0:8002::153".parse::<IpAddr>().unwrap()),);
        assert!(addresses.contains(&"2606:50c0:8003::153".parse::<IpAddr>().unwrap()),);
    }

    #[tokio::test]
    async fn test_ns0_transip_net() {
        assert_eq!(
            ipv6_address_lookup("ns0.transip.net").await.unwrap(),
            vec!["2a01:7c8:dddd:195::195".parse::<IpAddr>().unwrap(),],
        );
    }

    #[tokio::test]
    async fn test_ns1_transip_nl() {
        assert_eq!(
            ipv6_address_lookup("ns1.transip.nl.").await.unwrap(),
            vec!["2a01:7c8:7000:195::195".parse::<IpAddr>().unwrap(),],
        );
    }

    #[tokio::test]
    async fn test_ns2_transip_eu() {
        assert_eq!(
            ipv6_address_lookup("ns2.transip.eu.").await.unwrap(),
            vec!["2a01:7c8:f:c1f::195".parse::<IpAddr>().unwrap(),],
        );
    }

    #[tokio::test]
    async fn test_domain_ns() {
        let mut domain = nameservers_lookup("paulmin.nl").await.unwrap();
        domain.sort();
        assert_eq!(
            domain,
            vec![
                "ns0.transip.net.".to_owned(),
                "ns1.transip.nl.".to_owned(),
                "ns2.transip.eu.".to_owned(),
            ],
        );
    }
}
