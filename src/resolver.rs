use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::{TryFutureExt, future::join_all};
use hickory_resolver::{
    Resolver,
    config::{
        CLOUDFLARE, GOOGLE, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
    },
    lookup::Lookup,
    lookup_ip::LookupIp,
    net::runtime::TokioRuntimeProvider,
};

use crate::{Error, recursive_resolver};

pub(crate) enum ResolverType {
    Google,
    #[allow(dead_code)]
    Cloudflare,
    #[allow(dead_code)]
    Local,
}

impl ResolverType {
    fn nameservers(&self) -> &[IpAddr] {
        match self {
            ResolverType::Google => GOOGLE.ips,
            ResolverType::Cloudflare => CLOUDFLARE.ips,
            ResolverType::Local => &[
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ],
        }
    }

    pub fn resolver(&self, ipv6_only: bool) -> Resolver<TokioRuntimeProvider> {
        match self {
            ResolverType::Google => recursive_resolver(self.nameservers(), ipv6_only),
            ResolverType::Cloudflare => recursive_resolver(self.nameservers(), ipv6_only),
            ResolverType::Local => recursive_resolver(self.nameservers(), ipv6_only),
        }
    }

    pub fn recursive_resolver(&self, ipv6_only: bool) -> RecursiveResolver {
        self.resolver(ipv6_only).into()
    }
}

fn to_ips(lookup: LookupIp) -> Vec<IpAddr> {
    lookup.iter().collect::<Vec<IpAddr>>()
}

fn to_strings(lookup: Lookup) -> Vec<String> {
    lookup
        .answers()
        .iter()
        .map(|a| a.data.to_string())
        .collect()
}

fn ipv6_resolver(
    group: Vec<NameServerConfig>,
    recursion: bool,
) -> Result<Resolver<TokioRuntimeProvider>, Error> {
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], group),
        TokioRuntimeProvider::new(),
    );
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv6Only;
    builder.options_mut().recursion_desired = recursion;
    builder.options_mut().use_hosts_file = ResolveHosts::Never;
    builder.build().map_err(Into::into)
}

pub struct RecursiveResolver {
    inner: Resolver<TokioRuntimeProvider>,
}

impl From<Resolver<TokioRuntimeProvider>> for RecursiveResolver {
    fn from(resolver: Resolver<TokioRuntimeProvider>) -> Self {
        Self { inner: resolver }
    }
}

impl RecursiveResolver {
    pub async fn authoritive_resolvers(
        &self,
        domain_name: &str,
    ) -> Result<Vec<AuthoritiveResolver>, Error> {
        self.nameservers(domain_name)
            .and_then(async |nameservers| {
                join_all(
                    nameservers
                        .iter()
                        .map(|hostname| self.authoritive_resolver(hostname)),
                )
                .await
                .into_iter()
                .collect::<Result<Vec<AuthoritiveResolver>, Error>>()
            })
            .await
    }

    pub async fn nameservers(&self, domain_name: &str) -> Result<Vec<String>, Error> {
        self.inner
            .ns_lookup(domain_name)
            .map_ok(to_strings)
            .err_into()
            .await
    }

    pub async fn authoritive_resolver(
        &self,
        host_name: &str,
    ) -> Result<AuthoritiveResolver, Error> {
        let j = self.inner.lookup_ip(host_name).map_ok(to_ips).await?;

        ipv6_resolver(
            j.into_iter().map(NameServerConfig::udp_and_tcp).collect(),
            false,
        )
        .map(AuthoritiveResolver)
    }
}

/// Authoritive nameserver Resolver
pub struct AuthoritiveResolver(hickory_resolver::Resolver<TokioRuntimeProvider>);

impl AuthoritiveResolver {
    pub async fn has_single_acme(&self, domain_name: &str, challenge: &str) -> Result<bool, Error> {
        self.0.clear_cache();
        let lookup: Lookup = self
            .0
            .txt_lookup(format!("_acme-challenge.{}", domain_name))
            .await?;
        let count = lookup.answers().iter().count();
        if count == 1 {
            Ok(lookup
                .answers()
                .iter()
                .any(|txt| txt.data.to_string().as_str() == challenge))
        } else {
            Err(Error::MultipleAcme)
        }
    }
}

#[cfg(test)]
mod test {
    use super::RecursiveResolver;
    use crate::ResolverType;

    const DOMAIN_NAME: &str = "paulmin.nl.";

    #[test]
    fn google_nameserver() {
        let _ = ResolverType::Google.resolver(true);
    }

    #[tokio::test]
    async fn paul_min_nl() {
        let resolver: RecursiveResolver = ResolverType::Google.resolver(true).into();

        let mut names = resolver.nameservers(DOMAIN_NAME).await.unwrap();
        names.sort();

        assert_eq!(
            names,
            vec![
                "ns0.transip.net.".to_owned(),
                "ns1.transip.nl.".to_owned(),
                "ns2.transip.eu.".to_owned(),
            ]
        )
    }
}
