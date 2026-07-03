// Copyright: Ankitects Pty Ltd and contributors
// License: GNU AGPL, version 3 or later; http://www.gnu.org/licenses/agpl.html

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use reqwest::Url;

use crate::error::AnkiError;
use crate::sync::login::SyncAuth;

pub(crate) fn ensure_internet_connection_available(auth: &SyncAuth) -> Result<(), AnkiError> {
    if endpoint_requires_network(auth.endpoint.as_ref()) && !has_usable_network_interface() {
        return Err(AnkiError::network_offline(
            "no active network connection detected",
        ));
    }

    Ok(())
}

fn endpoint_requires_network(endpoint: Option<&Url>) -> bool {
    let Some(host) = endpoint.and_then(Url::host_str) else {
        return true;
    };

    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }

    host.parse::<IpAddr>()
        .map(|addr| !addr.is_loopback())
        .unwrap_or(true)
}

#[cfg(unix)]
fn has_usable_network_interface() -> bool {
    let mut addrs = std::ptr::null_mut();

    // SAFETY: getifaddrs() initializes addrs on success, and freeifaddrs()
    // releases it before returning.
    unsafe {
        if libc::getifaddrs(&mut addrs) != 0 {
            return true;
        }

        let mut current = addrs;
        while !current.is_null() {
            let ifaddr = &*current;
            if let Some(addr) = ifaddr.ifa_addr.as_ref() {
                let flags = ifaddr.ifa_flags as libc::c_int;
                if is_active_non_loopback_interface(flags) && is_usable_addr(addr) {
                    libc::freeifaddrs(addrs);
                    return true;
                }
            }

            current = ifaddr.ifa_next;
        }

        libc::freeifaddrs(addrs);
    }

    false
}

#[cfg(unix)]
fn is_active_non_loopback_interface(flags: libc::c_int) -> bool {
    flags & libc::IFF_UP != 0
        && flags & libc::IFF_LOOPBACK == 0
        && flags & libc::IFF_RUNNING != 0
}

#[cfg(unix)]
fn is_usable_addr(addr: &libc::sockaddr) -> bool {
    match i32::from(addr.sa_family) {
        libc::AF_INET => {
            // SAFETY: family was checked above.
            let addr = unsafe { *(addr as *const _ as *const libc::sockaddr_in) };
            is_usable_ipv4(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()))
        }
        libc::AF_INET6 => {
            // SAFETY: family was checked above.
            let addr = unsafe { *(addr as *const _ as *const libc::sockaddr_in6) };
            is_usable_ipv6(Ipv6Addr::from(addr.sin6_addr.s6_addr))
        }
        _ => false,
    }
}

#[cfg(not(unix))]
fn has_usable_network_interface() -> bool {
    true
}

fn is_usable_ipv4(addr: Ipv4Addr) -> bool {
    !(addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_multicast())
}

fn is_usable_ipv6(addr: Ipv6Addr) -> bool {
    !(addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_unicast_link_local()
        || addr.is_unique_local()
        || addr.is_multicast())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_sync_servers_do_not_require_network() {
        let localhost = Url::parse("http://localhost:27701/").unwrap();
        let loopback = Url::parse("http://127.0.0.1:27701/").unwrap();

        assert!(!endpoint_requires_network(Some(&localhost)));
        assert!(!endpoint_requires_network(Some(&loopback)));
    }

    #[test]
    fn ankiweb_requires_network() {
        assert!(endpoint_requires_network(None));
        assert!(endpoint_requires_network(Some(
            &Url::parse("https://sync.ankiweb.net/").unwrap()
        )));
    }

    #[test]
    fn link_local_addresses_are_not_usable_for_internet_sync() {
        assert!(!is_usable_ipv4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_usable_ipv6("fe80::1".parse().unwrap()));
    }

    #[test]
    fn routable_addresses_are_usable_for_internet_sync() {
        assert!(is_usable_ipv4(Ipv4Addr::new(192, 168, 1, 2)));
        assert!(is_usable_ipv6("2001:4860:4860::8888".parse().unwrap()));
    }
}
