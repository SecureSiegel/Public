use anyhow::{Context, Result};
use pnet::datalink;
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::process::Command;

fn main() -> Result<()> {
    println!("Scanning for active devices on private network...\n");

    let mut active_devices = BTreeSet::new();

    for interface in datalink::interfaces() {
        if !interface.is_up() || interface.is_loopback() {
            continue;
        }

        println!("Scanning interface: {}", interface.name);

        for ip_network in &interface.ips {
            if let IpNetwork::V4(v4_net) = ip_network {
                if !is_private_ipv4(v4_net.ip()) {
                    continue;
                }

                println!("  Checking subnet: {}/{}", v4_net.network(), v4_net.prefix());
                let devices = scan_subnet(v4_net)?;
                active_devices.extend(devices);
            }
        }
    }

    println!("\n=== Active Devices ===");
    if active_devices.is_empty() {
        println!("No active devices found.");
    } else {
        for device_ip in &active_devices {
            println!("{}", device_ip);
        }
    }

    println!("\nTotal devices found: {}", active_devices.len());
    Ok(())
}

fn scan_subnet(network: &Ipv4Network) -> Result<Vec<Ipv4Addr>> {
    let mut active_devices = Vec::new();
    let mut current = network.network();

    while current <= network.broadcast() {
        if current != network.network() && current != network.broadcast() && ping_host(current)? {
            active_devices.push(current);
        }

        current = next_ipv4(current);
    }

    Ok(active_devices)
}

fn ping_host(ip: Ipv4Addr) -> Result<bool> {
    let timeout = "0.5";
    let output = Command::new("ping")
        .args(["-n", "-q", "-c", "1", "-W", timeout, &ip.to_string()])
        .output()
        .context("failed to execute ping")?;

    Ok(output.status.success())
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    octets[0] == 10
        || (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31))
        || (octets[0] == 192 && octets[1] == 168)
}

fn next_ipv4(ip: Ipv4Addr) -> Ipv4Addr {
    let [a, b, c, d] = ip.octets();
    if d == 255 {
        if c == 255 {
            if b == 255 {
                return Ipv4Addr::new(a, b, c, d);
            }
            return Ipv4Addr::new(a, b + 1, 0, 0);
        }
        return Ipv4Addr::new(a, b, c + 1, 0);
    }

    Ipv4Addr::new(a, b, c, d + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances_ipv4_addresses_correctly() {
        assert_eq!(next_ipv4(Ipv4Addr::new(192, 168, 1, 1)), Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(next_ipv4(Ipv4Addr::new(192, 168, 1, 255)), Ipv4Addr::new(192, 168, 2, 0));
    }

    #[test]
    fn detects_private_ipv4_ranges() {
        assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 50)));
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
    }
}
