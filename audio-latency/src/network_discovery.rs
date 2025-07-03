use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use tracing::{info, warn, debug};

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_addresses: Vec<IpAddr>,
    pub mtu: u32,
    pub is_up: bool,
    pub interface_type: String, // "ethernet", "bridge", "veth", etc.
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: String,
    pub gateway: Option<String>,
    pub interface: String,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct NetworkTopology {
    pub interfaces: Vec<NetworkInterface>,
    pub routes: Vec<RouteEntry>,
    pub default_interface: Option<String>,
    pub pod_interfaces: Vec<String>, // Interfaces that likely carry pod traffic
}

impl NetworkTopology {
    pub fn discover() -> Result<Self> {
        info!("Starting network topology discovery");
        
        let interfaces = discover_interfaces()?;
        let routes = discover_routes()?;
        let default_interface = find_default_interface(&routes);
        let pod_interfaces = identify_pod_interfaces(&interfaces);
        
        let topology = NetworkTopology {
            interfaces,
            routes,
            default_interface,
            pod_interfaces,
        };
        
        topology.log_topology();
        
        Ok(topology)
    }
    
    fn log_topology(&self) {
        info!(
            event_type = "network_topology_discovered",
            interface_count = self.interfaces.len(),
            route_count = self.routes.len(),
            default_interface = self.default_interface.as_deref().unwrap_or("none"),
            pod_interface_count = self.pod_interfaces.len(),
            "Network topology discovery complete"
        );
        
        for interface in &self.interfaces {
            info!(
                event_type = "interface_discovered",
                name = %interface.name,
                ip_count = interface.ip_addresses.len(),
                mtu = interface.mtu,
                is_up = interface.is_up,
                interface_type = %interface.interface_type,
                ips = ?interface.ip_addresses,
                "Network interface discovered"
            );
        }
        
        debug!("Routes discovered:");
        for route in &self.routes {
            debug!(
                destination = %route.destination,
                gateway = route.gateway.as_deref().unwrap_or("direct"),
                interface = %route.interface,
                metric = route.metric,
                "Route entry"
            );
        }
        
        if !self.pod_interfaces.is_empty() {
            info!(
                pod_interfaces = ?self.pod_interfaces,
                "Identified likely pod traffic interfaces"
            );
        }
    }
    
    pub fn get_recommended_interfaces(&self) -> Vec<String> {
        // Return interfaces we should monitor for pod traffic
        if !self.pod_interfaces.is_empty() {
            self.pod_interfaces.clone()
        } else if let Some(default) = &self.default_interface {
            vec![default.clone()]
        } else {
            vec!["eth0".to_string()] // Fallback
        }
    }
}

fn discover_interfaces() -> Result<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();
    
    // Use `ip addr show` to get interface information
    let output = Command::new("ip")
        .args(&["addr", "show"])
        .output()?;
    
    if !output.status.success() {
        warn!("Failed to run 'ip addr show': {}", String::from_utf8_lossy(&output.stderr));
        return Ok(interfaces);
    }
    
    let output_str = String::from_utf8(output.stdout)?;
    interfaces.extend(parse_ip_addr_output(&output_str)?);
    
    Ok(interfaces)
}

fn parse_ip_addr_output(output: &str) -> Result<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();
    let mut current_interface: Option<NetworkInterface> = None;
    
    for line in output.lines() {
        let line = line.trim();
        
        // Interface line: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001"
        if let Some(colon_pos) = line.find(':') {
            if line.chars().nth(0).unwrap_or(' ').is_ascii_digit() {
                // Save previous interface
                if let Some(iface) = current_interface.take() {
                    interfaces.push(iface);
                }
                
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[1].trim_end_matches(':').to_string();
                    let flags = parts.get(2).unwrap_or(&"").to_string();
                    let is_up = flags.contains("UP");
                    
                    let mtu = parts.iter()
                        .position(|&x| x == "mtu")
                        .and_then(|i| parts.get(i + 1))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(1500);
                    
                    let interface_type = infer_interface_type(&name);
                    
                    current_interface = Some(NetworkInterface {
                        name,
                        ip_addresses: Vec::new(),
                        mtu,
                        is_up,
                        interface_type,
                    });
                }
            }
        }
        
        // IP address line: "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"
        if line.starts_with("inet ") || line.starts_with("inet6 ") {
            if let Some(ref mut iface) = current_interface {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let addr_with_prefix = parts[1];
                    if let Some(addr_str) = addr_with_prefix.split('/').next() {
                        if let Ok(addr) = addr_str.parse::<IpAddr>() {
                            iface.ip_addresses.push(addr);
                        }
                    }
                }
            }
        }
    }
    
    // Save last interface
    if let Some(iface) = current_interface {
        interfaces.push(iface);
    }
    
    Ok(interfaces)
}

fn infer_interface_type(name: &str) -> String {
    if name.starts_with("eth") {
        "ethernet".to_string()
    } else if name.starts_with("veth") {
        "veth".to_string()
    } else if name.starts_with("br") || name.contains("bridge") {
        "bridge".to_string()
    } else if name.starts_with("docker") {
        "docker".to_string()
    } else if name.starts_with("cni") {
        "cni".to_string()
    } else if name == "lo" {
        "loopback".to_string()
    } else {
        "unknown".to_string()
    }
}

fn discover_routes() -> Result<Vec<RouteEntry>> {
    let mut routes = Vec::new();
    
    // Use `ip route show` to get routing information
    let output = Command::new("ip")
        .args(&["route", "show"])
        .output()?;
    
    if !output.status.success() {
        warn!("Failed to run 'ip route show': {}", String::from_utf8_lossy(&output.stderr));
        return Ok(routes);
    }
    
    let output_str = String::from_utf8(output.stdout)?;
    routes.extend(parse_ip_route_output(&output_str)?);
    
    Ok(routes)
}

fn parse_ip_route_output(output: &str) -> Result<Vec<RouteEntry>> {
    let mut routes = Vec::new();
    
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        
        let destination = parts[0].to_string();
        
        let mut gateway = None;
        let mut interface = String::new();
        let mut metric = None;
        
        let mut i = 1;
        while i < parts.len() {
            match parts[i] {
                "via" if i + 1 < parts.len() => {
                    gateway = Some(parts[i + 1].to_string());
                    i += 2;
                }
                "dev" if i + 1 < parts.len() => {
                    interface = parts[i + 1].to_string();
                    i += 2;
                }
                "metric" if i + 1 < parts.len() => {
                    metric = parts[i + 1].parse().ok();
                    i += 2;
                }
                _ => i += 1,
            }
        }
        
        if !interface.is_empty() {
            routes.push(RouteEntry {
                destination,
                gateway,
                interface,
                metric,
            });
        }
    }
    
    Ok(routes)
}

fn find_default_interface(routes: &[RouteEntry]) -> Option<String> {
    routes
        .iter()
        .find(|route| route.destination == "default" || route.destination == "0.0.0.0/0")
        .map(|route| route.interface.clone())
}

fn identify_pod_interfaces(interfaces: &[NetworkInterface]) -> Vec<String> {
    let mut pod_interfaces = Vec::new();
    
    for interface in interfaces {
        // In EKS, pod interfaces are often:
        // - Additional ethernet interfaces (eth1, eth2, etc.)
        // - Have specific IP ranges
        // - Are UP and have IPs assigned
        
        if !interface.is_up || interface.ip_addresses.is_empty() {
            continue;
        }
        
        // Skip loopback and docker interfaces
        if interface.name == "lo" || interface.name.starts_with("docker") {
            continue;
        }
        
        // In EKS, secondary ENIs often start with eth1, eth2, etc.
        if interface.name.starts_with("eth") && interface.name != "eth0" {
            pod_interfaces.push(interface.name.clone());
            continue;
        }
        
        // Also check for interfaces with pod CIDR ranges (typical AWS ranges)
        for ip in &interface.ip_addresses {
            if let IpAddr::V4(ipv4) = ip {
                let octets = ipv4.octets();
                // Common AWS pod CIDR ranges
                if (octets[0] == 192 && octets[1] == 168) || 
                   (octets[0] == 172 && (16..=31).contains(&octets[1])) ||
                   (octets[0] == 10) {
                    if !pod_interfaces.contains(&interface.name) {
                        pod_interfaces.push(interface.name.clone());
                    }
                    break;
                }
            }
        }
    }
    
    pod_interfaces
}

// Metrics integration
pub fn create_network_metrics(topology: &NetworkTopology) -> HashMap<String, f64> {
    let mut metrics = HashMap::new();
    
    metrics.insert("network_interfaces_total".to_string(), topology.interfaces.len() as f64);
    metrics.insert("network_routes_total".to_string(), topology.routes.len() as f64);
    metrics.insert("network_pod_interfaces_total".to_string(), topology.pod_interfaces.len() as f64);
    
    // Count interfaces by type
    let mut type_counts: HashMap<String, u32> = HashMap::new();
    for interface in &topology.interfaces {
        *type_counts.entry(interface.interface_type.clone()).or_insert(0) += 1;
    }
    
    for (iface_type, count) in type_counts {
        metrics.insert(format!("network_interfaces_by_type_{}", iface_type), count as f64);
    }
    
    metrics
}