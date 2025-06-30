use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use crate::config::ContainerRuntime;

#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub container_id: String,
    pub pod_name: Option<String>,
    pub namespace: Option<String>,
    pub runtime: ContainerRuntime,
}

pub struct ContainerIdentifier {
    runtime: ContainerRuntime,
}

impl ContainerIdentifier {
    pub fn new(runtime: ContainerRuntime) -> Self {
        Self { runtime }
    }
    
    /// Extract container info from a process PID by reading cgroups
    pub fn identify_by_pid(&self, pid: u32) -> Result<Option<ContainerInfo>> {
        let cgroup_path = format!("/proc/{}/cgroup", pid);
        
        if !Path::new(&cgroup_path).exists() {
            return Ok(None);
        }
        
        let cgroup_content = fs::read_to_string(&cgroup_path)
            .context("Failed to read cgroup file")?;
        
        // Try to detect runtime if set to auto
        let runtime = match self.runtime {
            ContainerRuntime::AutoDetect => self.detect_runtime(&cgroup_content),
            _ => self.runtime.clone(),
        };
        
        match runtime {
            ContainerRuntime::Docker => self.parse_docker_cgroup(&cgroup_content),
            ContainerRuntime::Containerd => self.parse_containerd_cgroup(&cgroup_content),
            ContainerRuntime::Crio => self.parse_crio_cgroup(&cgroup_content),
            ContainerRuntime::AutoDetect => {
                // Try all parsers
                self.parse_docker_cgroup(&cgroup_content)
                    .or_else(|_| self.parse_containerd_cgroup(&cgroup_content))
                    .or_else(|_| self.parse_crio_cgroup(&cgroup_content))
            }
        }
    }
    
    fn detect_runtime(&self, cgroup_content: &str) -> ContainerRuntime {
        if cgroup_content.contains("/docker/") {
            ContainerRuntime::Docker
        } else if cgroup_content.contains("/containerd/") {
            ContainerRuntime::Containerd
        } else if cgroup_content.contains("/crio/") {
            ContainerRuntime::Crio
        } else {
            ContainerRuntime::AutoDetect
        }
    }
    
    fn parse_docker_cgroup(&self, content: &str) -> Result<Option<ContainerInfo>> {
        // Example: 12:memory:/docker/7d3b1c3a.../kubepods/besteffort/pod123/456
        for line in content.lines() {
            if let Some(docker_path) = line.split("/docker/").nth(1) {
                let parts: Vec<&str> = docker_path.split('/').collect();
                if !parts.is_empty() {
                    let container_id = parts[0].chars().take(12).collect::<String>();
                    
                    // Extract k8s info if present
                    let (pod_name, namespace) = self.extract_k8s_info(&parts);
                    
                    return Ok(Some(ContainerInfo {
                        container_id,
                        pod_name,
                        namespace,
                        runtime: ContainerRuntime::Docker,
                    }));
                }
            }
        }
        Ok(None)
    }
    
    fn parse_containerd_cgroup(&self, content: &str) -> Result<Option<ContainerInfo>> {
        // Example: 12:memory:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod123.slice/cri-containerd-456.scope
        for line in content.lines() {
            if line.contains("cri-containerd-") {
                if let Some(container_part) = line.split("cri-containerd-").nth(1) {
                    let container_id = container_part
                        .split('.')
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(12)
                        .collect::<String>();
                    
                    // Extract pod info from the path
                    let (pod_name, namespace) = if let Some(pod_part) = line.split("pod").nth(1) {
                        let pod_uid = pod_part.split('.').next().unwrap_or("");
                        // In real implementation, we'd look up pod by UID
                        (Some(format!("pod-{}", pod_uid)), None)
                    } else {
                        (None, None)
                    };
                    
                    return Ok(Some(ContainerInfo {
                        container_id,
                        pod_name,
                        namespace,
                        runtime: ContainerRuntime::Containerd,
                    }));
                }
            }
        }
        Ok(None)
    }
    
    fn parse_crio_cgroup(&self, content: &str) -> Result<Option<ContainerInfo>> {
        // Example: 12:memory:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod123.slice/crio-456.scope
        for line in content.lines() {
            if line.contains("crio-") && !line.contains("crio-conmon-") {
                if let Some(container_part) = line.split("crio-").nth(1) {
                    let container_id = container_part
                        .split('.')
                        .next()
                        .unwrap_or("")
                        .chars()
                        .take(12)
                        .collect::<String>();
                    
                    let (pod_name, namespace) = self.extract_k8s_info_from_path(line);
                    
                    return Ok(Some(ContainerInfo {
                        container_id,
                        pod_name,
                        namespace,
                        runtime: ContainerRuntime::Crio,
                    }));
                }
            }
        }
        Ok(None)
    }
    
    fn extract_k8s_info(&self, parts: &[&str]) -> (Option<String>, Option<String>) {
        // Look for pod UID pattern
        for (i, part) in parts.iter().enumerate() {
            if part.starts_with("pod") && i + 1 < parts.len() {
                let pod_uid = parts[i + 1];
                // In production, we'd look this up via k8s API
                return (Some(format!("pod-{}", &pod_uid[..8])), None);
            }
        }
        (None, None)
    }
    
    fn extract_k8s_info_from_path(&self, path: &str) -> (Option<String>, Option<String>) {
        if let Some(pod_section) = path.split("pod").nth(1) {
            let pod_uid = pod_section
                .split(|c: char| !c.is_alphanumeric() && c != '-')
                .find(|s| s.len() >= 8)
                .unwrap_or("");
            
            if !pod_uid.is_empty() {
                return (Some(format!("pod-{}", &pod_uid[..8])), None);
            }
        }
        (None, None)
    }
}

/// Get the PID of a TCP connection
pub fn get_pid_for_connection(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> Result<Option<u32>> {
    // Read /proc/net/tcp to find the inode
    let tcp_content = fs::read_to_string("/proc/net/tcp")
        .context("Failed to read /proc/net/tcp")?;
    
    let src_hex = ip_port_to_hex(src_ip, src_port)?;
    let dst_hex = ip_port_to_hex(dst_ip, dst_port)?;
    
    let mut inode = None;
    for line in tcp_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 9 {
            if (parts[1] == src_hex && parts[2] == dst_hex) || 
               (parts[1] == dst_hex && parts[2] == src_hex) {
                inode = Some(parts[9].parse::<u64>().unwrap_or(0));
                break;
            }
        }
    }
    
    if let Some(inode) = inode {
        // Search all processes for this socket inode
        for entry in fs::read_dir("/proc")? {
            if let Ok(entry) = entry {
                if let Some(pid_str) = entry.file_name().to_str() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        let fd_path = format!("/proc/{}/fd", pid);
                        if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                            for fd_entry in fd_entries {
                                if let Ok(fd_entry) = fd_entry {
                                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                                        if let Some(link_str) = link.to_str() {
                                            if link_str.contains(&format!("socket:[{}]", inode)) {
                                                return Ok(Some(pid));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(None)
}

fn ip_port_to_hex(ip: &str, port: u16) -> Result<String> {
    let octets: Vec<u8> = ip.split('.')
        .map(|s| s.parse::<u8>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid IP address")?;
    
    // Convert to little-endian hex format used in /proc/net/tcp
    Ok(format!("{:02X}{:02X}{:02X}{:02X}:{:04X}",
        octets[3], octets[2], octets[1], octets[0],
        port))
}