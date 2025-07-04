use anyhow::Result;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{Api, ResourceExt},
    runtime::{watcher, WatchStreamExt},
    Client,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

#[derive(Clone, Debug)]
pub struct PodMetadata {
    pub pod_name: String,
    pub namespace: String,
    #[allow(dead_code)]
    pub node_name: String,
    pub workload_kind: String,
    pub workload_name: String,
}

#[derive(Clone)]
pub struct PodCache {
    inner: Arc<RwLock<HashMap<IpAddr, PodMetadata>>>,
}

impl PodCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get(&self, ip: &IpAddr) -> Option<PodMetadata> {
        let cache = self.inner.read().await;
        cache.get(ip).cloned()
    }

    async fn insert(&self, ip: IpAddr, metadata: PodMetadata) {
        let mut cache = self.inner.write().await;
        debug!(
            pod_name = %metadata.pod_name,
            namespace = %metadata.namespace,
            ip = %ip,
            "Adding pod to cache"
        );
        cache.insert(ip, metadata);
    }

    async fn remove(&self, ip: &IpAddr) {
        let mut cache = self.inner.write().await;
        if cache.remove(ip).is_some() {
            debug!(ip = %ip, "Removed pod from cache");
        }
    }

    #[allow(dead_code)]
    pub async fn size(&self) -> usize {
        let cache = self.inner.read().await;
        cache.len()
    }
}

pub struct PodWatcher {
    client: Client,
    cache: PodCache,
}

impl PodWatcher {
    pub async fn new() -> Result<Self> {
        let client = Client::try_default().await?;
        Ok(Self {
            client,
            cache: PodCache::new(),
        })
    }

    pub fn cache(&self) -> &PodCache {
        &self.cache
    }

    pub async fn start(self) -> Result<()> {
        use kube::runtime::watcher::Config;

        let api: Api<Pod> = Api::all(self.client.clone());
        let watcher = watcher(api, Config::default());

        debug!("Starting pod watcher");

        let mut stream = watcher.applied_objects().boxed();
        let mut last_cache_report = std::time::Instant::now();

        while let Some(pod_result) = stream.next().await {
            match pod_result {
                Ok(pod) => {
                    self.handle_pod_event(&pod).await;
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Error watching pods"
                    );
                }
            }

            // Report cache size every 30 seconds
            if last_cache_report.elapsed() > std::time::Duration::from_secs(30) {
                let cache_size = self.cache.size().await;
                debug!("Pod cache size: {} pods", cache_size);
                last_cache_report = std::time::Instant::now();
            }
        }

        Ok(())
    }

    async fn handle_pod_event(&self, pod: &Pod) {
        let pod_name = pod.name_any();
        let namespace = pod.namespace().unwrap_or_default();

        // Extract pod IP
        let pod_ip = match pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.as_ref())
            .and_then(|ip| IpAddr::from_str(ip).ok())
        {
            Some(ip) => ip,
            None => {
                // Pod doesn't have an IP yet or it's being deleted
                return;
            }
        };

        // Check if pod is being deleted
        if pod.metadata.deletion_timestamp.is_some() {
            self.cache.remove(&pod_ip).await;
            debug!("Pod removed from cache: {} ({})", pod_ip, pod_name);
            return;
        }

        // Extract node name
        let node_name = match pod.spec.as_ref().and_then(|s| s.node_name.as_ref()) {
            Some(node) => node.clone(),
            None => return, // Pod not scheduled yet
        };

        // Extract workload information from owner references
        let (workload_kind, workload_name) = self.extract_workload_info(pod);

        let metadata = PodMetadata {
            pod_name: pod_name.clone(),
            namespace: namespace.clone(),
            node_name,
            workload_kind,
            workload_name,
        };

        self.cache.insert(pod_ip, metadata.clone()).await;

        debug!(
            "Pod cached: {} -> {}:{} in namespace {} on node {}",
            pod_ip,
            metadata.workload_kind,
            metadata.workload_name,
            metadata.namespace,
            metadata.node_name
        );
    }

    pub(crate) fn extract_workload_info(&self, pod: &Pod) -> (String, String) {
        extract_workload_info_from_pod(pod)
    }
}

// Standalone function for extracting workload info, easier to test
fn extract_workload_info_from_pod(pod: &Pod) -> (String, String) {
    if let Some(owner_refs) = &pod.metadata.owner_references {
        // Look for ReplicaSet first (most common for Deployments)
        for owner in owner_refs {
            match owner.kind.as_str() {
                "ReplicaSet" => {
                    // Extract deployment name from ReplicaSet name
                    // ReplicaSet names are typically: deployment-name-<hash>
                    let rs_name = &owner.name;
                    if let Some(dash_pos) = rs_name.rfind('-') {
                        let potential_deployment = &rs_name[..dash_pos];
                        // Verify it's a hash by checking if the suffix is alphanumeric
                        let suffix = &rs_name[dash_pos + 1..];
                        if suffix.chars().all(|c| c.is_alphanumeric()) && suffix.len() >= 5 {
                            return ("Deployment".to_string(), potential_deployment.to_string());
                        }
                    }
                    return ("ReplicaSet".to_string(), rs_name.clone());
                }
                "DaemonSet" => {
                    return ("DaemonSet".to_string(), owner.name.clone());
                }
                "StatefulSet" => {
                    return ("StatefulSet".to_string(), owner.name.clone());
                }
                "Job" => {
                    return ("Job".to_string(), owner.name.clone());
                }
                "CronJob" => {
                    return ("CronJob".to_string(), owner.name.clone());
                }
                _ => {}
            }
        }

        // If we have any owner, use it
        if let Some(owner) = owner_refs.first() {
            return (owner.kind.clone(), owner.name.clone());
        }
    }

    // No owner reference - probably a standalone pod
    ("Pod".to_string(), pod.name_any())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

    #[test]
    fn test_pod_cache_operations() {
        let cache = PodCache::new();
        let runtime = tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            // Test insert and get
            let metadata = PodMetadata {
                pod_name: "test-pod".to_string(),
                namespace: "default".to_string(),
                node_name: "node-1".to_string(),
                workload_kind: "Deployment".to_string(),
                workload_name: "test-app".to_string(),
            };

            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            cache.insert(ip, metadata.clone()).await;

            let retrieved = cache.get(&ip).await;
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().pod_name, "test-pod");

            // Test remove
            cache.remove(&ip).await;
            assert!(cache.get(&ip).await.is_none());
        });
    }

    #[test]
    fn test_workload_extraction_deployment() {
        let mut pod = Pod::default();
        pod.metadata.owner_references = Some(vec![OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "ReplicaSet".to_string(),
            name: "my-app-5d7f8c9b6".to_string(),
            uid: "12345".to_string(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }]);

        let (kind, name) = extract_workload_info_from_pod(&pod);
        assert_eq!(kind, "Deployment");
        assert_eq!(name, "my-app");
    }

    #[test]
    fn test_workload_extraction_daemonset() {
        let mut pod = Pod::default();
        pod.metadata.owner_references = Some(vec![OwnerReference {
            api_version: "apps/v1".to_string(),
            kind: "DaemonSet".to_string(),
            name: "node-monitor".to_string(),
            uid: "12345".to_string(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }]);

        let (kind, name) = extract_workload_info_from_pod(&pod);
        assert_eq!(kind, "DaemonSet");
        assert_eq!(name, "node-monitor");
    }

    #[test]
    fn test_workload_extraction_no_owner() {
        let mut pod = Pod::default();
        pod.metadata.name = Some("standalone-pod".to_string());

        let (kind, name) = extract_workload_info_from_pod(&pod);
        assert_eq!(kind, "Pod");
        assert_eq!(name, "standalone-pod");
    }
}
