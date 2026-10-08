//! One membership client per service, sharing the session's endpoint.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use iroh::Endpoint;
use lmk_membership::Membership;
use lmk_membership::client::ServeClient;
use lmk_proto::group::Service;

pub(crate) struct Logs {
    endpoint: Endpoint,
    clients: Mutex<HashMap<String, Arc<dyn Membership>>>,
}

impl Logs {
    pub fn new(endpoint: Endpoint) -> Self {
        Logs { endpoint, clients: Mutex::default() }
    }

    pub fn client(&self, service: &Service) -> Result<Arc<dyn Membership>> {
        let name = serde_json::to_string(service)?;
        let mut clients = self.clients.lock().unwrap();
        if let Some(client) = clients.get(&name) {
            return Ok(client.clone());
        }
        let client: Arc<dyn Membership> = match service {
            Service::Serve { .. } => Arc::new(ServeClient::for_service(self.endpoint.clone(), service)?),
            #[cfg(not(target_arch = "wasm32"))]
            Service::Folder(path) => Arc::new(lmk_membership::folder::FolderClient::new(path)),
            #[cfg(target_arch = "wasm32")]
            Service::Folder(_) => anyhow::bail!("a browser cannot reach a folder"),
        };
        clients.insert(name, client.clone());
        Ok(client)
    }
}
