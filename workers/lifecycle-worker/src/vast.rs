use std::{env, fs, net::IpAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_API_URL: &str = "https://console.vast.ai/api/v0/";
const DEFAULT_MAX_HOURLY_MICROS: u64 = 640_000;
const DEFAULT_DISK_GB: u64 = 16;

#[derive(Clone)]
pub(crate) struct VastBroker {
    client: Client,
    base_url: Url,
    token: Arc<String>,
    pub(crate) node_id: String,
    pub(crate) max_hourly_micros: u64,
    disk_gb: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Offer {
    pub(crate) id: u64,
    pub(crate) gpu_name: String,
    pub(crate) gpu_ram: u64,
    pub(crate) dph_total: f64,
}

#[derive(Debug, Clone)]
pub(crate) struct Instance {
    pub(crate) status: String,
    pub(crate) gpu_name: String,
    pub(crate) gpu_ram: u64,
    pub(crate) verification: String,
    pub(crate) hourly_micros: u64,
    pub(crate) ssh_host: Option<String>,
    pub(crate) ssh_port: Option<u16>,
}

#[derive(Deserialize)]
struct OfferResponse {
    #[serde(default)]
    offers: Vec<Offer>,
}

#[derive(Deserialize)]
struct CreateResponse {
    new_contract: u64,
}

#[derive(Deserialize)]
struct InstanceResponse {
    instances: RawInstance,
}

#[derive(Deserialize)]
struct InstancesResponse {
    #[serde(default)]
    instances: Vec<ListedInstance>,
}

#[derive(Deserialize)]
struct RawInstance {
    actual_status: String,
    gpu_name: String,
    gpu_ram: u64,
    verification: String,
    dph_total: f64,
    ssh_host: Option<String>,
    ssh_port: Option<u16>,
}

#[derive(Deserialize)]
struct ListedInstance {
    id: u64,
    label: Option<String>,
}

#[derive(Serialize)]
struct CreateRequest<'a> {
    image: &'a str,
    label: String,
    disk: u32,
    runtype: &'static str,
    cancel_unavail: bool,
}

impl VastBroker {
    pub(crate) fn from_environment() -> anyhow::Result<Option<Self>> {
        let Ok(node_id) = env::var("PRISM_VAST_NODE_ID") else {
            return Ok(None);
        };
        if node_id.trim().is_empty() {
            return Ok(None);
        }
        let token = read_token()?;
        let base_url = Url::parse(
            &env::var("PRISM_VAST_API_URL").unwrap_or_else(|_| DEFAULT_API_URL.to_owned()),
        )?;
        validate_api_url(&base_url)?;
        let max_hourly_micros = env_u64("PRISM_VAST_MAX_HOURLY_MICROS", DEFAULT_MAX_HOURLY_MICROS)?;
        if !(1..=10_000_000).contains(&max_hourly_micros) {
            anyhow::bail!("PRISM_VAST_MAX_HOURLY_MICROS is outside the supported range");
        }
        let disk_gb = u32::try_from(env_u64("PRISM_VAST_DISK_GB", DEFAULT_DISK_GB)?)?;
        if !(16..=2_048).contains(&disk_gb) {
            anyhow::bail!("PRISM_VAST_DISK_GB must be between 16 and 2048");
        }
        Ok(Some(Self {
            client: Client::builder().timeout(Duration::from_secs(30)).build()?,
            base_url,
            token: Arc::new(token),
            node_id,
            max_hourly_micros,
            disk_gb,
        }))
    }

    async fn search_offers(&self) -> anyhow::Result<Vec<Offer>> {
        let response = self
            .client
            .post(self.base_url.join("bundles/")?)
            .bearer_auth(self.token.as_str())
            .json(&serde_json::json!({
                "gpu_name": {"in": ["L40S"]},
                "num_gpus": {"eq": 1},
                "gpu_ram": {"gte": 45000},
                "reliability": {"gte": 0.99},
                "verified": {"eq": true},
                "rentable": {"eq": true},
                "type": "ondemand",
                "limit": 64
            }))
            .send()
            .await
            .context("search Vast offers")?
            .error_for_status()
            .context("Vast offer search failed")?
            .json::<OfferResponse>()
            .await
            .context("decode Vast offer search")?;
        Ok(response.offers)
    }

    pub(crate) async fn cheapest_l40s(&self) -> anyhow::Result<Option<Offer>> {
        Ok(select_offer(self.search_offers().await?, self.max_hourly_micros))
    }

    pub(crate) async fn ranked_l40s(&self, limit: usize) -> anyhow::Result<Vec<Offer>> {
        Ok(rank_offers(self.search_offers().await?, self.max_hourly_micros, limit))
    }

    pub(crate) async fn create(
        &self,
        offer_id: u64,
        image: &str,
        lease_id: u64,
    ) -> anyhow::Result<u64> {
        let response = self
            .client
            .put(self.base_url.join(&format!("asks/{offer_id}/"))?)
            .bearer_auth(self.token.as_str())
            .json(&CreateRequest {
                image,
                label: format!("prism-lease-{lease_id}"),
                disk: self.disk_gb,
                runtype: "ssh_direct",
                cancel_unavail: true,
            })
            .send()
            .await
            .context("create Vast instance")?
            .error_for_status()
            .context("Vast instance creation failed")?
            .json::<CreateResponse>()
            .await
            .context("decode Vast instance creation")?;
        if response.new_contract == 0 {
            anyhow::bail!("Vast returned an invalid instance ID");
        }
        Ok(response.new_contract)
    }

    pub(crate) async fn find_by_label(&self, label: &str) -> anyhow::Result<Option<u64>> {
        let mut url = self.base_url.join("../v1/instances/")?;
        url.query_pairs_mut()
            .append_pair(
                "select_filters",
                &serde_json::json!({"label": {"eq": label}}).to_string(),
            )
            .append_pair("select_cols", r#"["id","label"]"#);
        let response = self
            .client
            .get(url)
            .bearer_auth(self.token.as_str())
            .send()
            .await
            .context("list Vast instances")?
            .error_for_status()
            .context("Vast instance listing failed")?
            .json::<InstancesResponse>()
            .await
            .context("decode Vast instance listing")?;
        let mut matches = response
            .instances
            .into_iter()
            .filter(|instance| instance.label.as_deref() == Some(label));
        let found = matches.next().map(|instance| instance.id);
        if matches.next().is_some() {
            anyhow::bail!("multiple Vast instances share the lease label");
        }
        Ok(found)
    }

    pub(crate) async fn attach_ssh_key(
        &self,
        instance_id: u64,
        ssh_key: &str,
    ) -> anyhow::Result<()> {
        self.client
            .post(
                self.base_url
                    .join(&format!("instances/{instance_id}/ssh/"))?,
            )
            .bearer_auth(self.token.as_str())
            .json(&serde_json::json!({"ssh_key": ssh_key}))
            .send()
            .await
            .context("attach Vast SSH key")?
            .error_for_status()
            .context("Vast SSH key attachment failed")?;
        Ok(())
    }

    pub(crate) async fn instance(&self, instance_id: u64) -> anyhow::Result<Instance> {
        let response = self
            .client
            .get(self.base_url.join(&format!("instances/{instance_id}/"))?)
            .bearer_auth(self.token.as_str())
            .send()
            .await
            .context("read Vast instance")?
            .error_for_status()
            .context("Vast instance lookup failed")?
            .json::<InstanceResponse>()
            .await
            .context("decode Vast instance")?
            .instances;
        if response
            .ssh_host
            .as_deref()
            .is_some_and(|host| !valid_ssh_host(host))
        {
            anyhow::bail!("Vast returned an invalid SSH host");
        }
        Ok(Instance {
            status: response.actual_status,
            gpu_name: response.gpu_name,
            gpu_ram: response.gpu_ram,
            verification: response.verification,
            hourly_micros: hourly_micros(response.dph_total)?,
            ssh_host: response.ssh_host,
            ssh_port: response.ssh_port,
        })
    }

    pub(crate) async fn destroy(&self, instance_id: u64) -> anyhow::Result<()> {
        let response = self
            .client
            .delete(self.base_url.join(&format!("instances/{instance_id}/"))?)
            .bearer_auth(self.token.as_str())
            .send()
            .await
            .context("destroy Vast instance")?;
        if !matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::GONE) {
            response
                .error_for_status()
                .context("Vast instance destruction failed")?;
        }
        Ok(())
    }
}

fn rank_offers(offers: Vec<Offer>, max_hourly_micros: u64, limit: usize) -> Vec<Offer> {
    let mut eligible: Vec<Offer> = offers
        .into_iter()
        .filter(|offer| {
            offer.gpu_name.eq_ignore_ascii_case("L40S")
                && offer.gpu_ram >= 45_000
                && hourly_micros(offer.dph_total).is_ok_and(|cost| cost <= max_hourly_micros)
        })
        .collect();
    eligible.sort_by_key(|offer| hourly_micros(offer.dph_total).unwrap_or(u64::MAX));
    eligible.truncate(limit);
    eligible
}

fn select_offer(offers: Vec<Offer>, max_hourly_micros: u64) -> Option<Offer> {
    rank_offers(offers, max_hourly_micros, 1).into_iter().next()
}

pub(crate) fn hourly_micros(value: f64) -> anyhow::Result<u64> {
    if !value.is_finite() || value <= 0.0 {
        anyhow::bail!("Vast returned an invalid hourly price");
    }
    let micros = (value * 1_000_000.0).ceil();
    if micros > u64::MAX as f64 {
        anyhow::bail!("Vast hourly price is out of range");
    }
    Ok(micros as u64)
}

fn read_token() -> anyhow::Result<String> {
    let token = match env::var("PRISM_VAST_API_KEY_FILE") {
        Ok(path) => fs::read_to_string(PathBuf::from(path)).context("read Vast API key file")?,
        Err(_) => env::var("PRISM_VAST_API_KEY")
            .context("PRISM_VAST_API_KEY_FILE or PRISM_VAST_API_KEY is required")?,
    };
    let token = token.trim().to_owned();
    if token.is_empty() || token.contains(char::is_whitespace) {
        anyhow::bail!("Vast API key is invalid");
    }
    Ok(token)
}

fn env_u64(key: &str, default: u64) -> anyhow::Result<u64> {
    env::var(key)
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .with_context(|| format!("{key} must be an unsigned integer"))
        .map(|value| value.unwrap_or(default))
}

fn validate_api_url(url: &Url) -> anyhow::Result<()> {
    let local_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if url.scheme() != "https" && !local_http {
        anyhow::bail!("PRISM_VAST_API_URL must use HTTPS");
    }
    Ok(())
}

fn valid_ssh_host(host: &str) -> bool {
    if host.len() > 253 {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(id: u64, gpu: &str, ram: u64, price: f64) -> Offer {
        Offer {
            id,
            gpu_name: gpu.to_owned(),
            gpu_ram: ram,
            dph_total: price,
        }
    }

    #[test]
    fn selects_the_cheapest_qualified_l40s() {
        let selected = select_offer(
            vec![
                offer(1, "L40S", 46_068, 0.61),
                offer(2, "L40S", 46_068, 0.59),
                offer(3, "RTX 6000 Ada", 49_140, 0.40),
                offer(4, "L40S", 46_068, 0.70),
            ],
            640_000,
        )
        .unwrap();
        assert_eq!(selected.id, 2);
    }

    #[test]
    fn rejects_prices_above_the_ceiling() {
        assert!(select_offer(vec![offer(1, "L40S", 46_068, 0.640_001)], 640_000).is_none());
    }

    #[test]
    fn allows_only_secure_or_loopback_api_urls() {
        assert!(validate_api_url(&Url::parse(DEFAULT_API_URL).unwrap()).is_ok());
        assert!(validate_api_url(&Url::parse("http://127.0.0.1:8080/").unwrap()).is_ok());
        assert!(validate_api_url(&Url::parse("http://example.com/").unwrap()).is_err());
    }

    #[test]
    fn rejects_shell_metacharacters_in_ssh_hosts() {
        assert!(valid_ssh_host("ssh123.vast.ai"));
        assert!(valid_ssh_host("203.0.113.10"));
        assert!(!valid_ssh_host("ssh.vast.ai;curl.example"));
        assert!(!valid_ssh_host("-ssh.vast.ai"));
    }
}
