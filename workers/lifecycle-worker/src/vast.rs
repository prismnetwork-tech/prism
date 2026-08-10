use std::{env, fs, net::IpAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_API_URL: &str = "https://console.vast.ai/api/v0/";
const DEFAULT_MAX_HOURLY_MICROS: u64 = 640_000;
const DEFAULT_DISK_GB: u64 = 16;
const DEFAULT_GPU_MODELS: &str = "L40S";
const DEFAULT_MIN_GPU_RAM_MIB: u64 = 45_000;

#[derive(Clone)]
pub(crate) struct VastBroker {
    client: Client,
    base_url: Url,
    token: Arc<String>,
    /// Every broker identity this worker answers for. One bonded node is one
    /// concurrent lease, because the registry frees a node only when its lease
    /// settles, so serving more than one customer at a time means holding more
    /// than one identity.
    pub(crate) node_ids: Arc<Vec<String>>,
    pub(crate) max_hourly_micros: u64,
    /// Which GPUs the broker will rent on a renter's behalf. One class leaves
    /// the network at the mercy of one market: when a verified L40S costs more
    /// than a lease charges, there is nothing to sell at any price.
    pub(crate) gpu_models: Arc<Vec<String>>,
    pub(crate) min_gpu_ram_mib: u64,
    disk_gb: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Offer {
    pub(crate) id: u64,
    pub(crate) machine_id: u64,
    pub(crate) gpu_name: String,
    pub(crate) gpu_ram: u64,
    pub(crate) dph_total: f64,
}

#[derive(Debug, Clone)]
pub(crate) struct Survey {
    /// Offers Vast returned for the search, before this broker's own rules.
    pub(crate) listed: usize,
    /// Of those, the ones in a class and memory size this broker rents.
    pub(crate) of_our_class: usize,
    pub(crate) cheapest_of_class: Option<u64>,
    pub(crate) ceiling: u64,
    /// One host per slot we are willing to advertise, cheapest first.
    pub(crate) hosts: Vec<Offer>,
    /// Every host of a class this broker rents, before the price ceiling.
    admitted: Vec<Offer>,
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
    pub(crate) direct_port_start: i64,
    pub(crate) machine_id: u64,
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

/// Every field but the identity is absent for the first minutes of a booting
/// instance, so none of them can be required: a missing field is a machine that
/// has not finished coming up, not a malformed response.
#[derive(Deserialize)]
struct RawInstance {
    #[serde(default)]
    actual_status: Option<String>,
    #[serde(default)]
    gpu_name: Option<String>,
    #[serde(default)]
    gpu_ram: Option<u64>,
    #[serde(default)]
    verification: Option<String>,
    #[serde(default)]
    dph_total: Option<f64>,
    #[serde(default)]
    ssh_host: Option<String>,
    #[serde(default)]
    ssh_port: Option<u16>,
    /// Vast reports -1 when the host could not reserve a forwarded port range,
    /// and nothing at all until it has tried.
    #[serde(default)]
    direct_port_start: Option<i64>,
    #[serde(default)]
    machine_id: Option<u64>,
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
        // Compose renders an unset variable as the empty string, so an env_var
        // that is present and blank has to read as absent. Taking Ok("") for an
        // answer here skips the singular name and takes the whole market down.
        let configured = non_empty_env("PRISM_VAST_NODE_IDS")
            .or_else(|| non_empty_env("PRISM_VAST_NODE_ID"))
            .unwrap_or_default();
        let node_ids: Vec<String> = configured
            .split(',')
            .map(|id| id.trim().to_owned())
            .filter(|id| !id.is_empty())
            .collect();
        if node_ids.is_empty() {
            if non_empty_env("PRISM_VAST_API_KEY_FILE").is_some()
                || non_empty_env("PRISM_VAST_API_KEY").is_some()
            {
                tracing::warn!(
                    "PRISM_VAST_NODE_IDS is empty, so the broker offers no capacity at all"
                );
            }
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
        let gpu_models: Vec<String> = env::var("PRISM_VAST_GPU_MODELS")
            .unwrap_or_else(|_| DEFAULT_GPU_MODELS.to_owned())
            .split(',')
            .map(|model| model.trim().to_owned())
            .filter(|model| !model.is_empty())
            .collect();
        if gpu_models.is_empty() {
            anyhow::bail!("PRISM_VAST_GPU_MODELS must name at least one GPU");
        }
        let min_gpu_ram_mib = env_u64("PRISM_VAST_MIN_GPU_RAM_MIB", DEFAULT_MIN_GPU_RAM_MIB)?;
        if !(1_024..=1_048_576).contains(&min_gpu_ram_mib) {
            anyhow::bail!("PRISM_VAST_MIN_GPU_RAM_MIB is outside the supported range");
        }
        let disk_gb = u32::try_from(env_u64("PRISM_VAST_DISK_GB", DEFAULT_DISK_GB)?)?;
        if !(16..=2_048).contains(&disk_gb) {
            anyhow::bail!("PRISM_VAST_DISK_GB must be between 16 and 2048");
        }
        Ok(Some(Self {
            client: Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(30))
                .build()?,
            base_url,
            token: Arc::new(token),
            node_ids: Arc::new(node_ids),
            max_hourly_micros,
            gpu_models: Arc::new(gpu_models),
            min_gpu_ram_mib,
            disk_gb,
        }))
    }

    async fn search_offers(&self) -> anyhow::Result<Vec<Offer>> {
        let response = self
            .client
            .post(self.base_url.join("bundles/")?)
            .bearer_auth(self.token.as_str())
            .json(&serde_json::json!({
                "gpu_name": {"in": self.gpu_models.as_ref()},
                "num_gpus": {"eq": 1},
                "gpu_ram": {"gte": self.min_gpu_ram_mib},
                "reliability": {"gte": 0.99},
                "verified": {"eq": true},
                "rentable": {"eq": true},
                "direct_port_count": {"gte": 1},
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

    /// The same survey, but keeping as many distinct hosts as there are free
    /// slots to advertise. Listing more slots than hosts sells capacity that is
    /// not there.
    pub(crate) async fn survey_many(&self, ceiling: u64, slots: usize) -> anyhow::Result<Survey> {
        let mut survey = self.survey(ceiling).await?;
        survey.hosts = rank_offers(survey.admitted.clone(), self.ceiling(ceiling), slots, &[]);
        Ok(survey)
    }

    /// What the market held, what this broker would rent, and the best of it.
    /// "No capacity" is three different situations and they need telling apart.
    pub(crate) async fn survey(&self, ceiling: u64) -> anyhow::Result<Survey> {
        let offers = self.search_offers().await?;
        let listed = offers.len();
        let admitted: Vec<Offer> = offers
            .into_iter()
            .filter(|offer| self.admits(&offer.gpu_name, offer.gpu_ram))
            .collect();
        let of_our_class = admitted.len();
        let cheapest_of_class = admitted
            .iter()
            .filter_map(|offer| hourly_micros(offer.dph_total).ok())
            .min();
        Ok(Survey {
            listed,
            of_our_class,
            cheapest_of_class,
            ceiling: self.ceiling(ceiling),
            hosts: rank_offers(admitted.clone(), self.ceiling(ceiling), 1, &[]),
            admitted,
        })
    }

    /// Whether an instance is one of the classes this broker rents.
    /// Whether a lease's node is one this worker brokers for.
    pub(crate) fn owns(&self, node_id: &str) -> bool {
        self.node_ids.iter().any(|owned| owned == node_id)
    }

    pub(crate) fn policy(&self) -> String {
        format!(
            "{} with at least {} MiB, up to {} micros/hr",
            self.gpu_models.join(" or "),
            self.min_gpu_ram_mib,
            self.max_hourly_micros
        )
    }

    pub(crate) fn admits(&self, gpu_name: &str, gpu_ram_mib: u64) -> bool {
        gpu_ram_mib >= self.min_gpu_ram_mib
            && self
                .gpu_models
                .iter()
                .any(|model| model.eq_ignore_ascii_case(gpu_name))
    }

    /// Sourcing above what the renter pays is a loss the settlement worker will
    /// refuse to sign off, stranding the escrow. Whatever the operator sets, the
    /// lease's own rate is the real ceiling.
    pub(crate) fn ceiling(&self, retail_hourly_micros: u64) -> u64 {
        self.max_hourly_micros.min(retail_hourly_micros)
    }

    pub(crate) async fn ranked(
        &self,
        limit: usize,
        rejected: &[i64],
        ceiling: u64,
    ) -> anyhow::Result<Vec<Offer>> {
        let offers = self
            .search_offers()
            .await?
            .into_iter()
            .filter(|offer| self.admits(&offer.gpu_name, offer.gpu_ram))
            .collect();
        Ok(rank_offers(offers, self.ceiling(ceiling), limit, rejected))
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

    /// Newest first, so a caller adopting one instance can destroy the rest.
    pub(crate) async fn find_by_label(&self, label: &str) -> anyhow::Result<Vec<u64>> {
        let mut url = self.base_url.join("../v1/instances/")?;
        url.query_pairs_mut()
            .append_pair(
                "select_filters",
                &serde_json::json!({"label": {"eq": label}}).to_string(),
            )
            .append_pair("select_cols", r#"["id","label"]"#)
            .append_pair("limit", "100");
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
        let mut found: Vec<u64> = response
            .instances
            .into_iter()
            .filter(|instance| instance.label.as_deref() == Some(label))
            .map(|instance| instance.id)
            .collect();
        found.sort_unstable_by(|a, b| b.cmp(a));
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
        let body = self
            .client
            .get(self.base_url.join(&format!("instances/{instance_id}/"))?)
            .bearer_auth(self.token.as_str())
            .send()
            .await
            .context("read Vast instance")?
            .error_for_status()
            .context("Vast instance lookup failed")?
            .text()
            .await
            .context("read Vast instance body")?;
        instance_from_response(&body)
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

/// An instance only counts as running once it reports everything admission has
/// to judge it on. Reporting a half-populated machine as running would put the
/// admission checks in front of defaults rather than facts.
fn instance_from_response(body: &str) -> anyhow::Result<Instance> {
    let raw = serde_json::from_str::<InstanceResponse>(body)
        .with_context(|| format!("decode Vast instance: {}", truncate(body, 300)))?
        .instances;
    if raw
        .ssh_host
        .as_deref()
        .is_some_and(|host| !valid_ssh_host(host))
    {
        anyhow::bail!("Vast returned an invalid SSH host");
    }
    let complete = raw.gpu_name.is_some()
        && raw.gpu_ram.is_some()
        && raw.verification.is_some()
        && raw.dph_total.is_some()
        && raw.direct_port_start.is_some()
        && raw.machine_id.is_some_and(|machine_id| machine_id != 0);
    let status = match raw.actual_status {
        Some(status) if status == "running" && !complete => "loading".to_owned(),
        Some(status) => status,
        None => "loading".to_owned(),
    };
    Ok(Instance {
        status,
        gpu_name: raw.gpu_name.unwrap_or_default(),
        gpu_ram: raw.gpu_ram.unwrap_or_default(),
        verification: raw.verification.unwrap_or_default(),
        hourly_micros: raw.dph_total.map(hourly_micros).transpose()?.unwrap_or(0),
        ssh_host: raw.ssh_host,
        ssh_port: raw.ssh_port,
        direct_port_start: raw.direct_port_start.unwrap_or_default(),
        machine_id: raw.machine_id.unwrap_or_default(),
    })
}

fn truncate(value: &str, limit: usize) -> &str {
    match value.char_indices().nth(limit) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

fn rank_offers(
    offers: Vec<Offer>,
    max_hourly_micros: u64,
    limit: usize,
    rejected: &[i64],
) -> Vec<Offer> {
    let mut eligible: Vec<Offer> = offers
        .into_iter()
        .filter(|offer| {
            hourly_micros(offer.dph_total).is_ok_and(|cost| cost <= max_hourly_micros)
                && !rejected.contains(&(offer.machine_id as i64))
        })
        .collect();
    eligible.sort_by_key(|offer| hourly_micros(offer.dph_total).unwrap_or(u64::MAX));
    eligible.truncate(limit);
    eligible
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

fn non_empty_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
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

    /// Compose writes an unset variable as the empty string. Reading that as a
    /// real value once left the broker with no nodes and the market with no GPUs.
    #[test]
    fn a_blank_variable_reads_as_absent() {
        let key = "PRISM_TEST_BLANK_NODE_IDS";
        unsafe { env::set_var(key, "  ") };
        assert_eq!(non_empty_env(key), None);
        unsafe { env::set_var(key, "0xabc") };
        assert_eq!(non_empty_env(key).as_deref(), Some("0xabc"));
        unsafe { env::remove_var(key) };
        assert_eq!(non_empty_env(key), None);
    }

    /// The same two steps `ranked` runs: keep the classes the broker rents,
    /// then take the cheapest that clears the ceiling.
    fn cheapest_of(offers: Vec<Offer>, max_hourly_micros: u64) -> Option<Offer> {
        let broker = broker(&["L40S"], 45_000, max_hourly_micros);
        let eligible = offers
            .into_iter()
            .filter(|offer| broker.admits(&offer.gpu_name, offer.gpu_ram))
            .collect();
        rank_offers(eligible, max_hourly_micros, 1, &[])
            .into_iter()
            .next()
    }

    fn broker(models: &[&str], min_gpu_ram_mib: u64, max_hourly_micros: u64) -> VastBroker {
        VastBroker {
            client: Client::new(),
            base_url: Url::parse(DEFAULT_API_URL).unwrap(),
            token: Arc::new("token".to_owned()),
            node_ids: Arc::new(vec!["0xabc".to_owned()]),
            max_hourly_micros,
            gpu_models: Arc::new(models.iter().map(|model| (*model).to_owned()).collect()),
            min_gpu_ram_mib,
            disk_gb: 16,
        }
    }

    fn offer(id: u64, gpu: &str, ram: u64, price: f64) -> Offer {
        Offer {
            id,
            machine_id: id * 10,
            gpu_name: gpu.to_owned(),
            gpu_ram: ram,
            dph_total: price,
        }
    }

    #[test]
    fn selects_the_cheapest_qualified_l40s() {
        let selected = cheapest_of(
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

    /// Machine 24733 advertises 124 forwarded ports and hands out none, so a
    /// lease that already burned it has to be able to reach past it to the next
    /// host instead of failing on the cheapest offer forever.
    #[test]
    fn ranking_skips_machines_a_lease_already_rejected() {
        let offers = vec![
            offer(1, "L40S", 46_068, 0.53),
            offer(2, "L40S", 46_068, 0.74),
            offer(3, "L40S", 46_068, 0.80),
        ];

        let ranked = rank_offers(offers.clone(), 900_000, 8, &[]);
        assert_eq!(ranked[0].id, 1);

        let ranked = rank_offers(offers, 900_000, 8, &[10, 20]);
        assert_eq!(
            ranked.iter().map(|offer| offer.id).collect::<Vec<_>>(),
            vec![3]
        );
    }

    #[test]
    fn rejects_prices_above_the_ceiling() {
        assert!(cheapest_of(vec![offer(1, "L40S", 46_068, 0.640_001)], 640_000).is_none());
    }

    /// Lease 29 sourced a host at 802_963 micros/hr against a retail rate of
    /// 799_200, ran to completion, and then could not be settled: the receipt
    /// would have signed off a loss, so the escrow stuck.
    #[test]
    fn an_operator_ceiling_cannot_exceed_what_the_renter_pays() {
        let broker = broker(&["L40S"], 45_000, 1_100_000);

        assert_eq!(broker.ceiling(799_200), 799_200);
        assert!(
            rank_offers(
                vec![offer(1, "L40S", 46_068, 0.802_963)],
                broker.ceiling(799_200),
                8,
                &[]
            )
            .is_empty()
        );
        assert_eq!(broker.ceiling(5_000_000), 1_100_000);
    }

    #[test]
    fn allows_only_secure_or_loopback_api_urls() {
        assert!(validate_api_url(&Url::parse(DEFAULT_API_URL).unwrap()).is_ok());
        assert!(validate_api_url(&Url::parse("http://127.0.0.1:8080/").unwrap()).is_ok());
        assert!(validate_api_url(&Url::parse("http://example.com/").unwrap()).is_err());
    }

    /// Instance 46008005 came back running and healthy with no forwarded port
    /// range, and every SSH attempt against the proxy endpoint it advertised
    /// was refused for the renter's key.
    #[test]
    fn an_instance_without_forwarded_ports_says_so() {
        let unreachable = instance_from_response(
            r#"{"instances":{"actual_status":"running","gpu_name":"L40S","gpu_ram":46068,
                "verification":"verified","dph_total":0.5363,"machine_id":24733,
                "ssh_host":"ssh1.vast.ai","ssh_port":18004,"direct_port_start":-1}}"#,
        )
        .unwrap();
        assert_eq!(unreachable.direct_port_start, -1);
        assert_eq!(unreachable.status, "running");
        assert_eq!(unreachable.machine_id, 24733);
    }

    /// Seven of the ten provisioning attempts for lease 28 died on "decode Vast
    /// instance" while the machine was still coming up, which is time the
    /// ten-minute provisioning window does not have.
    #[test]
    fn a_booting_instance_decodes_as_loading_rather_than_failing() {
        let booting = instance_from_response(r#"{"instances":{"id":46011038}}"#).unwrap();
        assert_eq!(booting.status, "loading");

        let half_up = instance_from_response(
            r#"{"instances":{"actual_status":"running","gpu_name":"L40S","machine_id":1}}"#,
        )
        .unwrap();
        assert_eq!(half_up.status, "loading");
    }

    /// A machine that cannot be named must be neither admitted nor rejected:
    /// blacklisting id 0 filters no offer, so the lease would keep reselecting
    /// the same broken host until its provisioning window closed.
    #[test]
    fn an_unnamed_or_unported_instance_is_still_loading() {
        for body in [
            r#"{"instances":{"actual_status":"running","gpu_name":"L40S","gpu_ram":46068,
                "verification":"verified","dph_total":0.53,"direct_port_start":28083}}"#,
            r#"{"instances":{"actual_status":"running","gpu_name":"L40S","gpu_ram":46068,
                "verification":"verified","dph_total":0.53,"direct_port_start":28083,
                "machine_id":0}}"#,
            r#"{"instances":{"actual_status":"running","gpu_name":"L40S","gpu_ram":46068,
                "verification":"verified","dph_total":0.53,"machine_id":39562}}"#,
            r#"{"instances":{"actual_status":"running","gpu_name":"L40S","gpu_ram":46068,
                "verification":"verified","dph_total":0.53,"machine_id":39562,
                "direct_port_start":null}}"#,
        ] {
            assert_eq!(instance_from_response(body).unwrap().status, "loading");
        }

        let up = instance_from_response(
            r#"{"instances":{"actual_status":"running","gpu_name":"L40S","gpu_ram":46068,
                "verification":"verified","dph_total":0.53,"machine_id":39562,
                "direct_port_start":28083}}"#,
        )
        .unwrap();
        assert_eq!(up.status, "running");
        assert_eq!(up.machine_id, 39562);
        assert_eq!(up.direct_port_start, 28083);
    }

    #[test]
    fn an_undecodable_instance_reports_what_vast_sent() {
        let error = instance_from_response(r#"{"error":"no such instance"}"#).unwrap_err();
        assert!(format!("{error:#}").contains("no such instance"));
    }

    /// A verified L40S costing more than a lease charges means no capacity at
    /// all while an A6000 with the same memory sits at half the price.
    #[test]
    fn a_broker_rents_every_class_it_is_configured_for() {
        let single = broker(&["L40S"], 45_000, 900_000);
        assert!(single.admits("L40S", 46_068));
        assert!(!single.admits("RTX A6000", 46_068));
        assert!(!single.admits("L40S", 24_576));

        let wide = broker(&["L40S", "RTX A6000"], 45_000, 900_000);
        assert!(wide.admits("L40S", 46_068));
        assert!(wide.admits("rtx a6000", 46_068));
        assert!(!wide.admits("RTX 4090", 24_564));
    }

    /// One bonded node is one concurrent lease. Advertising a slot with no host
    /// behind it sells capacity a second renter would find already taken, which
    /// is the listing-and-matching disagreement all over again.
    #[test]
    fn the_pool_never_advertises_more_slots_than_hosts() {
        let hosts = vec![
            offer(1, "RTX A6000", 49_140, 0.40),
            offer(2, "RTX A6000", 49_140, 0.44),
            offer(3, "L40S", 46_068, 0.60),
        ];

        // Four free slots, three hosts: three get advertised.
        assert_eq!(rank_offers(hosts.clone(), 799_200, 4, &[]).len(), 3);
        // Two free slots, three hosts: only two are sold, cheapest first.
        let two = rank_offers(hosts.clone(), 799_200, 2, &[]);
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].id, 1);
        // A ceiling that excludes everything sells nothing, however many slots.
        assert!(rank_offers(hosts, 300_000, 8, &[]).is_empty());
    }

    #[test]
    fn a_broker_answers_only_for_the_nodes_it_holds() {
        let single = broker(&["L40S"], 45_000, 900_000);
        assert!(single.owns("0xabc"));
        assert!(!single.owns("0xdef"));

        let pool = VastBroker {
            node_ids: Arc::new(vec!["0xaaa".to_owned(), "0xbbb".to_owned()]),
            ..broker(&["L40S"], 45_000, 900_000)
        };
        assert!(pool.owns("0xaaa"));
        assert!(pool.owns("0xbbb"));
        assert!(!pool.owns("0xccc"));
    }

    #[test]
    fn rejects_shell_metacharacters_in_ssh_hosts() {
        assert!(valid_ssh_host("ssh123.vast.ai"));
        assert!(valid_ssh_host("203.0.113.10"));
        assert!(!valid_ssh_host("ssh.vast.ai;curl.example"));
        assert!(!valid_ssh_host("-ssh.vast.ai"));
    }
}
