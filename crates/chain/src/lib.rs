use std::{env, net::IpAddr, time::Duration};

use anyhow::Context;
use aws_sdk_kms::{
    Client as KmsClient,
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use k256::{
    PublicKey,
    ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey, signature::hazmat::PrehashSigner},
    pkcs8::DecodePublicKey,
};
use rlp::RlpStream;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha3::{Digest, Keccak256};

const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_MAX_ATTEMPTS: usize = 4;
const RPC_RETRY_BASE_DELAY: Duration = Duration::from_millis(200);
const RPC_RETRY_MAX_DELAY: Duration = Duration::from_secs(2);
const RPC_RETRY_AFTER_LIMIT: Duration = Duration::from_secs(10);
const RPC_ERROR_BODY_LIMIT: usize = 1_024;

fn env_number(name: &str) -> Option<u64> {
    let raw = env::var(name).ok()?;
    match raw.trim().parse::<u64>() {
        Ok(value) if value > 0 => Some(value),
        _ => None,
    }
}
const TRANSACTION_RECONCILIATION_ATTEMPTS: usize = 3;
const TRANSACTION_RECONCILIATION_DELAY: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub struct RpcClient {
    client: reqwest::Client,
    url: url::Url,
    retry: RetryPolicy,
}

#[derive(Clone, Copy)]
struct RetryPolicy {
    max_attempts: usize,
    base_delay: Duration,
    max_delay: Duration,
    retry_after_limit: Duration,
    error_body_limit: usize,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: RPC_MAX_ATTEMPTS,
            base_delay: RPC_RETRY_BASE_DELAY,
            max_delay: RPC_RETRY_MAX_DELAY,
            retry_after_limit: RPC_RETRY_AFTER_LIMIT,
            error_body_limit: RPC_ERROR_BODY_LIMIT,
        }
    }
}

#[derive(Debug)]
struct TransientRpcError {
    message: String,
    source: Option<reqwest::Error>,
}

#[derive(Debug)]
pub struct RpcApplicationError {
    method: &'static str,
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(Debug)]
struct TransactionReprepareRequired {
    source: anyhow::Error,
}

impl RpcApplicationError {
    pub fn method(&self) -> &'static str {
        self.method
    }

    pub fn code(&self) -> i64 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn data(&self) -> Option<&serde_json::Value> {
        self.data.as_ref()
    }
}

impl std::fmt::Display for TransientRpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TransientRpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

impl std::fmt::Display for RpcApplicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "RPC {} failed with {}: {}",
            self.method, self.code, self.message
        )?;
        if let Some(data) = self.data.as_ref() {
            match data {
                serde_json::Value::String(data) => write!(formatter, " ({data})")?,
                data => write!(formatter, " ({data})")?,
            }
        }
        Ok(())
    }
}

impl std::error::Error for RpcApplicationError {}

impl std::fmt::Display for TransactionReprepareRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "signed transaction must be rebuilt: {}",
            self.source
        )
    }
}

impl std::error::Error for TransactionReprepareRequired {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Whether an RPC call exhausted retries on a transport or retryable HTTP failure.
pub fn is_transient_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<TransientRpcError>().is_some())
}

/// Whether submission proved a signed transaction unusable and it must be rebuilt.
///
/// A nonce error qualifies only after the exact transaction is absent from
/// both the transaction and receipt lookups. Ambiguous failures retain it.
pub fn requires_transaction_reprepare(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<TransactionReprepareRequired>()
            .is_some()
    })
}

fn is_repreparable_submission(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let Some(error) = cause.downcast_ref::<RpcApplicationError>() else {
            return false;
        };
        if error.method != "eth_sendRawTransaction" {
            return false;
        }
        rpc_error_contains(
            error,
            &[
                "nonce too low",
                "nonce is too low",
                "nonce too high",
                "nonce is too high",
                "replacement transaction underpriced",
                "transaction underpriced",
                "fee too low",
                "max fee per gas less than block base fee",
                "max fee per gas is less than block base fee",
                "gas price is less than block base fee",
                "gas price below block base fee",
                "transaction gas price is too low",
            ],
        )
    })
}

fn is_known_transaction_submission(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let Some(error) = cause.downcast_ref::<RpcApplicationError>() else {
            return false;
        };
        if error.method != "eth_sendRawTransaction" {
            return false;
        }
        let text = rpc_error_text(error);
        text.contains("already known")
            || text.contains("already-known")
            || ((text.contains("known transaction") || text.contains("known-transaction"))
                && !text.contains("unknown transaction")
                && !text.contains("unknown-transaction"))
    })
}

fn rpc_error_contains(error: &RpcApplicationError, needles: &[&str]) -> bool {
    let text = rpc_error_text(error);
    needles.iter().any(|needle| text.contains(needle))
}

fn rpc_error_text(error: &RpcApplicationError) -> String {
    let mut text = error.message.to_ascii_lowercase();
    if let Some(data) = error.data.as_ref() {
        text.push(' ');
        text.push_str(&data.to_string().to_ascii_lowercase());
    }
    text
}

pub enum EthereumSigner {
    Kms(KmsSigner),
    Local(LocalSigner),
}

pub struct KmsSigner {
    client: KmsClient,
    key_id: String,
    public_key: VerifyingKey,
    address: [u8; 20],
}

pub struct LocalSigner {
    key: SigningKey,
    address: [u8; 20],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedTransaction {
    pub nonce: u64,
    pub raw_transaction: String,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionOutcome {
    /// The exact hash was visible before any broadcast call was made.
    AlreadyObserved,
    /// `eth_sendRawTransaction` accepted the bytes and returned their hash.
    BroadcastAccepted,
    /// A broadcast was attempted and the endpoint, or an exact-hash recheck,
    /// proved that the same transaction was already known.
    BroadcastKnown,
}

impl SubmissionOutcome {
    pub fn broadcast_attempted(self) -> bool {
        self != Self::AlreadyObserved
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    pub status: String,
    pub block_number: String,
    pub block_hash: String,
    #[serde(default)]
    pub logs: Vec<ChainLog>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finality {
    Pending,
    Confirmed {
        block_number: u64,
        block_hash: String,
    },
    Reverted {
        block_number: u64,
        block_hash: String,
    },
}

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: serde_json::Value,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
    /// Revert payload. Without it every failed call is an indistinguishable
    /// "execution reverted", which hides the contract's own error.
    #[serde(default)]
    data: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct BlockHeader {
    hash: String,
    timestamp: String,
}

impl RpcClient {
    pub fn new(value: &str) -> anyhow::Result<Self> {
        // Every service shares one egress IP and one provider rate limit, so a
        // read-only service can afford to wait out a 429 that a signer cannot.
        // The defaults stay put; a deployment opts one service into patience.
        let mut retry = RetryPolicy::default();
        if let Some(attempts) = env_number("PRISM_RPC_MAX_ATTEMPTS") {
            retry.max_attempts = attempts as usize;
        }
        if let Some(millis) = env_number("PRISM_RPC_RETRY_BASE_MS") {
            retry.base_delay = Duration::from_millis(millis);
        }
        if let Some(millis) = env_number("PRISM_RPC_RETRY_MAX_MS") {
            retry.max_delay = Duration::from_millis(millis);
        }
        Self::with_policy(value, RPC_REQUEST_TIMEOUT, RPC_CONNECT_TIMEOUT, retry)
    }

    fn with_policy(
        value: &str,
        request_timeout: Duration,
        connect_timeout: Duration,
        retry: RetryPolicy,
    ) -> anyhow::Result<Self> {
        if retry.max_attempts == 0 {
            anyhow::bail!("RPC retry policy must allow at least one attempt");
        }
        let url = secure_rpc_url(value)?;
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(request_timeout)
                .connect_timeout(connect_timeout)
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()?,
            url,
            retry,
        })
    }

    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> anyhow::Result<T> {
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))?;
        let response = self.send(method, &body, rand::random()).await?;
        if let Some(error) = response.error {
            return Err(RpcApplicationError {
                method,
                code: error.code,
                message: error.message,
                data: error.data,
            }
            .into());
        }
        serde_json::from_value(response.result).context("RPC response contains an invalid result")
    }

    async fn send(
        &self,
        method: &'static str,
        body: &[u8],
        retry_seed: u64,
    ) -> anyhow::Result<RpcResponse> {
        for attempt in 1..=self.retry.max_attempts {
            let sent = self
                .client
                .post(self.url.clone())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec())
                .send()
                .await;
            let mut response = match sent {
                Ok(response) => response,
                Err(error) if retryable_transport(&error) => {
                    if attempt < self.retry.max_attempts {
                        self.wait_before_retry(body, attempt, retry_seed, None)
                            .await;
                        continue;
                    }
                    return Err(TransientRpcError {
                        message: format!(
                            "RPC {method} transport failed after {attempt} {}",
                            attempt_word(attempt)
                        ),
                        source: Some(error.without_url()),
                    }
                    .into());
                }
                Err(error) => {
                    let error = error.without_url();
                    return Err(anyhow::Error::new(error)).with_context(|| {
                        format!(
                            "RPC {method} transport failed after {attempt} {}",
                            attempt_word(attempt)
                        )
                    });
                }
            };

            let status = response.status();
            if !status.is_success() {
                let retry_after = numeric_retry_after(
                    response.headers().get(reqwest::header::RETRY_AFTER),
                    self.retry.retry_after_limit,
                );
                if retryable_status(status) && attempt < self.retry.max_attempts {
                    self.wait_before_retry(body, attempt, retry_seed, retry_after)
                        .await;
                    continue;
                }

                let detail = bounded_error_body(&mut response, self.retry.error_body_limit).await;
                let message = match detail {
                    Some(detail) => format!(
                        "RPC {method} returned HTTP {status} after {attempt} {}: {detail}",
                        attempt_word(attempt)
                    ),
                    None => format!(
                        "RPC {method} returned HTTP {status} after {attempt} {}",
                        attempt_word(attempt)
                    ),
                };
                if retryable_status(status) {
                    return Err(TransientRpcError {
                        message,
                        source: None,
                    }
                    .into());
                }
                anyhow::bail!(message);
            }

            match response.json::<RpcResponse>().await {
                Ok(response) => {
                    if let Some(error) = response
                        .error
                        .as_ref()
                        .filter(|error| retryable_rpc_application_error(error))
                    {
                        if attempt < self.retry.max_attempts {
                            self.wait_before_retry(body, attempt, retry_seed, None)
                                .await;
                            continue;
                        }
                        return Err(TransientRpcError {
                            message: format!(
                                "RPC {method} was rate-limited after {attempt} {}: {} ({})",
                                attempt_word(attempt),
                                sanitised_rpc_message(&error.message),
                                error.code
                            ),
                            source: None,
                        }
                        .into());
                    }
                    return Ok(response);
                }
                Err(error) if retryable_transport(&error) => {
                    if attempt < self.retry.max_attempts {
                        self.wait_before_retry(body, attempt, retry_seed, None)
                            .await;
                        continue;
                    }
                    return Err(TransientRpcError {
                        message: format!(
                            "RPC {method} response failed after {attempt} {}",
                            attempt_word(attempt)
                        ),
                        source: Some(error.without_url()),
                    }
                    .into());
                }
                Err(error) => {
                    let error = error.without_url();
                    return Err(anyhow::Error::new(error)).with_context(|| {
                        format!(
                            "RPC {method} response failed after {attempt} {}",
                            attempt_word(attempt)
                        )
                    });
                }
            }
        }

        unreachable!("RPC retry loop always returns on its final attempt")
    }

    async fn wait_before_retry(
        &self,
        body: &[u8],
        attempt: usize,
        retry_seed: u64,
        retry_after: Option<Duration>,
    ) {
        let delay = retry_delay(body, attempt, retry_seed, self.retry, retry_after);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    pub async fn quantity(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> anyhow::Result<u64> {
        let value: String = self.call(method, params).await?;
        parse_quantity(&value)
    }

    pub async fn chain_id(&self) -> anyhow::Result<u64> {
        self.quantity("eth_chainId", serde_json::json!([])).await
    }

    /// `eth_gasPrice` here answers with the current base fee rather than the
    /// next block's, so a transaction priced at exactly what it suggests is
    /// rejected as soon as the base fee ticks up. Double it. The surplus is
    /// refunded, and settlement transactions that cannot be replaced are worth
    /// far more than the headroom costs.
    pub async fn suggested_gas_price(&self) -> anyhow::Result<u64> {
        Ok(self
            .quantity("eth_gasPrice", serde_json::json!([]))
            .await?
            .saturating_mul(2))
    }

    pub async fn prepare_transaction(
        &self,
        signer: &EthereumSigner,
        to: [u8; 20],
        data: &[u8],
        chain_id: u64,
    ) -> anyhow::Result<PreparedTransaction> {
        let from = format!("0x{}", hex::encode(signer.address()));
        let destination = format!("0x{}", hex::encode(to));
        let nonce = self
            .quantity(
                "eth_getTransactionCount",
                serde_json::json!([from, "pending"]),
            )
            .await?;
        let gas_price = self.suggested_gas_price().await?;
        let gas_limit = self
            .quantity(
                "eth_estimateGas",
                serde_json::json!([{
                    "from": from,
                    "to": destination,
                    "data": format!("0x{}", hex::encode(data)),
                    "value": "0x0"
                }]),
            )
            .await?;
        let unsigned = legacy_unsigned_transaction(nonce, gas_price, gas_limit, to, data, chain_id);
        let digest: [u8; 32] = Keccak256::digest(&unsigned).into();
        let signature = signer.sign_digest(&digest).await?;
        let raw =
            legacy_signed_transaction(nonce, gas_price, gas_limit, to, data, chain_id, &signature);
        Ok(PreparedTransaction {
            nonce,
            transaction_hash: format!("0x{}", hex::encode(Keccak256::digest(&raw))),
            raw_transaction: format!("0x{}", hex::encode(raw)),
        })
    }

    pub async fn submit(
        &self,
        transaction: &PreparedTransaction,
    ) -> anyhow::Result<SubmissionOutcome> {
        let known: Option<serde_json::Value> = self
            .call(
                "eth_getTransactionByHash",
                serde_json::json!([transaction.transaction_hash]),
            )
            .await?;
        if known.is_some() {
            return Ok(SubmissionOutcome::AlreadyObserved);
        }
        self.broadcast(transaction).await
    }

    /// Broadcasts bytes whose durable owner has already checked exact-hash
    /// visibility and recorded the send attempt.
    pub async fn broadcast(
        &self,
        transaction: &PreparedTransaction,
    ) -> anyhow::Result<SubmissionOutcome> {
        let submitted = self
            .call(
                "eth_sendRawTransaction",
                serde_json::json!([transaction.raw_transaction]),
            )
            .await;
        let hash: String = match submitted {
            Ok(hash) => hash,
            Err(error) if is_known_transaction_submission(&error) => {
                return Ok(SubmissionOutcome::BroadcastKnown);
            }
            Err(error) if is_repreparable_submission(&error) => {
                if self
                    .transaction_observed(&transaction.transaction_hash)
                    .await?
                {
                    return Ok(SubmissionOutcome::BroadcastKnown);
                }
                return Err(TransactionReprepareRequired { source: error }.into());
            }
            Err(error) => return Err(error),
        };
        if !hash.eq_ignore_ascii_case(&transaction.transaction_hash) {
            anyhow::bail!("RPC returned an unexpected transaction hash");
        }
        Ok(SubmissionOutcome::BroadcastAccepted)
    }

    /// Whether the exact transaction is visible by hash or has a receipt.
    ///
    /// Multiple bounded reads tolerate ordinary RPC indexing lag without
    /// treating an ambiguous miss as proof that signed bytes are unusable.
    pub async fn transaction_observed(&self, transaction_hash: &str) -> anyhow::Result<bool> {
        for attempt in 1..=TRANSACTION_RECONCILIATION_ATTEMPTS {
            let known: Option<serde_json::Value> = self
                .call(
                    "eth_getTransactionByHash",
                    serde_json::json!([transaction_hash]),
                )
                .await?;
            if known.is_some() || self.transaction_receipt(transaction_hash).await?.is_some() {
                return Ok(true);
            }
            if attempt < TRANSACTION_RECONCILIATION_ATTEMPTS {
                tokio::time::sleep(TRANSACTION_RECONCILIATION_DELAY).await;
            }
        }
        Ok(false)
    }

    pub async fn finality(
        &self,
        transaction_hash: &str,
        confirmations: u64,
    ) -> anyhow::Result<Finality> {
        let receipt: Option<TransactionReceipt> = self
            .call(
                "eth_getTransactionReceipt",
                serde_json::json!([transaction_hash]),
            )
            .await?;
        let Some(receipt) = receipt else {
            return Ok(Finality::Pending);
        };
        let block_number = parse_quantity(&receipt.block_number)?;
        let current = self
            .quantity("eth_blockNumber", serde_json::json!([]))
            .await?;
        if current < block_number.saturating_add(confirmations) {
            return Ok(Finality::Pending);
        }
        let block: Option<BlockHeader> = self
            .call(
                "eth_getBlockByNumber",
                serde_json::json!([receipt.block_number, false]),
            )
            .await?;
        if block.is_none_or(|block| !block.hash.eq_ignore_ascii_case(&receipt.block_hash)) {
            return Ok(Finality::Pending);
        }
        let finality = if parse_quantity(&receipt.status)? == 1 {
            Finality::Confirmed {
                block_number,
                block_hash: receipt.block_hash,
            }
        } else {
            Finality::Reverted {
                block_number,
                block_hash: receipt.block_hash,
            }
        };
        Ok(finality)
    }

    pub async fn transaction_receipt(
        &self,
        transaction_hash: &str,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        self.call(
            "eth_getTransactionReceipt",
            serde_json::json!([transaction_hash]),
        )
        .await
    }

    pub async fn block_timestamp(&self, block_number: u64) -> anyhow::Result<u64> {
        let block: Option<BlockHeader> = self
            .call(
                "eth_getBlockByNumber",
                serde_json::json!([format!("0x{block_number:x}"), false]),
            )
            .await?;
        parse_quantity(&block.context("confirmed block is unavailable")?.timestamp)
    }
}

impl EthereumSigner {
    pub async fn from_environment(key_id_env: &str) -> anyhow::Result<Self> {
        if env::var("PRISM_ALLOW_DEVELOPMENT_SIGNER").as_deref() == Ok("1") {
            let encoded = env::var("PRISM_DEVELOPMENT_PRIVATE_KEY")
                .context("PRISM_DEVELOPMENT_PRIVATE_KEY is required for the development signer")?;
            return Ok(Self::Local(LocalSigner::new(&encoded)?));
        }
        let key_id = env::var(key_id_env).with_context(|| format!("{key_id_env} is required"))?;
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        Ok(Self::Kms(
            KmsSigner::new(KmsClient::new(&config), key_id).await?,
        ))
    }

    /// Sign with a key held on the machine. Prism's own services sign through
    /// KMS, but a node operator runs on hardware they own and has nowhere to
    /// put a KMS key, so operator-side tools take the private key directly.
    pub fn local(private_key: &str) -> anyhow::Result<Self> {
        Ok(Self::Local(LocalSigner::new(private_key)?))
    }

    pub fn address(&self) -> [u8; 20] {
        match self {
            Self::Kms(signer) => signer.address,
            Self::Local(signer) => signer.address,
        }
    }

    pub async fn sign_digest(&self, digest: &[u8; 32]) -> anyhow::Result<[u8; 65]> {
        match self {
            Self::Kms(signer) => signer.sign_digest(digest).await,
            Self::Local(signer) => signer.sign_digest(digest),
        }
    }
}

impl KmsSigner {
    async fn new(client: KmsClient, key_id: String) -> anyhow::Result<Self> {
        let output = client.get_public_key().key_id(&key_id).send().await?;
        if output.key_spec().map(|spec| spec.as_str()) != Some("ECC_SECG_P256K1") {
            anyhow::bail!("KMS key must use ECC_SECG_P256K1");
        }
        let der = output
            .public_key()
            .context("KMS response contains no public key")?
            .as_ref();
        let public_key = VerifyingKey::from(PublicKey::from_public_key_der(der)?);
        let address = ethereum_address(&public_key);
        Ok(Self {
            client,
            key_id,
            public_key,
            address,
        })
    }

    async fn sign_digest(&self, digest: &[u8; 32]) -> anyhow::Result<[u8; 65]> {
        let output = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await?;
        let der = output
            .signature()
            .context("KMS response contains no signature")?
            .as_ref();
        ethereum_signature(digest, &Signature::from_der(der)?, &self.public_key)
    }
}

impl LocalSigner {
    fn new(value: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
        let key = SigningKey::from_slice(&bytes).context("development private key is invalid")?;
        let address = ethereum_address(key.verifying_key());
        Ok(Self { key, address })
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> anyhow::Result<[u8; 65]> {
        let signature: Signature = self.key.sign_prehash(digest)?;
        ethereum_signature(digest, &signature, self.key.verifying_key())
    }
}

pub fn address(value: &str) -> anyhow::Result<[u8; 20]> {
    let bytes = hex::decode(
        value
            .strip_prefix("0x")
            .context("address must start with 0x")?,
    )?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("address must contain 20 bytes"))
}

pub fn word_u128(value: u128) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

pub fn word_bytes32(value: [u8; 32]) -> [u8; 32] {
    value
}

pub fn selector(signature: &str) -> [u8; 4] {
    Keccak256::digest(signature.as_bytes())[..4]
        .try_into()
        .expect("selector is four bytes")
}

pub fn parse_quantity(value: &str) -> anyhow::Result<u64> {
    u64::from_str_radix(
        value
            .strip_prefix("0x")
            .context("RPC quantity is not hex")?,
        16,
    )
    .context("RPC quantity exceeds uint64")
}

fn retryable_transport(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout()
}

fn retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::TOO_MANY_REQUESTS
            | reqwest::StatusCode::BAD_GATEWAY
            | reqwest::StatusCode::SERVICE_UNAVAILABLE
            | reqwest::StatusCode::GATEWAY_TIMEOUT
    )
}

fn retryable_rpc_application_error(error: &RpcError) -> bool {
    if error.code == 429 {
        return true;
    }
    if !(-32_099..=-32_000).contains(&error.code) {
        return false;
    }
    let error = RpcApplicationError {
        method: "rpc",
        code: error.code,
        message: error.message.clone(),
        data: error.data.clone(),
    };
    [
        "rate limit",
        "rate-limit",
        "too many requests",
        "request limit",
        "throughput limit",
        "capacity exceeded",
        "temporarily unavailable",
        "try again later",
    ]
    .iter()
    .any(|needle| rpc_error_contains(&error, &[*needle]))
}

fn sanitised_rpc_message(value: &str) -> String {
    let message: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(160)
        .collect();
    let message = message.trim();
    if message.is_empty() {
        "provider rate limit".to_owned()
    } else {
        message.to_owned()
    }
}

fn numeric_retry_after(
    value: Option<&reqwest::header::HeaderValue>,
    limit: Duration,
) -> Option<Duration> {
    let value = value?.to_str().ok()?.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let seconds = value.bytes().fold(0_u64, |seconds, byte| {
        seconds
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'))
    });
    Some(Duration::from_secs(seconds).min(limit))
}

fn retry_delay(
    body: &[u8],
    attempt: usize,
    seed: u64,
    policy: RetryPolicy,
    retry_after: Option<Duration>,
) -> Duration {
    let retry_after = retry_after.map(|delay| delay.min(policy.retry_after_limit));
    let base_ms = u64::try_from(policy.base_delay.as_millis()).unwrap_or(u64::MAX);
    let max_ms = u64::try_from(policy.max_delay.as_millis()).unwrap_or(u64::MAX);
    if base_ms == 0 || max_ms == 0 {
        return retry_after.unwrap_or(Duration::ZERO);
    }

    let shift = u32::try_from(attempt.saturating_sub(1).min(63)).unwrap_or(63);
    let ceiling = base_ms.saturating_mul(1_u64 << shift).min(max_ms);
    let floor = ceiling / 2;
    let width = ceiling.saturating_sub(floor).saturating_add(1);
    let mut hasher = Keccak256::new();
    hasher.update(body);
    hasher.update(attempt.to_le_bytes());
    hasher.update(seed.to_le_bytes());
    let digest = hasher.finalize();
    let sample = u64::from_le_bytes(digest[..8].try_into().expect("digest contains eight bytes"));
    let spread = Duration::from_millis(floor.saturating_add(sample % width));
    retry_after.map_or(spread, |delay| spread.max(delay))
}

async fn bounded_error_body(response: &mut reqwest::Response, limit: usize) -> Option<String> {
    if limit == 0 {
        return None;
    }

    let mut body = Vec::with_capacity(limit.min(256));
    let mut truncated = false;
    while body.len() < limit {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(_) => return sanitise_error_body(&body, truncated),
        };
        let remaining = limit - body.len();
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    sanitise_error_body(&body, truncated)
}

fn sanitise_error_body(body: &[u8], truncated: bool) -> Option<String> {
    let mut detail: String = String::from_utf8_lossy(body)
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    detail = detail.trim().to_owned();
    if detail.is_empty() {
        return None;
    }
    if truncated {
        detail.push('…');
    }
    Some(detail)
}

fn attempt_word(attempt: usize) -> &'static str {
    if attempt == 1 { "attempt" } else { "attempts" }
}

fn ethereum_address(public_key: &VerifyingKey) -> [u8; 20] {
    let encoded = public_key.to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    digest[12..]
        .try_into()
        .expect("Ethereum address is 20 bytes")
}

fn ethereum_signature(
    digest: &[u8; 32],
    signature: &Signature,
    public_key: &VerifyingKey,
) -> anyhow::Result<[u8; 65]> {
    let signature = signature.normalize_s().unwrap_or(*signature);
    let recovery_id = [0_u8, 1_u8]
        .into_iter()
        .filter_map(RecoveryId::from_byte)
        .find(|recovery_id| {
            VerifyingKey::recover_from_prehash(digest, &signature, *recovery_id)
                .is_ok_and(|recovered| recovered == *public_key)
        })
        .context("signature does not recover the configured public key")?;
    let bytes = signature.to_bytes();
    let mut output = [0_u8; 65];
    output[..64].copy_from_slice(&bytes);
    output[64] = 27 + recovery_id.to_byte();
    Ok(output)
}

fn legacy_unsigned_transaction(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: [u8; 20],
    data: &[u8],
    chain_id: u64,
) -> Vec<u8> {
    let mut stream = RlpStream::new_list(9);
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    stream.append(&to.as_slice());
    stream.append(&0_u8);
    stream.append(&data);
    stream.append(&chain_id);
    stream.append(&0_u8);
    stream.append(&0_u8);
    stream.out().to_vec()
}

fn legacy_signed_transaction(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: [u8; 20],
    data: &[u8],
    chain_id: u64,
    signature: &[u8; 65],
) -> Vec<u8> {
    let v = chain_id * 2 + 35 + u64::from(signature[64] - 27);
    let mut stream = RlpStream::new_list(9);
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    stream.append(&to.as_slice());
    stream.append(&0_u8);
    stream.append(&data);
    stream.append(&v);
    stream.append(&trim_integer(&signature[..32]));
    stream.append(&trim_integer(&signature[32..64]));
    stream.out().to_vec()
}

fn trim_integer(value: &[u8]) -> &[u8] {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    &value[first..]
}

fn secure_rpc_url(value: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(value)?;
    let local_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        });
    if url.scheme() != "https" && !local_http {
        anyhow::bail!("RPC URL must use HTTPS outside localhost");
    }
    if url.username() != "" || url.password().is_some() {
        anyhow::bail!("RPC URL must not contain credentials");
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        task::JoinHandle,
    };

    struct MockResponse {
        status: &'static str,
        headers: Vec<(&'static str, &'static str)>,
        body: Vec<u8>,
        delay: Duration,
    }

    struct MockServer {
        url: String,
        bodies: Arc<Mutex<Vec<Vec<u8>>>>,
        task: JoinHandle<()>,
    }

    impl MockResponse {
        fn json(status: &'static str, body: &str) -> Self {
            Self {
                status,
                headers: vec![("Content-Type", "application/json")],
                body: body.as_bytes().to_vec(),
                delay: Duration::ZERO,
            }
        }
    }

    async fn mock_server(responses: Vec<MockResponse>) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&bodies);
        let task = tokio::spawn(async move {
            let mut handlers = Vec::with_capacity(responses.len());
            for response in responses {
                let (stream, _) = listener.accept().await.unwrap();
                let captured = Arc::clone(&captured);
                handlers.push(tokio::spawn(async move {
                    serve_response(stream, response, captured).await;
                }));
            }
            for handler in handlers {
                handler.await.unwrap();
            }
        });
        MockServer { url, bodies, task }
    }

    async fn serve_response(
        mut stream: TcpStream,
        response: MockResponse,
        bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    ) {
        let body = read_request_body(&mut stream).await;
        bodies.lock().unwrap().push(body);
        tokio::time::sleep(response.delay).await;
        let headers = response
            .headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect::<String>();
        let head = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
            response.status,
            response.body.len(),
            headers
        );
        let _ = stream.write_all(head.as_bytes()).await;
        let _ = stream.write_all(&response.body).await;
    }

    async fn read_request_body(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1_024];
        let header_end = loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "client closed before sending HTTP headers");
            request.extend_from_slice(&buffer[..read]);
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        while request.len() < header_end + content_length {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "client closed before sending the HTTP body");
            request.extend_from_slice(&buffer[..read]);
        }
        request[header_end..header_end + content_length].to_vec()
    }

    fn test_policy(max_attempts: usize) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            retry_after_limit: Duration::from_secs(30),
            error_body_limit: 64,
        }
    }

    fn rpc_client(url: &str, max_attempts: usize) -> RpcClient {
        RpcClient::with_policy(
            url,
            Duration::from_secs(1),
            Duration::from_secs(1),
            test_policy(max_attempts),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn retries_only_selected_http_statuses_with_identical_payloads() {
        let mut responses = [
            "408 Request Timeout",
            "429 Too Many Requests",
            "502 Bad Gateway",
            "503 Service Unavailable",
            "504 Gateway Timeout",
        ]
        .into_iter()
        .map(|status| {
            let mut response = MockResponse::json(status, "retry");
            if status.starts_with("429") {
                response.headers.push(("Retry-After", "0"));
            }
            response
        })
        .collect::<Vec<_>>();
        responses.push(MockResponse::json(
            "200 OK",
            r#"{"jsonrpc":"2.0","id":1,"result":"0x2a"}"#,
        ));
        let server = mock_server(responses).await;
        let result: String = rpc_client(&server.url, 6)
            .call("eth_test", serde_json::json!([7]))
            .await
            .unwrap();
        assert_eq!(result, "0x2a");
        server.task.await.unwrap();
        let bodies = server.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 6);
        assert!(bodies.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[tokio::test]
    async fn json_rpc_application_errors_are_not_retried() {
        let server = mock_server(vec![MockResponse::json(
            "200 OK",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted","data":"0xdead"}}"#,
        )])
        .await;
        let error = rpc_client(&server.url, 4)
            .call::<String>("eth_call", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("execution reverted (0xdead)"));
        assert!(!is_transient_error(&error));
        let rpc = error.downcast_ref::<RpcApplicationError>().unwrap();
        assert_eq!(rpc.method(), "eth_call");
        assert_eq!(rpc.code(), -32_000);
        assert_eq!(rpc.message(), "execution reverted");
        assert_eq!(rpc.data(), Some(&serde_json::json!("0xdead")));
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn object_valued_rpc_data_is_typed_and_classified() {
        let server = mock_server(vec![MockResponse::json(
            "200 OK",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"submission failed","data":{"cause":{"message":"nonce too low"},"txHash":"0xdead"}}}"#,
        )])
        .await;
        let error = rpc_client(&server.url, 1)
            .call::<String>("eth_sendRawTransaction", serde_json::json!(["0x01"]))
            .await
            .unwrap_err();

        assert!(is_repreparable_submission(&error));
        let rpc = error.downcast_ref::<RpcApplicationError>().unwrap();
        assert_eq!(rpc.data().unwrap()["cause"]["message"], "nonce too low");
        server.task.await.unwrap();
    }

    #[tokio::test]
    async fn known_transaction_errors_are_accepted() {
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"already known"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"submission failed","data":{"message":"known transaction"}}}"#,
        ] {
            let server = mock_server(vec![
                MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
                MockResponse::json("200 OK", body),
            ])
            .await;

            let outcome = rpc_client(&server.url, 1)
                .submit(&stored_transaction())
                .await
                .unwrap();
            assert_eq!(outcome, SubmissionOutcome::BroadcastKnown);
            assert!(outcome.broadcast_attempted());
            server.task.await.unwrap();
            assert_eq!(server.bodies.lock().unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn an_observed_transaction_skips_the_broadcast() {
        let server = mock_server(vec![MockResponse::json(
            "200 OK",
            r#"{"jsonrpc":"2.0","id":1,"result":{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#,
        )])
        .await;

        let outcome = rpc_client(&server.url, 1)
            .submit(&stored_transaction())
            .await
            .unwrap();

        assert_eq!(outcome, SubmissionOutcome::AlreadyObserved);
        assert!(!outcome.broadcast_attempted());
        server.task.await.unwrap();
        let bodies = server.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        let request: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        assert_eq!(request["method"], "eth_getTransactionByHash");
    }

    #[tokio::test]
    async fn an_accepted_broadcast_is_reported_separately() {
        let server = mock_server(vec![
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"result":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            ),
        ])
        .await;

        let outcome = rpc_client(&server.url, 1)
            .submit(&stored_transaction())
            .await
            .unwrap();

        assert_eq!(outcome, SubmissionOutcome::BroadcastAccepted);
        assert!(outcome.broadcast_attempted());
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn unknown_transaction_errors_are_not_misclassified_as_known() {
        let server = mock_server(vec![
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unknown transaction"}}"#,
            ),
        ])
        .await;

        let error = rpc_client(&server.url, 1)
            .submit(&stored_transaction())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unknown transaction"));
        server.task.await.unwrap();
    }

    #[tokio::test]
    async fn only_proven_unusable_transactions_are_reprepare_candidates() {
        let server = mock_server(vec![
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
            ),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"Nonce is too low for this account"}}"#,
            ),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
            ),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"replacement transaction underpriced"}}"#,
            ),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"submission rejected","data":{"cause":"max fee per gas less than block base fee"}}}"#,
            ),
            MockResponse::json("503 Service Unavailable", "try later"),
        ])
        .await;
        let client = rpc_client(&server.url, 1);

        for _ in 0..2 {
            let error = client
                .call::<String>("eth_sendRawTransaction", serde_json::json!(["0x01"]))
                .await
                .unwrap_err()
                .context("submit lifecycle transaction");
            assert!(is_repreparable_submission(&error));
            assert!(!requires_transaction_reprepare(&error));
        }

        let wrong_method = client
            .call::<String>("eth_call", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(!is_repreparable_submission(&wrong_method));

        let underpriced = client
            .call::<String>("eth_sendRawTransaction", serde_json::json!(["0x01"]))
            .await
            .unwrap_err();
        assert!(is_repreparable_submission(&underpriced));

        let base_fee = client
            .call::<String>("eth_sendRawTransaction", serde_json::json!(["0x01"]))
            .await
            .unwrap_err();
        assert!(is_repreparable_submission(&base_fee));

        let ambiguous = client
            .call::<String>("eth_sendRawTransaction", serde_json::json!(["0x01"]))
            .await
            .unwrap_err();
        assert!(is_transient_error(&ambiguous));
        assert!(!is_repreparable_submission(&ambiguous));
        assert!(!requires_transaction_reprepare(&ambiguous));

        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 6);
    }

    #[tokio::test]
    async fn transaction_preparation_reads_the_pending_nonce() {
        let server = mock_server(vec![
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":"0x2a"}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":"0x5208"}"#),
        ])
        .await;
        let signer = EthereumSigner::local(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let prepared = rpc_client(&server.url, 1)
            .prepare_transaction(&signer, [7; 20], &[1, 2, 3], 4_663)
            .await
            .unwrap();

        assert_eq!(prepared.nonce, 42);
        server.task.await.unwrap();
        let bodies = server.bodies.lock().unwrap();
        let nonce_request: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        assert_eq!(nonce_request["method"], "eth_getTransactionCount");
        assert_eq!(nonce_request["params"][1], "pending");
    }

    fn stored_transaction() -> PreparedTransaction {
        PreparedTransaction {
            nonce: 7,
            raw_transaction: "0x01".to_owned(),
            transaction_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        }
    }

    #[tokio::test]
    async fn nonce_error_keeps_a_transaction_that_appears_on_recheck() {
        let server = mock_server(vec![
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
            ),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"result":{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#,
            ),
        ])
        .await;

        let outcome = rpc_client(&server.url, 1)
            .submit(&stored_transaction())
            .await
            .unwrap();
        assert_eq!(outcome, SubmissionOutcome::BroadcastKnown);
        server.task.await.unwrap();
        let bodies = server.bodies.lock().unwrap();
        let methods = bodies
            .iter()
            .map(|body| {
                serde_json::from_slice::<serde_json::Value>(body).unwrap()["method"].clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            methods,
            [
                "eth_getTransactionByHash",
                "eth_sendRawTransaction",
                "eth_getTransactionByHash"
            ]
        );
    }

    #[tokio::test]
    async fn nonce_error_keeps_a_transaction_with_an_exact_receipt() {
        let server = mock_server(vec![
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
            ),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"result":{"status":"0x1","blockNumber":"0x2a","blockHash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","logs":[]}}"#,
            ),
        ])
        .await;

        let outcome = rpc_client(&server.url, 1)
            .submit(&stored_transaction())
            .await
            .unwrap();
        assert_eq!(outcome, SubmissionOutcome::BroadcastKnown);
        server.task.await.unwrap();
        let bodies = server.bodies.lock().unwrap();
        let last: serde_json::Value = serde_json::from_slice(bodies.last().unwrap()).unwrap();
        assert_eq!(last["method"], "eth_getTransactionReceipt");
        assert_eq!(last["params"][0], stored_transaction().transaction_hash);
    }

    #[tokio::test]
    async fn nonce_error_requires_reprepare_after_an_exact_hash_double_miss() {
        let server = mock_server(vec![
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
            ),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
        ])
        .await;

        let error = rpc_client(&server.url, 1)
            .submit(&stored_transaction())
            .await
            .unwrap_err();
        assert!(requires_transaction_reprepare(&error));
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 8);
    }

    #[tokio::test]
    async fn underpriced_replacement_requires_reprepare_only_after_exact_hash_misses() {
        let server = mock_server(vec![
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"submission rejected","data":{"message":"replacement transaction underpriced"}}}"#,
            ),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
        ])
        .await;

        let error = rpc_client(&server.url, 1)
            .submit(&stored_transaction())
            .await
            .unwrap_err();
        assert!(requires_transaction_reprepare(&error));
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 8);
    }

    #[tokio::test]
    async fn nonce_reconciliation_tolerates_bounded_indexing_lag() {
        let server = mock_server(vec![
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
            ),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"result":{"hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#,
            ),
        ])
        .await;

        let outcome = rpc_client(&server.url, 1)
            .submit(&stored_transaction())
            .await
            .unwrap();
        assert_eq!(outcome, SubmissionOutcome::BroadcastKnown);
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn failed_nonce_reconciliation_retains_the_stored_transaction() {
        let server = mock_server(vec![
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":null}"#),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
            ),
            MockResponse::json("503 Service Unavailable", "try later"),
        ])
        .await;

        let error = rpc_client(&server.url, 1)
            .submit(&stored_transaction())
            .await
            .unwrap_err();
        assert!(is_transient_error(&error));
        assert!(!requires_transaction_reprepare(&error));
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn retries_explicit_json_rpc_rate_limits_with_identical_payloads() {
        let server = mock_server(vec![
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"rate limit exceeded"}}"#,
            ),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":429,"message":"too many requests"}}"#,
            ),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"result":"0x2a"}"#,
            ),
        ])
        .await;
        let result: String = rpc_client(&server.url, 3)
            .call("eth_test", serde_json::json!([7]))
            .await
            .unwrap();
        assert_eq!(result, "0x2a");
        server.task.await.unwrap();
        let bodies = server.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 3);
        assert!(bodies.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[tokio::test]
    async fn exhausted_json_rpc_rate_limits_are_transient() {
        let server = mock_server(vec![
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"rate limit\nexceeded"}}"#,
            ),
            MockResponse::json(
                "200 OK",
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"rate limit\nexceeded"}}"#,
            ),
        ])
        .await;
        let error = rpc_client(&server.url, 2)
            .call::<String>("eth_test", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(is_transient_error(&error));
        assert!(error.to_string().contains("after 2 attempts"));
        assert!(!error.to_string().contains('\n'));
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn exhausted_retryable_http_errors_are_transient_through_context() {
        let statuses = [
            "408 Request Timeout",
            "429 Too Many Requests",
            "502 Bad Gateway",
            "503 Service Unavailable",
            "504 Gateway Timeout",
        ];
        let responses = statuses
            .iter()
            .flat_map(|status| {
                [
                    MockResponse::json(status, "first"),
                    MockResponse::json(status, "exhausted"),
                ]
            })
            .collect();
        let server = mock_server(responses).await;
        let client = rpc_client(&server.url, 2);
        for status in statuses {
            let error = client
                .call::<String>("eth_test", serde_json::json!([]))
                .await
                .unwrap_err();
            assert!(is_transient_error(&error));
            assert!(error.to_string().contains(status));
            assert!(error.to_string().contains("exhausted"));
            let wrapped = error.context("caller context");
            assert!(is_transient_error(&wrapped));
        }
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 10);
    }

    #[tokio::test]
    async fn retries_timeouts_with_the_same_payload() {
        let mut delayed =
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":"stale"}"#);
        delayed.delay = Duration::from_millis(50);
        let server = mock_server(vec![
            delayed,
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":"fresh"}"#),
        ])
        .await;
        let client = RpcClient::with_policy(
            &server.url,
            Duration::from_millis(10),
            Duration::from_millis(10),
            test_policy(2),
        )
        .unwrap();
        let result: String = client
            .call("eth_test", serde_json::json!([1, 2, 3]))
            .await
            .unwrap();
        assert_eq!(result, "fresh");
        server.task.await.unwrap();
        let bodies = server.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0], bodies[1]);
    }

    #[tokio::test]
    async fn retries_connection_failures_up_to_the_attempt_limit() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let error = RpcClient::with_policy(
            &url,
            Duration::from_millis(50),
            Duration::from_millis(50),
            test_policy(3),
        )
        .unwrap()
        .call::<String>("eth_test", serde_json::json!([]))
        .await
        .unwrap_err();
        assert!(error.to_string().contains("after 3 attempts"));
        assert!(is_transient_error(&error));
    }

    #[tokio::test]
    async fn exhausted_response_timeouts_are_transient() {
        let mut first =
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":"first"}"#);
        first.delay = Duration::from_millis(50);
        let mut second =
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":"second"}"#);
        second.delay = Duration::from_millis(50);
        let server = mock_server(vec![first, second]).await;
        let client = RpcClient::with_policy(
            &server.url,
            Duration::from_millis(10),
            Duration::from_millis(10),
            test_policy(2),
        )
        .unwrap();
        let error = client
            .call::<String>("eth_test", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(is_transient_error(&error));
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn http_errors_keep_bounded_sanitised_context() {
        let server = mock_server(vec![MockResponse {
            status: "400 Bad Request",
            headers: Vec::new(),
            body: b"unsafe\nbody\x1b[31m-secret-tail".to_vec(),
            delay: Duration::ZERO,
        }])
        .await;
        let mut policy = test_policy(4);
        policy.error_body_limit = 16;
        let client = RpcClient::with_policy(
            &server.url,
            Duration::from_secs(1),
            Duration::from_secs(1),
            policy,
        )
        .unwrap();
        let error = client
            .call::<String>("eth_test", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(!is_transient_error(&error));
        let rendered = error.to_string();
        assert!(rendered.contains("HTTP 400 Bad Request after 1 attempt"));
        assert!(rendered.contains("unsafe body [31m"));
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains("secret-tail"));
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn malformed_successful_responses_are_not_transient() {
        let server = mock_server(vec![
            MockResponse::json("200 OK", "{"),
            MockResponse::json("200 OK", r#"{"jsonrpc":"2.0","id":1,"result":42}"#),
        ])
        .await;
        let client = rpc_client(&server.url, 4);
        let malformed = client
            .call::<String>("eth_test", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(!is_transient_error(&malformed));
        let wrong_result = client
            .call::<String>("eth_test", serde_json::json!([]))
            .await
            .unwrap_err();
        assert!(!is_transient_error(&wrong_result));
        server.task.await.unwrap();
        assert_eq!(server.bodies.lock().unwrap().len(), 2);
    }

    #[test]
    fn numeric_retry_after_is_bounded_and_dates_are_ignored() {
        let limit = Duration::from_secs(30);
        let huge =
            reqwest::header::HeaderValue::from_static("999999999999999999999999999999999999999999");
        let date = reqwest::header::HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT");
        assert_eq!(numeric_retry_after(Some(&huge), limit), Some(limit));
        assert_eq!(numeric_retry_after(Some(&date), limit), None);

        let mut policy = test_policy(2);
        policy.base_delay = Duration::from_millis(10);
        policy.max_delay = Duration::from_millis(10);
        assert_eq!(
            retry_delay(b"request", 1, 0, policy, Some(Duration::from_secs(300))),
            limit
        );
    }

    #[test]
    fn retry_status_allowlist_is_narrow() {
        for status in [408, 429, 502, 503, 504] {
            assert!(retryable_status(
                reqwest::StatusCode::from_u16(status).unwrap()
            ));
        }
        for status in [400, 401, 403, 404, 409, 500, 501] {
            assert!(!retryable_status(
                reqwest::StatusCode::from_u16(status).unwrap()
            ));
        }
    }

    #[test]
    fn local_signer_produces_recoverable_low_s_signatures() {
        let signer =
            LocalSigner::new("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let digest = [7_u8; 32];
        let signature = signer.sign_digest(&digest).unwrap();
        assert!(matches!(signature[64], 27 | 28));
        let parsed = Signature::from_slice(&signature[..64]).unwrap();
        assert!(parsed.normalize_s().is_none());
        assert_eq!(
            hex::encode(signer.address),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn transaction_is_bound_to_chain_id() {
        let signature = {
            let mut signature = [1_u8; 65];
            signature[64] = 27;
            signature
        };
        let first = legacy_signed_transaction(1, 2, 3, [4_u8; 20], &[5], 4_663, &signature);
        let second = legacy_signed_transaction(1, 2, 3, [4_u8; 20], &[5], 46_630, &signature);
        assert_ne!(Keccak256::digest(first), Keccak256::digest(second));
    }
}
