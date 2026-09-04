# Changelog

## 0.4.0

### Added

- `fund_quote(quote)` funds a quote taken earlier with `quote()` and waits for
  what it bought, so a caller can show a human the machine and the price before
  any money moves and then fund exactly that. `lease()` is now `quote()` followed
  by `fund_quote()`.
- `infer()` buys one generation from the open tier. The endpoint owns the GPU,
  the wallet pays per call, and the supplier can read the prompt and the answer.
- `confidential_infer()` buys one generation from a model running in a GPU TEE.
  The prompt is encrypted to a key the enclave's hardware quote commits to, and
  the quote is verified before anything is sent: to Intel's root, against the key
  set, and against the code this SDK pins. A check that does not hold raises
  `ConfidentialError` and no prompt leaves the process. There is no fallback to
  the open tier. `verify_gpu=True` also ties NVIDIA's GPU evidence to the same TD
  first.
- `verify_confidential()`, reachable as `run["verify"]()`, re-checks a generation
  after the fact against the exact bytes of the exchange: the receipt the
  workload signed over them and the attestation behind the key set they were
  sealed to. `render_checks()` prints the result.
- Spend limits shared with the MCP server and the AgentKit provider.
  `PRISM_MAX_USDG` caps one lease or generation, `PRISM_DAILY_BUDGET_USDG` caps
  a rolling day, and one ledger at `PRISM_LEDGER_PATH` holds both, so a wallet
  has one ceiling however many clients are holding it. `PrismToolset` enforces
  them: a `max_usdg` from the model lowers the operator's per-call cap for one
  call and can never raise it. `read_budget()`, `SpendLedger` and
  `record_spend()` are exported for callers wiring their own tools.
- `Lease.deposit_micros` and `Lease.deposit_source`. The deposit is read from the
  `LeaseFunded` log of the funding transaction, which is what the escrow pulled.
  The quote's `maximum_escrow` is a ceiling and stands in only when there is no
  log to read, which `deposit_source` says.
- `prismnetwork[confidential]` installs the DCAP verifier and a JWT reader.
  Without them a confidential call refuses rather than sending a prompt to
  hardware nothing has checked.

### Changed

- `release(lease_id)` releases a lease by id alone, for one the process holds no
  handle to, such as the lease a failed `fund_quote()` names in its error.
- `end_lease()` releases the lease on the network and is what stops the meter.
  Settlement charges the seconds between access opening and the release and
  returns the rest of the deposit. Before this the call only deleted the local
  key and an interactive lease billed for its whole window. A release the
  control plane refuses is raised, because the machine is still billing.

- Every failure after a payment settled carries the transaction hash in
  `PrismError.broadcast` and in `body["payment_tx"]`, including one raised while
  the answer was being read. A ledger settles against the transfer instead of
  reverting money that has moved. `broadcast` stays `False` for anything that
  never reached the chain.
- A payment stays cached until the caller holds the answer, so a retry after an
  unreadable answer redeems the transfer already made rather than paying twice.
- A 200 whose body is not a completion is handed back whole: `text` is `None` and
  `response` holds what the endpoint served. A body that is not JSON raises
  `PaymentError` with code `malformed_answer`, and anything else that breaks
  while reading a paid answer raises `answer_unreadable`. Both name the transfer.
