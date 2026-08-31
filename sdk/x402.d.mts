/// The digest both sides compare: the command for a job, the request bytes for
/// a generation.
export declare function hashRequest(payload: string | Uint8Array): string;

/// The message a payer signs on the legacy rail, binding a transaction to the
/// one request it buys.
export declare function boundMessage(txHash: string, requestHash: string): string;
