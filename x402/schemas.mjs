// Call shapes for the paid endpoints, shared by the discovery document and the
// runtime 402 so the two can never describe different calls.
export const jobInput = {
  type: "object",
  properties: {
    command: { type: "string", minLength: 1, description: "The shell command to run on the GPU box." },
  },
  required: ["command"],
};

export const jobOutput = {
  type: "object",
  properties: {
    job_id: { type: "string" },
    status: { type: "string" },
    token: { type: "string", description: "Bearer token for polling this job." },
    poll: { type: "string", description: "Where to poll." },
  },
  required: ["job_id", "status", "token", "poll"],
};

/// A literal response, for the discovery extension's `output.example`. A schema
/// there is rejected: the field is for a sample, not a description.
export const jobExample = {
  job_id: "3f2a1c88-0f1e-4c1a-9f0b-7c2d5e6a1b34",
  status: "queued",
  token: "b7c1e0a2-9d3f-4a55-8e21-0c6f4b9d2a17",
  poll: "/jobs/3f2a1c88-0f1e-4c1a-9f0b-7c2d5e6a1b34",
};

/// A literal request, for the discovery extension's `info.input.body`.
export const jobInputExample = { command: "nvidia-smi" };
