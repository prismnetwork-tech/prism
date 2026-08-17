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
