import assert from "node:assert/strict";
import { test } from "node:test";

import { VAULT_KEY_STATEMENT } from "./vault.mjs";
import {
  DEFAULT_WORKSPACE_TRUST_FLOOR,
  PrismWorkspace,
  WORKSPACE_KEY_STATEMENT,
  WorkspaceError,
  workspaceAssociatedData,
} from "./workspace.mjs";

const STORAGE = "https://storage.test";

// Object storage. Presigned URLs are opaque bearer strings here exactly as they
// are in S3, so a test can assert one never left this process.
const objects = new Map();

globalThis.fetch = async (url, init = {}) => {
  const key = String(url).split("?")[0];
  if (init.method === "PUT") {
    objects.set(key, new Uint8Array(init.body));
    return { ok: true, status: 200 };
  }
  const stored = objects.get(key);
  if (!stored) return { ok: false, status: 404 };
  return {
    ok: true,
    status: 200,
    async arrayBuffer() {
      return stored.slice().buffer;
    },
  };
};

// Stands in for the control plane: it holds exactly what a real deployment
// holds, so a test that reads a renter's files out of `workspaces` proves the
// service could have read them too.
class FakeService {
  constructor() {
    this.workspaces = new Map();
    this.sent = [];
    this.serveVersion = null;
  }

  request(method, segments, { body = null } = {}) {
    this.sent.push({ method, segments, body });
    const [id, action] = segments;
    if (!id) {
      if (method === "GET") return [...this.workspaces.values()].map((w) => this.#record(w));
      if (method === "POST") return this.#create(body);
      throw new Error(`unexpected ${method} /workspaces`);
    }
    const workspace = this.workspaces.get(id);
    if (!workspace) throw new WorkspaceError("workspace_not_found");
    if (method === "DELETE") {
      this.workspaces.delete(id);
      return null;
    }
    if (action === "upload") return this.#upload(workspace, body);
    if (action === "commit") return this.#commit(workspace, body);
    if (action === "download") return this.#download(workspace);
    throw new Error(`unexpected ${method} ${segments.join("/")}`);
  }

  #create(body) {
    const workspace = {
      workspace_id: crypto.randomUUID(),
      name: body.name,
      version: 0,
      snapshots: new Map(),
      min_trust_class: body.min_trust_class,
    };
    this.workspaces.set(workspace.workspace_id, workspace);
    return this.#record(workspace);
  }

  #record(workspace, version = workspace.version) {
    const snapshot = workspace.snapshots.get(version);
    return {
      workspace_id: workspace.workspace_id,
      name: workspace.name,
      version,
      min_trust_class: workspace.min_trust_class,
      ...(snapshot ? { snapshot } : {}),
    };
  }

  // Only ever the next version, so a URL handed out here cannot overwrite bytes
  // the renter still holds metadata for.
  #upload(workspace, body) {
    assert.equal(typeof body.size_bytes, "number");
    const version = workspace.version + 1;
    const key = `${workspace.workspace_id}/${version}`;
    return { url: `${STORAGE}/${key}?sig=${crypto.randomUUID()}`, version, key };
  }

  #commit(workspace, body) {
    if (body.version !== workspace.version + 1) {
      throw new WorkspaceError("workspace_version_conflict");
    }
    // Storage is the only party that knows what arrived, the same check the
    // control plane makes before it records a snapshot.
    const stored = objects.get(`${STORAGE}/${workspace.workspace_id}/${body.version}`);
    if (!stored) throw new WorkspaceError("snapshot_not_uploaded");
    if (stored.length !== body.size_bytes) throw new WorkspaceError("snapshot_size_mismatch");
    workspace.version = body.version;
    workspace.snapshots.set(body.version, {
      wrapped_key: body.wrapped_key,
      nonce: body.nonce,
      ciphertext_digest: body.ciphertext_digest,
      size_bytes: body.size_bytes,
    });
    return this.#record(workspace);
  }

  #download(workspace) {
    const version = this.serveVersion ?? workspace.version;
    return {
      url: `${STORAGE}/${workspace.workspace_id}/${version}?sig=${crypto.randomUUID()}`,
      version,
      ...workspace.snapshots.get(version),
    };
  }
}

// A leased machine with tar and base64 and nothing else. tar is the identity
// here; what matters is that the client only asks for those two commands and
// that everything it hands over crosses on stdin.
class FakeMachine {
  constructor() {
    this.files = new Map();
    this.commands = [];
    this.oversize = false;
  }

  run(lease, command, { stdin = null } = {}) {
    this.commands.push({ command, stdin });
    if (command.includes("base64 -d")) {
      const [, path] = /tar -C '([^']+)' -xzf -/.exec(command);
      this.files.set(path, new Uint8Array(Buffer.from(stdin, "base64")));
      return { code: 0, stdout: "", stderr: "", timedOut: false };
    }
    const [, path] = /tar -C '([^']+)' -czf/.exec(command);
    const archive = this.files.get(path);
    if (!archive) {
      return { code: 2, stdout: "", stderr: `tar: ${path}: No such file or directory`, timedOut: false };
    }
    if (this.oversize) {
      // Padded the way BSD wc pads it, which the marker has to survive.
      return { code: 3, stdout: "", stderr: "prism_snapshot_too_large:   68719476736", timedOut: false };
    }
    // Wrapped the way coreutils and busybox both wrap it.
    const wrapped = Buffer.from(archive).toString("base64").replace(/(.{76})/g, "$1\n");
    return { code: 0, stdout: wrapped, stderr: "", timedOut: false };
  }
}

// A deterministic stand-in for a wallet. Real secp256k1 signing is deterministic
// per RFC 6979, which is what lets the same wallet re-derive the same key.
function fakeAgent(service, machine, { address = "0xAbC0000000000000000000000000000000000001", statement = null } = {}) {
  return {
    address,
    session: "session",
    async authenticate() {},
    async signVaultStatement(asked) {
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(`${address.toLowerCase()}\0${statement ?? asked}`),
      );
      return `0x${Buffer.from(digest).toString("hex")}`;
    },
    async workspaceRequest(method, segments, options) {
      return service.request(method, segments, options);
    },
    run(lease, command, options) {
      return machine.run(lease, command, options);
    },
  };
}

const lease = { leaseId: 7, access: { ssh_host: "10.0.0.4", ssh_port: 22 }, keyPath: "/tmp/key" };

async function unlocked(service, machine, options) {
  return new PrismWorkspace(fakeAgent(service, machine, options)).unlock();
}

function bytes(text) {
  return new Uint8Array(Buffer.from(text, "utf8"));
}

test("a directory saved from one machine restores onto another", async () => {
  const service = new FakeService();
  const source = new FakeMachine();
  const target = new FakeMachine();
  const checkpoint = bytes("step=4200\nloss=0.13\n");
  source.files.set("/root/out", checkpoint);

  const client = await unlocked(service, source);
  const workspace = await client.create("finetune-run");
  const saved = await client.save(lease, workspace, "/root/out");
  assert.equal(saved.version, 1);

  const restorer = await unlocked(service, target);
  await restorer.restore(lease, workspace, "/root/out", { expectVersion: 1 });
  assert.deepEqual(target.files.get("/root/out"), checkpoint);
});

test("neither the service nor the object store holds anything readable", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("OPENAI_API_KEY=sk-live-9912"));

  const client = await unlocked(service, machine);
  const workspace = await client.create("secrets");
  await client.save(lease, workspace, "/root/out");

  const onTheWire = JSON.stringify(service.sent);
  assert.ok(!onTheWire.includes("sk-live-9912"), "the file reached the service in the clear");
  assert.ok(!onTheWire.includes("OPENAI"), "part of the file reached the service");
  for (const object of objects.values()) {
    assert.ok(!Buffer.from(object).toString("binary").includes("sk-live"), "storage holds readable bytes");
  }
});

test("the presigned url never reaches the leased machine", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("weights"));

  const client = await unlocked(service, machine);
  const workspace = await client.create("weights");
  await client.save(lease, workspace, "/root/out");
  await client.restore(lease, workspace, "/root/back");

  for (const { command } of machine.commands) {
    assert.ok(!command.includes(STORAGE), "a bearer capability was handed to the host");
    assert.ok(!command.includes("sig="), "a presigned signature was handed to the host");
  }
});

test("the archive crosses on stdin, not in the command", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("private working files"));

  const client = await unlocked(service, machine);
  const workspace = await client.create("work");
  await client.save(lease, workspace, "/root/out");
  await client.restore(lease, workspace, "/root/out");

  const extract = machine.commands.at(-1);
  assert.ok(extract.command.includes("base64 -d | tar -C '/root/out' -xzf -"));
  assert.ok(!extract.command.includes("private working files"));
  assert.equal(Buffer.from(extract.stdin, "base64").toString("utf8"), "private working files");
});

test("storage that altered a snapshot is caught before anything is decrypted", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("checkpoint"));

  const client = await unlocked(service, machine);
  const workspace = await client.create("tampered");
  await client.save(lease, workspace, "/root/out");

  const [key] = [...objects.keys()].filter((k) => k.includes(workspace.workspace_id));
  const stored = objects.get(key);
  stored[stored.length - 1] ^= 0x01;

  const before = machine.commands.length;
  await assert.rejects(() => client.restore(lease, workspace, "/root/back"), (err) => {
    assert.ok(err instanceof WorkspaceError);
    assert.equal(err.code, "workspace_digest_mismatch");
    assert.equal(err.body.expected_bytes, err.body.served_bytes);
    return true;
  });
  assert.equal(machine.commands.length, before, "the machine was touched after a failed check");
});

test("a truncated snapshot is refused rather than decrypted", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("a longer checkpoint file"));

  const client = await unlocked(service, machine);
  const workspace = await client.create("truncated");
  await client.save(lease, workspace, "/root/out");

  const [key] = [...objects.keys()].filter((k) => k.includes(workspace.workspace_id));
  objects.set(key, objects.get(key).slice(0, 8));

  await assert.rejects(
    () => client.restore(lease, workspace, "/root/back"),
    /workspace_digest_mismatch/,
  );
});

test("a different wallet cannot open another wallet's snapshot", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("passport scans"));

  const owner = await unlocked(service, machine);
  const workspace = await owner.create("private");
  await owner.save(lease, workspace, "/root/out");

  const intruder = await unlocked(service, machine, {
    address: "0xDef0000000000000000000000000000000000002",
  });
  await assert.rejects(() => intruder.restore(lease, workspace, "/root/back"), (err) => {
    assert.equal(err.code, "workspace_key_mismatch");
    return true;
  });
});

test("the vault key does not open a workspace", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("training set"));

  const client = await unlocked(service, machine);
  const workspace = await client.create("separate");
  await client.save(lease, workspace, "/root/out");

  // A wallet that signed the vault statement instead, which is the whole point
  // of the two clients asking for different ones.
  const crossed = await unlocked(service, machine, { statement: VAULT_KEY_STATEMENT });
  await assert.rejects(() => crossed.restore(lease, workspace, "/root/back"), /workspace_key_mismatch/);
});

test("being served an older version is refused, not quietly restored", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("first"));

  const client = await unlocked(service, machine);
  const workspace = await client.create("versions");
  await client.save(lease, workspace, "/root/out");
  machine.files.set("/root/out", bytes("second"));
  const latest = await client.save(lease, workspace, "/root/out");
  assert.equal(latest.version, 2);

  // An old snapshot is internally consistent, so it decrypts cleanly and
  // nothing downstream would notice. The record already says which version is
  // current, so a grant for any other one is a rollback and is refused without
  // the caller having to know to ask.
  service.serveVersion = 1;
  await assert.rejects(
    () => client.restore(lease, workspace, "/root/back"),
    (err) => {
      assert.equal(err.code, "workspace_version_rollback");
      assert.equal(err.body.expected, 2);
      assert.equal(err.body.served, 1);
      return true;
    },
  );
  assert.equal(machine.files.has("/root/back"), false);

  await assert.rejects(
    () => client.restore(lease, workspace, "/root/back", { expectVersion: 2 }),
    (err) => {
      assert.equal(err.code, "workspace_version_rollback");
      assert.equal(err.body.served, 1);
      return true;
    },
  );
});

test("a rewritten trust floor breaks the seal instead of lowering the bar", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("model weights"));

  const client = await unlocked(service, machine);
  const workspace = await client.create("guarded", { minTrustClass: "attested" });
  await client.save(lease, workspace, "/root/out");

  // What a compromised control plane would do to get a snapshot onto a host it
  // can read: rewrite the policy field and serve it back.
  service.workspaces.get(workspace.workspace_id).min_trust_class = "open";
  await assert.rejects(
    () => client.restore(lease, workspace, "/root/back"),
    /workspace_authentication_failed/,
  );
  await assert.rejects(
    () => client.restore(lease, workspace, "/root/back", { expectTrustClass: "attested" }),
    /workspace_trust_floor_changed/,
  );
});

test("a directory too large to carry fails on the machine", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("x"));
  machine.oversize = true;

  const client = await unlocked(service, machine);
  const workspace = await client.create("huge");
  await assert.rejects(() => client.save(lease, workspace, "/root/out"), (err) => {
    assert.equal(err.code, "workspace_snapshot_too_large");
    assert.equal(err.body.bytes, 68_719_476_736);
    return true;
  });
  assert.deepEqual([...objects.keys()].filter((k) => k.includes(workspace.workspace_id)), []);
  assert.equal(service.workspaces.get(workspace.workspace_id).version, 0);
});

test("a missing directory reports what the machine said", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();

  const client = await unlocked(service, machine);
  const workspace = await client.create("absent");
  await assert.rejects(() => client.save(lease, workspace, "/root/nope"), (err) => {
    assert.equal(err.code, "workspace_archive_failed");
    assert.match(err.body.stderr, /No such file or directory/);
    return true;
  });
});

test("restoring a workspace nothing was ever saved to says so", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();

  const client = await unlocked(service, machine);
  const workspace = await client.create("empty");
  await assert.rejects(() => client.restore(lease, workspace, "/root/out"), /workspace_empty/);
});

test("workspaces default to a floor live capacity can clear", async () => {
  const service = new FakeService();
  const client = await unlocked(service, new FakeMachine());

  const workspace = await client.create("default");
  assert.equal(workspace.min_trust_class, DEFAULT_WORKSPACE_TRUST_FLOOR);
  assert.equal(DEFAULT_WORKSPACE_TRUST_FLOOR, "open");
  assert.equal(PrismWorkspace.permits("open", "open"), true);
  assert.equal(PrismWorkspace.permits("attested", "isolated"), false);
  assert.throws(() => PrismWorkspace.permits("open", "sgx"), /invalid_trust_floor/);
});

test("names, paths, ids and lease handles are checked before anything is sent", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  machine.files.set("/root/out", bytes("x"));
  const client = await unlocked(service, machine);
  const workspace = await client.create("checked");

  await assert.rejects(() => client.create(""), /invalid_workspace_name/);
  await assert.rejects(() => client.create("x".repeat(65)), /invalid_workspace_name/);
  await assert.rejects(() => client.create("x", { minTrustClass: "private" }), /invalid_trust_floor/);
  await assert.rejects(() => client.remove("not-a-uuid"), /invalid_workspace_id/);
  await assert.rejects(() => client.save({}, workspace, "/root/out"), /invalid_lease_handle/);
  await assert.rejects(
    () => client.save(lease, workspace, "/root/'; rm -rf /"),
    /invalid_remote_path/,
  );
});

test("locking discards the key", async () => {
  const service = new FakeService();
  const client = await unlocked(service, new FakeMachine());
  const workspace = await client.create("locked");

  assert.equal(client.unlocked, true);
  client.lock();
  assert.equal(client.unlocked, false);
  await assert.rejects(() => client.save(lease, workspace, "/root/out"), /workspace_locked/);
  await assert.rejects(() => client.restore(lease, workspace, "/root/out"), /workspace_locked/);
});

// Pinned against the identical vector in prism-protocol's Rust test. These two
// implementations must agree byte for byte or every stored snapshot stops
// opening.
test("associated data matches the protocol vector", () => {
  const aad = workspaceAssociatedData(
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
    "018f3a2b-4c5d-7e8f-9012-3456789abcde",
    7,
    "isolated",
  );

  assert.equal(
    Buffer.from(aad).toString("binary"),
    // Explicit \u0000 escapes: "\0" before a digit is an octal escape, which
    // would quietly change the vector.
    "prism.workspace.v1\u00000x1f9840a85d5af5bf1d1762f925bdaddc4201f984\u0000018f3a2b-4c5d-7e8f-9012-3456789abcde\u00007\u0000isolated\u0000",
  );
});

test("the key statement names its own domain and is not the vault's", () => {
  assert.match(WORKSPACE_KEY_STATEMENT, /prism\.workspace\.kdf\.v1/);
  assert.match(WORKSPACE_KEY_STATEMENT, /never sent/);
  assert.notEqual(WORKSPACE_KEY_STATEMENT, VAULT_KEY_STATEMENT);
});

test("a large snapshot survives the base64 and chunking paths", async () => {
  const service = new FakeService();
  const machine = new FakeMachine();
  const archive = new Uint8Array(2_000_000);
  for (let offset = 0; offset < archive.length; offset += 0x10000) {
    crypto.getRandomValues(archive.subarray(offset, offset + 0x10000));
  }
  machine.files.set("/root/out", archive);

  const client = await unlocked(service, machine);
  const workspace = await client.create("large");
  await client.save(lease, workspace, "/root/out");
  await client.restore(lease, workspace, "/root/back");

  assert.deepEqual(machine.files.get("/root/back"), archive);
});
