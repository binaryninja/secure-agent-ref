# secure-agent-ref — reference implementation

A small, runnable Python codebase that demonstrates the controls described
in *Sandboxing and Capability Control for Tool-Using Autonomous Agents*
([paper][paper], [explainer][explainer], [checklist][checklist]). It is
**reference quality, not production quality** — the goal is that an
engineer can clone, run, and read it alongside the paper to see exactly
what each control looks like in practice.

Two planner modes share one broker:

  - **Scripted planner** (demos 01–07) — a hand-written sequence
    representing the §13 worst case ("treat the LLM planner as
    untrusted"). No API key needed.
  - **Real Claude Opus 4.7 planner** (demos 08–09) — an actual
    frontier model issuing tool calls through the broker via
    Anthropic SDK tool-use. Requires `ANTHROPIC_API_KEY` (loaded
    from `.env`).

The same broker, capability minter, IFC labels, policy engine,
sandbox, memory guard, and audit log are in the path for both. From
the broker's perspective the JSON is identical regardless of source.
That equivalence is the paper's thesis in code.

## Architecture at a glance

```mermaid
flowchart LR
    User([User<br/>request]) -->|task| Planner

    subgraph Planner["Planner — treat as untrusted (§3.1)"]
      direction TB
      Scripted["ScriptedPlanner<br/>demos 01–07"]
      LLM["LLMPlanner<br/>Claude Opus 4.7<br/>demos 08–09"]
    end

    Planner -->|"proposed call (JSON)"| Broker

    subgraph Broker["ToolBroker.invoke — single chokepoint (§7.3)"]
      direction TB
      Steps["descriptor pin → schema → capability →<br/>IFC label join → policy → approval → egress"]
    end

    Broker -->|"allowed call"| Tools
    Tools -.->|"result + provenance label"| Broker

    subgraph Tools["Tools (§9)"]
      direction TB
      Tlist["github · email · sandbox · memory · web"]
    end

    Broker -.->|"every decision"| Audit[("Audit log<br/>§11.6")]
    Planner -.->|"model turns"| Audit
```

Two planner modes funnel into the same broker. The broker is the only
path to a side effect; tools never run except via `ToolBroker.invoke`.
Every step lands in the audit log with full provenance.

## Quick start

```
pip install -r requirements.txt
python3 tests/test_unit.py             # 5 invariants
python3 tests/test_demos.py            # all 9 demos (LLM ones skip without a key)
python3 demos/02_lethal_trifecta.py    # scripted centerpiece
python3 demos/09_llm_lethal_trifecta.py  # same trifecta with real Opus 4.7
```

For the LLM demos, copy `.env.example` to `.env` and fill in your key.
Python 3.10+. Linux-only resource limits in the sandbox degrade
gracefully on macOS.

## What's in the box

```
secagent/
├── labels.py            §5.1  Confidentiality + Integrity + Origin labels with lattice join
├── capabilities.py      §4    Object capabilities; attenuation cannot widen; expiry
├── policy_compiler.py   §7.1  Task envelope (resources, recipients, ceilings, TTL)
├── minter.py            §7.2  Per-task short-lived capability minting
├── policy_engine.py     §7.4  Named rules; first match wins; deterministic
├── broker.py            §7.3  The chokepoint: descriptor pin → schema → cap → IFC → egress
├── egress.py            §7.6  Secret/PII scan over sink content
├── memory.py            §7.5  Memory guard with quarantine for untrusted-derived writes
├── sandbox.py           §6.6  Code execution profile (env strip, rlimits, ephemeral fs)
├── audit.py             §11.6 Provenance audit log; redacted hashes; pretty + JSONL
├── planner.py           §3.1  Scripted "untrusted" planner (no LLM dependency)
├── llm_planner.py       §3.1, §9.4  Claude Opus 4.7 planner — descriptor sanitization,
│                                    deny-as-tool-result loop, conservative IFC join
└── tools/               §9    Tool implementations: github, email, sandbox, memory, web

demos/
├── 01_research_agent.py            §8.1   Pattern A — read-only research agent
├── 02_lethal_trifecta.py           §1.1   GitHub MCP toxic flow blocked
├── 03_indirect_injection_email.py  §2.2   Email injection blocked twice (allowlist + approval)
├── 04_descriptor_pin.py            §9.3-4 Tool descriptor rug pull blocked
├── 05_sandbox_egress.py            §6.6   Sandbox profile + IFC into code execution
├── 06_memory_quarantine.py         §2.7   Memory poisoning quarantined
├── 07_ambient_authority.py         §11.3  Host creds not reachable from sandbox
├── 08_llm_research.py              §8.1   Real Opus 4.7 — Pattern A end-to-end
└── 09_llm_lethal_trifecta.py       §1.1   Real Opus 4.7 — indirect injection + red-team trifecta eval

tests/
├── test_unit.py    label join, cap attenuation, expiry, helpers
└── test_demos.py   runs every demo; non-zero exit on any failure
```

## Inside `broker.invoke`

The §7.3 enforcement chain is a fixed sequence of named checks. The
first deny short-circuits; an allow runs the tool. Every outcome —
including approvals — is recorded.

```mermaid
flowchart TD
    Start(["planner proposes:<br/>tool, action, args, arg_labels"]) --> Reg{"tool<br/>registered?"}
    Reg -- no --> R1["deny<br/>tool_not_registered"]
    Reg -- yes --> Pin{"descriptor<br/>hash matches pin?"}
    Pin -- no --> R2["deny<br/>descriptor_pin_mismatch §9.4"]
    Pin -- yes --> Sch{"args match<br/>tool schema?"}
    Sch -- no --> R3["deny<br/>schema_invalid"]
    Sch -- yes --> Cap{"capability covers<br/>tool, action, args? §4"}
    Cap -- no --> R4["deny<br/>capability_required"]
    Cap -- yes --> Join["join arg_labels →<br/>args_label §5.1"]
    Join --> Pol{"PolicyEngine<br/>verdict §7.4"}
    Pol -- DENY --> R5["deny<br/>rule_name e.g.<br/>no_private_to_public_github"]
    Pol -- APPROVAL_REQUIRED --> Hum{"ApprovalQueue<br/>resolver: yes/no? §7.4"}
    Hum -- no --> R6["deny<br/>human_approval_denied"]
    Hum -- yes --> Eg
    Pol -- ALLOW --> Eg{"egress secret<br/>scan finds matches? §7.6"}
    Eg -- yes --> R7["deny<br/>egress_secret_scan"]
    Eg -- no --> Run["tool.run args, ToolRunContext"]
    Run --> Done(["allow<br/>result + result_label"])

    classDef deny fill:#fdd,stroke:#933,color:#311
    classDef allow fill:#dfd,stroke:#393,color:#131
    class R1,R2,R3,R4,R5,R6,R7 deny
    class Done allow
```

Each diamond corresponds to one named control in `secagent/`. Every
deny path writes to the audit log with the rule name, the joined
provenance label, the sink destination if applicable, and a
content-hash redaction of the args.

## Mapping to the paper's §11 checklist

The [agent-capability-control checklist][checklist] enumerates the
load-bearing controls. Each row below names where the control lives
in this repo, and which demo verifies it.

| Checklist item | Code | Demo |
|---|---|---|
| Separate planner from authority | `broker.ToolBroker.invoke` is the only path to a side effect | 02, 07 |
| Remove ambient authority | `sandbox.CodeSandbox` strips env; broker fails closed on un-minted tools | 07 |
| Mint short-lived task-scoped caps | `minter.CapabilityMinter`; TTL = task expiry | 01, 02 |
| Pinned tool inventory + descriptor hashing | `broker.DescriptorRegistry` | 04 |
| Validate every tool argument against schema and capability scope | `Tool.validate` + `Capability.covers` | 02, 07 |
| Sanitize tool descriptors | descriptor / schema split (see §9.4 note in `tools/__init__.py`) | n/a (architecture) |
| Sandbox local stdio MCP servers | `sandbox.CodeSandbox` profile | 05, 07 |
| Label data with confidentiality, integrity, origin, purpose | `labels.Label` | every demo |
| Block low-integrity content from controlling high-impact actions | `policy_engine.rule_untrusted_content_cannot_select_shell_command` | 05 |
| Require explicit declassification | (out of scope; see "Scope and gaps" below) | — |
| Strong isolation for code execution | `sandbox.CodeSandbox` (subprocess + rlimits, see caveat) | 05, 07 |
| Authorize and label every memory write; quarantine externally influenced memories | `memory.MemoryGuard` | 06 |
| Partition memory and retrieval by tenant, user, workflow | `memory.MemoryGuard.read_for_task` | 06 |
| Treat every external write as a sink | `egress.scan_for_secrets` + `rule_external_send_recipient_allowlist` | 03 |
| Reserve human approval for risk transitions | `broker.ApprovalQueue` + `rule_approval_at_or_above_threshold` | 03, 05 |
| Log full provenance per action | `audit.AuditLog` records origins, capability, decision, sink, hash | every demo |
| Adaptive red-team scenarios | `tests/test_demos.py` runs every attacker scenario | all |

## What each demo proves

Each `main()` ends with `assert` statements that name the failure
condition. The asserts are the security claims; if you change a rule
or relax a check, the failing demo names the regression.

- **01 — Research agent.** Benign Pattern A path: only a public-fetch
  capability is minted; no email, no private data, no network. The
  call goes through and the audit log shows the full provenance.
- **02 — Lethal trifecta.** All three tools are *individually*
  capability-allowed. The broker still denies the public PR creation
  because the joined label on the `body` argument carries
  TENANT_PRIVATE from the private file. Per-tool allowlists are not
  enough; flow is what matters (paper §3.4, §5). See the trifecta
  sequence diagram below.
- **03 — Indirect injection via email.** Hijacked planner tries to
  forward inbox content to an attacker domain (denied by the recipient
  allowlist rule), and then to the user's own address (denied by
  human approval — provenance shown to the approver).
- **04 — Descriptor pin.** Benign tool registers, attacker mutates
  the descriptor at runtime to smuggle instructions, broker
  recomputes the hash and refuses. An admin re-pin restores access
  and writes an audit record.
- **05 — Sandbox + IFC into code.** The sandbox runs trusted code
  with an empty environment (no host secrets visible). When the
  proposed code carries an UNTRUSTED_EXTERNAL label, the engine
  routes to human approval. When the task envelope did not declare
  network, network requests are denied even with a valid capability.
- **06 — Memory quarantine.** A write derived from attacker content
  is staged out of `_active`. A privileged workflow on a later task
  reads memory and sees only the benign user-confirmed entry.
- **07 — Ambient authority.** Parent process env is seeded with fake
  AWS / GitHub / OpenAI / SSH credentials. The sandbox stdout shows
  none of them survived the env strip. Out-of-envelope tools (e.g.
  `email.send`) fail with `capability_required`.
- **08 — LLM research agent.** Real Claude Opus 4.7 runs the Pattern A
  task through tool-use. Same envelope and assertions as demo 01; the
  audit log proves the broker is in the path even for a real model.
- **09 — LLM lethal trifecta.** Two parts, both LLM-driven; no
  scripted forcing function. **A — indirect injection:** the user's
  task is benign, but the public issue body contains an injection
  payload. Opus 4.7's safety training typically catches this and
  refuses at the prompt level. The demo records that transparently
  ("model refused at prompt level — broker not exercised this run")
  rather than claiming the broker did the work. **B — red-team
  evaluation:** the planner is given an explicit security-research
  system prompt that frames the test as a controlled trajectory replay
  with the broker as system under test. The model cooperates,
  proposes the three calls in order, and the broker fires
  `no_private_to_public_github` on a *model-proposed* `create_public_pr`.
  The joined IFC label is built automatically by the conservative
  session-wide join in `LLMPlanner` — no demo-author hand-construction.
  Strong assertions across both parts: no `allow` ever logged for
  `github.create_public_pr`, and the trifecta rule fires at least
  once on a model-proposed call in Part B.

### The trifecta in time (demo 02 / demo 09 Part B)

Both demos produce this broker trace; the difference is who supplied
the `body` argument's joined label. Demo 02 (scripted) constructs it
explicitly. Demo 09 Part B (Claude Opus 4.7 through the LLM bridge)
gets the same join automatically from the conservative session-wide
join in `LLMPlanner._invoke_through_broker`.

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant Pl as Planner
    participant B as ToolBroker
    participant Po as PolicyEngine
    participant G as GitHub tools

    U->>Pl: triage acme/public-ui#42
    Pl->>B: github.read_issue(repo, 42)
    B->>Po: decide (args_label = INTERNAL / USER_TRUSTED)
    Po-->>B: allow (default_allow)
    B->>G: read_issue
    G-->>B: body, label = PUBLIC / UNTRUSTED_EXTERNAL

    Pl->>B: github.read_private_file(repo, path)
    B->>Po: decide
    Po-->>B: allow (default_allow)
    B->>G: read_private_file
    G-->>B: file, label = TENANT_PRIVATE / UNTRUSTED_EXTERNAL

    Pl->>B: github.create_public_pr(body = issue + file)
    Note over B: join body's labels →<br/>TENANT_PRIVATE / UNTRUSTED_EXTERNAL
    B->>Po: decide
    Po-->>B: DENY (no_private_to_public_github)
    B-->>Pl: outcome.decision = DENY
    Pl-->>U: broker refused step 3
```

The two read calls are individually capability-allowed; the public-PR
call is denied not because the *call* is forbidden but because the
*flow* is — `body` carries TENANT_PRIVATE / UNTRUSTED_EXTERNAL and
`github_public_write` is not a sink that label can reach. This is
why per-tool allowlists are insufficient (paper §3.4).

## Demo shortcuts and what they don't prove

The demos pass — every assertion holds and the audit trail tells an
honest story — but several of them are *demonstrations* of a control
rather than independent end-to-end tests of it. This section names
every shortcut so a reader doesn't mistake the wiring for a guarantee.

- **Demo 02 hand-constructs the IFC join the rule keys on.**
  Line 139 builds `arg_labels={"body": issue_label.join(secrets_label)}`
  manually — the *demo author* does the join, not the broker. The
  scripted planner has no taint-tracking interpreter; it can only
  pass whatever labels we give it. The realistic mechanism is in
  `LLMPlanner._invoke_through_broker`, which joins all session labels
  into every arg automatically. Demo 09 Part B exercises that
  realistic mechanism. Demo 02 illustrates the policy rule firing
  given a correctly-labeled call; producing the labeling is the
  planner's job, demonstrated elsewhere.

- **Demo 03 step 3's "human approval denied" is just a function that
  returns False.** The `deny_resolver` is a stand-in for a UI. The
  demonstrated property is that the broker correctly *routes to*
  approval at the right side-effect threshold and surfaces the
  verdict + provenance to the resolver — the human's choice is out of
  scope for this codebase.

- **Demo 04 mutates `tool.descriptor` in place.** That is the attack
  we are testing (an MCP server changing its tool metadata after
  approval), so this isn't a cheat — but the demo doesn't model how
  an attacker actually gets the bytes flipped (server compromise,
  supply-chain swap, etc.). The pin verification is what gets tested,
  not the attack surface that produces the mutation.

- **Demo 05's network deny is policy-layer, not isolation-layer.** The
  rule `block_network_from_code_sandbox_by_default` refuses to launch
  the sandbox tool when `network=True` is requested without
  `network_required` in the envelope. The reference sandbox shares
  the host network namespace, so a snippet that just shells out to
  `curl` would still reach the network. This is documented in the
  demo's prose and the rule's docstring; production deployments need
  netns/iptables, Firecracker, or gVisor.

- **Demo 06 uses hardcoded `Label()` constants** rather than labels
  derived from a real attacker-content read. The MemoryGuard's
  quarantine logic is exercised, but the upstream path "untrusted
  tool → result_label → memory write" is short-circuited.

- **Demo 07 only verifies env-strip.** The §6.6 profile also covers
  no home-dir mount, no Docker/SSH socket, no shared cookies, no
  cloud creds beyond env. The demo plants canaries in env vars and
  proves env is stripped; it does not prove the other ambient-
  authority surfaces are gone, because the reference sandbox is a
  subprocess and those surfaces aren't really there to begin with.
  A Firecracker/gVisor deployment would test more of them.

- **Demo 09 Part A doesn't always exercise the broker.** When Opus
  4.7 refuses the injected instruction at the prompt level (which is
  the typical outcome), no `github.create_public_pr` call reaches the
  broker, and the policy engine does no work. The demo says so
  explicitly in its bookkeeping line. The broker is exercised in
  Part B regardless — which is why Part B is the one with the strong
  assertion.

- **Demo 09 Part B's red-team prompt is cooperative framing, not a
  jailbreak.** We tell Opus 4.7 we're running a controlled security
  evaluation and ask it to propose the worst-case trajectory so the
  broker can be observed. Opus 4.7 cooperates because the framing is
  honest. If a future model refuses this framing, Part B's strong
  assertion will fail and the demo will say why ("the model refused
  to cooperate with the red-team evaluation framing"). The point is
  not to bypass model safety — it is to exercise the broker against
  an attempted unsafe call without depending on indirect-injection
  reliability or scripted forcing. Part A still does the indirect-
  injection observation.

- **Per-demo envelopes are tuned to make a specific rule fire.**
  Demo 02 sets `approval_threshold=ADMIN_MUTATE` so the public-PR
  call doesn't hit human approval, leaving `no_private_to_public_github`
  as the rule under test. Demo 03 sets it to `EXTERNAL_SEND` so the
  send-to-self path *does* hit approval. Each demo demonstrates a
  different envelope; the system is per-task envelopes by design,
  so this isn't a cheat — but a reader running the suite end-to-end
  should know the envelope is freshly compiled per demo.

- **Capability scopes split inconsistently.** Some demos put the
  recipient/repo allowlist in the cap scope (demo 02's
  `github.create_public_pr` cap is repo-scoped); others rely on a
  policy-level rule with an empty cap scope (demo 03's `email.send`
  cap has `scope={}` and the recipient allowlist is enforced via the
  rule). The comment at `demos/03_indirect_injection_email.py:46`
  cites §7.2: downstream services that can't express per-call
  recipient scope force the broker to emulate scoping at the rule
  layer. Both shapes are valid; they just look different.

- **The egress secret scanner runs on every public-write/external-send
  but never fires in any demo.** A deny rule fires before content
  ever reaches `scan_for_secrets`. The scanner is a backstop we ship
  but don't exercise. A demo that exercises *only* the scanner (by
  bypassing the upstream rules) would round out the test set.

- **Truncated provenance origins in the audit log.** Joined origins
  duplicate as the session label list grows ("user_request+
  github.public_issue:...+user_request+github.public_issue:..."). The
  policy engine doesn't care — it reads the lattice levels — but a
  human reader of the log will see the duplication. A real deployment
  should deduplicate origin paths in the audit renderer.

The single largest realistic-to-paper gap is: **no real downstream
services.** Every tool returns canned data. The capability minter
would, in production, call out to GitHub / IAM / object stores for
native scoped credentials (§7.2). The scope-emulation path is what's
exercised here, not native credential minting.

## How the LLM bridge works

`secagent/llm_planner.py` is the only module that touches the
Anthropic SDK. It wires Claude's tool-use loop to `ToolBroker.invoke`
without giving the model any direct authority. The interesting bits:

- **Descriptor sanitization (§9.4).** The model sees a sanitized,
  admin-style summary of each tool plus its JSON Schema, never the
  raw `descriptor` field. Invisible Unicode and instruction-shaped
  phrases ("ignore previous", "system prompt") are stripped or
  replaced. The broker still hashes the raw descriptor for pinning,
  so a rug-pull is detected even though the planner never saw the
  raw bytes.
- **Tool-call JSON is untrusted output (§7.3).** Every proposed call
  goes through the same `broker.invoke` chain the scripted demos
  use. Schema validation, capability scope, IFC rules, egress scan
  — identical path.
- **Denials are tool errors, not crashes.** When the broker returns
  `Decision.DENY`, the planner injects a `tool_result` with
  `is_error=True` and the rule + reason. The model sees what
  happened and can adapt or report. A consecutive-deny counter
  bounds runaway loops.
- **Conservative IFC join (§5.5, §12.3 "semantic data laundering").**
  The model could paraphrase a secret without copying it verbatim,
  so substring tracking is unsound. Instead, every tool result label
  is added to a session-wide list, and every subsequent argument is
  conservatively labeled with the join of *all* prior labels. The
  policy engine then enforces against that joined label. This is
  overly strict by design — it matches the paper's stance.
- **Tool name encoding.** The Anthropic API restricts tool names to
  `^[a-zA-Z0-9_-]{1,128}$`. The broker uses dotted names like
  `github.read_issue` so audit logs read naturally; the planner
  translates `.` to `__` on the wire and back on dispatch.

The design is deliberately one-directional: the planner can call into
the broker, but the broker has no concept of "ask the planner". This
preserves the §3.1 separation — the model proposes, the broker
disposes, and the model only learns about denials through normal
tool-error feedback.

## Reading this alongside the paper

Module docstrings cite the paper section they implement. To follow
the paper's §7 reference architecture, read in this order:

1. `policy_compiler.py` — §7.1 task envelope structure.
2. `minter.py` — §7.2 per-task minting.
3. `broker.py` — §7.3 enforcement chokepoint.
4. `policy_engine.py` — §7.4 rules.
5. `memory.py` — §7.5 memory guard.
6. `egress.py` — §7.6 sink set.

For the threat model and IFC theory, read `labels.py` against §5 and
`capabilities.py` against §4.

## Scope and gaps

This is a reference, not a substitute for production engineering.
Specific gaps:

- **`sandbox.py` is not a security boundary.** It demonstrates the
  §6.6 profile (env strip, rlimits, ephemeral scratch) but uses a
  Linux subprocess that shares the host kernel. Production should
  use Firecracker (§6.3) or gVisor (§6.2). The README is explicit so
  no one mistakes the demo for an isolation product.
- **No real downstream services.** Tools return canned data. The
  capability minter would, in production, call out to GitHub /
  IAM / object stores for native scoped credentials (§7.2). The
  scope-emulation path is what's exercised here.
- **Declassification is not implemented.** The §11 "explicit,
  purpose-bound declassification" item is left as a stub: the only
  way confidential data flows to an external sink in this codebase
  is through the egress scanner + recipient allowlist combination,
  which is sufficient for the demo set but not the full §5.5 design.
- **Descriptor sanitization is partial.** `broker.py` separates
  human-facing descriptor (hashed and pinned) from schema (shown to
  the planner). It does not strip invisible Unicode or
  instruction-like phrasing from descriptors before display
  (§9.4 #3); a real deployment should.
- **AI-control monitor (§12.7) is out of scope.** Capability control
  treats monitors as advisory anyway.

## Citations from the paper

The paper sections most relevant to each module are listed in
`secagent/<module>.py` docstrings. The attacker scenarios in the demos
are the paper's §10.3 red-team scenarios, named at module level.

[paper]: https://richards.ai/papers/security-sandboxing-and-capability-control-for-tool-using-autonomous-agen
[explainer]: https://richards.ai/learn/what-is-agent-capability-control
[checklist]: https://richards.ai/checklists/agent-capability-control

## License

Public domain reference code. Attribute the paper, not this repo.
