# Vyuu MCP Gateway Handoff

This file summarizes the current implementation state so another coding agent can continue without reconstructing the session history.

**See [`BACKLOG.md`](BACKLOG.md) for the durable to-do list** — what's pending, why, rough effort, and dependencies. This file is the chronological session log + how-to-resume; the backlog is the planning surface.

## Sub-session update — 2026-08-27d (MCP server drill-in)

The tool catalogue was reachable only from inside the Publish-vserver
flow, which is the wrong moment: an operator deciding WHETHER to publish
needs to read the descriptions first, and those descriptions are also
where a hostile upstream would hide instructions aimed at the calling
model.

Each server row now has **Drill in →** opening a drawer with three tabs:

- **Tools** — every capability as an MCP client sees it on `tools/list`:
  name, full description, risk category, kind. Search across name and
  description, filter by kind, optional raw `schema_json`. A capability
  with no description says so explicitly — the calling model sees only
  a name and a schema there, which is worth noticing.
- **Risk** — the stored assessment with each finding's evidence quote
  and mitigation, and a button to (re-)assess.
- **Details** — runtime, transport, source, health, last sync, id.

The row's risk pill now OPENS this drawer rather than firing the
assessment directly: a click there spends real money at an LLM vendor,
and a table row is too easy to hit by accident.

### Two bugs found by looking at it

- **The drawer rendered nowhere.** I placed it next to `#vserver-drawer`,
  which lives INSIDE the vservers `<section class="panel">` — so it
  inherited `is-hidden` whenever the operator was on any other nav.
  `hidden=false` and invisible. A modal belongs at shell level, not
  nested in one panel; it is now a sibling of the panels.
- **The console CSP blocks inline styles.** `style-src 'self'` with no
  `unsafe-inline`, so a `style=` ATTRIBUTE written via `innerHTML`
  silently never applies and only shows up as a console error. CSSOM
  assignment (`el.style.font = ...`) is NOT blocked and is the correct
  route. Mine is fixed; ~6 pre-existing occurrences in the static HTML
  remain and are spawned as a separate task.

## Sub-session update — 2026-08-27c (RISK-1 · LLM risk classification — CORE LANDED)

**1117 no-DB, 1367 real-DB, zero failures.** New `risk/` package, 23
tests, both load-bearing rules verified by inverting them.

### Grounded, not invented — read this before extending it

Two published sources were **fetched and read**, not recalled:

- **OWASP MCP Top 10** (beta) from `owasp.org/www-project-mcp-top-10`.
  MCP01:2025–MCP10:2025 with their exact titles, in
  `risk/taxonomy.py`.
- **MCP-in-SoS, arXiv:2603.10194**, "Risk assessment framework for
  open-source MCP servers". The PDF was extracted and the equations
  transcribed: LA/LE/MI/CC/TS factors, `Likelihood = LA·LE·MI` (eq. 6),
  `Impact = TS·CC` (eq. 7), `R = L·I` (eq. 8), and the aggregation
  `Rexp`/`Rrms`/`Roverall` (eq. 9-11). It also supplies the four
  MCP-primitive threat categories (Tool / Resource / Prompt / Protocol).

**Model ids were also checked, not recalled.** `gpt-5.6-terra` and
`gpt-5.6-luna` are real and postdate my training; I would have written
them off as a mishearing. `gemini-3.7-flash` is the current GA. If you
touch `KNOWN_MODELS`, verify against the vendor's live model list rather
than memory.

### The honest limitation, stated in three places

The paper runs **static analysis over server source code** and counts
real CWE findings. We have no source — we have tool names, descriptions
and input schemas from capability sync. So this reuses the paper's
*scoring* on a *weaker evidence base*. That surface is exactly right for
tool-poisoning and prompt classes and nearly blind to anything needing
code. It is in the module docstring, on every assessment as
`evidence_basis`, and must stay in the UI. A number whose provenance is
invisible gets read as more than it is.

### Two things I got wrong and fixed

- **Normalising against the theoretical maximum.** `MAX_FINDING_RISK` is
  3750 and nothing real approaches it, so ten maximally-bad findings
  scored 32/100 and the whole scale read "everything is fine". The band
  now anchors on `REFERENCE_SEVERE_FINDING_RISK` (1200 — a genuinely
  severe finding). A yardstick nothing can touch measures nothing.
- **The band used `Roverall`**, which includes the log-volume factor, so
  fifty trivial findings outranked three critical ones. It now uses
  `Rrms`, which the paper builds precisely to emphasise high-risk
  findings. Volume is still reported, where it informs without
  dominating.

### Risk reduction: arithmetic, not two opinions

The obvious implementation — classify the server, classify the vserver,
subtract — is wrong and `risk/reduction.py` says why at length. Two runs
are two opinions; they differ from sampling and phrasing, so the
"reduction" would be partly noise and occasionally NEGATIVE. Instead the
upstream is assessed **once** and published risk is computed from the
*same findings*, restricted to those still reaching a published tool.

A finding naming **no** tools (transport weakness, supply-chain
provenance) is **retained**, never credited as eliminated — curating a
tool list does not change how a server is built. That rule is what keeps
the number defensible, and it is also why reductions come out smaller
than operators expect. Verified live: a Falcon-shaped set went
`high (57.1) → low (9.6)`, 83.2% reduction, naming remote-shell and
quarantine-delete as eliminated while retaining the transport finding.

### All four remaining pieces landed (same session)

**1117 no-DB, 1374 real-DB, zero failures.** Migration `20260827_0025`.

- **Persistence.** `mcp_server_risk_assessments` and
  `virtual_server_risk_assessments`, both RLS-isolated. Rows accumulate
  rather than being overwritten: a sync that adds a `delete_*` tool must
  show as risk MOVING, and movement cannot be seen against a value that
  was replaced in place. `source_assessment_ids` on the vserver row makes
  a stale comparison detectable rather than merely suspicious.
- **Tenant config** on `tenants`, following the `slug` pattern. The API
  key is a **SecretStore ref**; the endpoint rejects anything shaped like
  a real key (`sk-`, `AIza`, …) because that table gets dumped and read
  by support.
- **API** — `/admin/risk/model`, `/admin/risk/summary`,
  `/admin/risk/preview`, plus assess/read on servers and vservers.
- **Console** — four surfaces: *Risk classifier* settings, *Risk
  posture* (the CISO view), a **Risk tab** on the vserver drawer, and a
  per-row assess action on the servers table.

### What the operator actually sees

Risk posture: `3/24 assessed · 12.5% coverage`, average 33/100, `20.1
points removed across 2 bundles`, `57.3% average reduction`, then where
the risk is, what curation removed, and an OWASP MCP Top 10 breakdown.
Coverage is as prominent as the averages on purpose — "average risk 33"
over the three servers that happen to have been assessed is a statement
about those three, and presenting it as the estate's posture is the most
likely way this feature misleads.

The vserver Risk tab reads: `MODERATE 43 → MODERATE 28 · removes 15
points (34.9%), eliminating 2 findings`, then **NO LONGER REACHABLE**
(RTR shell, element deletion) against **STILL REACHABLE**, where the
schema-resources finding is labelled *"server-wide — not addressable by
choosing tools"*. That label is the honest part and it is why reductions
come out smaller than operators expect.

### FIRST LIVE RUN — three real defects, one of them mine

Run against claude-sonnet-5 with a real key. **1117 no-DB, 1374 real-DB.**
Three things broke, and each one only shows up against a real model.

**1. `findings` returned as a `str`.** Under a forced tool-use schema
the model intermittently serialises the array as a JSON string — seen on
1 of 5 slices of a CrowdStrike catalogue while the other four returned
proper arrays. The parser now decodes it. This is tolerance about
ENCODING, not content: decoded findings still pass every validation, and
a test asserts an evidence-free finding is still rejected when it
arrives encoded.

**2. Output exhaustion on a large catalogue.** A 141-tool server blew
the output budget mid-generation, and Anthropic returns a PARTIAL tool
input when that happens — valid JSON with `findings` incomplete, which
reads as a schema bug. Raising 8192 → 32000 moved the threshold without
removing it, so the catalogue is now **chunked at 40 tools per call**.
Each slice is told it is a slice (otherwise the model writes "this
server exposes 40 tools" and that becomes the summary), one bad slice
fails the whole run, and confidence is the MINIMUM across slices.

The honest cost: the model sees one slice at a time and can miss a risk
that exists only in the combination of two distant tools.

**3. THE IMPORTANT ONE — reduction was measured on a non-monotonic
metric.** Curating soc-console eliminated 24 findings and the severity
profile went UP, 28.4 → 32.0, because what remained was a smaller,
nastier set. `points_reduced` was computed from that band, so it clamped
to "0.0 points removed" next to two numbers that plainly disagreed.

`Rrms` is not monotonic under removal. `Rexp` is a sum, so it is.
Reduction is now measured on exposure, and the band change is reported
separately as `severity_profile_delta` — which may be POSITIVE and is
surfaced rather than hidden. The same bundle now reads:

    reachable risk removed : 70.9%  (6099 risk points)
    severity profile       : 28.4 -> 32.0  (+3.6)
    findings               : 24 eliminated / 9 retained

Both statements are true: less risk is reachable, and what remains is
more concentrated. The UI explains the rise in place, because an
operator who has just cut 24 findings and watched the band go up will
not trust anything else on the page without that sentence.

I had written the negative-reduction hazard into `reduction.py` as an
argument against using two LLM opinions, and missed that one set of
findings scored by RMS has exactly the same defect. It took real data to
show it.

### What Sonnet actually found

Better than the synthetic data I had been testing with. On CrowdStrike
(190 capabilities, 26 findings, 1m51s) the top risk was **not** RTR
remote shell, which is what I had assumed:

    R=720 [MCP02] AV/behavioral exclusions can silently blind endpoint protection
    R=675 [MCP06] Executing arbitrary SOAR workflows with opaque side effects
    R=576 [MCP02] Suppression rules can silently hide findings from compliance
    R=480 [MCP02] Disabling endpoint protection policies weakens security posture
    R=432 [MCP05] RTR allows arbitrary command_string on live endpoints

The "blind the sensor" class ranked above remote execution, which is
almost certainly right for an EDR bridge and is not a connection I made.
On Postgres it caught the one that matters: *"read-only guarantee
enforced only by natural-language description, not by the schema"*.

### Band now weights the worst finding (scoring v2)

`Rrms` alone is an average, so breadth diluted depth: one critical
finding among twenty trivial ones scored **21.8/100 — moderate**, which
is not how anyone triages. The band is now

    0.5 x (worst finding) + 0.5 x Rrms,  scaled against 1200

`MAX_FINDING_WEIGHT = 0.5`, and `scoring_version` is bumped to `"2"` —
rows written under v1 carry a `normalised` today's thresholds do not
describe.

Chosen on real data, not intuition. The decisive case was a Postgres
bridge exposing unrestricted arbitrary SQL: **42.9 "moderate" on RMS
alone, 61.5 "high"** once its worst finding counted for half. The second
reading is right. 0.5 rather than higher because depth alone is not the
whole story either — one bad tool and one bad tool plus forty mediocre
ones are not the same exposure, and the RMS half keeps that visible.

Verified not to break the other direction: fifty trivial findings still
score 0.2 "low", and a uniform finding set is unchanged because max ==
rms makes the blend a no-op there.

### Optimisation pass — one win, one dead end, and the numbers

**Prompt caching: WORKS.** The system prompt is ~1,800 tokens and
identical for every slice, so a 5-slice server resent it five times. It
is now sent as a block with `cache_control: ephemeral`. Measured on a
real CrowdStrike run: **3,690 tokens cache-read on every slice, 18,450
per assessment**. Usage is logged per call (`risk_model_usage`) because
caching is otherwise invisible — it either works or silently does not,
and the only other signal is the bill.

**temperature=0: NOT AVAILABLE.** The obvious lever for a scoring
system, and the default model refuses it:

    400 `temperature` is deprecated for this model.

Sending it unconditionally broke every Anthropic assessment. It is now
opt-in (`temperature: float | None = None`), never sent to Anthropic,
and passed through for OpenAI/Gemini only when set. A test pins that,
because the failure mode is total.

**Consequence: run-to-run variance on Anthropic cannot be reduced this
way.** The anchored prompt is the only lever that applies and it
narrows rather than removes the spread. If variance matters more later,
the remaining options are N runs with a median factor per finding, or
only reporting a band change that clears a margin.

### Real token cost, measured

CrowdStrike, 190 capabilities, 5 slices:

    slice 1:  input  4,104   output 1,615   cache_read 3,690
    slice 2:  input 22,672   output 2,573   cache_read 3,690
    slice 3:  input 25,931   output 2,653   cache_read 3,690
    slice 4:  input 30,578   output 3,004   cache_read 3,690
    slice 5:  input 21,174   output 2,827   cache_read 3,690
    ---------------------------------------------------------
    ~104k input, ~12.7k output per full assessment

Input is dominated by tool DESCRIPTIONS, not by our prompt.
`MAX_DESCRIPTION_CHARS` is 2,000 and CrowdStrike uses most of it.

Slice 1 being 5x cheaper is the tell: the first 40 capabilities are
`falcon://…/fql-guide` RESOURCES with empty descriptions. Roughly 49 of
CrowdStrike's 190 capabilities carry no description at all, so a whole
call is spent on near-empty input. Not stripped — a resource URI can
itself be a finding, as the Postgres run proved by flagging
`postgres://user@host/db` — but grouping empty-description capabilities
into one slice instead of letting them consume a full one is a cheap
win nobody has taken.

### Optimisations NOT done, ranked by value

1. **Skip re-assessment when nothing changed.** `mcp_servers.last_sync_drift`
   already records whether a sync altered the catalogue. Re-assessing an
   unchanged server is a full-price call for an answer we hold.
2. **Pack empty-description capabilities together** so they do not each
   claim a slice (see above).
3. **Cheap model for routine re-assessment, expensive for first
   contact.** Already configurable per tenant; nothing automates it.
4. **Trim `MAX_DESCRIPTION_CHARS`.** Would cut input materially and
   costs signal — descriptions are the tool-poisoning surface. Measure
   before touching.

### Prompt rewritten with anchored scales (measured, not asserted)

The original prompt named the five factors and left "high" undefined,
so the model recalibrated from scratch on every run. That is the
mechanism behind the variance below.

The prompt now carries, in order: what the input is, **seven risk
classes to work through** (state change, security-control mutation,
execution, data reach, description-as-instruction, constraint claimed
but not enforced, authorisation shape), **five-level anchored
definitions for every rated factor**, per-field output expectations,
a worked example, and the rules. ~1,800 tokens.

Two anchors worth keeping verbatim: `modes_of_introduction` and
`common_consequences` both say "most findings are 1-2" and tell the
model NOT to inflate them to signal severity — they are breadth
multipliers in the paper's formula and an inflated count moves the
score more than the severity rating does.

Measured on ft-postgres, worst-finding risk across runs:

    before (2 runs)  R=960, R=576          spread 384, bands differed
    after  (3 runs)  R=640, R=480, R=640   spread 160, ALL bands agreed

Not solved — one of three runs still came in low (31.5 vs 42.1/43.4).
But every run agreed on `moderate`, and the band is what an operator
reads. Three runs is a small sample; treat the direction as established
and the magnitude as rough.

Five tests guard the prompt's contract, including that every rating
level stays defined. They normalise whitespace first: the prompt is
hard-wrapped for source readability, and a test that broke on reflowing
would get deleted rather than fixed.

### RUN-TO-RUN VARIANCE — read this before trusting a band change

Re-assessing the same three servers with the same model produced
**different factor ratings**. The Postgres arbitrary-SQL finding scored
**R=960 on one run and R=576 on the next** — same server, same prompt,
same `claude-sonnet-5`. CrowdStrike moved 26 findings to 25.

The consequence: a band change between two assessments is **not
reliable evidence that the server changed**. Nothing currently
distinguishes model variance from real drift, and the console presents a
re-assessment as though it were a measurement.

Not addressed. Options if this matters: run N times and take the median
factor per finding, pin temperature if the API exposes it, or only
report a band change when it crosses a threshold by some margin. Until
then, treat a single assessment as one opinion and the history as
noisy.

### Superseded calibration note

CrowdStrike scored **moderate 27.1** on 26 findings including an R=720.
`Rrms` averages, so many mid-tier findings dilute a few severe ones.
Faithful to the paper, and arguably too generous for a band a CISO
reads. Worth deciding whether the band should weight the maximum finding
more heavily before anyone relies on it.

### Superseded — kept for the reasoning

### Not yet exercised against a live model

Every path is proven with `httpx.MockTransport` through the real service
code, and the dev-DB demo data was generated the same way. **No call has
been made to a real Anthropic/OpenAI/Gemini endpoint** — that needs a
key in the secret store. The first real run is the thing to try next,
and the wire formats in `providers.py` are the most likely place to find
a surprise.

### Two guards worth knowing

- `tests/tenant_isolation` keeps a hand-maintained inventory of every
  table; both new ones had to be added by hand. That is the guard
  working — add yours, do not loosen it.
- The classifier is asked for `evidence` on every finding and the parser
  **rejects** a finding without it. It is the cheapest defence against a
  confident invention, and it gives a reviewer something to check.

### The original plan, for reference

The domain core was complete before this; the remaining list was:

1. **Persistence** — `mcp_server_risk_assessments` +
   `virtual_server_risk_assessments` (model used, findings JSONB,
   scores, assessed_at) and a migration.
2. **Tenant config** — selected model id + vendor + API-key *ref*
   (SecretStore, never the key), so the operator can pick a model.
3. **API** — assess-server, assess-vserver, read assessment.
4. **Console** — model picker, per-server risk badge, the
   before-publish view on the vserver drawer, and the CISO summary.

`classifier.py` and `providers.py` are ready to call; nothing has been
wired to a live LLM yet, so no assessment has run against a real model.

## Sub-session update — 2026-08-27b (CRED-1 · API key lifetime policy)

**1094 no-DB, 1344 real-DB, zero failures.** New table, migration
`20260827_0024`, round-tripped both ways.

### The gap this closes

`user_api_keys.expires_at` has existed since the table was created and
is enforced on every inbound call. **Nothing ever set it** — both
issuance paths defaulted it to NULL. So a user key lived until somebody
remembered to revoke it, and a credential nobody has to renew is a
credential nobody reviews. The lab tenant had **17 live keys with no
expiry**, which is the feature's own best argument.

### Resolution: user → group → tenant → unlimited

Three scopes because one tenant-wide number forces the strictest case on
everyone, which in practice means the number gets set loose.

**With several groups the SHORTEST wins, never the longest.** If the
longest won, joining a group would extend your own credential lifetime —
group membership would become a privilege escalation, and an admin
adding someone to `contractors` for one reason would silently be
granting another. Membership can only ever tighten. There is a test that
inverts `min` to `max` and fails with that sentence.

Per-user policy wins in **both** directions, because it is the exception
mechanism: without it a documented carve-out has nowhere to live and the
admin loosens the group instead.

### Enforcement

Both issuance paths (portal self-serve and operator-issued) resolve the
ceiling and stamp `expires_at`. A request **inside** the ceiling is
honoured — a ceiling is a maximum, not a mandate. A request **beyond**
it is refused naming both numbers, matching the JIT convention: silently
clamping hands back a credential that dies earlier than the caller was
told, and they find out when something breaks.

No policy configured resolves to `None`, which is the pre-existing
behaviour — a tenant that has not adopted this keeps working. It reports
as `unlimited` rather than as a number.

### Keys issued before the policy existed

Those carry NULL forever and are exactly what the policy was written to
catch, so a rule that only applies going forward would not make the
tenant true. `find_nonconforming_keys` surfaces them; **applying is a
separate, audited action**, not a side effect of saving a policy —
saving states intent, shortening live credentials is an outage for
whoever holds them, and the operator should choose when that lands. Keys
are shortened to `now + ceiling`, never into the past.

### Two things worth knowing

- `user_group_memberships` has **no `tenant_id` column** — it is scoped
  transitively through `groups`. I assumed it did and wrote a filter
  that could not compile. Resolution joins `Group` for the tenant check.
- `tests/tenant_isolation` has an inventory guard listing every table.
  A new tenant-scoped table fails it until someone adds it by hand. That
  is the guard working; add yours to the set rather than loosening it.

### Portal copy

Same treatment as the console: five ledes of 119–186 chars shortened to
one sentence each with detail in a `title`. The portal was already much
leaner than the console — 5 offenders against 14.

## Sub-session update — 2026-08-27 (operator console: JIT drill-in, copy, tooltips)

Three UI asks, plus two defects the work exposed. **1094 no-DB, 1326
real-DB, still zero failures.** `operator_ui.py` is back to its
pre-existing 11 `E501`s — none of the new lines are long.

### JIT moved out of the table and into the drill-in

The vservers table lost its `JIT ACCESS` column and the two inline
buttons that opened `prompt()` chains. Both now live in a **JIT tab** on
the row drawer, as real form controls.

The old flow was three chained `confirm()`/`prompt()` dialogs plus a
`name=minutes` free-text box, and it was wrong for the task in two ways:
a chain of modal prompts cannot be reviewed before committing — answer
question two and question one is already gone — and it could not show
which tools the bundle actually publishes, so the operator was typing
tool names from memory into a box that only failed after submit. The tab
lists every allowlisted tool with its own minutes field, and the whole
policy is visible at once before Save.

**Gate by the EXPOSED name.** `jit_tools` is matched against
`resolved_tool.exposed_name` at call time, but `/vservers/{id}/tools`
returns upstream names only. Rendering those would have let an operator
gate `query` on a bundle that exposes `warehouse_query` — a gate that
silently matches nothing. The tab applies `rename_map` and shows
`warehouse_query ← query` so the mapping is visible.

**Drawer render race, found while testing this.** Every tab renderer is
async and they all write into one container, so opening the drawer
(which renders Tools) and immediately clicking another tab left the
wrong body with the new tab's buttons appended underneath. Each switch
now takes a ticket and a stale renderer drops its output. Pre-existing,
but the JIT tab's two awaits made it easy to hit.

### Copy moved into tooltips

Fourteen panel ledes ran 150–382 characters. Each is now one short
sentence with the detail in a `title`. Longest remaining is 144.

The tooltips themselves then got trimmed a second time: a 200-character
tooltip is the same wall of text one hover away, and the first pass had
merely relocated it.

### JIT badge kept in the row, read-only

Moving the whole column out went one step too far: "which bundles allow
temporary access?" is a scanning question, and making it cost one
drill-in per row turns a glance into an audit. The column is back as a
**read-only** badge — `auto · ≤2h` / `review · ≤2h` / `off` / `n/a` for
public — with a `N GATED` chip when per-tool elevation is configured.
No buttons: everything is changed in the drill-in.

The chip shows independent of the bundle toggle, because the common case
is standing bundle access with one dangerous tool gated — a row reading
`off` may still have two gated tools, and hiding that would misreport it.

(Watch for `const window = …` in this file — legal, block-scoped, and it
shadows the global. I wrote it in the first draft of this badge.)

### Lab now binds the LAN

`VYUU_LAB_HOST=0.0.0.0` binds every interface. `LAB_HOST` used to drive
both the bind address AND the printed URLs, so a wildcard bind would
have advertised `http://0.0.0.0:8010` — a bind address is not a
reachable one. Added `_advertised_host()`, which resolves the address
this machine presents on its LAN (a `connect()` on a UDP socket, which
sends nothing and just asks the routing table), overridable with
`VYUU_LAB_ADVERTISE_HOST`. Set `VYUU_PUBLIC_BASE_URL` to match so the
copyable `/v/.../mcp` endpoints work from other machines.

**This is lab-only and it is exposed.** The operator token is signed
with `lab-not-for-production`, a secret that is in the source — anyone
who can reach the port can mint an admin token for the tenant, which
includes calling the wired CrowdStrike credentials. Fine on a trusted
home LAN; do not do it anywhere else.

### Register-wizard tooltips — the actual shape bugs

Two real defects, both visible only on screen:

1. **The `i` trigger was a 16×38 capsule, not a circle.** Inside a flex
   row the default `align-items: stretch` overrode the 16px height, and
   with `border-radius: 999px` that rendered a tall orange pill glued to
   the panel edge. Pinned both axes and opted out of the stretch.
2. **The popover pointed at nothing.** Positioning was
   `left = trigger.left - 280` — a fixed shift with no viewport check,
   so for a trigger at the panel's right edge the panel landed to its
   left, unattached, covering the field it was explaining. It now
   centres under the trigger, clamps inside the viewport, flips above
   when there is no room below, and carries an arrow whose offset
   tracks the trigger even after clamping. Width is
   `min(360px, 100vw - 32px)` instead of a hard 360, and it repositions
   on scroll rather than being left stranded.

## Sub-session update — 2026-08-26f (fixes + full re-test + UI walkthrough)

Every issue from the previous functionality run is fixed, plus one more
the browser surfaced. **All four test lines pass with ZERO failures** —
including the real-Postgres RLS tests that had been failing for the whole
project:

| line | result |
|---|---|
| no-DB · mcp 1.27.0 | 1094 passed |
| no-DB · mcp 2.1.1 | 1094 passed |
| real Postgres · mcp 1.27.0 | **1326 passed, 0 failed** |
| real Postgres · mcp 2.1.1 | **1326 passed, 0 failed** |

### The RLS failures were a PG16 semantics change, not a missing grant

Every prior handoff told the next agent to run `ALTER ROLE vyuu
CREATEROLE;`. That advice was wrong — the role already had CREATEROLE and
the `CREATE ROLE` succeeded. **PostgreSQL 16 split role membership into
ADMIN / INHERIT / SET**, and a CREATEROLE user is auto-granted membership
with `admin_option = t` but **`set_option = f`**, so the subsequent `SET
ROLE` was refused. Verified directly against `pg_auth_members` before
changing anything.

Fixed in the fixture with `GRANT "<role>" TO CURRENT_USER WITH SET TRUE`,
guarded on `server_version_num >= 160000` since `WITH SET` is a syntax
error before 16. Delete the CREATEROLE line from your notes.

### Five defects fixed

1. **`vserver_name` NULL on `tool_call_events`.** The audit factory never
   accepted the field, so only `access_attempt` rows had it — an operator
   filtering by the name they know got a silent subset. It cost me a
   wrong conclusion last session before I re-queried by id.
2. **A synced server still read `down`.** The 5 s health probe races the
   first `uvx`/`npx` fetch on a newly registered stdio server and nothing
   re-probes. A completed sync now records health: we opened a session,
   spoke MCP and read the capability list, so discarding that in favour
   of a stale timeout was throwing away better evidence.
3. **`grant_id: null` on a granted elevation.** Root cause was deeper
   than the hardcoded `None` it looked like: `_issue_tool_elevation`
   returned `JitElevation(grant=None)` because a per-tool elevation
   issues a `VirtualServerToolGrant`, a different type from the
   bundle-level `grant` field. Added `tool_grant` and threaded it.
4. **Three statuses rendered as `unknown`.** `NO_TOOL_ELEVATION`,
   `INSUFFICIENT_SCOPE` and `INPUT_REQUIRED_DENIED` were simply absent
   from `_STATUS_TO_ENVELOPE`. Each is something the caller can act on —
   an elevation is self-service, a scope denial is not, an MRTR refusal
   needs an operator — and a category that does not discriminate is the
   same as no category. Note the third: the MRTR refusal shipped in P3
   was itself surfacing as `unknown`. `needs_tool_elevation` is marked
   retryable (same reasoning as `capabilities_not_synced`);
   `upstream_input_refused` deliberately is not.
5. **NEW — the MCP servers TOOLS column could never show a value.** The
   console read `server._tool_count`, which nothing in the codebase ever
   assigned, so every row rendered "—" in every deployment, including a
   server exposing 141 tools. The API did not compute a count at all.
   Added `tool_count` to the servers list response from one grouped
   query (not a per-row fetch, which would be an N+1 across the
   catalog). `None` still means "never synced", which is a different
   statement from "synced and exposes nothing".

Every fix has a regression test, and all five were verified load-bearing
by reverting the fix and watching the specific test fail.

### Verified in the browser, not just by curl

Walked the operator console and the end-user portal:

- **MCP servers** — the three freshly registered servers read `Healthy`
  with tool counts 1 / 11 / 141, while `falcon-crwd-mcp` (registered
  before the fix) still reads `Down`. Both fixes in one frame.
- **Virtual servers** — `soc-console`, 7 tools, 1 grant, `auto · ≤2h`,
  `2 tools` gated.
- **Access requests** — LIVE ELEVATIONS: "2 people have temporary access
  right now", soonest-expiring first, with justifications and TOOL
  badges.
- **Security posture** — all 9 controls including the new inbound-CIMD
  row, `ON · re-checked every 15 min`.
- **Events** — 16 calls / 8 blocked / 2 unsanctioned, with the denials
  naming their exact policy reason and tool-call rows now showing
  `soc-console · <tool>`.
- **Portal** (signed in with local-db email + password) — "Your last 5
  tool calls" populated, Tool history showing 16 / 6 / 6 where all three
  read **0** before the portal fix, and the catalog card offering
  `falcon_delete_quarantined_files · up to 20m · Elevate →`.

The Tool history table shows the `vserver_name` fix as a before/after in
one screen: rows from before the fix show `(vserver)`, rows after show
`soc-console`.

### Note for whoever runs this next

The `LIVE ELEVATIONS` strip lives in the **Access requests** panel, not
Virtual servers — deliberately, per the comment in the markup ("the
queue is about decisions not yet made, this is about authority currently
live"). I went looking for it on the wrong panel and briefly thought it
was broken.

## Sub-session update — 2026-08-26e (end-to-end functionality test)

Drove the gateway against three real upstreams with a real user, and it
found a user-facing bug that 1087 green tests did not.

**Setup.** CrowdStrike Falcon (`falcon-mcp`, pypi, live US-2 tenant, 190
capabilities), Excalidraw (`excalidraw-mcp`, npm, 11 tools), and Postgres
(`@modelcontextprotocol/server-postgres`, npm, against a throwaway
`vyuu_ft_demo` DB — deliberately NOT the gateway's own database, since the
tool is LLM-callable). Identity via **local-db users**, because the
Google Workspace directory has no usable credentials (see below). One
vserver `soc-console` federating all three, `query` renamed to
`warehouse_query`.

### BUG-PORTAL-1 — "my tool calls" was empty for every user, always

`GET /portal/{tenant}/recent-tool-calls` and `/tool-history-summary`
scoped results by looking up the caller's rows in `user_api_keys` and
filtering the audit ring buffer on those **key ids**. But
`ApiKeyIdentityProvider` builds
`ApiKeyPrincipal(id=str(user_id), key_id=str(key_id))` — the principal is
the *human*; the key is only how they authenticated, and the emitted
event does not carry `key_id` at all. The two sets never intersect, so
both endpoints returned empty/zero for every user who had ever made a
call.

**Why it survived.** The endpoint test injected its own synthetic events
using the key id as `principal.id`. It agreed with the endpoint, and
neither agreed with the provider. The failure is also invisible by
construction: the endpoint answers **200 with an empty list**, which is
indistinguishable from a user who has made no calls.

Fixed by scoping to `session.user_id` (which also keeps working across
key rotation — the original intent of "every key the user has ever
held"). The endpoint test now injects the real principal shape and
carries a key-id-shaped event as a negative control, and
`test_recent_tool_calls_principal_matches_the_provider` drives the actual
provider so the two sides cannot drift again. Verified against the
provider by inverting it: the test fails with its own diagnostic.

Live after the fix: 8 calls, 6 distinct tools, 4 blocked, with the other
user's calls correctly excluded.

### What worked, verified against real upstreams

- **Federation.** One `tools/list` returned all three upstreams' tools
  with the rename applied.
- **Allowlist.** `falcon_create_policy` (real, but not published)
  refused as `tool_not_in_virtual_server`, upstream never contacted.
- **Grants.** The un-granted user is refused at `initialize` — no tool
  enumeration, so no information leak.
- **Per-tool JIT (JIT-2).** A tool on the allowlist, held by a user with
  a *permanent* grant, still refused with `no_tool_elevation`. Requesting
  30 min against a 10 min ceiling was rejected naming both numbers.
  After an 8-minute auto-approved elevation the same call succeeded.
- **Argument validation.** A malformed call was rejected as
  `malformed_args` at the gateway, against the upstream's own
  `inputSchema`, before reaching CrowdStrike.
- **Audit.** All 9 calls persisted with principal, decision,
  `policy_rule_id`, both latencies, and `auth_modes.auth_org_tier=true`
  where env-var credentials were injected. `args_summary` records field
  types and sizes but **not values**.

### Two smaller findings, not fixed

- **`vserver_name` is NULL on `tool_call_events`** but populated on
  `access_attempt` rows. Querying the audit table by vserver *name*
  silently returns partial results — it cost me a wrong conclusion
  mid-session before I re-queried by id.
- **First registration of a pypi/npm stdio server reliably shows
  `down`.** The automatic probe uses `upstream_health_timeout_seconds`
  (5 s) and races the first `uvx`/`npx` package fetch; nothing re-probes,
  so a server that then syncs 190 capabilities still reads `down` until
  an operator clicks. `POST /{id}/health/check` returns `healthy`
  immediately once the package is cached. Note `GET /{id}/health` reads
  the stored snapshot — only the POST re-probes.

### Google Workspace IdP — configured, not usable

`idp_directories` holds a `google_workspace` row (`Skandasec.com`, SAML,
polling enabled, `customer_id=my_customer`) but its
`workspace_service_account_ref` points at a placeholder and no
service-account JSON exists anywhere on this machine. The poller says so
on every boot: *"workspace service-account JSON is malformed or missing
private_key / client_email"*. To make it real, put a domain-wide-
delegation service-account JSON in the secret store under that ref.
Until then, identity for testing is local-db users.

## Sub-session update — 2026-08-26d (MCP-2 P3 finished)

The two items P3 had left: consuming an inbound client's CIMD, and making
the call site actually use the CIMD plan. Both landed. **1087 tests on
both SDK lines (mcp 1.27.0 and 2.1.1); 1308 real-DB** — the 4 real-DB
failures remain the standing `ALTER ROLE vyuu CREATEROLE;` gap.

### The failure mode that shaped the outbound wiring

Offering our document URL to `discover_and_register` is the easy part —
the decision happens where the AS metadata is already in hand, so there
is one discovery implementation rather than a competing second probe.

The part worth reading is what `invalid_client` had to be taught. It
means **opposite things per mechanism**: for DCR the registration was
evicted, so dropping the row and re-registering fixes it; for CIMD
nothing was ever registered, so dropping the row would re-probe, read the
same unchanged advertisement, present the same refused URL and fail
identically — forever. That is a permanent Connect failure assembled from
two individually-correct behaviours, and it would have shipped invisibly
because each half looks right on its own.

So a refused CIMD row is **marked `cimd_rejected`, not deleted**. The
tombstone is what makes the fall-back to DCR that `oauth_cimd.py` already
documented actually happen. `tests/api/test_cimd_outbound_wiring.py`
asserts it, with the working-CIMD-row case as the negative control (that
row must *not* be deleted, or every Connect re-runs discovery).

Migration `20260826_0023`: `auth_mechanism` plus a nullable
`registration_endpoint`, since a CIMD row records no registration and a
placeholder in that column would read as a fact. Round-tripped both ways
against the test DB.

### The inbound half, and why it is allowed to exist

`identity/cimd_inbound.py` fetches a URL that arrives in a request. That
needs a better justification than "the spec has it", and the honest one
is **revocation**: CIMD's revocation story is "stop serving the
document", so a gateway that never fetches can never observe it — an
allowlisted client stays valid forever, including after its own operator
has decommissioned it. Second, `client_name` in the audit trail instead
of an opaque URL.

Four bounds, all load-bearing:

1. **Only allowlisted client_ids are ever fetched.** Membership is
   checked *first*. The `allowlist and …` term in `ema_oauth.py` is the
   same guarantee restated — an empty allowlist means nothing vouched for
   the URL, so nothing is fetched. Drop that term and an unauthenticated
   caller can point the gateway anywhere.
2. **Every fetch goes through `ssrf_guard.py`.** The resolver takes a
   *transport*, not a client, specifically so no caller — tests included
   — can opt out of it. The loopback test proves the guard fires before
   the mock transport is reached.
3. **Redirects refused**, since following one moves the fetch to a host
   nobody allowlisted and breaks self-identification.
4. **Positive and negative caching**, with a shorter negative TTL: a
   resolved document is a stable fact, a failure is usually a blip
   someone is already fixing.

Body reading is **streamed against the cap**, not buffered then measured
— checking after the read lets a hostile document cost us its full length
regardless of the limit.

**It fails closed, inverting the outbound rule on purpose.** Outbound,
CIMD and DCR grant identical authority, so falling back costs nothing.
Inbound, the document is how we learn who the caller *is*, and no second
mechanism establishes that fact; treating "the fetch failed" as "identity
confirmed" would make the check worse than not having it. Both docstrings
now cross-reference the other so the asymmetry does not read as an
inconsistency.

Off by default. Surfaced in the Security posture panel as **`info` when
off, not `warn`** — string matching is the behaviour the gateway has
always had and it is not unsafe, only blind to revocation, and enabling
resolution makes a third party's uptime part of this auth path. That is a
trade to make deliberately, not to be nagged into.

### Verified live

Ran the lab against `vyuu_gateway_dev` at head and drove the posture
endpoint with the flag off and on: `info` / "matched as strings only" →
`good` / "stops being accepted within 10 minutes", with the configured
TTL flowing into the sentence. The lab also demonstrated the https gate
working by accident — its `public_base_url` is http, so
`_cimd_client_id_for` returns None and that deployment would never offer
a document to an AS.

**One trap re-confirmed:** the first lab start used a bare `python3` and
therefore ran the *other* team's `vyuu_gateway` from
`<sibling handoff folder>/src`, which has no
security-posture router — the symptom was a puzzling 404 on a route that
demonstrably exists. Always
`PYTHONPATH=<repository root>/src` for anything
outside pytest.

## Sub-session update — 2026-08-26c (surfacing the new features in the UI)

The ask was to open the features we had built onto the UI and **watch them
behave**. That second half is the part that paid: driving the live console
found two defects that 1055 green tests did not.

**1055 tests (no-DB, both SDK lines) · 1270 real-DB.** The 4 real-DB failures
are the standing `ALTER ROLE vyuu CREATEROLE;` gap in
`tests/integration/test_rls_real_postgres.py` — the role cannot `SET ROLE` to
a non-`BYPASSRLS` test role — not a regression.

### New panel — Security posture

`src/vyuu_gateway/api/security_posture.py` + a `security-posture` nav item.
Eight controls, each reporting **the consequence of its current state** rather
than a bare on/off:

> Per-user refresh tokens are stored in PLAINTEXT. A database dump, backup or
> read replica exposes every user's connected SaaS accounts, and nothing
> rotates because nobody can tell.

The reasoning, from the module docstring: *a security control nobody can see is
a control nobody can verify, and several of these default off deliberately —
which is only defensible if turning them on is discoverable.* Each row carries
the env vars that change it, so the panel is actionable and not just a report.

Rows sort **warn → info → good**, so the thing that needs attention is at the
top. Note the MRTR severity: deny-all is `good` (it is the safe state) and the
warn is `elicit_url` allowed with no host allow-list — the phishing-shaped one.
The `cimd_client_id` strip only renders when `public_base_url` is https, since
a client_id that is an http URL is not one anybody should copy.

`tests/api/test_security_posture.py` (17 tests). The load-bearing one asserts
the consequence text **differs between states** — a consequence identical in
both states is decoration, not information.

### Two defects the live UI found

- **`jit_tools` was missing from both vserver response schemas**, so the
  console's gated-tool count silently read zero and every row's button said
  `Tools` instead of `1 tool`. Added to `VirtualServerResponse` *and*
  `VirtualServerListItemResponse`, populated in the list builder, and set
  explicitly in `create_virtual_server` — the same transient-ORM-instance trap
  already documented there for `visibility` (a column `default=` fires at
  INSERT, so a hand-built instance reads `None`).
- **`PATCH /idp/directories/{id}/workspace-polling` returned HTTP 500.**
  `_to_response()` takes a `Request` the handler never passed, so it raised
  `TypeError` **after** committing: the change applied and the operator saw a
  failure. Service-layer tests could not catch it — the fault was in FastAPI
  dependency wiring, not in the service. `tests/idp/test_workspace_polling_api.py`
  now drives the real route (6 tests, incl. both audit directions).

### IdP column made kind-aware

`LAST SCIM` became `PROVISIONING`, because it read `SCIM · never` for Google
Workspace directories that have no SCIM by design — an alarming-looking cell
describing correct behaviour. It now reads `polling · <when>` / `polling ·
pending` / `manual` for Workspace and keeps SCIM wording elsewhere.

### Verified live, not just asserted

Ran the lab against `vyuu_gateway_dev` at head and exercised each surface in
the browser: posture panel flipping `good → warn` when MRTR config changed;
the vservers JIT column (`auto · ≤2h`, `1 tool`, `n/a · public` with no
buttons); the LIVE ELEVATIONS strip (`2 people have temporary access right
now`, soonest-expiring first); the portal `Temporary · 26m left` pill and
`TOOLS NEEDING TEMPORARY ELEVATION` row; over-ceiling rejection copy; and the
Workspace PROVISIONING cell. The Admin audit panel showed every new action
attributed correctly — `jit_auto_approve` as `system`, operator actions as
`operator`.

### One thing to know before you run ruff

`ruff check .` reports 56 errors and `format --check` wants 168 files, but the
repo is at its historical baseline: the installed ruff is **0.15.12** against a
pyproject floor of `>=0.7.0`, and the newer default rules flag pre-existing
code (e.g. `N806` in `tests/scim/test_scim_server.py`, untouched here). Every
file touched this session is clean except 11 `E501`s in `operator_ui.py`, all
on **pre-existing** lines inside the embedded JS. I left them: line-wrapping
inside `_JS` is exactly where the escaping trap lives (hit three times this
session), and fixing 11 of 56 restores no gate.

## Sub-session update — 2026-08-26b (everything except H3)

Eight items. **1038 tests on both MCP SDK lines; 1247 real-DB.** Ruff at the pre-session baseline.

### MCP-2 P3 — finished except the inbound CIMD half

- **MRTR wired into the tool-call path.** The gate sits where the upstream response returns, so a refusal is a `tool_call` event carrying the kinds and the destination URL. `_upstream_failure_result` gained a decision override: a timeout is an ALLOW that failed upstream, but this is the *gateway* refusing, and an operator filtering Events for denials has to see it.
- **RFC 9207** — expected issuer signed into the OAuth `state` at initiate, checked **before** the code is exchanged. Both entry points carry it; one without would silently lose mix-up protection while the other had it. A *missing* `iss` is accepted deliberately (most static providers never send one; rejecting breaks them all and stops no attacker).
- **DCR `application_type: "web"`** — not just the default: some AS relax redirect_uri rules for `native` clients, so an inferred `native` weakens the check protecting our callback.
- **CIMD** — document at `/.well-known/oauth-client`, mounted at the ROOT because the URL *is* the client_id. Falls back to DCR rather than closed, because both paths grant identical authority.

**Still open in P3:** consuming *someone else's* CIMD (a server-side fetch of an attacker-supplied URL — must go through `ssrf_guard.py`; deliberately not started rather than started carelessly), and wiring the CIMD plan into `_resolve_client_id_and_auth_url`.

### Security work that needed no customer to ask

- **AWS-KMS-1** — `OAuthUserToken` stored refresh tokens **in plaintext**, by documented decision. Envelope encryption now seals them, with AAD binding each value to its row so a ciphertext copied between rows fails authentication. Self-describing values mean **no migration and no flag day** — plaintext rows keep working and seal on next write.
- **P2** — recategorised out of "Performance": a rotated `auth_headers` secret only took effect when a connection happened to drop, so rotating a *leaked* credential left it live for hours. Pool now retires clients by age (from BUILD, not release — else a busy connection stays "fresh" forever).
- **S1.b** — Sigstore verification for `binary` upstreams, on every client build. A missing `cosign` is a hard failure, not a skip.

### Two items decided by measurement rather than left pending

`tests/perf/client_reuse_benchmark.py` exists because P1/P3 both recorded "hold off until measurement shows it matters". Result: reuse saves **~0.43 ms/call, 50%**, on loopback (a floor — real TLS to a remote AS is more).

- **P3 → not doing.** Token refreshes happen once per token lifetime, so the saving is unmeasurable in production, and a long-lived client needs an `aclose()` nothing currently calls.
- **P1 → unblocked, deployment-dependent.** Passthrough is per-call, so the arithmetic differs. Run the benchmark against a representative upstream; under ~10 calls/s per upstream, don't.

### Two backlog corrections

- **S9** is `parked`, duplicated as `Parked-3`. It reads as open in any "not shipped" filter — same misclassification as the IDP-1/A4/H3 entries fixed earlier. Not built: its own unpark condition is "a customer names it".
- **Operator UI open items** — every entry was already shipped inline. Retitled.

### Negative controls: 30 run, three caught vacuous tests

Worth knowing, because all three looked fine:

1. **JIT-2 cap test** — 20/10 cap/batch passes even with the cap broken (20 is a multiple of 10). Now 17/10.
2. **Envelope "fresh key and nonce"** — compared whole envelope strings, which differ anyway because the wrapped-key segment randomises on its own. Passed with a hard-coded data key *and* nonce. Now compares the nonce and ciphertext segments.
3. **Keycloak "token from another realm"** — passed with issuer checking disabled, because `JwksCache` derives the JWKS URL from `issuer_url`, so a wrong issuer dies at *key lookup* and never reaches the claim check. Replaced with a tampered-signature test and a wrong-audience test.

Also: the k8s TLS test and the MRTR UNKNOWN-guard test both passed against a broken implementation until rewritten.

### Keycloak: run it before trusting the docstring

A3-β.x was run against a real Keycloak 26. Three things a written-but-unrun docstring would have got wrong: `KEYCLOAK_ADMIN` → `KC_BOOTSTRAP_ADMIN_USERNAME`; the master realm's `sslRequired=external` 403s every plain-HTTP admin call from inside Docker; and the default user profile requires first/last name, without which every grant fails `invalid_grant` with a message that mentions neither. Commands are in the module docstring. Container was torn down.

### Pickup hooks

- **MCP-2 P3's inbound CIMD half** — needs the SSRF guard; the interesting one left.
- **H3's PII-class redaction** — excluded by request; still blocked on the policy provider modelling redaction rules.
- **P1** — measure, then decide.
- The 4 real-DB failures still want `ALTER ROLE vyuu CREATEROLE;`.

## Sub-session update — 2026-08-26 (JIT-2 · IDP-3 · MCP-2 P2 — the SDK v2 migration)

Three tracks, all shipped. **The suite now passes on MCP SDK v1.27.0 AND v2.1.1 — 897 tests, identical on both.**

### MCP-2 P2 — much smaller than feared, and much sharper

`ClientSession`, `streamable_http_client`, `sse_client` and `stdio_client` all survive v2. The real breaks are nine mechanical renames, absorbed by `src/vyuu_gateway/mcp/sdk_compat.py` — the single place that knows which SDK is installed. It is scaffolding: when the pin moves to `mcp>=2`, every branch in it collapses.

**Two silent production bugs the migration exposed. These are the reason the exercise was worth doing:**

1. **`model_dump()` stopped producing the wire format.** v2 snake_cased the Python attributes but *kept* the camelCase wire aliases. A bare `model_dump()` — correct on v1, where field names already were wire names — emits `is_error` and `input_schema` on v2. Nothing errors. The gateway returns 200, the JSON looks plausible, and every MCP client silently stops seeing the fields. Fixed by routing every wire boundary through `dump_wire()` (`by_alias=True`, a verified no-op on v1). **If you add a wire boundary, use `dump_wire`, never bare `model_dump`.**
2. **The legacy `initialize` advertised the *stateless* protocol version.** The handler echoed the SDK's `LATEST_PROTOCOL_VERSION` — which means "newest this SDK knows", not "the version this handshake implements". Under v2 that constant is `2026-07-28`, the stateless revision that has *no* `initialize`. So a stateful handshake was claiming to speak the stateless protocol; v2's own client rejects it, correctly. Now pinned as our own `LEGACY_PROTOCOL_VERSION`. Serving a protocol version is a commitment we make; it must not move because a dependency shipped a release.

**Still pinned to `mcp<2`,** and the reason is written into `pyproject.toml`: the proof is our suite plus *fake* upstreams. Interop with the real servers this gateway fronts (Copilot MCP, Falcon, drawio) has only been exercised on v1. Flip after a lab run against v2 — one line, plus adding `httpx2`.

**Reproducing the v2 run** (the venv is in the session scratchpad and will not survive):

```bash
python3 -m venv /tmp/mcp2venv && /tmp/mcp2venv/bin/pip install "mcp==2.1.1" httpx2 \
  pytest fastapi "sqlalchemy>=2" psycopg "pydantic[email]" pydantic-settings pyjwt \
  jsonschema bcrypt httpx starlette python-multipart pysaml2 redis boto3 hvac alembic
PYTHONPATH=src /tmp/mcp2venv/bin/python -m pytest tests
```

### JIT-2 — per-tool elevation

The open question is settled: **an elevation requires existing vserver access.** It narrows, never grants — two paths to one resource is how authorization systems become unauditable.

Own table (`virtual_server_tool_grants`), not a nullable column on `virtual_server_grants`: that table is read as "may this principal reach this vserver" by four different consumers, and adding a tool column would change the meaning of every existing row for every query that forgot to filter on it.

`jit_tools` is **independent of `jit_enabled`** — the primary case is standing bundle access with one dangerous tool gated, on a vserver whose whole-bundle JIT is off.

Watch out: `access_requests`'s partial-unique index is now `(user_id, vserver_id, COALESCE(exposed_tool_name, ''))`. The `COALESCE` is load-bearing — NULLs compare *distinct* in a Postgres unique index, so without it two whole-vserver pending requests for the same pair would both be allowed.

### IDP-3 — subdomain-per-tenant

The design deviates from the backlog sketch on purpose. That sketch wanted a `Host` dispatcher in `main.py`; it is unnecessary, because every route is already `/{tenant_id}/…` and the session token carries the tenant after login. Extending `GET /api/v1/auth/default-tenant` was enough, and **both login pages already consume it** — so subdomain routing landed with no change to either page.

**The property to protect:** `Host` is client-supplied, so resolving a tenant from it grants nothing. `test_host_resolution_grants_nothing` pins that. If it ever fails, this feature has become tenant confusion.

### Validation

- **no-DB: 897 passed / 0 failed, on BOTH SDK versions.**
- **real-DB: 1106 passed, 4 failed** — still only the `CREATEROLE` environment issue (`ALTER ROLE vyuu CREATEROLE;`, not run here).
- Migrations `20260825_0020` (JIT-2) and `20260825_0021` (IDP-3), both downgrade-round-tripped.
- 12 negative controls across the three tracks; all fail correctly.
- Ruff back to the pre-session baseline. The automated test sweep did leave debris — stale `FastMCP` annotations (F821) and misplaced imports — which ruff caught and I cleaned; worth knowing if you run a similar regex sweep.

### One trap worth carrying forward

`operator_ui.py`'s `_JS` is a plain `"""` string; `portal_ui.py`'s is `r"""`. So a JS escape must be written `\\n` in the operator file and `\n` in the portal file. Getting it wrong inside a template literal is harmless (a real newline is legal there) but inside a double-quoted JS string it is a syntax error — which `tests/test_operator_ui_js_syntax.py` caught, exactly the bug class its docstring says it exists for.

### Pickup hooks

- **MCP-2 P3** — MRTR `InputRequiredResult` as a policy surface, RFC 9207 `iss`, DCR `application_type`, CIMD.
- **IDP-2** — Google Workspace polling adapter (designed, not started).
- **H3's second half** — PII-class response redaction; blocked on the policy provider modelling redaction rules.
- Smaller: A6.y (Kubernetes secrets), AWS KMS, S1.b, S9, P1–P3, the Operator UI list.

## Sub-session update — 2026-08-25e (JIT-1 shipped · BUG-SCIM-1 fixed · H1 shipped)

### JIT-1 — just-in-time (time-boxed) vserver access

Private vservers can now offer temporary elevation instead of standing grants. Migration `20260825_0018`; service in `registry/jit_service.py`; endpoints on both the operator and portal surfaces; both UIs wired.

**The enforcement path needed no change, and that is the interesting part.** `virtual_servers/access.py` already skipped grants past `expires_at`, and `_authenticate_and_authorize` re-runs that check on *every* inbound request rather than once per session — so an elevation that lapses mid-session cuts off at the caller's next tool call. No sweeper, no session invalidation, no revocation broadcast. JIT only adds the policy for *how long* and *on whose say-so*. The load-bearing test (`test_expired_jit_grant_stops_granting_access`) drives the real enforcement function rather than asserting on a column, because "the row has an expiry" and "access actually ended" are different claims.

Decisions to carry forward:

- **`virtual_server_grants.granted_by` is now NULLABLE.** An auto-approved elevation has no operator behind it; a sentinel operator row would put a human's name on a decision they did not make. `granted_via` (`operator` / `jit_auto` / `jit_approved`) carries provenance so NULL is never ambiguous. If you touch grant-creation code, set `granted_via` explicitly.
- **Over-ceiling requests are rejected, not clamped**, and an approver may grant *less* than was asked for but never more. Silently shortening a window means a user plans around access they do not have.
- **JIT cannot be enabled on a public vserver** — nothing to elevate into.
- **New vservers set the JIT fields explicitly in `create_virtual_server`**, following the existing `visibility` comment there: column defaults fire at INSERT, so a transient instance reads `None` and the response schema rejects it. This bit me once (5 test failures) — if you add a NOT NULL column that appears on a response schema, set it at the creation site.

### BUG-SCIM-1 — SCIM was broken in production, not in the tests

The two long-standing `tests/scim/test_scim_server.py` failures were **real**. `authenticate_scim` resolves `idp_directories` by id before the tenant is known, but the table is FORCE-RLS, so the untenanted SELECT matched zero rows and every SCIM request 401'd — including with a bearer the gateway had just minted. The heartbeat UPDATE in the same transaction was silently updating zero rows too.

Fixed with migration `20260825_0019`: a PERMISSIVE **SELECT-only** policy that opens the read only when `app.scim_bootstrap = 'on'` *and* no tenant is bound. `is_local => true` scopes that capability to one transaction; the dependency then `rollback()`s before `bind_tenant_context`, which is also what repairs the heartbeat (the `after_begin` listener only fires on the *next* transaction).

**My original recommendation in BACKLOG.md was wrong** and is worth knowing: a `SECURITY DEFINER` function does *not* solve this. FORCE RLS subjects the table **owner** to its own policies, and such a function runs as the owner. Only a `BYPASSRLS` role escapes.

### H1 — DNS-time SSRF backstop

`upstream/ssrf_guard.py`. Registration checks IP *literals*; nothing checked where a *name* pointed at call time, so `mcp.evil.test` → `169.254.169.254` sailed through. The guard resolves, validates **every** returned address, and **pins** the connection to the one it checked — validate-then-reresolve is a TOCTOU race that DNS rebinding is designed to win. `Host` + `sni_hostname` keep TLS certificate validation on the registered name.

**Default ON.** Different call from the retention default: the failure mode is a visible, reversible connection error that names its own remedy, not silent data loss. Verified against the real resolver — the lab's `mcp.draw.io` still connects (pinned to IPv6), `localhost` is blocked, and `VYUU_HTTP_URL_ALLOW_PRIVATE_NETWORKS=true` restores an internal target. If someone reports an internal upstream breaking after upgrade, that is this, and the error text tells them what to set.

### Validation

- **no-DB: 852 passed, 0 failed.**
- **real-DB: 1042 passed, 4 failed** — down from 8 at the start of the day. All four remaining are one environment cause: `tests/integration/test_rls_real_postgres.py` needs to `SET ROLE` to a throwaway role, and the local `vyuu` role lacks `CREATEROLE`. Fix with `ALTER ROLE vyuu CREATEROLE;` as a superuser — **not run here**, since it changes privileges on a database that is not ours to re-grant.
- 48 new tests across the day (11 retention, 21 JIT, 2 SCIM guards, 21 SSRF minus overlap).
- **Seven negative controls run across the day, and two of them caught vacuous tests** — a JIT cap test that passed with the cap broken (20/10 is a multiple; now 17/10), and a SCIM rollback whose removal nothing detected until the heartbeat test was added. Assume a new test is vacuous until a control says otherwise.
- Ruff: no new findings beyond 2 × `N806` that match the surrounding file's own `Session = ...` convention.

### Backlog reconciliation

"Complete the backlog per documentation" turned up three entries that
described work already done. Anyone picking them up would have rebuilt
working code:

| Entry | Was | Actually |
|---|---|---|
| **IDP-1** | "IN PROGRESS 2026-05-04" | All 5 sub-phases shipped. (Sub-phase 2, SCIM, was *silently broken* by FORCE RLS the whole time — see BUG-SCIM-1.) |
| **A4** · 401-driven token refresh | `pending` | Shipped. `_looks_like_unauthorized()` in `mcp/outbound.py`; 8 passing tests in `tests/upstream/test_oauth_401_refresh.py`. |
| **H3** · Payload limits + redaction | `pending` | Limits + secret-*shape* redaction shipped (`api/payload_limits.py`, wired at `inbound_mcp.py:786`). PII-class redaction genuinely open, and blocked on the policy provider modelling redaction rules. |

Each entry now records what shipped, what remains, and how it was
verified. Spot-checked the rest against the tree — A6.y (Kubernetes
secrets) is a docstring mention only, P3 still builds a fresh
`httpx.AsyncClient` per refresh, and S1.b/S9/Keycloak have no code. Those
are genuinely open.

### Pickup hooks

- **JIT-2** — per-tool elevation. Designed in `BACKLOG.md` with the open question (does a tool elevation imply vserver access?) called out; settle that first.
- **MCP-2 P2** (SDK v2; `httpx`→`httpx2` in `mcp/outbound.py`), **P3** (MRTR, RFC 9207 `iss`, CIMD).
- **IDP-3** subdomain routing.
- Retention defaults: decide whether the SaaS build ships opinionated non-zero windows.

## Sub-session update — 2026-08-25d (RETENTION-1 shipped · diagnostic-bundle fixtures fixed · a real SCIM bug found)

Cleanup pass: close the last compliance gap and get the no-DB suite green. Both done. A third thing fell out of it that matters more than either.

### RETENTION-1 — durable-audit retention prune

New `audit/retention.py`: `RetentionSweeper` (daily async worker, same `start()`/`stop()`/`run_one_cycle()` shape as `HardDeleteSweeper`) over a synchronous `prune_once()` core, covering `tool_call_events` and `admin_audit_log`. Wired in `main.py` lifespan; reported in the diagnostic bundle under `background_workers.audit_retention_sweeper` (bundle version → 1.2).

Three decisions worth carrying forward:

- **Default is keep-forever (`0`), not 90 days.** This ships the *mechanism*, not the *policy* — the window is a legal decision and the delete is irreversible, so upgrading the gateway must never silently destroy audit history. The honest consequence: a deployment that never sets `VYUU_TOOL_CALL_EVENT_RETENTION_DAYS` still grows without limit. That is now an explicit documented choice rather than a missing capability. If a customer wants opinionated defaults, flip the two config defaults — nothing else changes.
- **`create_app` refuses to boot when `VYUU_ADMIN_AUDIT_RETENTION_DAYS < VYUU_TOOL_CALL_EVENT_RETENTION_DAYS`.** The admin log holds the `retention.prune` rows explaining the event table's gaps; pruning it first deletes the explanation while the gap is still visible.
- **The audit row is written *after* the deletes** — a deliberate exception to the same-transaction rule in `audit/admin_audit.py`, because a chunked prune has no single transaction to share. Failure logs at ERROR with full detail so it is reconstructible. Rationale is in the module docstring; don't "fix" it back into one transaction without reading that.

Per-tenant + RLS-bound because both tables are FORCE RLS — an unscoped `DELETE` matches zero rows (the same trap that made `tool_call_events` look empty during the lab DB migration). Deletes are chunked (5,000) and capped (200,000/table/tenant/cycle) so a first prune drains over several cycles instead of holding one huge transaction against the live audit write path.

### Diagnostic-bundle fixtures — the 7 failures are gone

Root cause was not only the missing `_Result.scalar()`. `_FakeDb` answered `execute()` calls **by arrival order** from a 4-item script, so any new section querying ahead of `servers`/`vservers` silently fed them another section's rows *while the assertions kept passing*. Replaced with dispatch on the compiled SQL's target table; unscripted tables read as empty. Also swapped the hard-coded `"1.0"` bundle-version literal for the `_BUNDLE_VERSION` constant (it had drifted to `1.1`, and my own bump to `1.2` in this same session would have broken it again), and made the top-level key list exhaustive so a section that stops being emitted is actually caught.

### Found while verifying: BUG-SCIM-1 — SCIM auth is broken, not the tests

The two `tests/scim/test_scim_server.py` failures have been carried as "SCIM auth setup" environment noise. They are not. `authenticate_scim` (`scim/auth.py:81`) resolves the directory through an **untenanted** session, but `idp_directories` is FORCE RLS — so the read returns zero rows, the dependency reads that as "unknown directory", and **every SCIM request 401s**, including with a bearer the gateway just minted. Reproduced directly against Postgres (`WITH GUC -> 1`, `WITHOUT GUC -> 0`).

Blast radius: SCIM provisioning/deprovisioning is dead for any deployment whose DB role is not superuser or `BYPASSRLS` — which is the posture `SECURITY.md` recommends. **Not fixed here** (out of scope for this pass, and the fix is a real design choice). Filed as `BUG-SCIM-1` in `BACKLOG.md` with three options and a recommendation (`SECURITY DEFINER` lookup returning only `(tenant_id, scim_token_hash)`).

Also fixed, same disease: `tests/audit/test_admin_audit.py` never bound the RLS GUC, so its 2 failures were self-inflicted. Note the trap — the rollback test asserts `persisted is None`, which an unbound SELECT satisfies *vacuously*; both the write **and** the verify sessions needed binding. Confirmed non-vacuous by flipping `rollback()` to `commit()` and watching it fail.

### Validation

- **no-DB: 831 passed, 0 failed** — the suite is fully green for the first time in several sessions (was 820 + 7 failures).
- **real-DB (`vyuu_gateway_os_test`): 996 passed, 6 failed** — down from 8. The remaining 6 are two distinct causes: 4 × `test_rls_real_postgres` fail on `permission denied to set role "vyuu_rls_test_*"` (the local `vyuu` role lacks `CREATEROLE` — genuinely environment, fix with `ALTER ROLE vyuu CREATEROLE;`), and 2 × SCIM which are **BUG-SCIM-1 above, not environment**.
- 11 new retention tests. Three negative controls run and all three fail correctly: dropping the tenant binding, removing the cycle cap, ignoring the cutoff. The cap test was **rewritten after the control caught it passing vacuously** — a 20/10 cap/batch pair passes even with the cap broken, because 20 is a multiple of 10; it now uses 17/10 so the final chunk must be short.
- Ruff: zero new findings repo-wide (baseline 63 → 62; the one I introduced, an `I001` in `main.py`, is fixed). Pre-existing `E501`/`N806`/`N815` left alone.

### Trap for the next agent: bare `python3` imports the WRONG repo

`pip` has `vyuu_gateway` installed **editable, pointing at
`<sibling handoff folder>/src`** (the other team's repo).
So from inside `securegateway`:

```
python3 -c "import vyuu_gateway; print(vyuu_gateway.__file__)"
# -> <sibling handoff folder>/src/vyuu_gateway/__init__.py
```

Any ad-hoc script, `python -c`, or REPL check silently exercises **their**
code, not ours. It cost a confusing debugging detour this session (a
wiring check reported the retention sweeper "missing" when it was
present — the script was reading a tree that has no such module).

`pytest` is unaffected: `pyproject.toml` sets `pythonpath = ["src"]`,
which prepends `securegateway/src` — verified explicitly by asserting on
`vyuu_gateway.__file__` from inside a test. **All suite results in this
handoff are against `securegateway/src`.**

For anything outside pytest, set it yourself:

```bash
PYTHONPATH=<repository root>/src python3 ...
```

Related: a bare run also binds `SessionLocal` to the **default** DB
(`vyuu_gateway` — the other team's, at their head `20260811_0018`), which
lacks our `virtual_servers.required_scopes`. Set
`VYUU_DATABASE_URL=...vyuu_gateway_os_test` (our head, `20260825_0017`)
for any manual run.

### Pickup hooks

- **BUG-SCIM-1** — highest-value open item now; SCIM is a shipped feature that does not work.
- **MCP-2 P2** (SDK v2 migration; `httpx`→`httpx2` in `mcp/outbound.py`), **P3** (MRTR as a policy surface; RFC 9207 `iss`; CIMD).
- **IDP-3** subdomain routing.
- Retention defaults: decide whether to ship opinionated non-zero defaults for the SaaS build.

## Sub-session update — 2026-08-25c (EMA-1 P3 — scope gating, operator toggle, NHI attestation, portal notice)

Completes EMA-1. P1/P2 made the gateway an EMA Resource + Resource Authorization Server; P3 makes the governance *usable* and adds the narrowing that EMA's own scopes imply.

### Scope gating (the substantive half)

Migration `20260825_0017` adds `virtual_servers.required_scopes` — JSONB `exposed_tool_name -> scope`, deliberately symmetric with `rename_map` on the same row.

*Why not a `virtual_server_tools` column:* the resolver's tool query is a three-way join whose row shape is hard-coded in several test fakes, and the map is needed exactly where the `VirtualServer` row is already loaded. `ResolvedToolsList` carries it out of `resolve_tools`, so **no join change and no fake breakage**. Keying on the EXPOSED (post-rename) name matches what the caller actually asks for, which is what the lifecycle compares.

The gate sits after tool resolution and before policy — so a denial is a **`tool_call` event naming the tool** (visible in the Events panel with `policy_rule_id=insufficient_scope`), not an opaque connection-level 401. New `PolicyDenyReason.INSUFFICIENT_SCOPE` + `ToolCallStatus.INSUFFICIENT_SCOPE`. `FederatedUserPrincipal.scopes` is parsed from the token's space-delimited `scope` (RFC 6749 §3.3).

**Decision — fails closed.** A principal carrying no scopes (an API key; scopes are an EMA concept) is denied on a scope-gated tool: it cannot demonstrate the required authority. `required_scopes` is empty by default so nothing existing changes; opting a tool in is a deliberate act. Flip to "narrow only principals that carry scopes" if a customer needs service keys to bypass — one condition in `lifecycle.py`.

### Operator control

`PATCH /api/v1/idp/directories/{id}/ema` — enable/disable per directory + client allowlist, audited as `idp.ema_enable` / `idp.ema_disable` with `revokes_outstanding_tokens` in the detail. Guards: EMA cannot be enabled on a directory with no `oidc_issuer` (nothing to anchor ID-JAG validation against), and the **audience defaults to the canonical per-tenant issuer** our own RFC 9728 metadata advertises — making the operator retype it would only invite a mismatch, though an explicit value still wins. Operator console gains an **AGENT AUTH (EMA)** column with an inline toggle whose confirm text states the blast radius.

### Observability + portal

- NHI map's AI-app column now prefers the IdP-**attested** `client_id` over the self-declared `user_agent` (carried on `client_metadata`, so no migration). An attested client is sanctioned by definition — the IdP's policy gate vetted it at token-exchange.
- Portal API-keys page reveals an "your organisation uses SSO for AI tools" notice when any connected directory is EMA-enabled, driven off the existing public per-tenant directory list.

### Validation

- 13 new tests (5 scope-gate no-DB + 8 real-DB EMA incl. 2 new P3 endpoint tests). Suites: **820 passed** no-DB, **976 passed** real-DB; same 15 pre-existing failures, none new.
- The gate tests assert **positively** — a probe upstream records whether the call got through, so "allowed" means *reached upstream*, not merely *not denied*. Verified with a negative control: disabling the gate makes exactly the 2 gating tests fail.
- The endpoint test proves the kill-switch end-to-end: mint a token, use it, disable EMA, and the **same still-unexpired token** 401s on the next call.
- `ruff` clean on every file touched. (The autofixer again edited files beyond my diff, so I re-checked `F821/F811/F401` across `src/` and import-walked every module — clean.)

### Pickup hooks

- **MCP-2 P2** (SDK v2 migration — riskiest; `httpx`→`httpx2` in `mcp/outbound.py`), **P3** (MRTR as a policy surface; RFC 9207 `iss`; DCR `application_type`; **CIMD**, which 2026-07-28 prefers over RFC 7591 DCR).
- **`tool_call_events` retention prune** — still the smallest open compliance gap.
- **IDP-3** subdomain routing.
- **7 `test_diagnostic_bundle` failures** — fixture drift (`_Result` fake lacks `.scalar()`); fixing them gets the no-DB suite fully green.

## Sub-session update — 2026-08-25b (EMA-1 P1+P2 shipped — Vyuu as MCP Resource Authorization Server)

Adopted **MCP Enterprise-Managed Authorization** through the *bridge* tier (the locked decision in `docs/implementation/EMA-1-adoption-guide.md`): Vyuu is now both the EMA **Resource Server** and the **Resource Authorization Server**, so an enterprise governs MCP access in Okta/Entra while Vyuu stays the runtime enforcement + observability point — and upstream MCP servers never have to implement EMA themselves.

### Shape

```
ID-JAG (IdP-signed RS256, JWKS, async)  →  POST /v/{tenant}/oauth/token   [once per grant]
Vyuu access token (HS256, local secret) →  POST /v/{tenant}/{vs}/mcp      [every call]
```

Keeping the JWKS round-trip off the hot path is the whole point of the two-stage design: `IdentityProvider.validate_principal` is synchronous, so the per-call leg is a local HMAC verify (~µs) instead of a network fetch.

### Shipped

- **`migrations/20260825_0016`** — `idp_directories`: `ema_enabled` (per-directory opt-in; connecting for SCIM/SSO does NOT silently trust the issuer for agents), `ema_audience`, `ema_jwks_uri`, `ema_allowed_client_ids`; new `ema_consumed_jti` (PK `(tenant_id, jti)`, ENABLE-RLS) as the single-use replay guard. Downgrade/upgrade round-trip verified.
- **`api/ema_oauth.py`** — RFC 9728 metadata at the path-insertion form clients compute, plus the jwt-bearer token endpoint. Validation ladder: unverified `iss` → EMA-enabled directory *in this tenant* (selects the trust anchor only, grants nothing) → signature vs that directory's JWKS (asymmetric algs only — HS* deliberately excluded so a public JWKS value can never be forced into symmetric verification) → `aud` → `resource`→vserver-in-tenant → client allowlist → single-use `jti`. Every failure returns the same opaque `invalid_grant`.
- **`identity/jwt_bearer_provider.py` + `identity/chain.py`** — hot-path verify + ordered fall-through. Each leg fast-rejects the other's bearer shape, so chaining costs one string compare.
- **`FEDERATED_USER` principal** (`identity/models.py`, `audit/events.py`) — `principal_type` is free text in `tool_call_events`, so NHI separates enterprise-federated callers **with no migration**, carrying the IdP `sub` and the MCP `client_id` (a better AI-app signal than user-agent sniffing).
- **`idp/service.py::find_or_jit_create_directory_user`** — the `(directory_id, external_id)` JIT rule lifted out of `idp_signin.py`; OIDC sign-in, SAML sign-in and ID-JAG exchange now share ONE matching rule and one placeholder shape, so SCIM reconciliation can't drift per entry point.
- Inbound 401 advertises `WWW-Authenticate: Bearer resource_metadata="…"` when EMA is on (how EMA clients discover where to redeem). Sweeper prunes expired `jti` rows.

### Bug found + fixed en route

`virtual_servers/access.py` gated private-vserver grants on `principal.type == API_KEY`. Every federated user would have been silently denied on private vservers. Now any principal type that resolves to a real `users.id` (api_key **or** federated_user) can hold grants — caught by the e2e test, not by inspection.

### Validation

- 36 focused tests green (15 EMA + 9 MCP-2 modern + 12 IDP-1). Full: no-DB **815 passed**, dedicated-DB **969 passed**.
- The e2e proves the moat explicitly: an IdP-blessed token is still **403'd** on a private vserver without a Vyuu grant, passes once granted, and is **401'd mid-lifetime** the moment the user is disabled — the per-call kill-switch EMA structurally cannot provide.
- `ruff` clean across every file touched. Fixed an `F821` the autofixer introduced in `idp_signin.py` (it stripped `Any` once my refactor removed its other uses) — replaced with the real `SamlLoginResult` type rather than restoring the alias.

### Shared-DB drift — RESOLVED for this tree

Provisioned a dedicated **`vyuu_gateway_os_test`** database and migrated it from scratch. Real-DB failures dropped **32 → 15**; the 17 that vanished were all prod-repo schema drift (e.g. `mcp_capabilities.capability_ref`) leaking through the shared `vyuu_gateway` DB. Run DB-backed tests with:

```bash
VYUU_TEST_DATABASE_URL="postgresql+psycopg://vyuu@127.0.0.1:5432/vyuu_gateway_os_test" pytest
```

Remaining 15 are all pre-existing and environmental/fixture, none from this work: 7 `test_diagnostic_bundle` (fake `_Result` lacks `.scalar()`), 4 `test_rls_real_postgres` (`permission denied to set role` — the `vyuu` role lacks CREATEROLE), 2 `test_scim_server` (401 auth setup), 2 `test_admin_audit` (unbound session vs `admin_audit_log` RLS).

### Pickup hooks

- **EMA-1 P3**: scope→tool gating **AND-combined** with existing grants/policy; per-vserver client allowlist surfacing; operator-console EMA toggle on the IdP directory panel + federated identities in NHI; portal "your org uses Okta — no key needed" messaging.
- **MCP-2 P2/P3** unchanged (SDK v2 migration; MRTR-as-policy-surface; RFC 9207 `iss` + DCR `application_type` + **CIMD**, which 2026-07-28 prefers over RFC 7591 DCR).
- **New env vars** for EMA-1 are listed in the BACKLOG entry (`VYUU_EMA_ENABLED`, `VYUU_EMA_SIGNING_SECRET`, `VYUU_EMA_ACCESS_TOKEN_TTL_SECONDS`, `VYUU_PUBLIC_BASE_URL`).

## Sub-session update — 2026-08-25 (MCP SDK v2 / spec 2026-07-28 assessment + MCP-2 P1 dual-era inbound shipped)

The MCP spec revision **2026-07-28** went normative and Python SDK **v2.0.0** shipped for it — a breaking rewrite (stateless protocol, no `Mcp-Session-Id`, `server/discover`, namespaced `_meta`, `subscriptions/listen`, back-channel→MRTR, httpx2 + snake_case types). Full implications + plan in **BACKLOG.md → MCP-2**.

### Shipped this session

- **Defensive pin** `mcp>=1.13.0,<2` in `pyproject.toml` (both repos) — a fresh install would otherwise resolve 2.x and break (`streamablehttp_client` removed, snake_case types, httpx2). v1.x remains maintained upstream.
- **MCP-2 P1 — dual-era inbound (2026-07-28) support**, all in our own server code, no SDK dependency:
  - `api/inbound_mcp.py`: modern dispatch — a request carrying `_meta` `io.modelcontextprotocol/protocolVersion` (or the `MCP-Protocol-Version` header, or the `server/discover` method) is served **statelessly**; `initialize` still selects the legacy session path; legacy-shaped no-session requests keep the exact "Missing session ID" body (that's what dual-era clients probe before falling back).
  - `server/discover` → spec-shaped DiscoverResult (`supportedVersions: ["2026-07-28"]`, tools capabilities, instructions, `ttlMs`, **`cacheScope: "private"`** — the catalog is grant-dependent — and serverInfo `_meta`).
  - Stateless `tools/list` carries the required CacheableResult fields; stateless `tools/call` reuses the legacy handler wholesale via an **ephemeral never-registered `GatewaySession`** — new optional `ToolCallRequest.session` lets both eras hand the lifecycle a pre-resolved session (legacy path now skips its duplicate registry lookup too).
  - Spec errors: `UnsupportedProtocolVersionError` **-32022** with dual-era `supported` list (modern + `LATEST_PROTOCOL_VERSION`); `HeaderMismatchError` **-32020** when a present `Mcp-Method` header disagrees with the body.
  - **NHI enrichment, no migration:** `AuditClientMetadata.protocol_version` rides the `tool_call_events.client_metadata` JSONB; populated on both eras (legacy = negotiated at initialize, modern = per request) → "who is on which protocol revision" is now queryable.
  - Tests: `tests/api/test_inbound_mcp_modern.py` — 9 e2e tests driving **raw 2026-era JSON-RPC bodies** through the gateway to a real FastMCP fake upstream (discover shape, header-only selection, stateless call + audit enrichment, -32022/-32020, bad-bearer 401 + access_attempt, era-separation regressions incl. "legacy results carry NO `resultType`").

### Validation

- No-DB suite: **806 passed**; only pre-existing failures are the 7 `test_diagnostic_bundle` ones (test-fixture drift: fake `_Result` lacks `.scalar()` — flagged as a spin-off task chip, not silently fixed since the dev team owns the tree now).
- Real-DB suite: additional failures are **environmental, not code** — the shared lab Postgres had been migrated ahead by the OTHER team's tree (e.g. `mcp_capabilities.capability_ref NOT NULL` exists in no migration of ours). Resolved the next day — see "Repo situation" below.

### Repo situation — corrected 2026-08-25

`<repository root>` is **the** MCP-gateway codebase (not a git
repo; no branches involved). `<sibling handoff folder>` is NOT a copy of it —
it is a separate git repo with **55 commits** of a different team's feature line
(workload identities, governed invocation + idempotency, capability
binding/digest, credentials, user-capability-authority; migrations
`20260811_0016` → `20260825_0020`). Earlier notes in this file that described it
as "prod" and this tree as "open-source, cherry-picked from" were wrong.

Consequences that were real and are now fixed:
- The two trees' alembic chains **fork at `20260505_0015`** (ours:
  `20260825_0016_ema_idp_jag`; theirs: `20260811_0016`…`20260825_0020`, with two
  different files both numbered `_0016`). Merging would need a manual merge
  revision.
- Our lab pointed at the `vyuu_gateway` database, which **their** migrations had
  advanced to head `20260811_0018` — a revision our tree cannot resolve, and
  missing our EMA schema. Fixed by cloning that database to **`vyuu_gateway_dev`**
  (all lab data preserved: 39 servers, 98 events, 236 users, 54 vservers),
  dropping NOT NULL on the two foreign columns our inserts hit
  (`mcp_capabilities.capability_ref`, `.definition_digest`), rewriting
  `alembic_version` to the common ancestor, and upgrading to our head.
  `.claude/launch.json` now points at `vyuu_gateway_dev`. The shared
  `vyuu_gateway` DB was left untouched.
- Tests use a separate clean **`vyuu_gateway_os_test`**.


### Pickup hooks

- **MCP-2 P2** (SDK v2 migration, own branch: `Client` API, snake_case sweep, httpx2 in `mcp/outbound.py` — riskiest file, we inject clients + mTLS + read httpx-private `_transport`).
- **MCP-2 P3**: MRTR `InputRequiredResult` passthrough as a *policy surface*; RFC 9207 `iss` + DCR `application_type`; **CIMD** (Client ID Metadata Documents — 2026-07-28 deprecates RFC 7591 DCR; our DCR self-heal needs a CIMD sibling within the 12-month window). Fold auth items into EMA-1.
- **EMA-1** remains next big rock after MCP-2 P1 (guide: `docs/implementation/EMA-1-adoption-guide.md`).

## Sub-session update — 2026-05-05 (TOOL-EVENTS-1 + single-tenant on-prem mode + Health & servers page + Troubleshooting move + onboarding doc set + dev-lead handoff folder)

Read this section first. Five distinct landings, all shipped end-to-end with tests + lab verification.

### Validation as of pause

```bash
pytest --tb=no                                                    # 804 passed, 171 skipped (no DB)
VYUU_TEST_DATABASE_URL=postgresql+psycopg://vyuu@127.0.0.1:5432/vyuu_gateway pytest   # 952 passed, 15 skipped, 8 pre-existing failures (RLS test-role privileges, SCIM auth setup) — none from this session
```

Lab verified end-to-end: emit events → restart → buffer rehydrated from Postgres → operator UI shows history. Screenshots captured during the session.

### A. Single-tenant on-prem mode

Driven by user feedback: "99% of customers will deploy this on-prem with one tenant; asking them to paste a tenant_id every login is bad UX."

- **`Settings.default_tenant_id`** ([config.py](src/vyuu_gateway/config.py)) — `UUID | None`, env `VYUU_DEFAULT_TENANT_ID`. Unset = SaaS multi-tenant mode (existing behaviour).
- **Public endpoint `GET /api/v1/auth/default-tenant`** ([api/idp_signin.py](src/vyuu_gateway/api/idp_signin.py)) — returns `{tenant_id, display_name}` or 404. No auth required so the login page can fetch it before sign-in.
- **Operator + portal login pages** ([api/operator_ui.py](src/vyuu_gateway/api/operator_ui.py), [api/portal_ui.py](src/vyuu_gateway/api/portal_ui.py)) — fetch `/default-tenant` on load. If 200: pre-fill tenant input + hide it via `wrap.style.display='none'` + update subhead to `Sign in to <tenant.name>` + render the connected-IdP "Continue with X" buttons immediately. If 404: fall back to `?tenant=<uuid>` URL param or sessionStorage.
- **Lab wired** — [.claude/launch.json](.claude/launch.json) sets `VYUU_DEFAULT_TENANT_ID="11111111-1111-1111-1111-111111111111"` for the drawio lab tenant.
- **Resolution order documented in JS comments**: server-configured → URL param → sessionStorage. First match wins.

### B. TOOL-EVENTS-1 — persistent audit pipeline (the load-bearing fix)

User report: "every time you change code the dashboard goes blank, I have to generate fresh events." That was right — the operator-console Events / NHI map / Identities panels read from an in-memory ring buffer that reset on every restart. Architecturally wrong for a security product. **Fix: Postgres becomes the source of truth, buffer becomes a hot read-cache.**

Migration: [`migrations/versions/20260505_0015_tool_call_events.py`](migrations/versions/20260505_0015_tool_call_events.py)

- New table `tool_call_events` — every column from `AuditEvent` plus `event_id` PK + `tenant_id` FK. FORCE RLS enabled (mirrors `admin_audit_log` posture). Indexes on `(tenant_id, occurred_at)`, `(tenant_id, vserver_id, occurred_at)`, `(tenant_id, principal_id, occurred_at)`, `(tenant_id, event_type, occurred_at)`.
- FKs to `virtual_servers` / `mcp_servers` use `ON DELETE SET NULL` — events outlive their referenced entities for forensic reasons. `vserver_name` denormalised at write time.

Code:

- **[`db/models.py::ToolCallEvent`](src/vyuu_gateway/db/models.py)** — ORM mirror of the table.
- **[`audit/persistent.py`](src/vyuu_gateway/audit/persistent.py)** (NEW):
  - `PostgresToolCallEventStore` — implements `AuditEmitter` Protocol; opens a fresh tenant-bound session per event, INSERTs synchronously, commits, delegates to inner emitter. Wraps next-stage emitter (Kafka / no-op) — chain pattern matches `RecentAuditEmitter`. Failures log loud + continue (audit failures must not break tool calls).
  - `query_tool_call_events(db, *, tenant_id, since, until, vserver_id, upstream_server_id, event_type, principal_id, principal_id_in, limit)` — Postgres-backed read with time-window filters.
  - `seed_recent_buffer_from_postgres(session_factory, *, buffer_appender, per_tenant_limit=2000)` — startup hydration. Iterates `tenants` (no RLS) for the discovery query, then binds tenant context per tenant for the actual select. Pushes events oldest-first into the buffer's deque.
- **[`audit/recent.py`](src/vyuu_gateway/audit/recent.py)** — added `warm_load(event)` method (distinct from `emit_nowait` because warm-loaded events must NOT be re-emitted to the inner chain).
- **[`main.py`](src/vyuu_gateway/main.py)** — emitter chain composed top-down: `RecentAuditEmitter(inner=PostgresToolCallEventStore(SessionLocal, inner=raw_emitter))`. Lifespan startup calls `seed_recent_buffer_from_postgres(...)` — guarded by `len(recent) == 0` so tests that emit before entering the test client context don't double-load.
- **[`api/audit_events.py`](src/vyuu_gateway/api/audit_events.py)**, **[`api/nhi_map.py`](src/vyuu_gateway/api/nhi_map.py)**, **[`api/identities.py`](src/vyuu_gateway/api/identities.py)** — refactored to query Postgres via `query_tool_call_events` with `since=` defaulting to `last 24h`. NHI map + Identities also accept `since`/`until`. Identity timeline: pre-filters by `principal_id` (covered by `tool_call_events_tenant_principal_idx`), over-fetches 10× the limit so Python-side `decision`/`risk_floor` narrows can still produce up to limit rows.
- **UI time-range pickers** — Events / NHI map / Identities each got a `<select>` with `1h / 24h / 7d / 30d` (default 24h). Shared JS helper `windowSelectorToSinceIso(value)`. `change` auto-refetches.

Tests:

- **[`tests/audit/test_persistent_store.py`](tests/audit/test_persistent_store.py)** (NEW) — 4 tests: emit-persists-to-postgres, query-returns-after-restart (the load-bearing one), buffer-warmup-rehydrates, RLS-blocks-cross-tenant.
- **[`tests/api/test_audit_events_endpoint.py`](tests/api/test_audit_events_endpoint.py)** + **[`tests/api/test_identities_endpoint.py`](tests/api/test_identities_endpoint.py)** + **[`tests/audit/test_access_attempt_events.py`](tests/audit/test_access_attempt_events.py)** — converted from buffer-only fakes to real-Postgres integration (gated on `VYUU_TEST_DATABASE_URL`) since the endpoints now query the durable table. Pattern: seed tenant + operator → emit through chain → assert via endpoint → cleanup tenant (cascade drops events).
- **[`tests/tenant_isolation/test_tenant_isolation.py`](tests/tenant_isolation/test_tenant_isolation.py)** — added `tool_call_events` to the expected tenant-scoped table set.

Lab proof: emitted 5 events → stopped lab → restarted → log line `audit_buffer_seeded events=5 tenants=3` → `GET /api/v1/audit-events?since=...` returned all 5 → operator UI Events panel rendered them with the new time-window picker visible.

### C. Diagnostic bundle v1.1

Bumped from v1.0 to cover everything we've built since. [`api/diagnostic_bundle.py`](src/vyuu_gateway/api/diagnostic_bundle.py).

New sections:
- `persistent_audit` — `tool_call_events` total count + count-in-window + oldest/newest occurred_at + by-event-type + by-decision distributions.
- `audit_buffer_warmup` — buffer current size + max capacity + diagnostic note (helps when `total_events > 0` but `buffer_current_size = 0`).
- `idp_directories` — per-directory: kind, signin protocol, last sync, users provisioned (no SCIM tokens — only the configuration metadata).
- `admin_audit` — actions in window + by-actor distribution + last 20 rows in detail.
- `background_workers` — SCIM hard-delete sweeper state (running, cycles, last-swept-count) + capability sync scheduler state (running, interval, max-concurrent-per-tenant).

`_BUNDLE_VERSION = "1.1"`. JSON shape stays additive — older support tooling that reads v1.0 fields still works.

### D. Health & servers page (new operator-console page)

Cloud-style "Overview" page mapped to our actual entities (no regions / no primary-standby; this is single-instance on-prem). [`api/health_overview.py`](src/vyuu_gateway/api/health_overview.py) (NEW) backs it.

Endpoint `GET /api/v1/admin/health-overview` returns:
- `gateway_info` — version, environment, host, platform, uptime, RSS, CPU%, FDs.
- `kpis` — `gateway_instances` (1 today; multi-instance HA = future), `uptime_seconds`, `p50/p95/p99_latency_ms_1h` (Postgres `percentile_cont` over `tool_call_events.latency_ms_total`), `avg_latency_ms_1h`, `signing_key` posture, `idp_certificates_to_track` (one row per SAML directory — full cert parsing is the IdP-detail page's job).
- `status_cards` — five tiles each with status `ok/warn/error` + label + detail string: Database reachable + audit DB writeable, audit pipeline (hot buffer + persistent table), IdP directories connected, capability sync, SCIM sweeper.
- `mcp_servers` — table-shaped rows: server name + id + transport + health pill + avg latency 1h + calls 1h + capability count + last sync + registered at.
- `latency_series` — sparse hourly p95/p99 buckets for the last 24h, fed into an inline SVG chart on the page (no chart lib).

UI panel in [`api/operator_ui.py`](src/vyuu_gateway/api/operator_ui.py) under `data-nav="health-overview"`:
- KPI tile row (instances / uptime / p95 / certs)
- Tenant info card (tenant id / signing key / environment / version)
- 5 status tiles (left-border colored by status)
- MCP servers table styled like the screenshot the user shared
- Inline-SVG p95/p99 chart with y-tick gridlines + x-axis hour labels
- Polls every 15s while panel visible
- Sidebar nav added under **Overview** group with a heart-pulse glyph

### E. Troubleshooting moved to Settings + diagnostic-bundle window picker

Diagnostic bundle download was on the Dashboard panel. Moved out:
- Removed `<button id="download-diagnostic-bundle">` from the Dashboard panel header.
- New panel `data-nav="troubleshooting"` under **Settings** group with a wrench glyph.
- Added a window picker (`Last 15min / 1h / 6h / 24h`) wired to `?since_minutes=` so support hand-offs can target the right window.
- Coverage explainer grid (8 cards: Process & host, Connectivity, MCP servers + vservers, Audit pipeline, IdP directories, Admin audit, Background workers, Circuit breakers + inflight gate) so operators know what's in the bundle before they download.

### F. Engineering onboarding doc set + dev-lead handoff folder

User requirement: package the project for dev-lead handoff with a clean tarball-able copy.

**Onboarding docs** in [`docs/onboarding/`](docs/onboarding/) (12 files; core 9 + depth tier 2):

Core path:
- `README.md` — read-order index
- `SETUP.md` — 15-minute local bring-up (prereqs, DB, migrations, lab server, first sign-in, common snags)
- `ARCHITECTURE.md` — three planes (inbound MCP / operator API / portal), audit pipeline diagram, RLS posture
- `BACKEND.md` — per-package guide of `src/vyuu_gateway/` with stack + responsibilities
- `FRONTEND.md` — no-framework ideology, operator + portal patterns, time-window picker pattern, live-poll pattern
- `AUTH.md` — every authentication surface (operator JWT, portal session, API key, SCIM bearer, OIDC, SAML, outbound auth modes)
- `NETWORK.md` — ports, route map, MCP transports, RLS posture, on-prem ingress assumptions
- `TESTING.md` — test layout, conventions (DB-integration pattern, tenant fixture, RLS asserts), how to write new ones, CI gotchas
- `RUNBOOK.md` — symptom → cause → fix for the dozen most likely operational issues
- `KNOWLEDGE_BASE.md` — feature → file:line jump-table

Depth tier (added 2026-05-05 per dev-lead handoff request):
- `BACKEND_DEEP_DIVE.md` (~770 lines) — module dependency graph, ERD overview, full request lifecycles with ASCII sequence diagrams (inbound MCP / operator API + admin audit / SCIM provisioning push / IdP SSO OIDC + SAML / audit fan-out chain / capability sync cycle), schema deep-dive column-by-column for every tenant-scoped table, failure-mode summary at the request level.
- `LOW_LEVEL_ARCH.md` (~545 lines) — process model (single uvicorn, no workers, why), async vs sync rules, connection pooling (Postgres / httpx / stdio), transaction boundaries + the per-request transaction shape, RLS GUC mechanics + the cross-tenant scan pattern + why FORCE for some tables, concurrency primitives (RecentAuditEmitter Lock / inflight gate Semaphore / circuit breaker state machine), memory budget per-process / per-tenant / per-request with concrete numbers for a typical on-prem deploy, startup + shutdown sequences, failure-mode matrix (subsystem fails → effect → recovery), hot-path performance characteristics with measured p50/p95.

Reference tier (added 2026-05-05 same session, post dev-lead-audit):
- `API_REFERENCE.md` (~250 lines) — every one of the 105 endpoints by surface (Inbound MCP / HTML / auth / catalog / IAM / observability / admin / IdP / portal / SCIM / health) with auth column (operator / portal / api_key / SCIM / public) + brief purpose. Curated companion to `/openapi.json`.
- `MIGRATIONS.md` (~280 lines) — Alembic conventions: tenant-scoped table template (RLS + FK + index + policy), when to FORCE RLS, FK semantics (CASCADE vs SET NULL with denormalised label), index column-order rules, TEXT + CHECK over native ENUM, idempotent seed pattern, downgrade requirements, tested apply/revert flow.
- `SECURITY.md` (~270 lines) — threat model (assets / attackers / defenses), explicit "what we do NOT defend against" (host compromise, supply chain, side-channel, DDoS, e2e arg encryption), engineer rules (secrets handling: never log full bearer / never in URL / never in bundle; tenant boundary: always tenant-scoped session, cross-tenant scan pattern; auth boundary: one resolver per surface; mutating endpoints: same-transaction admin audit), dependency policy, audit retention posture.
- `MCP_SPECIFICS.md` (~250 lines) — protocol oddities: streamable_http vs sse vs stdio quirks, session-id semantics, why we DON'T cache `tools/list`, `<connect>` sentinel for access_attempt events, H5 raw-payload capture cap (10 MiB default, sentinel on overflow), `args_summary` shape (top_level_keys + types + sizes, no values), why we don't synthesise responses on DENY, OAuth-AC + RFC 7591 DCR with IAT, why `tools/list` from a vserver isn't 1:1 with upstream (the curated projection).
- `CHANGELOG.md` (~150 lines) — reverse-chronological landings: 2026-05-05 (TOOL-EVENTS-1 + single-tenant + Health page), 2026-05-04 (IDP-1 + UI redesign), 2026-05-03 (DCR auto-recovery + scheduler authcode), 2026-05-02 (stress + DEVOPS), 2026-05-01 (OAuth JWT-bearer + authcode), 2026-04-30 (auth modes + binary), 2026-04-29 (initial schema). Each entry: schema id + new endpoints + new modules + breaking config + tests landed.
- `SBOM.md` (~280 lines) + `sbom.cdx.json` (CycloneDX v1.6, ~125 KB, 104 components) — Software Bill of Materials. SBOM.md covers: 14 direct runtime deps + 4 dev + 3 optional groups (kafka/nats/perf), full transitive table for 78 third-party packages with version + license, license-distribution summary (40 MIT / 17 Apache / 12 BSD / 2 LGPL / 2 MPL / 1 each ISC/PSF/Unlicense — no GPL/SSPL), risk callouts (psycopg LGPL-3.0 dynamic-link is OK for proprietary use; certifi+pathspec MPL-2.0 file-level copyleft we don't trip), system deps (Postgres 14+, xmlsec1, libpq, optional Redis/Kafka/NATS, reverse proxy), regenerate commands (`pip-licenses`, `cyclonedx-py environment`), update process (when to refresh, quarterly CVE scan with `pip-audit`, annual license audit), vendor/customer request playbook (which artefact to send for a Stage-4 procurement review).

Hygiene change 2026-05-05 (post-LICENSE-removal):
- `LICENSE` file removed from both folders — project is **not open source**, all rights reserved internal IP. README licensing block updated to make this explicit.

Critical handoff hygiene added 2026-05-05 (post-audit):
- `LICENSE` (Apache 2.0 placeholder) added to both folders, with a NOTE block at the bottom flagging that the project owner should confirm the license choice with their legal team before external publication. Alternative options (MIT / Apache / AGPL / commercial) listed.
- `.gitignore` added to both folders (was missing from source repo too) — covers Python caches, venvs, test artifacts, IDE state, `.env`, `*.pem`, `*.key`, downloaded diagnostic bundles, perf artifacts, Alembic cache. Critical because if dev lead `git init`s the destination, they'd otherwise commit `__pycache__`, `dump.rdb`, lab `.env`, etc.
- `.dockerignore` + `AGENTS.md` copied to destination (existed in source, missed in initial copy).
- `.DS_Store` stripped from destination (re-leaks every macOS rsync — added to `.gitignore`).

**Destination folder** at [`<sibling handoff folder>/`](file://<sibling handoff folder>):
- `rsync -a --exclude=__pycache__ --exclude=.venv ...` of `src/`, `tests/`, `migrations/`, `examples/`, `scripts/`, `deploy/`, `docs/`
- Top-level: `pyproject.toml`, `alembic.ini`, `Dockerfile`, `README.md`, `BACKLOG.md`
- Fresh `.env.example` with every required env var documented
- Fresh `.claude/launch.json.example` with secrets stripped (placeholder OAuth client refs)
- BACKLOG.md client_id redacted (`Ov23lil5...` → `<redacted-client-id>`)
- 5.1 MB total, 139 src files, 103 test files, 19 migrations, 0 secrets
- Top-level READMEs in both folders point to the onboarding set

### Files to know about post-pause

- New routers: `api/health_overview.py`, `audit/persistent.py`, `tests/audit/test_persistent_store.py`
- Modified emitter chain: `main.py` lifespan startup hook + emitter wiring
- New panels: `data-nav="health-overview"`, `data-nav="troubleshooting"` in `api/operator_ui.py`
- Latest migration head: `20260505_0015`

### Pickup hooks for next session

Possible next moves (not started):
- **`tool_call_events` retention/prune cron** — currently no automatic prune; a 90-day window would match typical compliance retention.
- **Multi-instance HA** — `gateway_instances=1` is hard-coded in health-overview; turning it into a real registry needs heartbeat into Postgres + per-instance row.
- **IdP cert expiry parsing** — `_idp_cert_expiries` returns `expires_in_days: None` and defers to the IdP detail page; pulling `cryptography` in to parse PEM `not_after` would let the Health page show actual cert expiry.
- **IDP-2 backlog** — Google Workspace polling adapter (since custom Workspace SAML apps don't push SCIM); see BACKLOG.md.
- **IDP-3 backlog** — subdomain-per-tenant routing for the SaaS path (complement to single-tenant on-prem).

## Sub-session update — 2026-05-04 (Operator UI tabular redesign across 6 panels + dark-mode token cleanup + IDP-1 phase 1 foundation)

Read this section first. Half the session was a UI redesign sweep across the operator console; the second half started **IDP-1 (Entra ID + Google Workspace SCIM)** and laid down the schema foundation. **Pause here — IDP-1 phases 1d–5b still ahead, picking up next morning.**

### Validation as of pause

```bash
pytest tests/ --tb=no                   # 812 passed, 136 skipped, 2 warnings
```

Both lab restarts succeeded; `/operator` console verified end-to-end in light + dark mode for every redesigned panel.

### A. Operator-console tabular redesign (light + dark, all 6 panels)

The pattern: replace the prior stacked-card layouts with **eyebrow + serif H1 + KPI strip + filter pills + search + table + slide-over drawer + create-modal** so every panel feels like one product. Each redesigned list endpoint also got a **single-trip aggregate response** so the table never fans out per-row.

**Backend — new wire shapes (all are strict supersets, single-row endpoints unchanged):**

- `UserListItemResponse` ([users_schemas.py](src/vyuu_gateway/registry/users_schemas.py)) — adds `api_key_count`, `group_count`, `last_api_key_used_at`. Backed by `list_users_with_aggregates()` ([users_service.py](src/vyuu_gateway/registry/users_service.py)) — single SQL with two LEFT-JOINed subqueries (active-only key count + max `last_used_at` + group count).
- `GroupListItemResponse` — adds `member_count`, `vserver_grant_count`. `list_groups_with_aggregates()` — LEFT JOINs `user_group_memberships` + `virtual_server_grants` (filtered to `principal_kind = 'group'`).
- `AccessRequestListItemResponse` ([access_requests_schemas.py](src/vyuu_gateway/registry/access_requests_schemas.py)) — adds `user_email`, `user_display_name`, `vserver_name`, `vserver_visibility`, `decided_by_email`. `list_access_requests_with_context()` — three LEFT JOINs (`users`, `virtual_servers`, `operators`) so the admin queue reads names not UUIDs.
- `VirtualServerListItemResponse` ([virtual_servers/schemas.py](src/vyuu_gateway/virtual_servers/schemas.py)) — adds `tool_count`, `grant_count`. `list_virtual_servers_with_aggregates()`.
- Identities aggregator ([audit/identity_aggregator.py](src/vyuu_gateway/audit/identity_aggregator.py)) extended with `latest_client_name` / `latest_client_version` / `latest_user_agent` / `distinct_clients` — surfaced as the `via Cursor 0.42` badge on the Identities row + drill-in. The MCP `clientInfo` was already captured on every `AuditEvent`; this surface just exposes it.

The `FakeDbSession` test fixture ([tests/api/test_capability_sync_and_vservers.py](tests/api/test_capability_sync_and_vservers.py)) gained `execute_results: list[list[tuple[Any, ...]]]` + a `_ExecuteResult` helper for the new multi-column queries.

**UI — operator_ui.py rebuilds:**

Each panel got the same chrome (`events-panel-v2` + `events-head` + `events-kpi-grid` + `events-pill-row` + `events-table` + `identity-drawer`) and a custom column-width set:

- **Events** — colored type badges (`endpoint_session` ocean / `api_key` orange / `server_agent` warn-amber), unsanctioned-row left-border + tint, KPI strip with HIGH-RISK ACTIVITY tile.
- **Identities** — KPI tiles (TOTAL / HIGH-RISK / NEW · 24H / TOP INTERFACE), filter pills incl. `User tokens` / `Endpoint sessions` / `Service agents` / `High risk` (renamed from "Humans/API keys/Agents" — see naming note below), VIA column shows `Cursor 0.42.0` from `clientInfo`, drill-in drawer with Timeline / Graph / Summary tabs.
- **Users** — KPI strip (TOTAL / DISABLED / PENDING RESET / NEW · 24H), pills (`All / Active / Disabled / Local auth / SSO / Pending reset`), table (USER w/ status pill + AUTH + LAST SEEN + API KEYS + GROUPS + CREATED + Drill-in), drawer tabs (Activity / API keys / Groups), `+ New user` modal replaces the bottom-of-page form. `Reset password` / `Disable` are inline on row + inside the Activity tab.
- **Groups** — KPIs (TOTAL / UNUSED / EMPTY / LARGEST), pills (`All / In use / Empty / Unused`), table (GROUP / MEMBERS / VSERVER GRANTS / CREATED / Drill-in), drawer tabs (Members chip-editor / Vserver grants — the latter walks `vservers` and calls `/grants` per-vserver to find references; bounded by tenant's vserver count, only runs when the tab is opened).
- **Access requests** — KPIs (PENDING / OLDEST PENDING / APPROVED·7D / DECLINED·7D), pills (`Pending / All / Approved / Declined / Withdrawn`, **Pending active by default** since this is a working queue), table (REQUEST email + "wants → vserver · visibility" / NOTE truncated italic / STATUS color-pill / SUBMITTED / Approve+Decline inline). Drawer surfaces full request detail incl. `Decided by` operator email + `Grant created` UUID. New `formatAge()` helper for the OLDEST KPI — stays relative past 24h (`1d`, `2w`).
- **Admins** — KPIs (TOTAL / DISABLED / PENDING RESET / **NEVER LOGGED IN** — this last one is the security signal: a credentialed-but-unused operator account is a stale invite), pills (`All / Active / Disabled / Admin / Editor / Viewer / Pending reset`), table (ADMIN status-pill + email + id / ROLE color-coded tag / LAST LOGIN / CREATED / Reset+Disable inline). No drill-in drawer — admins have no per-row activity beyond the row itself. `+ New admin` modal.
- **Virtual servers** — KPIs (TOTAL / EMPTY / PRIVATE / PUBLIC), pills (`All / Public / Private / Has grants / Empty`), table (VSERVER visibility-pill + name + id / URL with copy / TOOLS / GRANTS / CREATED / Drill-in). Drawer tabs (Tools / Access — visibility flip + grants list + issue-grant form / Settings — delete with confirmation). Replaces the old card grid; `+ New vserver` modal wraps the existing tools-textarea form.

### B. Naming corrections during the redesign

The user pushed back on two labels and they were replaced everywhere:

- **"Humans" pill is wrong** — Cursor `endpoint_session` is software at the wheel even with a human driving. Renamed `Humans → Endpoint sessions`, `API keys → User tokens`, `Agents → Service agents` in `labelForIdentityType()`. Type pill is now about **how the call was authenticated**; a separate **VIA** column answers "what client interface" via the protocol-level `clientInfo` (Cursor / Claude Desktop / mcp-remote / etc.).
- **No green in the Vyuu palette** — initial pills used `#2F6B3D` greens for "active / approved". The canonical [`vyuu-tokens.css`](Vyuu%20MCP%20Gateway/vyuu-tokens.css) reserves the warm spectrum for pending/risk/brand and the cool ocean tokens (`--vyuu-info-*`) for "decided positively / informational". Active pills, Approved access requests, and the events-table "Allowed" outcome word now use `var(--vyuu-info-ink)` on `var(--vyuu-info-tint)` — both theme-correct and brand-aligned.

### C. Dark-mode token sweep

The user reported that recent additions weren't visible after toggling to dark. Cause: hardcoded hex/rgba (`#A85820`, `rgba(160, 60, 60, 0.06)`, etc.) instead of the dark-mode-aware `--vyuu-*` tokens. Replaced everywhere across the new CSS + a couple of inline `style.color` JS sites:

| Hardcoded | Token |
|---|---|
| `#A85820`, `rgba(168, 88, 32, ...)` | `--vyuu-orange-deep` / `--vyuu-orange-mist` |
| `#8A2F2F`, `rgba(160, 60, 60, ...)` | `--vyuu-danger-ink` / `--vyuu-danger-tint` / `--vyuu-danger` |
| `#2F6B3D`, `#2F7A3A`, `rgba(72, 134, 84, ...)` | `--vyuu-info-ink` / `--vyuu-info-tint` / `--vyuu-info` |

Verified light + dark in browser across Identities, Users, Groups, Access requests, Admins, Virtual servers; no visual regressions.

### D. IDP-1 phase 1 — schema foundation (Entra ID + Google Workspace SCIM + admin audit log)

User scope locked in five answers:

1. **Provider kinds:** Entra + Workspace only (no generic SCIM connector).
2. **Sign-in protocol:** OIDC + SAML, admin chooses per-directory.
3. **Secrets:** existing `secret_store` (Vault / Postgres) for now; KMS upgrade captured in BACKLOG entry "AWS KMS · Envelope encryption" extended to reference IdP secrets.
4. **Deprovisioning:** soft-disable on SCIM-deactivate, hard-delete after 7 days, every step recorded in a new persistent **admin audit log** (distinct from the in-memory `RecentAuditEmitter` which captures inbound MCP tool calls — admin audit captures *what admins did to the platform*).
5. **Group nesting:** flat only, no recursive expansion.

#### Phase 1a — BACKLOG.md ([BACKLOG.md](BACKLOG.md))

Added IDP-1 section under "Auth & identity" with the five locked decisions + sub-phase plan. Extended the existing "AWS KMS" backlog entry to flag IdP secrets as a third candidate use case.

#### Phase 1b — migration `20260504_0014` ([migrations/versions/20260504_0014_idp_directories_and_admin_audit.py](migrations/versions/20260504_0014_idp_directories_and_admin_audit.py))

Applied to the dev DB. Adds:

- **`idp_directories`** — per-tenant, RLS-enforced. Columns: `kind ∈ {'entra', 'google_workspace'}`, `display_name`, `signin_protocol ∈ {'oidc', 'saml'}`, `scim_token_hash` (argon2id of the bearer the admin pastes into the IdP), OIDC fields (`oidc_issuer`, `oidc_client_id`, `oidc_client_secret_ref`), SAML fields (`saml_entity_id`, `saml_sso_url`, `saml_idp_certificate`), `metadata` JSONB, `last_sync_at`. Unique `(tenant_id, kind)` so admins can connect both Entra and Workspace but not two of the same.
- **`admin_audit_log`** — per-tenant, RLS-enforced. Columns: `actor_operator_id` (FK SET NULL — preserves rows past operator deletion), `actor_kind ∈ {'operator', 'system', 'scim'}`, `actor_display`, `action` (free-text dotted verb — `user.disable`, `vserver.delete`, `grant.revoke`, `idp.connect`, `scim.deactivate_user`, `scim.hard_delete_user`), `target_kind` / `target_id` / `target_display`, `detail` JSONB, `occurred_at`. Three indexes — per-tenant feed, per-action filter, per-target lookup.
- **`users` extensions** — `idp_directory_id` (FK SET NULL), `external_id` (IdP's stable id — Entra `objectId` / Workspace `id`), partial-unique `(tenant_id, idp_directory_id, external_id) WHERE external_id IS NOT NULL`, `soft_deleted_at` (the 7-day grace window before hard-delete). `users_auth_method_check` constraint dropped + recreated to include `'scim'`.
- **`groups` extensions** — same `(idp_directory_id, external_id)` pair + partial-unique.

#### Phase 1c — SQLAlchemy models ([src/vyuu_gateway/db/models.py](src/vyuu_gateway/db/models.py))

Added:

- `class IdpDirectoryKind(StrEnum)` — `ENTRA`, `GOOGLE_WORKSPACE`.
- `class IdpSigninProtocol(StrEnum)` — `OIDC`, `SAML`.
- `class IdpDirectory(Base)` — mirror of the table, including `metadata_json` mapped from the `metadata` column (avoids the SQLAlchemy `metadata` attribute clash).
- `class AdminAuditActorKind(StrEnum)` — `OPERATOR`, `SYSTEM`, `SCIM`.
- `class AdminAuditLog(Base)`.
- `User` extended with `idp_directory_id`, `external_id`, `soft_deleted_at` + the partial-unique index in `__table_args__`.
- `Group` extended with `idp_directory_id`, `external_id` + the partial-unique index.
- `UserAuthMethod` enum gained `SCIM = "scim"`.

`tests/tenant_isolation/test_tenant_isolation.py` updated to include `idp_directories` + `admin_audit_log` in the expected tenant-scoped table set. Full suite green.

### Resume next session — start of Phase 1d

**One decision the user still needs to confirm before the next phase starts:** when the admin-audit emitter retrofits into existing admin endpoints (disable user, revoke grant, delete vserver, etc.), should it write **synchronously in the same DB transaction** as the action (strict consistency — both succeed or both rollback), or **best-effort fire-and-forget**? My recommendation: synchronous in the same transaction, because for a compliance-grade audit log "the action happened but we forgot to log it" is the worst possible outcome. **User said: discuss in the morning.**

Pick up at `Phase 1d: Admin audit emitter + helpers`. The remaining phases in order:

| Phase | Work | Rough size |
|---|---|---|
| **1d** | `audit/admin_audit.py` emitter (sync API: `record(db, *, tenant_id, actor, action, target, detail)`) + retrofit into every existing admin endpoint | ~3–4h |
| **2a/b** | SCIM 2.0 server — `/scim/v2/{directory_id}/Users` + `/Groups`, PATCH op handling for both Entra `Operations[]` + Workspace `members[]` | ~6–8h |
| **3** | Hard-delete sweeper (cron loop, 7-day grace, audit row per sweep) | ~2h |
| **4a** | Per-directory OIDC sign-in — refactor `auth.py` to look up via `(directory_id, external_id)` first, fall back to existing `microsoft` / `google` JIT path | ~3h |
| **4b** | SAML sign-in — likely pull in `python3-saml` (or `xmlsec` + `lxml` directly); meaningful new dep + test surface | ~6–8h |
| **5a** | Operator console: Identity providers panel under SETTINGS + connect-wizard modal + per-directory chips on Users / Groups | ~4h |
| **5b** | Operator console: Admin audit log panel under OBSERVABILITY (table + filter pills by action / actor / target_kind) | ~2h |

**~1.5–2 working days** still ahead.

#### State of the dev DB

- Migration `20260504_0014` applied. Both new tables exist, RLS enabled.
- 4 demo admins in `operators` (alice + audit-bot + reviewer + lab-operator), 6 users (4 perf-demo-* + lab-operator + krishna), 3 groups (engineering with 3 members + 1 vserver grant, analysts with 2 members, legacy-stub empty + unused), 9 access-request rows mixing pending / approved / declined statuses against `cyberint-mcp-published` + `Notion-User-MCP` + `huggingface-mcp-public` (the latter flipped to `private` to enable seeded requests).
- Lab is currently running on port 8000 in the previous shell. To resume cleanly: `preview_stop` the existing server and `preview_start drawio-lab`.

#### Files touched (this sub-session)

- [BACKLOG.md](BACKLOG.md) — IDP-1 entry + KMS extension
- [migrations/versions/20260504_0014_idp_directories_and_admin_audit.py](migrations/versions/20260504_0014_idp_directories_and_admin_audit.py) — new migration
- [src/vyuu_gateway/db/models.py](src/vyuu_gateway/db/models.py) — new enums + models, User/Group extensions, UserAuthMethod gains SCIM
- [src/vyuu_gateway/registry/users_schemas.py](src/vyuu_gateway/registry/users_schemas.py) — UserListItemResponse, GroupListItemResponse
- [src/vyuu_gateway/registry/users_service.py](src/vyuu_gateway/registry/users_service.py) — `list_users_with_aggregates`, `list_groups_with_aggregates`
- [src/vyuu_gateway/api/users.py](src/vyuu_gateway/api/users.py) — list endpoints wired to enriched views
- [src/vyuu_gateway/registry/access_requests_schemas.py](src/vyuu_gateway/registry/access_requests_schemas.py) — AccessRequestListItemResponse
- [src/vyuu_gateway/registry/access_requests_service.py](src/vyuu_gateway/registry/access_requests_service.py) — `list_access_requests_with_context`
- [src/vyuu_gateway/api/access_requests.py](src/vyuu_gateway/api/access_requests.py) — admin endpoint serves enriched view
- [src/vyuu_gateway/virtual_servers/schemas.py](src/vyuu_gateway/virtual_servers/schemas.py) — VirtualServerListItemResponse
- [src/vyuu_gateway/virtual_servers/service.py](src/vyuu_gateway/virtual_servers/service.py) — `list_virtual_servers_with_aggregates`
- [src/vyuu_gateway/api/vservers.py](src/vyuu_gateway/api/vservers.py) — list endpoint serves enriched view
- [src/vyuu_gateway/audit/identity_aggregator.py](src/vyuu_gateway/audit/identity_aggregator.py) — clientInfo aggregation
- [src/vyuu_gateway/api/identities.py](src/vyuu_gateway/api/identities.py) — IdentitySummaryView gains client fields
- [src/vyuu_gateway/api/operator_ui.py](src/vyuu_gateway/api/operator_ui.py) — six panel rebuilds + dark-mode token sweep
- [tests/api/test_capability_sync_and_vservers.py](tests/api/test_capability_sync_and_vservers.py) — `_ExecuteResult` helper, `execute_results` queue
- [tests/tenant_isolation/test_tenant_isolation.py](tests/tenant_isolation/test_tenant_isolation.py) — adds `admin_audit_log` + `idp_directories` to expected set

---

## Sub-session update — 2026-05-03 (Closes U7 + U8 + U11 — scheduler authcode resolution, ref-field UX, IAT-gated enterprise DCR)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway_test \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest tests/ --ignore=tests/perf      # 947 passed, 1 skipped (+6 from this slate)
ruff check src/ tests/                  # All checks passed!
mypy src/vyuu_gateway                   # Success: no issues found in 120 source files
```

Three small backlog items closed in one slate. Each is independent — listing in the order shipped.

### U8 — `_ref` field UX (~2 hours, shipped)

The wizard's step 3 has five `_ref` inputs across three auth modes (`client_id_ref`, `client_secret_ref`, `private_key_ref`). Operators routinely pasted the *literal* OAuth client_id / client_secret / PEM body into these fields, expecting them to be the value field. The gateway then treats the literal as a SecretStore key, can't find it, falls back to `placeholder-<value>`, and OAuth fails silently at the IdP. This was the gap I myself hit during the live debugging two sub-sessions back.

Two changes in [`src/vyuu_gateway/api/operator_ui.py`](src/vyuu_gateway/api/operator_ui.py):

1. **Relabeled** every `_ref` input with an inline hint that says "Secret-store key, NOT the literal client_id" (or NOT the raw secret / PEM body). Hint includes a short example (`github-client-id` → resolves via Vault / env var).
2. **Soft-validation** via `_looksLikeLiteralCredential(value)` heuristic + `_renderRefWarning(input)`. When the operator's input matches the shape of an OAuth credential (16+ chars, mixed case, no kebab-case separators, no `vault:`/`aws:` prefix; or 32+ chars hex/base64), an inline orange warning appears below the field: *"⚠ This looks like a literal credential, not a secret-store key…"*. Non-blocking — operator can still submit (lab dev mode), but they see the warning before the gateway silently fails. Wired via `data-secret-ref-input` attribute on every `_ref` input + per-input `input` + `blur` listeners.

Live-verified: pasting `Ov23li…<redacted client id>` (real GitHub OAuth client_id format) into `client_id_ref` renders the warning instantly.

### U7 — Periodic capability-sync scheduler resolves principal_id for authcode (~½ day, shipped)

Earlier slates fixed the manual `/sync` endpoint to resolve `operator email → user_id` and pass `principal_id`. The periodic scheduler (`PeriodicCapabilitySyncScheduler` in [`src/vyuu_gateway/capabilities/scheduler.py`](src/vyuu_gateway/capabilities/scheduler.py)) was still calling `sync_server_capabilities` without a principal_id, so periodic auto-sync of `auth_authcode` upstreams silently failed (logged as `capability_sync_per_server_failed`).

The scheduler doesn't have an inbound user context, so it can't use the operator-email mapping. Fix: query `oauth_user_tokens` for any user who has Connected to this server and use that user's stored token. Pick the **most-recently-refreshed** one (lowest chance of being expired by the time the probe runs).

New `_resolve_authcode_principal(session, tenant_id, server_id)` returns:
- `None` for non-authcode servers (existing behavior — provider ignores).
- A `UUID` for authcode servers with at least one stored token.
- `_SKIP_AUTHCODE_NO_TOKEN` sentinel for authcode servers with no token rows yet — caller logs `capability_sync_skipped_no_authcode_token` and skips. The next operator-side Test connect or portal Connect re-authorises and the next tick succeeds.

3 new tests in [`tests/capabilities/test_scheduler.py`](tests/capabilities/test_scheduler.py):
- Authcode + multiple tokens → freshest user wins
- Authcode + no tokens → skipped (sync NOT called)
- Non-authcode → existing behavior unchanged (principal_id=None)

`_FakeSession` extended with `get(McpServer, ...)` + OAuthUserToken-aware `scalar()` + `oauth_tokens` parameter.

### U11 — Initial Access Token (RFC 7591 §3) for enterprise DCR (~1 day, shipped)

Some enterprise OAuth servers (Okta tenants, certain Auth0 configurations, private B2B IdPs) gate the registration endpoint behind a Bearer IAT — a token that's only issued via the vendor dashboard. Public SaaS DCR servers (Notion, Linear, Cloudflare, Sentry, etc.) accept unauthenticated registration; enterprise IdPs don't. Without this, U9's DCR client surfaced a "vendor may require an Initial Access Token" error and operators had to fall back to the static-creds path, defeating the "no per-vendor setup" promise of DCR.

Single optional field on every layer:

| Layer | Change |
|---|---|
| [`registry/schemas.py`](src/vyuu_gateway/registry/schemas.py) | New `OAuthAuthCodeSpec.initial_access_token_ref: str = ""` field (max 1024). Validator unchanged — the field is allowed in any state but only consulted when `dcr_enabled=True`. |
| [`upstream/oauth_dcr.py`](src/vyuu_gateway/upstream/oauth_dcr.py) | `discover_and_register()` accepts `initial_access_token: str \| None = None`. When set, attaches `Authorization: Bearer <iat>` to the RFC 7591 registration POST. Headers built into a dict so the existing `Accept: application/json` stays. |
| [`api/oauth_authcode.py`](src/vyuu_gateway/api/oauth_authcode.py) `_resolve_client_id_and_auth_url` | Reads `spec.initial_access_token_ref`, resolves it via the SecretStore, passes the resolved token to `discover_and_register`. SecretStore lookup failure surfaces as 502 with the ref name in the detail. |
| [`api/operator_ui.py`](src/vyuu_gateway/api/operator_ui.py) | New optional `Initial Access Token ref` input below the DCR banner. Only visible in DCR mode (`data-authcode-dcr-only`). Marked `data-secret-ref-input` so it gets U8's literal-credential warning too. Hint copy explains when operators need to fill it in. |

3 new tests in [`tests/upstream/test_oauth_dcr.py`](tests/upstream/test_oauth_dcr.py):
- IAT provided → stub AS observes `Bearer <iat>` on the registration POST + returns the issued client_id.
- AS gates registration behind IAT + caller didn't provide one → DCR fails at `registration` step.
- No IAT provided to an ungated AS → no `Authorization` header sent (opt-in, not always-on).

Live-verified: ticking the wizard's DCR toggle reveals the IAT field; toggling DCR off hides it again.

### Files changed (summary)

| File | What |
|---|---|
| [`src/vyuu_gateway/registry/schemas.py`](src/vyuu_gateway/registry/schemas.py) | U11 — `initial_access_token_ref` on `OAuthAuthCodeSpec` |
| [`src/vyuu_gateway/upstream/oauth_dcr.py`](src/vyuu_gateway/upstream/oauth_dcr.py) | U11 — `initial_access_token` kwarg, conditional `Authorization: Bearer` on registration POST |
| [`src/vyuu_gateway/api/oauth_authcode.py`](src/vyuu_gateway/api/oauth_authcode.py) | U11 — IAT ref resolution in `_resolve_client_id_and_auth_url` |
| [`src/vyuu_gateway/capabilities/scheduler.py`](src/vyuu_gateway/capabilities/scheduler.py) | U7 — `_resolve_authcode_principal` + sentinel + sync wiring |
| [`src/vyuu_gateway/api/operator_ui.py`](src/vyuu_gateway/api/operator_ui.py) | U8 — relabel `_ref` fields + soft-validation; U11 — IAT input + CSS for warning + `.secret-ref-warn` style |
| [`tests/capabilities/test_scheduler.py`](tests/capabilities/test_scheduler.py) | U7 — 3 new tests + `_FakeSession.get()` + OAuthUserToken-aware scalar |
| [`tests/upstream/test_oauth_dcr.py`](tests/upstream/test_oauth_dcr.py) | U11 — 3 new tests + stub `require_iat` mode |

### Backlog state after this round

- ✅ U6 (catalog), U7, U8, U9 (PKCE+DCR), U10 (auto-recovery), U11 (IAT), U12 (wizard checkbox) — **all closed**
- The remaining pending items in BACKLOG.md predate this DCR run

---

## Sub-session update — 2026-05-03 (DCR auto-recovery on `invalid_client` — closes U10)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway_test \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest tests/ --ignore=tests/perf      # 941 passed, 1 skipped (+2 from this slate)
ruff check src/ tests/                  # All checks passed!
mypy src/vyuu_gateway                   # Success: no issues found in 120 source files
```

### What this slate ships

The DCR work earlier today (U9) registered the gateway as an OAuth client at the upstream AS on first Connect. **U10** handles the failure mode where those credentials get evicted later:

- Operator manually deleted the gateway's app from the vendor dashboard.
- AS implementation cycled internal state and dropped the client.
- AS idle-timeout policy expired the client.

Without recovery, the next token refresh 401s with `error=invalid_client`, capability sync fails, and the operator has to manually wipe the `mcp_server_dcr_clients` row + force users to re-Connect. U10 automates the cleanup so the system self-heals.

### Behavior

When the gateway's token endpoint call returns 401/400 with body `{"error": "invalid_client", ...}` (RFC 6749 §5.2) **and** the upstream is `dcr_enabled`:

1. Drop the stale `mcp_server_dcr_clients` row.
2. Drop **every** `oauth_user_tokens` row for this server (refresh tokens were issued under the dead client_id and won't survive re-registration).
3. Raise `OAuthTokenError` with actionable text: *"upstream OAuth client credentials were revoked by the authorization server — gateway has dropped the stale DCR registration. Reconnect from /portal to issue fresh credentials."*
4. The next operator-side `/operator-initiate` (or portal `/initiate`) hits the existing lazy-DCR helper from U9 — sees no `mcp_server_dcr_clients` row → re-runs discovery + registration → gets a fresh `client_id` → caches it.

Static-creds (non-DCR) servers are unaffected — `invalid_client` from a GitHub-style upstream gets the existing generic error treatment because the operator's vendor dashboard owns the lifecycle there; nuking stored user tokens automatically would be the wrong call.

### Files added / changed

| File | Change |
|---|---|
| [`src/vyuu_gateway/upstream/oauth_authcode.py`](src/vyuu_gateway/upstream/oauth_authcode.py) | New `_looks_like_invalid_client(response)` helper detects RFC 6749 §5.2 shape (4xx + JSON `error: invalid_client`). New `OAuthAuthCodeTokenProvider._invalidate_dcr_state()` method drops the dcr_clients row + all oauth_user_tokens for the server, with a structured log line. `_refresh_in_place` calls it on detection (only when `dcr_enabled`). |
| [`src/vyuu_gateway/api/oauth_authcode.py`](src/vyuu_gateway/api/oauth_authcode.py) | Callback path same detection — covers the rare race where the AS evicts our creds between authorize and token exchange. Returns 409 with "Reconnect required" instead of generic 502. |
| [`tests/upstream/test_oauth_authcode.py`](tests/upstream/test_oauth_authcode.py) | Two new tests: `test_refresh_invalid_client_drops_dcr_state_and_user_tokens` verifies cleanup fires + correct DELETE statements run; `test_refresh_invalid_client_skipped_for_static_creds_servers` verifies non-DCR servers keep the existing generic-error path. `_FakeSession` extended with `execute()` recorder + optional `dcr_client` slot for `get(McpServerDcrClient, ...)`. |

### Live verification

Validated end-to-end against real Notion, walking the full lifecycle:

```bash
# Starting state: dcr row + stored token for the Notion server
SELECT client_id FROM mcp_server_dcr_clients WHERE server_id='8951f62b-...';
# htnVLUEG8A1rH0qw

# Manually trigger _invalidate_dcr_state() (mimics what the refresh
# path does on a real invalid_client from Notion)
python3 -c "...provider._invalidate_dcr_state()"
# WARNING dcr_client_invalidated_state_dropped

# Both rows wiped:
SELECT count(*) FROM mcp_server_dcr_clients WHERE server_id='8951f62b-...'  # 0
SELECT count(*) FROM oauth_user_tokens      WHERE server_id='8951f62b-...'  # 0

# Next /operator-initiate runs DCR against real Notion again:
POST /api/v1/oauth-authcode/8951f62b-.../operator-initiate
# 200 OK with authorization_url containing client_id=GaVQjfcQOKcsPSX3
# (Notion issued a brand-new client; persisted to dcr_clients)
```

The full self-heal loop ran without operator intervention — the next user Connect/Test connect just works.

### Known limitations

- **Refresh attempt that triggered cleanup still fails.** We can't transparently retry the refresh because the user's refresh_token was minted under the dead client_id. The user gets the actionable error message and re-Connects (one-click in /portal). Truly transparent retry would require a fresh OAuth round trip mid-tool-call — not worth the complexity.
- **Periodic scheduler doesn't re-Connect users automatically.** If the scheduler triggers cleanup, all users see "not connected" until they re-Connect via /portal. Acceptable — vendor evictions are rare; users notice quickly.

### Bonus — U12 wizard DCR checkbox (also shipped this round)

Operators registering DCR-capable upstreams not yet in the catalog (Sentry, HuggingFace, PayPal, Cloudflare Workers, etc.) no longer need to POST to `/api/v1/servers` with curl. Step 3 of the wizard now has a "Use Dynamic Client Registration" checkbox above the existing DCR banner. New `setDcrMode(enabled)` helper in `operator_ui.py` keeps three surfaces in lockstep — visible checkbox, hidden `auth_authcode_dcr_enabled` input (read by `serializeAuthFields`), and `body[data-authcode-mode]` (drives CSS that hides static ref fields + reveals the banner). Catalog clicks now route through the same helper, so the toggle reflects the operator's catalog choice. The live-preview manifest mirrors `dcr_enabled: true` in the JSON, and the checklist gate switches to "DCR enabled + redirect_uri" (both green by default) so the operator can advance to step 5 and submit. Live-verified end-to-end. Files: [`src/vyuu_gateway/api/operator_ui.py`](src/vyuu_gateway/api/operator_ui.py) (HTML + CSS + JS).

---

## Sub-session update — 2026-05-03 (OAuth 2.1 PKCE + Dynamic Client Registration — zero-setup MCP connectors)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway_test \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest tests/ --ignore=tests/perf      # 939 passed, 1 skipped (+9 from this slate)
ruff check src/ tests/                  # All checks passed!
mypy src/vyuu_gateway                   # Success: no issues found in 120 source files
```

### What this slate ships

The connector catalog from earlier today (8 SaaS cards) wired Notion + Linear with `auth_authcode` + placeholder OAuth-app refs. Notion's hosted MCP doesn't actually use the create-an-OAuth-app-in-dashboard flow — it implements **OAuth 2.1 with Dynamic Client Registration (RFC 7591)**, the modern MCP-Auth standard. Without DCR support, operators couldn't use the Notion card without first creating a "Public integration" in Notion's developer settings. That defeats the catalog's "no per-vendor setup" value.

This slate adds:

1. **PKCE (RFC 7636)** to the existing authcode flow — required by OAuth 2.1; benefits both static-creds (GitHub) and DCR (Notion/Linear) paths.
2. **Full DCR client** (RFC 9728 → 8414 → 7591) that auto-discovers a vendor's authorization server metadata and registers the gateway as an OAuth client on first Connect — no operator dashboard work.
3. **`mcp_server_dcr_clients` table** to persist the DCR-issued credentials (one row per server, lazy-populated on first /initiate call).
4. **Catalog + wizard updates** so DCR-capable vendors (Notion, Linear today; any future spec-compliant MCP) are flagged with an `auto OAuth (DCR)` badge and the wizard hides the static-creds inputs in DCR mode.

### Coverage — what works automatically with this slate

| Coverage tier | What happens | Examples |
|---|---|---|
| **Tier 1 — Zero setup** | Operator clicks catalog card → Register → Test connect → done. Gateway DCRs itself, runs OAuth, gets tokens. | Notion, Linear, Anthropic-hosted MCPs, Cloudflare, Sentry, anything built on the official MCP SDK |
| **Tier 2 — Static OAuth** | Operator creates OAuth App in vendor dashboard, pastes client_id/secret refs into wizard, then Connect. | GitHub, Google Workspace, Atlassian (legacy) — vendors that pre-date the MCP-Auth spec |
| **Tier 3 — Hybrid (IAT)** | Pending: vendor requires Initial Access Token (RFC 7591 §3) — some Okta / Auth0 enterprise tenants. Backlogged. | n/a today |

### How DCR works end-to-end (first Connect on a fresh server)

1. **Probe** — gateway POSTs `initialize` to `server.source_location` unauthenticated.
2. **WWW-Authenticate hint** — vendor returns `401` with `Bearer realm="OAuth", resource_metadata="..."`.
3. **Resource metadata** (RFC 9728) — GET that URL → returns `authorization_servers: [...]`.
4. **AS metadata** (RFC 8414) — GET `<as>/.well-known/oauth-authorization-server` → returns `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `code_challenge_methods_supported`.
5. **Register** (RFC 7591) — POST our client metadata to `registration_endpoint` → vendor returns `client_id` (+ optional `client_secret`).
6. **Persist** — write a row to `mcp_server_dcr_clients` keyed by `server_id`. All subsequent Connects (any user) reuse this row — DCR runs at most once per server.
7. **Authorize URL** — gateway uses the auto-discovered `authorization_endpoint` + DCR-issued `client_id` to build the standard OAuth-authcode URL with PKCE.

### Live verification against real Notion

```bash
# Register a Notion server with the catalog payload (no client refs):
POST /api/v1/servers
{
  "display_name": "Notion (DCR)",
  "source_type": "http",
  "source_location": "https://mcp.notion.com/mcp",
  "transport": "streamable_http",
  "auth_authcode": {
    "dcr_enabled": true,
    "scopes": [],
    "redirect_uri": "http://localhost:8000/api/v1/oauth-authcode/callback"
  }
}
# → 201 Created

# Trigger Test connect — this fires DCR for the first time:
POST /api/v1/oauth-authcode/{server_id}/operator-initiate
# → 200 OK with authorization_url containing:
#   - https://mcp.notion.com/authorize    (auto-discovered)
#   - client_id=htnVLUEG8A1rH0qw          (just issued by Notion's /register)
#   - code_challenge=...&code_challenge_method=S256  (PKCE)
#   - state JWT carrying code_verifier

# DB now has the row:
SELECT client_id FROM mcp_server_dcr_clients;
# htnVLUEG8A1rH0qw

# Second call to operator-initiate — same client_id, still 1 row (cached).
```

### Files added / changed

| File | Change |
|---|---|
| [`src/vyuu_gateway/upstream/oauth_dcr.py`](src/vyuu_gateway/upstream/oauth_dcr.py) | NEW — `discover_and_register()` runs the full RFC 9728 → 8414 → 7591 dance. HTTPS-only enforcement at every step (MITM defense). Surfaces step-named errors so operators see e.g. "DCR failed at registration: vendor may require an Initial Access Token". |
| [`src/vyuu_gateway/db/models.py`](src/vyuu_gateway/db/models.py) | NEW — `McpServerDcrClient` ORM model (PK `server_id`, columns: `client_id`, `client_secret`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `registration_response`, tenant-scoped). |
| [`migrations/versions/20260503_0013_dcr_clients.py`](migrations/versions/20260503_0013_dcr_clients.py) | NEW — table + RLS policy. |
| [`src/vyuu_gateway/registry/schemas.py`](src/vyuu_gateway/registry/schemas.py) | `OAuthAuthCodeSpec.dcr_enabled: bool = False` field. URL/ref required-field validators relax when `dcr_enabled=true` (those values come from runtime discovery + DCR). |
| [`src/vyuu_gateway/upstream/oauth_authcode.py`](src/vyuu_gateway/upstream/oauth_authcode.py) | `OAuthAuthCodeConfig.dcr_enabled` flag + `_resolve_client_creds()` that pulls from `mcp_server_dcr_clients` instead of SecretStore in DCR mode. Token refresh path supports both confidential (Basic auth) and public (`client_id` in body) clients. |
| [`src/vyuu_gateway/api/oauth_authcode.py`](src/vyuu_gateway/api/oauth_authcode.py) | PKCE: `_generate_pkce_pair()`, `code_verifier` embedded in state JWT, `code_challenge=...&code_challenge_method=S256` in authorize URL, callback echoes `code_verifier` to token endpoint. New `_resolve_client_id_and_auth_url()` helper handles both static + DCR modes (lazy-registers + persists DCR row on first call). Both `/initiate` endpoints + the `/callback` use the helper. |
| [`src/vyuu_gateway/upstream/provider.py`](src/vyuu_gateway/upstream/provider.py) | Wires `dcr_enabled` from spec to `OAuthAuthCodeConfig`. |
| [`src/vyuu_gateway/upstream/connector_catalog.py`](src/vyuu_gateway/upstream/connector_catalog.py) | `ConnectorTemplate.dcr_enabled: bool = False` field. Notion + Linear templates flipped to DCR mode (their oauth_authcode JSON drops static URLs/refs, sets `dcr_enabled: true`). |
| [`src/vyuu_gateway/api/connector_catalog.py`](src/vyuu_gateway/api/connector_catalog.py) | Response schema exposes `dcr_enabled` so the UI renders the badge. |
| [`src/vyuu_gateway/api/operator_ui.py`](src/vyuu_gateway/api/operator_ui.py) | Wizard step-3 banner appears when `body[data-authcode-mode="dcr"]`; the four static-fields collapse via CSS. Catalog click sets the mode + flips a hidden `auth_authcode_dcr_enabled` input that `serializeAuthFields()` merges into the assembled JSON. Cards show "auto OAuth (DCR)" suffix in the meta line. |
| [`tests/upstream/test_oauth_dcr.py`](tests/upstream/test_oauth_dcr.py) | NEW — 8 tests against an ASGI stub mimicking real Notion: happy path with confidential client, public client (no secret), WWW-Authenticate hint missing → fall back to well-known, no `registration_endpoint` → DCR not supported, plaintext discovery URL rejected, IAT-required hint surfaced. |
| [`tests/users/test_oauth_authcode_api.py`](tests/users/test_oauth_authcode_api.py) | NEW PKCE round-trip test: state JWT carries `code_verifier`, authorize URL has `code_challenge_method=S256`, hash matches verifier. |
| [`tests/api/test_connector_catalog.py`](tests/api/test_connector_catalog.py) | DCR connectors skip static-fields validation. |
| [`tests/tenant_isolation/test_tenant_isolation.py`](tests/tenant_isolation/test_tenant_isolation.py) | New `mcp_server_dcr_clients` added to expected tenant-scoped tables set (this test catches future tables without RLS — exactly its job). |

### Security posture

- **HTTPS-only discovery** — every URL in the discovery chain (resource metadata, AS metadata, registration, authorize, token) is verified to use HTTPS. Plaintext rejected with a step-named error.
- **PKCE S256 mandatory** in our outbound flow — even confidential clients send it. Code interception attacks (RFC 7636 §1) blocked.
- **Tenant-scoped DCR rows** — `mcp_server_dcr_clients` has the same RLS posture as `oauth_user_tokens`. The gateway's `bind_tenant_context` GUC scopes reads.
- **No Initial Access Token support yet** — vendors that require IAT at `/register` (some Okta tenants) are out of scope for v1; DcrError surfaces the failure with a hint pointing operators at the static-creds path.

### Known limitations

- **Re-registration on `invalid_client` not yet automatic.** If the AS evicts our DCR-issued credentials, sync would 401. Today the operator deletes the `mcp_server_dcr_clients` row manually + re-Connects to trigger a fresh registration. Backlog item.
- **Software statements (RFC 7591 §2.3) not supported.** Vendors requiring signed JWT proof of identity at registration would fail with "Initial Access Token" hint (close enough — both are dashboard-issued tokens). No public SaaS uses this today.
- **Periodic capability-sync scheduler** still doesn't resolve `principal_id` for authcode upstreams (U7 from earlier today). Independent of DCR — same fix applies once shipped.

---

## Sub-session update — 2026-05-03 (Perf P1.1+P1.4, SaaS connector catalog, auth_authcode chicken-and-egg fix)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway_test \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest tests/ --ignore=tests/perf      # 930 passed, 1 skipped
ruff check src/ tests/                  # All checks passed!
mypy src/vyuu_gateway                   # Success: no issues found in 119 source files
```

This sub-session shipped four loosely-coupled slates. Each one is described separately below; they all share the same final test/lint/mypy posture above.

### 1 · QA-backlog perf items P1.1 + P1.4 — flame graph + spike test

Two items from `docs/QA-BACKLOG.md` Tier-1 closed.

**P1.4 — Spike test** ([`tests/perf/spike_test.py`](tests/perf/spike_test.py))

Synchronized 0→N barrier-released burst harness. Two passes (under-cap 100, over-cap 150) × 3 spikes each, with an independent `/healthz` pinger on its own httpx client. Over-cap pass returned **22 clean 503s — exactly `150−128`** — proving the inflight gate works under burst.

But the run also surfaced two real, previously-hidden bottlenecks:

- **Audit DB pool exhaustion** — 59× `QueuePool limit of size 20 overflow 40 reached` errors. The 60-connection ceiling is fine for the steady-state soak but breaks under a synchronized 100-burst.
- **MCP stdio queue tail** — 220-second `latency_ms_total` on some calls. The 4-slot persistent stdio pool can't drain a 100-burst within the harness 30s timeout, so spike 2 lands on a wedged system.

Mitigations + operational guidance written into [`docs/STRESS-TESTING.md`](docs/STRESS-TESTING.md) §12.6.

**P1.1 — CPU flame graph** ([`tests/perf/results/flame-2026-05-03.svg`](tests/perf/results/flame-2026-05-03.svg))

py-spy needs root on macOS (SIP), so pivoted to `cProfile` + `flameprof` via [`tests/perf/lab_for_profile.py`](tests/perf/lab_for_profile.py). Captured 60s under 32 in-flight load. Top findings written into `docs/STRESS-TESTING.md` §13:

1. **Sync `psycopg2` driver under async code** — 8.79s self time on `connection.wait` (31% of profile). [`src/vyuu_gateway/db/session.py:11`](src/vyuu_gateway/db/session.py:11) uses sync `create_engine`. Migrating to `asyncpg` is the biggest single win.
2. **`resolve_tools` runs once per call with no caching** — 14.32s cumulative across 10,030 calls. LRU cache on `(vserver_id, tool_name)` would shave ~30%.
3. **~8 SQL queries per tool call** — 80,276 SQL execs across ~10K calls. Worth a focused audit.
4. **SQLAlchemy compilation overhead** is ~2.4s self time across `cache_key`, `coercions`, `_maybe_prepare_gen`.

Optimization queue ranked by measured impact in §13.5. Not shipped — these are *measurement-backed prioritization* for any future single-worker RPS sprint.

### 2 · SaaS connector catalog (Quick add from catalog)

User asked for "pre-populated MCP servers section in MCP tab" so customers don't have to remember 8 vendors' OAuth URLs and upstream endpoints. Eight connectors shipped: GitHub Copilot, Notion, Linear, Jira, Confluence, Slack, Microsoft 365, Asana. Card grid sits above the existing MCP-servers table; click a card → existing 5-step register wizard opens with everything pre-filled.

**Architecture choice — extend, don't rebuild.** The wizard's existing OAuth-preset popover (`OAUTH_PROVIDER_PRESETS` in `operator_ui.py:8609`) covers the OAuth-metadata half. The catalog adds the runtime/source-URL/transport pre-fill on top. No new submit endpoint — clicking a card primes the form; the existing `POST /api/v1/servers` does the registration.

**Files added/changed:**

- [`src/vyuu_gateway/upstream/connector_catalog.py`](src/vyuu_gateway/upstream/connector_catalog.py) — typed `ConnectorTemplate` dataclass + 8-entry `CONNECTOR_CATALOG`. Extending: append a `ConnectorTemplate`, restart, UI auto-renders.
- [`src/vyuu_gateway/api/connector_catalog.py`](src/vyuu_gateway/api/connector_catalog.py) — `GET /api/v1/operator/connector-catalog` endpoint (operator-bearer scoped, read-only, no DB writes). Wired in `main.py`.
- [`src/vyuu_gateway/api/operator_ui.py`](src/vyuu_gateway/api/operator_ui.py) — new "Quick add from catalog" panel (HTML + CSS + JS). The `applyConnectorTemplate(tpl)` JS sets the runtime radio, display_name, source_location, transport, auth_mode, then calls the existing `applyPresetToStructuredFields()` for OAuth subfields. No duplication of preset machinery.
- [`tests/api/test_connector_catalog.py`](tests/api/test_connector_catalog.py) — 9 tests (catalog schema invariants + endpoint payload shape + auth requirement).
- [`docs/ADMIN-GUIDE.md`](docs/ADMIN-GUIDE.md) §5.0 — documents the catalog and how to extend it.

### 3 · auth_authcode chicken-and-egg fix (the deeper issue surfaced by the catalog)

The catalog made one platform UX gap immediately visible: registering an OAuth-authcode upstream (e.g. GitHub Copilot MCP) hits a chicken-and-egg loop the operator can't escape:

1. Sync needs an OAuth bearer to talk to GitHub
2. Bearer requires a user to complete `Connect → GitHub` in /portal
3. Connect button in /portal only renders for users granted access to a vserver wrapping this upstream
4. Publishing a vserver requires synced tools

**Three fixes shipped, in order of dependency:**

**3a. Skip auto-sync at registration when only `auth_authcode` is configured.** New `_only_authcode()` in [`src/vyuu_gateway/api/servers.py`](src/vyuu_gateway/api/servers.py). Without this, the auto-sync background task (Tier-1 stress fix from a prior session) hits the upstream 5× → 401 cascade → `CircuitBreakerOpenError` → confusing 502 cascade for the operator. Other auth modes (M2M, JWT-bearer, env, passthrough, mTLS, no-auth) keep their auto-sync.

**3b. Translate manual-sync 502 → friendly 412 when authcode + no token.** New `_maybe_raise_authcode_no_token()` in `servers.py`. Runs only on the failure path so happy-path scalar() counts in unit tests are unchanged. Returns:

> Cannot sync — this server uses per-user OAuth (auth_authcode) and no user has authorized it yet. Click Connect → on this row to authorize at least one user, then click Sync.

**3c. Operator-side "Test connect" — the actual fix.** Operators can't bounce through /portal to test a brand-new upstream because portal-side Connect requires vserver access (which requires synced tools, which requires the token we're trying to mint). New endpoint + button:

- **Endpoint** `POST /api/v1/oauth-authcode/{server_id}/operator-initiate` (in [`src/vyuu_gateway/api/oauth_authcode.py`](src/vyuu_gateway/api/oauth_authcode.py)). Operator-bearer authed. Looks up the operator's email via `operators` table → finds matching `users` row by `(tenant_id, email)` (PLATFORM.md §3.1: bootstrap maps operator email → user email 1:1). If no matching user → 412 with "Sign into /portal once to provision your user record." Otherwise mints the same state JWT the portal flow uses, carrying that user_id, returns the GitHub authorize URL. Reuses every callback / token-write path unchanged.
- **UI** "Test connect" button on the MCP-servers row, visible only when `auth_authcode` is set. Click → calls the endpoint → opens IdP authorize URL in a new tab → user approves → callback writes token under operator's underlying portal user.

**Tests:** 4 new in [`tests/users/test_oauth_authcode_api.py`](tests/users/test_oauth_authcode_api.py) — happy path resolves user_id, 412 when no matching user, 400 when server lacks auth_authcode, 401 when no operator bearer.

### 4 · principal_id threading through capability sync chain (the bug 3a/3b/3c masked)

Even with a stored `oauth_user_tokens` row from the Test connect flow, **Sync still 502'd** with `HTTPStatusError` (401 from GitHub). Root cause: `StreamableHttpMcpClient.list_capabilities()` used a cached pooled session WITHOUT calling `_build_per_call_overrides`. So for `auth_authcode` upstreams, sync's outbound call carried NO `Authorization` header regardless of stored tokens. Tool calls worked because they go through `_call_session` which builds per-call overrides; sync skipped that entire path.

**Fix:** thread `principal_id` through every layer of the capability sync chain so the OAuth bearer is attached to sync probes.

**Layers updated:**

| File | Change |
|---|---|
| [`src/vyuu_gateway/mcp/outbound.py`](src/vyuu_gateway/mcp/outbound.py) | `OutboundMcpClient` Protocol + StreamableHttp / SSE / stdio impls accept `principal_id`. HTTP impl uses `_build_per_call_overrides(None, principal_id=...)` — empty per_call → cached session, present per_call → one-shot session with OAuth bearer baked in. Stdio ignores it (auth via env vars). |
| [`src/vyuu_gateway/upstream/pool.py`](src/vyuu_gateway/upstream/pool.py) | `PooledOutboundMcpClient.list_capabilities` threads kwarg through pool wrapper. |
| [`src/vyuu_gateway/capabilities/client.py`](src/vyuu_gateway/capabilities/client.py) | `McpCapabilityClient.list_capabilities` Protocol updated. |
| [`src/vyuu_gateway/capabilities/upstream_adapter.py`](src/vyuu_gateway/capabilities/upstream_adapter.py) | Adapter forwards principal_id. |
| [`src/vyuu_gateway/capabilities/sync.py`](src/vyuu_gateway/capabilities/sync.py) | `DatabaseCapabilitySyncService.sync_server_capabilities` accepts + forwards principal_id. |
| [`src/vyuu_gateway/capabilities/fake_client.py`](src/vyuu_gateway/capabilities/fake_client.py) | Test fixture matches signature. |
| [`src/vyuu_gateway/api/servers.py`](src/vyuu_gateway/api/servers.py) | New `_resolve_operator_user_id()` uses a fresh `SessionLocal()` (NOT the request-scoped session) so it doesn't disturb test mocks' scalar queue. Manual sync endpoint resolves operator email → user_id → passes to sync_service. |
| [`examples/drawio_lab_server.py`](examples/drawio_lab_server.py) | `_LoggingUpstreamClient.list_capabilities` accepts kwarg. |
| Test stubs updated in [`tests/api/test_capability_sync_and_vservers.py`](tests/api/test_capability_sync_and_vservers.py), [`tests/capabilities/test_scheduler.py`](tests/capabilities/test_scheduler.py). |

**Live verification:** registered GitHub Copilot from catalog → Test connect → completed real OAuth at GitHub → clicked Sync → **HTTP 200, 43 capabilities discovered** (2 prompts + 41 tools: `get_me`, `search_repositories`, `create_pull_request`, `search_code`, etc.).

### Known gaps deferred to backlog

- **U7 — Periodic capability-sync scheduler resolves principal_id for authcode upstreams.** The scheduler in `capabilities/scheduler.py` still calls `sync_server_capabilities` without principal_id. Periodic auto-sync of authcode upstreams silently fails (logged as `capability_sync_per_server_failed`). Fix: in the scheduler, for each server with `auth_authcode` set, query the most-recently-refreshed `oauth_user_tokens.user_id` for that server. Half-day. Tracked in BACKLOG.md.
- **U8 — Wizard step-3 `_ref` field labeling.** Operators (including the assistant in this session) frequently paste literal OAuth values into `client_id_ref` / `client_secret_ref` instead of secret-store keys. Resolver then returns `placeholder-<value>` which fails OAuth at the IdP without a clear error. Two-hour fix: rename labels + soft-validation hint when the value shape looks like a credential. Tracked in BACKLOG.md.

### How to resume

```bash
# Lab is already configured to use API-key identity + GitHub OAuth
# creds via .claude/launch.json. To start cleanly:
pkill -f lab_with_metrics 2>/dev/null
python3 examples/drawio_lab_server.py    # via launch.json env-vars
# Or use the preview server: preview_start({name: "drawio-lab"})

# /operator → MCP servers → Quick add from catalog grid (8 cards)
# Click GitHub Copilot MCP → wizard pre-filled → step 5 Register
# Click Test connect on the new row → OAuth in new tab → approve
# Click Sync → 43 capabilities discovered
# Click Publish vserver → drawer lists tools → pick subset → publish

# Operator bearer (lab seed):
#   eyJ0ZW5hbnRfaWQi…<lab token>
# Portal user (operator's underlying user, for Connect from /portal):
#   email: lab-operator@example.com
#   password: LabOperator-2026!
# Other portal user (granted access to existing vservers):
#   email: krishna@vyuulab.io
#   password: LabUser-2026!
```

---

## Sub-session update — 2026-05-02 (NHI hover full-entrail BFS + Identities user-graph 4-column redesign)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 868 passed, 0 skipped (unchanged — pure UI work)
ruff check src tests  # All checks passed!
mypy src tests  # Success: no issues found in 193 source files
```

### What this sub-session shipped

User screenshotted the NHI map + an Identities individual-user graph with 56 falcon-mcp tools in a radial concentric layout. Two specific asks:

1. **NHI hover** — "if I hover the user it should show his entrail, not just the next node." The previous `setHighlight` only lit 1-hop neighbours, so hovering a user lit only their AI-app cards — not the chain of MCPs, tools, and risks the user actually reaches.
2. **Identities user graph** — "totally messed up, can you make it bit more beautified." The radial concentric layout collapsed past ~15 tools per ring; falcon-mcp's 56 capabilities turned the outer ring into an unreadable label-pile.

Both shipped.

### 1 · NHI hover: directional-flow highlight (ancestors ∪ descendants)

`src/vyuu_gateway/api/operator_ui.py` `setHighlight` rewritten **twice** in this sub-session:

1. **First pass — undirected BFS over connected component.** Lit too much: in a Sankey-style graph where every column shares the same far ends (every user → every AI app → every MCP), undirected BFS from any single node reaches the entire canvas. Hovering one node lit all 7 users, all 4 AI apps, all 4 MCPs.

2. **Second pass (shipping) — directional traversal through the hovered node.** Computes:
   - `ancestors`   — every node from which you can REACH nodeId by walking forward (source → target) edges
   - `descendants` — every node REACHABLE FROM nodeId by walking forward edges
   Lit nodes = ancestors ∪ descendants. Lit edges = edges whose both endpoints fall within the same side (the union covers seam-edges incident to nodeId since nodeId belongs to both sets).

Concrete effect: hovering `filesystem MCP` now lights only the 1-2 users who actually reach it, the 1-2 AI apps that route to it, the MCP itself, and the agents/tools/risks it fans out to — exactly what the user requested with their reference screenshot ("hover over second column node only related nodes are highlighted"). Every unrelated peer in every column dims to opacity 0.05/0.18 so the operator's eye snaps straight to the impact subgraph.

### 2 · Identities user-graph 4-column card layout

Replaces the radial concentric layout. Same visual language as the NHI map for consistency.

**Layout**

- 4 columns, each a vertical stack of rounded-rect cards: `IDENTITY` · `VSERVERS` · `TOOLS EXPOSED` · `UPSTREAM MCPs`
- Card geometry: `CARD_W = 220`, `CARD_H = 36`, `ROW_GAP = 10` — labels live INSIDE the cards (no overlap with edges).
- Bezier edges enter `leftAnchor` / exit `rightAnchor` of cards, coloured by the source column.
- Most-connected card sits at top of each column (Sankey-style — easier to read).
- Tool cards carry a risk-coloured status dot on the LEFT and a small uppercase risk tag on the RIGHT (`READ`, `WRITE`, `DELETE`, etc.) so the operator can scan the tool list and pick out destructive capabilities at a glance.
- Principal card gets a subtle accent ring around its status dot to set it apart visually.

**Containment**

- Wrapped in a new `.identity-graph-frame` div with `max-height: 640px; overflow: auto`. So an upstream like falcon-mcp with 56 tools renders as a long but scrollable column instead of an unreadable ring.

**Interactivity (matches NHI map)**

- Hover-highlight uses the same directional-flow algorithm (ancestors via reverse edges ∪ descendants via forward edges) — hovering a vserver card lights only the principal who reaches it, the vserver itself, the tools it exposes, and the upstream those tools live on. Sibling vservers + their fan-out dim cleanly.
- Click pins focus; click empty space clears it.
- 120ms opacity transitions on cards and edges; saffron drop-shadow on highlighted edges.

**Legend**

- Top row: column-coloured dots for `identity` / `vservers` / `tools exposed` / `upstream mcps`.
- Bottom row (only when at least one tool has a risk_category): `RISK` eyebrow + 8 risk-tone swatches in danger → safe order (admin → delete → credential_access → execute → data_export → write → network → read).

**Visual smoke test**

Synthetic 35-card / 59-edge graph rendered in the lab preview (krishna@vyuulab.io with github-readonly + falcon-mcp-soc-1 + drawio-stdio fan-out). All four columns line up, labels stay inside cards, bezier edges converge cleanly into the upstream column, risk tags read clearly on every tool card, legend + risk row paint at the bottom. Hovering `github-readonly` lit 9 cards (krishna + github-readonly + 6 GitHub tools + github-mcp upstream) and dimmed the other 26 (falcon + drawio columns), confirming the directional traversal.

### Files updated

- `src/vyuu_gateway/api/operator_ui.py`
  - `setHighlight` BFS rewrite in `renderNhiMap` (the NHI map function).
  - `renderIdentityGraph` rewritten as 4-column card layout with hover-highlight + click-focus.
  - New CSS: `.identity-graph-frame`, `.identity-graph-svg .identity-graph-card`, `.identity-graph-edge`, `.identity-graph-edge-hl`, `.identity-graph-legend`, `.identity-graph-risk-legend`, `.identity-graph-legend-dot`, `.identity-graph-legend-eyebrow`.

### Next slates (still open — same as prior sub-session)

- **A4** · 401-driven token refresh on phase-3/phase-4 OAuth (~½ d)
- **H1** · DNS-time SSRF backstop (~½ d)
- **A6.y** · Kubernetes Secrets backend (~1 d)
- **S1.b** · Cosign / Sigstore signature verification (~½ d)
- **H3** · Payload-size limits + response inspection / redaction (½ d for limits, 2-3 d for full redaction)
- **Connections-as-clients panel** — new backend tracking for per-session client_version + device_fingerprint (1.5 d)
- **Anomaly alerts on N1** (~2 d)

---

## Sub-session update — 2026-05-02 (NHI map interactive 5-col redesign + sidebar marks from Vyuu Design System + Capabilities tab removed)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 868 passed, 0 skipped (unchanged from prior sub-session — no new test files; nhi_map test fixture updated to keep tool/risk nodes sanctioned)
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session shipped

User reviewed the operator console against the [Vyuu Design System](local path removed) library and asked for four concrete improvements:

1. **NHI Map** — make it interactive; "the names are going through the lines" (labels overlapping bezier curves).
2. **NHI Map** — add a `tool call` column.
3. **NHI Map** — add a `risk category` toggle option (replaces the tool name as the 5th column).
4. **Capabilities tab** — empty / duplicates the Publish drawer's "tools in this vserver" list. Remove if redundant.
5. **Sidebar tab logos** — replace the geometric placeholders with the Vyuu Design System's product marks.

All five shipped.

### 1 · NHI Map — card-based interactive 5-column layout

**Backend (`src/vyuu_gateway/api/nhi_map.py`)**

- `NhiMapNode.column` literal extended with `tool` and `risk` values.
- New `risk_by_tool: dict[(server_id, tool_name), str]` lookup from `mcp_capabilities` joined inside `get_nhi_map(...)`. Same str-vs-enum coercion as identities.py: `risk.value if hasattr(risk, "value") else (str(risk) if risk else "unknown")`.
- For every audit event with both `upstream_server_id` and `tool`, emit a `tool:<server_id>:<tool>` node and connect it to the upstream MCP node; emit a `risk:<category>` node and also connect it to the upstream MCP node. Tool/risk nodes are always emitted as `sanctioned=True` (the unsanctioned flag is reserved for unrecognized inbound clients — tool/risk are derivative of the MCP server, which itself carries the sanctioned bit).
- Existing test `test_nhi_map_sanctioned_only_drops_unknown_clients` had to be reconfirmed: with the new tool/risk emission, those nodes inherit `sanctioned=True` from the parent server even when the tool isn't found in `mcp_capabilities` (treated as `risk = "unknown"`). The test was already passing under that fixture; left untouched.

**Frontend (`src/vyuu_gateway/api/operator_ui.py` `renderNhiMap`)**

- Replaced the prior naked-text-over-bezier rendering with **rounded-rect cards** (`CARD_W = 200`, `CARD_H = 36`, `ROW_GAP = 14`). Labels live INSIDE the cards now — no more overlap with edges.
- Edges enter from `rightAnchor(card) = {x: card.x + CARD_W, y: card.y + CARD_H/2}` and exit at `leftAnchor(card) = {x: card.x, y: card.y + CARD_H/2}`. Bezier control points placed at the column midline so curves don't graze adjacent cards.
- Hover-highlight: hovering a card calls `setHighlight(nodeId)` which dims (`opacity: 0.25`) all nodes/edges that aren't the hovered node + its 1-hop neighbours via the `.nhi-edge-hl` and `.nhi-card-hl` CSS classes.
- Click-focus: clicking a card pins the highlight (toggle on/off) so the operator can read across the focused subgraph without holding the cursor steady.
- 5th column is gated by a new `<select id="nhi-map-fifth">` with options:
  - `Tools` — emits the `tool:*` nodes as a 5th column (default).
  - `Risk category` — emits the `risk:*` nodes as a 5th column (collapses tool granularity into the 5 risk buckets: read / write / delete / admin / unknown).
  - `Off` — 4-column layout (matches the prior version).
- The toggle filters the cached `_lastNhiMap` FE-side without a refetch — the backend always emits both tool + risk node sets per audit event.
- New CSS (`.nhi-map-svg .nhi-card`, `.nhi-map-svg .nhi-card-hl`, `.nhi-edge`, `.nhi-edge-hl`) keeps the cream/ink palette and uses saffron-orange as the highlight stroke. Cards transition opacity at `120ms ease-out`.

**Verified in preview:** kicked off three GitHub tool calls (`get_me`, `search_repositories`, `list_issues`) to populate the audit ring buffer; map renders as 6 cards across 4 columns by default (user / ai_app / mcp_server / tool) with edges connecting them; toggling to `Risk category` collapses the 5th column to two cards (`read`, `write`); toggling to `Off` removes the 5th column entirely.

### 2 · Capabilities tab removed

The "Capabilities" panel in the operator console had been an empty stub in this codebase for a while; on inspection it was a dupe of the Publish drawer's "Tools in this vserver" list (same data source, same row factory). Removed:

- The `data-nav="capabilities"` sidebar item is gone.
- The `<div data-nav-panel="capabilities">` panel content was replaced with a hidden stub at `~line 737` of `operator_ui.py` (kept as a `style="display:none"` div so any deep-link `#nav=capabilities` fragments fall through to Home rather than 404'ing the JS).
- No backend endpoint was wired to it — nothing to remove server-side.

If we later want a "Capabilities catalog" view (every tool across every server, filterable by risk/source/sanctioned), it would be a new endpoint joining `mcp_servers + mcp_capabilities` directly and not coupled to a specific vserver. Sized as a follow-up if the need surfaces.

### 3 · Sidebar tab logos — replaced with Vyuu Design System marks

The sidebar had been using ad-hoc Lucide-style geometric SVGs. Replaced with proper product marks from the design system:

| Sidebar slot | Mark | Rationale |
|---|---|---|
| Brand block (top) | **ChakravyuhaMark** — 4 concentric arcs + center dot | Vyuu's primary product mark. |
| `NHI map` nav item | **AgentMark** — almond outline + inner ring + dot | NHIs are agent-shaped identities. |
| `Identities` nav item | **AgentMark** | Same family — both surface non-human identity work. |
| `MCP servers` nav item | **McpMark** — two crossing arcs | The design system's purpose-built MCP icon. |
| Other items (vservers / tool calls / api keys / …) | Geometric Lucide-style SVGs | Kept as-is — design system doesn't define marks for those concepts. |

All inline SVGs use `currentColor` for stroke/fill so they tone with the active/hover state of the nav item without needing per-state SVG variants. Active item gets the saffron stroke; hover toggles ink → ink-deep.

### Files updated

- `src/vyuu_gateway/api/nhi_map.py` — tool + risk column emission, `risk_by_tool` lookup, str-vs-enum coercion at boundary.
- `src/vyuu_gateway/api/operator_ui.py` — `renderNhiMap` rewrite (card layout, hover/click interactivity, 5th-column toggle), `_lastNhiMap` cache, sidebar SVG marks (ChakravyuhaMark / AgentMark / McpMark inlined), Capabilities panel hidden stub.
- `.claude/launch.json` — added `VYUU_LAB_USE_API_KEY_IDENTITY=1` plus the GitHub OAuth client_id/secret env vars so `preview_start` brings up a fully-working lab.
- (No new test files; existing `test_nhi_map_sanctioned_only_drops_unknown_clients` continues to pass under the tool/risk-always-sanctioned rule.)

### Quick repro

```bash
# Boot lab on :8000 with all secrets seeded.
python3 examples/drawio_lab_server.py
# Navigate to http://127.0.0.1:8000/operator → NHI map.
# Hover any card to dim the rest of the graph; click to pin focus.
# Toggle the 5th-column dropdown between Tools / Risk category / Off.
```

### Next slates (still open — same as prior sub-session)

- **A4** · 401-driven token refresh on phase-3/phase-4 OAuth (~½ d)
- **H1** · DNS-time SSRF backstop (~½ d)
- **A6.y** · Kubernetes Secrets backend (~1 d)
- **S1.b** · Cosign / Sigstore signature verification (~½ d)
- **H3** · Payload-size limits + response inspection / redaction (½ d for limits, 2-3 d for full redaction)
- **Connections-as-clients panel** — design-mock semantics needs new backend tracking for per-session client_version + device_fingerprint (1.5 d)
- **Anomaly alerts on N1** (~2 d)

---

## Sub-session update — 2026-05-02 (E2E proven + 11 hotfixes + UX-1/2/3 polish)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 868 passed, 0 skipped (+44 vs prior session)
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session delivered

**Proved two end-to-end MCP integrations against real upstreams:**

1. **GitHub Copilot MCP** via `auth_authcode` (OAuth user flow) →
   real `Presidentsu` profile returned through Cursor → Vyuu →
   `https://api.githubcopilot.com/mcp/`. User authorised the lab's
   GitHub OAuth app with `read:user repo read:org` scopes; the
   gateway persisted the access token in `oauth_user_tokens` and
   rides it on every upstream call.
2. **CrowdStrike Falcon MCP** via `auth_env` (stdio + uvx + PyPI) →
   78 real capabilities synced (56 tools + 22 resources). Risk
   classifier correctly toned `falcon_delete_firewall_rule_groups`
   as `delete`, `falcon_add_ioc` as `write`, etc.

### Eleven hotfixes shipped during the E2E run

| # | Where | Fix |
|---|---|---|
| 1 | `examples/drawio_lab_server.py` `_LoggingUpstreamClient.call_tool` | Added missing `inbound_headers` + `principal_id` kwargs (gateway started passing them for `auth_passthrough`); previously every tool call 502'd with `TypeError: got unexpected keyword argument 'inbound_headers'`. |
| 2 | `src/vyuu_gateway/upstream/oauth_authcode.py` `_is_expired` | NULL `expires_at` + NULL `refresh_token` was treated as "expired" — broke GitHub OAuth Apps which return long-lived tokens with neither field. Now: NULL/NULL → trust upstream's indefinite contract. |
| 3 | `src/vyuu_gateway/capabilities/sync.py` `_serialize_drift_for_storage` | `c.kind.value` blew up on the `removed` list (entries from ORM rows where SQLAlchemy surfaces `kind` as a plain str despite the enum type hint). Defensive `_kind_str()` + isinstance check on `risk_category`. |
| 4 | `src/vyuu_gateway/api/operator_ui.py` register form | Added `novalidate` so HTML5 form validation doesn't try to focus `required` inputs hidden inside step-1/step-2 wizard containers (silent submit-abort with no visible error). |
| 5 | `registerServer` JSON-error visibility + mode-aware harvest + invalid-JSON gate | Errors written to `register-output` were invisible (block hidden in wizard). Now: every error path unhides it. Fields irrelevant to the picked auth_mode (e.g. `auth_passthrough` JSON when mode=none) are skipped on submit. Step 5 review checklist gates the Register button on no `<invalid JSON>` sentinels. |
| 6 | `examples/drawio_lab_server.py` `_seed_auth_env_secrets` + `_LabPassThroughSecretStore` | New servers registered after lab boot weren't getting their `auth_env` refs into the in-memory SecretStore → `SecretNotFoundError` → circuit breaker open → 502 forever. Two-layer fix: (a) walk every `mcp_servers` row at boot and seed each ref with the literal value (or env-var override via `LAB_AUTH_ENV_<REF>`), (b) `InMemorySecretStore` subclass that pass-throughs the ref name as the literal value on cache miss — handles runtime registrations without a lab restart. |
| 7 | `src/vyuu_gateway/api/operator_ui.py` row Sync button | Errors went to a hidden `register-output` block (inside the wizard panel). Now: success → inline saffron toast next to the row's actions; failure → opens row drawer in `mode: "sync-error"` with the full upstream stderr (operators can read CrowdStrike's "Failed to authenticate" / GitHub's 401 detail directly). |
| 8 | `src/vyuu_gateway/api/identities.py` `_resolve_risk_lookup` | Same str-vs-enum SQLAlchemy quirk as #3, this time on `mcp_capabilities.risk_category`. Coerce at the boundary: `risk if isinstance(risk, RiskCategory) else RiskCategory(risk)`. Identities tab was 500'ing on every request. |
| 9 | (folded into #6) | `_LabPassThroughSecretStore` — runtime ref pass-through. |
| 10 | `src/vyuu_gateway/api/operator_ui.py` | Helper defined as `escapeHtmlOp` but **15+ call sites used `escapeHtml`** (no `Op` suffix). The Identities renderer hit `ReferenceError: escapeHtml is not defined`. Added a one-line alias. |
| 11 | New `DELETE /api/v1/servers/{id}` endpoint + UI button | Cascade-delete (FK `ondelete=CASCADE` reaps capabilities + vserver_tools + oauth_user_tokens). Returns a counts summary; UI shows a saffron banner above the table on success and the row drawer with the upstream error on failure. New tests: `test_delete_server_cascades_dependents_and_returns_summary`, `test_delete_server_returns_404_for_unknown_id`. |
| 12 | `src/vyuu_gateway/api/inbound_mcp.py` JSON-RPC reply path | Upstream-reported errors (`response.isError=True`) were being **stripped of their content** and replaced with the gateway's generic `"upstream MCP server error: upstream returned an MCP tool error"` wrapper. Operators saw two stacked generic strings instead of the actually-useful upstream message. Fix: when `status == UPSTREAM_ERROR` and `result.response.isError`, pass the upstream's `CallToolResult` through unchanged. Now VT returns `"VirusTotal API error: File 'deadbeef…' not found"`, GitHub returns its rate-limit detail, CrowdStrike returns its scope-required message — directly visible to Cursor / curl. Gateway-initiated failures (timeout, deny, malformed args, unknown tool) still go through the synthesised `_tool_error_payload` path so operators get the gateway's classification for those. |
| 13 | New `src/vyuu_gateway/tool_calls/error_envelope.py` + 39 tests | Hotfix #12 fixed VT specifically; this slate generalises it. Every tool-call error path — gateway-initiated, upstream-`isError`, upstream-system-exception — now flows through one structured envelope. Each error response carries: a bracketed text prefix `[<source> · <category>] <message>` (so any client that just renders `content[0].text` sees the source + classification at a glance), and a `meta["vyuu.error"]` block with `source`, `category`, `retryable`, `correlation_id`, `upstream_server_id`, `upstream_tool_name` (so clients with structured-error awareness can react programmatically — retry on `transient`, re-auth on `auth_failed`, re-prompt on `malformed_args`). Heuristic classifier `classify_upstream_error_text` pattern-matches common phrasings into 9 categories (rate_limited / auth_failed / not_found / timeout / malformed_args / denied_by_policy / tool_not_in_vserver / upstream_internal / transient / unknown), with `unknown` as a deliberate conservative fallback so we don't mis-tag and push clients into wrong recovery actions. The earlier "vyuu wraps with our generic message" path is gone — the envelope IS the unified format. Verified on the same VT bogus-hash call: now returns `source=upstream_mcp / category=not_found / retryable=false`. 39 unit tests cover the classifier matrix + envelope builder + retryable flag per category + the upstream-isError adapter + correlation-id auto-mint when absent. |

### UX-1/2/3 batch — design polish on top of the working E2E

**UX-1 · Env pill bound to real `/api/v1/health`.**

Was hardcoded `gateway · v1.0.0`. Now reads `environment` + `version`
from the health response (e.g. `local · drawio-lab` in the lab).
Status dot turns saffron when healthy, red when fetch fails.

**UX-2 · Tool history KPI rollups + design-aligned table.**

- New backend endpoint `GET /api/v1/portal/{tenant_id}/tool-history-summary?window_days=N`
  returns `{window_days, total_calls, distinct_tools, blocked_count,
  blocked_tool_examples}`. Filters the `RecentAuditEmitter` ring
  buffer by the calling user's API keys (same scoping as
  `recent-tool-calls`); 7-day default, capped at 90.
  `ToolHistorySummaryResponse` Pydantic schema.
- Portal Tool history page now renders three KPI cards above the
  table (CALLS · 7 DAYS / DISTINCT TOOLS / BLOCKED with
  example-tool meta line). Blocked card switches to amber-tint
  background when `count > 0`.
- Recent-rows table adds a 6th column (`Outcome` pill: allow / deny /
  block / error) when called with `variant: "history"`. The Home
  page's last-5 calls keeps the 5-col layout (no Outcome column).
- Latency cell turns red when `> 1000ms` so slow tool calls jump out.

**UX-3 · Connections panel as table + Quick-connect grid.**

Reframed from "Clients (Cursor / Claude Desktop / ChatGPT)" — the
design's mock — to **Linked SaaS accounts** since that's what we
actually track today (per-user delegated OAuth tokens). The
device/client tracking would need new audit-event aggregation;
sized as a follow-up in BACKLOG.

- 5-column table (Account / Scope / Last refreshed / Expires /
  Action). Saffron status dot, mono-styled scope, friendly
  relative-time strings (`3h ago`, `2d ago`), Disconnect button.
- New **Quick connect** grid below the table: cards for every MCP
  server in the user's catalog that requires per-user OAuth but
  isn't yet authorised. Each card → click triggers `/initiate` and
  bounces through the IdP. De-duplicated by `server_id` (multiple
  vservers may wrap the same upstream).

### Files updated

- `src/vyuu_gateway/registry/portal_schemas.py` — `ToolHistorySummaryResponse`
- `src/vyuu_gateway/api/portal.py` — new `my_tool_history_summary_endpoint`
- `src/vyuu_gateway/api/portal_ui.py` — env pill JS, KPI card HTML +
  CSS + JS, connections-table layout (HTML/CSS/JS), Quick-connect
  grid (HTML/CSS/JS)

### Verified end-to-end on http://127.0.0.1:8000

- `GET /api/v1/health` → `{"environment":"local","version":"drawio-lab"}` →
  pill renders `local · drawio-lab`
- `GET /api/v1/portal/{tenant}/tool-history-summary` → 200 with
  `{window_days:7, total_calls:0, distinct_tools:0, blocked_count:0,
  blocked_tool_examples:[]}` (empty after restart; populates as
  Cursor → Vyuu → GitHub calls flow through)
- Connections table renders correctly when there's a linked GitHub
  account; Quick-connect shows whichever OAuth-authcode MCP servers
  the user has catalog access to but hasn't connected.

### Next slates (still open)

- **A4** · 401-driven token refresh on phase-3/phase-4 OAuth (~½ d)
- **H1** · DNS-time SSRF backstop (~½ d)
- **Connections-as-clients panel** (1.5 d) — design-mock semantics
  needs new backend tracking for per-session client_version +
  device_fingerprint from audit events
- **Anomaly alerts on N1** (~2 d) — feeds the existing alerts bell
  with richer signal than just deny/block events
- **A6.y** · Kubernetes Secrets backend (~1 d)
- **S1.b** · Cosign / Sigstore signature verification for binary
  source type (~½ d)
- **H3** · Payload-size limits + response inspection / redaction
  (½ d for limits, 2-3 d for full redaction)

---

## Sub-session update — 2026-05-02 (Portal redesign · sidebar app-shell + Home + Tool catalog + recent-tool-calls + port 8000)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 827 passed, 0 skipped (+3 new portal tests)
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session shipped

User shared screenshots of the Claude Design portal slates (Home +
Tool catalog) and asked for the portal to be brought up to parity.
Then asked to move the lab off port 8765 to 8000 so the configured
GitHub OAuth callback (`localhost:8000/api/v1/oauth-authcode/callback`)
points at the same gateway process.

**1. Portal `/portal` redesigned end-to-end.**

Replaced the tab-rail layout (`Catalog / My requests / API keys /
Connections / Settings`) with the sidebar app-shell pattern that
matches the operator console:

- 248px sticky sidebar with brand block, sectioned nav (`Get started`
  · `Discover` · `My account`), live count badges (Connections · API
  keys · My requests), user pill at the bottom showing email + tenant
  prefix, Log out button.
- Topbar with `Portal › <section>` breadcrumb and an env pill
  (`gateway · v1.0.0` placeholder).
- Per-section panels driven by `[data-portal-nav]` toggle (replaces
  the prior `data-tab-panel` mechanism). Last-visited nav restored
  from `sessionStorage["vyuu.portal.nav"]` on next sign-in.

**2. New Home screen.**

Replaces the catalog-as-landing model with a proper greeting + setup
+ rails layout:

- Hero: `WELCOME` eyebrow + `Hi {firstName} — connect your AI tools
  to your tenant's sanctioned MCPs` + sub copy + `Connect a new
  client →` saffron CTA. First-name extracted from email local-part.
- Setup card (saffron-tinted background): `ONE-TIME SETUP · 2 MINUTES`
  eyebrow + `Point your IDE at this URL` heading + a JSON snippet
  pre-filled with the user's first granted vserver URL + Cursor /
  Claude Desktop / Custom client buttons.
- Right rail: `YOUR ACCESS · What you can use` (saffron dot per
  granted vserver, label, OPEN TO ALL / GRANTED meta) + a `Browse
  catalog →` CTA. Pending card appears when there are open access
  requests, count + per-request meta.
- `Your last 5 tool calls` table — calls the new
  `/recent-tool-calls?limit=5` endpoint (see below).

**3. Tool catalog redesign.**

Replaces the old card grid with the bundle-card layout from the mock:

- Page head: `DISCOVER · TOOL CATALOG` eyebrow + `What's connected`
  title + `Sanctioned MCP bundles, surfaced as virtual servers…` sub.
- Filter pills (`All bundles` / `Open to me` / `Needs request` /
  `Restricted`) replace the old `<select>` access filter; one active
  at a time, group filter state read via `activeFilter("catalog")`.
- 2-col bundle-card grid: mono-styled vserver name + status pill
  (saffron `Open to you` / amber `Needs request` / grey `Restricted`),
  description, meta pill row (visibility + `OAuth N/M` when the
  bundle wraps per-user OAuth upstreams), bottom CTA (saffron
  `Request access →` for locked, saffron `Connect →` for granted).
  Click `Connect →` toggles an inline config-snippet block.

**4. Live nav-count badges + sidebar persistence.**

Each refresh function (`renderKeys`, `renderRequests`, `renderConnections`)
now also paints its sibling sidebar count badge (`#nav-count-keys`,
`#nav-count-requests`, `#nav-count-connections`). Hidden when count is 0.
The Home page's right rails reuse the catalog / requests caches —
when those refresh, the rails repaint without an extra fetch via
monkey-patched `renderCatalog` / `renderRequests`.

**5. Connections / API keys / My requests / Settings panels.**

Lifted to the new app-shell layout. Existing rendering logic kept
(card factories, OAuth-connect CTAs, key-issue flow, password-rotate
form) — only the panel chrome changed (page-head + bundle-grid layout).
Filter selects replaced with the same filter-pill pattern as catalog.
The redesign of these panels into the design's table layout (Connections
as Client / Device / Identity binding rows; History with KPI cards)
is sized in BACKLOG as a follow-up.

**6. New backend endpoint: `GET /api/v1/portal/{tenant_id}/recent-tool-calls`.**

Surfaces the in-memory `RecentAuditEmitter` ring buffer scoped to the
calling user's API keys. Implementation:

- Extended `RecentAuditEmitter.query()` with a new
  `principal_id_in: frozenset[str] | None` filter — when set, only
  events whose `principal.id` is in the given set come back. Used by
  the portal endpoint, harmless for existing operator-side callers.
- Endpoint looks up every API key the user has ever held (active +
  revoked — the buffer holds at most ~1000 events so revoked keys
  may still surface their last calls there), wraps the ids into a
  `frozenset`, and queries.
- Returns `RecentToolCallResponse` rows: `event_id`, `observed_at`,
  `tool`, `vserver_id`, `vserver_name`, `decision`, `via` (principal
  display), `latency_ms`. Empty list (200) when no keys / no buffer
  wired up — keeps the UI benign on stripped-down deployments.
- 3 new tests in `tests/users/test_portal_api.py`:
  empty-when-no-keys, filter-to-caller-keys (positive + cross-tenant
  + cross-principal), cross-tenant 403.

**7. Removed the SURFACE toggle from the portal sidebar.**

User caught this: the mock had an `Operator / User Portal` switch in
the sidebar foot, but it was a design-only navigation device, not real
functionality (operators don't need to flip surfaces; the operator
console is at `/operator`). Both markup and the supporting CSS
(`.surface-toggle*`) are gone.

**8. Lab port migration: 8765 → 8000.**

To align with the GitHub OAuth app's configured callback at
`localhost:8000/api/v1/oauth-authcode/callback`, the drawio lab now
boots on 8000:

- `examples/drawio_lab_server.py` — `LAB_PORT = 8765` → `8000`
- `.claude/launch.json` — `"port": 8765` → `"port": 8000`
- `src/vyuu_gateway/api/operator_ui.py` — one stale `:8765`
  placeholder in the OAuth-authcode `redirect_uri` input flipped
  to `:8000` (the GitHub / Drive / Slack / Notion / MS Graph /
  Atlassian preset values were already on `:8000`).

The collision: `scripts/demo_oauth_authcode.py` was already running
on 8000 with similar GitHub-demo seed data. That process was killed
(its database seeds persist in Postgres, so the `github-demo` server +
`github-demo-vserver` still appear in catalogs).

### Files updated

- `src/vyuu_gateway/api/portal_ui.py` — full UI rewrite (HTML body,
  ~700 lines of new CSS for app-shell + topbar + hero + setup card +
  rails + recent table + bundle cards + filter pills, JS swaps
  `selectTab` for `setActivePortalNav` + adds `refreshHome` /
  `paintHomeAccessList` / `paintHomePendingList` /
  `refreshToolHistory` / `fetchUserToolCalls` / `paintRecentRows`).
- `src/vyuu_gateway/api/portal.py` — new
  `my_recent_tool_calls_endpoint`, imports `RecentAuditEmitter` +
  `UserApiKey` for the user-scoped query.
- `src/vyuu_gateway/registry/portal_schemas.py` —
  `RecentToolCallResponse` Pydantic model.
- `src/vyuu_gateway/audit/recent.py` — `principal_id_in` parameter
  on `RecentAuditEmitter.query()`.
- `tests/users/test_portal_api.py` — 3 new endpoint tests, hoisted
  imports for the audit-event factories.
- `examples/drawio_lab_server.py` + `.claude/launch.json` — port
  migration.

### Verified end-to-end via preview server (port 8000)

- `/api/v1/health` → 200, `/operator` → 200, `/portal` → 200.
- Provisioned a portal user via the operator API
  (`krishna+portal@example.com` / `super-strong-portal-pw-12+`) and
  signed in through the new `/auth/{tenant_id}/login` endpoint.
- Home renders the saffron greeting, the IDE-config snippet card
  with a dark code block, and "Your access · What you can use" with
  one bundle (`github-demo-vserver`, OPEN TO ALL).
- Sidebar navigation between Home / Tool catalog / Connections / API
  keys / My requests / Tool history / Settings flips panels cleanly,
  breadcrumb updates, last-visited persists.
- Tool catalog shows the 9 vservers in the lab tenant as bundle cards
  with `Needs request` (amber) status pills and saffron `Request
  access →` CTAs. Filter pills active-state cycles correctly.

### Hotfix during E2E test

Operator hit a 500 on `Connect →` from the portal: the in-memory
`SecretStore` started empty after the lab restart, so the
`POST /api/v1/oauth-authcode/{server_id}/initiate` call's
`get_secret(tenant, "github-demo-client-id")` raised
`SecretNotFoundError`. The DB row for the `github-demo` MCP server
had been seeded earlier by `scripts/demo_oauth_authcode.py`, but
the in-process secret store doesn't survive across the lab-server
swap.

Fix: new helper `_seed_oauth_authcode_secrets(store)` in
`examples/drawio_lab_server.py` that walks every `mcp_servers` row
with `auth_authcode IS NOT NULL` and seeds both `client_id_ref` +
`client_secret_ref` from env (or a placeholder fallback so the
authorize URL at least redirects cleanly to the IdP). Ran on
startup; logs `[lab] seeded N OAuth-authcode secret refs…`.
Verified: `/initiate` now returns 200 with a valid
`https://github.com/login/oauth/authorize?...` URL.

Real OAuth-app credentials come from `DEMO_GH_CLIENT_ID` /
`DEMO_GH_CLIENT_SECRET` (backwards-compat with the demo seeder) or
the generic `LAB_OAUTH_CLIENT_ID_<REF>` /
`LAB_OAUTH_CLIENT_SECRET_<REF>` env-var pattern.

Follow-up after operator hit GitHub's `404 Not Found` from the
authorize URL (placeholder client_id isn't a real app at GitHub):
the lab now prints a loud per-server boot banner when any
`auth_authcode` server resolved to a placeholder, with the exact
env-var names to set + the OAuth-app registration link with the
correct `/api/v1/oauth-authcode/callback` URL pre-filled. Boot
log now reads:

```
[lab] seeded 4 OAuth-authcode secret refs (0 from env, 4 placeholder).

======================================================================
  ⚠  OAuth-authcode placeholders in use — Connect → will 404
======================================================================
  · github-demo
      set DEMO_GH_CLIENT_ID=<real value> before booting the lab
      ...
```

### Next slates

- **Connections panel** as the design's table layout (Client / Device
  / vServer / Identity binding / Last used / Issued / Revoke). Needs
  backend tracking for client-version + device-fingerprint per
  session — not present today. ~1.5 days.
- **Tool history panel** as the design's table layout with 3 KPI
  cards (Calls 7d / Distinct tools / Blocked) above. The
  `recent-tool-calls` endpoint already returns the rows we need; the
  KPI rollups would need a small aggregation endpoint. ~1 day.
- **Onboarding modal** for first-run portal users — design has a
  `PortalOnboarding` slate. Skipped for now since the existing
  setup-card on Home already covers the same content for v1.
- **Env pill** currently hardcoded to `gateway · v1.0.0`; wire it
  to `/api/v1/health`'s actual `environment` + `version`. ~30 min.
- The remaining open backlog from prior batches still applies
  (anomaly alerts on N1, A4 token refresh, AWS KMS for
  oauth_user_tokens, multi-run drift history).

---

## Sub-session update — 2026-05-02 (5-step MCP registration wizard)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 824 passed, 0 skipped (UI-only batch — no test delta)
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session shipped

User compared the operator console's flat `Register MCP server` form
to a Claude Design mock and asked for "similar flow once user clicks
on register MCP servers" — the screenshot showed a 5-step wizard
(Runtime → Connection → Authentication → Capabilities → Review)
with a saffron progress rail, per-step body cards, a sticky live-
preview rail, and a per-step Continue / Back footer.

Implemented the wizard as a UX layer over the existing register form
fields — the form fields stay the canonical state, the wizard just
navigates + gates per step.

**Wizard chrome.**

- New `<section class="panel wizard-shell" data-nav="servers">`
  replaces the old flat panel. Hidden by default
  (`data-wizard-mode="closed"`); the existing `+ Register` button
  in the table panel-head now flips it to `data-wizard-mode="open"`
  and sets `body[data-wizard-active="true"]` so CSS hides the
  table panel (scoped to `.content` so the sidebar nav button
  stays visible).
- Header: eyebrow `CATALOG · NEW SERVER`, h1 `Register an MCP server`,
  subtitle, top-right `Cancel` button.
- Progress rail: 5 ordered pills with a connector line. Three
  states per pill: pending (default outlined number), current
  (saffron border + bold label), done (saffron-filled + ✓).
- Body: a 2-col grid (`minmax(0, 2fr) minmax(280px, 1fr)`) — the
  step body cards on the left, the existing live `register-preview`
  pane on the right. Stacks under 1100px.
- Footer: `← Back` (disabled on step 1), `Continue →` (hidden on
  step 5; replaced by the in-step `Register MCP server` submit
  button), and a foot-status that surfaces what's blocking
  Continue ("Endpoint is required.", etc.).

**Per-step content.**

- *Step 1 · Runtime* — 5 radio-card grid (HTTP / npm / pypi / stdio /
  binary) using the same `:has(input:checked)` pattern as the
  auth-mode picker, plus the `display_name` input. Source-type
  radios drive `body[data-source-type]` so stdio-only fields
  reveal automatically in step 2.
- *Step 2 · Connection* — `source_location` (with a hint that
  re-labels for stdio-family runtimes), transport select, args,
  env_vars_ref. The args + env_vars_ref fields collapse on HTTP
  via `body[data-source-type="http"] [data-stdio-only] { display: none; }`.
- *Step 3 · Authentication* — the existing 6-card auth-mode picker,
  per-mode structured field groups, OAuth provider preset popovers,
  and mTLS panel — all reused verbatim.
- *Step 4 · Capabilities* — informational checkpoint. Optional
  manifest-URL preview that calls the existing
  `POST /api/v1/servers/from-manifest` endpoint and renders the
  auto-detected fields + notes. Skip is fine — the hint copy
  steers operators to use Sync after registration.
- *Step 5 · Review &amp; register* — final manifest JSON
  (built via `buildPreviewPayload()`) plus a per-step pre-flight
  checklist (Runtime + display name set / Endpoint provided / Auth
  required fields complete / Capabilities probe with skip-meta).
  In-step `Register MCP server` button submits.

**Per-step validation gates.**

- `isStepValid(step)` reads the form via FormData per step:
  - Step 1: `source_type` set + `display_name` non-empty
  - Step 2: `source_location` non-empty
  - Step 3: every `is-ok` class on the live `register-preview-checklist-list`
    items (which already encodes the per-mode required-fields rule)
  - Steps 4–5: always pass (preflight optional, review final)
- `paint()` runs the gate after every form `input` / `change` event
  and after each Continue / Back click. The Continue button toggles
  `disabled` accordingly; the foot-status surfaces what's missing.
- One subtle plumbing issue caught in preview: the OAuth-preset
  popover writes directly to inputs without firing `input` events,
  so the wizard's gate didn't refresh after a preset fill. Fix —
  the existing `applyPresetToStructuredFields` monkey-patch (which
  already calls `refreshRegisterPreview` after a fill) now also
  dispatches a synthetic `input` event on the form, so any
  form-level listener (the wizard's `paint()`, future similar
  controllers) reliably re-evaluates.

**Submit + close.**

- The existing `registerForm.addEventListener("submit", registerServer)`
  binding stays. After a successful POST `/servers` the handler:
  resets the form, restores `data-auth-mode="none"` and
  `data-source-type="http"`, refreshes the table, and calls
  `wizard.close()` to flip back to list mode. On failure, the
  wizard stays open + the `register-output` block (hidden by
  default in wizard mode) reveals so the error is visible.

### Files updated

- `src/vyuu_gateway/api/operator_ui.py`
  - HTML: register panel rewritten as `wizard-shell` with header,
    progress rail (5 pills), 5 `wizard-step` body containers,
    moved live-preview aside into the wizard body, footer with
    Back / Continue / status / submit.
  - CSS: `.wizard-shell`, `.wizard-head`, `.wizard-title`,
    `.wizard-sub`, `.wizard-cancel`, `.wizard-progress`,
    `.wizard-step-pill[.is-current|.is-done]`, `.wizard-step`,
    `.wizard-step-title`, `.wizard-form`, `.wizard-field`,
    `.wizard-field-row`, `.runtime-card-grid`, `.runtime-card`,
    `.wizard-preflight*`, `.wizard-review*`, `.wizard-foot*`,
    `.wizard-back`, `.wizard-next`, `.wizard-register-btn`.
    Hide-table-when-wizard-open rule scoped to `.content` so the
    sidebar nav stays visible.
  - JS: new `wizard` IIFE (`open` / `close` / `paint` / `next` /
    `back` / `isStepValid` / `renderReviewStep` / `probeUpstream`).
    `+ Register` button handler swapped from scrollIntoView to
    `wizard.open()`. `registerServer` extended with `wizard.close()`
    on success + form reset. Source-type select handler swapped
    for radio-group equivalent. Preset monkey-patch dispatches a
    synthetic `input` event for downstream form-listeners.

### Verified end-to-end via preview server

- `+ Register` → wizard opens at step 1, table panel hides, sidebar
  nav stays visible, Back disabled, Continue disabled with status
  "Pick a runtime + give the server a display name."
- Type `github-corp` → Continue enables. Click → step 2.
- Type `https://api.githubcopilot.com/mcp/` → Continue enables.
  Click → step 3.
- Pick OAuth user, open info popover, click GitHub preset →
  preview checklist goes 7-of-7 saffron, Continue enables. Click
  twice (skip step 4) → step 5.
- Step 5 shows the manifest JSON and 4-row checklist (3 OK + 1
  skipped). Click `Register MCP server` → POST succeeds, server
  count goes 20 → 21, wizard closes back to list mode.

### Next slates

- **User portal redesign** (separate slate, kicks off next): user
  shared screenshots of a designed `/portal` Home (greeting +
  IDE-config card + your-access rail + last-N tool calls) and
  Tool catalog (vserver bundles as cards with filter pills +
  Connect / Request access CTAs). Sized as ~3 days.
- The wizard's Step 4 currently calls only the static manifest-URL
  preview — a real "probe upstream" preflight (TLS handshake, OIDC
  discovery, scope verification matching the Claude mock's checklist
  with `TLS 1.3 · 142ms`, `.well-known found`, `3 scopes verified`)
  needs a new no-persist endpoint. Sized as ~1 day.

---

## Sub-session update — 2026-05-02 (per-server sync cadence + persisted last-sync drift + notification bell)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 824 passed, 0 skipped (+7 vs. last batch)
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session shipped

Continuation of the BACKLOG "next slates" — the three items left from
the Claude Design handoff that touched schema or upstream work.
Closed all of them.

**1. Per-server capability-sync cadence.**

New nullable `mcp_servers.sync_cadence_minutes` column (migration
`20260502_0012`). Semantics:

- `NULL` → use the global default
  (`Settings.capability_sync_interval_seconds`).
- `0` → manual only — the periodic scheduler skips this server.
- `N>0` → throttle to no more often than every N minutes.

The CHECK constraint enforces ≥ 0; the Pydantic schema additionally
caps at `43200` (30 days) so a typo can't park a server for years.

- New `users_service.update_sync_cadence(...)`
  ⟂ `PATCH /api/v1/servers/{id}/sync-cadence` endpoint with a
  dedicated `ServerSyncCadenceUpdateRequest` schema.
  Atomic, low-risk — flipping cadence doesn't round-trip the full
  registration shape.
- `ServerRegistrationRequest` accepts `sync_cadence_minutes` at
  registration time, and `ServerRegistrationResponse` echoes it
  back (alongside the existing health / pull metadata).
- `PeriodicCapabilitySyncScheduler._fetch_registered_servers`
  filters out servers that aren't due — the new
  `_is_due_for_sync(server, now)` helper covers the four cases
  (manual-only / never-synced / throttled / use-default). Tests
  cover all four.
- UI: a per-row `<select class="cadence-select">` in the MCP
  servers table (Default / Hourly / 6 hours / Daily / Weekly /
  Manual only). Change → PATCH; cached row updates so subsequent
  re-renders reflect the new value.

**2. Persisted last-sync drift (visual diff).**

Same migration adds `mcp_servers.last_sync_drift` JSONB. Both sync
paths (upstream probe and manual seed) now serialise the
`CapabilityDrift` plus per-entry `risk_category` into the column
on every run. Wiped + replaced on the next sync — only ever holds
"the most recent snapshot", as designed in the BACKLOG note.

JSON shape:

```json
{
  "synced_at": "2026-05-02T10:00:00Z",
  "has_changes": true,
  "added":   [{"kind": "tool", "name": "...", "risk_category": "delete"}],
  "removed": [{"kind": "tool", "name": "...", "risk_category": "read"}],
  "changed": [{"kind": "tool", "name": "...", "risk_category": "write"}],
  "unchanged_count": 12
}
```

- New `_serialize_drift_for_storage(...)` helper in
  `capabilities/sync.py` that takes the in-memory `CapabilityDrift`
  + the descriptors / prior caps and produces the JSON. The
  classify-helper closure binds the server so the JSON-builder
  stays decoupled from the McpServer model.
- UI: a small `+N −M ~K since last sync` pill renders in the Server
  cell whenever the persisted drift has changes. Risk-toned —
  any added/changed tool whose `risk_category` is in the high-risk
  set (`delete / admin / credential_access / data_export /
  execute`) tones the pill red; plain additions/changes tone
  amber; removed-only is neutral grey. Click → opens the row
  drawer in `mode: "drift"` showing three sections (added /
  changed / removed) with risk-pill rows.
- The Sync button mirrors the API result into the cached row's
  `last_sync_drift` so the pill appears immediately, before any
  /servers refetch.
- Test coverage:
  `test_sync_endpoint_drives_capability_discovery_through_provider`
  extended to assert `last_sync_drift` is persisted with
  resolved risk categories (e.g. `delete_file` → `delete`).
  Three new PATCH tests cover the cadence endpoint
  (200 / 422 negative / 422 over-30d / 404 unknown).

**3. Notification bell + alert feed (thin shell).**

Implemented as a sidebar-foot button next to the search trigger.
Surfaces denied / blocked / errored tool calls from the last hour
by filtering the existing `RecentAuditEmitter` ring buffer
client-side. No new backend endpoint. Designed so the deeper
"anomaly alerts on N1 data" backlog item slots in later as a
data-source upgrade — the UI doesn't change.

- Bell trigger has a danger-toned badge that's hidden when count
  is 0; shows "1" / "2" / … / "99+" otherwise.
- Click → opens an overlay (reuses `.palette-overlay` /
  `.palette-card`) with an alert-row list. Each row: decision pill
  (deny / block / error), tool name, principal display + reason,
  observed-at time. Click row → navigates to Events panel + closes.
- Polling: `setInterval` every 60 s refreshes the badge count.
  Polling no-ops when the operator isn't signed in (no
  `vyuu_operator_token` in sessionStorage), so it's safe to start
  on page boot.
- Esc / backdrop click closes; an inline "refresh" kbd-styled
  button on the input row re-fetches on demand.

### Files updated

- New migration `migrations/versions/20260502_0012_sync_cadence_and_drift.py`
- `src/vyuu_gateway/db/models.py` — two new columns + CHECK constraint
- `src/vyuu_gateway/registry/schemas.py` — fields on
  `ServerRegistrationRequest` / `ServerRegistrationResponse` +
  new `ServerSyncCadenceUpdateRequest`
- `src/vyuu_gateway/registry/service.py` — wire `sync_cadence_minutes`
  into `register_mcp_server`; new `update_sync_cadence(...)` +
  `ServerNotFoundError`
- `src/vyuu_gateway/api/servers.py` — new
  `PATCH /servers/{id}/sync-cadence` endpoint
- `src/vyuu_gateway/capabilities/sync.py` —
  `_serialize_drift_for_storage` helper, written from both sync
  paths into `server.last_sync_drift`
- `src/vyuu_gateway/capabilities/scheduler.py` — `_is_due_for_sync`
  filter applied inside `_fetch_registered_servers`
- `src/vyuu_gateway/api/operator_ui.py` — cadence selector,
  drift pill + drift drawer, alerts overlay + JS shell, supporting
  CSS (`.cadence-select`, `.drift-pill*`, `.drift-list*`,
  `.alert-row*`, `.alerts-trigger`, `.alerts-badge`)
- `tests/capabilities/test_scheduler.py` — 4 new tests for
  `_is_due_for_sync` matrix
- `tests/api/test_capability_sync_and_vservers.py` — 3 new tests
  for the cadence PATCH endpoint + assertion that
  `last_sync_drift` is persisted on sync

### Verified end-to-end via preview server

- Cadence selector flips to "Daily" → PATCH succeeds → cached
  `sync_cadence_minutes` = 1440.
- Sync on `drawio-http` returns no drift (catalogue unchanged) —
  pill correctly hides.
- Fabricated drift (added `delete_workspace` + `list_diagrams`,
  changed `create_diagram`) → pill renders
  `+2 −0 ~1 since last sync` with `drift-pill-danger` class
  (because of the `delete` risk).
- Click pill → drift drawer opens with title
  "Last capability sync — drawio-http", three sections each
  showing the right risk pills.
- Alerts overlay: empty state copy correct on a tenant with no
  denied events. Fabricated 3 audit events (deny + block + allow)
  → list filters out the allow → badge shows "2", rows render
  with decision pills.

### Next slates (now mostly clear)

- Anomaly alerts on N1 data (~2 days) — would replace the
  client-side decision filter in the alerts shell with a dedicated
  alert source. UI doesn't change, just the data path.
- A4 (401-driven token refresh on the OAuth user-token path).
- AWS KMS envelope encryption for `oauth_user_tokens` at rest.
- Visual diff *history* (multi-run retention) — the current
  feature only persists the most recent drift; a separate
  `mcp_capabilities_history` table would be the next step if
  customers ask for diffs over arbitrary time windows.
- Inbound MCP rate limiting per-(tenant, principal).

---

## Sub-session update — 2026-05-02 (⌘K search palette + inline rename_map + inline group editor with chips)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 817 passed, 0 skipped
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session shipped

User directive (still in force): *"start working on them"* — i.e. the
"next slates" list at the bottom of the prior HANDOFF entry. Picked
the three items that don't require new schema:

**1. Inline `rename_map` in the Publish vserver drawer.**

The standalone vserver form has always supported `rename_map`, but
the inline drawer (which covers the 90% single-server case) didn't —
operators had to drop back to the standalone form just to disambiguate
a tool name. Drawer rows are now a 2-col grid: checkbox + tool name
on the left, "rename to: <input>" on the right.

- Each tool row restructured from a `<label>` to a `<div>` with a
  nested `<label class="publish-tool-row-left">` so the rename
  input has its own focus target (clicking it doesn't toggle the
  checkbox via implicit label association).
- `data-role="tool-pick"` and `data-role="tool-rename"` selectors
  for harvest. Empty / whitespace inputs and identity-rename inputs
  are skipped — no no-op rename entries land in the request.
- Light client-side regex guard
  (`/^[a-zA-Z][a-zA-Z0-9_-]{0,127}$/`) — friendly inline error
  beats a 422 round-trip; server's the canonical source of truth.
- Hint copy updated: "Pick the tools you want to expose. Rename
  any of them inline to disambiguate collisions or match your
  team's naming."
- Stacks on viewports below 580px (was 720px before — dropped
  because the drawer width inside a 248px sidebar shell is
  ~700px on a normal laptop).

**2. Inline group editor with member chips.**

Replaced the single-select + Add/Remove buttons (status surfaced
through a panel-shared `createGroupOutput` div) with a self-contained
chip list per group card.

- New endpoint: `GET /api/v1/groups/{group_id}/members` →
  `list[UserResponse]`. Backed by new
  `users_service.list_group_members(...)` that joins users to
  `user_group_memberships` filtered by group, ordered by email.
  Tenant-scoped via `get_group` (404 for cross-tenant ids).
- Each group card now renders: eyebrow with live "MEMBERS · N"
  count, a flex-wrapping row of saffron chips (one per member,
  with × button), and an Add row whose dropdown filters out
  current members + disables itself when everyone's already in.
- Optimistic updates — Add appends + repaints immediately, then
  the server call confirms; remove (×) drops the chip on
  click-after-confirm. Errors surface inline at the bottom of
  the card, not way up at the panel header.
- New test in `tests/users/test_users_api.py`: extended
  `test_create_group_and_add_member` to also exercise GET
  `/members` (200 + sorted list), 404 on bogus group id,
  and post-DELETE empty list.

**3. ⌘K search palette.**

Topbar palette pattern from the Claude Design handoff —
implemented as a global overlay rather than a topbar bar
(we have a left sidebar, no topbar). Trigger lives in the
sidebar foot.

- HTML: `<button id="palette-trigger">` with kbd hint, plus a
  `<div id="palette-overlay" hidden>` that contains the input
  card + grouped results list + keyboard-shortcut footer.
- CSS: backdrop overlay with `color-mix(in srgb, var(--vyuu-ink)
  50%, transparent)`, centered card at 12vh from top, max
  640px wide / 70vh tall. Result rows have a saffron focus
  ring, kind pill on the right (server / vserver / user / group),
  meta line in mono. Empty state via `:empty::before`.
- JS (`palette` IIFE): searches in-memory `serversCache`,
  `principalCache.users`, `principalCache.groups`, and a
  palette-local `vserversCache` populated lazily on first open.
  No new backend search endpoint — every cache is already
  populated by the existing list endpoints.
- Keyboard: ⌘K / Ctrl+K toggles from anywhere; Esc closes;
  ↑/↓ navigate the focused row; Enter activates (calls
  `setActiveNav(navIdForKind)` + closes). Click on result
  works the same way.
- Cap of 25 results per query — keeps the DOM cheap on
  100-server tenants.

### Files updated

- `src/vyuu_gateway/registry/users_service.py` — new
  `list_group_members(...)` function.
- `src/vyuu_gateway/api/users.py` — new `GET /groups/{id}/members`
  endpoint.
- `src/vyuu_gateway/api/operator_ui.py`
  - HTML: `#palette-trigger` button in `.sidebar-foot`,
    `#palette-overlay` block before `</body>`.
  - CSS: `.publish-tool-row` becomes a 2-col grid (with
    `.publish-tool-row-left` + `.publish-tool-row-rename`);
    `.group-card`, `.group-member-chips`, `.group-member-chip`,
    `.group-member-chip-x`, `.group-add-row`, `.group-add-select`,
    `.group-status`; `.palette-trigger*`, `.palette-overlay`,
    `.palette-card`, `.palette-input*`, `.palette-results`,
    `.palette-section-label`, `.palette-result*`, `.palette-foot`,
    `.palette-empty`.
  - JS: `renderPublishDrawer` row structure changed; create-vserver
    handler harvests rename inputs into `rename_map`. `renderGroup`
    rewritten as inline-chip editor (`paintMembers`,
    `refreshAddOptions`, `loadMembers`, `addMember`, `removeMember`).
    New `palette` IIFE wires the global ⌘K shortcut.
- `tests/users/test_users_api.py` — extended
  `test_create_group_and_add_member` to cover the new endpoint.

### Verified end-to-end via preview server

- ⌘K (and trigger button click) opens overlay, focuses input,
  lazy-fetches missing caches.
- Typing "drawio" against the lab tenant returns 8 results
  grouped into MCP servers + Virtual servers sections.
- ↑/↓ navigates focus, Enter on focused server result routes to
  `setActiveNav("servers")` and closes the palette.
- ⌘K and Ctrl+K both toggle. Esc closes. No-match shows the
  "No matches for X. Searches across…" hint.
- Group card flow: pick user → Add → optimistic chip + count
  goes "MEMBERS · 0" → "MEMBERS · 1" + status "✓ added X" →
  click chip × → confirm → "MEMBERS · 0" + status "✓ removed".

### Next slates

Still open from BACKLOG.md "Operator UI · open items derived from
the Claude Design handoff":

- **Notification bell + alert feed** (~2 days, blocked on
  anomaly alerts on N1 data shipping first)
- **Visual diff on capability-sync** (~1.5 days, needs
  `mcp_capabilities_history` schema for prior-snapshot retention)
- **Per-card sync-cadence scheduling** (~1 day, needs
  `mcp_servers.sync_cadence` column)

Higher-up backlog: A4 (401-driven token refresh), AWS KMS envelope
encryption for `oauth_user_tokens`, anomaly alerts on N1.

---

## Sub-session update — 2026-05-02 (UX polish: as-of staleness, theme + density toggles, live JSON preview, empty-state copy)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 690 passed, 127 skipped (817 total — skipped require live infra)
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session shipped

User directive: *"start off with everything next few session our main
goal improvise UX"*. Continuation of the Claude Design handoff items
that were deferred from the previous batch. All UI-only changes
(no schema, no API, no behaviour) — pure operator experience polish.

**1. Per-panel "as of HH:MM:SS" staleness indicator.**

Every panel-head now stamps a mono `as of HH:MM:SS` pill next to the
Refresh button after a load completes. Closes the auto-refresh
feedback loop from the previous batch — operators couldn't tell
when a panel was last fetched, so "is this stale?" required
clicking Refresh defensively.

- New `markAsOf(refreshButtonId)` helper. Wraps the pill + Refresh
  button in a `.panel-head-actions` flex container if missing
  (the panel-head's `grid-template-columns: 1fr auto` would
  otherwise wedge the pill as a 3rd child and stretch the button).
- `setActiveNav` dispatch table reformatted to `[refreshButtonId,
  loaderFn]` tuples; calls `markAsOf` after the loader resolves.
- Subtle styling: mono `--vyuu-mono`, muted ink, no background —
  reads like metadata, not a button.

**2. Light/dark theme toggle + cozy/compact density toggle.**

Sidebar foot grew a 2-button `.ui-pref-row`: theme (☀ / ☾) and
density (≡ / ☰). Persisted in localStorage as `vyuu_ui_theme` and
`vyuu_ui_density`; restored on page boot before paint to avoid
flash-of-wrong-theme.

- `[data-theme="dark"]` block with full token overrides:
  `--vyuu-bg`, `--vyuu-panel`, `--vyuu-ink`, `--vyuu-ink-muted`,
  `--vyuu-line`, etc. Brand-cream `--vyuu-on-primary` stays
  cream in both modes so the wordmark + saffron buttons still read.
- `[data-density="compact"]` overrides `--vyuu-pad-card` /
  `--vyuu-pad-row` / `--vyuu-gap-section` plus a few selector-level
  tightenings (`.panel`, `.servers-table tbody td`, `.vserver-card`,
  `.card`, `.panel-head`, `.nav-item`).
- `applyUiPref(kind, value)` writes to `document.documentElement.dataset`
  and persists. Delegated click handler on `button[data-theme]` /
  `button[data-density]` plus an active-state ring.

**3. Live JSON preview pane on the Register MCP form.**

Register form is now a 2-column grid (`minmax(0, 2fr) minmax(280px, 1fr)`)
that stacks under 1100px. Right rail is a sticky `.register-preview`
showing:

- A pretty-printed **JSON shape** of the payload that will be POSTed
  (`buildPreviewPayload()` mirrors `serializeAuthFields`'s collect/split/
  parse logic exactly — what operators see is what gets sent).
- A **required-fields checklist** keyed off the picked auth mode
  (oauth → token_url + client_id_ref + client_secret_ref;
  authcode → 5 fields; jwt_bearer → 6 fields). Required rows turn
  saffron when satisfied — gives operators an instant readiness signal
  without hitting Submit and parsing a 422.
- Updates on every `input` / `change` event on the form, plus after the
  preset-popover (GitHub / Drive / Slack / Notion / MS Graph /
  Atlassian) auto-fills the structured fields.

Verified end-to-end during the preview session: picked OAuth user,
filled `display_name=github-corp` + `source_location=...`, hit the
GitHub preset → `previewBytes: 523, checklistOk: 7, checklistTotal: 7`.

**4. Empty + loading state copy upgrade.**

Replaced terse one-word states ("No admins.", "No users.", "No groups.",
"No pending requests.", "No virtual servers in this tenant.",
"(no grants)") with action-oriented copy that hints at the next move:

- *Vservers:* "No virtual servers published yet. Sync capabilities on
  a registered MCP server, then publish a curated bundle here."
- *Admins:* "No additional admins. Use Add admin above to invite
  another operator with view-only or full access."
- *Access requests:* "No requests waiting. When users request access
  to a vserver, approvals queue here."
- *Users:* "No tenant users yet. Users register through the sign-up
  flow or you can create them via the API."
- *Groups:* "No groups defined. Groups bundle users for shared vserver
  grants — handy for team-wide access."
- *Capabilities:* "No tools synced yet for X. Click Sync capabilities
  on the server row to pull its tool catalogue."
- *Grants:* "No active grants. Pick a user or group below and Grant
  access."
- Loading copy normalized: every "Loading..." → "Loading…" (single
  ellipsis char) for typographic consistency.

### Files updated

- `src/vyuu_gateway/api/operator_ui.py`
  - HTML: theme/density toggle row in `.sidebar-foot`; Register form
    wrapped in `.register-layout`; new `<aside class="register-preview">`
    with `#register-preview-pre` + `#register-preview-checklist-list`.
  - CSS: `[data-theme="dark"]` block (~30 token overrides);
    `[data-density="compact"]` overrides; `.ui-pref-row`,
    `.ui-pref-toggle`, `.panel-head-actions`, `.as-of-pill`,
    `.register-layout`, `.register-preview*`,
    `.register-preview-checklist*`.
  - JS: `markAsOf`, `applyUiPref`, theme/density boot IIFE,
    `buildPreviewPayload`, `refreshRegisterPreview`, monkey-patched
    `applyPresetToStructuredFields` to fire the preview after preset
    fills. `setActiveNav` dispatch table refactored to tuples.
    Empty/loading copy rewrite across `loadVservers`, `loadAdmins`,
    `loadAccessRequests`, `loadUsers`, `loadGroups`,
    `loadCapabilitiesForServer`, the grants render in `loadAccessUI`,
    `loadServers`, `loadIdentities`, `loadAuditEvents`,
    `loadSecretStoreStatus`, `renderPublishDrawer`.

### Next slates

The Claude Design handoff items still open (sized in BACKLOG.md):

- ⌘K search palette on the topbar (~1.5 days)
- Notification bell + alert feed (after anomaly alerts, ~2 days)
- Visual diff on capability-sync (~1.5 days, needs snapshot retention)
- Per-card sync-cadence scheduling (~1 day, needs schema)
- Inline rename_map in Publish drawer (~30 min)
- Group editor inline member-pick dropdown (~½ day)

---

## Sub-session update — 2026-05-02 (Enterprise-grade MCP servers table + Vservers card grid + Gateway-health → sidebar pill)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 817 passed, 0 skipped
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session shipped

The user's preview-session feedback was direct: the previous layout
wasn't enterprise-ready. Two specific complaints:

> "The cards are stacked vertically in MCP servers, and one half is
> entirely occupied by long gateway health card, and it is plain
> empty except that 4-5 lines in the beginning"

> "if you were to use the mock and complete everything what is
> needed?"

Implemented the design handoff's actual proposal for these screens —
no more half-measures.

**MCP servers — converted from a stacked card list to a proper table.**

- 6 columns: Server (health-dot + name + id·transport), Runtime
  (HTTP / npm / pypi / stdio / binary pill), Auth mode pill,
  Tools count, Health label, per-row actions (Sync, Publish vserver).
- Search bar (filters on name / id / runtime / auth mode / source
  location, all in-memory against a cached server list).
- Filter pills along the toolbar: All · HTTP · stdio·npm ·
  stdio·pypi · stdio · binary. One active at a time.
- Per-row Publish vserver opens a single shared row drawer that
  anchors *below* the selected row (not as a card-local expander
  fighting the table layout). Auto-fetches the server's tools (or
  triggers a sync when empty), checkbox list with risk pills,
  one-click create. Same /api/v1/vservers backend — no API changes.
- A `+ Register` saffron-primary button in the panel head scrolls
  to the existing Register form (which is the same panel — no
  cross-panel choreography).

**Gateway-health card — gone from the MCP servers panel.**

The standalone "Gateway health" card was eating a third of the
screen with five lines of JSON. The mock proposed retiring it
because it's a deployment concern, not a per-server concern.
Replaced with a tiny **sidebar-foot status pill**:

- Renders `service · version` (or `service · environment`) in mono
- Color-coded dot: saffron when healthy, danger red when down
- Auto-loads on page boot (the existing `loadHealth()` call now
  also writes into `updateGatewayStatusPill()`)
- Tooltip explains: "Gateway liveness and build context"
- The hidden-but-wired-up `<section data-nav="__hidden_health__">`
  preserves the original `#refresh-health` button + `#health-output`
  pre block so existing JS that pokes those ids keeps working
  (we toggle visibility, not bindings).

**Virtual servers — mock-aligned card grid.**

- 2-column responsive grid (`auto-fit, minmax(360px, 1fr)`)
- Per card: vServer mark (28px) prominently in upper-left, status
  dot + name in serif, public/private pill in upper-right,
  pills row (creation date + tool count), saffron-tinted mono
  URL line with one-click **Copy** button, action bar with
  Show tools / Delete (the existing Manage-access expander still
  appends below — its wrapper code in the access-control module
  is untouched).
- Tool count is fetched lazily (fire-and-forget after card paints)
  so the grid renders instantly and the pills update when
  /api/v1/vservers/{id}/tools returns.

### Files updated

- `src/vyuu_gateway/api/operator_ui.py`
  - HTML: Register MCP form replaced with the table-shell + toolbar
    layout; Gateway-health card retired into a hidden `data-nav`
    section that just keeps the wiring alive; sidebar foot now
    has a `#gateway-status-pill`.
  - CSS: `.servers-table*`, `.server-toolbar`, `.filter-pill`,
    `.health-dot`, `.row-drawer`, `.gateway-status-pill`,
    `.vserver-card / .vserver-head / .vserver-pills /
    .vserver-url-row / .copy-btn / .vserver-actions`
    (~250 lines of new styles).
  - JS: `loadServers` now caches into `serversCache` + calls
    `renderServers()` which applies in-memory filter+search.
    `renderServerRow()` builds a `<tr>` (replaces card factory
    `renderServer`); `toggleRowDrawer()` manages a single shared
    row drawer; `authModeLabel()` / `authPillTone()` /
    `sourcePillFor()` translate registry rows to pill metadata.
    `updateGatewayStatusPill()` mirrors the health JSON into the
    sidebar pill. `renderVserver()` rewritten end-to-end to match
    the mock; the access-control wrapper at line ~3592 still
    works because it just `appendChild`s onto the returned card.

### Next slates

The Claude Design handoff items still open (sized in BACKLOG.md):

- ⌘K search palette on the topbar (~1.5 days)
- Live YAML manifest preview in the Register form right rail (~1 day)
- Notification bell + alert feed (after anomaly alerts, ~2 days)
- Density toggle, light/dark theme toggle (~½ day each)
- Visual diff on capability-sync (~1.5 days, needs snapshot retention)
- Per-card sync-cadence scheduling (~1 day, needs schema)

---

## Sub-session update — 2026-05-02 (Auto-refresh on nav + inline Publish vserver drawer)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 817 passed, 0 skipped
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session shipped

User feedback from a preview session: every panel needed a Refresh
click, and the vserver-creation flow forced cross-panel choreography
(Sync capabilities on a server card → switch to Capabilities panel →
switch to Virtual servers panel → fill name + tool ids by hand).

Two fixes:

1. **Auto-refresh on nav switch.** `setActiveNav` now invokes the
   matching loader (`loadDashboard` / `loadNhiMap` / `loadServers` +
   `loadHealth` for the MCP servers nav / `loadVservers` /
   `loadIdentities` / `loadUsers` / `loadGroups` /
   `loadAccessRequests` / `loadAdmins` / `loadAuditEvents` /
   `loadSecretStoreStatus`) on every nav-click. Skipped silently when
   no bearer token is in sessionStorage (would 401-spam otherwise).
   Operators no longer click Refresh after each switch — the
   sidebar click is the intent signal.

2. **Inline "Publish vserver" drawer on the MCP server card.**
   Each server card grew a fourth button: **Publish vserver**.
   Click → drawer expands inline below the card with:
   - Auto-fetched tool list (auto-syncs if empty)
   - Vserver name input
   - One checkbox per discovered tool, all checked by default
     (faster: most operators want all the tools they synced)
   - Per-tool risk pill (delete → danger, write → warn,
     read/network → info, unknown omitted)
   - Create button → POST /api/v1/vservers with `tool_specs`
     derived from the checked rows
   - Inline status: "✓ created /v/{tenant}/{name}/mcp" or the error
   The standalone vserver form (further down the same panel) is
   kept for the rename_map case + multi-server vservers; the new
   drawer covers the 90% single-server case in one click.

### Files updated

- `src/vyuu_gateway/api/operator_ui.py`
  - `setActiveNav` extended with the auto-load dispatch table.
  - `renderServer` adds the "Publish vserver" button + drawer.
  - New `renderPublishDrawer` function (~80 lines) that fetches
    capabilities, falls back to triggering a sync if empty, and
    builds the inline form. Reuses the existing
    `POST /api/v1/vservers` endpoint — no backend changes.
  - New CSS for `.publish-drawer`, `.publish-tool-list`,
    `.publish-tool-row`.

### Side fix from earlier in this session
(carried forward from the previous sub-session)

- 500 on `GET /api/v1/servers` when any seeded row had a
  `http://localhost:...` redirect_uri. `OAuthAuthCodeSpec`
  validator now permits HTTP only on localhost / 127.0.0.1 /
  ::1 hosts — matches Google's documented exception, what
  GitHub / Slack / Notion accept, and what local-dev iteration
  needs. Production registrations against non-localhost hosts
  still require HTTPS.

### Open items pushed to BACKLOG.md

The Claude Design handoff proposed a number of patterns we
deliberately or pragmatically skipped. Now itemized in
`BACKLOG.md` under "Operator UI · open items derived from the
Claude Design handoff" — sized honestly, ranked roughly by
operator value:

- Per-section "as of HH:MM:SS" staleness timestamp (~15 min)
- Live YAML manifest preview in Register form right rail (~1 day)
- ⌘K search palette on the topbar (~1.5 days)
- Notification bell + alert feed (~2 days, after anomaly alerts)
- Density toggle (compact / cozy) (~½ day)
- Light/dark theme toggle (~½ day; tokens already there)
- Inline tool-spec rename map in Publish drawer (~30 min)
- Per-card Sync-now scheduling cadence (~1 day, needs schema)
- Visual diff on capability-sync (~1.5 days, needs snapshot store)
- Group editor inline (member-pick dropdown) (~½ day)

### Next slates

- **Anomaly alerts on N1 data** — first ever risk=high action by
  NHI, Nx denials in 5 min. Couples with the notification bell.
  1 day.
- **AWS KMS envelope encryption** for `oauth_user_tokens`. 1–2 days.
- **A4 (401-driven token refresh)** for phase-3/4/5 OAuth.

---

## Sub-session update — 2026-05-02 (Register form redesign + 500 fix on /servers list)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 817 passed, 0 skipped
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session shipped

**Two real fixes, both from the user's preview-session feedback:**

1. **500 Internal Server Error on `GET /api/v1/servers`** — the
   `OAuthAuthCodeSpec.redirect_uri` validator required HTTPS on
   every URL, which crashed the entire admin list endpoint when
   any single existing row had a `http://localhost:...` redirect
   URI (legitimately seeded for local dev demos like the
   `github-demo` row). The validator now permits HTTP only when
   the host is `localhost` / `127.0.0.1` / `::1` — matching
   Google's own documented exception for local-dev OAuth
   iterations and what GitHub / Slack / Notion actually accept.
   Production registrations against a non-localhost host still
   require HTTPS. Existing schema-validation tests still pass
   because they all use non-localhost hostnames in their
   plaintext-URL rejection cases.

2. **Register MCP server form was a wall of dense JSON-blob
   inputs** — six auth fields each demanding the operator type a
   nested JSON object with the right keys, no validation, no
   structure, no presets that landed where you'd expect them. The
   feedback was direct: "super messy, tidy it up, take inspiration
   from the mock design". Replaced with:
   - **6-card mode picker** (None / Org headers / Pass-through /
     OAuth M2M / OAuth user / JWT-bearer), one selected at a time,
     saffron-tinted active state mirroring the design handoff's
     `auth-mode-card` pattern.
   - **Per-mode structured field groups** that show only when the
     matching mode is picked, gated by `body[data-auth-mode="X"]`
     CSS selectors. Each group is a 2-up `auth-grid` with proper
     labelled inputs: `token_url`, `client_id_ref`,
     `client_secret_ref`, `audience` (M2M); `auth_url`,
     `token_url`, `client_id_ref`, `client_secret_ref`,
     `redirect_uri`, `scopes`, `extra_authorize_params` (authcode);
     `token_url`, `algorithm` (RS256/RS384/RS512/ES256/ES384/PS256
     dropdown), `private_key_ref`, `issuer`, `subject`,
     `audience`, `scope`, `additional_claims` (jwt-bearer).
   - **Stdio env-var sub-panel** auto-reveals when source_type
     is stdio/npm/pypi/binary via `body[data-source-type=...]`.
   - **mTLS sub-panel** sits below the picker (transport-layer
     credential, coexists with any application-layer mode).
   - **Hidden inputs** (`auth_oauth`, `auth_authcode`,
     `auth_jwt_bearer`) hold the assembled JSON; a new
     `serializeAuthFields()` JS helper walks the active mode's
     structured fields, validates required ones, parses
     comma-separated `scopes` into an array and JSON-parses
     `extra_authorize_params` / `additional_claims`, and writes
     the result into the hidden inputs before the existing
     `FormData`-based payload assembly runs. No backend changes
     needed.
   - **OAuth preset popovers** now fill the structured fields
     (not the JSON blob). New `applyPresetToStructuredFields()`
     helper auto-flips the mode picker, walks the preset shape,
     and writes each sub-field with the saffron flash-ok ack on
     each. Verified end-to-end: clicking Google Drive populates
     all 7 authcode fields including `extra_authorize_params:
     {access_type: offline, prompt: consent}` correctly nested as
     a JSON object on submit.

### Files updated

- `src/vyuu_gateway/registry/schemas.py` — `OAuthAuthCodeSpec`
  `validate_urls` now splits the strictness: HTTPS-only on
  `auth_url` + `token_url` (IdP-side, where client_secret travels)
  but `redirect_uri` is HTTPS *unless* host is localhost.
- `src/vyuu_gateway/api/operator_ui.py` — Register form HTML
  rewritten (~140 lines of structured markup replacing ~80 lines
  of JSON-blob `<input>`s); new CSS for `.auth-section /
  .auth-mode-picker / .auth-mode-card / .auth-fields / .auth-grid`
  (~120 lines); JS additions: `serializeAuthFields()`,
  `collectAuthSubfields()`, `setHidden()`,
  `applyPresetToStructuredFields()`, mode-picker change handler,
  source-type → body-attribute mirror (~150 lines total).

### Where to look

`/operator` → **MCP servers** (sidebar) → scroll past Gateway
health to the Register MCP server form. Click any auth-mode card
to switch the visible structured fields. Click the orange `i`
next to "OAuth authorization-code · per-user delegated" → click
**Google Drive** → all 7 authcode fields populate, mode flips
to authcode automatically, `extra_authorize_params` shows
`{"access_type":"offline","prompt":"consent"}` so Google issues
refresh tokens.

### Next slates

- **Anomaly alerts** on N1 data (1 day).
- **AWS KMS envelope encryption** for `oauth_user_tokens` (1–2 days).
- **A4 (401-driven token refresh)** for phase-3/4/5.
- **OAuth preset catalog UX** — the popover currently surfaces 6
  providers; could grow to a typed search box if the list passes
  ~10. Not urgent.

---

## Sub-session update — 2026-05-01 (Operator app-shell + sidebar nav — fixing the 11k-pixel scroll)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 817 passed, 0 skipped
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

### What this sub-session shipped

The previous session shipped the dashboard, NHI map, identities panel,
mini-marks, and OAuth-preset popovers — but stacked everything in a
single 11,655-pixel-tall page with no nav. The user did a preview
session, screenshotted, and immediately saw the problem: to reach
Identities the operator scrolled past 13 panels.

This session fixes the structural UX problem the prior batch
deferred. The operator console is now a **proper app shell**:

- **Left sidebar** (248px, sticky, scrollable) with grouped nav:
  - **Overview** — Dashboard / NHI map
  - **Catalog** — MCP servers / Virtual servers / Capabilities
  - **Identity & access** — Identities / Users / Groups /
    Access requests / Admins
  - **Observability** — Events
  - **Settings** — Secret store
  - **Sign in / out** at the foot
- **Single visible section** at a time, driven by `.is-hidden`
  class toggling in JS (the simpler attribute-selector approach
  lost specificity to pre-existing `.auth-panel { display: grid }`
  rules — `.is-hidden { display: none !important }` is correct here).
- **Persisted last-visited nav** in `sessionStorage` so a refresh
  returns the operator to where they were.
- **Auto-jump on sign-in** — pasting a bearer token or password-
  signing in flips the view from `signin` straight to `dashboard`,
  same as web app norms.
- **Mobile fallback** — sidebar collapses to a top strip below 900px
  via `@media (max-width: 900px)`.

### Why this matters

| Before | After |
|---|---|
| 11,655 px page height with 14 stacked panels | ~720–2,300 px per section, only one visible at a time |
| Identities = scroll past 9 panels | Identities = one click |
| Register MCP form lost in the middle of the page | Catalog → MCP servers, form is the focused surface |
| No persistent context — restart loses position | Last-visited nav restores on reload |

### Files updated

- `src/vyuu_gateway/api/operator_ui.py` — wrapped `<main>` in
  `<div class="app-shell">` with a sibling `<aside class="sidebar">`;
  tagged every existing `<section>` with `data-nav="<id>"` (no
  handler rewires — visibility is the only change); new sidebar
  CSS (~120 lines); new `setActiveNav` JS + delegated click
  handler + `sessionStorage` persistence (~50 lines).
- All existing handlers (loadDashboard, loadIdentities,
  loadServers, etc.) unchanged — they still target the same DOM
  ids; only their parent section's visibility flips.

### Side fix: OAuth-preset popover used `escapeHtml` instead of
`escapeHtmlOp`

The previous session's popover JS referenced `escapeHtml`, which
only exists in the portal UI. The operator UI uses `escapeHtmlOp`.
Fixed inline; verified in preview that all 6 provider presets
(GitHub / Google Drive / Slack / Notion / MS Graph / Atlassian)
now fill the auth_authcode field correctly.

### Next slates

- **Anomaly alerts** on N1 data (1 day).
- **AWS KMS envelope encryption** for `oauth_user_tokens` (1–2 days).
- **A4 (401-driven token refresh)** for phase-3/4/5.
- **Light/dark theme toggle** — design system supports `[data-theme=
  "dark"]` already; would need a top-bar toggle that flips body attr.

---

## Sub-session update — 2026-05-01 (Claude Design handoff — mini-marks + OAuth presets + Register form completion)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 817 passed, 0 skipped
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 191 source files
```

(No new tests this batch — UI-only changes; existing JS-syntax test
covers the new JavaScript via `node --check`.)

### What this sub-session shipped

The user fetched a Claude Design handoff bundle and asked us to
"implement the relevant aspects" — and explicitly flagged that the
design over- and under-estimated certain things. We pulled the
genuinely valuable patterns and skipped the over-reach (no full
sidebar reflow, no AI-Shield branding bleed, no 5-step wizard).

**Three concrete additions to `/operator`:**

1. **Mini-marks for the gateway's three core primitives.**
   `markNHI()`, `markVServer()`, `markToolCall()` JS factories return
   live SVG nodes drawn in the Vyuu saffron + sienna + ocean-info
   palette. Each glyph is geometrically distinct:
   - **NHI** — human silhouette inside a hex "machine ring" (the
     human/principal binding)
   - **vServer** — three offset stacked plates with a fan-out chord
     (one URL → many tools)
   - **ToolCall** — chevron-bracket envelope around a centered dot
     (the call unit)
   Wired into `renderIdentityRow` (Identities panel), `renderVserver`
   (Virtual servers panel), and `renderAuditEvent` (Events panel).
   New `.has-mark` CSS hook anchors them in the upper-right of each
   card without interfering with existing layouts.

2. **Register form completion.** The form previously only supported
   `auth_oauth` (M2M) — not `auth_authcode`, `auth_jwt_bearer`, or
   `mtls_cert_ref` / `mtls_key_ref`. All four fields now exist;
   payload serialisation handles the JSON-vs-string distinction
   correctly (auth_* are JSON objects; mTLS refs are scalar strings).
   This means an operator can now configure A1 / A2 / mTLS upstreams
   from the UI without curling the API.

3. **OAuth provider preset catalog + info-button popovers.** Six
   providers carry the canonical `auth_authcode` / `auth_jwt_bearer`
   shapes — GitHub, Google Drive (with `access_type=offline` baked
   in), Slack, Notion, Microsoft Graph, Atlassian. Click the `i`
   button next to a field → side popover opens with field-specific
   copy + a list of provider preset rows → one click fills the JSON.
   Visual ack via a one-shot `flash-ok` animation on the populated
   field. Implemented via:
   - `OAUTH_PROVIDER_PRESETS` array
   - `INFO_BUTTON_COPY` static body-copy dict
   - delegated `click` handler that toggles `.info-popover` elements
     anchored next to the trigger

### Files updated

- `src/vyuu_gateway/api/operator_ui.py` — new SVG mark factories
  (~70 lines), Register-form HTML additions, payload-serialisation
  extension, OAuth preset catalog + info-button JS (~250 lines),
  matching CSS rules (~110 lines).

### What we deliberately skipped

The Claude Design bundle proposed several patterns the user flagged
as "overestimated":

- **Full sidebar reflow + grouped nav** — touches the entire
  3500-line operator UI; high risk for a single-session change.
  Defer until there's appetite for a structural UX overhaul.
- **5-step Add-Server wizard** — the existing flat form works; a
  wizard adds steps without solving a real pain. The preset popovers
  give operators 90% of the wizard's value (one-click provider
  fills) without the multi-screen complexity.
- **AI Shield branding overlay / Tweaks panel / design canvas** —
  user explicitly said "Gateway will be an add-on & separate
  product, don't get confused" earlier in the chat transcript.

### Files reviewed (read-only — for context)

The Claude Design handoff bundle (extracted to `/tmp/anthropic-design/`
during this session) contains the full JSX prototypes:

- `project/marks.jsx` — geometric SVG marks (ported)
- `project/primitives.jsx` — `T` palette, `InfoButton` component
  (ported as vanilla JS)
- `project/screens-operator2.jsx` — Add-Server wizard with OAuth
  presets (concept ported, wizard skeleton skipped)
- `project/shell.jsx` — sidebar + topbar (skipped)
- `project/Vyuu Deck.html` — investor pitch slides (out of scope)

### Where to look

`/operator` →

- **Registered servers** + **Virtual servers** panels: each card now
  carries the relevant mini-mark (NHI / vServer / ToolCall) in the
  upper-right.
- **Register MCP server** form: scroll past the M2M `auth_oauth`
  field to see four new fields (`auth_authcode`, `auth_jwt_bearer`,
  `mtls_cert_ref`, `mtls_key_ref`), each with an `i` info button.
  Click the info button next to **Auth OAuth authcode** → popover
  opens with provider rows → click GitHub / Google Drive / Slack /
  Notion / MS Graph / Atlassian → JSON fills.
- **Identities** + **Events** panels: row-anchored marks make the
  page scannable.

### Next slates

Now genuinely worth picking up:

- **Full sidebar app-shell reflow** (1.5 days) — replaces the
  vertical-stack layout with the design's grouped sidebar nav
  (Overview / Catalog / Identity & access / Observability /
  Settings). Significant UX lift, careful with the existing JS.
- **Anomaly alerts** on N1 data (1 day).
- **AWS KMS envelope encryption** for `oauth_user_tokens` (1–2 days).
- **A4 (401-driven token refresh)** for phase-3/4/5.

---

## Sub-session update — 2026-05-01 (Dashboard + NHI map + Users admin — design-system aligned)

Read this section first.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 817 passed, 0 skipped
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 189 source files
```

(10 new tests this batch: 4 admin-dashboard, 6 NHI-map — 2 pure-function
+ 4 real-Postgres integration.)

### What this sub-session shipped

**Three operator-facing surfaces wired into `/operator`, all hitting
new tenant-scoped endpoints:**

**Dashboard panel.** New top-of-page KPI grid driven by
`GET /api/v1/admin/dashboard` (`api/admin_dashboard.py`). Single
endpoint aggregates seven KPIs — NHI count + 24h-active, sanctioned
MCP servers + 24h-active, virtual servers published, pending access
requests, high-risk-call count, denied/errored count, OAuth-connected
SaaS reach. Each card uses the design-system `kpi-label` /
`kpi-value` / `kpi-delta` pattern (Fraunces 36px display value,
Inter eyebrow label, neutral muted delta line). Tone variants
(`alert` / `warn`) tint the value when the metric is non-zero
in a way that matters (pending requests > 0, high-risk calls > 0).

**NHI map ("People & AI — who uses what").** New 4-column bipartite
SVG visualisation, 1 endpoint (`api/nhi_map.py`,
`GET /api/v1/nhi-map`). Layers: Users / AI Apps / MCP Servers /
Agents. AI Apps inferred from `client_metadata.user_agent` against a
known-clients allowlist (Cursor, Claude Desktop, ChatGPT, Continue,
Cline, Zed, Goose, Windsurf) — anything else renders dashed
("unsanctioned"). Edges are bezier curves between adjacent columns;
stroke-width scales with interaction count; dashed when either
endpoint is unsanctioned. Sanctioned-only filter; legend dots; sample
size annotation at the bottom. Brand-aligned colours via
`var(--vyuu-*)` tokens.

**Users panel admin drill-in.** Existing `/operator` Users panel
(which already let admins create / disable / reset-password) now
gains two per-row expanders — "Show activity" pulls
`/api/v1/identities/{user_id}/summary` (risk score, OAuth
connections, reachable upstreams, max risk category) and "API keys"
pulls `/api/v1/users/{id}/api-keys` and exposes a per-key
**Revoke (admin)** button → `DELETE /api/v1/users/{id}/api-keys/{key_id}`.
Confirmation dialog before revoke; revoked-at flagged with a danger
pill on subsequent renders.

**Brand chrome.** `/operator` hero updated to the design system's
voice — eyebrow now reads `MCP SECURITY · Govern every tool call`,
heading is `Operator Console`, lede is one sentence about what's on
this surface.

### Files added

- `src/vyuu_gateway/api/admin_dashboard.py` — KPI aggregation
- `src/vyuu_gateway/api/nhi_map.py` — 4-column bipartite data
- `tests/api/test_admin_dashboard.py` (4 tests)
- `tests/api/test_nhi_map_endpoint.py` (6 tests)

### Files updated

- `src/vyuu_gateway/api/operator_ui.py` — three new HTML sections
  (Dashboard, NHI map; Users panel re-uses existing markup with
  drill-in JS attached via `attachUserAdminControls`), three new
  JS modules (≈ 350 lines), KPI grid CSS, NHI map frame CSS.
- `src/vyuu_gateway/main.py` — wired both new routers.

### Where to see it

`http://localhost:8000/operator` — the panels appear in this order:

1. **Auth** (sign in)
2. **Dashboard** ← new (top-of-page KPIs)
3. **NHI map** ← new
4. Gateway health + Registered servers
5. Register MCP server, Virtual servers, Access requests
6. Users (now with Show-activity + API-keys expanders) ← upgraded
7. Groups, Admins, Secret store
8. **Identities** (N1 — per-principal aggregation; previously shipped)
9. Events

The NHI map populates once tool calls flow through the gateway —
the `client_metadata.user_agent` field (already captured on
inbound) drives the AI-app classification. Until traffic arrives
the panel says `(no tool-call events seen yet)`.

### Next slates

- **Anomaly alerts** on N1 data ("first ever risk=high action by
  this NHI", "Nx denials in 5min") — scheduled jobs writing to a
  new `nhi_alerts` table.
- **OAuth provider preset catalog** (Google Drive / Slack / Notion /
  Atlassian) — half-day, low-risk UI sugar.
- **A4 (401-driven token refresh)** for phase-3 / phase-4 OAuth.
- **AWS KMS envelope encryption** for `oauth_user_tokens`.
- **A6.y (Kubernetes Secrets backend)**.

---

## Sub-session update — 2026-05-01 (NHI dashboard + relation graph + visualisation — N1 + N2 + N3)

Read this section first; the earlier work sits below it.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 807 passed, 0 skipped in ~41s
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 187 source files
```

(38 new tests this batch: 9 aggregator unit, 10 list/timeline endpoint
unit, 10 graph-layer integration vs real Postgres, 5 graph-endpoint
integration, plus 4 absorbed into the existing operator-UI JS syntax
suite via the new render funcs.)

### What this sub-session shipped

**Three slates, all powered by the data the gateway was already
emitting (audit events + capabilities + grants + oauth_user_tokens):**

**N1 — Identities dashboard.** New `/operator` "Identities" panel
that aggregates `RecentAuditEmitter` events per principal:

- Service `audit/identity_aggregator.py` — pure function
  `summarize_identities(events, risk_lookup) → list[IdentitySummary]`.
  Counts total / allowed / denied / upstream-error calls, distinct
  vservers / upstreams / tools touched, last + first seen timestamps,
  per-RiskCategory histogram, and a `high_risk_calls` bucket
  (delete + admin + credential_access + data_export + execute).
- Endpoints `GET /api/v1/identities` and
  `GET /api/v1/identities/{id}/timeline` in `api/identities.py`.
  Tenant-scoped via operator JWT. `high_risk_only` query param + a
  `risk_floor` filter on the timeline.
- UI: per-identity card with risk pills, histogram, and three
  expanders (Show timeline, Show graph, Show summary).

**N2 — NHI relation-graph query layer.** New module
`graph/identity_graph.py` exposing three reads, all backed by the
existing schema:

- `principal_summary(tenant, principal_id) → PrincipalSummary | None`
  — granted vservers (direct + group + public, with `grant_path`),
  exposed tools (joined to risk_category), reachable upstreams
  (with `oauth_connected` state from `oauth_user_tokens`), OAuth
  connection rows, derived `risk_score` 0..100.
- `who_can_do(tenant, tool_name, risk_floor) → list[WhoCanDoResult]`
  — reverse query for security review ("who can call delete_repo?").
  Public vservers are intentionally excluded from the response so
  operators don't get flooded with the entire tenant.
- `dependency_chain(tenant, principal_id) → DependencyGraph` —
  nodes + directed edges (principal → vserver → tool → upstream).
- Endpoints `GET /api/v1/identities/{id}/summary`,
  `GET /api/v1/identities/{id}/graph`, `GET /api/v1/who-can-do`.

**N3 — Visualisation in the operator UI.** Static radial-layered SVG
(no canvas, no force-directed iteration, no external deps). Inline
expander on each identity card:

- Concentric rings: principal at center, then vserver / tool /
  upstream rings outward. Edges drawn as soft 1.2px lines under the
  nodes. Tool nodes get a risk-tinted fill (admin/delete = orange-
  deep, credential_access = danger, execute/data_export = warn,
  read = subtle). Hover tooltips show full label + risk.
- "Show summary" sibling expander renders the `principal_summary`
  payload as a tidy details/list block — risk-score badge,
  reachable upstreams, OAuth connections.

### Files added

- `src/vyuu_gateway/audit/identity_aggregator.py`
- `src/vyuu_gateway/api/identities.py`
- `src/vyuu_gateway/graph/identity_graph.py`
- `tests/audit/test_identity_aggregator.py` (9 tests)
- `tests/api/test_identities_endpoint.py` (10 tests)
- `tests/api/test_identity_graph_endpoints.py` (5 tests, real PG)
- `tests/graph/test_identity_graph.py` (10 tests, real PG)

### Hot-path notes

- Endpoints reuse the in-memory `RecentAuditEmitter` for the dashboard
  and DB joins for the graph layer. No new schema; no new background
  jobs.
- Risk classification draws from `mcp_capabilities.risk_category`
  (already populated by S3) — UNKNOWN when not yet synced (neither
  inflated to high-risk nor dropped).
- Public vservers are deliberately excluded from `who_can_do`
  results to avoid tenant-wide enumeration.
- The radial SVG is static — no animation, no inline event handlers,
  no `<script>` injection. Plays nicely with the strict CSP
  `default-src 'self'`.

### Next slates from BACKLOG (pick when resuming)

- **OAuth provider preset catalog** (Google Drive / Slack / Notion /
  Atlassian / Microsoft Graph) — half-day, low-risk UI sugar.
- **Anomaly alerts on top of N1** — "first ever risk=high action by
  this NHI" / "Nx delete in 5min" — scheduled jobs writing to a
  `nhi_alerts` table.
- **A4 (401-driven token refresh)** for phase-3 / phase-4 OAuth.
- **AWS KMS envelope encryption** for `oauth_user_tokens` access +
  refresh tokens (currently plaintext at rest).
- **A6.y (Kubernetes Secrets backend)**.
- **H1 (DNS-time SSRF backstop)**.

---

## Sub-session update — 2026-05-01 (A1 + mTLS upstream + A2 — autonomous batch)

Read this section first; the earlier work sits below it.

### Validation

```bash
# Full no-skip suite (Postgres + Redis + NATS + drawio):
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@localhost:5432/vyuu_gateway \
VYUU_TEST_REDIS_URL=redis://localhost:6379/15 \
VYUU_TEST_NATS_URL=nats://localhost:4222 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 769 passed, 0 skipped, 0 failed in ~38s
ruff check .  # All checks passed!
mypy src tests  # Success: no issues found in 180 source files
```

(64 new tests across this batch: 10 OAuthAuthCodeTokenProvider unit,
7 auth_authcode schema, 12 oauth_authcode endpoint integration vs real
Postgres, 2 lifecycle principal_id threading, 1 catalog
requires-user-auth surfacing, 3 provider auth_authcode wiring, 4 mTLS
schema, 3 mTLS provider with `cryptography`-generated cert, 9
OAuthJwtBearerTokenProvider unit with real RSA assertion round-trip,
8 auth_jwt_bearer schema, 1 provider builder + 4 audit-flag
extensions.)

### What this sub-session shipped

**Three slates batched in a single autonomous sweep.**

**A1 — OAuth authorization-code (phase 4) — per-user delegated tokens.**
The "Connect to GitHub / Notion / Drive" UX. Adds
`mcp_servers.auth_authcode` JSONB column + new `oauth_user_tokens`
table (RLS-bound, unique per (tenant, user, server)). New
`OAuthAuthCodeTokenProvider` mirrors phase 3's caching shape but
loads tokens from the DB instead of memory; each
`fetch_token(principal_id=...)` call hits the row, returns the
access token if fresh, otherwise drives a refresh-token exchange
and updates the row. Per-user `asyncio.Lock` collapses concurrent
refreshes from the same user into one auth-server hit; different
users still proceed in parallel. RFC 6749 §6 refresh-rotation
honoured. Pool stays keyed by `(tenant, server)` — `principal_id`
threads through `call_tool` / `fetch_token` per-call without
fragmenting the connection pool.

Four endpoints under `/api/v1/oauth-authcode/`:

- `POST {server_id}/initiate` — returns the IdP authorize URL with
  a signed state JWT (HS256, 10-minute TTL, signed with
  `portal_session_signing_secret`). Portal redirects the browser.
- `GET callback?code=...&state=...` — no auth header (state IS auth).
  Validates state, exchanges code at the token endpoint, upserts the
  `oauth_user_tokens` row, renders an HTML success page. Errors
  render HTML failure pages with `html.escape` on user-supplied
  content.
- `GET connections` — list the calling user's linked accounts (joined
  against `mcp_servers` for display names; plaintext token NEVER
  returned).
- `DELETE {server_id}/connection` — disconnect (idempotent, 204).

Portal UI:

- `requires_user_auth_servers` field on each catalog entry surfaces
  underlying servers with `auth_authcode` set. Catalog cards render
  Connect / Reconnect buttons per upstream that needs per-user OAuth.
- New "Connections" tab lists linked accounts with Disconnect.
- Connect buttons POST to `/initiate` and `window.location` to the
  returned authorize URL — same-tab flow so back-button returns the
  user to the portal.

Schema validation: HTTPS-only on all three URLs, no whitespace in
scopes, mutually exclusive with `auth_oauth` and `auth_jwt_bearer`,
no Authorization-header collision with `auth_headers` /
`auth_passthrough`. `auth_oauth_authcode=true` flag stamped on
AuditEvent.

**M-A1.5 — mTLS upstream auth.** Schema plumbing + builder wiring for
client-cert auth to upstream MCPs. New `mcp_servers.mtls_cert_ref` +
`mtls_key_ref` columns (SecretStore refs to PEM-encoded cert + key).
Both must be set together (cert without key or vice-versa rejected
at schema + provider level). `MtlsClientCredential` dataclass +
`_build_mtls_ssl_context` helper materialise PEM bytes through brief
`tempfile.NamedTemporaryFile` (unlinked the moment OpenSSL absorbs
the cert chain) into an `ssl.SSLContext`. Plumbed into:

- `StreamableHttpMcpClient` — context cached on the pooled httpx
  client + reused on per-call OAuth one-shot clients (no
  `SSLContext` rebuild per tool call).
- `SseMcpClient` — custom `httpx_client_factory` plumbed into the
  MCP SDK's `sse_client`, which doesn't accept an httpx client
  directly.

Coexists freely with header / OAuth modes — mTLS is a transport-layer
credential, separate from the application-layer Authorization
header. `auth_mtls=true` flag stamped on AuditEvent.

**A2 — OAuth JWT-bearer (RFC 7523).** Asymmetric service-account
identity for Workspace SAs (Drive, Calendar, Gmail), AWS IAM Roles
Anywhere, vendor APIs that mandate signed-JWT exchange. Adds
`mcp_servers.auth_jwt_bearer` JSONB column. Config carries
`{token_url, algorithm, private_key_ref, issuer, subject, audience,
scope?, additional_claims?, assertion_ttl_seconds?, key_id?}`.

`OAuthJwtBearerTokenProvider`: same caching contract as phase 3
(asyncio.Lock single-flight, 60s safety buffer); on each refresh
signs a fresh assertion JWT with the resolved private key and POSTs
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<jwt>`
to the token endpoint. `principal_id` is ignored — gateway-as-SA is
M2M.

Schema validation: HTTPS-only token URL, allowed algorithms RS256 /
RS384 / RS512 / ES256 / ES384 / PS256 (symmetric / `none` rejected
because they defeat the asymmetric trust model). `additional_claims`
cannot redefine reserved claims (iss/sub/aud/exp/iat/nbf/jti — schema
enforced + provider re-checks at sign time). `assertion_ttl_seconds`
capped at 600 (RFC 7523 §3 says short-lived). Mutually exclusive
with `auth_oauth` and `auth_authcode`. HTTP-only. No Authorization
collision.

Workspace SA impersonation works out of the box: distinct `subject`
(impersonated user email) and `issuer` (SA email) thread into the
assertion's `sub` and `iss` claims. Google-specific in-assertion
`scope` lands via `additional_claims={"scope":
"https://www.googleapis.com/auth/..."}`. Body-level `scope` form
param handled separately for auth servers that prefer that form.

`auth_oauth_jwt_bearer=true` flag stamped on AuditEvent.

### Migrations applied

- `20260501_0009_oauth_authcode.py` — `auth_authcode` JSONB +
  `oauth_user_tokens` table.
- `20260501_0010_mtls_and_oauth_token_rls.py` — `mtls_cert_ref` +
  `mtls_key_ref` columns + RLS-enable on `oauth_user_tokens`.
- `20260501_0011_oauth_jwt_bearer.py` — `auth_jwt_bearer` JSONB.

### Files added

- `src/vyuu_gateway/upstream/oauth_authcode.py`
- `src/vyuu_gateway/upstream/oauth_jwt_bearer.py`
- `src/vyuu_gateway/api/oauth_authcode.py`
- `tests/upstream/test_oauth_authcode.py`
- `tests/upstream/test_oauth_jwt_bearer.py`
- `tests/users/test_oauth_authcode_api.py`

### Hot-path notes

- Pool key is still `(tenant, server)`; `principal_id` flows in via
  the per-call `call_tool` arg. Phase-3 / phase-5 ignore it.
  Phase-4 uses it to look up the right user's stored token.
  Lifecycle parses `principal.id` into a UUID via
  `_principal_user_uuid`; non-UUID inputs (lab `FakeIdentityProvider`)
  collapse to None — phase-4 then surfaces
  `OAuthTokenError("user must connect first")`.
- `OAuthTokenProvider` Protocol gained an optional `principal_id`
  kwarg on `fetch_token`. All phase-3 implementations and test fakes
  ignore it explicitly via `del principal_id`.
- `AuthModeFlags` gained three new fields: `auth_oauth_authcode`,
  `auth_oauth_jwt_bearer`, `auth_mtls`. The upstream provider sets
  them from the relevant DB columns; audit events ride them.

### Next slates from BACKLOG (pick when resuming)

- A4 (401-driven refresh on top of phase 3 / phase 4)
- A6.y (Kubernetes Secrets backend)
- AWS KMS envelope encryption (relevant now that A1 stores
  refresh+access tokens in plaintext)
- H1 (DNS-time SSRF backstop)
- H3 (payload size limits + response inspection)
- S1.b (Cosign / Sigstore signature verification for `binary`)

---

## Sub-session update — 2026-04-30 (Outbound auth — phase 3: OAuth client-credentials)

Read this section first; the earlier 2026-04-30 work sits below it.

### Validation

```bash
pytest        # 447 passed, 19 skipped
ruff check . # All checks passed!
mypy .       # Success: no issues found in 125 source files

# Full no-skip (Postgres + Redis + drawio):
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 466 passed
```

(Fifteen new tests this slice: 7 token provider unit tests, 5 schema/registration, 2 provider integration, 1 outbound end-to-end.)

### What this sub-session shipped

**Phase 3 of outbound auth — OAuth 2.0 client-credentials grant (RFC 6749).**

This closes the third leg of the outbound-auth tripod:

| Mode | Whose credential | Right for |
|---|---|---|
| Phase 1 — `auth_headers` (org-tier) | One corp credential in the gateway's `SecretStore` | Datadog, Wiz tenant, internal MCPs, Snyk org |
| Phase 2 — `auth_passthrough` (user-tier) | End user supplies their own per request | GitHub PAT, Notion, Linear, "I have my own PayPal merchant account" |
| **Phase 3 — `auth_oauth` (token exchange)** | Gateway brokers M2M token grant on the user's behalf | Wiz, OIDC-spec-compliant SaaS, Auth0/Okta-fronted internal services |

Phase 3 is the unblock for upstreams that require **token exchange** rather than a static API key. The gateway holds the durable identity (`client_id`, `client_secret`) in the `SecretStore` (refs only, not raw), brokers the M2M flow on each upstream connection, caches the access token in memory until expiry, and rides it as `Authorization: Bearer <token>` on every upstream call.

What's not in this slice: OAuth 2.0 **authorization-code** flow with per-user consent / redirects (phase 4). Different beast — token storage with TTL per (user, server), redirect handling, dynamic-client-registration, revocation. Pass-through (phase 2) handles the user-tier case for SaaS that issue PATs; authorization-code is for SaaS that don't (Linear, Salesforce, GitHub Apps).

1. **`vyuu_gateway/upstream/oauth.py`** — new module.
   - `OAuthClientCredentialsConfig` (frozen dataclass) — token_url, client_id_ref, client_secret_ref, optional scope + audience.
   - `OAuthTokenProvider` Protocol — `async fetch_token() -> str`.
   - `CachedOAuthTokenProvider` — in-memory token cache with concurrent-safe refresh:
     - **Fast path**: cached + not expired → returns token without acquiring the lock.
     - **Slow path**: under an `asyncio.Lock`, double-check then refresh. Hot upstream triggering N parallel calls during a refresh produces **one** token request to the auth server, not N.
     - 60s safety buffer on TTL — a token cached at T with `expires_in=3600` is treated as expired at T+3540 to avoid the boundary race.
     - Default `expires_in=3600` if the auth server omits it (RFC 6749 says it's optional).
     - Hard 10s timeout on the token POST.
     - `OAuthTokenError` raised on network failure / non-200 / malformed response — class name only, never the upstream response body (auth servers often echo identifying info in errors).
   - `client_id_ref` and `client_secret_ref` resolve through `SecretStore` on **every** refresh, not at provider construction. A rotated secret in the KMS takes effect on the next refresh without restarting the gateway.

2. **DB schema — migration `20260430_0004`.**
   - `mcp_servers.auth_oauth JSONB` (nullable). Carries the spec dict; refs only, never raw credentials.
   - Default null — most servers don't use OAuth.

3. **Schema validation — five new rules.**
   - `auth_oauth.token_url` must be **`https://`**. A plaintext token URL would expose `client_id` / `client_secret` on the wire (they ride as HTTP basic auth on the token request).
   - `auth_oauth` is HTTP-only (rejected on stdio at registration → 422).
   - `auth_oauth` cannot coexist with an explicit `Authorization` in `auth_headers` — OAuth always sets that header, so two sources would silently shadow.
   - `auth_oauth` cannot coexist with any `auth_passthrough` value of `Authorization` — same rule.
   - Both refs (`client_id_ref`, `client_secret_ref`) must be non-empty.

4. **Outbound client integration.**
   - `StreamableHttpMcpClient.__init__(..., oauth_token_provider=...)` accepts an optional provider.
   - When set, **every** `call_tool` goes through the **one-shot** session path (not the pooled path). The rotating bearer token is bound to the single call, never baked into the long-lived pooled httpx client.
   - `_build_per_call_overrides` merges org-tier `extra_headers` + OAuth bearer + user-tier passthrough. OAuth always wins on `Authorization` (the schema validator already prevents passthrough collision).
   - One-shot client mirrors the pooled client's `transport` so ASGITransport-backed tests work.

5. **Provider integration.**
   - `DatabaseBackedUpstreamClientProvider._build_oauth_provider(server)` — when `server.auth_oauth` is set, builds a `CachedOAuthTokenProvider` and caches it per `(tenant_id, server_id)` so the **in-memory access-token cache survives circuit-breaker / pool-reconnect cycles**. Rebuilding clients (e.g. after a transport change) doesn't refetch tokens.
   - Reuses the gateway's existing `SecretStore` instance.

6. **Operator UI.**
   - Fourth optional field on the register form, labeled "Auth OAuth (HTTP only) — JSON {token_url, client_id_ref, client_secret_ref, scope?, audience?}".
   - JS extends the existing JSON-parse + omit-when-empty pattern.

7. **Live verification (with the running lab):**
   - Registered `wiz-oauth-demo` at `https://api.wiz.io/mcp` with `auth_oauth = {token_url, client_id_ref, client_secret_ref, audience}`. Response echoes the **refs** (`wiz-client-secret`), never the resolved values.
   - Probed the resulting outbound client: `_oauth_token_provider` is a `CachedOAuthTokenProvider` with the right config.
   - Probed cache reuse: `provider.get_client(...)` twice → same `_oauth_token_provider` instance both times → token cache stays warm.
   - Negative cases verified through the live API:
     - `token_url=http://...` → 422 with `OAuth token_url must be an https URL`.
     - `auth_oauth + auth_headers["Authorization"]` → 422 with the collision error.

### Threat model & operational notes

- **No raw credentials persisted.** The DB carries only opaque refs. `client_id` / `client_secret` live in the `SecretStore` (Vault / AWS Secrets Manager / k8s secret in production; in-memory in dev). A DB dump or read-replica leak does not expose credentials. Access tokens never persist anywhere — they live in memory until expiry and vanish on gateway restart.
- **HTTPS-only token URL.** Schema rejects plaintext at registration time, not at first call. A misconfigured upstream cannot accidentally POST `client_secret` over HTTP.
- **Concurrent-safe refresh.** Hot upstream → N parallel calls during a token refresh → exactly **one** token request to the auth server. The async lock + double-check pattern in `CachedOAuthTokenProvider.fetch_token` enforces this. Test verifies it directly with 8 parallel callers.
- **Token never logged.** Lives on the one-shot httpx client's default headers and on `CachedOAuthTokenProvider._access_token` only. Structured logger's `extra={...}` doesn't include it. Audit events don't capture it.
- **No 401-driven refresh in this phase.** If the cached token expires mid-call (cache-side clock skew vs auth-server-side TTL), the call fails. Operator can manually re-sync. Adding a 401-detection retry on top of this is a small addition — about 30 lines — but it requires the upstream MCP SDK to expose 401s clearly, which today's `streamable_http_client` largely abstracts away. Worth measuring real-world flake rates before adding.
- **Token endpoint is independent of upstream pool.** OAuth requests use a fresh httpx client per refresh (no connection-state leakage across token requests). The 10s hard timeout prevents a slow auth server from wedging upstream calls — refresh fails fast, the call surfaces a clean `OAuthTokenError`.
- **Coexistence rules.** A server can be **either** OAuth **or** explicit Authorization (org or user-tier), never both. A server CAN combine OAuth (for `Authorization`) with org-tier `auth_headers` for *other* headers (`X-Tenant-Id`, etc.) and with user-tier `auth_passthrough` for *non-Authorization* headers.

### What's still pending (in enterprise-impact order)

1. **OAuth 2.0 authorization-code flow** — phase 4. Per-user delegated tokens via "Connect to GitHub / Notion / Linear / Salesforce" UX. Token storage with TTL per (user, server), redirect handling, dynamic-client-registration, revocation. ~3-5 days. Bigger than phase 3.
2. **OCI / Docker source type.** ~2 days.
3. **Static binary source type.** ~1 day. **Next up per the user's roadmap.**
4. **Real Kafka / NATS audit producer + AsyncGraphEventEmitter** — production telemetry. ~2-3 days. **Then this per the user's roadmap.**
5. **SSE outbound** — ~2 hours.
6. **Real OIDC / API-key identity provider** for the operator API + inbound MCP — replaces fakes.
7. **Audit signal for OAuth refresh / pass-through usage** — booleans on the audit event so operators can see which auth model is firing per call. ~1 hour.
8. **401-driven token refresh on top of phase 3.** ~half day if the SDK exposes 401s; otherwise more.
9. **Registration-time MCP probe + periodic capability-sync worker.** ~half day + ~1 day.
10. **DNS-time SSRF backstop, TLS / mTLS at ingress, payload-size limits.**

### Local-machine state

- Postgres (lab) on `127.0.0.1:5432`, DB `vyuu_gateway`, migrations through `20260430_0004`.
- Postgres (test cluster) on `127.0.0.1:55432`, DB `vyuu_gateway_rls_test`, also through `20260430_0004`.
- Redis on `127.0.0.1:6390/15`.
- Lab on `127.0.0.1:8765`. Operator console at `/operator`.
- Demo rows persisted from this session: `wiz-oauth-demo` (id `c4558c10-...`) — registered with `auth_oauth` against `https://auth.wiz.io/oauth/token`. Won't actually exchange (Wiz wouldn't recognize the seeded refs) but proves the registration → provider-wiring → outbound-client path.

---

## Sub-session update — 2026-05-01 (Portal Vyuu design pass + cards grid + search)

Read this section first. Earlier sub-sessions sit below.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 705 passed, 2 skipped (Keycloak-gated) — no behavior change
ruff check . # All checks passed!
mypy .       # Success: no issues found in 189 source files
```

(No backend changes — UI-only batch. JS-syntax test continues to assert both `operator_ui` + `portal_ui` pass `node --check`.)

### What this batch shipped

End-user portal at `/portal` got a full visual + UX overhaul without changing any API contracts. Three coordinated changes:

#### 1. Vyuu Design System — applied verbatim

The portal previously used a stand-alone dark-theme palette (`--bg: #0d1117` etc) that didn't match the operator console. It now uses **the exact same `:root` token block** the operator console uses, sourced from `Vyuu Design Handoff/tokens/tokens.css`:

- Cream-paper page background (`--vyuu-bg: #F7F4ED`), ivory panels, ink text (`--vyuu-ink: #1F2A2E`).
- Burnt-orange primary (`--vyuu-orange-deep: #A85820`) on submit buttons; ghost variant for secondary.
- Type stack: Fraunces serif headings, Inter UI / body, JetBrains Mono for code.
- Pill anatomy matches operator-side semantics — `.granted`/`.public`/`.approved` use `orange-soft` background, `.private`/`.pending` use `warn-tint`, `.declined`/`.withdrawn` use `danger-tint`, `.locked` uses `line-soft`.
- Tabs upgraded from underline-rail to a **pill-rail group** matching the operator console — selected tab gets the panel-coloured pill with `--vyuu-shadow-md` lift, others stay muted.
- Output blocks (the API-key plaintext etc) keep the dark code-bg + JetBrains Mono treatment from the spec.

The two surfaces are now visually consistent — same tenant administrator can flip between `/operator` and `/portal` and feel they're using one product.

#### 2. Cards-as-grid (side-by-side)

Previously the cards stacked vertically: one row per item, full width. Now:

```css
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 16px;
}
```

`auto-fill` + `minmax(300px, 1fr)` means at typical desktop widths you see two-three columns of side-by-side cards; below ~640px viewport they collapse to a single column. No JavaScript / breakpoint logic needed — pure CSS.

Each card became a **flex column** with three regions: `.card-meta` (title + badges + small details), middle space, and `.card-actions` (always at the bottom — buttons line up across cards regardless of meta length, looks clean).

The same grid + card structure applies across Catalog, My requests, and My API keys.

#### 3. Search + filter on every cards-grid panel

Every panel that lists a collection got a `.toolbar` row above the cards grid:

| Panel | Search input | Filter dropdown | Live count |
|---|---|---|---|
| **Catalog** | by vserver name / id (substring) | All / Has access / Locked | "X of Y" |
| **My access requests** | by note / decision_note / vserver id | All / Pending / Approved / Declined / Withdrawn | "X of Y" |
| **My API keys** | by label / prefix | All / Active / Revoked | "X of Y" |

Implementation note: search/filter operate over **cached server response** (one cache per panel) so keystrokes don't fire a fetch on every input. The user clicks **Refresh** when they want fresh data; the search input only re-renders from the local cache. Each panel got a tiny refactor: `refreshX()` now fetches + updates the cache + delegates to `renderX()`; `renderX()` reads the cache + applies filters + renders the visible subset. Filter inputs bind to `renderX()` directly via `addEventListener("input", renderX)`.

The toolbar's "X of Y" label updates live so users see the cardinality of their filter — useful when scanning a long catalog.

### Files changed

1. **`vyuu_gateway/api/portal_ui.py`** —
   - `_CSS`: full replacement with the Vyuu Design System tokens + matching panel / button / pill / form / output / tab styles. Cards grid uses `auto-fill, minmax(300px, 1fr)`.
   - `_HTML`: `.toolbar` rows added above each cards grid (Catalog / Requests / Keys); each carries a `<input type="search">`, a status `<select>`, and a `.toolbar-meta` count span.
   - `_JS`: `refreshCatalog/Requests/Keys` split into fetch-and-cache vs render-from-cache pairs. New filter input listeners. New `renderCatalogCard` / `renderRequestCard` / `renderKeyCard` helpers. Cards now use `.card-meta` + `.card-actions` instead of inline flex styling.

### What this is NOT

- No backend changes. Same routes, same payloads.
- No new tests needed — JS-syntax regression test (`tests/test_operator_ui_js_syntax.py`) covers the parse-check via `node --check`.
- No design-system token additions — kept verbatim from the operator-console copy. If the canonical tokens at `Vyuu Design Handoff/tokens/tokens.css` evolve, both UIs need a sync.

### Foundation for the upcoming Claude design pass

What's intentionally left for the design pass to refine:
- Exact spacing rhythm inside cards (current 18px feels right but unverified against the design).
- Empty-state illustrations / messaging tone.
- Login screen visual treatment (currently inherits the panel + form-grid baseline, no hero imagery).
- Mobile-specific layouts (current breakpoint behavior is auto-fill-driven; no phone-specific affordances).
- Settings tab content density (single panel today; could be sub-grouped).

The structural baseline (tab navigation, cards-as-grid, search on each panel) is deliberately stable so the design pass focuses on visual polish, not layout architecture.

### Resume-here cookbook

```bash
# 1. Server is already running with the new portal — hard-refresh
#    /portal in your browser (Cmd+Shift+R) and sign in.

# 2. Try the search:
#    Catalog tab → type into "Search by name…" — count updates as
#    you type, cards filter live. Drop the Access dropdown to "Locked"
#    to see only vservers you'd need to request.

# 3. Confirm Vyuu look:
curl -s http://127.0.0.1:8000/portal/app.css | grep -c "vyuu-orange-deep"
# → should print 10+ (the token + multiple usages)
```

---

## Sub-session update — 2026-04-30 (Access-attempt telemetry on Events panel)

The access-attempt section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 705 passed, 2 skipped (Keycloak-gated)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 189 source files
```

(6 new tests vs. previous 699 — `tests/audit/test_access_attempt_events.py`: factory shape + sentinel tool, vserver-not-found case (no UUID), recent-emitter event_type filter, endpoint event_type filter happy path, no-filter returns both types, bogus event_type → 422.)

### What this batch shipped

**The "smart-azz uses someone else's URL" telemetry gap.** Previously the lifecycle only emitted audit events on `tools/call`. Connection-level rejections (invalid bearer, vserver not found, no grant) returned the right HTTP status but **never reached the operator-console Events panel** — operators had no visibility into who was probing what.

Now: every `/v/{tenant}/{vserver}/mcp` rejection emits an `access_attempt` audit event into the same ring buffer that drives the Events panel. The user's specific concern — "smart-azz uses /v/t-id/example/mcp but this hasn't been provisioned to him, and tries to access using his API key" — surfaces as a `no_grant` reason, with the principal's actual identity recorded (because their bearer was valid).

### How it works

**Schema additions on `AuditEvent`** (default-friendly — existing consumers see no shape break):

- `event_type: AuditEventType` — enum `tool_call` | `access_attempt`. Default `tool_call` keeps existing emitters unchanged.
- `auth_failure_reason: AuthFailureReason | None` — enum `invalid_bearer` | `vserver_not_found` | `no_grant` | `disabled_principal`.
- `vserver_name: str | None` — populated for access attempts where the URL-path name is the only identifier (e.g. vserver-not-found case has no UUID).

New factory `create_access_attempt_audit_event(...)` mints these — sets `tool="<connect>"` (no real tool exists at this point), `decision=DENY`, `policy_rule_id=<reason>` (so audit-pipeline consumers grouping by rule_id surface auth-failures cleanly).

**Inbound route** (`api/inbound_mcp.py`) emits at three failure points:

1. **`IdentityValidationError`** (bad bearer) → `INVALID_BEARER` with synthetic `<unknown>` audit principal.
2. **Vserver lookup misses** → `VSERVER_NOT_FOUND` with the real principal + URL-path vserver name.
3. **`VirtualServerAccessDeniedError`** (no grant) → `NO_GRANT` with the real principal + actual `vserver_id` and `vserver_name`. **This is the headline case** the user asked about.

Emit is best-effort wrapped in `try/except` — audit failure must not break the request path. The event flows through the same `RecentAuditEmitter` that powers the Events panel + any inner Kafka / NATS producer.

**Query / endpoint surface:**

- `RecentAuditEmitter.query(event_type=...)` — new optional filter; tenant scoping unchanged.
- `GET /api/v1/audit-events?event_type=access_attempt` — typed FastAPI query param, 422 on bogus values.

**Operator UI:**

- Events panel filter row gets a new **Event type** dropdown (`— any —` / `tool calls` / `access attempts (auth failures)`).
- Access-attempt cards render distinctly:
  - Red left-border accent for at-a-glance visual separation
  - 🚫 prefix + `access denied` (danger) pill + reason pill (warn) at the head
  - "attempted vserver: \<name>" line when no UUID exists
  - Same principal / timestamp / vserver block as tool-call events
- `labelForAuthFailure()` JS helper maps the reason enum to human-readable labels.

### Verified end-to-end

```bash
$ curl -X POST http://127.0.0.1:8000/v/<tenant>/no-such-vserver/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}'
HTTP 401

$ curl http://127.0.0.1:8000/api/v1/audit-events?event_type=access_attempt \
  -H "Authorization: Bearer $OP_TOKEN"
[{
  "event_type": "access_attempt",
  "auth_failure_reason": "invalid_bearer",
  "vserver_name": "no-such-vserver",
  "principal": { "type": "api_key", "id": "<unknown>" },
  "decision": "deny", ...
}]
```

The card renders on `/operator` Events panel with the red-bordered styling.

### Files added / changed

1. **`vyuu_gateway/audit/events.py`** — `AuditEventType`, `AuthFailureReason` enums; `vserver_name` + `event_type` + `auth_failure_reason` fields on `AuditEvent`; new `create_access_attempt_audit_event(...)` factory.
2. **`vyuu_gateway/audit/recent.py`** — `query(event_type=...)` filter.
3. **`vyuu_gateway/api/inbound_mcp.py`** — `_emit_access_attempt(...)` helper + emit calls at the three failure points.
4. **`vyuu_gateway/api/audit_events.py`** — `AuditEventView` exposes the new fields; endpoint accepts `event_type` query param.
5. **`vyuu_gateway/api/operator_ui.py`** — Event type dropdown in the filter row; `renderAuditEvent` switches rendering for access-attempt cards; `labelForAuthFailure` helper.
6. **`tests/audit/test_access_attempt_events.py`** — 6 new tests.

### Backlog post-batch

Unchanged from previous batch — A1, A2, A3-β.x, A4, A6.y, AWS KMS, H1, H3, mTLS upstream, P1/P2/P3, S1.b. Plus the upcoming portal UI design pass (you're taking through Claude design).

### Resume-here cookbook

```bash
# 1. Sign in to /operator (existing login)

# 2. Trigger an access attempt — paste a vserver URL into Cursor with
#    a bearer that doesn't have a grant, OR curl directly:
curl -X POST http://127.0.0.1:8000/v/<tenant>/<some-vserver>/mcp \
  -H 'Authorization: Bearer <bearer-without-grant>' \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}'

# 3. /operator → Events panel → Event type filter = "access attempts"
#    → Refresh. The denied attempt appears with red-bordered card,
#    🚫 access denied + no_grant pills, and the attempted vserver
#    name + principal identity.
```

---

## Sub-session update — 2026-04-30 (Operator login + Admins panel + Events polish + Portal tabs)

The operator-login section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 699 passed, 2 skipped (Keycloak-gated)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 188 source files
```

(13 new tests vs. previous 686 — `tests/operator_auth/test_password_login.py` covers login happy/wrong-password/unknown-email/disabled/legacy-no-password, admin-create-then-login, weak-password 422, duplicate-email 409, self-disable 400, disable-then-login-fails, self-rotate, no-token 401.)

### What this batch shipped

Three coordinated UI / auth pieces:

#### 1. Operator login + Admins panel (replaces the paste-token flow)

DB migration `0008` adds `password_hash` + `last_login_at` + `disabled_at` + `must_change_password` to `operators`. Bootstrap is forward-compatible: on first restart after the migration, if a legacy operator matching `VYUU_BOOTSTRAP_ADMIN_EMAIL` exists with `password_hash=null`, the env-var password is applied with `must_change_password=true`. New deployments hit the create-from-scratch branch unchanged.

Backend:
- `OperatorPasswordAuthProvider` + `authenticate_operator_with_password` in `operator_auth/password_auth.py`. Reuses the existing JWT format (`mint_operator_test_token` mints; `authenticate_operator` verifies — both untouched). Anti-enumeration: every failure path uses the same generic `OperatorLoginError`, with constant-time bcrypt verify against a dummy hash on the unknown-email branch so timing doesn't leak.
- `POST /api/v1/operator-auth/login` — `(tenant_id, email, password)` → bearer token + operator metadata.
- `POST /api/v1/operator-auth/password` — self-rotate, requires current password.
- `GET / POST / DELETE / POST-password /api/v1/admins[/{id}]` — list / create / disable / reset password for other operators in the tenant.
- `delete /admins/{id}` blocks self-disable (400) so an admin can't lock the tenant out.

Operator UI:
- The "Operator token" panel becomes a **Sign in** form (tenant ID + email + password) with the existing paste-token flow demoted to an `<details>` "Advanced" expander for lab / automation use.
- After login: form hides, a "Signed in" block shows the active operator's email + role + tenant + a Log out button.
- New **"Admins"** panel between "Pending access requests" and "Users". Lists all operators with last_login + disabled state. "Create admin" form with email + role dropdown + initial password (>= 12 chars). Per-row Reset password / Disable buttons.

Tests + lab continue to use `mint_operator_test_token` directly — paste-token mode is preserved so nothing broke.

#### 2. Events panel polish + capture-default flag

`Settings.audit_capture_raw_default` (env: `VYUU_AUDIT_CAPTURE_RAW_DEFAULT`). Default `False` — privacy-by-default per spec §3.3. When `true`, `SimplePolicyProvider` returns `PolicyDecision.allow(capture_raw_args=True, capture_raw_response=True)` on every allow, so the operator console's Events panel renders full request + response bodies for every call (lab / POC default). Production keeps default-off; per-rule policy authoring still works either way.

UI:
- Renamed "Tool-call activity" → **"Events"**.
- New filter row: vserver dropdown · tool-name substring · decision dropdown · result limit. Tool + decision filters apply client-side over the same `/audit-events` payload (the buffer is bounded so per-card filter cost is trivial).
- Raw-args / raw-response now render via a shared `renderRawCaptureBlock(label, payload, truncated)` helper: pretty-printed JSON in a `<pre>`, a per-block **Copy** button using the Clipboard API, "truncated" pill when the size cap fired. Block default-open so operators see content immediately.
- Footer note when capture wasn't on stays in place (tells operators how to opt in).

#### 3. Portal tab navigation

`/portal` was an all-on-one-page scroll of four panels (Catalog · My Requests · API Keys · Change Password). Now: a tabbed interface — clicking a tab toggles which panel is visible.

- New `<nav class="tabs">` element with four tabs.
- New `selectTab(name)` JS handler flips `aria-selected` + the panel's `hidden` attribute.
- "Settings" tab + panel auto-hide for OIDC users (no password to rotate); local-auth keeps both.
- CSS: minimal — accent-coloured underline on the active tab, muted on the rest.

Same content; better navigation and visual hierarchy. Foundation for the upcoming Claude-design pass.

### Files added / changed

1. **`migrations/versions/20260430_0008_operator_password_auth.py`** — new migration.
2. **`vyuu_gateway/db/models.py`** — `Operator` got `password_hash` / `must_change_password` / `last_login_at` / `disabled_at`.
3. **`vyuu_gateway/operator_auth/password_auth.py`** — new module with login + admin-management service functions.
4. **`vyuu_gateway/api/operator_auth.py`** — new module: login + self-rotate + admins routes.
5. **`vyuu_gateway/main.py`** — wires `operator_auth_router` at `/api/v1`.
6. **`vyuu_gateway/bootstrap.py`** — operator `password_hash` is now seeded from `VYUU_BOOTSTRAP_ADMIN_PASSWORD` for new tenants AND backfilled on the first restart for legacy operators (forward-compat).
7. **`vyuu_gateway/policy/simple.py`** — `SimplePolicyProvider(capture_raw_audit=...)` toggles H5 capture by default per env flag.
8. **`vyuu_gateway/config.py`** — new `audit_capture_raw_default` setting.
9. **`vyuu_gateway/api/operator_ui.py`** — login form replaces paste-token; Admins panel + JS; Events panel rename + filters + Copy buttons + `renderRawCaptureBlock` helper.
10. **`vyuu_gateway/api/portal_ui.py`** — tab nav + `selectTab` handler + Settings tab auto-hide for OIDC users + minimal `.tabs` CSS.
11. **`tests/operator_auth/test_password_login.py`** — 13 end-to-end tests.

### Backlog post-batch

Still open:

- **A1** OAuth authorization-code (phase 4) — biggest functional gap.
- **A2** OAuth JWT-bearer (RFC 7523).
- **A3-β.x** Real-Keycloak integration test.
- **A4** 401-driven token refresh.
- **A6.y** k8s-secrets `SecretStore` impl.
- **AWS KMS** direct integration.
- **H1** DNS-time SSRF backstop.
- **H3** Payload-size limits + response redaction.
- **mTLS upstream-cert ref**.
- **P1/P2/P3** Performance polish.
- **S1.b** Cosign verification for binary source.
- **Portal UI design pass** — user is taking this through Claude design; tab navigation here is the structural baseline.

### Resume-here cookbook

```bash
# 1. Apply migrations:
VYUU_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
alembic upgrade head        # 0007 → 0008

# 2. Restart with audit-capture default ON for dev (events show full bodies):
VYUU_AUDIT_CAPTURE_RAW_DEFAULT=true \
VYUU_INBOUND_IDENTITY_PROVIDER=api_key \
VYUU_BOOTSTRAP_TENANT_NAME="Acme Corp" \
VYUU_BOOTSTRAP_ADMIN_EMAIL=admin@acme.example \
VYUU_BOOTSTRAP_ADMIN_PASSWORD="bootstrap-strong-12+chars" \
... uvicorn vyuu_gateway.main:create_app --factory --port 8000

# 3. Sign in via the new login form:
#    Open http://127.0.0.1:8000/operator
#    Fill in tenant_id, email, password (or paste a bearer token under
#    "Advanced" if you have automation that needs that).

# 4. Add a second admin via Admins panel → "Create admin" form.

# 5. After a tool call, hit Events panel → Refresh → full input/output
#    visible with Copy buttons.
```

---

## Sub-session update — 2026-04-30 (A6.x AWS Secrets Manager + operator backend-choice panel)

The A6.x section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 684 passed, 2 skipped (Keycloak-gated)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 183 source files
```

(15 new tests vs. previous 669 — `tests/test_aws_secrets_manager_store.py`. All use `botocore.stub.Stubber` so no live AWS calls.)

### What this sub-session shipped

**A6.x — AWS Secrets Manager `SecretStore` impl.** Drops in alongside Vault behind the same `SecretStore` Protocol, selected at deploy time via `VYUU_SECRET_STORE_BACKEND=aws_secrets_manager`. Path layout `{prefix}/{tenant_id}/{ref}` matches Vault's per-tenant URL prefix → IAM resource-ARN templating just works for per-tenant scoping. Full error-mapping discipline:

- `ResourceNotFoundException` → `SecretNotFoundError` (Protocol-standard).
- `AccessDeniedException` / `ThrottlingException` / `BotoCoreError` → `AwsSecretsManagerBackendError`. **Critical:** access-denied is NEVER masked as not-found — would hide IAM misconfiguration.
- Missing `SecretString` (binary-only secrets we don't support) → backend error.
- `value_field` config matches the Vault store's convention: when set, treat `SecretString` as JSON and pull the named key; when unset (the common case), the whole `SecretString` IS the value (operators paste a Bearer token directly).

Auth via boto3's default credential chain — IAM access keys, IAM Roles Anywhere, EC2/ECS/EKS instance / task / pod identity all work without code changes. `health_check()` calls `list_secrets(MaxResults=1)`; AccessDenied on `list_secrets` is treated as a soft warning (perfectly fine if the IAM policy is scoped to `GetSecretValue` only — we still know AWS is reachable).

**Operator UI panel — "Secret store".** New section on `/operator` between Groups and Tool-call activity. Renders:

- Active backend name + an `healthy` / `unhealthy` pill from a no-cost connectivity probe (Vault `/sys/health` or AWS `list_secrets`).
- Recommendation context: "Dev / lab / tests only" for memory, "POC + on-prem-only" for Vault, "AWS-native deployments and customers standardised on AWS" for AWS.
- Health-probe detail: Vault version, IAM posture, network-error class.
- Two `<details>` blocks with the env vars to switch to each non-active backend. Operators copy these into their deployment.

**Read-only on purpose** — the secret-store choice stays a deployment-time env var. Three reasons documented in `secret_store.py` docstring + the new ops doc:
1. Auth blast radius (Vault token / AWS keys are long-lived, treat env var as IaC).
2. Pool consistency (existing httpx clients have resolved secrets baked in; runtime swap = pool-wide invalidation).
3. Validation is the actual question the panel answers — "does the configured backend work as deployed?"

**`/api/v1/secret-store/status` endpoint** drives the panel. Operator JWT auth. Returns `SecretStoreStatusResponse` with stable wire shape (we don't dump internal `Settings` directly).

**`VaultSecretStore.health_check()`** added for symmetry. Hits `/v1/sys/health`; treats 200 (active) and 429 (standby) as healthy for read traffic. Reports sealed status + Vault version.

### Files added / changed

1. **`pyproject.toml`** — `boto3>=1.35.0` added. mypy override block extended to ignore-missing-imports for `boto3` / `botocore.*` (no py.typed marker on those packages yet).

2. **`vyuu_gateway/secrets/aws_secrets_manager.py`** — new `AwsSecretsManagerStore`. Lazy boto3 client, configurable region / prefix / value_field. `health_check()` returns `(ok, detail)`. `aclose()` no-op (boto3 doesn't need it; symmetry with Vault).

3. **`vyuu_gateway/secrets/__init__.py`** — re-exports new symbols.

4. **`vyuu_gateway/secrets/vault.py`** — `health_check()` added to `VaultSecretStore` for parity.

5. **`vyuu_gateway/config.py`** — new `aws_region` / `aws_secrets_prefix` / `aws_secrets_value_field` fields. Updated docstring on `secret_store_backend` to cover all three backends + when to pick each.

6. **`vyuu_gateway/main.py`** — `_build_default_secret_store` got the `aws_secrets_manager` branch. `secret_store_router` mounted at `/api/v1`.

7. **`vyuu_gateway/api/secret_store.py`** — new module. `GET /api/v1/secret-store/status` endpoint. `_probe_backend(store)` duck-typed to call `health_check` if present (so `InMemorySecretStore` works without modification — reports "in-process store").

8. **`vyuu_gateway/api/operator_ui.py`** — new "Secret store" HTML section + `loadSecretStoreStatus()` / `renderSecretStoreCard(status)` JS handlers.

9. **`docs/operations/secret-store-setup.md`** — new ops doc. Vault-vs-AWS picker, POC-→-prod progression diagram, install + IAM policy snippets for both, on-prem-talking-to-AWS guidance (network, latency, cost, compliance), explanation of why deployment-time vs UI-driven.

10. **Tests:** `tests/test_aws_secrets_manager_store.py` — 15 tests using `botocore.stub.Stubber`.

### Backend choice — what's the dev default?

The codebase `Settings.secret_store_backend` default stays `memory` because tests + the lab need to boot without an external dependency.

For deployment, **Vault is the recommended POC default** (per your direction): the operator-console panel surfaces this prominently, the new ops doc walks through it, and the lab `examples/drawio_lab_server.py` keeps using in-memory only because it's an explicit dev mode.

When a customer goes to deploy, the operator UI tells them: memory = dev only; Vault = POC + on-prem; AWS = AWS-native or already-standardised.

### Backlog post-batch

Still open:

- **A1** OAuth authorization-code (phase 4) — biggest remaining gap.
- **A2** OAuth JWT-bearer (RFC 7523).
- **A3-β.x** Real-Keycloak integration test.
- **A4** 401-driven token refresh.
- **A6.y** Kubernetes Secrets backend — same Protocol, lift-and-shift now that Vault + AWS are reference impls.
- **AWS KMS** direct integration (envelope encryption for at-rest data) — sized when use case is concrete; not currently blocking.
- **H1** DNS-time SSRF backstop.
- **H3** Payload-size limits + response redaction.
- **mTLS upstream-cert ref** — `mcp_servers.mtls_cert_ref` columns + builder wiring.
- **P1/P2/P3** Performance polish.
- **S1.b** Cosign verification for binary source.

### Resume-here cookbook

```bash
# Verify the new panel from curl:
curl -s "http://127.0.0.1:8000/api/v1/secret-store/status" \
  -H "Authorization: Bearer $OP_TOKEN" | jq

# Switch to Vault (POC):
VYUU_SECRET_STORE_BACKEND=vault \
VYUU_VAULT_ADDR=https://vault.example:8200 \
VYUU_VAULT_TOKEN=hvs.xxx \
... uvicorn vyuu_gateway.main:create_app --factory --port 8000

# Switch to AWS Secrets Manager (production):
VYUU_SECRET_STORE_BACKEND=aws_secrets_manager \
VYUU_AWS_REGION=us-east-1 \
AWS_ACCESS_KEY_ID=... \
AWS_SECRET_ACCESS_KEY=... \
... uvicorn vyuu_gateway.main:create_app --factory --port 8000

# Operator console:
open http://127.0.0.1:8000/operator
# → "Secret store" panel between Groups and Tool-call activity
```

---

## Sub-session update — 2026-04-30 (A6 Vault + H5 raw capture + S8 manifest discovery + H2 TLS docs)

The A6/H5/S8/H2 section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 669 passed, 2 skipped (Keycloak-gated)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 180 source files
```

(41 new tests vs. previous 628: 13 Vault, 11 H5 raw-capture, 17 S8 manifest.)

### What this batch shipped

Four backlog items in one push: one production-hardening (A6 — Vault), one compliance-flow (H5 — opt-in raw audit), one operator-UX (S8 — manifest discovery), one ops-docs (H2 — TLS / mTLS guide).

#### A6 — HashiCorp Vault SecretStore

`VaultSecretStore` reads from Vault KV v2 at `{mount}/data/{tenant_id}/{ref}`. Static-token auth (the simplest production-viable mode); AppRole / k8s-auth slots reserved for follow-up. Per-tenant URL prefix lets Vault ACL templates gate `{mount}/data/{tenant}/*` per-tenant identity — defense in depth on top of the gateway-side `tenant_id` parameter.

Key contract decisions:
- 404 → `SecretNotFoundError` (Protocol-standard, no leak about which other tenants might have the ref).
- 403 / 5xx → `VaultBackendError` (NOT `SecretNotFoundError` — masking a permissions error as missing-secret would hide ACL misconfiguration).
- Malformed payload / non-JSON / missing `value` field → `VaultBackendError`.
- Custom `value_field` lets operators with a non-standard JSON-key convention (e.g. `"token"` instead of `"value"`) override at construction.
- Lazy httpx client construction so importing this module is cheap.
- Optional `X-Vault-Namespace` header for Vault Enterprise namespacing.
- Configured via `VYUU_SECRET_STORE_BACKEND=vault` + `VYUU_VAULT_ADDR` + `VYUU_VAULT_TOKEN`. Missing addr/token raises a clear startup error.

Same Protocol as before — every existing call path (`auth_headers`, `auth_env`, OAuth client-credentials secret refs) works unchanged when the Vault store is wired.

#### H5 — opt-in raw-args / raw-response capture

The metadata-only audit dashboard from the customer batch told operators what was missing: actual values. H5 closes the gap with policy opt-in.

Wire shape:
- `PolicyDecision.allow(capture_raw_args=True, capture_raw_response=True)` — opt-in surface. Default is False on both fields, so existing policies stay metadata-only (the privacy-by-default per spec §3.3).
- `AuditEvent.raw_args` / `raw_response` — new optional fields, default `None`. When the policy opted in, the lifecycle populates these from the request/response.
- Size-cap helper `truncate_for_audit_capture(payload)` in `audit/events.py`:
  - Under 16 KB JSON-serialized → pass through unchanged.
  - Over 16 KB → cap each leaf string to 1 KB + truncation marker; re-check.
  - Still over → fallback to a `{"__truncated__": True, "size_bytes": N}` sentinel.
  - Non-serializable payload → `{"__non_serialisable__": True}` sentinel rather than raising.
- `AuditEvent.raw_args_truncated` / `raw_response_truncated` flags surface on the API + UI so operators see when the audit value was clipped.

Lifecycle wiring: `_emit_audit` accepts `raw_args` + `raw_response` kwargs; the success path populates them only when `decision.capture_raw_args` / `capture_raw_response` is True. Deny paths never carry raw response (no upstream call happened).

UI: the operator-console "Tool-call activity" panel now renders separate `<details>` blocks for raw args + raw response when present, with a "truncated" warning pill when the size cap fired. When NOT present, the panel still shows the existing privacy footer ("set policy capture_raw_args / capture_raw_response = true to opt in").

#### S8 — best-effort `mcp.json` manifest discovery

⚠️ **Spec stability caveat** — the upstream `mcp.json` schema is genuinely fluid. We ship a deliberate **conservative subset** of fields we recognize, fail safely on missing fields (no exceptions on sparse input), and round-trip the raw payload to the operator UI so anything not auto-mapped stays visible.

Recognized fields (with common aliases):
- `name` / `display_name` / `title` → `display_name`
- `description` / `summary` → `description`
- `transport` / `type` → `streamable_http` / `sse` / `stdio` (alias-folded)
- `endpoint` / `url` / `uri` / `http_url` / `streamable_http_url` → HTTP source location
- `command` + `args` → stdio source. `npx` and `uvx` get auto-mapped to `npm` / `pypi` source types respectively, with the package name extracted from args.
- `auth.scheme` / `auth.type` → `auth_hint` (informational; operator finalises auth config manually).

Surface: `POST /api/v1/servers/from-manifest` (operator JWT) — fetches the URL (HTTPS-only by default; `allow_http=true` for dev), parses, returns a `ManifestPreviewResponse` with auto-detected fields + raw manifest body + `notes` array calling out anything missing.

**Preview-only — no auto-registration.** A malicious manifest URL must not be able to silently land an upstream in a tenant's registry. The operator always confirms via the existing `POST /api/v1/servers` after seeing what was auto-detected. This is the exact pattern your earlier feedback established: dropdowns + previews instead of blind UUID prompts / blind URL ingestion.

#### H2 — TLS termination + mTLS operational guide

New doc at `docs/operations/tls-and-mtls.md` covers:
- Why TLS terminates at ingress, not in the gateway (perf + cert lifecycle).
- Reference deployments: k8s + cert-manager (NGINX ingress YAML), Caddy on a VM, AWS ALB / GCP Cloud Run / Azure App Service.
- TLS version + cipher policy + HSTS guidance.
- Inbound mTLS (client → ingress) — wiring, propagation of subject-DN to gateway via headers, sketch of a `MtlsIdentityProvider` follow-up.
- **Outbound mTLS to upstream MCPs** — `httpx.AsyncClient(cert=...)` already supports it; what's missing is `mcp_servers.mtls_cert_ref` + `mtls_key_ref` columns + schema rules + builder wiring (~½ day on top of A6). Until then: Envoy egress sidecar pattern works with no gateway code change.
- Production deployment checklist: env-var settings, secret-store backend, audit pipeline, mTLS-required upstreams, etc.

### Files added / changed

1. **`vyuu_gateway/secrets/vault.py`** — new `VaultSecretStore` (KV v2). Configurable mount, namespace, value_field, timeout. Lazy httpx client.
2. **`vyuu_gateway/secrets/__init__.py`** — re-exports `VaultSecretStore`, `VaultBackendError`, `VaultConfigurationError`.
3. **`vyuu_gateway/config.py`** — new `secret_store_backend` + `vault_addr` / `vault_token` / `vault_mount` / `vault_namespace` / `vault_value_field` / `vault_timeout_seconds` fields.
4. **`vyuu_gateway/main.py`** — new `_build_default_secret_store(settings)` factory. `create_app` calls it when no `secret_store=...` is passed.
5. **`vyuu_gateway/policy/interfaces.py`** — `PolicyDecision` got `capture_raw_args` + `capture_raw_response` boolean fields (default False). `PolicyDecision.allow(...)` accepts the flags as kwargs; `deny` never carries them.
6. **`vyuu_gateway/audit/events.py`** — new `truncate_for_audit_capture()` helper + `_cap_leaf_strings()`. `AuditEvent` got 4 new fields: `raw_args`, `raw_response`, `raw_args_truncated`, `raw_response_truncated`. `create_tool_call_audit_event` accepts `raw_args` / `raw_response` kwargs and threads them through the truncator.
7. **`vyuu_gateway/tool_calls/lifecycle.py`** — `_emit_audit` accepts `raw_args` / `raw_response` kwargs; the success path passes the request arguments + serialized `CallToolResult` when the policy opted in. New `_serialise_call_result()` helper.
8. **`vyuu_gateway/api/audit_events.py`** — `AuditEventView` exposes the new raw fields + truncation flags.
9. **`vyuu_gateway/api/operator_ui.py`** — Tool-call activity card renders raw-args / raw-response `<details>` blocks when present, with truncation pill. Default privacy footer when absent.
10. **`vyuu_gateway/registry/manifest.py`** — new module: `ParsedManifest` dataclass, `parse_manifest(payload)`, `fetch_manifest(url)`, `ManifestFetchError`, `ManifestParseError`.
11. **`vyuu_gateway/api/servers.py`** — new `POST /servers/from-manifest` endpoint with `ManifestPreviewRequest` / `ManifestPreviewResponse`.
12. **`docs/operations/tls-and-mtls.md`** — new ops doc.
13. **Tests:** `tests/test_vault_secret_store.py` (13), `tests/audit/test_h5_capture.py` (11), `tests/registry/test_manifest.py` (17). Total +41 → 669.

### Backlog post-batch

Still open:

- **A1** OAuth authorization-code (phase 4) — biggest remaining gap.
- **A2** OAuth JWT-bearer (RFC 7523).
- **A3-β.x** Real-Keycloak integration test.
- **A4** 401-driven token refresh.
- **A6.x** Additional `SecretStore` impls (AWS Secrets Manager, k8s-secrets) — same Protocol, lift-and-shift now that Vault is reference.
- **H1** DNS-time SSRF backstop.
- **H3** Payload-size limits + response redaction.
- **mTLS upstream-cert ref** — sized in the H2 doc; ~½ day on top of A6.
- **P1/P2/P3** Performance polish.
- **S1.b** Cosign verification for binary source.

### Resume-here cookbook (this batch)

```bash
# A6 — point the gateway at Vault dev mode:
docker run --rm -d -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-token \
  --name vyuu-vault hashicorp/vault server -dev -dev-listen-address=0.0.0.0:8200
docker exec -e VAULT_TOKEN=dev-token -e VAULT_ADDR=http://127.0.0.1:8200 \
  vyuu-vault vault kv put secret/<tenant_uuid>/paypal-bearer value="Bearer s3cret"

VYUU_SECRET_STORE_BACKEND=vault \
VYUU_VAULT_ADDR=http://127.0.0.1:8200 \
VYUU_VAULT_TOKEN=dev-token \
... uvicorn vyuu_gateway.main:create_app --factory --port 8000

# H5 — opt-in raw capture in a custom PolicyProvider:
return PolicyDecision.allow(
    capture_raw_args=True,
    capture_raw_response=True,
    rule_id="finance-compliance-rule-7",
)
# Tool-call activity panel on /operator now shows raw args + response.

# S8 — preview a manifest:
curl -s -X POST http://127.0.0.1:8000/api/v1/servers/from-manifest \
  -H "Authorization: Bearer $OP_TOKEN" \
  -H "content-type: application/json" \
  -d '{"manifest_url":"https://upstream.example/mcp.json"}' | jq

# H2 — operator handbook:
open docs/operations/tls-and-mtls.md
```

---

## Sub-session update — 2026-04-30 (Inbound identity provider settings flag)

The inbound-identity-provider section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### What this sub-session shipped

A one-flag fix for the production gateway's default inbound auth path. Discovered while a user was wiring Cursor against the gateway: Cursor logs `HTTP 404: Invalid OAuth error response` and falls back to SSE (which 405s), even with a valid API key in the config. Root cause: `create_app` defaulted `identity_provider` to `FakeIdentityProvider`, which expects `x-vyuu-*` headers (the lab convention) — Cursor only sends `Authorization: Bearer ...`, so every inbound call 401'd. Cursor's OAuth-discovery probes against the 401 then surfaced as the noisy 404 fallback chain.

The fix: a new `Settings.inbound_identity_provider` flag (`fake` | `api_key`, default `fake` to preserve lab + test behavior). When `VYUU_INBOUND_IDENTITY_PROVIDER=api_key` is set, `create_app` builds an `ApiKeyIdentityProvider(session_factory=SessionLocal)` instead of `FakeIdentityProvider()`. Callers that pass `identity_provider=...` explicitly (lab + most tests) bypass this branch entirely.

### How to use

Production deployments serving real Cursor / Claude Desktop / agent clients:

```bash
VYUU_INBOUND_IDENTITY_PROVIDER=api_key \
VYUU_DATABASE_URL=... \
VYUU_PORTAL_SESSION_SIGNING_SECRET=... \
VYUU_OPERATOR_AUTH_SIGNING_SECRET=... \
uvicorn vyuu_gateway.main:create_app --factory --port 8000
```

Verified end-to-end: login → portal session JWT → issue self-API-key → POST `/v/{tenant}/{vserver}/mcp` with `Authorization: Bearer vyuu_user_*` → **HTTP 200** with valid JSON-RPC initialize response. The session is correctly mapped to the real `user_id` from `user_api_keys`, and grant enforcement on private vservers fires through the production code path.

### Files changed

1. **`vyuu_gateway/config.py`** — new `inbound_identity_provider: str = "fake"` field on `Settings` with a docstring explaining when to flip.
2. **`vyuu_gateway/main.py`** — new `_build_default_identity_provider(settings)` helper. `create_app` calls it when no explicit `identity_provider` is passed. `ApiKeyIdentityProvider` is imported lazily inside the helper so test suites that don't need it don't pay the bcrypt import cost at module load.

### Validation

```bash
pytest        # 628 passed, 2 skipped (no behavior change for default-fake callers)
ruff check . # All checks passed!
mypy .       # Success: 175 source files
```

No new tests were added — the helper is exercised by every production code path that hits inbound MCP, and the existing api-key-provider integration tests cover the auth side.

### Cursor + Claude Desktop note

Browser-side OAuth discovery probes (Cursor's `/.well-known/oauth-protected-resource/...` calls) still 404 because the gateway doesn't speak OAuth — it uses static bearer tokens. Cursor's logs will show those 404s as warnings, but the actual MCP connection now succeeds (the warnings are cosmetic). A future enhancement could return RFC 9728 metadata at the well-known endpoint to silence the noise; not needed for v1.

---

## Sub-session update — 2026-04-30 (Customer feature batch: portal config snippets, principal dropdowns, tool-call activity dashboard)

The customer-feature section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 628 passed, 2 skipped (Keycloak-gated)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 175 source files
```

(12 new tests vs. quick-wins's 616 — `tests/audit/test_recent_emitter.py` 7 unit tests on the ring-buffer + per-tenant query, `tests/api/test_audit_events_endpoint.py` 5 endpoint tests covering tenant scoping / vserver filter / limit / 401 / 422.)

### What this sub-session shipped

Three customer-driven features, batched together because each was bounded.

#### Feature 1 — portal config snippets per accessible vserver

End users on `/portal` can now click **"Show config"** on any vserver they have access to. Inline expander reveals two copy-pasteable JSON snippets:

- **Cursor** — direct streamable-HTTP block for `~/.cursor/mcp.json` (`{"url":..., "type":"streamable-http", "headers":{"Authorization":"Bearer <YOUR_API_KEY>"}}`).
- **Claude Desktop** — `mcp-remote` stdio bridge wrapper for `claude_desktop_config.json` (since Claude Desktop's native HTTP MCP support is still version-gated).

Both snippets embed `<YOUR_API_KEY>` as a placeholder — the user pastes their own key (issued from the same portal page's "My API keys" panel). Each snippet has a one-click **Copy** button using `navigator.clipboard.writeText`. The vserver URL is derived from `window.location.origin` so it matches what they see in the browser.

Why this matters: previously, users had to figure out the vserver URL + manually compose the MCP config. Now it's a click + paste. Closes the "I have access — how do I actually connect?" gap that γ + δ left open.

#### Feature 2 — principal dropdowns instead of UUID prompts

The operator console used to call `prompt('user_id (UUID) to add to this group:')` and `prompt('principal UUID')`. Now both flows use real `<select>` dropdowns:

- **"Add member" / "Remove" buttons** on each group card — dropdown of users (email + truncated UUID).
- **"Issue grant" form** on each vserver's "Manage access" expander — kind dropdown (user|group) drives a principal dropdown that switches between the user and group lists.

Implementation detail: a `principalCache = {users: [], groups: []}` keeps the last-fetched lists, populated by the existing `loadUsers()` / `loadGroups()` panel refreshes. New `ensurePrincipalCacheLoaded()` lazy-fetches both lists on first dropdown focus so the operator doesn't have to manually click Refresh on the source panels first. New `fillSelectOptions(selectEl, items, labelFor)` helper centralizes option rendering; new `userLabel(u)` / `groupLabel(g)` produce the `email · uuid…` / `name · uuid…` shape.

The kind dropdown on the grant form fires a `change` event that re-populates the principal dropdown — so flipping `user → group` swaps the candidate list seamlessly.

#### Feature 3 — tool-call activity dashboard on `/operator`

End-to-end observability for tool calls per vserver. Two pieces:

1. **`RecentAuditEmitter`** (`vyuu_gateway/audit/recent.py`) — wraps any other `AuditEmitter` and additionally keeps the last 1000 events in an in-memory `deque` (thread-safe via a `Lock`). Every `emit_nowait` delegates to the inner emitter (so production durable audit through Kafka / NATS is **not** affected) AND records to the local buffer. `query(tenant_id, vserver_id?, upstream_server_id?, limit?)` returns the most-recent matching events newest-first, tenant-scoped (operators can only see their own tenant's events).

   `main.py` now wraps `audit_emitter` (whatever the caller provides, or the default `_LocalAuditEmitter`) in a `RecentAuditEmitter` and exposes both `app.state.audit_emitter` (now the wrapper) and `app.state.recent_audit_emitter` (same instance) so the new endpoint has a typed accessor.

2. **`GET /api/v1/audit-events`** (`vyuu_gateway/api/audit_events.py`) — operator JWT auth, tenant-scoped read against `app.state.recent_audit_emitter`. Optional `?vserver_id=` and `?upstream_server_id=` filters; `?limit=` capped 1–500 (default 100). Returns a stable `AuditEventView` shape that doesn't expose internal Pydantic model evolution.

3. **"Tool-call activity" panel** on `/operator` — new section below "Groups" with:
   - Filter row: vserver dropdown (auto-populated from `/api/v1/vservers`) + result limit (1–500) + Apply button + Refresh.
   - Per-event card showing tool name with **decision pill** (allow/deny/redact/rewrite) and **upstream-status pill** (ok/error/timeout/not_called), timestamp, total + upstream latency, principal type/id/display, vserver_id, upstream_server_id, **A5 auth-mode flags** (org-tier / user-passthrough / oauth-cc), expandable args metadata + response size.
   - Footer note on every card: *"Raw arg values + response body not captured by default (PII / compliance). Enable via policy opt-in (H5 — pending)."* — sets correct expectations for what's recorded vs. what would need explicit policy opt-in.

   The buffer is in-memory and **resets on gateway restart** — this is a dev/ops UI affordance, not a durable audit log. Production durable audit continues through Kafka / NATS via the inner emitter.

### What's deliberately NOT in this batch

- **H5** raw-args / raw-response capture under policy opt-in — explicitly deferred. The Tool-call activity panel surfaces what's recorded today (metadata only) and tells the operator how to opt in via H5 when that ships. PII / compliance default stays "metadata only".
- **Durable persistence of audit events to Postgres** — same reasoning. The Kafka / NATS pipeline is the durable audit story; the in-memory buffer is for the UI.

### Files added / changed

1. **`vyuu_gateway/audit/recent.py`** — new module: `RecentAuditEmitter` with thread-safe ring buffer, tenant-scoped `query(...)`, optional `inner` AuditEmitter delegation, `__len__`, test-only `all()`.

2. **`vyuu_gateway/api/audit_events.py`** — new module: `GET /api/v1/audit-events` endpoint with operator-JWT auth, vserver/upstream filters, limit param, stable `AuditEventView` response shape.

3. **`vyuu_gateway/main.py`** — `_LocalAuditEmitter.emit_nowait` signature tightened to satisfy the `AuditEmitter` Protocol exactly (was `event: object -> object`, now `event: AuditEvent -> EmitResult`). Wraps the configured emitter in `RecentAuditEmitter` and exposes via both `app.state.audit_emitter` and `app.state.recent_audit_emitter`. Adds `audit_events_router` to the `/api/v1` mount.

4. **`vyuu_gateway/api/portal_ui.py`** — new `renderConfigSnippets(container, vserver)` JS function. The catalog row's "Show config" button toggles an inline panel with Cursor + Claude Desktop snippets, each with a Copy button driven by the Clipboard API.

5. **`vyuu_gateway/api/operator_ui.py`** —
   - `principalCache` module-scope object + `ensurePrincipalCacheLoaded()` + `fillSelectOptions()` + `userLabel()` / `groupLabel()` helpers for the dropdown flow.
   - `renderGroup` now embeds an inline `<select>` of users with Add member / Remove buttons (no more `prompt()`).
   - `loadAccessUI` (the Manage-access expander) replaces the principal `<input>` with a `<select>` that switches via the kind dropdown's change event.
   - New "Tool-call activity" HTML section + JS: `populateAuditVserverOptions()`, `loadAuditEvents()`, `renderAuditEvent(event)`, `pillForDecision(d)`, `pillForUpstreamStatus(s)`, `escapeHtmlOp()`. Reuses existing `pill-*` classes from the design system.

6. **Tests:**
   - `tests/audit/test_recent_emitter.py` — 7 unit tests: tenant scoping, ring-buffer drop-oldest semantics, vserver filter, upstream-server filter, limit param, inner-emitter passthrough, zero-limit edge.
   - `tests/api/test_audit_events_endpoint.py` — 5 endpoint tests via `TestClient`: tenant isolation, vserver filter, limit clamp, 401 on no token, 422 on invalid limit.

### Backlog post-batch

Still open:

- **A1** OAuth authorization-code (phase 4) — the GitHub/Notion/Drive UX. Biggest remaining gap.
- **A2** OAuth JWT-bearer (RFC 7523).
- **A3-β.x** Real-Keycloak integration test.
- **A4** 401-driven token refresh.
- **A6** Real `SecretStore` impls (Vault / AWS / k8s).
- **H1** DNS-time SSRF backstop.
- **H2** TLS termination + mTLS docs.
- **H3** Payload-size limits + response redaction.
- **H5** Audit raw-args/response under explicit policy opt-in — the natural follow-up to this batch's metadata-only dashboard.
- **P1/P2/P3** Performance polish (measurement-gated).
- **S1.b** Cosign verification for binary source.

### Resume-here cookbook (this batch)

```bash
# 1. Catalog config snippets — sign in at /portal, click "Show config" on
#    any vserver you have access to, then "Copy" to clipboard.

# 2. Principal dropdowns — open /operator → "Groups" → "Add member" or
#    expand any vserver's "Manage access" → "Issue grant". Dropdowns
#    populate on focus (no manual Refresh needed).

# 3. Tool-call activity — open /operator → scroll to "Tool-call activity"
#    → click Refresh. Filter by vserver via the dropdown. Make a tool
#    call from Cursor/Claude Desktop hitting a /v/.../mcp URL, then
#    Refresh again to see it appear.
```

---

## Sub-session update — 2026-04-30 (Quick-wins batch: A5 + H6 + H4 + A3.y)

The quick-wins section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 616 passed, 2 skipped (Keycloak-gated)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 171 source files
```

(11 new tests vs. A3.x's 605 — `tests/upstream/test_provider.py` got 4 tests for A5's `get_auth_mode_flags`, 3 for H6's `{secret:...}` template path, 4 for H4's per-package allowlist. Plus three test fakes — `FakeUpstreamClientProvider` in tool_calls/graph tests, `_AssertingUpstreamProvider`, and three lab-side fakes — got `get_auth_mode_flags` stubs to satisfy the new Protocol member.)

### What this sub-session shipped

Four small backlog items in one batch — each was bounded enough to ship without ceremony, and together they close real operator UX / security gaps without touching the data model.

#### A5 — audit signal for which auth model fired per call

Operators want to know "is tenant X actually using OAuth / passthrough / static headers?" — without grepping config dumps or eyeballing audit-event metadata. Three new booleans on every `AuditEvent`:

- `auth_modes.auth_org_tier` — true iff the upstream had `auth_headers` OR `auth_env` configured
- `auth_modes.auth_user_tier_passthrough` — true iff `auth_passthrough` was set
- `auth_modes.auth_oauth_client_credentials` — true iff `auth_oauth` was set

Default is all-False (a model-level Pydantic default), so legacy event consumers that don't know about the field don't break. The flags are computed per call by `DatabaseBackedUpstreamClientProvider.get_auth_mode_flags(tenant_id, server_id)` — a soft-failing helper that returns all-False when the server can't be looked up (already-deleted, or denied before the upstream check), so audit emission never breaks the request path.

The lifecycle calls `get_auth_mode_flags` exactly once per tool call, only when `upstream_server_id` is known. Deny-paths that never resolved a server pass all-False through. Future `AuthJwtBearerFlag` / `AuthAuthCodeFlag` members slot into `AuthModeFlags` without breaking the wire format.

#### H6 — header-value templating `{secret:ref-name}`

Pre-H6, operators stored the FULL header value in the secret store (`Bearer eyJ...`), which couples secret content to header composition and means rotating just the token requires re-pasting the `Bearer ` prefix.

Now `auth_headers` and `auth_env` values support `{secret:ref-name}` placeholders:

- `{"Authorization": "Bearer {secret:paypal-token}"}` → secret holds only `eyJ...`
- `{"X-Api-Key": "{secret:wiz-id}/{secret:wiz-secret}"}` → multiple placeholders, both resolved
- `{"Authorization": "paypal-bearer"}` → still works (bare-ref fallback for backward compat — auto-detected when no `{secret:...}` token is present)

Detection rule: if `{secret:...}` appears anywhere in the value, it's a template; otherwise the whole value is treated as a bare ref. So no flag, no migration, no breaking change. Refs allow `[A-Za-z0-9_\-./:@]` (the conservative intersection of common secret-store identifier conventions).

#### H4 — per-package content allowlist on `StdioLaunchPolicy`

`StdioLaunchPolicy` already gated absolute binary paths (`allowed_binary_paths`); H4 extends the same pattern to npm and pypi packages:

```python
StdioLaunchPolicy(
    allowed_npm_packages=("@modelcontextprotocol/server-postgres",),
    allowed_pypi_packages=("crowdstrike-falcon-mcp@1.4.0",),
)
```

When the allowlist is non-empty, registration must match an entry verbatim — including any `@version` pin for pypi. So a deployment that allowlists `crowdstrike-falcon-mcp@1.4.0` rejects both unpinned (`crowdstrike-falcon-mcp`) and re-pinned (`crowdstrike-falcon-mcp@1.5.0`) variants, locking the supply chain. Empty tuples (the default) preserve lab behavior — any name-shape-valid package is allowed.

#### A3.y — lab opt-in to `ApiKeyIdentityProvider`

The lab default remains `FakeIdentityProvider` (so existing demos keep working with `x-vyuu-*` headers), but a one-line env flip switches to the production bcrypt-keyed bearer path:

```bash
VYUU_LAB_USE_API_KEY_IDENTITY=1 python examples/drawio_lab_server.py
```

The banner now prints which identity provider is active and how to flip it:

```
Identity provider: ApiKeyIdentityProvider (real bcrypt-keyed bearer)
→ Inbound MCP calls require Authorization: Bearer vyuu_user_*
→ Issue a key from /portal after signing in, then paste into
  Cursor / Claude Desktop config.
```

Useful for smoke-testing the production auth path end-to-end without standing up OIDC. The lab's debug-logging upstream wrapper picked up a `get_auth_mode_flags` passthrough so A5's audit-mode signal stays intact through the wrapper.

### Files changed

1. **`vyuu_gateway/audit/events.py`** — new `AuthModeFlags` Pydantic model + `auth_modes: AuthModeFlags` field on `AuditEvent` (default factory = all-False instance) + matching kwarg on `create_tool_call_audit_event`.

2. **`vyuu_gateway/upstream/provider.py`** —
   - `get_auth_mode_flags(tenant_id, server_id)` public method on `DatabaseBackedUpstreamClientProvider` — returns `AuthModeFlags` from the McpServer columns; soft-fails to all-False on lookup miss.
   - `_resolve_auth_map` rewritten to call new `_render_secret_template`, which auto-detects `{secret:...}` placeholders and falls back to bare-ref for backward compat. Multiple placeholders per value supported. `_SECRET_TEMPLATE_RE` constant defined at module top.
   - `StdioLaunchPolicy` got `allowed_npm_packages: tuple[str, ...] = ()` and `allowed_pypi_packages: tuple[str, ...] = ()` fields. `validate_npm_package` and `validate_pypi_package` enforce the allowlist when non-empty.

3. **`vyuu_gateway/tool_calls/lifecycle.py`** —
   - `UpstreamToolClientProvider` Protocol got a new `get_auth_mode_flags` method.
   - `_emit_audit` accepts an optional `auth_modes` kwarg; when omitted and an `upstream_server_id` is in scope, asks the provider for the flags. Each call site keeps its existing shape; the provider does the work.

4. **`examples/drawio_lab_server.py`** —
   - `_LoggingUpstreamProviderWrapper` got a `get_auth_mode_flags` passthrough so audit flags survive the lab's debug wrapper.
   - `_build_lab_app` now reads `VYUU_LAB_USE_API_KEY_IDENTITY` and constructs `ApiKeyIdentityProvider(session_factory=SessionLocal)` when set; falls back to `FakeIdentityProvider()`. Banner prints which provider is active.

5. **Tests:**
   - `tests/upstream/test_provider.py` — 11 new tests covering A5 (4) + H6 (3) + H4 (4).
   - Three test fakes updated for the new Protocol member: `tests/tool_calls/test_lifecycle.py` (FakeUpstreamClientProvider + OpenCircuitUpstreamClientProvider), `tests/tenant_isolation/test_tenant_isolation.py` (_AssertingUpstreamProvider), `tests/graph/test_lifecycle_graph_emission.py` (FakeUpstreamClientProvider), `tests/api/test_inbound_mcp.py` (FakeUpstreamProvider), `tests/lab/test_e2e_interoperability.py` (_FixedClientUpstreamProvider), `tests/lab/test_drawio_upstream.py` (_FixedClientUpstreamProvider).

### Backlog post-batch

Still open:

- **A1** OAuth authorization-code (phase 4) — the GitHub/Notion/Drive UX. Biggest remaining functional gap.
- **A2** OAuth JWT-bearer (RFC 7523) — Workspace Drive, IAM Roles Anywhere.
- **A3-β.x** Real-Keycloak integration test.
- **A4** 401-driven token refresh.
- **A6** Real `SecretStore` impls (Vault / AWS / k8s).
- **H1** DNS-time SSRF backstop.
- **H3** Payload-size limits + response redaction.
- **H5** Audit raw-args/response under explicit policy opt-in.
- **P1/P2/P3** Performance / pool / token-refresh polish.
- **S1.b** Cosign verification for binary source.

### Resume-here cookbook (quick-wins batch)

```bash
# A5 — see auth_modes flags in any audit event:
VYUU_TEST_DATABASE_URL=... pytest tests/upstream/test_provider.py::test_get_auth_mode_flags_marks_org_tier_when_auth_headers_set -v

# H6 — register an HTTP MCP with templated header value:
#   auth_headers = {"Authorization": "Bearer {secret:my-token}"}
# and store only the raw token in the secret store.

# H4 — set the allowlists in your StdioLaunchPolicy:
#   StdioLaunchPolicy(
#       allowed_npm_packages=("@modelcontextprotocol/server-postgres",),
#       allowed_pypi_packages=("crowdstrike-falcon-mcp@1.4.0",),
#   )
# Pass it to your DatabaseBackedUpstreamClientProvider via the existing seam.

# A3.y — flip the lab to the real auth path:
VYUU_LAB_USE_API_KEY_IDENTITY=1 python examples/drawio_lab_server.py
```

---

## Sub-session update — 2026-04-30 (A3.x: operator-console panels)

The A3.x section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 605 passed, 2 skipped (env-gated on real Keycloak)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 171 source files
```

(No new tests this slice — all of A3.x's behavior is exercised by the existing α/γ admin-API tests; A3.x is purely the missing UI on top of already-shipped + already-tested endpoints. Two existing tests needed a one-line fix: `_make_vserver` test helper now passes `visibility=VirtualServerVisibility.PRIVATE` because the Pydantic response schema now includes a non-nullable `visibility` field.)

### What this sub-session shipped

**A3.x** — fills the operator-console UI gap that was carry-over from α/γ. Admins no longer have to use curl / Swagger to manage end-user identity and the access-request queue.

The existing `/operator` console grew **three new panels** plus a **per-vserver expander**:

1. **"Pending access requests"** panel (γ queue) — lists every `pending` request in the tenant, each with one-click **Approve** (auto-creates a `VirtualServerGrant`) and **Decline** (prompts for an optional `decision_note`). After either action the queue refreshes.

2. **"Users"** panel — lists all end users (email, auth_method, disabled state) with per-row **Reset password** (local-auth only; prompts for new password) and **Disable** buttons. Below the list: a "Create local-auth user" form (email + display name + initial password ≥ 12 chars).

3. **"Groups"** panel — lists groups with per-row **Add member** / **Remove member** buttons (each prompts for a user UUID). Below: a "Create group" form (name + description).

4. **"Manage access" expander** on every vserver card — clicking it reveals:
   - Current visibility + a **Make public / Make private** toggle (calls `PATCH /api/v1/vservers/{id}/visibility`).
   - List of active grants with per-row **Revoke** buttons.
   - Inline "Issue grant" form (kind dropdown user|group + principal UUID + Grant button).

### Files changed

1. **`vyuu_gateway/api/operator_ui.py`** — three new HTML `<section>`s before `</main>`, ~250 LOC of new JS (handlers for all four panels + `loadAccessUI` for the per-vserver expander, which monkey-patches the existing `renderVserver` to append the "Manage access" button without rewriting the original function).

2. **`vyuu_gateway/virtual_servers/schemas.py`** — `VirtualServerResponse` now exposes the `visibility` field. The UI needs it to render the toggle + the SPA needs it to know whether to show "Request access" buttons (already used on `/portal` δ catalog, which had its own service path; this aligns the operator response shape).

3. **`vyuu_gateway/virtual_servers/service.py`** — `create_virtual_server` now passes `visibility=VirtualServerVisibility.PRIVATE` explicitly when constructing the new ORM instance. The model already had `default=` and `server_default=` set, but neither populates the Python attribute on plain `VirtualServer(...)` construction — only on flush. Tests using a fake DB session never flush, so the response-schema validation was failing on `visibility=None`. Inline comment in the service explains why.

4. **`tests/api/test_capability_sync_and_vservers.py`** — `_make_vserver` test helper now sets `visibility=VirtualServerVisibility.PRIVATE` so the response-schema validates correctly on read paths.

### Remaining backlog

- **A3-β.x** Real-Keycloak integration test (env-gated on `VYUU_TEST_KEYCLOAK_URL`).
- **A3.y** Lab opt-in to `ApiKeyIdentityProvider` (`VYUU_LAB_USE_API_KEY_IDENTITY=1`).
- **A4** 401-driven token refresh on top of phase 3 / phase 4 outbound auth.
- **A5/A6** Audit signal / observability follow-ups.
- **Notifications for pending access requests** — currently polling-only (per Q6); email/Slack on submit is a future ask.

### Resume-here cookbook (A3.x)

Open **http://127.0.0.1:8000/operator** with the operator JWT. Scroll past "Virtual servers" — three new panels appear in order: "Pending access requests", "Users", "Groups". Each has its own Refresh button. Each existing vserver card grows a "Manage access" button that toggles a visibility / grants editor inline.

End-to-end demo loop:

1. **Operator** creates a private vserver via the existing "Create virtual server" form.
2. **End user** signs in at `/portal`, sees it as locked, clicks "Request access" with a note.
3. **Operator** refreshes "Pending access requests" → sees the row → clicks **Approve**.
4. **End user** refreshes the catalog at `/portal` → row flips from locked → access.
5. **Operator** clicks "Manage access" on the vserver card to see the new grant in the active list, with a "Revoke" button next to it.

---

## Sub-session update — 2026-04-30 (A3-δ: end-user portal UI)

The δ section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 605 passed, 2 skipped (env-gated on real Keycloak)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 171 source files
```

(11 new tests vs. γ's 594 — `tests/users/test_portal_api.py`: whoami round-trip, cross-tenant 403, catalog public/private/granted, self-issue / list / revoke API keys, anti-enumeration on cross-user revoke, password rotate happy/wrong-current/weak-new, plus a static-asset smoke test.)

### What this sub-session shipped

**A3-δ** — end users now have a browser UI. The four A3 phases are complete: identity (α) + login (β) + request workflow (γ) + portal UI (δ).

The portal lives at **`/portal`** and is a single-page vanilla-JS app (same pattern as `/operator` — single Python module with HTML/CSS/JS as string constants, no React build, no node_modules). It calls the same JSON API surface that γ exposed plus the new catalog / self-API-keys / self-rotate-password endpoints this slice adds.

Layout:

1. **Login screen** — tenant ID + email + password form. Calls `POST /auth/{tenant}/login` (β), stores the session JWT in `sessionStorage`. Has an "Advanced: paste session token" fallback for users who already have a JWT.
2. **Catalog panel** — every vserver in the tenant with `public`/`private` + `access`/`locked` badges. "Request access" button on locked rows submits an access request inline.
3. **My access requests panel** — submitted requests with status badge; pending rows have a "Withdraw" button.
4. **My API keys panel** — self-issue (plaintext shown ONCE in a one-shot output area), list with prefix + created/last-used, revoke button.
5. **Change password panel** — local-auth users only; auto-hidden for OIDC users. Requires current password (defends against silent takeover via stolen session JWT).

### Files added / changed

1. **`vyuu_gateway/registry/portal_service.py`** — service layer for the portal-only surface:
   - `list_catalog(...)` returns one `CatalogEntry(vserver_id, name, description, visibility, has_access)` per vserver. `has_access` is True for public OR for private with an active grant (direct OR via group). Two ORM-mapped queries for grants (kept separate because `UNION ALL` of `select(Model)` strips the entity binding under SA 2.0).
   - `issue_my_api_key`, `list_my_api_keys`, `revoke_my_api_key` — same shape as the admin path in `users_service`, but with `user_id` pinned by the session.
   - `rotate_my_password` — validates the current password before swapping the hash. Rejects OIDC-authed users with `PortalRequiresLocalAuthError`.

2. **`vyuu_gateway/registry/portal_schemas.py`** — Pydantic for the portal endpoints: `CatalogEntryResponse`, `IssueMyApiKeyRequest`, `IssuedMyApiKeyResponse`, `MyApiKeySummaryResponse`, `RotateMyPasswordRequest`, `WhoAmIResponse`.

3. **`vyuu_gateway/api/portal.py`** — six routes mounted at `/api/v1/portal/{tenant_id}`:
   - `GET /me` — whoami (decoded session, pulls fresh user state from DB so `must_change_password` is current)
   - `GET /catalog` — vserver catalog with `has_access` flags
   - `GET /api-keys` — list mine
   - `POST /api-keys` — self-issue (plaintext returned ONCE)
   - `DELETE /api-keys/{id}` — revoke
   - `POST /password` — self-rotate
   Every endpoint enforces `session.tenant_id == path.tenant_id` (403 on mismatch) — same pattern as γ's portal endpoints.

4. **`vyuu_gateway/api/portal_ui.py`** — single Python module that serves `/portal`, `/portal/app.css`, `/portal/app.js` with strict CSP + nosniff headers. Mirrors `operator_ui.py`'s pattern (no React, no build step, plain HTML+CSS+JS).

5. **`vyuu_gateway/main.py`** — wires `portal_api_router` (mounted at `/api/v1/portal`) and `portal_ui_router` (root). Both new imports added at the top.

6. **Tests:** `tests/users/test_portal_api.py` — 11 end-to-end tests against real Postgres covering all six endpoints + the static-asset surface.

### Deferred (post-A3 / future sessions)

- **A3-β.x** Real-Keycloak integration test (env-gated on `VYUU_TEST_KEYCLOAK_URL`) — placeholder still in `tests/users/test_login_endpoint.py`.
- **A3.x** Operator-UI extensions (users / groups / grants / **access-request queue** / **visibility toggle**) — admin still drives these via API today.
- **A3.y** Lab opt-in to `ApiKeyIdentityProvider` (`VYUU_LAB_USE_API_KEY_IDENTITY=1`).
- **A4** 401-driven token refresh on top of phase 3 / phase 4 outbound auth.
- **A5/A6** Observability (audit signal for which auth model fired) and longer-term backlog.

### Resume-here cookbook (δ)

```bash
# 1. Apply migrations:
VYUU_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
alembic upgrade head

# 2. Start the gateway with bootstrap env vars set (γ cookbook covers this):
VYUU_BOOTSTRAP_TENANT_NAME="Acme Corp" \
VYUU_BOOTSTRAP_ADMIN_EMAIL="admin@acme.example" \
VYUU_BOOTSTRAP_ADMIN_PASSWORD="bootstrap-strong-12+chars" \
VYUU_PORTAL_SESSION_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
VYUU_OPERATOR_AUTH_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
VYUU_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
uvicorn vyuu_gateway.main:create_app --factory --port 8000

# 3. Open http://127.0.0.1:8000/portal in a browser.
#    - Paste the tenant_id from the bootstrap log line
#    - Sign in with admin@acme.example / bootstrap-strong-12+chars
#    - Catalog / requests / API-keys / change-password panels light up
```

---

## Sub-session update — 2026-04-30 (A3-γ: request / approval workflow)

The γ section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 594 passed, 2 skipped (env-gated on real Keycloak)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 166 source files
```

(25 new tests vs. β's 569 — 15 service-layer tests against real Postgres exercising the partial-unique pending index, plus 10 endpoint tests covering portal + admin surfaces with both portal-session and operator JWTs.)

### What this sub-session shipped

**A3-γ** — end users can now self-service request access to private vservers, and admins can approve / decline through a dedicated queue.

The slice closes the loop that was left open in α: in α, end users were stuck waiting for an admin to know-by-osmosis that they wanted access. γ makes the "I want in" → "I'll review" → "approved (grant created) / declined (with note)" workflow first-class.

The flow:

1. End user (portal session JWT, β) hits `POST /api/v1/portal/{tenant_id}/access-requests` with `{vserver_id, note}` — service rejects if the vserver is public, if the user already has access (direct or via group), or if a pending request already exists for the same (user, vserver). The "already has access" check uses the same SQL shape as `assert_principal_can_access_vserver` from α — no double-paths to drift.
2. Admin (operator JWT) hits `GET /api/v1/access-requests?status_filter=pending` to see the queue.
3. Admin approves → service atomically creates a `VirtualServerGrant(principal_kind=user)` AND flips the request to `approved`, recording `decided_by`, `decided_at`, and `created_grant_id` so the lineage is auditable. Idempotency: if the user gained access between submit and approve (e.g., admin issued a manual grant in parallel), the approve still succeeds, but `created_grant_id` stays null — this approval didn't create the grant.
4. Admin declines → `decided_by` + `decided_at` + `decision_note` recorded; no grant created.
5. User can withdraw a still-pending request (`DELETE /api/v1/portal/{tenant_id}/access-requests/{id}`). Approved / declined requests cannot be withdrawn — those are final states; the user gets a 409.

### Files added / changed

1. **`migrations/versions/20260430_0007_access_requests.py`** — new `access_requests` table.
   - `(id, tenant_id, user_id, vserver_id, status, note, decision_note, decided_by, decided_at, created_grant_id, created_at)`.
   - Check-constraint pins `status` to `pending|approved|declined|withdrawn`.
   - Three regular indexes (`(tenant_id, status)`, `user_id`, `vserver_id`) for the common queue / list-mine / vserver-card lookups.
   - **Partial unique index** on `(user_id, vserver_id) WHERE status = 'pending'` — guarantees a single pending request per (user, vserver). Approved / declined / withdrawn don't block re-requesting; that's intentional (declined for one reason → world changes → user re-files).

2. **`vyuu_gateway/db/models.py`** — new `AccessRequestStatus` enum (`PENDING`, `APPROVED`, `DECLINED`, `WITHDRAWN`) + `AccessRequest` ORM class. Mirrors the migration column-for-column. Imports `text` from sqlalchemy for the partial-unique `postgresql_where` predicate.

3. **`vyuu_gateway/registry/access_requests_schemas.py`** — Pydantic `SubmitAccessRequestRequest` (vserver_id + optional note), `AccessRequestResponse` (full record, used by both end-user and admin views), `DeclineAccessRequestRequest` (decision_note).

4. **`vyuu_gateway/registry/access_requests_service.py`** — six entry points (`submit`, `list_my`, `withdraw`, `list_admin`, `approve`, `decline`) plus internal `_load_pending` and `_user_has_active_grant` helpers. Typed errors map cleanly to HTTP status: `VserverNotFoundForRequestError` → 404, `VserverIsPublicError` / `UserAlreadyHasAccessError` / `DuplicatePendingRequestError` / `WrongRequestStateError` → 409, `AccessRequestNotFoundError` → 404. The service NEVER trusts caller-supplied `tenant_id` to be authoritative — every query gates on `(tenant_id, ...)` for defense-in-depth even when RLS is bound.

5. **`vyuu_gateway/users/portal_dependency.py`** — new module: FastAPI deps `authenticate_portal_session` (verifies HS256 portal JWT from β, returns `PortalSession`) and `get_portal_scoped_db` (yields a session bound to the portal user's tenant). Mirrors the operator side's `authenticate_operator` + `get_tenant_scoped_db` pattern. The portal-session-vs-path-tenant comparison is left to the route (depends on the path param).

6. **`vyuu_gateway/api/access_requests.py`** — single router file exposing two `APIRouter` instances:
   - `portal_router` (mounted at `/api/v1/portal`): `POST/GET/DELETE /{tenant_id}/access-requests[/{id}]`. Each endpoint enforces `session.tenant_id == path tenant_id` (403 on mismatch — defends against a leaked token replayed against a different tenant's URL).
   - `admin_router` (mounted at `/api/v1`): `GET /access-requests`, `POST /access-requests/{id}/approve`, `POST /access-requests/{id}/decline`.

7. **`vyuu_gateway/main.py`** — both new routers wired in.

8. **Tests:**
   - `tests/users/test_access_requests_service.py` — 15 tests against real Postgres covering: submit happy path, unknown vserver, public vserver, user-already-has-direct-grant, user-already-has-group-grant, duplicate-pending, approve happy path, approve-already-decided 409, approve-when-grant-exists idempotent path, decline records note, withdraw happy path, withdraw-after-approval 409, withdraw-not-owner 404 (anti-enumeration), list-mine status filter, admin-list status filter.
   - `tests/users/test_access_requests_api.py` — 10 endpoint tests (HTTP, real Postgres): portal submit happy path, public-vserver 409, cross-tenant-token 403, no-token 401, list-mine isolation between users, withdraw, admin queue, admin approve creates grant, admin decline records note, double-approve 409.

9. **`tests/tenant_isolation/test_tenant_isolation.py`** — added `access_requests` to the expected tenant-scoped table set so the static-guard test stays accurate.

### Deferred to a future session (δ + others)

- **A3-δ** End-user portal UI (`/portal` route, catalog views, "My API keys", request form, status pages) — γ ships the API; δ ships the React surface that calls it.
- **A3-β.x** Real-Keycloak integration test (env-gated on `VYUU_TEST_KEYCLOAK_URL`) — still pending.
- **A3.x** Operator UI panels (users / groups / grants / **access-request queue**) — γ added a fourth panel candidate for this carry-over.
- **A3.y** Lab opt-in to `ApiKeyIdentityProvider`.

### Resume-here cookbook (γ)

```bash
# 1. Apply migrations:
VYUU_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
alembic upgrade head        # advances 0006 → 0007

# 2. Mint a portal session for an end user (after β's /auth/{tenant}/login):
SESSION_JWT="..."   # from POST /api/v1/auth/{tenant_id}/login

# 3. End user submits a request:
curl -X POST "http://127.0.0.1:8000/api/v1/portal/$TENANT_ID/access-requests" \
  -H "Authorization: Bearer $SESSION_JWT" \
  -H 'content-type: application/json' \
  -d '{"vserver_id":"<uuid>", "note":"need this for project X"}'
# → 201 with the full request record

# 4. Admin sees the queue:
curl "http://127.0.0.1:8000/api/v1/access-requests?status_filter=pending" \
  -H "Authorization: Bearer $OPERATOR_JWT"

# 5. Admin approves (auto-creates the grant):
curl -X POST "http://127.0.0.1:8000/api/v1/access-requests/$REQ_ID/approve" \
  -H "Authorization: Bearer $OPERATOR_JWT"
```

---

## Sub-session update — 2026-04-30 (A3-β: OIDC + login flow)

The β section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 569 passed, 2 skipped (env-gated on real Keycloak)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 159 source files
```

(17 new tests vs. α's 554 — 8 OIDC core unit tests using generated RSA keys + mock httpx + mock JWKS, 4 portal session JWT round-trip tests, 5 login endpoint tests against real Postgres.)

### What this sub-session shipped

**A3-β** — humans can now actually log in. Three login paths land:
1. **Microsoft Entra ID** — per-tenant issuer (`https://login.microsoftonline.com/{tenant}/v2.0`), `oid` subject claim, JIT-provisioning on first sign-in.
2. **Google Workspace** — issuer `https://accounts.google.com`, optional `hd` (hosted-domain) claim pin so a Workspace customer's IdP can't be impersonated by a random `gmail.com` account.
3. **Local username + password** — bcrypt verify against the `users` table from α; constant-time anti-enumeration (same generic 401 for wrong-email / wrong-password / disabled).

All three mint the same artifact: an HS256-signed **portal session JWT** (`tenant_id` + `user_id` + `email` + `auth_method` + `iat` + `exp`), returned in the response body for SPA consumption. JIT provisioning means the first OIDC sign-in for an unknown email creates a new `User` row scoped to the path-level `tenant_id`, with `auth_method=microsoft|google` and `external_subject` pinned — subsequent logins find the same row by `(tenant_id, external_subject)` even if the user changes their email. `WrongAuthMethodError` is raised (and surfaces as 409) when an OIDC sign-in collides with an existing local-auth user, so an attacker can't shadow a known username with a Google sign-in.

What's not in this slice: the **operator** still authenticates via the existing operator JWT (`/operator/...` endpoints unchanged). β only added human login on the **end-user** side. Wiring operator auth through the same OIDC path is a γ-or-later refactor — the access-control models are different (operators are tenant-admin globals, users are per-tenant).

### Files added / changed

1. **`vyuu_gateway/users/oidc.py`** — JWKS cache + JWT validation.
   - `OidcConfig` (frozen dataclass): `issuer_url`, `audience`, optional `hosted_domain`, optional `subject_claim` override (Microsoft uses `oid`, Google uses default `sub`).
   - `JwksCache`: per-issuer `asyncio.Lock` for **single-flight refresh**. Hot upstream → N parallel `validate_token` calls → exactly one discovery + one JWKS fetch, not N. 5-minute TTL; refresh also fires on `kid` miss (covers IdP key rotation between TTL cycles). 10s fetch timeout.
   - `validate_token(token, config)`: full RS256 verify — discovery doc → JWKS URI → public key → signature + `iss` + `aud` + `exp` + optional `hosted_domain` (`hd` claim) + optional `subject_claim` extraction. Wraps every PyJWT failure mode in `OidcValidationError(reason)` with stable lowercase reason strings (`"expired"`, `"audience"`, `"issuer"`, `"signing key"`, `"hosted_domain"`).

2. **`vyuu_gateway/users/oidc_providers.py`** — concrete providers.
   - `OidcProvider` ABC: `authorization_url(state, nonce) -> str`, `async exchange_code_for_id_token(code) -> OidcLoginResult`.
   - `MicrosoftEntraIdProvider.build(microsoft_tenant_id, client_id, client_secret, redirect_uri, jwks_cache)` — issuer baked from tenant_id. Subject claim = `oid`.
   - `GoogleWorkspaceProvider.build(client_id, client_secret, redirect_uri, jwks_cache, hosted_domain=None)` — fixed Google issuer; `hosted_domain` flows through to `OidcConfig`.
   - `OidcLoginResult` dataclass: `email`, `subject`, `display_name`, `raw_claims`.

3. **`vyuu_gateway/users/sessions.py`** — portal session JWT.
   - `issue_portal_session(tenant_id, user_id, email, auth_method, signing_secret, ttl_seconds, now=None)` → HS256 JWT.
   - `verify_portal_session(token, signing_secret) -> PortalSession` — required claims: `exp`, `iat`, `iss="vyuu-gateway"`, `tenant_id`, `user_id`. `SessionTokenError("expired")` on expiry; generic `SessionTokenError` on tamper / wrong-secret / garbled.

4. **`vyuu_gateway/api/auth.py`** — login routes.
   - `POST /api/v1/auth/{tenant_id}/login` — local password.
   - `GET /api/v1/auth/{tenant_id}/oidc/{provider_name}` — initiate (returns `authorization_url` + `state` for the SPA to redirect through).
   - `POST /api/v1/auth/{tenant_id}/oidc/{provider_name}/callback` — code-exchange + JIT-provision + mint session.
   - **State CSRF defense:** state always begins with `{tenant_id}.` so a callback delivered to tenant A's URL with a state generated for tenant B is rejected at the path level.

5. **`vyuu_gateway/registry/users_service.py`** — added `upsert_oidc_user(...)` + `WrongAuthMethodError`. Lookup is by `(tenant_id, external_subject)` first (stable across email changes), then by `(tenant_id, email)` (covers the migration case). Provisions a new `User` if neither matches.

6. **`vyuu_gateway/config.py`** — added `portal_session_signing_secret`, `portal_session_ttl_seconds` (default 3600), and 4 Microsoft + 4 Google OIDC settings (each provider can be left unset; `_build_oidc_providers` only constructs the ones whose required settings are all present).

7. **`vyuu_gateway/main.py`** — `_build_oidc_providers(settings) -> dict[str, OidcProvider]` populates `app.state.oidc_providers`; lifespan unchanged otherwise.

8. **Tests:**
   - `tests/users/test_oidc.py` — 8 tests, **all hermetic** (no IdP needed): generated RSA key → handcrafted JWKS doc → mock httpx returns canned discovery + JWKS responses. Covers round-trip, expired, audience mismatch, issuer mismatch, unknown-kid-after-refresh, hosted_domain pin, JWKS refresh on kid miss, single-flight under 8 concurrent calls.
   - `tests/users/test_sessions.py` — 4 tests: round-trip, expired, wrong secret, garbled token.
   - `tests/users/test_login_endpoint.py` — 5 env-gated tests against real Postgres: happy-path local login (round-trips the session JWT), wrong-password 401, unknown-email 401 (anti-enumeration), disabled-user 401, OIDC initiate 404 when provider not configured.

### Deferred to a future session (γ + δ)

- **A3-γ** End-user request / admin approval workflow (`access_requests` table + endpoints + operator queue UI panel).
- **A3-δ** End-user portal UI (`/portal` route, catalog views, "My API keys", request form, login screen).
- **A3-β.x** Real-Keycloak integration test (env-gated on `VYUU_TEST_KEYCLOAK_URL`) — placeholder skipif documented in `tests/users/test_login_endpoint.py` header. The unit suite with generated RSA keys covers the security-critical path; Keycloak adds *full* discovery + token-endpoint integration coverage when CI infra exists for it.
- **A3.x** Operator UI panels for users / groups / grants (carry-over from α).
- **A3.y** Lab opt-in to `ApiKeyIdentityProvider` (`VYUU_LAB_USE_API_KEY_IDENTITY=1`).

### Resume-here cookbook (β)

The shortest path to exercising β locally:

```bash
# 1. Bring up Postgres + Redis (test cluster).
# 2. Apply migrations (idempotent):
VYUU_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
alembic upgrade head

# 3. First-run bootstrap creates a tenant + admin user atomically:
VYUU_BOOTSTRAP_TENANT_NAME="acme-corp" \
VYUU_BOOTSTRAP_ADMIN_EMAIL="admin@acme.example" \
VYUU_BOOTSTRAP_ADMIN_PASSWORD="bootstrap-strong-12+chars" \
VYUU_PORTAL_SESSION_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
VYUU_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
uvicorn vyuu_gateway.main:create_app --factory --port 8000

# 4. Hit the local-login endpoint (note: tenant_id from step 3's logs):
curl -X POST http://127.0.0.1:8000/api/v1/auth/<tenant-id>/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@acme.example","password":"bootstrap-strong-12+chars"}'
# → {"session_token": "...", "must_change_password": false, ...}
```

For Microsoft/Google, set the corresponding `VYUU_OIDC_MICROSOFT_*` or `VYUU_OIDC_GOOGLE_*` env vars and call `GET /api/v1/auth/<tenant-id>/oidc/microsoft` to retrieve the authorization URL the SPA should redirect through.

---

## Sub-session update — 2026-04-30 (A3-α: end-user identity + grant model)

The α section sits below. Earlier 2026-04-30 sub-sessions sit below that.

### Validation

```bash
pytest        # 554 passed (zero skipped, with all real services attached)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 152 source files
```

(32 new tests vs. the prior 522 — 17 unit tests for passwords + API keys, 7 ApiKeyIdentityProvider integration tests against real Postgres, 8 admin-API endpoint tests against real Postgres.)

### What this sub-session shipped

**A3-α** — the foundation for two-tier identity. End users are now a first-class entity, distinct from operators. Vservers carry a `visibility` flip (`public` / `private`). Private vservers require explicit grants (per-user OR per-group). The inbound MCP route enforces all of this. The operator API surface for managing users / groups / grants / API keys / visibility is live.

**β (OIDC + login flow) deferred to next session** — see "Open work" below. α alone is a production unblock for any deployment that's OK with admin-issued API keys per user; β makes the human-login UX (Microsoft / Google / username+password) work on top.

#### What's new in α

1. **Migration `20260430_0006`** — five new tables + one new column on `virtual_servers`:
   - `users` — end users; `auth_method ∈ {local, microsoft, google}`; `password_hash` (bcrypt) for local; `external_subject` (OIDC `sub`) for OIDC; `must_change_password` flag for forced rotation.
   - `groups` — admin-managed logical groupings.
   - `user_group_memberships` — many-to-many user ↔ group join (no `tenant_id` column; scoping via FKs to `users.tenant_id` + `groups.tenant_id`).
   - `virtual_server_grants` — explicit ACL for private vservers; targets either a user OR a group; `revoked_at` soft-deletes.
   - `user_api_keys` — per-user bearer tokens for inbound MCP; bcrypt-hashed; `key_prefix` carries the first 8 chars for operator-UI display.
   - `virtual_servers.visibility` — `public` (any tenant principal) | `private` (allowlist via grants). **Default `private`** per Q1.

2. **`vyuu_gateway/users/`** — new package.
   - `passwords.py` — bcrypt hashing + verify; minimum 12-char rule per Q3; constant-time anti-enumeration in `verify_password`.
   - `api_keys.py` — wire format `vyuu_user_<id-base32>_<secret-b64>`, prefix-based scope routing, bcrypt verify, malformed-key rejection.
   - `local_auth.py` — `(email, password) → User row` for `auth_method=local`, with **constant-time anti-enumeration** (always runs bcrypt-verify even on missing-email / wrong-method paths so attackers can't side-channel which emails exist).

3. **`identity/api_key_provider.py`** — new `ApiKeyIdentityProvider` that **trusts only the bearer token**. The architectural shift documented in the design sketch: production cannot trust client-supplied `x-vyuu-*` headers; tenant + principal identity come from the matched `user_api_keys` row alone. Drop-in replacement for `FakeIdentityProvider` (same `IdentityProvider` Protocol).

4. **`virtual_servers/access.py`** — visibility + grant enforcement. Single SQL `EXISTS` query covers direct user grants + transitive group grants. Wired into the inbound MCP route's `initialize` handler — 403 before session creation if the principal lacks a grant on a private vserver. Public vservers fall through.

5. **`registry/users_service.py`** + **`registry/users_schemas.py`** — service + Pydantic models for the admin API.

6. **`api/users.py`** — operator-side admin endpoints (~17 routes):
   - Users: `POST/GET /users`, `GET/{id}`, `POST /{id}/password` (admin reset, sets `must_change_password=True`), `DELETE /{id}` (soft-disable via `disabled_at`).
   - User API keys: `POST /users/{id}/api-keys` (returns plaintext **once**), `GET`, `DELETE/{key_id}` (soft-revoke).
   - Groups: `POST/GET /groups`, `POST/{id}/members`, `DELETE/{id}/members/{user_id}`.
   - Vserver visibility: `PATCH /vservers/{id}/visibility`.
   - Grants: `POST /vservers/{id}/grants`, `GET`, `DELETE/{grant_id}`.

7. **`bootstrap.py`** — first-run env-var auto-seed. When `VYUU_BOOTSTRAP_TENANT_NAME` + `VYUU_BOOTSTRAP_ADMIN_EMAIL` + `VYUU_BOOTSTRAP_ADMIN_PASSWORD` are all set AND no operators exist yet, the gateway lifespan creates the initial tenant + operator + admin user atomically. Idempotent — no-op once any operator exists. Replaces the original CLI/script-based bootstrap idea per user direction Q8 ("keep it simple").

8. **`tests/conftest.py`** — promotes `VYUU_TEST_DATABASE_URL` → `VYUU_DATABASE_URL` if set, BEFORE any vyuu_gateway import. Required because `SessionLocal` is built at module-import time from `Settings.database_url`.

9. **Lab compatibility** — pre-existing vservers (drawio-http, drawio-stdio, time-pypi) keep working. The `lab_bootstrap.py` was updated to seed `visibility=PUBLIC`, and test fixtures across `test_inbound_mcp.py`, `test_e2e_interoperability.py`, `test_drawio_upstream.py` now pass `visibility=VirtualServerVisibility.PUBLIC` explicitly. Default for *new* registrations through the production API stays `private`.

#### Architectural shift to be aware of

`FakeIdentityProvider` (still used in the lab) reads `x-vyuu-*` request headers and trusts them. **`ApiKeyIdentityProvider` ignores those headers entirely** — production deployments cannot trust client-supplied identity. The grant-enforcement test confirms: even if a request carries spoofed `x-vyuu-tenant-id` + `x-vyuu-principal-id` headers, the real provider derives `(tenant_id, user_id)` solely from the bearer-keyed `user_api_keys` row.

Lab continues to use the fake provider for its existing demos. Production wiring would be:

```python
create_app(
    identity_provider=ApiKeyIdentityProvider(SessionLocal),
    ...
)
```

#### Lab demo recipe (without the portal — admin uses curl/API directly)

```bash
# 0. As before: lab_bootstrap.py seeds tenant + operator + drawio demos.
python3 examples/lab_bootstrap.py

# 1. Start the lab.
python3 examples/drawio_lab_server.py

# 2. Use the printed admin token to:
TOKEN="<from lab banner>"
BASE="http://127.0.0.1:8765/api/v1"

# 2a. Create a local user.
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"alice@corp","password":"very-strong-12+chars","display_name":"Alice"}' \
  $BASE/users
# → returns {"id": "alice-uuid", ...}

# 2b. Issue an API key for alice.
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"label":"Claude Desktop on MacBook"}' \
  $BASE/users/<alice-uuid>/api-keys
# → returns {"plaintext": "vyuu_user_...", ...}  (SHOWN ONCE)

# 2c. Optional: flip drawio-http to private + grant alice access.
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"visibility":"private"}' \
  $BASE/vservers/<drawio-http-uuid>/visibility

curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"principal_kind":"user","principal_id":"<alice-uuid>"}' \
  $BASE/vservers/<drawio-http-uuid>/grants

# Alice's Claude Desktop config:
{
  "mcpServers": {
    "drawio-via-vyuu": {
      "url": "http://127.0.0.1:8765/v/<tenant>/drawio-http/mcp",
      "headers": {"Authorization": "Bearer vyuu_user_..."}
    }
  }
}
# Note: Alice's lab still uses FakeIdentityProvider, so the bearer above
# is ignored. To exercise ApiKeyIdentityProvider end-to-end, override
# the lab's `identity_provider=ApiKeyIdentityProvider(SessionLocal)` —
# documented as a follow-up in BACKLOG.
```

#### β: what's deferred + sized

1. **β1 — OIDC core.** JWKS fetch + cache (in-memory, ~5min TTL, single-flight refresh on `kid` miss); JWT validation (`iss` / `aud` / `exp` / signature). Reused by both Microsoft and Google providers — common code lives in a `users/oidc.py` module. ~half day.

2. **β2 — concrete providers.** `MicrosoftEntraIdProvider` (issuer `https://login.microsoftonline.com/{tenant}/v2.0`, claim mapping for `oid` / `email`) and `GoogleWorkspaceProvider` (issuer `https://accounts.google.com`, claim mapping for `sub` / `email` / `hd`). ~half day.

3. **β3 — login flow.** New routes `POST /api/v1/auth/login` (local password) and `GET /api/v1/auth/oidc/{provider}/callback` (OIDC redirect handling). Session cookie issuance (HTTP-only, signed). JIT user provisioning on first OIDC login when `tenant_id` claim matches an existing tenant. ~half day.

4. **β4 — tests.** Real local Keycloak via Docker (env-gated `VYUU_TEST_KEYCLOAK_URL`); JWKS-mock unit tests for the rotation path; end-to-end happy + failure paths. ~half day.

Total β estimate: ~2 days. **The user's portal UI** (catalog view, request-access form, my-API-keys page) is **γ + δ** in the original phasing — separate session.

### What's now possible end-to-end after α

- Admin registers MCP servers + publishes vservers (existing flow).
- Admin marks vservers `private` and grants user / group access (NEW).
- Admin creates local-auth users + groups via API (NEW).
- Admin issues per-user API keys (NEW). Each user's Claude Desktop / Cursor / agent uses its own key.
- Inbound MCP requests with a valid user API key resolve to a `(tenant_id, user_id)` identity — derived from the bearer alone, never from headers.
- Private vservers enforce grants on connect — direct user grants OR transitive group grants.
- Lab continues working unchanged (uses `FakeIdentityProvider` + public-visibility seed rows).

### What's NOT yet usable in production

- **No login UI for end users** — γ + δ. End users currently can't log in; admin creates them and hands out API keys out-of-band. Portal will close that loop.
- **No OIDC** — β. Operators / users can't sign in with Microsoft / Google / SSO yet.
- **No request/approval workflow** — γ. End users can't request access to MCPs they don't have; admin grants directly.

### Local-machine state

- Postgres (lab) on `127.0.0.1:5432`; Postgres (test) on `127.0.0.1:55432`. Migrations through `20260430_0006` on both.
- Redis on `127.0.0.1:6390/15`.
- NATS JetStream on `127.0.0.1:4222`.
- Lab on `127.0.0.1:8765`.
- New deps installed: `bcrypt>=4.0.0`, `email-validator>=2.0.0`. Both in `pyproject.toml` base dependencies.

---

## Sub-session update — 2026-04-30 (UX batch: U1, U2, U4)

Read this section first. Earlier 2026-04-30 sub-sessions sit below.

### Validation

```bash
pytest        # 522 passed (zero skipped, with all real services attached)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 136 source files
```

### What this sub-session shipped

Three small operator-UX wins ahead of the A3 (real identity provider) work next session.

**U4 — bounded stderr capture on stdio startup failure.** This is the highest-impact item of the three. `StdioMcpClient` historically redirected subprocess stderr to `/dev/null` for the right security reason (an untrusted upstream shouldn't be able to leak secrets / customer data into gateway logs). But when an upstream like CrowdStrike's `falcon-mcp` exits during `initialize` because `FALCON_CLIENT_ID` is missing, the operator only saw `McpError: Connection closed` → 502, with no clue why. The actual reason — `Configuration error: Falcon API credentials not provided. Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET.` — sat in stderr and got silently discarded.

Implementation:
- `StdioMcpClient._session` now uses a tempfile (real fileno required by `subprocess.Popen`) instead of `/dev/null`. The tempfile is auto-deleted on close; healthy upstreams' stderr is still effectively discarded.
- On startup failure, the `_session` `try/except` drains the tempfile (capped at 512 bytes — defense against a hostile upstream emitting unbounded stderr before exiting), runs `_sanitize_stderr_capture` (strips ANSI escapes, replaces control characters with space, refuses if the payload looks like a JSON-RPC message that ended up on stderr by mistake), and re-raises `UpstreamStartupDiagnosticError(original_error_class, sanitized_stderr)`.
- `_upstream_sync_error` in `api/servers.py` detects the diagnostic error and includes the stderr in the 502 detail. Other upstream errors stay metadata-only (sanitized error class only) — the bounded + sanitized stderr only surfaces for stdio startup failures specifically.
- **Live-verified through the lab.** Registered `falcon-mcp` via PyPI source type with no creds; sync now returns:
  > `upstream sync failed: McpError — upstream stderr: ...Configuration error: Falcon API credentials not provided. Either pass client_id and client_secret parameters or set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables.`
- Tests cover: live subprocess that exits with a stderr message, healthy subprocess (no diagnostic raised), sanitizer cap enforcement, ANSI/control-char stripping, JSON-shaped payload refusal, empty input.

**U1 — operator-UI CSS cleanup + meaning-coded pills.** Two fixes in one:

1. The CSS had two `:root` blocks left over from the design redesign — the first defining legacy vars (`--ink`, `--muted`, `--panel`, `--accent`, `--accent-dark`, `--green`, `--shadow`), the second the canonical Vyuu Design System tokens. The legacy block was dead-but-loaded code: the override-block selectors won, but the legacy vars stayed in memory and a few dead rules referenced them. Replaced both blocks with a single consolidated `:root` carrying only the Vyuu tokens. Carried forward the rules the legacy block uniquely owned (`*{box-sizing}`, `body{margin,min-height}`, `h1,h2,h3{margin:0}`, `.form-grid{display:grid; grid-template-columns}`, `.cards{display:grid}`, `.server-card strong{display:block}`, `.output{padding,overflow}`, `.form-grid button`, `.hint`).
2. Pills didn't encode meaning. Health pill was `var(--vyuu-orange-soft)` regardless of whether the server was `unknown`, `healthy`, `degraded`, or `down`. Now five variants per Vyuu spec — `.pill-orange` (positive/active), `.pill-warn` (in-flight/advisory), `.pill-danger` (failure), `.pill-info` (categorical), `.pill-neutral` (standby) — and a `pillClassForHealth(status)` JS helper that maps `health_status` to the right variant. Operators can glance at the row and tell good from bad without reading the label.

**U2 — discovery-succeeded-but-calls-may-need-creds advisory.** Some upstream MCPs (CheckPoint Quantum, many internal enterprise MCPs) follow a "discovery-open / invocation-gated" pattern: `initialize` and `tools/list` succeed without auth, but `tools/call` 401s. Operators sync, see "12 tools synced", get surprised when their first tool call fails. Now: after a successful sync, if the server has **zero** auth configured (`auth_headers` empty, `auth_env` empty, `auth_passthrough` empty, `auth_oauth` null) AND the sync returned a non-zero `capability_count`, the JSON output gets prefixed by an inline advisory:

> *"Discovery succeeded but tool calls may still require credentials — this server has no auth_headers / auth_env / auth_passthrough / auth_oauth configured."*

Rendered as a sibling `<p class="advisory">` to the JSON-output `<pre>`, so re-renders cleanly remove the prior advisory. Styled with the warn-tint Vyuu palette. Doesn't replace the JSON output — just nudges before the operator stops reading.

### Live state

- Lab still running on `127.0.0.1:8765`. Open `/operator`, paste the lab token, register a server with no creds → sync → see the advisory.
- All other local services (Postgres test cluster, Redis, NATS JetStream) still up from prior sub-sessions.

---

## Sub-session update — 2026-04-30 (Roadmap batch: S1, S3-S7, S10)

Read this section first. The earlier 2026-04-30 sub-sessions sit below.

### Validation

```bash
pytest        # 516 passed (zero skipped, with VYUU_TEST_NATS_URL +
              # VYUU_TEST_REDIS_URL + VYUU_TEST_DATABASE_URL +
              # VYUU_TEST_DRAWIO_UPSTREAM=1 attached)
ruff check . # All checks passed!
mypy .       # Success: no issues found in 136 source files
```

(~80 new tests across the six items below — most against real services where feasible: real NATS JetStream stream, real Uvicorn-hosted FastMCP SSE server, real `BackgroundTasks` execution, etc.)

### What this sub-session shipped

The user authorized blowing through the backlog roadmap items in sequence (S1 → S2-skipped → S3 → S4 → S5 → S6 → S7 → S10), pausing only for security-trade-off decisions. **S2 (OCI / Docker source type) was deliberately parked** — see the user-decision note in BACKLOG.md.

#### S1 — Static binary source type (`source_type=binary`)

- New enum value + migration `20260430_0005`. Distinct from `stdio` source type (which is for relative-name commands from a curated allowlist; binary is for absolute paths to pre-installed executables).
- `StdioLaunchPolicy.validate_binary_path` — absolute path required, no shell metacharacters, no `..` traversal, must exist + be executable, optional `allowed_binary_paths` allowlist for production deployments.
- Schema validator: must start with `/`. Lock-out for relative paths happens at registration; existence + permission checks happen at provider build (502 path).
- Operator UI dropdown updated.
- **Live verified**: registered `binary-demo` pointing at `/usr/bin/env`; relative-path negative case 422'd with the right error.
- **S1.b — Cosign / Sigstore signature verification** — added to BACKLOG. Optional supply-chain provenance layer on top of S1; not shipped this session.

#### S3 — Durable audit producers (Kafka + NATS)

- `vyuu_gateway/audit/kafka_producer.py` — `KafkaAuditProducer` over `aiokafka`. Single topic (`vyuu.audit.events` default), tenant_id as message key for per-tenant ordering on the same partition, headers carry `event_id` / `decision` / `tenant_id` for header-based routing without parsing the body. `acks=all` + idempotent producer for compliance-grade durability.
- `vyuu_gateway/audit/nats_producer.py` — `NatsAuditProducer` over `nats-py` JetStream. Per-tenant subject `vyuu.audit.events.<tenant_id>` under a shared stream (auto-creates: NO; that's a deployment concern). Headers: `Vyuu-Event-Id`, `Vyuu-Decision`, `Vyuu-Tenant-Id`.
- Both lazy-import their broker libraries — base install stays light. New optional extras `[kafka]` and `[nats]` in `pyproject.toml`.
- Existing `AsyncAuditEmitter` (queue + worker + disk-spool fallback) is unchanged — these slot in as `AuditProducer` Protocol implementations.
- **Live verified end-to-end against a real `nats-server -js`**: published an audit event, consumed it back via JetStream pull subscription, asserted wire format including correlation headers.

#### S4 — `AsyncGraphEventEmitter` + Kafka/NATS graph producers

- Mirror of the audit pipeline. `AsyncGraphEventEmitter` queues + worker; `KafkaGraphProducer` / `NatsGraphProducer` for the durable backend.
- Different topic / subject prefix (`vyuu.graph.events`) so audit + graph have separate retention / consumer groups.
- **No disk-spool fallback** for graph events (unlike audit) — graph events are derivable from audit events via `correlation_id`, so durability rides on the audit pipeline. Producer failure on graph → mark degraded + drop. Saves substantial plumbing for marginal value.
- Backpressure: queue-full → drop + flag `degraded`. Graph events are best-effort by design; we never block the request hot path waiting for queue space.
- **Live NATS round-trip verified** (asserts the `Vyuu-Correlation-Id` header is the durable join key with the audit pipeline).

#### S5 — SSE outbound transport

- New `SseMcpClient` in `mcp/outbound.py`, parallel to `StreamableHttpMcpClient`. Same auth shape — org-tier `extra_headers`, user-tier `auth_passthrough`, OAuth bearer. SSE doesn't pool an httpx client; sessions rebuild per call so all auth merges into per-session headers.
- Provider routes `transport=sse` → `SseMcpClient`. `UnsupportedUpstreamTransportError` is now defensive (fires only if a future enum value is added without a branch).
- **Tests run against a real Uvicorn-hosted FastMCP SSE app** on a free local port — full round trip including capability sync, passthrough header forwarding, and OAuth token injection.

#### S6 — Registration-time MCP probe

- `POST /api/v1/servers` now schedules a non-blocking health probe via FastAPI `BackgroundTasks` after a successful insert. The probe runs after the response is sent; the operator's `health_status` flips off `unknown` without manual intervention.
- Probe failures are caught at the wrapper layer; the existing `UpstreamHealthChecker.check_server` already persists `health_status=DOWN` with the sanitized error class.
- Tests cover the happy path (probe scheduled with the right args), the swallowed-exception path (registration response unaffected by probe failures), and end-to-end with `TestClient` (which runs background tasks synchronously after the response).

#### S7 — Periodic capability-sync worker

- `PeriodicCapabilitySyncScheduler` in `vyuu_gateway/capabilities/scheduler.py`. Off by default — `Settings.capability_sync_enabled=False`. Operators opt in via env var.
- Per-tenant concurrency cap (default 4) so a 1000-server tenant doesn't hammer all upstreams simultaneously. Tenants run in parallel; within a tenant, throttled by an `asyncio.Semaphore`.
- Per-call timeout (default 30s) — slow upstream doesn't block other servers in the cycle.
- Per-server failures swallowed + logged with the unwrapped error class (same `BaseExceptionGroup` drilling pattern as the health checker).
- Lifespan integration: gateway startup spawns the worker if enabled; shutdown cancels it cleanly.
- Tests use a `_FakeSession` with **bind-parameter-aware** `scalar()` so concurrent per-server syncs receive distinct rows (otherwise every concurrent `_sync_one` would re-process the same first server). 11 tests covering happy path, concurrency cap, separate-tenant parallelism, per-call timeout, per-server failure tolerance, lifecycle, opt-in default, and interval clamping.

#### S10 — Manual capability seeding endpoint

- `POST /api/v1/servers/{id}/capabilities` accepts a `CapabilitySeedRequest` (list of `{kind, name, schema_json, risk_category?}` entries) and writes them as the active snapshot via a new `seed_server_capabilities()` function in `capabilities/sync.py`.
- Use cases (all surfaced from real-world testing): credential-gated MCPs that can't be probed (CrowdStrike `falcon-mcp` validates credentials in its constructor), air-gapped deployments where the gateway can't reach the upstream during the sync window, compliance-freeze windows, pre-procurement evaluation.
- Same drift-detection contract as upstream sync — previous capabilities flip to deprecated, new ones are added, the response carries the same drift summary as `POST /sync`. Re-running `/sync` later replaces the manual snapshot with the probed snapshot via the existing drift logic.
- **`last_capabilities_pulled_at` is intentionally NOT updated** by manual seeding — that field signals "verified against upstream" and a manual seed has no such verification. Operator UI can surface "manually seeded — not verified" based on this flag.
- Per-capability `risk_category` overrides: operators can pin specific risks (compliance team forcing `delete_indicator` to `delete` even if the heuristic would have classified it `write`). Names without an override go through the standard `classify_tool_risk` heuristic.

### What's now possible end-to-end

After this batch, an operator can:
1. Register a credential-gated MCP (CrowdStrike Falcon) without provisioning credentials.
2. Manually seed its capability catalog from vendor docs (S10).
3. Publish a virtual server with a chosen subset of those tools.
4. Wire the actual credentials (S6 from the prior session — `auth_env` + `SecretStore`).
5. Optionally enable the periodic sync worker (S7) so when credentials land and the upstream becomes reachable, the catalog auto-refreshes against reality.
6. Audit events stream durably to Kafka/NATS (S3); graph events run in parallel (S4).
7. Either Streamable HTTP, SSE, stdio (npm/pypi/binary), or any combination of upstream MCPs are routed correctly.

### What's now in the BACKLOG

The remaining items are auth, security hardening, ops/observability:

- **A1** OAuth authorization-code flow (~3-5d) — unblocks Google Drive native, Notion, Linear, Salesforce, GitHub Apps.
- **A2** JWT-bearer / service-account flow (~1d) — unblocks Google Workspace, AWS IAM Roles Anywhere, GCP service accounts.
- **A3** Real OIDC / API-key identity provider (replaces fakes).
- **A4–A6** auth follow-ups (401 retry, audit signal, secret-store backends).
- **S1.b** Cosign / Sigstore signature verification on binary source type.
- **S2** parked (Docker daemon access, deliberate non-decision).
- **S8, S9** parked.
- **H1–H6** security hardening (DNS-time SSRF, TLS guidance, payload limits, allowlists, raw-args capture, header templating).
- **U1–U4** operator UX cleanups.
- **P1–P3** performance / measurement-driven optimizations.

### Local-machine state

- Postgres lab on `127.0.0.1:5432`, DB `vyuu_gateway`, migrations through `20260430_0005`.
- Postgres test cluster on `127.0.0.1:55432`, DB `vyuu_gateway_rls_test`, also through `20260430_0005`.
- Redis on `127.0.0.1:6390/15`.
- **NATS server with JetStream on `127.0.0.1:4222`** (started this session via `nats-server -js -p 4222 -m 8222 -sd /tmp/vyuu_nats_jetstream`). Tear down: `nats-server` is in the foreground / shell-managed; check with `lsof -i :4222`.
- Lab on `127.0.0.1:8765`.

---

## Sub-session update — 2026-04-30 (Outbound auth — phase 2: user-tier passthrough)

Earlier today; user-tier passthrough sits below.

### Validation

```bash
pytest        # 432 passed, 19 skipped
ruff check . # All checks passed!
mypy .       # Success: no issues found in 122 source files

# Full no-skip run (against local Postgres test cluster + Redis + real drawio):
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest       # 451 passed
```

(Six new tests this slice: 3 schema/registration, 2 outbound HTTP client, 1 lifecycle. The 19 environment-gated tests — 7 RLS Postgres, 9 Redis sessions, 3 real-network drawio — were also exercised end-to-end this session and all pass.)

### What this sub-session shipped

**Phase 2 of outbound auth — user-tier credential pass-through.**

This complements phase 1 (org-tier `auth_headers` resolved from a `SecretStore`). The key product insight:

> Different MCPs have different credential ownership models. A corporate Datadog dashboard is *org-tier* — one shared API key for the whole tenant. A developer using GitHub or Notion or PayPal has their *own* personal token — *user-tier*. The gateway needs both, and operators pick the model per server at registration.

What's now true: an operator can register a SaaS MCP **without storing any credential in the gateway at all**. Each end user supplies their own token in their MCP client config (`x-vyuu-paypal-token: Bearer their-personal-pat`). The gateway translates that to the upstream's expected header (`Authorization: Bearer ...`) and forwards. Different users → different tokens → different upstream principals → no org-shared credential, no per-user provisioning UX, no OAuth complexity.

What's not in this slice: OAuth 2.0 client-credentials and authorization-code flows (phase 3). Those are the prettiest UX ("click Connect to GitHub, forget about it") but real complexity. Pass-through covers an enormous share of real-world enterprise MCPs *without* OAuth — every PAT-based and token-based SaaS qualifies.

1. **DB schema — migration `20260430_0003`.**
   - `mcp_servers.auth_passthrough JSONB DEFAULT '{}'` — `{inbound_header_name → upstream_header_name}` map.
   - Defaults to empty so existing rows continue to work.

2. **`OutboundMcpClient` Protocol extension.**
   - `call_tool(tool_name, arguments, *, inbound_headers: dict[str, str] | None = None)`. Stdio implementation accepts (and ignores — registration validator rejects `auth_passthrough` on stdio so this can never be set).
   - `StreamableHttpMcpClient` carries an immutable `auth_passthrough_map` (set at construction by the provider from `server.auth_passthrough`). Per-call: filters the inbound headers through the map (case-insensitive on the inbound side, since Starlette lowercases), and forwards only matched entries — never blindly relays inbound headers.
   - When pass-through fires, the call uses a **one-shot httpx client** with merged `extra_headers` + `passthrough` — the credential never lives on the long-lived pooled client. A leaked credential cannot bleed into another tenant or another user's connection. The one-shot client mirrors the pooled client's `transport` so ASGI-transport-based tests still work.
   - When no inbound header matches, the call uses the pooled connection (existing fast path — connection reuse, etc.).

3. **Lifecycle plumbing.**
   - `ToolCallRequest.inbound_headers: dict[str, str]` (default `{}`).
   - `handle_tool_call` threads them into `upstream_clients.get_client(...).call_tool(..., inbound_headers=...)`.
   - The lifecycle does NO filtering — that's the upstream client's job, since the filter map is per-server and lives with the client.

4. **Inbound MCP route.**
   - Extracts the FastAPI `request.headers` into a plain dict and stuffs it on `ToolCallRequest.inbound_headers` for every `tools/call`.
   - Filtering happens downstream in the StreamableHttpMcpClient (per-server config). The route is dumb — it just plumbs.

5. **Schema validation — three new rules.**
   - `auth_passthrough` is HTTP-only (rejected on stdio at registration → 422).
   - `auth_passthrough` upstream-header values cannot collide with `auth_headers` keys — the operator must pick **one** model per upstream header. Otherwise resolution order would silently shadow whichever lost.
   - Per-entry: empty / control-character names rejected.

6. **Operator UI.**
   - Third optional field on the register form, labeled "Auth passthrough (HTTP only) — JSON {inbound_header:upstream_header} — each user supplies their own credential per request".
   - JS extends the existing JSON-parse + omit-when-empty pattern that already handles `auth_headers` / `auth_env`.

7. **Live verification (with the running lab):**
   - Registered an HTTP MCP at `https://httpbin.org/bearer` with `auth_passthrough={"x-vyuu-paypal-token": "Authorization"}`. **No** `auth_headers`, **no** `env_vars_ref`, **no** secret in the gateway store.
   - Probed `_select_passthrough` with five different inbound header sets:
     - `{x-vyuu-paypal-token: Bearer alice-pat}` → forwarded as `{Authorization: Bearer alice-pat}` ✓
     - `{X-Vyuu-Paypal-Token: Bearer bob-pat}` → case-insensitive match → `{Authorization: Bearer bob-pat}` ✓
     - `{x-rando-leak: ...}` → DROPPED (not in config) ✓
     - `{}` → `{}` ✓
   - Different users carrying different tokens → different upstream calls → no org-shared credential anywhere.

### Threat model & operational notes

- **No credential ever persists in the gateway.** Pass-through is by definition a per-request flow. The credential transits memory only for the duration of a single tool call (the one-shot httpx client + ClientSession lifetime).
- **Allowlist-only forwarding.** Only headers explicitly listed in `auth_passthrough` are forwarded. Random inbound headers (including any vendor-specific telemetry headers an MCP client might add) are NEVER blindly relayed to upstreams.
- **Case-insensitive on inbound, exact on upstream.** Starlette / HTTP normalizes inbound headers to lowercase, so matches are case-insensitive on the input side. Upstream header names are sent verbatim as the operator configured them (PayPal/GitHub/etc. are picky about exact casing in some implementations).
- **Pooled-vs-one-shot isolation.** Pass-through always builds a one-shot httpx client. That gives up connection reuse for those calls — a real cost at high throughput against the same upstream — but eliminates the risk of a stale per-user credential lingering in the pooled client. For a v1 the safety-vs-speed trade is the right one; if needed, a future "passthrough connection cache keyed by header signature" optimization fits cleanly.
- **No log leaks.** The forwarded credential is on the one-shot httpx client's default headers and never logged. The structured logger's `extra={...}` passthrough doesn't include it. Audit events do not capture per-call inbound headers.
- **Coexists with org-tier (`auth_headers`).** A server can have BOTH org-tier and user-tier auth as long as they target different upstream header names — the schema validator enforces this. Useful for upstreams that need a static API key (org) plus a per-user token (passthrough on a different header).
- **Audit signal.** `event.upstream_status` and standard latency / decision metadata fire as before. There's no explicit audit boolean that says "credential passed through" yet — worth adding before this leaves lab status, so operators can spot tenants where pass-through is actually being used.

### What's still pending

In rough enterprise-impact order:

1. **OAuth 2.0 client-credentials flow** (phase 3 of outbound auth). Auth-server URL + ref to client_id + ref to client_secret on the server row; cached token in memory; refresh on 401. Different from pass-through: pass-through means "user already has the token in hand"; OAuth means "gateway brokers the exchange." ~1 day.
2. **OAuth 2.0 authorization-code flow** with per-user tokens (e.g. "Connect to GitHub" UX). Bigger — token storage with TTL, redirect handling, revocation. Phase 4.
3. **Explicit audit signal for pass-through usage** — boolean flag on the audit event. ~1 hour.
4. **OCI / Docker source type** (~2 days).
5. **SSE outbound** (~2 hours).
6. **Static binary source type** (~1 day).
7. **Real OIDC / API-key identity provider** (replaces Fakes).
8. **Real Kafka / NATS audit producer + `AsyncGraphEventEmitter`.**
9. **Registration-time MCP probe + periodic capability-sync worker.**
10. **Operator-console UI cleanup** (dead `:root` block, color-coded pills).
11. **DNS-time SSRF backstop, TLS / mTLS at ingress, payload-size limits.**

### Local-machine state at the end of this sub-session

- Postgres 16 still running on `127.0.0.1:5432`, DB `vyuu_gateway`, migrations through `20260430_0003`.
- Lab is running on `127.0.0.1:8765`. Operator console: `http://127.0.0.1:8765/operator`.
- Lab has two demo rows in the DB from the live verification: `auth-demo` (org-tier `auth_headers={"Authorization": "demo-bearer"}` — phase 1) and `passthrough-demo` (user-tier `auth_passthrough={"x-vyuu-paypal-token": "Authorization"}` — phase 2).

### How to demo end-to-end

```bash
# Operator console
open http://127.0.0.1:8765/operator

# Register a server (paste the printed bearer token first):
#   Source type:        http
#   Source location:    https://mcp.paypal.com/mcp     (or any SaaS MCP)
#   Transport:          streamable_http
#   Auth headers:       (leave empty — no org credential)
#   Auth passthrough:   {"x-vyuu-paypal-token": "Authorization"}
#
# Each end user's claude_desktop_config.json:
# {
#   "mcpServers": {
#     "paypal-via-vyuu": {
#       "url": "http://127.0.0.1:8765/v/{tenant}/paypal/mcp",
#       "headers": {
#         "x-vyuu-tenant-id": "11111111-...",
#         "x-vyuu-principal-id": "alice@corp",
#         "x-vyuu-paypal-token": "Bearer alice-personal-pat"
#       }
#     }
#   }
# }
#
# When alice's Claude makes a tool call, the gateway forwards
#   Authorization: Bearer alice-personal-pat
# to PayPal. When bob's Claude makes the same call with his own
# token, PayPal sees Bob's token. No org-shared credential anywhere.
```

---

## Sub-session update — 2026-04-30 (Outbound auth — phase 1)

Earlier today; org-tier `auth_headers` / `auth_env` + `SecretStore` sit below.

### Validation

```bash
pytest        # 426 passed, 19 skipped
ruff check . # All checks passed!
mypy .       # Success: no issues found in 121 source files
```

(Twelve new tests this slice: 4 secret store, 3 provider auth-injection, 5 schema/registration.)

### What this sub-session shipped

**Phase 1 of outbound auth — secret store + header / env injection.**

This is the *unblock* for SaaS / commercial MCPs. Until this slice landed, registering CrowdStrike Falcon MCP, PayPal MCP, Wiz MCP, Snyk MCP, Datadog MCP, etc. worked, but the first call to the upstream would 401 because the gateway had nowhere to put the credential. Now operators register a server with **opaque secret refs**, and the gateway resolves them through a `SecretStore` at connection time — never persisting the raw credential in `mcp_servers`, never logging it.

What's not in this slice: OAuth 2.0 client-credentials flow (cached token + 401-driven refresh). That's phase 2 — small additive change on top of this one. mTLS to upstream is also deferred. Today's coverage handles the **80% case**: static API keys / bearer tokens / per-process env vars.

1. **`vyuu_gateway.secrets`** — new package.
   - `SecretStore` Protocol: `async get_secret(tenant_id, ref) -> str`. Tenant id is explicit so cross-tenant access raises `SecretNotFoundError` even when two tenants happen to share the same ref string.
   - `InMemorySecretStore` for dev / lab / tests. Tenant-scoped `(UUID, str) -> str` map; not thread-safe (writes happen at bootstrap, not in the hot path).
   - Production wires `VaultSecretStore` / `AwsSecretsManagerStore` / `KubernetesSecretStore` later — same Protocol contract, drop-in.

2. **DB schema — migration `20260430_0002`.**
   - `mcp_servers.auth_headers JSONB DEFAULT '{}'` — for HTTP transports; `{header_name: secret_ref}`.
   - `mcp_servers.auth_env JSONB DEFAULT '{}'` — for stdio transports; `{env_var_name: secret_ref}`.
   - Both default to empty so existing rows continue to work unchanged.
   - The gateway never stores raw credentials — only opaque references.

3. **Outbound clients accept the resolved values.**
   - `StreamableHttpMcpClient(..., extra_headers=...)` bakes them into the underlying `httpx.AsyncClient` so they ride on every outbound request (`initialize`, `tools/list`, `tools/call`, etc.). Combining `extra_headers` with a caller-provided `http_client` raises (`ValueError`) — pick one.
   - `StdioMcpClient(..., env=...)` threads them through to `StdioServerParameters(env=...)`, injecting into the spawned subprocess's environment. Header values and env values are never logged.

4. **Provider integration.**
   - `DatabaseBackedUpstreamClientProvider(secret_store=...)` resolves `auth_headers` / `auth_env` refs at client-build time. Empty maps short-circuit to no resolution. Missing refs raise `SecretNotFoundError`, which the existing 502 wrapper in `POST /api/v1/servers/{id}/sync` surfaces cleanly.
   - The pool's `ClientFactory` is now `Callable[[], Awaitable[OutboundMcpClient]]` (was sync). Necessary so the factory can `await store.get_secret(...)` — production secret stores are network-bound. Pool already runs under an async context, so no impact on the lifecycle.
   - Default for callers that don't pass a store: `InMemorySecretStore()` with no entries. Servers that haven't wired auth (e.g. drawio-http, mcp-server-time) behave exactly as before.

5. **Schema & validation.**
   - `ServerRegistrationRequest.auth_headers: dict[str, str] = {}`, `.auth_env: dict[str, str] = {}`. Both default to empty, so existing clients continue to work.
   - Per-transport rule: `auth_headers` rejected (422) on stdio; `auth_env` rejected (422) on HTTP — operators see the mistake at register, not at sync.
   - Per-entry: empty / control-character names rejected (defense against CRLF in HTTP headers, NUL in env vars, separate from the secret value). Empty refs rejected (would silently translate to "no secret").
   - `ServerRegistrationResponse` echoes the **refs**, never the resolved values.

6. **Operator UI.**
   - Two new optional inputs on the register form: "Auth headers (HTTP only)" and "Auth env (stdio only)", both accepting JSON object syntax `{"header_or_env_name": "secret_ref"}`.
   - JS validates the JSON before POST, and only includes the field in the request body when non-empty (so existing forms / no-auth registrations stay backward compatible).
   - Refs are stored verbatim; the operator never sees the resolved value through the UI.

7. **Lab demo.**
   - `examples/drawio_lab_server.py` now seeds a sample ref `"demo-bearer"` → `"Bearer demo-token-do-not-ship"` in an `InMemorySecretStore` and passes it to `create_app(secret_store=...)`.
   - End-to-end verified: registered an HTTP MCP at `https://httpbin.org/bearer` with `auth_headers={"Authorization": "demo-bearer"}`; pulling the resulting upstream client showed `authorization: Bearer demo-token-do-not-ship` baked into the httpx default headers — proving secret resolution fires at client-build time, not at registration.

### Threat model & operational notes

- **Refs vs values.** Raw credentials never live in `mcp_servers`. They sit in the secret store, which is network-bound in production. The DB carries only opaque pointers. A DB dump or read-replica leak does not expose credentials.
- **Tenant isolation.** Lookups are keyed `(tenant_id, ref)`, defense-in-depth on whatever isolation the underlying KMS already enforces. Cross-tenant lookups raise `SecretNotFoundError` even when refs collide.
- **No log leaks.** Header values and stdio env values are never logged. The structured logger's `extra={...}` passthrough does not include them.
- **Failure mode.** A missing ref raises `SecretNotFoundError`, which the sync endpoint maps to a clean 502 with sanitized error type — same shape as the upstream-unreachable case from the prior session. Operators see "upstream sync failed: SecretNotFoundError" and know to fix the ref binding.
- **Header / env injection at the *name* level.** Validators reject control characters in names so a malicious operator (or a typo) can't smuggle CRLF into an HTTP header name or NUL into an env var name. Values are passed through verbatim — defense at the name layer, trust at the value layer (since values come from the operator's own KMS).
- **What's NOT yet handled.**
  - **OAuth 2.0 client-credentials flow** — needed for upstreams that require token exchange + refresh on 401. Phase 2.
  - **mTLS to upstream** — operator-supplied client cert / key for SaaS MCPs that require it.
  - **Header-value templating** (e.g. `"Bearer {secret}"`) — today the operator stores the full header value (including any `Bearer ` prefix) in the secret. Templating is a v2 nicety.
  - **Per-package allowlist** on `auth_headers` / `auth_env` keys — today any name passes the regex, no membership check.
  - **Secret rotation.** A rotated secret in the KMS will be picked up on the next pool fetch (the factory re-resolves on each new connection). For long-lived pooled connections, rotation requires either a TTL on the pool or an explicit "evict" trigger. Worth measuring before adding.

### What's next, in enterprise-impact order

1. **OAuth 2.0 client-credentials flow** — phase 2 of outbound auth. Auth-server URL + client_id (ref) + client_secret (ref) on the server row; cached token in memory; refresh on 401. ~1 day on top of phase 1. Unblocks Wiz, Datadog (Bearer-only flows are covered today; OAuth-grant flows aren't).
2. **OCI / Docker source type** (~2 days). Several big-vendor MCPs ship as signed container images; gateway needs Docker daemon access + Cosign verification.
3. **SSE outbound** (~2 hours). Already in the enum; raises today.
4. **Static binary source type** (~1 day). Niche.
5. **Real OIDC / API-key identity provider** for the operator API + inbound MCP API (replaces `FakeOperatorAuthProvider` / `FakeIdentityProvider` — same Protocol contract).
6. **Real Kafka / NATS audit producer + `AsyncGraphEventEmitter`.** Today telemetry is in-process and lost on restart.
7. **Registration-time MCP probe + periodic capability-sync worker.** No scheduler today.
8. **Operator-console UI cleanup** — two follow-ups noted in the prior session (dead `:root` block; pills don't encode meaning).
9. **DNS-time SSRF backstop**, **TLS / mTLS on the inbound ingress**, **payload-size limits + response inspection**.

### Local-machine state at the end of this sub-session

- Postgres 16 running on `127.0.0.1:5432`, DB `vyuu_gateway`, migrations through `20260430_0002`.
- Lab is running on `127.0.0.1:8765`. Operator console: `http://127.0.0.1:8765/operator`. Demo secret seeded: ref `"demo-bearer"` → value `"Bearer demo-token-do-not-ship"` (lab tenant only).
- A test row `auth-demo` (id `a80f01e8-...`) is registered against `httpbin.org/bearer` with `auth_headers={"Authorization":"demo-bearer"}` from the live verification.

### How to demo end-to-end

```bash
# 1. Open the operator console.
open http://127.0.0.1:8765/operator

# 2. Paste the printed bearer token.

# 3. Register a server:
#    Source type:    http
#    Source location: https://httpbin.org/bearer
#    Transport:       streamable_http
#    Auth headers:    {"Authorization": "demo-bearer"}
#                     (the lab's seeded InMemorySecretStore resolves
#                     "demo-bearer" → "Bearer demo-token-do-not-ship")
#
# 4. Click "Sync capabilities" — the upstream call now carries
#    Authorization: Bearer demo-token-do-not-ship.
#    httpbin returns 200 (which doesn't speak MCP, so sync still 502s
#    on the protocol layer — but the auth header was sent).
#    Watch /tmp/lab.log to see the request go out.
```

---

## Sub-session update — 2026-04-30 (PyPI / `uvx` source type)

Earlier today; PyPI / uvx wiring sits below this section.

### Validation

```bash
pytest        # 412 passed, 19 skipped
ruff check . # All checks passed!
mypy .       # Success: no issues found in 117 source files
```

(Five new tests — three in `tests/upstream/test_provider.py` for the launch path, two in `tests/test_server_registration.py` for the registration API.)

### What this sub-session shipped

**PyPI / `uvx` source type — covers Python-published enterprise MCPs.**

The big enterprise vendors (CrowdStrike Falcon MCP, Palo Alto Cortex MCP, Wiz MCP, Snyk MCP, Datadog MCP, Anthropic reference servers, FastMCP-based servers) ship through PyPI and document `uvx <package>` as the install path. `npx`/npm covered the JS ecosystem; this closes the parallel gap for Python.

1. **Enum** — `McpServerSourceType.PYPI = "pypi"` added to `db/models.py`.
2. **Migration** — `migrations/versions/20260430_0001_add_pypi_source_type.py` drops + recreates the `mcp_servers_source_type_check` Postgres CHECK constraint with the expanded set `('npm', 'pypi', 'http', 'stdio')`. Down-migration restores the original three-value set.
3. **`StdioLaunchPolicy.validate_pypi_package`** — PEP 508 distribution-name regex `^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?:@[A-Za-z0-9][A-Za-z0-9._+!-]*)?$`. Accepts `mcp-server-time`, `crowdstrike-falcon-mcp`, `mcp_server_time`, `crowdstrike-falcon-mcp@1.4.0`. Rejects `../etc/passwd`, `pkg with space`, and other shell-metacharacter / path-traversal shapes. Mirrors the existing `validate_npm_package` shape.
4. **`DatabaseBackedUpstreamClientProvider`** — new branches in `_validate_supported` and `_build_stdio_client` for `PYPI`. Launch shape: `command="uvx"`, `args=[package, *server.args]`. **No `-y`** — `uvx` never prompts. `package@version` is honored by the regex, so production registrations should pin (`crowdstrike-falcon-mcp@1.4.0`, etc.) and the gateway will pass that through to `uvx` verbatim.
5. **Schema validator** — extended the existing transport rule: `pypi` (like `npm`) requires `stdio` transport. Wrong transport returns 422.
6. **Lab demo (third pre-baked vserver)** — `examples/lab_bootstrap.py` now seeds an `mcp-server-time` PyPI upstream (Anthropic reference; free; no API key) plus a `time-pypi` vserver bundling its `get_current_time` and `convert_time` tools. Fixed UUIDs (`...244` server, `...355` vserver) so the printed URLs are stable. The lab banner prints all three demos. **End-to-end verified** through the running lab: `POST /api/v1/servers/.../sync` returned `capability_count=2`; `streamablehttp_client.call_tool('get_current_time', {timezone: 'Asia/Kolkata'})` returned `{"timezone":"Asia/Kolkata","datetime":"2026-04-30T10:40:09+05:30","day_of_week":"Thursday","is_dst":false}` from the upstream `mcp-server-time` process spawned via `uvx`.

### Threat model & operational notes

- **Same as npm.** Arbitrary-package fetch+execute via a public registry. Mitigations parallel: tenant-scoped registration is audited; capability sync surfaces the actual tool surface before publish; `validate_pypi_package` checks name shape.
- **Per-package allowlist is a follow-up.** Today `validate_pypi_package` (and `validate_npm_package`) only check name regex, not membership in an approved set. Production should layer `StdioLaunchPolicy(allowed_pypi_packages=...)` on top — wire-in is one method + one config option.
- **`uvx` must be on PATH.** Container image must `pip install uv`. First call has cold-start latency (resolve + download); uv caches under `~/.cache/uv`, so a persistent volume in k8s avoids re-resolving on each pod restart.
- **Private indices** (`UV_INDEX_URL`, internal Artifactory / Nexus) — out of scope for this PR. Will ride on the per-tenant secret-store work that's the #2 priority below.

### What's next, in enterprise-impact order

The remaining source-type / transport gaps are documented now. After this PR, **adding more source types is not the bottleneck** — outbound authentication is.

1. **Outbound authentication to upstream MCPs (HIGHEST PRIORITY).** Without this, no enterprise SaaS MCP can actually be used through the gateway, regardless of how it's packaged. CrowdStrike Falcon MCP via `uvx` registers cleanly today — but the first time it tries to reach Falcon's API it'll 401 because there's no API-key injection. Three sub-features: (a) tenant-scoped secret store behind `env_vars_ref` (Vault / AWS Secrets Manager / k8s secret — pluggable), (b) header injection on outbound HTTP (`Authorization: Bearer <ref>`, custom-header templates), (c) OAuth 2.0 client-credentials flow with cached token + 401-driven refresh. ~2.5 days.
2. **OCI / Docker source type.** `source_type=oci`, command `docker`, args `["run","-i","--rm","--read-only",...]`. Several big-vendor MCPs ship as signed container images for sandbox + supply-chain provenance. Threat model: gateway needs Docker daemon access — has to ride on AppArmor / SELinux / rootless Podman. Cosign signature verification before pull. ~2 days.
3. **SSE outbound compatibility.** Already in the `McpTransport` enum, raises `UnsupportedUpstreamTransportError` today. Some legacy public MCPs still ship SSE-only. ~2 hours.
4. **Static binary source type.** Niche — already roughly possible via `STDIO` source_type with `allow_absolute_commands=True`. A dedicated source type would let the gateway verify binary signatures on register. ~1 day.
5. **Go modules / Cargo / Bun.** Real but extremely niche.
6. **MCP manifest discovery.** Register by URL to a published `mcp.json` and let the gateway fingerprint transport + auth requirements. Standardization is still in flux — wait.
7. **Per-package content allowlist** (touched on above).
8. **Items from the prior session that remain pending** — operator-console UI cleanup (two follow-ups noted in the previous handoff section), real OIDC / API-key identity provider, durable audit + graph emitters, registration-time MCP probe, periodic capability-sync scheduler, DNS-time SSRF backstop, TLS / mTLS at the ingress, payload-size limits + response inspection.

### Local-machine state at the end of this sub-session

- Postgres 16 still running on `127.0.0.1:5432`, DB `vyuu_gateway`. Migration `20260430_0001` applied. Bootstrap re-run idempotently — `time-pypi` server (`...244`) and vserver (`...355`) are now seeded alongside the prior drawio rows.
- Lab is running on `127.0.0.1:8765`. Operator console: `http://127.0.0.1:8765/operator`. Three pre-baked vservers (`drawio-http`, `drawio-stdio`, `time-pypi`) are visible in the Virtual Servers panel after pasting the lab token.
- `uvx` is at `~/.local/bin/uvx` (uv 0.11.8). On first call to `time-pypi` the lab spawns `uvx mcp-server-time` which downloads + caches the package; subsequent calls reuse the cached venv.

### How to resume

```bash
# 1. Postgres should be up; verify:
/opt/homebrew/opt/postgresql@16/bin/pg_isready -h 127.0.0.1

# 2. Bootstrap is idempotent — safe to re-run after a fresh DB:
VYUU_DATABASE_URL="postgresql+psycopg://vyuu@127.0.0.1:5432/vyuu_gateway" \
  python3 examples/lab_bootstrap.py

# 3. Start the lab (or restart if 8765 is taken — kill the old one first):
VYUU_DATABASE_URL="postgresql+psycopg://vyuu@127.0.0.1:5432/vyuu_gateway" \
  python3 examples/drawio_lab_server.py

# 4. Open http://127.0.0.1:8765/operator, paste the printed token, and the
#    three demo vservers (drawio-http, drawio-stdio, time-pypi) are live.
```

---

## Sub-session update — 2026-04-30 (post-Codex, lab E2E hardening)

This section covers the prior sub-session — end-to-end test pass against real Postgres, the `Method not found` bug it surfaced, and the operator-console UI redesign that followed.

### Validation at the end of this sub-session

```bash
cd <repository root>
pytest        # 407 passed, 19 skipped
ruff check . # All checks passed!
mypy .       # Success: no issues found in 116 source files
```

(One additional source file vs the prior count is from a small refactor inside `mcp/outbound.py`; one additional test is the new regression covering the `Method not found` bug fix below.)

### What this sub-session changed / shipped

1. **Lab moved fully onto the production code path.** Removed the lab's `_DispatchingUpstreamProvider` + `_LabResolverSession` fakes. `examples/drawio_lab_server.py` now calls `create_app(...)` with production defaults (so it builds the real `DatabaseBackedUpstreamClientProvider` against `SessionLocal`), then wraps `app.state.upstream_clients` in `_LoggingUpstreamProviderWrapper` to keep `[upstream:<id>]` debug lines flowing. `_LoggingUpstreamClient` now implements the **full** `OutboundMcpClient` Protocol (`initialize`, `list_tools`, `list_resources`, `list_prompts`, `list_capabilities`, `call_tool`) — it logs around `call_tool` and delegates the rest. `app.state.capability_sync_client` is rebuilt against the wrapped provider so HTTP-driven syncs also surface in stdout. No more `dependency_overrides[get_inbound_mcp_db]` — the production dep hits real Postgres.

2. **`examples/lab_bootstrap.py` (new).** Idempotently runs Alembic migrations and seeds the lab tenant (`11111111-...`), operator (`44444444-...`), drawio HTTP server (`22222222-...22`), drawio stdio server (`22222222-...33`), and the two pre-baked virtual servers (`drawio-http`, `drawio-stdio`) with **fixed UUIDs**. Re-running is a no-op. Capability rows are **not** seeded — exercising the real `POST /api/v1/servers/{id}/sync` path is now part of the demo.

3. **Real-world bug fix in `mcp/outbound.py`** — `StreamableHttpMcpClient.list_capabilities` and `StdioMcpClient.list_capabilities` were calling `session.list_tools()` + `list_resources()` + `list_prompts()` unconditionally. Real upstream MCP servers MAY omit any of those (the protocol's per-kind capability flags advertise this). `https://mcp.draw.io/mcp` does not implement `prompts/list`, so the SDK raised `McpError: Method not found` (JSON-RPC `-32601`) and the **whole** sync aborted with HTTP 500 — exactly the symptom that hit the operator console once a freshly-registered drawio HTTP server was synced.
   - **Fix**: factored `_list_or_empty(list_call, kind_label)` that catches `McpError` with code `-32601` and returns `[]`; other errors propagate. Added `_build_capability_descriptors(...)` to dedupe descriptor construction between transports. Both transports now degrade per-kind instead of failing the whole snapshot.
   - **Regression test**: `tests/mcp/test_streamable_http_outbound.py::test_list_capabilities_treats_method_not_found_per_kind_as_empty` builds a tools-only `FastMCP` server (no resources, no prompts) and asserts `list_capabilities` still returns the tool descriptor without raising.

4. **End-to-end verified through HTTP against the running lab** (no shortcuts, full production path, real Postgres):
   - `POST /api/v1/servers` with the lab bearer token registered a brand-new HTTP upstream
   - `POST /api/v1/servers/{id}/sync` returned `capability_count=3` (1 resource + 2 tools), drift correctly attributed
   - `GET /api/v1/servers/{id}/capabilities` returned the persisted snapshot with risk classification populated
   - `POST /api/v1/vservers` with a **single** `{server_id, tool_name: "create_diagram"}` published `drawio-test-vs`
   - Real `mcp.client.streamable_http.streamablehttp_client` against `/v/{tenant}/drawio-test-vs/mcp` returned exactly `['create_diagram']` from `list_tools` — proving the vserver's tool allowlist is enforced and nothing from the upstream leaks through that wasn't selected.
   - `inbound_mcp_session_created` and `inbound_mcp_session_deleted` lines fired around the call.

5. **HANDOFF reorganized** so the most recent session always sits at the top.

6. **Operator console restyled against the Vyuu Design System.** Codex read:
   - <local design folder>
   - <local design folder>
   The `/operator` surface now uses the Vyuu lockup, saffron-orange brand tokens, Fraunces/Inter/JetBrains font stacks, warm paper background, 12px bordered cards, restrained buttons/pills, no gradients/glass effects, and sentence-case UI copy. CSP remains tight (`default-src 'self'`); no Google Fonts or external assets were added. The logo is served same-origin at `GET /operator/logo.svg`. Source remains `src/vyuu_gateway/api/operator_ui.py`.

### Capabilities now demonstrably working end-to-end

- Tenant-scoped operator login (HMAC-signed lab token via `mint_operator_test_token`).
- HTTP upstream registration with SSRF guard + transport allowlist.
- Real network capability sync against a public MCP server (`mcp.draw.io`) through pool + circuit breaker.
- Per-kind capability sync degradation — servers can omit prompts/resources without breaking sync.
- Risk-classified capability persistence (the seeded server already shows `risk_category=credential_access` for `create_diagram`).
- Virtual-server publish that bundles a chosen subset of upstream tools.
- Tenant-scoped MCP Streamable HTTP route serving the published vserver — `tools/list` filtered to the allowlist.

### What's still pending

In rough priority order. None of these are blockers for the current lab demo working — they are the next features to land.

1. **Real OIDC / API-key identity provider** for both the operator API and the inbound MCP API. `FakeOperatorAuthProvider` and `FakeIdentityProvider` already define the Protocol contract — drop-in replacement.

2. **Real Kafka / NATS audit producer + `AsyncGraphEventEmitter`.** Today `_LocalAuditEmitter` records in-process and `NoOpGraphEventEmitter` discards. Telemetry vanishes when the gateway process restarts.

3. **SSE outbound compatibility.** Operator API accepts legacy `sse` registrations, but `DatabaseBackedUpstreamClientProvider` still raises `UnsupportedUpstreamTransportError` for SSE. Streamable HTTP and stdio/npm are fully implemented.

4. **Registration-time MCP probe + periodic capability-sync worker.** `register_mcp_server` writes the row with `health_status='unknown'` and never probes; sync is reachable via `POST /api/v1/servers/{id}/sync` (operator-triggered) but no scheduler runs it on a cadence.

5. **DNS resolution at outbound-client connect time** as the second SSRF backstop. Should ride on the upstream-provider real-pool work.

6. **TLS termination / mTLS on the gateway.** The lab runs HTTP. Production must terminate TLS at the ingress.

7. **Payload size limits + response inspection / redaction** on the inbound MCP route.

### Local-machine state at the end of this sub-session

- Postgres 16 running on `127.0.0.1:5432`. Database `vyuu_gateway` owned by role `vyuu`. Bootstrap data is seeded (lab tenant, operator, drawio HTTP/stdio servers, drawio HTTP/stdio vservers + the test vserver `drawio-test-vs`).
- The lab is running on `127.0.0.1:8765` (PID may have rotated; check `lsof -i :8765`). Operator console: `http://127.0.0.1:8765/operator`. Bearer token printed on startup is the HMAC-signed lab token tied to the seeded operator.
- A test server with display name `drawio-test-2` and ID `1c5c8975-7706-4b99-9fb6-2c17ead2a9db` exists in the DB from the E2E test, with 3 capabilities synced. Plus a vserver `drawio-test-vs` (ID `ace64084-...`) bundling its `create_diagram` tool.
- `.claude/launch.json` was added with `drawio-lab` (port 8765) and `lab-bootstrap` (no port) entries — that's the only addition to `.claude/`.

### How to resume

```bash
# 1. Postgres should already be up; verify:
/opt/homebrew/opt/postgresql@16/bin/pg_isready -h 127.0.0.1

# 2. Re-run bootstrap (no-op if already seeded; required if you wiped the DB):
VYUU_DATABASE_URL="postgresql+psycopg://vyuu@127.0.0.1:5432/vyuu_gateway" \
  python3 examples/lab_bootstrap.py

# 3. Start the lab (kill any prior instance first if 8765 is taken):
VYUU_DATABASE_URL="postgresql+psycopg://vyuu@127.0.0.1:5432/vyuu_gateway" \
  python3 examples/drawio_lab_server.py

# 4. Operator console: http://127.0.0.1:8765/operator
#    Token: printed on startup; copy/paste into the console.
```

---

## Codex Update — 2026-04-29 Late Session

This section supersedes the older status counts and "recommended next" list below. Older sections are retained as implementation history and may contain stale statements about unsupported stdio, lack of Postgres, and old test counts.

### Current validation

```bash
cd <repository root>
pytest        # 406 passed, 19 skipped
ruff check . # All checks passed!
mypy .       # Success: no issues found in 115 source files
```

Full no-skip run requires Redis, Postgres, and the drawio upstream env flag:

```bash
redis-server --port 6390 --save "" --appendonly no --dir /tmp --daemonize yes
/opt/homebrew/opt/postgresql@16/bin/pg_ctl -D /tmp/vyuu_pg_test -l /tmp/vyuu_pg_test.log -o "-p 55432 -k /tmp" start

VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest        # 407 passed

redis-cli -p 6390 shutdown nosave
/opt/homebrew/opt/postgresql@16/bin/pg_ctl -D /tmp/vyuu_pg_test stop
```

`alembic.ini` now includes `path_separator = os`, so the previous Alembic deprecation warning is gone.

### What Codex added after Claude's handoff

1. **Stdio outbound support** in [mcp/outbound.py](src/vyuu_gateway/mcp/outbound.py) and [upstream/provider.py](src/vyuu_gateway/upstream/provider.py).
   - `StdioMcpClient` uses the official MCP SDK `stdio_client`.
   - Stderr is redirected to `/dev/null` so upstream processes cannot leak secrets/customer data into gateway logs.
   - `source_type=stdio` launches an allowlisted executable with args.
   - `source_type=npm` launches through `npx -y <package> ...args`.
   - `StdioLaunchPolicy` validates commands, npm package names, and args before launch.
   - Tests: [tests/mcp/test_stdio_outbound.py](tests/mcp/test_stdio_outbound.py), [tests/upstream/test_provider.py](tests/upstream/test_provider.py).

2. **Upstream connection pool** in [upstream/pool.py](src/vyuu_gateway/upstream/pool.py).
   - Tenant-aware pool key: `(tenant_id, server_id, transport)`.
   - Bounded per upstream with `VYUU_UPSTREAM_MAX_CONNECTIONS_PER_SERVER`.
   - `PooledOutboundMcpClient` wraps transport clients.
   - Operation errors discard and close the leased client before reuse.
   - Provider no longer caches by bare `server_id`; cache is tenant-scoped.
   - App lifespan closes pooled upstream clients.
   - Tests: [tests/upstream/test_pool.py](tests/upstream/test_pool.py).

3. **Upstream health checks** in [upstream/health.py](src/vyuu_gateway/upstream/health.py).
   - `initialize()` probe marks `McpServer.health_status` `healthy` or `down`.
   - New columns: `last_health_checked_at`, `last_health_error`.
   - Only sanitized error type is stored, not raw upstream messages.
   - Operator endpoints:
     - `GET /api/v1/servers/{server_id}/health`
     - `POST /api/v1/servers/{server_id}/health/check`
   - Config: `VYUU_UPSTREAM_HEALTH_TIMEOUT_SECONDS`.
   - Migration: `20260429_0004_mcp_server_health_metadata.py`.
   - Tests: [tests/upstream/test_health_checks.py](tests/upstream/test_health_checks.py), [tests/test_server_health_api.py](tests/test_server_health_api.py).

4. **Circuit breakers** in [upstream/circuit_breaker.py](src/vyuu_gateway/upstream/circuit_breaker.py).
   - Tenant-scoped key: `(tenant_id, server_id, transport)`.
   - States: `closed`, `open`, `half_open`.
   - Open circuit rejects before pool acquisition / upstream process or HTTP client creation.
   - Config:
     - `VYUU_UPSTREAM_CIRCUIT_BREAKER_FAILURE_THRESHOLD`
     - `VYUU_UPSTREAM_CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SECONDS`
   - Lifecycle audits open-circuit failures via the existing upstream-error path.
   - Tests: [tests/upstream/test_circuit_breaker.py](tests/upstream/test_circuit_breaker.py), [tests/tool_calls/test_lifecycle.py](tests/tool_calls/test_lifecycle.py).

5. **Management-plane policy provider** in [policy/management_plane.py](src/vyuu_gateway/policy/management_plane.py).
   - Pull-through cached policy documents from mgmt plane:
     `GET {base_url}/api/v1/tenants/{tenant_id}/policies/{policy_id}`.
   - Cache key is tenant-scoped: `(tenant_id, policy_id)`.
   - TTL defaults to 60 seconds.
   - Evaluation is local in the hot path; tool args/responses are never sent to mgmt plane.
   - Fail-closed on missing policy id, HTTP error, invalid JSON, schema mismatch, or policy-id mismatch.
   - Policy rule IDs now flow into audit events via `PolicyDecision.rule_id`.
   - Config:
     - `VYUU_POLICY_PROVIDER_BACKEND=simple|management_plane`
     - `VYUU_MANAGEMENT_PLANE_POLICY_BASE_URL`
     - `VYUU_MANAGEMENT_PLANE_POLICY_TTL_SECONDS`
     - `VYUU_MANAGEMENT_PLANE_POLICY_BEARER_TOKEN`
   - Tests: [tests/policy/test_management_plane.py](tests/policy/test_management_plane.py).

6. **Postgres local test support**.
   - PostgreSQL 16 is installed via Homebrew.
   - Temp cluster used for tests: `/tmp/vyuu_pg_test`.
   - Test DB: `vyuu_gateway_rls_test`.
   - Redis test port remains `6390`.

7. **Gateway operator console** in [api/operator_ui.py](src/vyuu_gateway/api/operator_ui.py).
   - `GET /operator` serves a no-build FastAPI-hosted operator UI shell.
   - Assets are same-origin only: `GET /operator/app.css`, `GET /operator/app.js`.
   - CSP, `nosniff`, and no-referrer headers are set on the UI responses.
   - The UI stores the pasted bearer token only in browser session storage and calls authenticated operator APIs.
   - Added `GET /api/v1/servers` for tenant-scoped server listing.
   - Tests: [tests/test_operator_ui.py](tests/test_operator_ui.py), updated [tests/test_server_registration.py](tests/test_server_registration.py), [tests/tenant_isolation/test_tenant_isolation.py](tests/tenant_isolation/test_tenant_isolation.py).

### Important caveats / next agent must know

- **Management-plane policy E2E now works through inbound MCP initialize.** `_handle_initialize` loads the tenant-scoped `VirtualServer` and stores `vserver_id` + `policy_id` in `GatewaySession`, so `VYUU_POLICY_PROVIDER_BACKEND=management_plane` can allow/deny real inbound MCP calls when the virtual server has `policy_id` set.
- **Gateway operator UI is implemented, policy UI is not.** `/operator` is a gateway-local console for health, server listing, registration, and health checks. It is not the Vyuu customer management-plane policy UI/dashboard.
- **Connection pool is process-local.** The spec says shared across gateway instances; this implementation is the correct local abstraction but not distributed. Redis-backed distributed pooling is not implemented.
- **Stdio launch is direct process launch.** It is allowlisted and shell-free, but not containerized/gVisor/Firecracker-isolated yet. Do not treat it as shared-tenancy production sandboxing.
- **Registration-time probe and scheduled capability sync still pending.** Server registration persists metadata only. Capabilities and virtual-server rows must be seeded manually or through service code until worker/API work lands.
- **SSE remains legacy and unsupported in the outbound provider.** Keep calling it legacy compatibility, not the primary MCP HTTP transport.

### Recommended next work, in order

1. **Input and response inspection.**
   - Input inspection should run before policy/upstream, still without logging full args by default.
   - Response inspection/redaction should run after upstream response and before final client response/audit sizing.
   - Add explicit policy-controlled opt-in for full payload capture; default remains summarized/redacted only.

2. **Registration-time probe and capability sync worker.**
   - After registration, probe upstream and sync capabilities.
   - Periodic worker with backoff/staggering.
   - Emits drift events to mgmt plane when capability snapshots change.

3. **Operator API/UI gaps.**
   - Virtual server CRUD/list endpoints.
   - Capability snapshot browsing.
   - Audit pipeline status/metrics panels.

4. **Production integrations.**
   - Real OIDC/API-key identity providers.
   - Real Kafka/NATS audit producer and graph event emitter.
   - mTLS/TLS deployment wiring.
   - Containerized stdio/npm execution instead of direct process launch.

### Management-plane policy test setup

The gateway expects a management-plane policy endpoint:

```http
GET /api/v1/tenants/{tenant_id}/policies/{policy_id}
Authorization: Bearer <optional VYUU_MANAGEMENT_PLANE_POLICY_BEARER_TOKEN>
```

Response shape:

```json
{
  "policy_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  "version": "v1",
  "default_decision": "deny",
  "rules": [
    {"id": "allow-echo", "effect": "allow", "tools": ["echo"]},
    {"id": "deny-all", "effect": "deny"}
  ]
}
```

Rule matching is first-match-wins. Supported rule filters:

- `tools`: exposed virtual-server tool names.
- `upstream_tools`: original upstream tool names.
- `upstream_server_ids`: upstream server UUIDs.

Gateway env for provider mode:

```bash
export VYUU_POLICY_PROVIDER_BACKEND=management_plane
export VYUU_MANAGEMENT_PLANE_POLICY_BASE_URL=http://127.0.0.1:9001
export VYUU_MANAGEMENT_PLANE_POLICY_TTL_SECONDS=60
# optional:
export VYUU_MANAGEMENT_PLANE_POLICY_BEARER_TOKEN=dev-mgmt-token
```

For true Cursor/inbound E2E, make sure the target virtual server row has `policy_id` set; initialize will copy that value into the Redis/in-memory `GatewaySession`.

### HTTP and stdio config testing notes

Fastest HTTP smoke test:

```bash
export PYTHONPATH=src
python examples/drawio_lab_server.py
```

This exercises inbound Streamable HTTP → gateway lifecycle → outbound Streamable HTTP to `https://mcp.draw.io/mcp`, with lab-only stdout audit/upstream debug. It bypasses Postgres and management-plane policy.

Use this path when testing Cursor/client MCP routing quickly:

```text
http://127.0.0.1:8765/v/11111111-1111-1111-1111-111111111111/drawio/mcp
```

If you see `/.well-known/oauth-protected-resource... 404` in the logs, that is a harmless client discovery probe. The drawio lab server does not implement OAuth discovery.

Production-shaped local setup:

```bash
redis-server --port 6390 --save "" --appendonly no --dir /tmp --daemonize yes
/opt/homebrew/opt/postgresql@16/bin/pg_ctl -D /tmp/vyuu_pg_test -l /tmp/vyuu_pg_test.log -o "-p 55432 -k /tmp" start

export VYUU_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_dev
export VYUU_REDIS_URL=redis://127.0.0.1:6390/15
export VYUU_OPERATOR_AUTH_SIGNING_SECRET=dev-operator-secret
export PYTHONPATH=src
alembic upgrade head
uvicorn vyuu_gateway.main:create_app --factory --host 127.0.0.1 --port 8765
```

Do not run the full `uvicorn` gateway without setting `VYUU_DATABASE_URL`; otherwise it falls back to `postgresql+psycopg://vyuu:vyuu@localhost:5432/vyuu_gateway` and MCP initialize fails with `psycopg.OperationalError: connection refused` if Postgres is not running on port 5432.

The gateway operator console is available at:

```text
http://127.0.0.1:8765/operator
```

You need seed rows for `tenants` and `operators` before calling the operator API. Mint a dev operator token with:

```bash
python -c 'from uuid import UUID; from vyuu_gateway.operator_auth.fake import mint_operator_test_token; print(mint_operator_test_token(tenant_id=UUID("11111111-1111-1111-1111-111111111111"), operator_id=UUID("44444444-4444-4444-4444-444444444444"), signing_secret="dev-operator-secret"))'
```

HTTP registration payload:

```json
{
  "display_name": "drawio-http",
  "source_type": "http",
  "source_location": "https://mcp.draw.io/mcp",
  "transport": "streamable_http"
}
```

Stdio registration payload using the repo fake stdio server:

```json
{
  "display_name": "fake-stdio",
  "source_type": "stdio",
  "source_location": "python3",
  "transport": "stdio",
  "args": ["tests/mcp/fake_stdio_server.py"]
}
```

NPM/stdIO registration example:

```json
{
  "display_name": "filesystem-npm",
  "source_type": "npm",
  "source_location": "@modelcontextprotocol/server-filesystem",
  "transport": "stdio",
  "args": ["/tmp"]
}
```

Important: registration alone will not make the server callable through a virtual server yet. The gateway still needs capability rows (`mcp_capabilities`) and virtual-server allowlist rows (`virtual_servers`, `virtual_server_tools`). Use existing service code or manual DB seeding until the registration-time probe/sync worker and virtual-server API are implemented.

Full uvicorn mode therefore needs, at minimum:

- `tenants` row for the tenant UUID.
- `operators` row matching the dev operator token.
- `mcp_servers` rows for the upstreams.
- `mcp_capabilities` rows for exposed tools.
- `virtual_servers` row with `policy_id` if using management-plane policy mode.
- `virtual_server_tools` allowlist rows.

## Session Pickup Notes

**Last updated:** 2026-04-29 after Codex operator-UI and local-testing updates. Read the top Codex Update first; older historical sections are retained but may be less complete.

### Quick state check

```bash
cd <repository root>
pytest                                    # expect: 406 passed, 19 skipped
ruff check .                              # expect: All checks passed!
mypy .                                    # expect: Success: no issues found in 115 source files
```

If any of those don't match, *something* moved between sessions — investigate before adding work.

### Known-good lab state (do not break casually)

The lab now exposes **two virtual servers** behind a single process — the user has both wired and verified:

```
Cursor / Claude Desktop
   ├──→ /v/{tenant}/drawio-http/mcp   →  gateway  →  https://mcp.draw.io/mcp        (Streamable HTTP)
   └──→ /v/{tenant}/drawio-stdio/mcp  →  gateway  →  npx -y @drawio/mcp             (stdio per-call)
```

Run `python examples/drawio_lab_server.py` to start it. The script prints **both** Cursor `mcp.json` and Claude Desktop `claude_desktop_config.json` snippets — copy whichever fits. Stdout shows `[upstream:http]` or `[upstream:stdio]` per call so you can see which leg fired, plus `[audit]` and `inbound_mcp_session_*` lines.

Don't refactor `examples/` or `tests/lab/` without verifying both upstreams still work end-to-end. The stdio schemas in the lab were validated against the live `@drawio/mcp` npm package's `tools/list` so the gateway's strict-schema validation accepts what real clients send.

### What this sub-session added (2026-04-30, after Codex's stdio/pool/breaker/health work)

- Validated Codex's drop and confirmed clean: pytest 388 passed / 19 skipped, ruff + mypy clean across 112 source files at the start of this sub-session.
- Probed `@drawio/mcp` (npm) via `npx` to confirm its real tool surface and input schemas — `open_drawio_xml`, `open_drawio_csv`, `open_drawio_mermaid`, all parameterised on `content` (not `xml` / `csv` / `mermaid` as the earlier lab assumed).
- Reworked `examples/drawio_lab_server.py` to expose **two virtual servers** in one process: `drawio-http` (Streamable HTTP, real mcp.draw.io) and `drawio-stdio` (stdio, `npx -y @drawio/mcp`). Tools/schemas pinned to what the live upstreams actually return so strict-schema validation accepts real client payloads.
- Lab override now reads `vserver_name` from `request.path_params` so the per-request fake DB session yields the right vserver for each path, without changing the production `get_inbound_mcp_db` signature.
- The lab now prints **both** Cursor `mcp.json` and Claude Desktop `claude_desktop_config.json` snippets (native HTTP + `mcp-remote` stdio bridge for older Claude Desktop builds), plus the operator console URL (`/operator`) and a ready-to-paste operator bearer token minted from the lab signing secret.
- Smoke-tested both vservers end-to-end via the SDK: `[upstream:http] tools/call name='search_shapes'` returned the drawio shape catalog, `[upstream:stdio] tools/call name='open_drawio_xml'` ran through `npx -y @drawio/mcp` and returned cleanly. Distinct `vserver_id` and `upstream_server_id` recorded per audit event.

#### Closed the operator-flow gap (post-2026-04-30 customer flow)

Until this point, the operator console had a "Register Server" form but no way to discover tools or publish a virtual server through the UI / HTTP API — operators had to write a script. That gap is now closed end-to-end:

- **Capability sync HTTP endpoint** — `POST /api/v1/servers/{server_id}/sync` runs the existing `DatabaseCapabilitySyncService` against the gateway's real upstream provider (so it reuses the production pool / circuit breakers). Returns the drift summary + capability count. `UpstreamProviderCapabilityClient` adapter bridges `UpstreamToolClientProvider` → `McpCapabilityClient`.
- **Capability list HTTP endpoint** — `GET /api/v1/servers/{server_id}/capabilities` returns the active (non-deprecated) snapshot for the operator to pick from. Wire format uses `schema_json` (Python attr is `schema_payload` to side-step a pydantic v2 deprecation warning about shadowing `BaseModel.schema_json`).
- **Virtual server CRUD** — new router `src/vyuu_gateway/api/vservers.py` with `POST /api/v1/vservers`, `GET`, `GET/{id}`, `GET/{id}/tools`, `PATCH/{id}`, `DELETE/{id}`. Same security posture as `POST /api/v1/servers`: `tenant_id` and `created_by` are pulled from the bearer-token-resolved operator context, request body uses `extra="forbid"` so client attempts to inject them return 422. PATCH supports rename, policy_id swap, rename_map update, and full tool-list replace (atomic — bulk DELETE on `virtual_server_tools` then re-INSERT).
- **Capability sync + tools/list/call now async end-to-end.** Converted `McpCapabilityClient.list_capabilities`, `FakeInMemoryMcpClient`, and `DatabaseCapabilitySyncService.sync_server_capabilities` to async because the production sync runs network I/O via `OutboundMcpClient`. Existing capability-sync tests now `asyncio.run(...)` the service.
- **`create_virtual_server` signature change**: now `create_virtual_server(db, *, request, tenant_id, created_by)` with `tenant_id`/`created_by` as keyword-only required args, mirroring `register_mcp_server`. The schema dropped them from the request body. Existing `tests/virtual_servers/test_service.py` updated to the new signature.
- **Operator UI panels**: server cards now have **Sync capabilities** + **Show tools** buttons. New "Capabilities" panel renders synced tools as checkboxes that auto-fill the "Selected tools" textarea on the new "Virtual Servers" panel (which lists, creates, shows tool allowlists, and deletes vservers).
- **18 new endpoint tests** in `tests/api/test_capability_sync_and_vservers.py`: sync endpoint drives discovery through the provider and returns drift; missing servers 404; auth required for all; `schema_json` wire alias preserved in response; tenant filter present in SQL; vserver creation persists with auth-context tenant + creator; body-injected tenant_id rejected as 422; unknown upstream server in tools list → 400; duplicate name → 409; list / get / get-tools / update (rename + tool-replace) / delete all work; all six vserver endpoints reject unauthenticated.

After all of this: pytest 406 passed, 19 skipped; ruff and mypy clean across 115 source files.

#### Lab now uses the production code path end-to-end (2026-04-29 follow-up)

The earlier lab shape registered a fake resolver (`_LabResolverSession`) and a hand-wired `_DispatchingUpstreamProvider` that only knew the two pre-baked drawio entries. As soon as the user registered a *new* server through the operator console and triggered sync, the dispatcher raised `LookupError: no upstream client for (...)` because it had no entry for the freshly-issued `server_id`. That's now fixed: the lab uses real Postgres throughout and reuses the production providers.

- **`examples/lab_bootstrap.py`** (new) — applies Alembic migrations and idempotently seeds the lab tenant, operator, drawio HTTP server, drawio stdio server, and the two pre-baked virtual servers (`drawio-http`, `drawio-stdio`) with **fixed UUIDs** so the printed Cursor / Claude Desktop URLs stay stable across runs. Re-running the script is a no-op. Capability rows are *not* seeded — that exercises the real `POST /api/v1/servers/{id}/sync` path.
- **`examples/drawio_lab_server.py` rewritten** — drops `_DispatchingUpstreamProvider`, `_LabResolverSession`, `_build_vserver`, and the hard-coded capability fixtures. `create_app` is called with the production defaults so it builds `DatabaseBackedUpstreamClientProvider` against `SessionLocal`. The lab then *wraps* `app.state.upstream_clients` with `_LoggingUpstreamProviderWrapper` (caches a `_LoggingUpstreamClient` per `(tenant_id, server_id)`) and rebuilds `app.state.capability_sync_client` against the wrapped provider, so `[upstream:<id>]` lines still surface for both tool calls and capability sync. `_LoggingUpstreamClient` now implements the full `OutboundMcpClient` Protocol (delegates `initialize` / `list_*` / `list_capabilities`) so it slots in as a drop-in. No `dependency_overrides` on `get_inbound_mcp_db` — the production dependency hits real Postgres.
- **Lab prerequisites are real Postgres now.** Running order: `pg_ctl start` → `createdb vyuu_gateway` → `python examples/lab_bootstrap.py` → `python examples/drawio_lab_server.py`. The lab banner mentions the bootstrap step explicitly.
- **Bug fix in `mcp/outbound.py`** — `StreamableHttpMcpClient.list_capabilities` and `StdioMcpClient.list_capabilities` were calling `session.list_tools()` + `list_resources()` + `list_prompts()` unconditionally. Real upstream MCP servers MAY omit any of those methods (the protocol's per-kind capability flags advertise this). `mcp.draw.io/mcp` does not implement `prompts/list`, so the SDK raised `McpError: Method not found` (JSON-RPC `-32601`) and the *whole* sync aborted with HTTP 500. Fix: factored a `_list_or_empty(list_call, kind_label)` helper that catches `McpError` with code `-32601` and returns `[]`, plus a `_build_capability_descriptors` helper to dedupe the descriptor-construction code between the two transports. All other `McpError` codes still propagate.
- **End-to-end verified through HTTP** (with the running lab on `127.0.0.1:8765`): registered a brand-new HTTP server via `POST /api/v1/servers` → `POST /api/v1/servers/{id}/sync` returned `capability_count=3` (1 resource + 2 tools) with the drift split correctly → `GET /api/v1/servers/{id}/capabilities` returned the persisted snapshot → `POST /api/v1/vservers` with `[{server_id, tool_name: "create_diagram"}]` published a vserver → `streamablehttp_client` tools/list against `/v/{tenant}/drawio-test-vs/mcp` returned exactly `['create_diagram']`. `inbound_mcp_session_created` and `inbound_mcp_session_deleted` lines fired. No more 500s on sync.

### What shipped in the last session (2026-04-29)

Listed roughly in build order. All tests, ruff, and mypy were green at each step.

1. **URL registration security** ([registry/url_security.py](src/vyuu_gateway/registry/url_security.py)) — SSRF guard on HTTP source URLs (loopback / RFC1918 / link-local / IPv6 private / metadata hostnames / non-http schemes). Settings: `http_url_allow_private_networks`, `http_url_allowlist`, `http_url_denylist`. Returns 400 at the API.
2. **Tool risk classification** ([capabilities/risk.py](src/vyuu_gateway/capabilities/risk.py)) — heuristic classifier with priority-ordered regex rules; `RiskCategory` enum and a check-constrained column on `mcp_capabilities`. Migration `20260429_0003`.
3. **NHI graph events** ([graph/](src/vyuu_gateway/graph)) — six edge types per spec, builder + protocol + emitter. `correlation_id` ties to the audit `event_id`. Default emitter is no-op; `InMemoryGraphEventEmitter` for tests.
4. **RLS policy patch** — both migrations now use `current_setting('app.current_tenant_id', true)` (missing_ok). Without this the migrations crash any non-RLS-bypassing role.
5. **Operator-API auth** ([operator_auth/](src/vyuu_gateway/operator_auth)) — `Depends(authenticate_operator)` on `POST /api/v1/servers`. `tenant_id` and `registered_by` come from the verified bearer token, not the body. Body's `extra="forbid"` + missing fields return 422 if a client tries to inject them.
6. **RLS GUC binding** — `bind_tenant_context` + `after_begin` listener in [db/session.py](src/vyuu_gateway/db/session.py). Inbound + operator routes use `get_tenant_scoped_db` / `get_inbound_mcp_db` to bind the GUC per request.
7. **Dead `tool_calls/planner.py` deleted.** Tenant-isolation test rewritten to use the lifecycle.
8. **Inbound MCP endpoint** ([api/inbound_mcp.py](src/vyuu_gateway/api/inbound_mcp.py)) — `POST /v/{tenant_id}/{vserver_name}/mcp` + `DELETE`. Hand-written JSON-RPC handler over FastAPI (uses `mcp.types`). `initialize` mints sessions; `tools/list` and `tools/call` route through the lifecycle.
9. **Real upstream provider** ([upstream/provider.py](src/vyuu_gateway/upstream/provider.py)) — `DatabaseBackedUpstreamClientProvider` resolves `(tenant_id, server_id) → pooled outbound MCP clients via `mcp_servers`. `bind_tenant_context` on the lookup session. Streamable HTTP and stdio/npm outbound are supported; SSE remains legacy and unsupported.
10. **E2E interoperability lab** ([tests/lab/test_e2e_interoperability.py](tests/lab/test_e2e_interoperability.py)) — 16 tests covering initialize, tools/list, tools/call (allowed/denied/malformed), upstream timeout/error, audit + graph emission, tenant isolation across sessions.
11. **Drawio walkthrough** — [examples/drawio_lab_server.py](examples/drawio_lab_server.py) (runnable) + [tests/lab/test_drawio_upstream.py](tests/lab/test_drawio_upstream.py) (env-gated `VYUU_TEST_DRAWIO_UPSTREAM=1`). Real network test passes against `https://mcp.draw.io/mcp`.
12. **Lab debug visibility** — `_StdoutAuditEmitter` prints each audit event as JSON; `_LoggingUpstreamClient` captures raw args + response at the gateway's outbound boundary (lab-only — production stays metadata-only per AGENTS.md).
13. **`JsonFormatter` preserves `extra={...}` fields** ([logging_config.py](src/vyuu_gateway/logging_config.py)) — fixes the architecture-review finding that `logger.warning(..., extra={...})` was silently dropping structured context. Reserved fields (`level`, `logger`, etc.) can't be shadowed.
14. **Session lifecycle logs** in [api/inbound_mcp.py](src/vyuu_gateway/api/inbound_mcp.py) — `inbound_mcp_session_created`, `inbound_mcp_session_rejected`, `inbound_mcp_session_deleted`, all with structured tenant / session / principal context. The "Session has been terminated" issue the user hit on Cursor is now visible in stdout.
15. **Redis-backed session registry** ([sessions/redis_registry.py](src/vyuu_gateway/sessions/redis_registry.py)) — async-converted `SessionRegistry` Protocol. `RedisSessionRegistry` with JSON serialization, Redis `EX` TTL, corrupt-payload safety. Verified end-to-end against real Redis: cross-instance read-after-write proven by [tests/sessions/test_redis_registry.py](tests/sessions/test_redis_registry.py). `Settings.redis_url` switches the production wiring; in-memory remains the default for dev / lab / unit tests.

### Recommended next, prioritized

The following items are *features* (not bugs). They all have rationale + sketch in HANDOFF below. This ordering reflects what unblocks more downstream work.

1. **Real OIDC / API-key identity provider** for both the operator API and the inbound MCP API. Replaces `FakeOperatorAuthProvider` + `FakeIdentityProvider`. Same Protocol contract — drop-in. This is the biggest remaining "fake pretending to be production" gap.
2. **Real Kafka / NATS audit producer + `AsyncGraphEventEmitter`.** Today `_LocalAuditEmitter` records in-process and `NoOpGraphEventEmitter` discards. Until durable emission lands, telemetry vanishes when the gateway process restarts.
3. **SSE outbound compatibility.** The operator API accepts legacy `sse` registrations, but `DatabaseBackedUpstreamClientProvider` still raises `UnsupportedUpstreamTransportError` for SSE. Streamable HTTP and stdio/npm are implemented.
4. **Registration-time MCP probe + periodic capability sync worker.** `register_mcp_server` writes the row with `health_status='unknown'` and never probes; `DatabaseCapabilitySyncService.sync_server_capabilities` is now reachable via `POST /api/v1/servers/{id}/sync` (operator-triggered) but no scheduler runs it on a cadence.
5. **DNS resolution at outbound-client connect time** as the second SSRF backstop (see Deferred Follow-ups). Should ride on the upstream-provider real-pool work.
6. **TLS termination / mTLS on the gateway.** Today `examples/drawio_lab_server.py` runs HTTP. Production must terminate TLS at ingress; mTLS gateway-side is on the deferred list.
7. **Payload size limits + response inspection / redaction.** Neither is enforced.

### Things to NOT redo

- Don't reintroduce `tool_calls/planner.py` — deleted intentionally; the lifecycle is the single tool-call entry point. There's a docstring pin in [tool_calls/__init__.py](src/vyuu_gateway/tool_calls/__init__.py).
- Don't add `tenant_id` / `registered_by` back to `ServerRegistrationRequest` — they come from the bearer token now. Tests verify the body-injection path returns 422.
- Don't widen the audit event to capture raw args / responses by default — that contract is in [AGENTS.md](AGENTS.md) and spec §3.3. The opt-in path with redaction is a future feature, not a default.
- Don't set Redis as a hard runtime requirement. `redis_url` is optional; in-memory remains the default so the lab and dev workflows stay zero-dependency.

### Local-machine state to know about

- The user installed Redis via `brew install redis` during the last session for verification. It was started on port 6390 and shut down at the end. If the user wants to re-run Redis tests: `brew services start redis` (default port 6379) and `export VYUU_TEST_REDIS_URL=redis://127.0.0.1:6379/15`.
- PostgreSQL 16 is installed via Homebrew. The temp test cluster path is `/tmp/vyuu_pg_test`; start it on port 55432 with `/opt/homebrew/opt/postgresql@16/bin/pg_ctl -D /tmp/vyuu_pg_test -l /tmp/vyuu_pg_test.log -o "-p 55432 -k /tmp" start`.
- No git repository. Changes are tracked only by file timestamps.

## Repository Context

- Repo root: `<repository root>`
- Project: Vyuu MCP Gateway, a server-side MCP enforcement, routing, virtual-server, audit, and observability gateway.
- Required project guidance is in `AGENTS.md`.
- `AGENTS.md` now points to `docs/architecture/vyuu-gateway-spec.md`, which is the architecture spec present in this repo.
- Required checks before handoff/completion: `pytest`, `ruff check .`, `mypy .`.

Latest validation before this handoff:

```bash
pytest        # 406 passed, 19 skipped
ruff check . # passed
mypy .       # passed (115 source files)
```

With Redis/Postgres/drawio env vars set, the full no-skip count is `407 passed`:

```bash
VYUU_TEST_REDIS_URL=redis://127.0.0.1:6390/15 \
VYUU_TEST_DATABASE_URL=postgresql+psycopg://krishna@127.0.0.1:55432/vyuu_gateway_rls_test \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest
```

## Core Principles To Preserve

- Gateway is a data plane, not the Vyuu management plane.
- Gateway gates MCP tool calls, not LLM inference.
- Tenant isolation is mandatory: tenant-scoped models include `tenant_id`, and tenant-scoped queries filter by `tenant_id`.
- MCP servers are untrusted.
- Least privilege by default.
- Never log secrets, bearer/OAuth/API tokens, full tool args, full tool responses, or customer business data by default.
- Use official MCP SDK where practical.
- Streamable HTTP is the primary current HTTP MCP transport. SSE is legacy compatibility only.

## Implemented So Far

### Project Skeleton

- FastAPI app entrypoint in `src/vyuu_gateway/main.py`.
- Health endpoint in `src/vyuu_gateway/api/health.py`.
- Settings/config in `src/vyuu_gateway/config.py`.
- Structured JSON logging in `src/vyuu_gateway/logging_config.py`.
- Dockerfile for local dev.
- Pytest, ruff, and mypy configuration in `pyproject.toml`.

### Registry Data Model

- SQLAlchemy models in `src/vyuu_gateway/db/models.py`:
  - `Tenant`
  - `Operator`
  - `McpServer`
  - `McpCapability`
  - `VirtualServer`
  - `VirtualServerTool`
- Base/session modules in `src/vyuu_gateway/db/base.py` and `src/vyuu_gateway/db/session.py`.
- Alembic migrations:
  - `migrations/versions/20260429_0001_registry_tables.py`
  - `migrations/versions/20260429_0002_virtual_server_tables.py`
  - `migrations/versions/20260429_0003_capability_risk_category.py`
- Important: `McpCapability` includes `tenant_id` even though the spec example did not, because tenant isolation requires it.
- `McpCapability` also has a `risk_category` column (`RiskCategory` enum) populated by the heuristic classifier at sync time. See "Tool Risk Classification" below.

### Operator API Authentication

- Module: `src/vyuu_gateway/operator_auth/` (separate from `identity/`, which models MCP tool-call principals — different threat model and replacement timeline).
- `models.py`: `AuthenticatedOperator` (frozen dataclass: `tenant_id`, `operator_id`, `display`).
- `provider.py`: `OperatorAuthProvider` Protocol + `OperatorAuthError`.
- `fake.py`: `FakeOperatorAuthProvider` — HMAC-SHA256 signed bearer tokens for tests/dev. Constant-time signature compare. Not production-grade (no expiry, no rotation, no audience binding, hardcoded secret); replaceable via the Protocol.
- `dependency.py`: `authenticate_operator` FastAPI dependency using `HTTPBearer(auto_error=False)`. Missing token, malformed token, and verification failure all return HTTP 401 with `WWW-Authenticate: Bearer`. Detail strings are deliberately uniform — they do not leak which keys exist or why validation failed.
- Wired through `app.state.operator_auth` in `main.py`. `create_app(settings, *, operator_auth=None)` accepts an injected provider for tests.
- `Settings.operator_auth_signing_secret` — default `"dev-operator-auth-secret"`; MUST be overridden in production.

### RLS Tenant Context Binding

- The migrations enable RLS on every tenant-scoped table with policies that read `current_setting('app.current_tenant_id', true)::uuid`. The `, true` form (missing_ok) makes the GUC degrade to NULL when unset, which excludes rows under RLS rather than raising.
- `src/vyuu_gateway/db/session.py` registers a class-level `after_begin` listener on `Session`. On every transaction begin, it runs `SELECT set_config('app.current_tenant_id', :tenant_id, true)` if `session.info["tenant_id"]` is set.
- `bind_tenant_context(session, tenant_id)` writes that key.
- `src/vyuu_gateway/api/dependencies.py` provides `get_tenant_scoped_db` — a FastAPI dependency that depends on `authenticate_operator`, opens a `SessionLocal` session, calls `bind_tenant_context`, and yields. Every transaction the session opens reissues `set_config` (per-transaction, not per-session, so `is_local=true` clears at commit and we rebind for the next).
- Sessions that have not been tenant-bound (Alembic, admin scripts) leave the GUC unset; under a non-RLS-bypassing role this fails closed (queries see zero rows). Admin contexts must connect as a role with BYPASSRLS or that owns the tables.
- API endpoints MUST use `get_tenant_scoped_db`, not the unbound `get_db`. The latter exists only for migrations / admin scripts.

### Inbound MCP Streamable HTTP Endpoint

- Module: `src/vyuu_gateway/api/inbound_mcp.py`
- Routes: `POST /v/{tenant_id}/{vserver_name}/mcp` and `DELETE /v/{tenant_id}/{vserver_name}/mcp`.
- v1 supports JSON responses only (not SSE). MCP clients accept both per spec; SSE is deferred until a streaming-tool use case forces it.
- Methods handled: `initialize`, `notifications/initialized` (returns 202 with no body), `tools/list`, `tools/call`. Anything else → JSON-RPC `MethodNotFound (-32601)`.
- Authentication: every `initialize` re-validates the bearer token through the configured `IdentityProvider`. The lifecycle re-validates again per `tools/call`. Failure → JSON-RPC `InvalidRequest (-32600)` with HTTP 401 + `WWW-Authenticate: Bearer`.
- Session id is minted on `initialize` and returned via the `mcp-session-id` response header. Subsequent requests must include it as a request header.
- Error mapping policy:
  - Protocol-level (parse error, missing/expired session, unsupported method, malformed JSON-RPC body) → JSON-RPC error responses.
  - Tool-call decisions (`DENIED`, `MALFORMED_ARGS`, `TOOL_NOT_IN_VIRTUAL_SERVER`, `IDENTITY_INVALID`, `POLICY_ENGINE_ERROR`, `UPSTREAM_TIMEOUT`, `UPSTREAM_ERROR`, `AUDIT_UNAVAILABLE`) → MCP-compliant `CallToolResult` with `isError=true` and a textual reason.
- The route takes a tenant-bound DB session via `get_inbound_mcp_db(tenant_id)` (path-param-driven counterpart to `get_tenant_scoped_db`). All DB queries inside the request go through this session, so RLS applies.
- URL uses tenant UUID (not slug). Slugs (`/v/acme-bank/...`) require a `tenants.slug` column / migration; that's deferred (flagged below).

### Session Registry

- Modules: `src/vyuu_gateway/sessions/registry.py` (Protocol + in-memory impl + `GatewaySession`) and `src/vyuu_gateway/sessions/redis_registry.py` (Redis-backed impl).
- `GatewaySession` (frozen dataclass) carries `session_id`, `tenant_id`, `vserver_name`, `vserver_id`, `principal`, `client_metadata`, `policy_id`, and `expires_at`. `is_expired()` lets callers do their own expiry check.
- `SessionRegistry` Protocol: `async create_session`, `async get_session`, `async delete_session`. Async because the production Redis impl does network I/O; sync calls inside an async request handler would block the event loop. The in-memory impl matches the same async signature so call sites are uniform.
- `get_session(tenant_id, session_id)` returns `None` for missing or expired sessions; both impls evict expired entries lazily on lookup (Redis additionally lets the server TTL-expire keys; the registry rechecks `is_expired()` for clock-skew safety).
- Both impls key on `(tenant_id, session_id)` so a session id minted under tenant A is *not* reachable under tenant B even if the caller knows the id — verified end-to-end by the cross-tenant tests in both `tests/sessions/test_registry.py` and `tests/sessions/test_redis_registry.py`.
- `default_expiry(ttl_seconds=...)` computes `now + ttl`. Wired through `Settings.session_ttl_seconds` (default 3600).

#### Choosing the impl in production

`create_app` selects automatically from `Settings.redis_url`:

- `VYUU_REDIS_URL` unset → `InMemorySessionRegistry` (single-process; suitable for dev and the lab demo).
- `VYUU_REDIS_URL=redis://host:port/db` → `RedisSessionRegistry`. Sessions persist across gateway-process restarts and are visible to every gateway pod sharing the same Redis instance — required for any multi-replica / HA deployment.

The cross-instance property is verified by `test_session_created_by_instance_a_is_visible_to_instance_b` in `tests/sessions/test_redis_registry.py`, which builds two `RedisSessionRegistry` objects with separate clients pointed at the same Redis URL and proves a write through registry A is observable through registry B.

Storage shape: keys `{prefix}:{tenant_id}:{session_id}`, values JSON-serialized `GatewaySession`, TTL set via Redis `EX` to `expires_at - now`. Prefix configurable via `Settings.session_redis_key_prefix` (default `vyuu:session`).

### Real Upstream Streamable HTTP Client Provider

- Module: `src/vyuu_gateway/upstream/provider.py`
- `DatabaseBackedUpstreamClientProvider` resolves `(tenant_id, server_id) → StreamableHttpMcpClient` via the `mcp_servers` table.
- The lookup opens its own DB session (separate from the inbound request's session), `bind_tenant_context`s it to the calling tenant, and runs an explicit `tenant_id == ...` filter — defense in depth: RLS plus query filter.
- Supported outbound transports: `streamable_http` and `stdio`/`npm` via the official MCP SDK. Legacy `sse` upstreams still raise `UnsupportedUpstreamTransportError`; the lifecycle catches it via the generic upstream-exception path and audits the failure.
- Unknown server (no row for the pair) raises `UpstreamServerNotFoundError`, also surfacing as upstream error in the lifecycle.
- Per-`server_id` client cache, process-local, unbounded. Real connection pooling, health checks, and circuit breakers are deferred (see "Likely Next Work" — the cache is intentionally minimal so rotating an upstream just needs a process restart).

### Operator Server Registration API

- API router: `src/vyuu_gateway/api/servers.py`
- Schemas: `src/vyuu_gateway/registry/schemas.py`
- Service: `src/vyuu_gateway/registry/service.py`
- Authentication: `Depends(authenticate_operator)`. Tenant and operator come from the bearer token, never from the request body. `ServerRegistrationRequest` has `extra="forbid"` and no `tenant_id`/`registered_by` fields, so a body that includes them returns 422.
- Service signature: `register_mcp_server(db, *, request, tenant_id, registered_by)`. Both context fields are keyword-only without defaults; callers cannot forget them. The service still re-checks operator-in-tenant against the operators table as defense-in-depth — if a bearer token's claim and the operators table disagree, the row is not persisted (returns 401, not 404, because in this model the bearer token itself is the failed party).
- URL security guardrails: `src/vyuu_gateway/registry/url_security.py`
  - Blocks loopback, RFC1918, IPv4 link-local (incl. `169.254.169.254`), IPv6 loopback / link-local / unique-local, IPv4-mapped IPv6 variants, well-known cloud-metadata hostnames, and any non-`http(s)` scheme.
  - Three operator-tunable settings: `VYUU_HTTP_URL_ALLOW_PRIVATE_NETWORKS`, `VYUU_HTTP_URL_ALLOWLIST`, `VYUU_HTTP_URL_DENYLIST` (fnmatch globs).
  - Failures map to `HTTP 400` at `POST /api/v1/servers`.
- Supports request shape and persistence for source types:
  - `http`
  - `npm`
  - `stdio`
- No runtime MCP probing implemented for registration yet.
- Current API has `POST /api/v1/servers`, tenant-scoped `GET /api/v1/servers`, and health endpoints `GET /api/v1/servers/{server_id}/health` / `POST /api/v1/servers/{server_id}/health/check`.

### Capability Sync

- Client abstraction and descriptors:
  - `src/vyuu_gateway/capabilities/client.py`
- Fake in-memory MCP client:
  - `src/vyuu_gateway/capabilities/fake_client.py`
- Drift detection:
  - `src/vyuu_gateway/capabilities/drift.py`
- DB-backed sync service:
  - `src/vyuu_gateway/capabilities/sync.py`
- Sync behavior:
  - Fetches capabilities through a client abstraction.
  - Marks previous active capabilities deprecated.
  - Persists a new snapshot.
  - Detects added, removed, and changed capabilities.
  - Classifies each tool capability with `RiskCategory` and stores it on the row.
- Real periodic workers are not implemented yet.

### Tool Risk Classification

- Classifier: `src/vyuu_gateway/capabilities/risk.py`
- Enum `RiskCategory` in `db/models.py`: `read`, `write`, `delete`, `execute`, `network`, `credential_access`, `data_export`, `admin`, `unknown`.
- Heuristic, name + description + JSON-schema-property based, with priority-ordered regex rules (credential_access > admin > delete > execute > data_export > network > write > read).
- Server `display_name` is a fallback signal only when the primary haystack is silent.
- CamelCase tool names are split on lower→upper boundaries before matching.
- Resources and prompts always classify as `unknown` — the category is meaningful only for tools.
- Stored on `mcp_capabilities.risk_category` (migration `20260429_0003`), check-constrained.

### Streamable HTTP Outbound MCP Client

- Implementation: `src/vyuu_gateway/mcp/outbound.py`
- Uses official MCP Python SDK.
- Supports:
  - `initialize`
  - `tools/list`
  - `resources/list`
  - `prompts/list`
  - `tools/call`
  - combined `list_capabilities`
- Tests use `FastMCP` ASGI apps and `httpx.ASGITransport`.

### Virtual Servers

- Schemas: `src/vyuu_gateway/virtual_servers/schemas.py`
- Service: `src/vyuu_gateway/virtual_servers/service.py`
- Resolver: `src/vyuu_gateway/virtual_servers/resolver.py`
- Supports:
  - Creating a virtual server.
  - Adding allowlisted tools.
  - Rename map.
  - Collision handling by prefixing with upstream server display name and unique suffix if needed.
  - Synthesized `tools/list` MCP response.
- Inbound MCP virtual-server endpoint is implemented at `POST /v/{tenant_id}/{vserver_name}/mcp`; initialize resolves the tenant-scoped `VirtualServer` and stores `vserver_id` + `policy_id` on the session. Virtual-server CRUD now ships at `POST /api/v1/vservers`, `GET`, `GET/{id}`, `GET/{id}/tools`, `PATCH/{id}`, `DELETE/{id}` and is wired into the operator console panels.

### Policy Enforcement

- Interface: `src/vyuu_gateway/policy/interfaces.py`
- Simple provider: `src/vyuu_gateway/policy/simple.py`
- Current deny reasons include:
  - `audit_unavailable`
  - `identity_invalid`
  - `malformed_args`
  - `policy_engine_error`
  - `tool_denied`
  - `tool_not_in_virtual_server`
- `SimplePolicyProvider` supports:
  - allow all by default
  - explicit allowed tool set
  - explicit denied tool set
  - JSON Schema validation for backward compatibility
- Full lifecycle now performs schema validation before policy evaluation, so future policy providers can assume schema-valid args.

### Audit Events And Emission

- Event schema and args summarization:
  - `src/vyuu_gateway/audit/events.py`
- Producer protocol and test producer:
  - `src/vyuu_gateway/audit/producer.py`
- Async non-blocking emitter:
  - `src/vyuu_gateway/audit/emitter.py`
- Disk spool and spooling producer:
  - `src/vyuu_gateway/audit/spool.py`
- Audit failure modes:
  - `src/vyuu_gateway/audit/failure.py`
- Audit payload intentionally stores argument summaries only, not full argument values.
- `DiskSpool` supports max-size rejection via `AuditSpoolFullError`.
- `DiskSpool.replay_to(...)` replays spooled events to a producer and clears successfully replayed events.

### NHI Graph Events

- Module: `src/vyuu_gateway/graph/`
- `events.py`: `GraphEvent`, `GraphEdge`, `GraphNode`, plus `GraphEdgeType` (six edges: `principal_used_client`, `client_connected_vserver`, `vserver_exposed_tool`, `tool_routed_to_server`, `server_accessed_resource`, `principal_called_tool`) and `GraphNodeType`.
- `producer.py`: `GraphEventProducer` Protocol + `TestGraphEventProducer`.
- `emitter.py`: `GraphEventEmitter` Protocol + `NoOpGraphEventEmitter` (default) + `InMemoryGraphEventEmitter` (tests).
- `build.py`: pure `build_tool_call_graph_event(...)` taking primitives so the graph module is decoupled from `tool_calls/`.
- Wired into `ToolCallLifecycle` via the optional `graph_event_emitter` constructor arg. Each `handle_tool_call` allocates one `correlation_id = uuid4()` shared between the audit event (`event_id`) and the graph event (`correlation_id`) for downstream join.
- Emission policy:
  - `session_not_found` / `identity_invalid` → no graph event (no validated principal).
  - `tool_not_in_virtual_server` → only the principal/client/vserver chain.
  - All other paths → full chain. `server_accessed_resource` is included only when the upstream call was attempted (`OK` / `ERROR` / `TIMEOUT`).
- No graph DB. No Kafka producer.

Audit failure behavior:

- `strict`: tool calls are blocked if audit cannot be durably queued.
- `continuity`: calls continue but emit a critical degraded-state log.
- `monitor`: best-effort audit; calls continue.

Durability note:

- `EmitResult.durable=True` means the event was durably queued, currently via disk spool.
- In-memory async queue acceptance is `accepted=True` but not durable.
- `DiskSpoolAuditEmitter` is available for durable local enqueueing.

### Identity Validation

- Models: `src/vyuu_gateway/identity/models.py`
- Provider interface: `src/vyuu_gateway/identity/provider.py`
- Fake test provider: `src/vyuu_gateway/identity/fake.py`
- Principal model types:
  - `EndpointSessionPrincipal`
  - `ServerAgentPrincipal`
  - `ApiKeyPrincipal`
- Fake provider supports:
  - signed test tokens: `Authorization: Bearer <token>`
  - mock headers:
    - `x-vyuu-tenant-id`
    - `x-vyuu-principal-type`
    - `x-vyuu-principal-id`
    - `x-vyuu-principal-display`
- Real OIDC is explicitly not implemented.

### Tool-Call Lifecycle

- Main orchestration: `src/vyuu_gateway/tool_calls/lifecycle.py`
- Full lifecycle path:
  1. Client request object enters `ToolCallLifecycle.handle_tool_call(...)`.
  2. Tenant-scoped session lookup.
  3. Identity validation. Every tool call must resolve a principal before virtual-server resolution and policy evaluation.
  4. Virtual server tool resolution.
  5. Schema validation against resolved MCP tool input schema.
  6. Policy decision.
  7. Strict audit preflight check before upstream call when configured.
  8. Upstream MCP `tools/call`.
  9. Response/error handling.
  10. Audit event emission.

Lifecycle statuses include:

- `allowed`
- `denied`
- `identity_invalid`
- `malformed_args`
- `policy_engine_error`
- `session_not_found`
- `tool_not_in_virtual_server`
- `upstream_error`
- `upstream_timeout`
- `audit_unavailable`

Audit is emitted for:

- allowed calls
- denied calls
- malformed args
- upstream timeout
- upstream error
- policy engine error
- invalid identity
- missing session

Expected behavior:

- Invalid/missing identity is denied before policy evaluation and before upstream calls.
- Malformed args are denied before policy evaluation and before upstream calls.
- Policy engine exceptions are converted into deny outcomes and audited.
- Upstream exceptions and `TimeoutError` are converted into lifecycle results and audited.
- In strict audit mode, audit unavailability blocks allowed upstream calls before upstream execution.

## Test Coverage

Current test areas:

- `tests/test_health.py`
- `tests/test_config.py`
- `tests/test_logging_config.py`
- `tests/test_server_registration.py`
- `tests/db/test_models.py`
- `tests/db/test_migrations.py`
- `tests/capabilities/test_sync.py`
- `tests/capabilities/test_drift.py`
- `tests/capabilities/test_fake_client.py`
- `tests/mcp/test_streamable_http_outbound.py`
- `tests/mcp/test_streamable_http_protocol_compliance.py`
- `tests/virtual_servers/test_service.py`
- `tests/virtual_servers/test_resolver.py`
- `tests/policy/test_simple_policy.py`
- `tests/audit/test_events.py`
- `tests/audit/test_emitter.py`
- `tests/audit/test_failure_behavior.py`
- `tests/tool_calls/test_lifecycle.py`
- `tests/identity/test_fake_identity_provider.py`
- `tests/tenant_isolation/test_tenant_isolation.py`
- `tests/operator_auth/test_fake_provider.py`
- `tests/db/test_tenant_context.py`
- `tests/integration/test_rls_real_postgres.py` (env-gated; skipped without `VYUU_TEST_DATABASE_URL`)
- `tests/registry/test_url_security.py`
- `tests/capabilities/test_risk.py`
- `tests/graph/test_build.py`
- `tests/graph/test_lifecycle_graph_emission.py`
- `tests/sessions/test_registry.py`
- `tests/sessions/test_redis_registry.py` (env-gated; skipped without `VYUU_TEST_REDIS_URL`; verifies cross-instance read-after-write)
- `tests/upstream/test_provider.py`
- `tests/api/test_inbound_mcp.py` (drives the real `StreamableHttpMcpClient` SDK against the gateway in-process via ASGI transport)
- `tests/lab/test_e2e_interoperability.py` (end-to-end interop lab — see "E2E Interoperability Lab" below)

Tenant isolation suite verifies:

- Tenant A cannot list tenant B servers; `GET /api/v1/servers` and `list_mcp_servers` are tenant-filtered and authenticated.
- Tenant A cannot access tenant B virtual servers.
- Tenant A cannot see tenant B capabilities.
- Tenant A cannot call tools from tenant B virtual server.
- All tenant-scoped DB tables require non-null `tenant_id`.
- Current repository/service methods require tenant context.

MCP protocol compliance suite verifies:

- Streamable HTTP `initialize`
- `tools/list`
- `tools/call`
- invalid method JSON-RPC error
- unsupported protocol version rejection by the client
- missing session rejection
- terminated/expired session rejection
- reconnect with fresh sessions

Reconnect/resume note:

- True resume behavior is not implemented. Current test verifies fresh-session reconnect behavior.

RLS integration suite (env-gated by `VYUU_TEST_DATABASE_URL`) verifies, against real Postgres:

- Migrations enable RLS on every tenant-scoped table.
- `bind_tenant_context` actually issues `set_config` against a real session (read-back via `current_setting`).
- An unbound session leaves the GUC unset.
- Under a `NOBYPASSRLS` role with the GUC bound to tenant A, an *unfiltered* `SELECT FROM mcp_servers` only returns tenant A's rows — the regression test for "a repository forgets the `WHERE tenant_id =` clause".
- Under the same role with no GUC set, queries return zero rows (fail closed).
- Under the same role with the GUC bound to tenant B, querying tenant A's row by primary key returns nothing.
- The full `SessionLocal + bind_tenant_context` path is exercised end-to-end (not just hand-crafted SQL), proving the production code path is RLS-enforced.

The integration suite skips automatically when `VYUU_TEST_DATABASE_URL` is unset, so CI without a Postgres dependency stays green. To run it locally, point the env var at a Postgres instance the test process can reach as the database owner / superuser, then run `pytest tests/integration/`.

## E2E Interoperability Lab

The "lab" is the gateway's flagship integration suite at `tests/lab/test_e2e_interoperability.py`. It stands up the **real gateway**, a **real FastMCP-backed fake upstream**, and the **real MCP SDK client** in one process, wired via ASGI transports. There are no mocks of the lifecycle, the resolver, the upstream provider, or the MCP transport — the audit and NHI graph events asserted at the end come out of the production code paths.

### How to run

```bash
pytest tests/lab/test_e2e_interoperability.py -v
```

The lab is part of the default `pytest` run (it runs in well under a second), so any green CI proves it passes.

### What the lab proves

- `initialize` mints a session and returns server info via the real SDK.
- `tools/list` returns the synthesized virtual-server tools.
- `tools/call` round-trips through the lifecycle, the upstream provider, and the FastMCP fake upstream.
- Allowed, denied, malformed-args, upstream-`isError=true`, upstream-`TimeoutError`, and upstream-generic-`Exception` paths each return an MCP-compliant `CallToolResult` and do *not* crash the gateway.
- Every tool call emits exactly one audit event with the right tenant / principal / decision and exactly one NHI graph event whose `correlation_id` matches the audit `event_id`.
- Allowed calls produce the full six-edge NHI graph chain; policy-denied calls drop only the `server_accessed_resource` edge (the upstream was never reached).
- A session minted in tenant A cannot be used to call tools under tenant B's URL.
- Audit and graph events for tenant A and tenant B are correctly separated when both tenants share the same gateway instance.

### Deliberate constraints (do not "fix" without changing scope)

- **Single gateway instance.** The lab uses `InMemorySessionRegistry` because it doesn't need cross-pod sharing. The `RedisSessionRegistry` exists and is verified by `tests/sessions/test_redis_registry.py`; production multi-instance deployments switch to it via `Settings.redis_url`.
- **No real Postgres.** DB queries go through a fake resolver session that yields the resolved virtual-server / capability rows directly. The RLS / GUC layer is verified separately by the env-gated `tests/integration/test_rls_real_postgres.py`. Splitting these is intentional: the lab proves end-to-end *protocol* correctness fast, the integration suite proves *RLS* correctness against real Postgres.
- **HTTP only** (over ASGI transport — there is no socket). The gateway has no TLS code. **Production must terminate TLS at the ingress / load balancer**; mTLS gateway-side is on the deferred list.
- **Forced-failure stub clients.** The `UPSTREAM_TIMEOUT` and `UPSTREAM_ERROR` paths are exercised by `_ForcedTimeoutClient` / `_ForcedErrorClient` — stubs that raise the appropriate Python exception when `call_tool` is invoked. This is deliberate: the gateway's contract is "handle whatever the upstream client raises"; reproducing real SDK timeout behaviour over ASGI transport is fragile and would test the SDK rather than the gateway. The `boom` upstream tool exercises a separate path (a tool that raises *inside* FastMCP, which surfaces as a successful HTTP response with `isError=true`).

### Driving real MCP clients through the gateway against drawio (HTTP + stdio)

The lab now exposes **two virtual servers** behind one gateway process — one routing to the real Streamable HTTP drawio upstream, one routing to the npm-published stdio drawio upstream. Both are reachable simultaneously; clients pick a virtual server by URL path.

```bash
pip install -e .[dev]
python examples/drawio_lab_server.py
```

Endpoints (printed by the script — IDs are stable across runs):

| Virtual server | Upstream | Tools | URL |
|---|---|---|---|
| `drawio-http`  | `https://mcp.draw.io/mcp` (Streamable HTTP) | `create_diagram`, `search_shapes` | `http://127.0.0.1:8765/v/{tenant}/drawio-http/mcp` |
| `drawio-stdio` | `npx -y @drawio/mcp` (stdio launched per-call) | `open_drawio_xml`, `open_drawio_csv`, `open_drawio_mermaid` | `http://127.0.0.1:8765/v/{tenant}/drawio-stdio/mcp` |

Both upstreams are real — the gateway dispatches by `vserver_name` from the URL, looks up the matching upstream client, and invokes it through `ToolCallLifecycle`. Stdout shows `[upstream:http]` or `[upstream:stdio]` per call so you can see which leg fired.

Tool-input schemas in the lab match what the upstream's own `tools/list` returns (verified against the live npm package), so the gateway's strict-schema validation accepts what real clients send.

#### Cursor config (paste into `~/.cursor/mcp.json` or workspace `.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "drawio-http-via-vyuu": {
      "url": "http://127.0.0.1:8765/v/11111111-1111-1111-1111-111111111111/drawio-http/mcp",
      "type": "streamable-http",
      "headers": {
        "x-vyuu-tenant-id": "11111111-1111-1111-1111-111111111111",
        "x-vyuu-principal-type": "endpoint_session",
        "x-vyuu-principal-id": "cursor-http",
        "x-vyuu-principal-display": "cursor-http (local lab)"
      }
    },
    "drawio-stdio-via-vyuu": {
      "url": "http://127.0.0.1:8765/v/11111111-1111-1111-1111-111111111111/drawio-stdio/mcp",
      "type": "streamable-http",
      "headers": {
        "x-vyuu-tenant-id": "11111111-1111-1111-1111-111111111111",
        "x-vyuu-principal-type": "endpoint_session",
        "x-vyuu-principal-id": "cursor-stdio",
        "x-vyuu-principal-display": "cursor-stdio (local lab)"
      }
    }
  }
}
```

#### Claude Desktop config (paste into `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS)

Two forms — pick whichever matches your Claude Desktop build:

**Native HTTP MCP** (recent builds):

```json
{
  "mcpServers": {
    "drawio-http-via-vyuu": {
      "url": "http://127.0.0.1:8765/v/11111111-1111-1111-1111-111111111111/drawio-http/mcp",
      "type": "streamable-http",
      "headers": {
        "x-vyuu-tenant-id": "11111111-1111-1111-1111-111111111111",
        "x-vyuu-principal-type": "endpoint_session",
        "x-vyuu-principal-id": "claude-http",
        "x-vyuu-principal-display": "claude-http (local lab)"
      }
    },
    "drawio-stdio-via-vyuu": {
      "url": "http://127.0.0.1:8765/v/11111111-1111-1111-1111-111111111111/drawio-stdio/mcp",
      "type": "streamable-http",
      "headers": {
        "x-vyuu-tenant-id": "11111111-1111-1111-1111-111111111111",
        "x-vyuu-principal-type": "endpoint_session",
        "x-vyuu-principal-id": "claude-stdio",
        "x-vyuu-principal-display": "claude-stdio (local lab)"
      }
    }
  }
}
```

**Stdio-only Claude Desktop** (older builds — bridge through `mcp-remote`):

```json
{
  "mcpServers": {
    "drawio-http-via-vyuu": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://127.0.0.1:8765/v/11111111-1111-1111-1111-111111111111/drawio-http/mcp",
        "--header", "x-vyuu-tenant-id: 11111111-1111-1111-1111-111111111111",
        "--header", "x-vyuu-principal-type: endpoint_session",
        "--header", "x-vyuu-principal-id: claude-http"
      ]
    }
  }
}
```

The lab process prints both Cursor and Claude Desktop config blocks at startup so you can copy whichever fits.

#### Lab debug mode: visible audit events + raw tool I/O

The lab wires two debug wrappers that production does **not** ship:

- `[audit] {...}` lines: every audit event, dumped as JSON to stdout. The events themselves are spec-compliant (metadata + redacted `args_summary` only — no raw values). This wrapper just makes the existing in-memory events visible. Production audit emitters are shape-equivalent but route to Kafka / NATS / disk spool, never stdout.
- `[upstream] >>>` / `[upstream] <<<` lines: raw tool arguments going out and the full upstream response content coming back, captured at the gateway's outbound boundary. **Production never logs raw arguments or raw responses by default** — that's an explicit contract in [AGENTS.md](AGENTS.md) and spec §3.3 ("full args captured only when policy explicitly opts in"). The opt-in path with redaction rules is on the deferred list. The lab wrapper is for local iteration only and must not be lifted into a production audit emitter.

If you want the same call visibility but only metadata (no raw args / response content), drop the `_LoggingUpstreamClient` wrapper from `examples/drawio_lab_server.py` and rely on `[audit]` lines alone.

#### Troubleshooting: client sees `Session has been terminated or has expired`

This is the gateway returning JSON-RPC `-32600` because the client's `mcp-session-id` is no longer in the `InMemorySessionRegistry`. Most common causes:

1. **Lab process restart.** The in-memory registry is empty on every start; any session id the client cached from a previous run is invalid. Watch for `inbound_mcp_session_rejected` log lines — they include the rejected session id and the request method that hit it.
2. **TTL expiry.** Default is 1 hour (`Settings.session_ttl_seconds`). Long-idle clients eventually trip this.
3. **Client recovery race.** Cursor specifically can race two parallel tool calls into a "Failed to start MCP session reinitialization" state; the FSM then sits in "not connected" for a few minutes until the next `listOfferingsForUI` poll drives a clean re-`initialize`. Not a gateway bug, but `inbound_mcp_session_created` log lines will tell you the exact moment recovery succeeds.

Quick fix: reload the MCP server in the client (Cursor has a refresh button per server in its MCP panel) or restart the client. A persistent (Redis-backed) `SessionRegistry` would eliminate cause #1 in production; cause #2 + #3 are intrinsic to session-based MCP.

Two lab artifacts back this:

- **`tests/lab/test_drawio_upstream.py`** — three network-gated tests (`VYUU_TEST_DRAWIO_UPSTREAM=1` to enable) that drive the same gateway-config-with-real-drawio-upstream over real HTTPS. Skipped from the default `pytest` run so CI without internet stays green. Proves the gateway → real-world MCP server path works for `initialize` / `tools/list` / `tools/call` and that audit + graph emission survive the round trip.
- **`examples/drawio_lab_server.py`** — the runnable equivalent for connecting Cursor (or any other real MCP client). Same wiring as the lab tests, just with `uvicorn` instead of `pytest`.

#### What the lab demo does NOT exercise

- **Real Postgres / RLS / migrations.** The DB session is faked in. RLS verification lives in `tests/integration/test_rls_real_postgres.py`.
- **Real operator-API auth.** The lab gateway has the operator route registered but you wouldn't use it during the demo.
- **Durable audit / graph storage.** Events live in process memory only. When you stop the lab server, telemetry is gone.
- **The real upstream provider's DB-driven dispatch.** The lab uses a hand-wired `_DispatchingUpstreamProvider` keyed on `(tenant_id, server_id)` rather than `DatabaseBackedUpstreamClientProvider`, because the lab fakes the resolver DB. The transport choice (Streamable HTTP vs stdio-via-npx) is identical in shape to what production does — what's skipped is the row-lookup. Production wiring is exercised end-to-end by the env-gated Postgres / Redis suites.

### Production blockers before the lab can be replaced with real-world traffic

In rough operational order — these are the items that *must* land before pointing a real MCP client at a real upstream over a real network:

1. **Operator-API auth provider** that isn't an HMAC-signed test token. Replace `FakeOperatorAuthProvider` with a real OIDC / API-key provider.
2. **Inbound MCP auth provider** that isn't `FakeIdentityProvider`. Real session-token / API-key validation, not mock headers.
3. **TLS termination at the ingress** (or mTLS gateway-side) — currently no TLS code in the gateway.
4. **Runtime DB role split** (HANDOFF "Deferred Design Follow-ups → RLS role separation") so the runtime app runs as `NOBYPASSRLS`. Currently the app role bypasses RLS in practice because it shares the migration role.
5. **Real Kafka/NATS audit producer + async graph emitter** — currently `_LocalAuditEmitter` records in-process, `NoOpGraphEventEmitter` discards. Until these land, audit / graph events are not durable beyond a single gateway-process lifetime.
6. **SSE outbound compatibility** if legacy customers require it. Streamable HTTP and stdio/npm are implemented.
7. **Registration-time MCP probe + periodic capability sync worker** so capabilities don't silently go stale and registration doesn't accept dead URLs.
8. **Payload size limits + response inspection / redaction** — neither is enforced today.

The lab will *continue to pass* as each of these lands — it asserts on the gateway's contract, not on the implementation of any one provider.

## Important Implementation Notes

- The project is currently using fake/test identity and fake/in-process MCP servers only.
- There is no real Kafka/NATS producer yet.
- There is no real OIDC implementation yet (operator API uses an HMAC-signed test bearer token; spec §7.1's "tenant-scoped API key" is satisfied at the Protocol layer but not by a production provider).
- The inbound MCP endpoint exists (`/v/{tenant_id}/{vserver_name}/mcp`) and is verified end-to-end against the real SDK client. URLs use tenant UUIDs; tenant slugs require a schema change and are deferred.
- The upstream client provider supports Streamable HTTP and stdio/npm. Legacy `sse` outbound still raises `UnsupportedUpstreamTransportError`.
- There is no runtime MCP probing during registration yet.
- There is no periodic capability sync worker yet.
- The session registry has two impls: `InMemorySessionRegistry` (default; single-instance) and `RedisSessionRegistry` (selected by setting `VYUU_REDIS_URL`). Multi-instance / HA deployments must use the Redis impl.
- Upstream connection pool, health checks, and circuit breakers are implemented as local process abstractions. Distributed/shared upstream pooling across gateway instances is not implemented.
- Gateway operator console exists at `/operator`; the customer-facing Vyuu management-plane dashboard and policy UI are not implemented here.
- The RLS layer is now active: per-request `set_config('app.current_tenant_id', ...)` is run on every transaction. Production gateway connections must use a role with `NOBYPASSRLS`; admin / migration connections must use a role that bypasses RLS (table owner or superuser). The Alembic migrations themselves typically run as the table owner, which is correct.
- `__pycache__` files exist in the tree from running tests; ignore them unless cleanup is explicitly requested.

## Deferred Design Follow-ups (within shipped features)

These are *intentional v1 simplifications* in features that are otherwise complete. They are not bugs; they are tradeoffs to revisit when there is real signal (a customer asks, an incident reveals a gap, more corpus data is available, etc.). Documented here so the rationale is not lost between sessions.

### URL registration security (`src/vyuu_gateway/registry/url_security.py`)

- **No CIDR support in allowlist/denylist.** Matching is `fnmatch` glob only (e.g., `*.internal.example`). The global `allow_private_networks` flag covers the broad case; per-range CIDR rules are deferred until an operator asks. Add by parsing entries that contain `/` as `ipaddress.ip_network` and checking IP literals against them.
- **No DNS resolution at registration.** A public hostname that resolves to an internal IP would currently slip past — this is a structural URL check only. Real SSRF defense requires resolving hostnames at outbound-client connection time and re-validating the resolved address against the same rules. Track as a follow-up when the real outbound client provider is built (see `Likely Next Work` → "real upstream client provider").

### Tool risk classification (`src/vyuu_gateway/capabilities/risk.py`)

- **Heuristic, not authoritative.** Output is a *default tag* for audit consumers and policy authors; operator overrides at the policy/virtual-server layer remain the source of truth. Do not hard-gate on `risk_category` without an explicit policy decision.
- **Server metadata is a fallback signal only.** When the primary haystack (name + description + schema property names) is silent, the classifier falls back to the upstream server's `display_name`. It is *not* additive — a server named `vault` will not pull `list_repos` into `credential_access`. Revisit this blending strategy when there is real corpus data on tool naming patterns.
- **CamelCase splitting is naive.** Lower→upper transitions only. Acronym-aware splitting (`getURLPath` → `get URL Path`) is deferred — the snake_case bias of MCP tool names in the wild makes this low-priority.

### RLS role separation (`src/vyuu_gateway/db/session.py`, `migrations/env.py`)

- **Application and migration share one DB role today.** Both the runtime engine in `db/session.py` and Alembic's `migrations/env.py` resolve their connection URL via `get_settings().database_url`. There is no separate `migration_database_url`. This means whatever role is configured *must* satisfy both roles' needs: bypass RLS (for migrations to apply RLS-touching DDL and for fixture inserts) AND have row-level grants (for the runtime app to read/write under RLS). The simplest production-viable fit is a single role that owns the tables — table owners bypass RLS by default. **The consequence: the runtime application currently bypasses RLS in practice**; the policy machinery is wired correctly, but the role-level bypass overrides it.
- **Why this is deferred, not broken.** The `bind_tenant_context` + `after_begin` listener path is correct and verified end-to-end (see `tests/integration/test_rls_real_postgres.py`'s explicit `SET ROLE` to a `NOBYPASSRLS` role). The only thing missing is the runtime role split. The integration tests prove the layer *will* enforce isolation as soon as the runtime role stops bypassing RLS.
- **What to do before the operational handoff.** Either (a) add a separate `Settings.runtime_database_url` distinct from the migration URL, with the runtime URL pointing at a `NOBYPASSRLS` role that has `SELECT/INSERT/UPDATE/DELETE` grants on tenant-scoped tables, or (b) keep one URL but document that the role must be `NOBYPASSRLS` and run migrations under a different role via `--url` overrides. (a) is cleaner because it makes role-mismatch a config-shape error rather than an operator-discipline question.
- **What stays the same either way.** The application code does not change — `bind_tenant_context` and `get_tenant_scoped_db` are role-agnostic. This is purely an ops/config concern.

### Inbound MCP / sessions / upstream provider (`src/vyuu_gateway/api/inbound_mcp.py`, `sessions/registry.py`, `upstream/provider.py`)

- **JSON-only responses, no SSE.** The endpoint returns `application/json` JSON-RPC responses. The MCP spec lets servers respond with SSE for streaming and clients accept both. We picked JSON for the v1 cut; add SSE when a streaming-tool use case (long-running upstream calls, partial results) shows up.
- **URL uses tenant UUID, not slug.** Spec wants `/v/acme-bank/...` ergonomic URLs but adding a `tenants.slug` column is a separate migration (uniqueness constraint, URL-safe validator, registration UX). UUIDs unblock real-client testing without that migration.
- **Per-request `ToolCallLifecycle` construction.** Most providers come from `app.state` (singletons), but `VirtualServerResolver` needs the per-request DB session, so the lifecycle is rebuilt per `tools/call`. Cheap; simpler than a `ResolverFactory` indirection. Revisit if construction becomes a hot-path concern.
- **In-memory session registry is the default.** The Redis-backed impl ships and is wired (set `VYUU_REDIS_URL` to switch); leaving it on the default keeps the inbound endpoint zero-dependency for the lab. Both impls evict lazily on lookup.
- **Bearer token re-validation per request.** `initialize` validates the bearer; the lifecycle's per-call identity validation re-validates on every `tools/call`. This adds latency vs. trusting the session id alone, but means a revoked token stops working immediately rather than at session expiry. Revisit when latency budgets need it.
- **Process-local upstream pool / health / circuit breakers.** Pool keys and breaker keys include `(tenant_id, server_id, transport)`. This is not a distributed/shared pool across gateway instances.
- **SSE outbound still unsupported.** Streamable HTTP and stdio/npm outbound are implemented. Legacy SSE upstreams raise `UnsupportedUpstreamTransportError`; the error surfaces through the lifecycle as `UPSTREAM_ERROR`.

### NHI graph events (`src/vyuu_gateway/graph/build.py`)

- **`server_accessed_resource` resource node is coarse.** Identity is `resource:server:<id>:tool:<upstream_tool_name>` — the *tool* itself acts as a stand-in for the resource. We deliberately avoid extracting resource identifiers from arguments because that would require persisting argument content into the graph, which violates the no-customer-data principle in `AGENTS.md`. Refine the resource node when MCP `resources/read` flow and `resourceLink` response content awareness land — at that point the gateway can extract resource URIs from MCP-typed return values rather than from arguments.
- **No Kafka producer yet.** `GraphEventProducer` Protocol exists; the only emitter wired into the lifecycle is `NoOpGraphEventEmitter`. Adding a real producer is an isolated change: implement `GraphEventProducer` for Kafka/NATS, and an `AsyncGraphEventEmitter` mirroring `AsyncAuditEmitter` (queue + worker + overflow spool).
- **Strict-audit-preflight failures emit no graph event.** When the audit emitter cannot durably queue and we are in strict mode, the call is denied before any telemetry is emitted (audit *or* graph). This is by design — the call never happened — but it does mean the graph will not record the *attempt*. If an operator wants to track preflight-blocked attempts, that requires a separate emit point in `_strict_audit_preflight_failure`.

## Likely Next Work

Good next increments (in roughly the order they unblock real-client production traffic):

- Add legacy SSE outbound client support if compatibility demand appears.
- Add capability sync scheduling worker (currently sync runs only on demand).
- Add registration-time MCP probe (the spec requires it; today registration just inserts the row with `health_status=unknown`).
- Add virtual-server CRUD/list operator APIs and UI panels.
- Add response/input inspection and payload size limits with default-safe redaction.
- Add real OIDC / API-key validation provider for the operator API and the inbound MCP API (replaces `FakeOperatorAuthProvider` and `FakeIdentityProvider`).
- Add Kafka/NATS audit producer + an `AsyncGraphEventEmitter` (mirrors `AsyncAuditEmitter`).
- Replace process-local upstream pooling with a deployment-aware strategy if load tests prove cross-instance coordination is needed.
- Add observability metrics abstraction (Prometheus exposition, OTel tracing) — currently only stdout structured logs.
- Add SSE response support on the inbound endpoint (currently JSON-only).
- Add tenant slug column + slug-based URL form for the inbound endpoint (`/v/acme-bank/...`).

## Commands To Run

Use these before handing back work:

```bash
pytest
ruff check .
mypy .
```

## Safety Reminders

- Do not log raw tool arguments or raw tool responses.
- Do not log tokens or secrets.
- Do not store secrets in plaintext; registry only stores `env_vars_ref`.
- Maintain tenant filters in every tenant-scoped DB query.
- Treat upstream MCP servers as untrusted.
- Do not implement LLM gateway behavior.
