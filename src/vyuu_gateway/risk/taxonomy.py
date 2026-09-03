"""RISK-1 · the vocabulary a risk finding is allowed to use.

Two published sources, so a score can be argued with rather than merely
believed. Both are encoded here rather than left to the model, because a
classifier free to invent its own categories produces output that cannot
be compared between two servers, let alone tracked over time.

## OWASP MCP Top 10 (MCP01:2025 – MCP10:2025)

Fetched from `owasp.org/www-project-mcp-top-10`. This is the axis a CISO
already has language for, so it is what the summary view reports against.

## MCP-in-SoS (arXiv:2603.10194)

"Risk assessment framework for open-source MCP servers". Supplies the
scoring factors and the aggregation, both reproduced faithfully:

    LA(w)  CAPEC likelihood_of_attack
    LE(w)  CWE   likelihood_of_exploit
    MI(w)  CWE   modes_of_introduction_count   (breadth multiplier)
    CC(w)  CWE   common_consequences_count     (breadth multiplier)
    TS(w)  CAPEC typical_severity

    Likelihood(w) = LA · LE · MI                        (eq. 6)
    Impact(w)     = TS · CC                             (eq. 7)
    R(w)          = Likelihood(w) · Impact(w)           (eq. 8)

and at the server level, over findings c with frequency f(c):

    Rexp     = Σ f(c)·w(c)                              (eq. 9)
    Rrms     = sqrt( Σ f(c)·w(c)² / Σ f(c) )            (eq. 10)
    Roverall = Rrms · log10(N + 1)                      (eq. 11)

It also maps CWEs to four threat categories aligned with the MCP
primitives — Tool, Resource, Prompt, Protocol — which is the axis an
engineer can act on, so both axes are carried on every finding.

## Where our evidence differs from the paper's, and why that matters

The paper runs **static analysis over MCP server source code** (CodeQL,
Joern, Cisco AI Defender) and counts real CWE findings. We do not have
the source. We have what capability sync gives us: tool names, tool
descriptions, and input schemas — the same surface an attacking LLM
sees, which is exactly the right surface for tool-poisoning and prompt
classes and a much weaker one for anything requiring code.

So this reuses the paper's *scoring* on a *different evidence base*.
That is a real limitation, not a detail: a server can score low here and
still be riddled with injection bugs its description does not advertise.
Every assessment carries `evidence_basis` saying so, and the UI repeats
it, because a number whose provenance is invisible gets read as more
than it is.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum


class OwaspMcpRisk(StrEnum):
    """OWASP MCP Top 10, beta. Identifiers are the published ones."""

    MCP01 = "MCP01:2025"
    MCP02 = "MCP02:2025"
    MCP03 = "MCP03:2025"
    MCP04 = "MCP04:2025"
    MCP05 = "MCP05:2025"
    MCP06 = "MCP06:2025"
    MCP07 = "MCP07:2025"
    MCP08 = "MCP08:2025"
    MCP09 = "MCP09:2025"
    MCP10 = "MCP10:2025"


OWASP_MCP_TITLES: dict[OwaspMcpRisk, str] = {
    OwaspMcpRisk.MCP01: "Token Mismanagement & Secret Exposure",
    OwaspMcpRisk.MCP02: "Privilege Escalation via Scope Creep",
    OwaspMcpRisk.MCP03: "Tool Poisoning",
    OwaspMcpRisk.MCP04: "Software Supply Chain Attacks & Dependency Tampering",
    OwaspMcpRisk.MCP05: "Command Injection & Execution",
    OwaspMcpRisk.MCP06: "Intent Flow Subversion",
    OwaspMcpRisk.MCP07: "Insufficient Authentication & Authorization",
    OwaspMcpRisk.MCP08: "Lack of Audit and Telemetry",
    OwaspMcpRisk.MCP09: "Shadow MCP Servers",
    OwaspMcpRisk.MCP10: "Context Injection & Over-Sharing",
}


class McpThreatCategory(StrEnum):
    """The paper's four categories, aligned to the MCP primitives.

    Kept alongside the OWASP axis because they answer different
    questions: OWASP tells a CISO which published risk this is, the
    primitive tells an engineer which part of the surface to change.
    """

    TOOL = "tool"
    RESOURCE = "resource"
    PROMPT = "prompt"
    PROTOCOL = "protocol"


# The paper's five-point scales. Values are the integers substituted
# into equations 6-8; the labels are what the classifier is asked to
# choose between, because "High" is a judgement a model can make about a
# tool description and 4.0 is not.
LIKELIHOOD_SCALE: dict[str, int] = {
    "very_low": 1, "low": 2, "medium": 3, "high": 4, "very_high": 5,
}
SEVERITY_SCALE: dict[str, int] = {
    "very_low": 1, "low": 2, "medium": 3, "high": 4, "very_high": 5,
}

# MI and CC are counts, not ratings — breadth multipliers in the paper.
# Bounded so one implausible answer cannot dominate a server's score:
# the paper measured a mean of 1.56 consequences per weakness, so an
# unbounded count invented by a model is the most likely way this scoring
# gets distorted.
MAX_MODES_OF_INTRODUCTION = 5
MAX_COMMON_CONSEQUENCES = 6


@dataclass(frozen=True)
class RiskFactors:
    """One finding's five factors, on the paper's scales."""

    likelihood_of_attack: int      # LA
    likelihood_of_exploit: int     # LE
    modes_of_introduction: int     # MI
    common_consequences: int       # CC
    typical_severity: int          # TS

    def likelihood(self) -> int:
        """eq. 6 — LA · LE · MI."""
        return (
            self.likelihood_of_attack
            * self.likelihood_of_exploit
            * self.modes_of_introduction
        )

    def impact(self) -> int:
        """eq. 7 — TS · CC."""
        return self.typical_severity * self.common_consequences

    def risk(self) -> int:
        """eq. 8 — Likelihood · Impact."""
        return self.likelihood() * self.impact()


# Ceiling of R(w) with every factor maxed: (5·5·5)·(5·6) = 3750.
MAX_FINDING_RISK = (
    LIKELIHOOD_SCALE["very_high"]
    * LIKELIHOOD_SCALE["very_high"]
    * MAX_MODES_OF_INTRODUCTION
    * SEVERITY_SCALE["very_high"]
    * MAX_COMMON_CONSEQUENCES
)

# What a genuinely severe finding scores: very likely to be attacked,
# readily exploitable, introduced several ways, wide blast radius,
# critical severity. LA=5 · LE=4 · MI=3 · TS=5 · CC=4 = 1200.
#
# This is the anchor for the 0-100 band, NOT `MAX_FINDING_RISK`.
# Normalising against the theoretical maximum was the first thing I got
# wrong here: nothing real reaches 3750, so ten maximally-bad findings
# still landed at 32/100 and the whole scale read "everything is fine".
# A yardstick nothing can touch does not measure anything.
REFERENCE_SEVERE_FINDING_RISK = 1200

# How much of the band comes from the single worst finding, with the
# remainder from the RMS profile.
#
# The paper's Rrms alone is an average, so breadth dilutes depth: one
# critical finding among twenty trivial ones scored 21.8/100 — moderate
# — which is not how anyone triages. Real data made the case: a Postgres
# bridge exposing unrestricted arbitrary SQL (R=960) scored 42.9
# "moderate" on RMS alone, and 61.5 "high" once its worst finding
# counted for half. The second reading is the correct one.
#
# 0.5 rather than something higher because depth alone is not the whole
# story either: a server with one bad tool and a server with one bad
# tool plus forty mediocre ones are not the same exposure, and the RMS
# half keeps that visible. This split is a presentation choice, not a
# result from the paper, which ranks repositories against each other
# rather than against fixed bands.
MAX_FINDING_WEIGHT = 0.5


@dataclass(frozen=True)
class AggregateRisk:
    """Server- or vserver-level score. Mirrors equations 9-11."""

    exposure: float          # Rexp  — total risk carried
    severity_profile: float  # Rrms  — the paper's severity metric
    overall: float           # Roverall
    finding_count: int
    # The single worst finding. Half the band, so one critical risk
    # cannot be averaged away by a long tail of minor ones.
    max_finding: float = 0.0

    @property
    def band(self) -> str:
        """A word, because a CISO deck cannot use `Roverall = 41.7`.

        Thresholds are on the normalised 0-100 scale below, chosen so
        that a single maxed-out finding lands in `critical` and a server
        with only low-severity surface stays in `low`. They are a
        presentation choice, not a result from the paper — the paper
        ranks repositories against each other rather than against fixed
        bands.
        """

        score = self.normalised
        if score >= 70:
            return "critical"
        if score >= 45:
            return "high"
        if score >= 20:
            return "moderate"
        if score > 0:
            return "low"
        return "none"

    @property
    def normalised(self) -> float:
        """0-100: half the worst finding, half the RMS profile.

        Scaled against `REFERENCE_SEVERE_FINDING_RISK`, so 100 means
        "as bad as a severe finding".

        Not `Roverall`: that multiplies by a log of the finding count,
        which would rank fifty trivial findings above three critical
        ones. Not `Rrms` alone either — it is an average, so breadth
        dilutes depth, and one critical finding among twenty trivial
        ones scored 21.8/100. Blending the maximum in fixes that while
        keeping breadth visible. See `MAX_FINDING_WEIGHT`.

        Volume is still reported as `exposure` and `overall`, where it
        informs without dominating.
        """

        if self.finding_count <= 0:
            return 0.0
        blended = (
            MAX_FINDING_WEIGHT * self.max_finding
            + (1.0 - MAX_FINDING_WEIGHT) * self.severity_profile
        )
        ratio = blended / REFERENCE_SEVERE_FINDING_RISK
        return round(min(100.0, ratio * 100.0), 1)


def aggregate(finding_risks: list[int]) -> AggregateRisk:
    """Equations 9-11 over one server's findings.

    The paper aggregates by CWE with a frequency f(c). We carry one
    entry per finding, so f(c) = 1 throughout and the frequency weighting
    reduces to a plain sum — the formulas are unchanged, the weights are
    just all one.
    """

    n = len(finding_risks)
    if n == 0:
        return AggregateRisk(0.0, 0.0, 0.0, 0)
    exposure = float(sum(finding_risks))
    rms = math.sqrt(sum(r * r for r in finding_risks) / n)
    overall = rms * math.log10(n + 1)
    return AggregateRisk(
        exposure=round(exposure, 2),
        severity_profile=round(rms, 2),
        overall=round(overall, 2),
        finding_count=n,
        max_finding=float(max(finding_risks)),
    )
