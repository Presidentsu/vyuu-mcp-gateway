"""RISK-1 · what the gateway actually took off the table.

A virtual server publishes a curated subset of one or more upstreams.
The claim this module supports is: *these are the risks that existed on
the upstreams, and these are the ones your users can no longer reach.*

## Why the vserver is not assessed independently

The obvious implementation is to run the classifier twice — once on the
full server, once on the published subset — and subtract. Do not.

Two runs are two opinions. They differ for reasons that have nothing to
do with curation: sampling, phrasing, a model revision between them. The
subtraction would then report a "reduction" that is partly noise, and
occasionally a NEGATIVE one where publishing fewer tools scored worse.
Nobody can defend that number in a board pack.

So the upstream is assessed once, and the published risk is computed
from **the same findings**, restricted to those that still reach a
published tool. Every number in the comparison then comes from one set
of judgements, and the difference is arithmetic rather than opinion.

## What counts as eliminated

A finding survives publication if any tool it names is published. A
finding naming no tools at all — a server-wide property like transport
weakness or supply-chain provenance — survives too: curating the tool
list does not change how the server is built or shipped, and quietly
crediting the operator for removing it would be the most flattering
possible reading of the evidence.

That last rule is the one that keeps the number honest. It is also why
the reduction is usually smaller than an operator expects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from vyuu_gateway.risk.classifier import Finding
from vyuu_gateway.risk.taxonomy import AggregateRisk, aggregate


def finding_survives(finding: Finding, published_tools: set[str]) -> bool:
    """Whether a finding still reaches a user after curation."""

    if not finding.affected_tools:
        # Server-wide. Not addressable by choosing tools — see above.
        return True
    return any(tool in published_tools for tool in finding.affected_tools)


@dataclass(frozen=True)
class RiskReduction:
    """Inherent vs published, and the difference."""

    inherent: AggregateRisk
    published: AggregateRisk
    eliminated_findings: list[Finding]
    retained_findings: list[Finding]

    @property
    def points_reduced(self) -> float:
        """Risk points removed, measured on EXPOSURE (eq. 9).

        Exposure is a sum, so removing findings can only ever lower it —
        the comparison is monotonic by construction.

        The first version measured this on the normalised band, which is
        built from `Rrms`, and RMS is NOT monotonic under removal. A real
        run proved it: curating a CrowdStrike bundle eliminated 24
        findings and the severity profile went UP, 28.4 → 32.0, because
        what remained was a smaller and nastier set. The clamp below then
        printed "reduced 0.0 points" beside two numbers that plainly
        disagreed with it.

        I had written the negative-reduction hazard into this module as
        an argument against using two LLM opinions, and missed that one
        set of findings scored by RMS has the same defect.
        """

        return round(max(0.0, self.inherent.exposure - self.published.exposure), 1)

    @property
    def percent_reduced(self) -> float:
        """Share of reachable risk removed. The honest headline."""

        if self.inherent.exposure <= 0:
            return 0.0
        return round(
            min(100.0, self.points_reduced / self.inherent.exposure * 100.0), 1
        )

    @property
    def severity_profile_delta(self) -> float:
        """Change in the 0-100 band. May be POSITIVE, and that is real.

        A rise means curation removed breadth but left the worst
        findings concentrated — less risk reachable overall, but what
        remains is individually nastier. Surfaced rather than clamped:
        an operator who has just cut 24 findings and whose band went up
        deserves to know why, and hiding it makes every other number on
        the page look managed.
        """

        return round(self.published.normalised - self.inherent.normalised, 1)

    def to_json(self) -> dict[str, Any]:
        return {
            "inherent": {
                "normalised": self.inherent.normalised,
                "band": self.inherent.band,
                "finding_count": self.inherent.finding_count,
                "exposure": self.inherent.exposure,
            },
            "published": {
                "normalised": self.published.normalised,
                "band": self.published.band,
                "finding_count": self.published.finding_count,
                "exposure": self.published.exposure,
            },
            "points_reduced": self.points_reduced,
            "percent_reduced": self.percent_reduced,
            "severity_profile_delta": self.severity_profile_delta,
            "findings_eliminated": len(self.eliminated_findings),
            "findings_retained": len(self.retained_findings),
            # Named, not just counted. "We removed 4 risks" is a claim;
            # "we removed remote shell execution and quarantine deletion"
            # is the sentence that survives a board asking which four.
            "eliminated": [
                {
                    "title": f.title,
                    "owasp_mcp": f.owasp_mcp.value,
                    "risk": f.risk,
                    "affected_tools": list(f.affected_tools),
                }
                for f in sorted(
                    self.eliminated_findings, key=lambda f: f.risk, reverse=True
                )
            ],
            "retained": [
                {
                    "title": f.title,
                    "owasp_mcp": f.owasp_mcp.value,
                    "risk": f.risk,
                    "affected_tools": list(f.affected_tools),
                }
                for f in sorted(
                    self.retained_findings, key=lambda f: f.risk, reverse=True
                )
            ],
        }


def compute_reduction(
    upstream_findings: list[Finding], published_tools: set[str]
) -> RiskReduction:
    """Split one upstream assessment by what survives publication."""

    retained = [f for f in upstream_findings if finding_survives(f, published_tools)]
    eliminated = [
        f for f in upstream_findings if not finding_survives(f, published_tools)
    ]
    return RiskReduction(
        inherent=aggregate([f.risk for f in upstream_findings]),
        published=aggregate([f.risk for f in retained]),
        eliminated_findings=eliminated,
        retained_findings=retained,
    )
