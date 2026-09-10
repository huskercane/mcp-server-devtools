#!/usr/bin/env python3
"""Inspect cache observations read-only; report coverage, never infer absent rewards."""

import argparse
import collections
import json
import math
from pathlib import Path


def inspect(directory):
    events = collections.Counter()
    policies = collections.Counter()
    decisions = {}
    outcomes = {}
    corrupt = []
    duplicate_decisions = 0
    duplicate_outcomes = 0
    invalid_policies = 0
    legacy_decisions = 0
    legacy_tracked = 0
    sequences = collections.defaultdict(set)
    duplicate_sequences = 0
    files = sorted(directory.glob("*.audit.jsonl*"))
    for path in files:
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, 1):
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict) or not isinstance(row.get("event"), str):
                        raise ValueError("expected event object")
                    if not isinstance(row.get("sessionId"), str):
                        raise ValueError("expected session ID")
                    if "decisionId" in row and not isinstance(row["decisionId"], str):
                        raise ValueError("expected decision ID")
                except (ValueError, TypeError):
                    corrupt.append({"file": path.name, "line": line_number})
                    continue
                event = row.get("event", "unknown")
                events[event] += 1
                sequence = row.get("cacheEventSequence")
                if isinstance(sequence, int) and sequence > 0:
                    seen = sequences[row.get("sessionId")]
                    duplicate_sequences += sequence in seen
                    seen.add(sequence)
                if event not in ("http_cache_decision", "http_cache_outcome"):
                    continue
                identity = (row.get("sessionId"), row.get("decisionId"))
                if not all(identity):
                    legacy_decisions += event == "http_cache_decision"
                    continue
                if event == "http_cache_outcome":
                    duplicate_outcomes += identity in outcomes
                    outcomes[identity] = row
                    continue
                duplicate_decisions += identity in decisions
                decisions[identity] = row
                policies[row.get("policyVersion", "missing")] += 1
                if row.get("schemaVersion") != 2:
                    legacy_tracked += 1
                elif not valid_policy(row):
                    invalid_policies += 1

    closed = decisions.keys() & outcomes.keys()
    complete = {key for key in closed if outcomes[key].get("observationComplete") is True}
    exploratory = {key for key in complete if decisions[key].get("schemaVersion") == 2 and decisions[key].get("policyVersion") == "collect-v2" and valid_policy(decisions[key])}
    return {
        "files": len(files),
        "events": dict(events),
        "corruptRecords": corrupt,
        "legacyDecisionsWithoutIds": legacy_decisions,
        "legacyTrackedDecisions": legacy_tracked,
        "trackedDecisions": len(decisions),
        "policies": dict(policies),
        "invalidPolicyRecords": invalid_policies,
        "duplicateDecisions": duplicate_decisions,
        "duplicateOutcomes": duplicate_outcomes,
        "duplicateCacheSequences": duplicate_sequences,
        "missingCacheSequences": sum(max(seen) - len(seen) for seen in sequences.values()),
        "matchedTerminalOutcomes": len(closed),
        "missingTerminalOutcomes": len(decisions.keys() - outcomes.keys()),
        "orphanOutcomes": len(outcomes.keys() - decisions.keys()),
        "explicitlyCompleteOutcomes": len(complete),
        "censoredOrLegacyTerminalOutcomes": len(closed - complete),
        "completeExploratoryDecisionsByAction": dict(collections.Counter(decisions[key]["action"] for key in exploratory)),
        "completeExploratorySessions": len({key[0] for key in exploratory}),
        "completeExploratoryVendors": dict(collections.Counter(decisions[key].get("vendor", "unknown") for key in exploratory)),
        "completeExploratoryPositiveHitOutcomes": sum(outcomes[key].get("hitCount", 0) > 0 for key in exploratory),
        "assessment": "Coverage report only: training readiness also requires a chosen reward, independent validation sessions, and acceptable uncertainty. Missing outcomes are not zero rewards.",
    }


def valid_policy(row):
    actions = row.get("candidateActions")
    probabilities = row.get("candidateProbabilities")
    if not isinstance(actions, list) or not actions or not all(isinstance(a, str) for a in actions) or len(set(actions)) != len(actions):
        return False
    if not isinstance(probabilities, list) or len(actions) != len(probabilities):
        return False
    if not all(isinstance(p, (int, float)) and not isinstance(p, bool) and math.isfinite(p) and 0 < p <= 1 for p in probabilities):
        return False
    if not math.isclose(sum(probabilities), 1.0):
        return False
    action = row.get("action")
    probability = row.get("actionProbability")
    return action in actions and isinstance(probability, (int, float)) and not isinstance(probability, bool) and math.isclose(probability, probabilities[actions.index(action)])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path, default=Path.home() / ".mcp/data")
    args = parser.parse_args()
    if not args.directory.is_dir():
        parser.error("directory does not exist")
    print(json.dumps(inspect(args.directory), indent=2, sort_keys=True))
