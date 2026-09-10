import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("readiness", Path(__file__).with_name("cache-training-readiness.py"))
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


class ReadinessTests(unittest.TestCase):
    def test_counts_closed_missing_censored_and_corrupt_without_imputing_rewards(self):
        base = {"schemaVersion": 2, "sessionId": "s", "policyVersion": "collect-v2", "vendor": "test", "event": "http_cache_decision", "action": "admit", "candidateActions": ["reject", "admit_half_ttl", "admit"], "candidateProbabilities": [0.125, 0.125, 0.75], "actionProbability": 0.75}
        rows = [dict(base, decisionId=str(n), cacheEventSequence=n + 1) for n in range(3)]
        rows.extend([
            {"sessionId": "s", "decisionId": "0", "event": "http_cache_outcome", "observationComplete": True, "hitCount": 1, "cacheEventSequence": 5},
            {"sessionId": "s", "decisionId": "1", "event": "http_cache_outcome", "observationComplete": False, "hitCount": 0, "cacheEventSequence": 6},
        ])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.audit.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in rows) + "\n\x00damaged\n")
            result = readiness.inspect(Path(folder))
        self.assertEqual(result["missingTerminalOutcomes"], 1)
        self.assertEqual(result["censoredOrLegacyTerminalOutcomes"], 1)
        self.assertEqual(result["completeExploratoryDecisionsByAction"], {"admit": 1})
        self.assertEqual(result["completeExploratoryPositiveHitOutcomes"], 1)
        self.assertEqual(result["missingCacheSequences"], 1)
        self.assertEqual(result["corruptRecords"], [{"file": "test.audit.jsonl", "line": 6}])

    def test_policy_probabilities_must_describe_the_selected_action(self):
        base = {"action": "admit", "candidateActions": ["reject", "admit"], "candidateProbabilities": [0.25, 0.75], "actionProbability": 0.75}
        self.assertTrue(readiness.valid_policy(base))
        for update in [{"actionProbability": 1.0}, {"candidateProbabilities": [0, 1]}, {"candidateProbabilities": [0.5, 0.75]}, {"action": "unknown"}, {"candidateProbabilities": [float("nan"), 0.75]}]:
            self.assertFalse(readiness.valid_policy(dict(base, **update)))


if __name__ == "__main__":
    unittest.main()
