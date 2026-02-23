"""
test_esql_queries.py
Validates that all ES|QL query files:
  1. Exist on disk
  2. Contain required structural keywords (FROM, STATS, KEEP, etc.)
  3. Use correct ES|QL syntax conventions (no legacy COUNT_DISTINCT())
  4. Reference the correct index names
"""

import os
import re
import pytest

ESQL_DIR = os.path.join(os.path.dirname(__file__), "..", "tools", "esql")

EXPECTED_FILES = [
    "brute-force-detection.esql",
    "data-exfiltration-detection.esql",
    "privilege-escalation-detection.esql",
    "incident-correlation.esql",
    "timeline-builder.esql",
    "anomaly-scorer.esql",
    "mitre-attack-mapper.esql",
    "lateral-movement-detector.esql",
    "campaign-correlation.esql",
    "mttd-mttr-scorecard.esql",
]

VALID_SECURITY_INDEX = "security-simulated-events"
METRICS_INDEX = "incident-metrics"


def load_esql(filename: str) -> str:
    path = os.path.join(ESQL_DIR, filename)
    with open(path, "r") as f:
        return f.read()


# ── File existence ─────────────────────────────────────────────────────────────


class TestFileExistence:
    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_file_exists(self, filename):
        path = os.path.join(ESQL_DIR, filename)
        assert os.path.isfile(path), f"Missing ES|QL file: {filename}"

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_file_not_empty(self, filename):
        content = load_esql(filename)
        assert len(content.strip()) > 50, f"File too short: {filename}"


# ── Syntax checks ─────────────────────────────────────────────────────────────


class TestSyntax:
    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_no_legacy_count_distinct(self, filename):
        """COUNT_DISTINCT() was removed in ES|QL. Must use COUNT(DISTINCT x)."""
        content = load_esql(filename)
        assert "COUNT_DISTINCT(" not in content.upper(), (
            f"{filename} uses deprecated COUNT_DISTINCT() — use COUNT(DISTINCT x) instead"
        )

    @pytest.mark.parametrize(
        "filename", [f for f in EXPECTED_FILES if f != "mttd-mttr-scorecard.esql"]
    )
    def test_has_from_clause(self, filename):
        content = load_esql(filename)
        assert re.search(r"^\s*FROM\s+", content, re.MULTILINE | re.IGNORECASE), (
            f"{filename} missing FROM clause"
        )

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_has_stats_or_keep(self, filename):
        content = load_esql(filename).upper()
        assert "| STATS" in content or "| KEEP" in content or "| SORT" in content, (
            f"{filename} has no STATS, KEEP, or SORT pipe — likely incomplete"
        )

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_no_sql_style_select(self, filename):
        """ES|QL uses FROM not SELECT."""
        content = load_esql(filename)
        assert not re.search(r"^\s*SELECT\s+", content, re.MULTILINE | re.IGNORECASE), (
            f"{filename} uses SQL SELECT — should use ES|QL FROM"
        )


# ── Index name correctness ─────────────────────────────────────────────────────


class TestIndexNames:
    @pytest.mark.parametrize(
        "filename", [f for f in EXPECTED_FILES if f != "mttd-mttr-scorecard.esql"]
    )
    def test_uses_correct_security_index(self, filename):
        content = load_esql(filename)
        assert VALID_SECURITY_INDEX in content, (
            f"{filename} does not reference '{VALID_SECURITY_INDEX}'"
        )

    def test_scorecard_uses_metrics_index(self):
        content = load_esql("mttd-mttr-scorecard.esql")
        assert METRICS_INDEX in content, (
            "mttd-mttr-scorecard.esql does not reference 'incident-metrics'"
        )


# ── Content correctness per file ──────────────────────────────────────────────


class TestContentCorrectness:
    def test_brute_force_has_failure_filter(self):
        content = load_esql("brute-force-detection.esql")
        assert "failure" in content.lower()

    def test_brute_force_has_threshold(self):
        content = load_esql("brute-force-detection.esql")
        # Should have a numeric threshold (>= 5 or similar)
        assert re.search(r">=\s*\d+", content), (
            "brute-force-detection.esql missing threshold"
        )

    def test_exfil_has_bytes_threshold(self):
        content = load_esql("data-exfiltration-detection.esql")
        assert "bytes" in content.lower()

    def test_exfil_has_outbound_filter(self):
        content = load_esql("data-exfiltration-detection.esql")
        assert "outbound" in content.lower()

    def test_privesc_has_process_category(self):
        content = load_esql("privilege-escalation-detection.esql")
        assert "process" in content.lower()

    def test_lateral_movement_has_distinct_hosts(self):
        content = load_esql("lateral-movement-detector.esql")
        assert "DISTINCT" in content.upper()
        assert "host" in content.lower()

    def test_campaign_correlation_has_severity_tiers(self):
        content = load_esql("campaign-correlation.esql")
        assert "APT_CRITICAL" in content
        assert "HIGH" in content
        assert "MEDIUM" in content

    def test_anomaly_scorer_has_baseline_calculation(self):
        content = load_esql("anomaly-scorer.esql")
        assert "baseline" in content.lower()
        assert "anomaly_score" in content.lower()

    def test_mitre_mapper_has_all_techniques(self):
        content = load_esql("mitre-attack-mapper.esql")
        for technique in ["T1110", "T1041", "T1068", "T1021", "T1136", "T1046"]:
            assert technique in content, f"mitre-attack-mapper.esql missing {technique}"

    def test_scorecard_has_percentile(self):
        content = load_esql("mttd-mttr-scorecard.esql")
        assert "PERCENTILE" in content.upper()

    def test_scorecard_has_grading(self):
        content = load_esql("mttd-mttr-scorecard.esql")
        assert "Excellent" in content
        assert "Poor" in content
