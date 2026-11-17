"""Replay every scenario under every fragmentation and assert invariants.

The same wire transcript is cut five different ways; a correct adapter must
deliver identical bytes the same number of times, reach the same outcome,
and make the same reuse decision regardless of the cuts.
"""

import pytest

from tunnellab.scenarios import FRAGMENTATIONS, build_scenarios
from tunnellab.replay import run_all, run_scenario

SCENARIOS = build_scenarios()
SCENARIO_NAMES = [s.name for s in SCENARIOS]


@pytest.mark.parametrize("strategy", list(FRAGMENTATIONS))
@pytest.mark.parametrize("scenario", SCENARIOS, ids=SCENARIO_NAMES)
def test_each_scenario_passes_under_each_fragmentation(scenario, strategy) -> None:
    result = run_scenario(scenario, strategy)
    assert result.passed, (
        f"{scenario.name}[{strategy}] failures: {result.assertion_failures}"
    )


def test_fragmentation_does_not_change_outcome_or_bytes() -> None:
    for scenario in SCENARIOS:
        runs = {s: run_scenario(scenario, s) for s in FRAGMENTATIONS}
        kinds = {r.outcome.kind if r.outcome else f"error:{r.error.stage}"
                 for r in runs.values()}
        assert len(kinds) == 1, (scenario.name, kinds)
        # Delivered payload bytes are identical across fragmentations.
        http_bytes = {
            r.trace.to_dict()["byte_ledger"]["http_delivered"] for r in runs.values()
        }
        tunnel_bytes = {len(r.controller.tunnel_bytes) for r in runs.values()}
        assert len(http_bytes) == 1
        assert len(tunnel_bytes) == 1
        # Reuse decision is stable too.
        reusable = {
            (r.outcome.reusable if r.outcome else False) for r in runs.values()
        }
        assert len(reusable) == 1


def test_byte_conservation_balances_for_every_run() -> None:
    results, _, _ = run_all()
    for result in results:
        if result.error is not None:
            continue
        ledger = result.trace.to_dict()["byte_ledger"]
        residual, _ = result.controller.conn.trailing_data
        accounted = (
            ledger["http_delivered"]
            + ledger["tunnel_handed_over"]
            + len(residual)
        )
        framing = result.transport.bytes_read - accounted
        assert framing >= 0
        assert accounted + framing == result.transport.bytes_read


def test_tunnel_handover_happens_at_most_once() -> None:
    results, _, _ = run_all()
    for result in results:
        ledger = result.trace.to_dict()["byte_ledger"]
        assert ledger["tunnel_handover_count"] in (0, 1)


def test_switch_scenarios_never_reusable() -> None:
    switched = {
        "connect_accepted_same_read",
        "upgrade_accepted_same_read",
    }
    for scenario in SCENARIOS:
        if scenario.name not in switched:
            continue
        for strategy in FRAGMENTATIONS:
            result = run_scenario(scenario, strategy)
            assert result.outcome and result.outcome.kind == "switched"
            assert result.controller.is_permanently_closed
            assert not result.controller.reusable_for_next_request()


def test_rejected_switches_stay_on_http_path_and_reuse() -> None:
    denied = {
        "connect_denied_by_server",
        "upgrade_refused_by_server",
    }
    for scenario in SCENARIOS:
        if scenario.name not in denied:
            continue
        result = run_scenario(scenario, "one_byte")
        assert result.outcome and result.outcome.kind == "complete"
        assert result.outcome.reusable
        ledger = result.trace.to_dict()["byte_ledger"]
        assert ledger["tunnel_handed_over"] == 0


def test_unsolicited_101_is_classified_as_parse_failure_not_smuggling() -> None:
    scenario = next(s for s in SCENARIOS if s.name == "unsolicited_101")
    for strategy in FRAGMENTATIONS:
        result = run_scenario(scenario, strategy)
        assert result.error is not None
        assert result.error.stage == "parse"
        assert result.controller.is_permanently_closed


def test_pipelined_second_response_is_buffered_without_loss() -> None:
    scenario = next(s for s in SCENARIOS if s.name == "pipelined_two_responses")
    result = run_scenario(scenario, "whole")
    assert result.passed
    residual, _ = result.controller.conn.trailing_data
    # The second full response (headers + "second") survives in the buffer.
    assert b"second" in residual
    assert residual.startswith(b"HTTP/1.1 200")


def test_failure_stage_is_reported_for_every_failure_scenario() -> None:
    failure_names = {
        "mid_stream_disconnect",
        "early_close",
        "read_failure_mid_body",
        "unsolicited_101",
    }
    for scenario in SCENARIOS:
        if scenario.name not in failure_names:
            continue
        result = run_scenario(scenario, "boundary_cut")
        assert result.error is not None, scenario.name
        assert result.error.stage == scenario.expectations.failure_stage
