"""Trust-policy tests: switch decisions are bound to the request context.

The default policy denies everything. Only authorities/tokens explicitly
trusted by the *current* :class:`TrustContext` may be reached, and a context
never inherits trust from a previous exchange.
"""

import h11

from tunnellab.policy import (
    CONNECT,
    UPGRADE,
    SwitchPolicy,
    TrustContext,
    extract_switch_request,
)


def _connect(target: str) -> h11.Request:
    return h11.Request(
        method="CONNECT", target=target, headers=[("Host", target)]
    )


def _upgrade(token: str = "websocket") -> h11.Request:
    return h11.Request(
        method="GET",
        target="/chat",
        headers=[
            ("Host", "example.test"),
            ("Connection", "Upgrade"),
            ("Upgrade", token),
        ],
    )


def test_default_policy_denies_all_switches() -> None:
    policy = SwitchPolicy()
    ctx = TrustContext(client_id="c")
    assert policy.review_request(ctx, _connect("any:443")).denied
    assert policy.review_request(ctx, _upgrade()).denied


def test_ordinary_request_is_allowed_without_switch_trust() -> None:
    policy = SwitchPolicy()
    ctx = TrustContext(client_id="c")
    req = h11.Request(
        method="GET", target="/", headers=[("Host", "example.test")]
    )
    decision = policy.review_request(ctx, req)
    assert decision.allowed and decision.mode is None


def test_connect_requires_authority_in_current_context() -> None:
    policy = SwitchPolicy(default_authorities=frozenset({"default:443"}))
    trusted = TrustContext(
        client_id="c", allowed_authorities=frozenset({"allowed.example:443"})
    )
    blocked = TrustContext(client_id="c")  # grants nothing
    allowed = policy.review_request(trusted, _connect("allowed.example:443"))
    assert allowed.allowed and allowed.mode == CONNECT
    # Context without the authority is denied even though a default exists.
    assert policy.review_request(blocked, _connect("allowed.example:443")).denied
    # A different authority is denied.
    assert policy.review_request(trusted, _connect("evil.example:443")).denied


def test_upgrade_requires_trusted_token() -> None:
    ctx = TrustContext(client_id="c", allowed_upgrades=frozenset({"websocket"}))
    policy = SwitchPolicy()
    assert policy.review_request(ctx, _upgrade("websocket")).allowed
    denied = policy.review_request(ctx, _upgrade("evil-proto"))
    assert denied.denied and denied.mode == UPGRADE


def test_connect_with_untrusted_upgrade_token_is_denied() -> None:
    ctx = TrustContext(
        client_id="c",
        allowed_authorities=frozenset({"allowed.example:443"}),
        allowed_upgrades=frozenset({"websocket"}),
    )
    policy = SwitchPolicy()
    req = h11.Request(
        method="CONNECT",
        target="allowed.example:443",
        headers=[
            ("Host", "allowed.example:443"),
            ("Upgrade", "shadow-proto"),
        ],
    )
    assert policy.review_request(ctx, req).denied


def test_context_is_per_exchange_and_carries_no_shared_state() -> None:
    policy = SwitchPolicy()
    first = TrustContext(
        client_id="c", allowed_authorities=frozenset({"a.example:443"})
    )
    second = TrustContext(client_id="c")  # fresh, empty trust
    assert policy.review_request(first, _connect("a.example:443")).allowed
    # The second exchange cannot lean on the first context's authority.
    assert policy.review_request(second, _connect("a.example:443")).denied


def test_extract_classifies_request_modes() -> None:
    mode, _ = extract_switch_request(_connect("h:443"))
    assert mode == CONNECT
    mode, tokens = extract_switch_request(_upgrade("websocket"))
    assert mode == UPGRADE and b"websocket" in tokens
    plain = h11.Request(
        method="GET", target="/", headers=[("Host", "x")]
    )
    assert extract_switch_request(plain) == (None, ())


def test_server_acceptance_review_matches_event_shape() -> None:
    policy = SwitchPolicy()
    ctx = TrustContext(client_id="c")
    good_connect = h11.Response(status_code=200, headers=[])
    bad_connect = h11.Response(status_code=403, headers=[("Content-Length", "0")])
    good_upgrade = h11.InformationalResponse(
        status_code=101, headers=[("Upgrade", "websocket")]
    )
    assert policy.review_server_acceptance(ctx, CONNECT, "h:443", good_connect).allowed
    assert policy.review_server_acceptance(ctx, CONNECT, "h:443", bad_connect).denied
    assert policy.review_server_acceptance(ctx, UPGRADE, "/", good_upgrade).allowed
    assert policy.review_server_acceptance(
        ctx, UPGRADE, "/", h11.InformationalResponse(status_code=100, headers=[])
    ).denied
