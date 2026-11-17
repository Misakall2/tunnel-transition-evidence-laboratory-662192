"""Offline diagnostic laboratory for h11 proxy/connection transitions.

The package demonstrates, with in-memory byte streams only, where h11's
message parser ends and tunnel ownership begins.  It contains no sockets, no
name resolution and no proxy implementation -- see ``diagnostics`` for the
written analysis and ``tunnellab_tests`` for the executable assertions.

Public entry points:

* :class:`~tunnellab.controller.ConnectionController` -- the reference
  adapter wrapping an ``h11.Connection`` with policy-gated switching;
* :class:`~tunnellab.policy.SwitchPolicy` / :class:`~tunnellab.policy.TrustContext`
  -- caller-bound trust decisions;
* :class:`~tunnellab.transport.MemoryTransport` -- the offline byte pipe;
* :class:`~tunnellab.pool.ConnectionPool` -- switch-aware reuse rules;
* :func:`~tunnellab.replay.run_all` -- replay every scenario/fragmentation.
"""

from .controller import (
    ConnectionController,
    ExchangeFailed,
    Handover,
    Outcome,
    SwitchRejected,
)
from .policy import SwitchPolicy, TrustContext
from .pool import ConnectionPool, PooledConnection
from .replay import ReplayResult, evidence_payload, run_all, run_scenario
from .scenarios import FRAGMENTATIONS, Scenario, build_scenarios, fragment
from .trace import EventTrace, redact_headers
from .transport import MemoryTransport, ReadFailure, make_transport_pair

__version__ = "1.0.0"

__all__ = [
    "ConnectionController",
    "ExchangeFailed",
    "Handover",
    "Outcome",
    "SwitchRejected",
    "SwitchPolicy",
    "TrustContext",
    "ConnectionPool",
    "PooledConnection",
    "ReplayResult",
    "evidence_payload",
    "run_all",
    "run_scenario",
    "FRAGMENTATIONS",
    "Scenario",
    "build_scenarios",
    "fragment",
    "EventTrace",
    "redact_headers",
    "MemoryTransport",
    "ReadFailure",
    "make_transport_pair",
    "__version__",
]
