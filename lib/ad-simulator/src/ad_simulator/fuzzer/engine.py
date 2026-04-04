"""Fuzzer engine for the AD Simulator.

Orchestrates the execution of fuzz scenarios against a simulated
Active Directory domain, collecting results and timing information.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ad_simulator.fuzzer.scenarios import (
    FuzzResult,
    FuzzScenario,
    get_all_scenarios,
    get_scenario_by_name,
    get_scenarios_by_category,
    run_scenario,
)

if TYPE_CHECKING:
    from ad_simulator.ad.domain import ADDomain

logger = logging.getLogger(__name__)


class FuzzerEngine:
    """Orchestrates fuzz scenario execution against an AD domain.

    Each scenario is run against the provided domain instance.
    Results are accumulated and can be retrieved after execution.

    Attributes:
        domain: The :class:`ADDomain` under test.
    """

    def __init__(self, domain: ADDomain) -> None:
        self._domain = domain
        self._results: list[FuzzResult] = []

    @property
    def domain(self) -> ADDomain:
        """The domain under test."""
        return self._domain

    def run_all(self) -> list[FuzzResult]:
        """Run all registered fuzz scenarios.

        Returns:
            A list of :class:`FuzzResult` objects, one per scenario.
        """
        scenarios = get_all_scenarios()
        results: list[FuzzResult] = []
        for scenario in scenarios:
            logger.info("Running fuzz scenario: %s", scenario.name)
            result = self._run_single(scenario)
            results.append(result)
        self._results.extend(results)
        return results

    def run_by_category(self, category: str) -> list[FuzzResult]:
        """Run all scenarios in a given category.

        Args:
            category: The category to filter by (e.g. ``"protocol"``).

        Returns:
            A list of :class:`FuzzResult` objects.
        """
        scenarios = get_scenarios_by_category(category)
        results: list[FuzzResult] = []
        for scenario in scenarios:
            logger.info("Running fuzz scenario: %s (category=%s)", scenario.name, category)
            result = self._run_single(scenario)
            results.append(result)
        self._results.extend(results)
        return results

    def run_by_name(self, name: str) -> FuzzResult:
        """Run a single scenario by name.

        Args:
            name: The scenario name (e.g. ``"oversized_dn"``).

        Returns:
            A :class:`FuzzResult`.

        Raises:
            ValueError: If no scenario with the given name exists.
        """
        scenario = get_scenario_by_name(name)
        if scenario is None:
            raise ValueError(f"Unknown fuzz scenario: {name!r}")
        logger.info("Running fuzz scenario: %s", name)
        result = self._run_single(scenario)
        self._results.append(result)
        return result

    def get_results(self) -> list[FuzzResult]:
        """Return all accumulated results from previous runs.

        Returns:
            A list of :class:`FuzzResult` objects.
        """
        return list(self._results)

    def clear_results(self) -> None:
        """Clear all accumulated results."""
        self._results.clear()

    def _run_single(self, scenario: FuzzScenario) -> FuzzResult:
        """Run a single scenario and log the result.

        Args:
            scenario: The scenario to execute.

        Returns:
            A :class:`FuzzResult`.
        """
        result = run_scenario(scenario, self._domain)
        status = "PASS" if result.success else "FAIL"
        logger.info(
            "  %s: %s (%.1f ms) — %s",
            status,
            scenario.name,
            result.duration_ms,
            result.details,
        )
        return result
