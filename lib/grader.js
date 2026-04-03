// Security grading engine — analyzes fuzzer results and produces a pass/fail report
//
// Per-scenario finding:
//   PASS  — behavior matched expectations, target handled it securely
//   FAIL  — server accepted malicious input it should have rejected, or crashed
//   WARN  — server was stricter than expected (dropped when PASSED was expected)
//   INFO  — no expected value set, informational only
//
// Overall grade:
//   A — All tests pass, no crashes, all CVEs rejected
//   B — No critical/high failures, minor warnings only
//   C — No critical failures, some high/medium issues
//   D — High-severity failures present
//   F — Critical CVE accepted or host crashed

const { LDAP_CATEGORY_SEVERITY } = require('./ldap/scenarios');

/**
 * Normalize a response string for comparison
 */
function normalizeResponse(res) {
  if (!res) return '';
  let s = res.trim();
  s = s.replace(/\s*\(\d+\s+bytes\)/g, '');
  return s.trim();
}

/**
 * Classify a response string into a behavioral category for semantic matching.
 * Returns 'accepted', 'rejected', or 'unknown'.
 */
function classifyBehavior(response, status) {
  if (!response && !status) return 'unknown';
  const r = (response || '').trim();
  const s = (status || '').trim();

  // Rejection signals
  if (s === 'DROPPED' || s === 'TIMEOUT') return 'rejected';
  if (/Connection closed/i.test(r)) return 'rejected';
  if (/^Connection reset/i.test(r)) return 'rejected';
  // LDAP rejection signals
  if (/invalidCredentials/i.test(r)) return 'rejected';
  if (/protocolError/i.test(r)) return 'rejected';
  if (/unwillingToPerform/i.test(r)) return 'rejected';
  if (/insufficientAccessRights/i.test(r)) return 'rejected';
  if (/authMethodNotSupported/i.test(r)) return 'rejected';
  if (/strongerAuthRequired/i.test(r)) return 'rejected';
  if (/operationsError/i.test(r)) return 'rejected';
  if (s === 'ldap-error-response') return 'rejected';

  // Acceptance signals
  if (s === 'PASSED') return 'accepted';
  // LDAP acceptance signals
  if (/BindResponse\(success\)/i.test(r)) return 'accepted';
  if (/SearchResultDone\(success\)/i.test(r)) return 'accepted';
  if (/SearchResultEntry/i.test(r)) return 'accepted';

  return 'unknown';
}

/**
 * Analyze a single scenario result and produce a security finding
 */
function gradeResult(result, scenarioMeta) {
  const category = scenarioMeta ? scenarioMeta.category : null;
  const severity = category ? (LDAP_CATEGORY_SEVERITY[category] || 'low') : 'low';
  const expected = result.expected || (scenarioMeta ? scenarioMeta.expected : null);
  const status = result.status;
  const effective = status === 'TIMEOUT' ? 'DROPPED' : status;

  // Host crashed — always a critical failure
  if (result.hostDown) {
    return {
      grade: 'FAIL',
      severity: 'critical',
      reason: 'Target became unreachable — possible crash/DoS',
    };
  }

  // No expected value — informational
  if (!expected) {
    return { grade: 'INFO', severity, reason: 'No expected value defined' };
  }

  // Aborted / Error — skip grading
  if (status === 'ERROR' || status === 'ABORTED') {
    return { grade: 'INFO', severity, reason: `Scenario ${status.toLowerCase()}` };
  }

  // Server accepted input it should have rejected — security failure
  if (expected === 'DROPPED' && effective === 'PASSED') {
    return {
      grade: 'FAIL',
      severity,
      reason: 'Server accepted malicious/malformed input that should be rejected',
    };
  }

  // Server rejected input it should have accepted — compatibility issue
  if (expected === 'PASSED' && effective === 'DROPPED') {
    return {
      grade: 'WARN',
      severity,
      reason: 'Server rejected valid input — stricter than expected',
    };
  }

  // Matched expectations
  return { grade: 'PASS', severity, reason: null };
}

/**
 * Compute overall grade from all graded results
 */
function computeOverallGrade(gradedResults) {
  const stats = { pass: 0, fail: 0, warn: 0, info: 0 };
  const failsBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const findings = [];

  for (const r of gradedResults) {
    const g = r.finding;
    if (!g || typeof g === 'string') {
      const mapped = (typeof g === 'string') ? g : 'info';
      const gradeKey = (mapped === 'pass') ? 'pass' : (mapped === 'error' || mapped === 'timeout') ? 'fail' : 'info';
      stats[gradeKey] = (stats[gradeKey] || 0) + 1;
      if (gradeKey === 'fail') {
        failsBySeverity['medium'] = (failsBySeverity['medium'] || 0) + 1;
        findings.push({
          scenario: r.scenario,
          severity: 'medium',
          reason: r.response || mapped,
          status: r.status,
          category: r.category,
        });
      }
      continue;
    }
    const grade = g.grade || 'INFO';
    stats[grade.toLowerCase()] = (stats[grade.toLowerCase()] || 0) + 1;
    if (grade === 'FAIL') {
      failsBySeverity[g.severity || 'medium'] = (failsBySeverity[g.severity || 'medium'] || 0) + 1;
      findings.push({
        scenario: r.scenario,
        severity: g.severity || 'medium',
        reason: g.reason || 'Unknown failure',
        status: r.status,
        category: r.category,
      });
    }
  }

  const sevWeight = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => sevWeight[a.severity] - sevWeight[b.severity]);

  let grade, label;

  if (failsBySeverity.critical > 0) {
    grade = 'F';
    label = 'Critical vulnerabilities detected';
  } else if (gradedResults.some(r => r.hostDown)) {
    grade = 'F';
    label = 'Target crashed during testing';
  } else if (failsBySeverity.high > 0) {
    grade = 'D';
    label = 'High-severity protocol violations accepted';
  } else if (failsBySeverity.medium > 2) {
    grade = 'C';
    label = 'Multiple medium-severity issues';
  } else if (failsBySeverity.medium > 0 || failsBySeverity.low > 2) {
    grade = 'B';
    label = 'Minor issues detected';
  } else if (stats.warn > gradedResults.length * 0.3) {
    grade = 'B';
    label = 'Mostly secure, some strict rejections';
  } else {
    grade = 'A';
    label = 'All tests passed — robust LDAP implementation';
  }

  return { grade, label, findings, stats, failsBySeverity };
}

module.exports = { gradeResult, computeOverallGrade, normalizeResponse, classifyBehavior };
