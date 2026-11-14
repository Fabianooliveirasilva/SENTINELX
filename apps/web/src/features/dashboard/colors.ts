/**
 * Chart colours. Hex equivalents of the theme tokens (SVG presentation
 * attributes cannot read CSS variables), each set validated with the dataviz
 * palette validator against the chart surface #0c141e (dark):
 *
 * - SEVERITY (ordinal status, always labelled): adjacent CVD ΔE ≥ 12.3,
 *   normal-vision ΔE ≥ 16.0, contrast ≥ 3:1. Mirrors --severity-* in globals.css.
 * - SCAN_STATUS (state, legend + labels): CVD ΔE ≥ 11.3, normal ΔE ≥ 23.2.
 * - REMEDIATION (two categorical series, reference dark slots 1 and 3): all
 *   checks pass (CVD ΔE 19.6, normal ΔE 20.9).
 */
export const SEVERITY_COLORS = {
  critical: "#e6293f",
  high: "#f67f2f",
  medium: "#f0cf4c",
  low: "#3186e9",
  info: "#95a0ab",
} as const;

export const SCAN_STATUS_COLORS = { completed: "#41ce90", failed: "#f54748", cancelled: "#95a0ab" } as const;

export const REMEDIATION_COLORS = { opened: "#3987e5", resolved: "#199e70" } as const;

export const SERIES_PRIMARY = "#22cde5"; // --primary, single-series line and bars

// Recessive chrome.
export const GRID = "#243041";
export const AXIS_TEXT = "#9aa4b2";
