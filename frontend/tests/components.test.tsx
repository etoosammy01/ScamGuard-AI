import React from "react";
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { Scanner } from "../src/components/scanner";
import { Dashboard } from "../src/components/dashboard";
import { ErrorState, LoadingState } from "../src/components/ui";
test("scanner preview disables submissions and explains privacy", () => {
  const html = renderToStaticMarkup(<Scanner />);
  assert.match(html, /disabled=""/);
  assert.match(html, /no analysis is performed/);
  assert.match(html, /Phase 3/);
  assert.doesNotMatch(html, /<form/);
});
test("dashboard marks sample results as fictional", () => {
  const html = renderToStaticMarkup(<Dashboard />);
  assert.match(html, /DEMO DATA/);
  assert.match(html, /No scans have been performed/);
  assert.match(html, /24 high, 18 medium, 86 low/);
});
test("connection loading and error states are accessible", () => {
  assert.match(renderToStaticMarkup(<LoadingState />), /role="status"/);
  assert.match(
    renderToStaticMarkup(<ErrorState>API unavailable</ErrorState>),
    /API unavailable/,
  );
});
