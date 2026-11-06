import React from "react";
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import {
  BucketChart,
  StatusDialog,
  AIFallbackSummary,
} from "../src/components/admin-console";
test("analytics displays measured counts and calculated percentages with accessible meters", () => {
  const html = renderToStaticMarkup(
    <BucketChart
      rows={[
        { label: "message", count: 3 },
        { label: "url", count: 1 },
      ]}
    />,
  );
  assert.match(html, /75.0%/);
  assert.match(html, /25.0%/);
  assert.match(html, /aria-label="message: 3"/);
  assert.match(renderToStaticMarkup(<BucketChart rows={[]} />), /No activity/);
});
test("suspension confirmation explains session revocation and provides cancel", () => {
  const user = {
    id: "fixture",
    email: "fixture@example.invalid",
    full_name: "Fixture",
    role: "user",
    status: "active",
    created_at: "2026-01-01",
  };
  const html = renderToStaticMarkup(
    <StatusDialog
      user={user}
      saving={false}
      onCancel={() => {}}
      onConfirm={() => {}}
    />,
  );
  assert.match(html, /role="dialog"/);
  assert.match(html, /aria-modal="true"/);
  assert.match(html, /Active sessions will be revoked/);
  assert.match(html, /Cancel/);
  assert.match(html, /Confirm status change/);
  const reactivate = renderToStaticMarkup(
    <StatusDialog
      user={{ ...user, status: "suspended" }}
      saving={true}
      onCancel={() => {}}
      onConfirm={() => {}}
    />,
  );
  assert.match(reactivate, /Revoked sessions remain invalid/);
  assert.match(reactivate, /disabled/);
});

test("fallback rate excludes rules-only requests and labels its measured denominator", () => {
  const html = renderToStaticMarkup(
    <AIFallbackSummary
      rows={[
        { label: "not_requested", count: 100 },
        { label: "completed", count: 2 },
        { label: "disabled", count: 1 },
        { label: "unavailable", count: 1 },
      ]}
    />,
  );
  assert.match(html, /50.0% \(2 of 4\)/);
  assert.match(html, /not a provider error rate/);
  assert.match(
    renderToStaticMarkup(<AIFallbackSummary rows={[]} />),
    /No retained hybrid requests/,
  );
});
