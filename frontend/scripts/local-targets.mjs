// Browser suites are deliberately restricted to disposable loopback services.
export function assertLocalTargets(values) {
  for (const value of values) {
    const u = new URL(value);
    if (
      !["http:", "https:"].includes(u.protocol) ||
      !["localhost", "127.0.0.1", "[::1]"].includes(u.hostname) ||
      u.username ||
      u.password
    )
      throw new Error(
        "Browser tests require loopback service URLs without credentials.",
      );
  }
}
