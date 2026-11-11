import { test } from "node:test";
import assert from "node:assert/strict";

import {
  impersonateFetch,
  ImpersonateUnavailableError,
  ResourceTooLargeError,
} from "../src/fetch.js";

test("impersonateFetch throws ImpersonateUnavailableError when WEBCRAWL_IMPERSONATE_BIN points nowhere", async () => {
  const prev = process.env.WEBCRAWL_IMPERSONATE_BIN;
  process.env.WEBCRAWL_IMPERSONATE_BIN = "/nonexistent/curl-impersonate-path";
  try {
    await assert.rejects(
      () => impersonateFetch("https://example.com/"),
      ImpersonateUnavailableError
    );
  } finally {
    if (prev === undefined) delete process.env.WEBCRAWL_IMPERSONATE_BIN;
    else process.env.WEBCRAWL_IMPERSONATE_BIN = prev;
  }
});

test("ResourceTooLargeError message formats MB", () => {
  const e = new ResourceTooLargeError(150 * 1e6, 100 * 1e6);
  assert.match(e.message, /150\.0 MB/);
  assert.match(e.message, /100 MB/);
  assert.equal(e.name, "ResourceTooLargeError");
});
