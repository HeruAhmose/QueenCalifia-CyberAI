import React from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import QueenCalifiaV2Perfected from "../QueenCalifia_v2_Perfected.jsx";

function makeHeaders(init = {}) {
  const h = new Map(Object.entries(init).map(([k, v]) => [k.toLowerCase(), v]));
  return { get: (k) => h.get(String(k).toLowerCase()) || null };
}

function makeResponse({ status = 200, json = null, text = null, headers = {} }) {
  const ok = status >= 200 && status < 300;
  return {
    ok,
    status,
    headers: makeHeaders(headers),
    async json() {
      return json ?? {};
    },
    async text() {
      if (text != null) return String(text);
      return json != null ? JSON.stringify(json) : "";
    },
  };
}

function installFetchMock({ postEvidence }) {
  globalThis.fetch = vi.fn(async (url, opts = {}) => {
    const method = String(opts?.method || "GET").toUpperCase();
    const u = String(url);

    if (u.endsWith("/api/dashboard") && method === "GET") {
      return makeResponse({ status: 200, json: { mttd_seconds: 42, mttr_seconds: 3600 } });
    }
    if (u.endsWith("/api/incidents") && method === "GET") {
      return makeResponse({
        status: 200,
        json: {
          incidents: [
            {
              id: "inc-1",
              title: "Test Incident",
              severity: "critical",
              status: "open",
              created_at: "2026-02-05T00:00:00Z",
            },
          ],
        },
      });
    }
    if (u.endsWith("/api/incidents/inc-1") && method === "GET") {
      return makeResponse({
        status: 200,
        json: {
          incident: {
            id: "inc-1",
            title: "Test Incident",
            severity: "critical",
            status: "open",
            response_actions: [],
          },
        },
      });
    }
    if (u.endsWith("/api/incidents/inc-1/evidence") && method === "GET") {
      return makeResponse({ status: 200, json: { data: [] } });
    }
    if (u.endsWith("/api/incidents/inc-1/evidence") && method === "POST") {
      return postEvidence(u, opts);
    }

    return makeResponse({ status: 404, text: "not found" });
  });
}

async function openEvidenceModal(user) {
  await user.click(await screen.findByText("inc-1"));
  await user.click(await screen.findByRole("button", { name: /add evidence/i }));
  expect(screen.getByRole("dialog")).toBeInTheDocument();
}

async function fillEvidenceForm(user, { type, source, location, hash, size, notes }) {
  const dialog = screen.getByRole("dialog");
  const inputs = dialog.querySelectorAll("input, textarea");
  // Inputs are: Type, Source, Storage location, SHA-256, Size, Notes (textarea)
  await user.clear(inputs[0]);
  await user.type(inputs[0], type);
  await user.clear(inputs[1]);
  await user.type(inputs[1], source);
  await user.clear(inputs[2]);
  await user.type(inputs[2], location);
  await user.clear(inputs[3]);
  await user.type(inputs[3], hash);
  await user.clear(inputs[4]);
  await user.type(inputs[4], String(size));
  await user.clear(inputs[5]);
  await user.type(inputs[5], notes);
}

describe("Evidence modal flow (optimistic + rollback)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("optimistically inserts evidence and keeps it after success", async () => {
    installFetchMock({
      postEvidence: async () =>
        makeResponse({
          status: 200,
          json: {
            evidence_id: "ev-1",
            evidence_type: "pcap",
            source: "sensor-1",
            storage_location: "s3://bucket/key",
            hash_sha256: "abc",
            size_bytes: 99,
            notes: "n",
            created_at: "2026-02-05T00:00:01Z",
          },
        }),
    });

    render(<QueenCalifiaV2Perfected />);
    const user = userEvent.setup();

    await openEvidenceModal(user);
    await fillEvidenceForm(user, {
      type: "pcap",
      source: "sensor-1",
      location: "s3://bucket/key",
      hash: "abc",
      size: 99,
      notes: "capture",
    });

    await user.click(screen.getByRole("button", { name: /^add$/i }));

    await screen.findByText(/sensor-1/i);

    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    expect(screen.getByText(/sensor-1/i)).toBeInTheDocument();
  });

  it("optimistically inserts evidence then rolls back on failure", async () => {
    installFetchMock({
      postEvidence: async () => makeResponse({ status: 500, text: "boom" }),
    });

    render(<QueenCalifiaV2Perfected />);
    const user = userEvent.setup();

    await openEvidenceModal(user);
    await fillEvidenceForm(user, {
      type: "artifact",
      source: "sensor-err",
      location: "/vault/case/1",
      hash: "deadbeef",
      size: 1,
      notes: "fail",
    });

    await user.click(screen.getByRole("button", { name: /^add$/i }));

    await screen.findByText(/sensor-err/i);

    await waitFor(() => {
      expect(screen.queryByText(/sensor-err/i)).not.toBeInTheDocument();
    });

    expect(await screen.findByText(/degraded mode/i)).toBeInTheDocument();
  });
});
