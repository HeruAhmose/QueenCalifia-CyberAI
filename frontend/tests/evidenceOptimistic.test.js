import { describe, expect, it } from "vitest";
import {
  createOptimisticEvidence,
  replaceOptimisticEvidence,
  rollbackOptimisticEvidence,
} from "../lib/evidenceOptimistic.js";

describe("evidence optimistic helpers", () => {
  it("creates an optimistic evidence item", () => {
    const payload = {
      evidence_type: "artifact",
      source: "sensor-1",
      storage_location: "s3://bucket/key",
      hash_sha256: "abc",
      size_bytes: 123,
      notes: "n",
    };

    const { tempId, optimistic } = createOptimisticEvidence(payload, "tmp-1", "2026-02-05T00:00:00.000Z");
    expect(tempId).toBe("tmp-1");
    expect(optimistic).toMatchObject({
      evidence_id: "tmp-1",
      evidence_type: "artifact",
      source: "sensor-1",
      storage_location: "s3://bucket/key",
      hash_sha256: "abc",
      size_bytes: 123,
      notes: "n",
      optimistic: true,
      created_at: "2026-02-05T00:00:00.000Z",
    });
  });

  it("replaces optimistic item on success", () => {
    const list = [{ evidence_id: "tmp-1", optimistic: true }, { evidence_id: "e-2" }];
    const created = { evidence_id: "e-1", source: "server" };
    const out = replaceOptimisticEvidence(list, "tmp-1", created);
    expect(out[0]).toEqual(created);
    expect(out).toHaveLength(2);
  });

  it("rolls back optimistic item on failure", () => {
    const list = [{ evidence_id: "tmp-1", optimistic: true }, { evidence_id: "e-2" }];
    const out = rollbackOptimisticEvidence(list, "tmp-1");
    expect(out).toEqual([{ evidence_id: "e-2" }]);
  });
});
