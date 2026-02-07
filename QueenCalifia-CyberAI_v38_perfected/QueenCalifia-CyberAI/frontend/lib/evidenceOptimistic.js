/**
 * Pure helpers for Evidence optimistic UI.
 *
 * Used by the dashboard and unit-tested (Vitest).
 */

export function createOptimisticEvidence(payload, tempId = undefined, nowIso = undefined) {
  const id = tempId || `tmp-${Date.now()}`;
  const createdAt = nowIso || new Date().toISOString();

  const optimistic = {
    evidence_id: id,
    evidence_type: payload?.evidence_type || "artifact",
    source: payload?.source || "—",
    storage_location: payload?.storage_location || "—",
    hash_sha256: payload?.hash_sha256 || "—",
    size_bytes: Number(payload?.size_bytes || 0) || 0,
    notes: payload?.notes || "",
    created_at: createdAt,
    optimistic: true,
  };

  return { tempId: id, optimistic };
}

export function replaceOptimisticEvidence(list, tempId, created) {
  const arr = Array.isArray(list) ? list : [];
  return arr.map((x) => (x?.evidence_id === tempId ? created : x));
}

export function rollbackOptimisticEvidence(list, tempId) {
  const arr = Array.isArray(list) ? list : [];
  return arr.filter((x) => x?.evidence_id !== tempId);
}
