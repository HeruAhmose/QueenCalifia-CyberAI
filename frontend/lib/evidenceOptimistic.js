/**
 * Evidence optimistic helpers for AppLegacy.
 *
 * AppLegacy expects:
 * - `createOptimisticEvidence(payload)` to return `{ tempId, optimistic }`
 * - `replaceOptimisticEvidence(prev, tempId, created)` to swap the temp item
 * - `rollbackOptimisticEvidence(prev, tempId)` to remove the temp item
 */

function makeTempId() {
  return `temp_${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

export function createOptimisticEvidence(payload) {
  const tempId = makeTempId();

  // Keep the object shape compatible with how AppLegacy renders evidence cards.
  const optimistic = {
    ...payload,
    evidence_id: tempId,
  };

  return { tempId, optimistic };
}

export function replaceOptimisticEvidence(prev, tempId, created) {
  if (!Array.isArray(prev)) return Array.isArray(prev) ? prev : [created].filter(Boolean);
  return prev.map((e) => {
    if (!e) return e;
    return e.evidence_id === tempId ? created : e;
  });
}

export function rollbackOptimisticEvidence(prev, tempId) {
  if (!Array.isArray(prev)) return [];
  return prev.filter((e) => e?.evidence_id !== tempId);
}

