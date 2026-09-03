/**
 * Convert a live metric pair into a finite display percentage.
 * Missing denominators represent no data, never an arithmetic result.
 */
export function boundedPercent(value, maximum) {
  const numericValue = Number(value);
  const numericMaximum = Number(maximum);

  if (
    !Number.isFinite(numericValue) ||
    !Number.isFinite(numericMaximum) ||
    numericMaximum <= 0
  ) {
    return 0;
  }

  return Math.min(100, Math.max(0, (numericValue / numericMaximum) * 100));
}
