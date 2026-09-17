export class RateLimiter {
  private readonly hits = new Map<string, number[]>();

  constructor(
    private readonly maxPerMinute = 60,
    private readonly keygenPerHour = 10
  ) {}

  check(tokenId: string, kind: "op" | "keygen" = "op"): boolean {
    const now = Date.now();
    const window = kind === "keygen" ? 60 * 60 * 1000 : 60 * 1000;
    const max = kind === "keygen" ? this.keygenPerHour : this.maxPerMinute;
    const key = `${tokenId}:${kind}`;
    const list = (this.hits.get(key) ?? []).filter((t) => now - t < window);
    if (list.length >= max) {
      this.hits.set(key, list);
      return false;
    }
    list.push(now);
    this.hits.set(key, list);
    return true;
  }
}
