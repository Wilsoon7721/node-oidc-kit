/**
 * The polling vocabulary shared by the device grant (RFC 8628) and method escalation.
 * Only the provider can move a request out of `pending`, so a local timer is a courtesy to the user rather than a verdict.
 * Where the two disagree - a user finishing at 299 seconds against a client that gave up at 298 - the server is right.
 */

/** The provider is still waiting for the user. Keep polling. */
export const AUTHORIZATION_PENDING = "authorization_pending";
/** Polling faster than the advertised interval. Adopt the interval the provider returned. */
export const SLOW_DOWN = "slow_down";
/** The request passed its deadline. Terminal, and only the server may say so. */
export const EXPIRED_TOKEN = "expired_token";
/** The user refused. Terminal. */
export const ACCESS_DENIED = "access_denied";

/** The four terminal-or-continue outcomes a poll can report. */
export type PollErrorCode = typeof AUTHORIZATION_PENDING | typeof SLOW_DOWN | typeof EXPIRED_TOKEN | typeof ACCESS_DENIED;

/** How a single poll resolved. */
export type PollStep<T> =
  /** The flow finished successfully. */
  | { readonly state: "done"; readonly value: T }
  /** Not finished; poll again after `interval` seconds. */
  | { readonly state: "pending"; readonly interval: number; readonly slowDown: boolean; readonly expiresAt?: number };

/** Progress reported to {@link PollOptions.onPending} before each wait. */
export interface PollProgress {
  /** How many polls have been made so far, including the one that just returned. */
  attempt: number;
  /** Seconds the loop is about to wait. */
  interval: number;
  /** Whether the provider asked us to back off, having raised the interval itself. */
  slowDown: boolean;
  /** The server's deadline, in seconds since the epoch, when it reported one. */
  expiresAt?: number;
}

/** Options common to every polled flow. */
export interface PollOptions {
  /** Aborts the wait and rejects with the signal's reason. */
  signal?: AbortSignal;
  /**
   * Called before each wait, so a CLI can show progress.
   * Throwing from it aborts the loop, which is a reasonable way to implement a cancel.
   */
  onPending?: (progress: PollProgress) => void;
  /**
   * A local safety net, in seconds, after which the loop stops polling (default: none).
   * Off by default on purpose. The server already enforces the real deadline and reports `expired_token` when it passes.
   * A client-side limit that fires first turns a server-authoritative answer into a guess. Set it only to bound a hung process.
   */
  maxWaitSeconds?: number;
}

/** Injectable clock and timer, so tests do not have to wait in real time. */
export interface PollClock {
  now(): number;
  sleep(ms: number, signal?: AbortSignal): Promise<void>;
}

export const realClock: PollClock = {
  now: () => Date.now(),
  sleep: (ms, signal) =>
    new Promise<void>((resolve, reject) => {
      if (signal?.aborted) return reject(signal.reason);

      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, ms);

      const onAbort = () => {
        clearTimeout(timer);
        reject(signal?.reason);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
    }),
};

/**
 * Drives a polled flow to an answer.
 *
 * `step` performs one poll. It must resolve to `done` or `pending`, and throw for anything terminal - a denial, an expiry, or a protocol error.
 * This loop deliberately does not catch the errors.
 *
 * @param step Performs one poll.
 * @param initialInterval Seconds to wait between polls, until the provider says otherwise.
 * @throws {Error} The signal's reason if aborted, or whatever `step` threw.
 */
export async function pollUntilResolved<T>(step: (attempt: number) => Promise<PollStep<T>>, initialInterval: number, options: PollOptions = {}, clock: PollClock = realClock): Promise<T> {
  const startedAt = clock.now();
  let interval = Math.max(1, initialInterval || 5);
  let attempt = 0;

  for (;;) {
    if (options.signal?.aborted) throw options.signal.reason;

    attempt += 1;
    const result = await step(attempt);
    if (result.state === "done") return result.value;

    interval = Math.max(interval, Math.max(1, result.interval || interval));

    if (options.maxWaitSeconds !== undefined) {
      const elapsed = (clock.now() - startedAt) / 1000;
      if (elapsed + interval > options.maxWaitSeconds) {
        throw new Error(`Gave up waiting after ${Math.round(elapsed)}s (maxWaitSeconds: ${options.maxWaitSeconds}). The request may still be live at the provider.`);
      }
    }

    options.onPending?.({ attempt, interval, slowDown: result.slowDown, expiresAt: result.expiresAt });
    await clock.sleep(interval * 1000, options.signal);
  }
}
