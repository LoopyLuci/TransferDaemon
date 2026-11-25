/** Promise helpers shared by the relay and the hole-punch paths. */

/** A promise, and the function that settles it, for a result that some other code produces later. */
export function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

/**
 * The value of `promise`, or `undefined` when `ms` pass first. The promise is not cancelled: a later wait can still take
 * it, which a probe round relies on.
 */
export function valueWithin<T>(promise: Promise<T>, ms: number): Promise<T | undefined> {
  return new Promise<T | undefined>((resolve, reject) => {
    const timer = setTimeout(() => resolve(undefined), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}
