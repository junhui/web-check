// In-memory background jobs, so slow checks can reply { pending: true } and be polled
const jobs = new Map();

const DEFAULT_WAIT = 10000;
const DEFAULT_TTL = 10 * 60 * 1000;

// Reuse a running or recently finished job with this key, else start fn(report)
const getJob = (key, fn, ttlMs) => {
  const existing = jobs.get(key);
  if (existing && (!existing.finishedAt || Date.now() - existing.finishedAt < ttlMs)) {
    return existing;
  }
  const job = { startedAt: Date.now(), finishedAt: null, result: null, progress: null };
  const report = (progress) => {
    job.progress = progress;
  };
  job.promise = Promise.resolve()
    .then(() => fn(report))
    .catch((err) => ({ error: err.message }))
    .then((result) => {
      job.result = result;
      job.finishedAt = Date.now();
      setTimeout(() => jobs.get(key) === job && jobs.delete(key), ttlMs).unref?.();
      return result;
    });
  jobs.set(key, job);
  return job;
};

// Wait up to waitMs for the job, then return its result or { pending, elapsed, progress }
export const runJob = async (key, fn, { waitMs = DEFAULT_WAIT, ttlMs = DEFAULT_TTL } = {}) => {
  const job = getJob(key, fn, ttlMs);
  if (job.result) return job.result;
  let timer;
  const wait = new Promise((resolve) => {
    timer = setTimeout(resolve, waitMs);
  });
  const result = await Promise.race([job.promise, wait]);
  clearTimeout(timer);
  if (result) return result;
  return { pending: true, elapsed: Date.now() - job.startedAt, progress: job.progress };
};
