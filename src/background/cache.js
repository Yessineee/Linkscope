
const TTL_MS = 24 * 60 * 60 * 1000 

const cache = new Map()

export function cacheGet(key) {
  const entry = cache.get(key)
  if (!entry) return null
  if (Date.now() - entry.timestamp > TTL_MS) {
    cache.delete(key)
    return null
  }
  return entry.value
}

export function cacheSet(key, value) {
  cache.set(key, {
    value,
    timestamp: Date.now(),
  })
}

export function cacheHas(key) {
  return cacheGet(key) !== null
}

export function cacheClear() {
  cache.clear()
}