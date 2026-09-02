module.exports = {
  images: {
    // Only `allowed.test` is allowlisted. `notallowed.test` is NOT.
    remotePatterns: [{ protocol: 'http', hostname: 'allowed.test' }],
    // Disables ONLY the private-IP guard, not hasRemoteMatch(). This isolates
    // the question: is the redirect target re-checked against remotePatterns?
    dangerouslyAllowLocalIP: true,
  },
}
