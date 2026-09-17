export { redact, registerSensitive, clearSensitiveRegistry, containsSecret } from "./redact.js";
export { scanProject, SEVERITY_RANK } from "./scan.js";
export type { Finding, ScanResult, ScanOptions, Severity } from "./scan.js";
export {
  effectivePermissions,
  capabilityAllowed,
  denyReason,
  DEFAULT_PERMISSIONS,
  ALL_SCOPES
} from "./permissions.js";
export type { Capability, PermissionSet, ScopeName } from "./permissions.js";
