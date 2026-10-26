# Vite launch diagnostics: proposed finite runtime

This packet adds read-only diagnostics around the original Yarn workspace build
command. This new candidate has not run and awaits separate normal execution
review. The manual owned-fork workflow and controller gates are enabled only for
that review of one finite attempt. A newly created exact build admission expires
at 2026-10-26T03:25:00Z; its SHA is bound in the workflow and checked before every
phase and immediately before release. The previous 02:31 admission remains in
its preserved prior candidate and is not reused or extended. Historical boundary
and original-install proofs remain data; neither admits this execution alone.

[Actual run 40256371211](https://github.com/citadelculture/pftl-snap/actions/runs/40256371211)
at `b64678eccf02575b625bde37d0b8f5f828afc401` completed immutable install,
compiler identity and typecheck with exit 0. The compiler guard bound the actual
workspace TypeScript 5.0.4 package and implementation bytes. The production-build
phase exited 128 with empty stdout and exactly `permission denied: vite` on
stderr. Cleanup was verified. The full build remains unqualified, and the
EACCES cause is unproven. That original result is preserved separately.

The new module records metadata for eight fixed Node, shell, Yarn and Vite paths:
lstat facts, reviewed real paths and ancestor modes, UID/GID, device/inode and
file type. It reads `/proc/self/mountinfo` within explicit byte/line bounds and
retains the longest covering mount's filesystem type and safe mount options.
Host mount source/root paths, arbitrary option values and package contents are
not emitted. Resolved paths outside reviewed roots are redacted. Missing
`noexec` is not replaced with an assumed default.

Pinned Yarn 3.2.1 source constructs temporary executable shell wrappers and
prepends their directory to script PATH. The observer therefore watches only
canonical nonsymlink `/tmp/xfs-*` directories for `vite` metadata. It limits
directory enumeration, watched directories, event count and retained snapshots,
then closes its watchers. These events are best effort: an unobserved ephemeral
shim is inconclusive. No temporary file contents are read or changed.

After the original child exits, one bounded `PFTL_BUILD_LAUNCH_DIAGNOSTIC` JSON
line goes to stdout. Existing `*.stdout` artifact collection retains it as data;
it is not evaluated or treated as a runtime authorization. Stderr, exit status
and signal forwarding remain those of the original command. Diagnostic failure
does not substitute a command or change its exit status.

The original launch remains:

    node .yarn/releases/yarn-3.2.1.cjs workspace @postfiat/pftl-host-lite build

There is no direct-node Vite substitute, chmod, mount change, TMPDIR override,
inherited-control change, root-hook change or extra package execution. The
controller pins both the diagnostic module and updated wrapper before and
after every phase. Its other executable behavior is unchanged.

The source remains upstream `0820278c1cd38e6dd6a1ae38631889041bd6f9ba` with the
same qualified Snap-selection correction, host-lite TypeScript 5.0.4 pin, Vite
ambient declaration and lock. Lock SHA256 remains
`7e7d3d81d902cc4af88f38cf3a43eb831eeb20861d9097b23b4859f4844e4340`.
The finite phase order, compiler provenance checks, original policies, source
integrity checks and dist rules are unchanged.

Local Docker/tool identity checks, genuine container HOME and UID 1000, empty
capabilities, seccomp/no-new-privileges, inherited controls, credential
exclusions, read-only control mounts, nonce-bound namespace inspection,
installed/read-back filtering, per-phase endpoints, expiry checks, resource
bounds and owned cleanup are unchanged. No earlier admission is modified or
extended by this new candidate. This separately prepared finite runtime
candidate requires normal publication and execution review before any attempt;
the diagnostics alone authorize nothing.

Source preparation and pure tests establish no new package or native execution,
Vite build, browser/provider/wallet/signing/transaction behavior or Sharp native
load. Any permission or mount correction must follow actual causal evidence.
