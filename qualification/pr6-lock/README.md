# Locked host-lite compiler and production build: finite runtime candidate

This packet has not executed. It derives from independently reviewed closed
preparation v2, with only runtime gates, this description and a separate exact
build admission changed. The manual owned-fork workflow and controller gates are
open for normal review of one execution; source preparation alone does not
publish or dispatch it. admission/build-admission.json expires at
2026-10-26T02:31:00Z and is hash-bound in the workflow and revalidated before every
phase and immediately before package release. The expired install admission is
omitted. Root retains publication, dispatch, approval and result reconciliation.

The source is upstream 0820278c1cd38e6dd6a1ae38631889041bd6f9ba with four exact
changes: the previously qualified Snap-selection fix, TypeScript 5.0.4 pin,
Vite ambient declaration, and the lock generated and immutable-installed by
successful run 40251608388. The lock SHA256 is
7e7d3d81d902cc4af88f38cf3a43eb831eeb20861d9097b23b4859f4844e4340.
All 3,757 old lock entry bodies are unchanged; 89 descriptors were added.

Original root hooks and policies remain unchanged. The new inventory freezes the
qualified lock. The separate build admission binds this four-file payload, while
unchanged network helpers retain the historical boundary's original source and
payload identity. Both historical boundary proof and successful install proof
are hash-bound and checked; neither authorizes build execution by itself.

The finite phase order is immutable install, compiler identity, typecheck, then
production build. The old runner volume was cleaned; a new owned volume needs
an actual immutable installation. No resolution/generate phase, hook shim or
lifecycle-policy override is included.

Compiler phases run through Yarn's host-lite workspace environment:

    node .yarn/releases/yarn-3.2.1.cjs workspace @postfiat/pftl-host-lite exec node /lane/locked-compiler.cjs compiler-identity
    node .yarn/releases/yarn-3.2.1.cjs workspace @postfiat/pftl-host-lite exec node /lane/locked-compiler.cjs typecheck

This explicitly refines the initial exec-tsc contract to record provenance.
The guard resolves the workspace TypeScript 5.0.4 package directly, requires its
actual bin mapping to be {tsc: "./bin/tsc"}, and binds that package's bin/tsc.
Yarn 3.2.1 creates regular temporary shell shims and prepends their directory to
PATH; the guard deliberately does not select, equate or execute that shim.
It records relative real paths and SHA256 of package.json, bin/tsc, lib/tsc.js
and lib/typescript.js, then invokes the exact direct CLI with --version or
--noEmit --project tsconfig.json. Files are compared again after execution;
identity and typecheck bindings must match. A printed version alone cannot pass.
No package is imported by the provenance guard.

The final command invokes the unchanged workspace build script, vite build.
It introduces real esbuild 0.21.5 executable and Rollup 4.65.0 Linux addon use.
That native build scope is explicitly included in this separate finite admission.
No compiler/Python provisioning or disabled-script enablement is included.
Earlier YN0066 TypeScript compatibility-patch and peer warnings remain limits
until actual compiler/build outcomes are available.

The controller preserves local Docker/tool identities, genuine container HOME
and UID 1000, empty capabilities, seccomp/no-new-privileges, inherited controls,
credential exclusions, read-only control mounts, nonce-bound read-only namespace
identity inspection, installed/read-back filtering, fresh per-phase endpoints,
admission expiry rechecks immediately before atomic release, resources and owned
cleanup. Inspector and trusted wait gate extend only explicit phase labels.

All frozen source and lock bytes and modes are checked after each phase. Only
the final phase may create packages/host-lite/dist. Its regular nonempty files
are bounded to 256 files, 8 MiB each, 32 MiB total, hashed and copied to evidence.
The index must reference a local module script; each direct script/link reference
must resolve to a retained nonempty asset within dist. Symlinks, external URLs
and traversal are rejected. These are entry-reference and integrity checks;
no bundle is executed and dynamic browser imports are not qualified.

Next: normal review of this exact public inventory, followed by separately
controlled publication and one manual dispatch before admission expiry. No
publication, dispatch, compiler/build or package execution occurred in preparing
this packet or its pure tests. Browser/provider/wallet/signing and transaction
execution remain outside this workload.
