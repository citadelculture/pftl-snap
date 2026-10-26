# Qualified candidate workspace lock

This supplement completes the previously incomplete lock candidate for PR6 at `0820278c1cd38e6dd6a1ae38631889041bd6f9ba`. It combines the reviewed host-lite App identity correction, host-lite TypeScript5.0.4 and Vite client type reference with the generated root lock. The portable four-file patch is included; the full lock is also provided for direct byte verification.

Actual [hosted run40251608388](https://github.com/citadelculture/pftl-snap/actions/runs/40251608388) completed both pinned Yarn3.2.1 `install --no-immutable` and `install --immutable` with exit0 using the original root hook and LavaMoat policy. Both logs record the lifecycle runner's Sharp install step. The immutable phase retained candidate lock SHA256 `7e7d3d81d902cc4af88f38cf3a43eb831eeb20861d9097b23b4859f4844e4340`. Original dependency resolutions/checksums and root/site/snap workspace records were preserved. Owned runner resources were cleaned up and repository Actions were disabled after reconciliation.

Both commands completed **with warnings**. Generation reports Yarn builtin TypeScript compatibility-patch hunk failures for5.0.4 and4.9.5; peer-dependency warnings also remain. This result qualifies the lock and actual immutable original-hook installation. It does not establish a resolved-workspace TypeScript check, Vite build, Sharp native-load, real provider, wallet or transaction result. Those require separate executed validation.

The exact control source, frozen candidate input and confinement proof are pinned by provenance.json. The original first install attempt failed before packages at a namespace-identity permission check; that failure remains preserved in run40250501517. The successful revision used a narrow read-only privileged inspector while retaining an unprivileged controller and existing filter/release checks.

No reward or upstream adoption is claimed. See the byte-preserved stdout logs, normalized result, explicit empty-stderr record, provenance and independent data audit for the precise evidence and limits.
