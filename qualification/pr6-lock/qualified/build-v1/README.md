# Actual workspace compiler evidence and Vite launch failure

At upstream PR6 head `0820278c1cd38e6dd6a1ae38631889041bd6f9ba`, [run 40256371211](https://github.com/citadelculture/pftl-snap/actions/runs/40256371211) executed the candidate with the original root install hook and LavaMoat policy. The overall run failed at the production-build launch. No production build or browser behavior is qualified.

The immutable installation exited 0. The workspace-resolved TypeScript package was 5.0.4; its canonical `bin/tsc` was invoked directly with the pinned Node executable for `--version`, then `--noEmit --project tsconfig.json`. Both exited 0. The package JSON, CLI, compiler implementation and library hashes were checked before and after each invocation and matched across phases. This establishes the direct bound compiler typecheck, not the behavior of an executable shim on PATH.

The unchanged workspace `build` script (`vite build`) exited 128. Its stdout was empty and stderr was exactly `permission denied: vite` followed by a newline. No bundle was verified or included in the evidence. The executable-launch refusal is not evidence of an application compile error, and its underlying path, mode or mount cause is not yet established. No permission, mount or policy workaround was attempted.

The candidate lock remained `7e7d3d81d902cc4af88f38cf3a43eb831eeb20861d9097b23b4859f4844e4340`. All 3,757 original descriptor bodies remained unchanged with 89 additions. [The complete four-file patch and lock](https://github.com/citadelculture/pftl-snap/tree/7dea5dce72aba0455baefce4ddf2a5095d0c2bfe/qualification/pr6-lock/qualified/v1) remain available separately.

Nonempty phase logs are preserved verbatim; zero-length logs use explicitly labeled empty base64 JSON records. The phase logs preserve all warnings, including Yarn compatibility-patch hunk failures for TypeScript 5.0.4 and 4.9.5, peer warnings and disabled dependency-script notices. The successful direct compiler check does not erase those warnings. Cleanup succeeded; no owned container or workload home was retained. Repository Actions were disabled after the terminal run. Historical network-boundary evidence was revalidated as data, not reexecuted in this run.

`result-public.json` removes only the ephemeral Docker daemon identifier from the original result. `provenance.json` records both hashes and the exact normalization. The GitHub artifact digest and original report hash bind the public evidence to the failed run. No adoption or reward is claimed.
