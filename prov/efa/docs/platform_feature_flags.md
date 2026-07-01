# Per-Platform Firmware-Feature Flags

## Overview

Some EFA capabilities are gated by NIC firmware, and that firmware rolls out
to a platform's fleet gradually. This document describes the per-platform
feature-flag mechanism the EFA provider uses to make a **fleet-uniform**
decision about whether such a capability is available, independent of any
individual host's live firmware state.

The mechanism lives in `prov/efa/src/efa_platform_features.{c,h}`.

## Problem Statement

A capability may exist in EFA NIC firmware before that firmware has reached
100% of a platform's fleet. This creates a problem for SPMD applications such
as NCCL/RCCL (via [aws-ofi-nccl](https://github.com/aws/aws-ofi-nccl)): every
rank in a job must make the **same** enable decision, or a collective can
desynchronize.

A per-host runtime capability probe (for example, checking `efadv`
`device_caps` or comparing `inline_buf_size_ex` against `inline_buf_size`) is
therefore unsafe *during* a rollout: it answers differently on upgraded versus
not-yet-upgraded hosts within the same job, which is exactly the inconsistency
that breaks an SPMD collective.

## Solution: A Fleet-Uniform, Per-Platform Decision

Instead of probing the local host, a **platform** (an instance family, matched
by the DMI `product_name`) statically declares which firmware features are
known to be deployed fleet-wide. A feature is turned on for a platform (and the
provider recompiled) only once that platform's rollout is confirmed complete.
The result is a deterministic answer that is identical across every host in the
fleet, and it deliberately ignores the local host's live firmware state.

This is intentionally a **different signal** from the live per-host
`efa_device_support_*()` helpers, which report what the current NIC can do.
Use the per-host helpers when a per-host answer is correct (e.g. a
single-process application). Use the platform flag when a fleet-uniform answer
is required.

## Feature Identifiers

Features are bit positions in a `uint64_t` mask, defined by
`enum efa_platform_feature`. The enum is **append-only**: each value is a
permanent, distinct bit position, so builds of different components stay in
sync.

| Feature | Token | Polarity | Description |
|---|---|---|---|
| `EFA_PLATFORM_FEATURE_HW_CNTR` | `HW_CNTR` | opt-in | EFA hardware completion counter in device/GPU memory. Backs `efa_env.use_hw_cntr`. |
| `EFA_PLATFORM_FEATURE_WIDE_WQE` | `WIDE_WQE` | opt-out | Wide (128-byte) WQE / large inline write (`efadv` `inline_buf_size_ex`). Replaces the live per-host wide-WQE probe. |

The token is used in the override environment variables (see below) and must
stay in sync with the enum via `efa_platform_feature_name()`.

## Polarity: Opt-In vs. Opt-Out

Features come in two polarities, so the mechanism supports both:

- **Opt-in** (default off): the feature is off on every platform and is turned
  **on** only for platforms that explicitly list it. Used for capabilities that
  are not yet broadly deployed. `HW_CNTR` is opt-in.
- **Opt-out** (default on): the feature is on fleet-wide by default (listed in
  `efa_platform_default_on_features`) and is turned **off** only for platforms
  that explicitly opt out, because their firmware rollout is not yet complete.
  Used for broadly deployed capabilities. `WIDE_WQE` is opt-out.

Each entry in the platform table carries two masks, `opt_in` and `opt_out`, and
the effective per-platform default is:

```
(efa_platform_default_on_features & ~opt_out) | opt_in
```

A platform with no table entry (including an unknown or unreadable
`product_name`) receives exactly `efa_platform_default_on_features`.

## Decision Order

`efa_platform_has_feature(feature)` resolves a query in this order (highest
precedence first):

1. **`FI_EFA_DISABLE_FEATURES`** — a kill switch. If the feature's token is
   listed, the answer is **off**, regardless of anything else.
2. **`FI_EFA_FORCE_FEATURES`** — an early-enable override. If the feature's
   token is listed (and it is not disabled), the answer is **on**, regardless
   of the platform default.
3. **The per-platform default** — the computed `(default_on & ~opt_out) |
   opt_in` value for the matched platform.

`DISABLE` beats `FORCE`, and both beat the platform default.

## Environment Variables

Both variables take a comma- or space-separated list of feature tokens and are
registered via `fi_param_define`, so they appear in `fi_info -e`.

| Variable | Effect |
|---|---|
| `FI_EFA_FORCE_FEATURES` | Force the listed features **on**, overriding the platform default. Use only on a fleet known to have the firmware. |
| `FI_EFA_DISABLE_FEATURES` | Force the listed features **off** (kill switch). Highest precedence. |

Unknown tokens are logged (`EFA_WARN`) and ignored. The variables are parsed
once and cached.

### Examples

```bash
# Disable wide WQE everywhere (kill switch)
export FI_EFA_DISABLE_FEATURES=WIDE_WQE

# Force the hardware completion counter on for testing
export FI_EFA_FORCE_FEATURES=HW_CNTR

# Multiple features at once (comma or space separated)
export FI_EFA_DISABLE_FEATURES="WIDE_WQE HW_CNTR"
export FI_EFA_FORCE_FEATURES=HW_CNTR,WIDE_WQE
```

## Platform Matching

The running platform is identified by reading
`/sys/devices/virtual/dmi/id/product_name` and matching it against the
`name_prefix` of each entry in `efa_platform_table[]` (case-insensitive prefix
match). The EFA provider already relies on `/sys/devices/virtual/dmi/id/` for
the host id, so this is consistent with existing behavior. Matching is
best-effort: if the file cannot be read, the name is empty and no
platform-specific entry matches, so only the default-on baseline applies.

## Consumers

The flag currently gates two capabilities:

- **`HW_CNTR`** drives the default value of `efa_env.use_hw_cntr` (in
  `efa_env_unregistered_param_get()`). An explicit `FI_EFA_USE_HW_CNTR`
  environment variable still overrides the platform default in either
  direction.
- **`WIDE_WQE`** is consulted by `efa_device_support_wide_wqe()` and gates the
  wide-WQE code paths: the advertised `inject_size` in `efa_prov_info.c`, the
  extended inline-write QP flag in `efa_base_ep.c`, the inject-size hint path in
  `efa_user_info.c`, and the `FI_OPT_INJECT_MSG_SIZE` / `FI_OPT_INJECT_RMA_SIZE`
  `fi_setopt` calls in `efa_ep.c`. When wide WQE is disabled and an application
  requests an inject size larger than the device's base `inline_buf_size`, the
  request is rejected (`-FI_ENODATA` at `fi_getinfo`, `-FI_EINVAL` at
  `fi_setopt`).

## Adding a New Feature

1. Append a new `EFA_PLATFORM_FEATURE_*` bit to `enum efa_platform_feature`
   (never reuse or renumber an existing bit).
2. Add its token to `efa_platform_feature_name()` and to the
   `efa_platform_all_features[]` array.
3. Decide its polarity: for opt-out, add the bit to
   `efa_platform_default_on_features`; for opt-in, leave it out.
4. Set the appropriate `opt_in` / `opt_out` masks on the relevant entries in
   `efa_platform_table[]`.
5. Gate the consuming code path on `efa_platform_has_feature(<bit>)`.
6. Add unit tests in `prov/efa/test/efa_unit_test_platform_features.c`.

## Design Note: Why Not a Per-Host Probe?

libfabric can report per-host firmware capability, but that is the wrong signal
during a rollout: it is inconsistent across a heterogeneous fleet, which is
precisely what breaks an SPMD collective. The per-platform gate is the
consistency anchor; a per-host probe is intentionally **not** combined into the
enable decision, because doing so would reintroduce the inconsistency. This
mechanism is a stopgap until firmware rollout can be coordinated fleet-wide.
