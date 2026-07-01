/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_PLATFORM_FEATURES_H
#define EFA_PLATFORM_FEATURES_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Per-platform firmware-feature flags for staged rollouts.
 *
 * A capability may exist in EFA NIC firmware before that firmware has
 * reached 100%% of a platform's fleet. Some libfabric consumers (notably
 * NCCL/RCCL via aws-ofi-nccl) are SPMD: every rank in a job must make the
 * same enable decision, or a collective can desynchronize. A per-host
 * runtime capability probe (efadv device_caps / EFADV_DEVICE_ATTR_CAPS_*)
 * is therefore unsafe during a rollout -- it answers differently on
 * upgraded vs. not-yet-upgraded hosts.
 *
 * This mechanism lets a *platform* (instance family, matched by the DMI
 * product_name) statically declare which firmware features are known to be
 * deployed fleet-wide. A feature is turned on for a platform (and the
 * provider recompiled) only once its rollout is confirmed complete, giving
 * a deterministic, fleet-uniform answer that deliberately ignores any one
 * host's live device_caps.
 *
 * NOTE: this is intentionally a *different* signal from the existing
 * efa_device_support_*() helpers, which report live per-host capability.
 * Use efa_device_support_*() when the per-host answer is correct (e.g. a
 * single-process app deciding what this NIC can do). Use
 * efa_platform_has_feature() only when a fleet-uniform answer is required.
 *
 * Values are bit positions in a uint64_t mask; keep them distinct.
 */
enum efa_platform_feature {
	EFA_PLATFORM_FEATURE_NONE         = 0,
	/*
	 * EFA hardware completion counter in device/GPU memory (efadv
	 * hardware-counter path, gated by NIC firmware advertised through
	 * efadv device_caps). Backs efa_env.use_hw_cntr.
	 *
	 * Polarity: opt-IN. Off everywhere except platforms that list it.
	 */
	EFA_PLATFORM_FEATURE_HW_CNTR      = 1ULL << 0,
	/*
	 * Wide (128-byte) WQE / large inline write support (efadv
	 * inline_buf_size_ex, gated by NIC firmware). Replaces the live
	 * per-host efa_device_support_wide_wqe() probe with a fleet-uniform
	 * answer.
	 *
	 * Polarity: opt-OUT. Enabled fleet-wide by default (listed in
	 * efa_platform_default_on_features) and turned off only on platforms
	 * whose firmware rollout is not complete.
	 */
	EFA_PLATFORM_FEATURE_WIDE_WQE     = 1ULL << 1,
	/* append new features here; keep bits distinct and append-only */
};

/**
 * @brief Query whether a firmware-gated feature is enabled for the running
 *        platform.
 *
 * Returns a fleet-uniform, per-platform answer (not a per-host probe).
 * Decision order (highest precedence first):
 *   1. FI_EFA_DISABLE_FEATURES env -> force OFF (kill switch)
 *   2. FI_EFA_FORCE_FEATURES   env -> force ON  (early-enable / testing)
 *   3. the matched platform's static enabled_features bitmask (default off)
 *
 * Unknown / unmatched platform => false (conservative: assume no firmware
 * feature). The override env vars are parsed once and cached.
 *
 * @param[in] feature  a single efa_platform_feature bit
 * @return    true if the feature should be treated as enabled
 */
bool efa_platform_has_feature(uint64_t feature);

/**
 * @brief Map a feature bit to the token accepted in
 *        FI_EFA_FORCE_FEATURES / FI_EFA_DISABLE_FEATURES.
 *
 * @return the static token string, or NULL for an unknown / NONE feature.
 */
const char *efa_platform_feature_name(uint64_t feature);

/**
 * @brief Reset the cached override + platform state. Test-only.
 */
void efa_platform_features_reset_cache(void);

#endif /* EFA_PLATFORM_FEATURES_H */
