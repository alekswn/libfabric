/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <ofi.h>
#include <stdio.h>
#include <string.h>

#include "efa_prov.h"
#include "efa_platform_features.h"

/*
 * Features that are enabled fleet-wide by DEFAULT (opt-out polarity). A
 * platform gets these unless it lists the same bit in its opt_out mask
 * below. Features NOT in this baseline are off by default (opt-in
 * polarity) and are turned on only by a platform's opt_in mask.
 */
static const uint64_t efa_platform_default_on_features =
	EFA_PLATFORM_FEATURE_WIDE_WQE;

/*
 * The platform table. Each entry is one "column": an instance platform
 * matched against the DMI product_name (/sys/class/dmi/id/product_name) by
 * prefix, with two masks:
 *
 *   opt_in  - OR of opt-IN feature bits (off by default) to turn ON for
 *             this platform, once their firmware is confirmed fleet-wide.
 *   opt_out - OR of default-ON feature bits to turn OFF for this platform,
 *             because their firmware rollout is NOT yet complete here.
 *
 * The effective per-platform default is:
 *     (efa_platform_default_on_features & ~opt_out) | opt_in
 *
 * A platform with no entry gets exactly efa_platform_default_on_features.
 */
struct efa_platform_entry {
	const char *name_prefix;   /* DMI product_name prefix, e.g. "p5en" */
	uint64_t opt_in;           /* opt-in bits to enable here */
	uint64_t opt_out;          /* default-on bits to disable here */
};

static const struct efa_platform_entry efa_platform_table[] = {
	/* HW completion counter firmware is deployed on the P5en and P6-B200
	 * fleets (opt-in). */
	{ "p5en",       EFA_PLATFORM_FEATURE_HW_CNTR, 0 },
	{ "p6-b200",    EFA_PLATFORM_FEATURE_HW_CNTR, 0 },
	/* Wide WQE is on fleet-wide by default; opt these platforms OUT until
	 * their wide-WQE firmware rollout is confirmed complete. */
	{ "p6e-gb200",  0, EFA_PLATFORM_FEATURE_WIDE_WQE },
	{ "g7",         0, EFA_PLATFORM_FEATURE_WIDE_WQE },
};

/* All known features, for token <-> bit matching. Keep in sync with
 * enum efa_platform_feature and efa_platform_feature_name(). */
static const uint64_t efa_platform_all_features[] = {
	EFA_PLATFORM_FEATURE_HW_CNTR,
	EFA_PLATFORM_FEATURE_WIDE_WQE,
};

/* ---- cached state (parsed once) ---------------------------------------- */

static bool efa_platform_init_done = false;
static uint64_t efa_platform_default_features = 0; /* from matched platform */
static uint64_t efa_platform_force_features = 0;   /* FI_EFA_FORCE_FEATURES */
static uint64_t efa_platform_disable_features = 0; /* FI_EFA_DISABLE_FEATURES */

const char *efa_platform_feature_name(uint64_t feature)
{
	switch (feature) {
	case EFA_PLATFORM_FEATURE_HW_CNTR:
		return "HW_CNTR";
	case EFA_PLATFORM_FEATURE_WIDE_WQE:
		return "WIDE_WQE";
	case EFA_PLATFORM_FEATURE_NONE:
	default:
		return NULL;
	}
}

/*
 * Read the platform name from DMI. EFA already relies on
 * /sys/devices/virtual/dmi/id/board_asset_tag for the host id, so reading
 * product_name from the same place is consistent. Best-effort: on failure
 * we leave name empty and match nothing (=> all features off).
 */
static void efa_platform_read_name(char *buf, size_t buflen)
{
	FILE *fp;
	size_t n;

	buf[0] = '\0';

	fp = fopen("/sys/devices/virtual/dmi/id/product_name", "r");
	if (!fp)
		return;

	n = fread(buf, 1, buflen - 1, fp);
	fclose(fp);
	buf[n] = '\0';

	/* strip trailing newline / whitespace */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
			 buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
		buf[--n] = '\0';
	}
}

static uint64_t efa_platform_match_defaults(const char *name)
{
	uint64_t features;
	size_t i;

	/*
	 * Unknown / unreadable platform: apply only the fleet-wide default-on
	 * baseline. We can't opt any platform-specific bits in or out.
	 */
	if (!name || name[0] == '\0')
		return efa_platform_default_on_features;

	for (i = 0; i < ARRAY_SIZE(efa_platform_table); i++) {
		const char *pfx = efa_platform_table[i].name_prefix;
		if (strncasecmp(name, pfx, strlen(pfx)) == 0) {
			features = (efa_platform_default_on_features &
				    ~efa_platform_table[i].opt_out) |
				   efa_platform_table[i].opt_in;
			EFA_INFO(FI_LOG_CORE,
				 "Matched platform \"%s\" (product_name \"%s\"), "
				 "fleet-uniform features = 0x%lx "
				 "(opt_in=0x%lx opt_out=0x%lx)\n",
				 pfx, name, (unsigned long)features,
				 (unsigned long)efa_platform_table[i].opt_in,
				 (unsigned long)efa_platform_table[i].opt_out);
			return features;
		}
	}

	EFA_INFO(FI_LOG_CORE,
		 "No platform feature entry for product_name \"%s\"; "
		 "using default-on baseline = 0x%lx\n", name,
		 (unsigned long)efa_platform_default_on_features);
	return efa_platform_default_on_features;
}

/*
 * Parse one comma/space-separated feature-token list into a bitmask.
 * Unknown tokens are warned about and ignored. Uses fi_param so the vars
 * show up in `fi_info -e` and follow libfabric's env conventions.
 */
static uint64_t efa_platform_parse_tokens(const char *param, const char *value)
{
	uint64_t mask = 0;
	char *dup, *saveptr, *tok;

	if (!value || value[0] == '\0')
		return 0;

	dup = strdup(value);
	if (!dup) {
		EFA_WARN(FI_LOG_CORE, "strdup failed parsing %s\n", param);
		return 0;
	}

	for (tok = strtok_r(dup, ", ", &saveptr); tok;
	     tok = strtok_r(NULL, ", ", &saveptr)) {
		size_t i;
		bool matched = false;

		for (i = 0; i < ARRAY_SIZE(efa_platform_all_features); i++) {
			const char *name =
				efa_platform_feature_name(efa_platform_all_features[i]);
			if (name && strcmp(tok, name) == 0) {
				mask |= efa_platform_all_features[i];
				matched = true;
				break;
			}
		}
		if (!matched)
			EFA_WARN(FI_LOG_CORE,
				 "Ignoring unknown feature token \"%s\" in %s\n",
				 tok, param);
	}

	free(dup);
	return mask;
}

static void efa_platform_features_init(void)
{
	char name[64];
	char *force = NULL, *disable = NULL;

	if (efa_platform_init_done)
		return;

	/* 1. fleet-uniform per-platform defaults */
	efa_platform_read_name(name, sizeof(name));
	efa_platform_default_features = efa_platform_match_defaults(name);

	/* 2. env overrides (registered in efa_platform_features_define) */
	fi_param_get_str(&efa_prov, "force_features", &force);
	fi_param_get_str(&efa_prov, "disable_features", &disable);
	efa_platform_force_features =
		efa_platform_parse_tokens("FI_EFA_FORCE_FEATURES", force);
	efa_platform_disable_features =
		efa_platform_parse_tokens("FI_EFA_DISABLE_FEATURES", disable);

	efa_platform_init_done = true;
}

bool efa_platform_has_feature(uint64_t feature)
{
	/* require exactly one known bit; reject NONE and multi-bit queries */
	if (feature == 0 || (feature & (feature - 1)) != 0)
		return false;

	efa_platform_features_init();

	/* 1. explicit disable wins (kill switch) */
	if (efa_platform_disable_features & feature)
		return false;
	/* 2. explicit force enables regardless of platform default */
	if (efa_platform_force_features & feature)
		return true;
	/* 3. fall back to the matched platform's static, fleet-uniform default */
	return (efa_platform_default_features & feature) != 0;
}

void efa_platform_features_reset_cache(void)
{
	efa_platform_init_done = false;
	efa_platform_default_features = 0;
	efa_platform_force_features = 0;
	efa_platform_disable_features = 0;
}
