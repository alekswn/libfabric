/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

/*
 * Unit tests for the per-platform firmware-feature gate.
 *
 * These exercise efa_platform_has_feature() and its env-override precedence.
 * The env-override paths (FORCE / DISABLE) short-circuit before the platform
 * table lookup, so they are deterministic regardless of which instance the
 * test runs on. Each test resets the cached parse first.
 *
 * Uses the cmocka harness already used by the EFA unit tests.
 */

#include "efa_unit_tests.h"
#include "efa_platform_features.h"

/*
 * feature_name() must round-trip every known feature and return NULL for
 * NONE / unknown, so the FORCE/DISABLE token parser stays in sync with the
 * enum.
 */
void test_efa_platform_feature_name(void **state)
{
	(void)state;

	assert_null(efa_platform_feature_name(EFA_PLATFORM_FEATURE_NONE));

	assert_non_null(efa_platform_feature_name(EFA_PLATFORM_FEATURE_HW_CNTR));
	assert_string_equal(
		efa_platform_feature_name(EFA_PLATFORM_FEATURE_HW_CNTR),
		"HW_CNTR");

	assert_non_null(efa_platform_feature_name(EFA_PLATFORM_FEATURE_WIDE_WQE));
	assert_string_equal(
		efa_platform_feature_name(EFA_PLATFORM_FEATURE_WIDE_WQE),
		"WIDE_WQE");
}

/* NONE and multi-bit queries are never enabled. */
void test_efa_platform_feature_none(void **state)
{
	(void)state;

	unsetenv("FI_EFA_FORCE_FEATURES");
	unsetenv("FI_EFA_DISABLE_FEATURES");
	efa_platform_features_reset_cache();

	assert_false(efa_platform_has_feature(EFA_PLATFORM_FEATURE_NONE));
	/* multi-bit (two bits set) must be rejected */
	assert_false(efa_platform_has_feature(EFA_PLATFORM_FEATURE_HW_CNTR | 0x2ULL));
}

/* FORCE turns the feature on even on an unknown / non-matching platform. */
void test_efa_platform_feature_force(void **state)
{
	(void)state;

	setenv("FI_EFA_FORCE_FEATURES", "HW_CNTR", 1);
	unsetenv("FI_EFA_DISABLE_FEATURES");
	efa_platform_features_reset_cache();

	assert_true(efa_platform_has_feature(EFA_PLATFORM_FEATURE_HW_CNTR));

	unsetenv("FI_EFA_FORCE_FEATURES");
}

/* DISABLE wins over FORCE (kill switch). */
void test_efa_platform_feature_disable_wins(void **state)
{
	(void)state;

	setenv("FI_EFA_FORCE_FEATURES", "HW_CNTR", 1);
	setenv("FI_EFA_DISABLE_FEATURES", "HW_CNTR", 1);
	efa_platform_features_reset_cache();

	assert_false(efa_platform_has_feature(EFA_PLATFORM_FEATURE_HW_CNTR));

	unsetenv("FI_EFA_FORCE_FEATURES");
	unsetenv("FI_EFA_DISABLE_FEATURES");
}

/*
 * Unknown tokens are ignored: a FORCE list containing only an unknown
 * token must leave the result unchanged from the no-override baseline.
 *
 * We compare against the baseline rather than asserting false, because the
 * fall-through (step 3) result depends on the running platform's default --
 * on a platform that declares HW_CNTR fleet-wide the baseline is true. The
 * invariant under test is "unknown token changes nothing", which holds on
 * any platform.
 */
void test_efa_platform_feature_unknown_token(void **state)
{
	bool baseline;

	(void)state;

	/* baseline: no overrides at all */
	unsetenv("FI_EFA_FORCE_FEATURES");
	unsetenv("FI_EFA_DISABLE_FEATURES");
	efa_platform_features_reset_cache();
	baseline = efa_platform_has_feature(EFA_PLATFORM_FEATURE_HW_CNTR);

	/* an unknown FORCE token must be ignored => same as baseline */
	setenv("FI_EFA_FORCE_FEATURES", "NOT_A_REAL_FEATURE", 1);
	unsetenv("FI_EFA_DISABLE_FEATURES");
	efa_platform_features_reset_cache();
	assert_int_equal(efa_platform_has_feature(EFA_PLATFORM_FEATURE_HW_CNTR),
			 baseline);

	unsetenv("FI_EFA_FORCE_FEATURES");
}

/* Comma/space separated lists parse correctly. */
void test_efa_platform_feature_list_parse(void **state)
{
	(void)state;

	setenv("FI_EFA_FORCE_FEATURES", "FOO, HW_CNTR BAR", 1);
	unsetenv("FI_EFA_DISABLE_FEATURES");
	efa_platform_features_reset_cache();

	assert_true(efa_platform_has_feature(EFA_PLATFORM_FEATURE_HW_CNTR));

	unsetenv("FI_EFA_FORCE_FEATURES");
}

/*
 * WIDE_WQE has opt-OUT polarity: it is on fleet-wide by default. With no
 * overrides it must be enabled on any platform not explicitly opted out
 * (p6e-gb200 / g7). To keep the test deterministic regardless of the
 * instance it runs on, FORCE it -- which short-circuits before the
 * platform-table lookup and proves the default-on baseline bit exists and
 * is addressable by token.
 */
void test_efa_platform_feature_wide_wqe_force(void **state)
{
	(void)state;

	setenv("FI_EFA_FORCE_FEATURES", "WIDE_WQE", 1);
	unsetenv("FI_EFA_DISABLE_FEATURES");
	efa_platform_features_reset_cache();

	assert_true(efa_platform_has_feature(EFA_PLATFORM_FEATURE_WIDE_WQE));

	unsetenv("FI_EFA_FORCE_FEATURES");
}

/*
 * DISABLE is a kill switch that wins over the default-on baseline: even
 * though WIDE_WQE is on fleet-wide by default, FI_EFA_DISABLE_FEATURES=
 * WIDE_WQE must turn it off on any platform. Deterministic because DISABLE
 * short-circuits before the platform-table lookup.
 */
void test_efa_platform_feature_wide_wqe_disable(void **state)
{
	(void)state;

	unsetenv("FI_EFA_FORCE_FEATURES");
	setenv("FI_EFA_DISABLE_FEATURES", "WIDE_WQE", 1);
	efa_platform_features_reset_cache();

	assert_false(efa_platform_has_feature(EFA_PLATFORM_FEATURE_WIDE_WQE));

	unsetenv("FI_EFA_DISABLE_FEATURES");
}

/*
 * With no overrides, WIDE_WQE (default-on) and HW_CNTR (default-off) must
 * not resolve identically on a platform that is neither opted out of
 * WIDE_WQE nor opted in to HW_CNTR. We can't assert absolute values
 * without knowing the test host, but we can assert the two independent
 * env overrides move each feature independently.
 */
void test_efa_platform_feature_independent_bits(void **state)
{
	bool wide_forced, hw_disabled;

	(void)state;

	setenv("FI_EFA_FORCE_FEATURES", "WIDE_WQE", 1);
	setenv("FI_EFA_DISABLE_FEATURES", "HW_CNTR", 1);
	efa_platform_features_reset_cache();

	wide_forced = efa_platform_has_feature(EFA_PLATFORM_FEATURE_WIDE_WQE);
	hw_disabled = efa_platform_has_feature(EFA_PLATFORM_FEATURE_HW_CNTR);

	assert_true(wide_forced);   /* FORCE wins */
	assert_false(hw_disabled);  /* DISABLE wins */

	unsetenv("FI_EFA_FORCE_FEATURES");
	unsetenv("FI_EFA_DISABLE_FEATURES");
}
