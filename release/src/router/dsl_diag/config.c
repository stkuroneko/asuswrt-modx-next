/*
 * Copyright 2020, ASUSTeK Inc.
 * All Rights Reserved.
 *
 */

#include <shared.h>

void update_dsl_diag_state(int s)
{
	nvram_set_int("dslx_diag_state", s);
}

int is_dsl_link_up()
{
	return (nvram_match("dsltmp_adslsyncsts","up"));
}
