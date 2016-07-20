/*
 * Copyright 2016      Sven Verdoolaege
 *
 * Use of this software is governed by the MIT license
 *
 * Written by Sven Verdoolaege
 */

/* An isl_system is a system of constraints.
 * For now, use an isl_basic_map as the underlying representation,
 * but ignore the space and the local variables.
 */
#define isl_system	isl_basic_map

#include <isl_ctx_private.h>
#include <isl_int.h>
#include <isl_seq.h>
#include <isl_vec_private.h>
#include <isl_map_private.h>
#include <isl_system_private.h>

/* Return the dimension of "sys".
 *
 * The underlying basic map is expected to only have set dimensions.
 */
unsigned isl_system_dim(__isl_keep isl_system *sys)
{
	return isl_basic_map_total_dim(sys);
}

/* Return the isl_ctx to which "sys" belongs.
 */
isl_ctx *isl_system_get_ctx(__isl_keep isl_system *sys)
{
	return isl_basic_map_get_ctx(sys);
}

/* Free "sys" and return NULL.
 */
__isl_null isl_system *isl_system_free(__isl_take isl_system *sys)
{
	return isl_basic_map_free(sys);
}

/* Create an isl_system of dimension "n_var", with room for "extra"
 * extra variables, "n_eq" equality constraints and
 * "n_ineq" inequality constraints.
 */
__isl_give isl_system *isl_system_alloc(isl_ctx *ctx,
	unsigned n_var, unsigned extra, unsigned n_eq, unsigned n_ineq)
{
	isl_space *space;

	space = isl_space_set_alloc(ctx, 0, n_var);
	return isl_basic_map_alloc_space(space, extra, n_ineq, n_ineq);
}

/* Return a pointer to a new inequality constraint in "sys",
 * which is assumed to have enough room for this extra constraint.
 * Return NULL if an error occurs.
 *
 * After filling up the constraint, the caller should call
 * isl_system_finish_inequality.
 */
isl_int *isl_system_alloc_inequality(__isl_keep isl_system *sys)
{
	int k;

	k = isl_basic_map_alloc_inequality(sys);
	if (k < 0)
		return NULL;
	return sys->ineq[k];
}

/* Finish adding the inequality constraint "ineq" to "sys".
 *
 * This currently does nothing, but in future, it could normalize
 * the constraint, perform fangcheng (Gaussian elimination) and/or
 * check whether any sample value is still valid.
 */
__isl_give isl_system *isl_system_finish_inequality(__isl_take isl_system *sys,
	isl_int *ineq)
{
	return sys;
}

/* Return an isl_system that is equal to "sys" and that has only
 * a single reference.
 */
__isl_give isl_system *isl_system_cow(__isl_take isl_system *sys)
{
	return isl_basic_map_cow(sys);
}

/* Return an isl_system that is equal to "sys" and that has room
 * for at least "n_eq" more equality constraints and
 * "n_ineq" more inequality constraints.
 */
__isl_give isl_system *isl_system_extend_constraints(
	__isl_take isl_system *sys, unsigned n_eq, unsigned n_ineq)
{
	return isl_basic_map_extend_constraints(sys, n_eq, n_ineq);
}
