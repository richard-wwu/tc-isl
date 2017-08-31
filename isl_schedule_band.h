#ifndef ISL_SCHEDULE_BAND_H
#define ISL_SCHEDULE_BAND_H

#include <isl/aff.h>
#include <isl/ast_type.h>
#include <isl/schedule_band.h>
#include <isl/union_map.h>

/* Information about a band within a schedule.
 *
 * n is the number of scheduling dimensions within the band.
 * coincident is an array of length n, indicating whether a scheduling dimension
 *	satisfies the coincidence constraints in the sense that
 *	the corresponding dependence distances are zero.
 * permutable is set if the band is permutable.
 * mupa is the partial schedule corresponding to this band.  The dimension
 *	of mupa is equal to n.
 * loop_type contains the loop AST generation types for the members
 * in the band.  It may be NULL, if all members are
 * of type isl_ast_loop_default.
 * isolate_loop_type contains the loop AST generation types for the members
 * in the band for the isolated part.  It may be NULL, if all members are
 * of type isl_ast_loop_default.
 * ast_build_options are the remaining AST build options associated
 * to the band.
 * anchored is set if the node depends on its position in the schedule tree.
 *	In particular, it is set if the AST build options include
 *	an isolate option.
 */
struct isl_schedule_band {
	int ref;

	int n;
	int *coincident;
	int permutable;

	isl_multi_union_pw_aff *mupa;

	int anchored;
	isl_union_set *ast_build_options;
	enum isl_ast_loop_type *loop_type;
	enum isl_ast_loop_type *isolate_loop_type;
};

#endif
