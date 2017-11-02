#ifndef ISL_SCHEDLUE_TREE_H
#define ISL_SCHEDLUE_TREE_H

#include <isl_schedule_band.h>
#include <isl/schedule.h>
#include <isl/schedule_tree.h>
#include <isl/set.h>
#include <isl/union_set.h>

/* A schedule (sub)tree.
 *
 * The leaves of a tree are not explicitly represented inside
 * the isl_schedule_tree, except when the tree consists of only a leaf.
 *
 * The "band" field is valid when type is isl_schedule_node_band.
 * The "context" field is valid when type is isl_schedule_node_context
 * and represents constraints on the flat product of the outer band nodes,
 * possibly introducing additional parameters.
 * The "domain" field is valid when type is isl_schedule_node_domain
 * and introduces the statement instances scheduled by the tree.
 *
 * The "contraction" and "expansion" fields are valid when type
 * is isl_schedule_node_expansion.
 * "expansion" expands the reaching domain elements to one or more
 * domain elements for the subtree.
 * "contraction" maps these elements back to the corresponding
 * reaching domain element.  It does not involve any domain constraints.
 *
 * The "extension" field is valid when the is isl_schedule_node_extension
 * maps outer schedule dimenions (the flat product of the outer band nodes)
 * to additional iteration domains.
 *
 * The "filter" field is valid when type is isl_schedule_node_filter
 * and represents the statement instances selected by the node.
 *
 * The "guard" field is valid when type is isl_schedule_node_guard
 * and represents constraints on the flat product of the outer band nodes
 * that need to be enforced by the outer nodes in the generated AST.
 *
 * The "mark" field is valid when type is isl_schedule_node_mark and
 * identifies the mark.
 *
 * The "children" field is valid for all types except
 * isl_schedule_node_leaf.  This field is NULL if there are
 * no children (except for the implicit leaves).
 *
 * anchored is set if the node or any of its descendants depends
 * on its position in the schedule tree.
 */
struct isl_schedule_tree {
	int ref;
	isl_ctx *ctx;
	int anchored;
	enum isl_schedule_node_type type;
	union {
		isl_schedule_band *band;
		isl_set *context;
		isl_union_set *domain;
		struct {
			isl_union_pw_multi_aff *contraction;
			isl_union_map *expansion;
		};
		isl_union_map *extension;
		isl_union_set *filter;
		isl_set *guard;
		isl_id *mark;
	};
	isl_schedule_tree_list *children;
};

#endif
