#ifndef ISL_SYSTEM_H
#define ISL_SYSTEM_H

#include <isl_int.h>
#include <isl_system_type.h>

__isl_null isl_system *isl_system_free(__isl_take isl_system *sys);

__isl_give isl_system *isl_system_bound_si(__isl_take isl_system *sys,
	unsigned pos, int value, int upper);
__isl_give isl_system *isl_system_bound(__isl_take isl_system *sys,
	unsigned pos, isl_int value, int upper);

#endif
