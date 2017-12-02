/* Copyright 2016-2017 Tobias Grosser
 *
 * Use of this software is governed by the MIT license
 *
 * Written by Tobias Grosser, Weststrasse 47, CH-8003, Zurich
 */

#include <vector>
#include <string>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <isl/options.h>
#include <isl-noexceptions.h>

static void assert_impl(bool condition, const char *file, int line,
	const char *message)
{
	if (condition)
		return;

	fprintf(stderr, "Assertion failed in %s:%d %s\n", file, line, message);
	exit(EXIT_FAILURE);
}

static void assert_impl(isl::boolean condition, const char *file, int line,
	const char *message)
{
	assert_impl(bool(condition), file, line, message);
}

#define assert(exp) assert_impl(exp, __FILE__, __LINE__, #exp)

#include "isl_test_cpp-generic.cc"

/* Test that isl_bool values are returned correctly.
 *
 * We check in detail the following parts of the isl::boolean class:
 *  - The is_true, is_false, and is_error functions return true in case they
 *    are called on a true, false, or error instance of isl::boolean,
 *    respectively
 *  - Explicit conversion to 'bool'
 *  - Implicit conversion to 'bool'
 *  - The complement operator
 *  - Explicit construction from 'true' and 'false'
 *  - Explicit construction form isl_bool
 */
void test_return_bool(isl::ctx ctx)
{
	isl::set empty(ctx, "{ : false }");
	isl::set univ(ctx, "{ : }");
	isl::set null;

	isl::boolean b_true = empty.is_empty();
	isl::boolean b_false = univ.is_empty();
	isl::boolean b_error = null.is_empty();

	assert(b_true.is_true());
	assert(!b_true.is_false());
	assert(!b_true.is_error());

	assert(!b_false.is_true());
	assert(b_false.is_false());
	assert(!b_false.is_error());

	assert(!b_error.is_true());
	assert(!b_error.is_false());
	assert(b_error.is_error());

	assert(bool(b_true) == true);
	assert(bool(b_false) == false);

	assert(b_true);

	assert((!b_false).is_true());
	assert((!b_true).is_false());
	assert((!b_error).is_error());

	assert(isl::boolean(true).is_true());
	assert(!isl::boolean(true).is_false());
	assert(!isl::boolean(true).is_error());

	assert(isl::boolean(false).is_false());
	assert(!isl::boolean(false).is_true());
	assert(!isl::boolean(false).is_error());

	assert(isl::manage(isl_bool_true).is_true());
	assert(!isl::manage(isl_bool_true).is_false());
	assert(!isl::manage(isl_bool_true).is_error());

	assert(isl::manage(isl_bool_false).is_false());
	assert(!isl::manage(isl_bool_false).is_true());
	assert(!isl::manage(isl_bool_false).is_error());

	assert(isl::manage(isl_bool_error).is_error());
	assert(!isl::manage(isl_bool_error).is_true());
	assert(!isl::manage(isl_bool_error).is_false());
}

/* Test that return values are handled correctly.
 *
 * Test that isl C++ objects, integers, boolean values, and strings are
 * returned correctly.
 */
void test_return(isl::ctx ctx)
{
	test_return_obj(ctx);
	test_return_int(ctx);
	test_return_bool(ctx);
	test_return_string(ctx);
}

/* Test that foreach functions are modeled correctly.
 *
 * Verify that lambdas are correctly called as callback of a 'foreach'
 * function and that variables captured by the lambda work correctly. Also
 * check that the foreach function takes account of the return value of the
 * lambda and aborts in case isl::stat::error is returned and then returns
 * isl::stat::error itself.
 */
void test_foreach(isl::ctx ctx)
{
	isl::set s(ctx, "{ [0]; [1]; [2] }");

	std::vector<isl::basic_set> basic_sets;

	auto add_to_vector = [&] (isl::basic_set bs) {
		basic_sets.push_back(bs);
		return isl::stat::ok;
	};

	isl::stat ret1 = s.foreach_basic_set(add_to_vector);

	assert(ret1 == isl::stat::ok);
	assert(basic_sets.size() == 3);
	assert(isl::set(basic_sets[0]).is_subset(s));
	assert(isl::set(basic_sets[1]).is_subset(s));
	assert(isl::set(basic_sets[2]).is_subset(s));
	assert(!basic_sets[0].is_equal(basic_sets[1]));

	auto fail = [&] (isl::basic_set bs) {
		return isl::stat::error;
	};

	isl::stat ret2 = s.foreach_basic_set(fail);

	assert(ret2 == isl::stat::error);
}

/* Test that read-only list of vals are modeled correctly.
 *
 * Construct an std::vector of isl::vals and use its iterators to construct a
 * C++ isl list of vals. Compare these containers. Extract the C isl list from
 * the C++ one, verify that is has expected size and content. Modify the C isl
 * list and convert it back to C++. Verify that the new managed list has
 * expected content.
 */
void test_val_list(isl::ctx ctx)
{
	std::vector<isl::val> val_vector;
	for (int i = 0; i < 42; ++i) {
		isl::val val(ctx, i);
		val_vector.push_back(val);
	}
	isl::list<isl::val> val_list(ctx, val_vector.begin(),
		val_vector.end());

	assert(42 == val_list.size());
	for (int i = 0; i < 42; ++i) {
		isl::val val_at = val_list.at(i);
		isl::val val_op = val_list[i];
		isl::val expected(ctx, i);
		assert(val_at.eq(expected));
		assert(val_op.eq(expected));
	}

	isl_val_list *c_val_list = val_list.release();
	assert(42 == isl_val_list_n_val(c_val_list));
	for (int i = 0; i < 42; ++i) {
		isl_val *val = isl_val_list_get_val(c_val_list, i);
		assert(i == isl_val_get_num_si(val));
		isl_val_free(val);
	}

	c_val_list = isl_val_list_drop(c_val_list, 0, 32);
	val_list = isl::manage(c_val_list);
	assert(10 == val_list.size());
	for (int i = 0; i < 10; ++i) {
		isl::val expected(ctx, 32 + i);
		isl::val val_op = val_list[i];
		assert(val_op.eq(expected));
	}
}

/* Test that supplementary functions on lists are handled properly.
 *
 * Construct a list of basic_maps from an array thereof. Compute the
 * interaction of all basic_map in the list.
 */
void test_basic_map_list(isl::ctx ctx)
{
	isl::basic_map bmap1(ctx, "{[]->[a]: 0 <= a <= 42}");
	isl::basic_map bmap2(ctx, "{[]->[a]: 21 <= a <= 63}");
	isl::basic_map bmap3(ctx, "{[]->[a]: 21 <= a <= 42}");

	isl::basic_map bmap_array[] = { bmap1, bmap2, bmap3 };
	isl::list<isl::basic_map> bmap_list(ctx, bmap_array, bmap_array + 3);
	isl::basic_map result = bmap_list.intersect();
	assert(result.is_equal(bmap3));
}

/* Test if the list iterators are operating properly and whether they are
 * compatible with the standard library.
 *
 * Construct a standard vector from an isl list using list iterators. Check
 * that the size and content of the vector is equal to the size and content of
 * the list.
 *
 * Check that prefix and postfix increments of the iterators are implemented
 * correctly.
 */
void test_list_iterators(isl::ctx ctx)
{
	std::vector<isl::val> val_vector;
	for (int i = 0; i < 42; ++i) {
		isl::val val(ctx, i);
		val_vector.push_back(val);
	}
	isl::list<isl::val> val_list(ctx, val_vector.begin(),
		val_vector.end());

	std::vector<isl::val> other_val_vector;
	other_val_vector.resize(42);
	std::copy(val_list.begin(), val_list.end(), other_val_vector.begin());

	assert(42 == other_val_vector.size());
	for (int i = 0; i < 42; ++i) {
		isl::val expected(ctx, i);
		assert(expected.eq(other_val_vector[i]));
	}

	isl::list<isl::val>::iterator it = val_list.begin();
	for (int i = 0; i < 42; ++i) {
		isl::val expected(ctx, i);
		assert(it != val_list.end());
		assert(it->eq(expected));
		assert((*it).eq(expected));
		++it;
	}

	it = val_list.begin();
	isl::list<isl::val>::iterator it2 = val_list.begin();
	++it2;
	assert(it++ != it2);
	assert(it++ == it2);
	assert(it != it2);

	it = val_list.begin();
	it2 = val_list.begin();
	++it2;
	assert(++it == it2);
	assert(++it == ++it2);
	assert(++it != it2);
}

/* Test the isl C++ interface
 *
 * This includes:
 *  - The isl C <-> C++ pointer interface
 *  - Object construction
 *  - Different parameter types
 *  - Different return types
 *  - Foreach functions
 *  - Identifier allocation and equality
 *  - List of isl::val
 *  - Custom function of the list of isl::basic_map
 *  - List iterators
 */
int main()
{
	isl_ctx *ctx = isl_ctx_alloc();

	isl_options_set_on_error(ctx, ISL_ON_ERROR_ABORT);

	test_pointer(ctx);
	test_constructors(ctx);
	test_parameters(ctx);
	test_return(ctx);
	test_foreach(ctx);
	test_val_list(ctx);
	test_basic_map_list(ctx);
	test_list_iterators(ctx);

	isl_ctx_free(ctx);
}
