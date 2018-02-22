/// These are automatically generated C++ bindings for isl.
///
/// isl is a library for computing with integer sets and maps described by
/// Presburger formulas. On top of this, isl provides various tools for
/// polyhedral compilation, ranging from dependence analysis over scheduling
/// to AST generation.

#ifndef ISL_CPP
#define ISL_CPP

#include <isl/val.h>
#include <isl/aff.h>
#include <isl/set.h>
#include <isl/map.h>
#include <isl/ilp.h>
#include <isl/union_set.h>
#include <isl/union_map.h>
#include <isl/flow.h>
#include <isl/schedule.h>
#include <isl/schedule_node.h>
#include <isl/ast_build.h>
#include <isl/constraint.h>
#include <isl/id.h>

#include <isl/ctx.h>
#include <isl/options.h>

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

namespace isl {

class ctx {
	isl_ctx *ptr;
public:
	/* implicit */ ctx(isl_ctx *ctx) : ptr(ctx) {}
	isl_ctx *release() {
		auto tmp = ptr;
		ptr = nullptr;
		return tmp;
	}
	isl_ctx *get() {
		return ptr;
	}
};

/* Class capturing isl errors.
 *
 * The what() return value is stored in a reference counted string
 * to ensure that the copy constructor and the assignment operator
 * do not throw any exceptions.
 */
class exception : public std::exception {
	std::shared_ptr<std::string> what_str;

protected:
	inline exception(const char *what_arg, const char *msg,
		const char *file, int line);
public:
	exception() {}
	exception(const char *what_arg) {
		what_str = std::make_shared<std::string>(what_arg);
	}
	static inline exception create(enum isl_error error, const char *msg,
		const char *file, int line);
	static inline exception create_from_last_error(isl::ctx ctx);
	virtual const char *what() const noexcept {
		return what_str->c_str();
	}
};

/* Create an exception of a type described by "what_arg", with
 * error message "msg" in line "line" of file "file".
 *
 * Create a string holding the what() return value that
 * corresponds to what isl would have printed.
 * If no error message or no error file was set, then use "what_arg" instead.
 */
exception::exception(const char *what_arg, const char *msg, const char *file,
	int line)
{
	if (!msg || !file)
		what_str = std::make_shared<std::string>(what_arg);
	else
		what_str = std::make_shared<std::string>(std::string(file) +
				    ":" + std::to_string(line) + ": " + msg);
}

class exception_abort : public exception {
	friend exception;
	exception_abort(const char *msg, const char *file, int line) :
		exception("execution aborted", msg, file, line) {}
};

class exception_alloc : public exception {
	friend exception;
	exception_alloc(const char *msg, const char *file, int line) :
		exception("memory allocation failure", msg, file, line) {}
};

class exception_unknown : public exception {
	friend exception;
	exception_unknown(const char *msg, const char *file, int line) :
		exception("unknown failure", msg, file, line) {}
};

class exception_internal : public exception {
	friend exception;
	exception_internal(const char *msg, const char *file, int line) :
		exception("internal error", msg, file, line) {}
};

class exception_invalid : public exception {
	friend exception;
	exception_invalid(const char *msg, const char *file, int line) :
		exception("invalid argument", msg, file, line) {}
};

class exception_quota : public exception {
	friend exception;
	exception_quota(const char *msg, const char *file, int line) :
		exception("quota exceeded", msg, file, line) {}
};

class exception_unsupported : public exception {
	friend exception;
	exception_unsupported(const char *msg, const char *file, int line) :
		exception("unsupported operation", msg, file, line) {}
};

/* Create an exception of the class that corresponds to "error", with
 * error message "msg" in line "line" of file "file".
 *
 * isl_error_none is treated as an invalid error type.
 */
exception exception::create(enum isl_error error, const char *msg,
	const char *file, int line)
{
	switch (error) {
	case isl_error_none:
		break;
	case isl_error_abort: return exception_abort(msg, file, line);
	case isl_error_alloc: return exception_alloc(msg, file, line);
	case isl_error_unknown: return exception_unknown(msg, file, line);
	case isl_error_internal: return exception_internal(msg, file, line);
	case isl_error_invalid: return exception_invalid(msg, file, line);
	case isl_error_quota: return exception_quota(msg, file, line);
	case isl_error_unsupported:
				return exception_unsupported(msg, file, line);
	}

	throw exception_invalid("invalid error type", __FILE__, __LINE__);
}

/* Create an exception from the last error that occurred on "ctx" and
 * reset the error.
 *
 * If "ctx" is NULL or if it is not in an error state at the start,
 * then an invalid argument exception is thrown.
 */
exception exception::create_from_last_error(isl::ctx ctx)
{
	enum isl_error error;
	const char *msg, *file;
	int line;

	error = isl_ctx_last_error(ctx.get());
	msg = isl_ctx_last_error_msg(ctx.get());
	file = isl_ctx_last_error_file(ctx.get());
	line = isl_ctx_last_error_line(ctx.get());
	isl_ctx_reset_error(ctx.get());

	return create(error, msg, file, line);
}

/* Helper class for setting the on_error and resetting the option
 * to the original value when leaving the scope.
 */
class options_scoped_set_on_error {
	isl_ctx *ctx;
	int saved_on_error;
public:
	options_scoped_set_on_error(isl::ctx ctx, int on_error) {
		this->ctx = ctx.get();
		saved_on_error = isl_options_get_on_error(this->ctx);
		isl_options_set_on_error(this->ctx, on_error);
	}
	~options_scoped_set_on_error() {
		isl_options_set_on_error(ctx, saved_on_error);
	}
};

class id {
  friend inline isl::id manage(__isl_take isl_id *ptr);

  isl_id *ptr;

  inline explicit id(__isl_take isl_id *id);
public:
  id(isl::ctx ctx, const std::string &name) {
    ptr = isl_id_alloc(ctx.release(), name.c_str(), nullptr);
  }

  template <typename T>
  id(isl::ctx ctx, const std::string &name, T *usr,
     void (*deleter)(void *) = nullptr) {
    ptr = isl_id_alloc(ctx.release(), name.c_str(), usr);
    if (deleter)
      ptr = isl_id_set_free_user(ptr, deleter);
  }

  template <typename T>
  id(isl::ctx ctx, T *usr,
     void (*deleter)(void *) = nullptr) {
    ptr = isl_id_alloc(ctx.release(), nullptr, usr);
    if (deleter)
      ptr = isl_id_set_free_user(ptr, deleter);
  }

  template <typename T>
  T *get_user() {
    if (!ptr)
      return nullptr;
    return static_cast<T *>(isl_id_get_user(ptr));
  }

  inline /* implicit */ id();
  inline /* implicit */ id(const isl::id &obj);
  inline isl::id &operator=(isl::id obj);
  inline ~id();
  inline __isl_give isl_id *copy() const &;
  inline __isl_give isl_id *copy() && = delete;
  inline __isl_keep isl_id *get() const;
  inline __isl_give isl_id *release();
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline bool is_null() const;
  inline std::string to_str() const;

  inline std::string get_name() const;
  inline int get_hash() const;

  inline bool has_name() const;
  inline isl::id set_free_user(void (*deleter)(void *)) const;
  inline bool operator== (const isl::id &obj) const;
  inline bool operator!= (const isl::id &obj) const;
};

inline isl::id manage(__isl_take isl_id *ptr) {
  return id(ptr);
}

id::id()
    : ptr(nullptr) {}

id::id(const isl::id &obj)
    : ptr(obj.copy()) {}

id::id(__isl_take isl_id *ptr)
    : ptr(ptr) {}

id &id::operator=(isl::id obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

id::~id() {
  if (ptr)
    isl_id_free(ptr);
}

__isl_give isl_id *id::copy() const & {
  return isl_id_copy(ptr);
}

__isl_keep isl_id *id::get() const {
  return ptr;
}

__isl_give isl_id *id::release() {
  isl_id *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

id::operator bool() const {
  return !is_null();
}

isl::ctx id::get_ctx() const {
  return isl::ctx(isl_id_get_ctx(ptr));
}

bool id::is_null() const {
  return ptr == nullptr;
}

inline std::ostream& operator<<(std::ostream& os, const id& C) {
  os << C.to_str();
  return os;
}

std::string id::to_str() const {
  char *Tmp = isl_id_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}

int id::get_hash() const {
  return isl_id_get_hash(get());
}

std::string id::get_name() const {
  auto res = isl_id_get_name(get());
  std::string tmp(res);
  return tmp;
}

bool id::has_name() const {
  return isl_id_get_name(get()) != nullptr;
}

id id::set_free_user(void (*deleter)(void *)) const {
  auto res = isl_id_set_free_user(copy(), deleter);
  return manage(res);
}

bool id::operator==(const id &obj) const {
  return ptr == obj.ptr;
}

bool id::operator!=(const id &obj) const {
  return !operator==(obj);
}

enum class dim_type {
  cst = isl_dim_cst,
  param = isl_dim_param,
  in = isl_dim_in,
  out = isl_dim_out,
  set = isl_dim_set,
  div = isl_dim_div,
  all = isl_dim_all
};

enum class ast_op_type {
	error = isl_ast_op_error,
	_and = isl_ast_op_and,
	and_then = isl_ast_op_and_then,
	_or = isl_ast_op_or,
	or_else = isl_ast_op_or_else,
	max = isl_ast_op_max,
	min = isl_ast_op_min,
	minus = isl_ast_op_minus,
	add = isl_ast_op_add,
	sub = isl_ast_op_sub,
	mul = isl_ast_op_mul,
	div = isl_ast_op_div,
	fdiv_q = isl_ast_op_fdiv_q,	/* Round towards -infty */
	pdiv_q = isl_ast_op_pdiv_q,	/* Dividend is non-negative */
	pdiv_r = isl_ast_op_pdiv_r,	/* Dividend is non-negative */
	zdiv_r = isl_ast_op_zdiv_r,	/* Result only compared against zero */
	cond = isl_ast_op_cond,
	select = isl_ast_op_select,
	eq = isl_ast_op_eq,
	le = isl_ast_op_le,
	lt = isl_ast_op_lt,
	ge = isl_ast_op_ge,
	gt = isl_ast_op_gt,
	call = isl_ast_op_call,
	access = isl_ast_op_access,
	member = isl_ast_op_member,
	address_of = isl_ast_op_address_of
};

enum class ast_node_type {
	error = isl_ast_node_error,
	_for = isl_ast_node_for,
	_if = isl_ast_node_if,
	block = isl_ast_node_block,
	mark = isl_ast_node_mark,
	user = isl_ast_node_user
};

enum class ast_loop_type {
	error = isl_ast_loop_error,
	_default = isl_ast_loop_default,
	atomic = isl_ast_loop_atomic,
	unroll = isl_ast_loop_unroll,
	separate = isl_ast_loop_separate
};

enum class schedule_node_type {
        error = isl_schedule_node_error,
        band = isl_schedule_node_band,
        context = isl_schedule_node_context,
        domain = isl_schedule_node_domain,
        expansion = isl_schedule_node_expansion,
        extension = isl_schedule_node_extension,
        filter = isl_schedule_node_filter,
        leaf = isl_schedule_node_leaf,
        guard = isl_schedule_node_guard,
        mark = isl_schedule_node_mark,
        sequence = isl_schedule_node_sequence,
        set = isl_schedule_node_set
};

template <typename T>
class list;

template <typename T>
class list_iterator {
  const list<T> *lst;
  int pos;
  mutable T elementHolder;

  inline list_iterator(const list<T> *l, int p);

  friend list_iterator list<T>::begin() const;
  friend list_iterator list<T>::end() const;

public:
  typedef T value_type;
  typedef int difference_type;
  typedef std::input_iterator_tag iterator_category;
  typedef const T *pointer;
  typedef T reference;

  inline list_iterator();
  inline list_iterator(const list_iterator<T> &it);
  inline ~list_iterator();
  inline list_iterator &operator=(const list_iterator<T> &it);

  inline reference operator*() const;
  inline pointer operator->() const;
  inline list_iterator operator++(int);
  inline list_iterator &operator++();
  inline bool operator==(const list_iterator<T> &it) const;
  inline bool operator!=(const list_iterator<T> &it) const;

  static inline void swap(list_iterator<T> &it1, list_iterator<T> &it2);
};

template <typename T>
list_iterator<T>::list_iterator(const list<T> *l, int p) :
  lst(l), pos(p) {}

template <typename T>
list_iterator<T>::list_iterator() :
  lst(nullptr), pos(-1) {}

template <typename T>
list_iterator<T>::list_iterator(const list_iterator<T> &it) :
  lst(it.lst), pos(it.pos) {}

template <typename T>
list_iterator<T> &list_iterator<T>::operator=(const list_iterator<T> &it) {
  lst = it.lst;
  pos = it.pos;
  return *this;
}

template <typename T>
list_iterator<T>::~list_iterator() {}

template <typename T>
typename list_iterator<T>::reference list_iterator<T>::operator*() const {
  return lst->at(pos);
}

template <typename T>
typename list_iterator<T>::pointer list_iterator<T>::operator->() const {
  elementHolder = lst->at(pos);
  return &elementHolder;
}

template <typename T>
list_iterator<T> list_iterator<T>::operator++(int) {
  list_iterator<T> it = *this;
  ++*this;
  return it;
}

template <typename T>
list_iterator<T> &list_iterator<T>::operator++() {
  if (pos == -1 || !lst || pos >= lst->size() - 1)
    pos = -1;
  else
    ++pos;

  return *this;
}

template <typename T>
bool list_iterator<T>::operator==(const list_iterator<T> &it) const {
  if (lst != it.lst)
    throw std::invalid_argument(
			"cannot compare iterators from different containers");
  return pos == it.pos;
}

template <typename T>
bool list_iterator<T>::operator!=(const list_iterator<T> &it) const {
  return !(*this == it);
}

} // namespace isl

namespace isl {

// forward declarations
class aff;
class ast_build;
class ast_expr;
class ast_node;
class basic_map;
class basic_set;
class constraint;
class local_space;
class map;
class multi_aff;
class multi_pw_aff;
class multi_union_pw_aff;
class multi_val;
class point;
class pw_aff;
class pw_multi_aff;
class schedule;
class schedule_constraints;
class schedule_node;
class schedule_node_band;
class schedule_node_context;
class schedule_node_domain;
class schedule_node_expansion;
class schedule_node_extension;
class schedule_node_filter;
class schedule_node_guard;
class schedule_node_leaf;
class schedule_node_mark;
class schedule_node_sequence;
class schedule_node_set;
class set;
class space;
class union_access_info;
class union_flow;
class union_map;
class union_pw_aff;
class union_pw_multi_aff;
class union_set;
class union_set_list;
class val;

// declarations for isl::aff
inline isl::aff manage(__isl_take isl_aff *ptr);
inline isl::aff manage_copy(__isl_keep isl_aff *ptr);

class aff {
  friend inline isl::aff manage(__isl_take isl_aff *ptr);
  friend inline isl::aff manage_copy(__isl_keep isl_aff *ptr);

protected:
  isl_aff *ptr = nullptr;

  inline explicit aff(__isl_take isl_aff *ptr);

public:
  inline /* implicit */ aff();
  inline /* implicit */ aff(const isl::aff &obj);
  inline explicit aff(isl::local_space ls);
  inline explicit aff(isl::local_space ls, isl::val val);
  inline explicit aff(isl::local_space ls, enum isl::dim_type type, unsigned int pos);
  inline explicit aff(isl::ctx ctx, const std::string &str);
  inline isl::aff &operator=(isl::aff obj);
  inline ~aff();
  inline __isl_give isl_aff *copy() const &;
  inline __isl_give isl_aff *copy() && = delete;
  inline __isl_keep isl_aff *get() const;
  inline __isl_give isl_aff *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::aff add(isl::aff aff2) const;
  inline isl::aff add_coefficient_si(enum isl::dim_type type, int pos, int v) const;
  inline isl::aff add_constant_si(int v) const;
  inline isl::aff ceil() const;
  inline int dim(enum isl::dim_type type) const;
  inline isl::aff div(isl::aff aff2) const;
  inline isl::aff drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::set eq_set(isl::aff aff2) const;
  inline isl::aff floor() const;
  inline isl::set ge_set(isl::aff aff2) const;
  inline isl::val get_coefficient_val(enum isl::dim_type type, int pos) const;
  inline isl::val get_constant_val() const;
  inline isl::val get_denominator_val() const;
  inline isl::aff get_div(int pos) const;
  inline isl::local_space get_local_space() const;
  inline isl::space get_space() const;
  inline isl::set gt_set(isl::aff aff2) const;
  inline bool involves_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::set le_set(isl::aff aff2) const;
  inline isl::set lt_set(isl::aff aff2) const;
  inline isl::aff mod(isl::val mod) const;
  inline isl::aff mul(isl::aff aff2) const;
  inline isl::set ne_set(isl::aff aff2) const;
  inline isl::aff neg() const;
  static inline isl::aff param_on_domain_space(isl::space space, isl::id id);
  inline bool plain_is_equal(const isl::aff &aff2) const;
  inline isl::aff project_domain_on_params() const;
  inline isl::aff pullback(isl::multi_aff ma) const;
  inline isl::aff scale(isl::val v) const;
  inline isl::aff scale_down(isl::val v) const;
  inline isl::aff scale_down_ui(unsigned int f) const;
  inline isl::aff set_coefficient_si(enum isl::dim_type type, int pos, int v) const;
  inline isl::aff set_coefficient_val(enum isl::dim_type type, int pos, isl::val v) const;
  inline isl::aff set_constant_si(int v) const;
  inline isl::aff set_constant_val(isl::val v) const;
  inline isl::aff set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const;
  inline isl::aff set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const;
  inline isl::aff set_tuple_id(enum isl::dim_type type, isl::id id) const;
  inline isl::aff sub(isl::aff aff2) const;
  typedef isl_aff* isl_ptr_t;
};

// declarations for isl::ast_build
inline isl::ast_build manage(__isl_take isl_ast_build *ptr);
inline isl::ast_build manage_copy(__isl_keep isl_ast_build *ptr);

class ast_build {
  friend inline isl::ast_build manage(__isl_take isl_ast_build *ptr);
  friend inline isl::ast_build manage_copy(__isl_keep isl_ast_build *ptr);

protected:
  isl_ast_build *ptr = nullptr;

  inline explicit ast_build(__isl_take isl_ast_build *ptr);

public:
  inline /* implicit */ ast_build();
  inline /* implicit */ ast_build(const isl::ast_build &obj);
  inline explicit ast_build(isl::ctx ctx);
  inline isl::ast_build &operator=(isl::ast_build obj);
  inline ~ast_build();
  inline __isl_give isl_ast_build *copy() const &;
  inline __isl_give isl_ast_build *copy() && = delete;
  inline __isl_keep isl_ast_build *get() const;
  inline __isl_give isl_ast_build *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  inline isl::ast_expr access_from(isl::pw_multi_aff pma) const;
  inline isl::ast_expr access_from(isl::multi_pw_aff mpa) const;
  inline isl::ast_node ast_from_schedule(isl::union_map schedule) const;
  inline isl::ast_expr call_from(isl::pw_multi_aff pma) const;
  inline isl::ast_expr call_from(isl::multi_pw_aff mpa) const;
  inline isl::ast_expr expr_from(isl::set set) const;
  inline isl::ast_expr expr_from(isl::pw_aff pa) const;
  static inline isl::ast_build from_context(isl::set set);
  inline isl::union_map get_schedule() const;
  inline isl::space get_schedule_space() const;
  inline isl::ast_node node_from_schedule(isl::schedule schedule) const;
  inline isl::ast_node node_from_schedule_map(isl::union_map schedule) const;
  inline isl::ast_build set_iterators(isl::list<isl::id> iterators) const;
  typedef isl_ast_build* isl_ptr_t;
};

// declarations for isl::ast_expr
inline isl::ast_expr manage(__isl_take isl_ast_expr *ptr);
inline isl::ast_expr manage_copy(__isl_keep isl_ast_expr *ptr);

class ast_expr {
  friend inline isl::ast_expr manage(__isl_take isl_ast_expr *ptr);
  friend inline isl::ast_expr manage_copy(__isl_keep isl_ast_expr *ptr);

protected:
  isl_ast_expr *ptr = nullptr;

  inline explicit ast_expr(__isl_take isl_ast_expr *ptr);

public:
  inline /* implicit */ ast_expr();
  inline /* implicit */ ast_expr(const isl::ast_expr &obj);
  inline isl::ast_expr &operator=(isl::ast_expr obj);
  inline ~ast_expr();
  inline __isl_give isl_ast_expr *copy() const &;
  inline __isl_give isl_ast_expr *copy() && = delete;
  inline __isl_keep isl_ast_expr *get() const;
  inline __isl_give isl_ast_expr *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::id get_id() const;
  inline isl::ast_expr get_op_arg(int pos) const;
  inline int get_op_n_arg() const;
  inline enum isl::ast_op_type get_op_type() const;
  inline bool is_equal(const isl::ast_expr &expr2) const;
  inline isl::ast_expr set_op_arg(int pos, isl::ast_expr arg) const;
  inline std::string to_C_str() const;
  typedef isl_ast_expr* isl_ptr_t;
};

// declarations for isl::ast_node
inline isl::ast_node manage(__isl_take isl_ast_node *ptr);
inline isl::ast_node manage_copy(__isl_keep isl_ast_node *ptr);

class ast_node {
  friend inline isl::ast_node manage(__isl_take isl_ast_node *ptr);
  friend inline isl::ast_node manage_copy(__isl_keep isl_ast_node *ptr);

protected:
  isl_ast_node *ptr = nullptr;

  inline explicit ast_node(__isl_take isl_ast_node *ptr);

public:
  inline /* implicit */ ast_node();
  inline /* implicit */ ast_node(const isl::ast_node &obj);
  inline isl::ast_node &operator=(isl::ast_node obj);
  inline ~ast_node();
  inline __isl_give isl_ast_node *copy() const &;
  inline __isl_give isl_ast_node *copy() && = delete;
  inline __isl_keep isl_ast_node *get() const;
  inline __isl_give isl_ast_node *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::list<isl::ast_node> block_get_children() const;
  inline isl::ast_node for_get_body() const;
  inline isl::ast_expr for_get_cond() const;
  inline isl::ast_expr for_get_inc() const;
  inline isl::ast_expr for_get_init() const;
  inline isl::ast_expr for_get_iterator() const;
  inline bool for_is_degenerate() const;
  inline isl::id get_annotation() const;
  inline enum isl::ast_node_type get_type() const;
  inline isl::ast_expr if_get_cond() const;
  inline isl::ast_node if_get_else() const;
  inline isl::ast_node if_get_then() const;
  inline bool if_has_else() const;
  inline isl::id mark_get_id() const;
  inline isl::ast_node mark_get_node() const;
  inline isl::ast_node set_annotation(isl::id annotation) const;
  inline std::string to_C_str() const;
  inline isl::ast_expr user_get_expr() const;
  typedef isl_ast_node* isl_ptr_t;
};

// declarations for isl::list<ast_node>
inline isl::list<ast_node> manage(__isl_take isl_ast_node_list *ptr);
inline isl::list<ast_node> manage_copy(__isl_keep isl_ast_node_list *ptr);

template <>
class list<ast_node> {
  friend inline isl::list<ast_node> manage(__isl_take isl_ast_node_list *ptr);
  friend inline isl::list<ast_node> manage_copy(__isl_keep isl_ast_node_list *ptr);

protected:
  isl_ast_node_list *ptr = nullptr;

  inline explicit list(__isl_take isl_ast_node_list *ptr);

public:
  inline /* implicit */ list();
  inline /* implicit */ list(const isl::list<ast_node> &obj);
  inline isl::list<ast_node> &operator=(isl::list<ast_node> obj);
  inline ~list<ast_node>();
  inline __isl_give isl_ast_node_list *copy() const &;
  inline __isl_give isl_ast_node_list *copy() && = delete;
  inline __isl_keep isl_ast_node_list *get() const;
  inline __isl_give isl_ast_node_list *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  typedef isl_ast_node_list* isl_ptr_t;
  typedef list_iterator<ast_node> iterator;
  template <typename InputIt1, typename InputIt2>
  inline list(isl::ctx ctx, InputIt1 from, InputIt2 to);

  inline int size() const;
  inline iterator begin() const;
  inline iterator end() const;
  inline ast_node at(int pos) const;
  inline ast_node operator[](int pos) const;
};

// declarations for isl::basic_map
inline isl::basic_map manage(__isl_take isl_basic_map *ptr);
inline isl::basic_map manage_copy(__isl_keep isl_basic_map *ptr);

class basic_map {
  friend inline isl::basic_map manage(__isl_take isl_basic_map *ptr);
  friend inline isl::basic_map manage_copy(__isl_keep isl_basic_map *ptr);

protected:
  isl_basic_map *ptr = nullptr;

  inline explicit basic_map(__isl_take isl_basic_map *ptr);

public:
  inline /* implicit */ basic_map();
  inline /* implicit */ basic_map(const isl::basic_map &obj);
  inline explicit basic_map(isl::ctx ctx, const std::string &str);
  inline explicit basic_map(isl::basic_set domain, isl::basic_set range);
  inline explicit basic_map(isl::aff aff);
  inline explicit basic_map(isl::multi_aff maff);
  inline isl::basic_map &operator=(isl::basic_map obj);
  inline ~basic_map();
  inline __isl_give isl_basic_map *copy() const &;
  inline __isl_give isl_basic_map *copy() && = delete;
  inline __isl_keep isl_basic_map *get() const;
  inline __isl_give isl_basic_map *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::basic_map add_constraint(isl::constraint constraint) const;
  inline isl::basic_map affine_hull() const;
  inline isl::basic_map apply_domain(isl::basic_map bmap2) const;
  inline isl::basic_map apply_range(isl::basic_map bmap2) const;
  inline bool can_curry() const;
  inline bool can_uncurry() const;
  inline isl::basic_map curry() const;
  inline isl::basic_set deltas() const;
  inline isl::basic_map detect_equalities() const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::basic_set domain() const;
  static inline isl::basic_map empty(isl::space space);
  inline isl::basic_map flatten() const;
  inline isl::basic_map flatten_domain() const;
  inline isl::basic_map flatten_range() const;
  inline void foreach_constraint(const std::function<void(isl::constraint)> &fn) const;
  static inline isl::basic_map from_domain(isl::basic_set bset);
  static inline isl::basic_map from_range(isl::basic_set bset);
  inline isl::list<isl::constraint> get_constraint_list() const;
  inline isl::space get_space() const;
  inline std::string get_tuple_name(enum isl::dim_type type) const;
  inline isl::basic_map gist(isl::basic_map context) const;
  inline isl::basic_map intersect(isl::basic_map bmap2) const;
  inline isl::basic_map intersect_domain(isl::basic_set bset) const;
  inline isl::basic_map intersect_range(isl::basic_set bset) const;
  inline bool is_empty() const;
  inline bool is_equal(const isl::basic_map &bmap2) const;
  inline bool is_subset(const isl::basic_map &bmap2) const;
  inline isl::map lexmax() const;
  inline isl::map lexmin() const;
  inline int n_constraint() const;
  inline isl::basic_map project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::basic_map reverse() const;
  inline isl::basic_map sample() const;
  inline isl::basic_map uncurry() const;
  inline isl::map unite(isl::basic_map bmap2) const;
  inline isl::basic_set wrap() const;
  typedef isl_basic_map* isl_ptr_t;
};

// declarations for isl::list<basic_map>
inline isl::list<basic_map> manage(__isl_take isl_basic_map_list *ptr);
inline isl::list<basic_map> manage_copy(__isl_keep isl_basic_map_list *ptr);

template <>
class list<basic_map> {
  friend inline isl::list<basic_map> manage(__isl_take isl_basic_map_list *ptr);
  friend inline isl::list<basic_map> manage_copy(__isl_keep isl_basic_map_list *ptr);

protected:
  isl_basic_map_list *ptr = nullptr;

  inline explicit list(__isl_take isl_basic_map_list *ptr);

public:
  inline /* implicit */ list();
  inline /* implicit */ list(const isl::list<basic_map> &obj);
  inline isl::list<basic_map> &operator=(isl::list<basic_map> obj);
  inline ~list<basic_map>();
  inline __isl_give isl_basic_map_list *copy() const &;
  inline __isl_give isl_basic_map_list *copy() && = delete;
  inline __isl_keep isl_basic_map_list *get() const;
  inline __isl_give isl_basic_map_list *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  inline isl::basic_map intersect() const;
  typedef isl_basic_map_list* isl_ptr_t;
  typedef list_iterator<basic_map> iterator;
  template <typename InputIt1, typename InputIt2>
  inline list(isl::ctx ctx, InputIt1 from, InputIt2 to);

  inline int size() const;
  inline iterator begin() const;
  inline iterator end() const;
  inline basic_map at(int pos) const;
  inline basic_map operator[](int pos) const;
};

// declarations for isl::basic_set
inline isl::basic_set manage(__isl_take isl_basic_set *ptr);
inline isl::basic_set manage_copy(__isl_keep isl_basic_set *ptr);

class basic_set {
  friend inline isl::basic_set manage(__isl_take isl_basic_set *ptr);
  friend inline isl::basic_set manage_copy(__isl_keep isl_basic_set *ptr);

protected:
  isl_basic_set *ptr = nullptr;

  inline explicit basic_set(__isl_take isl_basic_set *ptr);

public:
  inline /* implicit */ basic_set();
  inline /* implicit */ basic_set(const isl::basic_set &obj);
  inline explicit basic_set(isl::ctx ctx, const std::string &str);
  inline /* implicit */ basic_set(isl::point pnt);
  inline isl::basic_set &operator=(isl::basic_set obj);
  inline ~basic_set();
  inline __isl_give isl_basic_set *copy() const &;
  inline __isl_give isl_basic_set *copy() && = delete;
  inline __isl_keep isl_basic_set *get() const;
  inline __isl_give isl_basic_set *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::basic_set add_constraint(isl::constraint constraint) const;
  inline isl::basic_set add_dims(enum isl::dim_type type, unsigned int n) const;
  inline isl::basic_set affine_hull() const;
  inline isl::basic_set apply(isl::basic_map bmap) const;
  inline isl::set compute_divs() const;
  inline isl::basic_set detect_equalities() const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::val dim_max_val(int pos) const;
  inline isl::basic_set flatten() const;
  inline void foreach_constraint(const std::function<void(isl::constraint)> &fn) const;
  inline isl::basic_set from_params() const;
  inline isl::list<isl::constraint> get_constraint_list() const;
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline isl::local_space get_local_space() const;
  inline isl::space get_space() const;
  inline isl::basic_set gist(isl::basic_set context) const;
  inline isl::basic_set intersect(isl::basic_set bset2) const;
  inline isl::basic_set intersect_params(isl::basic_set bset2) const;
  inline bool involves_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline bool is_empty() const;
  inline bool is_equal(const isl::basic_set &bset2) const;
  inline bool is_subset(const isl::basic_set &bset2) const;
  inline bool is_universe() const;
  inline bool is_wrapping() const;
  inline isl::set lexmax() const;
  inline isl::set lexmin() const;
  inline isl::val max_val(const isl::aff &obj) const;
  inline int n_constraint() const;
  inline unsigned int n_dim() const;
  inline unsigned int n_param() const;
  static inline isl::basic_set nat_universe(isl::space dim);
  inline isl::basic_set params() const;
  inline bool plain_is_universe() const;
  inline isl::basic_set project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::basic_set sample() const;
  inline isl::point sample_point() const;
  inline isl::basic_set set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const;
  inline isl::basic_set set_tuple_id(isl::id id) const;
  inline isl::set unite(isl::basic_set bset2) const;
  static inline isl::basic_set universe(isl::space space);
  inline isl::basic_map unwrap() const;
  typedef isl_basic_set* isl_ptr_t;
};

// declarations for isl::list<basic_set>
inline isl::list<basic_set> manage(__isl_take isl_basic_set_list *ptr);
inline isl::list<basic_set> manage_copy(__isl_keep isl_basic_set_list *ptr);

template <>
class list<basic_set> {
  friend inline isl::list<basic_set> manage(__isl_take isl_basic_set_list *ptr);
  friend inline isl::list<basic_set> manage_copy(__isl_keep isl_basic_set_list *ptr);

protected:
  isl_basic_set_list *ptr = nullptr;

  inline explicit list(__isl_take isl_basic_set_list *ptr);

public:
  inline /* implicit */ list();
  inline /* implicit */ list(const isl::list<basic_set> &obj);
  inline isl::list<basic_set> &operator=(isl::list<basic_set> obj);
  inline ~list<basic_set>();
  inline __isl_give isl_basic_set_list *copy() const &;
  inline __isl_give isl_basic_set_list *copy() && = delete;
  inline __isl_keep isl_basic_set_list *get() const;
  inline __isl_give isl_basic_set_list *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  typedef isl_basic_set_list* isl_ptr_t;
  typedef list_iterator<basic_set> iterator;
  template <typename InputIt1, typename InputIt2>
  inline list(isl::ctx ctx, InputIt1 from, InputIt2 to);

  inline int size() const;
  inline iterator begin() const;
  inline iterator end() const;
  inline basic_set at(int pos) const;
  inline basic_set operator[](int pos) const;
};

// declarations for isl::constraint
inline isl::constraint manage(__isl_take isl_constraint *ptr);
inline isl::constraint manage_copy(__isl_keep isl_constraint *ptr);

class constraint {
  friend inline isl::constraint manage(__isl_take isl_constraint *ptr);
  friend inline isl::constraint manage_copy(__isl_keep isl_constraint *ptr);

protected:
  isl_constraint *ptr = nullptr;

  inline explicit constraint(__isl_take isl_constraint *ptr);

public:
  inline /* implicit */ constraint();
  inline /* implicit */ constraint(const isl::constraint &obj);
  inline isl::constraint &operator=(isl::constraint obj);
  inline ~constraint();
  inline __isl_give isl_constraint *copy() const &;
  inline __isl_give isl_constraint *copy() && = delete;
  inline __isl_keep isl_constraint *get() const;
  inline __isl_give isl_constraint *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  static inline isl::constraint alloc_equality(isl::local_space ls);
  static inline isl::constraint alloc_inequality(isl::local_space ls);
  inline int cmp_last_non_zero(const isl::constraint &c2) const;
  inline int dim(enum isl::dim_type type) const;
  inline isl::aff get_aff() const;
  inline isl::aff get_bound(enum isl::dim_type type, int pos) const;
  inline isl::val get_coefficient_val(enum isl::dim_type type, int pos) const;
  inline isl::val get_constant_val() const;
  inline std::string get_dim_name(enum isl::dim_type type, unsigned int pos) const;
  inline isl::aff get_div(int pos) const;
  inline isl::local_space get_local_space() const;
  inline isl::space get_space() const;
  inline bool involves_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline int is_div_constraint() const;
  inline bool is_equal(const isl::constraint &constraint2) const;
  inline bool is_equality() const;
  inline bool is_lower_bound(enum isl::dim_type type, unsigned int pos) const;
  inline bool is_upper_bound(enum isl::dim_type type, unsigned int pos) const;
  inline int plain_cmp(const isl::constraint &c2) const;
  inline isl::constraint set_coefficient_si(enum isl::dim_type type, int pos, int v) const;
  inline isl::constraint set_coefficient_val(enum isl::dim_type type, int pos, isl::val v) const;
  inline isl::constraint set_constant_si(int v) const;
  inline isl::constraint set_constant_val(isl::val v) const;
  typedef isl_constraint* isl_ptr_t;
};

// declarations for isl::list<constraint>
inline isl::list<constraint> manage(__isl_take isl_constraint_list *ptr);
inline isl::list<constraint> manage_copy(__isl_keep isl_constraint_list *ptr);

template <>
class list<constraint> {
  friend inline isl::list<constraint> manage(__isl_take isl_constraint_list *ptr);
  friend inline isl::list<constraint> manage_copy(__isl_keep isl_constraint_list *ptr);

protected:
  isl_constraint_list *ptr = nullptr;

  inline explicit list(__isl_take isl_constraint_list *ptr);

public:
  inline /* implicit */ list();
  inline /* implicit */ list(const isl::list<constraint> &obj);
  inline isl::list<constraint> &operator=(isl::list<constraint> obj);
  inline ~list<constraint>();
  inline __isl_give isl_constraint_list *copy() const &;
  inline __isl_give isl_constraint_list *copy() && = delete;
  inline __isl_keep isl_constraint_list *get() const;
  inline __isl_give isl_constraint_list *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  typedef isl_constraint_list* isl_ptr_t;
  typedef list_iterator<constraint> iterator;
  template <typename InputIt1, typename InputIt2>
  inline list(isl::ctx ctx, InputIt1 from, InputIt2 to);

  inline int size() const;
  inline iterator begin() const;
  inline iterator end() const;
  inline constraint at(int pos) const;
  inline constraint operator[](int pos) const;
};

// declarations for isl::list<id>
inline isl::list<id> manage(__isl_take isl_id_list *ptr);
inline isl::list<id> manage_copy(__isl_keep isl_id_list *ptr);

template <>
class list<id> {
  friend inline isl::list<id> manage(__isl_take isl_id_list *ptr);
  friend inline isl::list<id> manage_copy(__isl_keep isl_id_list *ptr);

protected:
  isl_id_list *ptr = nullptr;

  inline explicit list(__isl_take isl_id_list *ptr);

public:
  inline /* implicit */ list();
  inline /* implicit */ list(const isl::list<id> &obj);
  inline isl::list<id> &operator=(isl::list<id> obj);
  inline ~list<id>();
  inline __isl_give isl_id_list *copy() const &;
  inline __isl_give isl_id_list *copy() && = delete;
  inline __isl_keep isl_id_list *get() const;
  inline __isl_give isl_id_list *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  typedef isl_id_list* isl_ptr_t;
  typedef list_iterator<id> iterator;
  template <typename InputIt1, typename InputIt2>
  inline list(isl::ctx ctx, InputIt1 from, InputIt2 to);

  inline int size() const;
  inline iterator begin() const;
  inline iterator end() const;
  inline id at(int pos) const;
  inline id operator[](int pos) const;
};

// declarations for isl::local_space
inline isl::local_space manage(__isl_take isl_local_space *ptr);
inline isl::local_space manage_copy(__isl_keep isl_local_space *ptr);

class local_space {
  friend inline isl::local_space manage(__isl_take isl_local_space *ptr);
  friend inline isl::local_space manage_copy(__isl_keep isl_local_space *ptr);

protected:
  isl_local_space *ptr = nullptr;

  inline explicit local_space(__isl_take isl_local_space *ptr);

public:
  inline /* implicit */ local_space();
  inline /* implicit */ local_space(const isl::local_space &obj);
  inline explicit local_space(isl::space dim);
  inline isl::local_space &operator=(isl::local_space obj);
  inline ~local_space();
  inline __isl_give isl_local_space *copy() const &;
  inline __isl_give isl_local_space *copy() && = delete;
  inline __isl_keep isl_local_space *get() const;
  inline __isl_give isl_local_space *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  inline isl::local_space add_dims(enum isl::dim_type type, unsigned int n) const;
  inline int dim(enum isl::dim_type type) const;
  inline isl::local_space domain() const;
  inline isl::local_space drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline int find_dim_by_name(enum isl::dim_type type, const std::string &name) const;
  inline isl::local_space flatten_domain() const;
  inline isl::local_space flatten_range() const;
  inline isl::local_space from_domain() const;
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline std::string get_dim_name(enum isl::dim_type type, unsigned int pos) const;
  inline isl::aff get_div(int pos) const;
  inline isl::space get_space() const;
  inline bool has_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline bool has_dim_name(enum isl::dim_type type, unsigned int pos) const;
  inline isl::local_space insert_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::local_space intersect(isl::local_space ls2) const;
  inline bool is_equal(const isl::local_space &ls2) const;
  inline bool is_params() const;
  inline bool is_set() const;
  inline isl::basic_map lifting() const;
  inline isl::local_space range() const;
  inline isl::local_space set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const;
  inline isl::local_space set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const;
  inline isl::local_space set_tuple_id(enum isl::dim_type type, isl::id id) const;
  inline isl::local_space wrap() const;
  typedef isl_local_space* isl_ptr_t;
};

// declarations for isl::map
inline isl::map manage(__isl_take isl_map *ptr);
inline isl::map manage_copy(__isl_keep isl_map *ptr);

class map {
  friend inline isl::map manage(__isl_take isl_map *ptr);
  friend inline isl::map manage_copy(__isl_keep isl_map *ptr);

protected:
  isl_map *ptr = nullptr;

  inline explicit map(__isl_take isl_map *ptr);

public:
  inline /* implicit */ map();
  inline /* implicit */ map(const isl::map &obj);
  inline explicit map(isl::ctx ctx, const std::string &str);
  inline /* implicit */ map(isl::basic_map bmap);
  inline explicit map(isl::set domain, isl::set range);
  inline explicit map(isl::aff aff);
  inline explicit map(isl::multi_aff maff);
  inline isl::map &operator=(isl::map obj);
  inline ~map();
  inline __isl_give isl_map *copy() const &;
  inline __isl_give isl_map *copy() && = delete;
  inline __isl_keep isl_map *get() const;
  inline __isl_give isl_map *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::map add_constraint(isl::constraint constraint) const;
  inline isl::map add_dims(enum isl::dim_type type, unsigned int n) const;
  inline isl::basic_map affine_hull() const;
  inline isl::map apply_domain(isl::map map2) const;
  inline isl::map apply_range(isl::map map2) const;
  inline bool can_curry() const;
  inline bool can_range_curry() const;
  inline bool can_uncurry() const;
  inline isl::map coalesce() const;
  inline isl::map complement() const;
  inline isl::map compute_divs() const;
  inline isl::map curry() const;
  inline isl::set deltas() const;
  inline isl::map detect_equalities() const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::set domain() const;
  inline isl::map domain_factor_domain() const;
  inline isl::map domain_factor_range() const;
  inline isl::map domain_map() const;
  inline isl::map domain_product(isl::map map2) const;
  static inline isl::map empty(isl::space space);
  inline int find_dim_by_id(enum isl::dim_type type, const isl::id &id) const;
  inline int find_dim_by_name(enum isl::dim_type type, const std::string &name) const;
  inline isl::map flatten() const;
  inline isl::map flatten_domain() const;
  inline isl::map flatten_range() const;
  inline void foreach_basic_map(const std::function<void(isl::basic_map)> &fn) const;
  static inline isl::map from(isl::pw_multi_aff pma);
  static inline isl::map from_domain(isl::set set);
  static inline isl::map from_range(isl::set set);
  static inline isl::map from_union_map(isl::union_map umap);
  inline isl::list<isl::basic_map> get_basic_map_list() const;
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline isl::space get_space() const;
  inline isl::id get_tuple_id(enum isl::dim_type type) const;
  inline std::string get_tuple_name(enum isl::dim_type type) const;
  inline isl::map gist(isl::map context) const;
  inline isl::map gist_domain(isl::set context) const;
  inline bool has_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline bool has_tuple_id(enum isl::dim_type type) const;
  inline bool has_tuple_name(enum isl::dim_type type) const;
  static inline isl::map identity(isl::space dim);
  inline isl::map insert_dims(enum isl::dim_type type, unsigned int pos, unsigned int n) const;
  inline isl::map intersect(isl::map map2) const;
  inline isl::map intersect_domain(isl::set set) const;
  inline isl::map intersect_params(isl::set params) const;
  inline isl::map intersect_range(isl::set set) const;
  inline bool is_bijective() const;
  inline bool is_disjoint(const isl::map &map2) const;
  inline bool is_empty() const;
  inline bool is_equal(const isl::map &map2) const;
  inline bool is_injective() const;
  inline bool is_single_valued() const;
  inline bool is_strict_subset(const isl::map &map2) const;
  inline bool is_subset(const isl::map &map2) const;
  inline isl::map lexmax() const;
  inline isl::map lexmin() const;
  inline int n_basic_map() const;
  inline isl::set params() const;
  inline isl::basic_map polyhedral_hull() const;
  inline isl::map project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::set range() const;
  inline isl::map range_curry() const;
  inline isl::map range_factor_domain() const;
  inline isl::map range_factor_range() const;
  inline isl::map range_map() const;
  inline isl::map range_product(isl::map map2) const;
  inline isl::map remove_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::map reset_tuple_id(enum isl::dim_type type) const;
  inline isl::map reverse() const;
  inline isl::basic_map sample() const;
  inline isl::map set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const;
  inline isl::map set_tuple_id(enum isl::dim_type type, isl::id id) const;
  inline isl::map set_tuple_name(enum isl::dim_type type, const std::string &s) const;
  inline isl::basic_map simple_hull() const;
  inline isl::map subtract(isl::map map2) const;
  inline isl::map uncurry() const;
  inline isl::map unite(isl::map map2) const;
  static inline isl::map universe(isl::space space);
  inline isl::basic_map unshifted_simple_hull() const;
  inline isl::set wrap() const;
  typedef isl_map* isl_ptr_t;
};

// declarations for isl::multi_aff
inline isl::multi_aff manage(__isl_take isl_multi_aff *ptr);
inline isl::multi_aff manage_copy(__isl_keep isl_multi_aff *ptr);

class multi_aff {
  friend inline isl::multi_aff manage(__isl_take isl_multi_aff *ptr);
  friend inline isl::multi_aff manage_copy(__isl_keep isl_multi_aff *ptr);

protected:
  isl_multi_aff *ptr = nullptr;

  inline explicit multi_aff(__isl_take isl_multi_aff *ptr);

public:
  inline /* implicit */ multi_aff();
  inline /* implicit */ multi_aff(const isl::multi_aff &obj);
  inline /* implicit */ multi_aff(isl::aff aff);
  inline explicit multi_aff(isl::ctx ctx, const std::string &str);
  inline isl::multi_aff &operator=(isl::multi_aff obj);
  inline ~multi_aff();
  inline __isl_give isl_multi_aff *copy() const &;
  inline __isl_give isl_multi_aff *copy() && = delete;
  inline __isl_keep isl_multi_aff *get() const;
  inline __isl_give isl_multi_aff *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::multi_aff add(isl::multi_aff multi2) const;
  inline isl::multi_aff add_dims(enum isl::dim_type type, unsigned int n) const;
  inline isl::multi_aff align_params(isl::space model) const;
  inline unsigned int dim(enum isl::dim_type type) const;
  static inline isl::multi_aff domain_map(isl::space space);
  inline isl::multi_aff drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::multi_aff factor_domain() const;
  inline isl::multi_aff factor_range() const;
  inline int find_dim_by_id(enum isl::dim_type type, const isl::id &id) const;
  inline int find_dim_by_name(enum isl::dim_type type, const std::string &name) const;
  inline isl::multi_aff flat_range_product(isl::multi_aff multi2) const;
  inline isl::multi_aff flatten_range() const;
  inline isl::multi_aff floor() const;
  inline isl::multi_aff from_range() const;
  inline isl::aff get_aff(int pos) const;
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline isl::space get_domain_space() const;
  inline isl::space get_space() const;
  inline isl::id get_tuple_id(enum isl::dim_type type) const;
  inline std::string get_tuple_name(enum isl::dim_type type) const;
  inline bool has_tuple_id(enum isl::dim_type type) const;
  static inline isl::multi_aff identity(isl::space space);
  inline isl::multi_aff insert_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::multi_aff mod_multi_val(isl::multi_val mv) const;
  inline isl::multi_aff neg() const;
  inline isl::multi_aff product(isl::multi_aff multi2) const;
  static inline isl::multi_aff project_out_map(isl::space space, enum isl::dim_type type, unsigned int first, unsigned int n);
  inline isl::multi_aff pullback(isl::multi_aff ma2) const;
  inline isl::multi_aff range_factor_domain() const;
  inline isl::multi_aff range_factor_range() const;
  static inline isl::multi_aff range_map(isl::space space);
  inline isl::multi_aff range_product(isl::multi_aff multi2) const;
  inline isl::multi_aff range_splice(unsigned int pos, isl::multi_aff multi2) const;
  inline isl::multi_aff reset_tuple_id(enum isl::dim_type type) const;
  inline isl::multi_aff reset_user() const;
  inline isl::multi_aff scale_down(isl::multi_val mv) const;
  inline isl::multi_aff scale_down_val(isl::val v) const;
  inline isl::multi_aff scale_multi_val(isl::multi_val mv) const;
  inline isl::multi_aff scale_val(isl::val v) const;
  inline isl::multi_aff set_aff(int pos, isl::aff el) const;
  inline isl::multi_aff set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const;
  inline isl::multi_aff set_tuple_id(enum isl::dim_type type, isl::id id) const;
  inline isl::multi_aff set_tuple_name(enum isl::dim_type type, const std::string &s) const;
  inline isl::multi_aff splice(unsigned int in_pos, unsigned int out_pos, isl::multi_aff multi2) const;
  inline isl::multi_aff sub(isl::multi_aff multi2) const;
  static inline isl::multi_aff zero(isl::space space);
  typedef isl_multi_aff* isl_ptr_t;
};

// declarations for isl::multi_pw_aff
inline isl::multi_pw_aff manage(__isl_take isl_multi_pw_aff *ptr);
inline isl::multi_pw_aff manage_copy(__isl_keep isl_multi_pw_aff *ptr);

class multi_pw_aff {
  friend inline isl::multi_pw_aff manage(__isl_take isl_multi_pw_aff *ptr);
  friend inline isl::multi_pw_aff manage_copy(__isl_keep isl_multi_pw_aff *ptr);

protected:
  isl_multi_pw_aff *ptr = nullptr;

  inline explicit multi_pw_aff(__isl_take isl_multi_pw_aff *ptr);

public:
  inline /* implicit */ multi_pw_aff();
  inline /* implicit */ multi_pw_aff(const isl::multi_pw_aff &obj);
  inline /* implicit */ multi_pw_aff(isl::multi_aff ma);
  inline /* implicit */ multi_pw_aff(isl::pw_aff pa);
  inline /* implicit */ multi_pw_aff(isl::pw_multi_aff pma);
  inline explicit multi_pw_aff(isl::ctx ctx, const std::string &str);
  inline isl::multi_pw_aff &operator=(isl::multi_pw_aff obj);
  inline ~multi_pw_aff();
  inline __isl_give isl_multi_pw_aff *copy() const &;
  inline __isl_give isl_multi_pw_aff *copy() && = delete;
  inline __isl_keep isl_multi_pw_aff *get() const;
  inline __isl_give isl_multi_pw_aff *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::multi_pw_aff add(isl::multi_pw_aff multi2) const;
  inline isl::multi_pw_aff add_dims(enum isl::dim_type type, unsigned int n) const;
  inline isl::multi_pw_aff align_params(isl::space model) const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::set domain() const;
  inline isl::multi_pw_aff drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::multi_pw_aff factor_domain() const;
  inline isl::multi_pw_aff factor_range() const;
  inline int find_dim_by_id(enum isl::dim_type type, const isl::id &id) const;
  inline int find_dim_by_name(enum isl::dim_type type, const std::string &name) const;
  inline isl::multi_pw_aff flat_range_product(isl::multi_pw_aff multi2) const;
  inline isl::multi_pw_aff flatten_range() const;
  inline isl::multi_pw_aff from_range() const;
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline isl::space get_domain_space() const;
  inline isl::pw_aff get_pw_aff(int pos) const;
  inline isl::space get_space() const;
  inline isl::id get_tuple_id(enum isl::dim_type type) const;
  inline std::string get_tuple_name(enum isl::dim_type type) const;
  inline bool has_tuple_id(enum isl::dim_type type) const;
  static inline isl::multi_pw_aff identity(isl::space space);
  inline isl::multi_pw_aff insert_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline bool is_equal(const isl::multi_pw_aff &mpa2) const;
  inline isl::multi_pw_aff mod_multi_val(isl::multi_val mv) const;
  inline isl::multi_pw_aff neg() const;
  inline isl::multi_pw_aff product(isl::multi_pw_aff multi2) const;
  inline isl::multi_pw_aff pullback(isl::multi_aff ma) const;
  inline isl::multi_pw_aff pullback(isl::pw_multi_aff pma) const;
  inline isl::multi_pw_aff pullback(isl::multi_pw_aff mpa2) const;
  inline isl::multi_pw_aff range_factor_domain() const;
  inline isl::multi_pw_aff range_factor_range() const;
  inline isl::multi_pw_aff range_product(isl::multi_pw_aff multi2) const;
  inline isl::multi_pw_aff range_splice(unsigned int pos, isl::multi_pw_aff multi2) const;
  inline isl::multi_pw_aff reset_tuple_id(enum isl::dim_type type) const;
  inline isl::multi_pw_aff reset_user() const;
  inline isl::multi_pw_aff scale_down(isl::multi_val mv) const;
  inline isl::multi_pw_aff scale_down_val(isl::val v) const;
  inline isl::multi_pw_aff scale_multi_val(isl::multi_val mv) const;
  inline isl::multi_pw_aff scale_val(isl::val v) const;
  inline isl::multi_pw_aff set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const;
  inline isl::multi_pw_aff set_pw_aff(int pos, isl::pw_aff el) const;
  inline isl::multi_pw_aff set_tuple_id(enum isl::dim_type type, isl::id id) const;
  inline isl::multi_pw_aff set_tuple_name(enum isl::dim_type type, const std::string &s) const;
  inline isl::multi_pw_aff splice(unsigned int in_pos, unsigned int out_pos, isl::multi_pw_aff multi2) const;
  inline isl::multi_pw_aff sub(isl::multi_pw_aff multi2) const;
  static inline isl::multi_pw_aff zero(isl::space space);
  typedef isl_multi_pw_aff* isl_ptr_t;
};

// declarations for isl::multi_union_pw_aff
inline isl::multi_union_pw_aff manage(__isl_take isl_multi_union_pw_aff *ptr);
inline isl::multi_union_pw_aff manage_copy(__isl_keep isl_multi_union_pw_aff *ptr);

class multi_union_pw_aff {
  friend inline isl::multi_union_pw_aff manage(__isl_take isl_multi_union_pw_aff *ptr);
  friend inline isl::multi_union_pw_aff manage_copy(__isl_keep isl_multi_union_pw_aff *ptr);

protected:
  isl_multi_union_pw_aff *ptr = nullptr;

  inline explicit multi_union_pw_aff(__isl_take isl_multi_union_pw_aff *ptr);

public:
  inline /* implicit */ multi_union_pw_aff();
  inline /* implicit */ multi_union_pw_aff(const isl::multi_union_pw_aff &obj);
  inline /* implicit */ multi_union_pw_aff(isl::union_pw_aff upa);
  inline /* implicit */ multi_union_pw_aff(isl::multi_pw_aff mpa);
  inline explicit multi_union_pw_aff(isl::union_set domain, isl::multi_val mv);
  inline explicit multi_union_pw_aff(isl::union_set domain, isl::multi_aff ma);
  inline explicit multi_union_pw_aff(isl::ctx ctx, const std::string &str);
  inline isl::multi_union_pw_aff &operator=(isl::multi_union_pw_aff obj);
  inline ~multi_union_pw_aff();
  inline __isl_give isl_multi_union_pw_aff *copy() const &;
  inline __isl_give isl_multi_union_pw_aff *copy() && = delete;
  inline __isl_keep isl_multi_union_pw_aff *get() const;
  inline __isl_give isl_multi_union_pw_aff *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::multi_union_pw_aff add(isl::multi_union_pw_aff multi2) const;
  inline isl::multi_union_pw_aff align_params(isl::space model) const;
  inline isl::multi_union_pw_aff apply_pw_multi_aff(isl::pw_multi_aff pma) const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::union_set domain() const;
  inline isl::multi_union_pw_aff drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::multi_pw_aff extract_multi_pw_aff(isl::space space) const;
  inline isl::multi_union_pw_aff factor_domain() const;
  inline isl::multi_union_pw_aff factor_range() const;
  inline int find_dim_by_id(enum isl::dim_type type, const isl::id &id) const;
  inline int find_dim_by_name(enum isl::dim_type type, const std::string &name) const;
  inline isl::multi_union_pw_aff flat_range_product(isl::multi_union_pw_aff multi2) const;
  inline isl::multi_union_pw_aff flatten_range() const;
  inline isl::multi_union_pw_aff floor() const;
  inline isl::multi_union_pw_aff from_range() const;
  static inline isl::multi_union_pw_aff from_union_map(isl::union_map umap);
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline isl::space get_domain_space() const;
  inline isl::space get_space() const;
  inline isl::id get_tuple_id(enum isl::dim_type type) const;
  inline std::string get_tuple_name(enum isl::dim_type type) const;
  inline isl::union_pw_aff get_union_pw_aff(int pos) const;
  inline isl::multi_union_pw_aff gist(isl::union_set context) const;
  inline bool has_tuple_id(enum isl::dim_type type) const;
  inline isl::multi_union_pw_aff mod_multi_val(isl::multi_val mv) const;
  inline isl::multi_union_pw_aff neg() const;
  inline isl::multi_union_pw_aff pullback(isl::union_pw_multi_aff upma) const;
  inline isl::multi_union_pw_aff range_factor_domain() const;
  inline isl::multi_union_pw_aff range_factor_range() const;
  inline isl::multi_union_pw_aff range_product(isl::multi_union_pw_aff multi2) const;
  inline isl::multi_union_pw_aff range_splice(unsigned int pos, isl::multi_union_pw_aff multi2) const;
  inline isl::multi_union_pw_aff reset_tuple_id(enum isl::dim_type type) const;
  inline isl::multi_union_pw_aff reset_user() const;
  inline isl::multi_union_pw_aff scale_down(isl::multi_val mv) const;
  inline isl::multi_union_pw_aff scale_down_val(isl::val v) const;
  inline isl::multi_union_pw_aff scale_multi_val(isl::multi_val mv) const;
  inline isl::multi_union_pw_aff scale_val(isl::val v) const;
  inline isl::multi_union_pw_aff set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const;
  inline isl::multi_union_pw_aff set_tuple_id(enum isl::dim_type type, isl::id id) const;
  inline isl::multi_union_pw_aff set_tuple_name(enum isl::dim_type type, const std::string &s) const;
  inline isl::multi_union_pw_aff set_union_pw_aff(int pos, isl::union_pw_aff el) const;
  inline isl::multi_union_pw_aff sub(isl::multi_union_pw_aff multi2) const;
  inline isl::multi_union_pw_aff union_add(isl::multi_union_pw_aff mupa2) const;
  static inline isl::multi_union_pw_aff zero(isl::space space);
  inline isl::union_set zero_union_set() const;
  typedef isl_multi_union_pw_aff* isl_ptr_t;
};

// declarations for isl::multi_val
inline isl::multi_val manage(__isl_take isl_multi_val *ptr);
inline isl::multi_val manage_copy(__isl_keep isl_multi_val *ptr);

class multi_val {
  friend inline isl::multi_val manage(__isl_take isl_multi_val *ptr);
  friend inline isl::multi_val manage_copy(__isl_keep isl_multi_val *ptr);

protected:
  isl_multi_val *ptr = nullptr;

  inline explicit multi_val(__isl_take isl_multi_val *ptr);

public:
  inline /* implicit */ multi_val();
  inline /* implicit */ multi_val(const isl::multi_val &obj);
  inline isl::multi_val &operator=(isl::multi_val obj);
  inline ~multi_val();
  inline __isl_give isl_multi_val *copy() const &;
  inline __isl_give isl_multi_val *copy() && = delete;
  inline __isl_keep isl_multi_val *get() const;
  inline __isl_give isl_multi_val *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::multi_val add(isl::multi_val multi2) const;
  inline isl::multi_val add_dims(enum isl::dim_type type, unsigned int n) const;
  inline isl::multi_val align_params(isl::space model) const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::multi_val drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::multi_val factor_domain() const;
  inline isl::multi_val factor_range() const;
  inline int find_dim_by_id(enum isl::dim_type type, const isl::id &id) const;
  inline int find_dim_by_name(enum isl::dim_type type, const std::string &name) const;
  inline isl::multi_val flat_range_product(isl::multi_val multi2) const;
  inline isl::multi_val flatten_range() const;
  inline isl::multi_val from_range() const;
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline isl::space get_domain_space() const;
  inline isl::space get_space() const;
  inline isl::id get_tuple_id(enum isl::dim_type type) const;
  inline std::string get_tuple_name(enum isl::dim_type type) const;
  inline isl::val get_val(int pos) const;
  inline bool has_tuple_id(enum isl::dim_type type) const;
  inline isl::multi_val insert_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::multi_val mod_multi_val(isl::multi_val mv) const;
  inline isl::multi_val neg() const;
  inline isl::multi_val product(isl::multi_val multi2) const;
  inline isl::multi_val range_factor_domain() const;
  inline isl::multi_val range_factor_range() const;
  inline isl::multi_val range_product(isl::multi_val multi2) const;
  inline isl::multi_val range_splice(unsigned int pos, isl::multi_val multi2) const;
  inline isl::multi_val reset_tuple_id(enum isl::dim_type type) const;
  inline isl::multi_val reset_user() const;
  inline isl::multi_val scale_down(isl::multi_val mv) const;
  inline isl::multi_val scale_down_val(isl::val v) const;
  inline isl::multi_val scale_multi_val(isl::multi_val mv) const;
  inline isl::multi_val scale_val(isl::val v) const;
  inline isl::multi_val set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const;
  inline isl::multi_val set_tuple_id(enum isl::dim_type type, isl::id id) const;
  inline isl::multi_val set_tuple_name(enum isl::dim_type type, const std::string &s) const;
  inline isl::multi_val set_val(int pos, isl::val el) const;
  inline isl::multi_val splice(unsigned int in_pos, unsigned int out_pos, isl::multi_val multi2) const;
  inline isl::multi_val sub(isl::multi_val multi2) const;
  static inline isl::multi_val zero(isl::space space);
  typedef isl_multi_val* isl_ptr_t;
};

// declarations for isl::point
inline isl::point manage(__isl_take isl_point *ptr);
inline isl::point manage_copy(__isl_keep isl_point *ptr);

class point {
  friend inline isl::point manage(__isl_take isl_point *ptr);
  friend inline isl::point manage_copy(__isl_keep isl_point *ptr);

protected:
  isl_point *ptr = nullptr;

  inline explicit point(__isl_take isl_point *ptr);

public:
  inline /* implicit */ point();
  inline /* implicit */ point(const isl::point &obj);
  inline explicit point(isl::space dim);
  inline isl::point &operator=(isl::point obj);
  inline ~point();
  inline __isl_give isl_point *copy() const &;
  inline __isl_give isl_point *copy() && = delete;
  inline __isl_keep isl_point *get() const;
  inline __isl_give isl_point *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::point add_ui(enum isl::dim_type type, int pos, unsigned int val) const;
  inline isl::val get_coordinate_val(enum isl::dim_type type, int pos) const;
  inline isl::space get_space() const;
  inline bool is_void() const;
  inline isl::point sub_ui(enum isl::dim_type type, int pos, unsigned int val) const;
  typedef isl_point* isl_ptr_t;
};

// declarations for isl::pw_aff
inline isl::pw_aff manage(__isl_take isl_pw_aff *ptr);
inline isl::pw_aff manage_copy(__isl_keep isl_pw_aff *ptr);

class pw_aff {
  friend inline isl::pw_aff manage(__isl_take isl_pw_aff *ptr);
  friend inline isl::pw_aff manage_copy(__isl_keep isl_pw_aff *ptr);

protected:
  isl_pw_aff *ptr = nullptr;

  inline explicit pw_aff(__isl_take isl_pw_aff *ptr);

public:
  inline /* implicit */ pw_aff();
  inline /* implicit */ pw_aff(const isl::pw_aff &obj);
  inline /* implicit */ pw_aff(isl::aff aff);
  inline explicit pw_aff(isl::local_space ls);
  inline explicit pw_aff(isl::local_space ls, enum isl::dim_type type, unsigned int pos);
  inline explicit pw_aff(isl::set domain, isl::val v);
  inline explicit pw_aff(isl::ctx ctx, const std::string &str);
  inline isl::pw_aff &operator=(isl::pw_aff obj);
  inline ~pw_aff();
  inline __isl_give isl_pw_aff *copy() const &;
  inline __isl_give isl_pw_aff *copy() && = delete;
  inline __isl_keep isl_pw_aff *get() const;
  inline __isl_give isl_pw_aff *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::pw_aff add(isl::pw_aff pwaff2) const;
  inline isl::pw_aff ceil() const;
  inline isl::pw_aff cond(isl::pw_aff pwaff_true, isl::pw_aff pwaff_false) const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::pw_aff div(isl::pw_aff pa2) const;
  inline isl::set domain() const;
  inline isl::map eq_map(isl::pw_aff pa2) const;
  inline isl::set eq_set(isl::pw_aff pwaff2) const;
  inline isl::pw_aff floor() const;
  inline void foreach_piece(const std::function<void(isl::set, isl::aff)> &fn) const;
  inline isl::set ge_set(isl::pw_aff pwaff2) const;
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline isl::space get_space() const;
  inline isl::id get_tuple_id(enum isl::dim_type type) const;
  inline isl::map gt_map(isl::pw_aff pa2) const;
  inline isl::set gt_set(isl::pw_aff pwaff2) const;
  inline bool has_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline bool has_tuple_id(enum isl::dim_type type) const;
  inline isl::pw_aff intersect_params(isl::set set) const;
  inline bool involves_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline bool involves_nan() const;
  inline bool is_cst() const;
  inline bool is_equal(const isl::pw_aff &pa2) const;
  inline isl::set le_set(isl::pw_aff pwaff2) const;
  inline isl::map lt_map(isl::pw_aff pa2) const;
  inline isl::set lt_set(isl::pw_aff pwaff2) const;
  inline isl::pw_aff max(isl::pw_aff pwaff2) const;
  inline isl::pw_aff min(isl::pw_aff pwaff2) const;
  inline isl::pw_aff mod(isl::val mod) const;
  inline isl::pw_aff mul(isl::pw_aff pwaff2) const;
  inline int n_piece() const;
  inline isl::set ne_set(isl::pw_aff pwaff2) const;
  inline isl::pw_aff neg() const;
  inline isl::set params() const;
  inline isl::pw_aff project_domain_on_params() const;
  inline isl::pw_aff pullback(isl::multi_aff ma) const;
  inline isl::pw_aff pullback(isl::pw_multi_aff pma) const;
  inline isl::pw_aff pullback(isl::multi_pw_aff mpa) const;
  inline isl::pw_aff reset_tuple_id(enum isl::dim_type type) const;
  inline isl::pw_aff scale(isl::val v) const;
  inline isl::pw_aff scale_down(isl::val f) const;
  inline isl::pw_aff set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const;
  inline isl::pw_aff set_tuple_id(enum isl::dim_type type, isl::id id) const;
  inline isl::pw_aff sub(isl::pw_aff pwaff2) const;
  inline isl::pw_aff tdiv_q(isl::pw_aff pa2) const;
  inline isl::pw_aff tdiv_r(isl::pw_aff pa2) const;
  inline isl::pw_aff union_add(isl::pw_aff pwaff2) const;
  typedef isl_pw_aff* isl_ptr_t;
};

// declarations for isl::pw_multi_aff
inline isl::pw_multi_aff manage(__isl_take isl_pw_multi_aff *ptr);
inline isl::pw_multi_aff manage_copy(__isl_keep isl_pw_multi_aff *ptr);

class pw_multi_aff {
  friend inline isl::pw_multi_aff manage(__isl_take isl_pw_multi_aff *ptr);
  friend inline isl::pw_multi_aff manage_copy(__isl_keep isl_pw_multi_aff *ptr);

protected:
  isl_pw_multi_aff *ptr = nullptr;

  inline explicit pw_multi_aff(__isl_take isl_pw_multi_aff *ptr);

public:
  inline /* implicit */ pw_multi_aff();
  inline /* implicit */ pw_multi_aff(const isl::pw_multi_aff &obj);
  inline explicit pw_multi_aff(isl::space space);
  inline /* implicit */ pw_multi_aff(isl::multi_aff ma);
  inline /* implicit */ pw_multi_aff(isl::pw_aff pa);
  inline explicit pw_multi_aff(isl::set domain, isl::multi_val mv);
  inline explicit pw_multi_aff(isl::map map);
  inline explicit pw_multi_aff(isl::ctx ctx, const std::string &str);
  inline isl::pw_multi_aff &operator=(isl::pw_multi_aff obj);
  inline ~pw_multi_aff();
  inline __isl_give isl_pw_multi_aff *copy() const &;
  inline __isl_give isl_pw_multi_aff *copy() && = delete;
  inline __isl_keep isl_pw_multi_aff *get() const;
  inline __isl_give isl_pw_multi_aff *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::pw_multi_aff add(isl::pw_multi_aff pma2) const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::set domain() const;
  inline isl::pw_multi_aff flat_range_product(isl::pw_multi_aff pma2) const;
  inline void foreach_piece(const std::function<void(isl::set, isl::multi_aff)> &fn) const;
  static inline isl::pw_multi_aff from(isl::multi_pw_aff mpa);
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline isl::pw_aff get_pw_aff(int pos) const;
  inline isl::space get_space() const;
  inline isl::id get_tuple_id(enum isl::dim_type type) const;
  inline bool has_tuple_id(enum isl::dim_type type) const;
  inline bool is_equal(const isl::pw_multi_aff &pma2) const;
  inline int n_piece() const;
  inline isl::pw_multi_aff product(isl::pw_multi_aff pma2) const;
  inline isl::pw_multi_aff project_domain_on_params() const;
  static inline isl::pw_multi_aff project_out_map(isl::space space, enum isl::dim_type type, unsigned int first, unsigned int n);
  inline isl::pw_multi_aff pullback(isl::multi_aff ma) const;
  inline isl::pw_multi_aff pullback(isl::pw_multi_aff pma2) const;
  inline isl::pw_multi_aff range_product(isl::pw_multi_aff pma2) const;
  inline isl::pw_multi_aff reset_tuple_id(enum isl::dim_type type) const;
  inline isl::pw_multi_aff scale_down_val(isl::val v) const;
  inline isl::pw_multi_aff scale_val(isl::val v) const;
  inline isl::pw_multi_aff set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const;
  inline isl::pw_multi_aff set_pw_aff(unsigned int pos, isl::pw_aff pa) const;
  inline isl::pw_multi_aff set_tuple_id(enum isl::dim_type type, isl::id id) const;
  inline isl::pw_multi_aff union_add(isl::pw_multi_aff pma2) const;
  typedef isl_pw_multi_aff* isl_ptr_t;
};

// declarations for isl::schedule
inline isl::schedule manage(__isl_take isl_schedule *ptr);
inline isl::schedule manage_copy(__isl_keep isl_schedule *ptr);

class schedule {
  friend inline isl::schedule manage(__isl_take isl_schedule *ptr);
  friend inline isl::schedule manage_copy(__isl_keep isl_schedule *ptr);

protected:
  isl_schedule *ptr = nullptr;

  inline explicit schedule(__isl_take isl_schedule *ptr);

public:
  inline /* implicit */ schedule();
  inline /* implicit */ schedule(const isl::schedule &obj);
  inline explicit schedule(isl::ctx ctx, const std::string &str);
  inline isl::schedule &operator=(isl::schedule obj);
  inline ~schedule();
  inline __isl_give isl_schedule *copy() const &;
  inline __isl_give isl_schedule *copy() && = delete;
  inline __isl_keep isl_schedule *get() const;
  inline __isl_give isl_schedule *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  static inline isl::schedule from_domain(isl::union_set domain);
  inline isl::union_set get_domain() const;
  inline isl::union_map get_map() const;
  inline isl::schedule_node get_root() const;
  inline isl::schedule insert_partial_schedule(isl::multi_union_pw_aff partial) const;
  inline bool plain_is_equal(const isl::schedule &schedule2) const;
  inline isl::schedule pullback(isl::union_pw_multi_aff upma) const;
  inline isl::schedule reset_user() const;
  inline isl::schedule sequence(isl::schedule schedule2) const;
  inline isl::schedule set(isl::schedule schedule2) const;
  typedef isl_schedule* isl_ptr_t;
};

// declarations for isl::schedule_constraints
inline isl::schedule_constraints manage(__isl_take isl_schedule_constraints *ptr);
inline isl::schedule_constraints manage_copy(__isl_keep isl_schedule_constraints *ptr);

class schedule_constraints {
  friend inline isl::schedule_constraints manage(__isl_take isl_schedule_constraints *ptr);
  friend inline isl::schedule_constraints manage_copy(__isl_keep isl_schedule_constraints *ptr);

protected:
  isl_schedule_constraints *ptr = nullptr;

  inline explicit schedule_constraints(__isl_take isl_schedule_constraints *ptr);

public:
  inline /* implicit */ schedule_constraints();
  inline /* implicit */ schedule_constraints(const isl::schedule_constraints &obj);
  inline explicit schedule_constraints(isl::ctx ctx, const std::string &str);
  inline isl::schedule_constraints &operator=(isl::schedule_constraints obj);
  inline ~schedule_constraints();
  inline __isl_give isl_schedule_constraints *copy() const &;
  inline __isl_give isl_schedule_constraints *copy() && = delete;
  inline __isl_keep isl_schedule_constraints *get() const;
  inline __isl_give isl_schedule_constraints *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::schedule compute_schedule() const;
  inline isl::union_map get_coincidence() const;
  inline isl::union_map get_conditional_validity() const;
  inline isl::union_map get_conditional_validity_condition() const;
  inline isl::set get_context() const;
  inline isl::union_set get_domain() const;
  inline isl::multi_union_pw_aff get_prefix() const;
  inline isl::union_map get_proximity() const;
  inline isl::union_map get_validity() const;
  inline isl::schedule_constraints intersect_domain(isl::union_set domain) const;
  static inline isl::schedule_constraints on_domain(isl::union_set domain);
  inline isl::schedule_constraints set_coincidence(isl::union_map coincidence) const;
  inline isl::schedule_constraints set_conditional_validity(isl::union_map condition, isl::union_map validity) const;
  inline isl::schedule_constraints set_context(isl::set context) const;
  inline isl::schedule_constraints set_prefix(isl::multi_union_pw_aff prefix) const;
  inline isl::schedule_constraints set_proximity(isl::union_map proximity) const;
  inline isl::schedule_constraints set_validity(isl::union_map validity) const;
  typedef isl_schedule_constraints* isl_ptr_t;
};

// declarations for isl::schedule_node
inline isl::schedule_node manage(__isl_take isl_schedule_node *ptr);
inline isl::schedule_node manage_copy(__isl_keep isl_schedule_node *ptr);

class schedule_node {
  friend inline isl::schedule_node manage(__isl_take isl_schedule_node *ptr);
  friend inline isl::schedule_node manage_copy(__isl_keep isl_schedule_node *ptr);

protected:
  isl_schedule_node *ptr = nullptr;

  inline explicit schedule_node(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node();
  inline /* implicit */ schedule_node(const isl::schedule_node &obj);
  inline isl::schedule_node &operator=(isl::schedule_node obj);
  inline ~schedule_node();
  inline __isl_give isl_schedule_node *copy() const &;
  inline __isl_give isl_schedule_node *copy() && = delete;
  inline __isl_keep isl_schedule_node *get() const;
  inline __isl_give isl_schedule_node *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  template <class T> inline bool isa();
  template <class T> inline T as();
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::schedule_node ancestor(int generation) const;
  inline isl::schedule_node child(int pos) const;
  inline isl::schedule_node cut() const;
  inline isl::schedule_node del() const;
  inline bool every_descendant(const std::function<bool(isl::schedule_node)> &test) const;
  inline isl::schedule_node first_child() const;
  inline void foreach_descendant_top_down(const std::function<bool(isl::schedule_node)> &fn) const;
  static inline isl::schedule_node from_domain(isl::union_set domain);
  static inline isl::schedule_node from_extension(isl::union_map extension);
  inline int get_ancestor_child_position(const isl::schedule_node &ancestor) const;
  inline isl::schedule_node get_child(int pos) const;
  inline int get_child_position() const;
  inline isl::union_set get_domain() const;
  inline isl::multi_union_pw_aff get_prefix_schedule_multi_union_pw_aff() const;
  inline isl::union_map get_prefix_schedule_relation() const;
  inline isl::union_map get_prefix_schedule_union_map() const;
  inline isl::union_pw_multi_aff get_prefix_schedule_union_pw_multi_aff() const;
  inline isl::schedule get_schedule() const;
  inline int get_schedule_depth() const;
  inline isl::schedule_node get_shared_ancestor(const isl::schedule_node &node2) const;
  inline int get_tree_depth() const;
  inline isl::union_set get_universe_domain() const;
  inline isl::schedule_node graft_after(isl::schedule_node graft) const;
  inline isl::schedule_node graft_before(isl::schedule_node graft) const;
  inline bool has_children() const;
  inline bool has_next_sibling() const;
  inline bool has_parent() const;
  inline bool has_previous_sibling() const;
  inline isl::schedule_node insert_context(isl::set context) const;
  inline isl::schedule_node insert_filter(isl::union_set filter) const;
  inline isl::schedule_node insert_guard(isl::set context) const;
  inline isl::schedule_node insert_mark(isl::id mark) const;
  inline isl::schedule_node insert_partial_schedule(isl::multi_union_pw_aff schedule) const;
  inline isl::schedule_node insert_sequence(isl::union_set_list filters) const;
  inline isl::schedule_node insert_set(isl::union_set_list filters) const;
  inline bool is_equal(const isl::schedule_node &node2) const;
  inline bool is_subtree_anchored() const;
  inline isl::schedule_node map_descendant_bottom_up(const std::function<isl::schedule_node(isl::schedule_node)> &fn) const;
  inline int n_children() const;
  inline isl::schedule_node next_sibling() const;
  inline isl::schedule_node order_after(isl::union_set filter) const;
  inline isl::schedule_node order_before(isl::union_set filter) const;
  inline isl::schedule_node parent() const;
  inline isl::schedule_node previous_sibling() const;
  inline isl::schedule_node root() const;
  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_band

class schedule_node_band : public schedule_node {
  friend bool schedule_node::isa<schedule_node_band>();
  friend schedule_node_band schedule_node::as<schedule_node_band>();
  static const auto type = isl_schedule_node_band;

protected:
  inline explicit schedule_node_band(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_band();
  inline /* implicit */ schedule_node_band(const isl::schedule_node_band &obj);
  inline isl::schedule_node_band &operator=(isl::schedule_node_band obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_set get_ast_build_options() const;
  inline isl::set get_ast_isolate_option() const;
  inline isl::multi_union_pw_aff get_partial_schedule() const;
  inline isl::union_map get_partial_schedule_union_map() const;
  inline bool get_permutable() const;
  inline isl::space get_space() const;
  inline bool member_get_coincident(int pos) const;
  inline isl::schedule_node_band member_set_ast_loop_type(int pos, enum isl::ast_loop_type type) const;
  inline isl::schedule_node_band member_set_coincident(int pos, int coincident) const;
  inline isl::schedule_node_band member_set_isolate_ast_loop_type(int pos, enum isl::ast_loop_type type) const;
  inline isl::schedule_node_band mod(isl::multi_val mv) const;
  inline unsigned int n_member() const;
  inline isl::schedule_node_band scale(isl::multi_val mv) const;
  inline isl::schedule_node_band scale_down(isl::multi_val mv) const;
  inline isl::schedule_node_band set_ast_build_options(isl::union_set options) const;
  inline isl::schedule_node_band set_permutable(int permutable) const;
  inline isl::schedule_node_band shift(isl::multi_union_pw_aff shift) const;
  inline isl::schedule_node_band split(int pos) const;
  inline isl::schedule_node_band tile(isl::multi_val sizes) const;
  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_context

class schedule_node_context : public schedule_node {
  friend bool schedule_node::isa<schedule_node_context>();
  friend schedule_node_context schedule_node::as<schedule_node_context>();
  static const auto type = isl_schedule_node_context;

protected:
  inline explicit schedule_node_context(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_context();
  inline /* implicit */ schedule_node_context(const isl::schedule_node_context &obj);
  inline isl::schedule_node_context &operator=(isl::schedule_node_context obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::set get_context() const;
  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_domain

class schedule_node_domain : public schedule_node {
  friend bool schedule_node::isa<schedule_node_domain>();
  friend schedule_node_domain schedule_node::as<schedule_node_domain>();
  static const auto type = isl_schedule_node_domain;

protected:
  inline explicit schedule_node_domain(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_domain();
  inline /* implicit */ schedule_node_domain(const isl::schedule_node_domain &obj);
  inline isl::schedule_node_domain &operator=(isl::schedule_node_domain obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_set get_domain() const;
  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_expansion

class schedule_node_expansion : public schedule_node {
  friend bool schedule_node::isa<schedule_node_expansion>();
  friend schedule_node_expansion schedule_node::as<schedule_node_expansion>();
  static const auto type = isl_schedule_node_expansion;

protected:
  inline explicit schedule_node_expansion(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_expansion();
  inline /* implicit */ schedule_node_expansion(const isl::schedule_node_expansion &obj);
  inline isl::schedule_node_expansion &operator=(isl::schedule_node_expansion obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_pw_multi_aff get_contraction() const;
  inline isl::union_map get_expansion() const;
  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_extension

class schedule_node_extension : public schedule_node {
  friend bool schedule_node::isa<schedule_node_extension>();
  friend schedule_node_extension schedule_node::as<schedule_node_extension>();
  static const auto type = isl_schedule_node_extension;

protected:
  inline explicit schedule_node_extension(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_extension();
  inline /* implicit */ schedule_node_extension(const isl::schedule_node_extension &obj);
  inline isl::schedule_node_extension &operator=(isl::schedule_node_extension obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_map get_extension() const;
  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_filter

class schedule_node_filter : public schedule_node {
  friend bool schedule_node::isa<schedule_node_filter>();
  friend schedule_node_filter schedule_node::as<schedule_node_filter>();
  static const auto type = isl_schedule_node_filter;

protected:
  inline explicit schedule_node_filter(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_filter();
  inline /* implicit */ schedule_node_filter(const isl::schedule_node_filter &obj);
  inline isl::schedule_node_filter &operator=(isl::schedule_node_filter obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_set get_filter() const;
  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_guard

class schedule_node_guard : public schedule_node {
  friend bool schedule_node::isa<schedule_node_guard>();
  friend schedule_node_guard schedule_node::as<schedule_node_guard>();
  static const auto type = isl_schedule_node_guard;

protected:
  inline explicit schedule_node_guard(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_guard();
  inline /* implicit */ schedule_node_guard(const isl::schedule_node_guard &obj);
  inline isl::schedule_node_guard &operator=(isl::schedule_node_guard obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::set get_guard() const;
  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_leaf

class schedule_node_leaf : public schedule_node {
  friend bool schedule_node::isa<schedule_node_leaf>();
  friend schedule_node_leaf schedule_node::as<schedule_node_leaf>();
  static const auto type = isl_schedule_node_leaf;

protected:
  inline explicit schedule_node_leaf(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_leaf();
  inline /* implicit */ schedule_node_leaf(const isl::schedule_node_leaf &obj);
  inline isl::schedule_node_leaf &operator=(isl::schedule_node_leaf obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_mark

class schedule_node_mark : public schedule_node {
  friend bool schedule_node::isa<schedule_node_mark>();
  friend schedule_node_mark schedule_node::as<schedule_node_mark>();
  static const auto type = isl_schedule_node_mark;

protected:
  inline explicit schedule_node_mark(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_mark();
  inline /* implicit */ schedule_node_mark(const isl::schedule_node_mark &obj);
  inline isl::schedule_node_mark &operator=(isl::schedule_node_mark obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::id get_id() const;
  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_sequence

class schedule_node_sequence : public schedule_node {
  friend bool schedule_node::isa<schedule_node_sequence>();
  friend schedule_node_sequence schedule_node::as<schedule_node_sequence>();
  static const auto type = isl_schedule_node_sequence;

protected:
  inline explicit schedule_node_sequence(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_sequence();
  inline /* implicit */ schedule_node_sequence(const isl::schedule_node_sequence &obj);
  inline isl::schedule_node_sequence &operator=(isl::schedule_node_sequence obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::schedule_node_set

class schedule_node_set : public schedule_node {
  friend bool schedule_node::isa<schedule_node_set>();
  friend schedule_node_set schedule_node::as<schedule_node_set>();
  static const auto type = isl_schedule_node_set;

protected:
  inline explicit schedule_node_set(__isl_take isl_schedule_node *ptr);

public:
  inline /* implicit */ schedule_node_set();
  inline /* implicit */ schedule_node_set(const isl::schedule_node_set &obj);
  inline isl::schedule_node_set &operator=(isl::schedule_node_set obj);
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  typedef isl_schedule_node* isl_ptr_t;
};

// declarations for isl::set
inline isl::set manage(__isl_take isl_set *ptr);
inline isl::set manage_copy(__isl_keep isl_set *ptr);

class set {
  friend inline isl::set manage(__isl_take isl_set *ptr);
  friend inline isl::set manage_copy(__isl_keep isl_set *ptr);

protected:
  isl_set *ptr = nullptr;

  inline explicit set(__isl_take isl_set *ptr);

public:
  inline /* implicit */ set();
  inline /* implicit */ set(const isl::set &obj);
  inline explicit set(isl::ctx ctx, const std::string &str);
  inline /* implicit */ set(isl::basic_set bset);
  inline /* implicit */ set(isl::point pnt);
  inline isl::set &operator=(isl::set obj);
  inline ~set();
  inline __isl_give isl_set *copy() const &;
  inline __isl_give isl_set *copy() && = delete;
  inline __isl_keep isl_set *get() const;
  inline __isl_give isl_set *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::set add_constraint(isl::constraint constraint) const;
  inline isl::set add_dims(enum isl::dim_type type, unsigned int n) const;
  inline isl::basic_set affine_hull() const;
  inline isl::set align_params(isl::space model) const;
  inline isl::set apply(isl::map map) const;
  inline isl::set coalesce() const;
  inline isl::set complement() const;
  inline isl::set compute_divs() const;
  inline isl::set detect_equalities() const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline bool dim_has_upper_bound(enum isl::dim_type type, unsigned int pos) const;
  inline isl::pw_aff dim_max(int pos) const;
  inline isl::pw_aff dim_min(int pos) const;
  static inline isl::set empty(isl::space space);
  inline int find_dim_by_id(enum isl::dim_type type, const isl::id &id) const;
  inline int find_dim_by_name(enum isl::dim_type type, const std::string &name) const;
  inline isl::set flatten() const;
  inline isl::map flatten_map() const;
  inline void foreach_basic_set(const std::function<void(isl::basic_set)> &fn) const;
  inline isl::set from_params() const;
  static inline isl::set from_union_set(isl::union_set uset);
  inline isl::list<isl::basic_set> get_basic_set_list() const;
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline isl::space get_space() const;
  inline isl::val get_stride(int pos) const;
  inline isl::id get_tuple_id() const;
  inline std::string get_tuple_name() const;
  inline isl::set gist(isl::set context) const;
  inline bool has_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline bool has_tuple_id() const;
  inline bool has_tuple_name() const;
  inline isl::map identity() const;
  inline isl::set insert_dims(enum isl::dim_type type, unsigned int pos, unsigned int n) const;
  inline isl::set intersect(isl::set set2) const;
  inline isl::set intersect_params(isl::set params) const;
  inline bool involves_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline bool is_disjoint(const isl::set &set2) const;
  inline bool is_empty() const;
  inline bool is_equal(const isl::set &set2) const;
  inline bool is_singleton() const;
  inline bool is_strict_subset(const isl::set &set2) const;
  inline bool is_subset(const isl::set &set2) const;
  inline bool is_wrapping() const;
  inline isl::set lexmax() const;
  inline isl::set lexmin() const;
  inline isl::set lower_bound_si(enum isl::dim_type type, unsigned int pos, int value) const;
  inline isl::set lower_bound_val(enum isl::dim_type type, unsigned int pos, isl::val value) const;
  inline isl::val max_val(const isl::aff &obj) const;
  inline isl::val min_val(const isl::aff &obj) const;
  inline int n_basic_set() const;
  inline unsigned int n_dim() const;
  inline unsigned int n_param() const;
  static inline isl::set nat_universe(isl::space dim);
  inline isl::set params() const;
  inline isl::val plain_get_val_if_fixed(enum isl::dim_type type, unsigned int pos) const;
  inline bool plain_is_universe() const;
  inline isl::basic_set polyhedral_hull() const;
  inline isl::set preimage_multi_aff(isl::multi_aff ma) const;
  inline isl::set product(isl::set set2) const;
  inline isl::set project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::set remove_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::set reset_tuple_id() const;
  inline isl::basic_set sample() const;
  inline isl::point sample_point() const;
  inline isl::set set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const;
  inline isl::set set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const;
  inline isl::set set_tuple_id(isl::id id) const;
  inline isl::set set_tuple_name(const std::string &s) const;
  inline isl::basic_set simple_hull() const;
  inline isl::set subtract(isl::set set2) const;
  inline isl::set unite(isl::set set2) const;
  static inline isl::set universe(isl::space space);
  inline isl::basic_set unshifted_simple_hull() const;
  inline isl::map unwrap() const;
  inline isl::set upper_bound_si(enum isl::dim_type type, unsigned int pos, int value) const;
  inline isl::set upper_bound_val(enum isl::dim_type type, unsigned int pos, isl::val value) const;
  inline isl::map wrapped_domain_map() const;
  typedef isl_set* isl_ptr_t;
};

// declarations for isl::list<set>
inline isl::list<set> manage(__isl_take isl_set_list *ptr);
inline isl::list<set> manage_copy(__isl_keep isl_set_list *ptr);

template <>
class list<set> {
  friend inline isl::list<set> manage(__isl_take isl_set_list *ptr);
  friend inline isl::list<set> manage_copy(__isl_keep isl_set_list *ptr);

protected:
  isl_set_list *ptr = nullptr;

  inline explicit list(__isl_take isl_set_list *ptr);

public:
  inline /* implicit */ list();
  inline /* implicit */ list(const isl::list<set> &obj);
  inline isl::list<set> &operator=(isl::list<set> obj);
  inline ~list<set>();
  inline __isl_give isl_set_list *copy() const &;
  inline __isl_give isl_set_list *copy() && = delete;
  inline __isl_keep isl_set_list *get() const;
  inline __isl_give isl_set_list *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  typedef isl_set_list* isl_ptr_t;
  typedef list_iterator<set> iterator;
  template <typename InputIt1, typename InputIt2>
  inline list(isl::ctx ctx, InputIt1 from, InputIt2 to);

  inline int size() const;
  inline iterator begin() const;
  inline iterator end() const;
  inline set at(int pos) const;
  inline set operator[](int pos) const;
};

// declarations for isl::space
inline isl::space manage(__isl_take isl_space *ptr);
inline isl::space manage_copy(__isl_keep isl_space *ptr);

class space {
  friend inline isl::space manage(__isl_take isl_space *ptr);
  friend inline isl::space manage_copy(__isl_keep isl_space *ptr);

protected:
  isl_space *ptr = nullptr;

  inline explicit space(__isl_take isl_space *ptr);

public:
  inline /* implicit */ space();
  inline /* implicit */ space(const isl::space &obj);
  inline explicit space(isl::ctx ctx, unsigned int nparam, unsigned int n_in, unsigned int n_out);
  inline explicit space(isl::ctx ctx, unsigned int nparam, unsigned int dim);
  inline explicit space(isl::ctx ctx, unsigned int nparam);
  inline isl::space &operator=(isl::space obj);
  inline ~space();
  inline __isl_give isl_space *copy() const &;
  inline __isl_give isl_space *copy() && = delete;
  inline __isl_keep isl_space *get() const;
  inline __isl_give isl_space *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::space add_dims(enum isl::dim_type type, unsigned int n) const;
  inline isl::space add_param(isl::id id) const;
  inline isl::space align_params(isl::space dim2) const;
  inline bool can_curry() const;
  inline bool can_uncurry() const;
  inline isl::space curry() const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::space domain() const;
  inline isl::space domain_map() const;
  inline isl::space domain_product(isl::space right) const;
  inline isl::space drop_dims(enum isl::dim_type type, unsigned int first, unsigned int num) const;
  inline int find_dim_by_id(enum isl::dim_type type, const isl::id &id) const;
  inline int find_dim_by_name(enum isl::dim_type type, const std::string &name) const;
  inline isl::space from_domain() const;
  inline isl::space from_range() const;
  inline isl::id get_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline std::string get_dim_name(enum isl::dim_type type, unsigned int pos) const;
  inline isl::id get_tuple_id(enum isl::dim_type type) const;
  inline std::string get_tuple_name(enum isl::dim_type type) const;
  inline bool has_dim_id(enum isl::dim_type type, unsigned int pos) const;
  inline bool has_dim_name(enum isl::dim_type type, unsigned int pos) const;
  inline bool has_equal_params(const isl::space &space2) const;
  inline bool has_equal_tuples(const isl::space &space2) const;
  inline bool has_tuple_id(enum isl::dim_type type) const;
  inline bool has_tuple_name(enum isl::dim_type type) const;
  inline bool is_equal(const isl::space &space2) const;
  inline bool is_params() const;
  inline bool is_set() const;
  inline isl::space map_from_domain_and_range(isl::space range) const;
  inline isl::space map_from_set() const;
  inline isl::space params() const;
  inline isl::space product(isl::space right) const;
  inline isl::space range() const;
  inline isl::space range_map() const;
  inline isl::space range_product(isl::space right) const;
  inline isl::space reset_tuple_id(enum isl::dim_type type) const;
  inline isl::space set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const;
  inline isl::space set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &name) const;
  inline isl::space set_from_params() const;
  inline isl::space set_tuple_id(enum isl::dim_type type, isl::id id) const;
  inline isl::space set_tuple_name(enum isl::dim_type type, const std::string &s) const;
  inline isl::space uncurry() const;
  inline isl::space unwrap() const;
  inline isl::space wrap() const;
  typedef isl_space* isl_ptr_t;
};

// declarations for isl::union_access_info
inline isl::union_access_info manage(__isl_take isl_union_access_info *ptr);
inline isl::union_access_info manage_copy(__isl_keep isl_union_access_info *ptr);

class union_access_info {
  friend inline isl::union_access_info manage(__isl_take isl_union_access_info *ptr);
  friend inline isl::union_access_info manage_copy(__isl_keep isl_union_access_info *ptr);

protected:
  isl_union_access_info *ptr = nullptr;

  inline explicit union_access_info(__isl_take isl_union_access_info *ptr);

public:
  inline /* implicit */ union_access_info();
  inline /* implicit */ union_access_info(const isl::union_access_info &obj);
  inline explicit union_access_info(isl::union_map sink);
  inline isl::union_access_info &operator=(isl::union_access_info obj);
  inline ~union_access_info();
  inline __isl_give isl_union_access_info *copy() const &;
  inline __isl_give isl_union_access_info *copy() && = delete;
  inline __isl_keep isl_union_access_info *get() const;
  inline __isl_give isl_union_access_info *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_flow compute_flow() const;
  inline isl::union_access_info set_kill(isl::union_map kill) const;
  inline isl::union_access_info set_may_source(isl::union_map may_source) const;
  inline isl::union_access_info set_must_source(isl::union_map must_source) const;
  inline isl::union_access_info set_schedule(isl::schedule schedule) const;
  inline isl::union_access_info set_schedule_map(isl::union_map schedule_map) const;
  typedef isl_union_access_info* isl_ptr_t;
};

// declarations for isl::union_flow
inline isl::union_flow manage(__isl_take isl_union_flow *ptr);
inline isl::union_flow manage_copy(__isl_keep isl_union_flow *ptr);

class union_flow {
  friend inline isl::union_flow manage(__isl_take isl_union_flow *ptr);
  friend inline isl::union_flow manage_copy(__isl_keep isl_union_flow *ptr);

protected:
  isl_union_flow *ptr = nullptr;

  inline explicit union_flow(__isl_take isl_union_flow *ptr);

public:
  inline /* implicit */ union_flow();
  inline /* implicit */ union_flow(const isl::union_flow &obj);
  inline isl::union_flow &operator=(isl::union_flow obj);
  inline ~union_flow();
  inline __isl_give isl_union_flow *copy() const &;
  inline __isl_give isl_union_flow *copy() && = delete;
  inline __isl_keep isl_union_flow *get() const;
  inline __isl_give isl_union_flow *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_map get_full_may_dependence() const;
  inline isl::union_map get_full_must_dependence() const;
  inline isl::union_map get_may_dependence() const;
  inline isl::union_map get_may_no_source() const;
  inline isl::union_map get_must_dependence() const;
  inline isl::union_map get_must_no_source() const;
  typedef isl_union_flow* isl_ptr_t;
};

// declarations for isl::union_map
inline isl::union_map manage(__isl_take isl_union_map *ptr);
inline isl::union_map manage_copy(__isl_keep isl_union_map *ptr);

class union_map {
  friend inline isl::union_map manage(__isl_take isl_union_map *ptr);
  friend inline isl::union_map manage_copy(__isl_keep isl_union_map *ptr);

protected:
  isl_union_map *ptr = nullptr;

  inline explicit union_map(__isl_take isl_union_map *ptr);

public:
  inline /* implicit */ union_map();
  inline /* implicit */ union_map(const isl::union_map &obj);
  inline /* implicit */ union_map(isl::basic_map bmap);
  inline /* implicit */ union_map(isl::map map);
  inline explicit union_map(isl::ctx ctx, const std::string &str);
  inline isl::union_map &operator=(isl::union_map obj);
  inline ~union_map();
  inline __isl_give isl_union_map *copy() const &;
  inline __isl_give isl_union_map *copy() && = delete;
  inline __isl_keep isl_union_map *get() const;
  inline __isl_give isl_union_map *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_map add_map(isl::map map) const;
  inline isl::union_map affine_hull() const;
  inline isl::union_map apply_domain(isl::union_map umap2) const;
  inline isl::union_map apply_range(isl::union_map umap2) const;
  inline isl::union_map coalesce() const;
  inline isl::union_map compute_divs() const;
  inline isl::union_map curry() const;
  inline isl::union_set deltas() const;
  inline isl::union_map detect_equalities() const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::union_set domain() const;
  inline isl::union_map domain_factor_domain() const;
  inline isl::union_map domain_factor_range() const;
  inline isl::union_map domain_map() const;
  inline isl::union_pw_multi_aff domain_map_union_pw_multi_aff() const;
  inline isl::union_map domain_product(isl::union_map umap2) const;
  static inline isl::union_map empty(isl::space space);
  inline isl::union_map eq_at(isl::multi_union_pw_aff mupa) const;
  inline isl::map extract_map(isl::space dim) const;
  inline isl::union_map factor_domain() const;
  inline isl::union_map factor_range() const;
  inline isl::union_map fixed_power(isl::val exp) const;
  inline isl::union_map flat_range_product(isl::union_map umap2) const;
  inline void foreach_map(const std::function<void(isl::map)> &fn) const;
  static inline isl::union_map from(isl::union_pw_multi_aff upma);
  static inline isl::union_map from(isl::multi_union_pw_aff mupa);
  static inline isl::union_map from_domain(isl::union_set uset);
  static inline isl::union_map from_domain_and_range(isl::union_set domain, isl::union_set range);
  static inline isl::union_map from_range(isl::union_set uset);
  inline isl::space get_space() const;
  inline isl::union_map gist(isl::union_map context) const;
  inline isl::union_map gist_domain(isl::union_set uset) const;
  inline isl::union_map gist_params(isl::set set) const;
  inline isl::union_map gist_range(isl::union_set uset) const;
  inline isl::union_map intersect(isl::union_map umap2) const;
  inline isl::union_map intersect_domain(isl::union_set uset) const;
  inline isl::union_map intersect_params(isl::set set) const;
  inline isl::union_map intersect_range(isl::union_set uset) const;
  inline bool is_bijective() const;
  inline bool is_empty() const;
  inline bool is_equal(const isl::union_map &umap2) const;
  inline bool is_injective() const;
  inline bool is_single_valued() const;
  inline bool is_strict_subset(const isl::union_map &umap2) const;
  inline bool is_subset(const isl::union_map &umap2) const;
  inline isl::union_map lexmax() const;
  inline isl::union_map lexmin() const;
  inline int n_map() const;
  inline isl::union_map polyhedral_hull() const;
  inline isl::union_map preimage_range_multi_aff(isl::multi_aff ma) const;
  inline isl::union_map product(isl::union_map umap2) const;
  inline isl::union_map project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::union_map project_out_all_params() const;
  inline isl::union_set range() const;
  inline isl::union_map range_factor_domain() const;
  inline isl::union_map range_factor_range() const;
  inline isl::union_map range_map() const;
  inline isl::union_map range_product(isl::union_map umap2) const;
  inline isl::union_map reverse() const;
  inline isl::union_map subtract(isl::union_map umap2) const;
  inline isl::union_map subtract_domain(isl::union_set dom) const;
  inline isl::union_map subtract_range(isl::union_set dom) const;
  inline isl::union_map uncurry() const;
  inline isl::union_map unite(isl::union_map umap2) const;
  inline isl::union_map universe() const;
  inline isl::union_set wrap() const;
  inline isl::union_map zip() const;
  typedef isl_union_map* isl_ptr_t;
};

// declarations for isl::union_pw_aff
inline isl::union_pw_aff manage(__isl_take isl_union_pw_aff *ptr);
inline isl::union_pw_aff manage_copy(__isl_keep isl_union_pw_aff *ptr);

class union_pw_aff {
  friend inline isl::union_pw_aff manage(__isl_take isl_union_pw_aff *ptr);
  friend inline isl::union_pw_aff manage_copy(__isl_keep isl_union_pw_aff *ptr);

protected:
  isl_union_pw_aff *ptr = nullptr;

  inline explicit union_pw_aff(__isl_take isl_union_pw_aff *ptr);

public:
  inline /* implicit */ union_pw_aff();
  inline /* implicit */ union_pw_aff(const isl::union_pw_aff &obj);
  inline /* implicit */ union_pw_aff(isl::pw_aff pa);
  inline explicit union_pw_aff(isl::union_set domain, isl::val v);
  inline explicit union_pw_aff(isl::union_set domain, isl::aff aff);
  inline explicit union_pw_aff(isl::ctx ctx, const std::string &str);
  inline isl::union_pw_aff &operator=(isl::union_pw_aff obj);
  inline ~union_pw_aff();
  inline __isl_give isl_union_pw_aff *copy() const &;
  inline __isl_give isl_union_pw_aff *copy() && = delete;
  inline __isl_keep isl_union_pw_aff *get() const;
  inline __isl_give isl_union_pw_aff *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_pw_aff add(isl::union_pw_aff upa2) const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::union_set domain() const;
  static inline isl::union_pw_aff empty(isl::space space);
  inline isl::pw_aff extract_pw_aff(isl::space space) const;
  inline isl::union_pw_aff floor() const;
  inline void foreach_pw_aff(const std::function<void(isl::pw_aff)> &fn) const;
  inline isl::space get_space() const;
  inline isl::union_pw_aff mod_val(isl::val f) const;
  inline int n_pw_aff() const;
  static inline isl::union_pw_aff param_on_domain(isl::union_set domain, isl::id id);
  inline bool plain_is_equal(const isl::union_pw_aff &upa2) const;
  inline isl::union_pw_aff pullback(isl::union_pw_multi_aff upma) const;
  inline isl::union_pw_aff scale_down(isl::val v) const;
  inline isl::union_pw_aff scale_val(isl::val v) const;
  inline isl::union_pw_aff sub(isl::union_pw_aff upa2) const;
  inline isl::union_pw_aff union_add(isl::union_pw_aff upa2) const;
  inline isl::union_set zero_union_set() const;
  typedef isl_union_pw_aff* isl_ptr_t;
};

// declarations for isl::union_pw_multi_aff
inline isl::union_pw_multi_aff manage(__isl_take isl_union_pw_multi_aff *ptr);
inline isl::union_pw_multi_aff manage_copy(__isl_keep isl_union_pw_multi_aff *ptr);

class union_pw_multi_aff {
  friend inline isl::union_pw_multi_aff manage(__isl_take isl_union_pw_multi_aff *ptr);
  friend inline isl::union_pw_multi_aff manage_copy(__isl_keep isl_union_pw_multi_aff *ptr);

protected:
  isl_union_pw_multi_aff *ptr = nullptr;

  inline explicit union_pw_multi_aff(__isl_take isl_union_pw_multi_aff *ptr);

public:
  inline /* implicit */ union_pw_multi_aff();
  inline /* implicit */ union_pw_multi_aff(const isl::union_pw_multi_aff &obj);
  inline /* implicit */ union_pw_multi_aff(isl::pw_multi_aff pma);
  inline explicit union_pw_multi_aff(isl::union_set domain, isl::multi_val mv);
  inline explicit union_pw_multi_aff(isl::ctx ctx, const std::string &str);
  inline /* implicit */ union_pw_multi_aff(isl::union_pw_aff upa);
  inline isl::union_pw_multi_aff &operator=(isl::union_pw_multi_aff obj);
  inline ~union_pw_multi_aff();
  inline __isl_give isl_union_pw_multi_aff *copy() const &;
  inline __isl_give isl_union_pw_multi_aff *copy() && = delete;
  inline __isl_keep isl_union_pw_multi_aff *get() const;
  inline __isl_give isl_union_pw_multi_aff *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_pw_multi_aff add(isl::union_pw_multi_aff upma2) const;
  inline unsigned int dim(enum isl::dim_type type) const;
  inline isl::union_set domain() const;
  inline isl::pw_multi_aff extract_pw_multi_aff(isl::space space) const;
  inline isl::union_pw_multi_aff flat_range_product(isl::union_pw_multi_aff upma2) const;
  inline void foreach_pw_multi_aff(const std::function<void(isl::pw_multi_aff)> &fn) const;
  static inline isl::union_pw_multi_aff from(isl::union_map umap);
  static inline isl::union_pw_multi_aff from_multi_union_pw_aff(isl::multi_union_pw_aff mupa);
  inline isl::space get_space() const;
  inline isl::union_pw_aff get_union_pw_aff(int pos) const;
  inline int n_pw_multi_aff() const;
  inline isl::union_pw_multi_aff pullback(isl::union_pw_multi_aff upma2) const;
  inline isl::union_pw_multi_aff scale_down_val(isl::val val) const;
  inline isl::union_pw_multi_aff scale_val(isl::val val) const;
  inline isl::union_pw_multi_aff union_add(isl::union_pw_multi_aff upma2) const;
  typedef isl_union_pw_multi_aff* isl_ptr_t;
};

// declarations for isl::union_set
inline isl::union_set manage(__isl_take isl_union_set *ptr);
inline isl::union_set manage_copy(__isl_keep isl_union_set *ptr);

class union_set {
  friend inline isl::union_set manage(__isl_take isl_union_set *ptr);
  friend inline isl::union_set manage_copy(__isl_keep isl_union_set *ptr);

protected:
  isl_union_set *ptr = nullptr;

  inline explicit union_set(__isl_take isl_union_set *ptr);

public:
  inline /* implicit */ union_set();
  inline /* implicit */ union_set(const isl::union_set &obj);
  inline /* implicit */ union_set(isl::basic_set bset);
  inline /* implicit */ union_set(isl::set set);
  inline /* implicit */ union_set(isl::point pnt);
  inline explicit union_set(isl::ctx ctx, const std::string &str);
  inline isl::union_set &operator=(isl::union_set obj);
  inline ~union_set();
  inline __isl_give isl_union_set *copy() const &;
  inline __isl_give isl_union_set *copy() && = delete;
  inline __isl_keep isl_union_set *get() const;
  inline __isl_give isl_union_set *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::union_set add_set(isl::set set) const;
  inline isl::union_set affine_hull() const;
  inline isl::union_set apply(isl::union_map umap) const;
  inline isl::union_set coalesce() const;
  inline isl::union_set compute_divs() const;
  inline isl::union_set detect_equalities() const;
  inline unsigned int dim(enum isl::dim_type type) const;
  static inline isl::union_set empty(isl::space space);
  inline isl::set extract_set(isl::space dim) const;
  inline void foreach_point(const std::function<void(isl::point)> &fn) const;
  inline void foreach_set(const std::function<void(isl::set)> &fn) const;
  inline isl::space get_space() const;
  inline isl::union_set gist(isl::union_set context) const;
  inline isl::union_set gist_params(isl::set set) const;
  inline isl::union_map identity() const;
  inline isl::union_set intersect(isl::union_set uset2) const;
  inline isl::union_set intersect_params(isl::set set) const;
  inline bool is_disjoint(const isl::union_set &uset2) const;
  inline bool is_empty() const;
  inline bool is_equal(const isl::union_set &uset2) const;
  inline bool is_params() const;
  inline bool is_strict_subset(const isl::union_set &uset2) const;
  inline bool is_subset(const isl::union_set &uset2) const;
  inline isl::union_set lexmax() const;
  inline isl::union_set lexmin() const;
  inline isl::multi_val max_multi_union_pw_aff(const isl::multi_union_pw_aff &obj) const;
  inline isl::multi_val min_multi_union_pw_aff(const isl::multi_union_pw_aff &obj) const;
  inline int n_set() const;
  inline isl::set params() const;
  inline isl::union_set polyhedral_hull() const;
  inline isl::union_set preimage(isl::multi_aff ma) const;
  inline isl::union_set preimage(isl::pw_multi_aff pma) const;
  inline isl::union_set preimage(isl::union_pw_multi_aff upma) const;
  inline isl::union_set project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const;
  inline isl::point sample_point() const;
  inline isl::union_set subtract(isl::union_set uset2) const;
  inline isl::union_set unite(isl::union_set uset2) const;
  inline isl::union_set universe() const;
  inline isl::union_map unwrap() const;
  inline isl::union_map wrapped_domain_map() const;
  typedef isl_union_set* isl_ptr_t;
};

// declarations for isl::union_set_list
inline isl::union_set_list manage(__isl_take isl_union_set_list *ptr);
inline isl::union_set_list manage_copy(__isl_keep isl_union_set_list *ptr);

class union_set_list {
  friend inline isl::union_set_list manage(__isl_take isl_union_set_list *ptr);
  friend inline isl::union_set_list manage_copy(__isl_keep isl_union_set_list *ptr);

protected:
  isl_union_set_list *ptr = nullptr;

  inline explicit union_set_list(__isl_take isl_union_set_list *ptr);

public:
  inline /* implicit */ union_set_list();
  inline /* implicit */ union_set_list(const isl::union_set_list &obj);
  inline explicit union_set_list(isl::union_set el);
  inline explicit union_set_list(isl::ctx ctx, int n);
  inline isl::union_set_list &operator=(isl::union_set_list obj);
  inline ~union_set_list();
  inline __isl_give isl_union_set_list *copy() const &;
  inline __isl_give isl_union_set_list *copy() && = delete;
  inline __isl_keep isl_union_set_list *get() const;
  inline __isl_give isl_union_set_list *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  inline isl::union_set_list add(isl::union_set el) const;
  inline isl::union_set_list concat(isl::union_set_list list2) const;
  inline void foreach(const std::function<void(isl::union_set)> &fn) const;
  inline isl::union_set get_union_set(int index) const;
  typedef isl_union_set_list* isl_ptr_t;
};

// declarations for isl::val
inline isl::val manage(__isl_take isl_val *ptr);
inline isl::val manage_copy(__isl_keep isl_val *ptr);

class val {
  friend inline isl::val manage(__isl_take isl_val *ptr);
  friend inline isl::val manage_copy(__isl_keep isl_val *ptr);

protected:
  isl_val *ptr = nullptr;

  inline explicit val(__isl_take isl_val *ptr);

public:
  inline /* implicit */ val();
  inline /* implicit */ val(const isl::val &obj);
  inline explicit val(isl::ctx ctx, long i);
  inline explicit val(isl::ctx ctx, const std::string &str);
  inline isl::val &operator=(isl::val obj);
  inline ~val();
  inline __isl_give isl_val *copy() const &;
  inline __isl_give isl_val *copy() && = delete;
  inline __isl_keep isl_val *get() const;
  inline __isl_give isl_val *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;
  inline std::string to_str() const;

  inline isl::val abs() const;
  inline bool abs_eq(const isl::val &v2) const;
  inline isl::val add(isl::val v2) const;
  inline isl::val ceil() const;
  inline int cmp_si(long i) const;
  inline isl::val div(isl::val v2) const;
  inline bool eq(const isl::val &v2) const;
  inline isl::val floor() const;
  inline isl::val gcd(isl::val v2) const;
  inline bool ge(const isl::val &v2) const;
  inline long get_den_si() const;
  inline long get_num_si() const;
  inline bool gt(const isl::val &v2) const;
  static inline isl::val infty(isl::ctx ctx);
  inline isl::val inv() const;
  inline bool is_divisible_by(const isl::val &v2) const;
  inline bool is_infty() const;
  inline bool is_int() const;
  inline bool is_nan() const;
  inline bool is_neg() const;
  inline bool is_neginfty() const;
  inline bool is_negone() const;
  inline bool is_nonneg() const;
  inline bool is_nonpos() const;
  inline bool is_one() const;
  inline bool is_pos() const;
  inline bool is_rat() const;
  inline bool is_zero() const;
  inline bool le(const isl::val &v2) const;
  inline bool lt(const isl::val &v2) const;
  inline isl::val max(isl::val v2) const;
  inline isl::val min(isl::val v2) const;
  inline isl::val mod(isl::val v2) const;
  inline isl::val mul(isl::val v2) const;
  static inline isl::val nan(isl::ctx ctx);
  inline bool ne(const isl::val &v2) const;
  inline isl::val neg() const;
  static inline isl::val neginfty(isl::ctx ctx);
  static inline isl::val negone(isl::ctx ctx);
  static inline isl::val one(isl::ctx ctx);
  inline int sgn() const;
  inline isl::val sub(isl::val v2) const;
  inline isl::val trunc() const;
  static inline isl::val zero(isl::ctx ctx);
  typedef isl_val* isl_ptr_t;
};

// declarations for isl::list<val>
inline isl::list<val> manage(__isl_take isl_val_list *ptr);
inline isl::list<val> manage_copy(__isl_keep isl_val_list *ptr);

template <>
class list<val> {
  friend inline isl::list<val> manage(__isl_take isl_val_list *ptr);
  friend inline isl::list<val> manage_copy(__isl_keep isl_val_list *ptr);

protected:
  isl_val_list *ptr = nullptr;

  inline explicit list(__isl_take isl_val_list *ptr);

public:
  inline /* implicit */ list();
  inline /* implicit */ list(const isl::list<val> &obj);
  inline isl::list<val> &operator=(isl::list<val> obj);
  inline ~list<val>();
  inline __isl_give isl_val_list *copy() const &;
  inline __isl_give isl_val_list *copy() && = delete;
  inline __isl_keep isl_val_list *get() const;
  inline __isl_give isl_val_list *release();
  inline bool is_null() const;
  inline explicit operator bool() const;
  inline isl::ctx get_ctx() const;

  typedef isl_val_list* isl_ptr_t;
  typedef list_iterator<val> iterator;
  template <typename InputIt1, typename InputIt2>
  inline list(isl::ctx ctx, InputIt1 from, InputIt2 to);

  inline int size() const;
  inline iterator begin() const;
  inline iterator end() const;
  inline val at(int pos) const;
  inline val operator[](int pos) const;
};

// implementations for isl::aff
isl::aff manage(__isl_take isl_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return aff(ptr);
}
isl::aff manage_copy(__isl_keep isl_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_aff_get_ctx(ptr);
  ptr = isl_aff_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return aff(ptr);
}

aff::aff()
    : ptr(nullptr) {}

aff::aff(const isl::aff &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_aff_get_ctx(obj.ptr));
}

aff::aff(__isl_take isl_aff *ptr)
    : ptr(ptr) {}

aff::aff(isl::local_space ls)
{
  if (ls.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = ls.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_zero_on_domain(ls.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
aff::aff(isl::local_space ls, isl::val val)
{
  if (ls.is_null() || val.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = ls.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_val_on_domain(ls.release(), val.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
aff::aff(isl::local_space ls, enum isl::dim_type type, unsigned int pos)
{
  if (ls.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = ls.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_var_on_domain(ls.release(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
aff::aff(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

aff &aff::operator=(isl::aff obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

aff::~aff() {
  if (ptr)
    isl_aff_free(ptr);
}

__isl_give isl_aff *aff::copy() const & {
  return isl_aff_copy(ptr);
}

__isl_keep isl_aff *aff::get() const {
  return ptr;
}

__isl_give isl_aff *aff::release() {
  isl_aff *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool aff::is_null() const {
  return ptr == nullptr;
}
aff::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const aff& C) {
  os << C.to_str();
  return os;
}


std::string aff::to_str() const {
  char *Tmp = isl_aff_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx aff::get_ctx() const {
  return isl::ctx(isl_aff_get_ctx(ptr));
}

isl::aff aff::add(isl::aff aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_add(copy(), aff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::add_coefficient_si(enum isl::dim_type type, int pos, int v) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_add_coefficient_si(copy(), static_cast<enum isl_dim_type>(type), pos, v);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::add_constant_si(int v) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_add_constant_si(copy(), v);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::ceil() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_ceil(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int aff::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::aff aff::div(isl::aff aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_div(copy(), aff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_drop_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set aff::eq_set(isl::aff aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_eq_set(copy(), aff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::floor() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_floor(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set aff::ge_set(isl::aff aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_ge_set(copy(), aff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val aff::get_coefficient_val(enum isl::dim_type type, int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_get_coefficient_val(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val aff::get_constant_val() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_get_constant_val(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val aff::get_denominator_val() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_get_denominator_val(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::get_div(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_get_div(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space aff::get_local_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_get_local_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space aff::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set aff::gt_set(isl::aff aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_gt_set(copy(), aff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool aff::involves_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_involves_dims(get(), static_cast<enum isl_dim_type>(type), first, n);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::set aff::le_set(isl::aff aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_le_set(copy(), aff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set aff::lt_set(isl::aff aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_lt_set(copy(), aff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::mod(isl::val mod) const
{
  if (!ptr || mod.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_mod_val(copy(), mod.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::mul(isl::aff aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_mul(copy(), aff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set aff::ne_set(isl::aff aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_ne_set(copy(), aff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::neg() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_neg(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::param_on_domain_space(isl::space space, isl::id id)
{
  if (space.is_null() || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_param_on_domain_space_id(space.release(), id.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

bool aff::plain_is_equal(const isl::aff &aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_plain_is_equal(get(), aff2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::aff aff::project_domain_on_params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_project_domain_on_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::pullback(isl::multi_aff ma) const
{
  if (!ptr || ma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_pullback_multi_aff(copy(), ma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::scale(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_scale_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::scale_down(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_scale_down_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::scale_down_ui(unsigned int f) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_scale_down_ui(copy(), f);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::set_coefficient_si(enum isl::dim_type type, int pos, int v) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_set_coefficient_si(copy(), static_cast<enum isl_dim_type>(type), pos, v);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::set_coefficient_val(enum isl::dim_type type, int pos, isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_set_coefficient_val(copy(), static_cast<enum isl_dim_type>(type), pos, v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::set_constant_si(int v) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_set_constant_si(copy(), v);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::set_constant_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_set_constant_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_set_dim_id(copy(), static_cast<enum isl_dim_type>(type), pos, id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_set_dim_name(copy(), static_cast<enum isl_dim_type>(type), pos, s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::set_tuple_id(enum isl::dim_type type, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_set_tuple_id(copy(), static_cast<enum isl_dim_type>(type), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff aff::sub(isl::aff aff2) const
{
  if (!ptr || aff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_aff_sub(copy(), aff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::ast_build
isl::ast_build manage(__isl_take isl_ast_build *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return ast_build(ptr);
}
isl::ast_build manage_copy(__isl_keep isl_ast_build *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_ast_build_get_ctx(ptr);
  ptr = isl_ast_build_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return ast_build(ptr);
}

ast_build::ast_build()
    : ptr(nullptr) {}

ast_build::ast_build(const isl::ast_build &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_ast_build_get_ctx(obj.ptr));
}

ast_build::ast_build(__isl_take isl_ast_build *ptr)
    : ptr(ptr) {}

ast_build::ast_build(isl::ctx ctx)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_alloc(ctx.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

ast_build &ast_build::operator=(isl::ast_build obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

ast_build::~ast_build() {
  if (ptr)
    isl_ast_build_free(ptr);
}

__isl_give isl_ast_build *ast_build::copy() const & {
  return isl_ast_build_copy(ptr);
}

__isl_keep isl_ast_build *ast_build::get() const {
  return ptr;
}

__isl_give isl_ast_build *ast_build::release() {
  isl_ast_build *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool ast_build::is_null() const {
  return ptr == nullptr;
}
ast_build::operator bool() const
{
  return !is_null();
}



isl::ctx ast_build::get_ctx() const {
  return isl::ctx(isl_ast_build_get_ctx(ptr));
}

isl::ast_expr ast_build::access_from(isl::pw_multi_aff pma) const
{
  if (!ptr || pma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_access_from_pw_multi_aff(get(), pma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_expr ast_build::access_from(isl::multi_pw_aff mpa) const
{
  if (!ptr || mpa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_access_from_multi_pw_aff(get(), mpa.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_node ast_build::ast_from_schedule(isl::union_map schedule) const
{
  if (!ptr || schedule.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_ast_from_schedule(get(), schedule.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_expr ast_build::call_from(isl::pw_multi_aff pma) const
{
  if (!ptr || pma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_call_from_pw_multi_aff(get(), pma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_expr ast_build::call_from(isl::multi_pw_aff mpa) const
{
  if (!ptr || mpa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_call_from_multi_pw_aff(get(), mpa.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_expr ast_build::expr_from(isl::set set) const
{
  if (!ptr || set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_expr_from_set(get(), set.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_expr ast_build::expr_from(isl::pw_aff pa) const
{
  if (!ptr || pa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_expr_from_pw_aff(get(), pa.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_build ast_build::from_context(isl::set set)
{
  if (set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = set.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_from_context(set.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::union_map ast_build::get_schedule() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_get_schedule(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space ast_build::get_schedule_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_get_schedule_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_node ast_build::node_from_schedule(isl::schedule schedule) const
{
  if (!ptr || schedule.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_node_from_schedule(get(), schedule.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_node ast_build::node_from_schedule_map(isl::union_map schedule) const
{
  if (!ptr || schedule.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_node_from_schedule_map(get(), schedule.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_build ast_build::set_iterators(isl::list<isl::id> iterators) const
{
  if (!ptr || iterators.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_build_set_iterators(copy(), iterators.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::ast_expr
isl::ast_expr manage(__isl_take isl_ast_expr *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return ast_expr(ptr);
}
isl::ast_expr manage_copy(__isl_keep isl_ast_expr *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_ast_expr_get_ctx(ptr);
  ptr = isl_ast_expr_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return ast_expr(ptr);
}

ast_expr::ast_expr()
    : ptr(nullptr) {}

ast_expr::ast_expr(const isl::ast_expr &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_ast_expr_get_ctx(obj.ptr));
}

ast_expr::ast_expr(__isl_take isl_ast_expr *ptr)
    : ptr(ptr) {}


ast_expr &ast_expr::operator=(isl::ast_expr obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

ast_expr::~ast_expr() {
  if (ptr)
    isl_ast_expr_free(ptr);
}

__isl_give isl_ast_expr *ast_expr::copy() const & {
  return isl_ast_expr_copy(ptr);
}

__isl_keep isl_ast_expr *ast_expr::get() const {
  return ptr;
}

__isl_give isl_ast_expr *ast_expr::release() {
  isl_ast_expr *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool ast_expr::is_null() const {
  return ptr == nullptr;
}
ast_expr::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const ast_expr& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const ast_expr& C1, const ast_expr& C2) {
  return C1.is_equal(C2);
}


std::string ast_expr::to_str() const {
  char *Tmp = isl_ast_expr_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx ast_expr::get_ctx() const {
  return isl::ctx(isl_ast_expr_get_ctx(ptr));
}

isl::id ast_expr::get_id() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_expr_get_id(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_expr ast_expr::get_op_arg(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_expr_get_op_arg(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int ast_expr::get_op_n_arg() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_expr_get_op_n_arg(get());
  return res;
}

enum isl::ast_op_type ast_expr::get_op_type() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_expr_get_op_type(get());
  return static_cast<enum isl::ast_op_type>(res);
}

bool ast_expr::is_equal(const isl::ast_expr &expr2) const
{
  if (!ptr || expr2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_expr_is_equal(get(), expr2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::ast_expr ast_expr::set_op_arg(int pos, isl::ast_expr arg) const
{
  if (!ptr || arg.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_expr_set_op_arg(copy(), pos, arg.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string ast_expr::to_C_str() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_expr_to_C_str(get());
  std::string tmp(res);
  free(res);
  return tmp;
}


// implementations for isl::ast_node
isl::ast_node manage(__isl_take isl_ast_node *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return ast_node(ptr);
}
isl::ast_node manage_copy(__isl_keep isl_ast_node *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_ast_node_get_ctx(ptr);
  ptr = isl_ast_node_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return ast_node(ptr);
}

ast_node::ast_node()
    : ptr(nullptr) {}

ast_node::ast_node(const isl::ast_node &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_ast_node_get_ctx(obj.ptr));
}

ast_node::ast_node(__isl_take isl_ast_node *ptr)
    : ptr(ptr) {}


ast_node &ast_node::operator=(isl::ast_node obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

ast_node::~ast_node() {
  if (ptr)
    isl_ast_node_free(ptr);
}

__isl_give isl_ast_node *ast_node::copy() const & {
  return isl_ast_node_copy(ptr);
}

__isl_keep isl_ast_node *ast_node::get() const {
  return ptr;
}

__isl_give isl_ast_node *ast_node::release() {
  isl_ast_node *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool ast_node::is_null() const {
  return ptr == nullptr;
}
ast_node::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const ast_node& C) {
  os << C.to_str();
  return os;
}


std::string ast_node::to_str() const {
  char *Tmp = isl_ast_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx ast_node::get_ctx() const {
  return isl::ctx(isl_ast_node_get_ctx(ptr));
}

isl::list<isl::ast_node> ast_node::block_get_children() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_block_get_children(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_node ast_node::for_get_body() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_for_get_body(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_expr ast_node::for_get_cond() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_for_get_cond(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_expr ast_node::for_get_inc() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_for_get_inc(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_expr ast_node::for_get_init() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_for_get_init(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_expr ast_node::for_get_iterator() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_for_get_iterator(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool ast_node::for_is_degenerate() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_for_is_degenerate(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::id ast_node::get_annotation() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_get_annotation(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

enum isl::ast_node_type ast_node::get_type() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_get_type(get());
  return static_cast<enum isl::ast_node_type>(res);
}

isl::ast_expr ast_node::if_get_cond() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_if_get_cond(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_node ast_node::if_get_else() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_if_get_else(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_node ast_node::if_get_then() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_if_get_then(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool ast_node::if_has_else() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_if_has_else(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::id ast_node::mark_get_id() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_mark_get_id(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_node ast_node::mark_get_node() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_mark_get_node(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::ast_node ast_node::set_annotation(isl::id annotation) const
{
  if (!ptr || annotation.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_set_annotation(copy(), annotation.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string ast_node::to_C_str() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_to_C_str(get());
  std::string tmp(res);
  free(res);
  return tmp;
}

isl::ast_expr ast_node::user_get_expr() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_ast_node_user_get_expr(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::list<ast_node>
isl::list<ast_node> manage(__isl_take isl_ast_node_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return list<ast_node>(ptr);
}
isl::list<ast_node> manage_copy(__isl_keep isl_ast_node_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_ast_node_list_get_ctx(ptr);
  ptr = isl_ast_node_list_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return list<ast_node>(ptr);
}

list<ast_node>::list()
    : ptr(nullptr) {}

list<ast_node>::list(const isl::list<ast_node> &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_ast_node_list_get_ctx(obj.ptr));
}

list<ast_node>::list(__isl_take isl_ast_node_list *ptr)
    : ptr(ptr) {}


list<ast_node> &list<ast_node>::operator=(isl::list<ast_node> obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

list<ast_node>::~list() {
  if (ptr)
    isl_ast_node_list_free(ptr);
}

__isl_give isl_ast_node_list *list<ast_node>::copy() const & {
  return isl_ast_node_list_copy(ptr);
}

__isl_keep isl_ast_node_list *list<ast_node>::get() const {
  return ptr;
}

__isl_give isl_ast_node_list *list<ast_node>::release() {
  isl_ast_node_list *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool list<ast_node>::is_null() const {
  return ptr == nullptr;
}
list<ast_node>::operator bool() const
{
  return !is_null();
}



isl::ctx list<ast_node>::get_ctx() const {
  return isl::ctx(isl_ast_node_list_get_ctx(ptr));
}


template <typename InputIt1, typename InputIt2>
list<ast_node>::list(isl::ctx ctx, InputIt1 from, InputIt2 to) {
  ptr = isl_ast_node_list_alloc(ctx.get(), std::distance(from, to));
  for ( ; from != to; ++from) {
    ptr = isl_ast_node_list_add(ptr, from->copy());
  }
}

int list<ast_node>::size() const {
  return isl_ast_node_list_n_ast_node(ptr);
}

isl::ast_node list<ast_node>::at(int pos) const {
  return manage(isl_ast_node_list_get_ast_node(ptr, pos));
}

isl::ast_node list<ast_node>::operator[](int pos) const {
  return manage(isl_ast_node_list_get_ast_node(ptr, pos));
}

typename isl::list<ast_node>::iterator
list<ast_node>::begin() const {
  return list_iterator<ast_node>(this, size() == 0 ? -1 : 0);
}

typename isl::list<ast_node>::iterator
list<ast_node>::end() const {
  return list_iterator<ast_node>(this, -1);
}


// implementations for isl::basic_map
isl::basic_map manage(__isl_take isl_basic_map *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return basic_map(ptr);
}
isl::basic_map manage_copy(__isl_keep isl_basic_map *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_basic_map_get_ctx(ptr);
  ptr = isl_basic_map_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return basic_map(ptr);
}

basic_map::basic_map()
    : ptr(nullptr) {}

basic_map::basic_map(const isl::basic_map &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_basic_map_get_ctx(obj.ptr));
}

basic_map::basic_map(__isl_take isl_basic_map *ptr)
    : ptr(ptr) {}

basic_map::basic_map(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
basic_map::basic_map(isl::basic_set domain, isl::basic_set range)
{
  if (domain.is_null() || range.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_from_domain_and_range(domain.release(), range.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
basic_map::basic_map(isl::aff aff)
{
  if (aff.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = aff.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_from_aff(aff.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
basic_map::basic_map(isl::multi_aff maff)
{
  if (maff.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = maff.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_from_multi_aff(maff.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

basic_map &basic_map::operator=(isl::basic_map obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

basic_map::~basic_map() {
  if (ptr)
    isl_basic_map_free(ptr);
}

__isl_give isl_basic_map *basic_map::copy() const & {
  return isl_basic_map_copy(ptr);
}

__isl_keep isl_basic_map *basic_map::get() const {
  return ptr;
}

__isl_give isl_basic_map *basic_map::release() {
  isl_basic_map *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool basic_map::is_null() const {
  return ptr == nullptr;
}
basic_map::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const basic_map& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const basic_map& C1, const basic_map& C2) {
  return C1.is_equal(C2);
}


std::string basic_map::to_str() const {
  char *Tmp = isl_basic_map_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx basic_map::get_ctx() const {
  return isl::ctx(isl_basic_map_get_ctx(ptr));
}

isl::basic_map basic_map::add_constraint(isl::constraint constraint) const
{
  if (!ptr || constraint.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_add_constraint(copy(), constraint.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::affine_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_affine_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::apply_domain(isl::basic_map bmap2) const
{
  if (!ptr || bmap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_apply_domain(copy(), bmap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::apply_range(isl::basic_map bmap2) const
{
  if (!ptr || bmap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_apply_range(copy(), bmap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool basic_map::can_curry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_can_curry(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool basic_map::can_uncurry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_can_uncurry(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::basic_map basic_map::curry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_curry(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_map::deltas() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_deltas(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::detect_equalities() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_detect_equalities(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int basic_map::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::basic_set basic_map::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::empty(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_empty(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::basic_map basic_map::flatten() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_flatten(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::flatten_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_flatten_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::flatten_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_flatten_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void basic_map::foreach_constraint(const std::function<void(isl::constraint)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::constraint)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_constraint *arg_0, void *arg_1) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      (*data->func)(isl::manage(arg_0));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_basic_map_foreach_constraint(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::basic_map basic_map::from_domain(isl::basic_set bset)
{
  if (bset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = bset.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_from_domain(bset.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::basic_map basic_map::from_range(isl::basic_set bset)
{
  if (bset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = bset.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_from_range(bset.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::list<isl::constraint> basic_map::get_constraint_list() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_get_constraint_list(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space basic_map::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string basic_map::get_tuple_name(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_get_tuple_name(get(), static_cast<enum isl_dim_type>(type));
  std::string tmp(res);
  return tmp;
}

isl::basic_map basic_map::gist(isl::basic_map context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_gist(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::intersect(isl::basic_map bmap2) const
{
  if (!ptr || bmap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_intersect(copy(), bmap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::intersect_domain(isl::basic_set bset) const
{
  if (!ptr || bset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_intersect_domain(copy(), bset.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::intersect_range(isl::basic_set bset) const
{
  if (!ptr || bset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_intersect_range(copy(), bset.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool basic_map::is_empty() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_is_empty(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool basic_map::is_equal(const isl::basic_map &bmap2) const
{
  if (!ptr || bmap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_is_equal(get(), bmap2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool basic_map::is_subset(const isl::basic_map &bmap2) const
{
  if (!ptr || bmap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_is_subset(get(), bmap2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::map basic_map::lexmax() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_lexmax(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map basic_map::lexmin() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_lexmin(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int basic_map::n_constraint() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_n_constraint(get());
  return res;
}

isl::basic_map basic_map::project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_project_out(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::reverse() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_reverse(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::sample() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_sample(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map basic_map::uncurry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_uncurry(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map basic_map::unite(isl::basic_map bmap2) const
{
  if (!ptr || bmap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_union(copy(), bmap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_map::wrap() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_wrap(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::list<basic_map>
isl::list<basic_map> manage(__isl_take isl_basic_map_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return list<basic_map>(ptr);
}
isl::list<basic_map> manage_copy(__isl_keep isl_basic_map_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_basic_map_list_get_ctx(ptr);
  ptr = isl_basic_map_list_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return list<basic_map>(ptr);
}

list<basic_map>::list()
    : ptr(nullptr) {}

list<basic_map>::list(const isl::list<basic_map> &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_basic_map_list_get_ctx(obj.ptr));
}

list<basic_map>::list(__isl_take isl_basic_map_list *ptr)
    : ptr(ptr) {}


list<basic_map> &list<basic_map>::operator=(isl::list<basic_map> obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

list<basic_map>::~list() {
  if (ptr)
    isl_basic_map_list_free(ptr);
}

__isl_give isl_basic_map_list *list<basic_map>::copy() const & {
  return isl_basic_map_list_copy(ptr);
}

__isl_keep isl_basic_map_list *list<basic_map>::get() const {
  return ptr;
}

__isl_give isl_basic_map_list *list<basic_map>::release() {
  isl_basic_map_list *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool list<basic_map>::is_null() const {
  return ptr == nullptr;
}
list<basic_map>::operator bool() const
{
  return !is_null();
}



isl::ctx list<basic_map>::get_ctx() const {
  return isl::ctx(isl_basic_map_list_get_ctx(ptr));
}

isl::basic_map list<basic_map>::intersect() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_map_list_intersect(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

template <typename InputIt1, typename InputIt2>
list<basic_map>::list(isl::ctx ctx, InputIt1 from, InputIt2 to) {
  ptr = isl_basic_map_list_alloc(ctx.get(), std::distance(from, to));
  for ( ; from != to; ++from) {
    ptr = isl_basic_map_list_add(ptr, from->copy());
  }
}

int list<basic_map>::size() const {
  return isl_basic_map_list_n_basic_map(ptr);
}

isl::basic_map list<basic_map>::at(int pos) const {
  return manage(isl_basic_map_list_get_basic_map(ptr, pos));
}

isl::basic_map list<basic_map>::operator[](int pos) const {
  return manage(isl_basic_map_list_get_basic_map(ptr, pos));
}

typename isl::list<basic_map>::iterator
list<basic_map>::begin() const {
  return list_iterator<basic_map>(this, size() == 0 ? -1 : 0);
}

typename isl::list<basic_map>::iterator
list<basic_map>::end() const {
  return list_iterator<basic_map>(this, -1);
}


// implementations for isl::basic_set
isl::basic_set manage(__isl_take isl_basic_set *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return basic_set(ptr);
}
isl::basic_set manage_copy(__isl_keep isl_basic_set *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_basic_set_get_ctx(ptr);
  ptr = isl_basic_set_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return basic_set(ptr);
}

basic_set::basic_set()
    : ptr(nullptr) {}

basic_set::basic_set(const isl::basic_set &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_basic_set_get_ctx(obj.ptr));
}

basic_set::basic_set(__isl_take isl_basic_set *ptr)
    : ptr(ptr) {}

basic_set::basic_set(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
basic_set::basic_set(isl::point pnt)
{
  if (pnt.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = pnt.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_from_point(pnt.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

basic_set &basic_set::operator=(isl::basic_set obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

basic_set::~basic_set() {
  if (ptr)
    isl_basic_set_free(ptr);
}

__isl_give isl_basic_set *basic_set::copy() const & {
  return isl_basic_set_copy(ptr);
}

__isl_keep isl_basic_set *basic_set::get() const {
  return ptr;
}

__isl_give isl_basic_set *basic_set::release() {
  isl_basic_set *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool basic_set::is_null() const {
  return ptr == nullptr;
}
basic_set::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const basic_set& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const basic_set& C1, const basic_set& C2) {
  return C1.is_equal(C2);
}


std::string basic_set::to_str() const {
  char *Tmp = isl_basic_set_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx basic_set::get_ctx() const {
  return isl::ctx(isl_basic_set_get_ctx(ptr));
}

isl::basic_set basic_set::add_constraint(isl::constraint constraint) const
{
  if (!ptr || constraint.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_add_constraint(copy(), constraint.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::add_dims(enum isl::dim_type type, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_add_dims(copy(), static_cast<enum isl_dim_type>(type), n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::affine_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_affine_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::apply(isl::basic_map bmap) const
{
  if (!ptr || bmap.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_apply(copy(), bmap.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set basic_set::compute_divs() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_compute_divs(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::detect_equalities() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_detect_equalities(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int basic_set::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::val basic_set::dim_max_val(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_dim_max_val(copy(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::flatten() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_flatten(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void basic_set::foreach_constraint(const std::function<void(isl::constraint)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::constraint)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_constraint *arg_0, void *arg_1) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      (*data->func)(isl::manage(arg_0));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_basic_set_foreach_constraint(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::basic_set basic_set::from_params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_from_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::list<isl::constraint> basic_set::get_constraint_list() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_get_constraint_list(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id basic_set::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space basic_set::get_local_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_get_local_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space basic_set::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::gist(isl::basic_set context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_gist(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::intersect(isl::basic_set bset2) const
{
  if (!ptr || bset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_intersect(copy(), bset2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::intersect_params(isl::basic_set bset2) const
{
  if (!ptr || bset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_intersect_params(copy(), bset2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool basic_set::involves_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_involves_dims(get(), static_cast<enum isl_dim_type>(type), first, n);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool basic_set::is_empty() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_is_empty(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool basic_set::is_equal(const isl::basic_set &bset2) const
{
  if (!ptr || bset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_is_equal(get(), bset2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool basic_set::is_subset(const isl::basic_set &bset2) const
{
  if (!ptr || bset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_is_subset(get(), bset2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool basic_set::is_universe() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_is_universe(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool basic_set::is_wrapping() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_is_wrapping(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::set basic_set::lexmax() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_lexmax(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set basic_set::lexmin() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_lexmin(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val basic_set::max_val(const isl::aff &obj) const
{
  if (!ptr || obj.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_max_val(get(), obj.get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int basic_set::n_constraint() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_n_constraint(get());
  return res;
}

unsigned int basic_set::n_dim() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_n_dim(get());
  return res;
}

unsigned int basic_set::n_param() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_n_param(get());
  return res;
}

isl::basic_set basic_set::nat_universe(isl::space dim)
{
  if (dim.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = dim.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_nat_universe(dim.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::basic_set basic_set::params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool basic_set::plain_is_universe() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_plain_is_universe(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::basic_set basic_set::project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_project_out(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::sample() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_sample(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::point basic_set::sample_point() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_sample_point(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_set_dim_name(copy(), static_cast<enum isl_dim_type>(type), pos, s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::set_tuple_id(isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_set_tuple_id(copy(), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set basic_set::unite(isl::basic_set bset2) const
{
  if (!ptr || bset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_union(copy(), bset2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set basic_set::universe(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_universe(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::basic_map basic_set::unwrap() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_basic_set_unwrap(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::list<basic_set>
isl::list<basic_set> manage(__isl_take isl_basic_set_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return list<basic_set>(ptr);
}
isl::list<basic_set> manage_copy(__isl_keep isl_basic_set_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_basic_set_list_get_ctx(ptr);
  ptr = isl_basic_set_list_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return list<basic_set>(ptr);
}

list<basic_set>::list()
    : ptr(nullptr) {}

list<basic_set>::list(const isl::list<basic_set> &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_basic_set_list_get_ctx(obj.ptr));
}

list<basic_set>::list(__isl_take isl_basic_set_list *ptr)
    : ptr(ptr) {}


list<basic_set> &list<basic_set>::operator=(isl::list<basic_set> obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

list<basic_set>::~list() {
  if (ptr)
    isl_basic_set_list_free(ptr);
}

__isl_give isl_basic_set_list *list<basic_set>::copy() const & {
  return isl_basic_set_list_copy(ptr);
}

__isl_keep isl_basic_set_list *list<basic_set>::get() const {
  return ptr;
}

__isl_give isl_basic_set_list *list<basic_set>::release() {
  isl_basic_set_list *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool list<basic_set>::is_null() const {
  return ptr == nullptr;
}
list<basic_set>::operator bool() const
{
  return !is_null();
}



isl::ctx list<basic_set>::get_ctx() const {
  return isl::ctx(isl_basic_set_list_get_ctx(ptr));
}


template <typename InputIt1, typename InputIt2>
list<basic_set>::list(isl::ctx ctx, InputIt1 from, InputIt2 to) {
  ptr = isl_basic_set_list_alloc(ctx.get(), std::distance(from, to));
  for ( ; from != to; ++from) {
    ptr = isl_basic_set_list_add(ptr, from->copy());
  }
}

int list<basic_set>::size() const {
  return isl_basic_set_list_n_basic_set(ptr);
}

isl::basic_set list<basic_set>::at(int pos) const {
  return manage(isl_basic_set_list_get_basic_set(ptr, pos));
}

isl::basic_set list<basic_set>::operator[](int pos) const {
  return manage(isl_basic_set_list_get_basic_set(ptr, pos));
}

typename isl::list<basic_set>::iterator
list<basic_set>::begin() const {
  return list_iterator<basic_set>(this, size() == 0 ? -1 : 0);
}

typename isl::list<basic_set>::iterator
list<basic_set>::end() const {
  return list_iterator<basic_set>(this, -1);
}


// implementations for isl::constraint
isl::constraint manage(__isl_take isl_constraint *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return constraint(ptr);
}
isl::constraint manage_copy(__isl_keep isl_constraint *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_constraint_get_ctx(ptr);
  ptr = isl_constraint_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return constraint(ptr);
}

constraint::constraint()
    : ptr(nullptr) {}

constraint::constraint(const isl::constraint &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_constraint_get_ctx(obj.ptr));
}

constraint::constraint(__isl_take isl_constraint *ptr)
    : ptr(ptr) {}


constraint &constraint::operator=(isl::constraint obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

constraint::~constraint() {
  if (ptr)
    isl_constraint_free(ptr);
}

__isl_give isl_constraint *constraint::copy() const & {
  return isl_constraint_copy(ptr);
}

__isl_keep isl_constraint *constraint::get() const {
  return ptr;
}

__isl_give isl_constraint *constraint::release() {
  isl_constraint *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool constraint::is_null() const {
  return ptr == nullptr;
}
constraint::operator bool() const
{
  return !is_null();
}

inline bool operator==(const constraint& C1, const constraint& C2) {
  return C1.is_equal(C2);
}



isl::ctx constraint::get_ctx() const {
  return isl::ctx(isl_constraint_get_ctx(ptr));
}

isl::constraint constraint::alloc_equality(isl::local_space ls)
{
  if (ls.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = ls.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_alloc_equality(ls.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::constraint constraint::alloc_inequality(isl::local_space ls)
{
  if (ls.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = ls.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_alloc_inequality(ls.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

int constraint::cmp_last_non_zero(const isl::constraint &c2) const
{
  if (!ptr || c2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_cmp_last_non_zero(get(), c2.get());
  return res;
}

int constraint::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::aff constraint::get_aff() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_get_aff(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff constraint::get_bound(enum isl::dim_type type, int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_get_bound(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val constraint::get_coefficient_val(enum isl::dim_type type, int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_get_coefficient_val(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val constraint::get_constant_val() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_get_constant_val(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string constraint::get_dim_name(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_get_dim_name(get(), static_cast<enum isl_dim_type>(type), pos);
  std::string tmp(res);
  return tmp;
}

isl::aff constraint::get_div(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_get_div(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space constraint::get_local_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_get_local_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space constraint::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool constraint::involves_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_involves_dims(get(), static_cast<enum isl_dim_type>(type), first, n);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

int constraint::is_div_constraint() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_is_div_constraint(get());
  return res;
}

bool constraint::is_equal(const isl::constraint &constraint2) const
{
  if (!ptr || constraint2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_is_equal(get(), constraint2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool constraint::is_equality() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_is_equality(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool constraint::is_lower_bound(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_is_lower_bound(get(), static_cast<enum isl_dim_type>(type), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool constraint::is_upper_bound(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_is_upper_bound(get(), static_cast<enum isl_dim_type>(type), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

int constraint::plain_cmp(const isl::constraint &c2) const
{
  if (!ptr || c2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_plain_cmp(get(), c2.get());
  return res;
}

isl::constraint constraint::set_coefficient_si(enum isl::dim_type type, int pos, int v) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_set_coefficient_si(copy(), static_cast<enum isl_dim_type>(type), pos, v);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::constraint constraint::set_coefficient_val(enum isl::dim_type type, int pos, isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_set_coefficient_val(copy(), static_cast<enum isl_dim_type>(type), pos, v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::constraint constraint::set_constant_si(int v) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_set_constant_si(copy(), v);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::constraint constraint::set_constant_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_constraint_set_constant_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::list<constraint>
isl::list<constraint> manage(__isl_take isl_constraint_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return list<constraint>(ptr);
}
isl::list<constraint> manage_copy(__isl_keep isl_constraint_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_constraint_list_get_ctx(ptr);
  ptr = isl_constraint_list_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return list<constraint>(ptr);
}

list<constraint>::list()
    : ptr(nullptr) {}

list<constraint>::list(const isl::list<constraint> &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_constraint_list_get_ctx(obj.ptr));
}

list<constraint>::list(__isl_take isl_constraint_list *ptr)
    : ptr(ptr) {}


list<constraint> &list<constraint>::operator=(isl::list<constraint> obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

list<constraint>::~list() {
  if (ptr)
    isl_constraint_list_free(ptr);
}

__isl_give isl_constraint_list *list<constraint>::copy() const & {
  return isl_constraint_list_copy(ptr);
}

__isl_keep isl_constraint_list *list<constraint>::get() const {
  return ptr;
}

__isl_give isl_constraint_list *list<constraint>::release() {
  isl_constraint_list *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool list<constraint>::is_null() const {
  return ptr == nullptr;
}
list<constraint>::operator bool() const
{
  return !is_null();
}



isl::ctx list<constraint>::get_ctx() const {
  return isl::ctx(isl_constraint_list_get_ctx(ptr));
}


template <typename InputIt1, typename InputIt2>
list<constraint>::list(isl::ctx ctx, InputIt1 from, InputIt2 to) {
  ptr = isl_constraint_list_alloc(ctx.get(), std::distance(from, to));
  for ( ; from != to; ++from) {
    ptr = isl_constraint_list_add(ptr, from->copy());
  }
}

int list<constraint>::size() const {
  return isl_constraint_list_n_constraint(ptr);
}

isl::constraint list<constraint>::at(int pos) const {
  return manage(isl_constraint_list_get_constraint(ptr, pos));
}

isl::constraint list<constraint>::operator[](int pos) const {
  return manage(isl_constraint_list_get_constraint(ptr, pos));
}

typename isl::list<constraint>::iterator
list<constraint>::begin() const {
  return list_iterator<constraint>(this, size() == 0 ? -1 : 0);
}

typename isl::list<constraint>::iterator
list<constraint>::end() const {
  return list_iterator<constraint>(this, -1);
}


// implementations for isl::list<id>
isl::list<id> manage(__isl_take isl_id_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return list<id>(ptr);
}
isl::list<id> manage_copy(__isl_keep isl_id_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_id_list_get_ctx(ptr);
  ptr = isl_id_list_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return list<id>(ptr);
}

list<id>::list()
    : ptr(nullptr) {}

list<id>::list(const isl::list<id> &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_id_list_get_ctx(obj.ptr));
}

list<id>::list(__isl_take isl_id_list *ptr)
    : ptr(ptr) {}


list<id> &list<id>::operator=(isl::list<id> obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

list<id>::~list() {
  if (ptr)
    isl_id_list_free(ptr);
}

__isl_give isl_id_list *list<id>::copy() const & {
  return isl_id_list_copy(ptr);
}

__isl_keep isl_id_list *list<id>::get() const {
  return ptr;
}

__isl_give isl_id_list *list<id>::release() {
  isl_id_list *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool list<id>::is_null() const {
  return ptr == nullptr;
}
list<id>::operator bool() const
{
  return !is_null();
}



isl::ctx list<id>::get_ctx() const {
  return isl::ctx(isl_id_list_get_ctx(ptr));
}


template <typename InputIt1, typename InputIt2>
list<id>::list(isl::ctx ctx, InputIt1 from, InputIt2 to) {
  ptr = isl_id_list_alloc(ctx.get(), std::distance(from, to));
  for ( ; from != to; ++from) {
    ptr = isl_id_list_add(ptr, from->copy());
  }
}

int list<id>::size() const {
  return isl_id_list_n_id(ptr);
}

isl::id list<id>::at(int pos) const {
  return manage(isl_id_list_get_id(ptr, pos));
}

isl::id list<id>::operator[](int pos) const {
  return manage(isl_id_list_get_id(ptr, pos));
}

typename isl::list<id>::iterator
list<id>::begin() const {
  return list_iterator<id>(this, size() == 0 ? -1 : 0);
}

typename isl::list<id>::iterator
list<id>::end() const {
  return list_iterator<id>(this, -1);
}


// implementations for isl::local_space
isl::local_space manage(__isl_take isl_local_space *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return local_space(ptr);
}
isl::local_space manage_copy(__isl_keep isl_local_space *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_local_space_get_ctx(ptr);
  ptr = isl_local_space_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return local_space(ptr);
}

local_space::local_space()
    : ptr(nullptr) {}

local_space::local_space(const isl::local_space &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_local_space_get_ctx(obj.ptr));
}

local_space::local_space(__isl_take isl_local_space *ptr)
    : ptr(ptr) {}

local_space::local_space(isl::space dim)
{
  if (dim.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = dim.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_from_space(dim.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

local_space &local_space::operator=(isl::local_space obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

local_space::~local_space() {
  if (ptr)
    isl_local_space_free(ptr);
}

__isl_give isl_local_space *local_space::copy() const & {
  return isl_local_space_copy(ptr);
}

__isl_keep isl_local_space *local_space::get() const {
  return ptr;
}

__isl_give isl_local_space *local_space::release() {
  isl_local_space *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool local_space::is_null() const {
  return ptr == nullptr;
}
local_space::operator bool() const
{
  return !is_null();
}

inline bool operator==(const local_space& C1, const local_space& C2) {
  return C1.is_equal(C2);
}



isl::ctx local_space::get_ctx() const {
  return isl::ctx(isl_local_space_get_ctx(ptr));
}

isl::local_space local_space::add_dims(enum isl::dim_type type, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_add_dims(copy(), static_cast<enum isl_dim_type>(type), n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int local_space::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::local_space local_space::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space local_space::drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_drop_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int local_space::find_dim_by_name(enum isl::dim_type type, const std::string &name) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_find_dim_by_name(get(), static_cast<enum isl_dim_type>(type), name.c_str());
  return res;
}

isl::local_space local_space::flatten_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_flatten_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space local_space::flatten_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_flatten_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space local_space::from_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_from_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id local_space::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string local_space::get_dim_name(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_get_dim_name(get(), static_cast<enum isl_dim_type>(type), pos);
  std::string tmp(res);
  return tmp;
}

isl::aff local_space::get_div(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_get_div(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space local_space::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool local_space::has_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_has_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool local_space::has_dim_name(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_has_dim_name(get(), static_cast<enum isl_dim_type>(type), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::local_space local_space::insert_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_insert_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space local_space::intersect(isl::local_space ls2) const
{
  if (!ptr || ls2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_intersect(copy(), ls2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool local_space::is_equal(const isl::local_space &ls2) const
{
  if (!ptr || ls2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_is_equal(get(), ls2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool local_space::is_params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_is_params(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool local_space::is_set() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_is_set(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::basic_map local_space::lifting() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_lifting(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space local_space::range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space local_space::set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_set_dim_id(copy(), static_cast<enum isl_dim_type>(type), pos, id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space local_space::set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_set_dim_name(copy(), static_cast<enum isl_dim_type>(type), pos, s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space local_space::set_tuple_id(enum isl::dim_type type, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_set_tuple_id(copy(), static_cast<enum isl_dim_type>(type), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::local_space local_space::wrap() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_local_space_wrap(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::map
isl::map manage(__isl_take isl_map *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return map(ptr);
}
isl::map manage_copy(__isl_keep isl_map *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_map_get_ctx(ptr);
  ptr = isl_map_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return map(ptr);
}

map::map()
    : ptr(nullptr) {}

map::map(const isl::map &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_map_get_ctx(obj.ptr));
}

map::map(__isl_take isl_map *ptr)
    : ptr(ptr) {}

map::map(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
map::map(isl::basic_map bmap)
{
  if (bmap.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = bmap.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_from_basic_map(bmap.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
map::map(isl::set domain, isl::set range)
{
  if (domain.is_null() || range.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_from_domain_and_range(domain.release(), range.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
map::map(isl::aff aff)
{
  if (aff.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = aff.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_from_aff(aff.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
map::map(isl::multi_aff maff)
{
  if (maff.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = maff.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_from_multi_aff(maff.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

map &map::operator=(isl::map obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

map::~map() {
  if (ptr)
    isl_map_free(ptr);
}

__isl_give isl_map *map::copy() const & {
  return isl_map_copy(ptr);
}

__isl_keep isl_map *map::get() const {
  return ptr;
}

__isl_give isl_map *map::release() {
  isl_map *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool map::is_null() const {
  return ptr == nullptr;
}
map::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const map& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const map& C1, const map& C2) {
  return C1.is_equal(C2);
}


std::string map::to_str() const {
  char *Tmp = isl_map_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx map::get_ctx() const {
  return isl::ctx(isl_map_get_ctx(ptr));
}

isl::map map::add_constraint(isl::constraint constraint) const
{
  if (!ptr || constraint.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_add_constraint(copy(), constraint.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::add_dims(enum isl::dim_type type, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_add_dims(copy(), static_cast<enum isl_dim_type>(type), n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map map::affine_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_affine_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::apply_domain(isl::map map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_apply_domain(copy(), map2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::apply_range(isl::map map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_apply_range(copy(), map2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool map::can_curry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_can_curry(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::can_range_curry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_can_range_curry(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::can_uncurry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_can_uncurry(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::map map::coalesce() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_coalesce(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::complement() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_complement(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::compute_divs() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_compute_divs(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::curry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_curry(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set map::deltas() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_deltas(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::detect_equalities() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_detect_equalities(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int map::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::set map::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::domain_factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_domain_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::domain_factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_domain_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::domain_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_domain_map(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::domain_product(isl::map map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_domain_product(copy(), map2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::empty(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_empty(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

int map::find_dim_by_id(enum isl::dim_type type, const isl::id &id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_find_dim_by_id(get(), static_cast<enum isl_dim_type>(type), id.get());
  return res;
}

int map::find_dim_by_name(enum isl::dim_type type, const std::string &name) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_find_dim_by_name(get(), static_cast<enum isl_dim_type>(type), name.c_str());
  return res;
}

isl::map map::flatten() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_flatten(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::flatten_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_flatten_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::flatten_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_flatten_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void map::foreach_basic_map(const std::function<void(isl::basic_map)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::basic_map)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_basic_map *arg_0, void *arg_1) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      (*data->func)(isl::manage(arg_0));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_map_foreach_basic_map(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::map map::from(isl::pw_multi_aff pma)
{
  if (pma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = pma.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_from_pw_multi_aff(pma.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::map map::from_domain(isl::set set)
{
  if (set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = set.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_from_domain(set.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::map map::from_range(isl::set set)
{
  if (set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = set.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_from_range(set.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::map map::from_union_map(isl::union_map umap)
{
  if (umap.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = umap.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_from_union_map(umap.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::list<isl::basic_map> map::get_basic_map_list() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_get_basic_map_list(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id map::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space map::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id map::get_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_get_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string map::get_tuple_name(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_get_tuple_name(get(), static_cast<enum isl_dim_type>(type));
  std::string tmp(res);
  return tmp;
}

isl::map map::gist(isl::map context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_gist(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::gist_domain(isl::set context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_gist_domain(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool map::has_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_has_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::has_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_has_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::has_tuple_name(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_has_tuple_name(get(), static_cast<enum isl_dim_type>(type));
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::map map::identity(isl::space dim)
{
  if (dim.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = dim.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_identity(dim.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::map map::insert_dims(enum isl::dim_type type, unsigned int pos, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_insert_dims(copy(), static_cast<enum isl_dim_type>(type), pos, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::intersect(isl::map map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_intersect(copy(), map2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::intersect_domain(isl::set set) const
{
  if (!ptr || set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_intersect_domain(copy(), set.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::intersect_params(isl::set params) const
{
  if (!ptr || params.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_intersect_params(copy(), params.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::intersect_range(isl::set set) const
{
  if (!ptr || set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_intersect_range(copy(), set.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool map::is_bijective() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_is_bijective(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::is_disjoint(const isl::map &map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_is_disjoint(get(), map2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::is_empty() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_is_empty(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::is_equal(const isl::map &map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_is_equal(get(), map2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::is_injective() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_is_injective(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::is_single_valued() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_is_single_valued(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::is_strict_subset(const isl::map &map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_is_strict_subset(get(), map2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool map::is_subset(const isl::map &map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_is_subset(get(), map2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::map map::lexmax() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_lexmax(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::lexmin() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_lexmin(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int map::n_basic_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_n_basic_map(get());
  return res;
}

isl::set map::params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map map::polyhedral_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_polyhedral_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_project_out(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set map::range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::range_curry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_range_curry(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::range_factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_range_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::range_factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_range_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::range_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_range_map(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::range_product(isl::map map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_range_product(copy(), map2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::remove_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_remove_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::reset_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_reset_tuple_id(copy(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::reverse() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_reverse(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map map::sample() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_sample(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_set_dim_id(copy(), static_cast<enum isl_dim_type>(type), pos, id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::set_tuple_id(enum isl::dim_type type, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_set_tuple_id(copy(), static_cast<enum isl_dim_type>(type), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::set_tuple_name(enum isl::dim_type type, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_set_tuple_name(copy(), static_cast<enum isl_dim_type>(type), s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_map map::simple_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_simple_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::subtract(isl::map map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_subtract(copy(), map2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::uncurry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_uncurry(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::unite(isl::map map2) const
{
  if (!ptr || map2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_union(copy(), map2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map map::universe(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_universe(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::basic_map map::unshifted_simple_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_unshifted_simple_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set map::wrap() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_map_wrap(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::multi_aff
isl::multi_aff manage(__isl_take isl_multi_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return multi_aff(ptr);
}
isl::multi_aff manage_copy(__isl_keep isl_multi_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_multi_aff_get_ctx(ptr);
  ptr = isl_multi_aff_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return multi_aff(ptr);
}

multi_aff::multi_aff()
    : ptr(nullptr) {}

multi_aff::multi_aff(const isl::multi_aff &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_multi_aff_get_ctx(obj.ptr));
}

multi_aff::multi_aff(__isl_take isl_multi_aff *ptr)
    : ptr(ptr) {}

multi_aff::multi_aff(isl::aff aff)
{
  if (aff.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = aff.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_from_aff(aff.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
multi_aff::multi_aff(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

multi_aff &multi_aff::operator=(isl::multi_aff obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

multi_aff::~multi_aff() {
  if (ptr)
    isl_multi_aff_free(ptr);
}

__isl_give isl_multi_aff *multi_aff::copy() const & {
  return isl_multi_aff_copy(ptr);
}

__isl_keep isl_multi_aff *multi_aff::get() const {
  return ptr;
}

__isl_give isl_multi_aff *multi_aff::release() {
  isl_multi_aff *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool multi_aff::is_null() const {
  return ptr == nullptr;
}
multi_aff::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const multi_aff& C) {
  os << C.to_str();
  return os;
}


std::string multi_aff::to_str() const {
  char *Tmp = isl_multi_aff_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx multi_aff::get_ctx() const {
  return isl::ctx(isl_multi_aff_get_ctx(ptr));
}

isl::multi_aff multi_aff::add(isl::multi_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_add(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::add_dims(enum isl::dim_type type, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_add_dims(copy(), static_cast<enum isl_dim_type>(type), n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::align_params(isl::space model) const
{
  if (!ptr || model.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_align_params(copy(), model.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int multi_aff::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::multi_aff multi_aff::domain_map(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_domain_map(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::multi_aff multi_aff::drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_drop_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int multi_aff::find_dim_by_id(enum isl::dim_type type, const isl::id &id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_find_dim_by_id(get(), static_cast<enum isl_dim_type>(type), id.get());
  return res;
}

int multi_aff::find_dim_by_name(enum isl::dim_type type, const std::string &name) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_find_dim_by_name(get(), static_cast<enum isl_dim_type>(type), name.c_str());
  return res;
}

isl::multi_aff multi_aff::flat_range_product(isl::multi_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_flat_range_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::flatten_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_flatten_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::floor() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_floor(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::from_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_from_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::aff multi_aff::get_aff(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_get_aff(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id multi_aff::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space multi_aff::get_domain_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_get_domain_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space multi_aff::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id multi_aff::get_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_get_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string multi_aff::get_tuple_name(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_get_tuple_name(get(), static_cast<enum isl_dim_type>(type));
  std::string tmp(res);
  return tmp;
}

bool multi_aff::has_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_has_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::multi_aff multi_aff::identity(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_identity(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::multi_aff multi_aff::insert_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_insert_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::mod_multi_val(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_mod_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::neg() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_neg(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::product(isl::multi_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::project_out_map(isl::space space, enum isl::dim_type type, unsigned int first, unsigned int n)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_project_out_map(space.release(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::multi_aff multi_aff::pullback(isl::multi_aff ma2) const
{
  if (!ptr || ma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_pullback_multi_aff(copy(), ma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::range_factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_range_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::range_factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_range_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::range_map(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_range_map(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::multi_aff multi_aff::range_product(isl::multi_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_range_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::range_splice(unsigned int pos, isl::multi_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_range_splice(copy(), pos, multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::reset_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_reset_tuple_id(copy(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::reset_user() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_reset_user(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::scale_down(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_scale_down_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::scale_down_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_scale_down_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::scale_multi_val(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_scale_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::scale_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_scale_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::set_aff(int pos, isl::aff el) const
{
  if (!ptr || el.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_set_aff(copy(), pos, el.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_set_dim_name(copy(), static_cast<enum isl_dim_type>(type), pos, s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::set_tuple_id(enum isl::dim_type type, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_set_tuple_id(copy(), static_cast<enum isl_dim_type>(type), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::set_tuple_name(enum isl::dim_type type, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_set_tuple_name(copy(), static_cast<enum isl_dim_type>(type), s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::splice(unsigned int in_pos, unsigned int out_pos, isl::multi_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_splice(copy(), in_pos, out_pos, multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::sub(isl::multi_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_sub(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_aff multi_aff::zero(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_aff_zero(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}


// implementations for isl::multi_pw_aff
isl::multi_pw_aff manage(__isl_take isl_multi_pw_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return multi_pw_aff(ptr);
}
isl::multi_pw_aff manage_copy(__isl_keep isl_multi_pw_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_multi_pw_aff_get_ctx(ptr);
  ptr = isl_multi_pw_aff_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return multi_pw_aff(ptr);
}

multi_pw_aff::multi_pw_aff()
    : ptr(nullptr) {}

multi_pw_aff::multi_pw_aff(const isl::multi_pw_aff &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_multi_pw_aff_get_ctx(obj.ptr));
}

multi_pw_aff::multi_pw_aff(__isl_take isl_multi_pw_aff *ptr)
    : ptr(ptr) {}

multi_pw_aff::multi_pw_aff(isl::multi_aff ma)
{
  if (ma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = ma.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_from_multi_aff(ma.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
multi_pw_aff::multi_pw_aff(isl::pw_aff pa)
{
  if (pa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = pa.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_from_pw_aff(pa.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
multi_pw_aff::multi_pw_aff(isl::pw_multi_aff pma)
{
  if (pma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = pma.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_from_pw_multi_aff(pma.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
multi_pw_aff::multi_pw_aff(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

multi_pw_aff &multi_pw_aff::operator=(isl::multi_pw_aff obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

multi_pw_aff::~multi_pw_aff() {
  if (ptr)
    isl_multi_pw_aff_free(ptr);
}

__isl_give isl_multi_pw_aff *multi_pw_aff::copy() const & {
  return isl_multi_pw_aff_copy(ptr);
}

__isl_keep isl_multi_pw_aff *multi_pw_aff::get() const {
  return ptr;
}

__isl_give isl_multi_pw_aff *multi_pw_aff::release() {
  isl_multi_pw_aff *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool multi_pw_aff::is_null() const {
  return ptr == nullptr;
}
multi_pw_aff::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const multi_pw_aff& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const multi_pw_aff& C1, const multi_pw_aff& C2) {
  return C1.is_equal(C2);
}


std::string multi_pw_aff::to_str() const {
  char *Tmp = isl_multi_pw_aff_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx multi_pw_aff::get_ctx() const {
  return isl::ctx(isl_multi_pw_aff_get_ctx(ptr));
}

isl::multi_pw_aff multi_pw_aff::add(isl::multi_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_add(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::add_dims(enum isl::dim_type type, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_add_dims(copy(), static_cast<enum isl_dim_type>(type), n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::align_params(isl::space model) const
{
  if (!ptr || model.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_align_params(copy(), model.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int multi_pw_aff::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::set multi_pw_aff::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_drop_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int multi_pw_aff::find_dim_by_id(enum isl::dim_type type, const isl::id &id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_find_dim_by_id(get(), static_cast<enum isl_dim_type>(type), id.get());
  return res;
}

int multi_pw_aff::find_dim_by_name(enum isl::dim_type type, const std::string &name) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_find_dim_by_name(get(), static_cast<enum isl_dim_type>(type), name.c_str());
  return res;
}

isl::multi_pw_aff multi_pw_aff::flat_range_product(isl::multi_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_flat_range_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::flatten_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_flatten_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::from_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_from_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id multi_pw_aff::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space multi_pw_aff::get_domain_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_get_domain_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff multi_pw_aff::get_pw_aff(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_get_pw_aff(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space multi_pw_aff::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id multi_pw_aff::get_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_get_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string multi_pw_aff::get_tuple_name(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_get_tuple_name(get(), static_cast<enum isl_dim_type>(type));
  std::string tmp(res);
  return tmp;
}

bool multi_pw_aff::has_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_has_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::multi_pw_aff multi_pw_aff::identity(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_identity(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::insert_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_insert_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool multi_pw_aff::is_equal(const isl::multi_pw_aff &mpa2) const
{
  if (!ptr || mpa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_is_equal(get(), mpa2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::multi_pw_aff multi_pw_aff::mod_multi_val(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_mod_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::neg() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_neg(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::product(isl::multi_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::pullback(isl::multi_aff ma) const
{
  if (!ptr || ma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_pullback_multi_aff(copy(), ma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::pullback(isl::pw_multi_aff pma) const
{
  if (!ptr || pma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_pullback_pw_multi_aff(copy(), pma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::pullback(isl::multi_pw_aff mpa2) const
{
  if (!ptr || mpa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_pullback_multi_pw_aff(copy(), mpa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::range_factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_range_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::range_factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_range_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::range_product(isl::multi_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_range_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::range_splice(unsigned int pos, isl::multi_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_range_splice(copy(), pos, multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::reset_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_reset_tuple_id(copy(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::reset_user() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_reset_user(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::scale_down(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_scale_down_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::scale_down_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_scale_down_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::scale_multi_val(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_scale_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::scale_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_scale_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_set_dim_name(copy(), static_cast<enum isl_dim_type>(type), pos, s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::set_pw_aff(int pos, isl::pw_aff el) const
{
  if (!ptr || el.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_set_pw_aff(copy(), pos, el.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::set_tuple_id(enum isl::dim_type type, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_set_tuple_id(copy(), static_cast<enum isl_dim_type>(type), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::set_tuple_name(enum isl::dim_type type, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_set_tuple_name(copy(), static_cast<enum isl_dim_type>(type), s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::splice(unsigned int in_pos, unsigned int out_pos, isl::multi_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_splice(copy(), in_pos, out_pos, multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::sub(isl::multi_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_sub(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_pw_aff::zero(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_pw_aff_zero(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}


// implementations for isl::multi_union_pw_aff
isl::multi_union_pw_aff manage(__isl_take isl_multi_union_pw_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return multi_union_pw_aff(ptr);
}
isl::multi_union_pw_aff manage_copy(__isl_keep isl_multi_union_pw_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_multi_union_pw_aff_get_ctx(ptr);
  ptr = isl_multi_union_pw_aff_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return multi_union_pw_aff(ptr);
}

multi_union_pw_aff::multi_union_pw_aff()
    : ptr(nullptr) {}

multi_union_pw_aff::multi_union_pw_aff(const isl::multi_union_pw_aff &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_multi_union_pw_aff_get_ctx(obj.ptr));
}

multi_union_pw_aff::multi_union_pw_aff(__isl_take isl_multi_union_pw_aff *ptr)
    : ptr(ptr) {}

multi_union_pw_aff::multi_union_pw_aff(isl::union_pw_aff upa)
{
  if (upa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = upa.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_from_union_pw_aff(upa.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
multi_union_pw_aff::multi_union_pw_aff(isl::multi_pw_aff mpa)
{
  if (mpa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = mpa.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_from_multi_pw_aff(mpa.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
multi_union_pw_aff::multi_union_pw_aff(isl::union_set domain, isl::multi_val mv)
{
  if (domain.is_null() || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_multi_val_on_domain(domain.release(), mv.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
multi_union_pw_aff::multi_union_pw_aff(isl::union_set domain, isl::multi_aff ma)
{
  if (domain.is_null() || ma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_multi_aff_on_domain(domain.release(), ma.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
multi_union_pw_aff::multi_union_pw_aff(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

multi_union_pw_aff &multi_union_pw_aff::operator=(isl::multi_union_pw_aff obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

multi_union_pw_aff::~multi_union_pw_aff() {
  if (ptr)
    isl_multi_union_pw_aff_free(ptr);
}

__isl_give isl_multi_union_pw_aff *multi_union_pw_aff::copy() const & {
  return isl_multi_union_pw_aff_copy(ptr);
}

__isl_keep isl_multi_union_pw_aff *multi_union_pw_aff::get() const {
  return ptr;
}

__isl_give isl_multi_union_pw_aff *multi_union_pw_aff::release() {
  isl_multi_union_pw_aff *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool multi_union_pw_aff::is_null() const {
  return ptr == nullptr;
}
multi_union_pw_aff::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const multi_union_pw_aff& C) {
  os << C.to_str();
  return os;
}


std::string multi_union_pw_aff::to_str() const {
  char *Tmp = isl_multi_union_pw_aff_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx multi_union_pw_aff::get_ctx() const {
  return isl::ctx(isl_multi_union_pw_aff_get_ctx(ptr));
}

isl::multi_union_pw_aff multi_union_pw_aff::add(isl::multi_union_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_add(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::align_params(isl::space model) const
{
  if (!ptr || model.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_align_params(copy(), model.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::apply_pw_multi_aff(isl::pw_multi_aff pma) const
{
  if (!ptr || pma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_apply_pw_multi_aff(copy(), pma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int multi_union_pw_aff::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::union_set multi_union_pw_aff::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_drop_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_pw_aff multi_union_pw_aff::extract_multi_pw_aff(isl::space space) const
{
  if (!ptr || space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_extract_multi_pw_aff(get(), space.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int multi_union_pw_aff::find_dim_by_id(enum isl::dim_type type, const isl::id &id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_find_dim_by_id(get(), static_cast<enum isl_dim_type>(type), id.get());
  return res;
}

int multi_union_pw_aff::find_dim_by_name(enum isl::dim_type type, const std::string &name) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_find_dim_by_name(get(), static_cast<enum isl_dim_type>(type), name.c_str());
  return res;
}

isl::multi_union_pw_aff multi_union_pw_aff::flat_range_product(isl::multi_union_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_flat_range_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::flatten_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_flatten_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::floor() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_floor(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::from_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_from_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::from_union_map(isl::union_map umap)
{
  if (umap.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = umap.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_from_union_map(umap.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::id multi_union_pw_aff::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space multi_union_pw_aff::get_domain_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_get_domain_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space multi_union_pw_aff::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id multi_union_pw_aff::get_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_get_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string multi_union_pw_aff::get_tuple_name(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_get_tuple_name(get(), static_cast<enum isl_dim_type>(type));
  std::string tmp(res);
  return tmp;
}

isl::union_pw_aff multi_union_pw_aff::get_union_pw_aff(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_get_union_pw_aff(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::gist(isl::union_set context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_gist(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool multi_union_pw_aff::has_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_has_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::multi_union_pw_aff multi_union_pw_aff::mod_multi_val(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_mod_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::neg() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_neg(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::pullback(isl::union_pw_multi_aff upma) const
{
  if (!ptr || upma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_pullback_union_pw_multi_aff(copy(), upma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::range_factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_range_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::range_factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_range_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::range_product(isl::multi_union_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_range_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::range_splice(unsigned int pos, isl::multi_union_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_range_splice(copy(), pos, multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::reset_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_reset_tuple_id(copy(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::reset_user() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_reset_user(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::scale_down(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_scale_down_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::scale_down_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_scale_down_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::scale_multi_val(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_scale_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::scale_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_scale_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_set_dim_name(copy(), static_cast<enum isl_dim_type>(type), pos, s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::set_tuple_id(enum isl::dim_type type, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_set_tuple_id(copy(), static_cast<enum isl_dim_type>(type), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::set_tuple_name(enum isl::dim_type type, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_set_tuple_name(copy(), static_cast<enum isl_dim_type>(type), s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::set_union_pw_aff(int pos, isl::union_pw_aff el) const
{
  if (!ptr || el.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_set_union_pw_aff(copy(), pos, el.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::sub(isl::multi_union_pw_aff multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_sub(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::union_add(isl::multi_union_pw_aff mupa2) const
{
  if (!ptr || mupa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_union_add(copy(), mupa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff multi_union_pw_aff::zero(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_zero(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::union_set multi_union_pw_aff::zero_union_set() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_union_pw_aff_zero_union_set(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::multi_val
isl::multi_val manage(__isl_take isl_multi_val *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return multi_val(ptr);
}
isl::multi_val manage_copy(__isl_keep isl_multi_val *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_multi_val_get_ctx(ptr);
  ptr = isl_multi_val_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return multi_val(ptr);
}

multi_val::multi_val()
    : ptr(nullptr) {}

multi_val::multi_val(const isl::multi_val &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_multi_val_get_ctx(obj.ptr));
}

multi_val::multi_val(__isl_take isl_multi_val *ptr)
    : ptr(ptr) {}


multi_val &multi_val::operator=(isl::multi_val obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

multi_val::~multi_val() {
  if (ptr)
    isl_multi_val_free(ptr);
}

__isl_give isl_multi_val *multi_val::copy() const & {
  return isl_multi_val_copy(ptr);
}

__isl_keep isl_multi_val *multi_val::get() const {
  return ptr;
}

__isl_give isl_multi_val *multi_val::release() {
  isl_multi_val *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool multi_val::is_null() const {
  return ptr == nullptr;
}
multi_val::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const multi_val& C) {
  os << C.to_str();
  return os;
}


std::string multi_val::to_str() const {
  char *Tmp = isl_multi_val_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx multi_val::get_ctx() const {
  return isl::ctx(isl_multi_val_get_ctx(ptr));
}

isl::multi_val multi_val::add(isl::multi_val multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_add(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::add_dims(enum isl::dim_type type, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_add_dims(copy(), static_cast<enum isl_dim_type>(type), n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::align_params(isl::space model) const
{
  if (!ptr || model.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_align_params(copy(), model.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int multi_val::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::multi_val multi_val::drop_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_drop_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int multi_val::find_dim_by_id(enum isl::dim_type type, const isl::id &id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_find_dim_by_id(get(), static_cast<enum isl_dim_type>(type), id.get());
  return res;
}

int multi_val::find_dim_by_name(enum isl::dim_type type, const std::string &name) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_find_dim_by_name(get(), static_cast<enum isl_dim_type>(type), name.c_str());
  return res;
}

isl::multi_val multi_val::flat_range_product(isl::multi_val multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_flat_range_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::flatten_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_flatten_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::from_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_from_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id multi_val::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space multi_val::get_domain_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_get_domain_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space multi_val::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id multi_val::get_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_get_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string multi_val::get_tuple_name(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_get_tuple_name(get(), static_cast<enum isl_dim_type>(type));
  std::string tmp(res);
  return tmp;
}

isl::val multi_val::get_val(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_get_val(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool multi_val::has_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_has_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::multi_val multi_val::insert_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_insert_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::mod_multi_val(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_mod_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::neg() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_neg(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::product(isl::multi_val multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::range_factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_range_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::range_factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_range_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::range_product(isl::multi_val multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_range_product(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::range_splice(unsigned int pos, isl::multi_val multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_range_splice(copy(), pos, multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::reset_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_reset_tuple_id(copy(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::reset_user() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_reset_user(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::scale_down(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_scale_down_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::scale_down_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_scale_down_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::scale_multi_val(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_scale_multi_val(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::scale_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_scale_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_set_dim_name(copy(), static_cast<enum isl_dim_type>(type), pos, s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::set_tuple_id(enum isl::dim_type type, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_set_tuple_id(copy(), static_cast<enum isl_dim_type>(type), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::set_tuple_name(enum isl::dim_type type, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_set_tuple_name(copy(), static_cast<enum isl_dim_type>(type), s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::set_val(int pos, isl::val el) const
{
  if (!ptr || el.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_set_val(copy(), pos, el.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::splice(unsigned int in_pos, unsigned int out_pos, isl::multi_val multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_splice(copy(), in_pos, out_pos, multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::sub(isl::multi_val multi2) const
{
  if (!ptr || multi2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_sub(copy(), multi2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val multi_val::zero(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_multi_val_zero(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}


// implementations for isl::point
isl::point manage(__isl_take isl_point *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return point(ptr);
}
isl::point manage_copy(__isl_keep isl_point *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_point_get_ctx(ptr);
  ptr = isl_point_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return point(ptr);
}

point::point()
    : ptr(nullptr) {}

point::point(const isl::point &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_point_get_ctx(obj.ptr));
}

point::point(__isl_take isl_point *ptr)
    : ptr(ptr) {}

point::point(isl::space dim)
{
  if (dim.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = dim.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_point_zero(dim.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

point &point::operator=(isl::point obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

point::~point() {
  if (ptr)
    isl_point_free(ptr);
}

__isl_give isl_point *point::copy() const & {
  return isl_point_copy(ptr);
}

__isl_keep isl_point *point::get() const {
  return ptr;
}

__isl_give isl_point *point::release() {
  isl_point *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool point::is_null() const {
  return ptr == nullptr;
}
point::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const point& C) {
  os << C.to_str();
  return os;
}


std::string point::to_str() const {
  char *Tmp = isl_point_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx point::get_ctx() const {
  return isl::ctx(isl_point_get_ctx(ptr));
}

isl::point point::add_ui(enum isl::dim_type type, int pos, unsigned int val) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_point_add_ui(copy(), static_cast<enum isl_dim_type>(type), pos, val);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val point::get_coordinate_val(enum isl::dim_type type, int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_point_get_coordinate_val(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space point::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_point_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool point::is_void() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_point_is_void(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::point point::sub_ui(enum isl::dim_type type, int pos, unsigned int val) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_point_sub_ui(copy(), static_cast<enum isl_dim_type>(type), pos, val);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::pw_aff
isl::pw_aff manage(__isl_take isl_pw_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return pw_aff(ptr);
}
isl::pw_aff manage_copy(__isl_keep isl_pw_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_pw_aff_get_ctx(ptr);
  ptr = isl_pw_aff_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return pw_aff(ptr);
}

pw_aff::pw_aff()
    : ptr(nullptr) {}

pw_aff::pw_aff(const isl::pw_aff &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_pw_aff_get_ctx(obj.ptr));
}

pw_aff::pw_aff(__isl_take isl_pw_aff *ptr)
    : ptr(ptr) {}

pw_aff::pw_aff(isl::aff aff)
{
  if (aff.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = aff.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_from_aff(aff.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
pw_aff::pw_aff(isl::local_space ls)
{
  if (ls.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = ls.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_zero_on_domain(ls.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
pw_aff::pw_aff(isl::local_space ls, enum isl::dim_type type, unsigned int pos)
{
  if (ls.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = ls.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_var_on_domain(ls.release(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
pw_aff::pw_aff(isl::set domain, isl::val v)
{
  if (domain.is_null() || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_val_on_domain(domain.release(), v.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
pw_aff::pw_aff(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

pw_aff &pw_aff::operator=(isl::pw_aff obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

pw_aff::~pw_aff() {
  if (ptr)
    isl_pw_aff_free(ptr);
}

__isl_give isl_pw_aff *pw_aff::copy() const & {
  return isl_pw_aff_copy(ptr);
}

__isl_keep isl_pw_aff *pw_aff::get() const {
  return ptr;
}

__isl_give isl_pw_aff *pw_aff::release() {
  isl_pw_aff *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool pw_aff::is_null() const {
  return ptr == nullptr;
}
pw_aff::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const pw_aff& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const pw_aff& C1, const pw_aff& C2) {
  return C1.is_equal(C2);
}


std::string pw_aff::to_str() const {
  char *Tmp = isl_pw_aff_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx pw_aff::get_ctx() const {
  return isl::ctx(isl_pw_aff_get_ctx(ptr));
}

isl::pw_aff pw_aff::add(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_add(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::ceil() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_ceil(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::cond(isl::pw_aff pwaff_true, isl::pw_aff pwaff_false) const
{
  if (!ptr || pwaff_true.is_null() || pwaff_false.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_cond(copy(), pwaff_true.release(), pwaff_false.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int pw_aff::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::pw_aff pw_aff::div(isl::pw_aff pa2) const
{
  if (!ptr || pa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_div(copy(), pa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set pw_aff::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map pw_aff::eq_map(isl::pw_aff pa2) const
{
  if (!ptr || pa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_eq_map(copy(), pa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set pw_aff::eq_set(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_eq_set(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::floor() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_floor(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void pw_aff::foreach_piece(const std::function<void(isl::set, isl::aff)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::set, isl::aff)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_set *arg_0, isl_aff *arg_1, void *arg_2) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_2);
    try {
      (*data->func)(isl::manage(arg_0), isl::manage(arg_1));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_pw_aff_foreach_piece(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::set pw_aff::ge_set(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_ge_set(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id pw_aff::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space pw_aff::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id pw_aff::get_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_get_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map pw_aff::gt_map(isl::pw_aff pa2) const
{
  if (!ptr || pa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_gt_map(copy(), pa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set pw_aff::gt_set(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_gt_set(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool pw_aff::has_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_has_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool pw_aff::has_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_has_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::pw_aff pw_aff::intersect_params(isl::set set) const
{
  if (!ptr || set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_intersect_params(copy(), set.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool pw_aff::involves_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_involves_dims(get(), static_cast<enum isl_dim_type>(type), first, n);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool pw_aff::involves_nan() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_involves_nan(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool pw_aff::is_cst() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_is_cst(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool pw_aff::is_equal(const isl::pw_aff &pa2) const
{
  if (!ptr || pa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_is_equal(get(), pa2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::set pw_aff::le_set(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_le_set(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map pw_aff::lt_map(isl::pw_aff pa2) const
{
  if (!ptr || pa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_lt_map(copy(), pa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set pw_aff::lt_set(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_lt_set(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::max(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_max(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::min(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_min(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::mod(isl::val mod) const
{
  if (!ptr || mod.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_mod_val(copy(), mod.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::mul(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_mul(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int pw_aff::n_piece() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_n_piece(get());
  return res;
}

isl::set pw_aff::ne_set(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_ne_set(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::neg() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_neg(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set pw_aff::params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::project_domain_on_params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_project_domain_on_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::pullback(isl::multi_aff ma) const
{
  if (!ptr || ma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_pullback_multi_aff(copy(), ma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::pullback(isl::pw_multi_aff pma) const
{
  if (!ptr || pma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_pullback_pw_multi_aff(copy(), pma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::pullback(isl::multi_pw_aff mpa) const
{
  if (!ptr || mpa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_pullback_multi_pw_aff(copy(), mpa.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::reset_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_reset_tuple_id(copy(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::scale(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_scale_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::scale_down(isl::val f) const
{
  if (!ptr || f.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_scale_down_val(copy(), f.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_set_dim_id(copy(), static_cast<enum isl_dim_type>(type), pos, id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::set_tuple_id(enum isl::dim_type type, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_set_tuple_id(copy(), static_cast<enum isl_dim_type>(type), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::sub(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_sub(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::tdiv_q(isl::pw_aff pa2) const
{
  if (!ptr || pa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_tdiv_q(copy(), pa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::tdiv_r(isl::pw_aff pa2) const
{
  if (!ptr || pa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_tdiv_r(copy(), pa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_aff::union_add(isl::pw_aff pwaff2) const
{
  if (!ptr || pwaff2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_aff_union_add(copy(), pwaff2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::pw_multi_aff
isl::pw_multi_aff manage(__isl_take isl_pw_multi_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return pw_multi_aff(ptr);
}
isl::pw_multi_aff manage_copy(__isl_keep isl_pw_multi_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_pw_multi_aff_get_ctx(ptr);
  ptr = isl_pw_multi_aff_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return pw_multi_aff(ptr);
}

pw_multi_aff::pw_multi_aff()
    : ptr(nullptr) {}

pw_multi_aff::pw_multi_aff(const isl::pw_multi_aff &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_pw_multi_aff_get_ctx(obj.ptr));
}

pw_multi_aff::pw_multi_aff(__isl_take isl_pw_multi_aff *ptr)
    : ptr(ptr) {}

pw_multi_aff::pw_multi_aff(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_identity(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
pw_multi_aff::pw_multi_aff(isl::multi_aff ma)
{
  if (ma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = ma.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_from_multi_aff(ma.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
pw_multi_aff::pw_multi_aff(isl::pw_aff pa)
{
  if (pa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = pa.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_from_pw_aff(pa.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
pw_multi_aff::pw_multi_aff(isl::set domain, isl::multi_val mv)
{
  if (domain.is_null() || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_multi_val_on_domain(domain.release(), mv.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
pw_multi_aff::pw_multi_aff(isl::map map)
{
  if (map.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = map.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_from_map(map.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
pw_multi_aff::pw_multi_aff(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

pw_multi_aff &pw_multi_aff::operator=(isl::pw_multi_aff obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

pw_multi_aff::~pw_multi_aff() {
  if (ptr)
    isl_pw_multi_aff_free(ptr);
}

__isl_give isl_pw_multi_aff *pw_multi_aff::copy() const & {
  return isl_pw_multi_aff_copy(ptr);
}

__isl_keep isl_pw_multi_aff *pw_multi_aff::get() const {
  return ptr;
}

__isl_give isl_pw_multi_aff *pw_multi_aff::release() {
  isl_pw_multi_aff *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool pw_multi_aff::is_null() const {
  return ptr == nullptr;
}
pw_multi_aff::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const pw_multi_aff& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const pw_multi_aff& C1, const pw_multi_aff& C2) {
  return C1.is_equal(C2);
}


std::string pw_multi_aff::to_str() const {
  char *Tmp = isl_pw_multi_aff_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx pw_multi_aff::get_ctx() const {
  return isl::ctx(isl_pw_multi_aff_get_ctx(ptr));
}

isl::pw_multi_aff pw_multi_aff::add(isl::pw_multi_aff pma2) const
{
  if (!ptr || pma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_add(copy(), pma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int pw_multi_aff::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::set pw_multi_aff::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::flat_range_product(isl::pw_multi_aff pma2) const
{
  if (!ptr || pma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_flat_range_product(copy(), pma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void pw_multi_aff::foreach_piece(const std::function<void(isl::set, isl::multi_aff)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::set, isl::multi_aff)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_set *arg_0, isl_multi_aff *arg_1, void *arg_2) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_2);
    try {
      (*data->func)(isl::manage(arg_0), isl::manage(arg_1));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_pw_multi_aff_foreach_piece(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::pw_multi_aff pw_multi_aff::from(isl::multi_pw_aff mpa)
{
  if (mpa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = mpa.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_from_multi_pw_aff(mpa.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::id pw_multi_aff::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff pw_multi_aff::get_pw_aff(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_get_pw_aff(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space pw_multi_aff::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id pw_multi_aff::get_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_get_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool pw_multi_aff::has_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_has_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool pw_multi_aff::is_equal(const isl::pw_multi_aff &pma2) const
{
  if (!ptr || pma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_is_equal(get(), pma2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

int pw_multi_aff::n_piece() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_n_piece(get());
  return res;
}

isl::pw_multi_aff pw_multi_aff::product(isl::pw_multi_aff pma2) const
{
  if (!ptr || pma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_product(copy(), pma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::project_domain_on_params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_project_domain_on_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::project_out_map(isl::space space, enum isl::dim_type type, unsigned int first, unsigned int n)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_project_out_map(space.release(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::pullback(isl::multi_aff ma) const
{
  if (!ptr || ma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_pullback_multi_aff(copy(), ma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::pullback(isl::pw_multi_aff pma2) const
{
  if (!ptr || pma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_pullback_pw_multi_aff(copy(), pma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::range_product(isl::pw_multi_aff pma2) const
{
  if (!ptr || pma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_range_product(copy(), pma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::reset_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_reset_tuple_id(copy(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::scale_down_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_scale_down_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::scale_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_scale_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_set_dim_id(copy(), static_cast<enum isl_dim_type>(type), pos, id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::set_pw_aff(unsigned int pos, isl::pw_aff pa) const
{
  if (!ptr || pa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_set_pw_aff(copy(), pos, pa.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::set_tuple_id(enum isl::dim_type type, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_set_tuple_id(copy(), static_cast<enum isl_dim_type>(type), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff pw_multi_aff::union_add(isl::pw_multi_aff pma2) const
{
  if (!ptr || pma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_pw_multi_aff_union_add(copy(), pma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule
isl::schedule manage(__isl_take isl_schedule *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return schedule(ptr);
}
isl::schedule manage_copy(__isl_keep isl_schedule *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_schedule_get_ctx(ptr);
  ptr = isl_schedule_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return schedule(ptr);
}

schedule::schedule()
    : ptr(nullptr) {}

schedule::schedule(const isl::schedule &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_schedule_get_ctx(obj.ptr));
}

schedule::schedule(__isl_take isl_schedule *ptr)
    : ptr(ptr) {}

schedule::schedule(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

schedule &schedule::operator=(isl::schedule obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

schedule::~schedule() {
  if (ptr)
    isl_schedule_free(ptr);
}

__isl_give isl_schedule *schedule::copy() const & {
  return isl_schedule_copy(ptr);
}

__isl_keep isl_schedule *schedule::get() const {
  return ptr;
}

__isl_give isl_schedule *schedule::release() {
  isl_schedule *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool schedule::is_null() const {
  return ptr == nullptr;
}
schedule::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const schedule& C) {
  os << C.to_str();
  return os;
}


std::string schedule::to_str() const {
  char *Tmp = isl_schedule_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule::get_ctx() const {
  return isl::ctx(isl_schedule_get_ctx(ptr));
}

isl::schedule schedule::from_domain(isl::union_set domain)
{
  if (domain.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_from_domain(domain.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::union_set schedule::get_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_get_domain(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map schedule::get_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_get_map(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule::get_root() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_get_root(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule schedule::insert_partial_schedule(isl::multi_union_pw_aff partial) const
{
  if (!ptr || partial.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_insert_partial_schedule(copy(), partial.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool schedule::plain_is_equal(const isl::schedule &schedule2) const
{
  if (!ptr || schedule2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_plain_is_equal(get(), schedule2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::schedule schedule::pullback(isl::union_pw_multi_aff upma) const
{
  if (!ptr || upma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_pullback_union_pw_multi_aff(copy(), upma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule schedule::reset_user() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_reset_user(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule schedule::sequence(isl::schedule schedule2) const
{
  if (!ptr || schedule2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_sequence(copy(), schedule2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule schedule::set(isl::schedule schedule2) const
{
  if (!ptr || schedule2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_set(copy(), schedule2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule_constraints
isl::schedule_constraints manage(__isl_take isl_schedule_constraints *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return schedule_constraints(ptr);
}
isl::schedule_constraints manage_copy(__isl_keep isl_schedule_constraints *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_schedule_constraints_get_ctx(ptr);
  ptr = isl_schedule_constraints_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return schedule_constraints(ptr);
}

schedule_constraints::schedule_constraints()
    : ptr(nullptr) {}

schedule_constraints::schedule_constraints(const isl::schedule_constraints &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_schedule_constraints_get_ctx(obj.ptr));
}

schedule_constraints::schedule_constraints(__isl_take isl_schedule_constraints *ptr)
    : ptr(ptr) {}

schedule_constraints::schedule_constraints(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

schedule_constraints &schedule_constraints::operator=(isl::schedule_constraints obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

schedule_constraints::~schedule_constraints() {
  if (ptr)
    isl_schedule_constraints_free(ptr);
}

__isl_give isl_schedule_constraints *schedule_constraints::copy() const & {
  return isl_schedule_constraints_copy(ptr);
}

__isl_keep isl_schedule_constraints *schedule_constraints::get() const {
  return ptr;
}

__isl_give isl_schedule_constraints *schedule_constraints::release() {
  isl_schedule_constraints *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool schedule_constraints::is_null() const {
  return ptr == nullptr;
}
schedule_constraints::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const schedule_constraints& C) {
  os << C.to_str();
  return os;
}


std::string schedule_constraints::to_str() const {
  char *Tmp = isl_schedule_constraints_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_constraints::get_ctx() const {
  return isl::ctx(isl_schedule_constraints_get_ctx(ptr));
}

isl::schedule schedule_constraints::compute_schedule() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_compute_schedule(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map schedule_constraints::get_coincidence() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_get_coincidence(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map schedule_constraints::get_conditional_validity() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_get_conditional_validity(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map schedule_constraints::get_conditional_validity_condition() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_get_conditional_validity_condition(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set schedule_constraints::get_context() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_get_context(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set schedule_constraints::get_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_get_domain(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff schedule_constraints::get_prefix() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_get_prefix(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map schedule_constraints::get_proximity() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_get_proximity(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map schedule_constraints::get_validity() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_get_validity(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_constraints schedule_constraints::intersect_domain(isl::union_set domain) const
{
  if (!ptr || domain.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_intersect_domain(copy(), domain.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_constraints schedule_constraints::on_domain(isl::union_set domain)
{
  if (domain.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_on_domain(domain.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::schedule_constraints schedule_constraints::set_coincidence(isl::union_map coincidence) const
{
  if (!ptr || coincidence.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_set_coincidence(copy(), coincidence.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_constraints schedule_constraints::set_conditional_validity(isl::union_map condition, isl::union_map validity) const
{
  if (!ptr || condition.is_null() || validity.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_set_conditional_validity(copy(), condition.release(), validity.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_constraints schedule_constraints::set_context(isl::set context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_set_context(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_constraints schedule_constraints::set_prefix(isl::multi_union_pw_aff prefix) const
{
  if (!ptr || prefix.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_set_prefix(copy(), prefix.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_constraints schedule_constraints::set_proximity(isl::union_map proximity) const
{
  if (!ptr || proximity.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_set_proximity(copy(), proximity.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_constraints schedule_constraints::set_validity(isl::union_map validity) const
{
  if (!ptr || validity.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_constraints_set_validity(copy(), validity.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule_node
isl::schedule_node manage(__isl_take isl_schedule_node *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return schedule_node(ptr);
}
isl::schedule_node manage_copy(__isl_keep isl_schedule_node *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_schedule_node_get_ctx(ptr);
  ptr = isl_schedule_node_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return schedule_node(ptr);
}

schedule_node::schedule_node()
    : ptr(nullptr) {}

schedule_node::schedule_node(const isl::schedule_node &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_schedule_node_get_ctx(obj.ptr));
}

schedule_node::schedule_node(__isl_take isl_schedule_node *ptr)
    : ptr(ptr) {}


schedule_node &schedule_node::operator=(isl::schedule_node obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

schedule_node::~schedule_node() {
  if (ptr)
    isl_schedule_node_free(ptr);
}

__isl_give isl_schedule_node *schedule_node::copy() const & {
  return isl_schedule_node_copy(ptr);
}

__isl_keep isl_schedule_node *schedule_node::get() const {
  return ptr;
}

__isl_give isl_schedule_node *schedule_node::release() {
  isl_schedule_node *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool schedule_node::is_null() const {
  return ptr == nullptr;
}
schedule_node::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const schedule_node& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node& C1, const schedule_node& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


template <class T>
bool schedule_node::isa()
{
  if (is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return isl_schedule_node_get_type(get()) == T::type;
}
template <class T>
T schedule_node::as()
{
  return isa<T>() ? T(copy()) : T();
}

isl::ctx schedule_node::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}

isl::schedule_node schedule_node::ancestor(int generation) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_ancestor(copy(), generation);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::child(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_child(copy(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::cut() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_cut(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::del() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_delete(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool schedule_node::every_descendant(const std::function<bool(isl::schedule_node)> &test) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct test_data {
    const std::function<bool(isl::schedule_node)> *func;
    std::exception_ptr eptr;
  } test_data = { &test };
  auto test_lambda = [](isl_schedule_node *arg_0, void *arg_1) -> isl_bool {
    auto *data = static_cast<struct test_data *>(arg_1);
    try {
      auto ret = (*data->func)(isl::manage_copy(arg_0));
      return ret ? isl_bool_true : isl_bool_false;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_bool_error;
    }
  };
  auto res = isl_schedule_node_every_descendant(get(), test_lambda, &test_data);
  if (test_data.eptr)
    std::rethrow_exception(test_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return bool(res);
}

isl::schedule_node schedule_node::first_child() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_first_child(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void schedule_node::foreach_descendant_top_down(const std::function<bool(isl::schedule_node)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<bool(isl::schedule_node)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_schedule_node *arg_0, void *arg_1) -> isl_bool {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      auto ret = (*data->func)(isl::manage_copy(arg_0));
      return ret ? isl_bool_true : isl_bool_false;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_bool_error;
    }
  };
  auto res = isl_schedule_node_foreach_descendant_top_down(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::schedule_node schedule_node::from_domain(isl::union_set domain)
{
  if (domain.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_from_domain(domain.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::schedule_node schedule_node::from_extension(isl::union_map extension)
{
  if (extension.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = extension.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_from_extension(extension.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

int schedule_node::get_ancestor_child_position(const isl::schedule_node &ancestor) const
{
  if (!ptr || ancestor.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_ancestor_child_position(get(), ancestor.get());
  return res;
}

isl::schedule_node schedule_node::get_child(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_child(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int schedule_node::get_child_position() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_child_position(get());
  return res;
}

isl::union_set schedule_node::get_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_domain(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff schedule_node::get_prefix_schedule_multi_union_pw_aff() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_prefix_schedule_multi_union_pw_aff(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map schedule_node::get_prefix_schedule_relation() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_prefix_schedule_relation(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map schedule_node::get_prefix_schedule_union_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_prefix_schedule_union_map(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_multi_aff schedule_node::get_prefix_schedule_union_pw_multi_aff() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_prefix_schedule_union_pw_multi_aff(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule schedule_node::get_schedule() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_schedule(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int schedule_node::get_schedule_depth() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_schedule_depth(get());
  return res;
}

isl::schedule_node schedule_node::get_shared_ancestor(const isl::schedule_node &node2) const
{
  if (!ptr || node2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_shared_ancestor(get(), node2.get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int schedule_node::get_tree_depth() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_tree_depth(get());
  return res;
}

isl::union_set schedule_node::get_universe_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_get_universe_domain(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::graft_after(isl::schedule_node graft) const
{
  if (!ptr || graft.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_graft_after(copy(), graft.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::graft_before(isl::schedule_node graft) const
{
  if (!ptr || graft.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_graft_before(copy(), graft.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool schedule_node::has_children() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_has_children(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool schedule_node::has_next_sibling() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_has_next_sibling(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool schedule_node::has_parent() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_has_parent(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool schedule_node::has_previous_sibling() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_has_previous_sibling(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::schedule_node schedule_node::insert_context(isl::set context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_insert_context(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::insert_filter(isl::union_set filter) const
{
  if (!ptr || filter.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_insert_filter(copy(), filter.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::insert_guard(isl::set context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_insert_guard(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::insert_mark(isl::id mark) const
{
  if (!ptr || mark.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_insert_mark(copy(), mark.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::insert_partial_schedule(isl::multi_union_pw_aff schedule) const
{
  if (!ptr || schedule.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_insert_partial_schedule(copy(), schedule.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::insert_sequence(isl::union_set_list filters) const
{
  if (!ptr || filters.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_insert_sequence(copy(), filters.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::insert_set(isl::union_set_list filters) const
{
  if (!ptr || filters.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_insert_set(copy(), filters.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool schedule_node::is_equal(const isl::schedule_node &node2) const
{
  if (!ptr || node2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_is_equal(get(), node2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool schedule_node::is_subtree_anchored() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_is_subtree_anchored(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::schedule_node schedule_node::map_descendant_bottom_up(const std::function<isl::schedule_node(isl::schedule_node)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<isl::schedule_node(isl::schedule_node)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_schedule_node *arg_0, void *arg_1) -> isl_schedule_node * {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      auto ret = (*data->func)(isl::manage(arg_0));
      return ret.release();
    } catch (...) {
      data->eptr = std::current_exception();
      return NULL;
    }
  };
  auto res = isl_schedule_node_map_descendant_bottom_up(copy(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int schedule_node::n_children() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_n_children(get());
  return res;
}

isl::schedule_node schedule_node::next_sibling() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_next_sibling(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::order_after(isl::union_set filter) const
{
  if (!ptr || filter.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_order_after(copy(), filter.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::order_before(isl::union_set filter) const
{
  if (!ptr || filter.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_order_before(copy(), filter.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::parent() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_parent(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::previous_sibling() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_previous_sibling(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::schedule_node schedule_node::root() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_root(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule_node_band

schedule_node_band::schedule_node_band()
    : schedule_node() {}

schedule_node_band::schedule_node_band(const isl::schedule_node_band &obj)
    : schedule_node(obj)
{
}

schedule_node_band::schedule_node_band(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_band &schedule_node_band::operator=(isl::schedule_node_band obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_band& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_band& C1, const schedule_node_band& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_band::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_band::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}

isl::union_set schedule_node_band::get_ast_build_options() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_get_ast_build_options(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set schedule_node_band::get_ast_isolate_option() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_get_ast_isolate_option(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_union_pw_aff schedule_node_band::get_partial_schedule() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_get_partial_schedule(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map schedule_node_band::get_partial_schedule_union_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_get_partial_schedule_union_map(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool schedule_node_band::get_permutable() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_get_permutable(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::space schedule_node_band::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool schedule_node_band::member_get_coincident(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_member_get_coincident(get(), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::schedule_node_band schedule_node_band::member_set_ast_loop_type(int pos, enum isl::ast_loop_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_member_set_ast_loop_type(copy(), pos, static_cast<enum isl_ast_loop_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}

isl::schedule_node_band schedule_node_band::member_set_coincident(int pos, int coincident) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_member_set_coincident(copy(), pos, coincident);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}

isl::schedule_node_band schedule_node_band::member_set_isolate_ast_loop_type(int pos, enum isl::ast_loop_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_member_set_isolate_ast_loop_type(copy(), pos, static_cast<enum isl_ast_loop_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}

isl::schedule_node_band schedule_node_band::mod(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_mod(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}

unsigned int schedule_node_band::n_member() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_n_member(get());
  return res;
}

isl::schedule_node_band schedule_node_band::scale(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_scale(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}

isl::schedule_node_band schedule_node_band::scale_down(isl::multi_val mv) const
{
  if (!ptr || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_scale_down(copy(), mv.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}

isl::schedule_node_band schedule_node_band::set_ast_build_options(isl::union_set options) const
{
  if (!ptr || options.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_set_ast_build_options(copy(), options.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}

isl::schedule_node_band schedule_node_band::set_permutable(int permutable) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_set_permutable(copy(), permutable);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}

isl::schedule_node_band schedule_node_band::shift(isl::multi_union_pw_aff shift) const
{
  if (!ptr || shift.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_shift(copy(), shift.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}

isl::schedule_node_band schedule_node_band::split(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_split(copy(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}

isl::schedule_node_band schedule_node_band::tile(isl::multi_val sizes) const
{
  if (!ptr || sizes.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_band_tile(copy(), sizes.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res).as<isl::schedule_node_band>();
}


// implementations for isl::schedule_node_context

schedule_node_context::schedule_node_context()
    : schedule_node() {}

schedule_node_context::schedule_node_context(const isl::schedule_node_context &obj)
    : schedule_node(obj)
{
}

schedule_node_context::schedule_node_context(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_context &schedule_node_context::operator=(isl::schedule_node_context obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_context& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_context& C1, const schedule_node_context& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_context::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_context::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}

isl::set schedule_node_context::get_context() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_context_get_context(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule_node_domain

schedule_node_domain::schedule_node_domain()
    : schedule_node() {}

schedule_node_domain::schedule_node_domain(const isl::schedule_node_domain &obj)
    : schedule_node(obj)
{
}

schedule_node_domain::schedule_node_domain(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_domain &schedule_node_domain::operator=(isl::schedule_node_domain obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_domain& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_domain& C1, const schedule_node_domain& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_domain::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_domain::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}

isl::union_set schedule_node_domain::get_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_domain_get_domain(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule_node_expansion

schedule_node_expansion::schedule_node_expansion()
    : schedule_node() {}

schedule_node_expansion::schedule_node_expansion(const isl::schedule_node_expansion &obj)
    : schedule_node(obj)
{
}

schedule_node_expansion::schedule_node_expansion(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_expansion &schedule_node_expansion::operator=(isl::schedule_node_expansion obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_expansion& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_expansion& C1, const schedule_node_expansion& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_expansion::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_expansion::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}

isl::union_pw_multi_aff schedule_node_expansion::get_contraction() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_expansion_get_contraction(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map schedule_node_expansion::get_expansion() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_expansion_get_expansion(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule_node_extension

schedule_node_extension::schedule_node_extension()
    : schedule_node() {}

schedule_node_extension::schedule_node_extension(const isl::schedule_node_extension &obj)
    : schedule_node(obj)
{
}

schedule_node_extension::schedule_node_extension(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_extension &schedule_node_extension::operator=(isl::schedule_node_extension obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_extension& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_extension& C1, const schedule_node_extension& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_extension::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_extension::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}

isl::union_map schedule_node_extension::get_extension() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_extension_get_extension(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule_node_filter

schedule_node_filter::schedule_node_filter()
    : schedule_node() {}

schedule_node_filter::schedule_node_filter(const isl::schedule_node_filter &obj)
    : schedule_node(obj)
{
}

schedule_node_filter::schedule_node_filter(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_filter &schedule_node_filter::operator=(isl::schedule_node_filter obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_filter& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_filter& C1, const schedule_node_filter& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_filter::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_filter::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}

isl::union_set schedule_node_filter::get_filter() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_filter_get_filter(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule_node_guard

schedule_node_guard::schedule_node_guard()
    : schedule_node() {}

schedule_node_guard::schedule_node_guard(const isl::schedule_node_guard &obj)
    : schedule_node(obj)
{
}

schedule_node_guard::schedule_node_guard(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_guard &schedule_node_guard::operator=(isl::schedule_node_guard obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_guard& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_guard& C1, const schedule_node_guard& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_guard::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_guard::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}

isl::set schedule_node_guard::get_guard() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_guard_get_guard(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule_node_leaf

schedule_node_leaf::schedule_node_leaf()
    : schedule_node() {}

schedule_node_leaf::schedule_node_leaf(const isl::schedule_node_leaf &obj)
    : schedule_node(obj)
{
}

schedule_node_leaf::schedule_node_leaf(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_leaf &schedule_node_leaf::operator=(isl::schedule_node_leaf obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_leaf& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_leaf& C1, const schedule_node_leaf& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_leaf::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_leaf::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}



// implementations for isl::schedule_node_mark

schedule_node_mark::schedule_node_mark()
    : schedule_node() {}

schedule_node_mark::schedule_node_mark(const isl::schedule_node_mark &obj)
    : schedule_node(obj)
{
}

schedule_node_mark::schedule_node_mark(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_mark &schedule_node_mark::operator=(isl::schedule_node_mark obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_mark& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_mark& C1, const schedule_node_mark& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_mark::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_mark::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}

isl::id schedule_node_mark::get_id() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_schedule_node_mark_get_id(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::schedule_node_sequence

schedule_node_sequence::schedule_node_sequence()
    : schedule_node() {}

schedule_node_sequence::schedule_node_sequence(const isl::schedule_node_sequence &obj)
    : schedule_node(obj)
{
}

schedule_node_sequence::schedule_node_sequence(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_sequence &schedule_node_sequence::operator=(isl::schedule_node_sequence obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_sequence& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_sequence& C1, const schedule_node_sequence& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_sequence::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_sequence::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}



// implementations for isl::schedule_node_set

schedule_node_set::schedule_node_set()
    : schedule_node() {}

schedule_node_set::schedule_node_set(const isl::schedule_node_set &obj)
    : schedule_node(obj)
{
}

schedule_node_set::schedule_node_set(__isl_take isl_schedule_node *ptr)
    : schedule_node(ptr) {}


schedule_node_set &schedule_node_set::operator=(isl::schedule_node_set obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}



inline std::ostream& operator<<(std::ostream& os, const schedule_node_set& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const schedule_node_set& C1, const schedule_node_set& C2) {
  return C1.is_equal(C2);
}


std::string schedule_node_set::to_str() const {
  char *Tmp = isl_schedule_node_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx schedule_node_set::get_ctx() const {
  return isl::ctx(isl_schedule_node_get_ctx(ptr));
}



// implementations for isl::set
isl::set manage(__isl_take isl_set *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return set(ptr);
}
isl::set manage_copy(__isl_keep isl_set *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_set_get_ctx(ptr);
  ptr = isl_set_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return set(ptr);
}

set::set()
    : ptr(nullptr) {}

set::set(const isl::set &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_set_get_ctx(obj.ptr));
}

set::set(__isl_take isl_set *ptr)
    : ptr(ptr) {}

set::set(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
set::set(isl::basic_set bset)
{
  if (bset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = bset.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_from_basic_set(bset.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
set::set(isl::point pnt)
{
  if (pnt.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = pnt.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_from_point(pnt.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

set &set::operator=(isl::set obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

set::~set() {
  if (ptr)
    isl_set_free(ptr);
}

__isl_give isl_set *set::copy() const & {
  return isl_set_copy(ptr);
}

__isl_keep isl_set *set::get() const {
  return ptr;
}

__isl_give isl_set *set::release() {
  isl_set *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool set::is_null() const {
  return ptr == nullptr;
}
set::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const set& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const set& C1, const set& C2) {
  return C1.is_equal(C2);
}


std::string set::to_str() const {
  char *Tmp = isl_set_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx set::get_ctx() const {
  return isl::ctx(isl_set_get_ctx(ptr));
}

isl::set set::add_constraint(isl::constraint constraint) const
{
  if (!ptr || constraint.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_add_constraint(copy(), constraint.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::add_dims(enum isl::dim_type type, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_add_dims(copy(), static_cast<enum isl_dim_type>(type), n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set set::affine_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_affine_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::align_params(isl::space model) const
{
  if (!ptr || model.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_align_params(copy(), model.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::apply(isl::map map) const
{
  if (!ptr || map.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_apply(copy(), map.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::coalesce() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_coalesce(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::complement() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_complement(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::compute_divs() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_compute_divs(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::detect_equalities() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_detect_equalities(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int set::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

bool set::dim_has_upper_bound(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_dim_has_upper_bound(get(), static_cast<enum isl_dim_type>(type), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::pw_aff set::dim_max(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_dim_max(copy(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_aff set::dim_min(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_dim_min(copy(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::empty(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_empty(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

int set::find_dim_by_id(enum isl::dim_type type, const isl::id &id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_find_dim_by_id(get(), static_cast<enum isl_dim_type>(type), id.get());
  return res;
}

int set::find_dim_by_name(enum isl::dim_type type, const std::string &name) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_find_dim_by_name(get(), static_cast<enum isl_dim_type>(type), name.c_str());
  return res;
}

isl::set set::flatten() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_flatten(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map set::flatten_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_flatten_map(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void set::foreach_basic_set(const std::function<void(isl::basic_set)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::basic_set)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_basic_set *arg_0, void *arg_1) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      (*data->func)(isl::manage(arg_0));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_set_foreach_basic_set(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::set set::from_params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_from_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::from_union_set(isl::union_set uset)
{
  if (uset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = uset.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_from_union_set(uset.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::list<isl::basic_set> set::get_basic_set_list() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_get_basic_set_list(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id set::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space set::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val set::get_stride(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_get_stride(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id set::get_tuple_id() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_get_tuple_id(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string set::get_tuple_name() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_get_tuple_name(get());
  std::string tmp(res);
  return tmp;
}

isl::set set::gist(isl::set context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_gist(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool set::has_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_has_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool set::has_tuple_id() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_has_tuple_id(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool set::has_tuple_name() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_has_tuple_name(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::map set::identity() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_identity(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::insert_dims(enum isl::dim_type type, unsigned int pos, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_insert_dims(copy(), static_cast<enum isl_dim_type>(type), pos, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::intersect(isl::set set2) const
{
  if (!ptr || set2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_intersect(copy(), set2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::intersect_params(isl::set params) const
{
  if (!ptr || params.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_intersect_params(copy(), params.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool set::involves_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_involves_dims(get(), static_cast<enum isl_dim_type>(type), first, n);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool set::is_disjoint(const isl::set &set2) const
{
  if (!ptr || set2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_is_disjoint(get(), set2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool set::is_empty() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_is_empty(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool set::is_equal(const isl::set &set2) const
{
  if (!ptr || set2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_is_equal(get(), set2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool set::is_singleton() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_is_singleton(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool set::is_strict_subset(const isl::set &set2) const
{
  if (!ptr || set2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_is_strict_subset(get(), set2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool set::is_subset(const isl::set &set2) const
{
  if (!ptr || set2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_is_subset(get(), set2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool set::is_wrapping() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_is_wrapping(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::set set::lexmax() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_lexmax(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::lexmin() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_lexmin(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::lower_bound_si(enum isl::dim_type type, unsigned int pos, int value) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_lower_bound_si(copy(), static_cast<enum isl_dim_type>(type), pos, value);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::lower_bound_val(enum isl::dim_type type, unsigned int pos, isl::val value) const
{
  if (!ptr || value.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_lower_bound_val(copy(), static_cast<enum isl_dim_type>(type), pos, value.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val set::max_val(const isl::aff &obj) const
{
  if (!ptr || obj.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_max_val(get(), obj.get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val set::min_val(const isl::aff &obj) const
{
  if (!ptr || obj.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_min_val(get(), obj.get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int set::n_basic_set() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_n_basic_set(get());
  return res;
}

unsigned int set::n_dim() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_n_dim(get());
  return res;
}

unsigned int set::n_param() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_n_param(get());
  return res;
}

isl::set set::nat_universe(isl::space dim)
{
  if (dim.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = dim.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_nat_universe(dim.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::set set::params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val set::plain_get_val_if_fixed(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_plain_get_val_if_fixed(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool set::plain_is_universe() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_plain_is_universe(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::basic_set set::polyhedral_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_polyhedral_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::preimage_multi_aff(isl::multi_aff ma) const
{
  if (!ptr || ma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_preimage_multi_aff(copy(), ma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::product(isl::set set2) const
{
  if (!ptr || set2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_product(copy(), set2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_project_out(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::remove_dims(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_remove_dims(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::reset_tuple_id() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_reset_tuple_id(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set set::sample() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_sample(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::point set::sample_point() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_sample_point(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_set_dim_id(copy(), static_cast<enum isl_dim_type>(type), pos, id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_set_dim_name(copy(), static_cast<enum isl_dim_type>(type), pos, s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::set_tuple_id(isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_set_tuple_id(copy(), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::set_tuple_name(const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_set_tuple_name(copy(), s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::basic_set set::simple_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_simple_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::subtract(isl::set set2) const
{
  if (!ptr || set2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_subtract(copy(), set2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::unite(isl::set set2) const
{
  if (!ptr || set2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_union(copy(), set2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::universe(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_universe(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::basic_set set::unshifted_simple_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_unshifted_simple_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map set::unwrap() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_unwrap(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::upper_bound_si(enum isl::dim_type type, unsigned int pos, int value) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_upper_bound_si(copy(), static_cast<enum isl_dim_type>(type), pos, value);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::set set::upper_bound_val(enum isl::dim_type type, unsigned int pos, isl::val value) const
{
  if (!ptr || value.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_upper_bound_val(copy(), static_cast<enum isl_dim_type>(type), pos, value.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map set::wrapped_domain_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_set_wrapped_domain_map(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::list<set>
isl::list<set> manage(__isl_take isl_set_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return list<set>(ptr);
}
isl::list<set> manage_copy(__isl_keep isl_set_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_set_list_get_ctx(ptr);
  ptr = isl_set_list_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return list<set>(ptr);
}

list<set>::list()
    : ptr(nullptr) {}

list<set>::list(const isl::list<set> &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_set_list_get_ctx(obj.ptr));
}

list<set>::list(__isl_take isl_set_list *ptr)
    : ptr(ptr) {}


list<set> &list<set>::operator=(isl::list<set> obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

list<set>::~list() {
  if (ptr)
    isl_set_list_free(ptr);
}

__isl_give isl_set_list *list<set>::copy() const & {
  return isl_set_list_copy(ptr);
}

__isl_keep isl_set_list *list<set>::get() const {
  return ptr;
}

__isl_give isl_set_list *list<set>::release() {
  isl_set_list *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool list<set>::is_null() const {
  return ptr == nullptr;
}
list<set>::operator bool() const
{
  return !is_null();
}



isl::ctx list<set>::get_ctx() const {
  return isl::ctx(isl_set_list_get_ctx(ptr));
}


template <typename InputIt1, typename InputIt2>
list<set>::list(isl::ctx ctx, InputIt1 from, InputIt2 to) {
  ptr = isl_set_list_alloc(ctx.get(), std::distance(from, to));
  for ( ; from != to; ++from) {
    ptr = isl_set_list_add(ptr, from->copy());
  }
}

int list<set>::size() const {
  return isl_set_list_n_set(ptr);
}

isl::set list<set>::at(int pos) const {
  return manage(isl_set_list_get_set(ptr, pos));
}

isl::set list<set>::operator[](int pos) const {
  return manage(isl_set_list_get_set(ptr, pos));
}

typename isl::list<set>::iterator
list<set>::begin() const {
  return list_iterator<set>(this, size() == 0 ? -1 : 0);
}

typename isl::list<set>::iterator
list<set>::end() const {
  return list_iterator<set>(this, -1);
}


// implementations for isl::space
isl::space manage(__isl_take isl_space *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return space(ptr);
}
isl::space manage_copy(__isl_keep isl_space *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_space_get_ctx(ptr);
  ptr = isl_space_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return space(ptr);
}

space::space()
    : ptr(nullptr) {}

space::space(const isl::space &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_space_get_ctx(obj.ptr));
}

space::space(__isl_take isl_space *ptr)
    : ptr(ptr) {}

space::space(isl::ctx ctx, unsigned int nparam, unsigned int n_in, unsigned int n_out)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_alloc(ctx.release(), nparam, n_in, n_out);
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
space::space(isl::ctx ctx, unsigned int nparam, unsigned int dim)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_set_alloc(ctx.release(), nparam, dim);
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
space::space(isl::ctx ctx, unsigned int nparam)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_params_alloc(ctx.release(), nparam);
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

space &space::operator=(isl::space obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

space::~space() {
  if (ptr)
    isl_space_free(ptr);
}

__isl_give isl_space *space::copy() const & {
  return isl_space_copy(ptr);
}

__isl_keep isl_space *space::get() const {
  return ptr;
}

__isl_give isl_space *space::release() {
  isl_space *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool space::is_null() const {
  return ptr == nullptr;
}
space::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const space& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const space& C1, const space& C2) {
  return C1.is_equal(C2);
}


std::string space::to_str() const {
  char *Tmp = isl_space_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx space::get_ctx() const {
  return isl::ctx(isl_space_get_ctx(ptr));
}

isl::space space::add_dims(enum isl::dim_type type, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_add_dims(copy(), static_cast<enum isl_dim_type>(type), n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::add_param(isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_add_param_id(copy(), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::align_params(isl::space dim2) const
{
  if (!ptr || dim2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_align_params(copy(), dim2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool space::can_curry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_can_curry(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool space::can_uncurry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_can_uncurry(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::space space::curry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_curry(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int space::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::space space::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::domain_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_domain_map(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::domain_product(isl::space right) const
{
  if (!ptr || right.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_domain_product(copy(), right.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::drop_dims(enum isl::dim_type type, unsigned int first, unsigned int num) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_drop_dims(copy(), static_cast<enum isl_dim_type>(type), first, num);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int space::find_dim_by_id(enum isl::dim_type type, const isl::id &id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_find_dim_by_id(get(), static_cast<enum isl_dim_type>(type), id.get());
  return res;
}

int space::find_dim_by_name(enum isl::dim_type type, const std::string &name) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_find_dim_by_name(get(), static_cast<enum isl_dim_type>(type), name.c_str());
  return res;
}

isl::space space::from_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_from_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::from_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_from_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::id space::get_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_get_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string space::get_dim_name(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_get_dim_name(get(), static_cast<enum isl_dim_type>(type), pos);
  std::string tmp(res);
  return tmp;
}

isl::id space::get_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_get_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

std::string space::get_tuple_name(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_get_tuple_name(get(), static_cast<enum isl_dim_type>(type));
  std::string tmp(res);
  return tmp;
}

bool space::has_dim_id(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_has_dim_id(get(), static_cast<enum isl_dim_type>(type), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool space::has_dim_name(enum isl::dim_type type, unsigned int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_has_dim_name(get(), static_cast<enum isl_dim_type>(type), pos);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool space::has_equal_params(const isl::space &space2) const
{
  if (!ptr || space2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_has_equal_params(get(), space2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool space::has_equal_tuples(const isl::space &space2) const
{
  if (!ptr || space2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_has_equal_tuples(get(), space2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool space::has_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_has_tuple_id(get(), static_cast<enum isl_dim_type>(type));
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool space::has_tuple_name(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_has_tuple_name(get(), static_cast<enum isl_dim_type>(type));
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool space::is_equal(const isl::space &space2) const
{
  if (!ptr || space2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_is_equal(get(), space2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool space::is_params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_is_params(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool space::is_set() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_is_set(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::space space::map_from_domain_and_range(isl::space range) const
{
  if (!ptr || range.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_map_from_domain_and_range(copy(), range.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::map_from_set() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_map_from_set(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::product(isl::space right) const
{
  if (!ptr || right.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_product(copy(), right.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::range_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_range_map(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::range_product(isl::space right) const
{
  if (!ptr || right.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_range_product(copy(), right.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::reset_tuple_id(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_reset_tuple_id(copy(), static_cast<enum isl_dim_type>(type));
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::set_dim_id(enum isl::dim_type type, unsigned int pos, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_set_dim_id(copy(), static_cast<enum isl_dim_type>(type), pos, id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::set_dim_name(enum isl::dim_type type, unsigned int pos, const std::string &name) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_set_dim_name(copy(), static_cast<enum isl_dim_type>(type), pos, name.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::set_from_params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_set_from_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::set_tuple_id(enum isl::dim_type type, isl::id id) const
{
  if (!ptr || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_set_tuple_id(copy(), static_cast<enum isl_dim_type>(type), id.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::set_tuple_name(enum isl::dim_type type, const std::string &s) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_set_tuple_name(copy(), static_cast<enum isl_dim_type>(type), s.c_str());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::uncurry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_uncurry(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::unwrap() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_unwrap(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::space space::wrap() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_space_wrap(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::union_access_info
isl::union_access_info manage(__isl_take isl_union_access_info *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return union_access_info(ptr);
}
isl::union_access_info manage_copy(__isl_keep isl_union_access_info *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_union_access_info_get_ctx(ptr);
  ptr = isl_union_access_info_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return union_access_info(ptr);
}

union_access_info::union_access_info()
    : ptr(nullptr) {}

union_access_info::union_access_info(const isl::union_access_info &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_union_access_info_get_ctx(obj.ptr));
}

union_access_info::union_access_info(__isl_take isl_union_access_info *ptr)
    : ptr(ptr) {}

union_access_info::union_access_info(isl::union_map sink)
{
  if (sink.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = sink.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_access_info_from_sink(sink.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

union_access_info &union_access_info::operator=(isl::union_access_info obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

union_access_info::~union_access_info() {
  if (ptr)
    isl_union_access_info_free(ptr);
}

__isl_give isl_union_access_info *union_access_info::copy() const & {
  return isl_union_access_info_copy(ptr);
}

__isl_keep isl_union_access_info *union_access_info::get() const {
  return ptr;
}

__isl_give isl_union_access_info *union_access_info::release() {
  isl_union_access_info *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool union_access_info::is_null() const {
  return ptr == nullptr;
}
union_access_info::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const union_access_info& C) {
  os << C.to_str();
  return os;
}


std::string union_access_info::to_str() const {
  char *Tmp = isl_union_access_info_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx union_access_info::get_ctx() const {
  return isl::ctx(isl_union_access_info_get_ctx(ptr));
}

isl::union_flow union_access_info::compute_flow() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_access_info_compute_flow(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_access_info union_access_info::set_kill(isl::union_map kill) const
{
  if (!ptr || kill.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_access_info_set_kill(copy(), kill.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_access_info union_access_info::set_may_source(isl::union_map may_source) const
{
  if (!ptr || may_source.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_access_info_set_may_source(copy(), may_source.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_access_info union_access_info::set_must_source(isl::union_map must_source) const
{
  if (!ptr || must_source.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_access_info_set_must_source(copy(), must_source.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_access_info union_access_info::set_schedule(isl::schedule schedule) const
{
  if (!ptr || schedule.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_access_info_set_schedule(copy(), schedule.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_access_info union_access_info::set_schedule_map(isl::union_map schedule_map) const
{
  if (!ptr || schedule_map.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_access_info_set_schedule_map(copy(), schedule_map.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::union_flow
isl::union_flow manage(__isl_take isl_union_flow *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return union_flow(ptr);
}
isl::union_flow manage_copy(__isl_keep isl_union_flow *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_union_flow_get_ctx(ptr);
  ptr = isl_union_flow_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return union_flow(ptr);
}

union_flow::union_flow()
    : ptr(nullptr) {}

union_flow::union_flow(const isl::union_flow &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_union_flow_get_ctx(obj.ptr));
}

union_flow::union_flow(__isl_take isl_union_flow *ptr)
    : ptr(ptr) {}


union_flow &union_flow::operator=(isl::union_flow obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

union_flow::~union_flow() {
  if (ptr)
    isl_union_flow_free(ptr);
}

__isl_give isl_union_flow *union_flow::copy() const & {
  return isl_union_flow_copy(ptr);
}

__isl_keep isl_union_flow *union_flow::get() const {
  return ptr;
}

__isl_give isl_union_flow *union_flow::release() {
  isl_union_flow *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool union_flow::is_null() const {
  return ptr == nullptr;
}
union_flow::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const union_flow& C) {
  os << C.to_str();
  return os;
}


std::string union_flow::to_str() const {
  char *Tmp = isl_union_flow_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx union_flow::get_ctx() const {
  return isl::ctx(isl_union_flow_get_ctx(ptr));
}

isl::union_map union_flow::get_full_may_dependence() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_flow_get_full_may_dependence(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_flow::get_full_must_dependence() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_flow_get_full_must_dependence(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_flow::get_may_dependence() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_flow_get_may_dependence(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_flow::get_may_no_source() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_flow_get_may_no_source(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_flow::get_must_dependence() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_flow_get_must_dependence(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_flow::get_must_no_source() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_flow_get_must_no_source(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::union_map
isl::union_map manage(__isl_take isl_union_map *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return union_map(ptr);
}
isl::union_map manage_copy(__isl_keep isl_union_map *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_union_map_get_ctx(ptr);
  ptr = isl_union_map_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return union_map(ptr);
}

union_map::union_map()
    : ptr(nullptr) {}

union_map::union_map(const isl::union_map &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_union_map_get_ctx(obj.ptr));
}

union_map::union_map(__isl_take isl_union_map *ptr)
    : ptr(ptr) {}

union_map::union_map(isl::basic_map bmap)
{
  if (bmap.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = bmap.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_from_basic_map(bmap.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_map::union_map(isl::map map)
{
  if (map.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = map.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_from_map(map.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_map::union_map(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

union_map &union_map::operator=(isl::union_map obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

union_map::~union_map() {
  if (ptr)
    isl_union_map_free(ptr);
}

__isl_give isl_union_map *union_map::copy() const & {
  return isl_union_map_copy(ptr);
}

__isl_keep isl_union_map *union_map::get() const {
  return ptr;
}

__isl_give isl_union_map *union_map::release() {
  isl_union_map *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool union_map::is_null() const {
  return ptr == nullptr;
}
union_map::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const union_map& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const union_map& C1, const union_map& C2) {
  return C1.is_equal(C2);
}


std::string union_map::to_str() const {
  char *Tmp = isl_union_map_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx union_map::get_ctx() const {
  return isl::ctx(isl_union_map_get_ctx(ptr));
}

isl::union_map union_map::add_map(isl::map map) const
{
  if (!ptr || map.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_add_map(copy(), map.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::affine_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_affine_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::apply_domain(isl::union_map umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_apply_domain(copy(), umap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::apply_range(isl::union_map umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_apply_range(copy(), umap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::coalesce() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_coalesce(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::compute_divs() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_compute_divs(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::curry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_curry(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_map::deltas() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_deltas(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::detect_equalities() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_detect_equalities(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int union_map::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::union_set union_map::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::domain_factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_domain_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::domain_factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_domain_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::domain_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_domain_map(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_multi_aff union_map::domain_map_union_pw_multi_aff() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_domain_map_union_pw_multi_aff(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::domain_product(isl::union_map umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_domain_product(copy(), umap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::empty(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_empty(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::union_map union_map::eq_at(isl::multi_union_pw_aff mupa) const
{
  if (!ptr || mupa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_eq_at_multi_union_pw_aff(copy(), mupa.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::map union_map::extract_map(isl::space dim) const
{
  if (!ptr || dim.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_extract_map(get(), dim.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::fixed_power(isl::val exp) const
{
  if (!ptr || exp.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_fixed_power_val(copy(), exp.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::flat_range_product(isl::union_map umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_flat_range_product(copy(), umap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void union_map::foreach_map(const std::function<void(isl::map)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::map)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_map *arg_0, void *arg_1) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      (*data->func)(isl::manage(arg_0));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_union_map_foreach_map(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::union_map union_map::from(isl::union_pw_multi_aff upma)
{
  if (upma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = upma.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_from_union_pw_multi_aff(upma.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::union_map union_map::from(isl::multi_union_pw_aff mupa)
{
  if (mupa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = mupa.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_from_multi_union_pw_aff(mupa.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::union_map union_map::from_domain(isl::union_set uset)
{
  if (uset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = uset.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_from_domain(uset.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::union_map union_map::from_domain_and_range(isl::union_set domain, isl::union_set range)
{
  if (domain.is_null() || range.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_from_domain_and_range(domain.release(), range.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::union_map union_map::from_range(isl::union_set uset)
{
  if (uset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = uset.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_from_range(uset.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::space union_map::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::gist(isl::union_map context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_gist(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::gist_domain(isl::union_set uset) const
{
  if (!ptr || uset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_gist_domain(copy(), uset.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::gist_params(isl::set set) const
{
  if (!ptr || set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_gist_params(copy(), set.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::gist_range(isl::union_set uset) const
{
  if (!ptr || uset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_gist_range(copy(), uset.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::intersect(isl::union_map umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_intersect(copy(), umap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::intersect_domain(isl::union_set uset) const
{
  if (!ptr || uset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_intersect_domain(copy(), uset.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::intersect_params(isl::set set) const
{
  if (!ptr || set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_intersect_params(copy(), set.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::intersect_range(isl::union_set uset) const
{
  if (!ptr || uset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_intersect_range(copy(), uset.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool union_map::is_bijective() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_is_bijective(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_map::is_empty() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_is_empty(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_map::is_equal(const isl::union_map &umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_is_equal(get(), umap2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_map::is_injective() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_is_injective(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_map::is_single_valued() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_is_single_valued(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_map::is_strict_subset(const isl::union_map &umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_is_strict_subset(get(), umap2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_map::is_subset(const isl::union_map &umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_is_subset(get(), umap2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::union_map union_map::lexmax() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_lexmax(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::lexmin() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_lexmin(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int union_map::n_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_n_map(get());
  return res;
}

isl::union_map union_map::polyhedral_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_polyhedral_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::preimage_range_multi_aff(isl::multi_aff ma) const
{
  if (!ptr || ma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_preimage_range_multi_aff(copy(), ma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::product(isl::union_map umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_product(copy(), umap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_project_out(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::project_out_all_params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_project_out_all_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_map::range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::range_factor_domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_range_factor_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::range_factor_range() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_range_factor_range(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::range_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_range_map(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::range_product(isl::union_map umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_range_product(copy(), umap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::reverse() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_reverse(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::subtract(isl::union_map umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_subtract(copy(), umap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::subtract_domain(isl::union_set dom) const
{
  if (!ptr || dom.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_subtract_domain(copy(), dom.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::subtract_range(isl::union_set dom) const
{
  if (!ptr || dom.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_subtract_range(copy(), dom.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::uncurry() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_uncurry(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::unite(isl::union_map umap2) const
{
  if (!ptr || umap2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_union(copy(), umap2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::universe() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_universe(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_map::wrap() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_wrap(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_map::zip() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_map_zip(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::union_pw_aff
isl::union_pw_aff manage(__isl_take isl_union_pw_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return union_pw_aff(ptr);
}
isl::union_pw_aff manage_copy(__isl_keep isl_union_pw_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_union_pw_aff_get_ctx(ptr);
  ptr = isl_union_pw_aff_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return union_pw_aff(ptr);
}

union_pw_aff::union_pw_aff()
    : ptr(nullptr) {}

union_pw_aff::union_pw_aff(const isl::union_pw_aff &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_union_pw_aff_get_ctx(obj.ptr));
}

union_pw_aff::union_pw_aff(__isl_take isl_union_pw_aff *ptr)
    : ptr(ptr) {}

union_pw_aff::union_pw_aff(isl::pw_aff pa)
{
  if (pa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = pa.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_from_pw_aff(pa.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_pw_aff::union_pw_aff(isl::union_set domain, isl::val v)
{
  if (domain.is_null() || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_val_on_domain(domain.release(), v.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_pw_aff::union_pw_aff(isl::union_set domain, isl::aff aff)
{
  if (domain.is_null() || aff.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_aff_on_domain(domain.release(), aff.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_pw_aff::union_pw_aff(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

union_pw_aff &union_pw_aff::operator=(isl::union_pw_aff obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

union_pw_aff::~union_pw_aff() {
  if (ptr)
    isl_union_pw_aff_free(ptr);
}

__isl_give isl_union_pw_aff *union_pw_aff::copy() const & {
  return isl_union_pw_aff_copy(ptr);
}

__isl_keep isl_union_pw_aff *union_pw_aff::get() const {
  return ptr;
}

__isl_give isl_union_pw_aff *union_pw_aff::release() {
  isl_union_pw_aff *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool union_pw_aff::is_null() const {
  return ptr == nullptr;
}
union_pw_aff::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const union_pw_aff& C) {
  os << C.to_str();
  return os;
}


std::string union_pw_aff::to_str() const {
  char *Tmp = isl_union_pw_aff_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx union_pw_aff::get_ctx() const {
  return isl::ctx(isl_union_pw_aff_get_ctx(ptr));
}

isl::union_pw_aff union_pw_aff::add(isl::union_pw_aff upa2) const
{
  if (!ptr || upa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_add(copy(), upa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int union_pw_aff::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::union_set union_pw_aff::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_aff union_pw_aff::empty(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_empty(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::pw_aff union_pw_aff::extract_pw_aff(isl::space space) const
{
  if (!ptr || space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_extract_pw_aff(get(), space.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_aff union_pw_aff::floor() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_floor(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void union_pw_aff::foreach_pw_aff(const std::function<void(isl::pw_aff)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::pw_aff)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_pw_aff *arg_0, void *arg_1) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      (*data->func)(isl::manage(arg_0));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_union_pw_aff_foreach_pw_aff(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::space union_pw_aff::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_aff union_pw_aff::mod_val(isl::val f) const
{
  if (!ptr || f.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_mod_val(copy(), f.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int union_pw_aff::n_pw_aff() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_n_pw_aff(get());
  return res;
}

isl::union_pw_aff union_pw_aff::param_on_domain(isl::union_set domain, isl::id id)
{
  if (domain.is_null() || id.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_param_on_domain_id(domain.release(), id.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

bool union_pw_aff::plain_is_equal(const isl::union_pw_aff &upa2) const
{
  if (!ptr || upa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_plain_is_equal(get(), upa2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::union_pw_aff union_pw_aff::pullback(isl::union_pw_multi_aff upma) const
{
  if (!ptr || upma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_pullback_union_pw_multi_aff(copy(), upma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_aff union_pw_aff::scale_down(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_scale_down_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_aff union_pw_aff::scale_val(isl::val v) const
{
  if (!ptr || v.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_scale_val(copy(), v.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_aff union_pw_aff::sub(isl::union_pw_aff upa2) const
{
  if (!ptr || upa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_sub(copy(), upa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_aff union_pw_aff::union_add(isl::union_pw_aff upa2) const
{
  if (!ptr || upa2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_union_add(copy(), upa2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_pw_aff::zero_union_set() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_aff_zero_union_set(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::union_pw_multi_aff
isl::union_pw_multi_aff manage(__isl_take isl_union_pw_multi_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return union_pw_multi_aff(ptr);
}
isl::union_pw_multi_aff manage_copy(__isl_keep isl_union_pw_multi_aff *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_union_pw_multi_aff_get_ctx(ptr);
  ptr = isl_union_pw_multi_aff_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return union_pw_multi_aff(ptr);
}

union_pw_multi_aff::union_pw_multi_aff()
    : ptr(nullptr) {}

union_pw_multi_aff::union_pw_multi_aff(const isl::union_pw_multi_aff &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_union_pw_multi_aff_get_ctx(obj.ptr));
}

union_pw_multi_aff::union_pw_multi_aff(__isl_take isl_union_pw_multi_aff *ptr)
    : ptr(ptr) {}

union_pw_multi_aff::union_pw_multi_aff(isl::pw_multi_aff pma)
{
  if (pma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = pma.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_from_pw_multi_aff(pma.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_pw_multi_aff::union_pw_multi_aff(isl::union_set domain, isl::multi_val mv)
{
  if (domain.is_null() || mv.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = domain.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_multi_val_on_domain(domain.release(), mv.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_pw_multi_aff::union_pw_multi_aff(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_pw_multi_aff::union_pw_multi_aff(isl::union_pw_aff upa)
{
  if (upa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = upa.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_from_union_pw_aff(upa.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

union_pw_multi_aff &union_pw_multi_aff::operator=(isl::union_pw_multi_aff obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

union_pw_multi_aff::~union_pw_multi_aff() {
  if (ptr)
    isl_union_pw_multi_aff_free(ptr);
}

__isl_give isl_union_pw_multi_aff *union_pw_multi_aff::copy() const & {
  return isl_union_pw_multi_aff_copy(ptr);
}

__isl_keep isl_union_pw_multi_aff *union_pw_multi_aff::get() const {
  return ptr;
}

__isl_give isl_union_pw_multi_aff *union_pw_multi_aff::release() {
  isl_union_pw_multi_aff *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool union_pw_multi_aff::is_null() const {
  return ptr == nullptr;
}
union_pw_multi_aff::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const union_pw_multi_aff& C) {
  os << C.to_str();
  return os;
}


std::string union_pw_multi_aff::to_str() const {
  char *Tmp = isl_union_pw_multi_aff_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx union_pw_multi_aff::get_ctx() const {
  return isl::ctx(isl_union_pw_multi_aff_get_ctx(ptr));
}

isl::union_pw_multi_aff union_pw_multi_aff::add(isl::union_pw_multi_aff upma2) const
{
  if (!ptr || upma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_add(copy(), upma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int union_pw_multi_aff::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::union_set union_pw_multi_aff::domain() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_domain(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::pw_multi_aff union_pw_multi_aff::extract_pw_multi_aff(isl::space space) const
{
  if (!ptr || space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_extract_pw_multi_aff(get(), space.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_multi_aff union_pw_multi_aff::flat_range_product(isl::union_pw_multi_aff upma2) const
{
  if (!ptr || upma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_flat_range_product(copy(), upma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void union_pw_multi_aff::foreach_pw_multi_aff(const std::function<void(isl::pw_multi_aff)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::pw_multi_aff)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_pw_multi_aff *arg_0, void *arg_1) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      (*data->func)(isl::manage(arg_0));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_union_pw_multi_aff_foreach_pw_multi_aff(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::union_pw_multi_aff union_pw_multi_aff::from(isl::union_map umap)
{
  if (umap.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = umap.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_from_union_map(umap.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::union_pw_multi_aff union_pw_multi_aff::from_multi_union_pw_aff(isl::multi_union_pw_aff mupa)
{
  if (mupa.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = mupa.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_from_multi_union_pw_aff(mupa.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::space union_pw_multi_aff::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_aff union_pw_multi_aff::get_union_pw_aff(int pos) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_get_union_pw_aff(get(), pos);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int union_pw_multi_aff::n_pw_multi_aff() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_n_pw_multi_aff(get());
  return res;
}

isl::union_pw_multi_aff union_pw_multi_aff::pullback(isl::union_pw_multi_aff upma2) const
{
  if (!ptr || upma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_pullback_union_pw_multi_aff(copy(), upma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_multi_aff union_pw_multi_aff::scale_down_val(isl::val val) const
{
  if (!ptr || val.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_scale_down_val(copy(), val.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_multi_aff union_pw_multi_aff::scale_val(isl::val val) const
{
  if (!ptr || val.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_scale_val(copy(), val.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_pw_multi_aff union_pw_multi_aff::union_add(isl::union_pw_multi_aff upma2) const
{
  if (!ptr || upma2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_pw_multi_aff_union_add(copy(), upma2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::union_set
isl::union_set manage(__isl_take isl_union_set *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return union_set(ptr);
}
isl::union_set manage_copy(__isl_keep isl_union_set *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_union_set_get_ctx(ptr);
  ptr = isl_union_set_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return union_set(ptr);
}

union_set::union_set()
    : ptr(nullptr) {}

union_set::union_set(const isl::union_set &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_union_set_get_ctx(obj.ptr));
}

union_set::union_set(__isl_take isl_union_set *ptr)
    : ptr(ptr) {}

union_set::union_set(isl::basic_set bset)
{
  if (bset.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = bset.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_from_basic_set(bset.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_set::union_set(isl::set set)
{
  if (set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = set.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_from_set(set.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_set::union_set(isl::point pnt)
{
  if (pnt.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = pnt.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_from_point(pnt.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_set::union_set(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

union_set &union_set::operator=(isl::union_set obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

union_set::~union_set() {
  if (ptr)
    isl_union_set_free(ptr);
}

__isl_give isl_union_set *union_set::copy() const & {
  return isl_union_set_copy(ptr);
}

__isl_keep isl_union_set *union_set::get() const {
  return ptr;
}

__isl_give isl_union_set *union_set::release() {
  isl_union_set *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool union_set::is_null() const {
  return ptr == nullptr;
}
union_set::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const union_set& C) {
  os << C.to_str();
  return os;
}

inline bool operator==(const union_set& C1, const union_set& C2) {
  return C1.is_equal(C2);
}


std::string union_set::to_str() const {
  char *Tmp = isl_union_set_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx union_set::get_ctx() const {
  return isl::ctx(isl_union_set_get_ctx(ptr));
}

isl::union_set union_set::add_set(isl::set set) const
{
  if (!ptr || set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_add_set(copy(), set.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::affine_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_affine_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::apply(isl::union_map umap) const
{
  if (!ptr || umap.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_apply(copy(), umap.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::coalesce() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_coalesce(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::compute_divs() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_compute_divs(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::detect_equalities() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_detect_equalities(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

unsigned int union_set::dim(enum isl::dim_type type) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_dim(get(), static_cast<enum isl_dim_type>(type));
  return res;
}

isl::union_set union_set::empty(isl::space space)
{
  if (space.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = space.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_empty(space.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::set union_set::extract_set(isl::space dim) const
{
  if (!ptr || dim.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_extract_set(get(), dim.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void union_set::foreach_point(const std::function<void(isl::point)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::point)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_point *arg_0, void *arg_1) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      (*data->func)(isl::manage(arg_0));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_union_set_foreach_point(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

void union_set::foreach_set(const std::function<void(isl::set)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::set)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_set *arg_0, void *arg_1) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      (*data->func)(isl::manage(arg_0));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_union_set_foreach_set(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::space union_set::get_space() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_get_space(get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::gist(isl::union_set context) const
{
  if (!ptr || context.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_gist(copy(), context.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::gist_params(isl::set set) const
{
  if (!ptr || set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_gist_params(copy(), set.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_set::identity() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_identity(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::intersect(isl::union_set uset2) const
{
  if (!ptr || uset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_intersect(copy(), uset2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::intersect_params(isl::set set) const
{
  if (!ptr || set.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_intersect_params(copy(), set.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool union_set::is_disjoint(const isl::union_set &uset2) const
{
  if (!ptr || uset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_is_disjoint(get(), uset2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_set::is_empty() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_is_empty(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_set::is_equal(const isl::union_set &uset2) const
{
  if (!ptr || uset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_is_equal(get(), uset2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_set::is_params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_is_params(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_set::is_strict_subset(const isl::union_set &uset2) const
{
  if (!ptr || uset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_is_strict_subset(get(), uset2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool union_set::is_subset(const isl::union_set &uset2) const
{
  if (!ptr || uset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_is_subset(get(), uset2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::union_set union_set::lexmax() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_lexmax(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::lexmin() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_lexmin(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val union_set::max_multi_union_pw_aff(const isl::multi_union_pw_aff &obj) const
{
  if (!ptr || obj.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_max_multi_union_pw_aff(get(), obj.get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::multi_val union_set::min_multi_union_pw_aff(const isl::multi_union_pw_aff &obj) const
{
  if (!ptr || obj.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_min_multi_union_pw_aff(get(), obj.get());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int union_set::n_set() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_n_set(get());
  return res;
}

isl::set union_set::params() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_params(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::polyhedral_hull() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_polyhedral_hull(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::preimage(isl::multi_aff ma) const
{
  if (!ptr || ma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_preimage_multi_aff(copy(), ma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::preimage(isl::pw_multi_aff pma) const
{
  if (!ptr || pma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_preimage_pw_multi_aff(copy(), pma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::preimage(isl::union_pw_multi_aff upma) const
{
  if (!ptr || upma.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_preimage_union_pw_multi_aff(copy(), upma.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::project_out(enum isl::dim_type type, unsigned int first, unsigned int n) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_project_out(copy(), static_cast<enum isl_dim_type>(type), first, n);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::point union_set::sample_point() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_sample_point(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::subtract(isl::union_set uset2) const
{
  if (!ptr || uset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_subtract(copy(), uset2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::unite(isl::union_set uset2) const
{
  if (!ptr || uset2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_union(copy(), uset2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set union_set::universe() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_universe(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_set::unwrap() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_unwrap(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_map union_set::wrapped_domain_map() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_wrapped_domain_map(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::union_set_list
isl::union_set_list manage(__isl_take isl_union_set_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return union_set_list(ptr);
}
isl::union_set_list manage_copy(__isl_keep isl_union_set_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_union_set_list_get_ctx(ptr);
  ptr = isl_union_set_list_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return union_set_list(ptr);
}

union_set_list::union_set_list()
    : ptr(nullptr) {}

union_set_list::union_set_list(const isl::union_set_list &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_union_set_list_get_ctx(obj.ptr));
}

union_set_list::union_set_list(__isl_take isl_union_set_list *ptr)
    : ptr(ptr) {}

union_set_list::union_set_list(isl::union_set el)
{
  if (el.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = el.get_ctx();
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_list_from_union_set(el.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
union_set_list::union_set_list(isl::ctx ctx, int n)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_list_alloc(ctx.release(), n);
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

union_set_list &union_set_list::operator=(isl::union_set_list obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

union_set_list::~union_set_list() {
  if (ptr)
    isl_union_set_list_free(ptr);
}

__isl_give isl_union_set_list *union_set_list::copy() const & {
  return isl_union_set_list_copy(ptr);
}

__isl_keep isl_union_set_list *union_set_list::get() const {
  return ptr;
}

__isl_give isl_union_set_list *union_set_list::release() {
  isl_union_set_list *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool union_set_list::is_null() const {
  return ptr == nullptr;
}
union_set_list::operator bool() const
{
  return !is_null();
}



isl::ctx union_set_list::get_ctx() const {
  return isl::ctx(isl_union_set_list_get_ctx(ptr));
}

isl::union_set_list union_set_list::add(isl::union_set el) const
{
  if (!ptr || el.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_list_add(copy(), el.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::union_set_list union_set_list::concat(isl::union_set_list list2) const
{
  if (!ptr || list2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_list_concat(copy(), list2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

void union_set_list::foreach(const std::function<void(isl::union_set)> &fn) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  struct fn_data {
    const std::function<void(isl::union_set)> *func;
    std::exception_ptr eptr;
  } fn_data = { &fn };
  auto fn_lambda = [](isl_union_set *arg_0, void *arg_1) -> isl_stat {
    auto *data = static_cast<struct fn_data *>(arg_1);
    try {
      (*data->func)(isl::manage(arg_0));
      return isl_stat_ok;
    } catch (...) {
      data->eptr = std::current_exception();
      return isl_stat_error;
    }
  };
  auto res = isl_union_set_list_foreach(get(), fn_lambda, &fn_data);
  if (fn_data.eptr)
    std::rethrow_exception(fn_data.eptr);
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return void(res);
}

isl::union_set union_set_list::get_union_set(int index) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_union_set_list_get_union_set(get(), index);
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}


// implementations for isl::val
isl::val manage(__isl_take isl_val *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return val(ptr);
}
isl::val manage_copy(__isl_keep isl_val *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_val_get_ctx(ptr);
  ptr = isl_val_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return val(ptr);
}

val::val()
    : ptr(nullptr) {}

val::val(const isl::val &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_val_get_ctx(obj.ptr));
}

val::val(__isl_take isl_val *ptr)
    : ptr(ptr) {}

val::val(isl::ctx ctx, long i)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_int_from_si(ctx.release(), i);
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}
val::val(isl::ctx ctx, const std::string &str)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_read_from_str(ctx.release(), str.c_str());
  if (!res)
    throw exception::create_from_last_error(ctx);
  ptr = res;
}

val &val::operator=(isl::val obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

val::~val() {
  if (ptr)
    isl_val_free(ptr);
}

__isl_give isl_val *val::copy() const & {
  return isl_val_copy(ptr);
}

__isl_keep isl_val *val::get() const {
  return ptr;
}

__isl_give isl_val *val::release() {
  isl_val *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool val::is_null() const {
  return ptr == nullptr;
}
val::operator bool() const
{
  return !is_null();
}

inline std::ostream& operator<<(std::ostream& os, const val& C) {
  os << C.to_str();
  return os;
}


std::string val::to_str() const {
  char *Tmp = isl_val_to_str(get());
  if (!Tmp)
    return "";
  std::string S(Tmp);
  free(Tmp);
  return S;
}


isl::ctx val::get_ctx() const {
  return isl::ctx(isl_val_get_ctx(ptr));
}

isl::val val::abs() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_abs(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool val::abs_eq(const isl::val &v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_abs_eq(get(), v2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::val val::add(isl::val v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_add(copy(), v2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val val::ceil() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_ceil(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

int val::cmp_si(long i) const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_cmp_si(get(), i);
  return res;
}

isl::val val::div(isl::val v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_div(copy(), v2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool val::eq(const isl::val &v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_eq(get(), v2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::val val::floor() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_floor(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val val::gcd(isl::val v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_gcd(copy(), v2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool val::ge(const isl::val &v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_ge(get(), v2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

long val::get_den_si() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_get_den_si(get());
  return res;
}

long val::get_num_si() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_get_num_si(get());
  return res;
}

bool val::gt(const isl::val &v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_gt(get(), v2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::val val::infty(isl::ctx ctx)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_infty(ctx.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::val val::inv() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_inv(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

bool val::is_divisible_by(const isl::val &v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_divisible_by(get(), v2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_infty() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_infty(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_int() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_int(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_nan() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_nan(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_neg() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_neg(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_neginfty() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_neginfty(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_negone() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_negone(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_nonneg() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_nonneg(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_nonpos() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_nonpos(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_one() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_one(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_pos() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_pos(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_rat() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_rat(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::is_zero() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_is_zero(get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::le(const isl::val &v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_le(get(), v2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

bool val::lt(const isl::val &v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_lt(get(), v2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::val val::max(isl::val v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_max(copy(), v2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val val::min(isl::val v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_min(copy(), v2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val val::mod(isl::val v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_mod(copy(), v2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val val::mul(isl::val v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_mul(copy(), v2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val val::nan(isl::ctx ctx)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_nan(ctx.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

bool val::ne(const isl::val &v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_ne(get(), v2.get());
  if (res < 0)
    throw exception::create_from_last_error(get_ctx());
  return res;
}

isl::val val::neg() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_neg(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val val::neginfty(isl::ctx ctx)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_neginfty(ctx.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::val val::negone(isl::ctx ctx)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_negone(ctx.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

isl::val val::one(isl::ctx ctx)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_one(ctx.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}

int val::sgn() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_sgn(get());
  return res;
}

isl::val val::sub(isl::val v2) const
{
  if (!ptr || v2.is_null())
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_sub(copy(), v2.release());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val val::trunc() const
{
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  options_scoped_set_on_error saved_on_error(get_ctx(), ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_trunc(copy());
  if (!res)
    throw exception::create_from_last_error(get_ctx());
  return manage(res);
}

isl::val val::zero(isl::ctx ctx)
{
  options_scoped_set_on_error saved_on_error(ctx, ISL_ON_ERROR_CONTINUE);
  auto res = isl_val_zero(ctx.release());
  if (!res)
    throw exception::create_from_last_error(ctx);
  return manage(res);
}


// implementations for isl::list<val>
isl::list<val> manage(__isl_take isl_val_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  return list<val>(ptr);
}
isl::list<val> manage_copy(__isl_keep isl_val_list *ptr) {
  if (!ptr)
    throw isl::exception::create(isl_error_invalid,
        "NULL input", __FILE__, __LINE__);
  auto ctx = isl_val_list_get_ctx(ptr);
  ptr = isl_val_list_copy(ptr);
  if (!ptr)
    throw exception::create_from_last_error(ctx);
  return list<val>(ptr);
}

list<val>::list()
    : ptr(nullptr) {}

list<val>::list(const isl::list<val> &obj)
    : ptr(obj.copy())
{
  if (obj.ptr && !ptr)
    throw exception::create_from_last_error(isl_val_list_get_ctx(obj.ptr));
}

list<val>::list(__isl_take isl_val_list *ptr)
    : ptr(ptr) {}


list<val> &list<val>::operator=(isl::list<val> obj) {
  std::swap(this->ptr, obj.ptr);
  return *this;
}

list<val>::~list() {
  if (ptr)
    isl_val_list_free(ptr);
}

__isl_give isl_val_list *list<val>::copy() const & {
  return isl_val_list_copy(ptr);
}

__isl_keep isl_val_list *list<val>::get() const {
  return ptr;
}

__isl_give isl_val_list *list<val>::release() {
  isl_val_list *tmp = ptr;
  ptr = nullptr;
  return tmp;
}

bool list<val>::is_null() const {
  return ptr == nullptr;
}
list<val>::operator bool() const
{
  return !is_null();
}



isl::ctx list<val>::get_ctx() const {
  return isl::ctx(isl_val_list_get_ctx(ptr));
}


template <typename InputIt1, typename InputIt2>
list<val>::list(isl::ctx ctx, InputIt1 from, InputIt2 to) {
  ptr = isl_val_list_alloc(ctx.get(), std::distance(from, to));
  for ( ; from != to; ++from) {
    ptr = isl_val_list_add(ptr, from->copy());
  }
}

int list<val>::size() const {
  return isl_val_list_n_val(ptr);
}

isl::val list<val>::at(int pos) const {
  return manage(isl_val_list_get_val(ptr, pos));
}

isl::val list<val>::operator[](int pos) const {
  return manage(isl_val_list_get_val(ptr, pos));
}

typename isl::list<val>::iterator
list<val>::begin() const {
  return list_iterator<val>(this, size() == 0 ? -1 : 0);
}

typename isl::list<val>::iterator
list<val>::end() const {
  return list_iterator<val>(this, -1);
}

} // namespace isl

#endif /* ISL_CPP */
