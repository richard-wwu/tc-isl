#include "isl-noexceptions.h"

#include <cassert>
#include <iostream>
#include <limits>
#include <unordered_set>
#include <vector>

isl::aff operator*(int i, const isl::aff& A) {
  isl_ctx *ctx = A.get_ctx().get();
  isl::aff T(isl::local_space(A.get_space().domain()), isl::val(ctx, i));
  return A.mul(T);
}

isl::aff operator*(const isl::aff& A, int i) {
  return i * A;
}

isl::aff operator+(int i, const isl::aff& A) {
  isl_ctx *ctx = A.get_ctx().get();
  isl::aff T(isl::local_space(A.get_space().domain()), isl::val(ctx, i));
  return A.add(T);
}

isl::aff operator+(const isl::aff& A, const isl::aff& B) {
  return A.add(B);
}

isl::aff operator+(const isl::aff& A, int i) {
  return i + A;
}

isl::set operator>=(const isl::aff& A, int i) {
  isl_ctx *ctx = A.get_ctx().get();
  isl::aff T(isl::local_space(A.get_space().domain()), isl::val(ctx, i));
  return A.ge_set(T);
}

isl::set operator<=(const isl::aff& A, int i) {
  return A.neg() >= -i;
}

isl::set operator<=(int i, const isl::aff& A) {
  return A >= i;
}

isl::set operator>=(int i, const isl::aff& A) {
  return A <= i;
}

isl::set operator&(const isl::set& S1, const isl::set& S2) {
  return S1.intersect(S2);
}

isl::union_set operator&(isl::union_set S1, const isl::set& S2) {
  return S1.intersect(S2);
}

isl::union_set operator&(const isl::set& S1, isl::union_set S2) {
  return S2.intersect(S1);
}

isl::set operator&(const isl::set& S1, isl::point P2) {
  return S1.intersect(P2);
}

isl::set operator&(isl::point P1, const isl::set& S2) {
  return S2 & P1;
}

isl::set makeUniverseSet(const isl::ctx& ctx, std::vector<const char*> pNames) {
  auto s = isl::set::universe(isl::space(ctx, pNames.size()));
  int idx = 0;
  for (auto n : pNames) {
    s = isl::manage(isl_set_set_dim_name(s.take(), isl_dim_param, idx++, n));
  }
  return s;
}

// Better if we had isl::set::align(s) a member
isl::set makeAlignedSet(const isl::set& orig, const isl::set& s) {
  return isl::manage(
    isl_set_align_params(orig.copy(), isl_set_get_space(s.copy())));
}

isl::point makePoint(
    const isl::space& s, std::vector<const char*> names, std::vector<long> vals) {
  isl::point pt(s);
  int idx = 0;
  for (auto n : names) {
    int pos = isl_space_find_dim_by_name(s.get(), isl_dim_param, n);
    assert(pos >= 0);
    if (vals[idx] >= 0) {
      pt = isl::manage(
        isl_point_add_ui(pt.take(), isl_dim_param, pos, vals[idx]));
    } else {
      pt = isl::manage(
        isl_point_sub_ui(pt.take(), isl_dim_param, pos, -vals[idx]));
    }
    idx++;
  }
  return pt;
}

long evalIntegerAt(const isl::aff& a, const isl::point& pt) {
  // Parametric only
  assert(isl::set(pt).dim(isl::dim::in) == 0);
  assert(isl_aff_dim(a.get(), isl_dim_in) == isl::set(pt).dim(isl::dim::in));
  assert(isl_aff_dim(a.get(), isl_dim_param) == isl::set(pt).dim(isl::dim::param));
  auto aff_map = isl::manage(isl_map_from_aff(a.copy()));
  auto pt_map = isl::manage(isl_map_from_domain(isl::set(pt).release()));
  auto m = pt_map.apply_domain(aff_map);
  assert(m.is_single_valued());
  // Project out all parameters and only keep the value
  m = m.project_out(isl::dim::param, 0, isl::set(pt).dim(isl::dim::param));
  auto v = isl::manage(
    isl_map_plain_get_val_if_fixed(m.get(), isl_dim_in, 0));
  assert(isl_val_get_den_si(v.get()) == 1); // not a rational
  return isl_val_get_num_si(v.get());
}

void test_simple_union_set(isl::ctx ctx) {
  auto S1 = isl::set(ctx, "{ A[2, 8, 1] }");
  std::cout << S1 << std::endl;
  auto S2 = isl::union_set(ctx, "{ A[2, 8, 1]; B[1] }");
  std::cout << S2 << std::endl;
  std::cout << (S2 & S1) << std::endl;
  assert(bool(S1 == (S2 & S1)));
}

void test_simple_union_map(isl::ctx ctx) {
  auto M1 = isl::union_map(ctx, "{ A[2, 8, 1] -> B[0]; C[123] -> D[1] }");
  std::cout << M1 << " " << M1.reverse() << std::endl;
  auto M2 = isl::union_map(ctx, "{ B[0] -> B[1]; D[1] -> B[0] }");
  std::cout << M1 << " " << M1.reverse() << std::endl;
  std::cout << "Domain: " << M1.domain()  << std::endl;
  std::cout << "Range: " << M1.range()  << std::endl;
  std::cout << "DomainMap: " << M1.domain_map() << std::endl;
}

void test_simple_params(isl::ctx ctx) {
  // From string
  isl::set S1(ctx, R"S([p0, p1] -> {  : 0 <= p0 <= 10 and 0 <= p1 <= 20 })S");
  std::cout << S1 << std::endl;
  // Create a simple 2-D parametric domain
  isl::space ContextSpace(ctx, 2);
  isl::local_space Context(ContextSpace);
  isl::aff p0(Context, isl::dim::param, 0);
  isl::aff p1(Context, isl::dim::param, 1);
  // With range [0-10] x [0-20]
  isl::set S2 = 0 <= p0 & p0 <= 10 & 0 <= p1 & p1 <= 20;
  std::cout << S2 << std::endl;
  assert(S1.to_str() == S2.to_str());
}

void test_simple_set(isl::ctx ctx) {
  // From string
  isl::set S1(ctx, R"S([p0, p1] -> {  : 0 <= p0 <= 10 and 0 <= p1 <= 20 })S");
  std::cout << S1 << std::endl;

  // Add dim::set dimensions
  isl::set D = S1.add_dims(isl::dim::set, 2);
  std::cout << D << std::endl;
  assert(D.to_str() == std::string(
           "[p0, p1] -> { [i0, i1] : 0 <= p0 <= 10 and 0 <= p1 <= 20 }"));
}

class ScopeGuard {
  std::function<void()> onExit;
  ScopeGuard() = delete;
  ScopeGuard(ScopeGuard&) = delete;
  ScopeGuard(ScopeGuard&&) = delete;
  ScopeGuard operator=(ScopeGuard&) = delete;
  ScopeGuard operator=(ScopeGuard&&) = delete;
 public:
  template<class F> ScopeGuard(const F& f) : onExit(f) {}
  ~ScopeGuard() { onExit(); }
};

std::string to_c(const isl::ast_node& N) {
  auto p = isl_printer_to_str(N.get_ctx().get());
  ScopeGuard g([=]{ isl_printer_free(p); });
  p = isl_printer_set_output_format(p, ISL_FORMAT_C);
  p = isl_printer_print_ast_node(p, N.get());
  return isl_printer_get_str(p);
}

void test_simple_codegen(isl::ctx ctx) {
  isl::space ContextSpace(ctx, 0, 2);
  isl::local_space Context(ContextSpace);
  isl::aff i0(Context, isl::dim::set, 0);
  isl::aff i1(Context, isl::dim::set, 1);

  // With range [0-10] x [0-20]
  isl::set S2 = 0 <= i0 & i0 <= 10 & 0 <= i1 & i1 <= 20;
  std::cout << S2 << std::endl;
  auto B = isl::ast_build::from_context(isl::set(ctx, "{:}"));
  auto sched = isl::schedule::from_domain(S2);
  auto N1 = B.node_from_schedule(sched);
  auto um = isl::union_map::from_domain_and_range(S2, S2);
  auto N2 = B.node_from_schedule_map(um);
  std::cout << "SCHED: " << sched << std::endl;
  std::cout << to_c(N1);
  std::cout << "SCHED MAP: " << um << std::endl;
  std::cout << to_c(N2);
}

void test_simple_aff(isl::ctx ctx) {
  {
    // Union set with 2 named integer tuples
    auto a = isl::union_set(ctx, "{ A[1, 2, 3]; B[1] } ");
    std::cout << a << std::endl;
  }
  {
    // This aff is a pw_aff
    auto a = isl::pw_aff(ctx, "{ [i, j] -> [floor(i + j / 2)] }");
    std::cout << a << std::endl;
  }
  {
    // This pw_aff is not an aff
    auto a = isl::pw_aff(
      ctx, "{ [x] -> [x + 1] : 0 <= x < 10; [x] -> [0] : x = 10 }");
    std::cout << a << std::endl;
    // Under context
    auto b = isl::pw_aff(
      ctx, "[n] -> { [x] -> [x + 1] : 0 <= x < n; [x] -> [0] : x = n - 1 }");
    std::cout << b << std::endl;
  }
  {
    // This pw_multi_aff is not a pw_aff
    auto a = isl::pw_multi_aff(
      ctx, "{ [x] -> [x + 1, x + 1] : 0 <= x < 10; [x] -> [0, 123] : x = 10 }");
    std::cout << a << std::endl;
    // tuple of expression: multi_aff is not an aff (RHS has 2 expressions)
    auto b = isl::multi_aff(
      ctx, " { [i, j] -> [j + i, 2 * i] } ");
    std::cout << b << std::endl;
    // tuple of pw expression (needs parens)
    auto c = isl::multi_pw_aff(
      ctx, " { [i, j] -> [ (j + i : i > 0), (2 * i : j > 0)] } ");
    std::cout << c << std::endl;
  }
}

void test_simple_eval(isl::ctx ctx) {
  isl::pw_aff pwaff(
    ctx, R"ISL([x, y, z] -> { [(256)] : z > 10000;
             [floor((31 + x + y + z) / 32) ] : 0 <= z <= 9999 })ISL");

  isl::set res = makeUniverseSet(ctx, { "x", "y", "z" });
  isl::point pt = makePoint(
    isl::manage(isl_set_get_space(res.get())), {"x", "z"}, {1, 1234});

  auto B = isl::ast_build::from_context(res);
  long val = std::numeric_limits<long>::max();
  pwaff.foreach_piece([&pt, &val](isl::set s, isl::aff a){
      if ((s & pt).is_empty()) { return isl::stat::ok; }
      // only 1 piece should intersect non-empty
      assert(val == std::numeric_limits<long>::max());
      val = evalIntegerAt(a, pt);
      return isl::stat::ok;
    });
  assert(val == 39);
}

int main() {
  isl_ctx *ctx = isl_ctx_alloc();
  ScopeGuard g([=](){ isl_ctx_free(ctx); });

  test_simple_aff(ctx);
  test_simple_union_set(ctx);
  test_simple_union_map(ctx);
  test_simple_params(ctx);
  test_simple_set(ctx);
  test_simple_codegen(ctx);
  test_simple_aff(ctx);
  test_simple_eval(ctx);

  return 0;
}
