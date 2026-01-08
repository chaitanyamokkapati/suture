import common
import ida_typeinf
import ida_hexrays
import ida_hexrays_ctree
from common import Slice, cot_any, cot_none


def ccot(op):
	e = ida_hexrays.cexpr_t()
	e.op = op
	e.type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT)
	if op == ida_hexrays_ctree.cot_call:
		e.a = ida_hexrays.carglist_t()
	return e


class TestSliceMatch:
	def setup_method(self):
		self.cot_var = ida_hexrays_ctree.cot_var
		self.cot_num = ida_hexrays_ctree.cot_num
		self.cot_add = ida_hexrays_ctree.cot_add
		self.cot_call = ida_hexrays_ctree.cot_call
		self.cot_obj = ida_hexrays_ctree.cot_obj
		self.cot_asg = ida_hexrays_ctree.cot_asg

	def test_call_args_match(self):
		e_call = ccot(self.cot_call)
		e_call.x = ccot(self.cot_obj)
		arg0_expr = ccot(self.cot_var)
		arg0_wrapper = ida_hexrays.carg_t()
		arg0_wrapper.assign(arg0_expr)
		e_call.a.push_back(arg0_wrapper)
		s = Slice(base=self.cot_call, a={0: self.cot_var})
		collected = []
		assert s.matches(e_call, collected) is True
		assert arg0_expr in collected

	def test_binary_op_match(self):
		e_add = ccot(self.cot_add)
		e_var = ccot(self.cot_var)
		e_num = ccot(self.cot_num)

		e_add.cexpr.x = e_var
		e_add.cexpr.y = e_num

		s = Slice(base=self.cot_add, x=self.cot_var, y=self.cot_num)
		collected = []
		assert s.matches(e_add, collected) is True
		assert len(collected) == 3

	def test_backtracking_on_failure(self):
		e_add = ccot(self.cot_add)
		e_add.cexpr.x = ccot(self.cot_var)
		e_add.cexpr.y = ccot(self.cot_num)
		s = Slice(base=self.cot_add, x=self.cot_var, y=self.cot_var)
		collected = []
		result = s.matches(e_add, collected)
		assert result is False
		assert len(collected) == 0

	def test_recursive_slice_match(self):
		e_add = ccot(self.cot_add)
		e_add.cexpr.x = ccot(self.cot_var)
		e_add.cexpr.y = ccot(self.cot_num)
		e_asg = ccot(self.cot_asg)
		e_asg.cexpr.x = ccot(self.cot_var)
		e_asg.cexpr.y = e_add
		inner_slice = Slice(base=self.cot_add, x=self.cot_var, y=self.cot_num)
		outer_slice = Slice(base=self.cot_asg, x=self.cot_var, y=inner_slice)
		collected = []
		assert outer_slice.matches(e_asg, collected) is True
		assert len(collected) == 5

	def test_triple_recursive_match(self):
		e_inner_inner = ccot(self.cot_add)
		e_inner_inner.cexpr.x = ccot(self.cot_var)
		e_inner_inner.cexpr.y = ccot(self.cot_num)
		e_inner_add = ccot(self.cot_add)
		e_inner_add.cexpr.x = ccot(self.cot_var)
		e_inner_add.cexpr.y = e_inner_inner
		e_asg = ccot(self.cot_asg)
		e_asg.cexpr.x = ccot(self.cot_var)
		e_asg.cexpr.y = e_inner_add

		level3_slice = Slice(base=self.cot_add, x=self.cot_var, y=self.cot_num)
		level2_slice = Slice(base=self.cot_add, x=self.cot_var, y=level3_slice)
		outer_slice = Slice(base=self.cot_asg, x=self.cot_var, y=level2_slice)
		collected = []
		assert outer_slice.matches(e_asg, collected) is True
		assert len(collected) == 7
		assert collected[0].op == self.cot_asg
		assert collected[4].op == self.cot_add
		assert collected[6].op == self.cot_num

	def test_cot_any_child_match(self):
		e_add = ccot(ida_hexrays_ctree.cot_add)
		e_var = ccot(ida_hexrays_ctree.cot_var)
		e_num = ccot(ida_hexrays_ctree.cot_num)
		e_add.cexpr.x = e_var
		e_add.cexpr.y = e_num
		s = Slice(base=ida_hexrays_ctree.cot_add, x=cot_any, y=cot_any)
		collected = []
		assert s.matches(e_add, collected) is True
		assert len(collected) == 1

	def test_cot_none_unary_check(self):
		e_not = ccot(ida_hexrays_ctree.cot_lnot)
		e_not.cexpr.x = ccot(ida_hexrays_ctree.cot_var)
		s = Slice(base=ida_hexrays_ctree.cot_lnot, x=ida_hexrays_ctree.cot_var, y=cot_none)
		collected = []
		assert s.matches(e_not, collected) is True
		assert len(collected) == 2
		assert collected[0].op == ida_hexrays_ctree.cot_lnot

	def test_cot_call_assert(self):
		try:
			Slice(base=ida_hexrays_ctree.cot_var, a={0: common.cot_any})
			Slice(base=Slice(ida_hexrays_ctree.cot_var), a={0: common.cot_any})
		except AssertionError:
			assert True
		else:
			assert False
