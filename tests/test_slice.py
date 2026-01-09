import common
import ida_typeinf
import ida_hexrays
import ida_hexrays_ctree
from common import Slice, cot_any, cot_none
import pytest


def ccot(op):
	e = ida_hexrays.cexpr_t()
	e.op = op
	e.type = ida_typeinf.tinfo_t(ida_typeinf.BT_INT)
	if op == ida_hexrays_ctree.cot_call:
		e.a = ida_hexrays.carglist_t()
	return e


@pytest.fixture
def cot_ops():
	return {
		'cot_var': ida_hexrays_ctree.cot_var,
		'cot_num': ida_hexrays_ctree.cot_num,
		'cot_add': ida_hexrays_ctree.cot_add,
		'cot_call': ida_hexrays_ctree.cot_call,
		'cot_obj': ida_hexrays_ctree.cot_obj,
		'cot_asg': ida_hexrays_ctree.cot_asg
	}


def test_call_args_match(cot_ops):
	e_call = ccot(cot_ops['cot_call'])
	e_call.x = ccot(cot_ops['cot_obj'])
	arg0_expr = ccot(cot_ops['cot_var'])
	arg0_wrapper = ida_hexrays.carg_t()
	arg0_wrapper.assign(arg0_expr)
	e_call.a.push_back(arg0_wrapper)
	s = Slice(base=cot_ops['cot_call'], a={0: cot_ops['cot_var']})
	collected = []
	assert s.matches(e_call, collected) is True
	assert arg0_expr in collected


def test_binary_op_match(cot_ops):
	e_add = ccot(cot_ops['cot_add'])
	e_var = ccot(cot_ops['cot_var'])
	e_num = ccot(cot_ops['cot_num'])

	e_add.cexpr.x = e_var
	e_add.cexpr.y = e_num

	s = Slice(base=cot_ops['cot_add'], x=cot_ops['cot_var'], y=cot_ops['cot_num'])
	collected = []
	assert s.matches(e_add, collected) is True
	assert len(collected) == 3


def test_backtracking_on_failure(cot_ops):
	e_add = ccot(cot_ops['cot_add'])
	e_add.cexpr.x = ccot(cot_ops['cot_var'])
	e_add.cexpr.y = ccot(cot_ops['cot_num'])
	s = Slice(base=cot_ops['cot_add'], x=cot_ops['cot_var'], y=cot_ops['cot_var'])
	collected = []
	result = s.matches(e_add, collected)
	assert result is False
	assert len(collected) == 0


def test_recursive_slice_match(cot_ops):
	e_add = ccot(cot_ops['cot_add'])
	e_add.cexpr.x = ccot(cot_ops['cot_var'])
	e_add.cexpr.y = ccot(cot_ops['cot_num'])
	e_asg = ccot(cot_ops['cot_asg'])
	e_asg.cexpr.x = ccot(cot_ops['cot_var'])
	e_asg.cexpr.y = e_add
	inner_slice = Slice(base=cot_ops['cot_add'], x=cot_ops['cot_var'], y=cot_ops['cot_num'])
	outer_slice = Slice(base=cot_ops['cot_asg'], x=cot_ops['cot_var'], y=inner_slice)
	collected = []
	assert outer_slice.matches(e_asg, collected) is True
	assert len(collected) == 5


def test_triple_recursive_match(cot_ops):
	e_inner_inner = ccot(cot_ops['cot_add'])
	e_inner_inner.cexpr.x = ccot(cot_ops['cot_var'])
	e_inner_inner.cexpr.y = ccot(cot_ops['cot_num'])
	e_inner_add = ccot(cot_ops['cot_add'])
	e_inner_add.cexpr.x = ccot(cot_ops['cot_var'])
	e_inner_add.cexpr.y = e_inner_inner
	e_asg = ccot(cot_ops['cot_asg'])
	e_asg.cexpr.x = ccot(cot_ops['cot_var'])
	e_asg.cexpr.y = e_inner_add

	level3_slice = Slice(base=cot_ops['cot_add'], x=cot_ops['cot_var'], y=cot_ops['cot_num'])
	level2_slice = Slice(base=cot_ops['cot_add'], x=cot_ops['cot_var'], y=level3_slice)
	outer_slice = Slice(base=cot_ops['cot_asg'], x=cot_ops['cot_var'], y=level2_slice)
	collected = []
	assert outer_slice.matches(e_asg, collected) is True
	assert len(collected) == 7
	assert collected[0].op == cot_ops['cot_asg']
	assert collected[4].op == cot_ops['cot_add']
	assert collected[6].op == cot_ops['cot_num']


def test_cot_any_child_match():
	e_add = ccot(ida_hexrays_ctree.cot_add)
	e_var = ccot(ida_hexrays_ctree.cot_var)
	e_num = ccot(ida_hexrays_ctree.cot_num)
	e_add.cexpr.x = e_var
	e_add.cexpr.y = e_num
	s = Slice(base=ida_hexrays_ctree.cot_add, x=cot_any, y=cot_any)
	collected = []
	assert s.matches(e_add, collected) is True
	assert len(collected) == 1


def test_cot_none_unary_check():
	e_not = ccot(ida_hexrays_ctree.cot_lnot)
	e_not.cexpr.x = ccot(ida_hexrays_ctree.cot_var)
	s = Slice(base=ida_hexrays_ctree.cot_lnot, x=ida_hexrays_ctree.cot_var, y=cot_none)
	collected = []
	assert s.matches(e_not, collected) is True
	assert len(collected) == 2
	assert collected[0].op == ida_hexrays_ctree.cot_lnot


def test_a_param_without_cot_call():
	with pytest.raises(AssertionError):
		Slice(base=ida_hexrays_ctree.cot_var, a={0: Slice(common.cot_any)})


def test_nested_call_with_wildcard():
	with pytest.raises(NotImplementedError):
		Slice(base=ida_hexrays_ctree.cot_ptr,
		      x=Slice(ida_hexrays_ctree.cot_var,
		              x=Slice(ida_hexrays_ctree.cot_ptr,
		                      x=Slice(ida_hexrays_ctree.cot_call, a=Slice(ida_hexrays_ctree.cot_add)))))


def test_nested_call_with_dict():
	Slice(base=ida_hexrays_ctree.cot_ptr,
	      x=Slice(ida_hexrays_ctree.cot_var,
	              x=Slice(ida_hexrays_ctree.cot_ptr,
	                      x=Slice(ida_hexrays_ctree.cot_call,
	                              a={0: Slice(ida_hexrays_ctree.cot_add)}
	                              )
	                      )
	              )
	      )
