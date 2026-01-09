import ida_hexrays_ctree
import common
import idaapi
from ruletools import ParsePattern


def test_simple_single_node():
	pattern_str = "i.op is idaapi.cot_ptr"
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_ptr
	assert result.x is None
	assert result.y is None
	assert result.z is None
	assert result.a is None
	assert result.predicate is None


def test_two_level_chain():
	pattern_str = """
    i.op is idaapi.cot_ptr and
    i.x.op is idaapi.cot_cast
    """
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_ptr
	assert isinstance(result.x, common.Slice)
	assert result.x.base == ida_hexrays_ctree.cot_cast
	assert result.y is None
	assert result.z is None


def test_three_level_chain():
	pattern_str = """
    i.op is idaapi.cot_ptr and
    i.x.op is idaapi.cot_cast and
    i.x.x.op is idaapi.cot_add
    """
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_ptr
	assert isinstance(result.x, common.Slice)
	assert result.x.base == ida_hexrays_ctree.cot_cast
	assert isinstance(result.x.x, common.Slice)
	assert result.x.x.base == ida_hexrays_ctree.cot_add


def test_complex_nested_pattern():
	pattern_str = """
    i.op is idaapi.cot_ptr and
    i.x.op is idaapi.cot_cast and
    i.x.x.op is idaapi.cot_add and
    i.x.x.x.op is idaapi.cot_ptr and
    i.x.x.x.x.op is idaapi.cot_ptr and
    i.x.x.x.x.x.op is idaapi.cot_cast and
    i.x.x.x.x.x.x.op is idaapi.cot_var and
    i.x.x.y.op is idaapi.cot_num
    """
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_ptr
	assert result.x.base == ida_hexrays_ctree.cot_cast
	assert result.x.x.base == ida_hexrays_ctree.cot_add
	assert result.x.x.x.base == ida_hexrays_ctree.cot_ptr
	assert result.x.x.x.x.base == ida_hexrays_ctree.cot_ptr
	assert result.x.x.x.x.x.base == ida_hexrays_ctree.cot_cast
	assert result.x.x.x.x.x.x.base == ida_hexrays_ctree.cot_var
	assert result.x.x.y.base == ida_hexrays_ctree.cot_num


def test_y_branch():
	pattern_str = """
    i.op is idaapi.cot_add and
    i.x.op is idaapi.cot_var and
    i.y.op is idaapi.cot_num
    """
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_add
	assert result.x.base == ida_hexrays_ctree.cot_var
	assert result.y.base == ida_hexrays_ctree.cot_num


def test_z_branch():
	pattern_str = """
    i.op is idaapi.cot_tern and
    i.x.op is idaapi.cot_var and
    i.y.op is idaapi.cot_num and
    i.z.op is idaapi.cot_num
    """
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_tern
	assert result.x.base == ida_hexrays_ctree.cot_var
	assert result.y.base == ida_hexrays_ctree.cot_num
	assert result.z.base == ida_hexrays_ctree.cot_num


def test_function_call_arguments():
	pattern_str = """
    i.op is idaapi.cot_call and
    i.x.op is idaapi.cot_ptr and
    i.a[0].op is idaapi.cot_var and
    i.a[1].op is idaapi.cot_num
    i.a[2].op is idaapi.cot_any
    i.a[3].op is idaapi.cot_ptr
    i.a[4].op is idaapi.cot_xor
    i.a[5].op is idaapi.cot_none
    """
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_call
	assert result.x.base == ida_hexrays_ctree.cot_ptr
	assert result.a is not None
	assert 0 in result.a
	assert 1 in result.a
	assert result.a[0].base == ida_hexrays_ctree.cot_var
	assert result.a[1].base == ida_hexrays_ctree.cot_num
	assert result.a[2].base == common.cot_any
	assert result.a[3].base == ida_hexrays_ctree.cot_ptr
	assert result.a[4].base == ida_hexrays_ctree.cot_xor
	assert result.a[5].base == common.cot_none


def test_predicate_attachment():
	pattern_str = "i.op is idaapi.cot_ptr"
	pred = lambda x: x.type.is_funcptr()
	result = ParsePattern(pattern_str, predicate=pred)
	assert result.base == ida_hexrays_ctree.cot_ptr
	assert result.predicate == pred


def test_predicate_only_on_root():
	pattern_str = """
    i.op is idaapi.cot_ptr and
    i.x.op is idaapi.cot_cast
    """
	pred = lambda x: True
	result = ParsePattern(pattern_str, predicate=pred)
	assert result.predicate == pred
	assert result.x.predicate is None


def test_cot_any_from_common():
	pattern_str = "i.op is idaapi.cot_any"
	result = ParsePattern(pattern_str)
	assert result.base == common.cot_any


def test_cot_none_from_common():
	pattern_str = "i.op is idaapi.cot_none"
	result = ParsePattern(pattern_str)
	assert result.base == common.cot_none


def test_equals_syntax():
	pattern_str = "i.op == idaapi.cot_ptr"
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_ptr


def test_without_idaapi_prefix():
	pattern_str = "i.op is cot_ptr"
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_ptr


def test_nested_argument_access():
	pattern_str = """
    i.op is idaapi.cot_call and
    i.x.op is idaapi.cot_ptr and
    i.x.x.op is idaapi.cot_cast and
    i.a[0].op is idaapi.cot_var
    """
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_call
	assert result.x.base == ida_hexrays_ctree.cot_ptr
	assert result.x.x.base == ida_hexrays_ctree.cot_cast
	assert 0 in result.a
	assert result.a[0].base == ida_hexrays_ctree.cot_var


def test_cot_none():
	pattern_str = """
        i.op is idaapi.cot_call and
        i.x.op is idaapi.cot_ptr and
        i.x.x.op is idaapi.cot_none and
        i.a[0].op is idaapi.cot_var
        """
	result = ParsePattern(pattern_str)
	assert result.base == ida_hexrays_ctree.cot_call
	assert result.x.base == ida_hexrays_ctree.cot_ptr
	assert result.x.x.base == common.cot_none
	assert 0 in result.a
	assert result.a[0].base == ida_hexrays_ctree.cot_var


def test_or_syntax():
	pattern_str = """
    i.op is idaapi.cot_call or idaapi.cot_var and
	i.x.op is idaapi.cot_ptr or idaapi.cot_num or idaapi.cot_xor or common.cot_none
    """
	result = ParsePattern(pattern_str)
	assert result.base == (idaapi.cot_call, idaapi.cot_var)
	assert result.x.base == (idaapi.cot_ptr, idaapi.cot_num, idaapi.cot_xor, common.cot_none)
