import unittest
import ida_hexrays_ctree
import common
from ruletools import ParsePattern


class TestParsePattern(unittest.TestCase):

	def test_simple_single_node(self):
		pattern_str = "i.op is idaapi.cot_ptr"
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, ida_hexrays_ctree.cot_ptr)
		self.assertIsNone(result.x)
		self.assertIsNone(result.y)
		self.assertIsNone(result.z)
		self.assertIsNone(result.a)
		self.assertIsNone(result.predicate)

	def test_two_level_chain(self):
		pattern_str = """
        i.op is idaapi.cot_ptr and
        i.x.op is idaapi.cot_cast
        """
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, ida_hexrays_ctree.cot_ptr)
		self.assertIsInstance(result.x, common.Slice)
		self.assertEqual(result.x.base, ida_hexrays_ctree.cot_cast)
		self.assertIsNone(result.y)
		self.assertIsNone(result.z)

	def test_three_level_chain(self):
		pattern_str = """
        i.op is idaapi.cot_ptr and
        i.x.op is idaapi.cot_cast and
        i.x.x.op is idaapi.cot_add
        """
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, ida_hexrays_ctree.cot_ptr)
		self.assertIsInstance(result.x, common.Slice)
		self.assertEqual(result.x.base, ida_hexrays_ctree.cot_cast)
		self.assertIsInstance(result.x.x, common.Slice)
		self.assertEqual(result.x.x.base, ida_hexrays_ctree.cot_add)

	def test_complex_nested_pattern(self):
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
		self.assertEqual(result.base, ida_hexrays_ctree.cot_ptr)
		self.assertEqual(result.x.base, ida_hexrays_ctree.cot_cast)
		self.assertEqual(result.x.x.base, ida_hexrays_ctree.cot_add)
		self.assertEqual(result.x.x.x.base, ida_hexrays_ctree.cot_ptr)
		self.assertEqual(result.x.x.x.x.base, ida_hexrays_ctree.cot_ptr)
		self.assertEqual(result.x.x.x.x.x.base, ida_hexrays_ctree.cot_cast)
		self.assertEqual(result.x.x.x.x.x.x.base, ida_hexrays_ctree.cot_var)
		self.assertEqual(result.x.x.y.base, ida_hexrays_ctree.cot_num)

	def test_y_branch(self):
		pattern_str = """
        i.op is idaapi.cot_add and
        i.x.op is idaapi.cot_var and
        i.y.op is idaapi.cot_num
        """
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, ida_hexrays_ctree.cot_add)
		self.assertEqual(result.x.base, ida_hexrays_ctree.cot_var)
		self.assertEqual(result.y.base, ida_hexrays_ctree.cot_num)

	def test_z_branch(self):
		pattern_str = """
        i.op is idaapi.cot_tern and
        i.x.op is idaapi.cot_var and
        i.y.op is idaapi.cot_num and
        i.z.op is idaapi.cot_num
        """
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, ida_hexrays_ctree.cot_tern)
		self.assertEqual(result.x.base, ida_hexrays_ctree.cot_var)
		self.assertEqual(result.y.base, ida_hexrays_ctree.cot_num)
		self.assertEqual(result.z.base, ida_hexrays_ctree.cot_num)

	def test_function_call_arguments(self):
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
		self.assertEqual(result.base, ida_hexrays_ctree.cot_call)
		self.assertEqual(result.x.base, ida_hexrays_ctree.cot_ptr)
		self.assertIsNotNone(result.a)
		self.assertIn(0, result.a)
		self.assertIn(1, result.a)
		self.assertEqual(result.a[0].base, ida_hexrays_ctree.cot_var)
		self.assertEqual(result.a[1].base, ida_hexrays_ctree.cot_num)
		self.assertEqual(result.a[2].base, common.cot_any)
		self.assertEqual(result.a[3].base, ida_hexrays_ctree.cot_ptr)
		self.assertEqual(result.a[4].base, ida_hexrays_ctree.cot_xor)
		self.assertEqual(result.a[5].base, common.cot_none)

	def test_predicate_attachment(self):
		pattern_str = "i.op is idaapi.cot_ptr"
		pred = lambda x: x.type.is_funcptr()
		result = ParsePattern(pattern_str, predicate=pred)
		self.assertEqual(result.base, ida_hexrays_ctree.cot_ptr)
		self.assertEqual(result.predicate, pred)

	def test_predicate_only_on_root(self):
		pattern_str = """
        i.op is idaapi.cot_ptr and
        i.x.op is idaapi.cot_cast
        """
		pred = lambda x: True
		result = ParsePattern(pattern_str, predicate=pred)
		self.assertEqual(result.predicate, pred)
		self.assertIsNone(result.x.predicate)

	def test_cot_any_from_common(self):
		pattern_str = "i.op is idaapi.cot_any"
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, common.cot_any)

	def test_cot_none_from_common(self):
		pattern_str = "i.op is idaapi.cot_none"
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, common.cot_none)

	def test_equals_syntax(self):
		pattern_str = "i.op == idaapi.cot_ptr"
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, ida_hexrays_ctree.cot_ptr)

	def test_without_idaapi_prefix(self):
		pattern_str = "i.op is cot_ptr"
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, ida_hexrays_ctree.cot_ptr)

	def test_nested_argument_access(self):
		pattern_str = """
        i.op is idaapi.cot_call and
        i.x.op is idaapi.cot_ptr and
        i.x.x.op is idaapi.cot_cast and
        i.a[0].op is idaapi.cot_var
        """
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, ida_hexrays_ctree.cot_call)
		self.assertEqual(result.x.base, ida_hexrays_ctree.cot_ptr)
		self.assertEqual(result.x.x.base, ida_hexrays_ctree.cot_cast)
		self.assertIn(0, result.a)
		self.assertEqual(result.a[0].base, ida_hexrays_ctree.cot_var)

	def test_cot_none(self):
		pattern_str = """
	        i.op is idaapi.cot_call and
	        i.x.op is idaapi.cot_ptr and
	        i.x.x.op is idaapi.cot_none and
	        i.a[0].op is idaapi.cot_var
	        """
		result = ParsePattern(pattern_str)
		self.assertEqual(result.base, ida_hexrays_ctree.cot_call)
		self.assertEqual(result.x.base, ida_hexrays_ctree.cot_ptr)
		self.assertEqual(result.x.x.base, common.cot_none)
		self.assertIn(0, result.a)
		self.assertEqual(result.a[0].base, ida_hexrays_ctree.cot_var)
