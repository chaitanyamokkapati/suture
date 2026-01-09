from unittest.mock import Mock, MagicMock, patch
from common import AccessInfo, Populator, Rule, Slice, RuleExtractResult
from ida_hexrays_ctree import cexpr_t
from ruletools import ParsePattern
from ida_typeinf import tinfo_t


class MockStruct(Populator.Struct):
	def __init__(self):
		super().__init__()
		self.data = dict()

	def __repr__(self):
		return str(self.data)

	def __getitem__(self, key):
		return self.data[key]

	def __setitem__(self, key, value):
		self.data[key] = value

	def get_pointed_object(self):
		return self

	@staticmethod
	def is_ptr():
		return True

	@staticmethod
	def get_member_type(s, o):
		return s.data.get(o)

	@staticmethod
	def add_struct(n):
		return MockStruct()

	@staticmethod
	def add_member(s, n, t, o):
		s[o] = t
		return t


class _DebugRule(Rule):
	@property
	def pattern(self) -> Slice:
		return ParsePattern("""
			i.op is idaapi.cot_ptr and
			i.x.op is idaapi.cot_cast and
			i.x.x.op is idaapi.cot_add and
			i.x.x.x.op is idaapi.cot_var and
			i.x.x.y.op is idaapi.cot_num
			""")

	def extract(self, items: list[cexpr_t]) -> RuleExtractResult:
		r1 = AccessInfo(0, AccessInfo(0, tinfo_t("_QWORD")))
		r2 = AccessInfo(0, AccessInfo(8, tinfo_t("_DWORD")))
		return RuleExtractResult([r1, r2], self)


def test_debug_rule_nested_struct_layout():
	rule = _DebugRule()
	mock_items = [Mock()] * 5
	result = rule.extract(mock_items)
	assert len(result.info) == 2
	assert result.info[0].off == 0
	assert result.info[1].off == 0
	assert isinstance(result.info[0].tif, AccessInfo)
	assert result.info[0].tif.off == 0
	assert isinstance(result.info[1].tif, AccessInfo)
	assert result.info[1].tif.off == 8
	assert result.info[0].tif.tif == tinfo_t("_QWORD")
	assert result.info[1].tif.tif == tinfo_t("_DWORD")


@patch('ida_hexrays.make_pointer')
@patch('utils.add_struct')
@patch('utils.is_struct_ptr')
@patch('utils.get_ptr_shift')
@patch('utils.add_member')
@patch('utils.can_fit_member')
@patch('utils.get_member_type')
def test_nested_struct_access(
		get_member_type,
		can_fit_member,
		add_member,
		get_ptr_shift,
		is_struct_ptr,
		add_struct,
		make_pointer
):
	get_member_type.side_effect = MockStruct.get_member_type
	can_fit_member.return_value = (True, 0)
	add_member.side_effect = MockStruct.add_member
	get_ptr_shift.return_value = 0
	is_struct_ptr.return_value = True
	add_struct.side_effect = MockStruct.add_struct
	make_pointer.side_effect = lambda x: x

	results = RuleExtractResult([
		AccessInfo(0, AccessInfo(0, tinfo_t("_QWORD"))),
		AccessInfo(0, AccessInfo(8, tinfo_t("_BYTE"))),
		AccessInfo(8, AccessInfo(0, AccessInfo(16, tinfo_t("_WORD")))),
		AccessInfo(0, AccessInfo(16, AccessInfo(4, tinfo_t("_WORD"))))
	], rule="")

	s = MockStruct()

	Populator(s, [results])

	assert s[0][0] == tinfo_t("_QWORD")
	assert s[0][8] == tinfo_t("_BYTE")
	assert s[8][0][16] == tinfo_t("_WORD")
	assert s[0][16][4] == tinfo_t("_WORD")
