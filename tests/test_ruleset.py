from common import Rule, RuleSet, Slice
from ida_hexrays_ctree import cot_call, cot_add, cot_num


def test_call_expansion():
	class _Rule(Rule):
		@property
		def pattern(self) -> Slice:
			return Slice(cot_call, a=Slice(cot_add, y=cot_num))

		def extract(self, items):
			pass

	class _RuleSet(RuleSet):
		def __init__(self):
			super().__init__([
				_Rule
			])

	r = _RuleSet()
	assert len(r.rules) == RuleSet.ArgumentLimit
	for rule in r.rules:
		assert isinstance(rule._expanded_pattern.a, dict)
