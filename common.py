from __future__ import annotations
from typing import Callable, Type
from abc import ABC, abstractmethod

import ida_hexrays
import ida_hexrays_ctree
import ida_typeinf
import ida_lines
import idc
import utils
from ida_typeinf import tinfo_t

cot_any = 0xFFFFFFFF
cot_none = 0xFFFFFFFF << 1

DEBUG = 0


class Slice:
	def __init__(self, base: int | tuple[int, ...] | Slice,
	             x: int | Slice | tuple[int | Slice, ...] | None = None,
	             y: int | Slice | tuple[int | Slice, ...] | None = None,
	             z: int | Slice | tuple[int | Slice, ...] | None = None,
	             a: dict[int, Slice | int] | Slice | None = None,
	             predicate: Callable[[ida_hexrays_ctree.cexpr_t], bool] | None = None
	             ):
		self.base = base
		self.x = x
		self.y = y
		self.z = z
		self.a = a
		self.predicate = predicate
		if a and isinstance(base, int):
			assert base == ida_hexrays_ctree.cot_call
		self.validate_no_nested_calls()

	def validate_no_nested_calls(self):
		for attr in [self.x, self.y, self.z]:
			if isinstance(attr, Slice):
				if attr.base == ida_hexrays_ctree.cot_call:
					raise Exception("Nested cot_call is not supported")

		if isinstance(self.a, Slice):
			if self.a.base == ida_hexrays_ctree.cot_call:
				raise Exception("Nested cot_call is not supported")

		elif isinstance(self.a, dict):
			for val in self.a.values():
				if isinstance(val, Slice):
					if val.base == ida_hexrays_ctree.cot_call:
						raise Exception("Nested cot_call is not supported")

	def matches(self, expr: ida_hexrays_ctree.cexpr_t, collected: list[ida_hexrays_ctree.cexpr_t]) -> bool:
		init_len = len(collected)
		k1 = False

		if self.base == cot_any:
			k1 = True
			collected.append(expr)

		elif isinstance(self.base, Slice):
			if self.base.matches(expr, collected):
				k1 = True

		elif isinstance(self.base, tuple):
			for el in self.base:
				if isinstance(el, Slice):
					if el.matches(expr, collected):
						k1 = True
						break
				elif expr.op == el:
					k1 = True
					collected.append(expr)
					break
		else:
			if expr.op == self.base:
				k1 = True
				collected.append(expr)

		if not k1:
			del collected[init_len:]
			return False

		if self.predicate and not self.predicate(expr):
			del collected[init_len:]
			return False

		for attr, leaf in [(self.x, expr.cexpr.x), (self.y, expr.cexpr.y), (self.z, expr.cexpr.z)]:
			if attr is None:
				continue

			if attr == cot_none:
				if leaf:
					del collected[init_len:]
					return False
				continue

			if not leaf:
				del collected[init_len:]
				return False

			if isinstance(attr, Slice):
				if not attr.matches(leaf, collected):
					del collected[init_len:]
					return False

			elif isinstance(attr, tuple):
				match_in_tuple = False

				for el in attr:
					if isinstance(el, Slice):
						if el.matches(leaf, collected):
							match_in_tuple = True
							break
					elif leaf.op == el:
						match_in_tuple = True
						collected.append(leaf)
						break
				if not match_in_tuple:
					del collected[init_len:]
					return False

			elif attr != cot_any:
				if leaf.op != attr:
					del collected[init_len:]
					return False
				collected.append(leaf)

		if self.a and expr.op == ida_hexrays_ctree.cot_call:
			if not isinstance(self.a, dict):
				raise Exception("Failed a= expansion")

			for idx, arg in self.a.items():
				if idx >= len(expr.a):
					del collected[init_len:]
					return False

				arg_leaf = expr.a[idx]
				if isinstance(arg, Slice):
					if not arg.matches(arg_leaf, collected):
						del collected[init_len:]
						return False
				elif arg != cot_any:
					if arg_leaf.op != arg:
						del collected[init_len:]
						return False
					collected.append(arg_leaf)

		return True

	@property
	def complexity(self):
		return self._complexity()

	def _complexity(self, depth: int = 1) -> float:
		score = 0.0

		if isinstance(self.base, Slice):
			score += self.base._complexity(depth)
		elif isinstance(self.base, tuple):
			score += 0.8 * depth
		elif self.base == cot_any:
			score += 0.5 * depth
		else:
			score += 1.0 * depth

		if self.predicate:
			score += 2.0 * depth

		for attr in [self.x, self.y, self.z]:
			if attr is None or attr == cot_none:
				continue

			if isinstance(attr, Slice):
				score += attr._complexity(depth + 1)
			elif isinstance(attr, tuple):
				score += 0.8 * (depth + 1)
			elif attr != cot_any:
				score += 1.0 * (depth + 1)
			else:
				score += 0.5 * (depth + 1)

		if self.a:
			if isinstance(self.a, dict):
				for idx, attr in self.a.items():
					if isinstance(attr, Slice):
						score += attr._complexity(depth + 1)
					elif attr != cot_any:
						score += 1.0 * (depth + 1)
					else:
						score += 0.5 * (depth + 1)
			else:
				score += self.a._complexity(depth + 1)

		return score

	def similarity(self, other) -> float:
		if not isinstance(other, Slice):
			return 0.0

		total_score = 0.0
		max_score = 0.0

		base_score, base_max = self._compare_base(other)
		total_score += base_score
		max_score += base_max

		for attr in ['x', 'y', 'z']:
			score, max_s = self._compare_attr(getattr(self, attr), getattr(other, attr))
			total_score += score
			max_score += max_s

		a_score, a_max = self._compare_args(self.a, other.a)
		total_score += a_score
		max_score += a_max

		if self.predicate and other.predicate:
			total_score += 2.0
			max_score += 2.0
		elif self.predicate or other.predicate:
			max_score += 2.0

		return total_score / max_score if max_score > 0 else 0.0

	def _compare_base(self, other) -> tuple[float, float]:
		if isinstance(self.base, Slice) and isinstance(other.base, Slice):
			return self.base.similarity(other.base), 1.0
		elif isinstance(self.base, tuple) and isinstance(other.base, tuple):
			matches = sum(1 for a in self.base if a in other.base)
			return matches, max(len(self.base), len(other.base))
		elif self.base == other.base:
			return 1.0, 1.0
		return 0.0, 1.0

	def _compare_attr(self, a, b) -> tuple[float, float]:
		if a is None and b is None:
			return 0.0, 0.0
		if a is None or b is None:
			return 0.0, 1.0

		if isinstance(a, Slice) and isinstance(b, Slice):
			return a.similarity(b), 1.0
		elif isinstance(a, tuple) and isinstance(b, tuple):
			matches = sum(1 for x in a if x in b or any(
				isinstance(x, Slice) and isinstance(y, Slice) and x.similarity(y) > 0.8 for y in b))
			return matches, max(len(a), len(b))
		elif a == b:
			return 1.0, 1.0
		return 0.0, 1.0

	def _compare_args(self, a, b) -> tuple[float, float]:
		if a is None and b is None:
			return 0.0, 0.0
		if a is None or b is None:
			return 0.0, 1.0

		if isinstance(a, dict) and isinstance(b, dict):
			shared_keys = set(a.keys()) & set(b.keys())
			score = sum(1 for k in shared_keys if self._compare_attr(a[k], b[k])[0] > 0)
			return score, max(len(a), len(b))
		elif isinstance(a, Slice) and isinstance(b, Slice):
			return a.similarity(b), 1.0
		return 0.0, 1.0


class AccessInfo:
	def __init__(self, off: int, tif: ida_typeinf.tinfo_t | AccessInfo):
		self.off = off
		self.tif = tif

	def __eq__(self, other):
		return self.off == other.off and str(self.tif) == str(other.tif)


class RuleExtractResult:
	def __init__(self, info: list[AccessInfo] | AccessInfo, rule: Rule):
		self.info = [info] if isinstance(info, AccessInfo) else info
		self.rule = str(rule)

	@property
	def depth(self):
		return len(self.info)


class Rule(ABC):
	@property
	def weight(self):
		# Rules with higher weight run first
		# if weight is the same for multiple rules,
		# the more complex ones run first
		return 0

	@property
	def exclusive(self):
		# if pattern was found and Rule is exlusive,
		# all sub-nodes are removed as potential heads
		return True

	@property
	def elevated(self):
		# if pattern is elevated it ignores exlusivity
		return False

	def match(self, start: ida_hexrays_ctree.cexpr_t) -> list[ida_hexrays_ctree.cexpr_t] | None:
		collected = list()
		pat = getattr(self, "_expanded_pattern", self.pattern)
		if pat.matches(start, collected):
			return collected
		return None

	@property
	@abstractmethod
	def pattern(self) -> Slice:
		pass

	@abstractmethod
	def extract(self, items: list[ida_hexrays_ctree.cexpr_t]) -> RuleExtractResult:
		pass

	def __str__(self):
		return f"{self.__class__.__name__} ({self.pattern.complexity})"


class RuleSetAnalyser:
	_instance = None

	def __new__(cls, rule_set: RuleSet, *args, **kwargs):
		if cls._instance is None:
			cls._instance = super().__new__(cls)

		ins = cls._instance
		ins.find_similar(rule_set)
		return ins

	def find_similar(self, rule_set: RuleSet):
		threshold = 0.7
		comparisons = 0
		found = 0
		rules = rule_set._rules

		for i, a in enumerate(rules):
			for b in rules[i + 1:]:
				if str(a) == str(b) or a.pattern.complexity != b.pattern.complexity:
					continue

				comparisons += 1
				sim = a.pattern.similarity(b.pattern)

				if sim >= threshold:
					found += 1
					print(f"Similarity: {sim * 100:.1f}%")
					print(f"    {a}")
					print(f"    {b}")
					diff = self.find_diffs(a.pattern, b.pattern)
					if diff:
						print("Differences:")
						for d in diff:
							print(f"    {d}")
					print()

		print(f"\nAnalyzed {len(rules)} rules in {rule_set}, {comparisons} comparisons, {found} mergeable patterns\n")

	def find_diffs(self, a: Slice, b: Slice, path: str = "") -> list[str]:
		diffs = []

		if a.base != b.base:
			diffs.append(f"{path}base: {self.format_diff(a.base)} vs {self.format_diff(b.base)}")

		for attr in ['x', 'y', 'z']:
			a_val, b_val = getattr(a, attr), getattr(b, attr)

			if isinstance(a_val, Slice) and isinstance(b_val, Slice):
				diffs.extend(self.find_diffs(a_val, b_val, f"{path}{attr}."))
			elif a_val != b_val and a_val is not None and b_val is not None:
				diffs.append(f"{path}{attr} -> {self.format_diff(a_val)} vs {self.format_diff(b_val)}")

		if isinstance(a.a, dict) and isinstance(b.a, dict):
			for k in set(a.a.keys()) & set(b.a.keys()):
				if a.a[k] != b.a[k]:
					diffs.append(f"{path}a[{k}]: {self.format_diff(a.a[k])} vs {self.format_diff(b.a[k])}")

		return diffs

	def format_diff(self, val):
		import ruletools
		if isinstance(val, int):
			return ruletools.CotToStr(val)
		elif isinstance(val, tuple):
			return f"({', '.join(ruletools.CotToStr(v) if isinstance(v, int) else str(v) for v in val)})"
		return str(val)


class RuleSet(ABC):
	ArgumentLimit = 8

	def __init__(self, rules: list[Type[Rule]]):
		self._rules = self.expand_rules(rules)
		if DEBUG:
			RuleSetAnalyser(self)

	@staticmethod
	def expand_rules(rules: list[type[Rule]]):
		expanded = []
		for rule_cls in rules:
			ins = rule_cls()
			pattern = ins.pattern

			if pattern.base == ida_hexrays_ctree.cot_call:
				if isinstance(pattern.a, Slice):
					for i in range(RuleSet.ArgumentLimit):
						r = rule_cls()
						pat = Slice(
							base=pattern.base,
							x=pattern.x,
							y=pattern.y,
							z=pattern.z,
							a={i: pattern.a},
							predicate=pattern.predicate
						)
						setattr(r, "_expanded_pattern", pat)
						expanded.append(r)
				else:
					expanded.append(ins)
			else:
				expanded.append(ins)

		return expanded

	@property
	def rules(self) -> list[Rule]:
		return sorted(
			self._rules,
			key=lambda r: (r.weight, r.pattern.complexity),
			reverse=True
		)

	def add_rules(self, rules: list[Rule]):
		self._rules.extend(rules)

	def __str__(self):
		return str(self.__class__.__name__)


class Visitor(ida_hexrays_ctree.ctree_visitor_t):
	def __init__(self, matcher: Matcher):
		super().__init__(ida_hexrays_ctree.CV_PARENTS)
		self.matcher = matcher

	def visit_expr(self, arg0: ida_hexrays_ctree.cexpr_t) -> int:
		self.matcher.gather(len(self.parents), arg0)
		return 0


class MatchResult:
	def __init__(self, rule: Rule, items: list[ida_hexrays_ctree.cexpr_t]):
		self.rule = rule
		self.items = items

	def __str__(self):
		return f"{str(self.rule):<32}{ida_lines.tag_remove(self.items[0].cexpr.print1(None))}"


class Matcher:
	def __init__(self, cfunc: ida_hexrays_ctree.cfunc_t, rule_set: RuleSet):
		self.rule_set = rule_set
		self.heads: dict[int, tuple[int, ida_hexrays_ctree.cexpr_t]] = dict()
		self.hooks: set[int] = self.get_hooks(rule_set)
		self.visitor = Visitor(self).apply_to(cfunc.body, None)

	@staticmethod
	def get_hooks(rule_set: RuleSet) -> set[int]:
		ops = set()

		def extract_ops(b):
			if isinstance(b, int):
				ops.add(b)
			elif isinstance(b, Slice):
				extract_ops(b.base)
			elif isinstance(b, tuple):
				for el in b:
					extract_ops(el)

		for rule in rule_set.rules:
			extract_ops(rule.pattern.base)

		assert cot_any not in ops, "Rule pattern can't start with cot_any"
		assert cot_none not in ops, "Rule pattern can't start with cot_none"
		return ops

	def gather(self, depth: int, item: ida_hexrays_ctree.cexpr_t):
		if item.op in self.hooks:
			self.heads[item.obj_id] = (depth, item)

	def match(self) -> list[MatchResult]:
		excluded: list[ida_hexrays_ctree.citem_t] = list()
		matches: list[MatchResult] = list()

		for depth, item in sorted(self.heads.values(), key=lambda x: x[0]):
			for rule in self.rule_set.rules:
				if rule.pattern.base != item.op:
					continue

				if DEBUG:
					print(f"\nRunning Rule: {str(rule)}\n  Item: {item.obj_id:08X}\n  Depth: {depth}")

				if not rule.elevated and any([e.contains_expr(item) for e in excluded]):
					if DEBUG:
						print("  EXCLUDED")
					continue

				if items := rule.match(item):
					matches.append(MatchResult(rule, items))
					if DEBUG:
						print("  MATCHED")

					if rule.exclusive:
						if item.op == ida_hexrays_ctree.cot_call:
							if len(items) > 1:
								args = [a for a in item.a]
								found = False
								for i in items[1:]:
									if i in args:
										found = True
										break

								if not found:
									excluded.append(item)
							else:
								excluded.append(item)
						else:
							excluded.append(item)

		return matches


class Extractor:
	def __init__(self, lvar_name: str, cfunc: ida_hexrays_ctree.cfunc_t, matches: list[MatchResult]):
		self.lvar_name = lvar_name
		self.lvars = cfunc.get_lvars()
		self.filtered = self.filter(matches)

	def is_target_lvar(self, idx: int):
		return self.lvars[idx].name == self.lvar_name

	def filter(self, results):
		filtered = list()

		# keep only items that reference target lvar
		for r in results:
			for i in r.items:
				if i.op == ida_hexrays_ctree.cot_var and self.is_target_lvar(i.get_v().idx):
					filtered.append(r)
					break

		return filtered

	def extract(self) -> list[RuleExtractResult]:
		data = list()
		for r in self.filtered:
			if mem := r.rule.extract(r.items):
				data.append(mem)
		return data

	@property
	def data(self) -> tuple[list[MatchResult], list[RuleExtractResult]]:
		return self.filtered, self.extract()


class Populator:
	Struct = dict

	def __init__(self, struct_tif: ida_typeinf.tinfo_t, results: list[RuleExtractResult]):
		self.struct_tif = struct_tif
		self.results = results
		self.run()

	def run(self):
		layout = self.create_layout(self.results)

		def populate(stif, lays: dict[int, dict | tinfo_t]):
			if DEBUG:
				print(f"\n------ POPULATE ------")
				print(f"Struct Type: {stif}\n{"\n".join([f"0x{k:02X} -> {v}" for k, v in lays.items()])}")
				print()

			for off, t in lays.items():
				added = False

				if isinstance(t, Populator.Struct):
					psize = 8 if idc.__EA64__ else 4
				else:
					psize = t.get_size()

				can_fit, ov_off = utils.can_fit_member(stif, off, psize)

				if can_fit:
					if isinstance(t, dict):
						if ntif := utils.get_member_type(stif, off):
							if utils.is_struct_ptr(ntif):
								ntif = ntif.get_pointed_object()

						if not ntif:
							n = utils.new_tmpstruct_name()
							ntif = utils.add_struct(n)
							pt = ida_hexrays.make_pointer(ntif)
							utils.add_member(stif, n, pt, off)
							added = True

						populate(ntif, t)
					else:
						n = f"field_{off:X}"
						utils.add_member(stif, n, t, off)
						added = True

				ov = off if added else ov_off
				utils.log_struct_action(stif, ov, added)

		populate(self.struct_tif, layout)

	def resolve_conflict(self,
	                     org: Populator.Struct | tinfo_t,
	                     new: Populator.Struct | tinfo_t
	                     ) -> Populator.Struct | tinfo_t:
		if DEBUG:
			print(f"Type Conflict: ORG: {org} <-> NEW: {new}")

		if org == new:
			return org

		if isinstance(org, Populator.Struct):
			return org

		org_str = str(org)
		new_str = str(new)

		generics = {
			'_QWORD',
			'_DWORD',
			'_WORD',
			'_BYTE',
			'void *',
			'__int64',
			'__int32',
			'__int16',
			'__int8'
		}

		org_is_generic = org_str in generics
		new_is_generic = new_str in generics

		if org_is_generic and not new_is_generic:
			return new
		if new_is_generic and not org_is_generic:
			return org

		if new.is_ptr() and not org.is_ptr():
			return new
		if org.is_ptr() and not new.is_ptr():
			return org

		def strip_ptr(t: tinfo_t):
			while t.is_ptr():
				t = t.get_pointed_object()
			return t

		new_base = strip_ptr(new)

		if new_base.get_size() > 8 and not new_base.is_array():
			return org

		return new

	def create_layout(self, results: list[RuleExtractResult]):
		struct = Populator.Struct()

		def navigate(s, i):
			o = i.off
			t = i.tif

			if DEBUG:
				print("------ NAVIGATE ------")
				print(f"  0x{o:02X}\n  {t}")

			if isinstance(t, tinfo_t):
				org = s.get(o, None)
				if not org:
					s[o] = t
				else:
					s[o] = self.resolve_conflict(org, t)

			elif isinstance(t, AccessInfo):
				l = s.setdefault(o, Populator.Struct())
				if isinstance(l, tinfo_t):
					d = Populator.Struct()
					navigate(d, t)
					s[o] = self.resolve_conflict(l, d)
				else:
					navigate(l, t)

		for r in [a.info for a in results]:
			for info in r:
				navigate(struct, info)

		return struct
