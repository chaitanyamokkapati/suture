from rules import *
from common import RuleSet


class DefaultRuleSet(RuleSet):
	def __init__(self):
		super().__init__([
			# XYZ_DebugRule_XYZ,
			IndirectionPath1,
			IndirectionPath2,
			InterfaceDispatch,
			VirtualDispatch,
			FunctionalField,
			FieldAccess1,
			DataAssignment1,
			DataAssignment2,
			DataAssignment3,
			FunctionArgument1,
			FieldAccess2,
			FunctionArgument3,
			FunctionArgument4,
			NestedRootVtableCall
		])
