from rules import *
from common import RuleSet


class ClassRuleSet(RuleSet):
	def __init__(self):
		super().__init__([
			IndirectionPath1,
			IndirectionPath2,
			InterfaceDispatch,
			VirtualDispatch,
			FunctionalField,
			FieldAccess1,
			FieldAccess2,
			DataAssignment1,
			DataAssignment2,
			DataAssignment3,
			FunctionArgument1,
			FunctionArgument3,
			FunctionArgument4,
			FunctionArgument5,
			NestedRootVtableCall,
			DoubleNestedRootVtableCall1,
			DoubleNestedRootVtableCall2,
			DoubleNestedRootVtableCallWithOffset1,
			DoubleNestedRootVtableCallWithOffset2,
			TripleNestedVtableCall,
		])


class StackRuleSet(RuleSet):
	def __init__(self):
		super().__init__([
			IdxAssignment1,
			IdxAssignment2,
			IdxAssignment3,
			IdxAssignment4,
			DirectAssignmentFromFunction,
			DirectAssignment,
		])
