from rulesets import DefaultRuleSet
import ida_kernwin
import ida_hexrays
import ida_hexrays_micro
import ida_hexrays_ctree
import ida_typeinf
import ida_idaapi
import common
import utils

ACTION_NAME = "suture:create_update_struct"


class Suture(ida_kernwin.action_handler_t):
	def __init__(self):
		super().__init__()
		self.vdui: ida_hexrays.vdui_t
		self.cit: ida_hexrays_ctree.citem_t
		self.lvar: ida_hexrays_micro.lvar_t
		self.lvar_name: str
		self.lvar_type: ida_typeinf.tinfo_t
		self.lvar_type_new: ida_typeinf.tinfo_t | None
		self.added: bool

	def activate(self, ctx):
		self.vdui = utils.get_current_vdui()
		if not utils.can_process_lvar(self.vdui):
			return

		self.added = False

		self.init_attrs()
		utils.set_lvar_type(self.vdui, self.lvar_name, ida_typeinf.tinfo_t("__int64"))
		self.process()
		lt = self.lvar_type_new if self.added else self.lvar_type
		utils.set_lvar_type(self.vdui, self.lvar_name, lt)

	def update(self, ctx):
		return ida_kernwin.AST_ENABLE_FOR_WIDGET

	def init_attrs(self):
		self.cit = self.vdui.item.it
		self.lvar = utils.get_cursor_lvar(self.vdui)
		self.lvar_name = self.lvar.name
		self.lvar_type = ida_typeinf.tinfo_t(str(self.lvar.tif))
		self.lvar_type_new = None

	def process(self):
		new_struct_name = str()

		matcher = common.Matcher(self.vdui.cfunc, DefaultRuleSet())
		matches = matcher.match()

		filtered, extracted = common.Extractor(self.lvar_name, self.vdui.cfunc, matches).data

		if common.DEBUG:
			print("\n------ MATCHES ------")
			print("\n".join([str(i) for i in matches]))
			print("\n------ FILTERED ------")
			print("\n".join([str(i) for i in filtered]))

		if not filtered:
			print("No struct access found")
			return

		if not self.lvar_type.is_ptr() or not utils.is_struct_ptr(self.lvar_type):
			new_struct_name = utils.ask_struct_name()

			if not new_struct_name:
				return

		if new_struct_name:
			struct_tif = utils.add_struct(new_struct_name)
		else:
			struct_tif = self.lvar_type

		common.Populator(struct_tif, extracted)
		self.lvar_type_new = struct_tif if struct_tif.is_ptr() else ida_hexrays.make_pointer(struct_tif)
		self.added = True


class ContextHook(ida_kernwin.UI_Hooks):
	def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
		if not ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE \
				or not utils.can_process_lvar(ida_hexrays.get_widget_vdui(widget)):
			ida_kernwin.detach_action_from_popup(widget, ACTION_NAME)
		else:
			ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_NAME)


def run_tests():
	from pathlib import Path
	import pytest

	test_dir = Path(__file__).parent / "tests"

	targets = [
		test_dir / "test_parser.py::TestParsePattern",
		test_dir / "test_slice.py::TestSlice",
		test_dir / "test_ruleset.py::TestRuleSet",
	]

	pytest.main([str(t) for t in targets])


class SuturePlugin(ida_idaapi.plugin_t):
	wanted_name = "Suture"
	flags = ida_idaapi.PLUGIN_HIDE

	def init(self):
		if common.DEBUG:
			run_tests()
		if not ida_hexrays.init_hexrays_plugin():
			return ida_idaapi.PLUGIN_SKIP
		if not ida_kernwin.register_action(ida_kernwin.action_desc_t(
				ACTION_NAME, "Create/Update struct members", Suture(), shortcut="Shift-F")
		):
			return ida_idaapi.PLUGIN_SKIP
		self.hook = ContextHook()
		self.hook.hook()
		return ida_idaapi.PLUGIN_KEEP


def PLUGIN_ENTRY():
	return SuturePlugin()
