from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SymbolType
import json
import re

regex_vtable = re.compile(r"^PTR_(?:FUN|LAB)_[0-9a-fA-F]+$")
regex_match_vtable_assignment = re.compile(r"\*(?:param_1|this) = .*?&PTR_(?:FUN|LAB)_[0-9a-fA-F]+;$")

symbols = currentProgram.getSymbolTable().getAllSymbols(True)
listing = currentProgram.getListing()
flat_api = FlatProgramAPI(currentProgram)
flat_decompiler_api = FlatDecompilerAPI(flat_api)

labels = [sym for sym in symbols if sym.getSymbolType() == SymbolType.LABEL and regex_vtable.match(sym.getName())]

# why is alot of vtable like 0x180044fd8 not in this @fasjldf@@@4io5h10 bruhhhhh
def vtable_extract(label):
    functions = []

    address = label.getAddress()
    while True:
        unit = listing.getCodeUnitAt(address)
        l = unit.getLabel()
        if unit.getMnemonicString() != 'addr' or unit.getLength() != 8 or (l != None and not regex_vtable.match(l)):
            break

        f = flat_api.getFunctionAt(unit.getValue())
        if not f:
            f = flat_api.createFunction(unit.getValue(), unit.getValue().toString("FUN_"))

        functions.append(f)
        address = address.add(8)

    return functions


def vtable_dump(vtable: list) -> list:
    def mapper(func):
        if func is None:
            return None
        
        f_body = flat_decompiler_api.decompile(func)

        f_type = 'meth'
        if 'free(param_1);' in f_body:
            f_type = 'deldtor'
        elif regex_match_vtable_assignment.search(f_body):
            f_type = 'ctor'

        return {
            'name': func.getName(),
            'type': f_type,
            'ea': func.getEntryPoint().toString("0x"),
            'body': "\n".join(f_body.split("\r\n"))
        }

    return list(map(mapper, vtable))


vtables = {label.getAddress().toString("cls_0x"): vtable_extract(label) for label in labels}
vtables = {key: vtable_dump(vtables[key]) for key in vtables if not all(map(lambda y: y is None, vtables[key]))}

with open('D:\\vtable_output.json', 'wb+') as f:
    f.write(json.dumps(vtables, indent=2).encode('utf-8'))
