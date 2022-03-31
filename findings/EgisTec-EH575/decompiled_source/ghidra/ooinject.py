from dataclasses import dataclass, field
from pathlib import Path
import json
import re
import textwrap as tw

regex_match_vtable_assignment = re.compile(r"\*(?:param_1|this) = .*?&^PTR_(?:FUN|LAB)_([0-9a-fA-F]+)$;")

@dataclass
class CppFunction:
    name: str
    header_and_body: str

    def __repr__(self):
        return self.header_and_body

@dataclass
class CppVariable:
    name: str
    type: str = 'undefined'
    usages: list = field(default_factory=list)

    def __repr__(self):
        return f"{self.type} {self.name};  // usages: {' '.join(self.usages)}"

@dataclass
class CppClass:
    name: str
    size: int = None
    associated_vtables: list = field(default_factory=list)
    variables: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    vtable_functions: list = field(default_factory=list)

    def __repr__(self):
        variables = '\n'.join([str(_) for _ in self.variables])
        functions = '\n\n'.join([str(_) for _ in self.functions])
        vtable_functions = '\n\n'.join([str(_) for _ in self.vtable_functions])

        output = '// size: {}\n'.format(self.size) if self.size else ''
        output += '// associated_vtables: {}\n'.format(' '.join(self.associated_vtables)) if len(self.associated_vtables) > 0 else ''
        output += 'class {} {{\n{}\n\n{}\n\n  class vtable {{\n{}\n  }}\n}}'.format(self.name, tw.indent(variables, '  '), tw.indent(functions, '  '), tw.indent(vtable_functions, '    '))
        return output

def get_start_end_idx_of_function(f_name, code) -> tuple:
    start = next(re.finditer(r'\n\w[\w\s*]*{}\('.format(f_name), code)).start(0)
    end = 0

    braces = 0
    for i in range(start, len(code)):
        if code[i] == '{':
            braces += 1
        elif code[i] == '}':
            braces -= 1
            if braces == 0:
                end = i
                return start, end

def extract_into_classes(code: str, ooanalyzer, ghidra_vtable) -> tuple:
    classes = []
    cleanup = set()

    def variable_mapper(var):
        return CppVariable(name=f"var_{var['offset']}", type=f"undefined{var['size']}", usages=var['usages'])

    def function_mapper(class_name, function):
        nonlocal code, ghidra_vtable, cleanup

        if function is None:
            return None

        entrypoint_address = function['ea'][2:]
        code, changes = re.subn(r'(\w[\w\s*]*FUN_{}\().+?(?=[,)])'.format(entrypoint_address), r'\1{} *this'.format(class_name), code)

        if changes == 0:  # function not present in `code`
            f_body = next((f['body'] for f in ghidra_vtable[class_name] if f['name'] == "FUN_{}".format(entrypoint_address)), None) if class_name in ghidra_vtable else None
            if f_body is None:
                return CppFunction(name=f"FUN_{entrypoint_address}", header_and_body=f"// Untracked function, please refer to ghidra and find the function at this address manually\nundefined FUN_{entrypoint_address}(...) {{}}")

            f_body = re.sub(r'(\w[\w\s*]*FUN_{}\().+?(?=[,)])'.format(entrypoint_address), r'\1{} *this'.format(class_name), f_body).replace('param_1', 'this')

            prefix = "FUN"
            if function['type'] != 'meth':
                prefix = function['type'].upper()
                f_body = re.sub(r'FUN(_{})'.format(entrypoint_address), r'{}\1'.format(prefix), f_body)
            return CppFunction(name=f"{prefix}_{entrypoint_address}", header_and_body=f_body)

        prefix = "FUN"
        if function['type'] != 'meth':
            prefix = function['type'].upper()
            code = re.sub(r'FUN(_{})'.format(entrypoint_address), r'{}\1'.format(prefix), code)

        f_name = f"{prefix}_{entrypoint_address}"
        start, end = get_start_end_idx_of_function(f_name, code)
        cleanup.add((start, end))

        f_body = code[start:end+1].replace('param_1', 'this')
        return CppFunction(name=f_name, header_and_body=f_body)
    
    def associated_vtables_extractor(current_vtable_name: str, functions: list) -> list:
        constructors = filter(lambda f: f.name.startswith('CTOR_'), functions)
        return list({'0x' + group for c in constructors for group in [match.group(1) for match in regex_match_vtable_assignment.finditer(c.header_and_body)] if group != current_vtable_name})

    for info in sorted(ooanalyzer['structures'].values(), key=lambda x: x['name']):
        class_name = info['name']
        members = sorted(info['members'].values(), key=lambda x: int(x['offset'], 16))
        functions = sorted(filter(lambda f: not f['name'].startswith('virt_'), info['methods'].values()), key=lambda x: x['name'])

        variables = []
        if len(members) > 0:
            variables = [CppVariable(name='vfptr', type='vtable*', usages=members[0]['usages'])] + [variable_mapper(_) for _ in members[1:]]
        
        functions = sorted([function_mapper(class_name, _) for _ in functions], key=lambda fn: fn.name)
        vtable_functions = [function_mapper(class_name, _) for _ in ghidra_vtable[class_name]] if class_name in ghidra_vtable else []  # vtable must be in same order, as calls are made by offsets after vtable address
        associated_vtables = associated_vtables_extractor(class_name[6:], functions)

        classes.append(CppClass(name=class_name, size=info['size'], associated_vtables=associated_vtables, variables=variables, functions=functions, vtable_functions=vtable_functions))
    
    for class_name in set(ghidra_vtable.keys()) - set(ooanalyzer['structures'].keys()):
        info = ghidra_vtable[class_name]
        vtable_functions = [function_mapper(class_name, _) for _ in ghidra_vtable[class_name]]
        associated_vtables = associated_vtables_extractor(class_name[6:], functions)

        classes.append(CppClass(name=class_name, associated_vtables=associated_vtables, vtable_functions=vtable_functions))
    
    # cleanup
    for start, end in sorted(cleanup, reverse=True):
        print(start, end)
        code = code[:start] + code[end+1:]

    return code, classes


if __name__ == '__main__':
    ooanalyzer = (Path(__file__).parent / 'ooanalyzer' / 'output.json').read_text()
    ooanalyzer = json.loads(ooanalyzer)

    ghidra_vtable = (Path(__file__).parent / 'ghidra_scripts' / 'vtable_output.json').read_text()
    ghidra_vtable = json.loads(ghidra_vtable)

    decompiled_code = (Path(__file__).parent / 'EgisTouchFP0575.c').read_text()
    decompiled_code, classes = extract_into_classes(decompiled_code, ooanalyzer, ghidra_vtable)

    # decompiled_code = decompiled_code + '\n\n\n\n// ooinject start\n\n' + '\n\n\n'.join(map(str, classes))
    # decompiled_code = re.sub(r'\n{5,}', '\n'*4, decompiled_code) # restrict 4 newlines at max

    # (Path(__file__).parent / 'EgisTouchFP0575-ooinject.cpp').write_text(decompiled_code, 'utf-8')

# print(output)
# print(decompiled_code)
# print([line for line in decompiled_code.split('\n') if '{} *this'.format(info['name']) in line])
