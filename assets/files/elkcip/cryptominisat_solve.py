from ast import *
from typing import Any
from z3 import *

class ReplaceVar1Visitor(NodeTransformer): 
    def visit_Call(self, node : Call) -> Any:
        if node.func.id == "_var1":
            # Replace calls of the form `_var1({0: 0, _var280: 1, _var279: 1}, 0)` with `Nand(_var280, _var279)`
            node.func.id = "Nand"
            keys = node.args[0].keys
            values = node.args[0].values
            if keys[0].value == 0 and values[0].value == 0 \
            and values[1].value == 1 and values[2].value == 1:
                node.args = [keys[1], keys[2]]
            else:
                raise Exception("Unexpected var1 arguments")
            return node
        else:
            return node

class CleanupAssignmentsVisitor(NodeTransformer):
    def visit_Assign(self, node: Assign) -> Any:
        if isinstance(node.value, Call) and node.value.func.id == "_var6":
            # Remove assignments of the form `foo = _var6(...)`
            return None
        if node.targets[0].id in [f"_var{i}" for i in range(7)]:
            # Remove assignments of the form `_var{i} = ...`
            return None
        else:
            return self.generic_visit(node)
        
mapping : dict[str,Name] = dict()
class ReplaceAssignVisitor(NodeTransformer):
    def visit_Assign(self, node: Assign) -> Any:
        if isinstance(node.value, Call) and node.value.func.id == "_var3":
            # Identify assignments of the form `_var{i} = _var3(...)`. These are the assignments that we want to remove.
            # The first argument to `_var3` is the index of the flag character.
            # `varNumber` is the index of the variable that we are assigning to. We can use this to compute a mapping from the variables to the flag bits.
            flag_char_index : int = node.value.args[1].value
            varNumber: int = int(node.targets[0].id[4:])
            for i in range(0, 8):
                mapping[f"_var{varNumber + 1 + 2*i}"] = Name(id=f"flag_{flag_char_index}_{i}", ctx=Load())                
            return None
        elif node.targets[0].id in mapping:
            # Replace assignments of the form `_var8 = _var5(_var7, 1)` with `mapping[_var8] = Bool(mapping[_var8].id)`
            node.targets[0] = mapping[node.targets[0].id]
            node.value = Call(func=Name(id='Bool', ctx=Load()),args=[Str(s=node.targets[0].id)],keywords=[])
            return node
        else:
            return node
        
class ReplaceNameVisitor(NodeTransformer):
    def visit_Name(self, node: Name) -> Any:
        if node.id in mapping:
            # Replace all references to variables that have been remapped to flag bits.
            return mapping[node.id]
        else:
            return node

class ReplaceTrueFalseVisitor(NodeTransformer):
    def visit_Constant(self, node: Constant) -> Any:
        if isinstance(node.value, int):
            node.value = True if node.value == 1 else False
            return node
        else:
            return node

class AddSolverCalls(NodeTransformer):
    def visit_Assign(self, node: Assign) -> Assign:
        if isinstance(node.targets[0], Name) and not node.targets[0].id.startswith("flag"):
            # Replace the Assign statement "a = b" with "goal.add(a == b)"
            new_node = Expr(value=Call(func=Attribute(value=Name(id='goal', ctx=Load()), attr='add', ctx=Load()), args=[Compare(left=node.targets[0], ops=[Eq()], comparators=[node.value])], keywords=[]))
            return new_node
        else:
            return node

class AddVariableDefinitions(NodeTransformer):
    def visit_Module(self, node: Module) -> Any:
        node.body = [parse(f"result0 = Bool('result0')").body[0]] + \
            [parse(f"_var{i} = Bool('_var{i}')").body[0] for i in range(279, 50515+1)] + node.body
        return node

# Load the code from a file
with open("decompiled_code.py", "rt") as file:
    code = file.read()

# Parse the code into an AST
ast_tree = parse(code)

# Cleanup the AST
ast_tree = ReplaceVar1Visitor().visit(ast_tree)
ast_tree = CleanupAssignmentsVisitor().visit(ast_tree)
ast_tree = ReplaceAssignVisitor().visit(ast_tree)
ast_tree = ReplaceNameVisitor().visit(ast_tree)
ast_tree = ReplaceTrueFalseVisitor().visit(ast_tree)
# If you comment out the next two lines, the solver will not finish quickly.
ast_tree = AddSolverCalls().visit(ast_tree)
ast_tree = AddVariableDefinitions().visit(ast_tree)



code = unparse(ast_tree)
# print(code)
goal = Goal()
exec("""
def Nand(a,b):
    return Not(And(a,b))
"""
+ code)
goal.add(result0 == True)

# Apply Tseitin CNF to the goal
tseitin_cnf = Tactic('tseitin-cnf')
cnf_goal = tseitin_cnf(goal)[0]

# Mappings
mappings = dict()

def mapVar(s):
    s = str(s)
    if s in mappings:
        return str(mappings[s])
    else:
        next_id = len(mappings) + 1
        mappings[s] = next_id
        return str(next_id)

import itertools


def handle_array(p):
    decl = p.decl()
    if str(decl) == "Or":
        return itertools.chain.from_iterable([handle_array(c) for c in p.children()])
    elif str(decl) == "Not":
        if len(p.children()) == 1:
            return [-int(mapVar(p.children()[0]))]
        else:
            assert(false)
    else:
        return [int(mapVar(decl))]


def to_clause_array(p):
    return handle_array(p)

from pycryptosat import Solver
s = Solver()

for p in cnf_goal:
    clause = to_clause_array(p)
    s.add_clause(clause)

print("Solving")
sat, solution = s.solve()

binaryStr = ""
for i in range(16):
    for j in range(8):
        sol = solution[mappings[f"flag_{i}_{j}"]]
        if sol:
            binaryStr = "1" + binaryStr
        else:
            binaryStr = "0" + binaryStr
print(int(binaryStr, 2).to_bytes(16, byteorder="little"))
