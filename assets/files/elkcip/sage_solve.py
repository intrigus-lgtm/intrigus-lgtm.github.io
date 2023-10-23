from _ast import Assign, Call, Module, Name, Constant
import ast
from typing import Any
from z3 import *

class ReplaceVar1Visitor(ast.NodeTransformer): 
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

class CleanupAssignmentsVisitor(ast.NodeTransformer):
    def visit_Assign(self, node: Assign) -> Any:
        if isinstance(node.value, ast.Call) and node.value.func.id == "_var6":
            # Remove assignments of the form `foo = _var6(...)`
            return None
        if node.targets[0].id in [f"_var{i}" for i in range(7)]:
            # Remove assignments of the form `_var{i} = ...`
            return None
        else:
            return self.generic_visit(node)
        
mapping : dict[str,ast.Name] = dict()
class ReplaceAssignVisitor(ast.NodeTransformer):
    def visit_Assign(self, node: Assign) -> Any:
        if isinstance(node.value, ast.Call) and node.value.func.id == "_var3":
            # Identify assignments of the form `_var{i} = _var3(...)`. These are the assignments that we want to remove.
            # The first argument to `_var3` is the index of the flag character.
            # `varNumber` is the index of the variable that we are assigning to. We can use this to compute a mapping from the variables to the flag bits.
            flag_char_index : int = node.value.args[1].value
            varNumber: int = int(node.targets[0].id[4:])
            for i in range(0, 8):
                mapping[f"_var{varNumber + 1 + 2*i}"] = ast.Name(id=f"flag_{flag_char_index}_{i}", ctx=ast.Load())                
            return None
        elif node.targets[0].id in mapping:
            # Replace assignments of the form `_var8 = _var5(_var7, 1)` with `mapping[_var8] = Bool(mapping[_var8].id)`
            node.targets[0] = mapping[node.targets[0].id]
            node.value = Call(func=Name(id='Bool', ctx=ast.Load()),args=[ast.Str(s=node.targets[0].id)],keywords=[])
            return node
        else:
            return node
        
class ReplaceNameVisitor(ast.NodeTransformer):
    def visit_Name(self, node: Name) -> Any:
        if node.id in mapping:
            # Replace all references to variables that have been remapped to flag bits.
            return mapping[node.id]
        else:
            return node
        
class ReplaceNandToXorVisitor(ast.NodeTransformer):
    def visit_Module(self, node: Module) -> Any:
        for i in range(len(node.body)):
            match node.body[i:]:
                case [Assign(targets=[Name(id=C, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=A, ctx=ast.Load()), Name(id=A2, ctx=ast.Load())], keywords=[])),
                        Assign(targets=[Name(id=D, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=B, ctx=ast.Load()), Name(id=B2, ctx=ast.Load())], keywords=[])),
                        Assign(targets=[Name(id=E, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=D2, ctx=ast.Load()), Name(id=C2, ctx=ast.Load())], keywords=[])),
                        Assign(targets=[Name(id=F, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=A3, ctx=ast.Load()), Name(id=B3, ctx=ast.Load())], keywords=[])),
                        Assign(targets=[Name(id=G, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=E2, ctx=ast.Load()), Name(id=F2, ctx=ast.Load())], keywords=[])),
                        Assign(targets=[Name(id=H, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=G2, ctx=ast.Load()), Name(id=G3, ctx=ast.Load())], keywords=[])),
                    *rest] if A == A2 == A3 and B == B2 == B3 and C == C2 and D == D2 and E == E2 and F == F2 and G == G2 == G3:
                    node.body[i] = None
                    node.body[i+1] = None
                    node.body[i+2] = None
                    node.body[i+3] = None
                    node.body[i+4] = None
                    new_assign = Assign(targets=[Name(id=H, ctx=ast.Store())], value=Call(func=Name(id='Xor', ctx=ast.Load()), args=[Name(id=A, ctx=ast.Load()), Name(id=B, ctx=ast.Load())], keywords=[]))
                    ast.fix_missing_locations(new_assign)
                    node.body[i+5] = new_assign
                case [Assign(targets=[Name(id=C, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=A, ctx=ast.Load()), Name(id=A2, ctx=ast.Load())], keywords=[])),
                        Assign(targets=[Name(id=D, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Constant(value=0), Constant(value=0)], keywords=[])),
                        Assign(targets=[Name(id=E, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=D2, ctx=ast.Load()), Name(id=C2, ctx=ast.Load())], keywords=[])),
                        Assign(targets=[Name(id=F, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=A3, ctx=ast.Load()), Constant(value=0)], keywords=[])),
                        Assign(targets=[Name(id=G, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=E2, ctx=ast.Load()), Name(id=F2, ctx=ast.Load())], keywords=[])),
                        Assign(targets=[Name(id=H, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=G2, ctx=ast.Load()), Name(id=G3, ctx=ast.Load())], keywords=[])),
                    *rest] if A == A2 == A3 and C == C2 and D == D2 and E == E2 and F == F2 and G == G2 == G3:
                    node.body[i] = None
                    node.body[i+1] = None
                    node.body[i+2] = None
                    node.body[i+3] = None
                    node.body[i+4] = None
                    new_assign = Assign(targets=[Name(id=H, ctx=ast.Store())], value=Call(func=Name(id='Xor', ctx=ast.Load()), args=[Name(id=A, ctx=ast.Load()), Constant(value=0)], keywords=[]))
                    ast.fix_missing_locations(new_assign)
                    node.body[i+5] = new_assign
        return node
    
class ReplaceNandToAndVisitor(ast.NodeTransformer):
    def visit_Module(self, node: Module) -> Any:
        for i in range(len(node.body)):
            match node.body[i:]:
                case [Assign(targets=[Name(id=C, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=A, ctx=ast.Load()), Name(id=B, ctx=ast.Load())], keywords=[])),
                        Assign(targets=[Name(id=D, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=C2, ctx=ast.Load()), Name(id=C3, ctx=ast.Load())], keywords=[])),
                    *rest] if C == C2 == C3:
                    node.body[i] = None
                    new_assign = Assign(targets=[Name(id=D, ctx=ast.Store())], value=Call(func=Name(id='And', ctx=ast.Load()), args=[Name(id=A, ctx=ast.Load()), Name(id=B, ctx=ast.Load())], keywords=[]))
                    ast.fix_missing_locations(new_assign)
                    node.body[i+1] = new_assign
                case [Assign(targets=[Name(id=C, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=A, ctx=ast.Load()), Constant(value=B)], keywords=[])),
                        Assign(targets=[Name(id=D, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=C2, ctx=ast.Load()), Name(id=C3, ctx=ast.Load())], keywords=[])),
                    *rest] if C == C2 == C3:
                    node.body[i] = None
                    new_assign = Assign(targets=[Name(id=D, ctx=ast.Store())], value=Call(func=Name(id='And', ctx=ast.Load()), args=[Name(id=A, ctx=ast.Load()), Constant(value=B)], keywords=[]))
                    ast.fix_missing_locations(new_assign)
                    node.body[i+1] = new_assign
        return node
    
class ReplaceNandToNotVisitor(ast.NodeTransformer):
    def visit_Module(self, node: Module) -> Any:
        for i in range(len(node.body)):
            match node.body[i:]:
                case [Assign(targets=[Name(id=B, ctx=ast.Store())], value=Call(func=Name(id='Nand', ctx=ast.Load()), args=[Name(id=A, ctx=ast.Load()), Name(id=A2, ctx=ast.Load())], keywords=[])),
                    *rest] if A == A2:
                    new_assign = Assign(targets=[Name(id=B, ctx=ast.Store())], value=Call(func=Name(id='Not', ctx=ast.Load()), args=[Name(id=A, ctx=ast.Load())], keywords=[]))
                    ast.fix_missing_locations(new_assign)
                    node.body[i] = new_assign
        return node    
    
class RemoveNoneStatements(ast.NodeTransformer):
    def visit_Module(self, node: Module) -> Any:
        node.body = [x for x in node.body if x is not None]
        return node

# Load the code from a file
with open("decompiled_code.py", "rt") as file:
    code = file.read()

# Parse the code into an AST
ast_tree = ast.parse(code)

# Cleanup the AST
ast_tree = ReplaceVar1Visitor().visit(ast_tree)
ast_tree = CleanupAssignmentsVisitor().visit(ast_tree)
ast_tree = ReplaceAssignVisitor().visit(ast_tree)
ast_tree = ReplaceNameVisitor().visit(ast_tree)

# Replace NAND patterns.

ast_tree = ReplaceNandToXorVisitor().visit(ast_tree)
ast_tree = RemoveNoneStatements().visit(ast_tree)
ast_tree = ReplaceNandToAndVisitor().visit(ast_tree)
ast_tree = ReplaceNandToNotVisitor().visit(ast_tree)
ast_tree = RemoveNoneStatements().visit(ast_tree)

# print(ast.unparse(ast_tree))

statements = []
rows = []
row = [0] * 128
right_side = [0] * 128
right_side_index = 0
var_mapping = dict()

for i in range(16):
    for j in range(8):
        var_mapping[f"flag_{i}_{j}"] = j+i*8

for node in ast_tree.body:
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "And":
        # Stop accumulating statements when we reach an assign statement that has a call on the right-hand side to "And"
        for i in range(len(statements)):
            statement = statements[i]
            id = statement.value.args[0].id
            if id.startswith("_var"):
                right_side[right_side_index] = 0
            else:
                row[var_mapping[id]] = 1
                right_side[right_side_index] = 1
        rows.append(row)
        statements = []
        row = [0] * 128
        right_side_index += 1
        continue
    if node.targets[0].id.startswith("_var"):
        statements.append(node)

from sage.all import *

F = GF(2)
vec = vector(F, right_side)
mat = matrix(F, rows)
sol = mat.solve_right(vec)

print(int("".join(map(str, reversed(sol))), 2).to_bytes(16, "little"))