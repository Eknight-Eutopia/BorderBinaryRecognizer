import ida_funcs
import ida_name
import ida_hexrays

import socket

# from utils.logger import get_logger

# logger = get_logger(__name__)

# ---------------------------------------------------------
# 工具函数
# ---------------------------------------------------------

def dword_to_ip(val):
    b = struct.pack("<I", val)
    return ".".join(str(x) for x in b)

def rev16(v):
    return ((v & 0xff) << 8) | (v >> 8)

def skip_cast(e):
    while e.op == ida_hexrays.cot_cast:
        e = e.x
    return e

def get_ptr_value(e):
    target_op_list = [ida_hexrays.cot_memref, ida_hexrays.cot_ptr, ida_hexrays.cot_var]

def get_var(expr):
    var = None
    if expr.op == ida_hexrays.cot_var:
        var = expr.v
    elif expr.op == ida_hexrays.cot_obj:
        var = expr.obj_ea
    return var

class BindVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.assignments = []
        self.results = []

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_asg:
            self.assignments.append(e)
        if e.op == ida_hexrays.cot_call:
            self.handle_call(e)
        return 0

    def handle_call(self, e):
        callee = e.x
        if callee.op != ida_hexrays.cot_obj:
            return

        name = ida_name.get_ea_name(callee.obj_ea)
        if name != "bind":
            return

        print(f"\n[+] bind() found @ {hex(e.ea)}")

        if len(e.a) < 2:
            return
        # precheck socklen: ipv4: 0x10, ipv6: 0x1c
        socklen = e.a[2]
        if not self.precheck_socklen(socklen):
            return

        sockaddr = e.a[1]
        self.analyze_sockaddr(sockaddr)

    def precheck_socklen(self, expr):
        expr = skip_cast(expr)
        socklen = None
        if expr.op == ida_hexrays.cot_num:
            socklen = expr.numval()
        print(f"socklen: {socklen}")
        return socklen == 0x10 or socklen == 0x1c
    # -----------------------------------------------------

    def analyze_sockaddr(self, expr):
        # 解析变量
        # skip cast
        expr = skip_cast(expr)
        if expr.op == ida_hexrays.cot_ref:
            expr = expr.x

        if expr.op != ida_hexrays.cot_var and expr.op != ida_hexrays.cot_obj:
            print(f"invalid expr op: {ida_hexrays.get_ctype_name(expr.op)}")
            return

        var = get_var(expr)

        print(f"[*] var: {var}")
        ip = None
        port = None
        family = None
        for asg in self.assignments:
            lhs = asg.x
            rhs = asg.y
            print(f"lhs: {lhs}, lhs.op: {lhs.op}, rhs: {rhs}")
            if lhs.op == ida_hexrays.cot_var or lhs.op == ida_hexrays.cot_obj:
                base = lhs
                base_var = get_var(base)
                print(f"[*] base.v: {base_var}")
                if base.v != var:
                    continue
                if rhs.op == ida_hexrays.cot_num:
                    print(f"[*] rhs.num: {rhs.numval()}")
                    port = socket.htons(rhs.numval() // 0x10000)
                    ip = "0.0.0.0"
            # *(var + offset) = value
            elif lhs.op == ida_hexrays.cot_ptr:
                add = lhs.x
                base = None
                off = None
                # skip op cast
                while add.op == ida_hexrays.cot_cast:
                    add = add.x

                if add.op == ida_hexrays.cot_add:
                    base, off = add.x, add.y
                elif add.op == ida_hexrays.cot_ref:
                    assert add.x.op == ida_hexrays.cot_idx
                    base, off = add.x.x, add.x.y
                else:
                    continue

                # recursive retrieve base val
                if base.op == ida_hexrays.cot_memref:
                    assert base.x.op == ida_hexrays.cot_idx
                    base = base.x.x

                if (base.op != ida_hexrays.cot_var and base.op != ida_hexrays.cot_obj) or base.v != var:
                    continue

                if off.op != ida_hexrays.cot_num:
                    continue

                offset = off.numval()

                if rhs.op == ida_hexrays.cot_num:
                    if offset == 0:
                        port = rev16(rhs.numval())
                    elif offset == 2:
                        ip = dword_to_ip(rhs.numval())


        print(f"    IP   : {ip}")
        print(f"    Port : {port}")
        self.results.append((ip, port))

# ---------------------------------------------------------
# 主入口
# ---------------------------------------------------------

def analyze_function(func_ea):
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except ida_hexrays.DecompilationFailure:
        return []

    if not cfunc or not cfunc.body:
        return []

    v = BindVisitor(cfunc)
    v.apply_to(cfunc.body, None)
    return v.results

def find_bind_ipaddr():
    if not ida_hexrays.init_hexrays_plugin():
        print("[-] Hex-Rays not available")

    results = []

    qty = ida_funcs.get_func_qty()
    for i in range(qty):
        func = ida_funcs.getn_func(i)
        if not func:
            continue

        results.extend(analyze_function(func.start_ea))


if __name__ == "__main__":
    find_bind_ipaddr()
