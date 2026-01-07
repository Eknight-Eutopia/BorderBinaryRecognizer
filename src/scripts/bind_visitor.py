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

class MemWrite:
    def __init__(self, base, offset, value):
        self.base = base        # cot_var / cot_obj
        self.offset = offset    # int
        self.value = value      # cexpr_t

def peel_to_base_offset(expr):
    offset = 0
    cur = expr
    print(f"[*] cur op: {ida_hexrays.get_ctype_name(cur.op)}")
    while True:
        # *(...)
        if cur.op == ida_hexrays.cot_ptr:
            cur = cur.x
            continue

        # (type)expr
        if cur.op == ida_hexrays.cot_cast:
            cur = cur.x
            continue

        # &expr
        if cur.op == ida_hexrays.cot_ref:
            cur = cur.x
            continue

        # base + off
        if cur.op == ida_hexrays.cot_add:
            if cur.y.op == ida_hexrays.cot_num:
                offset += cur.y.numval()
                cur = cur.x
                continue
            return None

        # array index
        if cur.op == ida_hexrays.cot_idx:
            if cur.y.op != ida_hexrays.cot_num:
                return None

            idx = cur.y.numval()
            t = cur.x.type

            if t.is_array() and t.get_array_element().get_size() == 1:
                offset += idx
            else:
                elem_size = t.get_array_element().get_size()
                offset += idx * elem_size
            cur = cur.x
            continue

        # struct field / memory reference
        if cur.op == ida_hexrays.cot_memref:
            # memref.x 是 base，memref.m 是成员偏移
            offset += cur.m
            cur = cur.x
            continue

        break
    print(f"[*] cur.op: {ida_hexrays.get_ctype_name(cur.op)}, offset: {offset}")
    return cur, offset

def as_mem_write(asg):
    lhs, rhs = asg.x, asg.y
    bo = peel_to_base_offset(lhs)
    if not bo:
        return None

    base, offset = bo
    return MemWrite(base=base, offset=offset, value=rhs)


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
        sockaddr = None
        for asg in self.assignments:
            print(f"[*] addr: {hex(asg.ea)}")
            mw = as_mem_write(asg)
            if not mw:
                continue

            base, offset, rhs = mw.base, mw.offset, mw.value
            print(f"[*] base.op, base.v: {ida_hexrays.get_ctype_name(base.op)}, {base.v}")
            if get_var(base) != var:
                continue
            print(f"[*] rhs.op: {ida_hexrays.get_ctype_name(rhs.op)}")
            if rhs.op != ida_hexrays.cot_num:
                continue

            val = rhs.numval()
            if offset == 0:
                family = rev16(val & 0xffff)
                print(f"[*] family: {family}")
                if val & 0xffff0000 != 0:
                    port = rev16(val // 0x10000)
                    print(f"[*] port derived from family: {port}")

            if offset == 2:
                port = rev16(val)
                print(f"[*] port: {port}")

            elif offset == 4:
                ip = dword_to_ip(val)
                print(f"[*] ip: {ip}")


        print(f"[+] IP   : {ip}")
        print(f"[+] Port : {port}")
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
