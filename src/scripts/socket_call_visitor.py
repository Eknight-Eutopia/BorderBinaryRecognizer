import idc
import ida_funcs
import ida_name
import ida_hexrays
import ida_nalt

import logging
import json
from utils.utils import get_md5_hex
from utils.logger import get_logger

logger = get_logger(__name__)

DOMAIN_MAP = {
    1: "AF_UNIX",
    2: "AF_INET",
    10: "AF_INET6",
    16: "AF_NETLINK",
    17: "AF_PACKET",
}


class SocketCallVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.results = []

    def visit_expr(self, e):
        if e.op != ida_hexrays.cot_call:
            return 0

        callee = e.x
        if not callee or callee.op != ida_hexrays.cot_obj:
            return 0

        if ida_name.get_ea_name(callee.obj_ea) != "socket":
            return 0

        if len(e.a) < 1:
            return 0

        domain_expr = e.a[0]
        if domain_expr.op == ida_hexrays.cot_num:
            val = domain_expr.n._value
            name = DOMAIN_MAP.get(val, f"UNKNOWN({val})")
            self.results.append((e.ea, val, name))

        return 0


def analyze_function(func_ea):
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except ida_hexrays.DecompilationFailure:
        return []

    # ✅ IDA 9.x 必须检查
    if not cfunc or not cfunc.body:
        return []

    visitor = SocketCallVisitor()
    visitor.apply_to(cfunc.body, None)
    return visitor.results


def find_socket_domains():
    if not ida_hexrays.init_hexrays_plugin():
        logger.error("[!] Hex-Rays not available")
        return

    results = []

    qty = ida_funcs.get_func_qty()
    for i in range(qty):
        func = ida_funcs.getn_func(i)
        if not func:
            continue

        results.extend(analyze_function(func.start_ea))

    logger.debug("\n==== socket(domain) results ====")
    filename = ida_nalt.get_root_filename()
    filepath = ida_nalt.get_input_file_path()
    for ea, val, name in results:
        logger.debug(f"[0x{ea:x}] domain = {name} ({val})")
    ouput_path = idc.ARGV[1]
    with open(ouput_path, "w") as f:
        json.dump(
            [
                {"ea": ea, "val": val, "name": name} for ea, val, name in results
            ],
            f,
            indent=4
        )
    logger.debug(f"\nTotal: {len(results)} socket() calls found")
   
if __name__ == "__main__":
    find_socket_domains()
