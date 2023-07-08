import ida_funcs
import idautils
import ida_kernwin
import ida_idaapi
import ida_ida
import ida_ua
import idc
import idaapi

static_fields = {}
back_funcs = set()
for_funcs = set()
back_ins = set()
for_ins = set()


def get_previous_insn(cur_addr, match):
    global back_ins
    global back_funcs
    back_ins.add(cur_addr)
    back_funcs.add(ida_funcs.get_func(cur_addr))
    prev_addr = idc.prev_head(cur_addr)
    if prev_addr == idc.BADADDR:
        return None
    while idc.print_insn_mnem(prev_addr) not in match:
        back_ins.add(prev_addr)
        back_funcs.add(ida_funcs.get_func(prev_addr))
        prev_addr = idc.prev_addr(prev_addr)
        if prev_addr == idc.BADADDR:
            return None
    return prev_addr


def handle_ldstr(cur_addr):
    result = []
    for ref in idautils.DataRefsFrom(cur_addr):
        string_literal = idc.GetString(
            ref, strtype=idc.STRTYPE_C_16)
        result.append(string_literal)
    return result


def handle_ldsfld(cur_addr):
    fld_name = idc.GetDisasm(cur_addr).split(' ')[-1]
    if fld_name:
        # print(hex(cur_addr) + idc.GetDisasm(cur_addr) + fld_name)
        return static_fields[fld_name]
    else:
        return None


def handle_ReadByte(cur_addr):
    arg_0 = get_previous_insn(get_previous_insn(
        cur_addr, ["ldstr", "ldarg"]), ["ldstr"])
    arg_0 = idc.prev_head(idc.prev_head(cur_addr))
    if idc.print_insn_mnem(arg_0) == 'ldstr':
        return handle_ldstr(arg_0)
    else:
        print(
            '[' + hex(arg_0) + '] Could not get string for ReadByte ' + str(idc.GetDisasm(arg_0)))
        return None


def handle_OpenProcess(cur_addr):
    arg_0 = idc.prev_head(cur_addr)
    if idc.print_insn_mnem(arg_0) == 'ldstr':
        return handle_ldstr(arg_0)[0]
    else:
        print(
            '[' + hex(arg_0) + '] Could not get Process Name for OpenProcess ' + str(idc.GetDisasm(arg_0)))
        return None


def handle_FreezeValue(cur_addr):
    # arg_0 = get_previous_insn(get_previous_insn(
    #     get_previous_insn(cur_addr, ["ldstr", "ldsfld"]), ["ldstr", "ldsfld"]), ["ldstr", "ldsfld"])
    arg_0 = get_previous_insn(cur_addr, ['ldsfld'])
    if idc.print_insn_mnem(arg_0) == 'ldsfld':
        return handle_ldsfld(arg_0)
    else:
        print(
            '[' + hex(arg_0) + '] Could not get string for Freeze Value ' + str(idc.GetDisasm(arg_0)))
        return None


def handle_WriteMemory(cur_addr):
    arg_3 = get_previous_insn(cur_addr, ["ldstr", "ldsfld"])
    arg_2 = get_previous_insn(arg_3, ["ldstr", "ldsfld"])
    arg_1 = get_previous_insn(arg_2, ["ldstr", "ldsfld"])
    arg_0 = get_previous_insn(arg_1, ["ldstr", "ldsfld"])
    if idc.print_insn_mnem(arg_0) == 'ldstr':
        return handle_ldstr(arg_0)
    else:
        print(
            '[' + hex(arg_0) + '] Could not get string for WriteMemory ' + str(idc.GetDisasm(arg_0)))
        return None


def find_memory_access(cur_addr, end):
    global addresses
    global for_ins
    global for_funcs
    addresses = []
    while cur_addr < end:
        for_ins.add(cur_addr)
        for_funcs.add(ida_funcs.get_func(cur_addr))
        if cur_addr == idc.BADADDR:
            break
        elif idc.print_insn_mnem(cur_addr) in ['call', 'callvirt']:
            func_name = idc.print_operand(cur_addr, 0)
            if 'Memory' in func_name:
                if 'ReadByte' in func_name or 'Read2Byte' in func_name or 'ReadInt' in func_name:
                    res = handle_ReadByte(cur_addr)
                    if res:
                        addresses.append((res, "r"))
                elif 'OpenProcess' in func_name or 'GetProcIdFromName' in func_name:
                    process_name = handle_OpenProcess(cur_addr)
                    if process_name:
                        print("Opened and Attached to process: " + process_name)
                elif 'WriteMemory' in func_name:
                    res = handle_WriteMemory(cur_addr)
                    if res:
                        addresses.append((res, "w"))
                elif 'FreezeValue' in func_name:
                    addr = handle_FreezeValue(cur_addr)
                    if addr:
                        addresses.append((addr, "rw"))
                else:
                    print('[' + hex(cur_addr) + '] Not handled ' + func_name)
        cur_addr = idc.next_head(cur_addr)


def preprocess_static_fields():
    start_addr_range = ida_ida.cvar.inf.min_ea
    end_addr_range = ida_ida.cvar.inf.max_ea
    cur_addr = start_addr_range
    while cur_addr < end_addr_range:

        if cur_addr == idc.BADADDR:
            break

        if idc.print_insn_mnem(cur_addr) in ['stsfld']:
            fld_name = idc.GetDisasm(cur_addr).split(' ')[-1]
            # print("trying to find fld_name value: " + fld_name)
            fld_value = handle_ldstr(
                get_previous_insn(cur_addr, ['ldstr']))
            # print("found static field value: " + str(fld_value))
            static_fields[fld_name] = fld_value
        cur_addr = idc.next_head(cur_addr)


if __name__ == '__main__':
    start_addr_range = ida_ida.cvar.inf.min_ea
    end_addr_range = ida_ida.cvar.inf.max_ea
    oldTo = idaapi.set_script_timeout(0)
    preprocess_static_fields()
    find_memory_access(start_addr_range, end_addr_range)
    for address, type in addresses:
        if address:
            if not isinstance(address, list):
                print('Address Accessed: ' + str(add) + "\t" + str(type))
                continue
            for add in address:
                print('Address Accessed: ' + str(add) + "\t" + str(type))
    print("Forward Instruction: " + str(len(for_ins)))
    print("Forward Function: " + str(len(for_funcs)))
    print("Backward Instruction: " + str(len(back_ins)))
    print("Backward Function: " + str(len(back_funcs)))
