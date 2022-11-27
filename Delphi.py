"""
  +---------------------------------------------------------------------------+
  | IDA For Delphi                                                            |
  | IDA Python Script to Get All function names from Event Constructor (VCL)  |
  +---------------------------------------------------------------------------+
      Copyright(c) 2022 - Coldzer0 <Coldzer0 [at] protonmail.ch> @Coldzer0x0
"""
from idc         import *
from idaapi      import *
from idautils    import *
from ida_dbg     import *
from ida_bytes   import *
from ida_ida     import *
from ida_idaapi  import *
from ida_nalt    import *
from ida_kernwin import *
import collections

addr = 0
EP = 0
info = get_inf_structure()

def get_ret(addr):
    out = addr
    count = 0
    while True:
        # check for return 
        if get_byte(out) == 0xc3:
            return out
        else:
            out += 1
            count +=1  
            continue
        if count > 30:    
            out = -1
            break
        out += 1 
    return out
  
class MyDbgHook(DBG_Hooks):

    def dbg_bpt(self, tid, ea):
        global addr
        global Monitor
        
        if (ea == addr):
            ida_dbg.refresh_debugger_memory()
            func_name = ""
            func_addr = 0
            if (info.is_64bit()):
                func_name = ida_bytes.get_strlit_contents(idc.get_reg_value("RDX")+1 , get_byte(idc.get_reg_value("RDX")), ida_nalt.STRTYPE_C)
                func_addr = idc.get_reg_value("RAX")
            elif (info.is_32bit()):
                func_name = ida_bytes.get_strlit_contents(idc.get_reg_value("EDX")+1 , get_byte(idc.get_reg_value("EDX")), ida_nalt.STRTYPE_C)
                func_addr = idc.get_reg_value("EAX")
            else:
                print('Not Supported !')
                return
            # add it to the BP list
            idc.add_bpt(func_addr)
            
            idc.create_insn(func_addr) # Mark as Code if not ..
            funcPtr = ida_funcs.get_func(func_addr)
            if not funcPtr:
                ida_funcs.add_func(func_addr) # Mark as Function if not ..            
            name = "_DE_{}".format(func_name.decode("utf-8")) # DE -> DelphiEvent
            idc.set_name(func_addr, name, SN_NOWARN | SN_NOCHECK | SN_PUBLIC | SN_FORCE)
            
            print("func addr : 0x%x name : %s" % ( func_addr , name ))

            idaapi.continue_process()
        if (ea == EP):
            idaapi.continue_process()       
        return 0
    
    def dbg_process_exit(self, pid, tid, ea, code):
        print(("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid,
            tid, ea, code)))



# main
zero_ea = 0
pattern = ida_idaapi.BADADDR
patterns = ida_bytes.compiled_binpat_vec_t()
encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)

if (info.is_64bit()):
    pattern_text = "80 ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 48 8B ?? ?? 48 8D ?? ?? ?? ?? ?? ?? C3"
    err = ida_bytes.parse_binpat_str(patterns, zero_ea, pattern_text, 16, encoding)
    if not err:
        pattern = ida_bytes.bin_search(zero_ea, ida_ida.inf_get_max_ea(), patterns, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW)       
elif (info.is_32bit()):
    pattern_text = "80 E3 DF 75 ?? 49 75 ?? 8B 46 02 ?? ?? 5B C3"
    err = ida_bytes.parse_binpat_str(patterns, zero_ea, pattern_text, 16, encoding)
    if not err:
        pattern = ida_bytes.bin_search(zero_ea, ida_ida.inf_get_max_ea(), patterns, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW)
else:
    print('Not Supported !')
    exit()

if pattern == ida_idaapi.BADADDR:
    print("The Pattern not found")
    exit()

print("pattern addr : 0x%x" % pattern)
addr = get_ret(pattern)

print("Event Constructor addr : 0x%x" % addr)
if addr > 0:

    idc.add_bpt(addr);
    if ida_dbg.check_bpt(addr) >= 0:
        print("BP add at %x" % addr)
        # set the Dbg hook      
        try:
            if debughook:
                print("Removing previous hook ...")
                debughook.unhook()
        except:
            pass
        
        # Install the debug hook
        debughook = MyDbgHook()
        debughook.hook()
        print("Add new debughook ...")
        
        EP = idc.get_inf_attr(INF_START_IP)
        ida_dbg.add_bpt(EP)
        
        print("Entry point at 0x%x " % EP)
         
        idaapi.run_to(EP)
              
        # Start debugging
        run_requests()   
else:
    print("The Pattern not found")
