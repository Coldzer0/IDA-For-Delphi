import idc
import idaapi
import idautils
import collections

addr = 0
EP = 0
info = idaapi.get_inf_structure()

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
            ida_dbg.refresh_debugger_memory	()
            func_name = ""
            func_addr = 0
            if (info.is_64bit()):
                func_name = idc.get_strlit_contents(idc.get_reg_value("RDI") , int(idc.get_reg_value("RDI")-4), strtype=ida_nalt.STRTYPE_C_16)
                func_addr = idc.get_reg_value("RAX")
            elif (info.is_32bit()):
                func_name = idc.get_strlit_contents(idc.get_reg_value("EDX")+1 , get_byte(idc.get_reg_value("EDX")), ida_nalt.STRTYPE_C)
                func_addr = idc.get_reg_value("EAX")
            else:
                print('Not Supported !')
            # add it to the BP list
            idc.add_bpt(func_addr)
            try:
                idc.create_insn(func_addr) # Mark as Code if not ..
                ida_funcs.add_func(func_addr) # Mark as Function if not ..
                idc.set_name(func_addr, "_DE_"+func_name, idc.SN_NOWARN)
            except:
                pass
            
            print("func addr : 0x%x name : %s" % ( func_addr , func_name ))
            idaapi.continue_process()
        if (ea == EP):
            idaapi.continue_process()       
        return 0
    
    def dbg_process_exit(self, pid, tid, ea, code):
        print(("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid,
            tid, ea, code)))



# main

if (info.is_64bit()):
    pattern = idc.find_binary(0, SEARCH_DOWN, "80 ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 48 8B ?? ?? 48 8D ?? ?? ?? ?? ?? ?? C3");
elif (info.is_32bit()):
    pattern = idc.find_binary(0, SEARCH_DOWN, "80 E3 DF 75 ?? 49 75 ?? 8B 46 02 ?? ?? 5B C3");
else:
    print('Not Supported !')
    pattern = 0

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
