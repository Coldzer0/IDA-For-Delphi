from idc      import *
from idaapi   import *
from idautils import *


addr = 0
EP = 0
info = idaapi.get_inf_structure()

def get_ret(addr):
    out = addr
    count = 0
    while True:
        # check for ret 
        if Byte(out) == 0xc3:
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
            RefreshDebuggerMemory()
            func_name = ""
            func_addr = 0
            if (info.is_64bit()):
                func_name = idc.GetString(GetRegValue("RDI") , int(GetRegValue("RDI")-4), strtype=idaapi.ASCSTR_UNICODE)
                func_addr = GetRegValue("RAX")
            elif (info.is_32bit()):
                func_name = idc.GetString(GetRegValue("EDX")+1 , Byte(GetRegValue("EDX")), STRTYPE_C)
                func_addr = GetRegValue("EAX")
            else:
                print 'Not Supported !'
            # add it to the BP list
            idc.AddBpt(func_addr)
            try:
                idc.MakeCode(func_addr) # Mark as Code if not ..
                idc.MakeFunction(func_addr) # Mark as Function if not ..
                idc.MakeNameEx(func_addr, "_DE_"+func_name, idc.SN_NOWARN)
            except:
                pass
            
            print "func addr : 0x%x name : %s" % ( func_addr , func_name )
            idaapi.continue_process()
        if (ea == EP):
            idaapi.continue_process()       
        return 0
    
    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid,
            tid, ea, code))



# main

if (info.is_64bit()):
    pattern = FindBinary(0, SEARCH_DOWN, "80 ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 48 8B ?? ?? 48 8D ?? ?? ?? ?? ?? ?? C3");
elif (info.is_32bit()):
    pattern = FindBinary(0, SEARCH_DOWN, "80 E3 DF 75 ?? 49 75 ?? 8B 46 02 ?? ?? 5B C3");
else:
    print 'Not Supported !'
    pattern = 0

print "pattern addr : 0x%x" % pattern
addr = get_ret(pattern)

print "Event Constructor addr : 0x%x" % addr
if addr > 0:

    idc.AddBpt(addr);
    if idc.CheckBpt(addr) >= 0:
        print "BP add at %x" % addr
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
        
        EP = GetLongPrm(INF_START_IP)
        idc.AddBpt(EP)
        
        print "Entry point at 0x%x " % EP
         
        request_run_to(EP)
              
        # Start debugging
        run_requests()   
else:
    print "The Pattern not found"

