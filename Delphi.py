from idc      import *
from idaapi   import *
from idautils import *


addr = 0
EP = 0

def get_ret(addr):
  out = addr
  count = 0
  while True:
    # check for ret 
    if Byte(out) != 0xc3: 
        out += 1
        count +=1
    else:
        break    
    if count > 100:    
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
            func_name = idc.GetString(GetRegValue("EDX")+1 , Byte(GetRegValue("EDX")), STRTYPE_C)
            func_addr = GetRegValue("EAX")
            # add it to the BP list
            idc.AddBpt(func_addr)
            try:
                idc.MakeName(func_addr, "_DE_"+func_name)
            except:
                pass
            
            print "func addr : 0x%x name : %s - EDX = 0x%x" % ( func_addr , func_name , GetRegValue("EDX") )
            idaapi.continue_process()
        if (ea == EP):
            idaapi.continue_process()       
        return 0
    
    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid,
            tid, ea, code))



# main
pattern = FindBinary(0, SEARCH_DOWN, "80 E3 DF 75 ?? 49 75 ?? 8B 46 02 ?? ?? 5B C3");
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
        
        print "Monitor point at 0x%x " % EP
         
        request_run_to(EP)
              
        # Start debugging
        run_requests()   
else:
    print "The Pattern not found"

