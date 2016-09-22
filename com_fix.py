from ctypes import *
import struct
import binascii
import _winreg

CoCreateAddr = None

def get_com_name(clsid):
	#if clsid[0] == '{':
	#	#this is string form guid
	#	pass
	#else:
	#	#this is string hex guid
	#	pass
	p = c_wchar_p()
	b = create_string_buffer(clsid)
	oledll.ole32.ProgIDFromCLSID(byref(b), byref(p))
	return str(p.value)

def imp_cb(ea, name, ord):
	global CoCreateAddr
	if name == 'CoCreateInstance':
		CoCreateAddr =  ea
	
#find CoCreateInstance from imports
def find_cocreate_from_imports():
	nimps = idaapi.get_import_module_qty()
	mod = None
	
	for i in range(nimps):
		name = idaapi.get_import_module_name(i)
		if 'ole' in name:
			mod = i
			break
	
	if mod != None:
		addr = idaapi.enum_import_names(i,imp_cb)
		print(hex(addr))

find_cocreate_from_imports()
if CoCreateAddr != None:
	#print(hex(CoCreateAddr))
	for addr in XrefsTo(CoCreateAddr,flags=0):
		addr = addr.frm
		if GetMnem(addr) == "call":
			print("CoCreateInstance Called from: "+hex(addr))
			called_addr = addr

			addr = idc.PrevHead(addr)
			pcount = 0
			while pcount < 4:
				while GetMnem(addr) != "push":
					addr = idc.PrevHead(addr)
				pcount += 1
				if pcount == 1:
					clsid_addr = addr
				if pcount < 4:
					addr = idc.PrevHead(addr)
			#Get first param pushed which is address of domain
			iid_addr = GetOperandValue(addr,0)
			data_addr = GetOperandValue(clsid_addr,0)
			print("Data address: "+hex(data_addr))
			a = struct.pack('<IHHBBBBBBBB',Dword(data_addr), Word(data_addr+4),Word(data_addr+6),Byte(data_addr+8),Byte(data_addr+9),Byte(data_addr+10),Byte(data_addr+11),Byte(data_addr+12),Byte(data_addr+13),Byte(data_addr+14),Byte(data_addr+15))
			p = c_wchar_p()
			b = create_string_buffer(a)
			oledll.ole32.StringFromCLSID(byref(b),byref(p))
			print("CLSID GUID: " + str(p.value))
			
			p = c_wchar_p()
			b = create_string_buffer(a)
			try:
				oledll.ole32.ProgIDFromCLSID(byref(b), byref(p))
				progname = str(p.value)
				print(progname)
			except:
				progname = "unknown"
				print('unknown')
			
			iid = struct.pack('<IHHBBBBBBBB',Dword(iid_addr), Word(iid_addr+4),Word(iid_addr+6),Byte(iid_addr+8),Byte(iid_addr+9),Byte(iid_addr+10),Byte(iid_addr+11),Byte(iid_addr+12),Byte(iid_addr+13),Byte(iid_addr+14),Byte(iid_addr+15))
			p = c_wchar_p()
			b = create_string_buffer(iid)
			oledll.ole32.StringFromCLSID(byref(b),byref(p))
			iid = str(p.value)
			print("IID GUID: " + iid)
			

			if progname != "unknown":
				service = _winreg.QueryValue(_winreg.HKEY_CLASSES_ROOT, "Interface\\"+iid)
			if progname != "unknown":
				print(service)
				MakeComm(called_addr, service)
