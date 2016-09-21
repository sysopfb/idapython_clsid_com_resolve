#By Jason Reaves
# 20Sep2016


from ctypes import *
import struct
import binascii

CoCreateAddr = None

def get_com_name(clsid):
	#TODO
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
			while GetMnem(addr) != "push":
				addr = idc.PrevHead(addr)
			data_addr = GetOperandValue(addr,0)
			print("Data address: "+hex(data_addr))
			a = struct.pack('<IHHBBBBBBBB',Dword(data_addr), Word(data_addr+4),Word(data_addr+6),Byte(data_addr+8),Byte(data_addr+9),Byte(data_addr+10),Byte(data_addr+11),Byte(data_addr+12),Byte(data_addr+13),Byte(data_addr+14),Byte(data_addr+15))
			p = c_wchar_p()
			b = create_string_buffer(a)
			oledll.ole32.StringFromCLSID(byref(b),byref(p))
			print("GUID: " + str(p.value))
			p = c_wchar_p()
			b = create_string_buffer(a)
			try:
				oledll.ole32.ProgIDFromCLSID(byref(b), byref(p))
				print(str(p.value))
				MakeComm(called_addr, str(p.value))
			except:
				print('unknown')
