##############################################################################################
# Copyright 2017 The Johns Hopkins University Applied Physics Laboratory LLC
# All rights reserved.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this 
# software and associated documentation files (the "Software"), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, 
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE 
# OR OTHER DEALINGS IN THE SOFTWARE.
#
# 2020-08-07 - modified to work on IDA 7.x - Alexander Pick (alx@pwn.su)
#

##############################################################################################
# define_data_as_types.py
# Defines a segment of addresses as the user-specified data type (byte, word, or double word).
# The byte length for each of these types is architecture dependent, but generally:
#		1 byte  = Byte
#       2 bytes = Word
#		4 bytes = Double Word
# This script with undefine all bytes in the range first which means if you previously had
# code or strings defined in the area, they will be overwritten as data.
#
# Inputs: 	start_addr: 	Start address for segment to define as data
#			end_addr:		End address for segment to define as data
#			data_type:		Type of data to set segment to (dependent on architecture)
#
##############################################################################################

def define_as_data_by_size_for_block(start_addr, end_addr, data_size):
	curr_addr = start_addr
	while (curr_addr < end_addr):
		if (data_size == 1):
			ida_bytes.create_data(curr_addr, FF_BYTE, 1, ida_idaapi.BADADDR)
		elif (data_size == 2):
			ida_bytes.create_data(curr_addr, FF_WORD, 2, ida_idaapi.BADADDR)
		elif (data_size == 4):
			ida_bytes.create_data(curr_addr, FF_DWORD, 3, ida_idaapi.BADADDR)
		elif (data_size == 8):
			ida_bytes.create_data(curr_addr, FF_QWORD, 4, ida_idaapi.BADADDR)
		else:
			Warning("Invalid data_size. Breaking.")
			break
		curr_addr += data_size

start_addr = ida_kernwin.ask_addr(ida_ida.inf_get_min_ea(), "Please enter the starting address for the data to be defined.")
end_addr = ida_kernwin.ask_addr(ida_ida.inf_get_max_ea(),  "Please enter the ending address for the data to be defined.")

if ((start_addr is not None and end_addr is not None) and (start_addr != BADADDR and end_addr != BADADDR) and start_addr < end_addr):
	data_size = ida_kernwin.ask_long(1, "Enter the size of each data item to be defined in the address block.\nExample: '1' for byte, '2' for word, '4' for dword, '8' for qword\nNote the exact implementation will be dependent on architecture.")
	if (data_size == 1 or data_size ==  2 or data_size == 4 or data_size == 8):
		print ("[define_data_as_types.py] STARTING. start_addr: 0x%X, end_addr: 0x%X, data_size: %d" % (start_addr, end_addr, data_size))
		ida_bytes.del_items(start_addr, (end_addr - start_addr), DELIT_SIMPLE)
		print "[define_data_as_types.py] Undefined all data between 0x%X and 0x%0X" % (start_addr, end_addr)
		print "[define_data_as_types.py] Defining all data as size " + str(data_size) 
		define_as_data_by_size_for_block(start_addr, end_addr, data_size)
		print "[define_data_as_types.py] FINISHED."	
	else:
		Warning("[define_data_as_types.py] You entered a size of %d bytes. Please enter 1 (byte), 2 (short/word), 4(long, dword)");	

else:
	print "[define_data_as_types.py] ERROR. Please enter valid address values."