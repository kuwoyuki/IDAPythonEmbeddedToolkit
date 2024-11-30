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
# 2024-12-01 - modified to work on IDA 9.x - kuwoyuki (kuwoyuki@cock.li)
#

##############################################################################################
# define_code_functions.py
# Attempts to define the bytes in the user-entered address range as code and then as functions
# based on the user-define smart_prolog and smart_epilog regular expressions for that architecture.
#
# Inputs: 	start_addr: 	Start address for segment to define as data
#			end_addr:		End address for segment to define as data
#			data_type:		Type of data to set segment to (dependent on architecture)
#
##############################################################################################
import re
import idaapi
import ida_kernwin
import ida_ida
import ida_bytes
import ida_search
import ida_funcs
import idc

################### USER DEFINED VALUES ###################
# Enter a regular expression for how this architecture usually begins and ends functions.
# If the architecture does not dictate how to start or end a function use r".*" to allow
# for any instruction

processor_name = ida_ida.inf_get_procname()

if processor_name == "8051":
    # 8051 Architecture Prologue and Epilogue
    smart_prolog = re.compile(r".*")
    smart_epilog = re.compile(r"reti{0,1}")

elif processor_name == "PIC18Cxx":
    # PIC18 Architecture Prologue and Epilogue
    smart_prolog = re.compile(r".*")
    smart_epilog = re.compile(r"return  0")

elif processor_name == "m32r":
    # Mitsubishi M32R Architecture Prologue and Epilogue
    smart_prolog = re.compile(r"push +lr")
    smart_epilog = re.compile(r"jmp +lr.*")

elif processor_name == "TMS32028":
    # Texas Instruments TMS320C28x
    smart_prolog = re.compile(r".*")
    smart_epilog = re.compile(r"lretr")

elif processor_name == "AVR":
    # AVR
    smart_prolog = re.compile(r"push +r")
    smart_epilog = re.compile(r"reti{0,1}")

elif processor_name == "RH850":
    # RH850
    smart_prolog = re.compile(r"prepare \{.*\}, \d")
    smart_epilog = re.compile(r"dispose \d, \{*.\}, [lp]")

elif processor_name == "ARM":
    # ARM
    smart_prolog = re.compile(r"push \{R4,LR\}")
    smart_epilog = re.compile(r"pop \{R4,PC\}")

else:
    print(
        f"[define_code_functions.py] UNSUPPORTED PROCESSOR. Processor = {processor_name} is unsupported. Exiting."
    )
    raise NotImplementedError("Unsupported Processor Type.")

print(
    f"[define_code_functions.py] Processor = {processor_name} -- Reg Expressions Selected. Proceeding."
)
############################################################

def main():
    start_addr = ida_kernwin.ask_addr(
        ida_ida.inf_get_min_ea(),
        "Please enter the starting address for the data to be defined.",
    )
    end_addr = ida_kernwin.ask_addr(
        ida_ida.inf_get_max_ea(),
        "Please enter the ending address for the data to be defined.",
    )

    if (
        start_addr is None
        or end_addr is None
        or start_addr == idc.BADADDR
        or end_addr == idc.BADADDR
    ):
        print(
            "[make_code_functions.py] Quitting. Entered address values are not valid."
        )
        return

    do_make_unk = ida_kernwin.ask_yn(
        0, "Do you want to make all of the code block UNKNOWN first?"
    )

    if do_make_unk == -1:  # User cancelled
        return

    if do_make_unk == 1:
        curr_addr = start_addr
        while curr_addr < end_addr:
            ida_bytes.del_items(curr_addr, idc.DELIT_SIMPLE)
            curr_addr += 1

    curr_addr = start_addr
    print(
        f"[make_code_functions.py] Running script to define code and functions on 0x{start_addr:x} to 0x{end_addr:x}"
    )

    # First pass: Convert unknown bytes to code
    while curr_addr < end_addr:
        next_unexplored = ida_search.find_unknown(curr_addr, idaapi.SEARCH_DOWN)
        idc.create_insn(next_unexplored)
        curr_addr = next_unexplored

	# Finished attempting to make all unexplored bytes into code
	# Now, attempt to create functions of all code not currently in a function
    print(
        "[make_code_functions.py] Completed attempting to define bytes as code. Now trying to define functions."
    )
    curr_addr = start_addr
    while curr_addr != idc.BADADDR and curr_addr < end_addr:
        if (
            ida_bytes.is_code(ida_bytes.get_full_flags(curr_addr))
            and idc.get_func_attr(curr_addr, idc.FUNCATTR_START) == idc.BADADDR
        ):

            if smart_prolog.match(
                idc.generate_disasm_line(curr_addr, 0)
            ) or smart_epilog.match(
                idc.generate_disasm_line(idc.prev_head(curr_addr), 0)
            ):

                if ida_funcs.add_func(curr_addr):
                    curr_addr = idc.get_func_attr(curr_addr, idc.FUNCATTR_END)
                    continue

        curr_addr = idc.next_head(curr_addr)


if __name__ == "__main__":
    main()
