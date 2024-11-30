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
# make_strings.py
# Searches the user entered address range for a series of ASCII bytes to define as strings.
# If the continuous series of ASCII bytes has a length greater or equal to minimum_length and
# ends with a character in string_end, the scripts undefines the bytes in the series
# and attempts to define it as a string.
#
# Input: 	start_addr: 	Start address for range to search for strings
# 			end_addr:		End address for range to search for strings
#
##############################################################################################
import ida_kernwin
import ida_ida
import ida_bytes
import ida_nalt
import idc

################### USER DEFINED VALUES ###################
MIN_LENGTH = 5  # Minimum number of characters needed to define a string
STRING_END = [0x00]  # Possible "ending characters" for strings. A string will not be
# defined if it does not end with one of these characters
###########################################################


def make_strings(start_addr, end_addr):
    """
    Search for and create strings in the specified address range.

    Args:
        start_addr: Start address for range to search
        end_addr: End address for range to search
    """
    string_start = start_addr
    num_strings = 0

    print(
        f"[make_strings.py] STARTING. Attempting to make strings with a minimum length of {MIN_LENGTH} "
        f"on data in range 0x{start_addr:x} to 0x{end_addr:x}"
    )

    while string_start < end_addr:
        num_chars = 0
        curr_addr = string_start

        while curr_addr < end_addr:
            byte = idc.get_wide_byte(curr_addr)

            # Check if byte is printable ASCII or common control character
            if (0x20 <= byte < 0x7F) or byte in (0x9, 0xD, 0xA):
                num_chars += 1
                curr_addr += 1
            else:
                if byte in STRING_END and num_chars >= MIN_LENGTH:
                    # Undefine the current range of bytes
                    ida_bytes.del_items(
                        string_start, curr_addr - string_start, ida_bytes.DELIT_SIMPLE
                    )

                    # Try to create a string
                    if ida_bytes.create_strlit(
                        string_start, 0, ida_nalt.STRTYPE_TERMCHR
                    ):
                        print(
                            f"[make_strings.py] String created at 0x{string_start:x} to 0x{curr_addr:x}"
                        )
                        num_strings += 1
                        string_start = curr_addr
                        break
                    else:
                        break
                else:
                    # String does not end with one of the defined "ending characters", does not meet the minimum string length, or is not an ASCII character
                    break

        string_start += 1

    print(
        f"[make_strings.py] FINISHED. Created {num_strings} strings in range 0x{start_addr:x} to 0x{end_addr:x}"
    )


def main():
    """Main function to get user input and run string detection."""
    start_addr = ida_kernwin.ask_addr(
        ida_ida.inf_get_min_ea(),
        "Please enter the starting address for the data to be analyzed.",
    )
    end_addr = ida_kernwin.ask_addr(
        ida_ida.inf_get_max_ea(),
        "Please enter the ending address for the data to be analyzed.",
    )

    if (
        start_addr is None
        or end_addr is None
        or start_addr == idc.BADADDR
        or end_addr == idc.BADADDR
        or start_addr >= end_addr
    ):
        print("[make_strings.py] QUITTING. Entered address values not valid.")
        return

    make_strings(start_addr, end_addr)


if __name__ == "__main__":
    main()
