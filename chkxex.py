# simple Atari binary DOS file analyzer
#
# done by Seban/Slight
#
# file is released as addon to Turbo Copy 3/4 stream analyzer & decompressor
#
# >>> Python 3.8.2 was used to test & run this code <<<
#
# .O.	released at 2020.05.17
# ..O
# OOO	>>> Public Domain <<<

import os
import sys

# example cmd-line parameters, needed only when testing inside the IDLE Python IDE
#sys.argv = [sys.argv[0], 'krap_universal_hero.raw.xex']

# check the input args
if (len(sys.argv) < 2):
    print("No input file specified! Exiting.");
    exit(-1)

# get the input filename from command line
input_file_name = sys.argv[1]

# check if file exists
if (os.path.exists(input_file_name) == False):
    print("Input file not found! Exiting!")
    exit(-1)

# get the size of input file
input_file_size = os.path.getsize(input_file_name)

# print-out info about file
print("\nInput file is",input_file_name,"and the file size is", input_file_size, "bytes.\n")

# read data into bytearray
in_data = bytearray( open(input_file_name,"rb").read() )

# chcek header
if (in_data[0] != 0xff) or (in_data[1] != 0xff):
    print("Wrong file header! Atari DOS binary file expected. Exiting.")
    exit(-1)

# initial block count
blk = 1

# zeroize index
idx = 0

# clear fail flag
fail_flag = False

# main processing loop
while (idx < len(in_data)):

    # check if any sensible amount of data is present
    if (len(in_data) - idx) < 2:
        break

    # header analysis loop
    while(True):

        # get header bytes
        hdr_byte_lo = in_data[idx+0]
        hdr_byte_hi = in_data[idx+1]

        # move index 
        idx += 2
            
        # check for header seq 
        if ((hdr_byte_lo == 0xff) and (hdr_byte_hi == 0xff)):
            print("Header is: $%02x%02x" %(hdr_byte_hi,hdr_byte_lo))

            # chcek the data len
            if ((len(in_data) - idx) < 4):
                fail_flag = True
                break
            else:
                continue
        else:
            break

    # chceck the fail flag
    if (fail_flag):
        print("Unexpected end of data during header analysis!")
        break

    # calculate block start
    blk_start = hdr_byte_lo + (256*hdr_byte_hi)

    # calculate end of block        
    blk_end   = in_data[idx+0]+256*in_data[idx+1]

    # move index 
    idx += 2

    # calculate block length
    blk_len   = (blk_end - blk_start) + 1

    # print out the block info
    print("block %03d: $%04x-$%04x ($%04x)" %(blk,blk_start,blk_end,blk_len),end='')

    # check segment for INIT/RUN vectors
    if (
        ((blk_start == 0x2e0) and (blk_end == 0x2e1)) or
        ((blk_start == 0x2e2) and (blk_end == 0x2e3)) or
        ((blk_start == 0x2e0) and (blk_end == 0x2e3))):

        # is this special segment type?
        if ((blk_start == 0x2e0) and (blk_end == 0x2e1)):
            seg_name=" RUN"
        elif ((blk_start == 0x2e2) and (blk_end == 0x2e3)):
            seg_name="INIT"
        else:
            seg_name=" RUN/INIT"

        # print-out the special segment name
        print(" --->",seg_name,end=' ')

        # check if INIT/RUN segment bytes are present
        if ((len(in_data) - idx) >= blk_len):

            # print-out info depends of INIT/RUN block type
            if ((blk_start == 0x2e0) and (blk_end == 0x2e3)):
                print("$%02x%02x/$%02x%02x" %(in_data[idx+1],in_data[idx+0],in_data[idx+3],in_data[idx+2]))
            else:
                print("$%02x%02x" %(in_data[idx+1],in_data[idx+0]))
        else:
            print(" segment malformed! (out of data)")
            fail_flag = True
            break
    else:
        print()

    if (blk_end - blk_start) < 0:
        print("^^^^^^^^^: malformed segment header.")

    # how many data left?
    data_left = (len(in_data) - idx)

    # check the block length vs. data left
    if (data_left < blk_len):
        print("^^^^^^^^^: unexpected end of data at file segment! [missing $%04x byte(s)]" %(blk_len-data_left))
        break

    # move index to next block header
    idx += blk_len

    # increment block number
    blk += 1

# print empty line    
print()

# print out final info message
if (fail_flag):
    print("XEX file is corrupted and has serious errors in structure.")
else:
    print("File",input_file_name,"is OK!")
