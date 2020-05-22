import sys
import os 
import argparse
import random
import string
import struct
import math
banner="""\033[1m\33[33m

      .o  ooooo      ooo    oooo   .oooo.     .oooooo.   ooooooooooooo   .oooo.   ooooooooo.   
    o888  `888b.     `8'    `888 .dP""Y88b   d8P'  `Y8b  8'   888   `8  d8P'`Y8b  `888   `Y88. 
     888   8 `88b.    8      888       ]8P' 888               888      888    888  888   .d88' 
     888   8   `88b.  8      888     <88b.  888               888      888    888  888ooo88P'  
     888   8     `88b.8      888      `88b. 888               888      888    888  888`88b.    \033[0m\033[1m\33[34m
     888   8       `888      888 o.   .88P  `88b    ooo       888      `88b  d88'  888  `88b.  
    o888o o8o        `8  .o. 88P `8bd88P'    `Y8bood8P'      o888o      `Y8bd8P'  o888o  o888o 
                         `Y888P                                            \033[0m\033[1m\33[31m- by DARING JOKER \033[0m
"""
print(banner)
# normal logging behaviour
def printinfo(msg):
    print("\033[1m\33[33m[!] "+msg+"\033[0m")

def printsuccess(msg):
    print("\033[1m\33[34m[+] "+msg+"\033[0m")

def printfailure(msg):
    print("\033[1m\33[31m[-] "+msg+"\033[0m")

# Parsing the command line arguments
parser=argparse.ArgumentParser(description="Inject new Section to a pre-existing binary",epilog="CODED BY DARINGJOKER")
parser.add_argument("-t","--target",help="Path of the target executable to inject the code into.",required=True)
parser.add_argument("-p","--payload",help="path of the payload to inject into the pe file",required=True)
parser.add_argument("-n","--name",help="Name of the section to inject into executable\nUses a randomly generated name if not provided any.")
parser.add_argument("-d","--dump_on_exec",help="dump the payload on execute",action="store_true")
parser.add_argument("-r","--replace",help="repalace the original file with the injected file",action="store_true")
args=parser.parse_args()

#filtering and tuning the commandline arguments to make them useable
if (not args.name):
    args.name= "".join(random.choices(string.digits+string.ascii_letters,k=4+random.randint(0,4)))
elif(len(args.name)>8):
    args.name=args.name[:8]

#reading the target binary to read for diffrent parameters out of it
with open(args.target,"rb") as target:
    tdata=target.read()

#some helper functions to use with the injection process
def readWord(offset):
    return struct.unpack("<H",tdata[offset:offset+2])[0]


def readDword(offset):
    return struct.unpack("<L",tdata[offset:offset+4])[0]


def readDwords(offset,n):
    return struct.unpack("<"+"L"*n,tdata[offset:offset+4*n])


def readByte(offset):
    return struct.unpack("<B",tdata[offset:offset+1])[0]


def readbytes(offset,n):
    return list(struct.unpack("<"+"B"*n,tdata[offset:offset+n]))


def readStringn(offset,n):
    txt=""
    for x in range(n):
        char=struct.unpack("<B",tdata[offset+x:offset+x+1])[0]
        if char in map(ord,string.printable) and char!=0:
            txt+=chr(char)
        else:
            break
    return txt


def writeDword(offset,data):
    global tdata
    dat=struct.pack("<L",data)
    tdata=tdata[:offset]+dat+tdata[offset+4:]


def writeData(offset,data):
    global tdata
    l=len(data)
    tdata=tdata[:offset]+data+tdata[offset+l:]

#reading in several values from the target binary 

mzsignature=readWord(0x00) #the MZ signature at beginning of the file
peoffset=readDword(0x3c)   #the offset to the pe header from the beginning of the file
pesignature=readDword(peoffset+0x00) #The PE signature 
is_pefle=mzsignature==0x5a4d and pesignature==0x4550 #Boolean to verify if the given file is A PE executable
if not is_pefle:
    printfailure("The given target file is not a valid PE ... CAN NOT INJECT\nExiting...")
    sys.exit(0)
else:
    printsuccess("PE File Verification Successful..")
    noSections=readWord(peoffset+0x06) #no of sections present in the pe file currently
    imagebase=readDword(peoffset+0x34)  #the preferred base address of the binary
    sectionAlignment=readDword(peoffset+0x38) #the value to which the sections are aligned in memory(RAM)
    fileAlignment=readDword(peoffset+0x3c)    #the value to which the sections are aligned in disk (PEFILE)
    szoptionalhdr=readWord(peoffset+0x14)

    printsuccess("Successfully parsed the given target file with following information")
    print("PE Header Offset:",hex(peoffset),"\nImage Base:",hex(imagebase),"\nSection Alignment:",sectionAlignment,"(",hex(sectionAlignment),")")
    print("File Alignment:",fileAlignment,"(",hex(fileAlignment),")","\nNo of sections:",noSections)
     
    lastSoffset=peoffset+0x18+szoptionalhdr+(noSections-1)*0x28 #the offset to the last sections currently in the file
    lastSname=readStringn(lastSoffset,8)
    
    printsuccess("Successfully parsed last section offset")
    print("last section offset:",hex(lastSoffset),"\nlast Section name:",lastSname)
    lastSvirtualSize,lastSvirtualAddress,lastSrawSize,lastSrawAddress=readDwords(lastSoffset+0x08,4) #various fields in the last section currently
    
    #calculating the header value for new section header
    payload_size=os.stat(args.payload).st_size
    
    printinfo("Found the payload file with size : "+str(payload_size/1024)+" KB")
   
    payload_virtualAddress=lastSvirtualAddress+math.ceil(lastSvirtualSize/sectionAlignment)*sectionAlignment 
    payload_rawAddress=lastSrawAddress+math.ceil(lastSrawSize/fileAlignment)*fileAlignment
    payload_rawSize=math.ceil(payload_size/fileAlignment)*fileAlignment
    payload_virtualSize=math.ceil(payload_size/sectionAlignment)*sectionAlignment
    payload_characterstics=0xe0000060
    
    
    printsuccess("successfully calculated the new header fields")
    print("New Section Name:",args.name)
    print("Virtual address:",hex(payload_virtualAddress),"\nVirtual Size:",hex(payload_virtualSize),"\nRaw Size:",hex(payload_rawSize))
    print("Raw Address:",hex(payload_rawAddress),"\nCharacterstics:",hex(payload_characterstics))
    
    
    #preparing the new data to write into the file
    sectionheader=bytearray(args.name.encode("utf-8")+b"\x00"*(8-len(args.name)))+struct.pack("<LLLLLLLL",payload_virtualSize,payload_virtualAddress,payload_rawSize,payload_rawAddress,0,0,0,payload_characterstics)
    newsize=payload_virtualAddress+payload_virtualSize
    noSections+=1
    with open(args.payload,"rb") as payload:
        pdata=payload.read()
   
   
    printinfo("The values to be written are")
    print("Section Header:"," ".join([str(hex(x))[2:] for x in sectionheader]),"\nSection Header Length:",len(sectionheader),"( "+str(hex(len(sectionheader)))+" )","\nNew file size:",newsize,"\nNo of sections(updated):",noSections)
    
    
    writeDword(peoffset+0x50,newsize)
    writeDword(peoffset+0x06,noSections)
    writeData(lastSoffset+0x28,sectionheader)
    pdata=pdata+b"\x00"*(payload_rawSize-len(pdata))
    tdata=tdata+pdata
    if not args.replace:
        newname="".join(args.target.split(".")[:-1])+"_mod.exe"
    else:
        newname=args.target
    with open(newname,"wb") as outfile:
        outfile.write(tdata)
    
    printsuccess("payload injection successful...")