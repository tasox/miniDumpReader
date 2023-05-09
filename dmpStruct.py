from WindowsMinidump import *
from datetime import *
import pandas as pd
import argparse
import sys
import yara
import os
from pathlib import Path
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import logging

_memRanges = []
_replacements = [b"\x00",b"\x0f",b"\x1e",b"\x7f",b"\x10"]
_saveStrings = 'memoryStrings.txt'
#_saveStringHex = 'memoryStringHex.txt'
fo = open(_saveStrings,'w+')

def sysInfo(processStreams):

     for x in processStreams:
        streamTypeStr = str(x.stream_type)

        if streamTypeStr == "StreamTypes.system_info":
            """
                Useful col: 'ofs_service_pack', 'os_build', 'os_platform', 'os_suite_mask', 'os_type', 'os_ver_major', 'os_ver_minor', 'reserved2', 'service_pack'
            """
            print(f"{Fore.GREEN}[+] System Information ...{Style.RESET_ALL}")
            osBuild = x.data.os_build
            osPlatform = x.data.os_platform
            osVerMajor = x.data.os_ver_major
            osVerMinor = x.data.os_ver_minor
            osType = x.data.os_type
            osReserved = x.data.reserved2
            osServicePack = x.data.service_pack

            print(f"Build: {osBuild}")
            print(f"Platform: {osPlatform}")
            print(f"Windows Version: {osVerMajor}")
            print(f"Type: {osType}")
            print(f"Reserved: {osReserved}")
            print(f"Service Pack: {osServicePack}")
            print("=======\n")

            #fo.write("[+] System Information ...\n")
            #fo.write(f"Build: {osBuild}\n")
            #fo.write(f"Platform: {osPlatform}\n")
            #fo.write(f"Windows Version: {osVerMajor}\n")
            #fo.write(f"Type: {osType}\n")
            #fo.write(f"Reserved: {osReserved}\n")
            #fo.write(f"Service Pack: {osServicePack}\n")
            #fo.write("==============")

def pmemoryList(processStreams,hex=False):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)

        if streamTypeStr == "StreamTypes.memory_list":
            pMemoryRanges = x.data.mem_ranges
            #print("[+] Process Information ...")
            fo.write("[+] Process Information ...")
            for pMemoryRange in pMemoryRanges:
                processMemoryRange = pMemoryRange.addr_memory_range
                if processMemoryRange not in _memRanges:
                    _memRanges.append(processMemoryRange)
                    processMemoryData = pMemoryRange.memory.data
                    processMemoryDataDecoded = processMemoryData.decode("utf-8",errors="ignore")
                    df = pd.Series(processMemoryDataDecoded)
                    for i in _replacements:
                        rep = i.decode("utf-8",errors="ignore")
                        df[0] = df[0].replace(rep,'').replace('\n','')
                    processMemoryDataLength = pMemoryRange.memory.len_data

                    #print(f"Process memory range: {processMemoryRange}")
                    #print(f"> Data length (Bytes): {processMemoryDataLength}")
                    #print(f"> Process Data (Raw): {processMemoryData}")
                    #print(f"> Process Data (Decoded): {df[0].strip()}")
                    #print("=======")

                    fo.write(f"Process memory range: {processMemoryRange}\n")
                    fo.write(f"> Data length (Bytes): {processMemoryDataLength}\n")
                    if hex:
                        fo.write(f"> Process Data (Raw): {processMemoryData}\n")
                    fo.write(f"> Process Data (Decoded): {df[0].strip()}\n")
                    fo.write("================\n")
   
def pmoduleList(processStreams,hex=False):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)

        if streamTypeStr == "StreamTypes.module_list":
            #print("[+] Process Module list ...")
            fo.write("[+] Process Module list ...")

            pModuleList = x.data
            pModuleListDecoded = x.data.decode("utf-8",errors="ignore")
            df = pd.Series(pModuleListDecoded)
            for i in _replacements:
                rep = i.decode("utf-8",errors="ignore")
                df[0] = df[0].replace(rep,'').replace('\n','')
            #print(f"Process Module list: {pModuleList}")
            #print(f"Process Module list (Decoded): {df[0].strip()}")
            #print("=======")
            if hex:
                fo.write(f"Process Module list (Raw): {pModuleList}\n")
            fo.write(f"Process Module list (Decoded): {df[0].strip()}\n")
            fo.write("================\n")

def pfunctionTable(processStreams,hex=False):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)

        if streamTypeStr == "StreamTypes.function_table":
            #print(f"{Fore.GREEN}[+] Function table ...{Style.RESET_ALL}")
            fo.write("[+] Function table ...")

            pFunctionTable = x.data
            pFunctionTableDecoded = pFunctionTable.decode("utf-8",errors="ignore")
            df = pd.Series(pFunctionTableDecoded)
            for i in _replacements:
                rep = i.decode("utf-8",errors="ignore")
                df[0] = df[0].replace(rep,'').replace('\n','')
            #print(f"Process Function table: {pFunctionTable}")
            #print(f"Process Function table (Decoded): {df[0].strip()}")
            #print("=======")
            if hex:
                fo.write(f"Process Function table (Raw): {pFunctionTable}\n")
            fo.write(f"Process Function table (Decoded): {df[0].strip()}\n")
            fo.write("================\n")
            #print("\n")

def pThreadList(processStreams,hex=False):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)

        if streamTypeStr == "StreamTypes.thread_list":
            pThreads = x.data.threads
            print(f"{Fore.GREEN}[+] Threads Information ...{Style.RESET_ALL}")
            fo.write("[+] Threads Information ...")
            numThreads = x.data.num_threads
            print(f"Total Threads: {numThreads}")
            for pThread in pThreads:
                """
                Useful col: 'stack', 'suspend_count', 'teb', 'thread_context', 'thread_id'
                """
                tID = pThread.thread_id
                teb = pThread.teb
                suspend = pThread.suspend_count
                memoryRange = pThread.stack.addr_memory_range
                dataLength = pThread.stack.memory.len_data
                threadMemoryData = pThread.stack.memory.data
                threadMemoryDataDecoded = threadMemoryData.decode("utf-8",errors="ignore")
                df = pd.Series(threadMemoryDataDecoded)
                for i in _replacements:
                    rep = i.decode("utf-8",errors="ignore")
                    df[0] = df[0].replace(rep,'').replace('\n','')
                
                print(f"> Thread Environment Block(TEB): {teb}")
                print(f"> Thread ID: {tID}")
                print(f"> Suspended: {suspend}")
                print(f"> Thread memory range: {memoryRange}")
                print(f"> Data length (Bytes): {dataLength}")
                print("\n")
                #print(f"Data: {threadMemoryData}")
                #print(f"Data (Decoded): {df[0].strip()}")
                
                fo.write(f"Thread Environment Block(TEB): {teb}\n")
                fo.write(f"Thread ID: {tID}\n")
                fo.write(f"Suspended: {suspend}\n")
                fo.write(f"Thread memory range: {memoryRange}\n")
                fo.write(f"Data length (Bytes): {dataLength}\n")
                if hex:
                    fo.write(f"Data (Raw): {threadMemoryData}\n")
                fo.write(f"Data (Decoded): {df[0].strip()}\n")
                fo.write("================\n")

def handleData(processStreams,hex=False):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)
        if streamTypeStr == "StreamTypes.handle_data":
            #print(f"{Fore.GREEN}[+] Handle Data ...{Style.RESET_ALL}")
            fo.write("[+] Handle Data ...\n")
            if hex:
                fo.write(f"Process Handle Data (Raw): {x.data}\n")
            handleDataDecoded = x.data.decode("utf-8",errors="ignore")
            fo.write(f"Process Handle Data (Decoded): {handleDataDecoded}\n")
            fo.write("=======\n")


def systemMemoryInfo(processStreams,hex=False):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)
        if streamTypeStr == "StreamTypes.system_memory_info":
            #print(f"{Fore.GREEN}[+] System Memory Info ...{Style.RESET_ALL}")
            fo.write("[+] System Memory Info ...\n")
            if hex:
                fo.write(f"System Memory Info (Raw): {x.data}\n")
            systemMemoryInfoDecoded = x.data.decode("utf-8",errors="ignore")
            fo.write(f"System Memory Info (Decoded): {systemMemoryInfoDecoded}\n")
            fo.write("=======\n")

def threadNames(processStreams,hex=False):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)

        if streamTypeStr == "StreamTypes.thread_names":
            #print(f"{Fore.GREEN}[+] Thread Names ...{Style.RESET_ALL}")
            fo.write("[+] Thread Names ...\n")
            threadNamesDecoded = x.data.decode("utf-8",errors="ignore")
            if hex:
                fo.write(f"Thread Names (Raw): {x.data}\n")
            fo.write(f"Thread Names (Decoded): {threadNamesDecoded}\n")
            fo.write("=======\n")

def unused(processStreams,hex=False):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)

        if streamTypeStr == "StreamTypes.unused":
            unused = x.data.decode("utf-8",errors="ignore")
            #print(f"Unused (Decoded): {unused}")

def token(processStreams,hex=False):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)

        if streamTypeStr == "StreamTypes.token":
            #print(f"{Fore.GREEN}[+] Token Information ...{Style.RESET_ALL}")
            fo.write("[+] Token Information ...\n")
            token = x.data.decode("utf-8",errors="ignore")
            if hex:
                fo.write(f"Token (Raw): {x.data}\n")
            fo.write(f"Token (Decoded): {token}\n")
            fo.write("=======\n")

def mem64(processStreams,hex=False):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)

        if streamTypeStr == "StreamTypes.memory_64_list":
            #print(f"{Fore.GREEN}[+] Memory x64 list ...{Style.RESET_ALL}")
            fo.write("[+] Memory x64 list ...\n")
            if hex:
                fo.write(f"Memory x64 list (Raw): {x.data}\n")
            mem64 = x.data.decode("utf-8",errors="ignore")
            fo.write(f"Memory x64 list (Decoded): {mem64}\n")
            fo.write("=======\n")

def miscInfo(processStreams):

    for x in processStreams:
        streamTypeStr = str(x.stream_type)

        if streamTypeStr == "StreamTypes.misc_info":
            """
            Useful col: 'process_create_time', 'process_id', 'process_kernel_time', 'process_user_time'
            """

            pID = x.data.process_id
            pCreationTime = datetime.fromtimestamp(x.data.process_create_time)
            print("\n")
            print(f"{Fore.GREEN}[+] Process Information ....{Style.RESET_ALL}")
            print(f"> Process ID: {pID}")
            print(f"> Process Creation Time: {pCreationTime}")
            print("=======\n")

def fileManager(filePath):
    """
    https://www.pythoncheatsheet.org/cheatsheet/file-directory-path
    """
    dir = ''
    file = ''
    if filePath:
        # Check if is file
        if os.path.isfile(filePath):
            file = filePath
        # Check if is dir    
        elif not os.path.isfile(filePath):
            dir = filePath
        
    return dir,file

def yaraScanner(file,dir,dmpFile):

    rules = ''
    if file and not dir:
        rules = yara.compile(filepaths={'namespace1':file})

    elif dir and not file:
        _rules = {}
        c = 1
        # Listing directory
        for f in Path(dir).iterdir():
            _rules.update({'namespace'+str(c):f.as_posix()})
            c +=1
        try:
            rules = yara.compile(filepaths=_rules)
        except Exception as e: pass

    if rules:
        matches = rules.match(dmpFile,callback=console)

        return matches


def console(message):
    """
    https://yara.readthedocs.io/en/stable/yarapython.html
    """
    if message['matches'] == True:
        print(f"Matches: {message['matches']}")
        print(f"Rule Name: {message['rule']}")
        print(f"Strings: {message['strings']}")
        print("=====")

def main():

    parser = argparse.ArgumentParser(description="[*] Usage: dmpStruct.py -f <*.dmp>")
    parser.add_argument("-f","--file",action="store",help="Provide a DMP file (minidump)")
    parser.add_argument("-X","--hex",action="store_true",help="Writing data in hex into memoryStrings.txt")
    parser.add_argument("-y","--yara",action="store",help="Yara rule(s) directory or file.")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        print(parser.print_help())
    else:

        if args.file:
            try:
                data = WindowsMinidump.from_file(args.file)
            except Exception as e:
                raise(f"[-] Error::{e}")
        
        dir = ''
        file = ''
        if args.file and args.yara:
            try:
                dir,file = fileManager(args.yara)
            except Exception as e:
                raise(f"[-] Error::{e}")

        magic1 = data.magic1
        magic2 = data.magic2
        flags = data.flags
        nstreams = data.num_streams
        memory_dumped_date = datetime.fromtimestamp(data.timestamp)
        processStreams = data.streams

        miscInfo(processStreams)
        sysInfo(processStreams)
        if (dir or file) and args.file:
            print(f"{Fore.GREEN}[+] Yara scanner ... {Style.RESET_ALL}")
            yaraScanner(file,dir,args.file)
            print("\n")
        pmemoryList(processStreams,args.hex)
        pmoduleList(processStreams,args.hex)
        pfunctionTable(processStreams,args.hex)
        pThreadList(processStreams,args.hex)
        handleData(processStreams,args.hex)
        systemMemoryInfo(processStreams,args.hex)
        threadNames(processStreams,args.hex)
        token(processStreams,args.hex)
        #unused(processStreams,args.hex)

if __name__ == "__main__":
    main()
    colorama_init()
