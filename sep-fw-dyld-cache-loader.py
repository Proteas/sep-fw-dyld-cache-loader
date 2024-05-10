#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-


# 
# Proteas, 2023-02-06
# 


import os
import sys
import traceback

# ida
import idautils
import idaapi
import ida_idaapi
import ida_search
import ida_funcs
import ida_bytes
import ida_idp
import idc
import ida_auto
import ida_segment

import struct
from collections import namedtuple


# Library Search Path
sys.path.append("/usr/local/lib/python3.9/site-packages")

# lief, Version: 0.14.1
import lief
from lief import MachO
####################################################################################################

gDoLog = False
# gDoLog = True
####################################################################################################

####################################################################
#              LOADER MODULE INTERFACE FUNCTIONS                   #
####################################################################

# https://github.com/RolfRolles/HiddenBeeLoader/blob/master/HBLoad.py
# https://github.com/snare/ida-efiutils/blob/master/te_loader.py
# https://github.com/crytic/ida-evm/blob/master/evm-loader.py
# https://github.com/fail0verflow/rl78-ida-proc/blob/master/ps4syscon.py
# https://github.com/mandiant/idawasm/blob/master/idawasm/loader.py
# https://github.com/cseagle/ida_clemency/blob/master/clemency_ldr.py
# https://github.com/matteyeux/srom64helper/blob/master/srom64helper.py
# https://github.com/matteyeux/ida-iboot-loader/blob/main/iboot-loader.py
# https://github.com/nihilus/bflt-utils/blob/master/ida/bfltldr.py
# https://github.com/shuffle2/nxpad/blob/master/brcm_fwpatch_ldr.py
# https://github.com/quarkslab/samsung-trustzone-research/blob/master/scripts/loaders/IDAPro/tbase_loader.py
# https://github.com/bnbdr/ida-bpf-processor/blob/master/bpf_loader.py
# https://github.com/0xEBFE/3DSX-IDA-PRO-Loader/blob/master/3dsx.py
# https://github.com/SocraticBliss/ps3_syscon_loader/blob/master/ps3_syscon.py
# https://github.com/zznop/ida-genesis/blob/master/sg_smd.py

# https://github.com/lief-project/LIEF/blob/master/examples/python/macho_reader.py
# https://lief-project.github.io/doc/latest/api/python/macho.html

# https://bazad.github.io/2018/06/ios-12-kernelcache-tagged-pointers/
# https://gist.github.com/bazad/e11b259855a8ff6195ba17fc35bbc532
# https://github.com/bazad/ida_kernelcache/blob/master/ida_kernelcache/tagged_pointers.py
# https://gist.github.com/bazad/fe4e76a0a3b761d9fde7e74654ac14e4

# demangle
# https://github.com/hthh/switch-reversing/blob/master/loader/hthh_nxo64.py#L886

# load_nonbinary_file, build_loaders_list
# http://www.openrce.org/forums/posts/790

# Calling IDA APIs from IDAPython with ctypes
# https://hex-rays.com/blog/calling-ida-apis-from-idapython-with-ctypes/

####################################################################################################

def accept_file(li, filename):
    li.seek(0, idaapi.SEEK_END)
    size = li.tell()
    li.seek(0)

    if size < 0x4000:
        return 0

    headerData = li.read(0x4000)
    legionTypeStr = GetLegionTypeStr(headerData)
    if legionTypeStr is None:
        return 0

    print("[+] load sep fw: %s" % (filename))
    return {"format": "Apple SEP Firmware", "processor": "arm", "options":1|idaapi.ACCEPT_FIRST}
####################################################################################################

def load_file(li, neflags, format):
    # [+] neflags: 0x95, format: Apple SEP Firmware
    print("[+] neflags: 0x%X, format: %s" % (neflags, format))

    idaapi.set_processor_type("arm", idaapi.SETPROC_LOADER)
    idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT

    bReload = (neflags & idaapi.NEF_RELOAD) != 0
    if bReload:
        return 1

    LoadTypes()
    ParseSEPFirmware_IDA(li)

    return 1
####################################################################################################

def GetStructSize(name):
    stID = idaapi.get_struc_id(name)
    stSize = idaapi.get_struc_size(stID)
    return stSize
####################################################################################################

def CreateStruct(ea, name):
    stID = idaapi.get_struc_id(name)
    stSize = idaapi.get_struc_size(stID)

    ida_bytes.del_items(ea, ida_bytes.DELIT_DELNAMES, stSize)
    ida_bytes.create_data(ea, ida_bytes.FF_STRUCT, stSize, stID)

    return ea + stSize
####################################################################################################

def GetMemberValueFromStruct(ea, stName, mmName):
    stID = idaapi.get_struc_id(stName)
    stRef = idaapi.get_struc(stID)
    mmRef = idaapi.get_member_by_name(stRef, mmName)
    
    mmSize = mmRef.eoff - mmRef.soff
    if mmSize == 8:
        return ida_bytes.get_qword(ea + mmRef.soff)
    elif mmSize == 4:
        return ida_bytes.get_dword(ea + mmRef.soff)
    elif mmSize == 2:
        return ida_bytes.get_word(ea + mmRef.soff)
    elif mmSize == 1:
        return ida_bytes.get_byte(ea + mmRef.soff)
    else:
        print("[-] invalid size: %d" % mmSize)
    
    return -1
####################################################################################################

def LoadTypes():
    idc.add_default_til("macosx64_sdk14")
    idc.add_default_til("iphoneos64_sdk12")

    idc.import_type(-1, "mach_header_64")
    idc.import_type(-1, "load_command")
    idc.import_type(-1, "segment_command_64")
    idc.import_type(-1, "symtab_command")
    idc.import_type(-1, "uuid_command")
    idc.import_type(-1, "source_version_command")
    idc.import_type(-1, "dysymtab_command")
    idc.import_type(-1, "section_64")
    idc.import_type(-1, "thread_command")
    idc.import_type(-1, "dylinker_command")
    idc.import_type(-1, "build_version_command")
    idc.import_type(-1, "linkedit_data_command")
    idc.import_type(-1, "dylib_command")
    idc.import_type(-1, "symseg_command")
    idc.import_type(-1, "entry_point_command")
    idc.import_type(-1, "dylib_command")
    idc.import_type(-1, "encryption_info_command_64")
    # chained fixups
    idc.import_type(-1, "dyld_chained_fixups_header")
    idc.import_type(-1, "dyld_chained_import")
    idc.import_type(-1, "dyld_chained_starts_in_image")
    idc.import_type(-1, "dyld_chained_starts_in_segment")
    idc.import_type(-1, "dyld_chained_ptr_64_rebase")
    idc.import_type(-1, "dyld_chained_ptr_64_bind")
####################################################################################################

LC_SEP                   = 0x8000000
LC_REQ_DYLD              = 0x80000000

LC_SEGMENT               = 0x01
LC_SYMTAB                = 0x02
LC_SYMSEG                = 0x03
LC_UNIXTHREAD            = 0x05
LC_DYSYMTAB              = 0x0B
LC_LOAD_DYLIB            = 0x0C
LC_ID_DYLIB              = 0x0D
LC_LOAD_DYLINKER         = 0x0E
LC_SEGMENT_64            = 0x19
LC_UUID                  = 0x1B
LC_CODE_SIGNATURE        = 0x1D
LC_FUNCTION_STARTS       = 0x26
LC_DATA_IN_CODE          = 0x29
LC_SOURCE_VERSION        = 0x2A
LC_ENCRYPTION_INFO_64    = 0x2C
LC_BUILD_VERSION         = 0x32
LC_MAIN                  = 0x28 | LC_REQ_DYLD
LC_DYLD_EXPORTS_TRIE     = 0x33 | LC_REQ_DYLD
LC_DYLD_CHAINED_FIXUPS   = 0x34 | LC_REQ_DYLD
####################################################################################################

def LoadLiefObjToIDA_Header(li, fileOffset, liefObj, baseAddr, binName, sepFwData, sharedCacheBaseAddr):
    sharedCacheSlide = None

    eaBeginAddr = baseAddr + liefObj.imagebase
    eaEndAddr = baseAddr + liefObj.imagebase + liefObj.sections[0].offset

    segm = idaapi.segment_t()
    segm.bitness = 2  # 64-bit
    segm.start_ea = eaBeginAddr
    segm.end_ea = eaEndAddr
    segm.align = 0
    segm.type = idaapi.SEG_DATA
    segm.perm = ida_segment.SEGPERM_READ

    segName = "%s:%s" % (binName, "HEADER")
    idaapi.add_segm_ex(segm, segName, "DATA", idaapi.ADDSEG_OR_DIE)

    li.file2base(fileOffset, eaBeginAddr, eaEndAddr, True)

    # create structs
    curAddr = eaBeginAddr
    curAddr = CreateStruct(curAddr, "mach_header_64")

    ncmds = liefObj.header.nb_cmds
    for idxSeg in range(ncmds):
        lcAddr = curAddr
        cmd = GetMemberValueFromStruct(lcAddr, "load_command", "cmd")
        if cmd == LC_SEGMENT_64:
            CreateStruct(lcAddr, "segment_command_64")
            nsects = GetMemberValueFromStruct(lcAddr, "segment_command_64", "nsects")
            sectAddr = lcAddr + GetStructSize("segment_command_64")
            for idxSect in range(nsects):
                sectAddr = CreateStruct(sectAddr, "section_64")
        elif cmd == LC_SYMTAB:
            CreateStruct(lcAddr, "symtab_command")
        elif cmd == LC_UNIXTHREAD:
            CreateStruct(lcAddr, "thread_command")
        elif cmd == LC_UUID:
            CreateStruct(lcAddr, "uuid_command")
        elif cmd == LC_SOURCE_VERSION:
            CreateStruct(lcAddr, "source_version_command")
        elif cmd == LC_DYSYMTAB:
            CreateStruct(lcAddr, "dysymtab_command")
        elif cmd == LC_LOAD_DYLINKER:
            CreateStruct(lcAddr, "dylinker_command")
        elif cmd == LC_BUILD_VERSION:
            CreateStruct(lcAddr, "build_version_command")
        elif cmd == LC_CODE_SIGNATURE:
            CreateStruct(lcAddr, "linkedit_data_command")
        elif cmd == LC_LOAD_DYLIB:
            CreateStruct(lcAddr, "dylib_command")
        elif cmd == LC_FUNCTION_STARTS:
            CreateStruct(lcAddr, "linkedit_data_command")
        elif cmd == LC_DATA_IN_CODE:
            CreateStruct(lcAddr, "linkedit_data_command")
        elif cmd == LC_REQ_DYLD | LC_SEGMENT:
            pass
        elif cmd == (LC_REQ_DYLD | LC_SYMSEG):
            CreateStruct(lcAddr, "symseg_command")
        
        # 0x8000001
        elif cmd == (LC_SEGMENT | LC_SEP):
            CreateStruct(lcAddr, "linkedit_data_command")
            dataoff = GetMemberValueFromStruct(lcAddr, "linkedit_data_command", "dataoff")
            datasize = GetMemberValueFromStruct(lcAddr, "linkedit_data_command", "datasize")
            print("[+] 0x8000001, dataoff: 0x%X, datasize: 0x%X" % (dataoff, datasize))
            if dataoff != 0:
                sharedCacheSlide = (dataoff & 0xFFFFF) - 0x8000
            else:
                sharedCacheSlide = 0
        
        # 0x8000002, Cmd Unknown
        elif cmd == (LC_SYMTAB | LC_SEP):
            CreateStruct(lcAddr, "symtab_command")
            symoff = GetMemberValueFromStruct(lcAddr, "symtab_command", "symoff")
            nsyms = GetMemberValueFromStruct(lcAddr, "symtab_command", "nsyms")
            stroff = GetMemberValueFromStruct(lcAddr, "symtab_command", "stroff")
            strsize = GetMemberValueFromStruct(lcAddr, "symtab_command", "strsize")
            print("[+] 0x8000002, symoff: 0x%X, nsyms: %d, stroff: 0x%X, strsize: 0x%X" % (symoff, nsyms, stroff, strsize))
        
        # 0x8000003, Cmd Unknown
        elif cmd == (LC_SYMSEG | LC_SEP):
            CreateStruct(lcAddr, "symseg_command")
            offset = GetMemberValueFromStruct(lcAddr, "symseg_command", "offset")
            size = GetMemberValueFromStruct(lcAddr, "symseg_command", "size")
            print("[+] 0x8000003, offset: 0x%X, size: 0x%X, magic: 0x%X" % (offset, size, offset << 12))
        elif cmd == LC_MAIN:
            CreateStruct(lcAddr, "entry_point_command")
        elif cmd == LC_DYLD_EXPORTS_TRIE:
            dataoff = GetMemberValueFromStruct(lcAddr, "linkedit_data_command", "dataoff")
            datasize = GetMemberValueFromStruct(lcAddr, "linkedit_data_command", "datasize")
            print("[+] 0x%X: LC_DYLD_EXPORTS_TRIE, dataoff: 0x%X, datasize: 0x%X" % (cmd, dataoff, datasize))
            CreateStruct(lcAddr, "linkedit_data_command")
        # https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/common/MachOFile.cpp#L3390
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            dataoff = GetMemberValueFromStruct(lcAddr, "linkedit_data_command", "dataoff")
            datasize = GetMemberValueFromStruct(lcAddr, "linkedit_data_command", "datasize")
            print("[+] 0x%X: LC_DYLD_CHAINED_FIXUPS, dataoff: 0x%X, datasize: 0x%X" % (cmd, dataoff, datasize))
            CreateStruct(lcAddr, "linkedit_data_command")
        elif cmd == LC_ID_DYLIB:
            CreateStruct(lcAddr, "dylib_command")
        elif cmd == LC_ENCRYPTION_INFO_64:
            CreateStruct(lcAddr, "encryption_info_command_64")
        else:
            CreateStruct(lcAddr, "load_command")
            cmdSize = GetMemberValueFromStruct(lcAddr, "load_command", "cmdsize")
            print("[-] Unknown MachO Load Command: 0x%02X, 0x%X" % (cmd, cmdSize))
        curAddr = lcAddr + GetMemberValueFromStruct(lcAddr, "load_command", "cmdsize")

    return sharedCacheSlide
####################################################################################################

def GetSectionRange(liefObj, sectName):
    sectStartAddr = None
    sectEndAddr = None

    for section in liefObj.sections:
        if section.name == sectName:
            sectStartAddr = section.virtual_address
            sectEndAddr = section.virtual_address + section.size
            break;

    return (sectStartAddr, sectEndAddr)
####################################################################################################

def GetTextRange(liefObj):
    return GetSectionRange(liefObj, "__text")
####################################################################################################

def IsTaggedPointer(tgValue, imageBase, sectTextStartAddr, sectTextEndAddr):
    ptType = (tgValue >> 48) & 0xFFFF
    ptTag = (tgValue >> 32) & 0xFFFF
    ptOffset = tgValue & 0xFFFFFFFF

    if (((ptType & 0xF000) != 0x8000) or ((ptType & 0xF000) != 0x9000)):
        return False
    elif ptTag == 0:
        return False
    elif (imageBase + ptOffset) < sectTextStartAddr:
        return False
    elif (imageBase + ptOffset) >= sectTextEndAddr:
        return False
    else:
        return True
####################################################################################################

def UntagPointer(tgValue, imageBase):
    ptOffset = tgValue & 0xFFFFFFFF
    return imageBase + ptOffset
####################################################################################################

def LoadLiefObjToIDA(li, fileOffset, liefObj, baseAddr, binName, sepFwData, sharedCacheBaseAddr):
    sharedCacheSlide = LoadLiefObjToIDA_Header(li, fileOffset, liefObj, baseAddr, binName, sepFwData, sharedCacheBaseAddr)
    if (sharedCacheBaseAddr is not None) and (sharedCacheSlide is not None):
        if gDoLog: print("[+] name: %s, shared cache slide: 0x%X" % (binName, sharedCacheSlide))

    sectTextStartAddr, sectTextEndAddr = GetTextRange(liefObj)
    if gDoLog: print("[+] name: %s, start: 0x%X, end: 0x%X" % (binName, sectTextStartAddr, sectTextEndAddr))

    for section in liefObj.sections:
        segm = idaapi.segment_t()
        segm.bitness = 2  # 64-bit
        eaBeginAddr = baseAddr + section.virtual_address
        eaEndAddr = baseAddr + section.virtual_address + section.size
        segm.start_ea = eaBeginAddr
        segm.end_ea = eaEndAddr
        segm.align = section.alignment
        # print("name: %s, virt: 0x%X, size: 0x%X" % (section.name, section.virtual_address, section.size))
        segName = "%s:%s" % (binName, section.name)
        sectType = section.type
        sectSegName = section.segment_name
        
        if sectType  == lief.MachO.SECTION_TYPES.ZEROFILL:
            segm.type = idaapi.SEG_BSS

        # if "__TEXT" in sectSegName:
        if ("__text" in section.name) or ("__auth_stubs" in section.name):
            segm.perm = ida_segment.SEGPERM_EXEC | ida_segment.SEGPERM_READ
            segm.type = idaapi.SEG_CODE
            idaapi.add_segm_ex(segm, segName, "CODE", idaapi.ADDSEG_OR_DIE)
        else:
            segm.type = idaapi.SEG_DATA
            segm.perm = ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_READ
            idaapi.add_segm_ex(segm, segName, "DATA", idaapi.ADDSEG_OR_DIE)

        # load data to section
        if section.offset and section.size:
            if sectSegName == "__TEXT":
                ret = li.file2base(fileOffset + section.offset, eaBeginAddr, eaEndAddr, True)
            elif (sectSegName == "__DATA") or \
                 (sectSegName == "__LEGION") or \
                 (sectSegName == "__DATA_CONST") or \
                 (sectSegName == "__BOOTARGS") or \
                 (sectSegName == "STACK"):
                if True:
                    dataOffset = sepFwData.find(section.content)
                    if dataOffset == -1:
                        RaiseException("[-] can't locate data postion")
                    ret = li.file2base(dataOffset, eaBeginAddr, eaEndAddr, True)
                else:
                    # ida_bytes.put_bytes(eaBeginAddr, section.content.tobytes())
                    idaapi.mem2base(section.content.tobytes(), eaBeginAddr, -1)
            else:
                RaiseException("[-] unkown segment: %s" % (sectSegName))

        # format '__mod_init_func'
        if section.name == "__mod_init_func":
            itAddr = eaBeginAddr
            while itAddr < eaEndAddr:
                # idc.Qword -> idc.get_qword
                # idc.MakeQword(ea) -> ida_bytes.create_data(ea, FF_QWORD, 8, ida_idaapi.BADADDR)
                initCodeAddr = None
                origVal = ida_bytes.get_qword(itAddr)
                if origVal < 0x100000000:
                    initCodeAddr = baseAddr + origVal
                else:
                    newVal = origVal & 0xFFFFFFFF
                    initCodeAddr = baseAddr + newVal
                # idc.set_cmt(itAddr, "0x%X" % (origVal), 0)
                ida_bytes.patch_qword(itAddr, initCodeAddr)
                ida_bytes.create_data(itAddr, ida_bytes.FF_QWORD, 8, ida_idaapi.BADADDR)
                # idaapi.add_entry(initCodeAddr, initCodeAddr, "", 1)
                idc.create_insn(initCodeAddr)
                ida_funcs.add_func(initCodeAddr)
                # idc.OpOff  -> idc.op_plain_offset
                # idc.OpOffEx -> idc.op_offset
                # ida_auto.auto_wait()
                idc.op_plain_offset(itAddr, 0, 0x0)
                itAddr += 8

        # format '__init_offsets', '__auth_ptr'
        if (section.name == "__init_offsets") or (section.name == "__auth_ptr"):
            itAddr = eaBeginAddr
            while itAddr < eaEndAddr:
                initCodeAddr = None
                origVal = idc.get_qword(itAddr)
                if origVal < 0x100000000:
                    initCodeAddr = baseAddr + liefObj.imagebase + origVal
                else:
                    newVal = origVal & 0xFFFFFFFF
                    initCodeAddr = baseAddr + liefObj.imagebase + newVal
                # idc.set_cmt(itAddr, "0x%X" % (origVal), 0)
                ida_bytes.patch_qword(itAddr, initCodeAddr)
                ida_bytes.create_data(itAddr, ida_bytes.FF_QWORD, 8, ida_idaapi.BADADDR)
                idc.create_insn(initCodeAddr)
                ida_funcs.add_func(initCodeAddr)
                idc.op_plain_offset(itAddr, 0, 0x0)
                itAddr += 8

        # format '__const', '__const2'
        if section.name.startswith("__const"):
            itAddr = eaBeginAddr
            while itAddr < eaEndAddr:
                origVal = idc.get_qword(itAddr)
                if IsTaggedPointer(origVal, liefObj.imagebase, sectTextStartAddr, sectTextEndAddr):
                    print("[+] tagged pointer: 0x%X, 0x%X" % (itAddr, origVal))
                    untaggedVal = UntagPointer(origVal, baseAddr + liefObj.imagebase)
                    ida_bytes.del_items(itAddr, ida_bytes.DELIT_DELNAMES, 8)
                    idc.set_cmt(itAddr, "0x%X" % (origVal), 0)
                    ida_bytes.patch_qword(itAddr, untaggedVal)
                    ida_bytes.create_data(itAddr, ida_bytes.FF_QWORD, 8, ida_idaapi.BADADDR)
                    idc.create_insn(untaggedVal)
                    ida_funcs.add_func(untaggedVal)
                    idc.op_plain_offset(itAddr, 0, 0x0)
                itAddr += 8

        # '__auth_got', '__got'
        if (section.name == "__auth_got") or (section.name == "__got"):
            if (sharedCacheBaseAddr is not None) and (sharedCacheSlide is not None):
                itAddr = eaBeginAddr
                while itAddr < eaEndAddr:
                    origVal = idc.get_qword(itAddr)
                    newVal = origVal & 0xFFFFF
                    targetAddr = sharedCacheBaseAddr + (newVal - sharedCacheSlide)
                    # idc.set_cmt(itAddr, "0x%X" % (origVal), 0)
                    ida_bytes.patch_qword(itAddr, targetAddr)
                    ida_bytes.create_data(itAddr, ida_bytes.FF_QWORD, 8, ida_idaapi.BADADDR)
                    idc.create_insn(targetAddr)
                    ida_funcs.add_func(targetAddr)
                    idc.op_plain_offset(itAddr, 0, 0x0)
                    itAddr += 8

        # format 'debug_vars'
        if section.name == "debug_vars":
            count = int((eaEndAddr - eaBeginAddr) / 8)
            for idx in range(count):
                itAddr = eaBeginAddr + idx * 8
                if (idx % 3) == 2:
                    ida_bytes.create_data(itAddr, ida_bytes.FF_QWORD, 8, ida_idaapi.BADADDR)
                    continue

                initCodeAddr = None
                origVal = idc.get_qword(itAddr)
                if origVal < 0x100000000:
                    initCodeAddr = baseAddr + liefObj.imagebase + origVal
                else:
                    newVal = origVal & 0xFFFFFFFF
                    initCodeAddr = baseAddr + liefObj.imagebase + newVal
                idc.set_cmt(itAddr, "0x%X" % (origVal), 0)
                ida_bytes.patch_qword(itAddr, initCodeAddr)
                ida_bytes.create_data(itAddr, ida_bytes.FF_QWORD, 8, ida_idaapi.BADADDR)
                idc.op_plain_offset(itAddr, 0, 0x0)
        
        # fill zeros
        if sectType  == lief.MachO.SECTION_TYPES.ZEROFILL:
            itAddr = eaBeginAddr
            while itAddr < eaEndAddr:
                if section.alignment == 3:
                    ida_bytes.patch_qword(itAddr, 0)
                    itAddr += 8
                elif section.alignment == 2:
                    ida_bytes.patch_dword(itAddr, 0)
                    itAddr += 4
                else:
                    ida_bytes.patch_byte(itAddr, 0)
                    itAddr += 1
    
    # create entry
    entryName = "%s_start" % (binName)
    entryPointAddr = None
    if liefObj.thread_command:
        entryPointAddr = baseAddr + liefObj.thread_command.pc
    elif liefObj.main_command:
        entryPointAddr = baseAddr + liefObj.imagebase + liefObj.main_command.entrypoint
    else:
        print("[-] '%s' has no entry point" % (binName))

    if entryPointAddr is not None:
        idaapi.add_entry(entryPointAddr, entryPointAddr, entryName, 1)
        ida_funcs.add_func(entryPointAddr)

    # symbols
    for symbol in liefObj.symbols:
        symbol_value = 0
        if symbol.has_export_info:
            symbol_value = symbol.export_info.address
        elif symbol.has_binding_info:
            symbol_value = symbol.binding_info.address
        else:
            symbol_value = symbol.value
        symbol_name = symbol.name
        if (symbol_name == "") or (symbol_value == 0):
            continue
        try:
            idaapi.add_entry(baseAddr + symbol_value, baseAddr + symbol_value, symbol_name, 1)
            ida_funcs.add_func(baseAddr + symbol_value)
        except Exception as e:
            pass
####################################################################################################

def ParseSEPFirmware_IDA(li):
    li.seek(0, idaapi.SEEK_END)
    size = li.tell()
    li.seek(0)

    sepFwData = li.read(size)

    offsetInfo = GuessOffsetInfo(sepFwData)
    if offsetInfo is None:
        return 0

    kernel_text_offset = GetQword(sepFwData, offsetInfo["kernel_text"])
    if gDoLog: print("[+] kernel_text_offset: 0x%x" % (kernel_text_offset))

    kernel_text_offset = GetQword(sepFwData, offsetInfo["kernel_text"])
    if gDoLog: print("[+] kernel_text_offset: 0x%x" % (kernel_text_offset))

    root_text_offset = GetQword(sepFwData, offsetInfo["root_text"])
    if gDoLog: print("[+] root_text_offset: 0x%x" % (root_text_offset))

    name = GetStrSep(sepFwData, offsetInfo["root_name"])
    if gDoLog: print("[+] name: %s" % (name))

    # add seg: booter
    segmBooter = idaapi.segment_t()
    segmBooter.bitness = 2  # 64-bit
    segmBooter.start_ea = 0
    segmBooter.end_ea = kernel_text_offset
    segmBooter.align = 2
    segmBooter.perm = ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC
    segmBooter.type = idaapi.SEG_CODE
    idaapi.add_segm_ex(segmBooter, "BOOTER", "CODE", idaapi.ADDSEG_OR_DIE)
    li.file2base(0, 0, kernel_text_offset, True)
    idaapi.add_entry(0, 0, "BOOTER_start", 1)
    ida_funcs.add_func(0)

    app_count = GetDword(sepFwData, offsetInfo["app_count"])
    if gDoLog: print("[+] app_count: %d" % (app_count))
    lib_count = GetDword(sepFwData, offsetInfo["app_count"] + 0x4)
    if gDoLog: print("[+] lib_count: %d" % (app_count))

    # Extract the SEPOS kernel.
    if not IsFirmwareV4(sepFwData):
        assert_macho64(sepFwData, kernel_text_offset)
        size_offset = sepFwData.find(b'__LINKEDIT', kernel_text_offset)
        assert(size_offset > 0)
        size_offset += 0x20 # segname -> fileoff
        kernel_size = struct.unpack('<Q', sepFwData[size_offset:size_offset+8])[0]
        kernel_linkedit_size = struct.unpack('<Q', sepFwData[size_offset+8:size_offset+16])[0]
        kernel_size += kernel_linkedit_size
    else:
        size_offset = offsetInfo["kernel_text"] + 0x8
        kernel_size = struct.unpack('<Q', sepFwData[size_offset:size_offset+8])[0]

    output_file_index = 1

    kernelMachOData = sepFwData[kernel_text_offset:kernel_text_offset+kernel_size]
    kernelFatBinary = MachO.parse(list(kernelMachOData), config=MachO.ParserConfig.quick)
    if kernelFatBinary is not None:
        if kernelFatBinary.size != 1:
            RaiseException("[-] invalid macho: %s", name)
        kernelBinary = kernelFatBinary[0]
        LoadLiefObjToIDA(li, kernel_text_offset, kernelBinary, 0, "KERNEL", sepFwData, None)
    else:
        segmKernel = idaapi.segment_t()
        segmKernel.bitness = 2  # 64-bit
        eaKernelStart = kernel_text_offset
        eaKernelEnd = kernel_text_offset+kernel_size
        segmKernel.start_ea = eaKernelStart
        segmKernel.end_ea = eaKernelEnd
        segmKernel.align = 2
        segmKernel.perm = ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC
        segmKernel.type = idaapi.SEG_CODE
        idaapi.add_segm_ex(segmKernel, "KERNEL", "CODE", idaapi.ADDSEG_OR_DIE)
        li.file2base(kernel_text_offset, eaKernelStart, eaKernelEnd, True)
        idaapi.add_entry(eaKernelStart, eaKernelStart, "KERNEL_start", 1)
        ida_funcs.add_func(eaKernelStart)

    # Relocation Step
    # relocationStep = 1024 * 1024 * 16
    relocationStep = 1024 * 1024 * 1024 * 4

    # Extract the SEPOS root process.
    assert_macho64(sepFwData, root_text_offset)
    size_offset = sepFwData.find(b'__LINKEDIT', root_text_offset)
    assert(size_offset > 0)
    size_offset += 0x20 # segname -> fileoff
    root_size = struct.unpack('<Q', sepFwData[size_offset:size_offset+8])[0]
    root_linkedit_size = struct.unpack('<Q', sepFwData[size_offset+8:size_offset+16])[0]
    root_size += root_linkedit_size

    output_file_index += 1

    rootMachOData = sepFwData[root_text_offset:root_text_offset+root_size]
    rootFatBinary = MachO.parse(list(rootMachOData), config=MachO.ParserConfig.quick)
    if rootFatBinary.size != 1:
        RaiseException("[-] invalid macho: %s", name)
    rootBinary = rootFatBinary[0]
    # print_sections(rootBinary)
    rootBaseAddr = relocationStep * 1
    LoadLiefObjToIDA(li, root_text_offset, rootBinary, rootBaseAddr, "ROOT", sepFwData, None)

    if gDoLog: print("")

    app_info_base = offsetInfo["app_info"]
    app_info_size = offsetInfo["app_info_size"]

    # load shared cache
    sharedCacheBaseAddr = 0
    if lib_count != 0:
        idx = app_count
        # root is the first, so: idx + 2
        sharedCacheBaseAddr = relocationStep * (idx + 2)

        cur_base = app_info_base + app_info_size * idx
        if gDoLog: print("[+] lib base: 0x%X" % (cur_base))

        text_offset = GetQword(sepFwData, cur_base + offsetInfo["app_text"])
        if gDoLog: print("[+] lib text offset: 0x%X" % (text_offset))

        text_size = GetQword(sepFwData, cur_base + offsetInfo["app_text_size"])
        if gDoLog: print("[+] lib text size: 0x%X" % (text_size))

        data_offset = GetQword(sepFwData, cur_base + offsetInfo["app_data"])
        if gDoLog: print("[+] lib data offset: 0x%X" % (data_offset))

        data_size = GetQword(sepFwData, cur_base + offsetInfo["app_data_size"])
        if gDoLog: print("[+] lib data size: 0x%X" % (data_size))

        name = GetStrSep(sepFwData, cur_base + offsetInfo["app_name"])
        if gDoLog: print("[+] lib name: %s" % (name))

        assert_macho64(sepFwData, text_offset)

        if gDoLog: print("")

        # Reconstruct the lib binary.
        libMachOData = sepFwData[text_offset:text_offset+text_size] + sepFwData[data_offset:data_offset+data_size]
        libFatBinary = MachO.parse(list(libMachOData), config=MachO.ParserConfig.quick)
        if libFatBinary.size != 1:
            print("[-] invalid lib macho: %s", name)
        else:
            libBinary = libFatBinary[0]
            LoadLiefObjToIDA(li, text_offset, libBinary, sharedCacheBaseAddr, name, sepFwData, None)

    # Process the individual apps.
    for idx in range(app_count):
        # Unpack the entry for this app.
        cur_base = app_info_base + app_info_size * idx
        if gDoLog: print("[+] app base: 0x%X" % (cur_base))

        text_offset = GetQword(sepFwData, cur_base + offsetInfo["app_text"])
        if gDoLog: print("[+] app text offset: 0x%X" % (text_offset))

        text_size = GetQword(sepFwData, cur_base + offsetInfo["app_text_size"])
        if gDoLog: print("[+] app text size: 0x%X" % (text_size))

        data_offset = GetQword(sepFwData, cur_base + offsetInfo["app_data"])
        if gDoLog: print("[+] app data offset: 0x%X" % (data_offset))

        data_size = GetQword(sepFwData, cur_base + offsetInfo["app_data_size"])
        if gDoLog: print("[+] app data size: 0x%X" % (data_size))

        name = GetStrSep(sepFwData, cur_base + offsetInfo["app_name"])
        if gDoLog: print("[+] app name: %s" % (name))

        assert_macho64(sepFwData, text_offset)

        if gDoLog: print("")

        # Reconstruct the app binary.
        appMachOData = sepFwData[text_offset:text_offset+text_size] + sepFwData[data_offset:data_offset+data_size]
        appFatBinary = MachO.parse(list(appMachOData), config=MachO.ParserConfig.quick)
        if appFatBinary.size != 1:
            print("[-] invalid app macho: %s", name)
            continue
        appBinary = appFatBinary[0]

        # root is the first, so: idx + 2
        curAppBase = relocationStep * (idx + 2)
        LoadLiefObjToIDA(li, text_offset, appBinary, curAppBase, name, sepFwData, sharedCacheBaseAddr)
####################################################################################################

def GetDword(data, offset):
    val = struct.unpack('<I', data[offset:offset+0x4])[0]
    return val
####################################################################################################

def GetQword(data, offset):
    val = struct.unpack('<Q', data[offset:offset+0x8])[0]
    return val
####################################################################################################

def GetStr(data, offset, str_len):
    raw_str = data[offset:offset+str_len]
    return raw_str.decode('ascii').strip()
####################################################################################################

def GetStrSep(data, offset):
    return GetStr(data, offset, 16)
####################################################################################################

def GetLegionTypeStr(data):
    if data.find(b"Built by legion2P", 0, 0x4000) != -1:
        return "legion2P"
    elif data.find(b"Built by legion2p", 0, 0x4000) != -1:
        return "legion2p"
    elif data.find(b"Built by legion2", 0, 0x4000) != -1:
        return "legion2"
    else:
        return None
####################################################################################################

def IsFirmwareV4(data):
    legionTypeStr = GetLegionTypeStr(data)
    if legionTypeStr == "legion2":
        return False
    elif (legionTypeStr == "legion2P") or (legionTypeStr == "legion2p"):
        return True
    else:
        RaiseException("[-] should not go here: IsFirmwareV4")
####################################################################################################

# An assert that a file is a Mach-O.
def assert_macho64(data, offset):
    assert(struct.unpack('<I', data[offset:offset+4])[0] == 0xfeedfacf)
####################################################################################################

def GuessOffsetInfo(sepFwData):
    fwLen = len(sepFwData)
    if gDoLog: print("[+] file len: 0x%X" % (fwLen))

    posLegion2 = sepFwData.find(b"Built by legion2", 0, 0x4000)
    if posLegion2 == -1:
        RaiseException("[-] GuessOffsetInfo: 1")

    kernelTextOffset = sepFwData.find(b"\x00\x40\x00\x00\x00\x00\x00\x00", posLegion2, posLegion2 + 0x200)
    if kernelTextOffset == -1:
        RaiseException("[-] GuessOffsetInfo: 2")
    if gDoLog: print("[+] kernel text: 0x%X" % (kernelTextOffset))

    fwLenBytes = struct.pack('<Q', fwLen)
    fwLenOffset = sepFwData.find(fwLenBytes, kernelTextOffset + 8, kernelTextOffset + 0x30)
    if fwLenOffset == -1:
        RaiseException("[-] GuessOffsetInfo: 3")
    if gDoLog: print("[+] fw len: 0x%X" % (fwLenOffset))

    searchZeroStart = fwLenOffset + 8
    while (struct.unpack('<Q', sepFwData[searchZeroStart:searchZeroStart+8])[0]) or (struct.unpack('<Q', sepFwData[searchZeroStart+8:searchZeroStart+16])[0]):
        searchZeroStart += 8
    if gDoLog: print("[+] search zeros start: 0x%X" % (searchZeroStart))

    rootTextOffset = searchZeroStart
    while not struct.unpack('<Q', sepFwData[rootTextOffset:rootTextOffset+8])[0]:
        rootTextOffset += 8
    if gDoLog: print("[+] root text: 0x%X" % (rootTextOffset))

    rootNameOffset = sepFwData.find(b"SEPOS", rootTextOffset + 16, rootTextOffset + 16 + 0x70)
    if rootNameOffset == -1:
        RaiseException("[-] GuessOffsetInfo: 5")
    if gDoLog: print("[+] root name: 0x%X" % (rootNameOffset))

    appCountOffset = rootNameOffset + 16
    if gDoLog: print("[+] app count search start: 0x%X" % (appCountOffset))
    while True:
        appCount = struct.unpack('<I', sepFwData[appCountOffset:appCountOffset+4])[0]
        if 0xD <= appCount < 0x18:
            break
        appCountOffset += 4
    if gDoLog: print("[+] app count: 0x%X" % (appCountOffset))

    appInfoOffset = appCountOffset + 0x8
    if gDoLog: print("[+] app info: 0x%X" % (appInfoOffset))

    strOffset_SEPD = sepFwData.find(b"SEPD", appInfoOffset, appInfoOffset + 0x200)
    if strOffset_SEPD == -1:
        RaiseException("[-] GuessOffsetInfo: 6")

    strOffset_AESSEP = sepFwData.find(b"AESSEP", appInfoOffset, appInfoOffset + 0x200)
    if strOffset_AESSEP == -1:
        strOffset_AESSEP = sepFwData.find(b"sepServices", appInfoOffset, appInfoOffset + 0x200)
        if strOffset_AESSEP == -1:
            RaiseException("[-] GuessOffsetInfo: 7")
    appInfoSize = strOffset_AESSEP - strOffset_SEPD
    if gDoLog: print("[+] app info size: 0x%X" % (appInfoSize))

    appTextOffset = 0
    appTextSizeOffset = 0x8
    appDataOffset = 0x10
    appDataSizeOffset = 0x18
    appNameOffset = strOffset_SEPD - appInfoOffset
    if gDoLog: print("[+] app text: 0x%X" % (appTextOffset))
    if gDoLog: print("[+] app text len: 0x%X" % (appTextSizeOffset))
    if gDoLog: print("[+] app data: 0x%X" % (appDataOffset))
    if gDoLog: print("[+] app data len: 0x%X" % (appDataSizeOffset))
    if gDoLog: print("[+] app name: 0x%X" % (appNameOffset))

    # checking
    assert(kernelTextOffset < 0x4000)
    assert(rootTextOffset < 0x4000)
    assert(rootNameOffset < 0x4000)
    assert(appCountOffset < 0x4000)
    assert(appInfoOffset < 0x4000)

    offsetInfo = {}
    offsetInfo["kernel_text"] = kernelTextOffset
    offsetInfo["root_text"] = rootTextOffset
    offsetInfo["root_name"] = rootNameOffset
    offsetInfo["app_count"] = appCountOffset
    offsetInfo["app_info"] = appInfoOffset
    offsetInfo["app_info_size"] = appInfoSize
    offsetInfo["app_text"] = appTextOffset
    offsetInfo["app_text_size"] = appTextSizeOffset
    offsetInfo["app_data"] = appDataOffset
    offsetInfo["app_data_size"] = appDataSizeOffset
    offsetInfo["app_name"] = appNameOffset

    return offsetInfo
####################################################################################################

# RaiseException
def RaiseException(msg):
    raise Exception(msg)
####################################################################################################
