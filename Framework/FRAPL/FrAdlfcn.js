//
// FrAdlfcn.js
// Fried Apple Framework
//
// Created by Alexander Hude on 19/11/15.
// Copyright (c) 2015 FriedApple. All rights reserved.
//

const RTLD_LAZY    = 0x1;
const RTLD_NOW     = 0x2;
const RTLD_LOCAL   = 0x4;
const RTLD_GLOBAL  = 0x8;

const RTLD_DEFAULT = -2;

const _object_dlopen = Module.findExportByName("libdyld.dylib", "dlopen");
const dlopen = new NativeFunction(_object_dlopen, "pointer", ["pointer", "int"]);

const _object_dlclose = Module.findExportByName("libdyld.dylib", "dlclose");
const dlclose = new NativeFunction(_object_dlclose, "int", ["pointer"]);

const _object_dlsym = Module.findExportByName("libdyld.dylib", "dlsym");
const dlsym = new NativeFunction(_object_dlsym, "pointer", ["pointer", "pointer"]);

const _object_dladdr = Module.findExportByName("libdyld.dylib", "dladdr");
const dladdr = new NativeFunction(_object_dladdr, "int", ["pointer", "pointer"]);

const _object_dlerror = Module.findExportByName("libdyld.dylib", "dlerror");
const dlerror = new NativeFunction(_object_dlerror, "pointer", []);

const _object_dyld_get_image_name = Module.findExportByName("libdyld.dylib", "_dyld_get_image_name");
const dyld_get_image_name = new NativeFunction(_object_dyld_get_image_name, "pointer", ["int"]);

const _object_dyld_get_image_vmaddr_slide = Module.findExportByName("libdyld.dylib", "_dyld_get_image_vmaddr_slide");
const dyld_get_image_vmaddr_slide = new NativeFunction(_object_dyld_get_image_vmaddr_slide, "long", ["uint32"]);

const _object_dyld_get_image_header = Module.findExportByName("libdyld.dylib", "_dyld_get_image_header");
const dyld_get_image_header = new NativeFunction(_object_dyld_get_image_header, "pointer", ["uint32"]);


function fra_dladdr (address)
{
    var ptr_sz = 4;
    if (Process.arch == 'x64' || Process.arch == 'arm64')
        ptr_sz = 8

    var dl_info = Memory.alloc(ptr_sz*4);
    if (dladdr(address, dl_info) != 0)
    {
        var symbol = Memory.readCString(Memory.readPointer(dl_info.add(ptr_sz*2)));
        return {
            dli_fname: Memory.readCString(Memory.readPointer(dl_info)), 
            dli_fbase: Memory.readPointer(dl_info.add(ptr_sz)), 
            dli_sname: (symbol == null)? "" : symbol,
            dli_saddr: Memory.readPointer(dl_info.add(ptr_sz*3))
        }; 
    }
    else
    {
        return {    
            dli_fname: "undefined", 
            dli_fbase: ptr(0x0), 
            dli_sname: "undefined",
            dli_saddr: ptr(0x0)
        };
    }
}
