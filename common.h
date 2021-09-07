/* Copyright 2021 0x7ff
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef COMMON_H
#	define COMMON_H
#	include <CoreFoundation/CoreFoundation.h>
#	include <mach/mach.h>
#	define KADDR_FMT "0x%" PRIX64
#	define IO_OBJECT_NULL ((io_object_t)0)
#	define kIODeviceTreePlane "IODeviceTree"
typedef uint64_t kaddr_t;
typedef char io_string_t[512];
typedef uint32_t IOOptionBits;
typedef mach_port_t io_object_t;
typedef io_object_t io_registry_entry_t;

kern_return_t
IOObjectRelease(io_object_t);

int
proc_pidinfo(int, int, uint64_t, void *, int);

CFDictionaryRef
OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);

io_registry_entry_t
IORegistryEntryFromPath(mach_port_t, const io_string_t);

kern_return_t
mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);

kern_return_t
mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);

kern_return_t
mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

CFTypeRef
IORegistryEntryCreateCFProperty(io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits);

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

extern const mach_port_t kIOMasterPortDefault;
#endif
