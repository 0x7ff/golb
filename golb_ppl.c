/* Copyright 2020 0x7ff
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
#include "golb.h"
#include <compression.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define LZSS_F (18)
#define LZSS_N (4096)
#define LZSS_THRESHOLD (2)
#define IPC_ENTRY_SZ (0x18)
#define OS_ARRAY_CNT_OFF (0x14)
#define OS_STRING_LEN_OFF (0xC)
#define KCOMP_HDR_PAD_SZ (0x16C)
#define OS_SET_MEMBERS_OFF (0x18)
#define OS_ARRAY_ARRAY_OFF (0x20)
#define OS_STRING_STRING_OFF (0x10)
#define IPC_SPACE_IS_TABLE_OFF (0x20)
#define IPC_ENTRY_IE_OBJECT_OFF (0x0)
#define PROC_P_LIST_LE_PREV_OFF (0x8)
#define OS_DICTIONARY_COUNT_OFF (0x14)
#define VM_MAP_HDR_RBH_ROOT_OFF (0x38)
#define IPC_PORT_IP_KOBJECT_OFF (0x68)
#define PROC_P_LIST_LH_FIRST_OFF (0x0)
#define IO_MEMORY_MAP_F_ADDR_OFF (0x28)
#define PREBOOT_PATH "/private/preboot/"
#define IPC_SPACE_IS_TABLE_SZ_OFF (0x14)
#define OS_DICTIONARY_DICT_ENTRY_OFF (0x20)
#define IO_DEVICE_MEMORY_MAPPINGS_OFF (0x18)
#define OS_STRING_LEN(a) extract32(a, 14, 18)
#define LOADED_KEXT_SUMMARY_HDR_NAME_OFF (0x10)
#define LOADED_KEXT_SUMMARY_HDR_ADDR_OFF (0x60)
#define IO_REGISTRY_ENTRY_F_PROP_TABLE_OFF (0x20)
#define kCFCoreFoundationVersionNumber_iOS_10_0_b5 (1348)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b2 (1656)
#define kCFCoreFoundationVersionNumber_iOS_14_0_b1 (1740)
#define kCFCoreFoundationVersionNumber_iOS_11_0_b1 (1429.15)
#define kCFCoreFoundationVersionNumber_iOS_12_0_b1 (1535.13)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b1 (1652.20)
#define BOOT_PATH "/System/Library/Caches/com.apple.kernelcaches/kernelcache"

#define DER_INT (0x2U)
#define DER_SEQ (0x30U)
#define DER_IA5_STR (0x16U)
#define DER_OCTET_STR (0x4U)
#define PROC_PIDREGIONINFO (7)
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define VM_KERN_MEMORY_OSKEXT (5)
#define LOWGLO_VER_CODE "Kraken  "
#define KCOMP_HDR_MAGIC (0x636F6D70U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define kIODeviceTreePlane "IODeviceTree"
#define KCOMP_HDR_TYPE_LZSS (0x6C7A7373U)
#define LOWGLO_LAYOUT_MAGIC (0xC0DEC0DEU)
#define kIORegistryIterateRecursively (1U)
#define kIODeviceMemoryKey "IODeviceMemory"
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define kOSBundleLoadAddressKey "OSBundleLoadAddress"
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define LDR_W_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 2U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define IS_LDR_W_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xB9400000U)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))

#ifndef SECT_CSTRING
#	define SECT_CSTRING "__cstring"
#endif

#ifndef SEG_TEXT_EXEC
#	define SEG_TEXT_EXEC "__TEXT_EXEC"
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef uint32_t ipc_entry_num_t;

typedef struct {
	struct section_64 s64;
	const char *data;
} sec_64_t;

typedef struct {
	sec_64_t sec_text, sec_data, sec_cstring;
	struct symtab_command cmd_symtab;
	kaddr_t base, kslide;
	const char *kernel;
	size_t kernel_sz;
	char *data;
} pfinder_t;

typedef struct {
	struct {
		uint32_t next, prev;
	} vmp_q_pageq, vmp_listq, vmp_backgroundq;
	uint64_t vmp_offset;
	uint32_t vmp_object, q_flags, vmp_next_m, o_flags;
} vm_page_t;

typedef struct {
	struct {
		kaddr_t prev, next, start, end;
	} links;
	kaddr_t rbe_left, rbe_right, rbe_parent, vme_object;
	uint64_t vme_offset;
} vm_map_entry_t;

typedef struct {
	uint32_t pri_protection, pri_max_protection, pri_inheritance, pri_flags;
	uint64_t pri_offset;
	uint32_t pri_behavior, pri_user_wired_count, pri_user_tag, pri_pages_resident, pri_pages_shared_now_private, pri_pages_swapped_out, pri_pages_dirtied, pri_ref_count, pri_shadow_depth, pri_share_mode, pri_private_pages_resident, pri_shared_pages_resident, pri_obj_id, pri_depth;
	uint64_t pri_address, pri_size;
} proc_regioninfo_data_t;

typedef struct {
	uint8_t ver_code[8];
	kaddr_t zero, stext, ver, os_ver, kmod_ptr, trans_off, reboot_flag, manual_pkt_addr, alt_debugger, pmap_memq, pmap_mem_page_off, pmap_mem_chain_off, static_addr, static_sz, layout_major_ver, layout_magic, pmap_mem_start_addr, pmap_mem_end_addr, pmap_mem_page_sz, pmap_mem_from_array_mask, pmap_mem_first_ppnum, pmap_mem_packed_shift, pmap_mem_packed_base_addr, layout_minor_ver, page_shift;
} lowglo_t;

static lowglo_t lowglo;
static kread_func_t kread_buf;
static task_t tfp0 = TASK_NULL;
static kaddr_t kslide, kernproc, lowglo_ptr, our_task, our_map;
static size_t task_map_off, proc_task_off, proc_p_pid_off, task_itk_space_off;

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
	return (val >> start) & (~0U >> (32U - len));
}

static uint64_t
sextract64(uint64_t val, unsigned start, unsigned len) {
	return (uint64_t)((int64_t)(val << (64U - len - start)) >> (64U - len));
}

static size_t
decompress_lzss(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len) {
	const uint8_t *src_end = src + src_len, *dst_start = dst, *dst_end = dst + dst_len;
	uint16_t i, r = LZSS_N - LZSS_F, flags = 0;
	uint8_t text_buf[LZSS_N + LZSS_F - 1], j;

	memset(text_buf, ' ', r);
	while(src != src_end && dst != dst_end) {
		if(((flags >>= 1U) & 0x100U) == 0) {
			flags = *src++ | 0xFF00U;
			if(src == src_end) {
				break;
			}
		}
		if((flags & 1U) != 0) {
			text_buf[r++] = *dst++ = *src++;
			r &= LZSS_N - 1U;
		} else {
			i = *src++;
			if(src == src_end) {
				break;
			}
			j = *src++;
			i |= (j & 0xF0U) << 4U;
			j = (j & 0xFU) + LZSS_THRESHOLD;
			do {
				*dst++ = text_buf[r++] = text_buf[i++ & (LZSS_N - 1U)];
				r &= LZSS_N - 1U;
			} while(j-- != 0 && dst != dst_end);
		}
	}
	return (size_t)(dst - dst_start);
}

static const uint8_t *
der_decode(uint8_t tag, const uint8_t *der, const uint8_t *der_end, size_t *out_len) {
	size_t der_len;

	if(der_end - der > 2 && tag == *der++) {
		if(((der_len = *der++) & 0x80U) != 0) {
			*out_len = 0;
			if((der_len &= 0x7FU) <= sizeof(*out_len) && (size_t)(der_end - der) >= der_len) {
				while(der_len-- != 0) {
					*out_len = (*out_len << 8U) | *der++;
				}
			}
		} else {
			*out_len = der_len;
		}
		if(*out_len != 0 && (size_t)(der_end - der) >= *out_len) {
			return der;
		}
	}
	return NULL;
}

static const uint8_t *
der_decode_seq(const uint8_t *der, const uint8_t *der_end, const uint8_t **seq_end) {
	size_t der_len;

	if((der = der_decode(DER_SEQ, der, der_end, &der_len)) != NULL) {
		*seq_end = der + der_len;
	}
	return der;
}

static const uint8_t *
der_decode_uint64(const uint8_t *der, const uint8_t *der_end, uint64_t *r) {
	size_t der_len;

	if((der = der_decode(DER_INT, der, der_end, &der_len)) != NULL && (*der & 0x80U) == 0 && (der_len <= sizeof(*r) || (--der_len == sizeof(*r) && *der++ == 0))) {
		*r = 0;
		while(der_len-- != 0) {
			*r = (*r << 8U) | *der++;
		}
		return der;
	}
	return NULL;
}

static void *
kdecompress(const void *src, size_t src_len, size_t *dst_len) {
	const uint8_t *der, *octet, *der_end, *src_end = (const uint8_t *)src + src_len;
	struct {
		uint32_t magic, type, adler32, uncomp_sz, comp_sz;
		uint8_t pad[KCOMP_HDR_PAD_SZ];
	} kcomp_hdr;
	size_t der_len;
	uint64_t r;
	void *dst;

	if((der = der_decode_seq(src, src_end, &der_end)) != NULL && (der = der_decode(DER_IA5_STR, der, der_end, &der_len)) != NULL && der_len == 4 && (memcmp(der, "IMG4", der_len) != 0 || ((der = der_decode_seq(der + der_len, src_end, &der_end)) != NULL && (der = der_decode(DER_IA5_STR, der, der_end, &der_len)) != NULL && der_len == 4)) && memcmp(der, "IM4P", der_len) == 0 && (der = der_decode(DER_IA5_STR, der + der_len, der_end, &der_len)) != NULL && der_len == 4 && memcmp(der, "krnl", der_len) == 0 && (der = der_decode(DER_IA5_STR, der + der_len, der_end, &der_len)) != NULL && (der = der_decode(DER_OCTET_STR, der + der_len, der_end, &der_len)) != NULL && der_len > sizeof(kcomp_hdr)) {
		octet = der;
		memcpy(&kcomp_hdr, octet, sizeof(kcomp_hdr));
		if(kcomp_hdr.magic == __builtin_bswap32(KCOMP_HDR_MAGIC)) {
			if(kcomp_hdr.type == __builtin_bswap32(KCOMP_HDR_TYPE_LZSS) && (kcomp_hdr.comp_sz = __builtin_bswap32(kcomp_hdr.comp_sz)) <= der_len - sizeof(kcomp_hdr) && (kcomp_hdr.uncomp_sz = __builtin_bswap32(kcomp_hdr.uncomp_sz)) != 0 && (dst = malloc(kcomp_hdr.uncomp_sz)) != NULL) {
				if(decompress_lzss(octet + sizeof(kcomp_hdr), kcomp_hdr.comp_sz, dst, kcomp_hdr.uncomp_sz) == kcomp_hdr.uncomp_sz) {
					*dst_len = kcomp_hdr.uncomp_sz;
					return dst;
				}
				free(dst);
			}
		} else if((der = der_decode_seq(der + der_len, src_end, &der_end)) != NULL && (der = der_decode_uint64(der, der_end, &r)) != NULL && r == 1 && der_decode_uint64(der, der_end, &r) != NULL && r != 0 && (dst = malloc(r)) != NULL) {
			if(compression_decode_buffer(dst, r, octet, der_len, NULL, COMPRESSION_LZFSE) == r) {
				*dst_len = r;
				return dst;
			}
			free(dst);
		}
	}
	return NULL;
}

static kern_return_t
init_tfp0(void) {
	kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
	mach_port_t host;
	pid_t pid;

	if(ret != KERN_SUCCESS) {
		host = mach_host_self();
		if(MACH_PORT_VALID(host)) {
			printf("host: 0x%" PRIX32 "\n", host);
			ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
			mach_port_deallocate(mach_task_self(), host);
		}
	}
	if(ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
		if(pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
			return ret;
		}
		mach_port_deallocate(mach_task_self(), tfp0);
	}
	return KERN_FAILURE;
}

static kern_return_t
kread_buf_tfp0(kaddr_t addr, void *buf, mach_vm_size_t sz) {
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_vm_size_t read_sz, out_sz = 0;

	while(sz != 0) {
		read_sz = MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
		if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
			return KERN_FAILURE;
		}
		p += read_sz;
		sz -= read_sz;
		addr += read_sz;
	}
	return KERN_SUCCESS;
}

static kern_return_t
kread_addr(kaddr_t addr, kaddr_t *val) {
	return kread_buf(addr, val, sizeof(*val));
}

static kern_return_t
find_section(const char *p, struct segment_command_64 sg64, const char *sect_name, struct section_64 *sp) {
	for(; sg64.nsects-- != 0; p += sizeof(*sp)) {
		memcpy(sp, p, sizeof(*sp));
		if((sp->flags & SECTION_TYPE) != S_ZEROFILL) {
			if(sp->offset < sg64.fileoff || sp->size > sg64.filesize || sp->offset - sg64.fileoff > sg64.filesize - sp->size) {
				break;
			}
			if(sp->size != 0 && strncmp(sp->segname, sg64.segname, sizeof(sp->segname)) == 0 && strncmp(sp->sectname, sect_name, sizeof(sp->sectname)) == 0) {
				return KERN_SUCCESS;
			}
		}
	}
	return KERN_FAILURE;
}

static void
sec_reset(sec_64_t *sec) {
	memset(&sec->s64, '\0', sizeof(sec->s64));
	sec->data = NULL;
}

static kern_return_t
sec_read_buf(sec_64_t sec, kaddr_t addr, void *buf, size_t sz) {
	size_t off;

	if(addr < sec.s64.addr || sz > sec.s64.size || (off = addr - sec.s64.addr) > sec.s64.size - sz) {
		return KERN_FAILURE;
	}
	memcpy(buf, sec.data + off, sz);
	return KERN_SUCCESS;
}

static void
pfinder_reset(pfinder_t *pfinder) {
	pfinder->base = 0;
	pfinder->kslide = 0;
	pfinder->data = NULL;
	pfinder->kernel = NULL;
	pfinder->kernel_sz = 0;
	sec_reset(&pfinder->sec_text);
	sec_reset(&pfinder->sec_data);
	sec_reset(&pfinder->sec_cstring);
	memset(&pfinder->cmd_symtab, '\0', sizeof(pfinder->cmd_symtab));
}

static void
pfinder_term(pfinder_t *pfinder) {
	free(pfinder->data);
	pfinder_reset(pfinder);
}

static kern_return_t
pfinder_init_file(pfinder_t *pfinder, const char *filename) {
	struct symtab_command cmd_symtab;
	kern_return_t ret = KERN_FAILURE;
	struct segment_command_64 sg64;
	struct mach_header_64 mh64;
	struct load_command lc;
	struct section_64 s64;
	struct fat_header fh;
	struct stat stat_buf;
	struct fat_arch fa;
	const char *p, *e;
	size_t len;
	void *m;
	int fd;

	pfinder_reset(pfinder);
	if((fd = open(filename, O_RDONLY | O_CLOEXEC)) != -1) {
		if(fstat(fd, &stat_buf) != -1 && S_ISREG(stat_buf.st_mode) && stat_buf.st_size > 0) {
			len = (size_t)stat_buf.st_size;
			if((m = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0)) != MAP_FAILED) {
				if((pfinder->data = kdecompress(m, len, &pfinder->kernel_sz)) != NULL && pfinder->kernel_sz > sizeof(fh) + sizeof(mh64)) {
					pfinder->kernel = pfinder->data;
					memcpy(&fh, pfinder->kernel, sizeof(fh));
					if(fh.magic == __builtin_bswap32(FAT_MAGIC) && (fh.nfat_arch = __builtin_bswap32(fh.nfat_arch)) < (pfinder->kernel_sz - sizeof(fh)) / sizeof(fa)) {
						for(p = pfinder->kernel + sizeof(fh); fh.nfat_arch-- != 0; p += sizeof(fa)) {
							memcpy(&fa, p, sizeof(fa));
							if(fa.cputype == (cpu_type_t)__builtin_bswap32(CPU_TYPE_ARM64) && (fa.offset = __builtin_bswap32(fa.offset)) < pfinder->kernel_sz && (fa.size = __builtin_bswap32(fa.size)) <= pfinder->kernel_sz - fa.offset && fa.size > sizeof(mh64)) {
								pfinder->kernel_sz = fa.size;
								pfinder->kernel += fa.offset;
								break;
							}
						}
					}
					memcpy(&mh64, pfinder->kernel, sizeof(mh64));
					if(mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE && mh64.sizeofcmds < pfinder->kernel_sz - sizeof(mh64)) {
						for(p = pfinder->kernel + sizeof(mh64), e = p + mh64.sizeofcmds; mh64.ncmds-- != 0 && (size_t)(e - p) >= sizeof(lc); p += lc.cmdsize) {
							memcpy(&lc, p, sizeof(lc));
							if(lc.cmdsize < sizeof(lc) || (size_t)(e - p) < lc.cmdsize) {
								break;
							}
							if(lc.cmd == LC_SEGMENT_64) {
								if(lc.cmdsize < sizeof(sg64)) {
									break;
								}
								memcpy(&sg64, p, sizeof(sg64));
								if(sg64.vmsize == 0) {
									continue;
								}
								if(sg64.nsects != (lc.cmdsize - sizeof(sg64)) / sizeof(s64) || sg64.fileoff > pfinder->kernel_sz || sg64.filesize > pfinder->kernel_sz - sg64.fileoff) {
									break;
								}
								if(sg64.fileoff == 0 && sg64.filesize != 0) {
									if(pfinder->base != 0) {
										break;
									}
									pfinder->base = sg64.vmaddr;
									printf("base: " KADDR_FMT "\n", sg64.vmaddr);
								}
								if(strncmp(sg64.segname, SEG_TEXT_EXEC, sizeof(sg64.segname)) == 0) {
									if(find_section(p + sizeof(sg64), sg64, SECT_TEXT, &s64) != KERN_SUCCESS) {
										break;
									}
									pfinder->sec_text.s64 = s64;
									pfinder->sec_text.data = pfinder->kernel + s64.offset;
									printf("sec_text_addr: " KADDR_FMT ", sec_text_off: 0x%" PRIX32 ", sec_text_sz: 0x%" PRIX64 "\n", s64.addr, s64.offset, s64.size);
								} else if(strncmp(sg64.segname, SEG_DATA, sizeof(sg64.segname)) == 0) {
									if(find_section(p + sizeof(sg64), sg64, SECT_DATA, &s64) != KERN_SUCCESS) {
										break;
									}
									pfinder->sec_data.s64 = s64;
									pfinder->sec_data.data = pfinder->kernel + s64.offset;
									printf("sec_data_addr: " KADDR_FMT ", sec_data_off: 0x%" PRIX32 ", sec_data_sz: 0x%" PRIX64 "\n", s64.addr, s64.offset, s64.size);
								} else if(strncmp(sg64.segname, SEG_TEXT, sizeof(sg64.segname)) == 0) {
									if(find_section(p + sizeof(sg64), sg64, SECT_CSTRING, &s64) != KERN_SUCCESS || pfinder->kernel[s64.offset + s64.size - 1] != '\0') {
										break;
									}
									pfinder->sec_cstring.s64 = s64;
									pfinder->sec_cstring.data = pfinder->kernel + s64.offset;
									printf("sec_cstring_addr: " KADDR_FMT ", sec_cstring_off: 0x%" PRIX32 ", sec_cstring_sz: 0x%" PRIX64 "\n", s64.addr, s64.offset, s64.size);
								}
							} else if(lc.cmd == LC_SYMTAB) {
								if(lc.cmdsize != sizeof(cmd_symtab)) {
									break;
								}
								memcpy(&cmd_symtab, p, sizeof(cmd_symtab));
								printf("cmd_symtab_symoff: 0x%" PRIX32 ", cmd_symtab_nsyms: 0x%" PRIX32 ", cmd_symtab_stroff: 0x%" PRIX32 "\n", cmd_symtab.symoff, cmd_symtab.nsyms, cmd_symtab.stroff);
								if(cmd_symtab.nsyms != 0 && (cmd_symtab.symoff > pfinder->kernel_sz || cmd_symtab.nsyms > (pfinder->kernel_sz - cmd_symtab.symoff) / sizeof(struct nlist_64) || cmd_symtab.stroff > pfinder->kernel_sz || cmd_symtab.strsize > pfinder->kernel_sz - cmd_symtab.stroff || cmd_symtab.strsize == 0 || pfinder->kernel[cmd_symtab.stroff + cmd_symtab.strsize - 1] != '\0')) {
									break;
								}
								pfinder->cmd_symtab = cmd_symtab;
							}
							if(pfinder->base != 0 && pfinder->sec_text.s64.size != 0 && pfinder->sec_data.s64.size != 0 && pfinder->sec_cstring.s64.size != 0 && pfinder->cmd_symtab.cmdsize != 0) {
								ret = KERN_SUCCESS;
								break;
							}
						}
					}
				}
				munmap(m, len);
			}
		}
		close(fd);
	}
	if(ret != KERN_SUCCESS) {
		pfinder_term(pfinder);
	}
	return ret;
}

static kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
	kaddr_t x[32] = { 0 };
	uint32_t insn;

	for(; sec_read_buf(pfinder.sec_text, start, &insn, sizeof(insn)) == KERN_SUCCESS; start += sizeof(insn)) {
		if(IS_LDR_X(insn)) {
			x[RD(insn)] = start + LDR_X_IMM(insn);
		} else if(IS_ADR(insn)) {
			x[RD(insn)] = start + ADR_IMM(insn);
		} else if(IS_ADD_X(insn)) {
			x[RD(insn)] = x[RN(insn)] + ADD_X_IMM(insn);
		} else if(IS_LDR_W_UNSIGNED_IMM(insn)) {
			x[RD(insn)] = x[RN(insn)] + LDR_W_UNSIGNED_IMM(insn);
		} else if(IS_LDR_X_UNSIGNED_IMM(insn)) {
			x[RD(insn)] = x[RN(insn)] + LDR_X_UNSIGNED_IMM(insn);
		} else {
			if(IS_ADRP(insn)) {
				x[RD(insn)] = ADRP_ADDR(start) + ADRP_IMM(insn);
			}
			continue;
		}
		if(RD(insn) == rd) {
			if(to == 0) {
				if(x[rd] < pfinder.base) {
					break;
				}
				return x[rd];
			}
			if(x[rd] == to) {
				return start;
			}
		}
	}
	return 0;
}

static kaddr_t
pfinder_xref_str(pfinder_t pfinder, const char *str, uint32_t rd) {
	const char *p, *e;
	size_t len;

	for(p = pfinder.sec_cstring.data, e = p + pfinder.sec_cstring.s64.size; p != e; p += len) {
		len = strlen(p) + 1;
		if(strncmp(str, p, len) == 0) {
			return pfinder_xref_rd(pfinder, rd, pfinder.sec_text.s64.addr, pfinder.sec_cstring.s64.addr + (kaddr_t)(p - pfinder.sec_cstring.data));
		}
	}
	return 0;
}

static kaddr_t
pfinder_sym(pfinder_t pfinder, const char *sym) {
	const char *p, *strtab = pfinder.kernel + pfinder.cmd_symtab.stroff;
	struct nlist_64 nl64;

	for(p = pfinder.kernel + pfinder.cmd_symtab.symoff; pfinder.cmd_symtab.nsyms-- != 0; p += sizeof(nl64)) {
		memcpy(&nl64, p, sizeof(nl64));
		if(nl64.n_un.n_strx != 0 && nl64.n_un.n_strx < pfinder.cmd_symtab.strsize && (nl64.n_type & (N_STAB | N_TYPE)) == N_SECT && nl64.n_value >= pfinder.base && strcmp(strtab + nl64.n_un.n_strx, sym) == 0) {
			return nl64.n_value + pfinder.kslide;
		}
	}
	return 0;
}

static kaddr_t
pfinder_kernproc(pfinder_t pfinder) {
	kaddr_t ref = pfinder_sym(pfinder, "_kernproc");
	uint32_t insns[2];

	if(ref != 0) {
		return ref;
	}
	for(ref = pfinder_xref_str(pfinder, "\"Should never have an EVFILT_READ except for reg or fifo.\"", 0); sec_read_buf(pfinder.sec_text, ref, insns, sizeof(insns)) == KERN_SUCCESS; ref -= sizeof(*insns)) {
		if(IS_ADRP(insns[0]) && IS_LDR_X_UNSIGNED_IMM(insns[1]) && RD(insns[1]) == 3) {
			return pfinder_xref_rd(pfinder, RD(insns[1]), ref, 0);
		}
	}
	return 0;
}

static kaddr_t
pfinder_lowglo_ptr(pfinder_t pfinder) {
	kaddr_t ref = pfinder_sym(pfinder, "_lowGlo");

	if(ref != 0) {
		return ref;
	}
	for(ref = pfinder.sec_data.s64.addr; sec_read_buf(pfinder.sec_data, ref, &lowglo, sizeof(lowglo)) == KERN_SUCCESS; ref += PAGE_MAX_SIZE) {
		if(memcmp(&lowglo.ver_code, LOWGLO_VER_CODE, sizeof(lowglo.ver_code)) == 0 && lowglo.layout_magic == LOWGLO_LAYOUT_MAGIC && lowglo.pmap_mem_page_sz == sizeof(vm_page_t)) {
			return ref;
		}
	}
	return 0;
}

static kaddr_t
pfinder_init_kbase(pfinder_t *pfinder) {
	mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
	kaddr_t addr, kext_addr, kext_addr_slid;
	CFDictionaryRef kexts_info, kext_info;
	task_dyld_info_data_t dyld_info;
	char kext_name[KMOD_MAX_NAME];
	proc_regioninfo_data_t pri;
	struct mach_header_64 mh64;
	CFStringRef kext_name_cf;
	CFNumberRef kext_addr_cf;
	CFArrayRef kext_names;

	if(pfinder->kslide == 0) {
		if(tfp0 != TASK_NULL && task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS) {
			pfinder->kslide = dyld_info.all_image_info_size;
		}
		if(pfinder->kslide == 0) {
			for(addr = 0; proc_pidinfo(0, PROC_PIDREGIONINFO, addr, &pri, sizeof(pri)) == sizeof(pri); addr += pri.pri_size) {
				addr = pri.pri_address;
				if(pri.pri_protection == VM_PROT_READ && pri.pri_user_tag == VM_KERN_MEMORY_OSKEXT) {
					if(kread_buf(addr + LOADED_KEXT_SUMMARY_HDR_NAME_OFF, kext_name, sizeof(kext_name)) == KERN_SUCCESS) {
						printf("kext_name: %s\n", kext_name);
						if(kread_addr(addr + LOADED_KEXT_SUMMARY_HDR_ADDR_OFF, &kext_addr_slid) == KERN_SUCCESS) {
							printf("kext_addr_slid: " KADDR_FMT "\n", kext_addr_slid);
							if((kext_name_cf = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, kext_name, kCFStringEncodingUTF8, kCFAllocatorNull)) != NULL) {
								if((kext_names = CFArrayCreate(kCFAllocatorDefault, (const void **)&kext_name_cf, 1, &kCFTypeArrayCallBacks)) != NULL) {
									if((kexts_info = OSKextCopyLoadedKextInfo(kext_names, NULL)) != NULL) {
										if(CFGetTypeID(kexts_info) == CFDictionaryGetTypeID() && CFDictionaryGetCount(kexts_info) == 1 && (kext_info = CFDictionaryGetValue(kexts_info, kext_name_cf)) != NULL && CFGetTypeID(kext_info) == CFDictionaryGetTypeID() && (kext_addr_cf = CFDictionaryGetValue(kext_info, CFSTR(kOSBundleLoadAddressKey))) != NULL && CFGetTypeID(kext_addr_cf) == CFNumberGetTypeID() && CFNumberGetValue(kext_addr_cf, kCFNumberSInt64Type, &kext_addr) && kext_addr_slid > kext_addr) {
											pfinder->kslide = kext_addr_slid - kext_addr;
										}
										CFRelease(kexts_info);
									}
									CFRelease(kext_names);
								}
								CFRelease(kext_name_cf);
							}
						}
					}
					break;
				}
			}
		}
	}
	if(pfinder->base + pfinder->kslide > pfinder->base && kread_buf(pfinder->base + pfinder->kslide, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE) {
		pfinder->sec_text.s64.addr += pfinder->kslide;
		pfinder->sec_data.s64.addr += pfinder->kslide;
		pfinder->sec_cstring.s64.addr += pfinder->kslide;
		printf("kbase: " KADDR_FMT ", kslide: " KADDR_FMT "\n", pfinder->base + pfinder->kslide, pfinder->kslide);
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

static char *
get_boot_path(void) {
	size_t hash_len, path_len = sizeof(BOOT_PATH);
	io_registry_entry_t chosen;
	struct stat stat_buf;
	const uint8_t *hash;
	CFDataRef hash_cf;
	char *path = NULL;

	if(stat(PREBOOT_PATH, &stat_buf) != -1 && S_ISDIR(stat_buf.st_mode) && (chosen = IORegistryEntryFromPath(kIOMasterPortDefault, kIODeviceTreePlane ":/chosen")) != IO_OBJECT_NULL) {
		if((hash_cf = IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, kNilOptions)) != NULL) {
			if(CFGetTypeID(hash_cf) == CFDataGetTypeID() && (hash_len = (size_t)CFDataGetLength(hash_cf) << 1U) != 0) {
				path_len += strlen(PREBOOT_PATH) + hash_len;
				if((path = malloc(path_len)) != NULL) {
					memcpy(path, PREBOOT_PATH, strlen(PREBOOT_PATH));
					for(hash = CFDataGetBytePtr(hash_cf); hash_len-- != 0; ) {
						path[strlen(PREBOOT_PATH) + hash_len] = "0123456789ABCDEF"[(hash[hash_len >> 1U] >> ((~hash_len & 1U) << 2U)) & 0xFU];
					}
				}
			}
			CFRelease(hash_cf);
		}
		IOObjectRelease(chosen);
	}
	if(path == NULL) {
		path_len = sizeof(BOOT_PATH);
		path = malloc(path_len);
	}
	if(path != NULL) {
		memcpy(path + (path_len - sizeof(BOOT_PATH)), BOOT_PATH, sizeof(BOOT_PATH));
	}
	return path;
}

static kern_return_t
pfinder_init_offsets(void) {
	kern_return_t ret = KERN_FAILURE;
	pfinder_t pfinder;
	char *boot_path;

	task_map_off = 0x20;
	proc_task_off = 0x18;
	proc_p_pid_off = 0x10;
	task_itk_space_off = 0x290;
	if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_10_0_b5) {
		task_itk_space_off = 0x300;
		if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0_b1) {
			task_itk_space_off = 0x308;
			if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0_b1) {
				proc_task_off = 0x10;
				proc_p_pid_off = 0x60;
				task_itk_space_off = 0x300;
				if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1) {
					task_map_off = 0x28;
					task_itk_space_off = 0x320;
					if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b2) {
						proc_p_pid_off = 0x68;
						if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_14_0_b1) {
							task_itk_space_off = 0x330;
						}
					}
				}
			}
		}
	}
	if((boot_path = get_boot_path()) != NULL) {
		printf("boot_path: %s\n", boot_path);
		if(pfinder_init_file(&pfinder, boot_path) == KERN_SUCCESS) {
			pfinder.kslide = kslide;
			if(pfinder_init_kbase(&pfinder) == KERN_SUCCESS && (kernproc = pfinder_kernproc(pfinder)) != 0) {
				printf("kernproc: " KADDR_FMT "\n", kernproc);
				if((lowglo_ptr = pfinder_lowglo_ptr(pfinder)) != 0) {
					printf("lowglo_ptr: " KADDR_FMT "\n", lowglo_ptr);
					ret = KERN_SUCCESS;
				}
			}
			pfinder_term(&pfinder);
		}
		free(boot_path);
	}
	return ret;
}

static kern_return_t
find_task(pid_t pid, kaddr_t *task) {
	pid_t cur_pid;
	kaddr_t proc;

	if(kread_addr(kernproc + PROC_P_LIST_LH_FIRST_OFF, &proc) == KERN_SUCCESS) {
		while(proc != 0 && kread_buf(proc + proc_p_pid_off, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS) {
			if(cur_pid == pid) {
				return kread_addr(proc + proc_task_off, task);
			}
			if(pid == 0 || kread_addr(proc + PROC_P_LIST_LE_PREV_OFF, &proc) != KERN_SUCCESS) {
				break;
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
vm_map_lookup_entry(kaddr_t vm_map, kaddr_t virt, vm_map_entry_t *vm_entry) {
	kaddr_t rb_entry;

	if(kread_addr(vm_map + VM_MAP_HDR_RBH_ROOT_OFF, &rb_entry) == KERN_SUCCESS) {
		while(rb_entry != 0 && rb_entry != sizeof(vm_entry->links)) {
			printf("rb_entry: " KADDR_FMT "\n", rb_entry);
			if(kread_buf(rb_entry - sizeof(vm_entry->links), vm_entry, sizeof(*vm_entry)) != KERN_SUCCESS) {
				break;
			}
			printf("start: " KADDR_FMT ", end: " KADDR_FMT ", vme_object: " KADDR_FMT ", vme_offset: 0x%" PRIX64 "\n", vm_entry->links.start, vm_entry->links.end, vm_entry->vme_object, vm_entry->vme_offset);
			if(virt >= vm_entry->links.start) {
				if(virt < vm_entry->links.end) {
					return KERN_SUCCESS;
				}
				rb_entry = vm_entry->rbe_right;
			} else {
				rb_entry = vm_entry->rbe_left;
			}
		}
	}
	return KERN_FAILURE;
}

static kaddr_t
vm_page_unpack_ptr(kaddr_t p) {
	if(p != 0) {
		if((p & lowglo.pmap_mem_from_array_mask) != 0) {
			return lowglo.pmap_mem_start_addr + lowglo.pmap_mem_page_sz * (p & ~lowglo.pmap_mem_from_array_mask);
		}
		return lowglo.pmap_mem_packed_base_addr + (p << lowglo.pmap_mem_packed_shift);
	}
	return 0;
}

static kaddr_t
vm_page_get_phys_addr(kaddr_t vm_page) {
	ppnum_t phys_page;

	if(vm_page >= lowglo.pmap_mem_start_addr && vm_page < lowglo.pmap_mem_end_addr) {
		phys_page = (ppnum_t)((vm_page - lowglo.pmap_mem_start_addr) / lowglo.pmap_mem_page_sz + lowglo.pmap_mem_first_ppnum);
	} else if(kread_buf(vm_page + lowglo.pmap_mem_page_sz, &phys_page, sizeof(phys_page)) != KERN_SUCCESS) {
		phys_page = 0;
	}
	return (kaddr_t)phys_page << vm_kernel_page_shift;
}

static kern_return_t
cf_dictionary_get_int64(CFDictionaryRef dict, const void *key, uint64_t *num) {
	CFNumberRef num_cf = CFDictionaryGetValue(dict, key);
	kern_return_t ret = KERN_FAILURE;

	if(num_cf != NULL && CFGetTypeID(num_cf) == CFNumberGetTypeID() && CFNumberGetValue(num_cf, kCFNumberSInt64Type, num)) {
		ret = KERN_SUCCESS;
	}
	return ret;
}

static io_registry_entry_t
lookup_phys_in_io_device_tree(kaddr_t phys, mach_vm_size_t sz, CFIndex *range_idx, kaddr_t *phys_off) {
	io_registry_entry_t entry = IO_OBJECT_NULL;
	CFArrayRef ranges, range;
	mach_vm_size_t cur_sz;
	CFDictionaryRef dict;
	io_iterator_t iter;
	kaddr_t cur_phys;
	CFIndex i;

	*range_idx = kCFNotFound;
	if(IORegistryCreateIterator(kIOMasterPortDefault, kIODeviceTreePlane, kIORegistryIterateRecursively, &iter) == KERN_SUCCESS) {
		while((entry = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
			if((ranges = IORegistryEntryCreateCFProperty(entry, CFSTR(kIODeviceMemoryKey), kCFAllocatorDefault, kNilOptions)) != NULL) {
				if(CFGetTypeID(ranges) == CFArrayGetTypeID()) {
					for(i = 0; i < CFArrayGetCount(ranges); ++i) {
						range = CFArrayGetValueAtIndex(ranges, i);
						if(CFGetTypeID(range) == CFArrayGetTypeID() && CFArrayGetCount(range) == 1) {
							dict = CFArrayGetValueAtIndex(range, 0);
							if(CFGetTypeID(dict) == CFDictionaryGetTypeID() && cf_dictionary_get_int64(dict, CFSTR("address"), &cur_phys) == KERN_SUCCESS && phys >= cur_phys && cf_dictionary_get_int64(dict, CFSTR("length"), &cur_sz) == KERN_SUCCESS && sz <= (cur_sz = round_page_kernel(cur_sz)) && (*phys_off = phys - cur_phys) <= cur_sz - sz) {
								*range_idx = i;
								break;
							}
						}
					}
				}
				CFRelease(ranges);
			}
			if(*range_idx != kCFNotFound) {
				break;
			}
			IOObjectRelease(entry);
		}
		IOObjectRelease(iter);
	}
	return entry;
}

static kern_return_t
lookup_ipc_port(mach_port_name_t port_name, kaddr_t *ipc_port) {
	ipc_entry_num_t port_idx, is_table_sz;
	kaddr_t itk_space, is_table;

	if(MACH_PORT_VALID(port_name) && kread_addr(our_task + task_itk_space_off, &itk_space) == KERN_SUCCESS) {
		printf("itk_space: " KADDR_FMT "\n", itk_space);
		if(kread_buf(itk_space + IPC_SPACE_IS_TABLE_SZ_OFF, &is_table_sz, sizeof(is_table_sz)) == KERN_SUCCESS) {
			printf("is_table_sz: 0x%" PRIX32 "\n", is_table_sz);
			if((port_idx = MACH_PORT_INDEX(port_name)) < is_table_sz && kread_addr(itk_space + IPC_SPACE_IS_TABLE_OFF, &is_table) == KERN_SUCCESS) {
				printf("is_table: " KADDR_FMT "\n", is_table);
				return kread_addr(is_table + port_idx * IPC_ENTRY_SZ + IPC_ENTRY_IE_OBJECT_OFF, ipc_port);
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
lookup_io_object(io_object_t object, kaddr_t *ip_kobject) {
	kaddr_t ipc_port;

	if(lookup_ipc_port(object, &ipc_port) == KERN_SUCCESS) {
		printf("ipc_port: " KADDR_FMT "\n", ipc_port);
		return kread_addr(ipc_port + IPC_PORT_IP_KOBJECT_OFF, ip_kobject);
	}
	return KERN_FAILURE;
}

static kaddr_t
lookup_key_in_os_dict(kaddr_t os_dict, const char *key) {
	kaddr_t os_dict_entry_ptr, string_ptr, val = 0;
	uint32_t os_dict_cnt, cur_key_len;
	size_t key_len = strlen(key) + 1;
	struct {
		kaddr_t key, val;
	} os_dict_entry;
	char *cur_key;

	if((cur_key = malloc(key_len)) != NULL) {
		if(kread_addr(os_dict + OS_DICTIONARY_DICT_ENTRY_OFF, &os_dict_entry_ptr) == KERN_SUCCESS && os_dict_entry_ptr != 0) {
			printf("os_dict_entry_ptr: " KADDR_FMT "\n", os_dict_entry_ptr);
			if(kread_buf(os_dict + OS_DICTIONARY_COUNT_OFF, &os_dict_cnt, sizeof(os_dict_cnt)) == KERN_SUCCESS) {
				printf("os_dict_cnt: 0x%" PRIX32 "\n", os_dict_cnt);
				while(os_dict_cnt-- != 0 && kread_buf(os_dict_entry_ptr + os_dict_cnt * sizeof(os_dict_entry), &os_dict_entry, sizeof(os_dict_entry)) == KERN_SUCCESS) {
					printf("key: " KADDR_FMT ", val: " KADDR_FMT "\n", os_dict_entry.key, os_dict_entry.val);
					if(kread_buf(os_dict_entry.key + OS_STRING_LEN_OFF, &cur_key_len, sizeof(cur_key_len)) != KERN_SUCCESS) {
						break;
					}
					cur_key_len = OS_STRING_LEN(cur_key_len);
					printf("cur_key_len: 0x%" PRIX32 "\n", cur_key_len);
					if(cur_key_len == key_len) {
						if(kread_addr(os_dict_entry.key + OS_STRING_STRING_OFF, &string_ptr) != KERN_SUCCESS || string_ptr == 0) {
							break;
						}
						printf("string_ptr: " KADDR_FMT "\n", string_ptr);
						if(kread_buf(string_ptr, cur_key, key_len) != KERN_SUCCESS) {
							break;
						}
						if(memcmp(cur_key, key, key_len) == 0) {
							val = os_dict_entry.val;
							break;
						}
					}
				}
			}
		}
		free(cur_key);
	}
	return val;
}

static kern_return_t
get_object_from_os_array(kaddr_t os_array, uint32_t idx, kaddr_t *object) {
	uint32_t os_array_cnt;
	kaddr_t array_ptr;

	if(kread_addr(os_array + OS_ARRAY_ARRAY_OFF, &array_ptr) == KERN_SUCCESS && array_ptr != 0) {
		printf("array_ptr: " KADDR_FMT "\n", array_ptr);
		if(kread_buf(os_array + OS_ARRAY_CNT_OFF, &os_array_cnt, sizeof(os_array_cnt)) == KERN_SUCCESS) {
			printf("os_array_cnt: 0x%" PRIX32 "\n", os_array_cnt);
			if(idx < os_array_cnt) {
				return kread_addr(array_ptr + idx * sizeof(*object), object);
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
get_kvirt_from_entry(io_registry_entry_t entry, uint32_t range_idx, kaddr_t *kvirt) {
	kaddr_t object, f_prop_table, ranges, range, mappings, members, mapping;

	if(lookup_io_object(entry, &object) == KERN_SUCCESS) {
		printf("object: " KADDR_FMT "\n", object);
		if(kread_addr(object + IO_REGISTRY_ENTRY_F_PROP_TABLE_OFF, &f_prop_table) == KERN_SUCCESS) {
			printf("f_prop_table: " KADDR_FMT "\n", f_prop_table);
			if((ranges = lookup_key_in_os_dict(f_prop_table, kIODeviceMemoryKey)) != 0) {
				printf("ranges: " KADDR_FMT "\n", ranges);
				if(get_object_from_os_array(ranges, range_idx, &range) == KERN_SUCCESS) {
					printf("range: " KADDR_FMT "\n", range);
					if(kread_addr(range + IO_DEVICE_MEMORY_MAPPINGS_OFF, &mappings) == KERN_SUCCESS) {
						printf("mappings: " KADDR_FMT "\n", mappings);
						if(kread_addr(mappings + OS_SET_MEMBERS_OFF, &members) == KERN_SUCCESS) {
							printf("members: " KADDR_FMT "\n", members);
							if(get_object_from_os_array(members, 0, &mapping) == KERN_SUCCESS) {
								printf("mapping: " KADDR_FMT "\n", mapping);
								return kread_addr(mapping + IO_MEMORY_MAP_F_ADDR_OFF, kvirt);
							}
						}
					}
				}
			}
		}
	}
	return KERN_FAILURE;
}

void
golb_term(void) {
	if(tfp0 != TASK_NULL) {
		mach_port_deallocate(mach_task_self(), tfp0);
	}
	setpriority(PRIO_PROCESS, 0, 0);
}

kern_return_t
golb_init(kaddr_t _kslide, kread_func_t _kread_buf, kwrite_func_t _kwrite_buf) {
	(void)_kwrite_buf;
	kslide = _kslide;
	if(_kread_buf != NULL) {
		kread_buf = _kread_buf;
	} else if(init_tfp0() == KERN_SUCCESS) {
		printf("tfp0: 0x%" PRIX32 "\n", tfp0);
		kread_buf = kread_buf_tfp0;
	}
	if(setpriority(PRIO_PROCESS, 0, PRIO_MIN) != -1 && pfinder_init_offsets() == KERN_SUCCESS && kread_buf(lowglo_ptr, &lowglo, sizeof(lowglo)) == KERN_SUCCESS && find_task(getpid(), &our_task) == KERN_SUCCESS) {
		printf("our_task: " KADDR_FMT "\n", our_task);
		if(kread_addr(our_task + task_map_off, &our_map) == KERN_SUCCESS) {
			printf("our_map: " KADDR_FMT "\n", our_map);
			return KERN_SUCCESS;
		}
	}
	golb_term();
	return KERN_FAILURE;
}

kern_return_t
golb_flush_core_tlb_asid(void) {
	return KERN_SUCCESS;
}

kaddr_t
golb_find_phys(kaddr_t virt) {
	kaddr_t vphys, vm_page, virt_off = virt & vm_kernel_page_mask;
	vm_map_entry_t vm_entry;
	vm_page_t m;

	virt -= virt_off;
	if(vm_map_lookup_entry(our_map, virt, &vm_entry) == KERN_SUCCESS && vm_entry.vme_object != 0 && trunc_page_kernel(vm_entry.vme_offset) == 0 && kread_buf(vm_entry.vme_object, &m.vmp_listq.next, sizeof(m.vmp_listq.next)) == KERN_SUCCESS) {
		while((vm_page = vm_page_unpack_ptr(m.vmp_listq.next)) != 0) {
			printf("vm_page: " KADDR_FMT "\n", vm_page);
			if(vm_page == vm_entry.vme_object || kread_buf(vm_page, &m, sizeof(m)) != KERN_SUCCESS) {
				break;
			}
			printf("vmp_offset: 0x%" PRIX64 ", vmp_object: 0x%" PRIX32 "\n", m.vmp_offset, m.vmp_object);
			if(m.vmp_offset == virt - vm_entry.links.start && vm_page_unpack_ptr(m.vmp_object) == vm_entry.vme_object && (vphys = vm_page_get_phys_addr(vm_page)) != 0) {
				return vphys + virt_off;
			}
		}
	}
	return 0;
}

void
golb_unmap(golb_ctx_t ctx) {
	mach_vm_deallocate(mach_task_self(), trunc_page_kernel(ctx.virt), ctx.page_cnt << vm_kernel_page_shift);
}

kern_return_t
golb_map(golb_ctx_t *ctx, kaddr_t phys, mach_vm_size_t sz, vm_prot_t prot) {
	kaddr_t phys_off, kvirt, start_off;
	kern_return_t ret = KERN_FAILURE;
	vm_prot_t cur_prot, max_prot;
	io_registry_entry_t entry;
	CFIndex range_idx;

	if((entry = lookup_phys_in_io_device_tree(phys, sz, &range_idx, &phys_off)) != IO_OBJECT_NULL) {
		printf("entry: 0x%" PRIX32 ", range_idx: 0x%" PRIX32 ", phys_off: " KADDR_FMT "\n", entry, (uint32_t)range_idx, phys_off);
		if(get_kvirt_from_entry(entry, (uint32_t)range_idx, &kvirt) == KERN_SUCCESS) {
			printf("kvirt: " KADDR_FMT "\n", kvirt);
			start_off = (kvirt | phys_off) & vm_kernel_page_mask;
			if((sz = round_page_kernel(sz + start_off)) != 0 && mach_vm_remap(mach_task_self(), &ctx->virt, sz, 0, VM_FLAGS_ANYWHERE, tfp0, kvirt + phys_off, FALSE, &cur_prot, &max_prot, VM_INHERIT_NONE) == KERN_SUCCESS) {
				printf("virt: " KADDR_FMT "\n", ctx->virt);
				if((~cur_prot & prot) == 0) {
					ctx->page_cnt = sz >> vm_kernel_page_shift;
					ctx->virt += start_off;
					ret = KERN_SUCCESS;
				} else {
					mach_vm_deallocate(mach_task_self(), ctx->virt, sz);
				}
			}
		}
		IOObjectRelease(entry);
	}
	return ret;
}
