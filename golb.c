#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#define PMGR_SZ (0x100000)
#define PROC_TASK_OFF (0x10)
#define VM_MAP_PMAP_OFF (0x48)
#define IO_BASE (0x200000000ULL)
#define VM_MAP_FLAGS_OFF (0x10C)
#define VM_MAP_HDR_RBH_ROOT_OFF (0x38)
#ifdef __arm64e__
#	define CPU_DATA_RTCLOCK_DATAP_OFF (0x190)
#else
#	define CPU_DATA_RTCLOCK_DATAP_OFF (0x198)
#endif
#define VM_KERNEL_LINK_ADDRESS (0xFFFFFFF007004000ULL)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b2 (1656)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b1 (1652.20)
#define kCFCoreFoundationVersionNumber_iOS_13_2_b1 (1673.12)
#define TASK_MAP_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1 ? 0x28 : 0x20)
#define PROC_P_PID_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b2 ? 0x68 : 0x60)
#define PMAP_SW_ASID_OFF (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_2_b1 ? 0xE6 : kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1 ? 0xEE : 0xDC)

#define AP_RWRW (1U)
#define AP_RORO (3U)
#define PVH_LOCK_BIT (61U)
#define PVH_TYPE_PTEP (2U)
#define ARM_PTE_AF (0x400U)
#define ARM_PTE_NG (0x800U)
#define PVH_TYPE_MASK (3ULL)
#define KADDR_FMT "0x%" PRIX64
#define VM_KERN_MEMORY_CPU (9)
#define ARM64_VMADDR_BITS (48U)
#define ARM_PTE_TYPE_VALID (3U)
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define ARM_PTE_AP(a) ((a) << 6U)
#define PVH_FLAG_CPU (1ULL << 62U)
#define LOWGLO_VER_CODE "Kraken  "
#define PVH_FLAG_EXEC (1ULL << 60U)
#define CACHE_ATTRINDX_DISABLE (3U)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define PVH_LIST_MASK (~PVH_TYPE_MASK)
#define VM_MAP_FLAGS_NO_ZERO_FILL (4U)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define PVH_FLAG_LOCKDOWN (1ULL << 59U)
#define ARM_PTE_ATTRINDX(a) ((a) << 2U)
#define ARM_PTE_NX (0x40000000000000ULL)
#define LOWGLO_LAYOUT_MAGIC (0xC0DEC0DE)
#define ARM_PTE_PNX (0x20000000000000ULL)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define FAULT_MAGIC (0xAAAAAAAAAAAAAAAAULL)
#define PVH_FLAG_LOCK (1ULL << PVH_LOCK_BIT)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define IS_MOV_X(a) (((a) & 0xFFE00000U) == 0xAA000000U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))
#define ARM_PTE_MASK trunc_page_kernel((1ULL << ARM64_VMADDR_BITS) - 1)
#define PVH_HIGH_FLAGS (PVH_FLAG_CPU | PVH_FLAG_LOCK | PVH_FLAG_EXEC | PVH_FLAG_LOCKDOWN)

#define OP_IV (2U)
#define OP_KEY (1U)
#define OP_DATA (5U)
#define OP_FLAG (8U)
#define KEY_LEN_128 (0U)
#define KEY_LEN_192 (1U)
#define KEY_LEN_256 (2U)
#define AES_CMD_ENC (0U)
#define AES_CMD_DEC (1U)
#define AES_CMD_ECB (0U)
#define AES_CMD_CBC (16U)
#define AES_BLOCK_SZ (16)
#define CMD_OP_SHIFT (28U)
#define BLOCK_MODE_ECB (0U)
#define BLOCK_MODE_CBC (1U)
#define AES_KEY_SZ_128 (0U)
#define KEY_SELECT_UID1 (1U)
#define PMGR_PS_RUN_MAX (15U)
#define AES_CMD_DIR_MASK (15U)
#define KEY_SELECT_GID_AP_1 (2U)
#define KEY_SELECT_GID_AP_2 (3U)
#define TXT_IN_STS_RDY (1U << 0U)
#define AES_CMD_MODE_MASK (0xF0U)
#define AES_KEY_TYPE_UID0 (0x100U)
#define AES_KEY_TYPE_GID0 (0x200U)
#define AES_KEY_TYPE_GID1 (0x201U)
#define AES_KEY_TYPE_MASK (0xFFFU)
#define CMD_DATA_CMD_LEN_SHIFT (0U)
#define AES_KEY_SZ_192 (0x10000000U)
#define AES_KEY_SZ_256 (0x20000000U)
#define PMGR_PS_ACTUAL_PS_MASK (15U)
#define PMGR_PS_MANUAL_PS_MASK (15U)
#define AES_BLK_CTRL_STOP_UMASK (2U)
#define PMGR_PS_ACTUAL_PS_SHIFT (4U)
#define AES_KEY_SZ_MASK (0xF0000000U)
#define IV_IN_CTRL_VAL_SET (1U << 0U)
#define CMD_FLAG_SEND_INT_SHIFT (27U)
#define AES_BLK_CTRL_START_UMASK (1U)
#define KEY_IN_CTRL_LEN_128 (0U << 6U)
#define KEY_IN_CTRL_LEN_192 (1U << 6U)
#define KEY_IN_CTRL_LEN_256 (2U << 6U)
#define KEY_IN_CTRL_VAL_SET (1U << 0U)
#define TXT_IN_CTRL_VAL_SET (1U << 0U)
#define TXT_OUT_STS_VAL_SET (1U << 0U)
#define CMD_FLAG_STOP_CMDS_SHIFT (26U)
#define KEY_IN_CTRL_MOD_ECB (0U << 13U)
#define KEY_IN_CTRL_MOD_CBC (1U << 13U)
#define KEY_IN_CTRL_DIR_DEC (0U << 12U)
#define KEY_IN_CTRL_DIR_ENC (1U << 12U)
#define KEY_IN_CTRL_SEL_UID1 (1U << 4U)
#define KEY_IN_CTRL_SEL_GID0 (2U << 4U)
#define KEY_IN_CTRL_SEL_GID1 (3U << 4U)
#define AES_AP_SZ (vm_kernel_page_size)
#define CMD_KEY_CMD_KEY_LEN_SHIFT (22U)
#define CMD_KEY_CMD_ENCRYPT_SHIFT (20U)
#define CMD_DATA_CMD_LEN_MASK (0xFFFFFFU)
#define CMD_KEY_CMD_KEY_SELECT_SHIFT (24U)
#define CMD_KEY_CMD_BLOCK_MODE_SHIFT (16U)
#define CMD_DATA_UPPER_ADDR_DST_SHIFT (0U)
#define CMD_DATA_UPPER_ADDR_SRC_SHIFT (16U)
#define CMD_DATA_UPPER_ADDR_DST_MASK (0xFFU)
#define CMD_DATA_UPPER_ADDR_SRC_MASK (0xFFU)
#define AES_BLK_INT_STATUS_FLAG_CMD_UMASK (32U)
#define PMGR_BASE_ADDR (IO_BASE + pmgr_base_off)
#define AES_AP_BASE_ADDR (IO_BASE + aes_ap_base_off)
#define rAES_CTRL (*(volatile uint32_t *)(aes_ap_virt_base + 0x8))
#define rAES_AP_DIS (*(volatile uint32_t *)(aes_ap_virt_base + 0x4))
#define rAES_CMD_FIFO (*(volatile uint32_t *)(aes_ap_virt_base + 0x200))
#define rAES_AP_IV_IN0 (*(volatile uint32_t *)(aes_ap_virt_base + 0x100))
#define rAES_AP_IV_IN1 (*(volatile uint32_t *)(aes_ap_virt_base + 0x104))
#define rAES_AP_IV_IN2 (*(volatile uint32_t *)(aes_ap_virt_base + 0x108))
#define rAES_AP_IV_IN3 (*(volatile uint32_t *)(aes_ap_virt_base + 0x10C))
#define rAES_AP_TXT_IN0 (*(volatile uint32_t *)(aes_ap_virt_base + 0x40))
#define rAES_AP_TXT_IN1 (*(volatile uint32_t *)(aes_ap_virt_base + 0x44))
#define rAES_AP_TXT_IN2 (*(volatile uint32_t *)(aes_ap_virt_base + 0x48))
#define rAES_AP_TXT_IN3 (*(volatile uint32_t *)(aes_ap_virt_base + 0x4C))
#define rAES_INT_STATUS (*(volatile uint32_t *)(aes_ap_virt_base + 0x18))
#define rAES_AP_TXT_OUT0 (*(volatile uint32_t *)(aes_ap_virt_base + 0x80))
#define rAES_AP_TXT_OUT1 (*(volatile uint32_t *)(aes_ap_virt_base + 0x84))
#define rAES_AP_TXT_OUT2 (*(volatile uint32_t *)(aes_ap_virt_base + 0x88))
#define rAES_AP_TXT_OUT3 (*(volatile uint32_t *)(aes_ap_virt_base + 0x8C))
#define rAES_AP_TXT_IN_STS (*(volatile uint32_t *)(aes_ap_virt_base + 0xC))
#define rAES_AP_IV_IN_CTRL (*(volatile uint32_t *)(aes_ap_virt_base + 0xE0))
#define rAES_AP_TXT_IN_CTRL (*(volatile uint32_t *)(aes_ap_virt_base + 0x8))
#define rAES_AP_KEY_IN_CTRL (*(volatile uint32_t *)(aes_ap_virt_base + 0x90))
#define rAES_AP_TXT_OUT_STS (*(volatile uint32_t *)(aes_ap_virt_base + 0x50))
#define rPMGR_AES0_PS (*(volatile uint32_t *)(pmgr_virt_base + pmgr_aes0_ps_off))

#ifndef SEG_TEXT_EXEC
#	define SEG_TEXT_EXEC "__TEXT_EXEC"
#endif

#ifndef SECT_CSTRING
#	define SECT_CSTRING "__cstring"
#endif

#ifndef MIN
#	define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef uint64_t kaddr_t;

typedef struct {
	uint32_t cmd, iv[4];
} cmd_iv_t;

typedef struct {
	uint32_t cmd, key[8];
} cmd_key_t;

typedef struct {
	uint32_t key_id, key[4], val[4];
} key_seed_t;

typedef struct {
	uint32_t cmd, upper_addr, src_addr, dst_addr;
} cmd_data_t;

typedef struct {
	struct section_64 s64;
	char *data;
} sec_64_t;

typedef struct {
	sec_64_t sec_text, sec_data, sec_cstring;
	kaddr_t pc;
} pfinder_t;

typedef struct {
	uint16_t rev, ver;
	uint32_t pad;
	kaddr_t virt_base, phys_base;
	uint64_t mem_sz;
} boot_args_t;

typedef struct {
	struct {
		kaddr_t prev, next, start, end;
	} links;
	kaddr_t rbe_left, rbe_right, rbe_parent, vme_object;
	uint64_t vme_offset;
} vm_map_entry_t;

typedef struct {
	struct {
		uint32_t next, prev;
	} vmp_q_pageq, vmp_listq, vmp_backgroundq;
	uint64_t vmp_offset;
	uint32_t vmp_object, q_flags, vmp_next_m, o_flags;
} vm_page_t;

typedef struct {
	struct {
		kaddr_t ptep, pte;
	} *orig;
	size_t orig_cnt;
} phys_ctx_t;

typedef struct {
	uint8_t ver_code[8];
	kaddr_t zero, stext, ver, os_ver, kmod_ptr, trans_off, reboot_flag, manual_pkt_addr, alt_debugger, pmap_memq, pmap_mem_page_off, pmap_mem_chain_off, static_addr, static_sz, layout_major_ver, layout_magic, pmap_mem_start_addr, pmap_mem_end_addr, pmap_mem_page_sz, pmap_mem_from_array_mask, pmap_mem_first_ppnum, pmap_mem_packed_shift, pmap_mem_packed_base_addr, layout_minor_ver, page_shift;
} lowglo_t;

kern_return_t
mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);

kern_return_t
mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);

kern_return_t
mach_vm_copy(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t);

kern_return_t
mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

kern_return_t
mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

static bool aes_ap_v2;
static lowglo_t lowglo;
static boot_args_t boot_args;
static task_t tfp0 = MACH_PORT_NULL;
static phys_ctx_t pmgr_ctx, aes_ap_ctx;
static kaddr_t allproc, const_boot_args, pv_head_table_ptr, pv_head_table, our_map, our_pmap, aes_ap_base_off, pmgr_base_off, aes_ap_virt_base, pmgr_virt_base, pmgr_aes0_ps_off;

static key_seed_t uid_key_seeds[] = {
	{ 0x839, { 0xC55BB624, 0xDCDCDD8F, 0x6C8B5498, 0x4D84E73E }, { 0 } },
	{ 0x83A, { 0xDBAB10CB, 0x63ECC98A, 0xB4C228DB, 0x060ED6A9 }, { 0 } },
	{ 0x83B, { 0x87D0A77D, 0x171EFE90, 0xB83E2DC6, 0x2D94D81F }, { 0 } },
	{ 0x83C, { 0xD34AC2B2, 0xD84BF05D, 0x547433A0, 0x644EE6C4 }, { 0 } },
	{ 0x899, { 0xB5FCE8D1, 0x8DBF3739, 0xD14CC7EF, 0xB0D4F1D0 }, { 0 } },
	{ 0x89B, { 0x67993E18, 0x543CB06B, 0xF568A46F, 0x49BD0C1C }, { 0 } },
	{ 0x89C, { 0x7140B400, 0xCFF3A1A8, 0xFF9B2FD9, 0xFCDD75FB }, { 0 } },
	{ 0x89D, { 0xD8C29F34, 0x2C8AFBA6, 0xB47C0329, 0xAD23DAAC }, { 0 } },
	{ 0x8A0, { 0xC599B4D1, 0xDC3CA139, 0xD19BA498, 0xB0DD0C3E }, { 0 } },
	{ 0x8A3, { 0x65418256, 0xCDE05165, 0x4CF86FF5, 0xEF791AC1 }, { 0 } },
	{ 0x8A4, { 0xDFF7310C, 0x034D9281, 0xFA37B48C, 0xC9F76003 }, { 0 } }
};

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
	return (val >> start) & (~0U >> (32U - len));
}

static uint64_t
sextract64(uint64_t val, unsigned start, unsigned len) {
	return (uint64_t)((int64_t)(val << (64U - len - start)) >> (64U - len));
}

static kern_return_t
init_arm_globals(void) {
	int cpufamily = CPUFAMILY_UNKNOWN;
	size_t len = sizeof(cpufamily);

	if(sysctlbyname("hw.cpufamily", &cpufamily, &len, NULL, 0) == 0) {
		switch(cpufamily) {
			case CPUFAMILY_ARM_CYCLONE:
				pmgr_base_off = 0xE000000;
				pmgr_aes0_ps_off = 0x20100;
				aes_ap_base_off = 0xA108000;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_TYPHOON:
				pmgr_base_off = 0xE000000;
				pmgr_aes0_ps_off = 0x201E8;
				aes_ap_base_off = 0xA108000;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_TWISTER:
				aes_ap_v2 = true;
				pmgr_base_off = 0xE000000;
				pmgr_aes0_ps_off = 0x80210;
				aes_ap_base_off = 0xA108000;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_HURRICANE:
				aes_ap_v2 = true;
				pmgr_base_off = 0xE000000;
				pmgr_aes0_ps_off = 0x80220;
				aes_ap_base_off = 0xA108000;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_MONSOON_MISTRAL:
				aes_ap_v2 = true;
				pmgr_base_off = 0x32000000;
				pmgr_aes0_ps_off = 0x80240;
				aes_ap_base_off = 0x2E008000;
				return KERN_SUCCESS;
#if 0
			case CPUFAMILY_ARM_VORTEX_TEMPEST:
				aes_ap_v2 = true;
				pmgr_base_off = 0x3B000000;
				pmgr_aes0_ps_off = 0x80220;
				aes_ap_base_off = 0x35008000;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_LIGHTNING_THUNDER:
				aes_ap_v2 = true;
				pmgr_base_off = 0x3B000000;
				pmgr_aes0_ps_off = 0x801D0;
				aes_ap_base_off = 0x35008000;
				return KERN_SUCCESS;
#endif
			default:
				break;
		}
	}
	return KERN_FAILURE;
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
kread_buf(kaddr_t addr, void *buf, mach_vm_size_t sz) {
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
kwrite_buf(kaddr_t addr, const void *buf, mach_msg_type_number_t sz) {
	vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_msg_type_number_t write_sz;

	while(sz != 0) {
		write_sz = (mach_msg_type_number_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
		if(mach_vm_write(tfp0, addr, p, write_sz) != KERN_SUCCESS || mach_vm_machine_attribute(tfp0, addr, write_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
			return KERN_FAILURE;
		}
		p += write_sz;
		sz -= write_sz;
		addr += write_sz;
	}
	return KERN_SUCCESS;
}

static kern_return_t
kwrite_addr(kaddr_t addr, kaddr_t val) {
	return kwrite_buf(addr, &val, sizeof(val));
}

static kaddr_t
get_kbase(kaddr_t *kslide) {
	mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
	vm_region_extended_info_data_t extended_info;
	task_dyld_info_data_t dyld_info;
	kaddr_t addr, rtclock_datap;
	struct mach_header_64 mh64;
	mach_port_t obj_nm;
	mach_vm_size_t sz;

	if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS && dyld_info.all_image_info_size != 0) {
		*kslide = dyld_info.all_image_info_size;
		return VM_KERNEL_LINK_ADDRESS + *kslide;
	}
	cnt = VM_REGION_EXTENDED_INFO_COUNT;
	for(addr = 0; mach_vm_region(tfp0, &addr, &sz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&extended_info, &cnt, &obj_nm) == KERN_SUCCESS; addr += sz) {
		mach_port_deallocate(mach_task_self(), obj_nm);
		if(extended_info.user_tag == VM_KERN_MEMORY_CPU && extended_info.protection == VM_PROT_DEFAULT) {
			if(kread_addr(addr + CPU_DATA_RTCLOCK_DATAP_OFF, &rtclock_datap) != KERN_SUCCESS) {
				break;
			}
			printf("rtclock_datap: " KADDR_FMT "\n", rtclock_datap);
			rtclock_datap = trunc_page_kernel(rtclock_datap);
			do {
				if(rtclock_datap <= VM_KERNEL_LINK_ADDRESS) {
					return 0;
				}
				rtclock_datap -= vm_kernel_page_size;
				if(kread_buf(rtclock_datap, &mh64, sizeof(mh64)) != KERN_SUCCESS) {
					return 0;
				}
			} while(mh64.magic != MH_MAGIC_64 || mh64.cputype != CPU_TYPE_ARM64 || mh64.filetype != MH_EXECUTE);
			*kslide = rtclock_datap - VM_KERNEL_LINK_ADDRESS;
			return rtclock_datap;
		}
	}
	return 0;
}

static kern_return_t
find_section(kaddr_t sg64_addr, struct segment_command_64 sg64, const char *sect_name, struct section_64 *sp) {
	kaddr_t s64_addr, s64_end;

	for(s64_addr = sg64_addr + sizeof(sg64), s64_end = s64_addr + (sg64.cmdsize - sizeof(*sp)); s64_addr < s64_end; s64_addr += sizeof(*sp)) {
		if(kread_buf(s64_addr, sp, sizeof(*sp)) != KERN_SUCCESS) {
			break;
		}
		if(strncmp(sp->segname, sg64.segname, sizeof(sp->segname)) == 0 && strncmp(sp->sectname, sect_name, sizeof(sp->sectname)) == 0) {
			return KERN_SUCCESS;
		}
	}
	return KERN_FAILURE;
}

static void
sec_reset(sec_64_t *sec) {
	memset(&sec->s64, '\0', sizeof(sec->s64));
	sec->data = NULL;
}

static void
sec_term(sec_64_t *sec) {
	free(sec->data);
	sec_reset(sec);
}

static kern_return_t
sec_init(sec_64_t *sec) {
	if((sec->data = malloc(sec->s64.size)) != NULL) {
		if(kread_buf(sec->s64.addr, sec->data, sec->s64.size) == KERN_SUCCESS) {
			return KERN_SUCCESS;
		}
		sec_term(sec);
	}
	return KERN_FAILURE;
}

static void
pfinder_reset(pfinder_t *pfinder) {
	pfinder->pc = 0;
	sec_reset(&pfinder->sec_text);
	sec_reset(&pfinder->sec_data);
	sec_reset(&pfinder->sec_cstring);
}

static void
pfinder_term(pfinder_t *pfinder) {
	sec_term(&pfinder->sec_text);
	sec_term(&pfinder->sec_data);
	sec_term(&pfinder->sec_cstring);
	pfinder_reset(pfinder);
}

static kern_return_t
pfinder_init(pfinder_t *pfinder, kaddr_t kbase, kaddr_t kslide) {
	arm_unified_thread_state_t state;
	kern_return_t ret = KERN_FAILURE;
	struct segment_command_64 sg64;
	kaddr_t sg64_addr, sg64_end;
	struct mach_header_64 mh64;
	struct section_64 s64;

	pfinder_reset(pfinder);
	if(kread_buf(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE) {
		for(sg64_addr = kbase + sizeof(mh64), sg64_end = sg64_addr + (mh64.sizeofcmds - sizeof(sg64)); sg64_addr < sg64_end; sg64_addr += sg64.cmdsize) {
			if(kread_buf(sg64_addr, &sg64, sizeof(sg64)) != KERN_SUCCESS) {
				break;
			}
			if(sg64.cmd == LC_SEGMENT_64) {
				if(strncmp(sg64.segname, SEG_TEXT_EXEC, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_TEXT, &s64) == KERN_SUCCESS) {
					pfinder->sec_text.s64 = s64;
					printf("sec_text_addr: " KADDR_FMT ", sec_text_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				} else if(strncmp(sg64.segname, SEG_DATA, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_DATA, &s64) == KERN_SUCCESS) {
					pfinder->sec_data.s64 = s64;
					printf("sec_data_addr: " KADDR_FMT ", sec_data_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				} else if(strncmp(sg64.segname, SEG_TEXT, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_CSTRING, &s64) == KERN_SUCCESS) {
					pfinder->sec_cstring.s64 = s64;
					printf("sec_cstring_addr: " KADDR_FMT ", sec_cstring_sz: 0x%" PRIX64 "\n", s64.addr, s64.size);
				}
			} else if(sg64.cmd == LC_UNIXTHREAD) {
				if(kread_buf(sg64_addr + sizeof(struct thread_command), &state, sizeof(state)) != KERN_SUCCESS) {
					break;
				}
#undef ts_64
				pfinder->pc = state.uts.ts_64.__pc + kslide;
			}
			if(pfinder->sec_text.s64.size != 0 && pfinder->sec_data.s64.size != 0 && pfinder->sec_cstring.s64.size != 0 && pfinder->pc != 0) {
				if(sec_init(&pfinder->sec_text) == KERN_SUCCESS && sec_init(&pfinder->sec_data) == KERN_SUCCESS) {
					ret = sec_init(&pfinder->sec_cstring);
				}
				break;
			}
		}
	}
	if(ret != KERN_SUCCESS) {
		pfinder_term(pfinder);
	}
	return ret;
}

static kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
	uint64_t x[32] = { 0 };
	uint32_t insn;

	for(; start >= pfinder.sec_text.s64.addr && start < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insn)); start += sizeof(insn)) {
		memcpy(&insn, pfinder.sec_text.data + (start - pfinder.sec_text.s64.addr), sizeof(insn));
		if(IS_LDR_X(insn)) {
			x[RD(insn)] = start + LDR_X_IMM(insn);
		} else if(IS_ADR(insn)) {
			x[RD(insn)] = start + ADR_IMM(insn);
		} else if(IS_ADRP(insn)) {
			x[RD(insn)] = ADRP_ADDR(start) + ADRP_IMM(insn);
			continue;
		} else if(IS_ADD_X(insn)) {
			x[RD(insn)] = x[RN(insn)] + ADD_X_IMM(insn);
		} else if(IS_LDR_X_UNSIGNED_IMM(insn)) {
			x[RD(insn)] = x[RN(insn)] + LDR_X_UNSIGNED_IMM(insn);
		} else if(IS_RET(insn)) {
			memset(x, '\0', sizeof(x));
		}
		if(RD(insn) == rd) {
			if(to == 0) {
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

	for(p = pfinder.sec_cstring.data, e = p + pfinder.sec_cstring.s64.size; p < e; p += len) {
		len = strlen(p) + 1;
		if(strncmp(str, p, len) == 0) {
			return pfinder_xref_rd(pfinder, rd, pfinder.sec_text.s64.addr, pfinder.sec_cstring.s64.addr + (kaddr_t)(p - pfinder.sec_cstring.data));
		}
	}
	return 0;
}

static kaddr_t
pfinder_allproc(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "shutdownwait", 2);

	if(ref == 0) {
		ref = pfinder_xref_str(pfinder, "shutdownwait", 3); /* msleep */
	}
	return pfinder_xref_rd(pfinder, 8, ref, 0);
}

static kaddr_t
pfinder_pv_head_table_ptr(pfinder_t pfinder) {
	uint32_t insns[3];
	kaddr_t ref;

	for(ref = pfinder_xref_str(pfinder, "pmap_iommu_ioctl_internal", 8); ref >= pfinder.sec_text.s64.addr && ref < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insns)); ref -= sizeof(*insns)) {
		memcpy(insns, pfinder.sec_text.data + (ref - pfinder.sec_text.s64.addr), sizeof(insns));
		if(IS_ADRP(insns[0]) && IS_LDR_X_UNSIGNED_IMM(insns[1]) && IS_MOV_X(insns[2]) && RD(insns[2]) == 0) {
			return pfinder_xref_rd(pfinder, RD(insns[1]), ref, 0);
		}
	}
	return 0;
}

static kaddr_t
pfinder_const_boot_args(pfinder_t pfinder) {
	return pfinder_xref_rd(pfinder, 20, ADRP_ADDR(pfinder.pc), 0);
}

static kern_return_t
pfinder_lowglo(pfinder_t pfinder) {
	const char *p, *e;

	for(p = pfinder.sec_data.data, e = p + (pfinder.sec_data.s64.size - sizeof(lowglo)); p < e; p += PAGE_MAX_SIZE) {
		memcpy(&lowglo, p, sizeof(lowglo));
		if(memcmp(&lowglo.ver_code, LOWGLO_VER_CODE, sizeof(lowglo.ver_code)) == 0 && lowglo.layout_major_ver == 3 && lowglo.layout_magic == LOWGLO_LAYOUT_MAGIC && lowglo.pmap_mem_page_sz == sizeof(vm_page_t) && lowglo.layout_minor_ver == 0) {
			printf("lowglo: " KADDR_FMT "\n", pfinder.sec_data.s64.addr + (kaddr_t)(p - pfinder.sec_data.data));
			return KERN_SUCCESS;
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
pfinder_init_offsets(pfinder_t pfinder) {
	if((allproc = pfinder_allproc(pfinder)) != 0) {
		printf("allproc: " KADDR_FMT "\n", allproc);
		if((pv_head_table_ptr = pfinder_pv_head_table_ptr(pfinder)) != 0) {
			printf("pv_head_table_ptr: " KADDR_FMT "\n", pv_head_table_ptr);
			if((const_boot_args = pfinder_const_boot_args(pfinder)) != 0) {
				printf("const_boot_args: " KADDR_FMT "\n", const_boot_args);
				return pfinder_lowglo(pfinder);
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
find_task(pid_t pid, kaddr_t *task) {
	kaddr_t proc = allproc;
	pid_t cur_pid;

	while(kread_addr(proc, &proc) == KERN_SUCCESS && proc != 0) {
		if(kread_buf(proc + PROC_P_PID_OFF, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS && cur_pid == pid) {
			return kread_addr(proc + PROC_TASK_OFF, task);
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
vm_map_lookup_entry(kaddr_t vm_map, kaddr_t virt, vm_map_entry_t *vm_entry) {
	kaddr_t rb_entry;

	if(kread_addr(vm_map + VM_MAP_HDR_RBH_ROOT_OFF, &rb_entry) == KERN_SUCCESS) {
		while(rb_entry != sizeof(vm_entry->links)) {
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
		if(p & lowglo.pmap_mem_from_array_mask) {
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
phys_init(void) {
	kaddr_t our_task;
	uint32_t flags;

	if(kread_addr(pv_head_table_ptr, &pv_head_table) == KERN_SUCCESS) {
		printf("pv_head_table: " KADDR_FMT "\n", pv_head_table);
		if(kread_buf(const_boot_args, &boot_args, sizeof(boot_args)) == KERN_SUCCESS) {
			printf("virt_base: " KADDR_FMT ", phys_base: " KADDR_FMT ", mem_sz: 0x%" PRIX64 "\n", boot_args.virt_base, boot_args.phys_base, boot_args.mem_sz);
			if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
				printf("our_task: " KADDR_FMT "\n", our_task);
				if(kread_addr(our_task + TASK_MAP_OFF, &our_map) == KERN_SUCCESS) {
					printf("our_map: " KADDR_FMT "\n", our_map);
					if(kread_addr(our_map + VM_MAP_PMAP_OFF, &our_pmap) == KERN_SUCCESS) {
						printf("our_pmap: " KADDR_FMT "\n", our_pmap);
						if(kread_buf(our_map + VM_MAP_FLAGS_OFF, &flags, sizeof(flags)) == KERN_SUCCESS) {
							printf("flags: 0x%" PRIX32 "\n", flags);
							flags |= VM_MAP_FLAGS_NO_ZERO_FILL;
							return kwrite_buf(our_map + VM_MAP_FLAGS_OFF, &flags, sizeof(flags));
						}
					}
				}
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
phys_flush_core_tlb_asid(void) {
	uint8_t orig_sw_asid, fake_sw_asid = UINT8_MAX;

	if(kread_buf(our_pmap + PMAP_SW_ASID_OFF, &orig_sw_asid, sizeof(orig_sw_asid)) == KERN_SUCCESS) {
		printf("orig_sw_asid: 0x%" PRIX8 "\n", orig_sw_asid);
		if(orig_sw_asid != fake_sw_asid && kwrite_buf(our_pmap + PMAP_SW_ASID_OFF, &fake_sw_asid, sizeof(fake_sw_asid)) == KERN_SUCCESS) {
			return kwrite_buf(our_pmap + PMAP_SW_ASID_OFF, &orig_sw_asid, sizeof(orig_sw_asid));
		}
	}
	return KERN_FAILURE;
}

static kaddr_t
phys_find(kaddr_t virt) {
	kaddr_t vphys, vm_page, virt_off = virt & vm_kernel_page_mask;
	vm_map_entry_t vm_entry;
	vm_page_t m;

	virt -= virt_off;
	if(vm_map_lookup_entry(our_map, virt, &vm_entry) == KERN_SUCCESS && vm_entry.vme_object != 0 && vm_entry.vme_offset == 0 && kread_buf(vm_entry.vme_object, &m.vmp_listq.next, sizeof(m.vmp_listq.next)) == KERN_SUCCESS) {
		while((vm_page = vm_page_unpack_ptr(m.vmp_listq.next)) != 0 && vm_page != vm_entry.vme_object) {
			printf("vm_page: " KADDR_FMT "\n", vm_page);
			if(kread_buf(vm_page, &m, sizeof(m)) != KERN_SUCCESS) {
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

static void
phys_unmap(phys_ctx_t ctx) {
	size_t i;

	for(i = 0; i < ctx.orig_cnt; ++i) {
		kwrite_addr(ctx.orig[i].ptep, ctx.orig[i].pte);
	}
	phys_flush_core_tlb_asid();
	free(ctx.orig);
}

static kern_return_t
phys_map(phys_ctx_t *ctx, kaddr_t virt, kaddr_t phys, mach_vm_size_t sz, vm_prot_t prot) {
	kaddr_t phys_off, vm_page, vphys, pv_h, ptep, orig_pte, fake_pte;
	mach_vm_offset_t map_off;
	vm_map_entry_t vm_entry;
	vm_page_t m;

	if((virt & vm_kernel_page_mask) != 0) {
		return KERN_FAILURE;
	}
	phys_off = phys & vm_kernel_page_mask;
	if((sz = round_page_kernel(sz + phys_off)) == 0) {
		return KERN_FAILURE;
	}
	phys -= phys_off;
	for(map_off = 0; map_off < sz; map_off += vm_kernel_page_size) {
		*(volatile kaddr_t *)(virt + map_off) = FAULT_MAGIC;
	}
	if(vm_map_lookup_entry(our_map, virt, &vm_entry) != KERN_SUCCESS || vm_entry.vme_object == 0 || vm_entry.vme_offset != 0 || (vm_entry.links.end - virt) < sz || kread_buf(vm_entry.vme_object, &m.vmp_listq.next, sizeof(m.vmp_listq.next)) != KERN_SUCCESS || (ctx->orig = calloc(sz >> vm_kernel_page_shift, sizeof(ctx->orig[0]))) == NULL) {
		return KERN_FAILURE;
	}
	ctx->orig_cnt = 0;
	for(map_off = 0; map_off < sz; map_off += vm_kernel_page_size) {
		if((vm_page = vm_page_unpack_ptr(m.vmp_listq.next)) == 0) {
			break;
		}
		printf("vm_page: " KADDR_FMT "\n", vm_page);
		if(vm_page == vm_entry.vme_object || kread_buf(vm_page, &m, sizeof(m)) != KERN_SUCCESS) {
			break;
		}
		printf("vmp_offset: 0x%" PRIX64 ", vmp_object: 0x%" PRIX32 "\n", m.vmp_offset, m.vmp_object);
		if(m.vmp_offset != map_off + (virt - vm_entry.links.start) || vm_page_unpack_ptr(m.vmp_object) != vm_entry.vme_object || (vphys = vm_page_get_phys_addr(vm_page)) == 0) {
			break;
		}
		printf("vphys: " KADDR_FMT "\n", vphys);
		if(vphys < boot_args.phys_base || vphys >= trunc_page_kernel(boot_args.phys_base + boot_args.mem_sz) || kread_addr(pv_head_table + ((vphys - boot_args.phys_base) >> vm_kernel_page_shift) * sizeof(kaddr_t), &pv_h) != KERN_SUCCESS) {
			break;
		}
		printf("pv_h: " KADDR_FMT "\n", pv_h);
		if((pv_h & PVH_TYPE_MASK) != PVH_TYPE_PTEP) {
			break;
		}
		ptep = (pv_h & PVH_LIST_MASK) | PVH_HIGH_FLAGS;
		printf("ptep: " KADDR_FMT "\n", ptep);
		if(kread_addr(ptep, &orig_pte) != KERN_SUCCESS) {
			break;
		}
		printf("orig_pte: " KADDR_FMT "\n", orig_pte);
		if((orig_pte & ARM_PTE_TYPE_VALID) == 0 || (orig_pte & ARM_PTE_MASK) != vphys) {
			break;
		}
		ctx->orig[ctx->orig_cnt].ptep = ptep;
		ctx->orig[ctx->orig_cnt++].pte = orig_pte;
		fake_pte = ((phys + map_off) & ARM_PTE_MASK) | ARM_PTE_TYPE_VALID | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DISABLE) | ARM_PTE_AF | ARM_PTE_AP((prot & VM_PROT_WRITE) != 0 ? AP_RWRW : AP_RORO) | ARM_PTE_NX | ARM_PTE_PNX | ARM_PTE_NG;
		if(kwrite_addr(ptep, fake_pte) != KERN_SUCCESS) {
			break;
		}
	}
	if(map_off != sz || phys_flush_core_tlb_asid() != KERN_SUCCESS) {
		phys_unmap(*ctx);
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

static kern_return_t
aes_ap_init(void) {
	if(mach_vm_allocate(mach_task_self(), &aes_ap_virt_base, AES_AP_SZ, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
		printf("aes_ap_virt_base: " KADDR_FMT "\n", aes_ap_virt_base);
		if(phys_map(&aes_ap_ctx, aes_ap_virt_base, AES_AP_BASE_ADDR, AES_AP_SZ, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
			if(mach_vm_allocate(mach_task_self(), &pmgr_virt_base, PMGR_SZ, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
				printf("pmgr_virt_base: " KADDR_FMT "\n", pmgr_virt_base);
				if(phys_map(&pmgr_ctx, pmgr_virt_base, PMGR_BASE_ADDR, PMGR_SZ, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
					return KERN_SUCCESS;
				}
				mach_vm_deallocate(mach_task_self(), pmgr_virt_base, PMGR_SZ);
			}
			phys_unmap(aes_ap_ctx);
		}
		mach_vm_deallocate(mach_task_self(), aes_ap_virt_base, AES_AP_SZ);
	}
	return KERN_FAILURE;
}

static kern_return_t
aes_ap_v1_cmd(uint32_t cmd, const void *src, void *dst, size_t len, uint32_t opts) {
	uint32_t *local_dst = dst, key_in_ctrl = 0;
	kern_return_t ret = KERN_FAILURE;
	const uint32_t *local_src = src;
	size_t i;

	if((len % AES_BLOCK_SZ) != 0) {
		return KERN_FAILURE;
	}
	switch(cmd & AES_CMD_MODE_MASK) {
		case AES_CMD_ECB:
			key_in_ctrl |= KEY_IN_CTRL_MOD_ECB;
			break;
		case AES_CMD_CBC:
			key_in_ctrl |= KEY_IN_CTRL_MOD_CBC;
			break;
		default:
			return ret;
	}
	switch(cmd & AES_CMD_DIR_MASK) {
		case AES_CMD_ENC:
			key_in_ctrl |= KEY_IN_CTRL_DIR_ENC;
			break;
		case AES_CMD_DEC:
			key_in_ctrl |= KEY_IN_CTRL_DIR_DEC;
			break;
		default:
			return ret;
	}
	switch(opts & AES_KEY_SZ_MASK) {
		case AES_KEY_SZ_128:
			key_in_ctrl |= KEY_IN_CTRL_LEN_128;
			break;
		case AES_KEY_SZ_192:
			key_in_ctrl |= KEY_IN_CTRL_LEN_192;
			break;
		case AES_KEY_SZ_256:
			key_in_ctrl |= KEY_IN_CTRL_LEN_256;
			break;
		default:
			return ret;
	}
	switch(opts & AES_KEY_TYPE_MASK) {
		case AES_KEY_TYPE_UID0:
			key_in_ctrl |= KEY_IN_CTRL_SEL_UID1;
			break;
		case AES_KEY_TYPE_GID0:
			key_in_ctrl |= KEY_IN_CTRL_SEL_GID0;
			break;
		case AES_KEY_TYPE_GID1:
			key_in_ctrl |= KEY_IN_CTRL_SEL_GID1;
			break;
		default:
			return ret;
	}
	rPMGR_AES0_PS |= PMGR_PS_RUN_MAX;
	while((rPMGR_AES0_PS & PMGR_PS_MANUAL_PS_MASK) != ((rPMGR_AES0_PS >> PMGR_PS_ACTUAL_PS_SHIFT) & PMGR_PS_ACTUAL_PS_MASK)) {}
	if((rAES_AP_DIS & (opts & AES_KEY_TYPE_MASK)) != (opts & AES_KEY_TYPE_MASK)) {
		printf("old_iv: 0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "\n", rAES_AP_IV_IN0, rAES_AP_IV_IN1, rAES_AP_IV_IN2, rAES_AP_IV_IN3);
		printf("old_in: 0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "\n", rAES_AP_TXT_IN0, rAES_AP_TXT_IN1, rAES_AP_TXT_IN2, rAES_AP_TXT_IN3);
		printf("old_out: 0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "\n", rAES_AP_TXT_OUT0, rAES_AP_TXT_OUT1, rAES_AP_TXT_OUT2, rAES_AP_TXT_OUT3);
		rAES_AP_KEY_IN_CTRL = key_in_ctrl | KEY_IN_CTRL_VAL_SET;
		rAES_AP_IV_IN0 = rAES_AP_IV_IN1 = rAES_AP_IV_IN2 = rAES_AP_IV_IN3 = 0;
		rAES_AP_IV_IN_CTRL = IV_IN_CTRL_VAL_SET;
		for(i = 0; i < len / AES_BLOCK_SZ; ++i) {
			while((rAES_AP_TXT_IN_STS & TXT_IN_STS_RDY) != TXT_IN_STS_RDY) {}
			rAES_AP_TXT_IN0 = local_src[i];
			rAES_AP_TXT_IN1 = local_src[i + 1];
			rAES_AP_TXT_IN2 = local_src[i + 2];
			rAES_AP_TXT_IN3 = local_src[i + 3];
			rAES_AP_TXT_IN_CTRL = TXT_IN_CTRL_VAL_SET;
			while((rAES_AP_TXT_OUT_STS & TXT_OUT_STS_VAL_SET) != TXT_OUT_STS_VAL_SET) {}
			local_dst[i] = rAES_AP_TXT_OUT0;
			local_dst[i + 1] = rAES_AP_TXT_OUT1;
			local_dst[i + 2] = rAES_AP_TXT_OUT2;
			local_dst[i + 3] = rAES_AP_TXT_OUT3;
		}
		ret = KERN_SUCCESS;
	}
	rPMGR_AES0_PS &= ~PMGR_PS_RUN_MAX;
	while((rPMGR_AES0_PS & PMGR_PS_MANUAL_PS_MASK) != ((rPMGR_AES0_PS >> PMGR_PS_ACTUAL_PS_SHIFT) & PMGR_PS_ACTUAL_PS_MASK)) {}
	return ret;
}

static void
push_cmds(const uint32_t *cmd, size_t len) {
	size_t i;

	for(i = 0; i < len / sizeof(*cmd); ++i) {
		rAES_CMD_FIFO = cmd[i];
	}
}

static kern_return_t
aes_ap_v2_cmd(uint32_t cmd, kaddr_t phys_src, kaddr_t phys_dst, size_t len, uint32_t opts) {
	cmd_data_t data;
	cmd_key_t ckey;
	uint32_t flag;
	cmd_iv_t civ;

	if((len % AES_BLOCK_SZ) != 0) {
		return KERN_FAILURE;
	}
	ckey.cmd = OP_KEY << CMD_OP_SHIFT;
	switch(cmd & AES_CMD_MODE_MASK) {
		case AES_CMD_ECB:
			ckey.cmd |= BLOCK_MODE_ECB << CMD_KEY_CMD_BLOCK_MODE_SHIFT;
			break;
		case AES_CMD_CBC:
			ckey.cmd |= BLOCK_MODE_CBC << CMD_KEY_CMD_BLOCK_MODE_SHIFT;
			break;
		default:
			return KERN_FAILURE;
	}
	switch(cmd & AES_CMD_DIR_MASK) {
		case AES_CMD_ENC:
			ckey.cmd |= 1U << CMD_KEY_CMD_ENCRYPT_SHIFT;
			break;
		case AES_CMD_DEC:
			ckey.cmd |= 0U << CMD_KEY_CMD_ENCRYPT_SHIFT;
			break;
		default:
			return KERN_FAILURE;
	}
	switch(opts & AES_KEY_SZ_MASK) {
		case AES_KEY_SZ_128:
			ckey.cmd |= KEY_LEN_128 << CMD_KEY_CMD_KEY_LEN_SHIFT;
			break;
		case AES_KEY_SZ_192:
			ckey.cmd |= KEY_LEN_192 << CMD_KEY_CMD_KEY_LEN_SHIFT;
			break;
		case AES_KEY_SZ_256:
			ckey.cmd |= KEY_LEN_256 << CMD_KEY_CMD_KEY_LEN_SHIFT;
			break;
		default:
			return KERN_FAILURE;
	}
	switch(opts & AES_KEY_TYPE_MASK) {
		case AES_KEY_TYPE_UID0:
			ckey.cmd |= KEY_SELECT_UID1 << CMD_KEY_CMD_KEY_SELECT_SHIFT;
			break;
		case AES_KEY_TYPE_GID0:
			ckey.cmd |= KEY_SELECT_GID_AP_1 << CMD_KEY_CMD_KEY_SELECT_SHIFT;
			break;
		case AES_KEY_TYPE_GID1:
			ckey.cmd |= KEY_SELECT_GID_AP_2 << CMD_KEY_CMD_KEY_SELECT_SHIFT;
			break;
		default:
			return KERN_FAILURE;
	}
	rPMGR_AES0_PS |= PMGR_PS_RUN_MAX;
	while((rPMGR_AES0_PS & PMGR_PS_MANUAL_PS_MASK) != ((rPMGR_AES0_PS >> PMGR_PS_ACTUAL_PS_SHIFT) & PMGR_PS_ACTUAL_PS_MASK)) {}
	rAES_INT_STATUS = AES_BLK_INT_STATUS_FLAG_CMD_UMASK;
	rAES_CTRL = AES_BLK_CTRL_START_UMASK;
	push_cmds(&ckey.cmd, sizeof(ckey.cmd));
	civ.cmd = OP_IV << CMD_OP_SHIFT;
	memset(&civ.iv, '\0', sizeof(civ.iv));
	push_cmds(&civ.cmd, sizeof(civ));
	data.cmd = (OP_DATA << CMD_OP_SHIFT) | ((uint32_t)(len & CMD_DATA_CMD_LEN_MASK) << CMD_DATA_CMD_LEN_SHIFT);
	data.upper_addr = ((uint32_t)(phys_src >> 32U) & CMD_DATA_UPPER_ADDR_SRC_MASK) << CMD_DATA_UPPER_ADDR_SRC_SHIFT;
	data.upper_addr |= ((uint32_t)(phys_dst >> 32U) & CMD_DATA_UPPER_ADDR_DST_MASK) << CMD_DATA_UPPER_ADDR_DST_SHIFT;
	data.src_addr = (uint32_t)phys_src;
	data.dst_addr = (uint32_t)phys_dst;
	push_cmds(&data.cmd, sizeof(data));
	flag = (OP_FLAG << CMD_OP_SHIFT) | (1U << CMD_FLAG_SEND_INT_SHIFT) | (1U << CMD_FLAG_STOP_CMDS_SHIFT);
	push_cmds(&flag, sizeof(flag));
	while((rAES_INT_STATUS & AES_BLK_INT_STATUS_FLAG_CMD_UMASK) == 0) {}
	rAES_INT_STATUS = AES_BLK_INT_STATUS_FLAG_CMD_UMASK;
	rAES_CTRL = AES_BLK_CTRL_STOP_UMASK;
	if(pmgr_aes0_ps_off != 0x80240) {
		rPMGR_AES0_PS &= ~PMGR_PS_RUN_MAX;
		while((rPMGR_AES0_PS & PMGR_PS_MANUAL_PS_MASK) != ((rPMGR_AES0_PS >> PMGR_PS_ACTUAL_PS_SHIFT) & PMGR_PS_ACTUAL_PS_MASK)) {}
	}
	return KERN_SUCCESS;
}

static kern_return_t
aes_ap_cmd(uint32_t cmd, const void *src, void *dst, size_t len, uint32_t opts) {
	kaddr_t virt_src = (kaddr_t)src, virt_dst = (kaddr_t)dst, phys_src, phys_dst;
	vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
	size_t aes_len;

	if(aes_ap_v2) {
		while(len != 0) {
			if((phys_src = phys_find(virt_src)) == 0) {
				return KERN_FAILURE;
			}
			printf("phys_src: " KADDR_FMT "\n", phys_src);
			if((phys_dst = phys_find(virt_dst)) == 0) {
				return KERN_FAILURE;
			}
			printf("phys_dst: " KADDR_FMT "\n", phys_dst);
			aes_len = MIN(len, MIN(vm_kernel_page_size - (phys_src & vm_kernel_page_mask), vm_kernel_page_size - (phys_dst & vm_kernel_page_mask)));
			if(aes_ap_v2_cmd(cmd, phys_src, phys_dst, aes_len, opts) != KERN_SUCCESS || mach_vm_machine_attribute(mach_task_self(), virt_dst, aes_len, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
				return KERN_FAILURE;
			}
			virt_src += aes_len;
			virt_dst += aes_len;
			len -= aes_len;
		}
		return KERN_SUCCESS;
	}
	return aes_ap_v1_cmd(cmd, src, dst, len, opts);
}

static void
aes_ap_test(void) {
	size_t i;

	for(i = 0; i < sizeof(uid_key_seeds) / sizeof(uid_key_seeds[0]); ++i) {
		if(aes_ap_cmd(AES_CMD_CBC | AES_CMD_ENC, uid_key_seeds[i].key, uid_key_seeds[i].val, sizeof(uid_key_seeds[i].key), AES_KEY_SZ_256 | AES_KEY_TYPE_UID0) == KERN_SUCCESS) {
			printf("key_id: 0x%" PRIX32 ", val: 0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "\n", uid_key_seeds[i].key_id, uid_key_seeds[i].val[0], uid_key_seeds[i].val[1], uid_key_seeds[i].val[2], uid_key_seeds[i].val[3]);
		}
	}
}

static kern_return_t
aes_ap_file(const char *dir, const char *key_type, const char *in_filename, const char *out_filename) {
	uint32_t cmd = AES_CMD_CBC, opts = AES_KEY_SZ_256;
	kern_return_t ret = KERN_FAILURE;
	struct stat stat_buf;
	int in_fd, out_fd;
	size_t len;
	void *buf;

	if(strcmp(dir, "enc") == 0) {
		cmd |= AES_CMD_ENC;
	} else if(strcmp(dir, "dec") == 0) {
		cmd |= AES_CMD_DEC;
	} else {
		return ret;
	}
	if(strcmp(key_type, "UID0") == 0) {
		opts |= AES_KEY_TYPE_UID0;
	} else if(strcmp(key_type, "GID0") == 0) {
		opts |= AES_KEY_TYPE_GID0;
	} else if(strcmp(key_type, "GID1") == 0) {
		opts |= AES_KEY_TYPE_GID1;
	} else {
		return ret;
	}
	if((in_fd = open(in_filename, O_RDONLY | O_CLOEXEC)) != -1) {
		if(fstat(in_fd, &stat_buf) != -1 && stat_buf.st_size > 0) {
			len = (size_t)stat_buf.st_size;
			if((len % AES_BLOCK_SZ) == 0 && (buf = malloc(len)) != NULL) {
				if(read(in_fd, buf, len) != -1 && aes_ap_cmd(cmd, buf, buf, len, opts) == KERN_SUCCESS && (out_fd = open(out_filename, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, S_IROTH | S_IRGRP | S_IWUSR | S_IRUSR)) != -1) {
					if(write(out_fd, buf, len) != -1) {
						ret = KERN_SUCCESS;
					}
					close(out_fd);
				}
				free(buf);
			}
		}
		close(in_fd);
	}
	return ret;
}

static void
aes_ap_term(void) {
	phys_unmap(aes_ap_ctx);
	mach_vm_deallocate(mach_task_self(), aes_ap_virt_base, AES_AP_SZ);
	phys_unmap(pmgr_ctx);
	mach_vm_deallocate(mach_task_self(), pmgr_virt_base, PMGR_SZ);
}

int
main(int argc, char **argv) {
	kaddr_t kbase, kslide;
	pfinder_t pfinder;

	if(argc >= 2 && argc < 5) {
		printf("Usage: %s [enc/dec UID0/GID0/GID1 in out]\n", argv[0]);
	} else if(init_arm_globals() == KERN_SUCCESS) {
		printf("pmgr_base_off: " KADDR_FMT ", aes_ap_base_off: " KADDR_FMT ", pmgr_aes0_ps_off: " KADDR_FMT "\n", pmgr_base_off, aes_ap_base_off, pmgr_aes0_ps_off);
		if(init_tfp0() == KERN_SUCCESS) {
			printf("tfp0: 0x%" PRIX32 "\n", tfp0);
			if((kbase = get_kbase(&kslide))) {
				printf("kbase: " KADDR_FMT ", kslide: " KADDR_FMT "\n", kbase, kslide);
				if(pfinder_init(&pfinder, kbase, kslide) == KERN_SUCCESS) {
					if(pfinder_init_offsets(pfinder) == KERN_SUCCESS && phys_init() == KERN_SUCCESS && aes_ap_init() == KERN_SUCCESS) {
						if(argc == 5) {
							printf("aes_ap_file: 0x%" PRIX32 "\n", aes_ap_file(argv[1], argv[2], argv[3], argv[4]));
						} else {
							aes_ap_test();
						}
						aes_ap_term();
					}
					pfinder_term(&pfinder);
				}
			}
			mach_port_deallocate(mach_task_self(), tfp0);
		}
	}
}
