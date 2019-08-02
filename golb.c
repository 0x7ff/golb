#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

#define TASK_MAP_OFF (0x20)
#define PMGR_SIZE (0x100000)
#define PROC_TASK_OFF (0x10)
#define PROC_P_PID_OFF (0x60)
#define VM_MAP_PMAP_OFF (0x48)
#define IO_BASE (0x200000000ULL)
#define VM_MAP_FLAGS_OFF (0x10C)
#define USER_CLIENT_TRAP_OFF (0x40)
#define IPC_PORT_IP_KOBJECT_OFF (0x68)
#define TASK_ITK_REGISTERED_OFF (0x2E8)
#define VTAB_GET_EXTERNAL_TRAP_FOR_INDEX_OFF (0x5B8)

#define AP_RWRW (1U)
#define AP_RORO (3U)
#define PVH_LOCK_BIT (61U)
#define PVH_TYPE_PTEP (2U)
#define ARM_PTE_AF (0x400U)
#define PVH_TYPE_MASK (3ULL)
#define ARM_PGSHIFT_4K (12U)
#define ARM_PGSHIFT_16K (14U)
#define KADDR_FMT "0x%" PRIx64
#define ARM64_VMADDR_BITS (48U)
#define ARM_PTE_TYPE_VALID (3U)
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define MAX_VTAB_SZ (ARM_PGBYTES)
#define ARM_PTE_AP(a) ((a) << 6U)
#define PVH_FLAG_CPU (1ULL << 62U)
#define PVH_FLAG_EXEC (1ULL << 60U)
#define CACHE_ATTRINDX_DISABLE (3U)
#define IS_ISB(a) ((a) == 0xD5033FDFU)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define PVH_LIST_MASK (~PVH_TYPE_MASK)
#define VM_MAP_FLAGS_NO_ZERO_FILL (4U)
#define ARM_PGMASK (ARM_PGBYTES - 1ULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define ARM_PGBYTES (1U << arm_pgshift)
#define IO_OBJECT_NULL ((io_object_t)0)
#define PVH_FLAG_LOCKDOWN (1ULL << 59U)
#define ARM_PTE_ATTRINDX(a) ((a) << 2U)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define TRUNC_PAGE(a) ((a) & ~ARM_PGMASK)
#define IS_DSB_ISH(a) ((a) == 0xD5033B9FU)
#define FAULT_MAGIC (0x4455445564666477ULL)
#define PVH_FLAG_LOCK (1ULL << PVH_LOCK_BIT)
#define BL_IMM(a) (sextract64(a, 0, 26) << 2U)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define IS_TLBI_VMALLE1IS(a) ((a) == 0xD508831FU)
#define ROUND_PAGE(a) TRUNC_PAGE((a) + ARM_PGMASK)
#define IS_BL(a) (((a) & 0xFC000000U) == 0x94000000U)
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_IN_RANGE(a, b, c) ((a) >= (b) && (a) < (c))
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_CBZ_W(a) (((a) & 0xFF000000U) == 0x34000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define ARM_PTE_MASK TRUNC_PAGE((1ULL << ARM64_VMADDR_BITS) - 1)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))
#define PVH_HIGH_FLAGS (PVH_FLAG_CPU | PVH_FLAG_LOCK | PVH_FLAG_EXEC | PVH_FLAG_LOCKDOWN)

#define OPCODE_IV (2U)
#define OPCODE_KEY (1U)
#define KEY_LEN_128 (0U)
#define KEY_LEN_192 (1U)
#define KEY_LEN_256 (2U)
#define OPCODE_DATA (5U)
#define OPCODE_FLAG (8U)
#define AES_CMD_ENC (0U)
#define AES_CMD_DEC (1U)
#define AES_CMD_ECB (0U)
#define AES_CMD_CBC (16U)
#define AES_BLOCK_SIZE (16)
#define BLOCK_MODE_ECB (0U)
#define BLOCK_MODE_CBC (1U)
#define KEY_SELECT_UID1 (1U)
#define PMGR_PS_RUN_MAX (15U)
#define AES_KEY_SIZE_128 (0U)
#define AES_CMD_DIR_MASK (15U)
#define KEY_SELECT_GID_AP_1 (2U)
#define KEY_SELECT_GID_AP_2 (3U)
#define AES_AP_SIZE (ARM_PGBYTES)
#define TXT_IN_STS_RDY (1U << 0U)
#define AES_CMD_MODE_MASK (0xF0U)
#define AES_KEY_TYPE_UID0 (0x100U)
#define AES_KEY_TYPE_GID0 (0x200U)
#define AES_KEY_TYPE_GID1 (0x201U)
#define AES_KEY_TYPE_MASK (0xFFFU)
#define COMMAND_OPCODE_SHIFT (28U)
#define PMGR_PS_ACTUAL_PS_MASK (15U)
#define PMGR_PS_MANUAL_PS_MASK (15U)
#define PMGR_PS_ACTUAL_PS_SHIFT (4U)
#define IV_IN_CTRL_VAL_SET (1U << 0U)
#define KEY_IN_CTRL_LEN_128 (0U << 6U)
#define KEY_IN_CTRL_LEN_192 (1U << 6U)
#define KEY_IN_CTRL_LEN_256 (2U << 6U)
#define KEY_IN_CTRL_VAL_SET (1U << 0U)
#define TXT_IN_CTRL_VAL_SET (1U << 0U)
#define TXT_OUT_STS_VAL_SET (1U << 0U)
#define AES_KEY_SIZE_192 (0x10000000U)
#define AES_KEY_SIZE_256 (0x20000000U)
#define AES_KEY_SIZE_MASK (0xF0000000U)
#define KEY_IN_CTRL_MOD_ECB (0U << 13U)
#define KEY_IN_CTRL_MOD_CBC (1U << 13U)
#define KEY_IN_CTRL_DIR_DEC (0U << 12U)
#define KEY_IN_CTRL_DIR_ENC (1U << 12U)
#define KEY_IN_CTRL_SEL_UID1 (1U << 4U)
#define KEY_IN_CTRL_SEL_GID0 (2U << 4U)
#define KEY_IN_CTRL_SEL_GID1 (3U << 4U)
#define AES_BLK_CONTROL_STOP_UMASK (2U)
#define AES_BLK_CONTROL_START_UMASK (1U)
#define COMMAND_FLAG_STOP_COMMANDS_SHIFT (27U)
#define COMMAND_DATA_COMMAND_LENGTH_SHIFT (0U)
#define COMMAND_KEY_COMMAND_ENCRYPT_SHIFT (20U)
#define COMMAND_FLAG_SEND_INTERRUPT_SHIFT (26U)
#define COMMAND_DATA_UPPER_ADDR_DEST_SHIFT (0U)
#define PMGR_BASE_ADDR (IO_BASE + pmgr_base_off)
#define COMMAND_DATA_UPPER_ADDR_DEST_MASK (0xFFU)
#define COMMAND_KEY_COMMAND_BLOCK_MODE_SHIFT (16U)
#define COMMAND_DATA_UPPER_ADDR_SOURCE_SHIFT (16U)
#define COMMAND_KEY_COMMAND_KEY_LENGTH_SHIFT (22U)
#define COMMAND_KEY_COMMAND_KEY_SELECT_SHIFT (24U)
#define COMMAND_DATA_UPPER_ADDR_SOURCE_MASK (0xFFU)
#define AES_BLK_INT_STATUS_FLAG_COMMAND_UMASK (32U)
#define AES_AP_BASE_ADDR (IO_BASE + aes_ap_base_off)
#define COMMAND_DATA_COMMAND_LENGTH_MASK (0xFFFFFFU)
#define rAES_CONTROL (*(volatile uint32_t *)(aes_ap_virt_base + 0x8))
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
#define rAES_COMMAND_FIFO (*(volatile uint32_t *)(aes_ap_virt_base + 0x200))
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
typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

typedef struct {
	kaddr_t sec_text_start;
	uint64_t sec_text_sz;
	void *sec_text;
	kaddr_t sec_cstring_start;
	uint64_t sec_cstring_sz;
	void *sec_cstring;
	kaddr_t pc;
} pfinder_t;

typedef struct {
	kaddr_t obj;
	kaddr_t func;
	kaddr_t delta;
} io_external_trap_t;

typedef struct {
	uint16_t revision;
	uint16_t version;
	uint32_t padding;
	kaddr_t virt_base;
	kaddr_t phys_base;
	kaddr_t mem_size;
} boot_args_t;

typedef struct {
	struct {
		kaddr_t ptep;
		kaddr_t pte;
	} *orig;
	size_t orig_cnt;
} phys_ctx_t;

typedef struct {
	uint32_t command;
	uint32_t key[8];
} command_key_t;

typedef struct {
	uint32_t command;
	uint32_t iv[4];
} command_iv_t;

typedef struct {
	uint32_t command;
	uint32_t upper_addr;
	uint32_t source_addr;
	uint32_t dest_addr;
} command_data_t;

typedef struct {
	uint32_t id;
	uint32_t key[4];
	uint32_t val[4];
} key_seed_t;

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
mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);

kern_return_t
IOObjectRelease(io_object_t);

CFMutableDictionaryRef
IOServiceMatching(const char *);

io_service_t
IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);

kern_return_t
IOServiceOpen(io_service_t, task_port_t, uint32_t type, io_connect_t *);

kern_return_t
IOConnectTrap6(io_connect_t, uint32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

kern_return_t
IOServiceClose(io_connect_t);

extern const mach_port_t kIOMasterPortDefault;

static bool aes_ap_v2;
static unsigned arm_pgshift;
static boot_args_t boot_args;
static task_t tfp0 = MACH_PORT_NULL;
static phys_ctx_t pmgr_ctx, aes_ap_ctx;
static io_connect_t g_conn = IO_OBJECT_NULL;
static kaddr_t allproc, csblob_get_cdhash, pmap_find_phys, const_boot_args, flush_mmu_tlb, pv_head_table_ptr, pv_head_table, orig_vtab, fake_vtab, user_client, our_pmap, aes_ap_base_off, pmgr_base_off, aes_ap_virt_base, pmgr_virt_base, pmgr_aes0_ps_off;

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
extract32(uint32_t value, unsigned start, unsigned length) {
	return (value >> start) & (~0U >> (32U - length));
}

static uint64_t
sextract64(uint64_t value, unsigned start, unsigned length) {
	return (uint64_t)((int64_t)(value << (64U - length - start)) >> (64U - length));
}

static kern_return_t
init_arm_globals(void) {
	int cpufamily = CPUFAMILY_UNKNOWN;
	size_t len = sizeof(cpufamily);

	if(!sysctlbyname("hw.cpufamily", &cpufamily, &len, NULL, 0)) {
		switch(cpufamily) {
			case CPUFAMILY_ARM_CYCLONE:
				pmgr_base_off = 0xE000000;
				pmgr_aes0_ps_off = 0x20100;
				aes_ap_base_off = 0xA108000;
				arm_pgshift = ARM_PGSHIFT_4K;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_TYPHOON:
				pmgr_base_off = 0xE000000;
				pmgr_aes0_ps_off = 0x201E8;
				aes_ap_base_off = 0xA108000;
				arm_pgshift = ARM_PGSHIFT_4K;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_TWISTER:
				aes_ap_v2 = true;
				pmgr_base_off = 0xE000000;
				pmgr_aes0_ps_off = 0x80210;
				aes_ap_base_off = 0xA108000;
				arm_pgshift = ARM_PGSHIFT_16K;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_HURRICANE:
				aes_ap_v2 = true;
				pmgr_base_off = 0xE000000;
				pmgr_aes0_ps_off = 0x80220;
				aes_ap_base_off = 0xA108000;
				arm_pgshift = ARM_PGSHIFT_16K;
				return KERN_SUCCESS;
			case CPUFAMILY_ARM_MONSOON_MISTRAL:
				aes_ap_v2 = true;
				pmgr_base_off = 0x32000000;
				pmgr_aes0_ps_off = 0x80240;
				aes_ap_base_off = 0x2E008000;
				arm_pgshift = ARM_PGSHIFT_16K;
				return KERN_SUCCESS;
#if 0
			case CPUFAMILY_ARM_VORTEX_TEMPEST:
				aes_ap_v2 = true;
				pmgr_base_off = 0x3B000000;
				pmgr_aes0_ps_off = 0x80220;
				aes_ap_base_off = 0x35008000;
				arm_pgshift = ARM_PGSHIFT_16K;
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
			printf("host: 0x%" PRIx32 "\n", host);
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

static kaddr_t
get_kbase(kaddr_t *kslide) {
	mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
	task_dyld_info_data_t dyld_info;

	if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS) {
		*kslide = dyld_info.all_image_info_size;
		return dyld_info.all_image_info_addr;
	}
	return 0;
}

static kern_return_t
kread_buf(kaddr_t addr, void *buf, mach_vm_size_t sz) {
	mach_vm_address_t p = (mach_vm_address_t)buf;
	mach_vm_size_t read_sz, out_sz = 0;

	while(sz) {
		read_sz = MIN(sz, ARM_PGBYTES - (addr & ARM_PGMASK));
		if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
			return KERN_FAILURE;
		}
		p += read_sz;
		sz -= read_sz;
		addr += read_sz;
	}
	return KERN_SUCCESS;
}

static void *
kread_buf_alloc(kaddr_t addr, mach_vm_size_t read_sz) {
	void *buf = malloc(read_sz);

	if(buf) {
		if(kread_buf(addr, buf, read_sz) == KERN_SUCCESS) {
			return buf;
		}
		free(buf);
	}
	return NULL;
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

	while(sz) {
		write_sz = MIN(sz, ARM_PGBYTES - (addr & ARM_PGMASK));
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

static kern_return_t
kalloc(mach_vm_size_t sz, kaddr_t *addr) {
	return mach_vm_allocate(tfp0, addr, sz, VM_FLAGS_ANYWHERE);
}

static kern_return_t
kfree(kaddr_t addr, mach_vm_size_t sz) {
	return mach_vm_deallocate(tfp0, addr, sz);
}

static const struct section_64 *
find_section(const struct segment_command_64 *sgp, const char *sect_name) {
	const struct section_64 *sp = (const struct section_64 *)(sgp + 1);
	uint32_t i;

	for(i = 0; i < sgp->nsects; ++i) {
		if(!strncmp(sp->segname, sgp->segname, sizeof(sp->segname)) && !strncmp(sp->sectname, sect_name, sizeof(sp->sectname))) {
			return sp;
		}
		++sp;
	}
	return NULL;
}

static void
pfinder_reset(pfinder_t *pfinder) {
	pfinder->sec_text = pfinder->sec_cstring = NULL;
	pfinder->sec_text_start = pfinder->sec_text_sz = 0;
	pfinder->sec_cstring_start = pfinder->sec_cstring_sz = 0;
	pfinder->pc = 0;
}

static kern_return_t
pfinder_init(pfinder_t *pfinder, kaddr_t kbase, kaddr_t kslide) {
	const arm_unified_thread_state_t *state;
	const struct segment_command_64 *sgp;
	kern_return_t ret = KERN_FAILURE;
	const struct section_64 *sp;
	struct mach_header_64 mh64;
	uint32_t i;
	void *ptr;

	pfinder_reset(pfinder);
	if(kread_buf(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && (ptr = kread_buf_alloc(kbase + sizeof(mh64), mh64.sizeofcmds))) {
		sgp = (const struct segment_command_64 *)ptr;
		for(i = 0; i < mh64.ncmds; ++i) {
			if(sgp->cmd == LC_SEGMENT_64) {
				if(!strncmp(sgp->segname, SEG_TEXT_EXEC, sizeof(sgp->segname)) && (sp = find_section(sgp, SECT_TEXT))) {
					pfinder->sec_text_start = sp->addr;
					pfinder->sec_text_sz = sp->size;
					printf("sec_text_start: " KADDR_FMT ", sec_text_sz: 0x%" PRIx64 "\n", pfinder->sec_text_start, pfinder->sec_text_sz);
				} else if(!strncmp(sgp->segname, SEG_TEXT, sizeof(sgp->segname)) && (sp = find_section(sgp, SECT_CSTRING))) {
					pfinder->sec_cstring_start = sp->addr;
					pfinder->sec_cstring_sz = sp->size;
					printf("sec_cstring_start: " KADDR_FMT ", sec_cstring_sz: 0x%" PRIx64 "\n", pfinder->sec_cstring_start, pfinder->sec_cstring_sz);
				}
			} else if(sgp->cmd == LC_UNIXTHREAD) {
				state = (const arm_unified_thread_state_t *)((uintptr_t)sgp + sizeof(struct thread_command));
				pfinder->pc = state->ts_64.__pc + kslide;
			}
			if(pfinder->sec_text_sz && pfinder->sec_cstring_sz && pfinder->pc) {
				if((pfinder->sec_text = kread_buf_alloc(pfinder->sec_text_start, pfinder->sec_text_sz))) {
					if((pfinder->sec_cstring = kread_buf_alloc(pfinder->sec_cstring_start, pfinder->sec_cstring_sz))) {
						ret = KERN_SUCCESS;
					} else {
						free(pfinder->sec_text);
					}
				}
				break;
			}
			sgp = (const struct segment_command_64 *)((uintptr_t)sgp + sgp->cmdsize);
		}
		free(ptr);
	}
	return ret;
}

static kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
	const uint32_t *insn = pfinder.sec_text;
	uint64_t x[32] = { 0 };
	size_t i;

	for(i = (start - pfinder.sec_text_start) / sizeof(*insn); i < pfinder.sec_text_sz / sizeof(*insn); ++i) {
		if(IS_LDR_X(insn[i])) {
			x[RD(insn[i])] = pfinder.sec_text_start + (i * sizeof(*insn)) + LDR_X_IMM(insn[i]);
		} else if(IS_ADR(insn[i])) {
			x[RD(insn[i])] = pfinder.sec_text_start + (i * sizeof(*insn)) + ADR_IMM(insn[i]);
		} else if(IS_ADRP(insn[i])) {
			x[RD(insn[i])] = ADRP_ADDR(pfinder.sec_text_start + (i * sizeof(*insn))) + ADRP_IMM(insn[i]);
			continue;
		} else if(IS_ADD_X(insn[i])) {
			x[RD(insn[i])] = x[RN(insn[i])] + ADD_X_IMM(insn[i]);
		} else if(IS_LDR_X_UNSIGNED_IMM(insn[i])) {
			x[RD(insn[i])] = x[RN(insn[i])] + LDR_X_UNSIGNED_IMM(insn[i]);
		} else if(IS_RET(insn[i])) {
			memset(x, '\0', sizeof(x));
		}
		if(RD(insn[i]) == rd) {
			if(to) {
				if(x[rd] == to) {
					return pfinder.sec_text_start + (i * sizeof(*insn));
				}
			} else {
				return x[rd];
			}
		}
	}
	return 0;
}

static kaddr_t
pfinder_xref_str(pfinder_t pfinder, const char *str, uint32_t rd) {
	const char *p = pfinder.sec_cstring, *e = p + pfinder.sec_cstring_sz;
	size_t len;

	do {
		len = strlen(p) + 1;
		if(!strncmp(str, p, len)) {
			return pfinder_xref_rd(pfinder, rd, pfinder.sec_text_start, pfinder.sec_cstring_start + (kaddr_t)(p - (const char *)pfinder.sec_cstring));
		}
		p += len;
	} while(p < e);
	return 0;
}

static kaddr_t
pfinder_allproc(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "shutdownwait", 2);

	if(!ref) {
		ref = pfinder_xref_str(pfinder, "shutdownwait", 3); /* msleep */
	}
	return ref ? pfinder_xref_rd(pfinder, 8, ref, 0) : 0;
}

static kaddr_t
pfinder_csblob_get_cdhash(pfinder_t pfinder) {
	const uint32_t *insn = pfinder.sec_text;
	size_t i;

	for(i = 0; i < (pfinder.sec_text_sz / sizeof(*insn)) - 1; ++i) {
		if(IS_ADD_X(insn[i]) && RD(insn[i]) == 0 && RN(insn[i]) == 0 && ADD_X_IMM(insn[i]) == USER_CLIENT_TRAP_OFF && IS_RET(insn[i + 1])) {
			return pfinder.sec_text_start + (i * sizeof(*insn));
		}
	}
	return 0;
}

static kaddr_t
pfinder_pmap_find_phys(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "Kext %s - page %p is not backed by physical memory.", 2);
	const uint32_t *insn = pfinder.sec_text;
	size_t i;

	if(ref) {
		for(i = (ref - pfinder.sec_text_start) / sizeof(*insn); i > 0; --i) {
			if(IS_BL(insn[i])) {
				return pfinder.sec_text_start + (i * sizeof(*insn)) + BL_IMM(insn[i]);
			}
		}
	}
	return 0;
}

static kaddr_t
pfinder_pv_head_table_ptr(pfinder_t pfinder) {
	kaddr_t ref = pfinder_xref_str(pfinder, "\"pmap_batch_set_cache_attributes(): pn 0x%08x not managed\"", 0);
	const uint32_t *insn = pfinder.sec_text;
	size_t i;

	if(ref) {
		for(i = (ref - pfinder.sec_text_start) / sizeof(*insn); i < (pfinder.sec_text_sz / sizeof(*insn)) - 2; ++i) {
			if(IS_CBZ_W(insn[i]) && IS_ADRP(insn[i + 1]) && IS_LDR_X_UNSIGNED_IMM(insn[i + 2])) {
				return pfinder_xref_rd(pfinder, RD(insn[i + 1]), pfinder.sec_text_start + (i * sizeof(*insn)), 0);
			}
		}
	}
	return 0;
}

static kaddr_t
pfinder_const_boot_args(pfinder_t pfinder) {
	return pfinder_xref_rd(pfinder, 20, ADRP_ADDR(pfinder.pc), 0);
}

static kaddr_t
pfinder_flush_mmu_tlb(pfinder_t pfinder) {
	const uint32_t *insn = pfinder.sec_text;
	size_t i;

	for(i = 0; i < (pfinder.sec_text_sz / sizeof(*insn)) - 3; ++i) {
		if(IS_TLBI_VMALLE1IS(insn[i]) && IS_DSB_ISH(insn[i + 1]) && IS_ISB(insn[i + 2]) && IS_RET(insn[i + 3])) {
			return pfinder.sec_text_start + (i * sizeof(*insn));
		}
	}
	return 0;
}

static kern_return_t
pfinder_init_offsets(pfinder_t pfinder) {
	if((allproc = pfinder_allproc(pfinder))) {
		printf("allproc: " KADDR_FMT "\n", allproc);
		if((csblob_get_cdhash = pfinder_csblob_get_cdhash(pfinder))) {
			printf("csblob_get_cdhash: " KADDR_FMT "\n", csblob_get_cdhash);
			if((pmap_find_phys = pfinder_pmap_find_phys(pfinder))) {
				printf("pmap_find_phys: " KADDR_FMT "\n", pmap_find_phys);
				if((pv_head_table_ptr = pfinder_pv_head_table_ptr(pfinder))) {
					printf("pv_head_table_ptr: " KADDR_FMT "\n", pv_head_table_ptr);
					if((const_boot_args = pfinder_const_boot_args(pfinder))) {
						printf("const_boot_args: " KADDR_FMT "\n", const_boot_args);
						if((flush_mmu_tlb = pfinder_flush_mmu_tlb(pfinder))) {
							printf("flush_mmu_tlb: " KADDR_FMT "\n", flush_mmu_tlb);
							return KERN_SUCCESS;
						}
					}
				}
			}
		}
	}
	return KERN_FAILURE;
}

static void
pfinder_term(pfinder_t *pfinder) {
	free(pfinder->sec_text);
	free(pfinder->sec_cstring);
	pfinder_reset(pfinder);
}

static kern_return_t
find_task(pid_t pid, kaddr_t *task) {
	kaddr_t proc = allproc;
	pid_t cur_pid;

	while(kread_addr(proc, &proc) == KERN_SUCCESS && proc) {
		if(kread_buf(proc + PROC_P_PID_OFF, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS && cur_pid == pid) {
			return kread_addr(proc + PROC_TASK_OFF, task);
		}
	}
	return KERN_FAILURE;
}

static io_connect_t
get_conn(const char *name) {
	io_service_t serv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(name));
	io_connect_t conn = IO_OBJECT_NULL;

	if(MACH_PORT_VALID(serv)) {
		printf("serv: 0x%" PRIx32 "\n", serv);
		if(IOServiceOpen(serv, mach_task_self(), 0, &conn) != KERN_SUCCESS || !MACH_PORT_VALID(conn)) {
			conn = IO_OBJECT_NULL;
		}
		IOObjectRelease(serv);
	}
	return conn;
}

static kaddr_t
get_port(kaddr_t our_task, mach_port_t port) {
	kaddr_t ipc_port = 0;

	if(mach_ports_register(mach_task_self(), &port, 1) == KERN_SUCCESS) {
		if(kread_addr(our_task + TASK_ITK_REGISTERED_OFF, &ipc_port) != KERN_SUCCESS) {
			ipc_port = 0;
		}
		mach_ports_register(mach_task_self(), NULL, 0);
	}
	return ipc_port;
}

static void
kcall_term(void) {
	io_external_trap_t trap = { 0 };

	if(MACH_PORT_VALID(g_conn)) {
		if(fake_vtab) {
			kwrite_addr(user_client, orig_vtab);
			kfree(fake_vtab, MAX_VTAB_SZ);
			kwrite_buf(user_client + USER_CLIENT_TRAP_OFF, &trap, sizeof(trap));
		}
		IOServiceClose(g_conn);
	}
}

static kern_return_t
kcall_init(void) {
	kaddr_t our_task, ipc_port;

	if((g_conn = get_conn("AppleKeyStore")) != IO_OBJECT_NULL) {
		printf("g_conn: 0x%" PRIx32 "\n", g_conn);
		if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
			printf("our_task: " KADDR_FMT "\n", our_task);
			if((ipc_port = get_port(our_task, g_conn))) {
				printf("ipc_port: " KADDR_FMT "\n", ipc_port);
				if(kread_addr(ipc_port + IPC_PORT_IP_KOBJECT_OFF, &user_client) == KERN_SUCCESS) {
					printf("user_client: " KADDR_FMT "\n", user_client);
					if(kread_addr(user_client, &orig_vtab) == KERN_SUCCESS) {
						printf("orig_vtab: " KADDR_FMT "\n", orig_vtab);
						if(kalloc(MAX_VTAB_SZ, &fake_vtab) == KERN_SUCCESS) {
							printf("fake_vtab: " KADDR_FMT "\n", fake_vtab);
							if(mach_vm_copy(tfp0, orig_vtab, MAX_VTAB_SZ, fake_vtab) == KERN_SUCCESS && kwrite_addr(fake_vtab + VTAB_GET_EXTERNAL_TRAP_FOR_INDEX_OFF, csblob_get_cdhash) == KERN_SUCCESS) {
								return kwrite_addr(user_client, fake_vtab);
							}
						}
					}
				}
			}
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
kcall(kern_return_t *ret, kaddr_t func, size_t argc, ...) {
	io_external_trap_t trap;
	kaddr_t args[7] = { 1 };
	va_list ap;
	size_t i;

	va_start(ap, argc);
	for(i = 0; i < MIN(argc, 7); ++i) {
		args[i] = va_arg(ap, kaddr_t);
	}
	va_end(ap);
	trap.obj = args[0];
	trap.func = func;
	trap.delta = 0;
	if(kwrite_buf(user_client + USER_CLIENT_TRAP_OFF, &trap, sizeof(trap)) == KERN_SUCCESS) {
		*ret = IOConnectTrap6(g_conn, 0, args[1], args[2], args[3], args[4], args[5], args[6]);
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

static kern_return_t
phys_init(void) {
	kaddr_t our_task, our_map;
	uint32_t flags;

	if(kread_addr(pv_head_table_ptr, &pv_head_table) == KERN_SUCCESS) {
		printf("pv_head_table: " KADDR_FMT "\n", pv_head_table);
		if(kread_buf(const_boot_args, &boot_args, sizeof(boot_args)) == KERN_SUCCESS) {
			printf("virt_base: " KADDR_FMT "\n", boot_args.virt_base);
			printf("phys_base: " KADDR_FMT "\n", boot_args.phys_base);
			printf("mem_size: " KADDR_FMT "\n", boot_args.mem_size);
			if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
				printf("our_task: " KADDR_FMT "\n", our_task);
				if(kread_addr(our_task + TASK_MAP_OFF, &our_map) == KERN_SUCCESS) {
					printf("our_map: " KADDR_FMT "\n", our_map);
					if(kread_buf(our_map + VM_MAP_FLAGS_OFF, &flags, sizeof(flags)) == KERN_SUCCESS) {
						printf("flags: 0x%08" PRIx32 "\n", flags);
						flags |= VM_MAP_FLAGS_NO_ZERO_FILL;
						if(kwrite_buf(our_map + VM_MAP_FLAGS_OFF, &flags, sizeof(flags)) == KERN_SUCCESS) {
							if(kread_addr(our_map + VM_MAP_PMAP_OFF, &our_pmap) == KERN_SUCCESS) {
								printf("our_pmap: " KADDR_FMT "\n", our_pmap);
								return KERN_SUCCESS;
							}
						}
					}
				}
			}
		}
	}
	return KERN_FAILURE;
}

static void
phys_unmap(phys_ctx_t ctx) {
	kern_return_t ret;
	size_t i;

	for(i = 0; i < ctx.orig_cnt; ++i) {
		kwrite_addr(ctx.orig[i].ptep, ctx.orig[i].pte);
	}
	kcall(&ret, flush_mmu_tlb, 0);
	free(ctx.orig);
}

static kern_return_t
phys_map(phys_ctx_t *ctx, kaddr_t virt, kaddr_t phys, mach_vm_size_t sz, vm_prot_t prot) {
	kaddr_t phys_off, vphys, pv_h, ptep, orig_pte, fake_pte;
	kern_return_t ret;

	if(virt & ARM_PGMASK) {
		return KERN_FAILURE;
	}
	phys_off = phys & ARM_PGMASK;
	sz = ROUND_PAGE(sz + phys_off);
	phys -= phys_off;
	ctx->orig_cnt = 0;
	ctx->orig = calloc(sz >> arm_pgshift, sizeof(ctx->orig[0]));
	if(!ctx->orig) {
		return KERN_FAILURE;
	}
	while(sz) {
		__asm__ __volatile__("stnp %0, %0, [%1]" :: "r"(FAULT_MAGIC), "r"(virt));
		if(kcall(&ret, pmap_find_phys, 2, our_pmap, virt) != KERN_SUCCESS || ret <= 0) {
			break;
		}
		vphys = (kaddr_t)ret << arm_pgshift;
		printf("vphys: " KADDR_FMT "\n", vphys);
		if(!IS_IN_RANGE(vphys, boot_args.phys_base, TRUNC_PAGE(boot_args.phys_base + boot_args.mem_size))) {
			break;
		}
		if(kread_addr(pv_head_table + ((vphys - boot_args.phys_base) >> arm_pgshift) * sizeof(kaddr_t), &pv_h) != KERN_SUCCESS) {
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
		if(!(orig_pte & ARM_PTE_TYPE_VALID) || (orig_pte & ARM_PTE_MASK) != vphys) {
			break;
		}
		ctx->orig[ctx->orig_cnt].ptep = ptep;
		ctx->orig[ctx->orig_cnt++].pte = orig_pte;
		fake_pte = (phys & ARM_PTE_MASK) | ARM_PTE_TYPE_VALID | ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DISABLE) | ARM_PTE_AF | ARM_PTE_AP((prot & VM_PROT_WRITE) ? AP_RWRW : AP_RORO);
		if(kwrite_addr(ptep, fake_pte) != KERN_SUCCESS) {
			break;
		}
		phys += ARM_PGBYTES;
		virt += ARM_PGBYTES;
		sz -= ARM_PGBYTES;
	}
	if(sz || kcall(&ret, flush_mmu_tlb, 0) != KERN_SUCCESS) {
		phys_unmap(*ctx);
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

static kern_return_t
aes_ap_init(void) {
	if(mach_vm_allocate(mach_task_self(), &aes_ap_virt_base, AES_AP_SIZE, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
		printf("aes_ap_virt_base: " KADDR_FMT "\n", aes_ap_virt_base);
		if(phys_map(&aes_ap_ctx, aes_ap_virt_base, AES_AP_BASE_ADDR, AES_AP_SIZE, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
			if(mach_vm_allocate(mach_task_self(), &pmgr_virt_base, PMGR_SIZE, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
				printf("pmgr_virt_base: " KADDR_FMT "\n", pmgr_virt_base);
				if(phys_map(&pmgr_ctx, pmgr_virt_base, PMGR_BASE_ADDR, PMGR_SIZE, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
					return KERN_SUCCESS;
				}
				mach_vm_deallocate(mach_task_self(), pmgr_virt_base, PMGR_SIZE);
			}
			phys_unmap(aes_ap_ctx);
		}
		mach_vm_deallocate(mach_task_self(), aes_ap_virt_base, AES_AP_SIZE);
	}
	return KERN_FAILURE;
}

static kern_return_t
aes_ap_v1_cmd(uint32_t cmd, const void *src, void *dst, size_t len, uint32_t opts) {
	uint32_t *local_dst = dst, key_in_ctrl = 0;
	const uint32_t *local_src = src;
	size_t i;

	if(len % AES_BLOCK_SIZE) {
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
			return KERN_FAILURE;
	}
	switch(cmd & AES_CMD_DIR_MASK) {
		case AES_CMD_ENC:
			key_in_ctrl |= KEY_IN_CTRL_DIR_ENC;
			break;
		case AES_CMD_DEC:
			key_in_ctrl |= KEY_IN_CTRL_DIR_DEC;
			break;
		default:
			return KERN_FAILURE;
	}
	switch(opts & AES_KEY_SIZE_MASK) {
		case AES_KEY_SIZE_128:
			key_in_ctrl |= KEY_IN_CTRL_LEN_128;
			break;
		case AES_KEY_SIZE_192:
			key_in_ctrl |= KEY_IN_CTRL_LEN_192;
			break;
		case AES_KEY_SIZE_256:
			key_in_ctrl |= KEY_IN_CTRL_LEN_256;
			break;
		default:
			return KERN_FAILURE;
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
			return KERN_FAILURE;
	}
	rPMGR_AES0_PS |= PMGR_PS_RUN_MAX;
	while((rPMGR_AES0_PS & PMGR_PS_MANUAL_PS_MASK) != ((rPMGR_AES0_PS >> PMGR_PS_ACTUAL_PS_SHIFT) & PMGR_PS_ACTUAL_PS_MASK)) {}
	printf("old_iv: 0x%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "\n", rAES_AP_IV_IN0, rAES_AP_IV_IN1, rAES_AP_IV_IN2, rAES_AP_IV_IN3);
	printf("old_in: 0x%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "\n", rAES_AP_TXT_IN0, rAES_AP_TXT_IN1, rAES_AP_TXT_IN2, rAES_AP_TXT_IN3);
	printf("old_out: 0x%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "\n", rAES_AP_TXT_OUT0, rAES_AP_TXT_OUT1, rAES_AP_TXT_OUT2, rAES_AP_TXT_OUT3);
	rAES_AP_KEY_IN_CTRL = key_in_ctrl | KEY_IN_CTRL_VAL_SET;
	rAES_AP_IV_IN0 = rAES_AP_IV_IN1 = rAES_AP_IV_IN2 = rAES_AP_IV_IN3 = 0;
	rAES_AP_IV_IN_CTRL = IV_IN_CTRL_VAL_SET;
	for(i = 0; i < len / AES_BLOCK_SIZE; ++i) {
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
	rPMGR_AES0_PS &= ~PMGR_PS_RUN_MAX;
	while((rPMGR_AES0_PS & PMGR_PS_MANUAL_PS_MASK) != ((rPMGR_AES0_PS >> PMGR_PS_ACTUAL_PS_SHIFT) & PMGR_PS_ACTUAL_PS_MASK)) {}
	return KERN_SUCCESS;
}

static void
push_commands(const uint32_t *cmd, size_t len) {
	size_t i;

	for(i = 0; i < len / sizeof(*cmd); ++i) {
		rAES_COMMAND_FIFO = cmd[i];
	}
}

static kern_return_t
aes_ap_v2_cmd(uint32_t cmd, kaddr_t phys_src, kaddr_t phys_dst, size_t len, uint32_t opts) {
	command_data_t data;
	command_key_t ckey;
	command_iv_t civ;
	uint32_t flag;

	if(len % AES_BLOCK_SIZE) {
		return KERN_FAILURE;
	}
	ckey.command = OPCODE_KEY << COMMAND_OPCODE_SHIFT;
	switch(cmd & AES_CMD_MODE_MASK) {
		case AES_CMD_ECB:
			ckey.command |= BLOCK_MODE_ECB << COMMAND_KEY_COMMAND_BLOCK_MODE_SHIFT;
			break;
		case AES_CMD_CBC:
			ckey.command |= BLOCK_MODE_CBC << COMMAND_KEY_COMMAND_BLOCK_MODE_SHIFT;
			break;
		default:
			return KERN_FAILURE;
	}
	switch(cmd & AES_CMD_DIR_MASK) {
		case AES_CMD_ENC:
			ckey.command |= 1U << COMMAND_KEY_COMMAND_ENCRYPT_SHIFT;
			break;
		case AES_CMD_DEC:
			ckey.command |= 0U << COMMAND_KEY_COMMAND_ENCRYPT_SHIFT;
			break;
		default:
			return KERN_FAILURE;
	}
	switch(opts & AES_KEY_SIZE_MASK) {
		case AES_KEY_SIZE_128:
			ckey.command |= KEY_LEN_128 << COMMAND_KEY_COMMAND_KEY_LENGTH_SHIFT;
			break;
		case AES_KEY_SIZE_192:
			ckey.command |= KEY_LEN_192 << COMMAND_KEY_COMMAND_KEY_LENGTH_SHIFT;
			break;
		case AES_KEY_SIZE_256:
			ckey.command |= KEY_LEN_256 << COMMAND_KEY_COMMAND_KEY_LENGTH_SHIFT;
			break;
		default:
			return KERN_FAILURE;
	}
	switch(opts & AES_KEY_TYPE_MASK) {
		case AES_KEY_TYPE_UID0:
			ckey.command |= KEY_SELECT_UID1 << COMMAND_KEY_COMMAND_KEY_SELECT_SHIFT;
			break;
		case AES_KEY_TYPE_GID0:
			ckey.command |= KEY_SELECT_GID_AP_1 << COMMAND_KEY_COMMAND_KEY_SELECT_SHIFT;
			break;
		case AES_KEY_TYPE_GID1:
			ckey.command |= KEY_SELECT_GID_AP_2 << COMMAND_KEY_COMMAND_KEY_SELECT_SHIFT;
			break;
		default:
			return KERN_FAILURE;
	}
	rPMGR_AES0_PS |= PMGR_PS_RUN_MAX;
	while((rPMGR_AES0_PS & PMGR_PS_MANUAL_PS_MASK) != ((rPMGR_AES0_PS >> PMGR_PS_ACTUAL_PS_SHIFT) & PMGR_PS_ACTUAL_PS_MASK)) {}
	rAES_INT_STATUS = AES_BLK_INT_STATUS_FLAG_COMMAND_UMASK;
	rAES_CONTROL = AES_BLK_CONTROL_START_UMASK;
	push_commands(&ckey.command, sizeof(ckey.command));
	civ.command = OPCODE_IV << COMMAND_OPCODE_SHIFT;
	memset(&civ.iv, '\0', sizeof(civ.iv));
	push_commands(&civ.command, sizeof(civ));
	data.command = (OPCODE_DATA << COMMAND_OPCODE_SHIFT) | ((uint32_t)(len & COMMAND_DATA_COMMAND_LENGTH_MASK) << COMMAND_DATA_COMMAND_LENGTH_SHIFT);
	data.upper_addr = ((uint32_t)(phys_src >> 32U) & COMMAND_DATA_UPPER_ADDR_SOURCE_MASK) << COMMAND_DATA_UPPER_ADDR_SOURCE_SHIFT;
	data.upper_addr |= ((uint32_t)(phys_dst >> 32U) & COMMAND_DATA_UPPER_ADDR_DEST_MASK) << COMMAND_DATA_UPPER_ADDR_DEST_SHIFT;
	data.source_addr = (uint32_t)phys_src;
	data.dest_addr = (uint32_t)phys_dst;
	push_commands(&data.command, sizeof(data));
	flag = (OPCODE_FLAG << COMMAND_OPCODE_SHIFT) | (1U << COMMAND_FLAG_SEND_INTERRUPT_SHIFT) | (1U << COMMAND_FLAG_STOP_COMMANDS_SHIFT);
	push_commands(&flag, sizeof(flag));
	while(!(rAES_INT_STATUS & AES_BLK_INT_STATUS_FLAG_COMMAND_UMASK)) {}
	rAES_INT_STATUS = AES_BLK_INT_STATUS_FLAG_COMMAND_UMASK;
	rAES_CONTROL = AES_BLK_CONTROL_STOP_UMASK;
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
	kern_return_t ppn;
	size_t aes_len;

	if(aes_ap_v2) {
		while(len) {
			if(kcall(&ppn, pmap_find_phys, 2, our_pmap, virt_src) != KERN_SUCCESS || ppn <= 0) {
				return KERN_FAILURE;
			}
			phys_src = ((kaddr_t)ppn << arm_pgshift) | (virt_src & ARM_PGMASK);
			printf("phys_src: " KADDR_FMT "\n", phys_src);
			if(!IS_IN_RANGE(phys_src, boot_args.phys_base, TRUNC_PAGE(boot_args.phys_base + boot_args.mem_size))) {
				return KERN_FAILURE;
			}
			if(kcall(&ppn, pmap_find_phys, 2, our_pmap, virt_dst) != KERN_SUCCESS || ppn <= 0) {
				return KERN_FAILURE;
			}
			phys_dst = ((kaddr_t)ppn << arm_pgshift) | (virt_dst & ARM_PGMASK);
			printf("phys_dst: " KADDR_FMT "\n", phys_dst);
			if(!IS_IN_RANGE(phys_dst, boot_args.phys_base, TRUNC_PAGE(boot_args.phys_base + boot_args.mem_size))) {
				return KERN_FAILURE;
			}
			aes_len = MIN(len, MIN(ARM_PGBYTES - (phys_src & ARM_PGMASK), ARM_PGBYTES - (phys_dst & ARM_PGMASK)));
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
		if(aes_ap_cmd(AES_CMD_CBC | AES_CMD_ENC, uid_key_seeds[i].key, uid_key_seeds[i].val, sizeof(uid_key_seeds[i].key), AES_KEY_SIZE_256 | AES_KEY_TYPE_UID0) == KERN_SUCCESS) {
			printf("key: 0x%" PRIx32 ", val: 0x%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "\n", uid_key_seeds[i].id, uid_key_seeds[i].val[0], uid_key_seeds[i].val[1], uid_key_seeds[i].val[2], uid_key_seeds[i].val[3]);
		}
	}
}

static void
aes_ap_term(void) {
	phys_unmap(aes_ap_ctx);
	mach_vm_deallocate(mach_task_self(), aes_ap_virt_base, AES_AP_SIZE);
	phys_unmap(pmgr_ctx);
	mach_vm_deallocate(mach_task_self(), pmgr_virt_base, PMGR_SIZE);
}

int
main(void) {
	kaddr_t kbase, kslide;
	kern_return_t ret;
	pfinder_t pfinder;

	if(init_arm_globals() == KERN_SUCCESS) {
		printf("arm_pgshift: %u\n", arm_pgshift);
		printf("pmgr_base_off: " KADDR_FMT "\n", pmgr_base_off);
		printf("aes_ap_base_off: " KADDR_FMT "\n", aes_ap_base_off);
		printf("pmgr_aes0_ps_off: " KADDR_FMT "\n", pmgr_aes0_ps_off);
		if(init_tfp0() == KERN_SUCCESS) {
			printf("tfp0: 0x%" PRIx32 "\n", tfp0);
			if((kbase = get_kbase(&kslide))) {
				printf("kbase: " KADDR_FMT "\n", kbase);
				printf("kslide: " KADDR_FMT "\n", kslide);
				if(pfinder_init(&pfinder, kbase, kslide) == KERN_SUCCESS) {
					if(pfinder_init_offsets(pfinder) == KERN_SUCCESS) {
						if(kcall_init() == KERN_SUCCESS && kcall(&ret, csblob_get_cdhash, 1, USER_CLIENT_TRAP_OFF) == KERN_SUCCESS) {
							printf("csblob_get_cdhash(USER_CLIENT_TRAP_OFF): 0x%" PRIx32 "\n", ret);
							if(phys_init() == KERN_SUCCESS) {
								if(aes_ap_init() == KERN_SUCCESS) {
									aes_ap_test();
									aes_ap_term();
								}
							}
						}
						kcall_term();
					}
					pfinder_term(&pfinder);
				}
			}
			mach_port_deallocate(mach_task_self(), tfp0);
		}
	}
}
