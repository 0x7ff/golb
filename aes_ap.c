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
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#define IO_BASE (0x200000000ULL)

#define OP_IV (2U)
#define OP_KEY (1U)
#define OP_DATA (5U)
#define OP_FLAG (8U)
#define DMB_SY (0xFU)
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
#define PMGR_AES0_PS_SZ (vm_kernel_page_size)
#define PMGR_SECURITY_SZ (vm_kernel_page_size)
#define AES_BLK_INT_STATUS_FLAG_CMD_UMASK (32U)
#define AES_AP_BASE_ADDR (IO_BASE + aes_ap_base_off)
#define PMGR_AES0_PS_BASE_ADDR (IO_BASE + pmgr_aes0_ps_off)
#define rAES_CTRL (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x8))
#define PMGR_SECURITY_BASE_ADDR (IO_BASE + pmgr_security_base_off)
#define rAES_AP_DIS (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x4))
#define rPMGR_AES0_PS (*(volatile uint32_t *)(pmgr_aes0_ps_ctx.virt))
#define rPMGR_SECURITY (*(volatile uint32_t *)pmgr_security_ctx.virt)
#define rAES_CMD_FIFO (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x200))
#define rAES_AP_IV_IN0 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x100))
#define rAES_AP_IV_IN1 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x104))
#define rAES_AP_IV_IN2 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x108))
#define rAES_AP_IV_IN3 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x10C))
#define rAES_AP_TXT_IN0 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x40))
#define rAES_AP_TXT_IN1 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x44))
#define rAES_AP_TXT_IN2 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x48))
#define rAES_AP_TXT_IN3 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x4C))
#define rAES_INT_STATUS (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x18))
#define rAES_AP_TXT_OUT0 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x80))
#define rAES_AP_TXT_OUT1 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x84))
#define rAES_AP_TXT_OUT2 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x88))
#define rAES_AP_TXT_OUT3 (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x8C))
#define rAES_AP_TXT_IN_STS (*(volatile uint32_t *)(aes_ap_ctx.virt + 0xC))
#define rAES_AP_IV_IN_CTRL (*(volatile uint32_t *)(aes_ap_ctx.virt + 0xE0))
#define rAES_AP_TXT_IN_CTRL (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x8))
#define rAES_AP_KEY_IN_CTRL (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x90))
#define rAES_AP_TXT_OUT_STS (*(volatile uint32_t *)(aes_ap_ctx.virt + 0x50))

static bool aes_ap_v2;
static golb_ctx_t aes_ap_ctx, pmgr_aes0_ps_ctx, pmgr_security_ctx;
static kaddr_t aes_ap_base_off, pmgr_security_base_off, pmgr_aes0_ps_off;

static struct {
	uint32_t key_id, key[4], val[4];
} uid_key_seeds[] = {
	{ 0x835, { 0x01010101, 0x01010101, 0x01010101, 0x01010101 }, { 0 } },
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

static kern_return_t
init_arm_globals(void) {
	uint32_t cpufamily = CPUFAMILY_UNKNOWN;
	size_t len = sizeof(cpufamily);
	struct utsname uts;

	if(sysctlbyname("hw.cpufamily", &cpufamily, &len, NULL, 0) == 0 && uname(&uts) == 0) {
		switch(cpufamily) {
			case 0x37A09642U: /* CPUFAMILY_ARM_CYCLONE */
				aes_ap_base_off = 0xA108000;
				pmgr_aes0_ps_off = 0xE020100;
				return KERN_SUCCESS;
			case 0x2C91A47EU: /* CPUFAMILY_ARM_TYPHOON */
				aes_ap_base_off = 0xA108000;
				pmgr_aes0_ps_off = 0xE0201E8;
				return KERN_SUCCESS;
			case 0x92FB37C8U: /* CPUFAMILY_ARM_TWISTER */
			case 0x67CEEE93U: /* CPUFAMILY_ARM_HURRICANE */
				aes_ap_v2 = true;
				if(strstr(uts.machine, "iBridge2,") != NULL) {
					aes_ap_base_off = 0xA008000;
					pmgr_aes0_ps_off = 0xE080238;
					pmgr_security_base_off = 0x112D0000;
				} else {
					aes_ap_base_off = 0xA108000;
					if(strstr(uts.version, "T8011") != NULL) {
						pmgr_aes0_ps_off = 0xE080228;
					} else if(strstr(uts.version, "T8010") != NULL) {
						pmgr_aes0_ps_off = 0xE080230;
					} else if(strstr(uts.version, "S8001") != NULL) {
						pmgr_aes0_ps_off = 0xE080218;
					} else {
						pmgr_aes0_ps_off = 0xE080220;
					}
					pmgr_security_base_off = 0x102D0000;
				}
				return KERN_SUCCESS;
			case 0xE81E7EF6U: /* CPUFAMILY_ARM_MONSOON_MISTRAL */
				aes_ap_v2 = true;
				aes_ap_base_off = 0x2E008000;
				pmgr_aes0_ps_off = 0x32080240;
				pmgr_security_base_off = 0x352D0000;
				return KERN_SUCCESS;
#ifdef __arm64e__
			case 0x07D34B9FU: /* CPUFAMILY_ARM_VORTEX_TEMPEST */
				aes_ap_v2 = true;
				aes_ap_base_off = 0x35008000;
				pmgr_aes0_ps_off = 0x3B080228;
				pmgr_security_base_off = 0x3D2D0000;
				return KERN_SUCCESS;
			case 0x462504D2U: /* CPUFAMILY_ARM_LIGHTNING_THUNDER */
				aes_ap_v2 = true;
				aes_ap_base_off = 0x35008000;
				pmgr_aes0_ps_off = 0x3B0801D8;
				pmgr_security_base_off = 0x3D2D0000;
				return KERN_SUCCESS;
			case 0x1B588BB3U: /* CPUFAMILY_ARM_FIRESTORM_ICESTORM */
				aes_ap_v2 = true;
				aes_ap_base_off = 0x3500C000;
				pmgr_aes0_ps_off = 0x3B700238;
				pmgr_security_base_off = 0x3D2D0000;
				return KERN_SUCCESS;
#endif
			default:
				break;
		}
	}
	return KERN_FAILURE;
}

static void
aes_ap_term(void) {
	golb_unmap(aes_ap_ctx);
	golb_unmap(pmgr_aes0_ps_ctx);
	if(aes_ap_v2) {
		golb_unmap(pmgr_security_ctx);
	}
}

static kern_return_t
aes_ap_init(void) {
	if(golb_map(&aes_ap_ctx, AES_AP_BASE_ADDR, AES_AP_SZ, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
		if(golb_map(&pmgr_aes0_ps_ctx, PMGR_AES0_PS_BASE_ADDR, PMGR_AES0_PS_SZ, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
			if(!aes_ap_v2 || golb_map(&pmgr_security_ctx, PMGR_SECURITY_BASE_ADDR, PMGR_SECURITY_SZ, VM_PROT_READ) == KERN_SUCCESS) {
				return KERN_SUCCESS;
			}
			golb_unmap(pmgr_aes0_ps_ctx);
		}
		golb_unmap(aes_ap_ctx);
	}
	return KERN_FAILURE;
}

static kern_return_t
aes_ap_v1_cmd(uint32_t cmd, const void *src, void *dst, size_t len, uint32_t opts) {
	uint32_t *local_dst = dst, key_in_ctrl = 0, key_type;
	kern_return_t ret = KERN_FAILURE;
	const uint32_t *local_src = src;

	if(len == 0 || (len % AES_BLOCK_SZ) != 0) {
		return ret;
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
	switch((key_type = opts & AES_KEY_TYPE_MASK)) {
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
	if((~rAES_AP_DIS & key_type) != 0) {
		printf("old_iv: 0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "\n", rAES_AP_IV_IN0, rAES_AP_IV_IN1, rAES_AP_IV_IN2, rAES_AP_IV_IN3);
		printf("old_in: 0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "\n", rAES_AP_TXT_IN0, rAES_AP_TXT_IN1, rAES_AP_TXT_IN2, rAES_AP_TXT_IN3);
		printf("old_out: 0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "\n", rAES_AP_TXT_OUT0, rAES_AP_TXT_OUT1, rAES_AP_TXT_OUT2, rAES_AP_TXT_OUT3);
		rAES_AP_KEY_IN_CTRL = key_in_ctrl | KEY_IN_CTRL_VAL_SET;
		rAES_AP_IV_IN0 = 0;
		rAES_AP_IV_IN1 = 0;
		rAES_AP_IV_IN2 = 0;
		rAES_AP_IV_IN3 = 0;
		rAES_AP_IV_IN_CTRL = IV_IN_CTRL_VAL_SET;
		do {
			while((rAES_AP_TXT_IN_STS & TXT_IN_STS_RDY) == 0) {}
			rAES_AP_TXT_IN0 = *local_src++;
			rAES_AP_TXT_IN1 = *local_src++;
			rAES_AP_TXT_IN2 = *local_src++;
			rAES_AP_TXT_IN3 = *local_src++;
			rAES_AP_TXT_IN_CTRL = TXT_IN_CTRL_VAL_SET;
			while((rAES_AP_TXT_OUT_STS & TXT_OUT_STS_VAL_SET) == 0) {}
			*local_dst++ = rAES_AP_TXT_OUT0;
			*local_dst++ = rAES_AP_TXT_OUT1;
			*local_dst++ = rAES_AP_TXT_OUT2;
			*local_dst++ = rAES_AP_TXT_OUT3;
		} while((len -= AES_BLOCK_SZ) != 0);
		ret = KERN_SUCCESS;
	}
	rPMGR_AES0_PS &= ~PMGR_PS_RUN_MAX;
	while((rPMGR_AES0_PS & PMGR_PS_MANUAL_PS_MASK) != ((rPMGR_AES0_PS >> PMGR_PS_ACTUAL_PS_SHIFT) & PMGR_PS_ACTUAL_PS_MASK)) {}
	return ret;
}

static kern_return_t
aes_ap_v2_cmd(uint32_t cmd, kaddr_t phys_src, kaddr_t phys_dst, size_t len, uint32_t opts) {
	uint32_t key_cmd, key_select, status;
	kern_return_t ret = KERN_FAILURE;

	if(len == 0 || (len % AES_BLOCK_SZ) != 0) {
		return ret;
	}
	key_cmd = OP_KEY << CMD_OP_SHIFT;
	switch(cmd & AES_CMD_MODE_MASK) {
		case AES_CMD_ECB:
			key_cmd |= BLOCK_MODE_ECB << CMD_KEY_CMD_BLOCK_MODE_SHIFT;
			break;
		case AES_CMD_CBC:
			key_cmd |= BLOCK_MODE_CBC << CMD_KEY_CMD_BLOCK_MODE_SHIFT;
			break;
		default:
			return ret;
	}
	switch(cmd & AES_CMD_DIR_MASK) {
		case AES_CMD_ENC:
			key_cmd |= 1U << CMD_KEY_CMD_ENCRYPT_SHIFT;
			break;
		case AES_CMD_DEC:
			key_cmd |= 0U << CMD_KEY_CMD_ENCRYPT_SHIFT;
			break;
		default:
			return ret;
	}
	switch(opts & AES_KEY_SZ_MASK) {
		case AES_KEY_SZ_128:
			key_cmd |= KEY_LEN_128 << CMD_KEY_CMD_KEY_LEN_SHIFT;
			break;
		case AES_KEY_SZ_192:
			key_cmd |= KEY_LEN_192 << CMD_KEY_CMD_KEY_LEN_SHIFT;
			break;
		case AES_KEY_SZ_256:
			key_cmd |= KEY_LEN_256 << CMD_KEY_CMD_KEY_LEN_SHIFT;
			break;
		default:
			return ret;
	}
	switch(opts & AES_KEY_TYPE_MASK) {
		case AES_KEY_TYPE_UID0:
			key_select = KEY_SELECT_UID1;
			break;
		case AES_KEY_TYPE_GID0:
			key_select = KEY_SELECT_GID_AP_1;
			break;
		case AES_KEY_TYPE_GID1:
			key_select = KEY_SELECT_GID_AP_2;
			break;
		default:
			return ret;
	}
	key_cmd |= key_select << CMD_KEY_CMD_KEY_SELECT_SHIFT;
	if((rPMGR_SECURITY & (1U << (key_select - 1U))) == 0) {
		do {
			rPMGR_AES0_PS |= PMGR_PS_RUN_MAX;
			while((rPMGR_AES0_PS & PMGR_PS_MANUAL_PS_MASK) != ((rPMGR_AES0_PS >> PMGR_PS_ACTUAL_PS_SHIFT) & PMGR_PS_ACTUAL_PS_MASK)) {}
			__builtin_arm_dmb(DMB_SY);
			rAES_INT_STATUS = AES_BLK_INT_STATUS_FLAG_CMD_UMASK;
			rAES_CTRL = AES_BLK_CTRL_START_UMASK;
			rAES_CMD_FIFO = key_cmd;
			rAES_CMD_FIFO = OP_IV << CMD_OP_SHIFT;
			rAES_CMD_FIFO = 0;
			rAES_CMD_FIFO = 0;
			rAES_CMD_FIFO = 0;
			rAES_CMD_FIFO = 0;
			rAES_CMD_FIFO = (OP_DATA << CMD_OP_SHIFT) | (((uint32_t)len & CMD_DATA_CMD_LEN_MASK) << CMD_DATA_CMD_LEN_SHIFT);
			rAES_CMD_FIFO = (((uint32_t)(phys_src >> 32U) & CMD_DATA_UPPER_ADDR_SRC_MASK) << CMD_DATA_UPPER_ADDR_SRC_SHIFT) | (((uint32_t)(phys_dst >> 32U) & CMD_DATA_UPPER_ADDR_DST_MASK) << CMD_DATA_UPPER_ADDR_DST_SHIFT);
			rAES_CMD_FIFO = (uint32_t)phys_src;
			rAES_CMD_FIFO = (uint32_t)phys_dst;
			rAES_CMD_FIFO = (OP_FLAG << CMD_OP_SHIFT) | (1U << CMD_FLAG_SEND_INT_SHIFT) | (1U << CMD_FLAG_STOP_CMDS_SHIFT);
			while((rAES_INT_STATUS & AES_BLK_INT_STATUS_FLAG_CMD_UMASK) == 0) {}
			rAES_INT_STATUS = AES_BLK_INT_STATUS_FLAG_CMD_UMASK;
			status = rAES_INT_STATUS;
			__builtin_arm_dmb(DMB_SY);
			rAES_CTRL = AES_BLK_CTRL_STOP_UMASK;
		} while(status != 0);
		ret = KERN_SUCCESS;
	}
	return ret;
}

static kern_return_t
aes_ap_cmd(uint32_t cmd, const void *src, void *dst, size_t len, uint32_t opts) {
	kaddr_t virt_src = (kaddr_t)src, virt_dst = (kaddr_t)dst, phys_src, phys_dst;
	vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
	size_t aes_len;

	if(aes_ap_v2) {
		do {
			if((phys_src = golb_find_phys(virt_src)) == 0) {
				return KERN_FAILURE;
			}
			printf("phys_src: " KADDR_FMT "\n", phys_src);
			if((phys_dst = golb_find_phys(virt_dst)) == 0) {
				return KERN_FAILURE;
			}
			printf("phys_dst: " KADDR_FMT "\n", phys_dst);
			aes_len = MIN(len, MIN(vm_kernel_page_size - (phys_src & vm_kernel_page_mask), vm_kernel_page_size - (phys_dst & vm_kernel_page_mask)));
			if(mach_vm_machine_attribute(mach_task_self(), virt_src, aes_len, MATTR_CACHE, &mattr_val) != KERN_SUCCESS || aes_ap_v2_cmd(cmd, phys_src, phys_dst, aes_len, opts) != KERN_SUCCESS || mach_vm_machine_attribute(mach_task_self(), virt_dst, aes_len, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
				return KERN_FAILURE;
			}
			virt_src += aes_len;
			virt_dst += aes_len;
		} while((len -= aes_len) != 0);
		return KERN_SUCCESS;
	}
	return aes_ap_v1_cmd(cmd, src, dst, len, opts);
}

static void
aes_ap_test(void) {
	size_t i;

	for(i = 0; i < sizeof(uid_key_seeds) / sizeof(*uid_key_seeds) && aes_ap_cmd(AES_CMD_CBC | AES_CMD_ENC, uid_key_seeds[i].key, uid_key_seeds[i].val, sizeof(uid_key_seeds[i].key), AES_KEY_SZ_256 | AES_KEY_TYPE_UID0) == KERN_SUCCESS; ++i) {
		printf("key_id: 0x%" PRIX32 ", val: 0x%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "%08" PRIX32 "\n", uid_key_seeds[i].key_id, uid_key_seeds[i].val[0], uid_key_seeds[i].val[1], uid_key_seeds[i].val[2], uid_key_seeds[i].val[3]);
	}
}

static void
aes_ap_file(const char *dir, const char *key_type, const char *in_filename, const char *out_filename, size_t buf_sz) {
	uint32_t cmd, opts = AES_KEY_SZ_256;
	struct stat stat_buf;
	int in_fd, out_fd;
	size_t len;
	ssize_t n;
	void *buf;

	if(strcmp(dir, "enc") == 0) {
		cmd = AES_CMD_ENC;
	} else if(strcmp(dir, "dec") == 0) {
		cmd = AES_CMD_DEC;
	} else {
		return;
	}
	if(strcmp(key_type, "UID0") == 0) {
		opts |= AES_KEY_TYPE_UID0;
	} else if(strcmp(key_type, "GID0") == 0) {
		opts |= AES_KEY_TYPE_GID0;
	} else if(strcmp(key_type, "GID1") == 0) {
		opts |= AES_KEY_TYPE_GID1;
	} else {
		return;
	}
	if((buf_sz % AES_BLOCK_SZ) == 0 && (in_fd = open(in_filename, O_RDONLY | O_CLOEXEC)) != -1) {
		if(fstat(in_fd, &stat_buf) != -1 && S_ISREG(stat_buf.st_mode) && stat_buf.st_size > 0 && (len = (size_t)stat_buf.st_size) >= buf_sz && (len % AES_BLOCK_SZ) == 0) {
			if(buf_sz == AES_BLOCK_SZ) {
				buf_sz = len;
				cmd |= AES_CMD_ECB;
			} else {
				if(buf_sz == 0) {
					buf_sz = len;
				}
				cmd |= AES_CMD_CBC;
			}
			if((out_fd = open(out_filename, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IROTH | S_IRGRP | S_IWUSR | S_IRUSR)) != -1) {
				if((buf = malloc(buf_sz)) != NULL) {
					do {
						if((n = read(in_fd, buf, buf_sz)) <= 0 || (size_t)n != buf_sz || aes_ap_cmd(cmd, buf, buf, buf_sz, opts) != KERN_SUCCESS || (n = write(out_fd, buf, buf_sz)) <= 0 || (size_t)n != buf_sz) {
							break;
						}
						printf("Wrote %zu bytes to file \"%s\".\n", buf_sz, out_filename);
					} while((len -= buf_sz) != 0);
					printf("Remaining bytes: %zu\n", len);
					free(buf);
				}
				close(out_fd);
			}
		}
		close(in_fd);
	}
}

int
main(int argc, char **argv) {
	size_t buf_sz;

	if(argc != 1 && argc != 6) {
		printf("Usage: %s [enc/dec UID0/GID0/GID1 in_file out_file buf_sz]\n", argv[0]);
	} else if(init_arm_globals() == KERN_SUCCESS) {
		printf("aes_ap_base_off: " KADDR_FMT ", pmgr_aes0_ps_off: " KADDR_FMT "\n", aes_ap_base_off, pmgr_aes0_ps_off);
		if(golb_init() == KERN_SUCCESS) {
			if(aes_ap_init() == KERN_SUCCESS) {
				if(argc == 1) {
					aes_ap_test();
				} else if(sscanf(argv[5], "%zu", &buf_sz) == 1) {
					aes_ap_file(argv[1], argv[2], argv[3], argv[4], buf_sz);
				}
				aes_ap_term();
			}
			golb_term();
		}
	}
}
