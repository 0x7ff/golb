/* Copyright 2022 0x7ff
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
#include <mach/mach_time.h>
#include <sys/sysctl.h>

#define AMP_SZ (0x1000)
#define DCS_SZ (0x1000)
#define AMCC_SZ (0x4000)
#define DCS_SPACING (0x40000)
#define IO_BASE (0x200000000ULL)
#define AMP_SPACING (DCS_SPACING)
#define SDRAM_BASE (0x800000000ULL)
#define rAIC_GLB_CFG (*(volatile uint32_t *)aic_glb_cfg_ctx.virt)

extern void
ryuzaki(volatile uint32_t *, volatile uint32_t *, volatile uint32_t, volatile uint32_t);

static golb_ctx_t amp_ctx, dcs_ctx, amcc_ctx, aic_glb_cfg_ctx;
static size_t amp_base_off, dcs_base_off, amcc_base_off, aic_glb_cfg_base_off, burst_len = 0x20, addrcfg_off, mcuchnhash0_off, mcuchnhash1_off, addrmapmode_off;
static uint32_t ch_wid, ch_point, addrcfg, addrmapmode, mcuchnhash0, mcuchnhash1, mcsaddrbankhash0 = 0x6DB6, mcsaddrbankhash1 = 0x5B6D, mcsaddrbankhash2 = 0x36DB, dcs_num_channels;

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
	return (val >> start) & (~0U >> (32U - len));
}

static bool
is_device_type(const char *device_type) {
	io_registry_entry_t arm_io = IORegistryEntryFromPath(kIOMasterPortDefault, kIODeviceTreePlane ":/arm-io");
	CFDataRef device_type_cf;
	size_t device_type_len;
	bool ret = false;

	if(arm_io != IO_OBJECT_NULL) {
		if((device_type_cf = IORegistryEntryCreateCFProperty(arm_io, CFSTR("device_type"), kCFAllocatorDefault, kNilOptions)) != NULL) {
			ret = CFGetTypeID(device_type_cf) == CFDataGetTypeID() && (device_type_len = (size_t)CFDataGetLength(device_type_cf)) == strlen(device_type) + 1 && memcmp(device_type, CFDataGetBytePtr(device_type_cf), device_type_len) == 0;
			CFRelease(device_type_cf);
		}
		IOObjectRelease(arm_io);
	}
	return ret;
}

static kern_return_t
init_arm_globals(void) {
	uint32_t cpufamily = CPUFAMILY_UNKNOWN;
	size_t len = sizeof(cpufamily);

	if(sysctlbyname("hw.cpufamily", &cpufamily, &len, NULL, 0) == 0) {
		switch(cpufamily) {
			case 0x92FB37C8U: /* CPUFAMILY_ARM_TWISTER */
				if(is_device_type("s8001-io")) {
					amp_base_off = 0x420000;
					dcs_base_off = 0x400000;
					dcs_num_channels = 8;
					addrcfg_off = 0x4CC;
					addrmapmode_off = 0x4C8;
				} else {
					dcs_num_channels = 4;
					amp_base_off = 0x220000;
					dcs_base_off = 0x200000;
					addrcfg_off = 0x4C8;
					addrmapmode_off = 0x4C4;
				}
				aic_glb_cfg_base_off = 0xE100010;
				mcuchnhash0_off = 0x4A8;
				mcuchnhash1_off = 0x4AC;
				return KERN_SUCCESS;
			case 0x67CEEE93U: /* CPUFAMILY_ARM_HURRICANE */
				if(is_device_type("t8006-io")) {
					dcs_num_channels = 1;
				} else if(is_device_type("t8011-io")) {
					dcs_num_channels = 8;
				} else {
					dcs_num_channels = 4;
				}
				amp_base_off = 0x220000;
				dcs_base_off = 0x200000;
				aic_glb_cfg_base_off = 0xE100010;
				addrcfg_off = 0x4C8;
				mcuchnhash0_off = 0x4A8;
				mcuchnhash1_off = 0x4AC;
				addrmapmode_off = 0x4C4;
				return KERN_SUCCESS;
			case 0xE81E7EF6U: /* CPUFAMILY_ARM_MONSOON_MISTRAL */
				if(is_device_type("t8301-io")) {
					dcs_num_channels = 1;
				} else {
					dcs_num_channels = 4;
				}
				amp_base_off = 0x220000;
				dcs_base_off = 0x200000;
				aic_glb_cfg_base_off = 0x32100010;
				addrcfg_off = 0x4C8;
				mcuchnhash0_off = 0x4A8;
				mcuchnhash1_off = 0x4AC;
				addrmapmode_off = 0x4C4;
				return KERN_SUCCESS;
			case 0x07D34B9FU: /* CPUFAMILY_ARM_VORTEX_TEMPEST */
			case 0x462504D2U: /* CPUFAMILY_ARM_LIGHTNING_THUNDER */
			case 0x1B588BB3U: /* CPUFAMILY_ARM_FIRESTORM_ICESTORM */
				if(is_device_type("t8103-io")) {
					dcs_num_channels = 8;
				} else {
					dcs_num_channels = 4;
				}
				amp_base_off = 0x20C000;
				dcs_base_off = 0x200000;
				aic_glb_cfg_base_off = 0x3B100010;
				addrcfg_off = 0x1014;
				mcuchnhash0_off = 0x1004;
				mcuchnhash1_off = 0x1008;
				addrmapmode_off = 0x1010;
				return KERN_SUCCESS;
			default:
				break;
		}
	}
	return KERN_FAILURE;
}

static void
ryuzaki_term(void) {
	golb_unmap(amp_ctx);
	golb_unmap(dcs_ctx);
	golb_unmap(amcc_ctx);
	golb_unmap(aic_glb_cfg_ctx);
}

static kern_return_t
ryuzaki_init(void) {
	if(golb_map(&amp_ctx, IO_BASE + amp_base_off, dcs_num_channels * AMP_SPACING + AMP_SZ, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
		if(golb_map(&dcs_ctx, IO_BASE + dcs_base_off, dcs_num_channels * DCS_SPACING + DCS_SZ, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
			if(golb_map(&amcc_ctx, IO_BASE + amcc_base_off, AMCC_SZ, VM_PROT_READ) == KERN_SUCCESS) {
				ch_wid = (uint32_t)__builtin_ctz(dcs_num_channels);
				printf("ch_wid: 0x%" PRIX32 "\n", ch_wid);
				mcuchnhash0 = *(volatile uint32_t *)(amcc_ctx.virt + mcuchnhash0_off);
				printf("mcuchnhash0: 0x%" PRIX32 "\n", mcuchnhash0);
				ch_point = 7 + (uint32_t)__builtin_ctz(mcuchnhash0);
				printf("ch_point: 0x%" PRIX32 "\n", ch_point);
				if(ch_wid >= 2) {
					mcuchnhash1 = *(volatile uint32_t *)(amcc_ctx.virt + mcuchnhash1_off);
					printf("mcuchnhash1: 0x%" PRIX32 "\n", mcuchnhash1);
				}
				addrcfg = *(volatile uint32_t *)(amcc_ctx.virt + addrcfg_off);
				printf("addrcfg: 0x%" PRIX32 "\n", addrcfg);
				addrmapmode = *(volatile uint32_t *)(amcc_ctx.virt + addrmapmode_off);
				printf("addrmapmode: 0x%" PRIX32 "\n", addrmapmode);
				if(golb_map(&aic_glb_cfg_ctx, IO_BASE + aic_glb_cfg_base_off, sizeof(rAIC_GLB_CFG), VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
					return KERN_SUCCESS;
				}
				golb_unmap(amcc_ctx);
			}
			golb_unmap(dcs_ctx);
		}
		golb_unmap(amp_ctx);
	}
	return KERN_FAILURE;
}

static uint32_t
odd_parity(uint32_t in) {
	in = (in & 0xFFFFU) ^ (in >> 16U);
	in = (in & 0xFFU) ^ (in >> 8U);
	in = (in & 0xFU) ^ (in >> 4U);
	in = (in & 0x3U) ^ (in >> 2U);
	return (in & 0x1U) ^ (in >> 1U);
}

static kaddr_t
dram2phys(uint32_t ch, uint32_t rank, uint32_t bank, uint32_t row, uint32_t col) {
	uint32_t rank_wid = extract32(addrcfg, 24, 2), bank_wid = 2 + extract32(addrcfg, 0, 4), row_wid = 12 + extract32(addrcfg, 16, 4), col_wid = 8 + extract32(addrcfg, 8, 4), col_off = 2, row_off, bank_off, rank_off, addr, mask, chnhash;

	if(extract32(addrmapmode, 0, 1) == 0) {
		row_off = col_off + col_wid;
		bank_off = row_off + row_wid;
		rank_off = bank_off + bank_wid;
	} else if((bank_off = 6 + extract32(addrmapmode, 8, 5)) == col_off + col_wid) {
		rank_off = bank_off + bank_wid;
		row_off = rank_off + rank_wid;
	} else {
		mask = (1U << (bank_off - col_off)) - 1U;
		col = ((col & ~mask) << bank_wid) | (col & mask);
		rank_off = col_off + col_wid + bank_wid;
		row_off = rank_off + rank_wid;
	}
	bank ^= (odd_parity(row & ~mcsaddrbankhash2) << 2U) | (odd_parity(row & ~mcsaddrbankhash1) << 1U) | odd_parity(row & ~mcsaddrbankhash0);
	addr = (rank << rank_off) | (bank << bank_off) | (row << row_off) | (col << col_off);
	mask = (1U << ch_point) - 1U;
	addr = ((addr & ~mask) << ch_wid) | (addr & mask);
	chnhash = (ch << (ch_point - 7U)) | (addr >> 7U);
	ch = odd_parity(chnhash & mcuchnhash0);
	if(ch_wid >= 2) {
		ch |= odd_parity(chnhash & mcuchnhash1) << 1U;
	}
	addr |= (ch & ((1U << ch_wid) - 1U)) << ch_point;
	return SDRAM_BASE + addr;
}

static kern_return_t
phys2dram(kaddr_t phys, uint32_t *ch, uint32_t *rank, uint32_t *bank, uint32_t *row, uint32_t *col) {
	uint32_t rank_wid = extract32(addrcfg, 24, 2), bank_wid = 2 + extract32(addrcfg, 0, 4), row_wid = 12 + extract32(addrcfg, 16, 4), col_wid = 8 + extract32(addrcfg, 8, 4), col_off = 2, bank_off, addr = (uint32_t)(phys - SDRAM_BASE), mask;

	mask = (1U << ch_point) - 1U;
	addr = ((addr >> ch_wid) & ~mask) | (addr & mask);
	*col = addr >> col_off;
	if(extract32(addrmapmode, 0, 1) == 0) {
		*row = *col >> col_wid;
		*bank = *row >> row_wid;
		*rank = *bank >> bank_wid;
	} else {
		bank_off = 6 + extract32(addrmapmode, 8, 5);
		*bank = addr >> bank_off;
		if(bank_off == col_off + col_wid) {
			*rank = *bank >> bank_wid;
			*row = *rank >> rank_wid;
		} else {
			*rank = *col >> (col_wid + bank_wid);
			*row = *rank >> rank_wid;
			mask = (1U << (bank_off - col_off)) - 1U;
			*col = ((*col >> bank_wid) & ~mask) | (*col & mask);
		}
	}
	*rank &= (1U << rank_wid) - 1U;
	*row &= (1U << row_wid) - 1U;
	*bank &= (1U << bank_wid) - 1U;
	*bank ^= (odd_parity(*row & ~mcsaddrbankhash2) << 2U) | (odd_parity(*row & ~mcsaddrbankhash1) << 1U) | odd_parity(*row & ~mcsaddrbankhash0);
	*col &= (1U << col_wid) - 1U;
	for(*ch = 0; *ch < dcs_num_channels; ++*ch) {
		if(dram2phys(*ch, *rank, *bank, *row, *col) == phys) {
			return KERN_SUCCESS;
		}
	}
	return KERN_FAILURE;
}

static int
ryuzaki_test(void) {
	uint32_t ch, rank, bank, row, col, ba[3], r[16], c[10], act_cmd, write_cmd;
	thread_time_constraint_policy_data_t policy;
	mach_timebase_info_data_t timebase_info;
	int ret = EXIT_FAILURE;
	kaddr_t virt, phys;
	golb_ctx_t ctx;
	size_t i;

	if(mach_timebase_info(&timebase_info) == KERN_SUCCESS && mach_vm_allocate(mach_task_self(), &virt, vm_page_size, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
		printf("virt: " KADDR_FMT "\n", virt);
		*(volatile uint8_t *)virt = UINT8_MAX;
		if((phys = golb_find_phys(virt)) != 0) {
#if 1
			phys = dram2phys(dcs_num_channels - 1, 0, 0, 0xFFF, 0);
#endif
			printf("phys: " KADDR_FMT "\n", phys);
			if(golb_map(&ctx, phys, vm_page_size, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
				for(i = 0; i < burst_len; ++i) {
					((volatile uint8_t *)ctx.virt)[i] = UINT8_MAX;
				}
				if(phys2dram(phys, &ch, &rank, &bank, &row, &col) == KERN_SUCCESS) {
					printf("ch: 0x%" PRIX32 ", rank: 0x%" PRIX32 ", bank: 0x%" PRIX32 ", row: 0x%" PRIX32 ", col: 0x%" PRIX32 "\n", ch, rank, bank, row, col);
					for(i = 0; i < sizeof(ba) / sizeof(ba[0]); ++i) {
						ba[i] = (bank >> i) & 1U;
					}
					for(i = 0; i < sizeof(r) / sizeof(r[0]); ++i) {
						r[i] = (row >> i) & 1U;
					}
					for(i = 0; i < sizeof(c) / sizeof(c[0]); ++i) {
						c[i] = (col >> i) & 1U;
					}
					act_cmd = ((0x3U | (r[6] << 2U) | (r[7] << 3U) | (r[8] << 4U) | (r[9] << 5U) | (r[0] << 6U) | (r[1] << 7U) | (r[2] << 8U) | (r[3] << 9U) | (r[4] << 10U) | (r[5] << 11U)) << 16U) /* ACT-2 */ | ((0x1U | (r[12] << 2U) | (r[13] << 3U) | (r[14] << 4U) | (r[15] << 5U) | (ba[0] << 6U) | (ba[1] << 7U) | (ba[2] << 8U) | (r[10] << 10U) | (r[11] << 11U)) << 0U) /* ACT-1 */;
					write_cmd = ((0x12U | (c[8] << 5U) | (c[2] << 6U) | (c[3] << 7U) | (c[4] << 8U) | (c[5] << 9U) | (c[6] << 10U) | (c[7] << 11U)) << 16U) /* Write-2 */ | ((0x4U | (ba[0] << 6U) | (ba[1] << 7U) | (ba[2] << 8U) | (c[9] << 10U)) << 0U) /* Write-1 */;
					rAIC_GLB_CFG &= ~(1U << 0U);
					do {
						policy.period = 0;
						policy.preemptible = FALSE;
						policy.constraint = policy.computation = 50000000 * timebase_info.denom / timebase_info.numer;
						if(thread_policy_set(mach_thread_self(), THREAD_TIME_CONSTRAINT_POLICY, (thread_policy_t)&policy, THREAD_TIME_CONSTRAINT_POLICY_COUNT) == KERN_SUCCESS) {
							ryuzaki((volatile uint32_t *)(amp_ctx.virt + ch * AMP_SPACING), (volatile uint32_t *)(dcs_ctx.virt + ch * DCS_SPACING), act_cmd, write_cmd);
						}
						for(i = 0; i < burst_len; ++i) {
							if(((const volatile uint8_t *)ctx.virt)[i] != 0) {
								break;
							}
						}
					} while(i != burst_len);
					rAIC_GLB_CFG |= 1U << 0U;
					ret = 0;
				}
				golb_unmap(ctx);
			}
		}
		mach_vm_deallocate(mach_task_self(), virt, vm_page_size);
	}
	return ret;
}

int
main(void) {
	int ret = EXIT_FAILURE;

	if(init_arm_globals() == KERN_SUCCESS) {
		printf("amp_base_off: 0x%zX, dcs_base_off: 0x%zX, amcc_base_off: 0x%zX, aic_glb_cfg_base_off: 0x%zX, mcsaddrbankhash0: 0x%" PRIX32 ", mcsaddrbankhash1: 0x%" PRIX32 ", mcsaddrbankhash2: 0x%" PRIX32 ", dcs_num_channels: 0x%" PRIX32 ", burst_len: 0x%zX, addrcfg_off: 0x%zX, mcuchnhash0_off: 0x%zX, mcuchnhash1_off: 0x%zX, addrmapmode_off: 0x%zX\n", amp_base_off, dcs_base_off, amcc_base_off, aic_glb_cfg_base_off, mcsaddrbankhash0, mcsaddrbankhash1, mcsaddrbankhash2, dcs_num_channels, burst_len, addrcfg_off, mcuchnhash0_off, mcuchnhash1_off, addrmapmode_off);
		if(golb_init(0, NULL, NULL) == KERN_SUCCESS) {
			if(ryuzaki_init() == KERN_SUCCESS) {
				ret = ryuzaki_test();
				ryuzaki_term();
			}
			golb_term();
		}
	}
	return ret;
}
