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

#define MAX_CPUS (6)
#define MAX_EDITR_RETRIES (16)
#define IO_BASE (0x200000000ULL)

#define EDECR_SS (1U << 2U)
#define EDRCR_CSE (1U << 2U)
#define EDSCR_ERR (1U << 6U)
#define EDECR_REG_OFF (0x24)
#define EDITR_REG_OFF (0x84)
#define EDSCR_REG_OFF (0x88)
#define EDRCR_REG_OFF (0x90)
#define EDSCR_ITE (1U << 24U)
#define CORESIGHT_SZ (0x1000)
#define OSLAR_REG_OFF (0x300)
#define EDLAR_REG_OFF (0xFB0)
#define EDPRSR_SDR (1U << 11U)
#define EDPRSR_REG_OFF (0x314)
#define EDLAR_KEY (0xC5ACCE55U)
#define DBGDTRRX_REG_OFF (0x80)
#define DBGDTRTX_REG_OFF (0x8C)
#define EDPRSR_HALTED (1U << 4U)
#define DBGWRAP_DIS_RST (1U << 26U)
#define DBGWRAP_DBGRESTART (1U << 30U)
#define DBGWRAP_DBGHALT_ON_RST (1U << 29U)

typedef struct {
	size_t ed_base_off, utt_dbgwrap_base_off;
	golb_ctx_t ed_ctx, utt_dbgwrap_ctx;
} cpu_t;

static size_t cpu_cnt;
static cpu_t cpus[MAX_CPUS];
static bool has_32bit_dbgwrap;

static kern_return_t
init_arm_globals(void) {
	uint32_t cpufamily = CPUFAMILY_UNKNOWN;
	size_t len = sizeof(cpufamily);
	struct utsname uts;

	if(sysctlbyname("hw.cpufamily", &cpufamily, &len, NULL, 0) == 0 && uname(&uts) == 0) {
		switch(cpufamily) {
			case 0x37A09642U: /* CPUFAMILY_ARM_CYCLONE */
			case 0x2C91A47EU: /* CPUFAMILY_ARM_TYPHOON */
			case 0x92FB37C8U: /* CPUFAMILY_ARM_TWISTER */
				has_32bit_dbgwrap = true;
				cpus[cpu_cnt].ed_base_off = 0x2010000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x2040000;
				cpus[cpu_cnt].ed_base_off = 0x2110000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x2140000;
				if(strstr(uts.version, "T7001") != NULL) {
					cpus[cpu_cnt].ed_base_off = 0x2410000;
					cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x2440000;
				}
				return KERN_SUCCESS;
			case 0x67CEEE93U: /* CPUFAMILY_ARM_HURRICANE */
				cpus[cpu_cnt].ed_base_off = 0x2010000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x2040000;
				cpus[cpu_cnt].ed_base_off = 0x2110000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x2140000;
				if(strstr(uts.version, "T8011") != NULL) {
					cpus[cpu_cnt].ed_base_off = 0x2210000;
					cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x2240000;
				}
				return KERN_SUCCESS;
			case 0xE81E7EF6U: /* CPUFAMILY_ARM_MONSOON_MISTRAL */
				cpus[cpu_cnt].ed_base_off = 0x8010000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x8040000;
				cpus[cpu_cnt].ed_base_off = 0x8110000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x8140000;
				cpus[cpu_cnt].ed_base_off = 0x8210000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x8240000;
				cpus[cpu_cnt].ed_base_off = 0x8310000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x8340000;
				cpus[cpu_cnt].ed_base_off = 0x8410000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x8440000;
				cpus[cpu_cnt].ed_base_off = 0x8510000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x8540000;
				return KERN_SUCCESS;
			case 0x07D34B9FU: /* CPUFAMILY_ARM_VORTEX_TEMPEST */
			case 0x462504D2U: /* CPUFAMILY_ARM_LIGHTNING_THUNDER */
			case 0x1B588BB3U: /* CPUFAMILY_ARM_FIRESTORM_ICESTORM */
				cpus[cpu_cnt].ed_base_off = 0x10010000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x10040000;
				cpus[cpu_cnt].ed_base_off = 0x10110000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x10140000;
				cpus[cpu_cnt].ed_base_off = 0x10210000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x10240000;
				cpus[cpu_cnt].ed_base_off = 0x10310000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x10340000;
				cpus[cpu_cnt].ed_base_off = 0x11010000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x11040000;
				cpus[cpu_cnt].ed_base_off = 0x11110000;
				cpus[cpu_cnt++].utt_dbgwrap_base_off = 0x11140000;
				return KERN_SUCCESS;
			default:
				break;
		}
	}
	return KERN_FAILURE;
}

static void
coresight_term(void) {
	size_t i;

	for(i = 0; i < cpu_cnt; ++i) {
		golb_unmap(cpus[i].ed_ctx);
		golb_unmap(cpus[i].utt_dbgwrap_ctx);
	}
}

static kern_return_t
coresight_init(void) {
	kern_return_t ret = KERN_FAILURE;
	size_t i;

	for(i = 0; i < cpu_cnt; ++i) {
		if((ret = golb_map(&cpus[i].ed_ctx, IO_BASE + cpus[i].ed_base_off, CORESIGHT_SZ, VM_PROT_READ | VM_PROT_WRITE)) == KERN_SUCCESS && (ret = golb_map(&cpus[i].utt_dbgwrap_ctx, IO_BASE + cpus[i].utt_dbgwrap_base_off, has_32bit_dbgwrap ? sizeof(uint32_t) : sizeof(uint64_t), VM_PROT_READ | VM_PROT_WRITE)) != KERN_SUCCESS) {
			golb_unmap(cpus[i].ed_ctx);
		}
		if(ret != KERN_SUCCESS) {
			while(i-- != 0) {
				golb_unmap(cpus[i].ed_ctx);
				golb_unmap(cpus[i].utt_dbgwrap_ctx);
			}
			break;
		}
	}
	return ret;
}

static size_t
get_cpunum(void) {
	uint64_t p;

	__asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r" (p));
	return p & 7U;
}

static bool
coresight_exec_insn(size_t cpunum, uint32_t insn) {
	uint32_t edscr_val;
	size_t i;

	for(i = 0; i < MAX_EDITR_RETRIES; ++i) {
		*(volatile uint32_t *)(cpus[cpunum].ed_ctx.virt + EDITR_REG_OFF) = insn;
		while(((edscr_val = *(volatile uint32_t *)(cpus[cpunum].ed_ctx.virt + EDSCR_REG_OFF)) & EDSCR_ERR) == 0) {
			if((edscr_val & EDSCR_ITE) != 0) {
				return true;
			}
		}
		*(volatile uint32_t *)(cpus[cpunum].ed_ctx.virt + EDRCR_REG_OFF) = EDRCR_CSE;
	}
	return false;
}

static bool
coresight_read_reg_32(size_t cpunum, uint64_t reg, uint32_t *val) {
	if(coresight_exec_insn(cpunum, 0xD5130400U | (reg & 0x1FU)) /* msr DBGDTR_EL0, reg */) {
		*val = *(volatile uint32_t *)(cpus[cpunum].ed_ctx.virt + DBGDTRTX_REG_OFF);
		return true;
	}
	return false;
}

static bool
coresight_read_reg_64(size_t cpunum, uint64_t reg, kaddr_t *val) {
	if(coresight_exec_insn(cpunum, 0xD5130400U | (reg & 0x1FU)) /* msr DBGDTR_EL0, reg */) {
		*val = ((kaddr_t)*(volatile uint32_t *)(cpus[cpunum].ed_ctx.virt + DBGDTRRX_REG_OFF) << 32U) | *(volatile uint32_t *)(cpus[cpunum].ed_ctx.virt + DBGDTRTX_REG_OFF);
		return true;
	}
	return false;
}

static bool
coresight_write_reg(size_t cpunum, uint64_t reg, kaddr_t val) {
	*(volatile uint32_t *)(cpus[cpunum].ed_ctx.virt + DBGDTRTX_REG_OFF) = (uint32_t)(val >> 32U);
	*(volatile uint32_t *)(cpus[cpunum].ed_ctx.virt + DBGDTRRX_REG_OFF) = (uint32_t)val;
	return coresight_exec_insn(cpunum, 0xD5330400U | (reg & 0x1FU)) /* mrs reg, DBGDTR_EL0 */;
}

static bool
coresight_read_pc(size_t cpunum, kaddr_t *val) {
	kaddr_t x19;

	return coresight_read_reg_64(cpunum, 19, &x19) && coresight_exec_insn(cpunum, 0xD53B4520U | 19U) /* mrs x19, DLR_EL0 */ && coresight_read_reg_64(cpunum, 19, val) && coresight_write_reg(cpunum, 19, x19);
}

static bool
coresight_read_32(size_t cpunum, kaddr_t addr, uint32_t *val) {
	kaddr_t x19, x20;

	return coresight_read_reg_64(cpunum, 19, &x19) && coresight_read_reg_64(cpunum, 20, &x20) && coresight_write_reg(cpunum, 20, addr) && coresight_exec_insn(cpunum, 0xB8404400U | (20U << 5U) | 19U) /* ldr w19, [x20], #4 */ && coresight_read_reg_32(cpunum, 19, val) && coresight_write_reg(cpunum, 20, x20) && coresight_write_reg(cpunum, 19, x19);
}

static void
coresight_step(size_t cpunum) {
	if(has_32bit_dbgwrap) {
		*(volatile uint32_t *)cpus[cpunum].utt_dbgwrap_ctx.virt = DBGWRAP_DBGRESTART;
	} else {
		*(volatile uint64_t *)cpus[cpunum].utt_dbgwrap_ctx.virt = DBGWRAP_DBGRESTART;
	}
	while((*(volatile uint32_t *)(cpus[cpunum].ed_ctx.virt + EDPRSR_REG_OFF) & EDPRSR_SDR) == 0) {}
	while((*(volatile uint32_t *)(cpus[cpunum].ed_ctx.virt + EDPRSR_REG_OFF) & EDPRSR_HALTED) == 0) {}
}

static int
coresight_test(void) {
	kaddr_t pc, val;
	uint32_t insn;
	size_t i = 0;
	int ret;

	do {
		ret = EXIT_FAILURE;
		while(i == get_cpunum()) {}
		*(volatile uint32_t *)(cpus[i].ed_ctx.virt + EDLAR_REG_OFF) = EDLAR_KEY;
		if(has_32bit_dbgwrap) {
			*(volatile uint32_t *)cpus[i].utt_dbgwrap_ctx.virt = DBGWRAP_DBGHALT_ON_RST;
		} else {
			*(volatile uint64_t *)cpus[i].utt_dbgwrap_ctx.virt = DBGWRAP_DBGHALT_ON_RST;
		}
		while((*(volatile uint32_t *)(cpus[i].ed_ctx.virt + EDPRSR_REG_OFF) & EDPRSR_HALTED) == 0) {}
		*(volatile uint32_t *)(cpus[i].ed_ctx.virt + OSLAR_REG_OFF) = 0;
		*(volatile uint32_t *)(cpus[i].ed_ctx.virt + EDECR_REG_OFF) = EDECR_SS;
		while(coresight_read_pc(i, &pc)) {
			printf("pc: " KADDR_FMT "\n", pc);
			if(!coresight_read_32(i, pc, &insn)) {
				break;
			}
			printf("insn: 0x%" PRIX32 "\n", insn);
			if((insn & ~0x1FU) == 0xD51CF240U /* msr S3_4_c15_c2_2, reg */) {
				if(!coresight_read_reg_64(i, insn & 0x1FU, &val)) {
					break;
				}
				if(val == 1) {
					if(coresight_write_reg(i, insn & 0x1FU, 0)) {
						ret = 0;
					}
					break;
				}
			}
			coresight_step(i);
		}
		*(volatile uint32_t *)(cpus[i].ed_ctx.virt + EDECR_REG_OFF) = 0;
		if(has_32bit_dbgwrap) {
			*(volatile uint32_t *)cpus[i].utt_dbgwrap_ctx.virt = DBGWRAP_DBGRESTART | DBGWRAP_DIS_RST;
		} else {
			*(volatile uint64_t *)cpus[i].utt_dbgwrap_ctx.virt = DBGWRAP_DBGRESTART | DBGWRAP_DIS_RST;
		}
	} while(ret == 0 && ++i < cpu_cnt);
	return ret;
}

int
main(void) {
	int ret = EXIT_FAILURE;
	size_t i;

	if(init_arm_globals() == KERN_SUCCESS) {
		for(i = 0; i < cpu_cnt; ++i) {
			printf("cpus[%zu] = { .ed_base_off: 0x%zx, .utt_dbgwrap_base_off: 0x%zx }\n", i, cpus[i].ed_base_off, cpus[i].utt_dbgwrap_base_off);
		}
		if(golb_init(0, NULL, NULL) == KERN_SUCCESS) {
			if(coresight_init() == KERN_SUCCESS) {
				ret = coresight_test();
				coresight_term();
			}
			golb_term();
		}
	}
	return ret;
}
