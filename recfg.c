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
#include <sys/sysctl.h>

#define MAX_STAGES (8)
#define IO_BASE (0x200000000ULL)

#define rAOP_CFG_TABLE (*(volatile uint32_t *)aop_cfg_table_ctx.virt)
#define rAOP_SRAM_BASE (*(volatile uint32_t *)aop_sram_base_ctx.virt)
#define rAOP_TABLE_ENTRY (*(volatile uint32_t *)aop_table_entry_ctx.virt)

enum {
	RECFG_SUCCESS,
	RECFG_FAILURE,
	RECFG_ENOMEM,
	RECFG_UPDATE
};

enum {
	RECFG_META_CMD,
	RECFG_WRITE32_CMD,
	RECFG_READ_CMD,
	RECFG_WRITE64_CMD
};

enum {
	RECFG_META_END_CMD,
	RECFG_META_DELAY_CMD
};

typedef struct {
	int (*r32)(void *, kaddr_t *, uint32_t *, uint32_t *, bool *, uint32_t *), (*r64)(void *, kaddr_t *, uint64_t *, uint64_t *, bool *, uint32_t *), (*w32)(void *, kaddr_t *, uint32_t *), (*w64)(void *, kaddr_t *, uint64_t *), (*delay)(void *, uint32_t *);
} recfg_cbs_t;

static size_t aop_cfg_table_off, aop_sram_base_off, aop_recfg_base_off;
static golb_ctx_t aop_cfg_table_ctx, aop_sram_base_ctx, aop_table_entry_ctx;

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
	return (val >> start) & (~0U >> (32U - len));
}

static uint32_t
deposit32(uint32_t val, unsigned start, unsigned len, uint32_t field) {
	uint32_t mask = (~0U >> (32U - len)) << start;

	return (val & ~mask) | ((field << start) & mask);
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
				aop_cfg_table_off = 0x10000200;
				aop_sram_base_off = 0x10800008;
				return KERN_SUCCESS;
			case 0x67CEEE93U: /* CPUFAMILY_ARM_HURRICANE */
				if(is_device_type("t8012-io")) {
					aop_cfg_table_off = 0x112C0200;
					aop_recfg_base_off = 0x11F00000;
				} else {
					aop_cfg_table_off = 0x10000100;
					aop_sram_base_off = 0x10800008;
				}
				return KERN_SUCCESS;
			case 0xE81E7EF6U: /* CPUFAMILY_ARM_MONSOON_MISTRAL */
				aop_cfg_table_off = 0x352C0200;
				aop_recfg_base_off = 0x35F00000;
				return KERN_SUCCESS;
			case 0x07D34B9FU: /* CPUFAMILY_ARM_VORTEX_TEMPEST */
			case 0x462504D2U: /* CPUFAMILY_ARM_LIGHTNING_THUNDER */
			case 0x1B588BB3U: /* CPUFAMILY_ARM_FIRESTORM_ICESTORM */
				aop_cfg_table_off = 0x3D2C0200;
				aop_recfg_base_off = 0x3DF00000;
				return KERN_SUCCESS;
			default:
				break;
		}
	}
	return KERN_FAILURE;
}

static bool
memcpy_volatile(volatile void *dst, const volatile void *src, size_t n, bool check) {
	while(n-- != 0) {
		((volatile uint8_t *)dst)[n] = ((const volatile uint8_t *)src)[n];
		if(check) {
			__asm__ volatile("dsb ish" ::: "memory");
			if(((const volatile uint8_t *)dst)[n] != ((const volatile uint8_t *)src)[n]) {
				return false;
			}
		}
	}
	return true;
}

static int
recfg_check(const void *buf, size_t sz) {
	const volatile uint8_t *cmd_p, *cmd_e;
	uint32_t cnt, cmd, cmd_type;
	int ret = RECFG_ENOMEM;

	for(cmd_p = buf, cmd_e = (const volatile uint8_t *)buf + sz; cmd_e - cmd_p >= (ptrdiff_t)sizeof(cmd); ) {
		memcpy_volatile(&cmd, cmd_p, sizeof(cmd), false);
		if((cmd_type = extract32(cmd, 0, 2)) == RECFG_META_CMD) {
			if((cmd_type = extract32(cmd, 2, 4)) == RECFG_META_END_CMD) {
				ret = RECFG_SUCCESS;
				break;
			}
			if(cmd_type != RECFG_META_DELAY_CMD) {
				ret = RECFG_FAILURE;
				break;
			}
			cmd_p += sizeof(cmd);
		} else if(cmd_type == RECFG_WRITE32_CMD) {
			cnt = extract32(cmd, 2, 4) + 1;
			cmd_p += sizeof(cmd) + ((cnt + (sizeof(cmd) - 1U)) & ~(sizeof(cmd) - 1U)) + cnt * sizeof(uint32_t);
		} else if(cmd_type == RECFG_READ_CMD) {
			cmd_p += 2 * sizeof(cmd);
			if(extract32(cmd, 5, 1) != 0) {
				if(((kaddr_t)cmd_p & (sizeof(uint64_t) - 1U)) != 0) {
					cmd_p += sizeof(cmd);
				}
				cmd_p += 2 * sizeof(uint64_t);
			} else {
				cmd_p += 2 * sizeof(uint32_t);
			}
		} else if(cmd_type == RECFG_WRITE64_CMD) {
			cnt = extract32(cmd, 2, 4) + 1;
			cmd_p += sizeof(cmd) + ((cnt + (sizeof(cmd) - 1U)) & ~(sizeof(cmd) - 1U));
			if(((kaddr_t)cmd_p & (sizeof(uint64_t) - 1U)) != 0) {
				cmd_p += sizeof(cmd);
			}
			cmd_p += cnt * sizeof(uint64_t);
		}
	}
	return ret;
}

static int
recfg_walk(void *buf, size_t sz, recfg_cbs_t cbs, void *arg) {
	uint32_t i, cnt, cmd_a, cmd_b, data_32, mask_32, cmd_type, retry_cnt;
	volatile uint8_t *cmd_p, *cmd_e, *data_p;
	uint64_t data_64, mask_64;
	int ret = RECFG_FAILURE;
	kaddr_t addr;
	bool retry;

	for(cmd_p = buf, cmd_e = (volatile uint8_t *)buf + sz; cmd_e - cmd_p >= (ptrdiff_t)sizeof(cmd_a); ) {
		memcpy_volatile(&cmd_a, cmd_p, sizeof(cmd_a), false);
		if((cmd_type = extract32(cmd_a, 0, 2)) == RECFG_META_CMD) {
			if(extract32(cmd_a, 2, 4) == RECFG_META_END_CMD) {
				ret = RECFG_SUCCESS;
				break;
			}
			if(cbs.delay != NULL) {
				data_32 = extract32(cmd_a, 6, 26);
				if((ret = cbs.delay(arg, &data_32)) == RECFG_UPDATE) {
					cmd_a = deposit32(cmd_a, 6, 26, data_32);
					if(!memcpy_volatile(cmd_p, &cmd_a, sizeof(cmd_a), true)) {
						ret = RECFG_FAILURE;
						break;
					}
				} else if(ret != RECFG_SUCCESS) {
					break;
				}
			}
			cmd_p += sizeof(cmd_a);
		} else if(cmd_type == RECFG_WRITE32_CMD) {
			cnt = extract32(cmd_a, 2, 4) + 1;
			data_p = cmd_p + sizeof(cmd_a) + ((cnt + (sizeof(cmd_a) - 1U)) & ~(sizeof(cmd_a) - 1U));
			if(cbs.w32 != NULL) {
				for(i = 0; i < cnt; ++i) {
					memcpy_volatile(&data_32, data_p + i * sizeof(data_32), sizeof(data_32), false);
					memcpy_volatile(&cmd_b, cmd_p + sizeof(cmd_a) + (i & ~(sizeof(cmd_b) - 1U)), sizeof(cmd_b), false);
					addr = ((kaddr_t)extract32(cmd_a, 6, 26) << 10U) | ((kaddr_t)extract32(cmd_b, (i & 3U) << 3U, 8) << 2U);
					if((ret = cbs.w32(arg, &addr, &data_32)) == RECFG_UPDATE) {
						cmd_a = deposit32(cmd_a, 6, 26, (uint32_t)(addr >> 10U));
						cmd_b = deposit32(cmd_b, (i & 3U) << 3U, 8, (uint32_t)(addr >> 2U));
						if(!memcpy_volatile(cmd_p, &cmd_a, sizeof(cmd_a), true) || !memcpy_volatile(data_p + i * sizeof(data_32), &data_32, sizeof(data_32), true) || !memcpy_volatile(cmd_p + sizeof(cmd_a) + (i & ~(sizeof(cmd_b) - 1U)), &cmd_b, sizeof(cmd_b), true)) {
							ret = RECFG_FAILURE;
							break;
						}
					} else if(ret != RECFG_SUCCESS) {
						break;
					}
				}
				if(ret != RECFG_UPDATE && ret != RECFG_SUCCESS) {
					break;
				}
			}
			cmd_p = data_p + cnt * sizeof(data_32);
		} else if(cmd_type == RECFG_READ_CMD) {
			if(extract32(cmd_a, 5, 1) != 0) {
				data_p = cmd_p + sizeof(cmd_a) + sizeof(cmd_b);
				if(((kaddr_t)data_p & (sizeof(data_64) - 1U)) != 0) {
					data_p += sizeof(cmd_a);
				}
				if(cbs.r64 != NULL) {
					memcpy_volatile(&mask_64, data_p, sizeof(mask_64), false);
					memcpy_volatile(&cmd_b, cmd_p + sizeof(cmd_a), sizeof(cmd_b), false);
					memcpy_volatile(&data_64, data_p + sizeof(mask_64), sizeof(data_64), false);
					retry_cnt = extract32(cmd_b, 8, 8);
					retry = extract32(cmd_b, 16, 1) != 0;
					addr = ((kaddr_t)extract32(cmd_a, 6, 26) << 10U) | ((kaddr_t)extract32(cmd_b, 0, 8) << 2U);
					if((ret = cbs.r64(arg, &addr, &mask_64, &data_64, &retry, &retry_cnt)) == RECFG_UPDATE) {
						cmd_b = deposit32(cmd_b, 8, 8, retry_cnt);
						cmd_b = deposit32(cmd_b, 16, 1, retry ? 1 : 0);
						cmd_b = deposit32(cmd_b, 0, 8, (uint32_t)(addr >> 2U));
						cmd_a = deposit32(cmd_a, 6, 26, (uint32_t)(addr >> 10U));
						if(!memcpy_volatile(cmd_p, &cmd_a, sizeof(cmd_a), true) || !memcpy_volatile(data_p, &mask_64, sizeof(mask_64), true) || !memcpy_volatile(cmd_p + sizeof(cmd_a), &cmd_b, sizeof(cmd_b), true) || !memcpy_volatile(data_p + sizeof(mask_64), &data_64, sizeof(data_64), true)) {
							ret = RECFG_FAILURE;
							break;
						}
					} else if(ret != RECFG_SUCCESS) {
						break;
					}
				}
				cmd_p = data_p + sizeof(mask_64) + sizeof(data_64);
			} else {
				data_p = cmd_p + sizeof(cmd_a) + sizeof(cmd_b);
				if(cbs.r32 != NULL) {
					memcpy_volatile(&mask_32, data_p, sizeof(mask_32), false);
					memcpy_volatile(&cmd_b, cmd_p + sizeof(cmd_a), sizeof(cmd_b), false);
					memcpy_volatile(&data_32, data_p + sizeof(mask_32), sizeof(data_32), false);
					retry_cnt = extract32(cmd_b, 8, 8);
					retry = extract32(cmd_b, 16, 1) != 0;
					addr = ((kaddr_t)extract32(cmd_a, 6, 26) << 10U) | ((kaddr_t)extract32(cmd_b, 0, 8) << 2U);
					if((ret = cbs.r32(arg, &addr, &mask_32, &data_32, &retry, &retry_cnt)) == RECFG_UPDATE) {
						cmd_b = deposit32(cmd_b, 8, 8, retry_cnt);
						cmd_b = deposit32(cmd_b, 16, 1, retry ? 1 : 0);
						cmd_b = deposit32(cmd_b, 0, 8, (uint32_t)(addr >> 2U));
						cmd_a = deposit32(cmd_a, 6, 26, (uint32_t)(addr >> 10U));
						if(!memcpy_volatile(cmd_p, &cmd_a, sizeof(cmd_a), true) || !memcpy_volatile(cmd_p + sizeof(cmd_a), &cmd_b, sizeof(cmd_b), true) || !memcpy_volatile(data_p, &mask_32, sizeof(mask_32), true) || !memcpy_volatile(data_p + sizeof(mask_32), &data_32, sizeof(data_32), true)) {
							ret = RECFG_FAILURE;
							break;
						}
					} else if(ret != RECFG_SUCCESS) {
						break;
					}
				}
				cmd_p = data_p + sizeof(mask_32) + sizeof(data_32);
			}
		} else if(cmd_type == RECFG_WRITE64_CMD) {
			cnt = extract32(cmd_a, 2, 4) + 1;
			data_p = cmd_p + sizeof(cmd_a) + ((cnt + (sizeof(cmd_a) - 1U)) & ~(sizeof(cmd_a) - 1U));
			if(((kaddr_t)data_p & (sizeof(data_64) - 1U)) != 0) {
				data_p += sizeof(cmd_a);
			}
			if(cbs.w64 != NULL) {
				for(i = 0; i < cnt; ++i) {
					memcpy_volatile(&data_64, data_p + i * sizeof(data_64), sizeof(data_64), false);
					memcpy_volatile(&cmd_b, cmd_p + sizeof(cmd_a) + (i & ~(sizeof(cmd_b) - 1U)), sizeof(cmd_b), false);
					addr = ((kaddr_t)extract32(cmd_a, 6, 26) << 10U) | ((kaddr_t)extract32(cmd_b, (i & 3U) << 3U, 8) << 2U);
					if((ret = cbs.w64(arg, &addr, &data_64)) == RECFG_UPDATE) {
						cmd_a = deposit32(cmd_a, 6, 26, (uint32_t)(addr >> 10U));
						cmd_b = deposit32(cmd_b, (i & 3U) << 3U, 8, (uint32_t)(addr >> 2U));
						if(!memcpy_volatile(cmd_p, &cmd_a, sizeof(cmd_a), true) || !memcpy_volatile(data_p + i * sizeof(data_64), &data_64, sizeof(data_64), true) || !memcpy_volatile(cmd_p + sizeof(cmd_a) + (i & ~(sizeof(cmd_b) - 1U)), &cmd_b, sizeof(cmd_b), true)) {
							ret = RECFG_FAILURE;
							break;
						}
					} else if(ret != RECFG_SUCCESS) {
						break;
					}
				}
				if(ret != RECFG_UPDATE && ret != RECFG_SUCCESS) {
					break;
				}
			}
			cmd_p = data_p + cnt * sizeof(data_64);
		}
	}
	return ret;
}

static int
recfg_r32(void *arg, kaddr_t *addr, uint32_t *mask, uint32_t *data, bool *retry, uint32_t *retry_cnt) {
	(void)arg;
	if(*retry) {
		printf("r32 addr: " KADDR_FMT ", mask: 0x%" PRIX32 ", data: 0x%" PRIX32 ", retry_cnt: %" PRIu32 "\n", *addr, *mask, *data, *retry_cnt);
	} else {
		printf("r32 addr: " KADDR_FMT ", mask: 0x%" PRIX32 ", data: 0x%" PRIX32 "\n", *addr, *mask, *data);
	}
	return RECFG_UPDATE;
}

static int
recfg_r64(void *arg, kaddr_t *addr, uint64_t *mask, uint64_t *data, bool *retry, uint32_t *retry_cnt) {
	(void)arg;
	if(*retry) {
		printf("r64 addr: " KADDR_FMT ", mask: 0x%" PRIX64 ", data: 0x%" PRIX64 ", retry_cnt: %" PRIu32 "\n", *addr, *mask, *data, *retry_cnt);
	} else {
		printf("r64 addr: " KADDR_FMT ", mask: 0x%" PRIX64 ", data: 0x%" PRIX64 "\n", *addr, *mask, *data);
	}
	return RECFG_UPDATE;
}

static int
recfg_w32(void *arg, kaddr_t *addr, uint32_t *data) {
	(void)arg;
	printf("w32 addr: " KADDR_FMT ", data: 0x%" PRIX32 "\n", *addr, *data);
	return RECFG_UPDATE;
}

static int
recfg_w64(void *arg, kaddr_t *addr, uint64_t *data) {
	(void)arg;
	printf("w64 addr: " KADDR_FMT ", data: 0x%" PRIX64 "\n", *addr, *data);
	return RECFG_UPDATE;
}

static int
recfg_delay(void *arg, uint32_t *data) {
	(void)arg;
	printf("delay data: 0x%" PRIX32 "\n", *data);
	return RECFG_UPDATE;
}

static int
recfg(void) {
	kaddr_t sram_base, aop_table_entry;
	golb_ctx_t aop_stage_ctx;
	int ret = EXIT_FAILURE;
	size_t i, chunk_sz;
	recfg_cbs_t cbs = {
		.r32 = recfg_r32,
		.r64 = recfg_r64,
		.w32 = recfg_w32,
		.w64 = recfg_w64,
		.delay = recfg_delay
	};
	bool end;

	if(golb_map(&aop_cfg_table_ctx, IO_BASE + aop_cfg_table_off, sizeof(rAOP_CFG_TABLE), VM_PROT_READ) == KERN_SUCCESS) {
		if(aop_sram_base_off == 0) {
			sram_base = IO_BASE + aop_recfg_base_off;
		} else if(golb_map(&aop_sram_base_ctx, IO_BASE + aop_sram_base_off, sizeof(rAOP_SRAM_BASE), VM_PROT_READ) == KERN_SUCCESS) {
			sram_base = IO_BASE + rAOP_SRAM_BASE;
			golb_unmap(aop_sram_base_ctx);
		} else {
			sram_base = 0;
		}
		if(sram_base != 0) {
			printf("sram_base: " KADDR_FMT "\n", sram_base);
			i = 0;
			do {
				ret = EXIT_FAILURE;
				if(golb_map(&aop_table_entry_ctx, sram_base + rAOP_CFG_TABLE + i * sizeof(rAOP_TABLE_ENTRY), sizeof(rAOP_TABLE_ENTRY), VM_PROT_READ) == KERN_SUCCESS) {
					aop_table_entry = (kaddr_t)rAOP_TABLE_ENTRY << 4U;
					printf("aop_table_entry: " KADDR_FMT "\n", aop_table_entry);
					for(end = false, chunk_sz = vm_page_size; !end && golb_map(&aop_stage_ctx, aop_table_entry, chunk_sz, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS; ) {
						if((ret = recfg_check((const void *)aop_stage_ctx.virt, chunk_sz)) == RECFG_ENOMEM) {
							chunk_sz *= 2;
							ret = EXIT_FAILURE;
						} else {
							if(ret != RECFG_SUCCESS || recfg_walk((void *)aop_stage_ctx.virt, chunk_sz, cbs, NULL) == RECFG_SUCCESS) {
								ret = 0;
							} else {
								ret = EXIT_FAILURE;
							}
							end = true;
						}
						golb_unmap(aop_stage_ctx);
					}
					golb_unmap(aop_table_entry_ctx);
				}
			} while(ret == 0 && ++i < MAX_STAGES);
		}
		golb_unmap(aop_cfg_table_ctx);
	}
	return ret;
}

int
main(void) {
	int ret = EXIT_FAILURE;

	if(init_arm_globals() == KERN_SUCCESS) {
		printf("aop_cfg_table_off: 0x%zX, aop_sram_base_off: 0x%zX, aop_recfg_base_off: 0x%zX\n", aop_cfg_table_off, aop_sram_base_off, aop_recfg_base_off);
		if(golb_init(0, NULL, NULL) == KERN_SUCCESS) {
			ret = recfg();
			golb_term();
		}
	}
	return ret;
}
