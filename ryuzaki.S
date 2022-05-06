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
.text
.align 2

.global _ryuzaki
_ryuzaki:
	stp x19, x20, [sp, #-0x10]!
	mov w19, #1U << 0U
	orr w20, w19, #1U << 3U
	dsb ish
	str w19, [x0, #0xC00]
1:
	ldr w19, [x0, #0xC04]
	tbz w19, #0, 1b
	ldr w19, [x1]
	and w19, w19, #~(1U << 1U)
	str w19, [x1]
	str w2, [x0, #0xB00]
	str w2, [x0, #0xB04]
	ldr w19, [x0, #0xB0C]
	orr w19, w19, w20
	str w19, [x0, #0xB0C]
2:
	ldr w19, [x0, #0xB0C]
	tst w19, w20
	b.ne 2b
	str w3, [x0, #0xB00]
	str w3, [x0, #0xB04]
	ldr w19, [x0, #0xB0C]
	orr w19, w19, w20
	str w19, [x0, #0xB0C]
3:
	ldr w19, [x0, #0xB0C]
	tst w19, w20
	b.ne 3b
	ldr w19, [x1]
	orr w19, w19, #1U << 1U
	str w19, [x1]
	str wzr, [x0, #0xC00]
4:
	ldr w19, [x0, #0xC04]
	tbnz w19, #0, 4b
	dsb ish
	ldp x19, x20, [sp], #0x10
	ret

.global _ryuzaki_end
_ryuzaki_end:
