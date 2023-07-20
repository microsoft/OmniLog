#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <keep.h>
#include <kernel/cache_helpers.h>
#include <kernel/unwind.h>

/* void cpu_mmu_disable_dcache(void) - disable data cache */
FUNC cpu_mmu_disable_dcache , :
UNWIND(	.fnstart)
	push	{r12, lr}
UNWIND(	.save	{r12, lr})

	mov     r0, #DCACHE_OP_CLEAN_INV
	bl	dcache_op_all

	/* Disable Cache */
	read_sctlr r0
	bic	r0, r0, #SCTLR_C
	write_sctlr r0
	isb
	dsb

	mov	r0, #DCACHE_OP_CLEAN_INV
	bl	dcache_op_all

	pop	{r12, pc}
UNWIND(	.fnend)
END_FUNC cpu_mmu_disable_dcache
DECLARE_KEEP_PAGER cpu_mmu_disable_dcache
