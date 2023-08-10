// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   Memory management utilities.
 *         Primitive to allocate, free memory.
 */
#include <arm.h>
#include <caam_common.h>
#include <caam_trace.h>
#include <caam_utils_mem.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu.h>
#include <tee/entry_std.h>
#include <string.h>

#define MEM_TYPE_NORMAL 0      /* Normal allocation */
#define MEM_TYPE_ZEROED	BIT(0) /* Buffer filled with 0's */
#define MEM_TYPE_ALIGN	BIT(1) /* Address and size aligned on a cache line */

#if CAAM_DBG_TRACE(MEM)
#define DEBUG_INFO_SIZE
#endif

#define CAAM_MEM_INFO_HDR
#ifdef CAAM_MEM_INFO_HDR
struct __packed mem_info {
	void *addr;
#ifdef DEBUG_INFO_SIZE
	size_t size;
#endif /* DEBUG_INFO_SIZE */
	uint8_t type;
};

#define MEM_INFO_SIZE  ROUNDUP(sizeof(struct mem_info), sizeof(void *))
#define OF_MEM_INFO(p) (struct mem_info *)((uint8_t *)(p) - MEM_INFO_SIZE)

/*
 * Allocate an area of given size in bytes. Add the memory allocator
 * information in the newly allocated area.
 *
 * @size_in   Size in bytes to allocate
 * @type      Type of area to allocate (refer to MEM_TYPE_*)
 */
static void *mem_alloc(size_t size_in, uint8_t type)
{
	struct mem_info *info = NULL;
	vaddr_t ret_addr = 0;
	void *ptr = NULL;
	size_t alloc_size = 0;
	size_t size = 0;
	uint32_t cacheline_size = 0;

	MEM_TRACE("alloc %zu bytes of type %" PRIu8, size_in, type);

	/* Roundup needed to respect CAAM DMA behaviour */
	if (type & MEM_TYPE_ALIGN)
		size = ROUNDUP(size_in, CFG_CAAM_SIZE_ALIGN);
	else
		size = size_in;

	/*
	 * The mem_info header is added just before the returned
	 * buffer address
	 *
	 * --------------
	 * |  mem_info  |
	 * --------------
	 * |  Buffer    |
	 * --------------
	 */
	if (ADD_OVERFLOW(size, MEM_INFO_SIZE, &alloc_size))
		return NULL;

	if (type & MEM_TYPE_ALIGN) {
		/*
		 * Buffer must be aligned on a cache line:
		 *  - Buffer start address aligned on a cache line
		 *  - End of Buffer inside a cache line.
		 *
		 * If area's (mem info + buffer) to be allocated size is
		 * already cache line aligned add a cache line.
		 *
		 * Because Buffer address returned is moved up to a cache
		 * line start offset, add a cache line to full area allocated
		 * to ensure that end of the working buffer is in a cache line.
		 */
		cacheline_size = caam_mem_read_cacheline_size();
		if (size == cacheline_size) {
			if (ADD_OVERFLOW(alloc_size, cacheline_size,
					 &alloc_size))
				return NULL;
		}

		if (ADD_OVERFLOW(cacheline_size,
				 ROUNDUP(alloc_size, cacheline_size),
				 &alloc_size))
			return NULL;
	}

	if (type & MEM_TYPE_ZEROED)
		ptr = calloc(1, alloc_size);
	else
		ptr = malloc(alloc_size);

	if (!ptr) {
		MEM_TRACE("alloc Error - NULL");
		return NULL;
	}

	/* Calculate the return buffer address */
	ret_addr = (vaddr_t)ptr + MEM_INFO_SIZE;
	if (type & MEM_TYPE_ALIGN) {
		ret_addr = ROUNDUP(ret_addr, cacheline_size);
		MEM_TRACE("alloc %p 0x%" PRIxVA " %zu vs %zu", ptr, ret_addr,
			  alloc_size, size);
	}

	/*
	 * Add the mem_info header
	 */
	info = OF_MEM_INFO(ret_addr);
	info->addr = ptr;
#ifdef DEBUG_INFO_SIZE
	info->size = alloc_size;
#endif /* DEBUG_INFO_SIZE */
	info->type = type;

	MEM_TRACE("alloc returned %p -> %p", ptr, (void *)ret_addr);

	return (void *)ret_addr;
}

/*
 * Free allocated area
 *
 * @ptr  area to free
 */
static void mem_free(void *ptr)
{
	struct mem_info *info = NULL;

	if (!ptr)
		return;

	info = OF_MEM_INFO(ptr);
	MEM_TRACE("free %p info %p", ptr, info);
	MEM_TRACE("free @%p - %zu bytes of type %" PRIu8, info->addr,
		  info->size, info->type);

	free(info->addr);
}
#else /* CAAM_MEM_INFO_HDR */
/*
 * Allocate an area of given size in bytes
 *
 * @size   Size in bytes to allocate
 * @type   Type of area to allocate (refer to MEM_TYPE_*)
 */
static void *mem_alloc(size_t size, uint8_t type)
{
	void *ptr = NULL;
	size_t alloc_size = size;
	uint32_t cacheline_size = 0;

	MEM_TRACE("alloc (normal) %zu bytes of type %" PRIu8, size, type);

	if (type & MEM_TYPE_ALIGN) {
		cacheline_size = caam_mem_read_cacheline_size();
		if (ADD_OVERFLOW(alloc_size,
				 ROUNDUP(alloc_size, cacheline_size),
				 &alloc_size))
			return NULL;
	}

	ptr = malloc(alloc_size);
	if (!ptr) {
		MEM_TRACE("alloc (normal) Error - NULL");
		return NULL;
	}

	if (type & MEM_TYPE_ZEROED)
		memset(ptr, 0, alloc_size);

	MEM_TRACE("alloc (normal) returned %p", ptr);
	return ptr;
}

/*
 * Free allocated area
 *
 * @ptr  area to free
 */
static void mem_free(void *ptr)
{
	if (ptr) {
		MEM_TRACE("free (normal) %p", ptr);
		free(ptr);
	}
}
#endif /* CAAM_MEM_INFO_HDR */

/*
 * Allocate internal driver buffer aligned with a cache line.
 *
 * @buf   [out] buffer allocated
 * @size  size in bytes of the memory to allocate
 * @type  Type of area to allocate (refer to MEM_TYPE_*)
 */
static enum caam_status mem_alloc_buf(struct caambuf *buf, size_t size,
				      uint8_t type)
{
	buf->data = mem_alloc(size, type);

	if (!buf->data)
		return CAAM_OUT_MEMORY;

	buf->paddr = virt_to_phys(buf->data);
	if (!buf->paddr) {
		caam_free_buf(buf);
		return CAAM_OUT_MEMORY;
	}

	buf->length = size;
	buf->nocache = 0;
	return CAAM_NO_ERROR;
}

void *caam_alloc(size_t size)
{
	return mem_alloc(size, MEM_TYPE_NORMAL);
}

void *caam_calloc(size_t size)
{
	return mem_alloc(size, MEM_TYPE_ZEROED);
}

void *caam_calloc_align(size_t size)
{
	return mem_alloc(size, MEM_TYPE_ZEROED | MEM_TYPE_ALIGN);
}

void caam_free(void *ptr)
{
	mem_free(ptr);
}

uint32_t *caam_calloc_desc(uint8_t nbentries)
{
	return mem_alloc(DESC_SZBYTES(nbentries),
			 MEM_TYPE_ZEROED | MEM_TYPE_ALIGN);
}

void caam_free_desc(uint32_t **ptr)
{
	mem_free(*ptr);
	*ptr = NULL;
}

enum caam_status caam_alloc_buf(struct caambuf *buf, size_t size)
{
	return mem_alloc_buf(buf, size, MEM_TYPE_NORMAL);
}

enum caam_status caam_calloc_buf(struct caambuf *buf, size_t size)
{
	return mem_alloc_buf(buf, size, MEM_TYPE_ZEROED);
}

enum caam_status caam_calloc_align_buf(struct caambuf *buf, size_t size)
{
	return mem_alloc_buf(buf, size, MEM_TYPE_ZEROED | MEM_TYPE_ALIGN);
}

enum caam_status caam_alloc_align_buf(struct caambuf *buf, size_t size)
{
	return mem_alloc_buf(buf, size, MEM_TYPE_ALIGN);
}

void caam_free_buf(struct caambuf *buf)
{
	if (buf) {
		if (buf->data) {
			caam_free(buf->data);
			buf->data = NULL;
		}

		buf->length = 0;
		buf->paddr = 0;
		buf->nocache = 0;
	}
}

bool caam_mem_is_cached_buf(void *buf, size_t size)
{
	enum teecore_memtypes mtype = MEM_AREA_MAXTYPE;
	bool is_cached = true;

	/*
	 * First check if the buffer is a known memory area mapped
	 * with a type listed in the teecore_memtypes enum.
	 * If not mapped, this is a User Area and so assume
	 * it cacheable
	 */
	mtype = core_mmu_get_type_by_pa(virt_to_phys(buf));

	if (mtype != MEM_AREA_MAXTYPE)
		is_cached = core_vbuf_is(CORE_MEM_CACHED, buf, size);
	else if (core_vbuf_is(CORE_MEM_SDP_MEM, buf, size))
		is_cached = tee_entry_is_sdp_cached();

	return is_cached;
}

enum caam_status caam_cpy_block_src(struct caamblock *block,
				    struct caambuf *src, size_t offset)
{
	enum caam_status ret = CAAM_FAILURE;
	size_t cpy_size = 0;

	if (!src->data)
		return CAAM_FAILURE;

	/* Check if the temporary buffer is allocated, else allocate it */
	if (!block->buf.data) {
		ret = caam_alloc_align_buf(&block->buf, block->max);
		if (ret != CAAM_NO_ERROR) {
			MEM_TRACE("Allocation Block buffer error");
			goto end_cpy;
		}
	}

	/* Calculate the number of bytes to copy in the block buffer */
	MEM_TRACE("Current buffer is %zu (%zu) bytes", block->filled,
		  block->max);

	cpy_size = block->max - block->filled;
	cpy_size = MIN(cpy_size, src->length - offset);

	memcpy(&block->buf.data[block->filled], &src->data[offset], cpy_size);

	block->filled += cpy_size;

	ret = CAAM_NO_ERROR;

end_cpy:
	return ret;
}

int caam_mem_get_pa_area(struct caambuf *buf, struct caambuf **out_pabufs)
{
	int nb_pa_area = 0;
	size_t len = 0;
	size_t len_tohandle = 0;
	vaddr_t va = 0;
	vaddr_t next_va = 0;
	paddr_t pa = 0;
	paddr_t next_pa = 0;
	struct caambuf *pabufs = NULL;

	MEM_TRACE("Get PA Areas of %p-%zu (out %p)", buf->data, buf->length,
		  out_pabufs);

	if (out_pabufs) {
		/*
		 * Caller asked for the extracted contiguous
		 * physical areas.
		 * Allocate maximum possible small pages
		 */
		if (buf->length > SMALL_PAGE_SIZE) {
			nb_pa_area = buf->length / SMALL_PAGE_SIZE + 1;
			if (buf->length % SMALL_PAGE_SIZE)
				nb_pa_area++;
		} else {
			nb_pa_area = 2;
		}

		pabufs = caam_calloc(nb_pa_area * sizeof(*pabufs));
		if (!pabufs)
			return -1;

		MEM_TRACE("Allocate max %d Physical Areas", nb_pa_area);
	}

	/*
	 * Go thru all the VA space to extract the contiguous
	 * physical areas
	 */
	va = (vaddr_t)buf->data;
	pa = virt_to_phys((void *)va);

	nb_pa_area = 0;
	if (pabufs) {
		pabufs[nb_pa_area].data = (uint8_t *)va;
		pabufs[nb_pa_area].paddr = pa;
		pabufs[nb_pa_area].length = 0;
		pabufs[nb_pa_area].nocache = buf->nocache;
		MEM_TRACE("Add %d PA 0x%" PRIxPA " VA 0x%" PRIxVA, nb_pa_area,
			  pa, va);
	}

	for (len = buf->length; len; len -= len_tohandle) {
		len_tohandle =
			MIN(SMALL_PAGE_SIZE - (va & SMALL_PAGE_MASK), len);
		next_va = va + len_tohandle;
		next_pa = virt_to_phys((void *)next_va);

		if (pabufs)
			pabufs[nb_pa_area].length += len_tohandle;

		if (next_pa != (pa + len_tohandle)) {
			nb_pa_area++;
			if (pabufs) {
				pabufs[nb_pa_area].data = (uint8_t *)next_va;
				pabufs[nb_pa_area].paddr = next_pa;
				pabufs[nb_pa_area].length = 0;
				pabufs[nb_pa_area].nocache = buf->nocache;
			}
			MEM_TRACE("Add %d PA 0x%" PRIxPA " VA 0x%" PRIxVA,
				  nb_pa_area, next_pa, next_va);
		}

		va = next_va;
		pa = next_pa;
	}

	if (out_pabufs)
		*out_pabufs = pabufs;

	MEM_TRACE("Nb Physical Area %d", nb_pa_area + 1);
	return nb_pa_area + 1;
}

uint32_t caam_mem_read_cacheline_size(void)
{
	uint32_t value = 0;

#ifdef ARM64
	value = read_ctr_el0();
#else
	value = read_ctr();
#endif /* ARM64 */
	value = CTR_WORD_SIZE
		<< ((value >> CTR_DMINLINE_SHIFT) & CTR_DMINLINE_MASK);
	MEM_TRACE("System Cache Line size = %" PRIu32 " bytes", value);

	return value;
}
