// SPDX-License-Identifier: MIT
// Copyright (c) 2022, Microsoft Corporation.

#include <assert.h>
#include <common/debug.h>

#include <arch.h>
#include <arch_helpers.h>
#include <imx_usdhc.h>
#include <lib/spinlock.h>
#include <drivers/delay_timer.h>
#include <omnilog.h>

#define ROUNDUP_DIV(x, y) (__extension__({ \
	typeof(x) __roundup_x = (x); \
	typeof(y) __roundup_mask = (typeof(x))(y) - 1; \
	\
	(__roundup_x / (y)) + (__roundup_x & __roundup_mask ? 1 : 0); \
}))

#define ROUNDDOWN(x, y) (((x) / (y)) * (y))

struct omnilog_buffer {
	char   *bases[2];
	size_t  idx;
	uint8_t cur;
	uint8_t savereq;
	spinlock_t lock;
};

struct omnilog_metadata {
	uint64_t blocklast;
	uint64_t blockmax;
	uint8_t  uuid[16];
	uint8_t  _pad[MMC_BLOCK_SIZE-32];
} __attribute__ ((packed));

static struct omnilog_buffer omnilog_buf[PLATFORM_CORE_COUNT];
static size_t omnilog_bufsize = 0;

static struct omnilog_metadata omnilog_meta;
static spinlock_t omnilog_block_lock;

static uint8_t omnilog_configured = 0;
static uint8_t omnilog_usdhc_init = 0;

static uint64_t omnilog_log_size=0;

static size_t initialize_usdhc()
{
	imx_usdhc_params_t params;
	struct mmc_device_info info;

	INFO("OMNILOG: Initializing USDHC\n");
	memset(&params, 0, sizeof(imx_usdhc_params_t));
	params.bus_width = MMC_BUS_WIDTH_1;
	params.flags = 0;
	info.ocr_voltage = OCR_3_3_3_4 | OCR_3_2_3_3;
#ifdef OMNILOG_EMMC
	params.reg_base = 0x30B40000;
	params.clk_rate = 50000000;
	info.mmc_dev_type = MMC_IS_EMMC;
#else
	params.reg_base = 0x30B50000;
	params.clk_rate = 50000000;  /* Samsung SD Card */
	//params.clk_rate = 25000000; /* SandDisk SD Card */
	info.mmc_dev_type = MMC_IS_SD;
#endif

	imx_usdhc_init(&params, &info);

	INFO("OMNILOG: Device size: %llu blocks\n", info.device_size / MMC_BLOCK_SIZE);

	return info.device_size / MMC_BLOCK_SIZE;
}

#ifdef PERSIST_LOG
static int load_omnilog_metadata()
{
	size_t rc;

	flush_dcache_range((uintptr_t)&omnilog_meta, sizeof(omnilog_meta));
	rc = mmc_read_blocks(0, (uintptr_t)&omnilog_meta, sizeof(omnilog_meta));
	if (!rc)
		return -1;
	else
		return 0;
}

static int save_omnilog_metadata()
{
	size_t rc;

	flush_dcache_range((uintptr_t)&omnilog_meta, sizeof(omnilog_meta));
	rc = mmc_write_blocks(0, (uintptr_t)&omnilog_meta, sizeof(omnilog_meta));
	if (!rc)
		return -1;
	else
		return 0;
}
#endif

int omnilog_config_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3)
{
	char *addr, tempbuf[512];
	size_t bufsize;
	size_t blockmax;
	int i, j;

	if (omnilog_configured)
		return -1;


	addr = (char*)(ROUNDUP_DIV(x1, CACHE_WRITEBACK_GRANULE) * CACHE_WRITEBACK_GRANULE);
	assert(addr >= (char*)IMX_DRAM_BASE);
	INFO("OMNILOG: buffer address,aligned address and size: %lu %p %lu\n", x1, addr, x2);

	bufsize = (size_t)x2 - ((size_t)addr - (size_t)x1);
	omnilog_bufsize = ROUNDDOWN(bufsize / (PLATFORM_CORE_COUNT*2), MMC_BLOCK_SIZE);
	assert(omnilog_bufsize >= MMC_BLOCK_SIZE);

	for (i = 0; i < PLATFORM_CORE_COUNT; i++) {
		for (j = 0; j < 2; j++)
			omnilog_buf[i].bases[j] = &addr[(2*i+j)*omnilog_bufsize];
	}

	for (i = 0; i < PLATFORM_CORE_COUNT; i++) {
		INFO("OMNILOG: Core %d - Log buffers (%p, %p)\n", i,
				omnilog_buf[i].bases[0], omnilog_buf[i].bases[1]);
	}
	INFO("OMNILOG: Log buffer size: %lu * %d\n", omnilog_bufsize, PLATFORM_CORE_COUNT*2);

	omnilog_configured = 1;

	blockmax = initialize_usdhc();
#ifdef PERSIST_LOG
	if (load_omnilog_metadata())
		return -1;
#endif
	omnilog_meta.blockmax = blockmax;
	omnilog_meta.blocklast = sizeof(omnilog_meta) / MMC_BLOCK_SIZE;

	INFO("OMNILOG: Last block: %lu\n", omnilog_meta.blocklast);
	INFO("OMNILOG: Omnilog configured: %d\n", omnilog_configured);
#ifndef REINIT_OMNILOG_STORAGE
	// USDHC needs to be reinitialized after Linux (or OP-TEE?) boots up
	omnilog_usdhc_init = 1;
#endif

	// workaround: once Linux is loaded, we must read from SD Card
	// at least once to write data in it.
  mmc_read_blocks(1, (uintptr_t)tempbuf, 512);

#ifdef OMNILOG_TEST
  char  *buf;
  char  *buf2;
  buf = omnilog_buf[0].bases[0];
  buf2 = omnilog_buf[1].bases[0];
  for(i=0;i<2;i++) {
  memset(buf, 0, 512);
  memset(buf2, 0, 512);
  buf[0] = 'D'; buf[1] = 'E'; buf[2] = 'A'; buf[3] = 'D'; buf[4] = '\0';
  flush_dcache_range((uintptr_t)buf, 512);
  mmc_write_blocks(1, (uintptr_t)buf, 512);
  mmc_read_blocks(1, (uintptr_t)buf2, 512);
  INFO("OMNILOG-TEST: %p %p %s\n", buf, buf2, buf2);
}
#endif
	return 0;
}

int omnilog_log_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3)
{
	char *logentry;
	size_t entrysize;
	char *buf;
	uint8_t *bufcur;
	size_t *bufidx;
	uint8_t *savereq;
	spinlock_t *buflock;
	uint64_t mpidr;
	unsigned int id;
	int ret;
#ifdef REINIT_OMNILOG_STORAGE
	size_t blockmax;
#endif

	if (!omnilog_configured)
		return -1;

#ifdef REINIT_OMNILOG_STORAGE
	if (!omnilog_usdhc_init) {
		blockmax = initialize_usdhc();
#ifdef PERSIST_LOG
		if (log_omnilog_metadata())
			return -1;
#endif
		omnilog_meta.blockmax = blockmax;
		omnilog_meta.blocklast = sizeof(omnilog_meta) / MMC_BLOCK_SIZE;

		INFO("OMNILOG: Last block: %lu\n", omnilog_meta.blocklast);
		omnilog_usdhc_init = 1;
	}
#endif

	logentry = (char*)x1;
	if (logentry < (char*)IMX_DRAM_BASE)
		return -1;

	entrysize = (size_t)x2;

#ifdef OMNILOG_TEST
	INFO("OMNILOG: Log entrysize: %lu; omnilog_bufsize %lu\n", entrysize,omnilog_bufsize);
#endif
	if (entrysize == 0 || entrysize > omnilog_bufsize ||
			logentry + entrysize > (char*)(IMX_DRAM_BASE + IMX_DRAM_SIZE - 1))
			{
		return -1;
	}
	mpidr = read_mpidr();
	id = MPIDR_AFFLVL0_VAL(mpidr);

	bufcur = &(omnilog_buf[id].cur);
	bufidx = &(omnilog_buf[id].idx);

	if (*bufidx + entrysize > omnilog_bufsize) {
		//INFO("OMNILOG: buf_location: %lu; omnilog_bufsize %lu\n", *bufidx+entrysize,omnilog_bufsize);
		buflock = &(omnilog_buf[id].lock);
		spin_lock(buflock);

		savereq = &(omnilog_buf[id].savereq);
		//Return savereq, id
		if (*savereq) {
			spin_unlock(buflock);
			omnilog_store_handler(0, id, 0, 0);
			spin_lock(buflock);
		}

		*bufcur = *bufcur ? 0 : 1;
		*savereq = 1;

		spin_unlock(buflock);
		*bufidx = 0;
		ret = id + 1000;
	} else 
		ret = 0;
	

#ifdef OMNILOG_TEST
	INFO("OMNILOG: LOG: id %u bufcur %d bufidx %lu\n", id, *bufcur, *bufidx);
#endif

	buf = omnilog_buf[id].bases[*bufcur];
	memcpy(&buf[*bufidx], logentry, entrysize);
	*bufidx += entrysize;

	return ret;
}

int omnilog_store_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3)
{
	unsigned int id;
	char *buf;
	uint8_t *bufcur;
	size_t entries_max;
	size_t rc;
	int ret;

	if (!omnilog_configured) 
		return -1;
	
	id = (unsigned int)x1;
	//INFO("OMNILOG: STORE id number is %d\n",id);

	spin_lock(&omnilog_block_lock);
	spin_lock(&(omnilog_buf[id].lock));
	if (!omnilog_buf[id].savereq) {
		ret = 0;
		goto out;
	}

	bufcur = &(omnilog_buf[id].cur);
	if (*bufcur > 1) {
		ret = -1;
		goto out;
	}
	buf = omnilog_buf[id].bases[*bufcur ? 0 : 1];

#ifdef OMNILOG_TEST
	INFO("OMNILOG: STORE: id %u bufpart %d\n", id, *bufcur ? 0 : 1);
	INFO("OMNILOG: STORE: mmc write %lu %p %lu\n",
			omnilog_meta.blocklast, buf, omnilog_bufsize);
#endif

	flush_dcache_range((uintptr_t)buf, omnilog_bufsize);
	//INFO("OMNILOG: STORE: %s\n", buf);
#if 1
	rc = mmc_write_blocks(omnilog_meta.blocklast, (uintptr_t)buf,
			omnilog_bufsize);
	omnilog_log_size+=omnilog_bufsize;
#else
	udelay(omnilog_bufsize/10);
	rc = omnilog_bufsize;
	omnilog_log_size+=omnilog_bufsize;
#endif

	if (!rc) {
		ret = -1;
		goto out;
	}
	memset(buf, 0, omnilog_bufsize);
	omnilog_meta.blocklast += omnilog_bufsize / MMC_BLOCK_SIZE;
	omnilog_buf[id].savereq = 0;
	ret = 0;

#ifdef PERSIST_LOG
	if (save_omnilog_metadata()) {
		ret = -1;
		goto out;
	}
#endif

out:
	spin_unlock(&(omnilog_buf[id].lock));
	spin_unlock(&omnilog_block_lock);

	entries_max = 2 * PLATFORM_CORE_COUNT * omnilog_bufsize / MMC_BLOCK_SIZE;
	if (omnilog_meta.blocklast + entries_max >= omnilog_meta.blockmax) {
		// TODO: interact with the remote admin and/or reset the machine
	}

	//INFO("OMNILOG: STORE: mmc write complete\n");
	return ret;
}

int omnilog_read_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3)
{
	size_t blockidx;
	char *buf;
	size_t bufsize;
	size_t rc;

	if (!omnilog_configured)
		return -1;

	INFO("OMNILOG: Reading stored log entries\n");

	blockidx = (size_t)x1;
	buf = (char*)x2;
	if (buf == NULL)
		return -1;
	bufsize = (size_t)x3;
	if (bufsize < MMC_BLOCK_SIZE || bufsize % MMC_BLOCK_MASK != 0U)
		return -1;

	if (blockidx + bufsize / MMC_BLOCK_SIZE > omnilog_meta.blocklast)
		return -1;

	spin_lock(&omnilog_block_lock);

	flush_dcache_range((uintptr_t)buf, bufsize);
	rc = mmc_read_blocks(blockidx, (uintptr_t)buf, bufsize);

	spin_unlock(&omnilog_block_lock);
	if (!rc)
		return -1;

	return 0;
}

int omnilog_delete_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3)
{
	int ret;

	if (!omnilog_configured)
		return -1;

	INFO("OMNILOG: Deleting stored log entries\n");

	spin_lock(&omnilog_block_lock);

	omnilog_meta.blocklast = sizeof(omnilog_meta) / MMC_BLOCK_SIZE;
#ifdef PERSIST_LOG
	if (save_omnilog_metadata())
		ret = -1;
#endif

	spin_unlock(&omnilog_block_lock);

	return ret;
}

void omnilog_finalize()
{
	char *buf;
	int i, j;
	size_t rc;

	if (!omnilog_configured)
		return;

	INFO("OMNILOG: Finalizing OmniLog\n");

	return;

	for (i = 0; i < PLATFORM_CORE_COUNT; i++) {
		for (j = 0; j < 2; j++) {
			buf = omnilog_buf[i].bases[j];
			flush_dcache_range((uintptr_t)buf, omnilog_bufsize);
			rc = mmc_write_blocks(omnilog_meta.blocklast, (uintptr_t)buf,
					omnilog_bufsize);
			rc = 1;
			if (!rc)
				break;
			omnilog_meta.blocklast += omnilog_bufsize / MMC_BLOCK_SIZE;
		}
	}
	INFO("OMNILOG: Log count is %lu\n",omnilog_meta.blocklast);
	INFO("OMNILOG: Log volume is %lu\n",omnilog_log_size);

#ifdef PERSIST_LOG
	save_omnilog_metadata();
#endif
}
