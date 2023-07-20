// SPDX-License-Identifier: MIT
// Copyright (c) 2022, Microsoft Corporation.

#include <assert.h>
#include <common/debug.h>

#include <arch.h>
#include <arch_helpers.h>
#include <imx_usdhc.h>
#include <lib/spinlock.h>
#include <drivers/delay_timer.h>
#include <seclog.h>

#define ROUNDUP_DIV(x, y) (__extension__({ \
	typeof(x) __roundup_x = (x); \
	typeof(y) __roundup_mask = (typeof(x))(y) - 1; \
	\
	(__roundup_x / (y)) + (__roundup_x & __roundup_mask ? 1 : 0); \
}))

#define ROUNDDOWN(x, y) (((x) / (y)) * (y))

struct seclog_buffer {
	char   *bases[2];
	size_t  idx;
	uint8_t cur;
	uint8_t savereq;
	spinlock_t lock;
};

struct seclog_metadata {
	uint64_t blocklast;
	uint64_t blockmax;
	uint8_t  uuid[16];
	// TODO: credentials
	uint8_t  _pad[MMC_BLOCK_SIZE-32];
} __attribute__ ((packed));

static struct seclog_buffer seclog_buf[PLATFORM_CORE_COUNT];
static size_t seclog_bufsize = 0;

static struct seclog_metadata seclog_meta;
static spinlock_t seclog_block_lock;

static uint8_t seclog_configured = 0;
static uint8_t seclog_usdhc_init = 0;

static uint64_t seclog_log_size=0;

static size_t initialize_usdhc()
{
	imx_usdhc_params_t params;
	struct mmc_device_info info;

	INFO("SECLOG: Initializing USDHC\n");
	memset(&params, 0, sizeof(imx_usdhc_params_t));
	params.bus_width = MMC_BUS_WIDTH_1;
	params.flags = 0;
	info.ocr_voltage = OCR_3_3_3_4 | OCR_3_2_3_3;
#ifdef SECLOG_EMMC
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

	INFO("SECLOG: Device size: %llu blocks\n", info.device_size / MMC_BLOCK_SIZE);

	return info.device_size / MMC_BLOCK_SIZE;
}

#ifdef PERSIST_LOG
static int load_seclog_metadata()
{
	size_t rc;

	flush_dcache_range((uintptr_t)&seclog_meta, sizeof(seclog_meta));
	rc = mmc_read_blocks(0, (uintptr_t)&seclog_meta, sizeof(seclog_meta));
	if (!rc)
		return -1;
	else
		return 0;
}

static int save_seclog_metadata()
{
	size_t rc;

	flush_dcache_range((uintptr_t)&seclog_meta, sizeof(seclog_meta));
	rc = mmc_write_blocks(0, (uintptr_t)&seclog_meta, sizeof(seclog_meta));
	if (!rc)
		return -1;
	else
		return 0;
}
#endif

int seclog_config_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3)
{
	char *addr, tempbuf[512];
	size_t bufsize;
	size_t blockmax;
	int i, j;

	if (seclog_configured)
		return -1;


	addr = (char*)(ROUNDUP_DIV(x1, CACHE_WRITEBACK_GRANULE) * CACHE_WRITEBACK_GRANULE);
	assert(addr >= (char*)IMX_DRAM_BASE);
	INFO("SECLOG: buffer address,aligned address and size: %lu %p %lu\n", x1, addr, x2);

	bufsize = (size_t)x2 - ((size_t)addr - (size_t)x1);
	seclog_bufsize = ROUNDDOWN(bufsize / (PLATFORM_CORE_COUNT*2), MMC_BLOCK_SIZE);
	assert(seclog_bufsize >= MMC_BLOCK_SIZE);

	for (i = 0; i < PLATFORM_CORE_COUNT; i++) {
		for (j = 0; j < 2; j++)
			seclog_buf[i].bases[j] = &addr[(2*i+j)*seclog_bufsize];
	}

	for (i = 0; i < PLATFORM_CORE_COUNT; i++) {
		INFO("SECLOG: Core %d - Log buffers (%p, %p)\n", i,
				seclog_buf[i].bases[0], seclog_buf[i].bases[1]);
	}
	INFO("SECLOG: Log buffer size: %lu * %d\n", seclog_bufsize, PLATFORM_CORE_COUNT*2);

	seclog_configured = 1;

	blockmax = initialize_usdhc();
#ifdef PERSIST_LOG
	if (load_seclog_metadata())
		return -1;
#endif
	seclog_meta.blockmax = blockmax;
	seclog_meta.blocklast = sizeof(seclog_meta) / MMC_BLOCK_SIZE;

	INFO("SECLOG: Last block: %lu\n", seclog_meta.blocklast);
	INFO("SECLOG: Seclog configured: %d\n", seclog_configured);
#ifndef REINIT_SECLOG_STORAGE
	// USDHC needs to be reinitialized after Linux (or OP-TEE?) boots up
	seclog_usdhc_init = 1;
#endif

	// workaround: once Linux is loaded, we must read from SD Card (and eMMC?)
	// at least once to write data in it.
  mmc_read_blocks(1, (uintptr_t)tempbuf, 512);

#ifdef SECLOG_TEST
  char  *buf;
  char  *buf2;
  buf = seclog_buf[0].bases[0];
  buf2 = seclog_buf[1].bases[0];
  for(i=0;i<2;i++) {
  memset(buf, 0, 512);
  memset(buf2, 0, 512);
  buf[0] = 'D'; buf[1] = 'E'; buf[2] = 'A'; buf[3] = 'D'; buf[4] = '\0';
  flush_dcache_range((uintptr_t)buf, 512);
  mmc_write_blocks(1, (uintptr_t)buf, 512);
  mmc_read_blocks(1, (uintptr_t)buf2, 512);
  INFO("XXXXXX: %p %p %s\n", buf, buf2, buf2);
}
#endif
	return 0;
}

int seclog_log_handler(uint32_t smc_fid, u_register_t x1,
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
#ifdef REINIT_SECLOG_STORAGE
	size_t blockmax;
#endif

	if (!seclog_configured)
		return -1;

#ifdef REINIT_SECLOG_STORAGE
	if (!seclog_usdhc_init) {
		blockmax = initialize_usdhc();
#ifdef PERSIST_LOG
		if (log_seclog_metadata())
			return -1;
#endif
		seclog_meta.blockmax = blockmax;
		seclog_meta.blocklast = sizeof(seclog_meta) / MMC_BLOCK_SIZE;

		INFO("SECLOG: Last block: %lu\n", seclog_meta.blocklast);
		seclog_usdhc_init = 1;
	}
#endif

	logentry = (char*)x1;
	if (logentry < (char*)IMX_DRAM_BASE)
		return -1;

	entrysize = (size_t)x2;

#ifdef SECLOG_TEST
	INFO("SECLOG: Log entrysize: %lu; seclog_bufsize %lu\n", entrysize,seclog_bufsize);
#endif
	if (entrysize == 0 || entrysize > seclog_bufsize ||
			logentry + entrysize > (char*)(IMX_DRAM_BASE + IMX_DRAM_SIZE - 1))
			{
		return -1;
	}
	mpidr = read_mpidr();
	id = MPIDR_AFFLVL0_VAL(mpidr);

	bufcur = &(seclog_buf[id].cur);
	bufidx = &(seclog_buf[id].idx);

	if (*bufidx + entrysize > seclog_bufsize) {
		//INFO("SECLOG: buf_location: %lu; seclog_bufsize %lu\n", *bufidx+entrysize,seclog_bufsize);
		buflock = &(seclog_buf[id].lock);
		spin_lock(buflock);

		savereq = &(seclog_buf[id].savereq);
		//Return savereq, id
		if (*savereq) {
			spin_unlock(buflock);
			seclog_store_handler(0, id, 0, 0);
			spin_lock(buflock);
		}

		*bufcur = *bufcur ? 0 : 1;
		*savereq = 1;

		spin_unlock(buflock);
		*bufidx = 0;
		ret = id + 1000;
	} else 
		ret = 0;
	

#ifdef SECLOG_TEST
	INFO("SECLOG: LOG: id %u bufcur %d bufidx %lu\n", id, *bufcur, *bufidx);
#endif
	//spin_lock(&(seclog_buf[id].lock));

	buf = seclog_buf[id].bases[*bufcur];
	memcpy(&buf[*bufidx], logentry, entrysize);
//	strlcpy(&buf[*bufidx], logentry, entrysize);
	*bufidx += entrysize;
	//spin_unlock(&(seclog_buf[id].lock));

	return ret;
}

int seclog_store_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3)
{
	unsigned int id;
	char *buf;
	uint8_t *bufcur;
	size_t entries_max;
	size_t rc;
	int ret;

	if (!seclog_configured) 
		return -1;
	
	id = (unsigned int)x1;
	//INFO("SECLOG: STORE id number is %d\n",id);

	spin_lock(&seclog_block_lock);
	spin_lock(&(seclog_buf[id].lock));
	if (!seclog_buf[id].savereq) {
		ret = 0;
		goto out;
	}

	bufcur = &(seclog_buf[id].cur);
	if (*bufcur > 1) {
		ret = -1;
		goto out;
	}
	buf = seclog_buf[id].bases[*bufcur ? 0 : 1];

#ifdef SECLOG_TEST
	INFO("SECLOG: STORE: id %u bufpart %d\n", id, *bufcur ? 0 : 1);
	INFO("SECLOG: STORE: mmc write %lu %p %lu\n",
			seclog_meta.blocklast, buf, seclog_bufsize);
#endif

	flush_dcache_range((uintptr_t)buf, seclog_bufsize);
	//INFO("SECLOG: STORE: %s\n", buf);
#if 0
	//udelay(5000);	//5ms delay
	//rc = mmc_write_blocks(seclog_meta.blocklast, (uintptr_t)buf,
	//		seclog_bufsize);
#else
	udelay(seclog_bufsize/10);
	rc = seclog_bufsize;
	seclog_log_size+=seclog_bufsize;
#endif

	if (!rc) {
		ret = -1;
		goto out;
	}
	memset(buf, 0, seclog_bufsize);
	seclog_meta.blocklast += seclog_bufsize / MMC_BLOCK_SIZE;
	seclog_buf[id].savereq = 0;
	ret = 0;
//enabled
//	if (save_seclog_metadata()) {
//		ret = -1;
//		goto out;
//	}

out:
	spin_unlock(&(seclog_buf[id].lock));
	spin_unlock(&seclog_block_lock);

	entries_max = 2 * PLATFORM_CORE_COUNT * seclog_bufsize / MMC_BLOCK_SIZE;
	if (seclog_meta.blocklast + entries_max >= seclog_meta.blockmax) {
		// TODO: interact with the remote admin and/or reset the machine
	}

	//INFO("SECLOG: STORE: mmc write complete\n");
	return ret;
}

int seclog_read_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3)
{
	size_t blockidx;
	char *buf;
	size_t bufsize;
	size_t rc;

	if (!seclog_configured)
		return -1;

	INFO("SECLOG: Reading stored log entries\n");

	blockidx = (size_t)x1;
	buf = (char*)x2;
	if (buf == NULL)
		return -1;
	bufsize = (size_t)x3;
	if (bufsize < MMC_BLOCK_SIZE || bufsize % MMC_BLOCK_MASK != 0U)
		return -1;

	if (blockidx + bufsize / MMC_BLOCK_SIZE > seclog_meta.blocklast)
		return -1;

	spin_lock(&seclog_block_lock);

	flush_dcache_range((uintptr_t)buf, bufsize);
	rc = mmc_read_blocks(blockidx, (uintptr_t)buf, bufsize);

	spin_unlock(&seclog_block_lock);
	if (!rc)
		return -1;

	return 0;
}

int seclog_delete_handler(uint32_t smc_fid, u_register_t x1,
		u_register_t x2, u_register_t x3)
{
	int ret;

	if (!seclog_configured)
		return -1;

	INFO("SECLOG: Deleting stored log entries\n");

	// TODO: authenticated delete (e.g., a signed command)

	spin_lock(&seclog_block_lock);

	seclog_meta.blocklast = sizeof(seclog_meta) / MMC_BLOCK_SIZE;
#ifdef PERSIST_LOG
	if (save_seclog_metadata())
		ret = -1;
#endif

	spin_unlock(&seclog_block_lock);

	return ret;
}

void seclog_finalize(char *msg)
{
	char *buf;
	int i, j;
	size_t rc;

	if (!seclog_configured)
		return;

	INFO("SECLOG: Finalizing SecureLog\n");

	return;

	for (i = 0; i < PLATFORM_CORE_COUNT; i++) {
		for (j = 0; j < 2; j++) {
			buf = seclog_buf[i].bases[j];
			flush_dcache_range((uintptr_t)buf, seclog_bufsize);
			//rc = mmc_write_blocks(seclog_meta.blocklast, (uintptr_t)buf,
			//		seclog_bufsize);
			rc = 1;
			if (!rc)
				break;
			seclog_meta.blocklast += seclog_bufsize / MMC_BLOCK_SIZE;
		}
	}
	INFO("SECLOG: Log count is %lu\n",seclog_meta.blocklast);
	INFO("SECLOG: Log volume is %lu\n",seclog_log_size);

#ifdef PERSIST_LOG
	save_seclog_metadata();
#endif
}
