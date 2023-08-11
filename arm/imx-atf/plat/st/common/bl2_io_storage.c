/*
 * Copyright (c) 2015-2021, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <string.h>

#include <arch_helpers.h>
#include <common/debug.h>
#include <common/desc_image_load.h>
#include <drivers/io/io_block.h>
#include <drivers/io/io_driver.h>
#include <drivers/io/io_fip.h>
#include <drivers/io/io_memmap.h>
#include <drivers/io/io_mtd.h>
#include <drivers/io/io_storage.h>
#include <drivers/mmc.h>
#include <drivers/partition/partition.h>
#include <drivers/raw_nand.h>
#include <drivers/spi_nand.h>
#include <drivers/spi_nor.h>
#include <drivers/st/io_mmc.h>
#include <drivers/st/stm32_fmc2_nand.h>
#include <drivers/st/stm32_qspi.h>
#include <drivers/st/stm32_sdmmc2.h>
#include <drivers/usb_device.h>
#include <lib/fconf/fconf.h>
#include <lib/mmio.h>
#include <lib/utils.h>
#include <plat/common/platform.h>
#include <tools_share/firmware_image_package.h>

#include <platform_def.h>
#include <stm32cubeprogrammer.h>
#include <stm32mp_fconf_getter.h>
#include <usb_dfu.h>

/* IO devices */
uintptr_t fip_dev_handle;
uintptr_t storage_dev_handle;

static const io_dev_connector_t *fip_dev_con;

#if STM32MP_SDMMC || STM32MP_EMMC
static struct mmc_device_info mmc_info;

static uint32_t block_buffer[MMC_BLOCK_SIZE] __aligned(MMC_BLOCK_SIZE);

static io_block_dev_spec_t mmc_block_dev_spec = {
	/* It's used as temp buffer in block driver */
	.buffer = {
		.offset = (size_t)&block_buffer,
		.length = MMC_BLOCK_SIZE,
	},
	.ops = {
		.read = mmc_read_blocks,
		.write = NULL,
	},
	.block_size = MMC_BLOCK_SIZE,
};

static const io_dev_connector_t *mmc_dev_con;
#endif /* STM32MP_SDMMC || STM32MP_EMMC */

#if STM32MP_SPI_NOR
static io_mtd_dev_spec_t spi_nor_dev_spec = {
	.ops = {
		.init = spi_nor_init,
		.read = spi_nor_read,
	},
};
#endif

#if STM32MP_RAW_NAND
static io_mtd_dev_spec_t nand_dev_spec = {
	.ops = {
		.init = nand_raw_init,
		.read = nand_read,
		.seek = nand_seek_bb
	},
};

static const io_dev_connector_t *nand_dev_con;
#endif

#if STM32MP_SPI_NAND
static io_mtd_dev_spec_t spi_nand_dev_spec = {
	.ops = {
		.init = spi_nand_init,
		.read = nand_read,
		.seek = nand_seek_bb
	},
};
#endif

#if STM32MP_SPI_NAND || STM32MP_SPI_NOR
static const io_dev_connector_t *spi_dev_con;
#endif

#if STM32MP_USB_PROGRAMMER
static const io_dev_connector_t *memmap_dev_con;
#endif

io_block_spec_t image_block_spec = {
	.offset = 0U,
	.length = 0U,
};

int open_fip(const uintptr_t spec)
{
	return io_dev_init(fip_dev_handle, (uintptr_t)FIP_IMAGE_ID);
}

int open_storage(const uintptr_t spec)
{
	return io_dev_init(storage_dev_handle, 0);
}

static void print_boot_device(boot_api_context_t *boot_context)
{
	switch (boot_context->boot_interface_selected) {
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_SD:
		INFO("Using SDMMC\n");
		break;
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_EMMC:
		INFO("Using EMMC\n");
		break;
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_NOR_QSPI:
		INFO("Using QSPI NOR\n");
		break;
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_NAND_FMC:
		INFO("Using FMC NAND\n");
		break;
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_NAND_QSPI:
		INFO("Using SPI NAND\n");
		break;
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_SERIAL_USB:
		INFO("Using USB\n");
		break;
	default:
		ERROR("Boot interface %u not found\n",
		      boot_context->boot_interface_selected);
		panic();
		break;
	}

	if (boot_context->boot_interface_instance != 0U) {
		INFO("  Instance %d\n", boot_context->boot_interface_instance);
	}
}

#if STM32MP_SDMMC || STM32MP_EMMC
static void boot_mmc(enum mmc_device_type mmc_dev_type,
		     uint16_t boot_interface_instance)
{
	int io_result __unused;
	struct stm32_sdmmc2_params params;

	zeromem(&params, sizeof(struct stm32_sdmmc2_params));

	mmc_info.mmc_dev_type = mmc_dev_type;

	switch (boot_interface_instance) {
	case 1:
		params.reg_base = STM32MP_SDMMC1_BASE;
		break;
	case 2:
		params.reg_base = STM32MP_SDMMC2_BASE;
		break;
	case 3:
		params.reg_base = STM32MP_SDMMC3_BASE;
		break;
	default:
		WARN("SDMMC instance not found, using default\n");
		if (mmc_dev_type == MMC_IS_SD) {
			params.reg_base = STM32MP_SDMMC1_BASE;
		} else {
			params.reg_base = STM32MP_SDMMC2_BASE;
		}
		break;
	}

	params.device_info = &mmc_info;
	if (stm32_sdmmc2_mmc_init(&params) != 0) {
		ERROR("SDMMC%u init failed\n", boot_interface_instance);
		panic();
	}

	/* Open MMC as a block device to read GPT table */
	io_result = register_io_dev_block(&mmc_dev_con);
	if (io_result != 0) {
		panic();
	}

	io_result = io_dev_open(mmc_dev_con, (uintptr_t)&mmc_block_dev_spec,
				&storage_dev_handle);
	assert(io_result == 0);
}
#endif /* STM32MP_SDMMC || STM32MP_EMMC */

#if STM32MP_SPI_NOR
static void boot_spi_nor(boot_api_context_t *boot_context)
{
	int io_result __unused;

	io_result = stm32_qspi_init();
	assert(io_result == 0);

	io_result = register_io_dev_mtd(&spi_dev_con);
	assert(io_result == 0);

	/* Open connections to device */
	io_result = io_dev_open(spi_dev_con,
				(uintptr_t)&spi_nor_dev_spec,
				&storage_dev_handle);
	assert(io_result == 0);
}
#endif /* STM32MP_SPI_NOR */

#if STM32MP_RAW_NAND
static void boot_fmc2_nand(boot_api_context_t *boot_context)
{
	int io_result __unused;

	io_result = stm32_fmc2_init();
	assert(io_result == 0);

	/* Register the IO device on this platform */
	io_result = register_io_dev_mtd(&nand_dev_con);
	assert(io_result == 0);

	/* Open connections to device */
	io_result = io_dev_open(nand_dev_con, (uintptr_t)&nand_dev_spec,
				&storage_dev_handle);
	assert(io_result == 0);
}
#endif /* STM32MP_RAW_NAND */

#if STM32MP_SPI_NAND
static void boot_spi_nand(boot_api_context_t *boot_context)
{
	int io_result __unused;

	io_result = stm32_qspi_init();
	assert(io_result == 0);

	io_result = register_io_dev_mtd(&spi_dev_con);
	assert(io_result == 0);

	/* Open connections to device */
	io_result = io_dev_open(spi_dev_con,
				(uintptr_t)&spi_nand_dev_spec,
				&storage_dev_handle);
	assert(io_result == 0);
}
#endif /* STM32MP_SPI_NAND */

#if STM32MP_USB_PROGRAMMER
static void mmap_io_setup(void)
{
	int io_result __unused;

	io_result = register_io_dev_memmap(&memmap_dev_con);
	assert(io_result == 0);

	io_result = io_dev_open(memmap_dev_con, (uintptr_t)NULL,
				&storage_dev_handle);
	assert(io_result == 0);
}

static void stm32cubeprogrammer_usb(void)
{
	int ret __unused;
	struct usb_handle *pdev;

	/* Init USB on platform */
	pdev = usb_dfu_plat_init();

	ret = stm32cubeprog_usb_load(pdev, DWL_BUFFER_BASE, DWL_BUFFER_SIZE);
	assert(ret == 0);
}
#endif

void stm32mp_io_setup(void)
{
	int io_result __unused;
	boot_api_context_t *boot_context =
		(boot_api_context_t *)stm32mp_get_boot_ctx_address();

	print_boot_device(boot_context);

	if ((boot_context->boot_partition_used_toboot == 1U) ||
	    (boot_context->boot_partition_used_toboot == 2U)) {
		INFO("Boot used partition fsbl%u\n",
		     boot_context->boot_partition_used_toboot);
	}

	io_result = register_io_dev_fip(&fip_dev_con);
	assert(io_result == 0);

	io_result = io_dev_open(fip_dev_con, (uintptr_t)NULL,
				&fip_dev_handle);

	switch (boot_context->boot_interface_selected) {
#if STM32MP_SDMMC
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_SD:
		dmbsy();
		boot_mmc(MMC_IS_SD, boot_context->boot_interface_instance);
		break;
#endif
#if STM32MP_EMMC
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_EMMC:
		dmbsy();
		boot_mmc(MMC_IS_EMMC, boot_context->boot_interface_instance);
		break;
#endif
#if STM32MP_SPI_NOR
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_NOR_QSPI:
		dmbsy();
		boot_spi_nor(boot_context);
		break;
#endif
#if STM32MP_RAW_NAND
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_NAND_FMC:
		dmbsy();
		boot_fmc2_nand(boot_context);
		break;
#endif
#if STM32MP_SPI_NAND
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_NAND_QSPI:
		dmbsy();
		boot_spi_nand(boot_context);
		break;
#endif
#if STM32MP_USB_PROGRAMMER
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_SERIAL_USB:
		dmbsy();
		mmap_io_setup();
		break;
#endif

	default:
		ERROR("Boot interface %d not supported\n",
		      boot_context->boot_interface_selected);
		panic();
		break;
	}
}

int bl2_plat_handle_pre_image_load(unsigned int image_id)
{
	static bool gpt_init_done __unused;
	uint16_t boot_itf = stm32mp_get_boot_itf_selected();

	switch (boot_itf) {
#if STM32MP_SDMMC || STM32MP_EMMC
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_SD:
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_EMMC:
		if (!gpt_init_done) {
			const partition_entry_t *entry;

			partition_init(GPT_IMAGE_ID);
			entry = get_partition_entry(FIP_IMAGE_NAME);
			if (entry == NULL) {
				ERROR("Could NOT find the %s partition!\n",
				      FIP_IMAGE_NAME);
				return -ENOENT;
			}

			image_block_spec.offset = entry->start;
			image_block_spec.length = entry->length;

			gpt_init_done = true;
		} else {
			bl_mem_params_node_t *bl_mem_params = get_bl_mem_params_node(image_id);

			mmc_block_dev_spec.buffer.offset = bl_mem_params->image_info.image_base;
			mmc_block_dev_spec.buffer.length = bl_mem_params->image_info.image_max_size;
		}

		break;
#endif

#if STM32MP_RAW_NAND || STM32MP_SPI_NAND
#if STM32MP_RAW_NAND
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_NAND_FMC:
#endif
#if STM32MP_SPI_NAND
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_NAND_QSPI:
#endif
		image_block_spec.offset = STM32MP_NAND_FIP_OFFSET;
		break;
#endif

#if STM32MP_SPI_NOR
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_FLASH_NOR_QSPI:
		image_block_spec.offset = STM32MP_NOR_FIP_OFFSET;
		break;
#endif

#if STM32MP_USB_PROGRAMMER
	case BOOT_API_CTX_BOOT_INTERFACE_SEL_SERIAL_USB:
		if (image_id == FW_CONFIG_ID) {
			stm32cubeprogrammer_usb();
			/* FIP loaded at DWL address */
			image_block_spec.offset = DWL_BUFFER_BASE;
			image_block_spec.length = DWL_BUFFER_SIZE;
		}
		break;
#endif

	default:
		ERROR("FIP Not found\n");
		panic();
	}

	return 0;
}

/*
 * Return an IO device handle and specification which can be used to access
 * an image. Use this to enforce platform load policy.
 */
int plat_get_image_source(unsigned int image_id, uintptr_t *dev_handle,
			  uintptr_t *image_spec)
{
	int rc;
	const struct plat_io_policy *policy;

	policy = FCONF_GET_PROPERTY(stm32mp, io_policies, image_id);
	rc = policy->check(policy->image_spec);
	if (rc == 0) {
		*image_spec = policy->image_spec;
		*dev_handle = *(policy->dev_handle);
	}

	return rc;
}
