#
# Define the cryptographic algorithm to be built
#

#
# CAAM Debug: define 3x32 bits value (same bit used to debug a module)
# CFG_DBG_CAAM_TRACE  Module print trace
# CFG_DBG_CAAM_DESC   Module descriptor dump
# CFG_DBG_CAAM_BUF    Module buffer dump
#

# DBG_HAL    BIT32(0)  // HAL trace
# DBG_CTRL   BIT32(1)  // Controller trace
# DBG_MEM    BIT32(2)  // Memory utility trace
# DBG_SGT    BIT32(3)  // Scatter Gather trace
# DBG_PWR    BIT32(4)  // Power trace
# DBG_JR     BIT32(5)  // Job Ring trace
# DBG_RNG    BIT32(6)  // RNG trace
# DBG_HASH   BIT32(7)  // Hash trace
# DBG_RSA    BIT32(8)  // RSA trace
# DBG_CIPHER BIT32(9)  // Cipher trace
# DBG_BLOB   BIT32(10) // BLOB trace
# DBG_ECC    BIT32(11) // ECC trace
# DBG_DSA    BIT32(12) // DSA trace
# DBG_MP     BIT32(13)  // MP trace
# DBG_SM     BIT32(14) // SM trace
# DBG_DH     BIT32(15) // DH Trace
# DBG_DMAOBJ BIT32(16) // DMA Object Trace

CFG_DBG_CAAM_TRACE ?= 0x2
CFG_DBG_CAAM_DESC ?= 0x0
CFG_DBG_CAAM_BUF ?= 0x0

# Enable the BLOB module used for the hardware unique key
# CFG_NXP_CAAM_BLOB_DRV ?= y

ifeq ($(CFG_MX7ULP), y)
# i.MX 7ULP is sharing one single line of interrupt for the 2 Job Ring interfaces
# disable the use of interrupts in OP-TEE.
$(call force, CFG_CAAM_NO_ITR,y)
endif

ifeq ($(filter y, $(CFG_MX8QM) $(CFG_MX8QX)),y)
# Due to the CAAM DMA behaviour on iMX8QM & iMX8QX, 4 bytes need to be add to
# the buffer size when aligned memory allocation is done
$(call force, CFG_CAAM_SIZE_ALIGN,4)
#
# CAAM Job Ring configuration
#  - Normal boot settings
#  - HAB support boot settings
#
$(call force, CFG_JR_BLOCK_SIZE,0x10000)
$(call force,CFG_JR_INDEX,3)  # Job Ring 3
$(call force,CFG_JR_INT,486)  # CAAM_INT3 = 486
else ifneq (,$(filter y, $(CFG_MX8MM) $(CFG_MX8MN) $(CFG_MX8MP) $(CFG_MX8MQ)))
$(call force, CFG_CAAM_SIZE_ALIGN,1)
#
# CAAM Job Ring configuration
#  - Normal boot settings
#  - HAB support boot settings
#
$(call force, CFG_JR_BLOCK_SIZE,0x1000)
# On i.MX8 mscale devices OP-TEE runs before u-boot.
# HAB can still be reuse in u-boot to authenticate linux
# Use another Job ring other than the one used by HAB.
$(call force, CFG_JR_INDEX,2)  # Default JR index used
$(call force, CFG_JR_INT,146)  # Default JR IT Number (114 + 32) = 146
else
$(call force, CFG_CAAM_SIZE_ALIGN,1)
#
# CAAM Job Ring configuration
#  - Normal boot settings
#  - HAB support boot settings
#
$(call force, CFG_JR_BLOCK_SIZE,0x1000)
$(call force, CFG_JR_INDEX,0)  # Default JR index used
$(call force, CFG_JR_INT,137)  # Default JR IT Number (105 + 32) = 137
endif

# if CFG_DT is enable disable JR Node if taken by OP-TEE
# i.MX 8 with scfw do not need this option.
ifneq ($(filter y, $(CFG_MX8QM) $(CFG_MX8QX) $(CFG_MX8DXL)), y)
$(call force, CFG_CAAM_JR_DISABLE_NODE,y)
endif
#
# Configuration of the Crypto Driver
#
ifeq ($(CFG_CRYPTO_DRIVER), y)

$(call force, CFG_NXP_CAAM_RUNTIME_JR, y)

#
# Definition of all HW accelerations for all i.MX
#
$(call force, CFG_NXP_CAAM_RNG_DRV, y)
$(call force, CFG_WITH_SOFTWARE_PRNG,n)

# Force to 'y' the CFG_NXP_CAAM_xxx_DRV to enable the CAAM HW driver
# and enable the associated CFG_CRYPTO_DRV_xxx Crypto driver
# API
#
# Example: Enable CFG_CRYPTO_DRV_HASH and CFG_NXP_CAAM_HASH_DRV
#     $(eval $(call cryphw-enable-drv-hw, HASH))
define cryphw-enable-drv-hw
_var := $(strip $(1))
$$(call force, CFG_NXP_CAAM_$$(_var)_DRV, y)
$$(call force, CFG_CRYPTO_DRV_$$(_var), y)
endef

# Return 'y' if at least one of the variable
# CFG_CRYPTO_xxx_HW is 'y'
cryphw-one-enabled = $(call cfg-one-enabled, \
                        $(foreach v,$(1), CFG_NXP_CAAM_$(v)_DRV))

# Definition of the HW and Cryto Driver Algorithm supported by all i.MX
$(eval $(call cryphw-enable-drv-hw, HASH))
$(eval $(call cryphw-enable-drv-hw, CIPHER))
$(eval $(call cryphw-enable-drv-hw, HMAC))
$(eval $(call cryphw-enable-drv-hw, CMAC))
$(eval $(call cryphw-enable-drv-hw, SM))
$(eval $(call cryphw-enable-drv-hw, BLOB))

ifneq ($(filter y, $(CFG_MX6QP) $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) \
	$(CFG_MX6S) $(CFG_MX6SL) $(CFG_MX6SLL) $(CFG_MX6SX) $(CFG_MX7ULP)), y)
$(eval $(call cryphw-enable-drv-hw, RSA))
$(eval $(call cryphw-enable-drv-hw, ECC))
$(eval $(call cryphw-enable-drv-hw, DSA))
ifneq ($(filter y, $(CFG_MX8QM) $(CFG_MX8QX) $(CFG_MX8DXL)), y)
$(eval $(call cryphw-enable-drv-hw, MP))
CFG_PTA_MP ?= y
endif
$(eval $(call cryphw-enable-drv-hw, DH))

# Define the RSA Private Key Format used by the CAAM
#   Format #1: (n, d)
#   Format #2: (p, q, d)
#   Format #3: (p, q, dp, dq, qp)
CFG_NXP_CAAM_RSA_KEY_FORMAT ?= 3

CFG_CRYPTO_SM2_PKE = n
CFG_CRYPTO_SM2_DSA = n
CFG_CRYPTO_SM2_KEP = n

endif

$(call force, CFG_NXP_CAAM_ACIPHER_DRV, $(call cryphw-one-enabled, ECC RSA DH))

ifeq ($(CFG_IMX_DEK_HAB),y)
CFG_PTA_DEK ?= y
endif

#
# Enable Cryptographic Driver interface
#
CFG_CRYPTO_DRV_ACIPHER ?= $(CFG_NXP_CAAM_ACIPHER_DRV)
endif
