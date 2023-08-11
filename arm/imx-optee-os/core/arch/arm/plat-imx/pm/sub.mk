global-incdirs-y += .
srcs-$(CFG_PSCI_ARM32) += psci.c
srcs-$(CFG_MX7) += pm-imx7.c psci-suspend-imx7.S imx7_suspend.c \
	cpuidle-imx7d.c psci-cpuidle-imx7.S gpcv2.c

srcs-$(CFG_MX6) += pm-imx6.c imx6_suspend.c psci-suspend-imx6.S
srcs-$(CFG_MX6UL) += psci-cpuidle-imx6ul.S cpuidle-imx6ul.c
srcs-$(CFG_MX6ULL) += psci-cpuidle-imx6ull.S cpuidle-imx6ul.c
srcs-$(CFG_MX6SX) += psci-cpuidle-imx6sx.S cpuidle-imx6sx.c
srcs-$(CFG_MX6SL) += psci-cpuidle-imx6sl.S cpuidle-imx6sl.c
srcs-$(CFG_MX6SLL) += psci-cpuidle-imx6sll.S cpuidle-imx6sll.c
srcs-$(CFG_MX7ULP) += pm-imx7ulp.c psci-suspend-imx7ulp.S imx7ulp_suspend.c
srcs-$(CFG_MX8MM) += pm-imx8.c

cflags-psci.c-y += -Wno-suggest-attribute=noreturn
