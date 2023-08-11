// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018 NXP
 *
 */
#include <trace.h>
#include <libfdt.h>
#include <kernel/boot.h>
#include <imx.h>

#define DT_U32_PROP_SIZE	4
#define DT_NUM_PROP_MAX		5

/*
 * dt_overwrite() overwrites specified properties in the device tree.
 * Properties to overwrite and new properties are also specified in
 * the device tree.
 *
 * The format is the following :
 *
 * overw_str = <&node_1 prop_1 ... prop_n>,
 *		<&node_2 prop_1 ... prop_n>,
 *		...
 *		<&node_n prop_1 ... prop_n>;
 *
 * prop_n variables are 32bit integers.
 *
 * @node_str: Compatible string of optee node.
 * @prop_str: Property to overwrite (reg, clocks, ...).
 * @overw_str: Array in node_str containing new values to overwrite property
 *		specified prop_str.
 * @size_prop: Size of the property to overwrite.
 */
void dt_overwrite(const char *node_str, const char *prop_str,
				const char *overw_str, uint32_t size_prop)
{
	void *fdt, *prop;
	uint32_t *fdt_overw_node;
	int offset, phandle, ret, len;
	uint32_t i, j, sub_node, sub[DT_NUM_PROP_MAX];

	if (size_prop > DT_NUM_PROP_MAX)
		EMSG("Number of properties to overwrite is too high");

	if (node_str == NULL) {
		EMSG("Compatible string empty");
		return;
	}

	/* Get dtb */
	fdt = get_dt();
	if (fdt == NULL) {
		EMSG("No DTB found");
		return;
	}

	/* Get offset of node_str */
	offset = fdt_node_offset_by_compatible(fdt, 0, node_str);
	if (offset < 0) {
		EMSG("Cannot find %s node in the device tree", node_str);
		return;
	}

	/* Get overw_node property */
	fdt_overw_node = (uint32_t *)fdt_getprop(fdt, offset, overw_str, &len);
	if (!fdt_overw_node) {
		DMSG("%s not found in %s", overw_str, node_str);
		return;
	}
	sub_node = len / (size_prop * DT_U32_PROP_SIZE);

	/* For each node to substitute */
	for (i = 0; i < sub_node; i++) {

		/* fdt_overw_node[0] has to be the phandle */
		phandle = fdt32_to_cpu(fdt_overw_node[i*size_prop]);

		/* Save new properties starting from fdt_overw_node[1] */
		for (j = 0; j < size_prop; j++)
			sub[j] = fdt_overw_node[i*size_prop+j+1];

		/* Get offset based on the phandle */
		offset = fdt_node_offset_by_phandle(fdt, phandle);
		if (offset < 0) {
			EMSG("Cannot find offset based on phandle");
			return;
		}

		/* Get size of prop_str */
		prop = fdt_getprop_w(fdt, offset, prop_str, &len);
		if (!prop) {
			DMSG("There is no property %s in the phandle %d",
							prop_str, phandle);
			return;
		}

		/* Replace prop_str property */
		ret = fdt_setprop_inplace(fdt, offset, prop_str, sub, len);
		if (ret) {
			EMSG("Error setprop inplace ret=%d", ret);
			return;
		}
	}
}

void dt_debug(const char *node_str, const char *prop)
{
	void *fdt;
	uint32_t *fdt_prop;
	int offset;

	if (node_str == NULL) {
		EMSG("Compatible string empty");
		return;
	}

	/* Get dtb */
	fdt = get_dt();
	if (fdt == NULL) {
		EMSG("No DTB found");
		return;
	}

	/* Get offset of node_str */
	offset = fdt_node_offset_by_compatible(fdt, 0, node_str);
	if (offset < 0) {
		EMSG("Cannot find %s node in the device tree", node_str);
		return;
	}

	/* Get overw_clock property */
	fdt_prop = (uint32_t *)fdt_getprop(fdt, offset, prop, NULL);
	if (!fdt_prop) {
		EMSG("%s not found in %s", prop, node_str);
		return;
	}

	DMSG(
		"Node: %s prop %s = 0x%X, 0x%X, 0x%X",
			node_str,
			prop,
			fdt32_to_cpu(fdt_prop[0]),
			fdt32_to_cpu(fdt_prop[1]),
			fdt32_to_cpu(fdt_prop[2])
		);
}
