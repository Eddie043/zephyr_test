/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <sys/printk.h>
#include <cmsis_os2.h>
#include "mctp.h"

#define MCTP_SMBUS_NUM 2

typedef struct _mctp_smbus_port {
	mctp *mctp_inst;
	mctp_smbus_conf conf;
} mctp_smbus_port;

static mctp_smbus_port smbus_port[MCTP_SMBUS_NUM] = {
	{.conf.addr = 0x20, .conf.bus = 0x01},
	{.conf.addr = 0x20, .conf.bus = 0x02}
};

mctp_route_entry mctp_route_tbl[] = {
	{0x11, 0x01, 0x41},
	{0x12, 0x02, 0x42},
	{0x13, 0x01, 0x43},
	{0x14, 0x02, 0x44},
	{0x15, 0x01, 0x45},
	{0x16, 0x02, 0x46},
	{0xFF, 0xFF, 0xFF}
};

static mctp *find_mctp_by_smbus(uint8_t bus)
{
	uint8_t i;
	for (i = 0; i < MCTP_SMBUS_NUM; i++) {
		mctp_smbus_port *p = smbus_port + i;
		
		if (bus == p->conf.bus)
			return p->mctp_inst;
	}

	return NULL;
}

uint8_t get_route_info(uint8_t dest_endpoint, void **mctp_inst, void **medium_ext_params)
{
	if (!mctp_inst || !medium_ext_params)
		return MCTP_ERROR;

	uint8_t rc = MCTP_ERROR;
	uint32_t i;

	for (i = 0; ; i++) {
		mctp_route_entry *p = mctp_route_tbl + i;
		if (p->endpoint == dest_endpoint) {
			*mctp_inst = find_mctp_by_smbus(p->bus);
			mctp_smbus_ext_param *tmp_ext_param = (mctp_smbus_ext_param *)k_malloc(sizeof(mctp_smbus_ext_param));
			if (!tmp_ext_param)
				break;
			
			mctp_printf("tmp_ext_param = %p\n", tmp_ext_param);
			*medium_ext_params = tmp_ext_param;
			tmp_ext_param->addr = p->addr;
			rc = MCTP_SUCCESS;
			break;
		} else if (p->endpoint == 0xFF) {
			break;
		}
	}

	return rc;
}

void main(void)
{
	mctp_printf("MCTP test\n");

	uint32_t i;
	for (i = 0; i < MCTP_SMBUS_NUM; i++) {
		mctp_smbus_port *p = smbus_port + i;
		printk("smbus port %d\n", i);
		printk("bus = %x, addr = %x\n", p->conf.bus, p->conf.addr);

		p->mctp_inst = mctp_init();
		if (!p->mctp_inst) {
			mctp_printf("mctp_init failed!!\n");
			continue;
		}

		uint8_t rc = mctp_set_medium_configure(p->mctp_inst, MCTP_MEDIUM_TYPE_SMBUS, (void *)&p->conf);
		mctp_printf("mctp_set_medium_configure %s\n", (rc == MCTP_SUCCESS)? "success": "failed");

		if (MCTP_DEBUG) {
			MCTP_MEDIUM_TYPE medium_type = MCTP_MEDIUM_TYPE_UNKNOWN;
			void *medium_conf = NULL;
			rc = mctp_get_medium_configure(p->mctp_inst, &medium_type, &medium_conf);
			mctp_printf("mctp_get_medium_configure %s\n", (rc == MCTP_SUCCESS)? "success": "failed");
			mctp_printf("medium_type = %d\n", medium_type);

			mctp_smbus_conf *conf = (mctp_smbus_conf *)medium_conf;
			if (p)
				mctp_printf("p = %p, smbus bus = %x, addr = %x\n", conf, conf->bus, conf->addr);

			if (medium_conf)
				k_free(medium_conf);
		}

		mctp_reg_endpoint_resolve_func(p->mctp_inst, get_route_info);
		mctp_start(p->mctp_inst);
	}
#if 0
	mctp *mctp_inst = mctp_init();
	
	if (!mctp_inst)
		return;
	
	mctp_printf("mctp_init success!!\n");

	/* configure smbus */
	mctp_smbus_conf smbus_conf = {0};
	smbus_conf.addr = 0x20;
	smbus_conf.bus = 0x01;
	uint8_t rc = mctp_set_medium_configure(mctp_inst, MCTP_MEDIUM_TYPE_SMBUS, (void *)&smbus_conf);
	mctp_printf("mctp_set_medium_configure %s\n", (rc == MCTP_SUCCESS)? "success": "failed");

	if (MCTP_DEBUG) {
		MCTP_MEDIUM_TYPE medium_type = MCTP_MEDIUM_TYPE_UNKNOWN;
		void *medium_conf = NULL;
		rc = mctp_get_medium_configure(mctp_inst, &medium_type, &medium_conf);
		mctp_printf("mctp_get_medium_configure %s\n", (rc == MCTP_SUCCESS)? "success": "failed");
		mctp_printf("medium_type = %d\n", medium_type);

		if (medium_type == MCTP_MEDIUM_TYPE_SMBUS) {
			mctp_smbus_conf *p = (mctp_smbus_conf *)medium_conf;
			if (p)
				mctp_printf("p = %p, smbus bus = %x, addr = %x\n", p, p->bus, p->addr);
		}

		if (medium_conf)
			k_free(medium_conf);
	}

	mctp_start(mctp_inst);
#endif

	while (1) {
		i++;
		k_msleep(1000000);
#if 0
		if (!(i % 1000)) {
			uint8_t buf[65] = {1, 2, 3, 7, 8, 9};
			mctp_smbus_ext_param smbus_ext_param = {.addr = 0x80};
			mctp_send_msg(smbus_port[0].mctp_inst, i % 16, buf, sizeof(buf), 1, &smbus_ext_param);
		}

		if (!(i % 2000)) {
			uint8_t buf[65] = {9, 8, 7, 3, 2, 1};
			mctp_smbus_ext_param smbus_ext_param = {.addr = 0x60};
			mctp_send_msg(smbus_port[1].mctp_inst, i % 8, buf, sizeof(buf), 1, &smbus_ext_param);
		}
#endif
	}
}