#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr.h>
#include <sys/printk.h>
#include <cmsis_os2.h>
#include "mctp.h"

static uint16_t mctp_smbus_read(void *mctp_p, uint8_t *buf, uint32_t len, void *medium_priv_data)
{
    if (!mctp_p || !buf || !len)
        return 0;

    mctp *mctp_inst = (mctp *)mctp_p;
    (void)mctp_inst;
    /* TODO: read data from smbus and check the PEC */

    /* TODO: remove the smbus header */

    /* TODO: return the actually read data len */
    uint8_t test[] = {0x01, 0x11, 0x08, 0xC8, 0x01, 0x84, 0x05, 0x01, 0xE3};
    memcpy(buf, test, sizeof(test));
    return sizeof(test);
}

static uint16_t mctp_smbus_write(void *mctp_p, uint8_t *buf, uint32_t len, void *medium_priv_data)
{
    if (!mctp_p || !buf || !len)
        return 0;

    mctp *mctp_inst = (mctp *)mctp_p;
    (void)mctp_inst;

    mctp_smbus_ext_param *smbus_ext_param = (mctp_smbus_ext_param *)medium_priv_data;
    mctp_printf("smbus_ext_param addr = %x\n", smbus_ext_param->addr);
    if (MCTP_DEBUG)
        print_data_hex(buf, len);

    /* TODO: add the smbus header */

    /* TODO: write data to smbus */

    /* TODO: return the actually write data len */
    return 1;
}

uint8_t mctp_smbus_init(mctp *mctp_inst, mctp_smbus_conf *medium_conf)
{
    if (!mctp_inst)
        return MCTP_ERROR;

    mctp_inst->medium_conf = k_malloc(sizeof(*medium_conf));
    if (!mctp_inst->medium_conf)
        return MCTP_ERROR;

    memcpy(mctp_inst->medium_conf, medium_conf, sizeof(*medium_conf));

    mctp_inst->read_data = mctp_smbus_read;
    mctp_inst->write_data = mctp_smbus_write;

    return MCTP_SUCCESS; 
}

uint8_t mctp_smbus_deinit(mctp *mctp_inst)
{
    if (!mctp_inst)
        return MCTP_ERROR;

    mctp_inst->read_data = NULL;
    mctp_inst->write_data = NULL;

    if (mctp_inst->medium_conf) {
        k_free(mctp_inst->medium_conf);
        mctp_inst->medium_conf = NULL;
    }

    return MCTP_SUCCESS; 
}