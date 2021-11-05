#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr.h>
#include <sys/printk.h>
#include <cmsis_os2.h>
#include "mctp.h"

#define MCTP_SMBUS_PEC_SIZE 1

typedef struct __attribute__((packed)) {
    uint8_t cmd_code;
    uint8_t byte_cnt;
    uint8_t src_addr;
} smbus_hdr;

static uint16_t mctp_smbus_read(void *mctp_p, uint8_t *buf, uint32_t len, mctp_medium_ext_param *medium_priv_data)
{
    if (!mctp_p || !buf || !len || !medium_priv_data)
        return 0;

    mctp *mctp_inst = (mctp *)mctp_p;
    (void)mctp_inst;

    uint8_t rdata[256] = {0};
    uint8_t rlen = 0;
    /* TODO: read data from smbus and check the PEC */
    unsigned char test[73] = {
        0x0F, 0x46, 0x21, 0x01, 0x68, 0x08, 0x80, 0x01, 0x00, 0x00, 0x02, 0x00,
        0x22, 0x00, 0x00, 0xEA, 0x03, 0xA5, 0xEA, 0x5A, 0xA5, 0xEA, 0x5A, 0xA5,
        0xEA, 0x5A, 0xA5, 0x5A, 0x77, 0x46, 0x74, 0x41, 0x28, 0x00, 0x00, 0x00,
        0xE5, 0xD0, 0xE4, 0xDC, 0x00, 0x02, 0x02, 0x91, 0x01, 0x00, 0xFF, 0xFF,
        0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3C, 0x00, 0x00, 0x00,
        0xC0, 0xD8, 0x06, 0x00, 0x7C, 0x05, 0x00, 0x00, 0xC0, 0xD8, 0x06, 0x00,
        0x64
    };
    memcpy(rdata, test, sizeof(test));
    rlen = sizeof(test);
    smbus_hdr *hdr = (smbus_hdr *)rdata;
    mctp_printf("cmd_code = 0x%x, byte_cnt = %d, src_addr = 0x%x\n", hdr->cmd_code, hdr->byte_cnt, hdr->src_addr);
    mctp_printf("sizeof(smbus_hdr) = %d\n", sizeof(smbus_hdr));

    /* TODO: remove the smbus header */

    /* TODO: return the actually read data len */
    uint8_t rt_size = rlen - sizeof(smbus_hdr) - MCTP_SMBUS_PEC_SIZE;
    memcpy(buf, rdata + sizeof(smbus_hdr), rt_size);
    return rt_size;
    // return 0;
}

static uint16_t mctp_smbus_write(void *mctp_p, uint8_t *buf, uint32_t len, mctp_medium_ext_param medium_priv_data)
{
    if (!mctp_p || !buf || !len)
        return 0;

    mctp *mctp_inst = (mctp *)mctp_p;
    (void)mctp_inst;

    if (medium_priv_data.type != MCTP_MEDIUM_TYPE_SMBUS)
        return 0;
    
    mctp_printf("smbus_ext_param addr = %x\n", medium_priv_data.smbus_ext_param.addr);
    if (MCTP_DEBUG)
        print_data_hex(buf, len);

    /* TODO: add the smbus header */

    /* TODO: write data to smbus */

    /* TODO: return the actually write data len */
    return 1;
}

uint8_t mctp_smbus_init(mctp *mctp_inst, mctp_medium_conf medium_conf)
{
    if (!mctp_inst)
        return MCTP_ERROR;

    mctp_inst->medium_conf = medium_conf;
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
    memset(&mctp_inst->medium_conf, 0, sizeof(mctp_inst->medium_conf));
    return MCTP_SUCCESS; 
}