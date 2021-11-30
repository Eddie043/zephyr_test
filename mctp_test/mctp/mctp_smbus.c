#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr.h>
#include <sys/printk.h>
#include <sys/crc.h>
#include <cmsis_os2.h>
#include <logging/log.h>
#include "mctp.h"

LOG_MODULE_DECLARE(mctp);

#define MCTP_SMBUS_PEC_SIZE 1

#define MCTP_SMBUS_CMD_CODE 0x0F

typedef struct __attribute__((packed)) {
    uint8_t cmd_code;
    uint8_t byte_cnt;
    uint8_t src_addr;
} smbus_hdr;

static uint8_t cal_pec(uint8_t dest_addr, uint8_t *buf, uint32_t len, uint8_t *pec)
{
    if (!buf || !len || !pec)
        return MCTP_ERROR;

    uint8_t pec_buf[len];
    pec_buf[0] = dest_addr;
    memcpy(pec_buf + 1, buf, len - 1);

    LOG_HEXDUMP_DBG(pec_buf, sizeof(pec_buf), "cal_pec");

    *pec = crc8(pec_buf, sizeof(pec_buf), 0x07, 0x00, false);
    return MCTP_SUCCESS;
}

static bool is_pec_vaild(uint8_t dest_addr, uint8_t *buf, uint32_t len)
{
    if (!buf || !len)
        return false;
    
    uint8_t pec = 0;
    if (cal_pec(dest_addr, buf, len, &pec) == MCTP_ERROR)
        return false;

    uint8_t exp_pec = buf[len -1];

    if (pec != exp_pec) {
        LOG_WRN("pec error dest_addr %x, cal = %x, exp = %x", dest_addr, pec, exp_pec);
        LOG_HEXDUMP_WRN(buf, sizeof(len), "is_pec_vaild");
    }

    return (pec == exp_pec) ? true : false;
}

static uint8_t make_send_buf(mctp *mctp_inst, uint8_t *send_buf, uint32_t send_len, 
    uint8_t *mctp_data, uint32_t mctp_data_len, mctp_ext_param extra_data)
{
    if (!mctp_inst || !send_buf || !send_len || !mctp_data || !mctp_data_len)
        return MCTP_ERROR;

    smbus_hdr *hdr = (smbus_hdr *)send_buf;
    hdr->cmd_code = MCTP_SMBUS_CMD_CODE;
    hdr->src_addr = mctp_inst->medium_conf.smbus_conf.addr + 1; /* bit 0 always set */
    hdr->byte_cnt = 1 + mctp_data_len; /* extend 1 byte src addr */
    memcpy(send_buf + sizeof(*hdr), mctp_data, mctp_data_len);

    uint8_t pec = 0;
    if (cal_pec(extra_data.smbus_ext_param.addr, send_buf, send_len, &pec) == MCTP_ERROR)
        return MCTP_ERROR;

    send_buf[send_len - 1] = pec;
    return MCTP_SUCCESS;
}

static uint16_t mctp_smbus_read(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_param *extra_data)
{
    if (!mctp_p || !buf || !len || !extra_data)
        return 0;

    mctp *mctp_inst = (mctp *)mctp_p;

    uint8_t rdata[256] = {0};
    uint8_t rlen = 0;

    /* TODO: read data from smbus */

    smbus_hdr *hdr = (smbus_hdr *)rdata;

    /* does read data include pec?
     * rlen = 1(mctp cmd code 0x0F) + 1(byte count) + N(byte count) + 1(*pec, if exist)
     * so if rlen is equal N + 3, the pec is existion
     */
    const uint8_t is_pec_exist = ((hdr->byte_cnt + 3) == rlen) ? 1 : 0;

    if (is_pec_exist) {
        if (is_pec_vaild(mctp_inst->medium_conf.smbus_conf.addr, rdata, rlen) == false)
            return 0;
    }

    if (hdr->cmd_code != MCTP_SMBUS_CMD_CODE)
        return 0;
    
    extra_data->type = MCTP_MEDIUM_TYPE_SMBUS;
    extra_data->smbus_ext_param.addr = hdr->src_addr - 1;

    uint8_t rt_size = rlen - sizeof(smbus_hdr) - is_pec_exist;
    memcpy(buf, rdata + sizeof(smbus_hdr), rt_size);
    // return rt_size;
    return 0;
}

static uint16_t mctp_smbus_write(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_param extra_data)
{
    if (!mctp_p || !buf || !len)
        return 0;

    mctp *mctp_inst = (mctp *)mctp_p;

    if (extra_data.type != MCTP_MEDIUM_TYPE_SMBUS)
        return 0;
    
    LOG_HEXDUMP_DBG(buf, len, "mctp_smbus_write receive data");

    /* send len = 1(mctp cmd code 0x0F) + 1(byte count) + 1(src addr) + len(mctp data) + 1(*pec, if exist) */
    uint32_t send_len = len + 4;
    uint8_t send_buf[send_len];
    uint8_t rc = make_send_buf(mctp_inst, send_buf, send_len, buf, len, extra_data);
    if (rc == MCTP_ERROR) {
        LOG_WRN("make send buf failed!!");
        return 0;
    }

    LOG_DBG("smbus_ext_param addr = %x", extra_data.smbus_ext_param.addr);
    LOG_HEXDUMP_DBG(send_buf, send_len, "mctp_smbus_write make header");
    
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
