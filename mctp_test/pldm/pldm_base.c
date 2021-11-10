#include <zephyr.h>
#include <string.h>
#include <sys/printk.h>
#include <cmsis_os2.h>
#include "pldm.h"

struct _set_tid_req {
    uint8_t tid;
} __attribute__((packed));

struct _set_tid_resp {
    uint8_t completion_code;
} __attribute__((packed));

struct _get_tid_resp {
    uint8_t completion_code;
    uint8_t tid;
} __attribute__((packed));

uint8_t set_tid_resp(uint8_t *buf, uint16_t len, uint8_t *resp, uint16_t *resp_len)
{
    if (!buf || !resp || !resp_len)
        return PLDM_ERROR;
    
    struct _set_tid_req *req_p = (struct _set_tid_req *)buf;
    struct _set_tid_resp *resp_p = (struct _set_tid_resp *)resp;

    *resp_len = 1;
    resp_p->completion_code = (sizeof(*req_p) != len) ? PLDM_BASE_CODES_ERROR_INVALID_LENGTH : PLDM_BASE_CODES_SUCCESS;
    return PLDM_SUCCESS;
}

uint8_t get_tid_resp(uint8_t *buf, uint16_t len, uint8_t *resp, uint16_t *resp_len)
{
    pldm_printf("\n");
    if (!buf || !resp || !resp_len)
        return PLDM_ERROR;

    pldm_printf("\n");
    struct _get_tid_resp *p = (struct _get_tid_resp *)resp;
    p->completion_code = PLDM_BASE_CODES_SUCCESS;
    p->tid = 0x78;
    *resp_len = sizeof(*p);
    return PLDM_SUCCESS;
}

/* the last entry shoule be {PLDM_CMD_TBL_TERMINATE_CMD_CODE, NULL} in the cmd table */
static pldm_cmd_handler pldm_base_cmd_tbl[] = {
    {PLDM_BASE_CMD_CODE_SETTID, set_tid_resp},
    {PLDM_BASE_CMD_CODE_GETTID, get_tid_resp}
};

uint8_t pldm_base_handler_found(uint8_t code, void **ret_fn)
{
    pldm_cmd_proc_fn fn = NULL;
    uint8_t i;

    for (i = 0; i < sizeof(pldm_base_cmd_tbl) / sizeof(*pldm_base_cmd_tbl); i++) {
        if (pldm_base_cmd_tbl[i].cmd_code == code) {
            fn = pldm_base_cmd_tbl[i].fn;
            break;
        }
    }

    *ret_fn = (void *)fn;
    return fn ? PLDM_SUCCESS : PLDM_ERROR;
}