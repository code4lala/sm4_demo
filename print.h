#pragma once
#include <stdio.h>
#include <stdint.h>

#define LOGI(fmt, ...) printf("[I][%s][%d]" fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGD(fmt, ...) printf("[D][%s][%d]" fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[E][%s][%d]" fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

void PrintBuffer(const char *tag, const uint8_t *ptr, int32_t len);

#ifdef __cplusplus
}
#endif
