/**
 * @file attack_client_scan.c
 * @brief Timed promiscuous discovery of clients associated with a target AP.
 */
#include "attack_client_scan.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "wifi_controller.h"
#include "management_helper.h"
#include "webserver.h"

static const char *TAG = "client_scan";

static client_record_t s_clients[CLIENT_SCAN_MAX];
static volatile uint8_t s_count = 0;
static volatile bool s_running = false;
static uint8_t s_target_bssid[6];

/* 802.11 MAC header layout we care about */
typedef struct __attribute__((packed)) {
    uint8_t  fctl0;       /* protocol/type/subtype */
    uint8_t  fctl1;       /* flags incl. ToDS/FromDS */
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} dot11_hdr_t;

static bool mac_is_groupcast(const uint8_t *m) {
    /* broadcast / multicast (incl. 00:00:00:00:00:00) are not real clients */
    if (m[0] & 0x01) return true;
    uint8_t z = 0;
    for (int i = 0; i < 6; i++) z |= m[i];
    return z == 0;
}

static void record_client(const uint8_t *mac, int8_t rssi) {
    if (mac_is_groupcast(mac)) return;
    if (memcmp(mac, s_target_bssid, 6) == 0) return; /* the AP itself */

    for (uint8_t i = 0; i < s_count; i++) {
        if (memcmp(s_clients[i].mac, mac, 6) == 0) {
            s_clients[i].rssi = rssi;
            if (s_clients[i].frames < 0xFFFF) s_clients[i].frames++;
            return;
        }
    }
    if (s_count >= CLIENT_SCAN_MAX) return;
    memcpy(s_clients[s_count].mac, mac, 6);
    s_clients[s_count].rssi   = rssi;
    s_clients[s_count].frames = 1;
    ESP_LOGI(TAG, "client %02X:%02X:%02X:%02X:%02X:%02X (rssi %d)",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], rssi);
    s_count++;
}

static void sniff_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    if (pkt->rx_ctrl.sig_len < (int)sizeof(dot11_hdr_t)) return;

    const dot11_hdr_t *h = (const dot11_hdr_t *)pkt->payload;
    bool to_ds   = h->fctl1 & 0x01;
    bool from_ds = h->fctl1 & 0x02;
    int8_t rssi  = pkt->rx_ctrl.rssi;

    const uint8_t *bssid = NULL;
    const uint8_t *client = NULL;

    if (to_ds && !from_ds) {            /* client -> AP : addr1=BSSID, addr2=client */
        bssid  = h->addr1;
        client = h->addr2;
    } else if (!to_ds && from_ds) {     /* AP -> client : addr1=client, addr2=BSSID */
        bssid  = h->addr2;
        client = h->addr1;
    } else {
        return;                          /* ad-hoc / WDS: ignore */
    }

    if (memcmp(bssid, s_target_bssid, 6) != 0) return;
    record_client(client, rssi);
}

void client_scan_run(const wifi_ap_record_t *ap, uint32_t duration_ms) {
    if (ap == NULL || s_running) return;

    s_running = true;
    s_count   = 0;
    memcpy(s_target_bssid, ap->bssid, 6);

    ESP_LOGI(TAG, "Scanning clients of %02X:%02X:%02X:%02X:%02X:%02X on ch %d for %lu ms",
             ap->bssid[0], ap->bssid[1], ap->bssid[2], ap->bssid[3], ap->bssid[4],
             ap->bssid[5], ap->primary, (unsigned long)duration_ms);

    /* Free the radio: the mgmt AP and promiscuous capture cannot coexist. */
    webserver_stop();
    wifictl_mgmt_ap_stop();
    vTaskDelay(pdMS_TO_TICKS(150));

    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniff_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(ap->primary, WIFI_SECOND_CHAN_NONE);

    vTaskDelay(pdMS_TO_TICKS(duration_ms));

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);

    ESP_LOGI(TAG, "Scan done: %u client(s) found", s_count);

    /* Bring the management web interface back so the user can read results. */
    restore_management_system();

    s_running = false;
}

const client_record_t *client_scan_get_list(uint8_t *count) {
    if (count) *count = s_count;
    return s_clients;
}

bool client_scan_is_running(void) {
    return s_running;
}
