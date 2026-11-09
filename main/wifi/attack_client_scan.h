/**
 * @file attack_client_scan.h
 * @brief Discovers client stations (STAs) associated with a target AP.
 *
 * The ESP32 radio cannot serve the management AP and run promiscuous capture at
 * the same time, so discovery is a timed sniff: the caller drops the management
 * AP, this module captures on the target channel for a few seconds collecting the
 * MAC addresses of clients talking to the target BSSID, then the management AP is
 * restored and the web UI polls the resulting list.
 */
#ifndef ATTACK_CLIENT_SCAN_H
#define ATTACK_CLIENT_SCAN_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_wifi_types.h"

#define CLIENT_SCAN_MAX 32

typedef struct {
    uint8_t  mac[6];
    int8_t   rssi;     ///< last observed RSSI
    uint16_t frames;   ///< how many frames seen (rough activity indicator)
} client_record_t;

/**
 * @brief Run a blocking timed client scan against the given AP.
 *
 * Stops the management AP, sniffs the AP's channel for @p duration_ms collecting
 * clients of @p ap->bssid, then restores the management web interface. Results are
 * retrievable via client_scan_get_list() after this returns.
 *
 * @param ap          target AP (provides bssid + primary channel)
 * @param duration_ms how long to sniff (e.g. 8000)
 */
void client_scan_run(const wifi_ap_record_t *ap, uint32_t duration_ms);

/**
 * @brief Returns the discovered client list from the last scan.
 * @param[out] count number of records
 * @return pointer to internal array (valid until next scan)
 */
const client_record_t *client_scan_get_list(uint8_t *count);

/** @brief True while a scan is in progress. */
bool client_scan_is_running(void);

#endif /* ATTACK_CLIENT_SCAN_H */
