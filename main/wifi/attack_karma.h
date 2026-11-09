/**
 * @file attack_karma.h
 * @author y4n0
 * @date 2026
 * @copyright Copyright (c) 2026
 *
 * @brief KARMA attack — answer every probe request, become every SSID.
 *
 * A client with "auto-join" enabled periodically broadcasts probe requests for
 * the SSIDs in its preferred-network list, even when those networks are not in
 * range. Classic APs ignore probes for SSIDs they don't own. This module answers
 * all of them: whatever the client asks for, it gets a probe response saying
 * "right here" from our BSSID.
 *
 * The device then associates to us of its own free will. Nothing is deauth'd,
 * nothing is jammed — it walks over on its own.
 */
#ifndef ATTACK_KARMA_H
#define ATTACK_KARMA_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_wifi_types.h"
#include "attack.h"

#define KARMA_MAX_SSIDS 24

/**
 * @brief Starts the KARMA attack.
 *
 * Stops the management AP, tunes to @p ap_record's channel (or hops if NULL) and
 * begins answering probe requests with forged probe responses plus periodic
 * beacons so the SSIDs stay visible in client scans.
 *
 * @param ap_record reference AP used for channel selection; may be NULL (hops)
 */
void attack_karma_start(const wifi_ap_record_t *ap_record);

/** @brief Stops the KARMA attack and releases promiscuous mode. */
void attack_karma_stop(void);

/** @brief True while the KARMA sniffer is active. */
bool attack_karma_is_running(void);

/** @brief Number of distinct SSIDs harvested this run. */
uint8_t attack_karma_ssid_count(void);

/**
 * @brief Copies a harvested SSID by index.
 * @return SSID length, or 0 when @p idx is out of range.
 */
uint8_t attack_karma_get_ssid(uint8_t idx, char *out, uint8_t out_size);

#endif
