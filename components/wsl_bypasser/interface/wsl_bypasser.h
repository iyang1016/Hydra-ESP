/**
 * @file wsl_bypasser.h
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Provides interface for Wi-Fi Stack Libraries bypasser
 * 
 * This component bypasses blocking mechanism that doesn't allow sending some arbitrary 802.11 frames like deauth etc.
 */
#ifndef WSL_BYPASSER_H
#define WSL_BYPASSER_H

#include "esp_wifi_types.h"

/**
 * @brief Sends frame in frame_buffer using esp_wifi_80211_tx but bypasses blocking mechanism
 * 
 * @param frame_buffer 
 * @param size size of frame buffer
 */
void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size);

/**
 * @brief Sends deauthentication frame with forged source AP from given ap_record
 *  
 * This will send deauthentication frame acting as frame from given AP, and destination will be broadcast
 * MAC address - \c ff:ff:ff:ff:ff:ff
 * 
 * @param ap_record AP record with valid AP information 
 */
void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record);


void wsl_bypasser_send_beacon_frame(uint8_t *bssid, uint8_t *ssid, uint8_t ssid_length, uint8_t channel);


void wsl_bypasser_send_deauth_targeted(const uint8_t *ap_bssid, const uint8_t *client_mac);


void wsl_bypasser_send_disassociation_frame(const uint8_t *ap_bssid, const uint8_t *client_mac);

/**
 * @brief Sends a probe response frame answering a client's probe request.
 *
 * This is the KARMA primitive: the client asks "is <ssid> here?" and we answer
 * "yes, right here" using our own BSSID. Whatever SSID the client has in its PNL
 * gets a live-looking AP, which makes the device auto-connect attempts land on us.
 *
 * @param dst         client MAC (addr1)
 * @param bssid       our fake BSSID (addr2 + addr3)
 * @param ssid        SSID bytes to echo back
 * @param ssid_length SSID length (<= 32)
 * @param channel     channel the response advertises
 */
void wsl_bypasser_send_probe_response(const uint8_t *dst, const uint8_t *bssid,
                                      const uint8_t *ssid, uint8_t ssid_length,
                                      uint8_t channel);

/**
 * @brief Sends a beacon carrying a Channel Switch Announcement (CSA) IE.
 *
 * Clients that trust the CSA IE re-tune to @p new_channel on their own. Point
 * them at a channel we own and every STA walks off the real AP without a single
 * deauth frame — no reason code, no counter, nothing to log server-side.
 *
 * @param bssid        BSSID to impersonate (the real AP's)
 * @param ssid         SSID bytes
 * @param ssid_length  SSID length
 * @param channel      channel the beacon is transmitted on (current channel)
 * @param new_channel  channel the clients are told to move to
 */
void wsl_bypasser_send_csa_beacon(const uint8_t *bssid, const uint8_t *ssid,
                                  uint8_t ssid_length, uint8_t channel,
                                  uint8_t new_channel);
#endif
