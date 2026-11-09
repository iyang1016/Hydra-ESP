/**
 * @file attack_method.h
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-07
 * @copyright Copyright (c) 2021
 *
 * @brief Provides interface for common methods used in various attacks
 */
#ifndef ATTACK_METHOD_H
#define ATTACK_METHOD_H

#include "esp_wifi_types.h"
#include "attack.h"

/**
 * @brief Starts periodic deauthentication frame broadcast
 *
 * @param ap_record target AP record which BSSID will be used in deauthentication frame
 * @param period_sec period of broadcast in seconds
 */
void attack_method_broadcast(const wifi_ap_record_t *ap_record, unsigned period_sec);

/**
 * @brief Stop periodic deauthentication frame broadcast
 */
void attack_method_broadcast_stop();

/**
 * @brief Starts duplicated AP with same BSSID as genuine AP from ap_record
 *
 * This will execute deauthentication attack for given AP.
 * @param ap_record target AP that will be cloned/duplicated
 */
void attack_method_rogueap(const wifi_ap_record_t *ap_record);


void attack_method_evil_twin(const wifi_ap_record_t *ap_record);


void attack_method_super_clone(const wifi_ap_record_t *ap_record);
void attack_method_super_clone_stop(void);

bool is_super_clone_running(void);


/**
 * @brief Stops the deauth jammer attack.
 */
void attack_method_deauth_all_stop();


/* ── Targeted (single-client) deauth ─────────────────────────────────────────
 * Instead of broadcasting, knock one specific client off the target AP. The
 * client MAC is selected separately (e.g. from a client scan) and stored via
 * attack_method_set_target_client() before the attack starts.
 */

/** @brief Set the client MAC that targeted deauth will hit. */
void attack_method_set_target_client(const uint8_t mac[6]);

/** @brief Read the stored target client MAC. @return true if one is set. */
bool attack_method_get_target_client(uint8_t out_mac[6]);

/** @brief Clear the stored target client MAC. */
void attack_method_clear_target_client(void);

/**
 * @brief Start periodic targeted deauth+disassoc against the stored client MAC.
 *
 * No-op (logs an error) if no target client has been set. Uses the AP's BSSID
 * and channel from @p ap_record.
 */
void attack_method_targeted(const wifi_ap_record_t *ap_record);

/** @brief Stop the targeted deauth attack. */
void attack_method_targeted_stop(void);

#endif
