/**
 * @file attack_csa.h
 * @author y4n0
 * @date 2026
 * @copyright Copyright (c) 2026
 *
 * @brief Channel Switch Announcement attack.
 *
 * Instead of deauthing clients off an AP (which the client logs, counts, and
 * often immediately retries) we impersonate the AP and tell them the network is
 * moving to another channel. Clients that honor the CSA IE leave on their own
 * and then sit on an empty channel hunting for a network that isn't there.
 *
 * No reason code. No disassociation. Nothing to attribute to a deauth flood.
 */
#ifndef ATTACK_CSA_H
#define ATTACK_CSA_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_wifi_types.h"
#include "attack.h"

typedef enum {
    CSA_MODE_PUSH   = 0,   ///< announce one decoy channel and stay there
    CSA_MODE_ROTATE = 1    ///< keep moving the decoy channel, clients never settle
} csa_mode_t;

/**
 * @brief Starts the CSA attack against every AP in @p attack_config.
 *
 * @param attack_config must hold at least one target AP. method is the csa_mode_t.
 */
void attack_csa_start(attack_config_t *attack_config);

/** @brief Stops the CSA attack. */
void attack_csa_stop(void);

/** @brief True while CSA frames are being emitted. */
bool attack_csa_is_running(void);

#endif
