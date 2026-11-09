/**
 * @file attack_hunt.h
 * @author y4n0
 * @date 2026
 * @copyright Copyright (c) 2026
 *
 * @brief Unattended capture sweep — PMKID first, handshake as fallback.
 *
 * Walks the selected AP list one at a time and for each target:
 *
 *   phase 1  associate with a junk PSK, which makes the AP answer with EAPOL
 *            message 1 carrying the PMKID. No client has to be present.
 *   phase 2  if the AP doesn't leak a PMKID (many vendors fixed that), fall back
 *            to an active handshake capture: broadcast deauth until a client
 *            re-associates and a 4-way handshake lands in the capture.
 *
 * Everything captured is written into the same PCAP, so one download gives you
 * the whole sweep. Pull the cracks out of it offline with hcxpcapngtool — it
 * finds every PMKID and every complete handshake in a single pass.
 */
#ifndef ATTACK_HUNT_H
#define ATTACK_HUNT_H

#include <stdint.h>
#include <stdbool.h>
#include "attack.h"

/** Per-AP time budget, milliseconds. Tuned for "walk away and come back later". */
#define HUNT_PMKID_GRACE_MS  4000
#define HUNT_HS_WAIT_MS      12000
#define HUNT_MAX_TARGETS     8

/**
 * @brief Starts the sweep over every AP in @p attack_config.
 *
 * timeout in the config caps the whole sweep; 0 means run until every target has
 * been attempted.
 */
void attack_hunt_start(attack_config_t *attack_config);

/** @brief Stops the sweep early and releases the radio. */
void attack_hunt_stop(void);

/** @brief True while the sweep is running. */
bool attack_hunt_is_running(void);

#endif
