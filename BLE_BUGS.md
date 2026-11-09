# BLE Attack Bugs (BLE Spam + BT Payload)

Scope: `main/bt/attack_bt_spam.c` and `main/bt/bt_payload_attack.cpp`.
These are the reasons the BLE modules misbehave / crash.

---

## Critical — cause hard crashes / aborts

### 1. Base MAC changed at runtime (BT Payload) — `bt_payload_attack.cpp:70`
`generate_random_name_and_mac()` calls `esp_base_mac_addr_set(s_current_mac)` **after**
the system (and on most builds Wi-Fi/BT) has already started. `esp_base_mac_addr_set`
is only valid **before** the stack/controller is initialized. Called live it returns an
error (ignored here) or, with the controller up, leads to an abort/`ESP_ERROR_CHECK`
fail on the next BLE op. This runs on **every** `bt_payload_attack_start()`, so the
payload attack crashes essentially every time.
**Fix:** drop `esp_base_mac_addr_set`; set the random *BLE* address via
`ble_hs_id_set_rnd()` (like the spam module does) and advertise with
`BLE_OWN_ADDR_RANDOM`.

### 2. Advertising started before NimBLE host sync (BT Payload) — `bt_payload_attack.cpp:309-314`
`s_keyboard->begin()` then immediately `ble_gap_adv_stop()` / `ble_gap_adv_start()`.
There is no wait for `ble_hs_synced()`. Before sync the host has no identity address
and GAP calls return `BLE_HS_ENOTSYNCED` / hit asserts → crash. (The spam module
*does* wait — `attack_bt_spam.c:376-384` — payload does not.)
**Fix:** poll `ble_hs_synced()` (with timeout) before any `ble_gap_*` call.

### 3. Manual adv conflicts with BleKeyboard's own advertising — `bt_payload_attack.cpp:309-314`
`BleKeyboard::begin()` already configures the HID service and starts advertising.
Stopping it and starting a second raw `ble_gap_adv_start` with different params
double-drives GAP and leaves the HID service in an inconsistent adv state — pairing
fails and the host can assert. Pick **one** owner of advertising (let BleKeyboard do it).

### 4. NimBLE never deinitialized → re-init / coexistence crash — `attack_bt_spam.c:366`, `bt_payload_attack.cpp:325-349`
- Spam `init` calls `nimble_port_init()` and starts `nimble_host` task, but nothing ever
  calls `nimble_port_stop()` / `nimble_port_deinit()`. Stopping then re-starting spam,
  **or** running BT Payload after BLE Spam (and vice-versa), calls `nimble_port_init()` /
  `begin()` on an already-initialized host → assert/crash. The two BLE modules cannot
  currently coexist or be restarted.
- `bt_payload_attack_stop()` sets `s_init_done = false` (line 346) but leaves the NimBLE
  host running, so the next `start()` re-runs NVS/begin on a live host.
**Fix:** add a single shared BLE init/deinit owner, fully tear down NimBLE on stop, and
gate both modules so only one is active.

---

## High — races / use-after-free

### 5. `vTaskDelete` of a task holding the BLE host mutex (Spam) — `attack_bt_spam.c:429-432`
On stop timeout the task is force-deleted. If it is killed mid `ble_gap_adv_set_data` /
`ble_gap_adv_start` it still holds the NimBLE mutex and its stack is freed → heap/mutex
corruption that crashes later (often looks "random"). The 3 s timeout is plausible
because the loop's `vTaskDelay(adv_ms + 20)` plus config `delay_ms` can exceed it.
**Fix:** signal-and-join only; never `vTaskDelete` a task that may hold the host mutex.

### 6. Keyboard task force-deleted then object freed (Payload) — `bt_payload_attack.cpp:331-343`
`bt_payload_attack_stop()` does `vTaskDelete(s_task)` then immediately
`delete s_keyboard`. If `keyboard_task` was mid `execute_current_payload()`
(using `s_keyboard->write(...)`), it is killed without unwinding and the object it was
using is freed → use-after-free. `s_is_busy` is never checked before deleting.
**Fix:** request stop, wait for the task to observe `s_running==false` and exit, *then*
delete the keyboard.

---

## Medium — correctness (won't always crash, but wrong on-air)

### 7. `gen_apple_audio` fills the buffer to exactly 31 bytes — `attack_bt_spam.c:99`
Returns 31 with `buf[0]=0x1E` (AD len 30). That is the legal max, so any future field
added overflows `adv_raw[31]` silently. Tight, fragile; consider a guard
(`assert(i <= sizeof(adv_raw))`).

### 8. `gen_fastpair` TX-power byte math is wrong — `attack_bt_spam.c:190`
`(uint8_t)((esp_random() % 120) - 100)` — the comment claims "-100..+19 dBm" but the
`% 120` then `-100` on unsigned wraps to large values; the TX power AD field gets
nonsense. Use a signed range, e.g. `(int8_t)(-100 + esp_random() % 120)` stored as `int8_t`.

### 9. Apple address never rotates — `attack_bt_spam.c:311`
Apple types always advertise with `BLE_OWN_ADDR_PUBLIC` (one fixed MAC). Real
proximity-spam rotates the address; iOS dedupes by MAC so popups stop after the first.
Set a fresh random address for Apple frames too.

---

## Suggested fix order
1 and 2 first (they crash on every payload start), then 4 and 5/6 (restart/coexistence
and the use-after-free races), then the correctness items 7–9.
