/**
 * @file webserver.c
 * Serves HTML/CSS/JS/Icons/Fonts directly from SPIFFS filesystem.
 */

#include "webserver.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_spiffs.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "attack_deauth_detector.h"
#include "bt_payload_attack.h"
#include "wifi_controller.h"
#include "attack.h"
#include "attack_method.h"
#include "attack_client_scan.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"
#include "attack_eviltwin.h"

static const char *TAG = "webserver";
ESP_EVENT_DEFINE_BASE(WEBSERVER_EVENTS);

static httpd_handle_t server = NULL;
static bool spiffs_mounted   = false;

static void url_decode(char *dst, const char *src);



static void init_spiffs(void) {
    if (spiffs_mounted) return;
    esp_vfs_spiffs_conf_t conf = {
        .base_path              = "/spiffs",
        .partition_label        = "storage",
        .max_files              = 10,
        .format_if_mount_failed = false
    };
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SPIFFS mount failed: %s", esp_err_to_name(ret));
        return;
    }
    spiffs_mounted = true;
    size_t total = 0, used = 0;
    esp_spiffs_info("storage", &total, &used);
    ESP_LOGI(TAG, "SPIFFS: %d/%d bytes used", used, total);
}


/* ───────────────────────────── File serving ─────────────────────────────── */

static esp_err_t serve_file(httpd_req_t *req, const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) == -1) {
        ESP_LOGE(TAG, "File not found: %s", filepath);
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
        return ESP_FAIL;
    }

    FILE *f = fopen(filepath, "r");
    if (f == NULL) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to open file");
        return ESP_FAIL;
    }

    if      (strstr(filepath, ".html")) httpd_resp_set_type(req, "text/html");
    else if (strstr(filepath, ".css"))  httpd_resp_set_type(req, "text/css");
    else if (strstr(filepath, ".js"))   httpd_resp_set_type(req, "application/javascript");
    else if (strstr(filepath, ".png"))  httpd_resp_set_type(req, "image/png");
    else if (strstr(filepath, ".jpg") || strstr(filepath, ".jpeg"))
        httpd_resp_set_type(req, "image/jpeg");
    else if (strstr(filepath, ".ttf") || strstr(filepath, ".woff") || strstr(filepath, ".woff2"))
        httpd_resp_set_type(req, "font/ttf");
    else if (strstr(filepath, ".pcap")) httpd_resp_set_type(req, "application/octet-stream");
    else if (strstr(filepath, ".txt"))  httpd_resp_set_type(req, "text/plain");
    else                                httpd_resp_set_type(req, "text/plain");

    char buf[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (httpd_resp_send_chunk(req, buf, bytes_read) != ESP_OK) {
            fclose(f);
            return ESP_FAIL;
        }
    }

    fclose(f);
    return httpd_resp_send_chunk(req, NULL, 0);
}


static esp_err_t common_get_handler(httpd_req_t *req) {
    char filepath[256];
    const char *prefix = "/spiffs";

    if (strlen(req->uri) >= (sizeof(filepath) - strlen(prefix) - 1)) {
        ESP_LOGE(TAG, "URI too long: %s", req->uri);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "URI too long");
        return ESP_FAIL;
    }

    strcpy(filepath, prefix);
    strcat(filepath, req->uri);
    return serve_file(req, filepath);
}


/* ───────────────────────────── GET handlers ─────────────────────────────── */

static esp_err_t uri_root_get_handler(httpd_req_t *req) {
    return serve_file(req, "/spiffs/index.html");
}

static esp_err_t uri_ap_list_get_handler(httpd_req_t *req) {
    wifictl_scan_nearby_aps();
    const wifictl_ap_records_t *ap_records = wifictl_get_ap_records();

    char resp_chunk[40];
    httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    for (unsigned i = 0; i < ap_records->count; i++) {
        memcpy(resp_chunk,      ap_records->records[i].ssid,  33);
        memcpy(&resp_chunk[33], ap_records->records[i].bssid,  6);
        memcpy(&resp_chunk[39], &ap_records->records[i].rssi,  1);
        httpd_resp_send_chunk(req, resp_chunk, 40);
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t uri_status_get_handler(httpd_req_t *req) {
    const attack_status_t *attack_status = attack_get_status();
    httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    httpd_resp_send_chunk(req, (char *)attack_status, 4);
    if ((attack_status->state == FINISHED || attack_status->state == TIMEOUT)
        && attack_status->content_size > 0) {
        httpd_resp_send_chunk(req, attack_status->content, attack_status->content_size);
        }
        return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t uri_capture_pcap_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    return httpd_resp_send(req, (char *)pcap_serializer_get_buffer(), pcap_serializer_get_size());
}

static esp_err_t uri_capture_hccapx_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=y4n0_capture.hccapx");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store, no-cache, must-revalidate");
    return httpd_resp_send(req, (char *)hccapx_serializer_get(), sizeof(hccapx_t));
}

static esp_err_t uri_bt_status_handler(httpd_req_t *req) {
    char json[256];
    snprintf(json, sizeof(json),
             "{\"connected\":%s,\"busy\":%s,\"name\":\"%s\",\"mac\":\"%s\"}",
             bt_payload_is_connected() ? "true" : "false",
             bt_payload_is_busy()      ? "true" : "false",
             bt_payload_get_connected_name(),
             bt_payload_get_connected_mac());
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, strlen(json));
}

static esp_err_t uri_download_pass_get_handler(httpd_req_t *req) {
    return serve_file(req, "/spiffs/passwords.txt");
}

static esp_err_t uri_get_log_url_handler(httpd_req_t *req) {
    char url[256] = "http://192.168.4.1/log";
    nvs_handle_t nvs;
    if (nvs_open("storage", NVS_READONLY, &nvs) == ESP_OK) {
        size_t len = sizeof(url);
        nvs_get_str(nvs, "log_url", url, &len);
        nvs_close(nvs);
    }
    httpd_resp_set_type(req, "application/json");
    char response[300];
    snprintf(response, sizeof(response), "{\"url\":\"%s\"}", url);
    return httpd_resp_send(req, response, strlen(response));
}

static esp_err_t uri_detector_status_handler(httpd_req_t *req) {
    const deauth_detector_status_t *s = deauth_detector_get_status();
    httpd_resp_set_type(req, "application/json");

    char json[1024];
    int n = snprintf(json, sizeof(json), "{\"running\":%s,\"alerts\":[",
                     s->running ? "true" : "false");
    if (n < 0 || n >= (int)sizeof(json)) n = 0;

    bool first = true;
    for (int i = 0; i < s->count && n < (int)sizeof(json) - 80; i++) {
        if (!s->entries[i].alerting) continue;

        n += snprintf(json + n, sizeof(json) - n,
                      "%s{\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"count\":%d}",
                      first ? "" : ",",
                      s->entries[i].bssid[0], s->entries[i].bssid[1],
                      s->entries[i].bssid[2], s->entries[i].bssid[3],
                      s->entries[i].bssid[4], s->entries[i].bssid[5],
                      s->entries[i].count);
        first = false;
    }

    if (n < (int)sizeof(json) - 2) {
        json[n++] = ']';
        json[n++] = '}';
        json[n]   = '\0';
    }

    return httpd_resp_send(req, json, n);
}

static esp_err_t uri_evil_twin_status_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    const char *password    = get_evil_twin_password();
    int wrong_attempts      = get_wrong_attempts_count();
    char json[1024];

    if (password != NULL) {
        snprintf(json, sizeof(json),
                 "{\"status\":\"SUCCESS\",\"password\":\"%s\",\"wrong_attempts\":%d}",
                 password, wrong_attempts);
    } else if (is_evil_twin_active()) {
        char wrong_pwds[512];
        get_wrong_passwords(wrong_pwds, sizeof(wrong_pwds));
        snprintf(json, sizeof(json),
                 "{\"status\":\"RUNNING\",\"wrong_attempts\":%d,\"wrong_passwords\":\"%s\"}",
                 wrong_attempts, wrong_pwds);
    } else {
        snprintf(json, sizeof(json),
                 "{\"status\":\"STOPPED\",\"wrong_attempts\":%d}", wrong_attempts);
    }
    return httpd_resp_send(req, json, strlen(json));
}


/* ─────────────────────── Client scan / targeting ────────────────────────── */

/* AP record snapshot for the background scan task (records[] may change). */
static wifi_ap_record_t s_scan_ap;

static void client_scan_task(void *arg) {
    /* Blocking timed scan: drops the mgmt AP, sniffs, then restores the web UI. */
    client_scan_run(&s_scan_ap, 8000);
    vTaskDelete(NULL);
}

/* POST /client-scan  body: AP index (ascii). Fires an ~8s background scan; the
 * web UI drops out during the scan and should reconnect, then GET /client-list. */
static esp_err_t uri_client_scan_handler(httpd_req_t *req) {
    char buf[16];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) return ESP_FAIL;
    buf[ret] = '\0';

    if (client_scan_is_running()) {
        return httpd_resp_sendstr(req, "BUSY");
    }

    unsigned idx = (unsigned)atoi(buf);
    const wifi_ap_record_t *ap = wifictl_get_ap_record(idx);
    if (ap == NULL) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid AP index");
    }
    memcpy(&s_scan_ap, ap, sizeof(wifi_ap_record_t));

    /* Respond before the scan starts — it will tear down this very server. */
    httpd_resp_sendstr(req, "SCANNING");
    xTaskCreate(client_scan_task, "client_scan", 4096, NULL, 5, NULL);
    return ESP_OK;
}

/* GET /client-list  -> JSON list of clients found in the last scan. */
static esp_err_t uri_client_list_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");

    uint8_t count = 0;
    const client_record_t *list = client_scan_get_list(&count);

    char json[1024];
    int n = snprintf(json, sizeof(json), "{\"scanning\":%s,\"clients\":[",
                     client_scan_is_running() ? "true" : "false");

    for (uint8_t i = 0; i < count && n < (int)sizeof(json) - 80; i++) {
        n += snprintf(json + n, sizeof(json) - n,
                      "%s{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"rssi\":%d,\"frames\":%u}",
                      i ? "," : "",
                      list[i].mac[0], list[i].mac[1], list[i].mac[2],
                      list[i].mac[3], list[i].mac[4], list[i].mac[5],
                      list[i].rssi, list[i].frames);
    }
    n += snprintf(json + n, sizeof(json) - n, "]}");
    return httpd_resp_send(req, json, n);
}

/* POST /set-target-client  body: "AA:BB:CC:DD:EE:FF" -> stores targeted-deauth MAC. */
static esp_err_t uri_set_target_client_handler(httpd_req_t *req) {
    char buf[32];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) return ESP_FAIL;
    buf[ret] = '\0';

    unsigned m[6];
    if (sscanf(buf, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad MAC");
    }
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    attack_method_set_target_client(mac);
    return httpd_resp_sendstr(req, "OK");
}


/* ─────────────────────────── HEAD handlers ──────────────────────────────── */

static esp_err_t uri_reset_head_handler(httpd_req_t *req) {
    ESP_ERROR_CHECK(esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET,
                                   NULL, 0, portMAX_DELAY));
    return httpd_resp_send(req, NULL, 0);
}


/* ───────────────────────────── POST handlers ────────────────────────────── */

static esp_err_t uri_run_attack_post_handler(httpd_req_t *req) {
    attack_request_t attack_request;
    int received = httpd_req_recv(req, (char *)&attack_request, sizeof(attack_request_t));
    if (received != sizeof(attack_request_t)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad payload");
        return ESP_FAIL;
    }
    esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST,
                   &attack_request, sizeof(attack_request_t), portMAX_DELAY);
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t uri_bt_payload_set_handler(httpd_req_t *req) {
    char buf[16];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) return ESP_FAIL;
    buf[ret] = '\0';

    int payload = atoi(buf);
    if (payload < 1 || payload > 5) payload = 1;
    bt_payload_attack_set_payload(payload);
    return httpd_resp_sendstr(req, "OK");
}

static esp_err_t uri_bt_payload_run_handler(httpd_req_t *req) {
    bt_payload_attack_run_now();
    return httpd_resp_sendstr(req, "OK");
}

static esp_err_t uri_log_post_handler(httpd_req_t *req) {
    /* Was: stack buffer[2048] read with req->content_len. Any body bigger than
     * the buffer wrote straight past it. Stream to the file in fixed chunks so
     * the size of the POST no longer matters. */
    FILE *f = fopen("/spiffs/passwords.txt", "w");
    if (f == NULL) {
        ESP_LOGE(TAG, "Cannot open passwords.txt for writing");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "fs error");
    }

    char buf[512];
    int remaining = req->content_len;
    bool ok = true;

    while (remaining > 0) {
        int want = (remaining < (int)sizeof(buf)) ? remaining : (int)sizeof(buf);
        int ret  = httpd_req_recv(req, buf, want);
        if (ret <= 0) { ok = false; break; }
        if (fwrite(buf, 1, (size_t)ret, f) != (size_t)ret) { ok = false; break; }
        remaining -= ret;
    }

    fclose(f);

    if (!ok) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "recv failed");
    }
    return httpd_resp_sendstr(req, "Logged");
}

static esp_err_t uri_set_log_url_handler(httpd_req_t *req) {
    char buf[256];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) return ESP_FAIL;
    buf[ret] = '\0';

    nvs_handle_t nvs;
    if (nvs_open("storage", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_set_str(nvs, "log_url", buf);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
    return httpd_resp_sendstr(req, "OK");
}

static esp_err_t uri_detector_start_handler(httpd_req_t *req) {
    deauth_detector_start();
    return httpd_resp_send(req, "OK", 2);
}

static esp_err_t uri_detector_stop_handler(httpd_req_t *req) {
    deauth_detector_stop();
    return httpd_resp_send(req, "OK", 2);
}

static esp_err_t save_settings_post_handler(httpd_req_t *req) {
    char buf[128];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) return ESP_FAIL;
    buf[ret] = '\0';

    char raw_ssid[64] = {0}, raw_pass[96] = {0};
    char ssid[33] = {0}, pass[65] = {0};

    if (httpd_query_key_value(buf, "ssid", raw_ssid, sizeof(raw_ssid)) != ESP_OK ||
        httpd_query_key_value(buf, "pass", raw_pass, sizeof(raw_pass)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid data");
        }

        url_decode(ssid, raw_ssid);
    url_decode(pass, raw_pass);
    ssid[32] = '\0';
    pass[64] = '\0';

    ESP_LOGI(TAG, "Updating Management AP: SSID=%s", ssid);

    nvs_handle_t nvs_h;
    if (nvs_open("storage", NVS_READWRITE, &nvs_h) == ESP_OK) {
        nvs_set_str(nvs_h, "ap_ssid", ssid);
        nvs_set_str(nvs_h, "ap_pass", pass);
        nvs_commit(nvs_h);
        nvs_close(nvs_h);
    }
    httpd_resp_sendstr(req, "Settings Saved! Rebooting...");
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}


/* ─────────────────────────── URI table ──────────────────────────────────── */

static httpd_uri_t uri_root          = { .uri = "/",                 .method = HTTP_GET,  .handler = uri_root_get_handler };
static httpd_uri_t uri_ap_list       = { .uri = "/ap-list",          .method = HTTP_GET,  .handler = uri_ap_list_get_handler };
static httpd_uri_t uri_status        = { .uri = "/status",           .method = HTTP_GET,  .handler = uri_status_get_handler };
static httpd_uri_t uri_capture_pcap  = { .uri = "/capture.pcap",     .method = HTTP_GET,  .handler = uri_capture_pcap_get_handler };
static httpd_uri_t uri_hccapx        = { .uri = "/capture.hccapx",   .method = HTTP_GET,  .handler = uri_capture_hccapx_get_handler };
static httpd_uri_t uri_bt_status_get = { .uri = "/bt-status",        .method = HTTP_GET,  .handler = uri_bt_status_handler };
static httpd_uri_t uri_download_pass = { .uri = "/download-pass",    .method = HTTP_GET,  .handler = uri_download_pass_get_handler };
static httpd_uri_t uri_get_log_url   = { .uri = "/get-log-url",      .method = HTTP_GET,  .handler = uri_get_log_url_handler };
static httpd_uri_t uri_det_status    = { .uri = "/detector/status",  .method = HTTP_GET,  .handler = uri_detector_status_handler };
static httpd_uri_t uri_evil_status   = { .uri = "/evil-twin-status", .method = HTTP_GET,  .handler = uri_evil_twin_status_handler };
static httpd_uri_t uri_client_list   = { .uri = "/client-list",      .method = HTTP_GET,  .handler = uri_client_list_handler };


static httpd_uri_t uri_icons  = { .uri = "/icons/*",      .method = HTTP_GET, .handler = common_get_handler };
static httpd_uri_t uri_fonts  = { .uri = "/fonts/*",      .method = HTTP_GET, .handler = common_get_handler };
static httpd_uri_t uri_dtwin  = { .uri = "/devil_twin/*", .method = HTTP_GET, .handler = common_get_handler };
static httpd_uri_t uri_style  = { .uri = "/style.css",    .method = HTTP_GET, .handler = common_get_handler };
static httpd_uri_t uri_js     = { .uri = "/app.js",       .method = HTTP_GET, .handler = common_get_handler };


static httpd_uri_t uri_reset  = { .uri = "/reset",        .method = HTTP_HEAD, .handler = uri_reset_head_handler };

/* POST */
static httpd_uri_t uri_run_attack    = { .uri = "/run-attack",       .method = HTTP_POST, .handler = uri_run_attack_post_handler };
static httpd_uri_t uri_bt_payload_s  = { .uri = "/bt-payload-set",   .method = HTTP_POST, .handler = uri_bt_payload_set_handler };
static httpd_uri_t uri_bt_payload_r  = { .uri = "/bt-payload-run",   .method = HTTP_POST, .handler = uri_bt_payload_run_handler };
static httpd_uri_t uri_log_post      = { .uri = "/log",              .method = HTTP_POST, .handler = uri_log_post_handler };
static httpd_uri_t uri_set_log_url   = { .uri = "/set-log-url",      .method = HTTP_POST, .handler = uri_set_log_url_handler };
static httpd_uri_t uri_det_start     = { .uri = "/detector/start",   .method = HTTP_POST, .handler = uri_detector_start_handler };
static httpd_uri_t uri_det_stop      = { .uri = "/detector/stop",    .method = HTTP_POST, .handler = uri_detector_stop_handler };
static httpd_uri_t uri_save_settings = { .uri = "/save_settings",    .method = HTTP_POST, .handler = save_settings_post_handler };
static httpd_uri_t uri_client_scan   = { .uri = "/client-scan",      .method = HTTP_POST, .handler = uri_client_scan_handler };
static httpd_uri_t uri_set_target    = { .uri = "/set-target-client", .method = HTTP_POST, .handler = uri_set_target_client_handler };


/* ─────────────────────────── Public API ─────────────────────────────────── */

void webserver_stop(void) {
    if (server == NULL) {
        ESP_LOGW(TAG, "Webserver not running.");
        return;
    }
    if (httpd_stop(server) == ESP_OK) {
        server = NULL;
        ESP_LOGI(TAG, "Webserver stopped.");
    } else {
        ESP_LOGE(TAG, "Failed to stop webserver!");
    }
}

void webserver_run(void) {
    if (server != NULL) return;
    init_spiffs();

    httpd_config_t config     = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers   = 30;
    config.uri_match_fn       = httpd_uri_match_wildcard;

    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start webserver!");
        return;
    }


    httpd_register_uri_handler(server, &uri_root);
    httpd_register_uri_handler(server, &uri_ap_list);
    httpd_register_uri_handler(server, &uri_status);
    httpd_register_uri_handler(server, &uri_capture_pcap);
    httpd_register_uri_handler(server, &uri_hccapx);
    httpd_register_uri_handler(server, &uri_bt_status_get);
    httpd_register_uri_handler(server, &uri_download_pass);
    httpd_register_uri_handler(server, &uri_get_log_url);
    httpd_register_uri_handler(server, &uri_det_status);
    httpd_register_uri_handler(server, &uri_evil_status);
    httpd_register_uri_handler(server, &uri_client_list);


    httpd_register_uri_handler(server, &uri_icons);
    httpd_register_uri_handler(server, &uri_fonts);
    httpd_register_uri_handler(server, &uri_dtwin);
    httpd_register_uri_handler(server, &uri_style);
    httpd_register_uri_handler(server, &uri_js);


    httpd_register_uri_handler(server, &uri_reset);


    httpd_register_uri_handler(server, &uri_run_attack);
    httpd_register_uri_handler(server, &uri_bt_payload_s);
    httpd_register_uri_handler(server, &uri_bt_payload_r);
    httpd_register_uri_handler(server, &uri_log_post);
    httpd_register_uri_handler(server, &uri_set_log_url);
    httpd_register_uri_handler(server, &uri_det_start);
    httpd_register_uri_handler(server, &uri_det_stop);
    httpd_register_uri_handler(server, &uri_save_settings);
    httpd_register_uri_handler(server, &uri_client_scan);
    httpd_register_uri_handler(server, &uri_set_target);

    ESP_LOGI(TAG, "Webserver started — handlers registered.");
}


/* ─────────────────────────── URL decode ─────────────────────────────────── */

static void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            isxdigit((unsigned char)a) &&
            isxdigit((unsigned char)b)) {

            if (a >= 'a') a -= 32;
            a = (a >= 'A') ? a - 'A' + 10 : a - '0';

            if (b >= 'a') b -= 32;
            b = (b >= 'A') ? b - 'A' + 10 : b - '0';

            *dst++ = 16 * a + b;
            src += 3;
            } else if (*src == '+') {
                *dst++ = ' ';
                src++;
            } else {
                *dst++ = *src++;
            }
    }
    *dst = '\0';
}
