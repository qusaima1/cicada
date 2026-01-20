#include "cicada_mqtt.h"

#include <cstring>
#include <string>

extern "C" {
#include "esp_log.h"
#include "mqtt_client.h"
}

#include "mqtt_creds.h"
#include "cicada_cmd.h"

static const char* TAG = "cicada_mqtt";
static esp_mqtt_client_handle_t s_client = nullptr;
static char s_dev[64] = {0};

static void publish_ack(bool ok)
{
    if (!s_client) return;

    char ack_topic[128];
    std::snprintf(ack_topic, sizeof(ack_topic), "cicada/%s/ack/exec", s_dev);
    const char* msg = ok ? "{\"ok\":true}" : "{\"ok\":false}";
    esp_mqtt_client_publish(s_client, ack_topic, msg, 0, 1, 0);
}

static void on_cmd(const char* topic, int topic_len, const char* data, int data_len)
{
    (void)topic;
    (void)topic_len;

    // MQTT payload is not guaranteed to be null-terminated
    std::string payload(data, data + data_len);

    char cmd[64] = {0};
    char args[256] = {0};

    if (!cicada_cmd::verify_and_update_counter(s_dev,
                                               payload.c_str(),
                                               cmd, sizeof(cmd),
                                               args, sizeof(args))) {
        ESP_LOGW(TAG, "Rejected command");
        publish_ack(false);
        return;
    }

    ESP_LOGI(TAG, "Accepted command: %s args_json=%s", cmd, args);

    // TODO: execute command here (switch/case on cmd)

    publish_ack(true);
}

static void mqtt_event_handler(void* handler_args, esp_event_base_t base, int32_t event_id, void* event_data)
{
    (void)handler_args;
    (void)base;

    esp_mqtt_event_handle_t event = static_cast<esp_mqtt_event_handle_t>(event_data);

    switch (static_cast<esp_mqtt_event_id_t>(event_id)) {
    case MQTT_EVENT_CONNECTED: {
        ESP_LOGI(TAG, "MQTT connected");

        // Subscribe to command topic namespace for this device
        char sub_topic[128];
        std::snprintf(sub_topic, sizeof(sub_topic), "cicada/%s/cmd/#", s_dev);
        esp_mqtt_client_subscribe(s_client, sub_topic, 1);

        // Online status (retained)
        char st_topic[128];
        std::snprintf(st_topic, sizeof(st_topic), "cicada/%s/status", s_dev);
        esp_mqtt_client_publish(s_client, st_topic, "{\"online\":true}", 0, 1, 1);
        break;
    }
    case MQTT_EVENT_DATA:
        on_cmd(event->topic, event->topic_len, event->data, event->data_len);
        break;

    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT disconnected");
        break;

    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT error");
        break;

    default:
        break;
    }
}

void cicada_mqtt_start(const char* device_id)
{
    std::snprintf(s_dev, sizeof(s_dev), "%s", device_id);

    // IMPORTANT: avoid C++ designated initializers (order-sensitive). Use assignments.
    esp_mqtt_client_config_t cfg;
    std::memset(&cfg, 0, sizeof(cfg));

    cfg.broker.address.uri = "mqtts://192.168.1.151:8883";
    cfg.broker.verification.certificate = mqtt_creds::ca_pem();

    cfg.credentials.client_id = s_dev;
    cfg.credentials.authentication.certificate = mqtt_creds::client_crt_pem();
    cfg.credentials.authentication.key = mqtt_creds::client_key_pem();

    cfg.session.keepalive = 60;
    cfg.session.disable_clean_session = false;

    // Last will (retained offline marker)
    static char lwt_topic[128];
    std::snprintf(lwt_topic, sizeof(lwt_topic), "cicada/%s/status", s_dev);
    cfg.session.last_will.topic = lwt_topic;
    cfg.session.last_will.msg = "{\"online\":false}";
    cfg.session.last_will.qos = 1;
    cfg.session.last_will.retain = 1;

    s_client = esp_mqtt_client_init(&cfg);

    // C++ fix: cast ESP_EVENT_ANY_ID (-1) to esp_mqtt_event_id_t
    esp_mqtt_client_register_event(s_client,
                                   static_cast<esp_mqtt_event_id_t>(ESP_EVENT_ANY_ID),
                                   mqtt_event_handler,
                                   nullptr);

    esp_mqtt_client_start(s_client);

    ESP_LOGI(TAG, "MQTT started for device_id=%s", s_dev);
}
