# pysegway_mqtt
a MQTT bridge for Segway Scooters based on https://codeberg.org/NootNooot/segway-ninebot-ble-cli

# setup
Enter mqtt and scooter data to pysegway_config.ini
```
[MQTT]
# Adress of MQTT broker
broker = mqtt.server.local
#Port
port = 1883
# MQTT Topic to publish data
topic = segway/S1ABCDEFGHIKLMN

[SCOOTER]
# Bluetooth MAC Adress
adress = AA:BB:CC:DD:EE:FF
# Serial Number / Name
serial = S1ABCDEFGHIKLMN
# Password extracted from the App
password = 
```
To scan for your device you can use the original repository or python segway_ble_client_old.py

```python segway_ble_client_old.py scan```

Tha Password can be extraced like described here:
https://nootnooot.codeberg.page/segway-ninebot-ble/credentials-qr/#extracting-values-from-an-ios-backup
you will only need the {sn}_decrypt value

# usage

The mqtt code is only sending a keepalive at configured_topic/keepalive, to get data from the scooter you have to run a request.

Send
```update``` 
to the configured_topic/set (like: segway/S1ABCDEFGHIKLMN/set)

The scooter data will be published at configured_topic/info as json.

```
{"sn": "S1ABCDEFGHIKLMN", "ecu": "S1ABCDEFGHIKLMN", "main_power": 503, "mode": "none (0x0000)", "batterie": 94, "speed": 0.0, "ave_spd": 0.0, "sig_max": 0.0, "range_left": 81.80000000000001, "speed_limit": 0.0, "speed_max": 100.0, "speed_ave": 0, "mileage": 9999.955, "trip_mileage": 0, "time_full": 65535, "power": 0, "alarm": 0, "alarm_vol": 50, "alarm_sens": "Low", "auto_lock": 0, "promt_vol": "66", "promt_sound": "Sound 2", "voltage": -1, "bms_cycles": null}
```

The data is requested live so it may take up to 30s to get a feedback.

# homeassistant

There is also a example of a homeassistant integration
