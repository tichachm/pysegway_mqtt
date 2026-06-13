#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import asyncio
import segway_ble_client
from datetime import timedelta
import configparser

config = configparser.ConfigParser()
config.read('/app/pysegway_config.ini')

mqtt_server = config['MQTT']['broker']
mqtt_port = int(config['MQTT']['port'])
mqtt_topic = config['MQTT']['topic']

s_adress = config['SCOOTER']['adress']
s_sn = config['SCOOTER']['serial']
s_pw = config['SCOOTER']['password']

##################################################################
#MQTT
##################################################################

class MQTT:
    import time, json
    import paho.mqtt.client as mqtt
    import _thread
#    import paho.mqtt.subscribe as subscribe

    __instance = None
    @staticmethod
    def getInstance():
         """ Static access method. """
         if MQTT.__instance == None:
             MQTT()
         return MQTT.__instance

    def __init__(self):
        """ Virtually private constructor. """
        if MQTT.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            MQTT.__instance = self

        print("Init MQTT")
        self.connected = False

#        self.client = self.mqtt.Client(self.mqtt.CallbackAPIVersion.VERSION1,"MQTT_Receiver",clean_session=False)
        self.client = self.mqtt.Client(self.mqtt.CallbackAPIVersion.VERSION2,"pysegway_mqtt_" + str(s_sn),clean_session=False)

        self.client.on_message = self.on_message_print
        self.client.on_connect = self.on_connect

        self.connect()


    def on_message_print(self, client, userdata, message):
        print("Message:")
        print(message.topic)
        print(message.payload)

        if (mqtt_topic + "/set" in message.topic and "update" in message.payload.decode()):
            try:
                self._thread.start_new_thread( self.sendDataThread, (client, userdata, message, ) )
            except Exception as ex:
                print(ex)

    def sendDataThread(self, client, userdata, message):
        print("Update for " + str(s_sn) + " started")
        data = asyncio.run(segway_ble_client.get_info(s_adress,s_sn,segway_ble_client.ProtocolGen.GEN2,s_pw))
        self.send_json(mqtt_topic + "/info",data)
        print("Update for " + str(s_sn) + " published")

    # The callback for when the client receives a CONNACK response from the server.
    def on_connect(self, client, userdata, flags, reason_code, properties):
        self.connected = True
        print(f"Connected with result code {reason_code}")
        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        self.client.subscribe(mqtt_topic + "/set")

    def connect(self):
        try:
            print("Connecting to MQTT " + str(mqtt_server) + ":" + str(mqtt_port))
            self.client.connect(mqtt_server, mqtt_port, 60)
            self.client.loop_start()

        except Exception as ex:
            print("Error at MQTT connecting")
            print(ex)

    def send(self, topic, message):
        try:
            if not self.connected:
                self.connect()
            self.client.publish(topic,message)
        except:
            print("Error at MQTT" + topic)
            self.connected = False

    def send_json(self, id, message):
        try:
            self.client.publish(str(id) ,self.json.dumps(message))
        except:
            print("Error at MQTT" + id)


##############################################################################
#File
##############################################################################

class File:
    import sys, json

    def __init__(self,path):
        self.path = path

    def send_raw(self, message):
        try:
#            print ("Writing to: " + self.path)
            with open(self.path, "w") as f:
                f.write(message)
        except Exception as e:
            print ("Error writing File")
            print (e)

    def send(self, message):
        data = self.json.dumps(message)
        self.send_raw(data)



##############################################################################
if __name__ == '__main__':
    mq = MQTT().getInstance()
    while(True):
        time.sleep(30)
        mq.send(mqtt_topic + "/keepalive","pysegway_mqtt_" + str(s_sn) + "=Online")
        print("Sending keepalive")
