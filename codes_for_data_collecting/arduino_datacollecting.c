#include <SPI.h>
#include <Ethernet.h>
#include <SD.h>

#define SD_CS_PIN 4
#define BUFFER_SIZE 512

byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IPAddress ip(192, 168, 1, 201);
EthernetServer server(80);
File logFile;

void initSDCard() {
    if (!SD.begin(SD_CS_PIN)) {
        Serial.println("SD card initialization failed!");
        while (true);
    }
    Serial.println("SD card initialized.");
    }

void logDataToSD(String data) {
    logFile = SD.open("network_log.txt", FILE_WRITE);
    if (logFile) {
        logFile.println(data);
        logFile.close();
    } else {
        Serial.println("Error opening log file!");
    }
}

void processPacket(char *buffer, int length, IPAddress srcIP,
    IPAddress dstIP, String protocol) {
    String timestamp = String(day()) + "/" + String(month()) + "/" +
    String(year()) + " " + String(hour()) + ":" + String(minute()) + ":" + String(second());
    String logEntry = timestamp + ", SRC IP: " + srcIP.toString() + ", DST IP: " + dstIP.toString() + ", Protocol: " + protocol + ", Length: " + String(length);
    Serial.println(logEntry);
    logDataToSD(logEntry);
}

void setup() {
    Serial.begin(9600);
    Ethernet.begin(mac, ip);
    server.begin();
    initSDCard();
}

void loop() {
    EthernetClient client = server.available();
    if (client) {
        char buffer[BUFFER_SIZE];
        int index = 0;
        IPAddress srcIP = client.remoteIP();
        IPAddress dstIP = Ethernet.localIP();
        String protocol = "TCP";
        while (client.connected() && client.available() && index < BUFFER_SIZE) {
            buffer[index++] = client.read();
        }
        if (index > 0) {
            processPacket(buffer, index, srcIP, dstIP, protocol);
            EthernetClient relayClient = server.available();
            if (relayClient) {
                relayClient.write((uint8_t*)buffer, index);
            }
        }
        client.stop();
    }
}

