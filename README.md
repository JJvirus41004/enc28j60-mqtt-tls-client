# ENC28J60 MQTT TLS Client (ESP32)

## Overview
This project implements an MQTT client over ENC28J60 Ethernet with TLS 1.2 security on an ESP32.
Unlike typical implementations that rely on high-level libraries or Ethernet controllers with built-in TCP/IP offloading,
this project uses ENC28J60—a minimal SPI-based Ethernet controller—and manually integrates TLS and MQTT functionality.

The implementation provides fine-grained control over Ethernet communication, TLS handshaking, MQTT packet construction,
and task scheduling using FreeRTOS.

## Motivation
Most secure MQTT implementations in embedded systems rely on Wi-Fi or Ethernet modules like W5500 due to easier TLS support.
ENC28J60 lacks a TCP/IP stack, TLS offloading, and advanced buffering, making secure communication uncommon and challenging.

This project intentionally explores those constraints to understand how secure networking behaves in resource-limited embedded
environments and to document what it takes to make ENC28J60 work with TLS-secured MQTT.

## Hardware
- ESP32
- ENC28J60 Ethernet module (SPI-based)

## Software & Technologies
- Arduino IDE
- EthernetENC library
- mbedTLS (TLS 1.2)
- FreeRTOS
- Manual MQTT 3.1.1 packet implementation

## Architecture Highlights
- Ethernet communication over SPI using ENC28J60
- TLS 1.2 handshake and encrypted streams using mbedTLS
- Custom BIO callbacks bridging mbedTLS with EthernetClient
- Manual MQTT packet construction (CONNECT, SUBSCRIBE, PUBLISH, PINGREQ, PINGRESP)
- FreeRTOS-based task separation for non-blocking operation

## Key Features
- TLS-secured MQTT over ENC28J60 Ethernet
- X.509 root CA certificate validation
- Manual MQTT protocol handling (no PubSubClient)
- Publish and subscribe support
- JSON and raw payload switching
- Robust reconnection and resource cleanup
- Long-duration stability focus

## Engineering Challenges Addressed
- Implementing TLS without hardware offload
- Managing TLS memory usage on ESP32
- Handling partial TLS reads and fragmented MQTT packets
- Maintaining keep-alive and reconnection logic
- Safely parsing incoming MQTT data streams

## Incremental Development Approach
The project was developed in clearly defined stages to isolate complexity and validate each layer independently before integration:

1. **Basic MQTT Publish (Raw Payload)**
   - Established Ethernet connectivity over ENC28J60
   - Implemented raw MQTT CONNECT and PUBLISH packets
   - Verified successful message delivery to the broker

2. **MQTT Subscribe Handling**
   - Implemented SUBSCRIBE packet handling
   - Verified incoming MQTT messages from the broker
   - Confirmed correct topic matching and payload reception

3. **Serial ↔ MQTT Bidirectional Messaging**
   - Enabled sending MQTT messages from the serial monitor
   - Verified reception on the broker side
   - Implemented reverse flow to receive MQTT messages back on the serial interface
   - Used this phase to validate packet parsing and TLS stream handling

4. **Structured JSON Payload Integration**
   - Extended raw payload handling to structured JSON messages
   - Enabled formatted data publishing suitable for dashboard ingestion
   - Verified real-time visualization, logging, and field extraction on the MQTT dashboard

## Testing & Validation
The implementation was validated through repeated functional and stability tests as part of an R&D-focused embedded systems exploration.

The system was exercised across multiple extended test sessions to verify TLS handshaking, MQTT publish/subscribe behavior, packet integrity,
and memory stability. Heap usage and fragmentation were monitored during operation, confirming stable behavior under TLS, JSON handling,
Ethernet communication, and FreeRTOS task scheduling.

Additional testing was performed across multiple power cycles and network reconnect scenarios to observe recovery behavior. Under observed
test conditions, no loss of MQTT messages or UART-derived data was detected.

## Notes on Implementation
This project integrates and adapts reference implementations and documentation for Ethernet, TLS, and MQTT. The focus was on understanding
system behavior, debugging failures, and iteratively refining the design rather than relying on high-level abstractions.

The repository reflects a working implementation that is being actively revisited for further documentation, cleanup, and refinement.

## Repository Contents
- `enc28j60_mqtt_tls_client_esp32.ino` – ENC28J60-based MQTT client implementation with TLS and FreeRTOS integration

## Status
✔ Functional implementation  
🛠 Ongoing documentation and code refinement

## Documentation
- [ENC28J60 MQTT TLS Client – Design Notes & Experimental Observations](docs/enc28j60_mqtt_tls_rnd_notes.pdf)

Additional technical notes and experimental observations are available in the `docs/` directory.  
These documents were created by the author as part of an R&D-focused implementation carried out by the author

## Author
Jayant Kumar  
Platform: ESP32 + ENC28J60 + mbedTLS + FreeRTOS
