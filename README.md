# Network Intrusion Detection

This repository provides a framework for creating and testing a Network Intrusion Detection System (NIDS) using IoT devices and machine learning techniques. It includes code, scripts, and datasets necessary for data collection, processing, and model training to detect network intrusions effectively.

---

## Overview

The project is designed to monitor network traffic and identify cyberattacks in IoT and industrial environments. The system uses:
- **Raspberry Pi** and **Arduino** for data collection.
- **Synthetic attack generation** for training datasets.
- **Public datasets like UNSW-NB15** for enhanced dataset generation.
- Machine learning models (Random Forest, Gradient Boosting, etc.) for detecting anomalous activities.

---

## Repository Structure

### 1. Data Collection Scripts
- **`raspberry_datacollecting.py`**:
  - Captures and processes network traffic using a Raspberry Pi.
  - Stores traffic data in an SQLite database.
  - Captures details like IP addresses, ports, protocols, and packet lengths.
  
- **`arduino_datacollecting.c`**:
  - Monitors network packets using an Arduino with an Ethernet shield.
  - Logs data to an SD card, including IPs, protocols, and packet lengths.

### 2. Data Augmentation Scripts
- **`generate_data_with_unsw-nb15.py`**:
  - Augments collected data with attack and normal traffic from the UNSW-NB15 dataset.
  - Supports merging and aligning custom data with public datasets.

- **`generate_synthetic_attacks.py`**:
  - Creates synthetic attack data to mimic real-world scenarios.
  - Generates random timestamps, protocols, ports, and other attributes for synthetic attack samples.

### 3. Datasets
- **`traffic.csv`**: Original network traffic collected.
- **`augmented_with_unsw_nb15.csv`**: Dataset augmented with normal traffic from the UNSW-NB15 dataset.
- **`augmented_with_unsw_nb15_attacks.csv`**: Dataset with attack samples from the UNSW-NB15 dataset.
- **`augmented_traffic_with_synthetic_attacks.csv`**: Dataset including synthetic attack traffic.

### 4. Models
- **`models.ipynb`**: Contains every trained models and results.

### 5. Documentation
- **`NID_report.pdf`**: Research documentation detailing methods and results.

---
