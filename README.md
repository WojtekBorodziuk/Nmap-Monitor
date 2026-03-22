# Network Baseline Auditor & Diff Tool

## Overview
A simple script for scanning network addresses and comparing them. It acts as a continuous monitoring tool that establishes a network baseline and alerts you to any changes, such as new devices appearing, or ports being opened/closed.

## Features
* **Automated Network Scanning:** Uses Nmap to scan a target network rapidly (`-F -T4` arguments).
* **Baseline Creation:** Saves the results of the initial scan into a JSON file (`previous_scan.json`) to serve as a reference point.
* **Diff / Comparison Engine:** On subsequent runs, it compares the current scan against the baseline to detect:
  * Newly discovered hosts.
  * Newly opened ports on existing hosts.
  * Hosts that have gone offline.
  * Ports that have been closed.
* **Comprehensive Logging:** Outputs all activities and alerts to both the console and a local log file (`auditor.log`).

## Prerequisites
* Nmap installed on your system.
* Python 3.x
* Required Python packages listed in `requirements.txt`:
  * `python-nmap>=0.7.1`

## Usage
1. Install the required dependencies: `pip install -r requirements.txt`
2. Run the script: `python main.py`
3. Check the `auditor.log` for execution details and alerts. By default, the script is configured to scan `scanme.nmap.org`.
