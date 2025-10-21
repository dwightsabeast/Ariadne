# Ariadne

> Ariadne is an advanced tool used to scan, map, and archive a wide variety of websites.

![License](https://img.shields.io/badge/license-GNU_GPLv3-green) ![Version](https://img.shields.io/badge/version-v.026.1-blue) ![Language](https://img.shields.io/badge/language-PYTHON-yellow) 

## 📋 Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)

## ℹ️ Project Information

- **👤 Author:** dwightsabeast
- **📦 Version:** v.026.1
- **📄 License:** Unlicense
- **🏷️ Keywords:** archival, OSINT, site-discovery

## Features


This tool provides comprehensive website scanning capabilities, starting from a main-level URL. It features robust subdomain discovery and allows you to configure the scan depth, including the option to follow external links beyond the initial domain. During a scan, the tool performs 404 broken link checks, scans for key security headers, and can generate a sitemap on-the-fly.

<div align="center"><img width="764" height="362" alt="image" src="https://github.com/user-attachments/assets/d4b86a24-3639-4d8c-bdc0-2a8f2a256709" /></div>

Key features include the ability to export all discovered links, sites, and subdomains to a .csv file for external analysis. You can also archive found links directly to the Internet Archive, with support for scheduling regular archives. Additionally, the tool offers a "diff" functionality to compare scan results over time, helping you track changes. For advanced use, it also supports the ability to add and use proxies for scanning.

<div align="center"><img width="813" height="379" alt="image" src="https://github.com/user-attachments/assets/f99932ef-632a-4158-b65f-161a35d470ca" /></div>



## Prerequisites

[Python 3.14.0](https://www.python.org/downloads/ "Python 3.14.0") or later

The [latest chromedriver](https://googlechromelabs.github.io/chrome-for-testing/ "latest chromedriver") downloaded and placed into the same folder you wish to run Ariadne from

The [latest FireFox geckodriver](https://github.com/mozilla/geckodriver/releases "latest FireFox geckodriver") downloaded and placed into the same folder you wish to run Ariadne from

## Installation

Download and unzip the Source Code release

Place the ```chromedriver.exe``` ```THIRD_PARTY_NOTICES.chromedriver``` ```LICENSE.chromedriver``` and ```geckodriver.exe``` into the some folder you unzipped Ariadne to

<div align="center"><img width="846" height="674" alt="Screenshot 2025-10-20 183452" src="https://github.com/user-attachments/assets/e730a953-206b-4e8d-900f-726fb1430332" /></div>



Run ```start.bat``` (this will create a venv folder and install required Python dependencies on your first startup)

<div align="center"><img width="685" height="356" alt="image" src="https://github.com/user-attachments/assets/2ab6a8b9-82ca-4170-96b3-6249da5ec2f8" /></div>


Run ```index.html```

<div align="center"><img width="640" height="349" alt="image" src="https://github.com/user-attachments/assets/951978d2-2748-4e5b-ac05-0b616a17570e" /></div>

