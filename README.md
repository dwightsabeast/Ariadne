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
- **📄 License:** GNU GPLv3 
- **🏷️ Keywords:** archival, OSINT, site-discovery

## Features

![Ariadne_v 026 1](https://github.com/user-attachments/assets/37068fe5-4e8d-49e9-a4a6-19070dd095ca)


This tool enables users to scan a top level domain with up to 5 levels of depth, or "clicks", including the option to follow external links beyond the initial domain. The level and reach of Ariadne's scans ensures all links are found. Ariande also features robust subdomain discovery tool complete with passive and active discovery methods, a wildcard detection system, and the ability to brute force subdomain searches. After these scans have completed, the tool allows users to perform 404 broken link checks, scans for key security headers, and will generate a sitemap on-the-fly.

<div align="center"><img width="764" height="362" alt="image" src="https://github.com/user-attachments/assets/d4b86a24-3639-4d8c-bdc0-2a8f2a256709" /></div>

When the user has sufficiently sluethed a site, Ariadne gives the option to export to a .csv file, and archive all discovered links, sites, and subdomains. Before the user archives anything, they are given the option to diff anything found during a scan. This diff function allows users to see if any changes have been made to the given page since the last time that page was saved to the Internet Archive. This diff function occurs during scheduled scans in order to minimize archiving unchanged pages.

<div align="center"><img width="813" height="379" alt="image" src="https://github.com/user-attachments/assets/f99932ef-632a-4158-b65f-161a35d470ca" /></div>

## Prerequisites

[Python 3.14.0](https://www.python.org/downloads/ "Python 3.14.0") or later

The [latest chromedriver](https://googlechromelabs.github.io/chrome-for-testing/ "latest chromedriver") downloaded and placed into the same folder you wish to run Ariadne from

The [latest FireFox geckodriver](https://github.com/mozilla/geckodriver/releases "latest FireFox geckodriver") downloaded and placed into the same folder you wish to run Ariadne from

## Installation

Download and unzip the Source Code release

Place the ```chromedriver.exe``` ```THIRD_PARTY_NOTICES.chromedriver``` ```LICENSE.chromedriver``` and ```geckodriver.exe``` into the same folder you unzipped Ariadne to

<div align="center"><img width="846" height="674" alt="Screenshot 2025-10-20 183452" src="https://github.com/user-attachments/assets/e730a953-206b-4e8d-900f-726fb1430332" /></div>



Run ```start.bat``` (this will create a venv folder and install required Python dependencies on your first startup)

<div align="center"><img width="685" height="356" alt="image" src="https://github.com/user-attachments/assets/2ab6a8b9-82ca-4170-96b3-6249da5ec2f8" /></div>


Run ```index.html```

<div align="center"><img width="640" height="349" alt="image" src="https://github.com/user-attachments/assets/951978d2-2748-4e5b-ac05-0b616a17570e" /></div>

