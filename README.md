Microsoft Exchange 2019 Transport Filtering Agent
==================

## Overview
Detects potential malware with libyara.NET (we use our own build with different fixes).
Extracts archives with SevenZipSharp.
Disarms potentially malicious PDFs with based on xdpdf algorithm.
Parses subject/body/headers with regex, aho-corasik.
Checks MessageId and source subnet of messages.
Can send user email notifications about potentially malicious messages.
Marks potentially malicious message with special header, which helps you archive and reject malicious messages on your Exchange server.
Uses metrics to decide whether a message is malicious.

Using third party libraries:
https://github.com/pdonald/aho-corasick
https://github.com/braktech/xdpdf
https://github.com/squid-box/SevenZipSharp
https://github.com/microsoft/libyara.NET
https://logging.apache.org/log4net/
https://github.com/gdziadkiewicz/log4net.Ext.Json
https://github.com/lduchosal/ipnetwork

## Configuration
Config.cs - Class contains necessary configurations, without which agents work is impossible.
default_config.xml - once configured, will be backup fuse, and if you change config.xml with mistake, agent will use default configuration
config.xml - main configuration file.

## Logging
Information about messages processing is stored as JSON on filesystem via log4net.Ext.Json. Its useful to process these logs via ELK stack.