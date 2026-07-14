// Shared web chrome for VulnCast's device pages (DRY across all pages).
//
// The whole web UI is identical in captive-portal (AP) and connected (STA)
// modes; only the shared top status bar reflects the current state. Pages are
// composed by chunked sending so the CSS / brand / status bar / JS live in ONE
// place (web_ui.cpp):
//
//   vcSendHead(server, "Title");
//   server.sendContent_P(kBody);   // page-specific body (no CSS), a PROGMEM string
//   vcSendTail(server);
//
// Everything is self-contained (inline CSS/SVG/JS) so it works with no internet.
#pragma once

#include <ArduinoJson.h>
#include <WebServer.h>

// Emit <head> + shared CSS + <body> + the VULNCAST brand + the status-bar
// container (#sbar). Opens a chunked 200 text/html response.
void vcSendHead(WebServer &s, const char *title);

// Emit the shared status-bar script and close the document (final chunk).
void vcSendTail(WebServer &s);

// Serialize `d` and send it as an application/json response (shared by all
// REST handlers so the content-type / status handling lives in one place).
void vcSendJson(WebServer &s, int code, JsonDocument &d);
