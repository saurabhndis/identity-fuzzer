#!/usr/bin/env node
/**
 * Generate a 512x512 PNG icon for the Identity Fuzzer app.
 * Uses raw PNG encoding (no external dependencies).
 * Produces a shield icon with "IF" text.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const WIDTH = 512;
const HEIGHT = 512;

// Create RGBA pixel buffer
const pixels = Buffer.alloc(WIDTH * HEIGHT * 4, 0);

function setPixel(x, y, r, g, b, a = 255) {
  if (x < 0 || x >= WIDTH || y < 0 || y >= HEIGHT) return;
  const idx = (y * WIDTH + x) * 4;
  pixels[idx] = r;
  pixels[idx + 1] = g;
  pixels[idx + 2] = b;
  pixels[idx + 3] = a;
}

function fillCircle(cx, cy, radius, r, g, b, a = 255) {
  const r2 = radius * radius;
  for (let dy = -radius; dy <= radius; dy++) {
    for (let dx = -radius; dx <= radius; dx++) {
      if (dx * dx + dy * dy <= r2) {
        setPixel(cx + dx, cy + dy, r, g, b, a);
      }
    }
  }
}

function fillRect(x1, y1, x2, y2, r, g, b, a = 255) {
  for (let y = y1; y <= y2; y++) {
    for (let x = x1; x <= x2; x++) {
      setPixel(x, y, r, g, b, a);
    }
  }
}

function fillRoundedRect(x1, y1, x2, y2, radius, r, g, b, a = 255) {
  // Fill main body
  fillRect(x1 + radius, y1, x2 - radius, y2, r, g, b, a);
  fillRect(x1, y1 + radius, x2, y2 - radius, r, g, b, a);
  // Fill corners
  fillCircle(x1 + radius, y1 + radius, radius, r, g, b, a);
  fillCircle(x2 - radius, y1 + radius, radius, r, g, b, a);
  fillCircle(x1 + radius, y2 - radius, radius, r, g, b, a);
  fillCircle(x2 - radius, y2 - radius, radius, r, g, b, a);
}

// Shield shape - draw a shield-like polygon
function fillShield(cx, cy, w, h, r, g, b, a = 255) {
  const top = cy - h / 2;
  const bottom = cy + h / 2;
  const left = cx - w / 2;
  const right = cx + w / 2;

  for (let y = Math.floor(top); y <= Math.floor(bottom); y++) {
    const progress = (y - top) / (bottom - top); // 0 at top, 1 at bottom
    let halfWidth;
    if (progress < 0.55) {
      // Top portion - full width with rounded top
      halfWidth = w / 2;
    } else {
      // Bottom portion - narrows to a point
      const narrowProgress = (progress - 0.55) / 0.45;
      halfWidth = (w / 2) * (1 - narrowProgress);
    }
    for (let x = Math.floor(cx - halfWidth); x <= Math.floor(cx + halfWidth); x++) {
      setPixel(x, y, r, g, b, a);
    }
  }
}

// Draw background (dark blue-gray)
fillRoundedRect(20, 20, WIDTH - 21, HEIGHT - 21, 60, 30, 36, 50, 255);

// Draw shield (teal/cyan)
fillShield(256, 270, 320, 380, 0, 180, 200, 255);

// Draw inner shield (darker)
fillShield(256, 275, 280, 340, 20, 50, 70, 255);

// Draw "IF" text using simple block letters
// Letter I
fillRect(200, 150, 230, 340, 0, 220, 240, 255);
// Top serif of I
fillRect(185, 150, 245, 170, 0, 220, 240, 255);
// Bottom serif of I
fillRect(185, 320, 245, 340, 0, 220, 240, 255);

// Letter F
fillRect(260, 150, 290, 340, 0, 220, 240, 255);
// Top bar of F
fillRect(260, 150, 340, 170, 0, 220, 240, 255);
// Middle bar of F
fillRect(260, 235, 330, 255, 0, 220, 240, 255);

// Draw small lock icon at bottom of shield
fillRect(240, 370, 272, 400, 0, 180, 200, 255);
// Lock shackle (arc)
for (let angle = 0; angle <= Math.PI; angle += 0.01) {
  const lx = 256 + Math.cos(angle) * 14;
  const ly = 370 - Math.sin(angle) * 16;
  fillCircle(Math.round(lx), Math.round(ly), 2, 0, 180, 200, 255);
}

// Encode as PNG
function encodePNG(width, height, rgbaBuffer) {
  // PNG signature
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  function crc32(buf) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < buf.length; i++) {
      crc ^= buf[i];
      for (let j = 0; j < 8; j++) {
        crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
      }
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  function makeChunk(type, data) {
    const typeBuffer = Buffer.from(type, 'ascii');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length, 0);
    const crcData = Buffer.concat([typeBuffer, data]);
    const crcValue = Buffer.alloc(4);
    crcValue.writeUInt32BE(crc32(crcData), 0);
    return Buffer.concat([length, typeBuffer, data, crcValue]);
  }

  // IHDR chunk
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type: RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  // IDAT chunk - add filter byte (0 = None) before each row
  const rawData = Buffer.alloc(height * (1 + width * 4));
  for (let y = 0; y < height; y++) {
    rawData[y * (1 + width * 4)] = 0; // filter: None
    rgbaBuffer.copy(rawData, y * (1 + width * 4) + 1, y * width * 4, (y + 1) * width * 4);
  }
  const compressed = zlib.deflateSync(rawData, { level: 9 });

  // IEND chunk
  const iend = Buffer.alloc(0);

  return Buffer.concat([
    signature,
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', compressed),
    makeChunk('IEND', iend),
  ]);
}

const png = encodePNG(WIDTH, HEIGHT, pixels);
const outPath = path.join(__dirname, 'icon.png');
fs.writeFileSync(outPath, png);
console.log(`Icon written to ${outPath} (${png.length} bytes)`);
