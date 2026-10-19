#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Write app/concord.ico, the desktop application's icon.
 *
 * A shortcut with no icon of its own borrows the Node logo, which tells a user they launched a
 * script rather than an application. Concord installs nothing, so there is no icon toolchain
 * here: the ICO container and its DIB images are written byte by byte, which is a few dozen lines
 * and leaves nothing to install.
 *
 * Run it only when the mark changes. The output is committed, so a fresh clone has an icon.
 *
 *   node scripts/make-icon.mjs
 */

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const SIZES = [16, 32, 48, 64];

// The palette is the interface's own, from app/style.css, so the icon and the window agree.
const GROUND = [0x0a, 0x14, 0x10];
const ACCENT = [0x8b, 0xda, 0xa8];
const GOLD = [0xd9, 0xbd, 0x7c];

/** Coverage of one pixel by a shape, by sampling a grid inside it rather than guessing an edge. */
function coverage(x, y, size, inside) {
  const steps = 4;
  let hits = 0;
  for (let sy = 0; sy < steps; sy++) {
    for (let sx = 0; sx < steps; sx++) {
      const px = x + (sx + 0.5) / steps;
      const py = y + (sy + 0.5) / steps;
      if (inside(px / size, py / size)) hits++;
    }
  }
  return hits / (steps * steps);
}

const over = (under, src, alpha) => under.map((channel, i) => Math.round(channel * (1 - alpha) + src[i] * alpha));

/**
 * The mark: a rounded square, a broken ring reading as a C, and a single gold dot closing the
 * gap. Concord is agreement between parts, and a ring that does not quite close with one piece
 * set into it is that, at 16 pixels as well as at 64.
 */
function pixels(size) {
  const data = Buffer.alloc(size * size * 4);
  const radius = 0.22;
  const roundedSquare = (u, v) => {
    const dx = Math.max(radius - u, u - (1 - radius), 0);
    const dy = Math.max(radius - v, v - (1 - radius), 0);
    return dx * dx + dy * dy <= radius * radius;
  };
  const ring = (u, v) => {
    const dx = u - 0.5;
    const dy = v - 0.5;
    const r = Math.hypot(dx, dy);
    if (r < 0.215 || r > 0.345) return false;
    // Open the ring on the right, which is what turns a circle into a C.
    const degrees = Math.atan2(dy, dx) * 180 / Math.PI;
    return Math.abs(degrees) > 40;
  };
  const dot = (u, v) => Math.hypot(u - 0.78, v - 0.5) <= 0.085;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const square = coverage(x, y, size, roundedSquare);
      let colour = GROUND;
      let alpha = square;
      if (alpha > 0) {
        const onRing = coverage(x, y, size, ring);
        if (onRing > 0) colour = over(colour, ACCENT, onRing);
        const onDot = coverage(x, y, size, dot);
        if (onDot > 0) colour = over(colour, GOLD, onDot);
      }
      const at = (y * size + x) * 4;
      // DIB pixels are blue, green, red, alpha.
      data[at] = colour[2];
      data[at + 1] = colour[1];
      data[at + 2] = colour[0];
      data[at + 3] = Math.round(alpha * 255);
    }
  }
  return data;
}

/** One ICO image: a 40-byte BITMAPINFOHEADER, bottom-up BGRA rows, then an empty AND mask. */
function dib(size) {
  const source = pixels(size);
  const header = Buffer.alloc(40);
  header.writeUInt32LE(40, 0);
  header.writeInt32LE(size, 4);
  // Doubled height: the format expects the colour image and a mask stacked, even when the alpha
  // channel already carries the transparency.
  header.writeInt32LE(size * 2, 8);
  header.writeUInt16LE(1, 12);
  header.writeUInt16LE(32, 14);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(size * size * 4, 20);
  const rows = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    source.copy(rows, y * size * 4, (size - 1 - y) * size * 4, (size - y) * size * 4);
  }
  const maskStride = Math.ceil(size / 32) * 4;
  return Buffer.concat([header, rows, Buffer.alloc(maskStride * size)]);
}

const images = SIZES.map((size) => ({ size, bytes: dib(size) }));
const directory = Buffer.alloc(6 + images.length * 16);
directory.writeUInt16LE(0, 0);
directory.writeUInt16LE(1, 2);
directory.writeUInt16LE(images.length, 4);
let offset = directory.length;
images.forEach((image, index) => {
  const at = 6 + index * 16;
  // A 256-pixel edge is written as 0 in this field; every size here is smaller, so this is direct.
  directory.writeUInt8(image.size, at);
  directory.writeUInt8(image.size, at + 1);
  directory.writeUInt8(0, at + 2);
  directory.writeUInt8(0, at + 3);
  directory.writeUInt16LE(1, at + 4);
  directory.writeUInt16LE(32, at + 6);
  directory.writeUInt32LE(image.bytes.length, at + 8);
  directory.writeUInt32LE(offset, at + 12);
  offset += image.bytes.length;
});

const out = path.join(root, 'app', 'concord.ico');
fs.writeFileSync(out, Buffer.concat([directory, ...images.map((image) => image.bytes)]));
console.log(`Wrote ${path.relative(root, out).split(path.sep).join('/')}: ${SIZES.join(', ')} px, ${fs.statSync(out).size} bytes`);
