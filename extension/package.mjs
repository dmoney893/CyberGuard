// ZIP writer using stored entries: no platform-specific zip utility required.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const source = path.join(root, 'dist');
const manifest = JSON.parse(await fs.readFile(path.join(source, 'manifest.json'), 'utf8'));
if (manifest.manifest_version !== 3) throw new Error('Build the extension before packaging.');
const files = [];
async function walk(directory, prefix = '') {
  for (const entry of (await fs.readdir(directory, { withFileTypes: true })).sort((a,b) => a.name.localeCompare(b.name))) {
    const name = prefix + entry.name;
    if (entry.isDirectory()) await walk(path.join(directory, entry.name), name + '/');
    else if (entry.isFile()) files.push([name, await fs.readFile(path.join(directory, entry.name))]);
    else throw new Error(`Unsupported archive entry: ${name}`);
  }
}
await walk(source);
files.push(['INSTALL.txt', await fs.readFile(path.join(root, 'INSTALL.txt'))]);

function crc32(data) {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
const chunks = [], directory = [];
let offset = 0, directorySize = 0;
for (const [filename, data] of files) {
  const name = Buffer.from(filename);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x800, 6);
  local.writeUInt16LE(33, 12); // 1980-01-01 for reproducible archives.
  local.writeUInt32LE(crc32(data), 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  local.copy(central, 6, 4, 30);
  central.writeUInt32LE(offset, 42);
  chunks.push(local, name, data);
  directory.push(central, name);
  offset += local.length + name.length + data.length;
  directorySize += central.length + name.length;
}
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0);
end.writeUInt16LE(files.length, 8);
end.writeUInt16LE(files.length, 10);
end.writeUInt32LE(directorySize, 12);
end.writeUInt32LE(offset, 16);
const output = path.join(root, '..', 'public', 'downloads', 'CyberGuard-Extension.zip');
await fs.mkdir(path.dirname(output), { recursive: true });
await fs.writeFile(output, Buffer.concat([...chunks, ...directory, end]));
console.log(`Packaged extension ${manifest.version}: ${output}`);
