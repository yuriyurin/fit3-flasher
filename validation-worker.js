// Fit3 Flasher classic build. Edit the .mjs sources, then rebuild.
'use strict';
const config = (() => {
// Publish these assets together. Stock is AZA3 -> AZA3, not a universal downgrade.
const STOCK = Object.freeze({
  url: './firmware/stock-aza3.bin',
  version: 'R390XXU0AZA3',
  size: 18265369,
  sha256: '25e692badec82afe111c517c19c5dbdb1d28c8558c2b027143c43f5c8d05998a',
  updaterSha256: '122d0946e0776e9e6b01b300da3be077f47fa97acd44ddf501c302518eb069e4',
});
const SERVICE_UUID = 'db764ac8-4b08-7f25-aafe-59d03c27bae3';
const REMOTE_PATH = '/user/ota/R390_WEB_FOTA.bin';
const MAX_PACKAGE = 32 * 1024 * 1024;

return { STOCK, SERVICE_UUID, REMOTE_PATH, MAX_PACKAGE };
})();
const firmware = (({ STOCK, MAX_PACKAGE }) => {

const decoder = new TextDecoder('utf-8', { fatal: true });
const table = Uint32Array.from({ length: 256 }, (_, n) => {
  for (let k = 0; k < 8; k++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1;
  return n >>> 0;
});
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const b of bytes) crc = table[(crc ^ b) & 255] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
async function sha256(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}
function require(ok, text) { if (!ok) throw new Error(text); }
function view(b) { return new DataView(b.buffer, b.byteOffset, b.byteLength); }
function u32(b, o) { require(o >= 0 && o + 4 <= b.length, 'Файл обрезан.'); return view(b).getUint32(o, true); }
function u16(b, o) { require(o >= 0 && o + 2 <= b.length, 'Файл обрезан.'); return view(b).getUint16(o, true); }
function zstr(b) {
  const end = b.indexOf(0);
  require(end > 0, 'Некорректное текстовое поле пакета.');
  return decoder.decode(b.subarray(0, end));
}
function checksum(b, expected, what) { require(crc32(b) === expected, `Повреждён ${what}. Выберите исходный файл.`); }
const MAX_EXPANDED = 128 * 1024 * 1024;

// Supported profile: one ZIP member, stored/deflate, no ZIP64 or encryption.
// The same bounded reader is used in browser workers and offline tests.
async function unzipOne(zip, budget) {
  require(zip.length >= 52 && u32(zip, 0) === 0x04034b50, 'Компонент не является ZIP.');
  let end = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i--) {
    if (u32(zip, i) === 0x06054b50 && i + 22 + u16(zip, i + 20) === zip.length) { end = i; break; }
  }
  require(end >= 0, 'Не найден конец ZIP.');
  require(u16(zip, end + 4) === 0 && u16(zip, end + 6) === 0 &&
    u16(zip, end + 8) === 1 && u16(zip, end + 10) === 1, 'Неподдерживаемый ZIP.');
  const centralSize = u32(zip, end + 12), central = u32(zip, end + 16);
  require(central + centralSize === end && centralSize >= 46 && u32(zip, central) === 0x02014b50, 'Повреждён каталог ZIP.');
  const flags = u16(zip, central + 8), method = u16(zip, central + 10);
  const crc = u32(zip, central + 16), packed = u32(zip, central + 20), size = u32(zip, central + 24);
  const nameLen = u16(zip, central + 28), extraLen = u16(zip, central + 30), commentLen = u16(zip, central + 32);
  require(!(flags & ~0x808) && [0, 8].includes(method), 'Сжатие ZIP не поддерживается.');
  require(size > 0 && size <= budget, 'Слишком большой распакованный компонент.');
  require(centralSize === 46 + nameLen + extraLen + commentLen && u16(zip, central + 34) === 0 &&
    u32(zip, central + 42) === 0, 'Неоднозначная структура ZIP.');
  require(flags === u16(zip, 6) && method === u16(zip, 8), 'Заголовки ZIP не совпадают.');
  const localNameLen = u16(zip, 26), start = 30 + localNameLen + u16(zip, 28);
  require(localNameLen === nameLen && start + packed <= central, 'Некорректные границы ZIP.');
  require(zip.subarray(30, 30 + nameLen).every((v, i) => v === zip[central + 46 + i]), 'Имена ZIP не совпадают.');
  if (!(flags & 8)) {
    require(start + packed === central && u32(zip, 14) === crc && u32(zip, 18) === packed && u32(zip, 22) === size, 'Некорректные размеры ZIP.');
  } else {
    let descriptor = start + packed;
    if (u32(zip, descriptor) === 0x08074b50) descriptor += 4;
    require(descriptor + 12 === central && u32(zip, descriptor) === crc &&
      u32(zip, descriptor + 4) === packed && u32(zip, descriptor + 8) === size, 'Некорректный дескриптор ZIP.');
  }
  let raw;
  if (method === 0) raw = zip.slice(start, start + packed);
  else {
    const stream = new Blob([zip.subarray(start, start + packed)]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    const reader = stream.getReader();
    raw = new Uint8Array(size);
    let n = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        require(n + value.length <= size, 'Превышен заявленный размер ZIP.');
        raw.set(value, n); n += value.length;
      }
      require(n === size, 'Распакованный компонент обрезан.');
    } catch (e) { await reader.cancel().catch(() => {}); throw e; }
    finally { reader.releaseLock(); }
  }
  require(raw.length === size, 'Размер ZIP не совпадает.');
  checksum(raw, crc, 'ZIP-компонент');
  return raw;
}

function validateMain(raw) {
  require(raw.length >= 0x1010 && raw.length <= 0x380000, 'Размер main не поддерживается.');
  require(u32(raw, 0x1000) === 0x11223344 && u32(raw, 0x1004) === 0xdeaddead, 'Неверный заголовок main.');
  const size = u32(raw, 0x100c);
  require(size >= 0x1010 && size <= raw.length, 'Неверная длина main.');
  const normalized = raw.slice(0, size);
  normalized.fill(255, 0, 4); normalized.fill(0, 0x1000, 0x1010);
  checksum(normalized, u32(raw, 0x1008), 'образ main');
}

async function validatePackage(bytes, { stock = false, progress = () => {} } = {}) {
  require(bytes.length >= 92 && bytes.length <= MAX_PACKAGE, 'Выберите FWD-файл .bin размером до 32 МБ.');
  require(u32(bytes, 0) === 0x7e5a5a60, 'Нужен пакет FWD, а не отдельный образ main или ZIP.');
  const source = zstr(bytes.subarray(4, 68)), flags = u32(bytes, 72);
  const header = u32(bytes, 76), updaterSize = u32(bytes, 80), offset = u32(bytes, 84), size = u32(bytes, 88);
  require(source === STOCK.version && flags === 2, 'Поддерживаются пакеты с проверкой исходной версии R390XXU0AZA3.');
  require(header === 92 && updaterSize > 0 && updaterSize <= 0x38000 && offset === header + updaterSize + 4 &&
    size >= 80 && offset + size + 4 === bytes.length, 'Неверная структура FWD.');
  const updater = bytes.subarray(header, offset - 4), packet = bytes.subarray(offset, offset + size);
  checksum(updater, u32(bytes, offset - 4), 'updater');
  checksum(packet, u32(bytes, offset + size), 'пакет');
  require(await sha256(updater) === STOCK.updaterSha256, 'Пакет заменяет штатный updater. Такая установка здесь не поддерживается.');
  require(u32(packet, 0) === 0x7e5a5a5a && packet[69] === 0x18, 'Этот формат обновления не поддерживается.');
  const target = zstr(packet.subarray(4, 68)), count = packet[70], tableEnd = 80 + count * 128;
  require(target === STOCK.version, 'Этот установщик предназначен для AZA3 и модификаций на её основе.');
  require(count > 0 && tableEnd + 4 <= packet.length, 'Нет таблицы компонентов.');
  checksum(packet.subarray(0, tableEnd), u32(packet, tableEnd), 'каталог компонентов');
  let cursor = tableEnd + 4, expanded = 0, firmwareSize = 0, resourceSize = 0, mainCount = 0;
  const destinations = new Set();
  for (let i = 0; i < count; i++) {
    const o = 80 + i * 128, kind = u16(packet, o), attr = u16(packet, o + 2);
    const start = u32(packet, o + 4), stored = u32(packet, o + 8), path = zstr(packet.subarray(o + 12, o + 128));
    require((kind === 0 && attr === 0x34) || ([1, 4, 7].includes(kind) && attr === 0x74), 'Неподдерживаемый тип компонента.');
    require(path.startsWith('/') && !/[\\:\x00-\x1f]/.test(path) &&
      path.slice(1).split('/').every(p => p && p !== '.' && p !== '..'), 'Небезопасный путь компонента.');
    require(!destinations.has(path.toLowerCase()), 'Повторяющийся путь компонента.');
    destinations.add(path.toLowerCase());
    const imagePaths = {1: '/user/ota/app/best1502x_b319_user.bin', 4: '/user/ota/sensorhub/sensor_hub.bin', 7: '/user/ota/tp/tp_firmware_stx.bin'};
    require(kind === 0 ? (path.startsWith('/nand/system/') || path.startsWith('/user/rescue/')) : path === imagePaths[kind], 'Назначение компонента не поддерживается.');
    require(start === cursor && stored > 0 && start + stored + 4 <= packet.length, 'Компоненты пересекаются или обрезаны.');
    const raw = await unzipOne(packet.subarray(start, start + stored), MAX_EXPANDED - expanded);
    checksum(raw, u32(packet, start + stored), 'компонент прошивки');
    if (kind === 1) { validateMain(raw); mainCount++; }
    expanded += raw.length;
    if (kind) firmwareSize += raw.length; else resourceSize += raw.length;
    cursor = start + stored + 4;
    progress((i + 1) / count);
  }
  require(cursor === packet.length && mainCount === 1 && firmwareSize === u32(packet, 72) &&
    resourceSize === u32(packet, 76), 'Состав пакета не совпадает с заголовком.');
  const hash = await sha256(bytes);
  if (stock) require(bytes.length === STOCK.size && hash === STOCK.sha256, 'Стандартная прошивка на сервере не совпадает с проверенным оригиналом.');
  return { source, target, count, size: bytes.length, sha256: hash, stock: hash === STOCK.sha256 };
}

return { crc32, sha256, validatePackage };
})(config);
(({ validatePackage }) => {
self.onmessage = async ({ data }) => {
  try {
    const info = await validatePackage(new Uint8Array(data.buffer), {
      stock: data.stock, progress: value => self.postMessage({ progress: value }),
    });
    self.postMessage({ info });
  } catch (error) { self.postMessage({ error: error.message || 'Не удалось проверить прошивку.' }); }
};

})(firmware);
