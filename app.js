// Fit3 Flasher classic build. Edit the .mjs sources, then rebuild.
'use strict';
const APP_BASE_URL = new URL(document.currentScript.src);
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
const transport = (({ SERVICE_UUID, REMOTE_PATH }, { crc32 }) => {
const encoder = new TextEncoder(), decoder = new TextDecoder();
const delay = ms => new Promise(r => setTimeout(r, ms));
function aborted(signal) { if (signal?.aborted) throw new DOMException('Операция остановлена.', 'AbortError'); }
class SerialLink {
  constructor(port, signal) { this.port = port; this.signal = signal; this.pending = new Uint8Array(); this.broken = false; }
  async wait(promise, ms) {
    aborted(this.signal);
    let timer, onAbort;
    try {
      return await Promise.race([promise, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Часы не ответили вовремя. Подключитесь заново.')), ms);
        onAbort = () => reject(new DOMException('Операция остановлена.', 'AbortError'));
        this.signal?.addEventListener('abort', onAbort, { once: true });
      })]);
    } catch (error) {
      this.broken = true;
      await this.reader?.cancel().catch(() => {});
      throw error;
    } finally { clearTimeout(timer); this.signal?.removeEventListener('abort', onAbort); }
  }
  async open() {
    aborted(this.signal);
    await this.port.open({ baudRate: 115200, bufferSize: 262144, flowControl: 'none' });
    this.opened = true;
    this.reader = this.port.readable.getReader(); this.writer = this.port.writable.getWriter();
    if (this.signal?.aborted) { await this.close(); aborted(this.signal); }
  }
  async close() {
    if (!this.opened) return;
    this.opened = false;
    await this.reader?.cancel().catch(() => {});
    await this.writer?.abort().catch(() => {});
    try { this.reader?.releaseLock(); } catch {}
    try { this.writer?.releaseLock(); } catch {}
    this.reader = null; this.writer = null; this.pending = new Uint8Array();
    await this.port.close();
  }
  async send(data) {
    if (this.broken) throw new Error('Подключение прервано. Подключитесь заново.');
    aborted(this.signal);
    await this.wait(this.writer.write(typeof data === 'string' ? encoder.encode(data) : data), 30000);
  }
  async readExact(n, timeout = 30000) {
    if (this.broken) throw new Error('Подключение прервано.');
    aborted(this.signal);
    const out = new Uint8Array(n); let used = 0;
    while (used < n) {
      if (!this.pending.length) {
        const { value, done } = await this.wait(this.reader.read(), timeout);
        if (done) { this.broken = true; throw new Error('Связь с часами прервана.'); }
        this.pending = value;
      }
      const count = Math.min(this.pending.length, n - used);
      out.set(this.pending.subarray(0, count), used); used += count;
      this.pending = this.pending.subarray(count);
    }
    return out;
  }
  async expect(text) {
    if (decoder.decode(await this.readExact(text.length)) !== text) throw new Error('Часы отклонили передачу. Подключитесь заново.');
  }
}
async function choosePort() {
  return navigator.serial.requestPort({ filters: [{ bluetoothServiceClassId: SERVICE_UUID }], allowedBluetoothServiceClassIds: [SERVICE_UUID] });
}
async function withLink(port, signal, action) {
  const link = new SerialLink(port, signal);
  try { await link.open(); return await action(link); }
  finally { await link.close(); }
}
async function checkConnection(port, signal) { await withLink(port, signal, async () => {}); }
async function remoteSize(link) {
  await link.send(encoder.encode('061' + REMOTE_PATH + '\0'));
  const header = await link.readExact(5);
  if (header[0] !== 0x40) throw new Error('Не удалось проверить файл на часах.');
  return new DataView(header.buffer).getUint32(1, false);
}
async function stagePackage(port, bytes, { signal, fullReadback = false, progress = () => {} } = {}) {
  await withLink(port, signal, async link => {
    await link.send('300'); await link.expect('300');
    await link.send(`33bin,${REMOTE_PATH},${bytes.length}`); await link.expect('330');
    // One reusable frame avoids allocating ~18 MB of short-lived buffers.
    // The watch requires ACK 310 before the next frame; do not pipeline blocks.
    const frame = new Uint8Array(39604), frameView = new DataView(frame.buffer);
    const startedAt = performance.now(); let lastProgressAt = startedAt;
    for (let offset = 0; offset < bytes.length; offset += 39600) {
      const block = bytes.subarray(offset, Math.min(offset + 39600, bytes.length));
      frame.set(block);
      frameView.setUint32(block.length, crc32(block), true);
      await link.send(frame.subarray(0, block.length + 4)); await link.expect('310');
      const now = performance.now(), done = offset + block.length;
      if (done === bytes.length || now - lastProgressAt >= 200) {
        progress({ phase: 'upload', done, total: bytes.length,
          bytesPerSecond: Math.round(done * 1000 / Math.max(1, now - startedAt)) });
        lastProgressAt = now;
      }
    }
    await link.send('32'); await link.expect('320');
    await delay(250); aborted(signal);
    await link.send('34'); await link.expect('340');
  });
  await delay(2200); aborted(signal);
  await withLink(port, signal, async link => {
    const total = await remoteSize(link);
    if (total !== bytes.length) throw new Error('Размер файла на часах не совпадает. Установка заблокирована.');
    progress({ phase: 'verify', done: 0, total });
    if (!fullReadback) return;
    await delay(250);
    let offset = 0;
    while (offset < total) {
      await link.send('062');
      const header = await link.readExact(5);
      const n = new DataView(header.buffer).getUint32(1, false);
      if (header[0] !== 0x40 || n === 0 || n > 1024 * 1024 || n > total - offset) throw new Error('Некорректный блок проверки.');
      const data = await link.readExact(n, 180000), sum = await link.readExact(4, 180000);
      let actual = 0;
      for (let i = 0; i < n; i++) {
        actual = (actual + data[i]) >>> 0;
        if (data[i] !== bytes[offset + i]) throw new Error('Содержимое файла на часах не совпадает. Установка заблокирована.');
      }
      if (actual !== new DataView(sum.buffer).getUint32(0, false)) throw new Error('Ошибка контрольной суммы при чтении.');
      offset += n;
      progress({ phase: 'verify', done: offset, total });
      await delay(250);
    }
    await link.send('062'); await delay(100);
  });
  return { size: bytes.length, fullReadback };
}
async function startOta(port, { signal, onSending = () => {} } = {}) {
  await delay(2200); aborted(signal);
  return withLink(port, signal, async link => {
    onSending();
    await link.send('00AT^OTA_UPDATE');
    try { return { reply: decoder.decode(await link.readExact(4, 6000)) }; }
    catch { return { reply: null }; }
  });
}

return { choosePort, checkConnection, stagePackage, startOta, aborted };
})(config, firmware);
const i18n = (() => {
// UI-only localization. It never changes protocol bytes, hashes or package validation.
const EN = {
  'Fit3 Flasher — установка прошивки': 'Fit3 Flasher — firmware installer',
  'Fit3 Flasher, главная': 'Fit3 Flasher, home',
  'Язык интерфейса': 'Interface language',
  'УСТАНОВЩИК ПРОШИВКИ': 'FIRMWARE INSTALLER',
  'Прошивка': 'Firmware for',
  'Выберите файл для установки на часы. Восстановление стандартной прошивки доступно ниже.': 'Choose a firmware file for your watch. Stock recovery is available below.',
  'Откройте сайт по HTTPS в актуальном Chrome или Edge на ПК. Для работы нужен Web Serial.': 'Open this HTTPS site in a current desktop Chrome or Edge browser. Web Serial is required.',
  'Для работы установщика нужен JavaScript.': 'This installer requires JavaScript.',
  'Подключите часы': 'Connect your watch',
  'Сначала выполните сопряжение Galaxy Fit3 с компьютером.': 'Pair your Galaxy Fit3 with your computer first.',
  'Подключить': 'Connect', 'Отключить': 'Disconnect',
  'Выберите прошивку': 'Choose firmware', 'ВАШ ФАЙЛ': 'YOUR FILE',
  'Своя прошивка': 'Custom firmware',
  'Выберите файл прошивки для установки.': 'Select a firmware file to install.',
  'Выбрать прошивку': 'Choose firmware',
  'Восстановление стандартной прошивки': 'Restore stock firmware',
  'Вернуть чистую AZA3, если нужно убрать модификации. Не сбрасывает личные данные.': 'Restore clean AZA3 to remove firmware modifications. This does not erase personal data.',
  'Выбрать стандартную AZA3': 'Choose stock AZA3',
  'ОРИГИНАЛЬНЫЕ КОМПОНЕНТЫ': 'ORIGINAL COMPONENTS',
  'Стандартная AZA3': 'Stock AZA3',
  'Штатная система и ресурсы Samsung.': 'Original Samsung system and resources.',
  'Без модификаций, 17,4 МБ.': 'Unmodified components, 17.4 MB.',
  'Установить стандартную': 'Install stock firmware',
  'Внимание: риск повреждения часов': 'Warning: risk of damage to your watch',
  'Установка прошивки может привести к потере данных и неработоспособности устройства.': 'Flashing firmware may cause data loss or make your device unusable.',
  'Я понимаю и принимаю все риски прошивки и доверяю выбранному файлу.': 'I understand and accept all flashing risks and trust the selected file.',
  'Прошивка готова': 'Firmware ready', 'Продолжить': 'Continue',
  'Ход операции': 'Operation progress', 'Начать установку на часах': 'Start installation on watch', 'Отменить': 'Cancel',
  'Перед установкой': 'Before installing',
  'Часы должны загружаться и быть доступны по Bluetooth. Закройте другие программы, использующие подключение.': 'The watch must boot and be accessible over Bluetooth. Close other apps using the connection.',
  'Проверьте версию в «Настройки → О браслете → Сведения о ПО» и зарядите часы минимум до 50%.': 'Check the version in Settings → About band → Software information and charge the watch to at least 50%.',
  'Если раньше передавали другие OTA-пакеты и не знаете, остались ли они на часах, не запускайте установку: часы могут выбрать не тот файл.': 'If you previously transferred other OTA packages and do not know whether they remain on the watch, do not install: the watch could select the wrong file.',
  'Проверка целостности файла не гарантирует работоспособность модифицированной прошивки.': 'File integrity checks do not guarantee that modified firmware will work.',
  'Журнал установки': 'Installation log', 'Скачать журнал': 'Download log',
  'Проверки ещё не выполнялись.': 'No checks performed yet.', 'События установщика': 'Installer events',
  'Неофициальный инструмент. Не связан с Samsung.': 'Unofficial tool. Not affiliated with Samsung.',
  'ПОДДЕРЖАТЬ ПРОЕКТ': 'SUPPORT THE PROJECT',
  'На кофе разработчику': 'Buy the developer a coffee',
  'Если Fit3 Flasher оказался полезным, можно поддержать его развитие.': 'If Fit3 Flasher has been useful, you can support its development.',
  'Открыть DonationAlerts ↗': 'Open DonationAlerts ↗',
  'Поддержать проект через DonationAlerts': 'Support the project via DonationAlerts',
  'Закрыть': 'Close', 'ПЕРЕД НАЧАЛОМ': 'BEFORE YOU START', 'Проверьте часы': 'Check your watch',
  'У меня Galaxy Fit3 на AZA3, заряд не ниже 50%.': 'My device is a Galaxy Fit3 running AZA3, with at least 50% charge.',
  'На часах нет других ранее загруженных OTA-пакетов. Если я не уверен, установку не продолжаю.': 'There are no other previously uploaded OTA packages on the watch. If unsure, I will not proceed.',
  'Дополнительная проверка': 'Additional verification',
  'Полностью прочитать файл с часов и сравнить. Для стандартной прошивки это может занять больше часа.': 'Read the entire file back from the watch and compare it. Stock firmware may take over an hour.',
  'Обычно проверяются CRC передаваемых блоков и сохранённый размер. Это не полное чтение назад.': 'Normally, transfer block CRCs and the saved file size are checked. This is not full readback verification.',
  'Сначала файл будет передан на часы. Запуск установки — отдельной кнопкой.': 'The file will be uploaded first. A separate button starts the installation.',
  'Передать прошивку': 'Upload firmware',
  'Подключитесь заново перед повторной передачей.': 'Reconnect before trying the upload again.',
  'Операция остановлена': 'Operation cancelled', 'Не удалось продолжить': 'Unable to continue',
  'Обновление не запускалось.': 'The update was not started.', 'Неизвестная ошибка.': 'Unknown error.',
  '{reason} Незавершённый файл мог остаться на часах. Не запускайте OTA вручную.': '{reason} An incomplete file may remain on the watch. Do not start OTA manually.',
  'Ошибка: {error}': 'Error: {error}', 'Отмена: {error}': 'Cancelled: {error}',
  'Нужен актуальный Chrome или Edge с поддержкой блокировки вкладок.': 'A current Chrome or Edge browser with Web Locks support is required.',
  'Установщик уже используется в другой вкладке.': 'The installer is in use in another tab.',
  'Операция остановлена.': 'Operation cancelled.',
  'Проверка заняла слишком много времени.': 'File verification timed out.',
  'Не удалось запустить проверку файла. Проверьте файлы сайта и обновите браузер.': 'Could not start file verification. Check the site files and update your browser.',
  'Проверяем прошивку': 'Checking firmware', 'Проверка компонентов и контрольных сумм.': 'Checking components and checksums.',
  'Стандартная прошивка недоступна на сервере. Попробуйте позже.': 'Stock firmware is unavailable on the server. Try again later.',
  'Размер стандартной прошивки на сервере неверен.': 'The stock firmware file on the server has an incorrect size.',
  'Сервер вернул неверный файл прошивки.': 'The server returned an invalid firmware file.',
  'Скачиваем стандартную AZA3': 'Downloading stock AZA3',
  'Загрузка с этого сайта. На часы ничего не записывается.': 'Downloading from this site. Nothing is being written to the watch.',
  'Загрузка прошивки оборвалась. Попробуйте ещё раз.': 'The firmware download was interrupted. Try again.',
  'Выберите FWD-файл .bin размером до 32 МБ.': 'Choose a FWD .bin file up to 32 MB.',
  'Открываем файл': 'Opening file', 'Стандартная прошивка AZA3': 'Stock AZA3 firmware',
  'AZA3 → AZA3 · {size} МБ': 'AZA3 → AZA3 · {size} MB',
  '{count} компонентов проверено. SHA-256: {hash}': '{count} components verified. SHA-256: {hash}',
  'Пакет {source} → {target}; размер={size}; компонентов={count}; SHA-256={hash}; сток={stock}': 'Package {source} → {target}; size={size}; components={count}; SHA-256={hash}; stock={stock}',
  'Прошивка проверена': 'Firmware verified', 'Можно перейти к передаче на часы.': 'Ready to upload to the watch.', 'Теперь подключите часы.': 'Now connect your watch.',
  'Часы доступны. Выберите прошивку.': 'Watch connection available. Choose firmware.',
  'Подключение проверено': 'Connection verified', 'Установка ещё не запускалась.': 'Installation has not started yet.',
  'RFCOMM: открытие и закрытие порта проверено.': 'RFCOMM: port open/close verified.',
  'Подключение сброшено': 'Connection cleared',
  'Передаём прошивку': 'Uploading firmware', 'Не закрывайте вкладку и держите часы рядом.': 'Keep this tab open and the watch nearby.',
  '{operation}: {percent}% ({done}/{total} байт)': '{operation}: {percent}% ({done}/{total} bytes)',
  'Передача файла': 'File upload', 'Чтение и сравнение': 'Readback comparison',
  'Проверяем файл на часах': 'Verifying file on watch',
  'Полное сравнение с исходным файлом. Это может занять много времени.': 'Comparing every byte with the original file. This may take a long time.',
  'Сверяем сохранённый размер.': 'Checking the saved file size.',
  'Готово к установке': 'Ready to install',
  'Файл передан. Нажмите кнопку ниже, чтобы часы начали обновление. После запуска не выключайте часы.': 'File uploaded. Press the button below to start the update. Do not turn off the watch after starting.',
  'Передача: файл прочитан обратно, все байты совпадают.': 'Upload: full readback verified, every byte matches.',
  'Передача: CRC/ACK блоков и размер проверены; без полного чтения назад.': 'Upload: block CRC/ACKs and file size verified; no full readback.',
  'Запускаем обновление': 'Starting update', 'Не выключайте часы. Отмена больше недоступна.': 'Do not turn off the watch. Cancellation is no longer available.',
  'Попытка отправки команды OTA.': 'Attempting to send the OTA command.',
  'Команда OTA отправлена; ответ={reply}; установка пока не подтверждена.': 'OTA command sent; reply={reply}; installation is NOT verified.',
  'Команда установки отправлена': 'Installation command sent',
  'Дождитесь завершения обновления и перезагрузки часов. Успех установки проверьте на их экране.': 'Wait for the update and reboot to finish. Check the watch screen to confirm installation.',
  'Результат OTA неизвестен: {error}': 'OTA outcome unknown: {error}', 'Проверьте экран часов': 'Check the watch screen',
  'Связь прервалась при запуске. Обновление могло начаться — не повторяйте команду и не выключайте часы.': 'The connection was lost during startup. The update may have started — do not repeat the command or turn off the watch.',
  'Запуск отменён': 'Start cancelled', 'Файл остался на часах, но обновление не запускалось.': 'The file remains on the watch, but the update was not started.',
  'Установщик 2.4. {state}': 'Installer 2.4. {state}', 'Браузер готов к работе.': 'Browser ready.',
  'Этот браузер или способ открытия страницы не поддерживается.': 'This browser or page context is not supported.',
  'Часы не ответили вовремя. Подключитесь заново.': 'The watch did not respond in time. Reconnect.',
  'Подключение прервано. Подключитесь заново.': 'Connection interrupted. Reconnect.',
  'Подключение прервано.': 'Connection interrupted.', 'Связь с часами прервана.': 'The watch connection was lost.',
  'Часы отклонили передачу. Подключитесь заново.': 'The watch rejected the transfer. Reconnect.',
  'Не удалось проверить файл на часах.': 'Could not verify the file on the watch.',
  'Размер файла на часах не совпадает. Установка заблокирована.': 'The file size on the watch does not match. Installation blocked.',
  'Некорректный блок проверки.': 'Invalid readback block.',
  'Содержимое файла на часах не совпадает. Установка заблокирована.': 'File contents on the watch do not match. Installation blocked.',
  'Ошибка контрольной суммы при чтении.': 'Readback checksum mismatch.',
  'Не удалось проверить прошивку.': 'Could not verify firmware.',
  'Файл обрезан.': 'The file is truncated.', 'Некорректное текстовое поле пакета.': 'Invalid package text field.',
  'Компонент не является ZIP.': 'The component is not a ZIP archive.', 'Не найден конец ZIP.': 'ZIP end record not found.',
  'Неподдерживаемый ZIP.': 'Unsupported ZIP archive.', 'Повреждён каталог ZIP.': 'Corrupted ZIP directory.',
  'Сжатие ZIP не поддерживается.': 'Unsupported ZIP compression.', 'Слишком большой распакованный компонент.': 'The expanded component is too large.',
  'Неоднозначная структура ZIP.': 'Ambiguous ZIP structure.', 'Заголовки ZIP не совпадают.': 'ZIP headers do not match.',
  'Некорректные границы ZIP.': 'Invalid ZIP boundaries.', 'Имена ZIP не совпадают.': 'ZIP names do not match.',
  'Некорректные размеры ZIP.': 'Invalid ZIP sizes.', 'Некорректный дескриптор ZIP.': 'Invalid ZIP descriptor.',
  'Превышен заявленный размер ZIP.': 'ZIP data exceeds its declared size.', 'Распакованный компонент обрезан.': 'Expanded component is truncated.',
  'Размер ZIP не совпадает.': 'ZIP size mismatch.', 'Размер main не поддерживается.': 'Unsupported main image size.',
  'Неверный заголовок main.': 'Invalid main image header.', 'Неверная длина main.': 'Invalid main image length.',
  'Нужен пакет FWD, а не отдельный образ main или ZIP.': 'A FWD package is required, not a raw main image or ZIP archive.',
  'Поддерживаются пакеты с проверкой исходной версии R390XXU0AZA3.': 'Packages must enforce source version R390XXU0AZA3.',
  'Неверная структура FWD.': 'Invalid FWD structure.',
  'Пакет заменяет штатный updater. Такая установка здесь не поддерживается.': 'The package replaces the stock updater. This installer does not support that.',
  'Этот формат обновления не поддерживается.': 'Unsupported update format.',
  'Этот установщик предназначен для AZA3 и модификаций на её основе.': 'This installer supports AZA3 and modifications based on it.',
  'Нет таблицы компонентов.': 'Component table is missing.', 'Неподдерживаемый тип компонента.': 'Unsupported component type.',
  'Небезопасный путь компонента.': 'Unsafe component path.', 'Повторяющийся путь компонента.': 'Duplicate component path.',
  'Назначение компонента не поддерживается.': 'Unsupported component destination.', 'Компоненты пересекаются или обрезаны.': 'Components overlap or are truncated.',
  'Состав пакета не совпадает с заголовком.': 'Package contents do not match the header.',
  'Стандартная прошивка на сервере не совпадает с проверенным оригиналом.': 'Stock firmware on the server does not match the verified original.',
};

let language = 'ru';
try { if (localStorage.getItem('fit3-flasher-language') === 'en') language = 'en'; } catch {}
const getLanguage = () => language;
const msg = (key, params = {}) => ({ key, params });
function t(message, params = {}) {
  if (message && typeof message === 'object') return t(message.key, message.params);
  const key = String(message ?? '');
  let template = language === 'en' ? EN[key] ?? key : key;
  if (language === 'en' && /^Повреждён .+\. Выберите исходный файл\.$/.test(key)) {
    template = 'A checksum check failed. Select the original firmware file.';
  }
  return template.replace(/\{(\w+)\}/g, (all, name) => {
    if (!(name in params)) return all;
    const value = params[name];
    return value && typeof value === 'object' ? t(value) : String(value);
  });
}
const dynamic = new Map(), staticText = [], attributes = [];
function text(element, key, params = {}) {
  dynamic.set(element, msg(key, params)); element.textContent = t(key, params);
}
let onChange = () => {};
function setLanguage(next) {
  if (!['ru', 'en'].includes(next)) return;
  language = next;
  try { localStorage.setItem('fit3-flasher-language', next); } catch {}
  document.documentElement.lang = next;
  document.title = t('Fit3 Flasher — установка прошивки');
  for (const [node, raw] of staticText) {
    if (node.isConnected !== false) node.nodeValue = raw.replace(/\S[\s\S]*\S|\S/, part => t(part));
  }
  for (const [el, name, raw] of attributes) el.setAttribute(name, t(raw));
  for (const [el, value] of dynamic) el.textContent = t(value);
  document.getElementById('langRu').setAttribute('aria-pressed', String(next === 'ru'));
  document.getElementById('langEn').setAttribute('aria-pressed', String(next === 'en'));
  onChange();
}
function initI18n(change = () => {}) {
  // Capture only initial static text. Dynamic fields are registered with text().
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const exclude = 'script,style,noscript,#connectionText,#selectedName,#selectedVersion,#confirmFile,#status,#statusDetail,#percent,#verification,#log';
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    if (node.nodeValue.trim() && !node.parentElement?.closest(exclude)) staticText.push([node, node.nodeValue]);
  }
  for (const el of document.querySelectorAll('[aria-label]')) attributes.push([el, 'aria-label', el.getAttribute('aria-label')]);
  document.getElementById('langRu').addEventListener('click', () => setLanguage('ru'));
  document.getElementById('langEn').addEventListener('click', () => setLanguage('en'));
  onChange = change; setLanguage(language);
}

return { initI18n, text, t, msg };
})();
(({ STOCK, MAX_PACKAGE }, { choosePort, checkConnection, stagePackage, startOta, aborted }, { initI18n, text, t, msg }, { validatePackage }) => {

const $ = id => document.getElementById(id);
const ui = Object.fromEntries(['connect', 'disconnect', 'connectionText', 'choose', 'file', 'stock', 'selection', 'selectedName', 'selectedVersion', 'prepare', 'activity', 'status', 'statusDetail', 'percent', 'progress', 'start', 'cancel', 'unsupported', 'confirm', 'confirmFile', 'ready', 'clean', 'risk', 'fullReadback', 'confirmPrepare', 'verification', 'log', 'saveLog'].map(id => [id, $(id)]));
let supported = false, busy = false, phase = 'idle', port = null, selected = null, staged = null, controller = null, wakeLock = null, releaseSession = null;
const logLines = [];
let lastStatusTitle = '';
function renderLog() {
  const followEnd = ui.log.scrollHeight - ui.log.scrollTop - ui.log.clientHeight < 40;
  ui.log.textContent = logLines.map(line => `[${line.time}] ${t(line.message)}`).join('\n');
  if (followEnd) ui.log.scrollTop = ui.log.scrollHeight;
}
function log(key, params = {}) {
  logLines.push({ time: new Date().toISOString(), message: msg(key, params) });
  if (logLines.length > 300) logLines.shift();
  renderLog();
}
function render() {
  const locked = busy || !!staged || phase === 'sent' || phase === 'uncertain';
  ui.connect.disabled = !supported || locked || !!port;
  ui.connect.hidden = !!port;
  ui.disconnect.hidden = !port;
  ui.disconnect.disabled = busy || phase === 'sent' || phase === 'uncertain';
  ui.choose.disabled = ui.stock.disabled = !supported || locked;
  ui.prepare.disabled = !supported || !port || !selected || locked || !ui.risk.checked;
  ui.risk.disabled = busy || phase === 'sent' || phase === 'uncertain';
  ui.selection.hidden = !selected;
  ui.start.hidden = !staged;
  ui.start.disabled = busy || !staged || !ui.risk.checked;
  ui.cancel.hidden = (!busy && !staged) || phase === 'starting' || phase === 'sent' || phase === 'uncertain';
}
function status(title, detail = '', percent = null, kind = '', bytesPerSecond = null) {
  if (title !== lastStatusTitle) { log(title); lastStatusTitle = title; }
  ui.activity.hidden = false; ui.activity.className = 'activity card' + (kind ? ' ' + kind : '');
  text(ui.status, title); text(ui.statusDetail, detail);
  ui.percent.textContent = percent === null ? '' : `${Math.round(percent)}%${bytesPerSecond ? ` · ${(bytesPerSecond / 1024).toFixed(1)} KiB/s` : ''}`;
  if (percent === null) ui.progress.removeAttribute('value'); else ui.progress.value = percent;
  ui.progress.hidden = kind === 'error' || phase === 'sent' || phase === 'uncertain';
}
function forgetStage() { staged = null; releaseSession?.(); releaseSession = null; }
function fail(error, device = false) {
  forgetStage();
  const cancelled = error.name === 'AbortError';
  phase = 'idle';
  if (device) { port = null; text(ui.connectionText, 'Подключитесь заново перед повторной передачей.'); }
  const reason = msg(cancelled ? 'Обновление не запускалось.' : error.message || 'Неизвестная ошибка.');
  status(cancelled ? 'Операция остановлена' : 'Не удалось продолжить',
    device ? msg('{reason} Незавершённый файл мог остаться на часах. Не запускайте OTA вручную.', { reason }) : reason, 0, 'error');
  log(cancelled ? 'Отмена: {error}' : 'Ошибка: {error}', { error: msg(error.message) });
}
async function awake() { try { wakeLock = await navigator.wakeLock?.request('screen'); } catch {} }
async function finish() {
  busy = false; controller = null;
  await wakeLock?.release().catch(() => {}); wakeLock = null;
  render();
}
function begin(nextPhase) { busy = true; phase = nextPhase; controller = new AbortController(); render(); return controller.signal; }
async function claimSession() {
  if (!navigator.locks) throw new Error('Нужен актуальный Chrome или Edge с поддержкой блокировки вкладок.');
  await new Promise((resolve, reject) => {
    navigator.locks.request('fit3-fota-session', { ifAvailable: true }, async lock => {
      if (!lock) { reject(new Error('Установщик уже используется в другой вкладке.')); return; }
      await new Promise(release => { releaseSession = release; resolve(); });
    }).catch(reject);
  });
}
function validate(bytes, stock, signal) {
  // Chrome blocks module workers on file://. The classic deployable build
  // exposes the same validator locally so a user-selected file still works.
  if (typeof location !== 'undefined' && location.protocol === 'file:' &&
      typeof validatePackage === 'function') {
    return validatePackage(bytes, { stock, progress: value => {
      aborted(signal);
      status('Проверяем прошивку', 'Проверка компонентов и контрольных сумм.', value * 100);
    } });
  }
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./validation-worker.js', APP_BASE_URL), { type: 'module' });
    let timer;
    const cleanup = () => { clearTimeout(timer); worker.terminate(); signal.removeEventListener('abort', cancel); };
    const cancel = () => { cleanup(); reject(new DOMException('Операция остановлена.', 'AbortError')); };
    signal.addEventListener('abort', cancel, { once: true });
    timer = setTimeout(() => { cleanup(); reject(new Error('Проверка заняла слишком много времени.')); }, 120000);
    worker.onerror = () => { cleanup(); reject(new Error('Не удалось запустить проверку файла. Проверьте файлы сайта и обновите браузер.')); };
    worker.onmessage = ({ data }) => {
      if ('progress' in data) { status('Проверяем прошивку', 'Проверка компонентов и контрольных сумм.', data.progress * 100); return; }
      cleanup();
      if (data.error) reject(new Error(data.error)); else resolve(data.info);
    };
    worker.postMessage({ buffer: bytes.buffer, stock });
    if (signal.aborted) cancel();
  });
}
async function downloadStock(signal) {
  const response = await fetch(new URL(STOCK.url, APP_BASE_URL), { signal, cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
  if (!response.ok || !response.body) throw new Error('Стандартная прошивка недоступна на сервере. Попробуйте позже.');
  const length = response.headers.get('Content-Length');
  if (length && Number(length) !== STOCK.size && !response.headers.get('Content-Encoding')) throw new Error('Размер стандартной прошивки на сервере неверен.');
  const bytes = new Uint8Array(STOCK.size), reader = response.body.getReader(); let used = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (used + value.length > bytes.length) throw new Error('Сервер вернул неверный файл прошивки.');
      bytes.set(value, used); used += value.length;
      status('Скачиваем стандартную AZA3', 'Загрузка с этого сайта. На часы ничего не записывается.', used / bytes.length * 100);
    }
    if (used !== bytes.length) throw new Error('Загрузка прошивки оборвалась. Попробуйте ещё раз.');
    return bytes;
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
}
async function selectFirmware(file = null) {
  if (busy || staged || !supported || ['sent', 'uncertain'].includes(phase)) return;
  selected = null; forgetStage(); ui.risk.checked = false;
  const signal = begin('validate');
  try {
    await awake();
    if (file && (file.size < 92 || file.size > MAX_PACKAGE)) throw new Error('Выберите FWD-файл .bin размером до 32 МБ.');
    status(file ? 'Открываем файл' : 'Скачиваем стандартную AZA3');
    const bytes = file ? new Uint8Array(await file.arrayBuffer()) : await downloadStock(signal);
    aborted(signal);
    status('Проверяем прошивку', 'Проверка компонентов и контрольных сумм.', 0);
    const info = await validate(bytes, !file, signal); aborted(signal);
    selected = { bytes, info, name: info.stock ? 'Стандартная прошивка AZA3' : file.name };
    text(ui.selectedName, info.stock ? 'Стандартная прошивка AZA3' : '{name}', { name: selected.name });
    text(ui.selectedVersion, 'AZA3 → AZA3 · {size} МБ', { size: (info.size / 1048576).toFixed(1) });
    text(ui.verification, '{count} компонентов проверено. SHA-256: {hash}', { count: info.count, hash: info.sha256 });
    log('Пакет {source} → {target}; размер={size}; компонентов={count}; SHA-256={hash}; сток={stock}',
      { source: info.source, target: info.target, size: info.size, count: info.count, hash: info.sha256, stock: info.stock });
    phase = 'idle'; status('Прошивка проверена', port ? 'Можно перейти к передаче на часы.' : 'Теперь подключите часы.', 100, 'success');
  } catch (error) { selected = null; fail(error); }
  finally { await finish(); }
  if (!file && selected && port) showConfirmation();
}
function showConfirmation() {
  if (busy || !selected || !port || staged || phase !== 'idle' || !ui.risk.checked) return;
  for (const el of [ui.ready, ui.clean]) el.checked = false;
  ui.confirmPrepare.disabled = true; ui.confirm.returnValue = 'cancel';
  text(ui.confirmFile, selected.info.stock ? 'Стандартная прошивка AZA3' : '{name}', { name: selected.name }); ui.confirm.showModal();
}
ui.connect.addEventListener('click', async () => {
  if (busy || !supported || port) return;
  const signal = begin('connect');
  try {
    const candidate = await choosePort(); aborted(signal);
    await claimSession();
    await checkConnection(candidate, signal); aborted(signal);
    forgetStage(); port = candidate;
    text(ui.connectionText, 'Часы доступны. Выберите прошивку.');
    phase = 'idle'; status('Подключение проверено', 'Установка ещё не запускалась.', 100, 'success'); log('RFCOMM: открытие и закрытие порта проверено.');
  } catch (error) { fail(error); }
  finally { await finish(); }
});
ui.disconnect.addEventListener('click', () => {
  if (busy) return;
  forgetStage(); port = null;
  text(ui.connectionText, 'Сначала выполните сопряжение Galaxy Fit3 с компьютером.');
  phase = 'idle'; status('Подключение сброшено', 'Обновление не запускалось.', 0); render();
});
ui.choose.addEventListener('click', () => { ui.file.value = ''; ui.file.click(); });
ui.file.addEventListener('change', () => { if (ui.file.files[0]) selectFirmware(ui.file.files[0]); });
ui.stock.addEventListener('click', () => selectFirmware());
ui.prepare.addEventListener('click', showConfirmation);
for (const el of [ui.ready, ui.clean, ui.risk]) el.addEventListener('change', () => {
  ui.confirmPrepare.disabled = ![ui.ready, ui.clean, ui.risk].every(e => e.checked);
  render();
});
ui.confirm.addEventListener('close', async () => {
  if (ui.confirm.returnValue !== 'prepare' || ![ui.ready, ui.clean, ui.risk].every(e => e.checked) || busy || !port || !selected) return;
  const chosen = selected, chosenPort = port, fullReadback = ui.fullReadback.checked;
  let lastProgressPhase = '', lastProgressStep = -1;
  const signal = begin('stage');
  try {
    await claimSession(); await awake(); aborted(signal);
    status('Передаём прошивку', 'Не закрывайте вкладку и держите часы рядом.', 0);
    await stagePackage(chosenPort, chosen.bytes, { signal, fullReadback, progress: p => {
      const step = Math.floor(p.done / p.total * 10);
      if (p.phase !== lastProgressPhase || step !== lastProgressStep) {
        if (p.phase === 'upload' || fullReadback) log('{operation}: {percent}% ({done}/{total} байт)', {
          operation: msg(p.phase === 'upload' ? 'Передача файла' : 'Чтение и сравнение'), percent: Math.round(p.done / p.total * 100), done: p.done, total: p.total,
        });
        lastProgressPhase = p.phase; lastProgressStep = step;
      }
      status(p.phase === 'upload' ? 'Передаём прошивку' : 'Проверяем файл на часах',
        p.phase === 'upload' ? 'Не закрывайте вкладку и держите часы рядом.' : fullReadback ? 'Полное сравнение с исходным файлом. Это может занять много времени.' : 'Сверяем сохранённый размер.', p.done / p.total * 100, '', p.phase === 'upload' ? p.bytesPerSecond : null);
    } });
    aborted(signal);
    staged = { selected: chosen, port: chosenPort }; phase = 'staged';
    status('Готово к установке', 'Файл передан. Нажмите кнопку ниже, чтобы часы начали обновление. После запуска не выключайте часы.', 100, 'success');
    log(fullReadback ? 'Передача: файл прочитан обратно, все байты совпадают.' : 'Передача: CRC/ACK блоков и размер проверены; без полного чтения назад.');
  } catch (error) { fail(error, true); }
  finally { await finish(); }
});
ui.start.addEventListener('click', async () => {
  if (busy || !staged || staged.port !== port || staged.selected !== selected || !ui.risk.checked) return;
  const chosenPort = port;
  const signal = begin('starting'); staged = null; render(); let sending = false;
  try {
    await awake();
    status('Запускаем обновление', 'Не выключайте часы. Отмена больше недоступна.');
    const result = await startOta(chosenPort, { signal, onSending: () => { sending = true; log('Попытка отправки команды OTA.'); } });
    phase = 'sent';
    log('Команда OTA отправлена; ответ={reply}; установка пока не подтверждена.', { reply: JSON.stringify(result.reply) });
    status('Команда установки отправлена', 'Дождитесь завершения обновления и перезагрузки часов. Успех установки проверьте на их экране.', 100, 'success');
  } catch (error) {
    if (sending) {
      phase = 'uncertain'; log('Результат OTA неизвестен: {error}', { error: msg(error.message) });
      status('Проверьте экран часов', 'Связь прервалась при запуске. Обновление могло начаться — не повторяйте команду и не выключайте часы.', null, 'error');
    } else fail(error, true);
  } finally { forgetStage(); await finish(); }
});
ui.cancel.addEventListener('click', () => {
  if (phase === 'starting') return;
  if (busy) { controller?.abort(); return; }
  forgetStage(); phase = 'idle'; status('Запуск отменён', 'Файл остался на часах, но обновление не запускалось.', 0); render();
});
ui.saveLog.addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([logLines.map(line => `[${line.time}] ${t(line.message)}`).join('\n')], { type: 'text/plain;charset=utf-8' }));
  const a = document.createElement('a'); a.href = url; a.download = 'fit3-installer.log'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
window.addEventListener('beforeunload', event => { if (busy || staged) { event.preventDefault(); event.returnValue = ''; } });
document.addEventListener('visibilitychange', () => { if (!document.hidden && busy) awake(); });
// Port selection does not require firmware decompression or Web Locks.
// Keep those checks at the operation that actually needs them so a browser
// with a missing ZIP capability still opens the device chooser and reports
// the real validation error when a firmware file is selected.
supported = !!window.isSecureContext && !!navigator.serial;
ui.unsupported.hidden = supported;
text(ui.connectionText, 'Сначала выполните сопряжение Galaxy Fit3 с компьютером.');
text(ui.verification, 'Проверки ещё не выполнялись.');
initI18n(() => { renderLog(); render(); });
log('Установщик 2.4. {state}', { state: msg(supported ? 'Браузер готов к работе.' : 'Этот браузер или способ открытия страницы не поддерживается.') });
render();

})(config, transport, i18n, firmware);
