import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign, verify, createHash } from 'node:crypto';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const read = path => readFileSync(join(root, path), 'utf8');
const compatibility = JSON.parse(read('compatibility.json'));

function validate(release) {
  if (release.format !== compatibility.format || release.workflowHash !== compatibility.workflowHash ||
    !/^\d{1,6}\.\d{1,6}\.\d{1,6}$/.test(release.version) || !Number.isSafeInteger(release.sequence) || release.sequence < 1 ||
    typeof release.instruction !== 'string' || !release.instruction.trim() || release.instruction.length > 500000 ||
    typeof release.notes !== 'string' || release.notes.length > 20000 || !Number.isFinite(Date.parse(release.publishedAt)) ||
    !Array.isArray(release.prompts) || release.prompts.length > 100 ||
    release.prompts.some(p => typeof p.title !== 'string' || p.title.length > 500 || typeof p.body !== 'string' || !p.body.trim() || p.body.length > 60000))
    throw new Error('Неверный формат методического выпуска.');
  if (compatibility.requiredPromptPrefixes.some(prefix => !release.prompts.some(p => p.title.startsWith(prefix))) ||
    new Set(release.prompts.map(p => p.title)).size !== release.prompts.length)
    throw new Error('Неполный набор заданий либо повторяющиеся названия.');
  const markers = ['# Часть Б', '# Часть В', '# Часть Г'].map(s => release.instruction.indexOf(s));
  if (markers.some(i => i < 0) || !(markers[0] < markers[1] && markers[1] < markers[2])) throw new Error('Нарушена структура инструкции.');
}
function unpack(text, publicKey) {
  if (Buffer.byteLength(text) > 2000000) throw new Error('Пакет превышает 2 МБ.');
  const envelope = JSON.parse(text), bytes = Buffer.from(envelope.payload, 'base64');
  if (!verify(null, bytes, publicKey, Buffer.from(envelope.signature, 'base64'))) throw new Error('Подпись выпуска не подтверждена.');
  const payload = JSON.parse(bytes); validate(payload); return payload;
}
try {
  const { positionals, values } = parseArgs({ allowPositionals: true, options: {
    key: { type: 'string' }, version: { type: 'string' }, sequence: { type: 'string' },
  } });
  if (positionals[0] === 'verify') {
    const publicKey = createPublicKey(read('docs/public-key.pem'));
    const release = unpack(read('docs/latest.json'), publicKey);
    if (read('docs/latest.json') !== read('docs/release-' + release.version + '.json')) throw new Error('Последний пакет отличается от файла выпуска.');
    if (release.instruction !== read('methodology/instruction.md') || JSON.stringify(release.prompts) !== JSON.stringify(JSON.parse(read('methodology/prompts.json'))))
      throw new Error('Исходные материалы отличаются от последнего выпуска. Подготовьте новую версию.');
    console.log('Подпись и состав выпуска ' + release.version + ' проверены.');
  } else if (positionals[0] === 'pack' && values.key) {
    const key = createPrivateKey(readFileSync(values.key, 'utf8'));
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('Нужен ключ Ed25519.');
    const publicKey = createPublicKey(key).export({ type: 'spki', format: 'pem' }).toString();
    if (publicKey !== read('docs/public-key.pem')) throw new Error('Ключ не совпадает с открытым ключом издателя.');
    const previous = unpack(read('docs/latest.json'), publicKey);
    const release = { format: compatibility.format, version: values.version, sequence: Number(values.sequence),
      publishedAt: new Date().toISOString(), notes: read('CHANGELOG.md'), workflowHash: compatibility.workflowHash,
      instruction: read('methodology/instruction.md'), prompts: JSON.parse(read('methodology/prompts.json')) };
    validate(release);
    if (release.sequence <= previous.sequence) throw new Error('Порядковый номер выпуска должен увеличиваться.');
    const path = join(root, 'docs', 'release-' + release.version + '.json');
    if (existsSync(path)) throw new Error('Этот выпуск уже существует.');
    const bytes = Buffer.from(JSON.stringify(release));
    const envelope = JSON.stringify({ payload: bytes.toString('base64'), signature: sign(null, bytes, key).toString('base64') }, null, 2) + '\n';
    unpack(envelope, publicKey);
    writeFileSync(path, envelope, { flag: 'wx' });
    const temp = join(root, 'docs', '.latest-' + createHash('sha256').update(bytes).digest('hex') + '.tmp');
    writeFileSync(temp, envelope); renameSync(temp, join(root, 'docs/latest.json'));
    console.log('Выпуск ' + release.version + ' подготовлен. Выполните проверку и опубликуйте изменения репозитория.');
  } else throw new Error('Используйте verify либо pack --key ПУТЬ --version 1.1.0 --sequence 2.');
} catch (error) { console.error(error.message); process.exitCode = 1; }
