import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const source = resolve(frontendRoot, '..', '..', 'data', 'processed', 'lab_generated_unidirectional_flows.csv');
const destination = resolve(frontendRoot, 'public', 'data', 'lab_generated_unidirectional_flows.csv');

mkdirSync(dirname(destination), { recursive: true });
copyFileSync(source, destination);
console.log(`Copied lab dataset to ${destination}`);
