import dotenv from 'dotenv';
dotenv.config();
import { decryptObject } from '../src/crypto.js';

const b64 = process.argv[2];
if (!b64) {
  console.error('Usage: npm run decrypt -- "<base64>"');
  process.exit(1);
}
console.log(JSON.stringify(decryptObject(b64)));