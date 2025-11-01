import dotenv from 'dotenv';
dotenv.config();
import { encryptObject } from '../src/crypto.js';

const payload = process.argv[2];
if (!payload) {
  console.error('Usage: npm run encrypt -- "{\\"full_name\\":\\"Alice\\",...}"');
  process.exit(1);
}
const obj = JSON.parse(payload);
console.log(encryptObject(obj));