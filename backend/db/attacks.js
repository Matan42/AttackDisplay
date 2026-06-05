import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbPath = path.join(__dirname, 'attacks.db');

export function getDatabaseConnection() {
  const sqlite = sqlite3.verbose();
  return new sqlite.Database(dbPath);
}
