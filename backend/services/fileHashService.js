import { checkFileHash } from './virusTotalService.js';
import { createHash } from 'crypto';

/**
 * Compute MD5 hash of a file buffer
 * @param {Buffer} fileBuffer - Buffer containing file data
 * @returns {string} - MD5 hash hex string
 */
export function computeFileMD5(fileBuffer) {
  return createHash('md5').update(fileBuffer).digest('hex');
}

/**
 * Compute SHA256 hash of a file buffer
 * @param {Buffer} fileBuffer - Buffer containing file data
 * @returns {string} - SHA256 hash hex string
 */
export function computeFileSHA256(fileBuffer) {
  return createHash('sha256').update(fileBuffer).digest('hex');
}

/**
 * Compute MD5 hash of a file buffer and check it against VirusTotal
 * @param {Buffer} fileBuffer - Buffer containing file data
 * @returns {Promise<Object>} - VirusTotal check result
 */
export async function checkFileFromBuffer(fileBuffer) {
  // Compute MD5 hash
  const md5Hash = computeFileMD5(fileBuffer);

  // Check the hash against VirusTotal using existing service
  return await checkFileHash(md5Hash);
}