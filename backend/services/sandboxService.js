import axios from 'axios';
import { getDatabaseConnection, dbRun, dbGet, dbAll } from '../db/attacks.js';

const SANDBOX_API_URL = process.env.SANDBOX_API_URL || 'http://localhost:8000/api/v1';

/**
 * Submit a file for sandbox analysis
 * @param {Object} fileInfo - { filename, fileBuffer or path }z
 * @returns {Promise<Object>} - Task ID and status
 */
// Note: In a real implementation, you would upload the file to the sandbox API.
// For this exercise, we simulate by creating a local task record.
export async function submitFile(filename) {
  const db = getDatabaseConnection();
  try {
    const mockTaskId = 'SB-' + Math.floor(1000 + Math.random() * 9000);
    const timestamp = new Date().toISOString();
    // Default hash placeholders (in real scenario, compute from file)
    const md5 = '5d41402abc4b2a76b9719d911017c592'; // hash of "hello"
    const sha256 = '098f6bcd4621d373cade4e832627b4f6'; // hash of "test"

    await dbRun(db, `
      INSERT INTO sandbox_reports (id, filename, filesize, md5, sha256, status, score, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [mockTaskId, filename, 45210, md5, sha256, 'running', 0, timestamp]);

    return { taskId: mockTaskId, status: 'submitted', message: `File submitted for analysis. Task ID: ${mockTaskId}` };
  } finally {
    db.close();
  }
}

/**
 * Get status of a sandbox task
 * @param {string} taskId - Task ID
 * @returns {Promise<Object>} - Status and details
 */
export async function getTaskStatus(taskId) {
  const db = getDatabaseConnection();
  try {
    // First check local DB
    const localReport = await dbGet(db, 'SELECT id, status, score, filename, created_at FROM sandbox_reports WHERE id = ?', [taskId]);
    if (localReport) {
      return { ...localReport, source: 'local' };
    }

    // If not found locally, try remote sandbox API (if configured)
    if (SANDBOX_API_URL && SANDBOX_API_URL !== 'http://localhost:8000/api/v1') {
      try {
        const sbResponse = await axios.get(`${SANDBOX_API_URL}/tasks/view/${taskId}`);
        return { ...sbResponse.data.task, source: 'remote' };
      } catch (apiErr) {
        // If remote API fails, fall through to not found
      }
    }

    return null;
  } finally {
    db.close();
  }
}

/**
 * Get full report for a sandbox task
 * @param {string} taskId - Task ID
 * @returns {Promise<Object>} - Full report
 */
export async function getTaskReport(taskId) {
  const db = getDatabaseConnection();
  try {
    const report = await dbGet(db, 'SELECT * FROM sandbox_reports WHERE id = ?', [taskId]);
    if (!report) return null;

    // Parse JSON fields if any
    const parsed = {
      ...report,
      mitre_techniques: report.mitre_techniques ? JSON.parse(report.mitre_techniques) : [],
      tags: report.tags ? JSON.parse(report.tags) : [],
      behavior_log: report.behavior_log || '',
      network_activity: report.network_activity || '',
      summary: report.summary || ''
    };

    return parsed;
  } finally {
    db.close();
  }
}

/**
 * List recent sandbox tasks
 * @param {number} limit - Number of tasks to return
 * @returns {Promise<Array>} - List of tasks
 */
export async function listRecentTasks(limit = 10) {
  const db = getDatabaseConnection();
  try {
    const rows = await dbAll(db, `
      SELECT id, filename, status, score, created_at
      FROM sandbox_reports
      ORDER BY created_at DESC
      LIMIT ?
    `, [limit]);
    return rows;
  } finally {
    db.close();
  }
}

/**
 * Update sandbox task with analysis results (called by sandbox agent)
 * @param {string} taskId - Task ID
 * @param {Object} results - Analysis results
 * @returns {Promise<void>}
 */
export async function updateTaskResults(taskId, results) {
  const db = getDatabaseConnection();
  try {
    await dbRun(db, `
      UPDATE sandbox_reports
      SET status = ?, score = ?, summary = ?, tags = ?, behavior_log = ?, network_activity = ?, mitre_techniques = ?
      WHERE id = ?
    `, [
      results.status || 'completed',
      results.score || 0,
      results.summary || '',
      JSON.stringify(results.tags || []),
      results.behavior_log || '',
      results.network_activity || '',
      JSON.stringify(results.mitre_techniques || []),
      taskId
    ]);
  } finally {
    db.close();
  }
}