import express from 'express';
import cors from 'cors';
import {
  downloadAndSyncMitreData,
  searchAttacks,
  getAttackDetails,
  getMitreStats
} from './services/insertAttacks.js';

import { processBotMessage } from './services/botService.js';
import { listRecentTasks, getTaskStatus, getTaskReport, submitFile } from './services/sandboxService.js';
import { checkFileFromBuffer, computeFileMD5, computeFileSHA256 } from './services/fileHashService.js';
import { checkFileHash } from './services/virusTotalService.js';
import { getDatabaseConnection, dbRun } from './db/attacks.js';

const app = express();
const PORT = process.env.PORT || 5004;

// MIDDLEWARE CONFIGURATION
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Increase limit for file uploads
app.use(express.raw({ type: '*/*', limit: '10mb' })); // For raw file uploads

// HEALTH CHECK ENDPOINT
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'MATAN CYBER INTELLIGENCE PORTAL - Server Active',
    version: '1.0.0'
  });
});

// CYBER BOT CHAT OPERATIONS ENDPOINT
app.post('/api/bot/chat', async (req, res) => {
  const { message } = req.body;

  try {
    const result = await processBotMessage(message);
    res.json({
      success: true,
      ...result
    });
  } catch (error) {
    console.error('Bot request routing failure:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error inside CyberBot processing hub',
      error: error.message
    });
  }
});

// MITRE DATA SYNCHRONIZATION ENDPOINTS
app.post('/api/mitre/sync', async (req, res) => {
  try {
    const result = await downloadAndSyncMitreData();
    res.json(result);
  } catch (error) {
    console.error('Data replication synchronization failure:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to synchronize repository from MITRE source JSON',
      error: error.message
    });
  }
});

// MITRE DATABASE SEARCH ROUTE
app.get('/api/mitre/search', async (req, res) => {
  const query = String(req.query.q || '');
  const platform = String(req.query.platform || '');
  const tactic = String(req.query.tactic || '');
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 50;

  if (limit > 100) {
    return res.status(400).json({
      success: false,
      message: 'Requested index limit cannot exceed 100'
    });
  }

  try {
    const result = await searchAttacks(query, platform, tactic, page, limit);
    res.json(result);
  } catch (error) {
    console.error('Search operational failure:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// MITRE TECH DETAIL ACQUISITION ROUTE
app.get('/api/mitre/attack/:id', async (req, res) => {
  const id = req.params.id;
  if (!id || id.trim() === '') {
    return res.status(400).json({ success: false, message: 'Attack Technical ID value is required' });
  }

  try {
    const result = await getAttackDetails(id);
    if (!result.success) return res.status(404).json(result);
    res.json(result);
  } catch (error) {
    console.error(`Detailed execution tracking error for index ${id}:`, error);
    res.status(500).json({
      success: false,
      message: `Failed executing full detail request for record ${id}`,
      error: error.message
    });
  }
});

// SANDBOX ENDPOINTS
// List recent sandbox tasks
app.get('/api/sandbox/tasks', async (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 10;
  try {
    const tasks = await listRecentTasks(limit);
    res.json({ success: true, data: tasks });
  } catch (error) {
    console.error('Error fetching sandbox tasks:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get sandbox task status
app.get('/api/sandbox/tasks/:id', async (req, res) => {
  const taskId = req.params.id;
  try {
    const task = await getTaskStatus(taskId);
    if (!task) {
      return res.status(404).json({ success: false, message: `Task ${taskId} not found` });
    }
    res.json({ success: true, data: task });
  } catch (error) {
    console.error(`Error fetching task ${taskId}:`, error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get sandbox task full report
app.get('/api/sandbox/tasks/:id/report', async (req, res) => {
  const taskId = req.params.id;
  try {
    const report = await getTaskReport(taskId);
    if (!report) {
      return res.status(404).json({ success: false, message: `Report for task ${taskId} not found` });
    }
    res.json({ success: true, data: report });
  } catch (error) {
    console.error(`Error fetching report for task ${taskId}:`, error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Submit file for sandbox analysis (simulation)
app.post('/api/sandbox/analyze', async (req, res) => {
  const { filename } = req.body;
  if (!filename) {
    return res.status(400).json({ success: false, message: 'Filename is required' });
  }
  try {
    const result = await submitFile(filename);
    res.json({ success: true, data: result });
  } catch (error) {
    console.error('Error submitting file to sandbox:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// NEW ENDPOINT: Check uploaded file hash against VirusTotal and store result
app.post('/api/sandbox/check-file', async (req, res) => {
  // Get filename from headers or query? We'll use a header or default.
  // We can also get filename from the 'content-disposition' header, but for simplicity we'll require a header or use a query param.
  // Let's use a query parameter: ?filename=xxx
  const filename = req.query.filename || 'uploaded_file';
  try {
    // req.body contains the raw file buffer when using express.raw middleware
    const fileBuffer = req.body;
    if (!fileBuffer || fileBuffer.length === 0) {
      return res.status(400).json({ success: false, message: 'No file data provided' });
    }

    // Compute hashes
    const md5Hash = computeFileMD5(fileBuffer);
    const sha256Hash = computeFileSHA256(fileBuffer);

    // Check the hash against VirusTotal
    const vtResult = await checkFileHash(md5Hash);

    // Store the VT check result in sandbox_reports
    const db = getDatabaseConnection();
    let taskId;
    try {
      taskId = 'VT-' + Math.floor(1000 + Math.random() * 9000);
      const timestamp = new Date().toISOString();
      const filesize = fileBuffer.length;

      // Prepare summary and tags for storage
      const summary = `VT Result: ${vtResult.detected ? 'Malicious' : 'Clean'} (${vtResult.maliciousCount}/${vtResult.totalEngines} engines)`;
      const tags = JSON.stringify([vtResult]); // store as array for frontend parsing

      await dbRun(db, `
        INSERT INTO sandbox_reports (id, filename, filesize, md5, sha256, status, score, summary, tags, behavior_log, network_activity, mitre_techniques, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        taskId,
        filename,
        filesize,
        md5Hash,
        sha256Hash,
        'completed',
        vtResult.maliciousCount,
        summary,
        tags,
        vtResult.behavior_log || '',
        vtResult.network_activity || '',
        JSON.stringify(vtResult.mitre_techniques || []),
        timestamp
      ]);
    } finally {
      db.close();
    }

    // Return the VT result to the client
    res.json({ success: true, data: { ...vtResult, taskId } });
  } catch (error) {
    console.error('Error checking file against VirusTotal:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// SYSTEM EXCEPTION RUNTIMES AND ERROR HANDLERS
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Resource routing path not found' });
});

app.use((err, req, res, next) => {
  console.error('Global middleware caught exception:', err);
  res.status(500).json({ success: false, message: 'Internal application runtime error', error: err.message });
});

// INSTANCE STARTUP EXECUTIONS
app.listen(PORT, () => {
  console.log('MATAN CYBER INTELLIGENCE PORTAL - Server Active');
  console.log('Bot Communication URI available at: http://localhost:' + PORT + '/api/bot/chat');
  console.log('Sandbox API available at: http://localhost:' + PORT + '/api/sandbox');
  console.log('File hash checking available at: http://localhost:' + PORT + '/api/sandbox/check-file');
});