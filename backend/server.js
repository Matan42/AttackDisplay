import express from 'express';
import cors from 'cors';
import {
  downloadAndSyncMitreData,
  searchAttacks,
  getAttackDetails,
  getMitreStats
} from './services/insertAttacks.js';

// MATAN CYBER INTELLIGENCE PORTAL - SERVER
// Express.js RESTful API for MITRE ATTACK

const app = express();
const PORT = process.env.PORT || 5000;

// MIDDLEWARE CONFIGURATION

// Enable CORS and allow requests from frontend
app.use(cors());

// Parse JSON request bodies
app.use(express.json());

// HEALTH CHECK ENDPOINT

// GET /
// Returns API status
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'MATAN CYBER INTELLIGENCE PORTAL - Server Active',
    version: '1.0.0'
  });
});

// MITRE DATA SYNCHRONIZATION ENDPOINTS

// POST /api/mitre/sync
// Downloads and synchronizes MITRE ATTACK data
// Returns imported techniques and relationships
app.post('/api/mitre/sync', async (req, res) => {
  try {
    const result = await downloadAndSyncMitreData();
    res.json(result);
  } catch (error) {
    console.error('Sync error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to synchronize MITRE ATTACK data',
      error: error.message
    });
  }
});

// MITRE STATISTICS ENDPOINTS

// GET /api/mitre/stats
// Returns database statistics
app.get('/api/mitre/stats', async (req, res) => {
  try {
    const stats = await getMitreStats();
    res.json(stats);
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to load MITRE statistics',
      error: error.message
    });
  }
});

// MITRE SEARCH ENDPOINTS

// GET /api/mitre/search
// Query parameters:
// q - search term
// page - page number
// limit - results per page
// Example:
// /api/mitre/search?q=DLL&page=1&limit=50
app.get('/api/mitre/search', async (req, res) => {
  const query = req.query.q || '';
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 50;

  if (limit > 100) {
    return res.status(400).json({
      success: false,
      message: 'Limit cannot exceed 100'
    });
  }

  try {
    const result = await searchAttacks(query, page, limit);
    res.json(result);
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed searching MITRE attacks',
      error: error.message
    });
  }
});

// MITRE ATTACK DETAILS ENDPOINTS

// GET /api/mitre/attack/:id
// Returns detailed information about a technique
// Example:
// /api/mitre/attack/T1566
app.get('/api/mitre/attack/:id', async (req, res) => {
  const id = req.params.id;

  if (!id || id.trim() === '') {
    return res.status(400).json({
      success: false,
      message: 'Attack ID is required'
    });
  }

  try {
    const result = await getAttackDetails(id);

    if (!result.success) {
      return res.status(404).json(result);
    }

    res.json(result);
  } catch (error) {
    console.error(`Attack details error for ${id}:`, error);

    res.status(500).json({
      success: false,
      message: `Failed loading attack details for ${id}`,
      error: error.message
    });
  }
});

// ERROR HANDLING

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: err.message
  });
});

// SERVER STARTUP

app.listen(PORT, () => {
  console.log('MATAN CYBER INTELLIGENCE PORTAL');
  console.log('Server Active');
  console.log('API Base: http://localhost:' + PORT);
  console.log('Search: http://localhost:' + PORT + '/api/mitre/search?q=DLL');
  console.log('Stats: http://localhost:' + PORT + '/api/mitre/stats');
  console.log('Sync: POST http://localhost:' + PORT + '/api/mitre/sync');
});