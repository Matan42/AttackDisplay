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
import { getDatabaseConnection, dbRun } from './db/attacks.js';