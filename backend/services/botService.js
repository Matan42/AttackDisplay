import { checkFileHash } from './virusTotalService.js';
import { submitFile, getTaskStatus, getTaskReport, listRecentTasks, updateTaskResults } from './sandboxService.js';
import { searchAttacks, getAttackDetails, getMitreStats } from './attackService.js';
import { getDatabaseConnection } from '../db/attacks.js';

/**
 * Process incoming bot message and return appropriate response
 * @param {string} message - User message
 * @returns {Promise<Object>} - Response object with { response: string }
 */
export async function processBotMessage(message) {
  if (!message || typeof message !== 'string') {
    return { response: 'CyberBot: Empty message received. Please provide a valid command.' };
  }

  const cleanMsg = message.toLowerCase().trim();
  try {
    // Command Type 1: VirusTotal Hash Analysis (MD5 or SHA256 detection)
    const hashMatch = cleanMsg.match(/\b([a-fA-F0-9]{32}|[a-fA-F0-9]{64})\b/);
    if (hashMatch && (cleanMsg.includes('check') || cleanMsg.includes('vt') || cleanMsg.includes('md5') || cleanMsg.includes('sha256') || cleanMsg.includes('hash'))) {
      const fileHash = hashMatch[1];
      const vtResult = await checkFileHash(fileHash);
      if (vtResult.notFound) {
        return { response: `Info: The signature ${fileHash} was not found in the VirusTotal repository.` };
      }
      // Show detailed stats in simple format without curly braces
      const stats = vtResult.stats || {};
      let response = '';
      if (stats.malicious !== undefined) response += `malicious: ${stats.malicious}\n`;
      if (stats.suspicious !== undefined) response += `suspicious: ${stats.suspicious}\n`;
      if (stats.undetected !== undefined) response += `undetected: ${stats.undetected}\n`;
      if (stats.harmless !== undefined) response += `harmless: ${stats.harmless}\n`;
      if (stats.timeout !== undefined) response += `timeout: ${stats.timeout}\n`;
      if (stats['confirmed-timeout'] !== undefined) response += `confirmed-timeout: ${stats['confirmed-timeout']}\n`;
      if (stats.failure !== undefined) response += `failure: ${stats.failure}\n`;
      if (stats['type-unsupported'] !== undefined) response += `type-unsupported: ${stats['type-unsupported']}`;

      // Remove trailing newline if present
      return { response: response.trim() };
    }

    // Command Type 2: Local Database Query for MITRE ATT&CK Techniques
    if (cleanMsg.startsWith('search ') || cleanMsg.startsWith('find ') || cleanMsg.includes('query')) {
      let keyword = cleanMsg.replace(/^(search|find|query)\s+/i, '').replace(/the|for/g, '').trim();
      if (!keyword) {
        return { response: 'CyberBot: Please specify a keyword to search. Example: search DLL' };
      }

      const searchResult = await searchAttacks({ queryStr: keyword, limit: 5 });
      if (!searchResult.success || !searchResult.data || searchResult.data.length === 0) {
        return { response: `Search Result: No matching techniques found in the application database for keyword: "${keyword}".` };
      }

      const attackList = searchResult.data.map(r => `* ${r.id}: ${r.name}`).join('\n');
      return { response: `Search Result: Found matching techniques in the database:\n${attackList}` };
    }

    // Command Type 3: Sandbox Orchestration and Investigative Checks
    if (cleanMsg.includes('sandbox status') || cleanMsg.includes('task status') || cleanMsg.includes('sandbox check')) {
      const taskIdMatch = cleanMsg.match(/\d+/);
      if (!taskIdMatch) {
        return { response: 'CyberBot: Please provide the numeric Task ID for the sandbox investigation. Example: sandbox status 12' };
      }
      const taskId = taskIdMatch[0];

      const taskStatus = await getTaskStatus(taskId);
      if (!taskStatus) {
        return { response: `Info: Investigation Task ${taskId} was not found locally or via the connected Sandbox API endpoint.` };
      }

      return { response: `Sandbox Status: Investigation for Task ${taskId} records status as "${taskStatus.status}" with a threat score of ${taskStatus.score}/10.` };
    }

    // Command Type 4: File Analysis Request Execution
    if (cleanMsg.includes('sandbox analyze') || cleanMsg.includes('submit file')) {
      let filename = message.replace(/sandbox analyze|submit file/i, '').trim();
      if (!filename) filename = 'suspicious_payload.exe';

      const submitResult = await submitFile(filename);
      return { response: `Success: The file "${filename}" was transferred to the malware sandbox. Generated Task ID: ${submitResult.taskId}. Monitor progress using command: sandbox status ${submitResult.taskId}` };
    }

    // Command Type 5: Get Full Sandbox Report
    if (cleanMsg.includes('sandbox report') || cleanMsg.includes('get report')) {
      const taskIdMatch = cleanMsg.match(/\d+/);
      if (!taskIdMatch) {
        return { response: 'CyberBot: Please provide the numeric Task ID to get the full report. Example: sandbox report 12' };
      }
      const taskId = taskIdMatch[0];

      const report = await getTaskReport(taskId);
      if (!report) {
        return { response: `Info: No report found for Task ${taskId}.` };
      }

      // Format a concise report
      const reportSummary = `
Sandbox Report for Task ${taskId}
Filename: ${report.filename}
Status: ${report.status}
Threat Score: ${report.score}/10
Size: ${report.filesize} bytes
MD5: ${report.md5}
SHA256: ${report.sha256}
Summary: ${report.summary || 'No summary available'}
Tags: ${report.tags && report.tags.length > 0 ? report.tags.join(', ') : 'None'}
MITRE Techniques Detected: ${report.mitre_techniques && report.mitre_techniques.length > 0 ? report.mitre_techniques.join(', ') : 'None'}
`.trim();

      return { response: reportSummary };
    }

    // Command Type 6: List Recent Sandbox Tasks
    if (cleanMsg.includes('sandbox list') || cleanMsg.includes('list tasks')) {
      const limitMatch = cleanMsg.match(/\b\d+\b/);
      const limit = limitMatch ? parseInt(limitMatch[0], 10) : 5;

      const tasks = await listRecentTasks(limit);
      if (!tasks || tasks.length === 0) {
        return { response: `No sandbox tasks found.` };
      }

      const taskList = tasks.map(t => `* ${t.id} - ${t.filename} - ${t.status} (score: ${t.score})`).join('\n');
      return { response: `Recent Sandbox Tasks (last ${limit}):\n${taskList}` };
    }

    // Command Type 7: Get MITRE Statistics
    if (cleanMsg.includes('mitre stats') || cleanMsg.includes('stats')) {
      const statsResult = await getMitreStats();
      if (!statsResult.success) {
        return { response: 'Error retrieving MITRE statistics.' };
      }

      const { stats } = statsResult;
      const statsSummary = `
MITRE ATT&CK Database Statistics
Total Techniques: ${stats.totalTechniques}
Parent Techniques: ${stats.parentTechniques}
Sub-techniques: ${stats.subtechniques}
Number of Tactics: ${stats.tacticsCount}

Top Tactics:
${Object.entries(stats.tacticBreakdown)
  .sort(([,a], [,b]) => b - a)
  .slice(0, 5)
  .map(([tactic, count]) => `  - ${tactic}: ${count}`)
  .join('\n')}

Top Platforms:
${Object.entries(stats.platformBreakdown)
  .sort(([,a], [,b]) => b - a)
  .slice(0, 5)
  .map(([platform, count]) => `  - ${platform}: ${count}`)
  .join('\n')
}
`.trim();

      return { response: statsSummary };
    }

    // Command Type 8: Get Random Technique (for fun)
    if (cleanMsg.includes('random technique') || cleanMsg.includes('rand tech')) {
      const db = getDatabaseConnection();
      try {
        // Get total count of techniques
        const countRow = await dbGet(db, 'SELECT COUNT(*) as total FROM attacks');
        const total = countRow ? countRow.total : 0;

        if (total === 0) {
          return { response: 'No techniques found in the database.' };
        }

        // Get a random offset
        const randomOffset = Math.floor(Math.random() * total);

        // Fetch one technique at the random offset
        const randomTechnique = await dbGet(db, `
          SELECT * FROM attacks
          ORDER BY id
          LIMIT 1 OFFSET ?
        `, [randomOffset]);

        if (!randomTechnique) {
          return { response: 'Failed to fetch a random technique.' };
        }

        // Parse JSON fields
        const platforms = randomTechnique.platforms ? JSON.parse(randomTechnique.platforms) : [];
        const phaseName = randomTechnique.phase_name ? JSON.parse(randomTechnique.phase_name) : [];

        return {
          response: `Random Technique:\nID: ${randomTechnique.id}\nName: ${randomTechnique.name}\nTactic: ${phaseName.join(', ') || 'N/A'}\nPlatforms: ${platforms.join(', ') || 'N/A'}\nDescription: ${(randomTechnique.description || 'No description available').substring(0, 200)}${randomTechnique.description && randomTechnique.description.length > 200 ? '...' : ''}`
        };
      } finally {
        db.close();
      }
    }

    // Fallback response outlining available operational instructions
    return {
      response: 'CyberBot Terminal Interface\n' +
                'Unable to parse commands automatically. Please structure requests using the instructions below:\n\n' +
                '1. Search Library: "search <keyword>" or "find <keyword>"\n' +
                '2. Check Threat Signatures: "check md5 <hash_string>"\n' +
                '3. Execute Sandbox Analysis: "sandbox analyze <filename>"\n' +
                '4. Query Sandbox Status: "sandbox status <task_id>"\n' +
                '5. Get Full Sandbox Report: "sandbox report <task_id>"\n' +
                '6. List Recent Sandbox Tasks: "sandbox list [limit]"\n' +
                '7. Get MITRE Statistics: "mitre stats"\n' +
                '8. Get Random Technique: "random technique"'
    };
  } catch (error) {
    console.error('Error within processBotMessage execution:', error.message);
    return { response: `Error: CyberBot engine failed to execute command logic (${error.message}).` };
  }
}