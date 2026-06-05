import axios from 'axios';
import { getDatabaseConnection } from '../db/attacks.js';

//Attacks to put in the db
const MITRE_STIX_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';

// Helper to run query in promise
function dbRun(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function dbAll(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function dbGet(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

/**
 * Downloads and parses the attacks from the github repo
 * Inserts all techniques and subtechniques, along with relationships in a fast transaction
 */
export async function downloadAndSyncMitreData() {
  const db = getDatabaseConnection();
  console.log(`Starting synchronization from MITRE STIX source...`);

  try {
    //Fetch from github raw
    const response = await axios.get(MITRE_STIX_URL, {
      responseType: 'json',
      maxContentLength: 100 * 1024 * 1024 // 100MB
    });

    const bundle = response.data;
    if (!bundle || bundle.type !== 'bundle' || !Array.isArray(bundle.objects)) {
      throw new Error('Invalid STIX bundle structure received.');
    }

    const objects = bundle.objects;
    console.log(`Successfully downloaded MITRE data  now processing ${objects.length} STIX objects...`);

    const attackPatterns = [];
    const relationships = [];

    //Filter and map objects
    for (const obj of objects) {
      if (obj.type === 'attack-pattern') {
        //Find MITRE  id from external references
        const extRefs = obj.external_references || [];
        //check if attack is mitre-attack
        const mitreRef = extRefs.find(ref => ref.source_name === 'mitre-attack');
        //if it is save it's id, otherwise save NA
        const mitreId = mitreRef ? mitreRef.external_id : 'NA';
        //if platforms or phases are empty or not an array, save NA, otherwise save the array as JSON string
        const platforms = Array.isArray(obj.x_mitre_platforms) && obj.x_mitre_platforms.length > 0 
          ? JSON.stringify(obj.x_mitre_platforms) 
          : JSON.stringify(['NA']);
        //if kill_chain_phases is empty or not an array, save NA, otherwise save the array of phase names as JSON string
        const phases = Array.isArray(obj.kill_chain_phases) && obj.kill_chain_phases.length > 0
          ? JSON.stringify(obj.kill_chain_phases.map(p => p.phase_name))
          : JSON.stringify(['NA']);

         //Push to attackPatterns array for bulk insertion later
         //Will insert relationships in a separate loop after this one to ensure all techniques are inserted first
        attackPatterns.push({
          id: mitreId,
          stix_id: obj.id,
          name: obj.name || 'NA',
          description: obj.description || 'NA',
          platforms: platforms,
          detection: obj.x_mitre_detection || 'NA',
          phase_name: phases,
          is_subtechnique: obj.x_mitre_is_subtechnique === true ? 1 : 0
        });
      } else if (obj.type === 'relationship' && obj.relationship_type === 'subtechnique-of') {
        relationships.push({
          id: obj.id,
          source_ref: obj.source_ref, // The subtechnique UUID
          target_ref: obj.target_ref, // The parent technique UUID
          relationship_type: obj.relationship_type
        });
      }
    }

    console.log(`Parsed ${attackPatterns.length} attack patterns and ${relationships.length} relationships`);

    //Perform DB Ingestion inside a Transaction for high performance
    await dbRun(db, 'BEGIN TRANSACTION');

    // Clear old data
    await dbRun(db, 'DELETE FROM attacks');
    await dbRun(db, 'DELETE FROM relationships');

    // Insert attacks
    const insertAttackStmt = db.prepare(`
      INSERT OR REPLACE INTO attacks (id, stix_id, name, description, platforms, detection, phase_name, is_subtechnique)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const ap of attackPatterns) {
      insertAttackStmt.run(
        ap.id,
        ap.stix_id,
        ap.name,
        ap.description,
        ap.platforms,
        ap.detection,
        ap.phase_name,
        ap.is_subtechnique
      );
    }
    insertAttackStmt.finalize();

    // Insert relationships
    const insertRelStmt = db.prepare(`
      INSERT OR REPLACE INTO relationships (id, source_ref, target_ref, relationship_type)
      VALUES (?, ?, ?, ?)
    `);

    for (const r of relationships) {
      insertRelStmt.run(
        r.id,
        r.source_ref,
        r.target_ref,
        r.relationship_type
      );
    }
    insertRelStmt.finalize();

    await dbRun(db, 'COMMIT');
    console.log('Successfully saved all records to SQLite database');

    return {
      success: true,
      techniquesCount: attackPatterns.length,
      relationshipsCount: relationships.length
    };
  } catch (error) {
    await dbRun(db, 'ROLLBACK').catch(() => {});
    console.error('Error syncing MITRE data:', error.message);
    throw error;
  } finally {
    db.close();
  }
}

/**
 * Searches the database for attacks by keyword, ID, tactic phase or platform
 */
export async function searchAttacks(queryStr = '', page = 1, limit = 50) {
  const db = getDatabaseConnection();
  const offset = (page - 1) * limit;
  
  try {
    let sql = 'SELECT * FROM attacks';
    const params = [];

    if (queryStr && queryStr.trim() !== '') {
      const searchWildcard = `%${queryStr.trim()}%`;
      sql += ' WHERE name LIKE ? OR description LIKE ? OR id LIKE ? OR platforms LIKE ? OR phase_name LIKE ?';
      params.push(searchWildcard, searchWildcard, searchWildcard, searchWildcard, searchWildcard);
    }

    // Get count for pagination
    const countSql = `SELECT COUNT(*) as count FROM (${sql})`;
    const totalRow = await dbGet(db, countSql, params);
    const total = totalRow ? totalRow.count : 0;

    sql += ' ORDER BY id ASC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const rows = await dbAll(db, sql, params);

    // Parse platform and phase JSON strings back to arrays
    const formattedRows = rows.map(row => ({
      ...row,
      platforms: JSON.parse(row.platforms || '[]'),
      phase_name: JSON.parse(row.phase_name || '[]')
    }));

    return {
      success: true,
      data: formattedRows,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    };
  } catch (error) {
    console.error('Error searching attacks:', error.message);
    throw error;
  } finally {
    db.close();
  }
}

/**
 * Retrieves a single attack pattern by its MITRE ID or STIX ID,
 * and fetches all its relationships
 * Function gets: id (attack id or stix id) 
 * Function returns: attack details along with it's relationships (subtechniques if it's a parent, or parent technique if it's a subtechnique)
 */
export async function getAttackDetails(id) {
  const db = getDatabaseConnection();

  try {
    //Get the attack details
    const attack = await dbGet(db, 'SELECT * FROM attacks WHERE id = ? OR stix_id = ?', [id, id]);
    if (!attack) {
      return { success: false, message: `Attack technique '${id}' not found.` };
    }

    // Parse columns
    attack.platforms = JSON.parse(attack.platforms || '[]');
    attack.phase_name = JSON.parse(attack.phase_name || '[]');

    // Fetch relationships
    let subtechniques = [];
    let parentTechnique = null;

    if (attack.is_subtechnique === 0) {
      //Find all subtechniques where this technique is the parent
      const subtechRows = await dbAll(db, `
        SELECT a.* FROM attacks a
        JOIN relationships r ON a.stix_id = r.source_ref
        WHERE r.target_ref = ? AND r.relationship_type = 'subtechnique-of'
      `, [attack.stix_id]);

      subtechniques = subtechRows.map(row => ({
        ...row,
        platforms: JSON.parse(row.platforms || '[]'),
        phase_name: JSON.parse(row.phase_name || '[]')
      }));
    } else {
      //Find parent technique where this technique is the child
      const parentRow = await dbGet(db, `
        SELECT a.* FROM attacks a
        JOIN relationships r ON a.stix_id = r.target_ref
        WHERE r.source_ref = ? AND r.relationship_type = 'subtechnique-of'
      `, [attack.stix_id]);

      if (parentRow) {
        parentTechnique = {
          ...parentRow,
          platforms: JSON.parse(parentRow.platforms || '[]'),
          phase_name: JSON.parse(parentRow.phase_name || '[]')
        };
      }
    }

    return {
      success: true,
      data: {
        ...attack,
        relationships: {
          subtechniques,
          parentTechnique
        }
      }
    };
  } catch (error) {
    console.error(`Error getting details for attack ${id}:`, error.message);
    throw error;
  } finally {
    db.close();
  }
}


//Returns broad statistics from the database for the portal UI dashboard.
export async function getMitreStats() {
  const db = getDatabaseConnection();

  try {
    const totalRow = await dbGet(db, 'SELECT COUNT(*) as total FROM attacks');
    const subtechRow = await dbGet(db, 'SELECT COUNT(*) as total FROM attacks WHERE is_subtechnique = 1');
    const techRow = await dbGet(db, 'SELECT COUNT(*) as total FROM attacks WHERE is_subtechnique = 0');
    
    //Group by tactics(phase)
    const allPhases = await dbAll(db, 'SELECT phase_name FROM attacks');
    const phaseCounts = {};
    const platformCounts = {};

    allPhases.forEach(row => {
      try {
        const phases = JSON.parse(row.phase_name || '[]');
        phases.forEach(p => {
          if (p !== 'NA') phaseCounts[p] = (phaseCounts[p] || 0) + 1;
        });
      } catch (e) {}
    });

    const allPlatforms = await dbAll(db, 'SELECT platforms FROM attacks');
    allPlatforms.forEach(row => {
      try {
        const plats = JSON.parse(row.platforms || '[]');
        plats.forEach(p => {
          if (p !== 'NA') platformCounts[p] = (platformCounts[p] || 0) + 1;
        });
      } catch (e) {}
    });

    return {
      success: true,
      stats: {
        totalTechniques: totalRow ? totalRow.total : 0,
        parentTechniques: techRow ? techRow.total : 0,
        subtechniques: subtechRow ? subtechRow.total : 0,
        tacticsCount: Object.keys(phaseCounts).length,
        tacticBreakdown: phaseCounts,
        platformBreakdown: platformCounts
      }
    };
  } catch (error) {
    console.error('Error generating database statistics:', error.message);
    throw error;
  } finally {
    db.close();
  }
}