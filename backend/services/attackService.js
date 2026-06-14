import { getDatabaseConnection, dbRun, dbGet, dbAll } from '../db/attacks.js';

/**
 * Search attacks by keyword, platform, tactic
 * @param {Object} params - { queryStr, platform, tactic, page, limit }
 * @returns {Promise<Object>} - Search results with pagination
 */
export async function searchAttacks(params = {}) {
  const { queryStr = '', platform = '', tactic = '', page = 1, limit = 50 } = params;
  const db = getDatabaseConnection();
  const offset = (page - 1) * limit;

  const normalizedQuery = typeof queryStr === 'string' ? queryStr.trim() : String(queryStr || '').trim();
  const normalizedPlatform = typeof platform === 'string' ? platform.trim() : String(platform || '').trim();
  const normalizedTactic = typeof tactic === 'string' ? tactic.trim() : String(tactic || '').trim();

  try {
    let sql = 'SELECT * FROM attacks';
    const paramsArray = [];
    const conditions = [];

    if (normalizedQuery !== '') {
      const searchWildcard = `%${normalizedQuery}%`;
      conditions.push('(name LIKE ? OR description LIKE ? OR id LIKE ? OR platforms LIKE ? OR phase_name LIKE ?)');
      paramsArray.push(searchWildcard, searchWildcard, searchWildcard, searchWildcard, searchWildcard);
    }

    if (normalizedPlatform !== '') {
      conditions.push('platforms LIKE ?');
      paramsArray.push(`%${normalizedPlatform}%`);
    }

    if (normalizedTactic !== '') {
      conditions.push('phase_name LIKE ?');
      paramsArray.push(`%${normalizedTactic}%`);
    }

    if (conditions.length > 0) {
      sql += ` WHERE ${conditions.join(' AND ')}`;
    }

    // Get count for pagination
    const countSql = `SELECT COUNT(*) as count FROM (${sql})`;
    const totalRow = await dbGet(db, countSql, paramsArray);
    const total = totalRow ? totalRow.count : 0;

    sql += ' ORDER BY id ASC LIMIT ? OFFSET ?';
    paramsArray.push(limit, offset);

    const rows = await dbAll(db, sql, paramsArray);

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
 * Get attack details by ID (MITRE ID or STIX ID)
 * @param {string} id - Attack ID
 * @returns {Promise<Object>} - Attack details with relationships
 */
export async function getAttackDetails(id) {
  const db = getDatabaseConnection();
  try {
    // Get the attack details
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
      // Find all subtechniques where this technique is the parent
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
      // Find parent technique where this technique is the child
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

/**
 * Get MITRE statistics for dashboard
 * @returns {Promise<Object>} - Statistics
 */
export async function getMitreStats() {
  const db = getDatabaseConnection();
  try {
    const totalRow = await dbGet(db, 'SELECT COUNT(*) as total FROM attacks');
    const subtechRow = await dbGet(db, 'SELECT COUNT(*) as total FROM attacks WHERE is_subtechnique = 1');
    const techRow = await dbGet(db, 'SELECT COUNT(*) as total FROM attacks WHERE is_subtechnique = 0');

    // Group by tactics(phase)
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