import axios from 'axios';

const VT_API_KEY = process.env.VT_API_KEY || '1e3c8ccc51dc5bd5ac04de3c25962e75288fbc0b55ade412db813519ef76f238';
const VT_BASE = 'https://www.virustotal.com/api/v3';

/**
 * Check a file hash against VirusTotal and, if present,
 * pull behaviour / network / ATT&CK data.
 * @param {string} fileHash - MD5 or SHA256 hash
 * @returns {Promise<Object>} - VT result with extra fields
 */
export async function checkFileHash(fileHash) {
  if (!VT_API_KEY || VT_API_KEY === 'YOUR_VIRUSTOTAL_API_KEY') {
    throw new Error('VirusTotal API key is missing on the server configuration.');
  }

  try {
    // ---------- 1️⃣ Basic file report ----------
    const fileResp = await axios.get(`${VT_BASE}/files/${fileHash}`, {
      headers: { 'x-apikey': VT_API_KEY }
    });

    const attrs = fileResp.data.data.attributes;
    const stats = attrs.last_analysis_stats;
    const malicious = stats.malicious || 0;
    const total = (stats.malicious || 0) + (stats.undetected || 0);

    let threatLevel = 'clean';
    if (malicious > 0) threatLevel = 'malicious';
    else if (total === 0) threatLevel = 'unknown';

    // ---------- 2️⃣ Extract ATT&CK IDs from crowdsourced IDs ----------
    let mitreTechniques = [];
    if (Array.isArray(attrs.crowdsourced_ids_results)) {
      for (const ids of attrs.crowdsourced_ids_results) {
        const signature = ids.signature || '';
        // Simple regex that catches Txxxx or Txxxx.yyy
        const matches = signature.match(/T\d{4}(?:\.\d{3})?/g);
        if (matches) mitreTechniques.push(...matches);
      }
      // Deduplicate
      mitreTechniques = [...new Set(mitreTechniques)];
    }

    // ---------- 3️⃣ Behaviour log ----------
    let behaviorLog = '';

    // 3a) Try sandbox_verdicts that are already in the file report
    if (attrs.sandbox_verdicts && typeof attrs.sandbox_verdicts === 'object') {
      const entries = [];
      for (const [sandboxName, verdict] of Object.entries(attrs.sandbox_verdicts)) {
        const category = verdict.category || 'unknown';
        const result = verdict.result || 'no result';
        entries.push(`${sandboxName}: ${category}: ${result}`);
      }
      if (entries.length) behaviorLog = entries.join('\n');
    }

    // 3b) If still empty, try the behaviours endpoint (may require premium key)
    if (!behaviorLog) {
      try {
        const vtId = fileResp.data.data.id; // the VT internal ID
        const behResp = await axios.get(`${VT_BASE}/files/${vtId}/behaviours`, {
          headers: { 'x-apikey': VT_API_KEY }
        });

        if (Array.isArray(behResp.data.data)) {
          const entries = [];
          for (const beh of behResp.data.data) {
            // Some behaviours embed sandbox_verdicts directly
            if (beh.sandbox_verdicts && typeof beh.sandbox_verdicts === 'object') {
              for (const [sandboxName, verdict] of Object.entries(beh.sandbox_verdicts)) {
                const category = verdict.category || 'unknown';
                const result = verdict.result || 'no result';
                entries.push(`${sandboxName}: ${category}: ${result}`);
              }
            } else if (beh.category && beh.result) {
              // Fallback: direct fields
              entries.push(`${beh.category}: ${beh.result}`);
            }
          }
          if (entries.length) behaviorLog = entries.join('\n');
        }
      } catch (behErr) {
        // Not fatal – just keep whatever we got from sandbox_verdicts
        console.debug('VT behaviours endpoint not available or failed', behErr.message);
      }
    }

    // ---------- 4️⃣ Network activity ----------
    let networkActivity = '';

    // 4a) Try network_traffic that may be present in the file report
    if (attrs.network_traffic && typeof attrs.network_traffic === 'object') {
      const nt = attrs.network_traffic;
      const entries = [];

      // HTTP requests
      if (Array.isArray(nt.http_requests)) {
        for (const req of nt.http_requests) {
          const dst = req.dst_ip ? `→ ${req.dst_ip}` : '';
          const method = req.method ? `${req.method} ` : '';
          const url = req.url ? `${method}${req.url}` : '';
          if (dst || url) entries.push(`${dst}${url}`);
        }
      }
      // DNS requests
      if (Array.isArray(nt.dns)) {
        for (const dns of nt.dns) {
          const hostname = dns.hostname || '';
          const type = dns.type || '';
          const ip = dns.ip ? ` → ${dns.ip}` : '';
          if (hostname) entries.push(`DNS ${type} ${hostname}${ip}`);
        }
      }
      if (entries.length) networkActivity = entries.join('\n');
    }

    // 4b) If still empty, try to pull from behaviours (same as above but we already attempted)
    if (!networkActivity) {
      try {
        const vtId = fileResp.data.data.id;
        const behResp = await axios.get(`${VT_BASE}/files/${vtId}/behaviours`, {
          headers: { 'x-apikey': VT_API_KEY }
        });

        if (Array.isArray(behResp.data.data)) {
          const entries = [];
          for (const beh of behResp.data.data) {
            const network = beh.network;
            if (!network) continue;
            // HTTP
            if (Array.isArray(network.http_requests)) {
              for (const req of network.http_requests) {
                const dst = req.dst_ip ? `→ ${req.dst_ip}` : '';
                const method = req.method ? `${req.method} ` : '';
                const url = req.url ? `${method}${req.url}` : '';
                if (dst || url) entries.push(`${dst}${url}`);
              }
            }
            // DNS
            if (Array.isArray(network.dns)) {
              for (const dns of network.dns) {
                const hostname = dns.hostname || '';
                const type = dns.type || '';
                const ip = dns.ip ? ` → ${dns.ip}` : '';
                if (hostname) entries.push(`DNS ${type} ${hostname}${ip}`);
              }
            }
          }
          if (entries.length) networkActivity = entries.join('\n');
        }
      } catch (netErr) {
        console.debug('VT behaviours endpoint not available for network', netErr.message);
      }
    }

    // 4c) If still empty, fallback to crowdsourced_ids_rules (e.g., DNS rules) as a simple network hint
    if (!networkActivity && Array.isArray(attrs.crowdsourced_ids_results)) {
      const ruleMsgs = attrs.crowdsourced_ids_results
        .map(r => r.rule_msg || r.rule_category)
        .filter(Boolean);
      if (ruleMsgs.length) {
        networkActivity = ruleMsgs.join('\n');
      }
    }

    return {
      hash: fileHash,
      threatLevel,
      maliciousCount: malicious,
      totalEngines: total,
      stats,
      detected: malicious > 0,
      behavior_log: behaviorLog,
      network_activity: networkActivity,
      mitre_techniques: mitreTechniques,
      // Keep the raw VT object for debugging / tags column
      vtRaw: {
        ...attrs,
        // strip any huge binary blobs if you ever add them
      }
    };
  } catch (err) {
    if (err.response && err.response.status === 404) {
      return {
        hash: fileHash,
        threatLevel: 'unknown',
        maliciousCount: 0,
        totalEngines: 0,
        stats: {},
        detected: false,
        notFound: true,
        behavior_log: '',
        network_activity: '',
        mitre_techniques: [],
        vtRaw: {}
      };
    }
    throw err;
  }
}