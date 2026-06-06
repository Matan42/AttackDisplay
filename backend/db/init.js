const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
let sql;
const dbPath = path.join(__dirname, 'attacks.db');
//Function initialize the database 
//It creates three tables: attacks, relationships, and sandbox_reports if they do not exist
function initDB() {
  if(!fs.existsSync(dbPath)){
    console.log('Database file does not exist. Creating a new one:', dbPath);
    fs.closeSync(fs.openSync(dbPath, 'w'));
  }
  // connect to database
  const flags = sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE;
  console.log('Opening database with flags:', flags, dbPath);
  const db = new sqlite3.Database(dbPath, flags, (err) => {
    if (err) {
      return console.error(err.message);
    }
    console.log('Connected to the SQLite database.');

  
    db.serialize(() => {
    //Create attacks table
    db.run(`
      CREATE TABLE IF NOT EXISTS attacks (
        id TEXT PRIMARY KEY,
        stix_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        platforms TEXT,
        detection TEXT,
        phase_name TEXT,
        is_subtechnique INTEGER DEFAULT 0
      )
    `, (err) => {
      if (err) console.error('Failed to create attacks table:', err.message);
      else console.log('"attacks" table verified/created.');
    });

    //Create relationships table
    db.run(`
      CREATE TABLE IF NOT EXISTS relationships (
        id TEXT PRIMARY KEY,
        source_ref TEXT NOT NULL,
        target_ref TEXT NOT NULL,
        relationship_type TEXT NOT NULL
      )
    `, (err) => {
      if (err) console.error('Failed to create relationships table:', err.message);
      else console.log('"relationships" table verified/created.');
    });

    //Create sandbox_reports table
    db.run(`
      CREATE TABLE IF NOT EXISTS sandbox_reports (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        filesize INTEGER NOT NULL,
        md5 TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        status TEXT NOT NULL,
        score INTEGER DEFAULT 0,
        summary TEXT,
        tags TEXT,
        behavior_log TEXT,
        network_activity TEXT,
        mitre_techniques TEXT,
        created_at TEXT NOT NULL
      )
    `, (err) => {
      if (err) console.error('Failed to create sandbox_reports table:', err.message);
      else console.log('"sandbox_reports" table verified/created.');
    });


    db.run(`CREATE INDEX IF NOT EXISTS idx_nameON attacks(name)`, (err) => {
      if (err) console.error('Failed to create index on attacks(name):', err.message);
    });

    db.run(`CREATE INDEX IF NOT EXISTS idx_idON attacks(id)`, (err) => {
      if (err) console.error('Failed to create index on attacks(id):', err.message);
    });

    db.run(`CREATE INDEX IF NOT EXISTS idx_subtechON attacks(is_subtechnique)`, (err) => {
      if (err) console.error('Failed to create index on attacks(is_subtechnique):', err.message);
    });

    db.run(`CREATE INDEX IF NOT EXISTS idx_relationship_sourceON relationships(source_ref)`, (err) => {
      if (err) console.error('Failed to create index on relationships(source_ref):', err.message);
    });

    db.run(`CREATE INDEX IF NOT EXISTS idx_relationship_targetON relationships(target_ref)`, (err) => {
      if (err) console.error('Failed to create index on relationships(target_ref):', err.message);
    }); 
    // Close the DB connection after all table creation callbacks have run
    db.close((err) => {
      if (err) {
        return console.error(err.message);
      }
      console.log('DB initialized successfully and connection closed.');
    });
  });
});
}

// If this script is run directly, initialize the database
if (require.main === module) {
  initDB();
}