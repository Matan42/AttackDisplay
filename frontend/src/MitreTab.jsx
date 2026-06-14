import { useState, useEffect, useCallback } from 'react';
import { Search, RefreshCw, AlertTriangle, Info, Share2 } from 'lucide-react';
import { API_BASE, PLATFORMS, TACTICS } from './constants/api';
import './MitreTab.css';

// Main MITRE tab component that fetches and displays attack techniques.
export default function MitreTab() {
  // Component state for attacks, selection, filters, loading, and pagination.
  const [attacks, setAttacks] = useState([]);
  const [selectedAttack, setSelectedAttack] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [activePlatform, setActivePlatform] = useState('');
  const [activeTactic, setActiveTactic] = useState('');

  // Load the attack list from the backend, then update attacks and pagination
  const loadAttacks = useCallback(async () => {
    setLoading(true);
    try {
      const url = new URL(`${API_BASE}/mitre/search`);
      if (searchQuery) url.searchParams.set('q', searchQuery);
      url.searchParams.set('page', page);
      url.searchParams.set('limit', 12);
      if (activePlatform) url.searchParams.set('platform', activePlatform);
      if (activeTactic) url.searchParams.set('tactic', activeTactic);

      const res = await fetch(url.toString());
      const data = await res.json();
      if (data.success) {
        setAttacks(data.data);
        setTotalPages(data.pagination.totalPages);
        if (data.data.length > 0 && !selectedAttack) {
          loadAttackDetails(data.data[0].id);
        }
      }
    } catch (err) {
      console.error('Error loading attacks:', err);
    } finally {
      setLoading(false);
    }
  }, [searchQuery, activePlatform, activeTactic, page, selectedAttack]);

  // Load full details for a selected attack technique.
  const loadAttackDetails = async (id) => {
    setDetailsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/mitre/attack/${id}`);
      const data = await res.json();
      if (data.success) {
        setSelectedAttack(data.data);
      }
    } catch (err) {
      console.error('Error loading details:', err);
    } finally {
      setDetailsLoading(false);
    }
  };

  // Reload the attack list whenever pagination or filters change.
  useEffect(() => {
    setPage(1);
  }, [activePlatform, activeTactic]);

  useEffect(() => {
    loadAttacks();
  }, [loadAttacks]);

  // Submit search form and refresh results from page 1.
  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    loadAttacks();
  };

  // Clear active filters and reset search state.
  const clearFilters = () => {
    setActivePlatform('');
    setActiveTactic('');
    setSearchQuery('');
    setPage(1);
  };

  return (
    <div className="browser-grid">
      {/* Left Column - List and Filters */}
      <div className="browser-left-col">
        <div className="glass-panel search-filter-card">
          {/* Search and filter controls for the attack list. */}
          <div className="search-input-wrapper">
            <Search className="w-4 h-4 search-icon" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  handleSearchSubmit(e);
                }
              }}
              placeholder="Search DLL, Macro, Registry..."
              className="cyber-input"
              style={{ fontSize: '11px', height: '36px' }}
            />
          </div>

          <div>
            <span className="filter-section-title">Target Platform:</span>
            <div className="chips-container">
              {PLATFORMS.map((plat) => (
                <button
                  key={plat}
                  onClick={() => {
                    setPage(1);
                    setActivePlatform(activePlatform === plat ? '' : plat);
                  }}
                  className={`filter-chip ${activePlatform === plat ? 'active-cyan' : ''}`}
                >
                  {plat}
                </button>
              ))}
            </div>
          </div>

          <div>
            <span className="filter-section-title">Tactic:</span>
            <div
              className="chips-container"
              style={{ maxHeight: '96px', overflowY: 'auto', paddingRight: '4px' }}
            >
              {TACTICS.map((tac) => (
                <button
                  key={tac}
                  onClick={() => {
                    setPage(1);
                    setActiveTactic(activeTactic === tac ? '' : tac);
                  }}
                  className={`filter-chip ${activeTactic === tac ? 'active-purple' : ''}`}
                >
                  {tac}
                </button>
              ))}
            </div>
          </div>

          {(activePlatform || activeTactic || searchQuery) && (
            <button onClick={clearFilters} className="clear-filters-btn">
              Clear Filters
            </button>
          )}
        </div>

        <div className="glass-panel list-panel">
          {/* Attack list panel and loading/empty states. */}
          {loading ? (
            <div className="list-spinner-container">
              <RefreshCw className="w-8 h-8 animate-spin" style={{ color: 'var(--accent-cyan)' }} />
            </div>
          ) : attacks.length === 0 ? (
            <div className="list-empty-state">
              <AlertTriangle
                className="w-8 h-8"
                style={{ color: 'var(--accent-orange)', marginBottom: '8px' }}
              />
              <span className="list-empty-title">No matching attacks found</span>
              <p className="list-empty-desc">Try changing the search term or clearing filters.</p>
            </div>
          ) : (
            <div className="attacks-list-container">
              {attacks.map((ap) => (
                <div
                  key={ap.id}
                  onClick={() => loadAttackDetails(ap.id)}
                  className={`attack-item ${selectedAttack?.id === ap.id ? 'active' : ''}`}
                >
                  <div className="attack-item-left">
                    <span className="attack-item-name">{ap.name}</span>
                    <span className="attack-item-id terminal-text">{ap.id}</span>
                  </div>
                  <div className="attack-item-badge">
                    <span
                      className={`badge ${ap.is_subtechnique === 1 ? 'badge-medium' : 'badge-info'}`}
                      style={{ fontSize: '8px' }}
                    >
                      {ap.is_subtechnique === 1 ? 'Sub-Tech' : 'Tech'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="pagination-container">
            <button
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page === 1}
              className="pagination-btn"
            >
              Previous
            </button>
            <span className="pagination-text">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage(Math.min(totalPages, page + 1))}
              disabled={page === totalPages}
              className="pagination-btn"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Right Column - Detail View */}
      <div className="browser-right-col">
        {/* Detail view for the selected attack technique. */}
        <div className="glass-panel details-panel">
          {detailsLoading ? (
            <div className="list-spinner-container">
              <RefreshCw
                className="w-12 h-12 animate-spin"
                style={{ color: 'var(--accent-cyan)' }}
              />
            </div>
          ) : !selectedAttack ? (
            <div className="list-empty-state">
              <Info
                className="w-12 h-12"
                style={{ color: 'var(--text-muted)', marginBottom: '8px' }}
              />
              <span className="list-empty-title" style={{ fontSize: '13px' }}>
                No technique selected
              </span>
              <p className="list-empty-desc">Select a technique from the list to view its details.</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', flexGrow: 1 }}>
              <div className="details-header">
                <div className="details-header-title-row">
                  <h2>{selectedAttack.name}</h2>
                  <span className="details-header-id terminal-text">{selectedAttack.id}</span>
                </div>
                <div className="details-header-badges">
                  {selectedAttack.platforms.map((plat) => (
                    <span
                      key={plat}
                      className="badge badge-info"
                      style={{
                        fontSize: '9px',
                        background: 'rgba(255,255,255,0.05)',
                        borderColor: 'rgba(255,255,255,0.1)',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {plat}
                    </span>
                  ))}
                  {selectedAttack.phase_name.map((phase) => (
                    <span key={phase} className="badge badge-medium" style={{ fontSize: '9px' }}>
                      {phase}
                    </span>
                  ))}
                </div>
              </div>

              <div className="details-section">
                <span className="details-section-label">Attack Description:</span>
                <div className="details-description-box">{selectedAttack.description}</div>
              </div>

              <div className="details-section">
                <span className="details-section-label">Detection Methods:</span>
                <div className="details-detection-box">
                  {selectedAttack.detection ||
                    'No detection information defined for this technique.'}
                </div>
              </div>

              <div
                style={{
                  borderTop: '1px solid var(--border-color)',
                  paddingTop: '16px',
                  marginTop: 'auto',
                }}
              >
                <h4 className="relationships-header">
                  <Share2 className="w-4 h-4" style={{ color: 'var(--accent-cyan)' }} />
                  MITRE Technique Relations
                </h4>

                {selectedAttack.is_subtechnique === 0 ? (
                  <div>
                    <span
                      className="filter-section-title"
                      style={{ marginBottom: '8px', display: 'block' }}
                    >
                      Associated Sub-Techniques (
                      {selectedAttack.relationships.subtechniques?.length || 0}):
                    </span>
                    {selectedAttack.relationships.subtechniques?.length > 0 ? (
                      <div className="relations-grid">
                        {selectedAttack.relationships.subtechniques.map((s) => (
                          <div
                            key={s.id}
                            onClick={() => loadAttackDetails(s.id)}
                            className="subtech-relation-item"
                          >
                            <span className="subtech-relation-name">{s.name}</span>
                            <span className="subtech-relation-id terminal-text">{s.id}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span
                        style={{
                          fontSize: '10px',
                          color: 'var(--text-muted)',
                          fontStyle: 'italic',
                        }}
                      >
                        No associated sub-techniques.
                      </span>
                    )}
                  </div>
                ) : (
                  <div>
                    <span
                      className="filter-section-title"
                      style={{ marginBottom: '8px', display: 'block' }}
                    >
                      Parent Technique:
                    </span>
                    {selectedAttack.relationships.parentTechnique ? (
                      <div
                        onClick={() =>
                          loadAttackDetails(selectedAttack.relationships.parentTechnique.id)
                        }
                        className="parent-relation-item"
                      >
                        <div className="parent-relation-left">
                          <span className="parent-relation-name">
                            {selectedAttack.relationships.parentTechnique.name}
                          </span>
                          <span className="parent-relation-tag">Core Threat</span>
                        </div>
                        <span className="parent-relation-id terminal-text">
                          {selectedAttack.relationships.parentTechnique.id}
                        </span>
                      </div>
                    ) : (
                      <span
                        style={{
                          fontSize: '10px',
                          color: 'var(--text-muted)',
                          fontStyle: 'italic',
                        }}
                      >
                        Parent technique not found in database.
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}