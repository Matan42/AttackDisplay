import { useState, useEffect } from 'react';
import { RefreshCw, AlertTriangle, Info, Search, Upload } from 'lucide-react';
import { API_BASE } from './constants/api';
import './SandboxTab.css';

export default function SandboxTab() {
  const [tasks, setTasks] = useState([]);
  const [selectedTask, setSelectedTask] = useState(null);
  const [loading, setLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [dropAreaActive, setDropAreaActive] = useState(false);
  const [dropError, setDropError] = useState('');

  // Fetch recent sandbox tasks (now includes VT checks)
  const loadTasks = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/sandbox/tasks?limit=20`);
      const data = await res.json();
      if (data.success) {
        setTasks(data.data);
      }
    } catch (err) {
      console.error('Error loading sandbox tasks:', err);
      setDropError('Failed to load tasks');
    } finally {
      setLoading(false);
    }
  };

  // Get full report for a task (works for both sandbox and VT checks)
  const loadTaskReport = async (taskId) => {
    setReportLoading(true);
    try {
      const res = await fetch(`${API_BASE}/sandbox/tasks/${taskId}/report`);
      const data = await res.json();
      if (data.success) {
        const taskData = data.data;
        // Check if this is a VT check by examining tags
        let vtResult = null;
        if (Array.isArray(taskData.tags) && taskData.tags.length > 0) {
          const firstTag = taskData.tags[0];
          if (typeof firstTag === 'object' && firstTag !== null && 'detected' in firstTag) {
            vtResult = firstTag;
          }
        }
        // Attach vtResult to the task data for easy access in the UI
        taskData.vtResult = vtResult;
        setSelectedTask(taskData);
      } else {
        setDropError(`Failed to load report: ${data.message}`);
      }
    } catch (err) {
      console.error('Error loading task report:', err);
      setDropError('Failed to load report');
    } finally {
      setReportLoading(false);
    }
  };

  // Handle file drop or selection
  const handleFile = async (file) => {
    setDropError('');
    try {
      // Convert file to ArrayBuffer
      const arrayBuffer = await file.arrayBuffer();

      // Prepare form data? We'll send raw binary with query param for filename
      const res = await fetch(`${API_BASE}/sandbox/check-file?filename=${encodeURIComponent(file.name)}`, {
        method: 'POST',
        body: arrayBuffer,
        headers: {
          'Content-Type': 'application/octet-stream'
        }
      });

      const data = await res.json();
      if (!data.success) {
        setDropError(data.message || 'Unknown error');
        return;
      }

      // The endpoint stored the task and returned taskId in data.data.taskId
      const taskId = data.data.taskId;
      // Optionally, we can immediately load the report for this task
      setSelectedTask({ id: taskId, filename: file.name }); // optimistic
      loadTaskReport(taskId);
      // Refresh the task list to include the new task
      loadTasks();
    } catch (err) {
      console.error('Error processing file:', err);
      setDropError('Failed to process file');
    }
  };

  // Drag and drop handlers
  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDropAreaActive(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDropAreaActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDropAreaActive(false);

    const dt = e.dataTransfer;
    const file = dt.files[0];
    if (file) {
      handleFile(file);
    }
  };

  // Click to trigger file input (hidden)
  const handleClick = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.onchange = (e) => {
      const file = e.target.files[0];
      if (file) {
        handleFile(file);
      }
    };
    input.click();
  };

  useEffect(() => {
    loadTasks();
  }, []);

  // Helper to safely parse tags into an array of strings (for non-VT checks)
  const getTagsArray = (tags) => {
    if (!tags) return [];
    if (Array.isArray(tags)) return tags.filter(Boolean);
    if (typeof tags === 'string') {
      try {
        const parsed = JSON.parse(tags);
        return Array.isArray(parsed) ? parsed.filter(Boolean) : [];
      } catch (e) {
        // If tags is not valid JSON, return empty array
        return [];
      }
    }
    return [];
  };

  return (
    <div className="sandbox-tab-shell">
      <header className="sandbox-header">
        <h1>File Hash & Threat Intelligence Checker</h1>
        <p>Drop a file to compute its hash and check against VirusTotal for threats.</p>
      </header>

      <div className="sandbox-main">
        {/* Left Panel - Task List and Controls */}
        <div className="sandbox-left-panel">
          <div className="sandbox-controls">
            <div className="sandbox-input-group">
              <Search className="w-4 h-4" />
              <input
                type="text"
                placeholder="Search files..."
                className="sandbox-search-input"
                value={/* we could add search filter */ ''}
                onChange={/* we could implement */ () => {}}
              />
            </div>

            <div className="sandbox-button-group">
              <button onClick={loadTasks} className="sandbox-btn-secondary">
                <RefreshCw className="w-4 h-4" /> Refresh
              </button>
            </div>
          </div>

          {dropError && (
            <div className="sandbox-error">
              <AlertTriangle className="w-5 h-5" />
              <p>{dropError}</p>
            </div>
          )}

          <div className="sandbox-tasks-panel">
            {loading ? (
              <div className="sandbox-loading">
                <RefreshCw className="w-6 h-6 animate-spin" />
              </div>
            ) : tasks.length === 0 ? (
              <div className="sandbox-empty">
                <Info className="w-6 h-6" />
                <p>No file checks found.</p>
                <p>Drop a file to begin analysis.</p>
              </div>
            ) : (
              <div className="sandbox-task-list">
                {tasks.map(task => {
                  // Determine if this is a VT check by trying to parse tags
                  const tagsArray = getTagsArray(task.tags);
                  const isVTCheck = tagsArray.length > 0 && typeof tagsArray[0] === 'object' && 'detected' in tagsArray[0];
                  const taskType = isVTCheck ? 'VT Check' : 'Sandbox';
                  return (
                    <div
                      key={task.id}
                      onClick={() => {
                        setSelectedTask(task);
                        loadTaskReport(task.id);
                      }}
                      className={`sandbox-task-item ${selectedTask && selectedTask.id === task.id ? 'active' : ''}`}
                    >
                      <div className="sandbox-task-info">
                        <div className="sandbox-task-filename">{task.filename}</div>
                        <div className="sandbox-task-meta">
                          <span className={`sandbox-status-${task.status}`}>
                            {task.status}
                          </span>
                          <span className="sandbox-task-type">{taskType}</span>
                          {task.score !== undefined && (
                            <span className="sandbox-task-score">Score: {task.score}/10</span>
                          )}
                        </div>
                      </div>
                      <div className="sandbox-task-id">{task.id}</div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right Panel - File Drop and Report View */}
        <div className="sandbox-right-panel">
          {/* File Drop Area */}
          <div className="sandbox-drop-panel" onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}>
            {dropAreaActive ? (
              <div className="sandbox-drop-overlay">
                <Upload className="w-8 h-8" />
                <p>Release to check file</p>
              </div>
            ) : (
              <>
                <Upload className="w-10 h-10" />
                <h2>Drop File Here</h2>
                <p>or click to select</p>
                <p className="sandbox-drop-hint">
                  Supported: Any file (will be hashed and checked against VirusTotal)
                </p>
              </>
            )}
            <button onClick={handleClick} className="sandbox-select-btn">
              Select File
            </button>
          </div>

          {/* Report View */}
          <div className="sandbox-report-panel">
            {reportLoading ? (
              <div className="sandbox-loading">
                <RefreshCw className="w-8 h-8 animate-spin" />
              </div>
            ) : !selectedTask ? (
              <div className="sandbox-report-empty">
                <Info className="w-6 h-6" />
                <p>Select a task from the list to view its analysis report.</p>
              </div>
            ) : (
              <div className="sandbox-report-content">
                <div className="sandbox-report-header">
                  <h2>Analysis Report</h2>
                  <div className="sandbox-report-meta">
                    <span>Task ID: {selectedTask.id}</span>
                    <span>File: {selectedTask.filename}</span>
                    <span>Type: {selectedTask.vtResult ? 'VT Check' : 'Sandbox Analysis'}</span>
                    <span>Status: {selectedTask.status}</span>
                  </div>
                </div>

                {selectedTask.vtResult ? (
                  // VT Check Report
                  <>
                    <div className="sandbox-report-section">
                      <h3>file information</h3>
                      <p><strong>Size:</strong> {selectedTask.filesize} bytes</p>
                      <p><strong>MD5:</strong> {selectedTask.md5}</p>
                      <p><strong>SHA256:</strong> {selectedTask.sha256}</p>
                    </div>

                    <div className="sandbox-report-section">
                      <h3>virustotal result</h3>
                      <p>
                        {selectedTask.vtResult.detected ? (
                          <span style={{ color: 'var(--text-error)' }}>malicious</span>
                        ) : (
                          <span style={{ color: 'var(--text-success)' }}>clean</span>
                        )}
                        ({selectedTask.vtResult.maliciouscount} of {selectedTask.vtResult.totalengines} engines detected)
                      </p>
                    </div>

                    <div className="sandbox-report-section">
                      <h3>engine details</h3>
                      <pre className="sandbox-engine-details">
{JSON.stringify(selectedTask.vtResult.stats, null, 2)}
                      </pre>
                    </div>

                    {/* Tags - we can show the summary as a tag */}
                    <div className="sandbox-report-section">
                      <h3>tags</h3>
                      <span className="sandbox-tag">
                        vt result: {selectedTask.vtResult.detected ? 'malicious' : 'clean'} ({selectedTask.vtResult.maliciouscount}/{selectedTask.vtResult.totalengines} engines)
                      </span>
                    </div>

                    {/* mitre techniques detected */}
                    <div className="sandbox-report-section">
                      <h3>mitre techniques detected</h3>
                      {selectedTask && selectedTask.vtResult && selectedTask.vtResult.mitre_techniques && selectedTask.vtResult.mitre_techniques.length > 0
                        ? selectedTask.vtResult.mitre_techniques.map(tech => (
                            <span key={tech} className="sandbox-technique">
                              {tech}
                            </span>
                          ))
                        : <span>no mitre techniques detected.</span>}
                    </div>

                    {/* behavior log (sample) */}
                    <div className="sandbox-report-section">
                      <h3>behavior log (sample)</h3>
                      <pre className="sandbox-behavior-log">
{selectedTask.vtResult.behavior_log || 'No behavior log available.'}
                      </pre>
                    </div>

                    {/* network activity (sample) */}
                    <div className="sandbox-report-section">
                      <h3>network activity (sample)</h3>
                      <pre className="sandbox-network-activity">
{selectedTask.vtResult.network_activity || 'No network activity data.'}
                      </pre>
                    </div>
                  </>
                ) : (
                  // sandbox report (original)
                  <>
                    <div className="sandbox-report-section">
                      <h3>file information</h3>
                      <p><strong>Size:</strong> {selectedTask.filesize || 'N/A'} bytes</p>
                      <p><strong>MD5:</strong> {selectedTask.md5 || 'N/A'}</p>
                      <p><strong>SHA256:</strong> {selectedTask.sha256 || 'N/A'}</p>
                    </div>

                    <div className="sandbox-report-section">
                      <h3>analysis summary</h3>
                      <p>{selectedTask.summary || 'No summary available.'}</p>
                    </div>

                    <div className="sandbox-report-section">
                      <h3>tags</h3>
                      {getTagsArray(selectedTask.tags).map((tag, index) => (
                        <span key={index} className="sandbox-tag">
                          {tag}
                        </span>
                      ))}
                    </div>

                    <div className="sandbox-report-section">
                      <h3>mitre techniques detected</h3>
                      {selectedTask && selectedTask.mitre_techniques ? (
                        (() => {
                          try {
                            const parsed = JSON.parse(selectedTask.mitre_techniques);
                            return Array.isArray(parsed) ? parsed.map((tech, index) => (
                              <span key={index} className="sandbox-technique">
                                {tech}
                              </span>
                            )) : <span>no mitre techniques detected.</span>;
                          } catch (e) {
                            console.warn('failed to parse mitre_techniques as json:', selectedTask.mitre_techniques);
                            return <span>no mitre techniques detected.</span>;
                          }
                        })()
                      ) : (
                        <span>no mitre techniques detected.</span>
                      )}
                    </div>

                    <div className="sandbox-report-section">
                      <h3>behavior log (sample)</h3>
                      <pre className="sandbox-behavior-log">
{selectedTask.behavior_log || 'No behavior log available.'}
                      </pre>
                    </div>

                    <div className="sandbox-report-section">
                      <h3>network activity (sample)</h3>
                      <pre className="sandbox-network-activity">
{selectedTask.network_activity || 'No network activity data.'}
                      </pre>
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}