"""
隐私流量拦截代理 - Web 管理界面 (Flask)
替代 Electron 方案，无需 Node.js，Flask 已随 mitmproxy 安装。
"""
import json
import os
import subprocess
import sys
import threading
import time

import flask

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
REALTIME_LOG = os.path.join(LOGS_DIR, "realtime.jsonl")
PROXY_PORT = 8080
WEB_PORT = 8090

app = flask.Flask(__name__)

mitm_process = None
process_lock = threading.Lock()
latest_stats = {"total": 0, "blocked": 0, "ua_masked": 0, "headers_cleaned": 0, "cookies_filtered": 0}


def _free_port(port):
    """释放指定端口上残留的进程"""
    try:
        result = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )
        for line in result.stdout.splitlines():
            if f":{port} " in line and "LISTENING" in line:
                parts = line.strip().split()
                pid = parts[-1]
                subprocess.run(["taskkill", "/F", "/PID", pid],
                               capture_output=True,
                               creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    except Exception:
        pass


def _find_mitmdump():
    """尝试多个路径查找 mitmdump.exe"""
    candidates = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""),
                     "Packages", "PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0",
                     "LocalCache", "local-packages", "Python313", "Scripts", "mitmdump.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""),
                     "Packages", "PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0",
                     "LocalCache", "local-packages", "Python312", "Scripts", "mitmdump.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python313", "Scripts", "mitmdump.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Python", "Python312", "Scripts", "mitmdump.exe"),
        os.path.join("C:", os.sep, "Python313", "Scripts", "mitmdump.exe"),
        "mitmdump",
        "mitmdump.exe",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return "mitmdump"


def _read_logs(since_pos=0):
    """读取实时日志文件，返回 (新行列表, 文件末尾位置)"""
    if not os.path.exists(REALTIME_LOG):
        return [], 0
    with open(REALTIME_LOG, "r", encoding="utf-8") as f:
        f.seek(since_pos)
        lines = f.readlines()
        new_pos = f.tell()
    parsed = []
    for line in lines:
        line = line.strip()
        if line:
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return parsed, new_pos


# ---- 前端页面 (内嵌 HTML) ----
INDEX_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>隐私流量拦截代理</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      background: #0f1923; color: #d1d5db; display: flex; flex-direction: column; height: 100vh; overflow: hidden;
    }
    header {
      background: #1a2632; padding: 14px 24px; display: flex; align-items: center; justify-content: space-between;
      border-bottom: 1px solid #2a3a4a; flex-shrink: 0;
    }
    header h1 { font-size: 16px; font-weight: 600; color: #e5e7eb; }
    header h1 span { color: #6366f1; }
    .header-right { display: flex; align-items: center; gap: 14px; }
    .status-indicator { display: flex; align-items: center; gap: 6px; font-size: 13px; }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; background: #6b7280; transition: background .3s; }
    .status-dot.running { background: #22c55e; box-shadow: 0 0 6px #22c55e88; }
    .btn { padding: 7px 18px; border: none; border-radius: 6px; font-size: 13px; font-weight: 500; cursor: pointer; }
    .btn:disabled { opacity: .4; cursor: not-allowed; }
    .btn-start { background: #22c55e; color: #000; }
    .btn-start:hover:not(:disabled) { background: #16a34a; }
    .btn-stop { background: #ef4444; color: #fff; }
    .btn-stop:hover:not(:disabled) { background: #dc2626; }
    .stats-bar {
      display: flex; gap: 20px; padding: 10px 24px; background: #141f2b;
      border-bottom: 1px solid #1e2d3d; flex-shrink: 0; flex-wrap: wrap;
    }
    .stat-item { display: flex; align-items: center; gap: 6px; font-size: 13px; }
    .stat-item .num { font-weight: 700; font-variant-numeric: tabular-nums; color: #e5e7eb; min-width: 32px; }
    .stat-item .label { color: #9ca3af; }
    .stat-item .num.blocked { color: #ef4444; }
    .stat-item .num.masked { color: #6366f1; }
    .stat-item .num.cleaned { color: #f59e0b; }
    .stat-item .num.passed { color: #22c55e; }
    .main-content { display: flex; flex: 1; min-height: 0; }
    .traffic-panel { flex: 1; display: flex; flex-direction: column; min-width: 0; }
    .panel-header {
      padding: 8px 16px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px;
      color: #6b7280; background: #121c28; border-bottom: 1px solid #1e2d3d; flex-shrink: 0; display: flex; justify-content: space-between;
    }
    .panel-header .clear-btn { background: none; border: none; color: #6b7280; cursor: pointer; font-size: 12px; }
    .panel-header .clear-btn:hover { color: #e5e7eb; }
    .log-list {
      flex: 1; overflow-y: auto; padding: 4px 0;
      font-family: "SF Mono", "Cascadia Code", "Fira Code", Consolas, monospace; font-size: 12px;
    }
    .log-list::-webkit-scrollbar { width: 6px; }
    .log-list::-webkit-scrollbar-thumb { background: #2a3a4a; border-radius: 3px; }
    .log-entry {
      padding: 3px 16px; display: flex; gap: 10px; align-items: baseline;
      line-height: 1.5; border-bottom: 1px solid #0d1722;
    }
    .log-entry:hover { background: #1a2632; }
    .log-entry .method { font-weight: 600; color: #60a5fa; min-width: 48px; }
    .log-entry .action { font-weight: 700; min-width: 52px; text-align: center; }
    .log-entry .action.block { color: #ef4444; }
    .log-entry .action.pass { color: #22c55e; }
    .log-entry .host { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #d1d5db; }
    .log-entry .status { min-width: 32px; text-align: right; color: #9ca3af; }
    .log-entry .time { color: #4b5563; min-width: 70px; text-align: right; font-size: 11px; }
    .app-log-panel { width: 280px; display: flex; flex-direction: column; flex-shrink: 0; }
    .app-log-list {
      flex: 1; overflow-y: auto; padding: 4px 0;
      font-family: "SF Mono", "Cascadia Code", Consolas, monospace; font-size: 11px;
    }
    .app-log-list::-webkit-scrollbar { width: 6px; }
    .app-log-list::-webkit-scrollbar-thumb { background: #2a3a4a; border-radius: 3px; }
    .app-log-entry { padding: 2px 12px; color: #9ca3af; line-height: 1.6; border-bottom: 1px solid #0d1722; }
    .app-log-entry .al-time { color: #4b5563; margin-right: 6px; }
    .app-log-entry .al-error { color: #ef4444; }
    .app-log-entry .al-info { color: #9ca3af; }
    .empty-state { display: flex; align-items: center; justify-content: center; height: 100%; color: #4b5563; font-size: 13px; }
  </style>
</head>
<body>
  <header>
    <h1><span>隐私流量拦截代理</span></h1>
    <div class="header-right">
      <div class="status-indicator">
        <span class="status-dot" id="statusDot"></span>
        <span id="statusText">未启动</span>
      </div>
      <button class="btn btn-start" id="btnStart">启动代理</button>
      <button class="btn btn-stop" id="btnStop" disabled>停止代理</button>
    </div>
  </header>
  <div class="stats-bar">
    <div class="stat-item"><span class="num" id="statTotal">0</span><span class="label">请求总数</span></div>
    <div class="stat-item"><span class="num blocked" id="statBlocked">0</span><span class="label">已拦截</span></div>
    <div class="stat-item"><span class="num masked" id="statUA">0</span><span class="label">UA伪装</span></div>
    <div class="stat-item"><span class="num cleaned" id="statHeaders">0</span><span class="label">去头</span></div>
    <div class="stat-item"><span class="num passed" id="statCookies">0</span><span class="label">Cookie过滤</span></div>
  </div>
  <div class="main-content">
    <div class="traffic-panel">
      <div class="panel-header">
        <span>实时流量日志</span>
        <button class="clear-btn" id="clearLogs">清空</button>
      </div>
      <div class="log-list" id="logList"><div class="empty-state">启动代理后，流量日志将在此显示</div></div>
    </div>
    <div class="app-log-panel">
      <div class="panel-header">系统日志</div>
      <div class="app-log-list" id="appLogList"><div class="empty-state">---</div></div>
    </div>
  </div>
  <script>
    let logPos = 0;
    let logInterval = null;
    let statusInterval = null;

    async function api(url, method) {
      const res = await fetch(url, { method: method || "GET" });
      return res.json();
    }

    async function updateStatus() {
      const data = await api("/api/status");
      const running = data.running;
      document.getElementById("statusDot").className = "status-dot" + (running ? " running" : "");
      document.getElementById("statusText").textContent = running ? "运行中 (127.0.0.1:8080)" : "未启动";
      document.getElementById("btnStart").disabled = running;
      document.getElementById("btnStop").disabled = !running;
    }

    async function startProxy() {
      document.getElementById("btnStart").disabled = true;
      const res = await api("/api/start", "POST");
      if (res.error) addAppLog("error", res.error);
      await updateStatus();
    }

    async function stopProxy() {
      await api("/api/stop", "POST");
      await updateStatus();
    }

    function addLogEntry(entry) {
      const list = document.getElementById("logList");
      if (list.querySelector(".empty-state")) list.innerHTML = "";
      const div = document.createElement("div");
      div.className = "log-entry";
      const time = entry.timestamp ? entry.timestamp.slice(11, 19) : "";
      const actionCls = entry.action === "BLOCK" ? "block" : "pass";
      div.innerHTML = '<span class="method">' + entry.method + '</span>' +
        '<span class="action ' + actionCls + '">' + entry.action + '</span>' +
        '<span class="host" title="' + entry.host + '">' + entry.host + '</span>' +
        '<span class="status">' + (entry.status || "-") + '</span>' +
        '<span class="time">' + time + '</span>';
      list.appendChild(div);
      list.scrollTop = list.scrollHeight;
      while (list.childElementCount > 500) list.removeChild(list.firstChild);
    }

    function addAppLog(level, msg) {
      const list = document.getElementById("appLogList");
      if (list.querySelector(".empty-state")) list.innerHTML = "";
      const div = document.createElement("div");
      div.className = "app-log-entry";
      const t = new Date().toISOString().slice(11, 19);
      div.innerHTML = '<span class="al-time">' + t + '</span><span class="al-' + level + '">' + msg + '</span>';
      list.appendChild(div);
      list.scrollTop = list.scrollHeight;
      while (list.childElementCount > 200) list.removeChild(list.firstChild);
    }

    async function pollLogs() {
      try {
        const res = await fetch("/api/logs?pos=" + logPos);
        const data = await res.json();
        logPos = data.pos;
        for (const entry of data.logs) addLogEntry(entry);
        if (data.stats) {
          const s = data.stats;
          document.getElementById("statTotal").textContent = s.total || 0;
          document.getElementById("statBlocked").textContent = s.blocked || 0;
          document.getElementById("statUA").textContent = s.ua_masked || 0;
          document.getElementById("statHeaders").textContent = s.headers_cleaned || 0;
          document.getElementById("statCookies").textContent = s.cookies_filtered || 0;
        }
      } catch(e) {}
    }

    window.onload = function() {
      updateStatus();
      logInterval = setInterval(pollLogs, 300);
      statusInterval = setInterval(updateStatus, 2000);
      document.getElementById("btnStart").onclick = startProxy;
      document.getElementById("btnStop").onclick = stopProxy;
      document.getElementById("clearLogs").onclick = function() {
        document.getElementById("logList").innerHTML = '<div class="empty-state">日志已清空</div>';
      };
      addAppLog("info", "应用已加载，点击启动代理开始拦截");
    };
  </script>
</body>
</html>"""


# ---- API routes ----

@app.route("/")
def index():
    return flask.render_template_string(INDEX_HTML)


@app.route("/api/status", methods=["GET"])
def status():
    global mitm_process, latest_stats
    running = mitm_process is not None and mitm_process.poll() is None
    if mitm_process is not None and mitm_process.poll() is not None:
        mitm_process = None
        running = False
    return flask.jsonify({"running": running, "stats": latest_stats})


@app.route("/api/start", methods=["POST"])
def start_proxy():
    global mitm_process
    with process_lock:
        if mitm_process and mitm_process.poll() is None:
            return flask.jsonify({"ok": True, "message": "already running"})

        # 释放旧端口
        _free_port(PROXY_PORT)

        os.makedirs(LOGS_DIR, exist_ok=True)
        try:
            with open(REALTIME_LOG, "w") as f:
                f.write("")
        except OSError:
            pass

        mitmdump_path = _find_mitmdump()
        script_path = os.path.join(BASE_DIR, "proxy_script.py")

        import shutil
        if not os.path.exists(mitmdump_path) and mitmdump_path in ("mitmdump", "mitmdump.exe"):
            if not shutil.which(mitmdump_path):
                return flask.jsonify({"ok": False, "error": "mitmdump not found"}), 500

        try:
            startup_info = None
            if sys.platform == "win32":
                startup_info = subprocess.STARTUPINFO()
                startup_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startup_info.wShowWindow = 0

            mitm_process = subprocess.Popen(
                [mitmdump_path, "-s", script_path,
                 "--listen-port", str(PROXY_PORT), "--set", "block_global=false"],
                cwd=BASE_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                startupinfo=startup_info,
            )
            time.sleep(1)
            if mitm_process.poll() is not None:
                return flask.jsonify({
                    "ok": False,
                    "error": "mitmdump 启动后立即退出，请检查端口 8080 是否被占用"
                }), 500
            return flask.jsonify({"ok": True, "message": "proxy started"})
        except FileNotFoundError as e:
            return flask.jsonify({"ok": False, "error": f"启动失败: {e}"}), 500


@app.route("/api/stop", methods=["POST"])
def stop_proxy():
    global mitm_process
    with process_lock:
        if mitm_process and mitm_process.poll() is None:
            mitm_process.terminate()
            try:
                mitm_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                mitm_process.kill()
                mitm_process.wait(timeout=3)
            mitm_process = None
    return flask.jsonify({"ok": True})


@app.route("/api/logs")
def get_logs():
    global latest_stats
    pos = flask.request.args.get("pos", 0, type=int)
    logs, new_pos = _read_logs(pos)
    for entry in logs:
        if "total" in entry:
            latest_stats["total"] = entry["total"]
        if "blocked" in entry:
            latest_stats["blocked"] = entry["blocked"]
        if "ua_masked" in entry:
            latest_stats["ua_masked"] = entry["ua_masked"]
        if "headers_cleaned" in entry:
            latest_stats["headers_cleaned"] = entry["headers_cleaned"]
        if "cookies_filtered" in entry:
            latest_stats["cookies_filtered"] = entry["cookies_filtered"]
        if entry.get("action") == "BLOCK":
            latest_stats["blocked"] = latest_stats.get("blocked", 0) + 1
    return flask.jsonify({"logs": logs, "pos": new_pos, "stats": latest_stats})


if __name__ == "__main__":
    print("隐私流量拦截代理 Web 界面启动中...")
    print(f"打开浏览器访问 http://127.0.0.1:{WEB_PORT}")
    print(f"确保系统代理已设置为 127.0.0.1:{PROXY_PORT}")
    app.run(host="127.0.0.1", port=WEB_PORT, debug=False, threaded=True)
