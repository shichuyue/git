const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");

const PROXY_DIR = path.resolve(__dirname, "..");
const LOGS_DIR = path.join(PROXY_DIR, "logs");
const REALTIME_LOG = path.join(LOGS_DIR, "realtime.jsonl");
const PROXY_PORT = 8080;

let mainWindow = null;
let mitmProcess = null;
let logWatcher = null;

// ---- 自动查找 mitmdump 可执行文件 ----
function findMitmdump() {
  // 优先找用户目录下的 pip 安装路径
  const candidates = [
    path.join(os.homedir(), "AppData", "Local", "Packages",
      "PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0",
      "LocalCache", "local-packages", "Python313", "Scripts", "mitmdump.exe"),
    path.join(os.homedir(), "AppData", "Local", "Programs", "Python", "Python313",
      "Scripts", "mitmdump.exe"),
    path.join(os.homedir(), "AppData", "Roaming", "Python", "Python313",
      "Scripts", "mitmdump.exe"),
    "mitmdump",     // 如果在 PATH 中
    "mitmdump.exe",
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return "mitmdump"; // 回退，如果 PATH 里有也生效
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 750,
    title: "隐私流量拦截代理",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.loadFile("index.html");
  mainWindow.on("closed", () => { mainWindow = null; });
}

function ensureLogDir() {
  if (!fs.existsSync(LOGS_DIR)) {
    fs.mkdirSync(LOGS_DIR, { recursive: true });
  }
}

function startMitmProxy() {
  if (mitmProcess) return;

  ensureLogDir();
  const scriptPath = path.join(PROXY_DIR, "proxy_script.py");
  const mitmdumpPath = findMitmdump();

  sendLog("info", `使用 mitmdump: ${mitmdumpPath}`);

  mitmProcess = spawn(mitmdumpPath, [
    "-s", scriptPath,
    "--listen-port", String(PROXY_PORT),
    "--set", "block_global=false",
  ], {
    cwd: PROXY_DIR,
    windowsHide: true,
    env: { ...process.env },
  });

  mitmProcess.stdout.on("data", (data) => {
    sendLog("info", `[mitm] ${data.toString().trim()}`);
  });

  mitmProcess.stderr.on("data", (data) => {
    sendLog("info", `[mitm] ${data.toString().trim()}`);
  });

  mitmProcess.on("close", (code) => {
    mitmProcess = null;
    stopLogWatcher();
    sendLog("info", `mitmproxy 进程已退出 (code=${code})`);
    if (mainWindow) {
      mainWindow.webContents.send("proxy-status", { running: false });
    }
  });

  mitmProcess.on("error", (err) => {
    mitmProcess = null;
    stopLogWatcher();
    sendLog("error", `启动 mitmproxy 失败: ${err.message}`);
    if (mainWindow) {
      mainWindow.webContents.send("proxy-status", { running: false });
    }
  });

  if (mainWindow) {
    mainWindow.webContents.send("proxy-status", { running: true });
  }
  sendLog("info", `mitmproxy 已启动 (127.0.0.1:${PROXY_PORT})`);

  startLogWatcher();
}

function stopMitmProxy() {
  if (mitmProcess) {
    mitmProcess.kill("SIGTERM");
    mitmProcess = null;
    stopLogWatcher();
    sendLog("info", "mitmproxy 已停止");
    if (mainWindow) {
      mainWindow.webContents.send("proxy-status", { running: false });
    }
  }
}

function startLogWatcher() {
  stopLogWatcher();
  try {
    fs.writeFileSync(REALTIME_LOG, "", { flag: "w" });
  } catch (e) { /* ignore */ }
  let lastSize = 0;
  logWatcher = setInterval(() => {
    try {
      if (!fs.existsSync(REALTIME_LOG)) return;
      const stats = fs.statSync(REALTIME_LOG);
      if (stats.size > lastSize) {
        const fd = fs.openSync(REALTIME_LOG, "r");
        const buffer = Buffer.alloc(stats.size - lastSize);
        fs.readSync(fd, buffer, 0, buffer.length, lastSize);
        fs.closeSync(fd);
        lastSize = stats.size;
        const lines = buffer.toString("utf-8").split("\n").filter(Boolean);
        for (const line of lines) {
          try {
            const entry = JSON.parse(line);
            if (mainWindow) {
              mainWindow.webContents.send("traffic-log", entry);
            }
          } catch (e) { /* skip parse errors */ }
        }
      }
    } catch (e) { /* ignore */ }
  }, 200);
}

function stopLogWatcher() {
  if (logWatcher) {
    clearInterval(logWatcher);
    logWatcher = null;
  }
}

function sendLog(level, message) {
  if (mainWindow) {
    mainWindow.webContents.send("app-log", {
      timestamp: new Date().toISOString(),
      level,
      message,
    });
  }
}

// ---- IPC handlers ----

ipcMain.handle("proxy:start", () => {
  startMitmProxy();
  return { ok: true };
});

ipcMain.handle("proxy:stop", () => {
  stopMitmProxy();
  return { ok: true };
});

ipcMain.handle("proxy:status", () => {
  return { running: mitmProcess !== null };
});

// ---- App lifecycle ----

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  stopMitmProxy();
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  stopMitmProxy();
});
