const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("proxyAPI", {
  start: () => ipcRenderer.invoke("proxy:start"),
  stop: () => ipcRenderer.invoke("proxy:stop"),
  getStatus: () => ipcRenderer.invoke("proxy:status"),
  onProxyStatus: (callback) => {
    ipcRenderer.on("proxy-status", (_event, data) => callback(data));
  },
  onTrafficLog: (callback) => {
    ipcRenderer.on("traffic-log", (_event, data) => callback(data));
  },
  onAppLog: (callback) => {
    ipcRenderer.on("app-log", (_event, data) => callback(data));
  },
});
