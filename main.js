const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require("path");
const { spawn } = require("child_process");

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });
  mainWindow.loadFile("index.html");
}

app.whenReady().then(createWindow);

ipcMain.on("download-request", async (event, classroomLink) => {
  try {
    // ask where to save
    const output = dialog.showOpenDialogSync(mainWindow, {
      properties: ["openDirectory"],
      title: "Select output folder"
    });
    if (!output || !output[0]) {
      event.reply("download-complete", { success: false, error: "No folder selected" });
      return;
    }
    const outDir = output[0];

    // spawn python downloader.py
    const python = "python"; // ensure python on PATH
    const downloaderPath = path.join(process.cwd(),'resources','app.asar.unpacked','resources', "downloader.py");

    // Set USER_DATA_PATH so python saves token.json to a safe place
    const env = Object.assign({}, process.env);
    env.USER_DATA_PATH = app.getPath("userData");

    const child = spawn(python, [downloaderPath, classroomLink, outDir], { env });

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (data) => {
      // data may contain multiple lines
      const lines = data.toString().split(/\r?\n/).filter(Boolean);
      lines.forEach((line) => {
        console.log("py:", line);
        // Progress lines: OverallProgress: 12% for <name> (File i/total)
        const m = line.match(/^OverallProgress:\s*(\d+)%\s*for\s*(.+)\s*\(File\s*(\d+)\/(\d+)\)/i);
        if (m) {
          const percent = parseInt(m[1], 10);
          const file = m[2];
          const current = parseInt(m[3], 10);
          const total = parseInt(m[4], 10);
          mainWindow.webContents.send("download-progress", { percent, file, current, total });
        }
        // final success
        const ok = line.match(/^DOWNLOAD_SUCCESS::(.+)$/);
        if (ok) {
          const saved = ok[1];
          event.reply("download-complete", { success: true, path: saved });
        }
        // distributed total (optionally)
        const distributed = line.match(/^DISTRIBUTED_TOTAL::(\d+)/);
        if (distributed) {
          mainWindow.webContents.send("total-files", { total: parseInt(distributed[1], 10) });
        }
      });
    });

    child.stderr.on("data", (data) => {
      console.error("py err:", data.toString());
      mainWindow.webContents.send("download-error", { msg: data.toString() });
    });

    child.on("close", (code) => {
      if (code !== 0) {
        event.reply("download-complete", { success: false, error: `Python exited ${code}` });
      }
    });

  } catch (err) {
    event.reply("download-complete", { success: false, error: err.message });
  }
});
