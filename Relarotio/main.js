// main.js
const { app, BrowserWindow, dialog, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs'); // Módulo Node.js para acesso ao sistema de arquivos

function createWindow () {
  // Cria a janela do navegador.
  const win = new BrowserWindow({
    width: 1200, // Largura padrão
    height: 900, // Altura padrão
    minWidth: 900, // Largura mínima permitida
    minHeight: 700, // Altura mínima permitida
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true, // Importante para segurança
      nodeIntegration: false // Desabilita nodeIntegration no renderizador para segurança
    },
    icon: path.join(__dirname, 'assets/icon.png') // Define o ícone do aplicativo (ajuste o caminho se necessário)
  });

  // Carrega o arquivo index.html do seu aplicativo.
  win.loadFile('index.html');

  // Opcional: Abre as ferramentas de desenvolvedor (para depuração).
  // win.webContents.openDevTools();
}

// Este método será chamado quando o Electron terminar a inicialização
// e estiver pronto para criar janelas do navegador.
app.whenReady().then(() => {
  createWindow();

  // No macOS, é comum recriar uma janela no aplicativo quando o
  // ícone do dock é clicado e não há outras janelas abertas.
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Sai do aplicativo quando todas as janelas são fechadas, exceto no macOS.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// --- Comunicação entre Processos (IPC) ---
// Handler para a função de exportar relatório
// Esta função é chamada do `index.html` (processo de renderização) via `preload.js`
ipcMain.handle('export-file', async (event, content) => {
    try {
        // Abre uma caixa de diálogo para o usuário escolher onde salvar o arquivo
        const { filePath } = await dialog.showSaveDialog({
            title: 'Exportar Relatório CyberReporter',
            defaultPath: `relatorio-cyberreporter-${Date.now()}.txt`, // Nome de arquivo sugerido
            filters: [
                { name: 'Arquivos de Texto', extensions: ['txt'] },
                { name: 'Todos os Arquivos', extensions: ['*'] }
            ]
        });

        // Se o usuário selecionou um caminho, escreve o conteúdo no arquivo
        if (filePath) {
            fs.writeFileSync(filePath, content); // Usa o módulo Node.js 'fs' para salvar o arquivo
            return { success: true, message: 'Relatório exportado com sucesso!' };
        }
        return { success: false, message: 'Exportação cancelada.' };
    } catch (error) {
        console.error('Erro ao exportar arquivo:', error);
        return { success: false, message: `Erro ao exportar: ${error.message}` };
    }
});