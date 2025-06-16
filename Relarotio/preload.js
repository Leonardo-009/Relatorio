// preload.js
const { contextBridge, ipcRenderer } = require('electron');

// Expõe a API 'api' para o contexto global da janela (window.api)
// Isso permite que o seu script no index.html (processo de renderização)
// chame funções do Node.js (seguramente) através do ipcRenderer.
contextBridge.exposeInMainWorld('api', {
    // A função `exportFile` é uma interface para chamar o handler `export-file`
    // que está definido no `main.js`.
    exportFile: (content) => ipcRenderer.invoke('export-file', content),
    // Você pode adicionar outras funções aqui se precisar que o frontend acesse mais recursos do Node.js/Electron.
});