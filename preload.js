const { contextBridge, ipcRenderer } = require("electron");

/* This is the ENTIRE surface the renderer (the web page) can touch on the
   Node/OS side. Notice there is no "runArbitraryCommand" or "fetchAnyUrl" —
   only these five fixed, purpose-built calls. Even if the page's JS were
   ever compromised via an injection bug, this is the hard ceiling on what
   it could do to the host machine. */

contextBridge.exposeInMainWorld("prismAPI", {

    callApi: (serviceId, params) => ipcRenderer.invoke("prism:call-api", serviceId, params),

    runDiag: (commandId, target) => ipcRenderer.invoke("prism:run-diag", commandId, target),

    vaultExists: () => ipcRenderer.invoke("prism:vault-exists"),

    vaultStatus: () => ipcRenderer.invoke("prism:vault-status"),

    vaultCreate: (password) => ipcRenderer.invoke("prism:vault-create", password),

    vaultUnlock: (password) => ipcRenderer.invoke("prism:vault-unlock", password),

    vaultLock: () => ipcRenderer.invoke("prism:vault-lock"),

    vaultSaveKey: (serviceId, key) => ipcRenderer.invoke("prism:vault-save-key", serviceId, key),

    vaultDeleteKey: (serviceId) => ipcRenderer.invoke("prism:vault-delete-key", serviceId),

    vaultKeyStatus: () => ipcRenderer.invoke("prism:vault-key-status"),

    vaultExport: () => ipcRenderer.invoke("prism:vault-export"),

    vaultImport: () => ipcRenderer.invoke("prism:vault-import"),

    hasUsers: () => ipcRenderer.invoke("prism:has-users"),

    getUsers: () => ipcRenderer.invoke("prism:get-users"),

    createUser: (data) => ipcRenderer.invoke("prism:create-user", data),

    login: (data) => ipcRenderer.invoke("prism:login", data),

    updateUser: (data) => ipcRenderer.invoke("prism:update-user", data),

    deleteUser: (data) => ipcRenderer.invoke("prism:delete-user", data),

    getSystemStats: () => ipcRenderer.invoke("prism:get-system-stats")

});
