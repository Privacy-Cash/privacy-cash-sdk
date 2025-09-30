export async function getStorageInstance(): Promise<Storage> {
    if (typeof window !== "undefined" && window.localStorage) {
        // for web browser
        return window.localStorage;
    } else {
        // for Node
        if (!localStorage) {
            const { LocalStorage, path } = await import("./node-shim.js");
            localStorage = new LocalStorage(path.join(process.cwd(), "cache"));
            return localStorage
        }
        return localStorage
    }
}
