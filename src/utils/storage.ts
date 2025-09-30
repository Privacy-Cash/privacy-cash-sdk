export async function getStorageInstance(): Promise<Storage> {
    if (typeof window !== "undefined" && typeof window.localStorage !== "undefined") {
        // web browser
        return window.localStorage;
    } else if (typeof process !== "undefined" && process.versions?.node) {
        // Node runtime
        if (!localStorage) {
            const { LocalStorage, path } = await import("./node-shim.js");
            localStorage = new LocalStorage(path.join(process.cwd(), "cache"));
        }
        return localStorage;
    } else {
        throw new Error("Unknown environment: cannot determine storage");
    }
}