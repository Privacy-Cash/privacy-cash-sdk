// log level
export type LogLevel = "debug" | "info" | "warn" | "error";

export type LoggerFn = (level: LogLevel, message: string) => void;

const defaultLogger: LoggerFn = (level, message) => {
    const prefix = `[${level.toUpperCase()}]`;
    console.log(prefix, message);
};

let userLogger: LoggerFn = defaultLogger;

export function setLogger(logger: LoggerFn) {
    userLogger = logger;
}

function argToStr(args: unknown[]) {
    return args.map(arg => {
        if (typeof arg === "object" && arg !== null) {
            try {
                return JSON.stringify(arg);
            } catch {
                return String(arg);
            }
        }
        return String(arg);
    }).join(" ");
}
export const logger = {
    debug: (...args: unknown[]) => {
        userLogger('debug', argToStr(args))
    },
    info: (...args: unknown[]) => {
        userLogger('info', argToStr(args))
    },
    warn: (...args: unknown[]) => {
        userLogger('warn', argToStr(args))
    },
    error: (...args: unknown[]) => {
        userLogger('error', argToStr(args))
    },
}