declare module 'winston-mail' {
    import { TransportInstance } from "winston";

    interface Options {
        to: string | string[];
        from?: string | string[];
        host?: string;
        port?: number;
        username?: string;
        password?: string;
        subject?: string;
        ssl?: boolean | { key: string, ca: string, cert: string };
        tls?: boolean;
        level?: string;
        unique?: boolean;
        silent?: boolean;
        html?: boolean;
        timeout?: number;
        authentication?: "PLAIN" | "CRAM-MD5" | "LOGIN" | "XOAUTH2";
        formatter?: (data: { level: string, message: string, meta: any }) => string;
    }

    interface MailInstance extends TransportInstance {
        new (options: Options): MailInstance;
    }

    const Mail: MailInstance;
}