declare module 'le-store-certbot' {
    import {Store} from "greenlock";

    interface Opts {
        configDir?: string;
        logsDir?: string;
        workDir?: string;

        accountsDir?: string;
        renewalPath?: string;
        renewalDir?: string;

        privkeyPath?: string;
        fullchainPath?: string;
        certPath?: string;
        chainPath?: string;

        webrootPath?: string;
        rsaKeySize?: number;
        debug?: boolean;
    }

    interface CertbotStore extends Store {
        getOptions: () => Opts;
    }

    function create(opts: Opts): CertbotStore;
}
