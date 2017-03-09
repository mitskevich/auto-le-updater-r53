declare module 'greenlock' {
    type ChallengeType = "http-01" | "tls-sni-01" | "dns-01";

    const productionServerUrl: string;
    const stagingServerUrl: string;
    const rsaKeySize: number;
    const challengeType: ChallengeType;
    const challengeTypes: ChallengeType[];
    const acmeChallengePrefix: string;

    interface Args {
        test?: string;
        acmeChallengeDns: string;
    }

    interface Challenge {
        set: (args: Args, domain: string, challenge: string, keyAuthorization: string,
            cb: () => void) => void;
        get: (defaults: Args, domain: string, challenge: string, cb: () => void) => void;
        remove: (args: Args, domain: string, challenge: string, cb: () => void) => void;
    }

    interface Store {
        getOptions: () => any;
    }

    interface LetsEncryptOptions {
        server: "staging" | "production" | string;
        store?: Store;
        challenges?: { [name: string]: Challenge };
        challengeType?: ChallengeType;
        agreeToTerms?: (
            opts: AgreeOptions,
            cb: (err: Error | null | undefined, url: string) => undefined) => undefined;
        debug?: boolean;
        log?: (debug: boolean, ...msgs: string[]) => void;
    }

    interface AgreeOptions {
        email: string;
        domains: string[];
        tosUrl: string;
    }

    interface RegisterOptions {
        domains: string[],
        email: string,
        agreeTos?: boolean|string,
        rsaKeySize?: number;
        challengeType?: ChallengeType;
        duplicate?: boolean;
    }

    interface Certificate {
        privKey: string;
        cert: string;
        chain: string;
        issuedAt: number;
        expiresAt: number;
        subject: string;
        altnames: string[];
    }

    interface LetsEncrypt {
        register: (opts: RegisterOptions) => Promise<Certificate>;
        check: (opts: { domains: string[] }) => Promise<Certificate>;
        renew: (opts: RegisterOptions, cert: Certificate) => Promise<Certificate>;
    }

    function create(opts: LetsEncryptOptions): LetsEncrypt;
}
