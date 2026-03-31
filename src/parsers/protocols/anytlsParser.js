import { parseServerInfo, parseUrlParams, parseBool } from '../../utils.js';

export function parseAnytls(url) {
    const { addressPart, params, name } = parseUrlParams(url);

    const atIndex = addressPart.indexOf('@');
    const password = atIndex >= 0 ? addressPart.slice(0, atIndex) : addressPart;
    const serverPart = atIndex >= 0 ? addressPart.slice(atIndex + 1) : '';
    const { host, port } = parseServerInfo(serverPart);

    // peer= is the QuantumultX/legacy SNI field; sni= is the standard one
    const serverName = params.sni || params.peer;
    const insecure = params.insecure !== undefined
        ? parseBool(params.insecure)
        : (params['skip-cert-verify'] !== undefined ? parseBool(params['skip-cert-verify']) : false);

    const tls = {
        enabled: true,
        server_name: serverName,
        insecure: !!insecure
    };

    const proxyName = name || params.remarks || '';

    return {
        type: 'anytls',
        tag: proxyName,
        server: host,
        server_port: port,
        password: decodeURIComponent(password),
        tls
    };
}
