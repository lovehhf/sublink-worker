import { parseServerInfo, parseUrlParams, createTlsConfig, createTransportConfig, parseBool, decodeBase64 } from '../../utils.js';

export function parseVless(url) {
    const { addressPart, params, name } = parseUrlParams(url);

    let actualAddress = addressPart;
    let isQuantumultX = false;

    // QuantumultX VLESS format encodes the address as base64 (no '@' visible in URL)
    // Decoded form: ":uuid@host:port"
    if (!addressPart.includes('@')) {
        try {
            const decoded = decodeBase64(addressPart);
            if (decoded.includes('@')) {
                actualAddress = decoded;
                isQuantumultX = true;
            }
        } catch (_) { }
    }

    const atIndex = actualAddress.indexOf('@');
    const userPart = atIndex >= 0 ? actualAddress.slice(0, atIndex) : actualAddress;
    const serverPart = atIndex >= 0 ? actualAddress.slice(atIndex + 1) : '';
    // Strip leading ':' present in QuantumultX format
    const uuid = userPart.startsWith(':') ? userPart.slice(1) : userPart;
    const { host, port } = parseServerInfo(serverPart);

    // Normalize QuantumultX-specific params to standard form before TLS config creation
    if (isQuantumultX) {
        // tls=1 signals TLS; presence of pbk means Reality
        if (params.tls === '1' && !params.security) {
            params.security = params.pbk ? 'reality' : 'tls';
        }
        // peer= is the SNI field in QuantumultX
        if (params.peer && !params.sni) {
            params.sni = params.peer;
        }
    }

    const tls = createTlsConfig(params);
    if (tls.reality) {
        tls.utls = {
            enabled: true,
            fingerprint: 'chrome'
        };
    }
    const transport = params.type && params.type !== 'tcp' ? createTransportConfig(params) : undefined;

    // Parse UDP setting - primarily used for Clash output
    // In sing-box, UDP is controlled by 'network' field, but we preserve this for Clash compatibility
    const udp = params.udp !== undefined ? parseBool(params.udp) : undefined;

    // QuantumultX uses 'xtls' param for flow: 1=xtls-rprx-direct, 2=xtls-rprx-vision
    let flow = params.flow;
    if (!flow && params.xtls) {
        const xtlsFlowMap = { '1': 'xtls-rprx-direct', '2': 'xtls-rprx-vision' };
        flow = xtlsFlowMap[params.xtls];
    }

    // QuantumultX puts the proxy name in 'remarks' param instead of URL fragment
    const proxyName = name || params.remarks || '';

    return {
        type: 'vless',
        tag: proxyName,
        server: host,
        server_port: port,
        uuid: decodeURIComponent(uuid),
        tcp_fast_open: false,
        tls,
        transport,
        network: 'tcp',
        flow: flow ?? undefined,
        // Include udp if explicitly specified - will be used for Clash output
        // SingBoxConfigBuilder will strip this field for sing-box output
        ...(udp !== undefined ? { udp } : {})
    };
}
