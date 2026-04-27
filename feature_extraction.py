from collections import deque

import pandas as pd
from nfstream import NFStreamer
from scapy.all import IP, TCP, UDP, Raw, PcapReader


PROTOCOL_MAP = {
    6:   'tcp',
    17:  'udp',
    1:   'icmp',
    58:  'icmpv6',
    41:  'ipv6',
    132: 'sctp',
    2:   'igmp',
    47:  'gre',
    50:  'esp',
    89:  'ospf',
}

PORT_TO_SERVICE = {
    80:   'http',
    443:  'https',
    8080: 'http',
    21:   'ftp',
    20:   'ftp-data',
    22:   'ssh',
    53:   'dns',
    25:   'smtp',
    110:  'pop3',
    143:  'imap',
    23:   'telnet',
    3306: 'mysql',
    5432: 'postgres',
    6667: 'irc',
    161:  'snmp',
    67:   'dhcp',
    68:   'dhcp',
    123:  'ntp',
    137:  'netbios',
    138:  'netbios',
    139:  'netbios',
    445:  'smb',
    3389: 'rdp',
    5060: 'sip',
}


def load_pcap(pcap_path: str) -> pd.DataFrame:
    streamer = NFStreamer(source=pcap_path, statistical_analysis=True)
    df = streamer.to_pandas()
    df = df.sort_values('bidirectional_first_seen_ms').reset_index(drop=True)
    return df



def extract_basic_features(df: pd.DataFrame) -> pd.DataFrame:
    raw_df = pd.DataFrame()

    raw_df['dur']    = df['bidirectional_duration_ms'] / 1000
    raw_df['spkts']  = df['src2dst_packets']
    raw_df['dpkts']  = df['dst2src_packets']
    raw_df['sbytes'] = df['src2dst_bytes']
    raw_df['dbytes'] = df['dst2src_bytes']
    raw_df['sload']  = (df['src2dst_bytes'] * 8) / (df['src2dst_duration_ms'] / 1000)
    raw_df['dload']  = (df['dst2src_bytes'] * 8) / (df['dst2src_duration_ms'] / 1000)
    raw_df['sloss']  = df['src2dst_rst_packets']
    raw_df['dloss']  = df['dst2src_rst_packets']
    raw_df['sinpkt'] = df['src2dst_mean_piat_ms'] / 1000
    raw_df['smean']  = df['src2dst_mean_ps']
    raw_df['dmean']  = df['dst2src_mean_ps']

    raw_df['proto']  = df['protocol'].map(PROTOCOL_MAP).fillna(df['protocol'].astype(str))

    raw_df['service'] = df['dst_port'].map(PORT_TO_SERVICE)
    mask = raw_df['service'].isna()
    raw_df.loc[mask, 'service'] = df.loc[mask, 'src_port'].map(PORT_TO_SERVICE)
    raw_df['service'] = raw_df['service'].fillna('-')

    raw_df['state'] = df.apply(_get_state, axis=1)

    raw_df['is_sm_ips_ports'] = (
        (df['src_ip'] == df['dst_ip']) | (df['src_port'] == df['dst_port'])
    ).astype(int)

    return raw_df


def _get_state(row) -> str:
    proto = row['protocol']
    if proto == 6:
        has_rst = (row['src2dst_rst_packets'] > 0 or row['dst2src_rst_packets'] > 0)
        has_fin = (row['src2dst_fin_packets'] > 0 and row['dst2src_fin_packets'] > 0)
        has_syn = (row['src2dst_syn_packets'] > 0)
        if has_rst:
            return 'RST'
        elif has_fin:
            return 'FIN'
        elif has_syn:
            return 'INT'
        else:
            return 'CON'
    elif proto == 17:
        if row['src2dst_packets'] > 0 and row['dst2src_packets'] > 0:
            return 'CON'
        else:
            return 'REQ'
    elif proto in (1, 58):
        return 'ECO'
    else:
        return 'URN'


def _single_pcap_pass(pcap_path: str) -> dict:
    sttl_map          = {}
    dttl_map          = {}
    swin_map          = {}
    dwin_map          = {}
    syn_time          = {}
    synack_time       = {}
    ack_time          = {}
    trans_depth_map   = {}
    response_body_map = {}
    ftp_login_map     = {}

    http_methods = ('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ttl    = pkt[IP].ttl
            proto  = pkt[IP].proto

            
            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            else:
                src_port = 0
                dst_port = 0

            fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
            rev_key = (dst_ip, src_ip, dst_port, src_port, proto)

            
            if fwd_key not in sttl_map:
                sttl_map[fwd_key] = ttl
            if rev_key not in dttl_map:
                dttl_map[rev_key] = ttl

            
            if pkt.haslayer(TCP):
                window = pkt[TCP].window
                flags  = pkt[TCP].flags
                ts     = float(pkt.time)

                
                if fwd_key not in swin_map:
                    swin_map[fwd_key] = window
                if rev_key not in dwin_map:
                    dwin_map[rev_key] = window

                
                if flags == 0x02 and fwd_key not in syn_time:
                    syn_time[fwd_key] = ts
                if flags == 0x12 and rev_key not in synack_time:
                    synack_time[rev_key] = ts
                if flags == 0x10 and fwd_key not in ack_time:
                    if fwd_key in syn_time:
                        ack_time[fwd_key] = ts

                
                if pkt.haslayer(Raw):
                    try:
                        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    except Exception:
                        payload = ''

                    
                    if any(payload.startswith(m) for m in http_methods):
                        trans_depth_map[fwd_key] = trans_depth_map.get(fwd_key, 0) + 1

                    
                    if payload.startswith('HTTP/'):
                        found = False
                        for line in payload.split('\r\n'):
                            if line.lower().startswith('content-length:'):
                                try:
                                    length = int(line.split(':')[1].strip())
                                    response_body_map[fwd_key] = response_body_map.get(fwd_key, 0) + length
                                    found = True
                                except Exception:
                                    pass
                        if not found and '\r\n\r\n' in payload:
                            body = payload.split('\r\n\r\n', 1)[1]
                            response_body_map[fwd_key] = response_body_map.get(fwd_key, 0) + len(body.encode('utf-8'))

                    
                    if (src_port == 21 or dst_port == 21) and '230' in payload:
                        ftp_login_map[fwd_key] = 1
                        ftp_login_map[rev_key] = 1

    return {
        'sttl_map':          sttl_map,
        'dttl_map':          dttl_map,
        'swin_map':          swin_map,
        'dwin_map':          dwin_map,
        'syn_time':          syn_time,
        'synack_time':       synack_time,
        'ack_time':          ack_time,
        'trans_depth_map':   trans_depth_map,
        'response_body_map': response_body_map,
        'ftp_login_map':     ftp_login_map,
    }


def apply_pcap_features(df: pd.DataFrame, raw_df: pd.DataFrame, maps: dict) -> pd.DataFrame:
    """Apply all PCAP-derived maps onto raw_df in one place."""

    sttl_map          = maps['sttl_map']
    dttl_map          = maps['dttl_map']
    swin_map          = maps['swin_map']
    dwin_map          = maps['dwin_map']
    syn_time          = maps['syn_time']
    synack_time       = maps['synack_time']
    ack_time          = maps['ack_time']
    trans_depth_map   = maps['trans_depth_map']
    response_body_map = maps['response_body_map']
    ftp_login_map     = maps['ftp_login_map']

    def _key(r):
        return (r['src_ip'], r['dst_ip'], int(r['src_port']), int(r['dst_port']), int(r['protocol']))

    def _rkey(r):
        return (r['dst_ip'], r['src_ip'], int(r['dst_port']), int(r['src_port']), int(r['protocol']))

    def _rtt(r):
        k  = _key(r)
        t1 = syn_time.get(k)
        t2 = synack_time.get(k)
        t3 = ack_time.get(k)
        return pd.Series([
            round(t2 - t1, 6) if t1 and t2 else 0,
            round(t3 - t1, 6) if t1 and t3 else 0,
        ])

    raw_df['sttl']             = df.apply(lambda r: sttl_map.get(_key(r), 0),          axis=1)
    raw_df['dttl']             = df.apply(lambda r: dttl_map.get(_rkey(r), 0),         axis=1)
    raw_df['swin']             = df.apply(lambda r: swin_map.get(_key(r), 0),          axis=1)
    raw_df['dwin']             = df.apply(lambda r: dwin_map.get(_rkey(r), 0),         axis=1)
    raw_df[['synack','tcprtt']]= df.apply(_rtt, axis=1)
    raw_df['trans_depth']      = df.apply(lambda r: trans_depth_map.get(_key(r), 0),   axis=1)
    raw_df['response_body_len']= df.apply(lambda r: response_body_map.get(_key(r), 0), axis=1)
    raw_df['is_ftp_login']     = df.apply(lambda r: ftp_login_map.get(_key(r), 0),     axis=1)

    return raw_df



def compute_ct_features(df: pd.DataFrame, raw_df: pd.DataFrame):
    window = deque(maxlen=100)

    ct_srv_src       = []
    ct_srv_dst       = []
    ct_dst_src_ltm   = []
    ct_src_dport_ltm = []
    ct_dst_sport_ltm = []
    ct_state_ttl     = []

    for idx, row in df.iterrows():
        src_ip   = row['src_ip']
        dst_ip   = row['dst_ip']
        src_port = row['src_port']
        dst_port = row['dst_port']
        service  = raw_df.loc[idx, 'service']
        state    = raw_df.loc[idx, 'state']
        sttl     = raw_df.loc[idx, 'sttl']

        ct_srv_src.append(      sum(1 for f in window if f['src_ip'] == src_ip and f['service'] == service))
        ct_srv_dst.append(      sum(1 for f in window if f['dst_ip'] == dst_ip and f['service'] == service))
        ct_dst_src_ltm.append(  sum(1 for f in window if f['src_ip'] == src_ip and f['dst_ip'] == dst_ip))
        ct_src_dport_ltm.append(sum(1 for f in window if f['src_ip'] == src_ip and f['dst_port'] == dst_port))
        ct_dst_sport_ltm.append(sum(1 for f in window if f['dst_ip'] == dst_ip and f['src_port'] == src_port))
        ct_state_ttl.append(    sum(1 for f in window if f['state'] == state and f['sttl'] == sttl))

        window.append({
            'src_ip':   src_ip,
            'dst_ip':   dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'service':  service,
            'state':    state,
            'sttl':     sttl,
        })

    raw_df['ct_srv_src']       = ct_srv_src
    raw_df['ct_srv_dst']       = ct_srv_dst
    raw_df['ct_dst_src_ltm']   = ct_dst_src_ltm
    raw_df['ct_src_dport_ltm'] = ct_src_dport_ltm
    raw_df['ct_dst_sport_ltm'] = ct_dst_sport_ltm
    raw_df['ct_state_ttl']     = ct_state_ttl

    return raw_df




def compute_ct_flw_http_mthd(df: pd.DataFrame, raw_df: pd.DataFrame, trans_depth_map: dict) -> pd.DataFrame:
    window = deque(maxlen=100)
    ct_flw_http_mthd = []

    for _, row in df.iterrows():
        src_ip   = row['src_ip']
        dst_ip   = row['dst_ip']
        src_port = int(row['src_port'])
        dst_port = int(row['dst_port'])
        proto    = int(row['protocol'])
        fwd_key  = (src_ip, dst_ip, src_port, dst_port, proto)

        count = sum(1 for f in window if f['had_http'])
        ct_flw_http_mthd.append(count)

        had_http = fwd_key in trans_depth_map and trans_depth_map[fwd_key] > 0
        window.append({'had_http': had_http})

    raw_df['ct_flw_http_mthd'] = ct_flw_http_mthd
    return raw_df


def extract_all_features(pcap_path: str) -> pd.DataFrame:

    df = load_pcap(pcap_path)
    
    raw_df = extract_basic_features(df)

    maps = _single_pcap_pass(pcap_path)
    
    raw_df = apply_pcap_features(df, raw_df, maps)

    raw_df = compute_ct_features(df, raw_df)

    raw_df = compute_ct_flw_http_mthd(df, raw_df, maps['trans_depth_map'])

    return raw_df
