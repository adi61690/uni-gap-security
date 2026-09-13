from __future__ import annotations
import hashlib, struct
from typing import Any

def _ja3(ciphers, exts, groups, ec_formats, version=771):
    s=f"{version},{'-'.join(map(str,ciphers))},{'-'.join(map(str,exts))},{'-'.join(map(str,groups))},{'-'.join(map(str,ec_formats))}"
    return s, hashlib.md5(s.encode()).hexdigest()

def parse_tls_handshake(data: bytes) -> dict[str, Any]:
    """Inspect only TLS handshake records; application payload is never stored/returned."""
    if not data or len(data) < 5: return {}
    out: dict[str, Any]={}
    try:
        content_type=data[0]
        version=struct.unpack('!H', data[1:3])[0]
        rec_len=struct.unpack('!H', data[3:5])[0]
        if content_type != 22 or rec_len<=0 or len(data)<5+rec_len: return out
        hs=data[5:5+rec_len]
        if len(hs)<4: return out
        hstype=hs[0]; hlen=int.from_bytes(hs[1:4],'big')
        body=hs[4:4+hlen]
        out['record_version']=version
        out['handshake_type']=hstype
        out['record_length']=rec_len
        if hstype==1:
            if len(body)<34: return out
            client_version=struct.unpack('!H',body[0:2])[0]
            ptr=34
            sid_len=body[ptr]; ptr+=1+sid_len
            if ptr+2>len(body): return out
            cs_len=struct.unpack('!H',body[ptr:ptr+2])[0]; ptr+=2
            ciphers=[struct.unpack('!H',body[i:i+2])[0] for i in range(ptr, min(ptr+cs_len,len(body)),2) if i+2<=len(body)]; ptr+=cs_len
            if ptr>=len(body): return out
            comp_len=body[ptr]; ptr+=1+comp_len
            if ptr+2>len(body): return out
            ext_len=struct.unpack('!H',body[ptr:ptr+2])[0]; ptr+=2
            exts=[]; groups=[]; ec_formats=[]; sni=None; alpn=[]
            end=min(len(body),ptr+ext_len)
            while ptr+4<=end:
                et,el=struct.unpack('!HH',body[ptr:ptr+4]); ptr+=4
                ed=body[ptr:ptr+el]; ptr+=el; exts.append(et)
                if et==0 and len(ed)>=5:
                    try:
                        pos=2; nlen=struct.unpack('!H',ed[pos:pos+2])[0]; pos+=2; sni=ed[pos:pos+nlen].decode(errors='ignore')
                    except Exception: pass
                elif et==10 and len(ed)>=2:
                    gl=struct.unpack('!H',ed[:2])[0]; groups=[struct.unpack('!H',ed[i:i+2])[0] for i in range(2,min(2+gl,len(ed)),2) if i+2<=len(ed)]
                elif et==11 and ed:
                    fl=ed[0]; ec_formats=list(ed[1:1+fl])
                elif et==16 and len(ed)>=2:
                    total=struct.unpack('!H',ed[:2])[0]; pos=2; end2=min(len(ed),2+total)
                    while pos<end2:
                        n=ed[pos]; pos+=1; alpn.append(ed[pos:pos+n].decode(errors='ignore')); pos+=n
            ja3_string,ja3=_ja3(ciphers,exts,groups,ec_formats,client_version)
            out.update(tls_version=client_version,ciphers=ciphers,extensions=exts,supported_groups=groups,ec_point_formats=ec_formats,sni=sni,alpn=alpn,ja3_string=ja3_string,ja3=ja3)
        elif hstype==2:
            if len(body)>=34:
                server_version=struct.unpack('!H',body[0:2])[0]
                cipher=struct.unpack('!H',body[34:36])[0] if len(body)>=36 else None
                out.update(tls_version=server_version,selected_cipher=cipher,ja3s=f'{server_version},{cipher if cipher is not None else ""}')
    except Exception:
        return out
    return out
