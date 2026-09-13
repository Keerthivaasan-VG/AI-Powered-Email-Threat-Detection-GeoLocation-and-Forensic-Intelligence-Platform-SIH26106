from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
import hashlib, re
from pathlib import Path

MAX_SIZE=10*1024*1024
def parse_eml(content: bytes, filename: str):
    if not filename.lower().endswith(".eml"): raise ValueError("Only .eml files are accepted.")
    if len(content)>MAX_SIZE: raise ValueError("The selected file exceeds the 10 MB upload limit.")
    try: msg=BytesParser(policy=policy.default).parsebytes(content)
    except Exception as e: raise ValueError("Unable to parse the uploaded EML message.") from e
    def h(name):
        v=msg.get(name); return str(v) if v is not None else None
    def addresses(name):
        vals=getaddresses(msg.get_all(name,[]))
        return [{"name":n,"address":a} for n,a in vals if a]
    body=""
    html=""
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_attachment(): continue
            ct=part.get_content_type()
            try:
                data=part.get_content()
            except Exception:
                data=""
            if ct=="text/plain": body += str(data)+"\n"
            elif ct=="text/html": html += str(data)+"\n"
    else:
        try:
            data=msg.get_content()
            if msg.get_content_type()=="text/html": html=str(data)
            else: body=str(data)
        except Exception: pass
    attachments=[]
    for part in msg.iter_attachments():
        payload=part.get_payload(decode=True) or b""
        attachments.append({"filename":part.get_filename() or "unnamed","mimeType":part.get_content_type(),
                           "size":len(payload),"sha256":hashlib.sha256(payload).hexdigest(),
                           "contentDisposition":part.get_content_disposition() or "attachment"})
    headers=[]
    for k,v in msg.raw_items(): headers.append({"name":k,"value":str(v)})
    received=[h for h in headers if h["name"].lower()=="received"]
    auth=[h for h in headers if h["name"].lower() in {"authentication-results","received-spf","dkim-signature","arc-authentication-results","arc-seal","arc-message-signature"}]
    email={"filename":filename,"from":h("From"),"to":h("To"),"cc":h("Cc"),"bcc":h("Bcc"),"subject":h("Subject"),
           "dateTime": h("Date"), "replyTo":h("Reply-To"),"returnPath":h("Return-Path"),"sender":h("Sender"),
           "messageId":h("Message-ID"),"inReplyTo":h("In-Reply-To"),"references":h("References"),
           "addresses":{"from":addresses("From"),"to":addresses("To"),"cc":addresses("Cc"),"replyTo":addresses("Reply-To")}}
    raw="\n".join(f"{x['name']}: {x['value']}" for x in headers)
    return {"email":email,"headers":{"totalCount":len(headers),"receivedCount":len(received),
        "authenticationCount":len(auth),"all":headers,"received":received,"authenticationHeaders":auth,"raw":raw},
        "body":body,"html":html,"attachments":attachments}
