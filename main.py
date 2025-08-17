import os, re, sys, email
from email import policy
from urllib.parse import urlparse

def extract_urls(text):
    pattern = r'(https?://[^\s]+)'
    return re.findall(pattern, text or "")

def domain(addr):
    try:
        return addr.split("@",1)[1].lower()
    except Exception:
        return ""

def score_email(msg):
    score, notes = 0, []
    from_addr = email.utils.parseaddr(msg.get('From') or '')[1]
    reply_to = email.utils.parseaddr(msg.get('Reply-To') or '')[1]
    subject = msg.get('Subject') or ""
    body = msg.get_body(preferencelist=('plain','html'))
    text = body.get_content() if body else ""
    urls = extract_urls(text)

    # Heuristics
    if reply_to and domain(from_addr)!=domain(reply_to):
        score+=2; notes.append("From/Reply-to mismatch")
    if urls:
        score+=1; notes.append("Contains URL(s)")
        for u in urls:
            host = urlparse(u).hostname or ""
            if re.match(r"\d+\.\d+\.\d+\.\d+", host):
                score+=2; notes.append("IP-based URL")
            if host.count('.')>=3:
                score+=1; notes.append("Suspicious subdomain")
    if any(word in subject.lower() for word in ["urgent","verify","password","suspend"]):
        score+=1; notes.append("Urgent subject")

    return score, notes, urls

def main():
    if len(sys.argv)<2:
        print("Usage: python main.py <sample.eml>")
        sys.exit(1)
    path = sys.argv[1]
    with open(path,"rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    score, notes, urls = score_email(msg)
    print("From:", msg.get('From'))
    print("Subject:", msg.get('Subject'))
    print("Score:", score)
    print("Notes:", "; ".join(notes))
    if urls:
        print("URLs:", "; ".join(urls))

if __name__=="__main__":
    main()
