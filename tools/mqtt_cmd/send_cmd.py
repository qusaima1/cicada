import argparse, base64, json, subprocess, tempfile

def sign(priv_pem, data_bytes):
    with tempfile.TemporaryDirectory() as td:
        msg = f"{td}/msg.txt"
        sig = f"{td}/sig.der"
        open(msg, "wb").write(data_bytes)
        subprocess.check_call(["openssl", "dgst", "-sha256", "-sign", priv_pem, "-out", sig, msg])
        return open(sig, "rb").read()

def canonical(device_id, ctr, cmd, args_json):
    return (
        "CICADA-CMD-v1\n"
        f"device_id={device_id}\n"
        f"ctr={ctr}\n"
        f"cmd={cmd}\n"
        f"args_json={args_json}\n"
    ).encode("utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device-id", required=True)
    ap.add_argument("--ctr", type=int, required=True)
    ap.add_argument("--cmd", required=True)
    ap.add_argument("--args-json", default="{}")
    ap.add_argument("--priv", default="tools/control_keys/control_priv.pem")
    ap.add_argument("--host", default="192.168.1.151")
    ap.add_argument("--port", default="8883")
    ap.add_argument("--topic-prefix", default="cicada")
    args = ap.parse_args()

    payload = canonical(args.device_id, args.ctr, args.cmd, args.args_json)
    sig_der = sign(args.priv, payload)
    sig_b64 = base64.b64encode(sig_der).decode("ascii")

    msg = {
        "device_id": args.device_id,
        "ctr": args.ctr,
        "cmd": args.cmd,
        "args_json": args.args_json,
        "sig_b64": sig_b64,
    }

    topic = f"{args.topic_prefix}/{args.device_id}/cmd/exec"
    print("Publishing to", topic)
    print(json.dumps(msg))

    # Use mosquitto_pub with admin cert
    subprocess.check_call([
        "mosquitto_pub",
        "-h", args.host, "-p", str(args.port),
        "--cafile", "tools/mqtt_broker/certs/cicada_ca.crt",
        "--cert",   "tools/mqtt_broker/certs/admin.crt",
        "--key",    "tools/mqtt_broker/certs/admin.key",
        "-t", topic,
        "-m", json.dumps(msg)
    ])

if __name__ == "__main__":
    main()
